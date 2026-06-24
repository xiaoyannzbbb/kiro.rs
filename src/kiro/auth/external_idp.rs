//! 企业外部身份提供商（External IdP）登录支持
//!
//! 复现 `kiro-login-helper.py` 的企业 SSO（Microsoft 365 / Entra ID）登录流程中
//! 与外部 IdP 直接交互的部分：
//!
//! 1. [`oidc_discover`]：对 portal 回调给出的 `issuer_url` 做 OIDC discovery，
//!    解析 `authorization_endpoint` 与 `token_endpoint`。
//! 2. [`build_authorize_url`]：构建第二腿（leg-2）的授权码 + PKCE URL，浏览器
//!    302 跳转到企业 IdP 登录页。
//! 3. [`exchange_code`]：用 IdP 返回的授权码在 token 端点做 public client 兑换。
//! 4. [`refresh`]：用 refresh_token 在 token 端点刷新（public client）。
//!
//! ## 安全（SSRF / open-redirect 防护）
//!
//! `issuer_url` 来自可被攻击者影响的 portal 回调，因此 [`validate_external_idp_endpoint`]
//! 强制：仅 https、拒绝 IP 字面量主机、主机必须落在允许的后缀白名单内（前导点锚定
//! 子域边界，防止 `evil-microsoftonline.com` 这类伪造）。discovery 与发现得到的
//! authorize / token 两个端点都要校验；discovery 请求禁止跟随重定向，避免被 bounce
//! 到内网目标。

use std::net::IpAddr;
use std::str::FromStr;

use crate::http_client::{ProxyConfig, build_client, build_client_with_redirect};
use crate::kiro::model::token_refresh::{ExternalIdpErrorResponse, ExternalIdpTokenResponse};
use crate::model::config::Config;

/// 默认允许的外部 IdP 主机后缀（Microsoft Entra / Azure AD）。
///
/// 可通过 `config.externalIdpAllowedHosts` 覆盖 / 扩展以接入其它企业 IdP。
/// 前导点锚定子域边界。
pub const DEFAULT_ALLOWED_IDP_SUFFIXES: &[&str] = &[
    ".microsoftonline.com",
    ".microsoftonline.us",
    ".microsoftonline.cn",
];

/// 从 URL 字符串中提取 `(scheme, host)`（小写）。
///
/// 不依赖 `url` crate（与本项目其余部分保持一致）。仅做登录场景所需的有限解析：
/// `scheme://[userinfo@]host[:port][/path...]`，支持 IPv6 字面量 `[::1]`。
fn parse_scheme_host(raw: &str) -> Option<(String, String)> {
    let raw = raw.trim();
    let idx = raw.find("://")?;
    let scheme = raw[..idx].to_ascii_lowercase();
    if scheme.is_empty() {
        return None;
    }
    let rest = &raw[idx + 3..];
    // authority 截止到第一个 '/'、'?' 或 '#'
    let authority_end = rest
        .find(['/', '?', '#'])
        .unwrap_or(rest.len());
    let authority = &rest[..authority_end];
    // 去掉 userinfo（最后一个 '@' 之前）
    let host_port = match authority.rfind('@') {
        Some(at) => &authority[at + 1..],
        None => authority,
    };
    // 处理 IPv6 字面量 [::1]:port
    let host = if let Some(stripped) = host_port.strip_prefix('[') {
        // 取到 ']' 为止
        let end = stripped.find(']')?;
        stripped[..end].to_string()
    } else {
        // host[:port]
        host_port
            .split(':')
            .next()
            .unwrap_or(host_port)
            .to_string()
    };
    if host.is_empty() {
        return None;
    }
    Some((scheme, host.to_ascii_lowercase()))
}

/// 校验外部 IdP 端点 URL 是否安全可用。
///
/// - 必须 https；
/// - 必须有命名主机，且不得为 IP 字面量；
/// - 主机必须以 `allowed` 中某个后缀结尾。
pub fn validate_external_idp_endpoint(raw_url: &str, allowed: &[String]) -> anyhow::Result<()> {
    let (scheme, host) = parse_scheme_host(raw_url)
        .ok_or_else(|| anyhow::anyhow!("外部 IdP URL 解析失败: {}", raw_url))?;

    if scheme != "https" {
        anyhow::bail!("外部 IdP URL 必须为 https: {}", raw_url);
    }

    // 拒绝 IP 字面量主机（仅允许命名、白名单内的 IdP 主机）
    if IpAddr::from_str(&host).is_ok() {
        anyhow::bail!("外部 IdP 主机不得为 IP 字面量: {}", host);
    }

    let ok = allowed.iter().any(|suffix| {
        let s = suffix.trim().to_ascii_lowercase();
        !s.is_empty() && host.ends_with(&s)
    });
    if !ok {
        anyhow::bail!("外部 IdP 主机不在允许列表内: {}", host);
    }
    Ok(())
}

/// OIDC discovery：GET `{issuer}/.well-known/openid-configuration`（禁止跟随重定向），
/// 返回 `(authorization_endpoint, token_endpoint)`。
///
/// issuer 与发现得到的两个端点都会做 [`validate_external_idp_endpoint`] 校验。
pub async fn oidc_discover(
    issuer_url: &str,
    allowed: &[String],
    config: &Config,
    proxy: Option<&ProxyConfig>,
) -> anyhow::Result<(String, String)> {
    validate_external_idp_endpoint(issuer_url, allowed)?;

    let doc_url = format!(
        "{}/.well-known/openid-configuration",
        issuer_url.trim().trim_end_matches('/')
    );

    // discovery 禁止跟随重定向（防 bounce 到内网）
    let client = build_client_with_redirect(proxy, 30, config.tls_backend, false)?;
    let resp = client
        .get(&doc_url)
        .header("Accept", "application/json")
        .send()
        .await
        .map_err(|e| anyhow::anyhow!("OIDC discovery 请求失败: {}", e))?;

    let status = resp.status();
    if !status.is_success() {
        anyhow::bail!("OIDC discovery 失败: HTTP {}", status);
    }

    let doc: serde_json::Value = resp
        .json()
        .await
        .map_err(|e| anyhow::anyhow!("OIDC discovery 响应解析失败: {}", e))?;

    let auth_endpoint = doc
        .get("authorization_endpoint")
        .and_then(|v| v.as_str())
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .ok_or_else(|| anyhow::anyhow!("OIDC discovery 文档缺少 authorization_endpoint"))?;
    let token_endpoint = doc
        .get("token_endpoint")
        .and_then(|v| v.as_str())
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .ok_or_else(|| anyhow::anyhow!("OIDC discovery 文档缺少 token_endpoint"))?;

    validate_external_idp_endpoint(&auth_endpoint, allowed)?;
    validate_external_idp_endpoint(&token_endpoint, allowed)?;

    Ok((auth_endpoint, token_endpoint))
}

/// 构建第二腿（leg-2）授权码 + PKCE 的 IdP 授权 URL。
pub fn build_authorize_url(
    auth_endpoint: &str,
    client_id: &str,
    redirect_uri: &str,
    scopes: &str,
    challenge: &str,
    state: &str,
    login_hint: &str,
) -> String {
    let mut q = format!(
        "client_id={}&response_type=code&redirect_uri={}&scope={}&code_challenge={}&code_challenge_method=S256&response_mode=query&state={}",
        urlencoding::encode(client_id),
        urlencoding::encode(redirect_uri),
        urlencoding::encode(scopes),
        urlencoding::encode(challenge),
        urlencoding::encode(state),
    );
    if !login_hint.trim().is_empty() {
        q.push_str(&format!("&login_hint={}", urlencoding::encode(login_hint)));
    }
    let sep = if auth_endpoint.contains('?') { '&' } else { '?' };
    format!("{}{}{}", auth_endpoint, sep, q)
}

/// 用授权码兑换 IdP token（public client 授权码授予，form-encoded）。
pub async fn exchange_code(
    token_endpoint: &str,
    client_id: &str,
    code: &str,
    code_verifier: &str,
    redirect_uri: &str,
    scopes: &str,
    config: &Config,
    proxy: Option<&ProxyConfig>,
) -> anyhow::Result<ExternalIdpTokenResponse> {
    let mut form = vec![
        ("client_id", client_id),
        ("grant_type", "authorization_code"),
        ("code", code.trim()),
        ("redirect_uri", redirect_uri),
        ("code_verifier", code_verifier),
    ];
    if !scopes.trim().is_empty() {
        form.push(("scope", scopes));
    }
    post_token(token_endpoint, &form, config, proxy).await
}

/// 用 refresh_token 刷新 IdP token（public client，无 client_secret）。
pub async fn refresh(
    token_endpoint: &str,
    client_id: &str,
    refresh_token: &str,
    scopes: Option<&str>,
    config: &Config,
    proxy: Option<&ProxyConfig>,
) -> anyhow::Result<ExternalIdpTokenResponse> {
    let mut form = vec![
        ("client_id", client_id),
        ("grant_type", "refresh_token"),
        ("refresh_token", refresh_token),
    ];
    if let Some(s) = scopes {
        if !s.trim().is_empty() {
            form.push(("scope", s));
        }
    }
    post_token(token_endpoint, &form, config, proxy).await
}

/// 向 IdP token 端点发起 form-encoded POST 并解析响应（成功 / OAuth2 错误体）。
async fn post_token(
    token_endpoint: &str,
    form: &[(&str, &str)],
    config: &Config,
    proxy: Option<&ProxyConfig>,
) -> anyhow::Result<ExternalIdpTokenResponse> {
    let client = build_client(proxy, 30, config.tls_backend)?;
    let resp = client
        .post(token_endpoint)
        .header("Content-Type", "application/x-www-form-urlencoded")
        .header("Accept", "application/json")
        .form(form)
        .send()
        .await
        .map_err(|e| anyhow::anyhow!("外部 IdP token 请求失败: {}", e))?;

    let status = resp.status();
    let text = resp.text().await.unwrap_or_default();

    if !status.is_success() {
        // 尝试解析标准 OAuth2 错误体
        if let Ok(err) = serde_json::from_str::<ExternalIdpErrorResponse>(&text) {
            anyhow::bail!(
                "外部 IdP token 失败 (HTTP {}): {}{}",
                status,
                err.error,
                err.error_description
                    .map(|d| format!(": {}", d))
                    .unwrap_or_default()
            );
        }
        anyhow::bail!("外部 IdP token 失败 (HTTP {}): {}", status, text);
    }

    let parsed: ExternalIdpTokenResponse = serde_json::from_str(&text)
        .map_err(|e| anyhow::anyhow!("外部 IdP token 响应解析失败: {}", e))?;
    if parsed.access_token.trim().is_empty() {
        anyhow::bail!("外部 IdP token 响应缺少 access_token");
    }
    Ok(parsed)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn default_allowed() -> Vec<String> {
        DEFAULT_ALLOWED_IDP_SUFFIXES
            .iter()
            .map(|s| s.to_string())
            .collect()
    }

    #[test]
    fn test_validate_accepts_microsoft_host() {
        let allowed = default_allowed();
        assert!(validate_external_idp_endpoint(
            "https://login.microsoftonline.com/tenant/v2.0",
            &allowed
        )
        .is_ok());
    }

    #[test]
    fn test_validate_rejects_http() {
        let allowed = default_allowed();
        assert!(validate_external_idp_endpoint(
            "http://login.microsoftonline.com/tenant",
            &allowed
        )
        .is_err());
    }

    #[test]
    fn test_validate_rejects_ip_literal() {
        let allowed = vec![".microsoftonline.com".to_string(), ".0.0.1".to_string()];
        // IP 字面量即便后缀匹配也必须拒绝
        assert!(validate_external_idp_endpoint("https://127.0.0.1/x", &allowed).is_err());
    }

    #[test]
    fn test_validate_rejects_lookalike_suffix() {
        let allowed = default_allowed();
        // 后缀以 . 锚定，evil-microsoftonline.com 不应匹配 .microsoftonline.com
        assert!(validate_external_idp_endpoint(
            "https://evil-microsoftonline.com/x",
            &allowed
        )
        .is_err());
    }

    #[test]
    fn test_validate_rejects_non_allowlisted() {
        let allowed = default_allowed();
        assert!(validate_external_idp_endpoint("https://accounts.google.com/x", &allowed).is_err());
    }

    #[test]
    fn test_validate_custom_allowlist() {
        let allowed = vec![".okta.com".to_string()];
        assert!(
            validate_external_idp_endpoint("https://dev-123.okta.com/oauth2", &allowed).is_ok()
        );
        assert!(
            validate_external_idp_endpoint("https://login.microsoftonline.com/x", &allowed)
                .is_err()
        );
    }

    #[test]
    fn test_build_authorize_url_contains_params() {
        let url = build_authorize_url(
            "https://login.microsoftonline.com/tid/oauth2/v2.0/authorize",
            "client-123",
            "http://localhost:3128/oauth/callback",
            "openid profile offline_access",
            "challenge-xyz",
            "state-abc",
            "",
        );
        assert!(url.contains("client_id=client-123"));
        assert!(url.contains("response_type=code"));
        assert!(url.contains("code_challenge=challenge-xyz"));
        assert!(url.contains("code_challenge_method=S256"));
        assert!(url.contains("response_mode=query"));
        assert!(url.contains("state=state-abc"));
        // scope 与 redirect_uri 被 URL 编码
        assert!(url.contains("scope=openid%20profile%20offline_access"));
        assert!(url.contains("redirect_uri=http%3A%2F%2Flocalhost%3A3128%2Foauth%2Fcallback"));
        // 未提供 login_hint 时不应出现
        assert!(!url.contains("login_hint"));
    }

    #[test]
    fn test_build_authorize_url_with_login_hint() {
        let url = build_authorize_url(
            "https://login.microsoftonline.com/tid/oauth2/v2.0/authorize",
            "c",
            "http://localhost:3128/oauth/callback",
            "openid",
            "ch",
            "st",
            "user@corp.com",
        );
        assert!(url.contains("login_hint=user%40corp.com"));
    }

    #[test]
    fn test_external_idp_token_response_snake_case() {
        let json = r#"{
            "access_token": "at",
            "refresh_token": "rt",
            "expires_in": 3600,
            "token_type": "Bearer",
            "scope": "openid profile"
        }"#;
        let parsed: ExternalIdpTokenResponse = serde_json::from_str(json).unwrap();
        assert_eq!(parsed.access_token, "at");
        assert_eq!(parsed.refresh_token.as_deref(), Some("rt"));
        assert_eq!(parsed.expires_in, Some(3600));
    }
}
