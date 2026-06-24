//! Kiro IDE Social 登录流程（Portal PKCE OAuth）
//!
//! 复现 Kiro IDE 的 portal-auth-provider 流程：
//! 1. 生成 PKCE code_verifier + code_challenge
//! 2. 启本地 HTTP 回调服务器
//! 3. 返回 portal URL 供用户在浏览器完成登录
//! 4. 捕获回调中的 authorization code
//! 5. 用 code + code_verifier 换取 access_token + refresh_token

use std::net::TcpListener;

use sha2::{Digest, Sha256};
use tokio::sync::oneshot;

use crate::http_client::{ProxyConfig, build_client};
use crate::kiro::auth::external_idp;
use crate::kiro::model::token_refresh::{SocialCreateTokenRequest, SocialCreateTokenResponse};
use crate::model::config::Config;

/// Portal 认证 URL（Kiro 网页版入口）
pub const KIRO_PORTAL_URL: &str = "https://app.kiro.dev";

/// Kiro auth service 默认端点
pub const KIRO_AUTH_ENDPOINT: &str = "https://prod.us-east-1.auth.desktop.kiro.dev";

/// 与 IDE 一致的本地回调端口候选列表
const CALLBACK_PORTS: &[u16] = &[
    3128, 4649, 6588, 8008, 9091, 49153, 50153, 51153, 52153, 53153,
];

/// OAuth 回调数据
#[derive(Debug, Clone)]
pub struct OAuthCallbackData {
    pub code: String,
    pub login_option: String,
    pub path: String,
    /// OAuth state 参数（用于 CSRF 验证）
    pub state: String,
}

/// 回调服务器最终投递给等待方的结果。
///
/// social（Google/GitHub）与 external_idp（企业 IdP）登录共用同一个 Kiro 登录页和
/// 同一个 loopback 监听器，由 portal 根据邮箱决定走哪条腿。
pub enum CallbackResult {
    /// social 直接授权码回调（现有路径）
    Social(OAuthCallbackData),
    /// external_idp 第二腿（leg-2）捕获到的授权码及兑换上下文
    ExternalIdp(ExternalIdpCallback),
}

/// external_idp leg-2 捕获到的授权码及在 IdP token 端点兑换所需的上下文。
pub struct ExternalIdpCallback {
    pub code: String,
    /// leg-2 PKCE code_verifier
    pub code_verifier: String,
    pub token_endpoint: String,
    pub client_id: String,
    pub issuer_url: String,
    pub scopes: String,
    /// leg-2 发给 IdP 的 redirect_uri（兑换时须原样回传）
    pub redirect_uri: String,
}

/// external_idp 描述符腿（leg-1）建立、code 腿（leg-2）消费的中间状态。
struct Leg2Ctx {
    state: String,
    verifier: String,
    token_endpoint: String,
    issuer_url: String,
    client_id: String,
    scopes: String,
    redirect_uri: String,
}

/// 回调服务器关闭句柄
///
/// Drop 时自动向服务器发送关闭信号，服务器退出监听循环并释放端口。
pub struct ServerHandle {
    _shutdown_tx: oneshot::Sender<()>,
}

/// 启动本地回调服务器，返回端口号和关闭句柄
///
/// 关闭句柄 drop 时服务器自动停止。当收到有效的 OAuth 回调时，通过 channel 发送
/// [`CallbackResult`]（social 直接授权码 或 external_idp leg-2 授权码）。
///
/// `config` / `proxy` / `allowed_idp_suffixes` 仅在企业 external_idp 描述符腿做
/// OIDC discovery 时使用；纯 social 登录不会触及。
pub fn start_callback_server(
    tx: oneshot::Sender<CallbackResult>,
    config: Config,
    proxy: Option<ProxyConfig>,
    allowed_idp_suffixes: Vec<String>,
) -> anyhow::Result<(u16, ServerHandle)> {
    // 直接持有已绑定的 socket，避免 probe-and-bind 的 TOCTOU 竞态
    let (port, std_listener) = bind_available_port()?;

    let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();

    tokio::spawn(async move {
        run_callback_server(
            std_listener,
            tx,
            shutdown_rx,
            config,
            proxy,
            allowed_idp_suffixes,
        )
        .await;
    });

    Ok((
        port,
        ServerHandle {
            _shutdown_tx: shutdown_tx,
        },
    ))
}

fn bind_available_port() -> anyhow::Result<(u16, std::net::TcpListener)> {
    for &port in CALLBACK_PORTS {
        match TcpListener::bind(("127.0.0.1", port)) {
            Ok(listener) => {
                listener.set_nonblocking(true)?;
                return Ok((port, listener));
            }
            Err(_) => continue,
        }
    }
    anyhow::bail!(
        "所有回调端口均被占用，请确保没有其他程序占用 {:?}",
        CALLBACK_PORTS
    )
}

async fn run_callback_server(
    std_listener: std::net::TcpListener,
    tx: oneshot::Sender<CallbackResult>,
    mut shutdown_rx: oneshot::Receiver<()>,
    config: Config,
    proxy: Option<ProxyConfig>,
    allowed_idp_suffixes: Vec<String>,
) {
    use tokio::io::AsyncReadExt;
    use tokio::net::TcpListener;

    let port = std_listener.local_addr().map(|a| a.port()).unwrap_or(0);
    let listener = match TcpListener::from_std(std_listener) {
        Ok(l) => l,
        Err(e) => {
            tracing::error!("Social 回调服务器初始化失败 (port {}): {}", port, e);
            return;
        }
    };

    tracing::info!("Social 回调服务器已启动: http://127.0.0.1:{}", port);

    // 只投递一次成功结果；external_idp 双腿流程跨多次请求，故循环不在描述符腿提前退出。
    let mut tx = Some(tx);
    // external_idp leg-2 上下文（描述符腿建立，code 腿消费）
    let mut leg2: Option<Leg2Ctx> = None;

    loop {
        let (mut stream, _addr) = tokio::select! {
            result = listener.accept() => match result {
                Ok(s) => s,
                Err(_) => break,
            },
            _ = &mut shutdown_rx => {
                tracing::info!("Social 回调服务器收到关闭信号，端口 {} 已释放", port);
                break;
            }
        };

        let mut buf = vec![0u8; 8192];
        let n = match stream.read(&mut buf).await {
            Ok(n) => n,
            Err(_) => continue,
        };

        let request = String::from_utf8_lossy(&buf[..n]);
        let first_line = request.lines().next().unwrap_or("");

        // 仅处理 GET
        let path_and_query = match first_line.strip_prefix("GET ").and_then(|s| {
            s.strip_suffix(" HTTP/1.1")
                .or_else(|| s.strip_suffix(" HTTP/1.0"))
        }) {
            Some(p) => p,
            None => {
                write_404(&mut stream).await;
                continue;
            }
        };

        let (path, query) = match path_and_query.find('?') {
            Some(idx) => (&path_and_query[..idx], &path_and_query[idx + 1..]),
            None => (path_and_query, ""),
        };
        let params = parse_query_string(query);

        // --- external_idp 描述符腿（leg-1）：无 code，带 issuer_url / login_option=external_idp ---
        // 与 Python 一致：gate 在 path != /oauth/callback，避免伪造的 /oauth/callback 重置 leg-2。
        let is_descriptor = params
            .get("login_option")
            .map(|v| v.eq_ignore_ascii_case("external_idp"))
            .unwrap_or(false)
            || params
                .get("issuer_url")
                .map(|v| !v.is_empty())
                .unwrap_or(false);

        if path != "/oauth/callback" && is_descriptor {
            if leg2.is_some() {
                // 已在进行中的 leg-2，忽略重复描述符
                write_status(&mut stream, 204).await;
                continue;
            }

            let issuer_url = params.get("issuer_url").cloned().unwrap_or_default();
            let client_id = params.get("client_id").cloned().unwrap_or_default();
            let scopes = params.get("scopes").cloned().unwrap_or_default();
            let login_hint = params.get("login_hint").cloned().unwrap_or_default();

            if client_id.is_empty() {
                tracing::warn!("external_idp 描述符缺少 client_id");
                write_html_page(&mut stream, false, "外部 IdP 描述符缺少 client_id，请重试。")
                    .await;
                break; // 关闭 channel → 上层报错
            }

            // OIDC discovery（校验 issuer + authorize/token 两端点，禁止跟随重定向）
            let (auth_endpoint, token_endpoint) = match external_idp::oidc_discover(
                &issuer_url,
                &allowed_idp_suffixes,
                &config,
                proxy.as_ref(),
            )
            .await
            {
                Ok(v) => v,
                Err(e) => {
                    tracing::warn!("external_idp OIDC discovery 失败: {}", e);
                    write_html_page(&mut stream, false, "外部 IdP discovery 失败，请重试。").await;
                    break;
                }
            };

            let (verifier, challenge) = generate_pkce();
            let state2 = uuid::Uuid::new_v4().to_string();
            // leg-2 redirect_uri：照搬 Kiro IDE / Python 的 loopback 约定（host=localhost），
            // 端口用实际绑定端口（取自与 IDE 一致的 CALLBACK_PORTS）。
            let redirect_uri = format!("http://localhost:{}/oauth/callback", port);
            let authorize_url = external_idp::build_authorize_url(
                &auth_endpoint,
                &client_id,
                &redirect_uri,
                &scopes,
                &challenge,
                &state2,
                &login_hint,
            );

            leg2 = Some(Leg2Ctx {
                state: state2,
                verifier,
                token_endpoint,
                issuer_url,
                client_id,
                scopes,
                redirect_uri,
            });

            // 302 把同一浏览器标签页跳转到企业 IdP 登录页
            write_redirect(&mut stream, &authorize_url).await;
            continue;
        }

        // --- external_idp 第二腿（leg-2）：/oauth/callback 且存在 leg-2 上下文 ---
        if path == "/oauth/callback" {
            if let Some(ctx) = leg2.as_ref() {
                let cb_state = params.get("state").cloned().unwrap_or_default();
                if !cb_state.is_empty() && cb_state == ctx.state {
                    if let Some(err) = params.get("error") {
                        let desc = params
                            .get("error_description")
                            .cloned()
                            .unwrap_or_default();
                        tracing::warn!("external_idp 授权错误: {} {}", err, desc);
                        write_html_page(&mut stream, false, "外部 IdP 授权失败，请重试。").await;
                        break;
                    }
                    let code = params.get("code").cloned().unwrap_or_default();
                    if code.is_empty() {
                        write_status(&mut stream, 204).await;
                        continue;
                    }
                    write_html_page(
                        &mut stream,
                        true,
                        "登录成功，Token 已更新，请返回 Kiro Admin UI。",
                    )
                    .await;
                    if let Some(sender) = tx.take() {
                        let _ = sender.send(CallbackResult::ExternalIdp(ExternalIdpCallback {
                            code,
                            code_verifier: ctx.verifier.clone(),
                            token_endpoint: ctx.token_endpoint.clone(),
                            client_id: ctx.client_id.clone(),
                            issuer_url: ctx.issuer_url.clone(),
                            scopes: ctx.scopes.clone(),
                            redirect_uri: ctx.redirect_uri.clone(),
                        }));
                    }
                    break;
                }
                // state 不匹配 → 落到下方 social 解析（伪造/陈旧回调将在上层 CSRF 处失败）
            }
        }

        // --- social 直接授权码腿（现有逻辑）---
        if let Some(callback) = parse_callback(path_and_query) {
            write_html_page(
                &mut stream,
                true,
                "登录成功，Token 已更新，请返回 Kiro Admin UI。",
            )
            .await;
            if let Some(sender) = tx.take() {
                let _ = sender.send(CallbackResult::Social(callback));
            }
            break;
        } else if path == "/oauth/callback" || path == "/signin/callback" {
            // 带 error 参数的回调
            let error_msg = params
                .get("error_description")
                .or_else(|| params.get("error"))
                .cloned()
                .unwrap_or_else(|| "未知错误".to_string());
            write_html_page(&mut stream, false, &error_msg).await;
            break;
        }

        // 其他请求返回 404
        write_404(&mut stream).await;
    }
}

/// 写一个带成功 / 失败样式的 200 HTML 提示页。
async fn write_html_page(stream: &mut tokio::net::TcpStream, success: bool, message: &str) {
    use tokio::io::AsyncWriteExt;
    let heading = if success {
        "<h2>&#10003; 登录成功</h2>".to_string()
    } else {
        "<h2>&#10007; 登录失败</h2>".to_string()
    };
    let title = if success { "登录成功" } else { "登录失败" };
    let body = format!(
        "<html><head><meta charset='utf-8'><title>{}</title></head><body style='font-family:sans-serif;text-align:center;padding:60px'>{}<p>{}</p><p style='color:#888;font-size:13px'>此标签页可以关闭。</p></body></html>",
        title, heading, message
    );
    let response = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        body.len(),
        body
    );
    let _ = stream.write_all(response.as_bytes()).await;
    let _ = stream.flush().await;
}

/// 写一个 302 重定向响应（用于 external_idp leg-1 跳转到 IdP）。
async fn write_redirect(stream: &mut tokio::net::TcpStream, location: &str) {
    use tokio::io::AsyncWriteExt;
    let response = format!(
        "HTTP/1.1 302 Found\r\nLocation: {}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
        location
    );
    let _ = stream.write_all(response.as_bytes()).await;
    let _ = stream.flush().await;
}

/// 写一个无 body 的状态响应（如 204，用于忽略重复/无效回调）。
async fn write_status(stream: &mut tokio::net::TcpStream, code: u16) {
    use tokio::io::AsyncWriteExt;
    let response = format!("HTTP/1.1 {} \r\nContent-Length: 0\r\nConnection: close\r\n\r\n", code);
    let _ = stream.write_all(response.as_bytes()).await;
    let _ = stream.flush().await;
}

async fn write_404(stream: &mut tokio::net::TcpStream) {
    use tokio::io::AsyncWriteExt;
    let _ = stream
        .write_all(b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
        .await;
    let _ = stream.flush().await;
}

fn parse_callback(path_and_query: &str) -> Option<OAuthCallbackData> {
    let (path, query) = if let Some(idx) = path_and_query.find('?') {
        (&path_and_query[..idx], &path_and_query[idx + 1..])
    } else {
        return None;
    };

    if path != "/oauth/callback" && path != "/signin/callback" {
        return None;
    }

    let params = parse_query_string(query);

    // 必须有 code 且没有 error
    if params.contains_key("error") {
        return None;
    }

    let code = params.get("code")?.clone();
    let login_option = params.get("login_option").cloned().unwrap_or_default();
    let state = params.get("state").cloned().unwrap_or_default();

    Some(OAuthCallbackData {
        code,
        login_option,
        path: path.to_string(),
        state,
    })
}

/// base64url 编码（无填充），与 Kiro IDE 行为一致
fn base64url_encode(data: &[u8]) -> String {
    // 标准 base64 → 替换 +/= 为 base64url 规范
    let b64 = base64_encode_standard(data);
    b64.replace('+', "-").replace('/', "_").replace('=', "")
}

/// 标准 base64 编码（用于内部转换）
fn base64_encode_standard(data: &[u8]) -> String {
    const CHARS: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity((data.len() + 2) / 3 * 4);
    for chunk in data.chunks(3) {
        let b0 = chunk[0] as usize;
        let b1 = if chunk.len() > 1 {
            chunk[1] as usize
        } else {
            0
        };
        let b2 = if chunk.len() > 2 {
            chunk[2] as usize
        } else {
            0
        };
        out.push(CHARS[b0 >> 2] as char);
        out.push(CHARS[((b0 & 3) << 4) | (b1 >> 4)] as char);
        if chunk.len() > 1 {
            out.push(CHARS[((b1 & 0xf) << 2) | (b2 >> 6)] as char);
        } else {
            out.push('=');
        }
        if chunk.len() > 2 {
            out.push(CHARS[b2 & 0x3f] as char);
        } else {
            out.push('=');
        }
    }
    out
}

/// 生成 PKCE code_verifier 和 code_challenge
pub fn generate_pkce() -> (String, String) {
    // 32 字节随机数作为 verifier（与 IDE crypto.randomBytes(32).toString("base64url") 等价）
    let mut bytes = [0u8; 32];
    for (i, b) in bytes.iter_mut().enumerate() {
        *b = fastrand::u8(..).wrapping_add(i as u8);
    }
    // 使用 uuid v4 的随机性来增强
    let uuid_bytes = uuid::Uuid::new_v4().as_bytes().to_owned();
    for (i, b) in bytes.iter_mut().enumerate() {
        *b ^= uuid_bytes[i % 16];
    }

    let verifier = base64url_encode(&bytes);

    let mut hasher = Sha256::new();
    hasher.update(verifier.as_bytes());
    let digest = hasher.finalize();
    let challenge = base64url_encode(&digest);

    (verifier, challenge)
}

/// 构建供用户在浏览器中访问的 portal URL
pub fn build_portal_url(state: &str, code_challenge: &str, redirect_uri: &str) -> String {
    let params = format!(
        "state={}&code_challenge={}&code_challenge_method=S256&redirect_uri={}&redirect_from=KiroIDE",
        urlencoding::encode(state),
        urlencoding::encode(code_challenge),
        urlencoding::encode(redirect_uri),
    );
    format!("{}/signin?{}", KIRO_PORTAL_URL, params)
}

/// 简易 query string 解析（不依赖 url crate）
fn parse_query_string(query: &str) -> std::collections::HashMap<String, String> {
    query
        .split('&')
        .filter_map(|pair| {
            let mut iter = pair.splitn(2, '=');
            let key = iter.next()?.to_string();
            let val = iter
                .next()
                .map(|v| {
                    // 简单的 percent-decode（处理 %XX 和 + 号）
                    let with_space = v.replace('+', " ");
                    urlencoding::decode(&with_space)
                        .map(|s| s.into_owned())
                        .unwrap_or_else(|_| with_space)
                })
                .unwrap_or_default();
            Some((key, val))
        })
        .collect()
}

/// 用 authorization code 换取 access_token + refresh_token
pub async fn exchange_code_for_token(
    auth_endpoint: &str,
    code: &str,
    code_verifier: &str,
    full_redirect_uri: &str,
    config: &Config,
    proxy: Option<&ProxyConfig>,
) -> anyhow::Result<SocialCreateTokenResponse> {
    let url = format!("{}/oauth/token", auth_endpoint);
    let client = build_client(proxy, 30, config.tls_backend)?;

    let body = SocialCreateTokenRequest {
        code: code.to_string(),
        code_verifier: code_verifier.to_string(),
        redirect_uri: full_redirect_uri.to_string(),
        invitation_code: None,
    };

    let kiro_version = &config.kiro_version;
    let user_agent = format!("KiroIDE-{}", kiro_version);

    let resp = client
        .post(&url)
        .header("Content-Type", "application/json")
        .header("User-Agent", &user_agent)
        .header("host", auth_endpoint.trim_start_matches("https://"))
        .json(&body)
        .send()
        .await?;

    let status = resp.status();
    if !status.is_success() {
        let body_text = resp.text().await.unwrap_or_default();
        anyhow::bail!("Social token 交换失败 {}: {}", status, body_text);
    }

    resp.json::<SocialCreateTokenResponse>()
        .await
        .map_err(|e| anyhow::anyhow!("解析 Social token 响应失败: {}", e))
}
