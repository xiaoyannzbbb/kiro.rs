//! 企业外部 IdP（external_idp）专用端点
//!
//! 完全复刻官方 Kiro CLI 对企业 external_idp 账号使用的 `*.kiro.dev` 端点
//! （依据 Kiro CLI 抓包）：
//! - 对话 API: `POST https://runtime.{api_region}.kiro.dev/`
//!   - `x-amz-target: AmazonCodeWhispererStreamingService.GenerateAssistantResponse`
//!   - `Content-Type: application/x-amz-json-1.0`
//!   - `x-amzn-codewhisperer-optout: false`
//!   - `tokentype: EXTERNAL_IDP`
//!   - 请求体 `origin: KIRO_CLI`，根对象注入 `profileArn`
//!
//! 仅对 `auth_method == external_idp` 的凭据生效（由 `KiroProvider::endpoint_for`
//! 在识别到 external_idp 凭据时强制选用，与凭据的 `endpoint` 字段无关）。
//!
//! 注意：`origin=AI_EDITOR`（IDE 端点）下，部分企业 external_idp 账号的模型目录
//! **不含 Claude**；必须走 `KIRO_CLI` origin 才能拿到完整 Claude 目录。模型列表的
//! 对应处理见 `token_manager::get_available_models`。

use reqwest::RequestBuilder;
use uuid::Uuid;

use super::{KiroEndpoint, RequestContext};
use crate::kiro::endpoint::cli::set_origin_kiro_cli;
use crate::kiro::endpoint::ide::inject_profile_arn;

pub const EXTERNAL_IDP_ENDPOINT_NAME: &str = "external_idp";

pub struct ExternalIdpEndpoint;

impl ExternalIdpEndpoint {
    pub fn new() -> Self {
        Self
    }

    fn api_region<'a>(&self, ctx: &'a RequestContext<'_>) -> &'a str {
        ctx.credentials.effective_api_region(ctx.config)
    }

    fn host(&self, ctx: &RequestContext<'_>) -> String {
        format!("runtime.{}.kiro.dev", self.api_region(ctx))
    }

    fn user_agent(&self, ctx: &RequestContext<'_>) -> String {
        format!(
            "aws-sdk-rust/1.3.15 ua/2.1 api/codewhispererstreaming/0.1.16551 os/{} lang/rust/1.92.0 md/appVersion-{} app/AmazonQ-For-CLI",
            ctx.config.system_version,
            ctx.config.kiro_version,
        )
    }

    fn x_amz_user_agent(&self, _ctx: &RequestContext<'_>) -> String {
        "aws-sdk-rust/1.3.15 ua/2.1 api/codewhispererstreaming/0.1.16551 lang/rust/1.92.0 m/F app/AmazonQ-For-CLI".to_string()
    }
}

impl Default for ExternalIdpEndpoint {
    fn default() -> Self {
        Self::new()
    }
}

impl KiroEndpoint for ExternalIdpEndpoint {
    fn name(&self) -> &'static str {
        EXTERNAL_IDP_ENDPOINT_NAME
    }

    fn content_type(&self) -> &'static str {
        "application/x-amz-json-1.0"
    }

    fn api_url(&self, ctx: &RequestContext<'_>) -> String {
        format!("https://runtime.{}.kiro.dev/", self.api_region(ctx))
    }

    fn mcp_url(&self, ctx: &RequestContext<'_>) -> String {
        // 抓包未覆盖 MCP；按同域 runtime 主机的 /mcp 路径作最佳猜测。
        format!("https://runtime.{}.kiro.dev/mcp", self.api_region(ctx))
    }

    fn decorate_api(&self, req: RequestBuilder, ctx: &RequestContext<'_>) -> RequestBuilder {
        let mut req = req
            .header(
                "x-amz-target",
                "AmazonCodeWhispererStreamingService.GenerateAssistantResponse",
            )
            .header("x-amzn-codewhisperer-optout", "false")
            .header("x-amz-user-agent", self.x_amz_user_agent(ctx))
            .header("user-agent", self.user_agent(ctx))
            .header("host", self.host(ctx))
            .header("amz-sdk-invocation-id", Uuid::new_v4().to_string())
            .header("amz-sdk-request", "attempt=1; max=3")
            .header("Authorization", format!("Bearer {}", ctx.token));

        if let Some(tt) = ctx.credentials.token_type_header() {
            req = req.header("tokentype", tt);
        }
        req
    }

    fn decorate_mcp(&self, req: RequestBuilder, ctx: &RequestContext<'_>) -> RequestBuilder {
        let mut req = req
            .header("x-amz-user-agent", self.x_amz_user_agent(ctx))
            .header("user-agent", self.user_agent(ctx))
            .header("host", self.host(ctx))
            .header("amz-sdk-invocation-id", Uuid::new_v4().to_string())
            .header("amz-sdk-request", "attempt=1; max=3")
            .header("Authorization", format!("Bearer {}", ctx.token));

        if let Some(arn) = ctx.credentials.effective_profile_arn() {
            req = req.header("x-amzn-kiro-profile-arn", arn);
        }
        if let Some(tt) = ctx.credentials.token_type_header() {
            req = req.header("tokentype", tt);
        }
        req
    }

    fn transform_api_body(&self, body: &str, ctx: &RequestContext<'_>) -> String {
        // 1) 根对象注入真实 profileArn（external_idp 账号必带）
        // 2) origin 改为 KIRO_CLI（决定模型目录 / 鉴权口径）
        let body = inject_profile_arn(body, ctx.credentials.streaming_profile_arn().as_deref());
        set_origin_kiro_cli(&body)
    }
}
