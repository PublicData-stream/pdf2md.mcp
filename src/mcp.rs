//! Stateless, read-only MCP interface to the authorized caller service.
use std::{borrow::Cow, path::PathBuf, sync::Arc};

use crate::{
    auth::{AuthConfig, AuthMode},
    error::{LoadError, Result},
    service::CallerService,
};
use axum::{
    Json, Router,
    extract::{Request, State},
    http::{StatusCode, header},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::get,
};
use rmcp::{
    ErrorData, ServerHandler,
    model::{
        CallToolRequestParams, CallToolResponse, CallToolResult, ContentBlock, ListToolsResult,
        PaginatedRequestParams, ProtocolVersion, ServerCapabilities, ServerConfig, Tool,
        ToolAnnotations,
    },
    service::{RequestContext, RoleServer},
    transport::{
        StreamableHttpServerConfig, StreamableHttpService,
        streamable_http_server::session::local::LocalSessionManager,
    },
};
use serde::Deserialize;
use serde_json::{Value, json};
use tokio_util::sync::CancellationToken;

#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct McpConfig {
    pub enabled: bool,
    pub resource_url: Option<String>,
    pub allowed_origins: Vec<String>,
    pub max_read_bytes: u64,
    pub list_default_limit: usize,
    pub list_max_limit: usize,
    pub search_default_limit: usize,
    pub search_max_limit: usize,
    pub search_max_bytes: u64,
    pub search_timeout_secs: u64,
    pub search_concurrency: usize,
    pub rg_path: PathBuf,
}
impl Default for McpConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            resource_url: None,
            allowed_origins: vec![],
            max_read_bytes: 8 * 1024 * 1024,
            list_default_limit: 100,
            list_max_limit: 500,
            search_default_limit: 200,
            search_max_limit: 1000,
            search_max_bytes: 8 * 1024 * 1024,
            search_timeout_secs: 30,
            search_concurrency: 4,
            rg_path: "rg".into(),
        }
    }
}
impl McpConfig {
    pub fn validate(&self, auth: &AuthConfig) -> Result<()> {
        if !self.enabled {
            return Ok(());
        }
        let invalid = || LoadError::new("config_invalid", "invalid MCP configuration");
        if self.max_read_bytes == 0
            || self.max_read_bytes > 64 * 1024 * 1024
            || self.list_default_limit == 0
            || self.list_default_limit > self.list_max_limit
            || self.list_max_limit > 500
            || self.search_default_limit == 0
            || self.search_default_limit > self.search_max_limit
            || self.search_max_limit > 1000
            || self.search_max_bytes < 4096
            || self.search_max_bytes > 64 * 1024 * 1024
            || self.search_timeout_secs == 0
            || self.search_timeout_secs > 300
            || self.search_concurrency == 0
            || self.search_concurrency > 64
            || self.rg_path.as_os_str().is_empty()
        {
            return Err(invalid());
        }
        let valid_url = |s: &str| {
            url::Url::parse(s).ok().filter(|u| {
                (u.scheme() == "https"
                    || (u.scheme() == "http"
                        && matches!(u.host_str(), Some("localhost" | "127.0.0.1" | "::1"))))
                    && u.host_str().is_some()
                    && u.username().is_empty()
                    && u.password().is_none()
                    && u.query().is_none()
                    && u.fragment().is_none()
            })
        };
        if let Some(resource) = &self.resource_url {
            let Some(url) = valid_url(resource) else {
                return Err(invalid());
            };
            // Metadata is mounted as a literal route, never as an axum path capture.
            if url.path().contains(['{', '}']) {
                return Err(invalid());
            }
        }
        for origin in &self.allowed_origins {
            let Some(u) = valid_url(origin) else {
                return Err(invalid());
            };
            if u.origin().ascii_serialization() != *origin {
                return Err(invalid());
            }
        }
        if auth.mode == AuthMode::Oauth2 && (auth.oidc.is_none() || self.resource_url.is_none()) {
            return Err(invalid());
        }
        Ok(())
    }
}

#[derive(Clone)]
struct Endpoint {
    service: Arc<CallerService>,
}
#[derive(Clone)]
struct HttpState {
    service: Arc<CallerService>,
}

pub(crate) fn router(service: Arc<CallerService>, cancel: CancellationToken) -> Router {
    let handler = Endpoint {
        service: service.clone(),
    };
    let sdk: StreamableHttpService<Endpoint, LocalSessionManager> = StreamableHttpService::new(
        move || Ok(handler.clone()),
        Default::default(),
        StreamableHttpServerConfig::default()
            .with_legacy_session_mode(false)
            .with_json_response(true)
            .with_max_request_body_bytes(64 * 1024)
            .with_cancellation_token(cancel),
    );
    let state = HttpState {
        service: service.clone(),
    };
    let mut router = Router::new()
        .nest_service("/mcp", sdk)
        .layer(middleware::from_fn_with_state(state.clone(), guard));
    if service.config().auth.mode == AuthMode::Oauth2 {
        let path = url::Url::parse(
            service
                .config()
                .mcp
                .resource_url
                .as_deref()
                .expect("validated resource"),
        )
        .expect("validated resource")
        .path()
        .trim_end_matches('/')
        .to_owned();
        router = router.merge(
            Router::new()
                .route(
                    &format!("/.well-known/oauth-protected-resource{path}"),
                    get(metadata),
                )
                .with_state(state),
        );
    }
    router
}
async fn metadata(State(state): State<HttpState>) -> Json<Value> {
    let config = state.service.config();
    let oidc = config
        .auth
        .oidc
        .as_ref()
        .expect("validated OAuth configuration");
    Json(
        json!({"resource":config.mcp.resource_url, "authorization_servers":[oidc.issuer], "scopes_supported":[oidc.read_scope], "bearer_methods_supported":["header"]}),
    )
}
async fn guard(State(state): State<HttpState>, request: Request, next: Next) -> Response {
    let headers = request.headers();
    let origins = headers.get_all(header::ORIGIN);
    if origins.iter().count() > 1
        || origins.iter().next().is_some_and(|v| {
            v.to_str().ok().is_none_or(|v| {
                !state
                    .service
                    .config()
                    .mcp
                    .allowed_origins
                    .iter()
                    .any(|allowed| allowed == v)
            })
        })
    {
        return StatusCode::FORBIDDEN.into_response();
    }
    let token = match bearer(headers, state.service.config().auth.mode) {
        Ok(v) => v,
        Err(()) => return unauthorized(&state),
    };
    if let Err(error) = state.service.authorize(token, false, false).await {
        return match error.code.as_str() {
            "auth_invalid" => unauthorized(&state),
            "auth_forbidden" => challenge(&state, StatusCode::FORBIDDEN),
            _ => StatusCode::SERVICE_UNAVAILABLE.into_response(),
        };
    }
    next.run(request).await
}
fn unauthorized(state: &HttpState) -> Response {
    challenge(state, StatusCode::UNAUTHORIZED)
}
fn challenge(state: &HttpState, status: StatusCode) -> Response {
    let mut response = status.into_response();
    let resource = state
        .service
        .config()
        .mcp
        .resource_url
        .as_deref()
        .unwrap_or_default();
    let metadata = format!(
        "{}/.well-known/oauth-protected-resource{}",
        url::Url::parse(resource)
            .expect("validated resource")
            .origin()
            .ascii_serialization(),
        url::Url::parse(resource)
            .expect("validated resource")
            .path()
            .trim_end_matches('/')
    );
    let scope = &state
        .service
        .config()
        .auth
        .oidc
        .as_ref()
        .expect("validated OAuth configuration")
        .read_scope;
    let reason = if status == StatusCode::FORBIDDEN {
        ", error=\"insufficient_scope\""
    } else {
        ""
    };
    if let Ok(value) =
        format!("Bearer resource_metadata=\"{metadata}\", scope=\"{scope}\"{reason}").parse()
    {
        response
            .headers_mut()
            .insert(header::WWW_AUTHENTICATE, value);
    }
    response
}
fn bearer(
    headers: &axum::http::HeaderMap,
    mode: AuthMode,
) -> std::result::Result<Option<&str>, ()> {
    if mode != AuthMode::Oauth2 {
        return Ok(None);
    }
    let mut values = headers.get_all(header::AUTHORIZATION).iter();
    let value = values.next().ok_or(())?.to_str().map_err(|_| ())?;
    if values.next().is_some() {
        return Err(());
    }
    let mut parts = value.split_ascii_whitespace();
    match (parts.next(), parts.next(), parts.next()) {
        (Some(s), Some(v), None) if s.eq_ignore_ascii_case("bearer") => Ok(Some(v)),
        _ => Err(()),
    }
}

impl ServerHandler for Endpoint {
    fn get_info(&self) -> ServerConfig {
        ServerConfig::new(ServerCapabilities::builder().enable_tools().build())
    }
    fn supported_protocol_versions(&self) -> Cow<'static, [ProtocolVersion]> {
        Cow::Owned(vec![
            ProtocolVersion::V_2026_07_28,
            ProtocolVersion::V_2025_11_25,
        ])
    }
    async fn list_tools(
        &self,
        _: Option<PaginatedRequestParams>,
        _: RequestContext<RoleServer>,
    ) -> std::result::Result<ListToolsResult, ErrorData> {
        Ok(ListToolsResult::with_all_items(tools()))
    }
    async fn call_tool(
        &self,
        request: CallToolRequestParams,
        context: RequestContext<RoleServer>,
    ) -> std::result::Result<CallToolResponse, ErrorData> {
        let parts = context
            .extensions
            .get::<axum::http::request::Parts>()
            .ok_or_else(|| ErrorData::internal_error("request context unavailable", None))?;
        let token = bearer(&parts.headers, self.service.config().auth.mode)
            .map_err(|_| ErrorData::internal_error("request credentials unavailable", None))?;
        let args = Value::Object(request.arguments.unwrap_or_default());
        match self
            .service
            .call_tool(token, &request.name, args, &context.ct)
            .await
        {
            Ok(output) => {
                let text = output.text.unwrap_or_else(|| output.data.to_string());
                let mut result = CallToolResult::success(vec![ContentBlock::text(text)]);
                result.structured_content = Some(output.data);
                Ok(result.into())
            }
            Err(error) => {
                let data = serde_json::to_value(error).expect("serializable error");
                let mut result = CallToolResult::error(vec![ContentBlock::text(data.to_string())]);
                result.structured_content = Some(data);
                Ok(result.into())
            }
        }
    }
}
fn tools() -> Vec<Tool> {
    let selectors = json!({"type":"array","items":{"oneOf":[{"type":"object","properties":{"kind":{"const":"whole"}},"required":["kind"],"additionalProperties":false},{"type":"object","properties":{"kind":{"enum":["section","block"]},"id":{"type":"string"}},"required":["kind","id"],"additionalProperties":false},{"type":"object","properties":{"kind":{"const":"lines"},"start":{"type":"integer","minimum":1},"end":{"type":"integer","minimum":1}},"required":["kind","start","end"],"additionalProperties":false}]}});
    let defs = vec![
        (
            "list",
            "List documents, conversions, sections, or blocks",
            json!({"kind":{"enum":["documents","conversions","sections","blocks"]},"conversion_id":{"type":"string"},"document_id":{"type":"string"},"limit":{"type":"integer","minimum":1},"cursor":{"type":"string"}}),
            vec![],
        ),
        (
            "read",
            "Read whole unchanged converted Markdown, or return a size error",
            json!({"conversion_id":{"type":"string"}}),
            vec!["conversion_id"],
        ),
        (
            "read-page",
            "Read selected pages",
            json!({"conversion_id":{"type":"string"},"pages":{"type":"string"}}),
            vec!["conversion_id", "pages"],
        ),
        (
            "read-section",
            "Read exact Markdown sections or blocks selected by IDs from list, in request order",
            json!({"conversion_id":{"type":"string"},"selectors":{"type":"array","minItems":1,"maxItems":500,"uniqueItems":true,"items":{"type":"object","properties":{"kind":{"enum":["section","block"]},"id":{"type":"string"}},"required":["kind","id"],"additionalProperties":false}}}),
            vec!["conversion_id", "selectors"],
        ),
        (
            "table",
            "Read embedded PDF outline and bookmarks as a Markdown table of contents",
            json!({"conversion_id":{"type":"string"}}),
            vec!["conversion_id"],
        ),
        (
            "rg",
            "Search converted Markdown",
            json!({"pattern":{"type":"string"},"conversion_ids":{"type":"array","items":{"type":"string"}},"case":{"enum":["sensitive","insensitive","smart"]},"literal":{"type":"boolean"},"word":{"type":"boolean"},"context":{"type":"integer","minimum":0},"limit":{"type":"integer","minimum":1},"cursor":{"type":"string"}}),
            vec!["pattern"],
        ),
        (
            "count",
            "Count logical Markdown source lines in selections",
            json!({"conversion_id":{"type":"string"},"selectors":selectors}),
            vec!["conversion_id"],
        ),
        (
            "size",
            "Measure selection sizes in UTF-8 bytes",
            json!({"conversion_id":{"type":"string"},"selectors":selectors}),
            vec!["conversion_id"],
        ),
    ];
    defs.into_iter().map(|(name, desc, props, required)| { let schema = json!({"type":"object","properties":props,"required":required,"additionalProperties":false}); Tool::new(name, desc, schema.as_object().unwrap().clone()).with_annotations(ToolAnnotations::new().read_only(true)) }).collect()
}
