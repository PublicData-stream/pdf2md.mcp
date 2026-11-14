//! Stateless, read-only MCP interface to the authorized caller service.
use std::{borrow::Cow, path::PathBuf, sync::Arc};

use crate::{
    auth::{AuthConfig, AuthMode},
    error::{LoadError, Result},
    http::caller::{self, Presented, Scheme},
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
    /// Additional `Host` values accepted by `/mcp`, beyond loopback names and
    /// the authority of `resource_url`.
    pub allowed_hosts: Vec<String>,
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
            allowed_hosts: vec![],
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
        for host in &self.allowed_hosts {
            if HostRule::parse(host).is_none() {
                return Err(invalid());
            }
        }
        if auth.mode == AuthMode::Oauth2 {
            let (Some(oidc), Some(resource)) = (&auth.oidc, &self.resource_url) else {
                return Err(invalid());
            };
            // Clients request tokens for the advertised resource (RFC 8707),
            // so the validator must accept exactly that audience.
            if !oidc.accepts_audience(resource) {
                return Err(invalid());
            }
        }
        Ok(())
    }
    /// `Host` values accepted by `/mcp`: loopback names, the authority of
    /// `resource_url`, and `allowed_hosts`. Requests naming any other host
    /// are refused, which blocks DNS rebinding against the endpoint.
    fn host_rules(&self) -> Vec<HostRule> {
        let mut rules: Vec<HostRule> = ["localhost", "127.0.0.1", "[::1]"]
            .into_iter()
            .filter_map(HostRule::parse)
            .collect();
        if let Some(url) = self
            .resource_url
            .as_deref()
            .and_then(|s| url::Url::parse(s).ok())
            && let Some(host) = url.host_str()
        {
            rules.push(HostRule {
                host: normalize_host(host),
                port: url.port(),
            });
        }
        rules.extend(self.allowed_hosts.iter().filter_map(|s| HostRule::parse(s)));
        rules.dedup();
        rules
    }
}

/// A host name or IP literal, with an optional port. Without a port, any port
/// matches.
#[derive(Debug, Clone, PartialEq, Eq)]
struct HostRule {
    host: String,
    port: Option<u16>,
}
impl HostRule {
    fn parse(value: &str) -> Option<Self> {
        if value.is_empty() || value.contains(['@', '*', '/', '?', '#']) {
            return None;
        }
        let authority = axum::http::uri::Authority::try_from(value).ok()?;
        let host = authority.host();
        let bare = host.strip_prefix('[').and_then(|h| h.strip_suffix(']'));
        // IPv6 literals need brackets; other names must be valid URL hosts.
        match bare {
            Some(ip) => {
                ip.parse::<std::net::Ipv6Addr>().ok()?;
            }
            None => {
                if host.contains(':') {
                    return None;
                }
                url::Host::parse(host).ok()?;
            }
        }
        let rule = Self::from_authority(&authority)?;
        rule.port.is_none_or(|p| p != 0).then_some(rule)
    }
    /// Rejects authorities whose port does not fit in `u16`; the parser
    /// otherwise drops such a port silently.
    fn from_authority(authority: &axum::http::uri::Authority) -> Option<Self> {
        let port = authority.port_u16();
        let expected = match port {
            Some(port) => format!("{}:{port}", authority.host()),
            None => authority.host().to_owned(),
        };
        authority
            .as_str()
            .eq_ignore_ascii_case(&expected)
            .then(|| Self {
                host: normalize_host(authority.host()),
                port,
            })
    }
    fn matches(&self, request: &Self) -> bool {
        self.host == request.host && self.port.is_none_or(|p| request.port == Some(p))
    }
    /// The same rule in the form the MCP SDK's own Host check accepts.
    fn to_authority(&self) -> String {
        let host = if self.host.contains(':') {
            format!("[{}]", self.host)
        } else {
            self.host.clone()
        };
        match self.port {
            Some(port) => format!("{host}:{port}"),
            None => host,
        }
    }
}
fn normalize_host(host: &str) -> String {
    host.trim_start_matches('[')
        .trim_end_matches(']')
        .to_ascii_lowercase()
}
/// Reads the request authority from `Host`, or from the URI for HTTP/2.
fn request_host(request: &Request) -> std::result::Result<HostRule, StatusCode> {
    let mut values = request.headers().get_all(header::HOST).iter();
    let authority = match (values.next(), values.next()) {
        (Some(_), Some(_)) => return Err(StatusCode::BAD_REQUEST),
        (Some(value), None) => value
            .to_str()
            .ok()
            .and_then(|v| axum::http::uri::Authority::try_from(v).ok())
            .ok_or(StatusCode::BAD_REQUEST)?,
        (None, _) => request
            .uri()
            .authority()
            .cloned()
            .ok_or(StatusCode::BAD_REQUEST)?,
    };
    HostRule::from_authority(&authority).ok_or(StatusCode::BAD_REQUEST)
}

#[derive(Clone)]
struct Endpoint {
    service: Arc<CallerService>,
}
#[derive(Clone)]
struct HttpState {
    service: Arc<CallerService>,
    hosts: Arc<[HostRule]>,
}

pub(crate) fn router(service: Arc<CallerService>, cancel: CancellationToken) -> Router {
    let handler = Endpoint {
        service: service.clone(),
    };
    let hosts: Arc<[HostRule]> = service.config().mcp.host_rules().into();
    let sdk: StreamableHttpService<Endpoint, LocalSessionManager> = StreamableHttpService::new(
        move || Ok(handler.clone()),
        Default::default(),
        StreamableHttpServerConfig::default()
            .with_legacy_session_mode(false)
            .with_json_response(true)
            .with_max_request_body_bytes(64 * 1024)
            .with_allowed_hosts(hosts.iter().map(HostRule::to_authority))
            .with_cancellation_token(cancel),
    );
    let state = HttpState {
        service: service.clone(),
        hosts,
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
                    get(metadata).options(metadata_preflight),
                )
                .with_state(state),
        );
    }
    router
}
/// Protected-resource metadata is public and credential-free, so any origin
/// may read it; browser-based clients need that to start authorization.
async fn metadata(State(state): State<HttpState>) -> Response {
    let config = state.service.config();
    let oidc = config
        .auth
        .oidc
        .as_ref()
        .expect("validated OAuth configuration");
    let mut document = json!({"resource":config.mcp.resource_url, "authorization_servers":[oidc.issuer], "scopes_supported":[oidc.read_scope], "bearer_methods_supported":["header"]});
    // RFC 9728 section 2: advertise DPoP support and whether it is mandatory.
    if let Some(dpop) = &oidc.dpop {
        document["dpop_signing_alg_values_supported"] = json!(crate::dpop::SIGNING_ALGORITHMS);
        document["dpop_bound_access_tokens_required"] = json!(dpop.required);
    }
    ([(header::ACCESS_CONTROL_ALLOW_ORIGIN, "*")], Json(document)).into_response()
}
async fn metadata_preflight() -> Response {
    (
        StatusCode::NO_CONTENT,
        [
            (header::ACCESS_CONTROL_ALLOW_ORIGIN, "*"),
            (header::ACCESS_CONTROL_ALLOW_METHODS, "GET"),
            (header::ACCESS_CONTROL_ALLOW_HEADERS, "mcp-protocol-version"),
            (header::ACCESS_CONTROL_MAX_AGE, "86400"),
        ],
    )
        .into_response()
}
async fn guard(State(state): State<HttpState>, mut request: Request, next: Next) -> Response {
    // Check Host before any credential work (MCP Streamable HTTP security
    // guidance on DNS rebinding).
    match request_host(&request) {
        Ok(host) if state.hosts.iter().any(|rule| rule.matches(&host)) => {}
        Ok(_) => return StatusCode::FORBIDDEN.into_response(),
        Err(status) => return status.into_response(),
    }
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
    // RFC 6750 section 3.1: name an error only for the scheme that was used.
    let scheme = caller::scheme(headers);
    let reject = |error: LoadError| match error.code.as_str() {
        "auth_invalid" => challenge(&state, StatusCode::UNAUTHORIZED, scheme, false),
        "auth_dpop_invalid" => challenge(&state, StatusCode::UNAUTHORIZED, scheme, true),
        "auth_forbidden" => challenge(&state, StatusCode::FORBIDDEN, scheme, false),
        _ => StatusCode::SERVICE_UNAVAILABLE.into_response(),
    };
    let presented = match Presented::read(
        &state.service,
        request.method(),
        request.uri().path(),
        headers,
    ) {
        Ok(presented) => presented,
        Err(error) => return reject(error),
    };
    if let Err(error) = state
        .service
        .authorize(presented.credentials(), false, false)
        .await
    {
        return reject(error);
    }
    // Tool calls reuse the verified credentials: a DPoP proof is single use.
    request.extensions_mut().insert(presented);
    next.run(request).await
}
fn challenge(
    state: &HttpState,
    status: StatusCode,
    presented: Option<Scheme>,
    proof: bool,
) -> Response {
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
    let parameters = format!("resource_metadata=\"{metadata}\", scope=\"{scope}\"");
    for value in caller::challenges(&state.service, status, presented, proof, &parameters) {
        response
            .headers_mut()
            .append(header::WWW_AUTHENTICATE, value);
    }
    response
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
        let presented = parts
            .extensions
            .get::<Presented>()
            .ok_or_else(|| ErrorData::internal_error("request credentials unavailable", None))?;
        let args = Value::Object(request.arguments.unwrap_or_default());
        match self
            .service
            .call_tool(presented.credentials(), &request.name, args, &context.ct)
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
