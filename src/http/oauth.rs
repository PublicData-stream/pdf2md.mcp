//! Browser and token-broker routes for the optional registered OAuth client.
//!
//! Pages share `/oauth/oauth.css` and `/oauth/page.js` and render without
//! inline scripts or styles. Responses are `no-store` and use the service's
//! restrictive content security policy and `no-referrer` policy. Browser
//! navigations (`Accept: text/html`) to `/oauth/login` and `/oauth/callback`
//! receive an HTML error page; other clients keep the JSON error body.
use super::{ApiError, ApiJson, BrowserPage, invalid};
use crate::{
    error::LoadError,
    oauth::{GrantType, OAuthClient, TokenResponse, authorization_error},
};
use axum::{
    Json, Router,
    extract::{Query, State},
    http::{HeaderMap, HeaderValue, StatusCode, header},
    response::{Html, IntoResponse, Redirect, Response},
    routing::{get, post},
};
use serde::Deserialize;
use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

const PENDING_TTL: Duration = Duration::from_secs(600);
const MAX_PENDING: usize = 1024;
const CODE_COOKIE: &str = "pdf2md_oauth_state";
const IMPLICIT_COOKIE: &str = "pdf2md_implicit_state";
const DEVICE_CODE_GRANT: &str = "urn:ietf:params:oauth:grant-type:device_code";

#[derive(Clone)]
struct OAuthState {
    client: Arc<OAuthClient>,
    /// Authorization Code state -> PKCE verifier, bound to a browser cookie.
    pending: Arc<Mutex<HashMap<String, (String, Instant)>>>,
}

pub(super) fn router(client: Arc<OAuthClient>) -> Router {
    let mut router = Router::new();
    if client.enabled(GrantType::AuthorizationCode) || client.enabled(GrantType::Implicit) {
        router = router
            .route("/oauth/login", get(login))
            .route("/oauth/oauth.css", get(page_css))
            .route("/oauth/page.js", get(page_js));
    }
    if client.enabled(GrantType::AuthorizationCode) {
        router = router.route("/oauth/callback", get(callback));
    }
    if client.enabled(GrantType::Implicit) {
        router = router
            .route("/oauth/implicit", get(implicit_page))
            .route("/oauth/implicit.js", get(implicit_js));
    }
    if client.enabled(GrantType::DeviceCode) {
        router = router.route("/oauth/device", post(device));
    }
    if client.enabled(GrantType::DeviceCode) || client.enabled(GrantType::RefreshToken) {
        router = router.route("/oauth/token", post(token));
    }
    router.with_state(OAuthState {
        client,
        pending: Arc::new(Mutex::new(HashMap::new())),
    })
}

fn escape(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

fn cookie(
    name: &str,
    value: &str,
    path: &str,
    http_only: bool,
    secure: bool,
    max_age: u64,
) -> HeaderValue {
    let mut cookie = format!("{name}={value}; Path={path}; Max-Age={max_age}; SameSite=Lax");
    if http_only {
        cookie.push_str("; HttpOnly");
    }
    if secure {
        cookie.push_str("; Secure");
    }
    HeaderValue::from_str(&cookie).expect("cookie header")
}

fn cookie_value<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    headers
        .get_all(header::COOKIE)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(';'))
        .filter_map(|item| item.trim().split_once('='))
        .find(|(key, _)| *key == name)
        .map(|(_, value)| value)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct LoginQuery {
    grant: Option<GrantType>,
}

/// Start a browser grant: Authorization Code with PKCE (default) or Implicit.
async fn login(
    State(state): State<OAuthState>,
    headers: HeaderMap,
    Query(query): Query<LoginQuery>,
) -> Response {
    let grant = query.grant.unwrap_or(GrantType::AuthorizationCode);
    let result = start_login(&state, grant).await;
    browser_result(&headers, grant, result)
}

async fn start_login(state: &OAuthState, grant: GrantType) -> Result<Response, ApiError> {
    if !matches!(grant, GrantType::AuthorizationCode | GrantType::Implicit) {
        return Err(invalid("invalid_request", "unsupported browser grant"));
    }
    let request = state.client.authorization_request(grant).await?;
    let secure = state.client.secure_redirects();
    let set_cookie = if let Some(verifier) = request.code_verifier {
        let mut pending = state.pending.lock().unwrap_or_else(|e| e.into_inner());
        pending.retain(|_, (_, created)| created.elapsed() < PENDING_TTL);
        if pending.len() >= MAX_PENDING {
            return Err(LoadError::transient("service_busy", "too many pending sign-ins").into());
        }
        pending.insert(request.state.clone(), (verifier, Instant::now()));
        cookie(
            CODE_COOKIE,
            &request.state,
            "/oauth",
            true,
            secure,
            PENDING_TTL.as_secs(),
        )
    } else {
        cookie(
            IMPLICIT_COOKIE,
            &request.state,
            "/oauth/implicit",
            false,
            secure,
            PENDING_TTL.as_secs(),
        )
    };
    let mut response = Redirect::to(request.url.as_str()).into_response();
    response
        .headers_mut()
        .insert(header::SET_COOKIE, set_cookie);
    Ok(response)
}

#[derive(Deserialize)]
struct CallbackQuery {
    code: Option<String>,
    state: Option<String>,
    iss: Option<String>,
    error: Option<String>,
}

/// Authorization Code redirect endpoint: verify state, issuer and the
/// browser binding, then redeem the code with its PKCE verifier.
async fn callback(
    State(state): State<OAuthState>,
    headers: HeaderMap,
    Query(query): Query<CallbackQuery>,
) -> Response {
    let result = finish_code(&state, &headers, query).await;
    browser_result(&headers, GrantType::AuthorizationCode, result)
}

async fn finish_code(
    state: &OAuthState,
    headers: &HeaderMap,
    query: CallbackQuery,
) -> Result<Response, ApiError> {
    let returned = query
        .state
        .as_deref()
        .ok_or_else(|| invalid("oauth_state_mismatch", "unknown or expired sign-in"))?;
    // The state must match this browser's cookie, preventing login CSRF and
    // code injection into another user agent's session.
    if cookie_value(headers, CODE_COOKIE) != Some(returned) {
        return Err(invalid(
            "oauth_state_mismatch",
            "unknown or expired sign-in",
        ));
    }
    let verifier = {
        let mut pending = state.pending.lock().unwrap_or_else(|e| e.into_inner());
        pending.retain(|_, (_, created)| created.elapsed() < PENDING_TTL);
        pending.remove(returned)
    }
    .map(|(verifier, _)| verifier)
    .ok_or_else(|| invalid("oauth_state_mismatch", "unknown or expired sign-in"))?;
    state
        .client
        .check_response_issuer(query.iss.as_deref())
        .await?;
    if let Some(error) = &query.error {
        return Err(authorization_error(error).into());
    }
    let code = query
        .code
        .as_deref()
        .ok_or_else(|| invalid("oauth_error", "missing authorization code"))?;
    let tokens = state.client.exchange_code(code, &verifier).await?;
    let refreshable = state.client.enabled(GrantType::RefreshToken);
    let mut response = token_page(&tokens, refreshable).into_response();
    response.headers_mut().insert(
        header::SET_COOKIE,
        cookie(
            CODE_COOKIE,
            "",
            "/oauth",
            true,
            state.client.secure_redirects(),
            0,
        ),
    );
    Ok(response)
}

const CODE_FLOW: &str = "Authorization Code · PKCE";
const IMPLICIT_FLOW: &str = "Implicit";

fn flow_label(grant: GrantType) -> &'static str {
    match grant {
        GrantType::Implicit => IMPLICIT_FLOW,
        _ => CODE_FLOW,
    }
}

fn login_href(grant: GrantType) -> &'static str {
    match grant {
        GrantType::Implicit => "/oauth/login?grant=implicit",
        _ => "/oauth/login",
    }
}

/// Status of a page, which selects the header icon and colors.
#[derive(Clone, Copy)]
enum PageState {
    Success,
    Pending,
    Error,
}

impl PageState {
    fn as_str(self) -> &'static str {
        match self {
            Self::Success => "success",
            Self::Pending => "pending",
            Self::Error => "error",
        }
    }
}

/// One OAuth browser page. Values in `head` and `body` must already be
/// escaped; `title` and `message` are escaped here.
struct Page<'a> {
    flow: &'a str,
    state: PageState,
    title: &'a str,
    message: &'a str,
    head: String,
    body: String,
    scripts: &'a [&'a str],
}

impl Page<'_> {
    fn render(&self) -> String {
        let scripts: String = self
            .scripts
            .iter()
            .map(|src| format!("<script src=\"{src}\"></script>"))
            .collect();
        format!(
            "<!doctype html>\n<html lang=\"en\"><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\"><meta name=\"robots\" content=\"noindex\"><meta name=\"color-scheme\" content=\"dark\">{head}<title>{title} · pdf2md</title><link rel=\"stylesheet\" href=\"/oauth/oauth.css\"></head><body><header class=\"brand\"><span class=\"mark\" aria-hidden=\"true\">P</span><strong>pdf2md</strong><span>Sign-in</span></header><main id=\"page\" data-state=\"{state}\"><span class=\"flow\">{flow}</span><div class=\"status\"><span class=\"icon\" aria-hidden=\"true\"></span><div><h1 id=\"title\">{title}</h1><p id=\"status\" aria-live=\"polite\">{message}</p></div></div>{body}</main><footer>This page is never cached. Close it when you are done.</footer>{scripts}</body></html>\n",
            head = self.head,
            title = escape(self.title),
            state = self.state.as_str(),
            flow = escape(self.flow),
            message = escape(self.message),
            body = self.body,
        )
    }
}

/// Human-readable lifetime, e.g. `1 hour (3600 s)`.
fn duration(seconds: Option<u64>) -> String {
    let Some(seconds) = seconds else {
        return "Unknown".into();
    };
    let plural = |n: u64, unit: &str| format!("{n} {unit}{}", if n == 1 { "" } else { "s" });
    let (hours, minutes) = (seconds / 3600, seconds % 3600 / 60);
    let mut parts = Vec::new();
    if hours > 0 {
        parts.push(plural(hours, "hour"));
    }
    if minutes > 0 {
        parts.push(plural(minutes, "minute"));
    }
    if parts.is_empty() {
        return plural(seconds, "second");
    }
    format!("{} ({seconds} s)", parts.join(" "))
}

fn scope_chips(scope: &str) -> String {
    let chips: String = scope
        .split_whitespace()
        .map(|item| format!("<span class=\"chip\">{}</span>", escape(item)))
        .collect();
    if chips.is_empty() {
        "<span class=\"none\">None granted</span>".into()
    } else {
        format!("<span class=\"chips\">{chips}</span>")
    }
}

fn token_field(id: &str, label: &str, hint: &str, rows: u8, value: &str) -> String {
    format!(
        "<div class=\"field\"><div class=\"field-head\"><label for=\"{id}\">{label}<small>{hint}</small></label><button type=\"button\" class=\"copy secondary\" data-copy=\"{id}\" hidden>Copy</button></div><textarea id=\"{id}\" readonly rows=\"{rows}\" spellcheck=\"false\">{}</textarea></div>",
        escape(value)
    )
}

const TOKEN_NOTE: &str = "<p class=\"note\"><strong>Treat these tokens like passwords.</strong> pdf2md does not keep them, so copy what you need now. Do not paste them into chats, tickets or shared documents.</p>";

fn usage(refresh: bool) -> String {
    let refresh = if refresh {
        "<p>Before the access token expires, exchange the refresh token at <code>POST /oauth/token</code> with <code>{\"grant_type\": \"refresh_token\", \"refresh_token\": \"...\"}</code> and keep the new refresh token it returns.</p>"
    } else {
        ""
    };
    format!(
        "<div class=\"usage\"><p>Send the access token as a Bearer credential:</p><pre>Authorization: Bearer &lt;access token&gt;</pre>{refresh}</div>"
    )
}

/// Page actions. After a successful sign-in the API console comes first;
/// after a failure, starting again does.
fn actions(grant: GrantType, signed_in: bool) -> String {
    let login = login_href(grant);
    if signed_in {
        format!(
            "<nav class=\"actions\"><a class=\"button\" href=\"/docs\">Open API console</a><a class=\"button secondary\" href=\"{login}\">Sign in again</a></nav>"
        )
    } else {
        format!(
            "<nav class=\"actions\"><a class=\"button\" href=\"{login}\">Start sign-in again</a><a class=\"button secondary\" href=\"/docs\">Open API console</a></nav>"
        )
    }
}

/// Authorization Code result page. ID tokens are never displayed.
fn token_page(tokens: &TokenResponse, refreshable: bool) -> Html<String> {
    let refresh = tokens.refresh_token.as_deref();
    let mut body = format!(
        "<dl class=\"details\"><dt>Token type</dt><dd>{}</dd><dt>Expires in</dt><dd>{}</dd><dt>Scope</dt><dd>{}</dd></dl>",
        escape(&tokens.token_type),
        duration(tokens.expires_in),
        scope_chips(tokens.scope.as_deref().unwrap_or("")),
    );
    body.push_str(&token_field(
        "access-token",
        "Access token",
        "Bearer credential for the API and MCP endpoint",
        6,
        &tokens.access_token,
    ));
    if let Some(refresh) = refresh {
        body.push_str(&token_field(
            "refresh-token",
            "Refresh token",
            "Obtains new access tokens",
            3,
            refresh,
        ));
    }
    body.push_str(TOKEN_NOTE);
    body.push_str(&usage(refreshable && refresh.is_some()));
    body.push_str(&actions(GrantType::AuthorizationCode, true));
    Html(
        Page {
            flow: CODE_FLOW,
            state: PageState::Success,
            title: "Signed in",
            message: "Your tokens are ready. Copy them before you close this page.",
            head: String::new(),
            body,
            scripts: &["/oauth/page.js"],
        }
        .render(),
    )
}

/// Implicit redirect page. The access token stays in the URL fragment and is
/// read by the page script; the server never receives it.
async fn implicit_page(State(state): State<OAuthState>) -> Result<Html<String>, ApiError> {
    let require_iss = state.client.check_response_issuer(None).await.is_err();
    let mut body = String::from(
        "<noscript><p class=\"note\"><strong>JavaScript is required.</strong> The Implicit grant returns the token to this page's script, so it cannot finish without JavaScript.</p></noscript><section id=\"result\" hidden><dl class=\"details\"><dt>Token type</dt><dd>Bearer</dd><dt>Expires in</dt><dd id=\"expires\">Unknown</dd><dt>Scope</dt><dd id=\"scope\"><span class=\"none\">None granted</span></dd></dl>",
    );
    body.push_str(&token_field(
        "access-token",
        "Access token",
        "Bearer credential for the API and MCP endpoint",
        6,
        "",
    ));
    body.push_str(TOKEN_NOTE);
    body.push_str(&usage(false));
    body.push_str("</section>");
    body.push_str(&actions(GrantType::Implicit, true));
    Ok(Html(
        Page {
            flow: IMPLICIT_FLOW,
            state: PageState::Pending,
            title: "Completing sign-in",
            message: "Checking the authorization response from your provider.",
            head: format!(
                "<meta name=\"pdf2md-issuer\" content=\"{}\"><meta name=\"pdf2md-require-iss\" content=\"{require_iss}\">",
                escape(state.client.issuer())
            ),
            body,
            scripts: &["/oauth/page.js", "/oauth/implicit.js"],
        }
        .render(),
    ))
}

/// Title and explanation for a sign-in failure. Messages are fixed public
/// text; provider error descriptions are never shown.
fn error_text(code: &str) -> (&'static str, Option<&'static str>) {
    match code {
        "oauth_state_mismatch" => (
            "Sign-in expired",
            Some(
                "This sign-in is unknown, was already used, is older than ten minutes, or was started in another browser. Start again.",
            ),
        ),
        "oauth_issuer_mismatch" => (
            "Unexpected provider response",
            Some(
                "The authorization response did not come from the configured provider, so it was rejected.",
            ),
        ),
        "oauth_access_denied" => (
            "Access denied",
            Some("Authorization was denied by you or the provider."),
        ),
        "oauth_grant_disabled" => ("Sign-in method unavailable", None),
        "service_busy" => (
            "Too many sign-ins in progress",
            Some("Wait a moment, then start again."),
        ),
        _ => ("Sign-in failed", None),
    }
}

/// Render `error` as an HTML page with the JSON response's status, request ID
/// and retry headers.
fn error_page(grant: GrantType, error: ApiError) -> Response {
    let code = error.0.code.clone();
    let message = error.0.message.clone();
    let json = error.into_response();
    let (title, explanation) = error_text(&code);
    let request_id = json
        .headers()
        .get("x-request-id")
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default()
        .to_owned();
    let body = format!(
        "<dl class=\"error-code\"><dt>Error code</dt><dd>{}</dd><dt>Request ID</dt><dd>{}</dd></dl>{}",
        escape(&code),
        escape(&request_id),
        actions(grant, false),
    );
    let page = Page {
        flow: flow_label(grant),
        state: PageState::Error,
        title,
        message: explanation.unwrap_or(&message),
        head: String::new(),
        body,
        scripts: &[],
    }
    .render();
    let mut response = (json.status(), Html(page)).into_response();
    for name in [
        header::HeaderName::from_static("x-request-id"),
        header::RETRY_AFTER,
    ] {
        if let Some(value) = json.headers().get(&name) {
            response.headers_mut().insert(name, value.clone());
        }
    }
    response.extensions_mut().insert(BrowserPage);
    response
}

fn wants_html(headers: &HeaderMap) -> bool {
    headers
        .get_all(header::ACCEPT)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .any(|value| value.contains("text/html"))
}

/// Browser navigations receive HTML errors; API clients keep JSON errors.
fn browser_result(
    headers: &HeaderMap,
    grant: GrantType,
    result: Result<Response, ApiError>,
) -> Response {
    match result {
        Ok(response) => response,
        Err(error) if wants_html(headers) => error_page(grant, error),
        Err(error) => error.into_response(),
    }
}

async fn page_css() -> impl IntoResponse {
    (
        [(header::CONTENT_TYPE, "text/css; charset=utf-8")],
        include_str!("oauth.css"),
    )
}

async fn page_js() -> impl IntoResponse {
    (
        [(
            header::CONTENT_TYPE,
            "application/javascript; charset=utf-8",
        )],
        include_str!("oauth-page.js"),
    )
}

async fn implicit_js() -> impl IntoResponse {
    (
        [(
            header::CONTENT_TYPE,
            "application/javascript; charset=utf-8",
        )],
        include_str!("oauth-implicit.js"),
    )
}

/// Start RFC 8628 device authorization for a CLI or device caller.
async fn device(State(state): State<OAuthState>) -> Result<Response, ApiError> {
    let device = state.client.device_authorization().await?;
    Ok((StatusCode::OK, Json(device)).into_response())
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct TokenInput {
    grant_type: String,
    device_code: Option<String>,
    refresh_token: Option<String>,
}

/// Token broker for device-code polling and refresh-token exchange with the
/// registered client's credentials. Authorization Code redemption happens only
/// through the callback, and Client Credentials is never brokered.
async fn token(
    State(state): State<OAuthState>,
    ApiJson(input): ApiJson<TokenInput>,
) -> Result<Response, ApiError> {
    let tokens = match (
        input.grant_type.as_str(),
        input.device_code.as_deref(),
        input.refresh_token.as_deref(),
    ) {
        (DEVICE_CODE_GRANT, Some(code), None) => state.client.poll_device(code).await?,
        ("refresh_token", None, Some(refresh)) => state.client.refresh(refresh).await?,
        _ => return Err(invalid("invalid_request", "unsupported token request")),
    };
    Ok((StatusCode::OK, Json(tokens)).into_response())
}
