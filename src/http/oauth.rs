//! Browser sign-in routes for the optional registered OAuth client.
//!
//! Only the interactive Authorization Code grant (with PKCE) is served over
//! HTTP, and the result page shows an access token only. Refresh tokens are never returned, and no
//! route accepts a caller-supplied grant (device code or refresh token) to
//! redeem with the registered client's credentials: those grants run from the
//! trusted CLI, or directly between the caller's own client and the provider.
//!
//! Pages share `/oauth/oauth.css` and `/oauth/page.js` and render without
//! inline scripts or styles. Responses are `no-store` and use the service's
//! restrictive content security policy and `no-referrer` policy. Browser
//! navigations (`Accept: text/html`) to `/oauth/login` and `/oauth/callback`
//! receive an HTML error page; other clients keep the JSON error body.
use super::{ApiError, BrowserPage, invalid};
use crate::oauth::{GrantType, OAuthClient, TokenResponse, authorization_error};
use axum::{
    Router,
    extract::{Query, State},
    http::{HeaderMap, HeaderValue, header},
    response::{Html, IntoResponse, Redirect, Response},
    routing::get,
};
use serde::Deserialize;
use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

const PENDING_TTL: Duration = Duration::from_secs(600);
/// Pending Authorization Code sign-ins kept in memory. When the table is
/// full the oldest entry is replaced, so unauthenticated requests to
/// `/oauth/login` cannot lock other users out until entries expire.
const MAX_PENDING: usize = 8192;
const CODE_COOKIE: &str = "pdf2md_oauth_state";

#[derive(Clone)]
struct OAuthState {
    client: Arc<OAuthClient>,
    /// Authorization Code state -> PKCE verifier, bound to a browser cookie.
    pending: Arc<Mutex<HashMap<String, (String, Instant)>>>,
}

/// Routes exist only when the Authorization Code grant is enabled.
pub(super) fn router(client: Arc<OAuthClient>) -> Router {
    if !client.enabled(GrantType::AuthorizationCode) {
        return Router::new();
    }
    Router::new()
        .route("/oauth/login", get(login))
        .route("/oauth/callback", get(callback))
        .route("/oauth/oauth.css", get(page_css))
        .route("/oauth/page.js", get(page_js))
        .with_state(OAuthState {
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

/// The `state` cookie that binds a sign-in to this browser. It is never
/// readable by scripts.
fn state_cookie(value: &str, secure: bool, max_age: u64) -> HeaderValue {
    let mut cookie =
        format!("{CODE_COOKIE}={value}; Path=/oauth; Max-Age={max_age}; SameSite=Lax; HttpOnly");
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

/// Start the Authorization Code grant with PKCE.
async fn login(State(state): State<OAuthState>, headers: HeaderMap) -> Response {
    let result = start_login(&state).await;
    browser_result(&headers, result)
}

async fn start_login(state: &OAuthState) -> Result<Response, ApiError> {
    let request = state.client.authorization_request().await?;
    {
        let mut pending = state.pending.lock().unwrap_or_else(|e| e.into_inner());
        insert_pending(&mut pending, request.state.clone(), request.code_verifier);
    }
    let mut response = Redirect::to(request.url.as_str()).into_response();
    response.headers_mut().insert(
        header::SET_COOKIE,
        state_cookie(
            &request.state,
            state.client.secure_redirects(),
            PENDING_TTL.as_secs(),
        ),
    );
    Ok(response)
}

/// Record a pending sign-in, dropping expired entries and, at capacity, the
/// oldest one.
fn insert_pending(
    pending: &mut HashMap<String, (String, Instant)>,
    state: String,
    verifier: String,
) {
    pending.retain(|_, (_, created)| created.elapsed() < PENDING_TTL);
    while pending.len() >= MAX_PENDING {
        let Some(oldest) = pending
            .iter()
            .min_by_key(|(_, (_, created))| *created)
            .map(|(state, _)| state.clone())
        else {
            break;
        };
        pending.remove(&oldest);
    }
    pending.insert(state, (verifier, Instant::now()));
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
    browser_result(&headers, result)
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
    let mut response = token_page(&tokens).into_response();
    response.headers_mut().insert(
        header::SET_COOKIE,
        state_cookie("", state.client.secure_redirects(), 0),
    );
    Ok(response)
}

const CODE_FLOW: &str = "Authorization Code · PKCE";

/// Status of a page, which selects the header icon and colors.
#[derive(Clone, Copy)]
enum PageState {
    Success,
    Error,
}

impl PageState {
    fn as_str(self) -> &'static str {
        match self {
            Self::Success => "success",
            Self::Error => "error",
        }
    }
}

/// One OAuth browser page. `body` must already be escaped; `title` and
/// `message` are escaped here.
struct Page<'a> {
    state: PageState,
    title: &'a str,
    message: &'a str,
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
            "<!doctype html>\n<html lang=\"en\"><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\"><meta name=\"robots\" content=\"noindex\"><meta name=\"color-scheme\" content=\"dark\"><title>{title} · pdf2md</title><link rel=\"stylesheet\" href=\"/oauth/oauth.css\"></head><body><header class=\"brand\"><span class=\"mark\" aria-hidden=\"true\">P</span><strong>pdf2md</strong><span>Sign-in</span></header><main id=\"page\" data-state=\"{state}\"><span class=\"flow\">{flow}</span><div class=\"status\"><span class=\"icon\" aria-hidden=\"true\"></span><div><h1 id=\"title\">{title}</h1><p id=\"status\" aria-live=\"polite\">{message}</p></div></div>{body}</main><footer>This page is never cached. Close it when you are done.</footer>{scripts}</body></html>\n",
            title = escape(self.title),
            state = self.state.as_str(),
            flow = escape(CODE_FLOW),
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

const TOKEN_NOTE: &str = "<p class=\"note\"><strong>Treat this token like a password.</strong> pdf2md does not keep it, so copy it now. Do not paste it into chats, tickets or shared documents.</p>";

const USAGE: &str = "<div class=\"usage\"><p>Send the access token as a Bearer credential:</p><pre>Authorization: Bearer &lt;access token&gt;</pre><p>Sign in again when it expires. Refresh tokens are not shown here.</p></div>";

/// Page actions. After a successful sign-in the API console comes first;
/// after a failure, starting again does.
fn actions(signed_in: bool) -> &'static str {
    if signed_in {
        "<nav class=\"actions\"><a class=\"button\" href=\"/docs\">Open API console</a><a class=\"button secondary\" href=\"/oauth/login\">Sign in again</a></nav>"
    } else {
        "<nav class=\"actions\"><a class=\"button\" href=\"/oauth/login\">Start sign-in again</a><a class=\"button secondary\" href=\"/docs\">Open API console</a></nav>"
    }
}

/// Authorization Code result page. Only the access token is displayed: ID
/// tokens are not credentials for this service, and a refresh token issued to
/// the registered client stays out of the browser.
fn token_page(tokens: &TokenResponse) -> Html<String> {
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
    body.push_str(TOKEN_NOTE);
    body.push_str(USAGE);
    body.push_str(actions(true));
    Html(
        Page {
            state: PageState::Success,
            title: "Signed in",
            message: "Your access token is ready. Copy it before you close this page.",
            body,
            scripts: &["/oauth/page.js"],
        }
        .render(),
    )
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
        _ => ("Sign-in failed", None),
    }
}

/// Render `error` as an HTML page with the JSON response's status, request ID
/// and retry headers.
fn error_page(error: ApiError) -> Response {
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
        actions(false),
    );
    let page = Page {
        state: PageState::Error,
        title,
        message: explanation.unwrap_or(&message),
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
fn browser_result(headers: &HeaderMap, result: Result<Response, ApiError>) -> Response {
    match result {
        Ok(response) => response,
        Err(error) if wants_html(headers) => error_page(error),
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn full_pending_table_replaces_the_oldest_sign_in() {
        let mut pending = HashMap::new();
        let earlier = Instant::now() - Duration::from_secs(1);
        pending.insert("oldest".to_owned(), ("verifier".to_owned(), earlier));
        for index in 1..MAX_PENDING {
            insert_pending(&mut pending, format!("state-{index}"), "verifier".into());
        }
        assert_eq!(pending.len(), MAX_PENDING);
        assert!(pending.contains_key("oldest"));
        insert_pending(&mut pending, "newest".into(), "verifier".into());
        assert_eq!(pending.len(), MAX_PENDING);
        assert!(pending.contains_key("newest"));
        assert!(!pending.contains_key("oldest"));
    }
}
