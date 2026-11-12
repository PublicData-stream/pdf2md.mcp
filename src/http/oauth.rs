//! Browser and token-broker routes for the optional registered OAuth client.
//!
//! Pages use minimal functional markup. Responses are `no-store` and use the
//! service's restrictive content security policy and `no-referrer` policy.
use super::{ApiError, ApiJson, invalid};
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
        router = router.route("/oauth/login", get(login));
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
    Query(query): Query<LoginQuery>,
) -> Result<Response, ApiError> {
    let grant = query.grant.unwrap_or(GrantType::AuthorizationCode);
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
) -> Result<Response, ApiError> {
    let returned = query
        .state
        .as_deref()
        .ok_or_else(|| invalid("oauth_state_mismatch", "unknown or expired sign-in"))?;
    // The state must match this browser's cookie, preventing login CSRF and
    // code injection into another user agent's session.
    if cookie_value(&headers, CODE_COOKIE) != Some(returned) {
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
    let mut response = token_page("Authorization Code", &tokens).into_response();
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

fn token_page(flow: &str, tokens: &TokenResponse) -> Html<String> {
    let refresh = tokens
        .refresh_token
        .as_deref()
        .map(|value| {
            format!(
                "<label>Refresh token <textarea id=\"refresh-token\" readonly rows=\"3\">{}</textarea></label>",
                escape(value)
            )
        })
        .unwrap_or_default();
    Html(format!(
        "<!doctype html>\n<html lang=\"en\"><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\"><title>pdf2md sign-in</title></head><body><main><h1>Signed in</h1><p>Grant: {flow}. Token type: {}. Expires in: {} seconds. Scope: {}.</p><label>Access token <textarea id=\"access-token\" readonly rows=\"6\">{}</textarea></label>{refresh}<p>Send the access token as a Bearer credential. <a href=\"/docs\">API console</a></p></main></body></html>\n",
        escape(&tokens.token_type),
        tokens
            .expires_in
            .map(|v| v.to_string())
            .unwrap_or_else(|| "unknown".into()),
        escape(tokens.scope.as_deref().unwrap_or("")),
        escape(&tokens.access_token),
    ))
}

/// Implicit redirect page. The access token stays in the URL fragment and is
/// read by the page script; the server never receives it.
async fn implicit_page(State(state): State<OAuthState>) -> Result<Html<String>, ApiError> {
    let require_iss = state.client.check_response_issuer(None).await.is_err();
    Ok(Html(format!(
        "<!doctype html>\n<html lang=\"en\"><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\"><meta name=\"pdf2md-issuer\" content=\"{}\"><meta name=\"pdf2md-require-iss\" content=\"{require_iss}\"><title>pdf2md sign-in</title></head><body><main><h1>Implicit sign-in</h1><p id=\"status\" aria-live=\"polite\">Reading the authorization response.</p><label>Access token <textarea id=\"access-token\" readonly rows=\"6\"></textarea></label><p><a href=\"/oauth/login?grant=implicit\">Sign in again</a> · <a href=\"/docs\">API console</a></p></main><script src=\"/oauth/implicit.js\"></script></body></html>\n",
        escape(state.client.issuer()),
    )))
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
