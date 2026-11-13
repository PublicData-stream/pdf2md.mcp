//! Access-token credentials of one HTTP request.
//!
//! RFC 6750 Bearer and RFC 9449 DPoP presentations are read from the
//! `Authorization` header only. For the DPoP scheme the request's proof is
//! verified here, once per request.
use crate::{
    auth::{AuthMode, Credentials},
    dpop::{ProvenKey, SIGNING_ALGORITHMS, invalid_proof},
    error::LoadError,
    service::CallerService,
};
use axum::http::{HeaderMap, HeaderValue, Method, StatusCode, header};
use std::sync::Arc;

fn invalid() -> LoadError {
    LoadError::new(
        "auth_invalid",
        "valid access-token credentials are required",
    )
}

/// The authentication scheme a request used.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum Scheme {
    Bearer,
    Dpop,
}

/// Scheme of the request's `Authorization` header, without validating it.
pub(crate) fn scheme(headers: &HeaderMap) -> Option<Scheme> {
    let scheme = headers
        .get(header::AUTHORIZATION)?
        .to_str()
        .ok()?
        .split_ascii_whitespace()
        .next()?;
    if scheme.eq_ignore_ascii_case("bearer") {
        Some(Scheme::Bearer)
    } else if scheme.eq_ignore_ascii_case("dpop") {
        Some(Scheme::Dpop)
    } else {
        None
    }
}

/// What a request presented. Cloning shares the verified proof, so that the
/// proof counts as used once however many operations the request authorizes.
#[derive(Clone, Default)]
pub(crate) struct Presented {
    token: Option<String>,
    proven: Option<Arc<ProvenKey>>,
}
impl Presented {
    /// Read the credentials of a request to `path`. Anonymous modes ignore
    /// the header.
    pub(crate) fn read(
        service: &CallerService,
        method: &Method,
        path: &str,
        headers: &HeaderMap,
    ) -> Result<Self, LoadError> {
        if service.config().auth.mode != AuthMode::Oauth2 {
            return Ok(Self::default());
        }
        let mut values = headers.get_all(header::AUTHORIZATION).iter();
        let Some(value) = values.next() else {
            return Ok(Self::default());
        };
        if values.next().is_some() {
            return Err(invalid());
        }
        let mut parts = value
            .to_str()
            .map_err(|_| invalid())?
            .split_ascii_whitespace();
        let (Some(scheme), Some(token), None) = (parts.next(), parts.next(), parts.next()) else {
            return Err(invalid());
        };
        if scheme.eq_ignore_ascii_case("bearer") {
            return Ok(Self {
                token: Some(token.to_owned()),
                proven: None,
            });
        }
        if !scheme.eq_ignore_ascii_case("dpop") {
            return Err(invalid());
        }
        // RFC 9449 section 4.3 item 1: exactly one DPoP header field.
        let mut proofs = headers.get_all("dpop").iter();
        let (Some(proof), None) = (proofs.next(), proofs.next()) else {
            return Err(invalid_proof());
        };
        let proof = proof.to_str().map_err(|_| invalid_proof())?;
        let key = service.verify_dpop(proof, method.as_str(), path, token)?;
        Ok(Self {
            token: Some(token.to_owned()),
            proven: Some(Arc::new(key)),
        })
    }

    pub(crate) fn credentials(&self) -> Credentials<'_> {
        match (&self.token, &self.proven) {
            (Some(token), Some(key)) => Credentials::dpop(token, key),
            (token, _) => Credentials::bearer(token.as_deref()),
        }
    }
}

/// `WWW-Authenticate` challenges for a 401 or 403 response (RFC 6750
/// section 3, RFC 9449 section 7.1). `parameters` are appended to every
/// challenge, for example `resource_metadata`. The scheme the request used
/// carries the error code; `proof` marks a rejected DPoP proof.
pub(crate) fn challenges(
    service: &CallerService,
    status: StatusCode,
    presented: Option<Scheme>,
    proof: bool,
    parameters: &str,
) -> Vec<HeaderValue> {
    let dpop = service
        .config()
        .auth
        .oidc
        .as_ref()
        .and_then(|oidc| oidc.dpop.as_ref());
    let error = |scheme: Scheme| match status {
        StatusCode::FORBIDDEN if presented == Some(scheme) => "insufficient_scope",
        StatusCode::UNAUTHORIZED if presented == Some(scheme) && proof => "invalid_dpop_proof",
        StatusCode::UNAUTHORIZED if presented == Some(scheme) => "invalid_token",
        _ => "",
    };
    let build = |name: &str, mut items: Vec<String>, scheme: Scheme| {
        // A 403 answers the presented credentials only.
        if status == StatusCode::FORBIDDEN && presented != Some(scheme) {
            return None;
        }
        if !parameters.is_empty() {
            items.push(parameters.to_owned());
        }
        if !error(scheme).is_empty() {
            items.push(format!("error=\"{}\"", error(scheme)));
        }
        let value = if items.is_empty() {
            name.to_owned()
        } else {
            format!("{name} {}", items.join(", "))
        };
        value.parse().ok()
    };
    let mut values = Vec::new();
    if !dpop.is_some_and(|dpop| dpop.required) {
        values.extend(build("Bearer", vec![], Scheme::Bearer));
    }
    if dpop.is_some() {
        let algorithms = format!("algs=\"{}\"", SIGNING_ALGORITHMS.join(" "));
        values.extend(build("DPoP", vec![algorithms], Scheme::Dpop));
    }
    values
}
