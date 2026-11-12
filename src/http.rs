//! HTTP transport for the workspace-authorized caller service.
mod spec;

use crate::{auth::AuthMode, error::LoadError, service::CallerService};
use axum::{
    Json, Router,
    body::Body,
    extract::{DefaultBodyLimit, FromRequest, Multipart, Path, Query, Request, State},
    http::{HeaderMap, HeaderValue, StatusCode, header},
    middleware::{self, Next},
    response::{Html, IntoResponse, Response},
    routing::{get, post, put},
};
use futures_util::StreamExt;
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use serde_json::{Value, json};
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
use tokio::{
    io::{AsyncRead, AsyncWriteExt},
    sync::{OwnedSemaphorePermit, Semaphore},
};
use tokio_util::{io::ReaderStream, sync::CancellationToken};

const JSON_LIMIT: usize = 64 * 1024;

#[derive(Clone)]
struct App {
    service: Arc<CallerService>,
    cancel: CancellationToken,
    downloads: Arc<Semaphore>,
    ready: Arc<AtomicBool>,
}

/// Construct the HTTP router. Run `CallerService::run` alongside the listener.
pub fn router(service: Arc<CallerService>, cancel: CancellationToken) -> Router {
    let max = service
        .config()
        .limits
        .max_bytes
        .saturating_add(JSON_LIMIT as u64)
        .min(usize::MAX as u64) as usize;
    let app = App {
        downloads: Arc::new(Semaphore::new(service.config().http.downloads)),
        service,
        cancel,
        ready: Arc::new(AtomicBool::new(true)),
    };
    let mcp = app
        .service
        .config()
        .mcp
        .enabled
        .then(|| crate::mcp::router(app.service.clone(), app.cancel.clone()));
    let rest = Router::new()
        .route("/healthz", get(health))
        .route("/readyz", get(ready))
        .route("/openapi.json", get(openapi))
        .route("/docs", get(docs))
        .route("/docs.js", get(docs_js))
        .route("/docs.css", get(docs_css))
        .route("/v1/documents", post(upload))
        .route("/v1/documents/{id}/pdf", get(pdf))
        .route("/v1/documents/{id}/conversions", post(convert))
        .route("/v1/acquisitions", post(acquire))
        .route("/v1/sources", get(sources))
        .route("/v1/sources/{id}/fetch", post(fetch_source))
        .route("/v1/schedules", get(schedules))
        .route("/v1/schedules/{id}", put(set_schedule))
        .route("/v1/jobs", get(jobs))
        .route("/v1/jobs/{id}", get(job))
        .route("/v1/jobs/{id}/cancel", post(cancel_job))
        .route("/v1/jobs/{id}/retry", post(retry_job))
        .route("/v1/status", get(status))
        .route("/v1/history", get(history))
        .route("/v1/conversions", get(conversions))
        .route("/v1/conversions/{id}/manifest", get(manifest))
        .route("/v1/conversions/{id}/markdown", get(markdown))
        .route("/v1/conversions/{id}/assets/{name}", get(asset))
        .route("/v1/conversions/{id}/bundle.zip", get(bundle))
        .layer(DefaultBodyLimit::max(max))
        .layer(middleware::from_fn(response_headers))
        .with_state(app);
    if let Some(mcp) = mcp {
        rest.merge(mcp)
    } else {
        rest
    }
}

#[derive(Debug)]
struct ApiError(LoadError);
impl From<LoadError> for ApiError {
    fn from(value: LoadError) -> Self {
        Self(value)
    }
}
impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let code = self.0.code.as_str();
        let status = match code {
            "auth_invalid" => StatusCode::UNAUTHORIZED,
            "auth_forbidden" => StatusCode::FORBIDDEN,
            "auth_unavailable" => StatusCode::SERVICE_UNAVAILABLE,
            "document_not_found"
            | "conversion_not_found"
            | "job_not_found"
            | "source_not_found" => StatusCode::NOT_FOUND,
            "size_limit" | "body_limit" => StatusCode::PAYLOAD_TOO_LARGE,
            "media_type" => StatusCode::UNSUPPORTED_MEDIA_TYPE,
            "service_busy" | "queue_full" | "job_limit" | "job_capacity" => {
                StatusCode::TOO_MANY_REQUESTS
            }
            "idempotency_conflict"
            | "job_conflict"
            | "job_not_retryable"
            | "job_state"
            | "schedule_unavailable"
            | "source_changed"
            | "schedule_interval"
            | "conversion_pending" => StatusCode::CONFLICT,
            code if code.starts_with("storage_") || code == "worker_io" => {
                StatusCode::INTERNAL_SERVER_ERROR
            }
            _ => StatusCode::BAD_REQUEST,
        };
        let request_id = uuid::Uuid::new_v4().to_string();
        let mut response = (status, Json(json!({"code":self.0.code,"message":self.0.message,"retryable":self.0.retryable,"request_id":request_id}))).into_response();
        response
            .headers_mut()
            .insert("x-request-id", request_id.parse().expect("UUID header"));
        if status == StatusCode::UNAUTHORIZED {
            response
                .headers_mut()
                .insert(header::WWW_AUTHENTICATE, HeaderValue::from_static("Bearer"));
        }
        if matches!(
            status,
            StatusCode::TOO_MANY_REQUESTS | StatusCode::SERVICE_UNAVAILABLE
        ) {
            response.headers_mut().insert(
                header::RETRY_AFTER,
                self.0
                    .retry_after_secs
                    .unwrap_or(1)
                    .to_string()
                    .parse()
                    .expect("integer header"),
            );
        }
        response
    }
}
fn invalid(code: &str, message: &str) -> ApiError {
    LoadError::new(code, message).into()
}

async fn response_headers(request: Request, next: Next) -> Response {
    let mut response = next.run(request).await;
    // Normalize framework-generated rejection responses as well as application errors.
    if response.status().is_client_error()
        && !response
            .headers()
            .get(header::CONTENT_TYPE)
            .is_some_and(|v| v.as_bytes().starts_with(b"application/json"))
    {
        let status = response.status();
        let mut replacement = invalid(
            if status == StatusCode::PAYLOAD_TOO_LARGE {
                "body_limit"
            } else {
                "invalid_request"
            },
            status.canonical_reason().unwrap_or("request rejected"),
        )
        .into_response();
        *replacement.status_mut() = status;
        response = replacement;
    }
    let headers = response.headers_mut();
    if !headers.contains_key("x-request-id") {
        headers.insert(
            "x-request-id",
            uuid::Uuid::new_v4()
                .to_string()
                .parse()
                .expect("UUID header"),
        );
    }
    headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    headers.insert(
        "x-content-type-options",
        HeaderValue::from_static("nosniff"),
    );
    headers.insert("referrer-policy", HeaderValue::from_static("no-referrer"));
    headers.insert("content-security-policy", HeaderValue::from_static("default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self' blob:; base-uri 'none'; frame-ancestors 'none'"));
    response
}

fn token<'a>(app: &App, headers: &'a HeaderMap) -> Result<Option<&'a str>, ApiError> {
    if app.service.config().auth.mode != AuthMode::Oauth2 {
        return Ok(None);
    }
    let mut values = headers.get_all(header::AUTHORIZATION).iter();
    let Some(value) = values.next() else {
        return Ok(None);
    };
    if values.next().is_some() {
        return Err(invalid(
            "auth_invalid",
            "valid access-token credentials are required",
        ));
    }
    let value = value.to_str().map_err(|_| {
        invalid(
            "auth_invalid",
            "valid access-token credentials are required",
        )
    })?;
    let mut parts = value.split_ascii_whitespace();
    match (parts.next(), parts.next(), parts.next()) {
        (Some(scheme), Some(value), None) if scheme.eq_ignore_ascii_case("Bearer") => {
            Ok(Some(value))
        }
        _ => Err(invalid(
            "auth_invalid",
            "valid access-token credentials are required",
        )),
    }
}
fn key(headers: &HeaderMap) -> Result<Option<&str>, ApiError> {
    if headers.get_all("idempotency-key").iter().count() > 1 {
        return Err(invalid("invalid_request", "duplicate idempotency key"));
    }
    headers
        .get("idempotency-key")
        .map(|v| {
            v.to_str()
                .map_err(|_| invalid("invalid_request", "invalid idempotency key"))
        })
        .transpose()
}

struct ApiJson<T>(T);
impl<S: Send + Sync, T: DeserializeOwned> FromRequest<S> for ApiJson<T> {
    type Rejection = ApiError;
    async fn from_request(request: Request, state: &S) -> Result<Self, Self::Rejection> {
        let (parts, body) = request.into_parts();
        let bytes = axum::body::to_bytes(body, JSON_LIMIT)
            .await
            .map_err(|_| invalid("body_limit", "JSON body exceeds limit"))?;
        let request = Request::from_parts(parts, Body::from(bytes));
        Json::<T>::from_request(request, state)
            .await
            .map(|Json(value)| Self(value))
            .map_err(|error| {
                let code = if error.status() == StatusCode::PAYLOAD_TOO_LARGE {
                    "body_limit"
                } else if error.status() == StatusCode::UNSUPPORTED_MEDIA_TYPE {
                    "media_type"
                } else {
                    "invalid_request"
                };
                invalid(code, "invalid JSON request")
            })
    }
}
#[derive(Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct PageQuery {
    limit: Option<usize>,
    cursor: Option<String>,
    source: Option<String>,
    document_id: Option<String>,
}
#[derive(Serialize)]
struct Page<T> {
    items: Vec<T>,
    next_cursor: Option<String>,
}
fn page<T: Serialize>(items: Vec<T>, query: PageQuery) -> Result<Json<Page<T>>, ApiError> {
    let limit = query.limit.unwrap_or(100);
    if !(1..=1000).contains(&limit) {
        return Err(invalid(
            "invalid_request",
            "limit must be between 1 and 1000",
        ));
    }
    let offset = query
        .cursor
        .as_deref()
        .map(decode_cursor)
        .transpose()?
        .unwrap_or(0);
    if offset > items.len() {
        return Err(invalid("invalid_request", "invalid pagination cursor"));
    }
    let total = items.len();
    let selected = items.into_iter().skip(offset).take(limit).collect();
    let end = offset.saturating_add(limit);
    Ok(Json(Page {
        items: selected,
        next_cursor: (end < total).then(|| encode_cursor(end)),
    }))
}
fn encode_cursor(offset: usize) -> String {
    format!("p1-{offset:x}-{:x}", offset ^ 0x50df2a1)
}
fn decode_cursor(value: &str) -> Result<usize, ApiError> {
    let fail = || invalid("invalid_request", "invalid pagination cursor");
    let Some(rest) = value.strip_prefix("p1-") else {
        return Err(fail());
    };
    let Some((a, b)) = rest.split_once('-') else {
        return Err(fail());
    };
    let offset = usize::from_str_radix(a, 16).map_err(|_| fail())?;
    let check = usize::from_str_radix(b, 16).map_err(|_| fail())?;
    if offset ^ 0x50df2a1 != check {
        return Err(fail());
    }
    Ok(offset)
}
async fn health() -> Json<Value> {
    Json(json!({"status":"ok"}))
}
async fn ready(State(app): State<App>) -> Response {
    if app.ready.load(Ordering::Acquire) && !app.cancel.is_cancelled() {
        Json(json!({"status":"ready"})).into_response()
    } else {
        (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({"status":"stopping"})),
        )
            .into_response()
    }
}
async fn openapi(State(app): State<App>) -> Json<Value> {
    Json(spec::document(app.service.config()))
}
async fn docs() -> Html<&'static str> {
    Html(include_str!("http/docs.html"))
}
async fn docs_js() -> impl IntoResponse {
    (
        [(
            header::CONTENT_TYPE,
            "application/javascript; charset=utf-8",
        )],
        include_str!("http/docs.js"),
    )
}
async fn docs_css() -> impl IntoResponse {
    (
        [(header::CONTENT_TYPE, "text/css; charset=utf-8")],
        include_str!("http/docs.css"),
    )
}

#[derive(Deserialize, utoipa::ToSchema)]
#[serde(deny_unknown_fields)]
struct AcquisitionInput {
    url: String,
}
#[derive(Default, Deserialize, utoipa::ToSchema)]
#[serde(deny_unknown_fields)]
struct ConversionInput {
    pages: Option<String>,
    #[serde(default)]
    force: bool,
}
#[derive(Deserialize, utoipa::ToSchema)]
#[serde(deny_unknown_fields)]
struct ScheduleInput {
    enabled: bool,
}

async fn acquire(
    State(app): State<App>,
    headers: HeaderMap,
    ApiJson(input): ApiJson<AcquisitionInput>,
) -> Result<Response, ApiError> {
    let job = app
        .service
        .submit_acquisition(token(&app, &headers)?, input.url, key(&headers)?)
        .await?;
    accepted(job)
}
async fn fetch_source(
    State(app): State<App>,
    Path(id): Path<String>,
    headers: HeaderMap,
) -> Result<Response, ApiError> {
    accepted(
        app.service
            .submit_source(token(&app, &headers)?, &id, key(&headers)?)
            .await?,
    )
}
async fn convert(
    State(app): State<App>,
    Path(id): Path<String>,
    headers: HeaderMap,
    ApiJson(input): ApiJson<ConversionInput>,
) -> Result<Response, ApiError> {
    accepted(
        app.service
            .submit_conversion(
                token(&app, &headers)?,
                &id,
                input.pages.as_deref(),
                input.force,
                key(&headers)?,
            )
            .await?,
    )
}
fn accepted(job: crate::jobs::Job) -> Result<Response, ApiError> {
    let status = if job.status == "succeeded" {
        StatusCode::OK
    } else {
        StatusCode::ACCEPTED
    };
    let location = format!("/v1/jobs/{}", job.id);
    Ok((status, [(header::LOCATION, location)], Json(job)).into_response())
}
async fn sources(
    State(app): State<App>,
    headers: HeaderMap,
    Query(query): Query<PageQuery>,
) -> Result<Response, ApiError> {
    Ok(page(app.service.sources(token(&app, &headers)?).await?, query)?.into_response())
}
async fn jobs(
    State(app): State<App>,
    headers: HeaderMap,
    Query(query): Query<PageQuery>,
) -> Result<Response, ApiError> {
    let (limit, offset) = bounds(&query)?;
    Ok(bounded_page(
        app.service
            .jobs_page(token(&app, &headers)?, limit + 1, offset)
            .await?,
        limit,
        offset,
    )
    .into_response())
}
async fn job(
    State(app): State<App>,
    Path(id): Path<String>,
    headers: HeaderMap,
) -> Result<Response, ApiError> {
    Ok(Json(app.service.get_job(token(&app, &headers)?, &id).await?).into_response())
}
async fn cancel_job(
    State(app): State<App>,
    Path(id): Path<String>,
    headers: HeaderMap,
) -> Result<Response, ApiError> {
    Ok(Json(app.service.cancel_job(token(&app, &headers)?, &id).await?).into_response())
}
async fn retry_job(
    State(app): State<App>,
    Path(id): Path<String>,
    headers: HeaderMap,
) -> Result<Response, ApiError> {
    accepted(
        app.service
            .retry_job(token(&app, &headers)?, &id, key(&headers)?)
            .await?,
    )
}
async fn schedules(
    State(app): State<App>,
    headers: HeaderMap,
    Query(query): Query<PageQuery>,
) -> Result<Response, ApiError> {
    Ok(page(app.service.schedules(token(&app, &headers)?).await?, query)?.into_response())
}
async fn set_schedule(
    State(app): State<App>,
    Path(id): Path<String>,
    headers: HeaderMap,
    ApiJson(input): ApiJson<ScheduleInput>,
) -> Result<Response, ApiError> {
    Ok(Json(
        app.service
            .set_schedule(token(&app, &headers)?, &id, input.enabled)
            .await?,
    )
    .into_response())
}
fn bounds(query: &PageQuery) -> Result<(usize, usize), ApiError> {
    let limit = query.limit.unwrap_or(100);
    if !(1..=1000).contains(&limit) {
        return Err(invalid(
            "invalid_request",
            "limit must be between 1 and 1000",
        ));
    }
    let offset = query
        .cursor
        .as_deref()
        .map(decode_cursor)
        .transpose()?
        .unwrap_or(0);
    Ok((limit, offset))
}
fn bounded_page<T: Serialize>(mut items: Vec<T>, limit: usize, offset: usize) -> Json<Page<T>> {
    let more = items.len() > limit;
    items.truncate(limit);
    Json(Page {
        items,
        next_cursor: more.then(|| encode_cursor(offset.saturating_add(limit))),
    })
}
async fn status(
    State(app): State<App>,
    headers: HeaderMap,
    Query(query): Query<PageQuery>,
) -> Result<Response, ApiError> {
    let (limit, offset) = bounds(&query)?;
    Ok(bounded_page(
        app.service
            .status_page(token(&app, &headers)?, limit + 1, offset)
            .await?,
        limit,
        offset,
    )
    .into_response())
}
async fn history(
    State(app): State<App>,
    headers: HeaderMap,
    Query(query): Query<PageQuery>,
) -> Result<Response, ApiError> {
    let (limit, offset) = bounds(&query)?;
    let items = app
        .service
        .history_page(
            token(&app, &headers)?,
            query.source.as_deref(),
            limit + 1,
            offset,
        )
        .await?;
    Ok(bounded_page(items, limit, offset).into_response())
}
async fn conversions(
    State(app): State<App>,
    headers: HeaderMap,
    Query(query): Query<PageQuery>,
) -> Result<Response, ApiError> {
    let (limit, offset) = bounds(&query)?;
    let items = app
        .service
        .conversion_history_page(
            token(&app, &headers)?,
            query.document_id.as_deref(),
            limit + 1,
            offset,
        )
        .await?;
    Ok(bounded_page(items, limit, offset).into_response())
}
fn multipart_error(error: axum::extract::multipart::MultipartError) -> ApiError {
    if error.status() == StatusCode::PAYLOAD_TOO_LARGE {
        invalid("body_limit", "multipart body exceeds limit")
    } else {
        invalid("invalid_request", "invalid multipart upload")
    }
}
async fn upload(State(app): State<App>, request: Request) -> Result<Response, ApiError> {
    let authorization = token(&app, request.headers())?.map(str::to_owned);
    let mut session = app.service.prepare_upload(authorization.as_deref()).await?;
    let timeout = std::time::Duration::from_secs(app.service.config().limits.timeout_secs);
    let receive = async {
        let content = request
            .headers()
            .get(header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_owned();
        let limit = app.service.config().limits.max_bytes;
        if request
            .headers()
            .get(header::CONTENT_LENGTH)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.parse::<u64>().ok())
            .is_some_and(|n| n > limit.saturating_add(JSON_LIMIT as u64))
        {
            return Err(invalid(
                "body_limit",
                "upload exceeds configured byte limit",
            ));
        }
        let mut output = tokio::fs::File::from_std(
            session
                .file_mut()
                .as_file()
                .try_clone()
                .map_err(crate::error::io_error)?,
        );
        let mut bytes = 0u64;
        if content
            .split(';')
            .next()
            .is_some_and(|s| s.trim().eq_ignore_ascii_case("application/pdf"))
        {
            let mut stream = request.into_body().into_data_stream();
            while let Some(chunk) = stream.next().await {
                let chunk = chunk.map_err(|_| invalid("invalid_request", "incomplete upload"))?;
                bytes = bytes.saturating_add(chunk.len() as u64);
                if bytes > limit {
                    return Err(invalid(
                        "body_limit",
                        "upload exceeds configured byte limit",
                    ));
                }
                output
                    .write_all(&chunk)
                    .await
                    .map_err(crate::error::io_error)?;
            }
        } else if content.starts_with("multipart/form-data;") {
            let mut multipart = Multipart::from_request(request, &app)
                .await
                .map_err(|_| invalid("invalid_request", "invalid multipart upload"))?;
            let mut found = false;
            while let Some(mut field) = multipart.next_field().await.map_err(multipart_error)? {
                if found || field.name() != Some("file") {
                    return Err(invalid(
                        "invalid_request",
                        "upload requires exactly one file field",
                    ));
                }
                found = true;
                while let Some(chunk) = field.chunk().await.map_err(multipart_error)? {
                    bytes = bytes.saturating_add(chunk.len() as u64);
                    if bytes > limit {
                        return Err(invalid(
                            "body_limit",
                            "upload exceeds configured byte limit",
                        ));
                    }
                    output
                        .write_all(&chunk)
                        .await
                        .map_err(crate::error::io_error)?;
                }
            }
            if !found {
                return Err(invalid("invalid_request", "upload requires a file field"));
            }
        } else {
            return Err(invalid(
                "media_type",
                "use application/pdf or multipart/form-data",
            ));
        }
        output.flush().await.map_err(crate::error::io_error)?;
        output.sync_all().await.map_err(crate::error::io_error)?;
        drop(output);
        Ok::<(), ApiError>(())
    };
    tokio::select! {
        _=app.cancel.cancelled()=>return Err(invalid("cancelled","upload cancelled")),
        result=tokio::time::timeout(timeout,receive)=>result.map_err(|_|invalid("run_timeout","upload deadline exceeded"))??,
    }
    let result = app.service.finish_upload(session, &app.cancel).await?;
    Ok((StatusCode::CREATED, Json(result)).into_response())
}
fn download_slot(app: &App) -> Result<OwnedSemaphorePermit, ApiError> {
    app.downloads
        .clone()
        .try_acquire_owned()
        .map_err(|_| invalid("service_busy", "download capacity unavailable"))
}
fn stream_response<R: AsyncRead + Send + Unpin + 'static>(
    reader: R,
    content_type: &str,
    filename: &str,
    permit: OwnedSemaphorePermit,
) -> Result<Response, ApiError> {
    let stream = ReaderStream::new(reader).map(move |item| {
        let _ = &permit;
        item
    });
    let mut response = Response::new(Body::from_stream(stream));
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        content_type
            .parse()
            .map_err(|_| invalid("internal", "invalid content type"))?,
    );
    response.headers_mut().insert(
        header::CONTENT_DISPOSITION,
        format!("attachment; filename=\"{filename}\"")
            .parse()
            .map_err(|_| invalid("internal", "invalid filename"))?,
    );
    Ok(response)
}
async fn pdf(
    State(app): State<App>,
    Path(id): Path<String>,
    headers: HeaderMap,
) -> Result<Response, ApiError> {
    let permit = download_slot(&app)?;
    let reader = app.service.read_pdf(token(&app, &headers)?, &id).await?;
    stream_response(reader, "application/pdf", "document.pdf", permit)
}
async fn manifest(
    State(app): State<App>,
    Path(id): Path<String>,
    headers: HeaderMap,
) -> Result<Response, ApiError> {
    Ok(Json(
        app.service
            .conversion_manifest(token(&app, &headers)?, &id)
            .await?,
    )
    .into_response())
}
async fn markdown(
    State(app): State<App>,
    Path(id): Path<String>,
    headers: HeaderMap,
) -> Result<Response, ApiError> {
    let permit = download_slot(&app)?;
    let reader = app
        .service
        .read_artifact(token(&app, &headers)?, &id, "document.md")
        .await?;
    stream_response(
        reader,
        "text/markdown; charset=utf-8",
        "document.md",
        permit,
    )
}
async fn asset(
    State(app): State<App>,
    Path((id, name)): Path<(String, String)>,
    headers: HeaderMap,
) -> Result<Response, ApiError> {
    let permit = download_slot(&app)?;
    let path = format!("assets/{name}");
    if !crate::conversion::valid_artifact_path(&path) {
        return Err(invalid("document_not_found", "asset unavailable"));
    }
    let reader = app
        .service
        .read_artifact(token(&app, &headers)?, &id, &path)
        .await?;
    stream_response(reader, "image/png", &name, permit)
}
async fn bundle(
    State(app): State<App>,
    Path(id): Path<String>,
    headers: HeaderMap,
) -> Result<Response, ApiError> {
    let permit = download_slot(&app)?;
    let bearer = token(&app, &headers)?;
    let bundle = app.service.read_bundle(bearer, &id).await?;
    let manifest = bundle.manifest().clone();
    let temp = tempfile::tempdir_in("/tmp").map_err(crate::error::io_error)?;
    let mut paths = Vec::new();
    for (index, artifact) in manifest.artifacts.iter().enumerate() {
        if !crate::conversion::valid_artifact_path(&artifact.path) {
            return Err(invalid("storage_corrupt", "invalid stored artifact"));
        }
        let mut reader = bundle.read_artifact(index).await?;
        let path = temp.path().join(&artifact.path);
        if let Some(parent) = path.parent() {
            tokio::fs::create_dir_all(parent)
                .await
                .map_err(crate::error::io_error)?;
        }
        let mut file = tokio::fs::File::create(&path)
            .await
            .map_err(crate::error::io_error)?;
        tokio::io::copy(&mut reader, &mut file)
            .await
            .map_err(crate::error::io_error)?;
        paths.push((artifact.path.clone(), path));
    }
    let manifest_path = temp.path().join("manifest.json");
    tokio::fs::write(
        &manifest_path,
        serde_json::to_vec(&manifest)
            .map_err(|_| invalid("storage_corrupt", "invalid manifest"))?,
    )
    .await
    .map_err(crate::error::io_error)?;
    paths.push(("manifest.json".into(), manifest_path));
    let zip_path = temp.path().join("bundle.zip");
    let output = zip_path.clone();
    let (temp, permit, bundle) = tokio::task::spawn_blocking(move || -> Result<_, LoadError> {
        let file = std::fs::File::create(output).map_err(crate::error::io_error)?;
        let mut writer = zip::ZipWriter::new(file);
        for (name, path) in paths {
            writer
                .start_file(
                    name,
                    zip::write::SimpleFileOptions::default()
                        .compression_method(zip::CompressionMethod::Stored),
                )
                .map_err(|_| LoadError::new("storage_io", "bundle assembly failed"))?;
            let mut input = std::fs::File::open(path).map_err(crate::error::io_error)?;
            std::io::copy(&mut input, &mut writer).map_err(crate::error::io_error)?;
        }
        writer
            .finish()
            .map_err(|_| LoadError::new("storage_io", "bundle assembly failed"))?;
        Ok((temp, permit, bundle))
    })
    .await
    .map_err(|_| invalid("storage_io", "bundle assembly failed"))??;
    let reader = tokio::fs::File::open(zip_path)
        .await
        .map_err(crate::error::io_error)?;
    let stream = ReaderStream::new(reader).map(move |item| {
        let _ = (&permit, &temp, &bundle);
        item
    });
    Ok((
        [
            (header::CONTENT_TYPE, "application/zip"),
            (
                header::CONTENT_DISPOSITION,
                "attachment; filename=\"bundle.zip\"",
            ),
        ],
        Body::from_stream(stream),
    )
        .into_response())
}
