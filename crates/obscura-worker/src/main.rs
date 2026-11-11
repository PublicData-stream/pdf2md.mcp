use globset::Glob;
use obscura_browser::{BrowserContext, Page};
use obscura_net::{CookieJar, ObscuraNetError, ResourceRequest, StealthHttpClient};
#[allow(dead_code)]
#[path = "../../../src/model.rs"]
mod model;
use model::{Acquired, BrowserJob, BrowserStep};
use std::{
    io::{Read, Write},
    os::unix::fs::OpenOptionsExt,
    sync::{
        Arc, Mutex,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, Instant},
};
use url::Url;

type Result<T> = std::result::Result<T, &'static str>;
const MAX_INPUT: u64 = 8 * 1024 * 1024;
static RETRY_AFTER: AtomicU64 = AtomicU64::new(u64::MAX);

fn transient_status(response: &obscura_net::Response) -> Option<&'static str> {
    let code = match response.status {
        429 => "http_429",
        500 => "http_500",
        502 => "http_502",
        503 => "http_503",
        504 => "http_504",
        _ => return None,
    };
    if let Some(value) = response.headers.get("retry-after") {
        let delay = value.parse::<u64>().ok().or_else(|| {
            httpdate::parse_http_date(value)
                .ok()?
                .duration_since(std::time::SystemTime::now())
                .ok()
                .map(|d| d.as_secs())
        });
        if let Some(delay) = delay {
            RETRY_AFTER.store(delay, Ordering::Relaxed);
        }
    }
    Some(code)
}

#[tokio::main(flavor = "current_thread")]
async fn main() {
    let mut input = Vec::new();
    let result = if std::io::stdin()
        .take(MAX_INPUT + 1)
        .read_to_end(&mut input)
        .is_err()
        || input.len() as u64 > MAX_INPUT
    {
        Err("invalid_job")
    } else {
        match serde_json::from_slice::<BrowserJob>(&input) {
            Ok(job) => run(job).await,
            Err(_) => Err("invalid_job"),
        }
    };
    let value = match result {
        Ok(acquired) => serde_json::json!({"status":"ok", "acquired":acquired}),
        Err(code) => {
            let retry = RETRY_AFTER.load(Ordering::Relaxed);
            serde_json::json!({"status":"error", "code":code, "retry_after_secs": if retry == u64::MAX { None } else { Some(retry) }})
        }
    };
    let _ = serde_json::to_writer(std::io::stdout().lock(), &value);
}

fn valid_origin(s: &str) -> Result<Url> {
    let url = Url::parse(s).map_err(|_| "invalid_job")?;
    if url.scheme() != "https"
        || url.host_str().is_none()
        || url.port_or_known_default() != Some(443)
        || !url.username().is_empty()
        || url.password().is_some()
    {
        return Err("invalid_job");
    }
    Ok(url)
}
fn is_allowed(url: &str, allowed: &[String]) -> bool {
    let Ok(u) = valid_origin(url) else {
        return false;
    };
    allowed
        .iter()
        .any(|s| valid_origin(s).is_ok_and(|a| a.origin() == u.origin()))
}
fn valid_proxy(proxy: &str) -> bool {
    let Ok(url) = Url::parse(proxy) else {
        return false;
    };
    wreq::Proxy::all(proxy).is_ok()
        && url.scheme() == "http"
        && matches!(url.host_str(), Some("127.0.0.1") | Some("[::1]"))
        && url.port().is_some()
        && url.username().is_empty()
        && url.password().is_none()
        && url.path() == "/"
        && url.query().is_none()
        && url.fragment().is_none()
}
fn valid_pdf(bytes: &[u8]) -> bool {
    bytes[..bytes.len().min(1024)]
        .windows(5)
        .any(|w| w == b"%PDF-")
}
fn set_cookie(jar: &CookieJar, cookie: &model::BrowserCookie) -> Result<()> {
    let url = valid_origin(&cookie.origin)?;
    if cookie.name.is_empty()
        || cookie
            .name
            .bytes()
            .any(|b| b <= 32 || b >= 127 || b"()<>@,;:\\\"/[]?={}".contains(&b))
        || cookie
            .value
            .bytes()
            .any(|b| !(33..127).contains(&b) || b";,\\\"".contains(&b))
    {
        return Err("invalid_job");
    }
    jar.set_cookie(
        &format!("{}={}; Path=/; Secure; HttpOnly", cookie.name, cookie.value),
        &url,
    );
    Ok(())
}
fn save(job: &BrowserJob, bytes: &[u8], url: &str) -> Result<Acquired> {
    if bytes.len() as u64 > job.max_bytes {
        return Err("size_limit");
    }
    if !valid_pdf(bytes) {
        return Err("pdf_not_found");
    }
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(&job.output)
        .map_err(|_| "storage_io")?;
    if file.write_all(bytes).is_err() || file.sync_all().is_err() {
        let _ = std::fs::remove_file(&job.output);
        return Err("storage_io");
    }
    Ok(Acquired {
        bytes: bytes.len() as u64,
        final_url: url.to_string(),
    })
}
fn navigation_error(error: impl std::fmt::Display) -> &'static str {
    let text = error.to_string().to_ascii_lowercase();
    if text.contains("response body exceeded") {
        "upstream_limit"
    } else if text.contains("timed out") || text.contains("timeout") {
        "upstream_timeout"
    } else if text.contains("network error") || text.contains("connection") {
        "network_failed"
    } else {
        "browser_failed"
    }
}
async fn run(job: BrowserJob) -> Result<Acquired> {
    if !valid_proxy(&job.proxy_url) {
        return Err("invalid_proxy");
    }
    if job.max_bytes == 0
        || usize::try_from(job.max_bytes).is_err()
        || job.timeout_secs == 0
        || !is_allowed(&job.url, &job.allowed_origins)
        || job.allowed_origins.iter().any(|s| valid_origin(s).is_err())
        || job
            .cookies
            .iter()
            .any(|c| !is_allowed(&c.origin, &job.allowed_origins))
    {
        return Err("invalid_job");
    }
    let matcher = Glob::new(&job.response_url_glob)
        .map_err(|_| "invalid_job")?
        .compile_matcher();
    if job.raw {
        let jar = Arc::new(CookieJar::new());
        for cookie in &job.cookies {
            set_cookie(&jar, cookie)?;
        }
        let client = StealthHttpClient::with_proxy(jar, Some(&job.proxy_url), false);
        let url = valid_origin(&job.url)?;
        let response = client
            .fetch_resource_with_callbacks(
                &url,
                ResourceRequest::navigation().with_max_response_bytes(job.max_bytes as usize),
                None,
            )
            .await
            .map_err(|e| match e {
                ObscuraNetError::ResponseTooLarge { .. } => "size_limit",
                ObscuraNetError::Network(s) if s.to_ascii_lowercase().contains("timed out") => {
                    "upstream_timeout"
                }
                ObscuraNetError::Network(_) => "network_failed",
                _ => "browser_failed",
            })?;
        if let Some(code) = transient_status(&response) {
            return Err(code);
        }
        if !(200..300).contains(&response.status)
            || !is_allowed(response.url.as_str(), &job.allowed_origins)
            || !matcher.is_match(response.url.as_str())
        {
            return Err("pdf_not_found");
        }
        return save(&job, &response.body, response.url.as_str());
    }
    let context = Arc::new(BrowserContext::with_full_options(
        "pdf2md".into(),
        Some(job.proxy_url.clone()),
        true,
        None,
    ));
    for cookie in &job.cookies {
        set_cookie(&context.cookie_jar, cookie)?;
    }
    let mut page = Page::new("pdf2md".into(), context);
    let capture = Arc::new(Mutex::new(None::<(String, Vec<u8>)>));
    let failure = Arc::new(Mutex::new(None::<&'static str>));
    let errors = failure.clone();
    let found = capture.clone();
    let origins = job.allowed_origins.clone();
    let max = job.max_bytes;
    page.on_response(Arc::new(move |_, response| {
        if is_allowed(response.url.as_str(), &origins)
            && matcher.is_match(response.url.as_str())
            && let Some(code) = transient_status(response)
        {
            if let Ok(mut result) = errors.lock() {
                *result = Some(code);
            }
            return;
        }
        if (200..300).contains(&response.status)
            && is_allowed(response.url.as_str(), &origins)
            && matcher.is_match(response.url.as_str())
            && valid_pdf(&response.body)
        {
            if response.body.len() as u64 > max {
                if let Ok(mut result) = errors.lock() {
                    *result = Some("size_limit");
                }
            } else if let Ok(mut result) = found.lock()
                && result.is_none()
            {
                *result = Some((response.url.to_string(), response.body.clone()));
            }
        }
    }));
    page.navigate(&job.url).await.map_err(navigation_error)?;
    for step in &job.steps {
        match step {
            BrowserStep::Navigate { url } => {
                if !is_allowed(url, &job.allowed_origins) {
                    return Err("invalid_job");
                }
                page.navigate(url).await.map_err(navigation_error)?;
            }
            BrowserStep::WaitSelector {
                selector,
                timeout_secs,
            } => {
                let end = Instant::now()
                    .checked_add(Duration::from_secs(*timeout_secs))
                    .ok_or("invalid_job")?;
                let script = format!(
                    "Boolean(document.querySelector({}))",
                    serde_json::to_string(selector).map_err(|_| "invalid_job")?
                );
                while page.evaluate(&script).as_bool() != Some(true) {
                    if Instant::now() >= end {
                        return Err("browser_failed");
                    }
                    page.settle(100).await;
                    page.process_pending_navigation()
                        .await
                        .map_err(navigation_error)?;
                }
            }
            BrowserStep::Fill {
                selector,
                value,
                origin,
            } => {
                if !is_allowed(&page.url_string(), &job.allowed_origins)
                    || valid_origin(&page.url_string())?.origin() != valid_origin(origin)?.origin()
                {
                    return Err("invalid_job");
                }
                let script = format!(
                    "(()=>{{let e=document.querySelector({});if(!e)return false;e.value={};e.dispatchEvent(new Event('input',{{bubbles:true}}));e.dispatchEvent(new Event('change',{{bubbles:true}}));return true}})()",
                    serde_json::to_string(selector).map_err(|_| "invalid_job")?,
                    serde_json::to_string(value).map_err(|_| "invalid_job")?
                );
                if page.evaluate(&script).as_bool() != Some(true) {
                    return Err("browser_failed");
                }
            }
            BrowserStep::Click { selector } => {
                let script = format!(
                    "(()=>{{let e=document.querySelector({});if(!e)return false;e.click();return true}})()",
                    serde_json::to_string(selector).map_err(|_| "invalid_job")?
                );
                if page.evaluate(&script).as_bool() != Some(true) {
                    return Err("browser_failed");
                }
            }
            BrowserStep::Settle { milliseconds } => page.settle(*milliseconds).await,
            BrowserStep::Script { javascript } => {
                page.evaluate(javascript);
            }
            BrowserStep::WaitPdf { timeout_secs } => {
                let end = Instant::now()
                    .checked_add(Duration::from_secs(*timeout_secs))
                    .ok_or("invalid_job")?;
                while capture.lock().map_err(|_| "browser_failed")?.is_none()
                    && Instant::now() < end
                {
                    page.settle(100).await;
                    page.process_pending_navigation()
                        .await
                        .map_err(navigation_error)?;
                }
                if capture.lock().map_err(|_| "browser_failed")?.is_none() {
                    return Err(failure
                        .lock()
                        .map_err(|_| "browser_failed")?
                        .unwrap_or("pdf_not_found"));
                }
            }
        }
        page.process_pending_navigation()
            .await
            .map_err(navigation_error)?;
    }
    let result = capture
        .lock()
        .map_err(|_| "browser_failed")?
        .take()
        .ok_or_else(|| {
            failure
                .lock()
                .ok()
                .and_then(|v| *v)
                .unwrap_or("pdf_not_found")
        })?;
    save(&job, &result.1, &result.0)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn only_local_valid_proxy_is_accepted() {
        assert!(valid_proxy("http://127.0.0.1:12345"));
        for url in [
            "",
            "http://example.com:1234",
            "https://127.0.0.1:80",
            "http://user:pass@127.0.0.1:80",
            "http://127.0.0.1:80/path",
            "socks5://127.0.0.1:80",
        ] {
            assert!(!valid_proxy(url));
        }
    }
    #[test]
    fn pdf_header_must_appear_in_first_1024_bytes() {
        assert!(valid_pdf(b"\n%PDF-1.7"));
        let mut bytes = vec![b' '; 1024];
        bytes.extend_from_slice(b"%PDF-1.7");
        assert!(!valid_pdf(&bytes));
    }
    #[test]
    fn origin_requires_https_and_port_443() {
        let allowed = vec!["https://example.org".to_owned()];
        assert!(is_allowed("https://example.org/path", &allowed));
        assert!(!is_allowed("https://example.org:444/path", &allowed));
        assert!(!is_allowed("https://evil.example.org/", &allowed));
    }
}
