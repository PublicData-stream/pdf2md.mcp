//! OpenAPI schemas and operation descriptions shared by the bundled console.
use super::{AcquisitionInput, ConversionInput, ScheduleInput};
use crate::{auth::AuthMode, config::Config};
use serde_json::{Value, json};
use utoipa::{OpenApi, ToSchema};

#[derive(ToSchema)]
#[allow(dead_code)]
struct Error {
    code: String,
    message: String,
    retryable: bool,
    request_id: String,
}
#[derive(ToSchema)]
#[allow(dead_code)]
struct Observation {
    source_id: String,
    attempt_id: String,
    document_id: Option<String>,
    outcome: String,
    mode: String,
    bytes: u64,
    observed_at: String,
    url: Option<String>,
    error_code: Option<String>,
}
#[derive(ToSchema)]
#[allow(dead_code)]
struct Job {
    id: String,
    kind: String,
    status: String,
    created_at: String,
    started_at: Option<String>,
    finished_at: Option<String>,
    document_id: Option<String>,
    observation_id: Option<String>,
    conversion_id: Option<String>,
    error_code: Option<String>,
    retry_of: Option<String>,
}
#[derive(ToSchema)]
#[allow(dead_code)]
struct Schedule {
    source_id: String,
    enabled: bool,
    interval_secs: u64,
    next_due: i64,
    status: String,
    error_code: Option<String>,
}
#[derive(ToSchema)]
#[allow(dead_code)]
struct UploadResult {
    observation: Observation,
    conversion_job: Option<Job>,
}
#[derive(OpenApi)]
#[openapi(
    info(
        title = "pdf2md HTTP API",
        version = "1.0.0",
        description = "Workspace-scoped PDF acquisition, conversion, history and polling. Access tokens are obtained from an OAuth2/OIDC client, such as the optional registered client under /oauth/."
    ),
    components(schemas(
        AcquisitionInput,
        ConversionInput,
        ScheduleInput,
        Error,
        Observation,
        Job,
        Schedule,
        UploadResult
    ))
)]
struct Api;

pub(super) fn document(config: &Config) -> Value {
    let mut doc = serde_json::to_value(Api::openapi()).expect("OpenAPI is serializable");
    let oauth = config.auth.mode == AuthMode::Oauth2;
    if oauth {
        doc["components"]["securitySchemes"] = json!({"bearerAuth":{"type":"http","scheme":"bearer","description":"OAuth2 access token; JWT or introspection as configured. OIDC ID tokens are not accepted."}});
    }
    let read = config
        .auth
        .oidc
        .as_ref()
        .map(|o| o.read_scope.as_str())
        .unwrap_or("pdf2md:read");
    let write = config
        .auth
        .oidc
        .as_ref()
        .map(|o| o.write_scope.as_str())
        .unwrap_or("pdf2md:write");
    let operate = config
        .auth
        .oidc
        .as_ref()
        .map(|o| o.operate_scope.as_str())
        .unwrap_or("pdf2md:operate");
    let endpoints = [
        (
            "get",
            "/v1/status",
            "Latest acquisition observations",
            None,
            "Observation",
            false,
            false,
            true,
        ),
        (
            "get",
            "/v1/history",
            "Acquisition history",
            None,
            "Observation",
            false,
            false,
            true,
        ),
        (
            "get",
            "/v1/conversions",
            "Conversion history",
            None,
            "ConversionAttempt",
            false,
            false,
            true,
        ),
        (
            "post",
            "/v1/documents",
            "Upload one PDF",
            Some("Upload"),
            "UploadResult",
            true,
            false,
            false,
        ),
        (
            "get",
            "/v1/documents/{id}/pdf",
            "Download a PDF",
            None,
            "Binary",
            false,
            false,
            false,
        ),
        (
            "post",
            "/v1/acquisitions",
            "Acquire a public HTTPS PDF",
            Some("AcquisitionInput"),
            "Job",
            true,
            false,
            false,
        ),
        (
            "post",
            "/v1/documents/{id}/conversions",
            "Convert a stored PDF",
            Some("ConversionInput"),
            "Job",
            true,
            false,
            false,
        ),
        (
            "get",
            "/v1/sources",
            "List published source descriptions",
            None,
            "PublishedSource",
            false,
            false,
            true,
        ),
        (
            "post",
            "/v1/sources/{id}/fetch",
            "Fetch a published source",
            None,
            "Job",
            true,
            true,
            false,
        ),
        (
            "get",
            "/v1/schedules",
            "List workspace polling grants",
            None,
            "Schedule",
            false,
            false,
            true,
        ),
        (
            "put",
            "/v1/schedules/{id}",
            "Enable or disable source polling",
            Some("ScheduleInput"),
            "Schedule",
            true,
            true,
            false,
        ),
        (
            "get",
            "/v1/jobs",
            "List workspace jobs",
            None,
            "Job",
            false,
            false,
            true,
        ),
        (
            "get",
            "/v1/jobs/{id}",
            "Inspect a job",
            None,
            "Job",
            false,
            false,
            false,
        ),
        (
            "post",
            "/v1/jobs/{id}/cancel",
            "Cancel a job",
            None,
            "Job",
            true,
            false,
            false,
        ),
        (
            "post",
            "/v1/jobs/{id}/retry",
            "Retry an unsuccessful job",
            None,
            "Job",
            true,
            false,
            false,
        ),
        (
            "get",
            "/v1/conversions/{id}/manifest",
            "Read a verified bundle manifest",
            None,
            "Manifest",
            false,
            false,
            false,
        ),
        (
            "get",
            "/v1/conversions/{id}/markdown",
            "Download Markdown",
            None,
            "Binary",
            false,
            false,
            false,
        ),
        (
            "get",
            "/v1/conversions/{id}/assets/{name}",
            "Download a bundle image",
            None,
            "Binary",
            false,
            false,
            false,
        ),
        (
            "get",
            "/v1/conversions/{id}/bundle.zip",
            "Download a ZIP bundle",
            None,
            "Binary",
            false,
            false,
            false,
        ),
    ];
    // Existing persisted model schemas are described here without coupling storage to transport.
    doc["components"]["schemas"]["ConversionAttempt"] = json!({"type":"object","required":["id","document_id","profile_key","created_at","status","options","automatic"],"properties":{"id":{"type":"string"},"document_id":{"type":"string"},"profile_key":{"type":"string"},"created_at":{"type":"string"},"finished_at":{"type":["string","null"]},"error_code":{"type":["string","null"]},"status":{"type":"string"},"options":{"type":"object","properties":{"pages":{"type":["array","null"],"items":{"type":"integer","minimum":1}}}},"automatic":{"type":"boolean"},"bundle_id":{"type":["string","null"]}}});
    doc["components"]["schemas"]["PublishedSource"] = json!({"type":"object","properties":{"id":{"type":"string"},"mode":{"type":"string"},"interval_secs":{"type":["integer","null"]}}});
    doc["components"]["schemas"]["Manifest"] = json!({"type":"object","required":["format_version","document_id","artifacts"],"properties":{"format_version":{"type":"integer"},"document_id":{"type":"string"},"converter":{"type":"string"},"options":{"type":"object"},"pages":{"type":"array","items":{"type":"integer"}},"warnings":{"type":"array","items":{"type":"string"}},"artifacts":{"type":"array","items":{"type":"object","required":["path","sha256","bytes"],"properties":{"path":{"type":"string"},"sha256":{"type":"string"},"bytes":{"type":"integer"}}}}}});
    for (method, path, summary, input, output, is_write, is_operate, paginated) in endpoints {
        let schema = if output == "Binary" {
            json!({"type":"string","format":"binary"})
        } else {
            json!({"$ref":format!("#/components/schemas/{output}")})
        };
        let schema = if paginated {
            json!({"type":"object","required":["items","next_cursor"],"properties":{"items":{"type":"array","items":schema},"next_cursor":{"type":["string","null"]}}})
        } else {
            schema
        };
        let success = if path == "/v1/documents" {
            "201"
        } else if method == "post" && path != "/v1/jobs/{id}/cancel" {
            "202"
        } else {
            "200"
        };
        let media = if path.ends_with("/pdf") {
            "application/pdf"
        } else if path.ends_with("/markdown") {
            "text/markdown"
        } else if path.ends_with("/bundle.zip") {
            "application/zip"
        } else if path.contains("/assets/") {
            "image/png"
        } else {
            "application/json"
        };
        let mut operation = json!({"summary":summary,"operationId":format!("{}_{}",method,path.replace('/',"_").replace(['{','}','.'],"")),"responses":{success:{"description":"Successful response","content":{media:{"schema":schema}}},"400":{"description":"Invalid request","content":{"application/json":{"schema":{"$ref":"#/components/schemas/Error"}}}},"401":{"description":"Invalid access token"},"403":{"description":"Operation is not permitted"},"404":{"description":"Resource unavailable in this workspace"},"409":{"description":"Conflicting request or policy changed"},"413":{"description":"Body exceeds limit"},"415":{"description":"Unsupported content type"},"429":{"description":"Capacity unavailable"},"503":{"description":"Identity provider unavailable"}}});
        if success == "202" {
            operation["responses"]["200"] = json!({"description":"Existing completed conversion or idempotent result","content":{"application/json":{"schema":{"$ref":"#/components/schemas/Job"}}}});
            operation["responses"]["202"]["headers"] =
                json!({"Location":{"schema":{"type":"string"},"description":"Job polling URL"}});
        }
        let mut parameters = Vec::new();
        for parameter in ["id", "name"] {
            if path.contains(&format!("{{{parameter}}}")) {
                parameters.push(json!({"in":"path","name":parameter,"required":true,"schema":{"type":"string"}}));
            }
        }
        if paginated {
            parameters.push(json!({"in":"query","name":"limit","schema":{"type":"integer","minimum":1,"maximum":1000,"default":100}}));
            parameters.push(json!({"in":"query","name":"cursor","schema":{"type":"string"}}));
        }
        if path == "/v1/history" {
            parameters.push(json!({"in":"query","name":"source","schema":{"type":"string"}}));
        }
        if path == "/v1/conversions" {
            parameters.push(json!({"in":"query","name":"document_id","schema":{"type":"string"}}));
        }
        if method == "post" && path != "/v1/documents" && path != "/v1/jobs/{id}/cancel" {
            parameters.push(json!({"in":"header","name":"Idempotency-Key","schema":{"type":"string","minLength":1,"maxLength":128}}));
        }
        operation["parameters"] = json!(parameters);
        for status in [
            "400", "401", "403", "404", "409", "413", "415", "429", "503",
        ] {
            operation["responses"][status]["content"] =
                json!({"application/json":{"schema":{"$ref":"#/components/schemas/Error"}}});
        }
        if path == "/v1/jobs/{id}/cancel" || path == "/v1/jobs/{id}/retry" {
            operation["description"] = json!(
                "Configured-source jobs additionally require the operate scope in OAuth mode."
            );
        }
        if let Some(input) = input {
            operation["requestBody"] = if input == "Upload" {
                json!({"required":true,"content":{"application/pdf":{"schema":{"type":"string","format":"binary"}},"multipart/form-data":{"schema":{"type":"object","required":["file"],"properties":{"file":{"type":"string","format":"binary"}}}}}})
            } else {
                json!({"required":true,"content":{"application/json":{"schema":{"$ref":format!("#/components/schemas/{input}")}}}})
            };
        }
        if oauth {
            operation["security"] = json!([{"bearerAuth":[]}]);
            let mut scopes = vec![read];
            if is_write {
                scopes.push(write)
            }
            if is_operate {
                scopes.push(operate)
            }
            operation["x-required-scopes"] = json!(scopes);
        } else {
            operation["security"] = json!([]);
        }
        if is_write && config.auth.mode == AuthMode::NoneRo {
            operation["description"] =
                json!("Anonymous writes are disabled in the current server mode.");
        }
        doc["paths"][path][method] = operation;
    }
    doc
}
