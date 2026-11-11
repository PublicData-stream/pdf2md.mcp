use serde::{Deserialize, Serialize};
use std::path::PathBuf;

pub const DEFAULT_MAX_BYTES: u64 = 512 * 1024 * 1024;
pub const DEFAULT_TIMEOUT_SECS: u64 = 20 * 60;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Observation {
    pub source_id: String,
    pub attempt_id: String,
    pub document_id: Option<String>,
    pub outcome: String,
    pub mode: String,
    pub bytes: u64,
    pub observed_at: String,
    pub url: Option<String>,
    pub error_code: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Acquired {
    pub bytes: u64,
    pub final_url: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BrowserCookie {
    pub name: String,
    pub value: String,
    pub origin: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "action", rename_all = "snake_case", deny_unknown_fields)]
pub enum BrowserStep {
    Navigate {
        url: String,
    },
    WaitSelector {
        selector: String,
        #[serde(default = "step_timeout")]
        timeout_secs: u64,
    },
    Fill {
        selector: String,
        value: String,
        origin: String,
    },
    Click {
        selector: String,
    },
    Settle {
        #[serde(default = "settle_ms")]
        milliseconds: u64,
    },
    Script {
        javascript: String,
    },
    WaitPdf {
        #[serde(default = "step_timeout")]
        timeout_secs: u64,
    },
}
fn step_timeout() -> u64 {
    30
}
fn settle_ms() -> u64 {
    500
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BrowserJob {
    pub url: String,
    pub output: PathBuf,
    pub max_bytes: u64,
    pub timeout_secs: u64,
    pub proxy_url: String,
    pub allowed_origins: Vec<String>,
    pub cookies: Vec<BrowserCookie>,
    pub steps: Vec<BrowserStep>,
    pub response_url_glob: String,
    pub raw: bool,
}
