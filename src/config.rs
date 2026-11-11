use crate::error::{LoadError, Result};
use crate::model::{BrowserCookie, BrowserStep, DEFAULT_MAX_BYTES, DEFAULT_TIMEOUT_SECS};
use serde::{Deserialize, Serialize};
use std::{
    collections::HashSet,
    path::{Path, PathBuf},
};

#[derive(Debug, Clone, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct Config {
    #[serde(default)]
    pub conversion: crate::conversion::ConversionConfig,
    #[serde(default)]
    pub auth: crate::auth::AuthConfig,
    pub database_url_env: Option<String>,
    #[serde(default)]
    pub limits: Limits,
    #[serde(default)]
    pub sources: Vec<Source>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Limits {
    pub max_bytes: u64,
    pub timeout_secs: u64,
    pub concurrency: usize,
    pub worker_max_rss_mib: u64,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_bytes: DEFAULT_MAX_BYTES,
            timeout_secs: DEFAULT_TIMEOUT_SECS,
            concurrency: 1,
            worker_max_rss_mib: 4096,
        }
    }
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize, clap::ValueEnum)]
#[serde(rename_all = "snake_case")]
pub enum Mode {
    Https,
    Obscura,
    Browser,
}

impl Mode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Https => "https",
            Self::Obscura => "obscura",
            Self::Browser => "browser",
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Source {
    pub id: String,
    pub mode: Mode,
    pub url: String,
    #[serde(default)]
    pub allowed_origins: Vec<String>,
    pub interval_secs: Option<u64>,
    pub max_bytes: Option<u64>,
    pub timeout_secs: Option<u64>,
    #[serde(default)]
    pub headers: Vec<Header>,
    #[serde(default)]
    pub cookies: Vec<Cookie>,
    #[serde(default)]
    pub steps: Vec<Step>,
    pub response_url_glob: Option<String>,
}

impl Source {
    pub fn one_off(url: String, mode: Mode) -> Self {
        use sha2::{Digest, Sha256};
        let id = format!("url:{:x}", Sha256::digest(url.as_bytes()));
        Self {
            id,
            url,
            mode,
            allowed_origins: vec![],
            interval_secs: None,
            max_bytes: None,
            timeout_secs: None,
            headers: vec![],
            cookies: vec![],
            steps: vec![],
            response_url_glob: None,
        }
    }
    pub fn limits(&self, defaults: &Limits) -> Limits {
        Limits {
            max_bytes: self.max_bytes.unwrap_or(defaults.max_bytes),
            timeout_secs: self.timeout_secs.unwrap_or(defaults.timeout_secs),
            ..defaults.clone()
        }
    }
}

/// Secret values are never included in application output or error messages.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Secret {
    pub literal: Option<String>,
    pub env: Option<String>,
    pub file: Option<PathBuf>,
}
impl Secret {
    pub fn resolve(&self) -> Result<String> {
        if usize::from(self.literal.is_some())
            + usize::from(self.env.is_some())
            + usize::from(self.file.is_some())
            != 1
        {
            return Err(LoadError::new(
                "secret_config",
                "select exactly one secret input",
            ));
        }
        let value = if let Some(v) = &self.literal {
            v.clone()
        } else if let Some(name) = &self.env {
            std::env::var(name).map_err(|_| {
                LoadError::new(
                    "secret_unavailable",
                    "secret environment variable unavailable",
                )
            })?
        } else {
            read_regular(self.file.as_ref().expect("validated secret input"), 65536)?
                .trim_end_matches(['\r', '\n'])
                .to_owned()
        };
        if value.len() > 65536 {
            return Err(LoadError::new("secret_config", "secret exceeds size limit"));
        }
        Ok(value)
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Header {
    pub name: String,
    pub value: Secret,
    pub origin: String,
}
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Cookie {
    pub name: String,
    pub value: Secret,
    pub origin: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "action", rename_all = "snake_case", deny_unknown_fields)]
pub enum Step {
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
        value: Secret,
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
        file: PathBuf,
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

pub fn resolve_steps(steps: &[Step]) -> Result<Vec<BrowserStep>> {
    steps
        .iter()
        .map(|s| {
            Ok(match s {
                Step::Navigate { url } => BrowserStep::Navigate { url: url.clone() },
                Step::WaitSelector {
                    selector,
                    timeout_secs,
                } => BrowserStep::WaitSelector {
                    selector: selector.clone(),
                    timeout_secs: *timeout_secs,
                },
                Step::Fill {
                    selector,
                    value,
                    origin,
                } => BrowserStep::Fill {
                    selector: selector.clone(),
                    value: value.resolve()?,
                    origin: origin.clone(),
                },
                Step::Click { selector } => BrowserStep::Click {
                    selector: selector.clone(),
                },
                Step::Settle { milliseconds } => BrowserStep::Settle {
                    milliseconds: *milliseconds,
                },
                Step::WaitPdf { timeout_secs } => BrowserStep::WaitPdf {
                    timeout_secs: *timeout_secs,
                },
                Step::Script { file } => {
                    let text = read_regular(file, 1024 * 1024).map_err(|_| {
                        LoadError::new(
                            "script_unavailable",
                            "operator script unavailable or not UTF-8",
                        )
                    })?;
                    if text.len() > 1024 * 1024 {
                        return Err(LoadError::new(
                            "script_config",
                            "operator script exceeds size limit",
                        ));
                    }
                    BrowserStep::Script { javascript: text }
                }
            })
        })
        .collect()
}

fn read_regular(path: &Path, limit: u64) -> Result<String> {
    use std::{io::Read, os::unix::fs::OpenOptionsExt};
    let fail = || {
        LoadError::new(
            "config_file",
            "configuration input must be a readable regular UTF-8 file within its size limit",
        )
    };
    let file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
        .map_err(|_| fail())?;
    let before = file.metadata().map_err(|_| fail())?;
    if !before.is_file() || before.len() > limit {
        return Err(fail());
    }
    let mut bytes = Vec::new();
    file.take(limit + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| fail())?;
    if bytes.len() as u64 > limit {
        return Err(fail());
    }
    String::from_utf8(bytes).map_err(|_| fail())
}
pub fn resolve_cookies(cookies: &[Cookie]) -> Result<Vec<BrowserCookie>> {
    cookies
        .iter()
        .map(|c| {
            Ok(BrowserCookie {
                name: c.name.clone(),
                value: c.value.resolve()?,
                origin: c.origin.clone(),
            })
        })
        .collect()
}

impl Config {
    pub fn read(path: Option<&Path>) -> Result<Self> {
        let mut cfg: Self = match path {
            Some(p) => {
                let text = read_regular(p, 8 * 1024 * 1024)
                    .map_err(|_| LoadError::new("config_io", "configuration file unavailable"))?;
                toml::from_str(&text)
                    .map_err(|_| LoadError::new("config_invalid", "invalid TOML configuration"))?
            }
            None => Self::default(),
        };
        // Referenced files are relative to the TOML file, not the caller's cwd.
        if let Some(base) = path.and_then(Path::parent) {
            if let Some(oidc) = &mut cfg.auth.oidc {
                if let Some(secret) = &mut oidc.client_secret
                    && let Some(file) = &mut secret.file
                    && file.is_relative()
                {
                    *file = base.join(&*file);
                }
                if let Some(file) = &mut oidc.ca_file
                    && file.is_relative()
                {
                    *file = base.join(&*file);
                }
            }
            for source in &mut cfg.sources {
                for header in &mut source.headers {
                    relative_secret(&mut header.value, base);
                }
                for cookie in &mut source.cookies {
                    relative_secret(&mut cookie.value, base);
                }
                for step in &mut source.steps {
                    match step {
                        Step::Script { file } if file.is_relative() => *file = base.join(&*file),
                        Step::Fill { value, .. } => relative_secret(value, base),
                        _ => {}
                    }
                }
            }
        }
        cfg.validate()?;
        Ok(cfg)
    }
    pub fn validate(&self) -> Result<()> {
        self.conversion.limits.validate()?;
        self.auth.validate()?;
        if self.limits.concurrency == 0
            || self.limits.concurrency > 64
            || self.limits.max_bytes == 0
            || self.limits.timeout_secs == 0
            || self.limits.worker_max_rss_mib == 0
            || self.limits.worker_max_rss_mib > u64::MAX / (1024 * 1024)
        {
            return Err(LoadError::new(
                "config_invalid",
                "limits must be positive; concurrency must be at most 64",
            ));
        }
        let mut ids = HashSet::new();
        for s in &self.sources {
            if s.id.is_empty()
                || s.id.len() > 128
                || !s
                    .id
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"_-.:".contains(&b))
                || !ids.insert(&s.id)
                || s.id.starts_with("manual:")
            {
                return Err(LoadError::new(
                    "config_invalid",
                    "source IDs must be unique portable identifiers",
                ));
            }
            if s.max_bytes == Some(0) || s.timeout_secs == Some(0) || s.interval_secs == Some(0) {
                return Err(LoadError::new(
                    "config_invalid",
                    "source limits and polling intervals must be positive",
                ));
            }
            if !matches!(s.mode, Mode::Https) && !s.headers.is_empty() {
                return Err(LoadError::new(
                    "config_invalid",
                    "custom headers require direct HTTPS mode",
                ));
            }
            if matches!(s.mode, Mode::Https) && (!s.steps.is_empty() || !s.cookies.is_empty()) {
                return Err(LoadError::new(
                    "config_invalid",
                    "browser cookies and steps require a browser mode",
                ));
            }
            if matches!(s.mode, Mode::Obscura) && !s.steps.is_empty() {
                return Err(LoadError::new(
                    "config_invalid",
                    "navigation steps require browser mode",
                ));
            }
            if matches!(s.mode, Mode::Browser)
                && s.response_url_glob.as_ref().is_none_or(String::is_empty)
            {
                return Err(LoadError::new(
                    "config_invalid",
                    "browser workflows require a PDF response URL matcher",
                ));
            }
            crate::policy::NetworkPolicy::for_source(s)?;
        }
        Ok(())
    }
}
fn relative_secret(s: &mut Secret, base: &Path) {
    if let Some(file) = &mut s.file
        && file.is_relative()
    {
        *file = base.join(&*file);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn defaults_match_operator_limits() {
        let c = Config::default();
        assert_eq!(c.limits.max_bytes, 1073741824);
        assert!(c.conversion.enabled);
        assert_eq!(c.conversion.limits.max_pages, 25_000);
        assert_eq!(c.limits.timeout_secs, 1200);
        assert_eq!(c.limits.concurrency, 1);
    }
    #[test]
    fn duplicate_ids_and_zero_intervals_fail() {
        let mut c = Config::default();
        let s = Source::one_off("https://example.com/a".into(), Mode::Https);
        c.sources = vec![s.clone(), s];
        assert!(c.validate().is_err());
        c.sources.pop();
        c.sources[0].interval_secs = Some(0);
        assert!(c.validate().is_err());
    }
    #[test]
    fn secret_requires_single_input() {
        let s = Secret {
            literal: Some("private".into()),
            env: Some("NAME".into()),
            file: None,
        };
        assert_eq!(s.resolve().unwrap_err().code, "secret_config");
    }

    #[test]
    fn operator_files_reject_symlinks_and_special_files() {
        let dir = tempfile::tempdir_in("/tmp").unwrap();
        let path = dir.path().join("secret");
        std::fs::write(&path, "value\n").unwrap();
        assert_eq!(read_regular(&path, 64).unwrap(), "value\n");
        let link = dir.path().join("link");
        std::os::unix::fs::symlink(&path, &link).unwrap();
        assert!(read_regular(&link, 64).is_err());
        assert!(read_regular(Path::new("/dev/zero"), 64).is_err());
        assert!(read_regular(&path, 2).is_err());
    }
}
