use crate::error::{LoadError, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub const CONVERTER: &str = "pdf_oxide/0.3.78;profile/2";
pub const MAX_ARTIFACTS: usize = 100_000;
pub const MAX_HEADER_BYTES: usize = 1024 * 1024;

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConversionOptions {
    pub pages: Option<Vec<u32>>,
}

impl ConversionOptions {
    pub fn parse_pages(value: &str) -> Result<Self> {
        let invalid = || LoadError::new("conversion_pages", "invalid page selection");
        let mut pages = std::collections::BTreeSet::new();
        for part in value.split(',') {
            let part = part.trim();
            let (first, last) = if let Some((a, b)) = part.split_once('-') {
                (
                    a.parse::<u32>().map_err(|_| invalid())?,
                    b.parse::<u32>().map_err(|_| invalid())?,
                )
            } else {
                let n = part.parse::<u32>().map_err(|_| invalid())?;
                (n, n)
            };
            if first == 0
                || last < first
                || last.saturating_sub(first) >= MAX_HEADER_BYTES as u32 / 12
            {
                return Err(invalid());
            }
            for page in first..=last {
                pages.insert(page);
                if pages.len() > MAX_HEADER_BYTES / 12 {
                    return Err(invalid());
                }
            }
        }
        if pages.is_empty() {
            return Err(invalid());
        }
        Ok(Self {
            pages: Some(pages.into_iter().collect()),
        })
    }

    pub fn validate(&self) -> Result<()> {
        if let Some(pages) = &self.pages
            && (pages.is_empty()
                || pages.len() > MAX_HEADER_BYTES / 12
                || pages[0] == 0
                || pages.windows(2).any(|p| p[0] >= p[1]))
        {
            return Err(LoadError::new("conversion_pages", "invalid page selection"));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ConversionLimits {
    pub max_bytes: u64,
    pub max_pages: u32,
    pub timeout_secs: u64,
    pub max_address_space_mib: u64,
    pub max_image_pixels: u64,
    pub max_output_bytes: u64,
    pub max_index_bytes: usize,
    pub max_index_entries: usize,
    pub max_outline_bytes: usize,
    pub max_outline_entries: usize,
    pub max_outline_depth: usize,
    pub concurrency: usize,
}

impl Default for ConversionLimits {
    fn default() -> Self {
        Self {
            max_bytes: 1024 * 1024 * 1024,
            max_pages: 25_000,
            timeout_secs: 3600,
            max_address_space_mib: 8192,
            max_image_pixels: 32_000_000,
            max_output_bytes: 1024 * 1024 * 1024,
            max_index_bytes: super::index::MAX_INDEX_BYTES,
            max_index_entries: super::index::MAX_ENTRIES,
            max_outline_bytes: super::index::MAX_OUTLINE_BYTES,
            max_outline_entries: super::index::MAX_OUTLINE_ENTRIES,
            max_outline_depth: super::index::MAX_OUTLINE_DEPTH,
            concurrency: 1,
        }
    }
}

impl ConversionLimits {
    pub fn validate(&self) -> Result<()> {
        if self.max_bytes == 0
            || self.max_bytes > i64::MAX as u64
            || self.max_pages == 0
            || self.timeout_secs == 0
            || self.timeout_secs > 31_536_000
            || self.max_address_space_mib == 0
            || self
                .max_address_space_mib
                .checked_mul(1024 * 1024)
                .is_none()
            || self.max_image_pixels == 0
            || self.max_output_bytes < 4096
            || self.max_output_bytes > i64::MAX as u64
            || !(4096..=super::index::MAX_INDEX_BYTES).contains(&self.max_index_bytes)
            || !(1..=super::index::MAX_ENTRIES).contains(&self.max_index_entries)
            || !(256..=super::index::MAX_OUTLINE_BYTES).contains(&self.max_outline_bytes)
            || !(1..=super::index::MAX_OUTLINE_ENTRIES).contains(&self.max_outline_entries)
            || !(1..=super::index::MAX_OUTLINE_DEPTH).contains(&self.max_outline_depth)
            || self.concurrency == 0
            || self.concurrency > 32
        {
            return Err(LoadError::new(
                "config_invalid",
                "invalid conversion resource limits",
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ConversionConfig {
    pub enabled: bool,
    pub limits: ConversionLimits,
}
impl Default for ConversionConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            limits: ConversionLimits::default(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Artifact {
    pub path: String,
    pub sha256: String,
    pub bytes: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConversionManifest {
    pub format_version: u32,
    pub document_id: String,
    pub converter: String,
    pub options: ConversionOptions,
    pub pages: Vec<u32>,
    pub warnings: Vec<String>,
    pub artifacts: Vec<Artifact>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConversionAttempt {
    pub id: String,
    pub document_id: String,
    pub profile_key: String,
    pub options: ConversionOptions,
    pub status: String,
    pub automatic: bool,
    pub created_at: String,
    pub finished_at: Option<String>,
    pub error_code: Option<String>,
    pub bundle_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkerSummary {
    pub pages: Vec<u32>,
    pub warnings: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkerJob {
    pub options: ConversionOptions,
    pub limits: ConversionLimits,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum WorkerFrame {
    Artifact {
        path: String,
        bytes: u64,
    },
    Complete {
        pages: Vec<u32>,
        warnings: Vec<String>,
    },
    Error {
        code: String,
    },
}

pub fn profile_key(document_id: &str, options: &ConversionOptions) -> Result<String> {
    profile_key_for(document_id, CONVERTER, options)
}

pub(crate) fn profile_key_for(
    document_id: &str,
    converter: &str,
    options: &ConversionOptions,
) -> Result<String> {
    options.validate()?;
    let value = serde_json::to_vec(&(document_id, converter, options))
        .map_err(|_| LoadError::new("conversion_options", "invalid conversion options"))?;
    Ok(format!("{:x}", Sha256::digest(value)))
}

/// Only application-generated relative asset names are accepted across IPC and storage.
pub fn valid_artifact_path(path: &str) -> bool {
    if matches!(path, "document.md" | "text-index.json" | "outline.json") {
        return true;
    }
    let Some(name) = path.strip_prefix("assets/page") else {
        return false;
    };
    let Some(name) = name.strip_suffix(".png") else {
        return false;
    };
    let Some((page, index)) = name.split_once('_') else {
        return false;
    };
    !page.is_empty()
        && !index.is_empty()
        && page.bytes().all(|b| b.is_ascii_digit())
        && index.bytes().all(|b| b.is_ascii_digit())
        && path.len() < 128
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn selections_are_normalized_and_bounded() {
        assert_eq!(
            ConversionOptions::parse_pages("3,1-2,2").unwrap().pages,
            Some(vec![1, 2, 3])
        );
        for value in ["", "0", "3-1", "1-4294967295", "1,", "-1"] {
            assert!(ConversionOptions::parse_pages(value).is_err());
        }
        assert!(!valid_artifact_path("assets/../../secret.png"));
        assert!(valid_artifact_path("assets/page1_0.png"));
    }
}
