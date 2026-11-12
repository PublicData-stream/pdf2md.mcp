use pdf2md_mcp::conversion::{
    engine,
    types::{ConversionLimits, ConversionOptions},
    worker,
};
use std::io::Write;
use tokio_util::sync::CancellationToken;

#[path = "common/conversion_pdf.rs"]
mod conversion_pdf;
use conversion_pdf::sample_pdf;

#[test]
fn selected_pages_produce_text_and_corresponding_png_assets() {
    let mut output = Vec::new();
    let summary = engine::convert(
        sample_pdf(),
        &ConversionOptions {
            pages: Some(vec![1]),
        },
        &ConversionLimits::default(),
        |path, data| {
            output.push((path.to_string(), data.to_vec()));
            Ok(())
        },
    )
    .unwrap();
    assert_eq!(summary.pages, vec![1]);
    let index: pdf2md_mcp::conversion::index::TextIndex = serde_json::from_slice(
        &output
            .iter()
            .find(|(p, _)| p == "text-index.json")
            .unwrap()
            .1,
    )
    .unwrap();
    let outline: pdf2md_mcp::conversion::index::Outline =
        serde_json::from_slice(&output.iter().find(|(p, _)| p == "outline.json").unwrap().1)
            .unwrap();
    assert_eq!(outline.status, "absent");
    assert_eq!(index.pages[0].page, 1);
    let (path, png) = output.iter().find(|(p, _)| p.ends_with(".png")).unwrap();
    assert_eq!(path, "assets/page1_1.png");
    assert!(png.starts_with(b"\x89PNG\r\n\x1a\n"));
    let markdown = String::from_utf8(
        output
            .iter()
            .find(|(p, _)| p == "document.md")
            .unwrap()
            .1
            .clone(),
    )
    .unwrap();
    pdf2md_mcp::conversion::index::validate_index(&index, &markdown, &[1]).unwrap();
    assert_eq!(
        markdown,
        "<!-- pdf-page: 1 -->\n\nFirst page\n\n![Image 1 from page 1](assets/page1_1.png)\n"
    );
}

#[test]
fn conversion_rejects_invalid_pages_and_invalid_limits() {
    let bad = ConversionOptions {
        pages: Some(vec![3]),
    };
    assert_eq!(
        engine::convert(sample_pdf(), &bad, &ConversionLimits::default(), |_, _| Ok(
            ()
        ))
        .unwrap_err()
        .code,
        "invalid_pages"
    );
    let limits = ConversionLimits {
        max_output_bytes: 1,
        ..Default::default()
    };
    assert_eq!(
        engine::convert(
            sample_pdf(),
            &ConversionOptions::default(),
            &limits,
            |_, _| Ok(())
        )
        .unwrap_err()
        .code,
        "config_invalid"
    );
}

#[tokio::test]
async fn subprocess_streams_artifacts_with_hashes() {
    let mut input = tempfile::tempfile().unwrap();
    input.write_all(&sample_pdf()).unwrap();
    let stage = tempfile::tempdir().unwrap();
    let (summary, artifacts) = worker::run(
        input,
        &ConversionOptions::default(),
        &ConversionLimits::default(),
        std::path::Path::new(env!("CARGO_BIN_EXE_pdf2md-convert-worker")),
        stage.path(),
        &CancellationToken::new(),
    )
    .await
    .unwrap();
    assert_eq!(summary.pages, vec![1, 2]);
    assert!(
        artifacts
            .iter()
            .any(|a| a.path == "document.md" && a.sha256.len() == 64)
    );
    assert!(artifacts.iter().any(|a| a.path == "assets/page1_1.png"));
}

#[cfg(unix)]
fn fake_worker(body: &str) -> (tempfile::TempDir, std::path::PathBuf) {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("worker");
    std::fs::write(&path, format!("#!/bin/sh\n{body}\n")).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
    (dir, path)
}

#[cfg(unix)]
async fn run_fake(body: &str, cancel: &CancellationToken, timeout_secs: u64) -> String {
    let (_dir, path) = fake_worker(body);
    let mut input = tempfile::tempfile().unwrap();
    input.write_all(b"%PDF-1.4\n").unwrap();
    let staging = tempfile::tempdir().unwrap();
    let limits = ConversionLimits {
        timeout_secs,
        ..Default::default()
    };
    worker::run(
        input,
        &ConversionOptions::default(),
        &limits,
        &path,
        staging.path(),
        cancel,
    )
    .await
    .unwrap_err()
    .code
}

#[cfg(unix)]
#[tokio::test]
async fn supervisor_rejects_unsafe_paths_and_oversized_headers() {
    let cancel = CancellationToken::new();
    assert_eq!(run_fake("/bin/cat >/dev/null; printf '%s\\n' '{\"kind\":\"artifact\",\"path\":\"../escape\",\"bytes\":0}'", &cancel, 5).await, "worker_protocol");
    assert_eq!(
        run_fake(
            "/bin/cat >/dev/null; /usr/bin/head -c 1048577 /dev/zero",
            &cancel,
            5
        )
        .await,
        "worker_protocol"
    );
    assert_eq!(run_fake("/bin/cat >/dev/null; printf '%s\\n' '{\"kind\":\"error\",\"code\":\"arbitrary secret\"}'", &cancel, 5).await, "worker_failed");
}

#[cfg(unix)]
#[tokio::test]
async fn supervisor_stops_on_deadline_and_cancellation() {
    let cancel = CancellationToken::new();
    assert_eq!(
        run_fake("exec /bin/sleep 30", &cancel, 1).await,
        "worker_timeout"
    );
    let cancel = CancellationToken::new();
    let trigger = cancel.clone();
    tokio::spawn(async move {
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        trigger.cancel();
    });
    assert_eq!(
        run_fake("exec /bin/sleep 30", &cancel, 5).await,
        "cancelled"
    );
}

#[cfg(unix)]
#[tokio::test]
async fn timed_out_worker_is_reaped() {
    let pid_dir = tempfile::tempdir().unwrap();
    let pid_path = pid_dir.path().join("pid");
    let body = format!("echo $$ > '{}'; exec /bin/sleep 30", pid_path.display());
    assert_eq!(
        run_fake(&body, &CancellationToken::new(), 1).await,
        "worker_timeout"
    );
    let pid: i32 = std::fs::read_to_string(pid_path)
        .unwrap()
        .trim()
        .parse()
        .unwrap();
    // SAFETY: signal zero probes the PID without delivering a signal.
    let result = unsafe { libc::kill(pid, 0) };
    assert_eq!(result, -1);
    assert_eq!(
        std::io::Error::last_os_error().raw_os_error(),
        Some(libc::ESRCH)
    );
}

#[test]
fn unicode_to_unicode_map_is_preserved() {
    let mut result = Vec::new();
    engine::convert(
        conversion_pdf::unicode_pdf(),
        &ConversionOptions::default(),
        &ConversionLimits::default(),
        |path, bytes| {
            if path == "document.md" {
                result.extend_from_slice(bytes);
            }
            Ok(())
        },
    )
    .unwrap();
    assert_eq!(
        String::from_utf8(result).unwrap(),
        "<!-- pdf-page: 1 -->\n\n가\n"
    );
}

#[test]
fn preserves_synthetic_heading_list_and_table() {
    let mut result = Vec::new();
    engine::convert(
        conversion_pdf::structure_pdf(),
        &ConversionOptions::default(),
        &ConversionLimits::default(),
        |path, bytes| {
            if path == "document.md" {
                result.extend_from_slice(bytes);
            }
            Ok(())
        },
    )
    .unwrap();
    assert_eq!(
        String::from_utf8(result).unwrap(),
        "<!-- pdf-page: 1 -->\n\n# Heading\n\nBody text here.\n\n- Item one\n- Item two\n\n| Name | Value |\n|---|---|\n| One | Two |\n"
    );
}

#[test]
fn rejects_image_over_pixel_limit_before_decode() {
    let mut pdf = sample_pdf();
    let needle = b"/W 1 /H 1";
    let pos = pdf
        .windows(needle.len())
        .position(|part| part == needle)
        .unwrap();
    pdf[pos + 3] = b'2';
    let limits = ConversionLimits {
        max_image_pixels: 1,
        ..Default::default()
    };
    assert_eq!(
        engine::convert(pdf, &ConversionOptions::default(), &limits, |_, _| Ok(()))
            .unwrap_err()
            .code,
        "image_limit"
    );
}

#[cfg(unix)]
#[tokio::test]
async fn staged_output_filesystem_failure_is_a_storage_error() {
    let (_dir, path) = fake_worker(
        "/bin/cat >/dev/null; printf '%s\\n' '{\"kind\":\"artifact\",\"path\":\"document.md\",\"bytes\":0}'",
    );
    let temp = tempfile::tempdir().unwrap();
    let input = tempfile::tempfile().unwrap();
    let err = worker::run(
        input,
        &ConversionOptions::default(),
        &ConversionLimits::default(),
        &path,
        &temp.path().join("missing"),
        &CancellationToken::new(),
    )
    .await
    .unwrap_err();
    assert_eq!(err.code, "storage_io");
}

#[cfg(unix)]
#[tokio::test]
async fn supervisor_rejects_declared_artifact_over_output_budget() {
    let (_dir, path) = fake_worker(
        "/bin/cat >/dev/null; printf '%s\\n' '{\"kind\":\"artifact\",\"path\":\"document.md\",\"bytes\":4097}'",
    );
    let stage = tempfile::tempdir().unwrap();
    let limits = ConversionLimits {
        max_output_bytes: 4096,
        ..Default::default()
    };
    let error = worker::run(
        tempfile::tempfile().unwrap(),
        &ConversionOptions::default(),
        &limits,
        &path,
        stage.path(),
        &CancellationToken::new(),
    )
    .await
    .unwrap_err();
    assert_eq!(error.code, "output_limit");
    assert!(!stage.path().join("document.md").exists());
}

#[cfg(unix)]
#[tokio::test]
async fn aborting_supervisor_kills_worker_process_group() {
    let pid_dir = tempfile::tempdir().unwrap();
    let parent_path = pid_dir.path().join("parent.pid");
    let child_path = pid_dir.path().join("child.pid");
    let body = format!(
        "echo $$ > '{}'; /bin/sleep 30 & echo $! > '{}'; wait",
        parent_path.display(),
        child_path.display()
    );
    let (_worker_dir, worker_path) = fake_worker(&body);
    let stage = tempfile::tempdir().unwrap();
    let stage_path = stage.path().to_path_buf();
    let task = tokio::spawn(async move {
        worker::run(
            tempfile::tempfile().unwrap(),
            &ConversionOptions::default(),
            &ConversionLimits::default(),
            &worker_path,
            &stage_path,
            &CancellationToken::new(),
        )
        .await
    });
    tokio::time::timeout(std::time::Duration::from_secs(5), async {
        while !parent_path.exists() || !child_path.exists() {
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("fixture worker started");
    let parent: i32 = std::fs::read_to_string(parent_path)
        .unwrap()
        .trim()
        .parse()
        .unwrap();
    let child: i32 = std::fs::read_to_string(child_path)
        .unwrap()
        .trim()
        .parse()
        .unwrap();
    task.abort();
    assert!(task.await.unwrap_err().is_cancelled());
    // An orphan may remain briefly as a zombie until the host reaps it; it is no longer executing.
    async fn stopped(pid: i32) {
        tokio::time::timeout(std::time::Duration::from_secs(5), async move {
            loop {
                let status = std::fs::read_to_string(format!("/proc/{pid}/status"));
                if status.as_ref().is_err()
                    || status.as_ref().is_ok_and(|s| {
                        s.lines()
                            .any(|l| l.starts_with("State:") && l.contains('Z'))
                    })
                {
                    break;
                }
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("process group stopped");
    }
    stopped(parent).await;
    stopped(child).await;
}

#[test]
fn rejects_jpeg_with_dimensions_larger_than_pdf_dictionary() {
    let limits = ConversionLimits {
        max_image_pixels: 1,
        ..Default::default()
    };
    let error = engine::convert(
        conversion_pdf::mismatched_jpeg_pdf(),
        &ConversionOptions::default(),
        &limits,
        |_, _| Ok(()),
    )
    .unwrap_err();
    assert_eq!(error.code, "image_limit");
}

#[test]
fn rejects_malformed_and_password_protected_pdf() {
    let run = |bytes| {
        engine::convert(
            bytes,
            &ConversionOptions::default(),
            &ConversionLimits::default(),
            |_, _| Ok(()),
        )
        .unwrap_err()
        .code
    };
    assert_eq!(run(b"not a PDF".to_vec()), "invalid_pdf");
    assert_eq!(run(conversion_pdf::encrypted_pdf()), "encrypted_pdf");
}

#[test]
fn accepts_jpeg_with_matching_bounded_dimensions() {
    let mut pdf = conversion_pdf::mismatched_jpeg_pdf();
    let needle = b"/Width 1 /Height 1";
    let pos = pdf
        .windows(needle.len())
        .position(|part| part == needle)
        .unwrap();
    pdf[pos + 7] = b'2';
    pdf[pos + 17] = b'2';
    let limits = ConversionLimits {
        max_image_pixels: 4,
        ..Default::default()
    };
    let mut has_png = false;
    engine::convert(
        pdf,
        &ConversionOptions::default(),
        &limits,
        |path, bytes| {
            if path.ends_with(".png") {
                has_png = bytes.starts_with(b"\x89PNG\r\n\x1a\n");
            }
            Ok(())
        },
    )
    .unwrap();
    assert!(has_png);
}

#[test]
fn pdf_bookmarks_are_exported_as_outline() {
    let mut output = Vec::new();
    engine::convert(
        conversion_pdf::outline_pdf(),
        &ConversionOptions::default(),
        &ConversionLimits::default(),
        |path, bytes| {
            output.push((path.to_string(), bytes.to_vec()));
            Ok(())
        },
    )
    .unwrap();
    let outline: pdf2md_mcp::conversion::index::Outline = serde_json::from_slice(
        &output
            .iter()
            .find(|(path, _)| path == "outline.json")
            .unwrap()
            .1,
    )
    .unwrap();
    assert_eq!(outline.status, "available");
    assert_eq!(outline.entries.len(), 1);
    assert_eq!(outline.entries[0].title, "Chapter");
}

#[test]
fn configured_metadata_limits_preserve_pages_and_report_overflow() {
    let limits = ConversionLimits {
        max_index_entries: 1,
        max_outline_depth: 1,
        ..Default::default()
    };
    let mut output = Vec::new();
    engine::convert(
        sample_pdf(),
        &ConversionOptions::default(),
        &limits,
        |path, data| {
            output.push((path.to_owned(), data.to_vec()));
            Ok(())
        },
    )
    .unwrap();
    let index: pdf2md_mcp::conversion::index::TextIndex = serde_json::from_slice(
        &output
            .iter()
            .find(|(p, _)| p == "text-index.json")
            .unwrap()
            .1,
    )
    .unwrap();
    assert_eq!(index.structure_status, "unavailable");
    assert!(index.sections.is_empty() && index.blocks.is_empty());
    assert_eq!(index.pages.len(), 2);
    output.clear();
    engine::convert(
        conversion_pdf::outline_pdf(),
        &ConversionOptions::default(),
        &limits,
        |path, data| {
            output.push((path.to_owned(), data.to_vec()));
            Ok(())
        },
    )
    .unwrap();
    let outline: pdf2md_mcp::conversion::index::Outline =
        serde_json::from_slice(&output.iter().find(|(p, _)| p == "outline.json").unwrap().1)
            .unwrap();
    assert_eq!(outline.status, "unavailable");
    assert!(outline.entries.is_empty());
}

#[test]
fn metadata_limits_default_and_reject_out_of_bounds() {
    let defaults: ConversionLimits = serde_json::from_str("{}").unwrap();
    defaults.validate().unwrap();
    let mut invalid = defaults.clone();
    invalid.max_index_bytes = 4095;
    assert!(invalid.validate().is_err());
    invalid = defaults;
    invalid.max_outline_depth += 1;
    assert!(invalid.validate().is_err());
}

#[test]
fn conversion_profile_keys_preserve_existing_sha256_identity() {
    assert_eq!(
        pdf2md_mcp::conversion::types::profile_key("abc", &ConversionOptions::default()).unwrap(),
        "e43b4c62576dce0385617b90889aa5397161ce28f8d89b55188eb806cb61cd20"
    );
    assert_eq!(
        pdf2md_mcp::conversion::types::profile_key(
            "abc",
            &ConversionOptions {
                pages: Some(vec![1, 3])
            }
        )
        .unwrap(),
        "3bb235454ff2f507a908aa8069f62b6709114529a05171eb6e4fbf5d69b66e54"
    );
}
