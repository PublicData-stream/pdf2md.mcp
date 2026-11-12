#[path = "common/conversion_pdf.rs"]
mod conversion_pdf;
use std::{
    fs,
    process::{Command, Output},
};

fn cli(root: &std::path::Path, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_pdf2md-mcp"))
        .args(["--data-dir", root.to_str().unwrap(), "--json"])
        .args(args)
        .env("TMPDIR", "/tmp")
        .output()
        .unwrap()
}
fn rows(bytes: &[u8]) -> Vec<serde_json::Value> {
    String::from_utf8_lossy(bytes)
        .lines()
        .filter(|l| !l.is_empty())
        .map(|l| serde_json::from_str(l).unwrap())
        .collect()
}
#[test]
fn automatic_conversion_preserves_acquisition_output_and_exports_selected_pages() {
    let dir = tempfile::tempdir_in("/tmp").unwrap();
    assert!(cli(dir.path(), &["scan"]).status.success());
    fs::write(
        dir.path().join("pdfs/sample.pdf"),
        conversion_pdf::sample_pdf(),
    )
    .unwrap();
    let accepted = cli(dir.path(), &["scan"]);
    assert!(
        accepted.status.success(),
        "{}",
        String::from_utf8_lossy(&accepted.stderr)
    );
    let acquired = rows(&accepted.stdout);
    assert_eq!(acquired.len(), 1);
    assert_eq!(acquired[0]["outcome"], "accepted");
    assert!(acquired[0].get("status").is_none());
    let auto = rows(&accepted.stderr);
    assert_eq!(auto.len(), 1);
    assert_eq!(auto[0]["status"], "succeeded");
    let document = acquired[0]["document_id"].as_str().unwrap();
    let converted = cli(dir.path(), &["convert", document, "--pages", "2"]);
    assert!(
        converted.status.success(),
        "{}",
        String::from_utf8_lossy(&converted.stderr)
    );
    let result = rows(&converted.stdout).remove(0);
    assert_eq!(result["status"], "succeeded");
    let id = result["id"].as_str().unwrap();
    let export = dir.path().join("exported");
    assert!(
        cli(
            dir.path(),
            &["export", id, "--output", export.to_str().unwrap()]
        )
        .status
        .success()
    );
    let markdown = fs::read_to_string(export.join("document.md")).unwrap();
    assert!(markdown.contains("Second page"));
    assert!(!markdown.contains("First page"));
    assert!(markdown.contains("<!-- pdf-page: 2 -->"));
    assert!(
        !cli(
            dir.path(),
            &["export", id, "--output", export.to_str().unwrap()]
        )
        .status
        .success()
    );
    let cached = rows(&cli(dir.path(), &["convert", document, "--pages", "2"]).stdout);
    assert_eq!(cached[0]["id"], id);
    let forced = rows(
        &cli(
            dir.path(),
            &["convert", document, "--pages", "2", "--force"],
        )
        .stdout,
    );
    assert_ne!(forced[0]["id"], id);
    let history = rows(&cli(dir.path(), &["conversion-history", document]).stdout);
    assert_eq!(history.len(), 3);
    assert_eq!(rows(&cli(dir.path(), &["history"]).stdout).len(), 1);
}

#[test]
fn parser_failure_keeps_pdf_and_requires_explicit_retry() {
    let dir = tempfile::tempdir_in("/tmp").unwrap();
    assert!(cli(dir.path(), &["scan"]).status.success());
    fs::write(
        dir.path().join("pdfs/malformed.pdf"),
        b"%PDF-1.7\nnot a complete PDF",
    )
    .unwrap();
    let accepted = cli(dir.path(), &["scan"]);
    assert!(accepted.status.success());
    let acquired = rows(&accepted.stdout).remove(0);
    let document = acquired["document_id"].as_str().unwrap();
    assert!(dir.path().join("objects").join(document).is_file());
    assert_eq!(rows(&accepted.stderr)[0]["status"], "failed");
    assert!(cli(dir.path(), &["scan"]).stdout.is_empty());
    assert_eq!(
        rows(&cli(dir.path(), &["conversion-history"]).stdout).len(),
        1
    );
    assert!(!cli(dir.path(), &["convert", document]).status.success());
    assert_eq!(
        rows(&cli(dir.path(), &["conversion-history"]).stdout).len(),
        2
    );
    assert!(
        fs::read_dir(dir.path().join("conversions"))
            .unwrap()
            .next()
            .is_none()
    );
}

#[test]
fn disabled_auto_can_be_overridden_by_explicit_conversion() {
    let dir = tempfile::tempdir_in("/tmp").unwrap();
    let config = dir.path().join("config.toml");
    fs::write(&config, "[conversion]\nenabled = false\n").unwrap();
    let args = ["--config", config.to_str().unwrap(), "scan"];
    assert!(cli(dir.path(), &args).status.success());
    fs::write(
        dir.path().join("pdfs/sample.pdf"),
        conversion_pdf::sample_pdf(),
    )
    .unwrap();
    let acquired = cli(dir.path(), &args);
    assert!(acquired.status.success());
    assert!(acquired.stderr.is_empty());
    assert!(cli(dir.path(), &["conversion-history"]).stdout.is_empty());
    let document = rows(&acquired.stdout)[0]["document_id"]
        .as_str()
        .unwrap()
        .to_owned();
    assert!(
        cli(
            dir.path(),
            &["--config", config.to_str().unwrap(), "convert", &document]
        )
        .status
        .success()
    );
}

#[test]
fn daemon_keeps_reads_responsive_and_preserves_unstarted_work_on_shutdown() {
    use std::{
        io::Write,
        os::unix::fs::PermissionsExt,
        thread,
        time::{Duration, Instant},
    };
    let dir = tempfile::tempdir_in("/tmp").unwrap();
    assert!(cli(dir.path(), &["scan"]).status.success());
    let worker = dir.path().join("slow-worker");
    let marker = dir.path().join("started");
    let stderr_path = dir.path().join("daemon-stderr.log");
    fs::write(&worker, format!("#!/usr/bin/python3\nimport os,sys,time\nsys.stdin.buffer.read()\nopen({:?},'w').write(str(os.getpid()))\ntime.sleep(60)\n", marker.to_str().unwrap())).unwrap();
    fs::set_permissions(&worker, fs::Permissions::from_mode(0o700)).unwrap();
    let mut child = Command::new(env!("CARGO_BIN_EXE_pdf2md-mcp"))
        .args([
            "--data-dir",
            dir.path().to_str().unwrap(),
            "--conversion-worker",
            worker.to_str().unwrap(),
            "watch",
        ])
        .stdout(std::process::Stdio::null())
        .stderr(fs::File::create(&stderr_path).unwrap())
        .spawn()
        .unwrap();
    struct Cleanup<'a>(&'a mut std::process::Child);
    impl Drop for Cleanup<'_> {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }
    let guard = Cleanup(&mut child);
    fs::write(
        dir.path().join("pdfs/first.pdf"),
        conversion_pdf::sample_pdf(),
    )
    .unwrap();
    let mut second = fs::File::create(dir.path().join("pdfs/second.pdf")).unwrap();
    second.write_all(&conversion_pdf::sample_pdf()).unwrap();
    second.write_all(b"\n% second version\n").unwrap();
    drop(second);
    let start = Instant::now();
    while !marker.exists() {
        assert!(
            start.elapsed() < Duration::from_secs(30),
            "worker did not start; daemon stderr: {}",
            fs::read_to_string(&stderr_path).unwrap_or_default()
        );
        if let Some(status) = guard.0.try_wait().unwrap() {
            panic!(
                "daemon exited with {status}; stderr: {}",
                fs::read_to_string(&stderr_path).unwrap_or_default()
            );
        }
        thread::sleep(Duration::from_millis(50));
    }
    let before_read = Instant::now();
    let attempts = rows(&cli(dir.path(), &["conversion-history"]).stdout);
    assert!(before_read.elapsed() < Duration::from_secs(5));
    assert_eq!(attempts.len(), 2);
    assert_eq!(
        attempts.iter().filter(|a| a["status"] == "running").count(),
        1
    );
    assert_eq!(
        attempts.iter().filter(|a| a["status"] == "pending").count(),
        1
    );
    unsafe {
        libc::kill(guard.0.id() as i32, libc::SIGTERM);
    }
    let start = Instant::now();
    let status = loop {
        if let Some(status) = guard.0.try_wait().unwrap() {
            break status;
        }
        assert!(
            start.elapsed() < Duration::from_secs(10),
            "daemon failed to shut down"
        );
        thread::sleep(Duration::from_millis(50));
    };
    assert!(status.success());
    let attempts = rows(&cli(dir.path(), &["conversion-history"]).stdout);
    assert_eq!(
        attempts
            .iter()
            .filter(|a| a["status"] == "cancelled")
            .count(),
        1
    );
    assert_eq!(
        attempts.iter().filter(|a| a["status"] == "pending").count(),
        1
    );
    let pid: i32 = fs::read_to_string(marker).unwrap().parse().unwrap();
    assert_eq!(unsafe { libc::kill(pid, 0) }, -1);
}
