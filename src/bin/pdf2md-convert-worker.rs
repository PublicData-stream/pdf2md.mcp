fn main() {
    if pdf2md_mcp::conversion::worker::child_main().is_err() {
        std::process::exit(1);
    }
}
