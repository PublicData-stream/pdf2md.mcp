//! Read-only tools over the authenticated caller's verified conversion bundles.
use super::*;
use serde::Deserialize;
use serde_json::{Value, json};
use std::collections::HashSet;
use tokio::io::{AsyncReadExt, AsyncSeekExt};

pub struct ToolOutput {
    pub text: Option<String>,
    pub data: Value,
}

pub(super) struct ToolState {
    secret: String,
    #[allow(dead_code)]
    search: Arc<Semaphore>,
}
impl ToolState {
    pub(super) fn new(concurrency: usize) -> Self {
        Self {
            secret: uuid::Uuid::new_v4().to_string(),
            search: Arc::new(Semaphore::new(concurrency)),
        }
    }
    fn signature(&self, workspace: &Path, binding: &str, offset: usize) -> String {
        // Prefix and suffix the secret to prevent length extension of the keyed digest.
        let mut hash = Sha256::new();
        hash.update(self.secret.as_bytes());
        hash.update(workspace.as_os_str().as_encoded_bytes());
        hash.update(binding.as_bytes());
        hash.update(offset.to_be_bytes());
        hash.update(self.secret.as_bytes());
        hex::encode(hash.finalize())
    }
    fn encode(&self, workspace: &Path, binding: &str, offset: usize) -> String {
        format!("{offset}.{}", self.signature(workspace, binding, offset))
    }
    fn decode(&self, workspace: &Path, binding: &str, cursor: Option<&str>) -> Result<usize> {
        let Some(cursor) = cursor else { return Ok(0) };
        let (offset, signature) = cursor.split_once('.').ok_or_else(invalid_cursor)?;
        let offset = offset.parse().map_err(|_| invalid_cursor())?;
        if signature != self.signature(workspace, binding, offset) {
            return Err(invalid_cursor());
        }
        Ok(offset)
    }
}
fn invalid_cursor() -> LoadError {
    LoadError::new("invalid_cursor", "invalid or expired cursor")
}
fn invalid() -> LoadError {
    LoadError::new("invalid_arguments", "invalid tool arguments")
}
fn upgrade() -> LoadError {
    LoadError::new("upgrade_required", "conversion lacks indexed metadata")
}
fn output(data: Value) -> ToolOutput {
    ToolOutput { text: None, data }
}
fn parse<T: for<'de> Deserialize<'de>>(value: Value) -> Result<T> {
    serde_json::from_value(value).map_err(|_| invalid())
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Id {
    conversion_id: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PageArgs {
    conversion_id: String,
    pages: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ListArgs {
    kind: Option<String>,
    conversion_id: Option<String>,
    document_id: Option<String>,
    limit: Option<usize>,
    cursor: Option<String>,
}
#[derive(Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
enum Selector {
    Whole,
    Section { id: String },
    Block { id: String },
    Lines { start: u64, end: u64 },
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct MeasureArgs {
    conversion_id: String,
    selectors: Option<Vec<Selector>>,
}

#[derive(Deserialize, Serialize, Hash, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
enum StructureSelector {
    Section { id: String },
    Block { id: String },
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SectionArgs {
    conversion_id: String,
    selectors: Vec<StructureSelector>,
}

impl CallerService {
    pub async fn call_tool<'c>(
        &self,
        token: impl Into<Credentials<'c>>,
        name: &str,
        arguments: Value,
        cancel: &CancellationToken,
    ) -> Result<ToolOutput> {
        let token: Credentials<'c> = token.into();
        let workspace = self.authorize(token, false, false).await?;
        let _download_permit = self
            .downloads
            .clone()
            .try_acquire_owned()
            .map_err(|_| busy())?;
        if cancel.is_cancelled() {
            return Err(LoadError::new("cancelled", "operation cancelled"));
        }
        match name {
            "list" => self.tool_list(&workspace, parse(arguments)?).await,
            "read" => {
                let arg: Id = parse(arguments)?;
                let bundle = workspace
                    .store
                    .open_verified_bundle(&arg.conversion_id)
                    .await?;
                let text =
                    read_text(&bundle, "document.md", self.config.mcp.max_read_bytes).await?;
                Ok(ToolOutput {
                    data: json!({"conversion_id": arg.conversion_id, "document_id":bundle.manifest().document_id, "pages":bundle.manifest().pages, "bytes": text.len()}),
                    text: Some(text),
                })
            }
            "read-page" => self.tool_pages(&workspace, parse(arguments)?).await,
            "read-section" => self.tool_sections(&workspace, parse(arguments)?).await,
            "table" => self.tool_table(&workspace, parse(arguments)?).await,
            "count" | "size" => {
                self.tool_measure(&workspace, parse(arguments)?, name == "size")
                    .await
            }
            "rg" => {
                self.tool_search(&workspace, parse(arguments)?, cancel)
                    .await
            }
            _ => Err(LoadError::new("tool_not_found", "unknown tool")),
        }
    }
    async fn tool_list(
        &self,
        workspace: &AuthorizedWorkspace,
        arg: ListArgs,
    ) -> Result<ToolOutput> {
        let kind = arg.kind.as_deref().unwrap_or("documents");
        let limit = arg.limit.unwrap_or(self.config.mcp.list_default_limit);
        if limit == 0 || limit > self.config.mcp.list_max_limit {
            return Err(invalid());
        }
        let binding = serde_json::to_string(&(kind, &arg.conversion_id, &arg.document_id, limit))
            .map_err(|_| invalid())?;
        let offset =
            self.tool_state
                .decode(workspace.store.root(), &binding, arg.cursor.as_deref())?;
        let mut values: Vec<Value> = match kind {
            "documents" => {
                if arg.conversion_id.is_some() || arg.document_id.is_some() {
                    return Err(invalid());
                }
                let ids = workspace
                    .store
                    .tool_documents_page(limit + 1, offset)
                    .await?;
                let mut entries = Vec::with_capacity(ids.len());
                for id in ids {
                    let latest:Option<(String,String)>=sqlx::query_as("SELECT id,status FROM conversion_attempts WHERE namespace=$1 AND document_id=$2 ORDER BY created_at DESC,id DESC LIMIT 1")
                        .bind(&workspace.store.namespace).bind(&id).fetch_optional(&workspace.store.pool).await.map_err(crate::storage::db_error)?;
                    entries.push(json!({"document_id":id,"latest_conversion_id":latest.as_ref().map(|v|&v.0),"conversion_status":latest.as_ref().map(|v|v.1.as_str()).unwrap_or("not_requested")}));
                }
                entries
            }
            "conversions" => {
                if arg.conversion_id.is_some() {
                    return Err(invalid());
                }
                let attempts = workspace
                    .store
                    .conversion_history_page(arg.document_id.as_deref(), limit + 1, offset)
                    .await?;
                let mut entries = Vec::with_capacity(attempts.len());
                for attempt in attempts {
                    let mut value = serde_json::to_value(&attempt).expect("serializable attempt");
                    if attempt.status == "succeeded" {
                        let manifest = workspace
                            .store
                            .verified_conversion_manifest(&attempt.id)
                            .await?;
                        value["pages"] = json!(manifest.pages);
                        value["format_version"] = json!(manifest.format_version);
                        value["capabilities"] = if manifest.format_version >= 2 {
                            json!([
                                "read",
                                "read-page",
                                "read-section",
                                "table",
                                "rg",
                                "count",
                                "size",
                                "structure"
                            ])
                        } else {
                            json!(["read", "rg", "count", "size"])
                        };
                    }
                    entries.push(value);
                }
                entries
            }
            "sections" | "blocks" => {
                if arg.document_id.is_some() {
                    return Err(invalid());
                }
                let id = arg.conversion_id.as_deref().ok_or_else(invalid)?;
                let bundle = workspace.store.open_verified_bundle(id).await?;
                let index = indexed(&bundle).await?;
                require_structure(&index)?;
                let spans = if kind == "sections" {
                    index.sections
                } else {
                    index.blocks
                };
                spans
                    .into_iter()
                    .skip(offset)
                    .take(limit + 1)
                    .map(|v| serde_json::to_value(v).expect("serializable span"))
                    .collect()
            }
            _ => return Err(invalid()),
        };
        let more = values.len() > limit;
        values.truncate(limit);
        let next = more.then(|| {
            self.tool_state.encode(
                workspace.store.root(),
                &binding,
                offset.checked_add(limit).expect("bounded database offset"),
            )
        });
        Ok(output(
            json!({"kind":kind,"items":values,"next_cursor":next}),
        ))
    }
    async fn tool_sections(
        &self,
        workspace: &AuthorizedWorkspace,
        arg: SectionArgs,
    ) -> Result<ToolOutput> {
        if arg.selectors.is_empty() || arg.selectors.len() > 500 {
            return Err(invalid());
        }
        let mut seen = HashSet::new();
        if arg.selectors.iter().any(|s| !seen.insert(s)) {
            return Err(invalid());
        }
        let bundle = workspace
            .store
            .open_verified_bundle(&arg.conversion_id)
            .await?;
        let mut file = open_artifact(&bundle, "document.md").await?;
        let index =
            indexed_source(&bundle, Some(file.try_clone().await.map_err(io_error)?)).await?;
        require_structure(&index)?;
        let mut spans = Vec::with_capacity(arg.selectors.len());
        let mut total = 0u64;
        for selector in &arg.selectors {
            let (source, id) = match selector {
                StructureSelector::Section { id } => (&index.sections, id),
                StructureSelector::Block { id } => (&index.blocks, id),
            };
            let span = source
                .iter()
                .find(|span| &span.id == id)
                .ok_or_else(|| LoadError::new("selector_not_found", "selector unavailable"))?;
            total = total
                .checked_add(span.end - span.start)
                .filter(|&bytes| bytes <= self.config.mcp.max_read_bytes)
                .ok_or_else(|| LoadError::new("size_limit", "selected spans exceed read limit"))?;
            spans.push(span);
        }
        let mut results = Vec::with_capacity(spans.len());
        for (selector, span) in arg.selectors.iter().zip(spans) {
            let text = read_range(&mut file, span.start, span.end).await?;
            results.push(json!({"selector":selector,"span":span,"bytes":text.len(),"text":text}));
        }
        Ok(output(
            json!({"conversion_id":arg.conversion_id,"bytes":total,"results":results}),
        ))
    }
    async fn tool_pages(
        &self,
        workspace: &AuthorizedWorkspace,
        arg: PageArgs,
    ) -> Result<ToolOutput> {
        let requested = ConversionOptions::parse_pages(&arg.pages)?
            .pages
            .ok_or_else(invalid)?;
        let bundle = workspace
            .store
            .open_verified_bundle(&arg.conversion_id)
            .await?;
        let index = indexed(&bundle).await?;
        let mut ranges = Vec::with_capacity(requested.len());
        let mut total = 0u64;
        for page in requested {
            let span = index
                .pages
                .binary_search_by_key(&page, |p| p.page)
                .ok()
                .map(|i| &index.pages[i])
                .ok_or_else(|| LoadError::new("page_not_found", "requested page unavailable"))?;
            total = total
                .checked_add(span.end - span.start)
                .ok_or_else(invalid)?;
            if total > self.config.mcp.max_read_bytes {
                return Err(LoadError::new(
                    "size_limit",
                    "selected pages exceed read limit",
                ));
            }
            ranges.push((page, span.start, span.end));
        }
        let mut file = open_artifact(&bundle, "document.md").await?;
        let mut pages = Vec::with_capacity(ranges.len());
        for (page, start, end) in ranges {
            let text = read_range(&mut file, start, end).await?;
            pages.push(json!({"page":page,"text":text}));
        }
        Ok(output(
            json!({"conversion_id":arg.conversion_id,"pages":pages}),
        ))
    }
    async fn tool_table(&self, workspace: &AuthorizedWorkspace, arg: Id) -> Result<ToolOutput> {
        let bundle = workspace
            .store
            .open_verified_bundle(&arg.conversion_id)
            .await?;
        if bundle.manifest().format_version < 2 {
            return Err(upgrade());
        }
        let raw = read_text(&bundle, "outline.json", 1024 * 1024).await?;
        let outline: crate::conversion::index::Outline = serde_json::from_str(&raw)
            .map_err(|_| LoadError::new("storage_corrupt", "invalid outline"))?;
        crate::conversion::index::validate_outline(&outline)?;
        fn render(
            entries: &[crate::conversion::index::OutlineEntry],
            depth: usize,
            out: &mut String,
        ) {
            for entry in entries {
                let mut title = String::new();
                for ch in entry.title.chars() {
                    match ch {
                        '&' => title.push_str("&amp;"),
                        '<' => title.push_str("&lt;"),
                        '>' => title.push_str("&gt;"),
                        '\n' | '\r' => title.push(' '),
                        '\\' | '`' | '*' | '_' | '{' | '}' | '[' | ']' | '(' | ')' | '#' | '+'
                        | '-' | '.' | '!' | '|' => {
                            title.push('\\');
                            title.push(ch);
                        }
                        _ => title.push(ch),
                    }
                }
                let page = entry
                    .page
                    .map(|p| format!("page {p}"))
                    .unwrap_or_else(|| "destination unresolved".into());
                out.push_str(&format!("{}- {} ({})\n", "  ".repeat(depth), title, page));
                render(&entry.children, depth + 1, out);
            }
        }
        let mut text = String::new();
        render(&outline.entries, 0, &mut text);
        Ok(ToolOutput {
            text: Some(text),
            data: json!({"conversion_id":arg.conversion_id,"status":outline.status}),
        })
    }
    async fn tool_measure(
        &self,
        workspace: &AuthorizedWorkspace,
        arg: MeasureArgs,
        size: bool,
    ) -> Result<ToolOutput> {
        let bundle = workspace
            .store
            .open_verified_bundle(&arg.conversion_id)
            .await?;
        let selectors = arg.selectors.unwrap_or_else(|| vec![Selector::Whole]);
        if selectors.is_empty() || selectors.len() > 500 {
            return Err(invalid());
        }
        let needs_index = selectors
            .iter()
            .any(|s| matches!(s, Selector::Section { .. } | Selector::Block { .. }));
        if needs_index {
            let index = indexed(&bundle).await?;
            require_structure(&index)?;
            let mut spans = Vec::with_capacity(selectors.len());
            for sel in &selectors {
                let span = match sel {
                    Selector::Section { id } | Selector::Block { id } => {
                        let source = if matches!(sel, Selector::Section { .. }) {
                            &index.sections
                        } else {
                            &index.blocks
                        };
                        let span = source.iter().find(|v| &v.id == id).ok_or_else(|| {
                            LoadError::new("selector_not_found", "selector unavailable")
                        })?;
                        Some((span.start, span.end))
                    }
                    _ => None,
                };
                spans.push(span);
            }
            return measure_stream(&bundle, &arg.conversion_id, &selectors, &spans, size).await;
        }
        measure_stream(
            &bundle,
            &arg.conversion_id,
            &selectors,
            &vec![None; selectors.len()],
            size,
        )
        .await
    }
}

async fn measure_stream(
    bundle: &crate::conversion::store::VerifiedBundle,
    conversion_id: &str,
    selectors: &[Selector],
    spans: &[Option<(u64, u64)>],
    size: bool,
) -> Result<ToolOutput> {
    use std::collections::{BTreeSet, HashMap};
    let mut keys = Vec::new();
    let mut seen = HashSet::new();
    let mut line_targets = BTreeSet::new();
    let mut points = BTreeSet::new();
    for (i, s) in selectors.iter().enumerate() {
        let key = match s {
            Selector::Whole => "whole".to_owned(),
            Selector::Lines { start, end } if *start > 0 && end >= start && *end < u64::MAX => {
                line_targets.insert(*start);
                line_targets.insert(end + 1);
                format!("lines:{start}:{end}")
            }
            Selector::Section { id } | Selector::Block { id } => {
                let (a, b) = spans[i].ok_or_else(invalid)?;
                points.insert(a);
                points.insert(b);
                format!(
                    "{}:{id}",
                    if matches!(s, Selector::Section { .. }) {
                        "section"
                    } else {
                        "block"
                    }
                )
            }
            _ => return Err(invalid()),
        };
        if !seen.insert(key.clone()) {
            return Err(invalid());
        }
        keys.push(key);
    }
    let mut file = open_artifact(bundle, "document.md").await?;
    let mut positions = HashMap::new();
    let mut next = points.into_iter().peekable();
    let mut starts = HashMap::new();
    let mut bytes = 0u64;
    let mut lf = 0u64;
    let mut last = None;
    if line_targets.contains(&1) {
        starts.insert(1, 0u64);
    }
    let mut buffer = vec![0u8; 65536];
    loop {
        let n = file.read(&mut buffer).await.map_err(io_error)?;
        if n == 0 {
            break;
        }
        for &byte in &buffer[..n] {
            if next.peek() == Some(&bytes) {
                positions.insert(bytes, (lf, last));
                next.next();
            }
            bytes += 1;
            if byte == b'\n' {
                lf += 1;
                if line_targets.contains(&(lf + 1)) {
                    starts.insert(lf + 1, bytes);
                }
            }
            last = Some(byte);
        }
    }
    if next.peek() == Some(&bytes) {
        positions.insert(bytes, (lf, last));
        next.next();
    }
    if next.peek().is_some() {
        return Err(LoadError::new("storage_corrupt", "invalid text span"));
    }
    let total_lines = lf + u64::from(last.is_some() && last != Some(b'\n'));
    starts.insert(total_lines + 1, bytes);
    let mut results = Vec::with_capacity(selectors.len());
    for (i, s) in selectors.iter().enumerate() {
        let value = match s {
            Selector::Whole => {
                if size {
                    bytes
                } else {
                    total_lines
                }
            }
            Selector::Lines { start, end } => {
                if *end > total_lines {
                    return Err(LoadError::new(
                        "selector_not_found",
                        "line range unavailable",
                    ));
                }
                if size {
                    starts[&(end + 1)] - starts[start]
                } else {
                    end - start + 1
                }
            }
            Selector::Section { .. } | Selector::Block { .. } => {
                let (a, b) = spans[i].ok_or_else(invalid)?;
                if size {
                    b - a
                } else {
                    positions[&b].0 - positions[&a].0 + u64::from(positions[&b].1 != Some(b'\n'))
                }
            }
        };
        results.push(json!({"selector":keys[i],"value":value}));
    }
    Ok(output(
        json!({"conversion_id":conversion_id,"unit":if size {"bytes"} else {"lines"},"results":results}),
    ))
}
async fn open_artifact(
    bundle: &crate::conversion::store::VerifiedBundle,
    path: &str,
) -> Result<tokio::fs::File> {
    let index = bundle
        .manifest()
        .artifacts
        .iter()
        .position(|a| a.path == path)
        .ok_or_else(upgrade)?;
    let bundle = bundle.clone();
    let file = tokio::task::spawn_blocking(move || bundle.open_artifact(index))
        .await
        .map_err(|_| LoadError::new("storage_io", "artifact verification failed"))??;
    Ok(tokio::fs::File::from_std(file))
}
async fn read_text(
    bundle: &crate::conversion::store::VerifiedBundle,
    path: &str,
    max: u64,
) -> Result<String> {
    let artifact = bundle
        .manifest()
        .artifacts
        .iter()
        .find(|a| a.path == path)
        .ok_or_else(upgrade)?;
    if artifact.bytes > max {
        return Err(LoadError::new("size_limit", "artifact exceeds read limit"));
    }
    let mut file = open_artifact(bundle, path).await?;
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes).await.map_err(io_error)?;
    String::from_utf8(bytes).map_err(|_| LoadError::new("storage_corrupt", "artifact is not UTF-8"))
}
async fn read_range(file: &mut tokio::fs::File, start: u64, end: u64) -> Result<String> {
    file.seek(std::io::SeekFrom::Start(start))
        .await
        .map_err(io_error)?;
    let length =
        usize::try_from(end.checked_sub(start).ok_or_else(invalid)?).map_err(|_| invalid())?;
    let mut bytes = vec![0; length];
    file.read_exact(&mut bytes).await.map_err(io_error)?;
    String::from_utf8(bytes).map_err(|_| LoadError::new("storage_corrupt", "invalid text boundary"))
}
fn require_structure(index: &crate::conversion::index::TextIndex) -> Result<()> {
    if index.structure_status != "available" {
        return Err(LoadError::new(
            "metadata_unavailable",
            "Markdown structure index unavailable",
        ));
    }
    Ok(())
}
async fn indexed(
    bundle: &crate::conversion::store::VerifiedBundle,
) -> Result<crate::conversion::index::TextIndex> {
    indexed_source(bundle, None).await
}
async fn indexed_source(
    bundle: &crate::conversion::store::VerifiedBundle,
    source: Option<tokio::fs::File>,
) -> Result<crate::conversion::index::TextIndex> {
    use std::collections::{BTreeSet, HashMap};
    if bundle.manifest().format_version < 2 {
        return Err(upgrade());
    }
    let raw = read_text(bundle, "text-index.json", 16 * 1024 * 1024).await?;
    let index: crate::conversion::index::TextIndex = serde_json::from_str(&raw)
        .map_err(|_| LoadError::new("storage_corrupt", "invalid text index"))?;
    let corrupt = || LoadError::new("storage_corrupt", "invalid text index");
    let bytes = bundle
        .manifest()
        .artifacts
        .iter()
        .find(|a| a.path == "document.md")
        .ok_or_else(corrupt)?
        .bytes;
    if index.version != 1
        || index.pages.len() != bundle.manifest().pages.len()
        || !matches!(index.structure_status.as_str(), "available" | "unavailable")
        || index.sections.len() + index.blocks.len() > 100_000
        || (index.structure_status == "unavailable"
            && (!index.sections.is_empty() || !index.blocks.is_empty()))
    {
        return Err(corrupt());
    }
    let mut points = BTreeSet::new();
    let mut previous = 0u64;
    for (i, p) in index.pages.iter().enumerate() {
        if p.page != bundle.manifest().pages[i]
            || (i == 0 && p.start != 0)
            || (i > 0 && previous.checked_add(7) != Some(p.start))
            || p.start > p.end
            || p.end > bytes
            || p.start < previous
        {
            return Err(corrupt());
        }
        if p.end - p.start < format!("<!-- pdf-page: {} -->\n\n", p.page).len() as u64 {
            return Err(corrupt());
        }
        previous = p.end;
        points.insert(p.start);
        points.insert(p.end);
    }
    if index.pages.is_empty() || previous.checked_add(1) != Some(bytes) {
        return Err(corrupt());
    }
    let mut expected = Vec::with_capacity(index.pages.len() * 2 + 1);
    for (i, p) in index.pages.iter().enumerate() {
        if i > 0 {
            expected.push((index.pages[i - 1].end, b"\n\n---\n\n".to_vec()));
        }
        expected.push((
            p.start,
            format!("<!-- pdf-page: {} -->\n\n", p.page).into_bytes(),
        ));
    }
    expected.push((previous, b"\n".to_vec()));
    let mut expected = expected.into_iter().peekable();
    for (prefix, spans) in [("s", &index.sections), ("b", &index.blocks)] {
        let mut parents = HashMap::new();
        let mut previous_start = 0;
        for (i, span) in spans.iter().enumerate() {
            if span.id != format!("{prefix}{}", i + 1)
                || span.start >= span.end
                || span.end > bytes
                || span.start < previous_start
                || span.parent_id.as_ref().is_some_and(|p| {
                    parents
                        .get(p)
                        .is_none_or(|&(a, b)| span.start < a || span.end > b)
                })
            {
                return Err(corrupt());
            }
            let page = index
                .pages
                .partition_point(|p| p.start <= span.start)
                .checked_sub(1)
                .ok_or_else(corrupt)?;
            let p = &index.pages[page];
            if span.start < p.start + format!("<!-- pdf-page: {} -->\n\n", p.page).len() as u64
                || span.start >= p.end
            {
                return Err(corrupt());
            }
            previous_start = span.start;
            parents.insert(span.id.clone(), (span.start, span.end));
            points.insert(span.start);
            points.insert(span.end);
            points.insert(span.end - 1);
        }
    }
    // Check all recorded UTF-8 boundaries and source line positions in one
    // streaming pass; large documents never need to fit in the read budget.
    let mut file = match source {
        Some(file) => file,
        None => open_artifact(bundle, "document.md").await?,
    };
    let mut positions = HashMap::new();
    let mut next = points.into_iter().peekable();
    let mut position = 0u64;
    let mut lines = 0u64;
    let mut buf = vec![0u8; 65536];
    loop {
        let n = file.read(&mut buf).await.map_err(io_error)?;
        if n == 0 {
            break;
        }
        for &byte in &buf[..n] {
            while expected
                .peek()
                .is_some_and(|(start, data)| position >= *start + data.len() as u64)
            {
                expected.next();
            }
            if let Some((start, data)) = expected.peek()
                && position >= *start
                && byte != data[(position - *start) as usize]
            {
                return Err(corrupt());
            }
            if next.peek() == Some(&position) {
                positions.insert(position, (lines, byte & 0xc0 != 0x80));
                next.next();
            }
            if byte == b'\n' {
                lines += 1;
            }
            position += 1;
        }
    }
    if next.peek() == Some(&position) {
        positions.insert(position, (lines, true));
        next.next();
    }
    if position != bytes || next.peek().is_some() {
        return Err(corrupt());
    }
    for p in &index.pages {
        if !positions[&p.start].1 || !positions[&p.end].1 {
            return Err(corrupt());
        }
    }
    for span in index.sections.iter().chain(&index.blocks) {
        if !positions[&span.start].1
            || !positions[&span.end].1
            || span.start_line != positions[&span.start].0 + 1
            || span.end_line != positions[&(span.end - 1)].0 + 1
        {
            return Err(corrupt());
        }
    }
    Ok(index)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SearchArgs {
    pattern: String,
    conversion_ids: Option<Vec<String>>,
    case: Option<String>,
    literal: Option<bool>,
    word: Option<bool>,
    context: Option<u8>,
    limit: Option<usize>,
    cursor: Option<String>,
}
impl CallerService {
    async fn tool_search(
        &self,
        workspace: &AuthorizedWorkspace,
        arg: SearchArgs,
        cancel: &CancellationToken,
    ) -> Result<ToolOutput> {
        use std::process::Stdio;
        use tokio::{
            io::{AsyncBufReadExt, BufReader},
            process::Command,
        };
        let limit = arg.limit.unwrap_or(self.config.mcp.search_default_limit);
        let case = arg.case.as_deref().unwrap_or("sensitive");
        if arg.pattern.len() > 65536
            || arg.pattern.is_empty()
            || !matches!(case, "sensitive" | "insensitive" | "smart")
            || arg.context.unwrap_or(0) > 20
            || limit == 0
            || limit > self.config.mcp.search_max_limit
            || arg.conversion_ids.as_ref().is_some_and(|ids| {
                ids.len() > 1000
                    || ids.is_empty()
                    || ids.iter().collect::<HashSet<_>>().len() != ids.len()
            })
        {
            return Err(invalid());
        }
        let _permit = tokio::select! { _=cancel.cancelled()=>return Err(LoadError::new("cancelled","operation cancelled")), permit=self.tool_state.search.clone().acquire_owned()=>permit.map_err(|_| busy())? };
        let binding = serde_json::to_string(&(
            &arg.pattern,
            &arg.conversion_ids,
            case,
            arg.literal.unwrap_or(false),
            arg.word.unwrap_or(false),
            arg.context.unwrap_or(0),
            limit,
        ))
        .map_err(|_| invalid())?;
        let (cutoff, mut doc, mut record) = if let Some(cursor) = &arg.cursor {
            let parts: Vec<&str> = cursor.split('|').collect();
            if parts.len() != 4 {
                return Err(invalid_cursor());
            }
            let doc = parts[1].parse::<usize>().map_err(|_| invalid_cursor())?;
            let record = parts[2].parse::<usize>().map_err(|_| invalid_cursor())?;
            let signed = format!("{binding}|{}|{record}", parts[0]);
            if parts[3]
                != self
                    .tool_state
                    .signature(workspace.store.root(), &signed, doc)
            {
                return Err(invalid_cursor());
            }
            (parts[0].to_owned(), doc, record)
        } else {
            (chrono::Utc::now().to_rfc3339(), 0, 0)
        };
        let cursor_for = |doc: usize, record: usize| {
            let signed = format!("{binding}|{cutoff}|{record}");
            format!(
                "{cutoff}|{doc}|{record}|{}",
                self.tool_state
                    .signature(workspace.store.root(), &signed, doc)
            )
        };
        let deadline =
            tokio::time::Instant::now() + Duration::from_secs(self.config.mcp.search_timeout_secs);
        let mut validation = Command::new(&self.config.mcp.rg_path);
        validation
            .args(["--no-config", "--quiet", "-e"])
            .arg(&arg.pattern)
            .arg("-")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .env_remove("RIPGREP_CONFIG_PATH")
            .kill_on_drop(true);
        if arg.literal.unwrap_or(false) {
            validation.arg("--fixed-strings");
        }
        let mut child = validation
            .spawn()
            .map_err(|_| LoadError::new("search_unavailable", "search process unavailable"))?;
        let status = tokio::select! {
            _=cancel.cancelled()=>{let _=child.kill().await;let _=child.wait().await;return Err(LoadError::new("cancelled","operation cancelled"));},
            _=tokio::time::sleep_until(deadline)=>{let _=child.kill().await;let _=child.wait().await;return Ok(output(json!({"results":[],"partial":true,"incomplete_reason":"timeout","next_cursor":cursor_for(doc,record)})));},
            result=child.wait()=>result.map_err(io_error)?,
        };
        if !matches!(status.code(), Some(0 | 1)) {
            return Err(LoadError::new(
                "search_failed",
                "invalid search pattern or search process failure",
            ));
        }
        let mut results = Vec::new();
        macro_rules! bounded {
            ($operation:expr) => { tokio::select! {
                _=cancel.cancelled()=>return Err(LoadError::new("cancelled","operation cancelled")),
                _=tokio::time::sleep_until(deadline)=>return Ok(output(json!({"results":results,"partial":true,"incomplete_reason":"timeout","next_cursor":cursor_for(doc,record)}))),
                result=$operation=>result?,
            }};
        }
        let mut output_bytes = 2048u64;
        let mut matching_lines = 0usize;
        let mut scanned = 0usize;
        loop {
            if cancel.is_cancelled() {
                return Err(LoadError::new("cancelled", "operation cancelled"));
            }
            if tokio::time::Instant::now() >= deadline || scanned >= 1000 {
                return Ok(output(
                    json!({"results":results,"partial":true,"incomplete_reason":if scanned>=1000 {"scan_limit"} else {"timeout"},"next_cursor":cursor_for(doc,record)}),
                ));
            }
            let conversion_id = if let Some(ids) = &arg.conversion_ids {
                if doc >= ids.len() {
                    break;
                }
                ids[doc].clone()
            } else {
                let mut attempts = bounded!(workspace.store.conversion_history_page(None, 1, doc));
                let Some(attempt) = attempts.pop() else { break };
                if attempt.status != "succeeded"
                    || attempt.finished_at.as_deref().is_none_or(|finished| {
                        match (
                            chrono::DateTime::parse_from_rfc3339(finished),
                            chrono::DateTime::parse_from_rfc3339(&cutoff),
                        ) {
                            (Ok(a), Ok(b)) => a > b,
                            _ => true,
                        }
                    })
                {
                    doc += 1;
                    record = 0;
                    scanned += 1;
                    continue;
                }
                attempt.id
            };
            let bundle = bounded!(workspace.store.open_verified_bundle(&conversion_id));
            let path_index = bundle
                .manifest()
                .artifacts
                .iter()
                .position(|a| a.path == "document.md")
                .ok_or_else(upgrade)?;
            let copy = bundle.clone();
            let control = cancel.clone();
            let end = std::time::Instant::now()
                + deadline.saturating_duration_since(tokio::time::Instant::now());
            let mut input = bounded!(async {
                tokio::task::spawn_blocking(move || {
                    copy.open_artifact_bounded(path_index, &control, end)
                })
                .await
                .map_err(|_| LoadError::new("storage_io", "artifact verification failed"))?
            });
            let page_index = if bundle.manifest().format_version >= 2 {
                let clone = input.try_clone().map_err(io_error)?;
                let index = bounded!(indexed_source(
                    &bundle,
                    Some(tokio::fs::File::from_std(clone))
                ));
                std::io::Seek::seek(&mut input, std::io::SeekFrom::Start(0)).map_err(io_error)?;
                Some(index)
            } else {
                None
            };
            let mut command = Command::new(&self.config.mcp.rg_path);
            command.arg("--no-config").arg("--json").arg("--text");
            match case {
                "insensitive" => {
                    command.arg("--ignore-case");
                }
                "smart" => {
                    command.arg("--smart-case");
                }
                _ => {
                    command.arg("--case-sensitive");
                }
            }
            if arg.literal.unwrap_or(false) {
                command.arg("--fixed-strings");
            }
            if arg.word.unwrap_or(false) {
                command.arg("--word-regexp");
            }
            command
                .arg("--context")
                .arg(arg.context.unwrap_or(0).to_string())
                .arg("-e")
                .arg(&arg.pattern)
                .arg("-")
                .env_remove("RIPGREP_CONFIG_PATH")
                .stdin(Stdio::from(input))
                .stdout(Stdio::piped())
                .stderr(Stdio::null())
                .kill_on_drop(true);
            let mut child = command
                .spawn()
                .map_err(|_| LoadError::new("search_unavailable", "search process unavailable"))?;
            let stdout = child.stdout.take().ok_or_else(|| {
                LoadError::new("search_unavailable", "search process unavailable")
            })?;
            let mut reader = BufReader::new(stdout);
            let mut current = 0usize;
            let mut interrupted = None;
            let stream_result:Result<()> = async {
            loop {
                let mut line = Vec::new();
                let mut bounded =
                    (&mut reader).take(self.config.mcp.search_max_bytes.saturating_add(1));
                let read = tokio::select! {
                    _=cancel.cancelled()=>{interrupted=Some("cancelled");break},
                    _=tokio::time::sleep_until(deadline)=>{interrupted=Some("timeout");break},
                    value=bounded.read_until(b'\n',&mut line)=>value.map_err(io_error)?,
                };
                if read == 0 {
                    break;
                }
                if line.len() as u64 > self.config.mcp.search_max_bytes || !line.ends_with(b"\n") {
                    interrupted = Some("record_size_limit");
                    break;
                }
                let value: Value = serde_json::from_slice(&line).map_err(|_| {
                    LoadError::new("search_failed", "invalid search process output")
                })?;
                if !matches!(
                    value.get("type").and_then(Value::as_str),
                    Some("match" | "context")
                ) {
                    continue;
                }
                if current < record {
                    current += 1;
                    continue;
                }
                let is_match=value["type"]=="match";
                let absolute=value["data"]["absolute_offset"].as_u64();
                let page=absolute.and_then(|offset| page_index.as_ref().and_then(|idx| {
                    idx.pages.partition_point(|p|p.start<=offset).checked_sub(1).and_then(|i|idx.pages.get(i)).filter(|p|offset<p.end).map(|p|p.page)
                }));
                let event=json!({"conversion_id":conversion_id,"document_id":bundle.manifest().document_id,"page":page,"event":value});
                // Reserve JSON text fallback escaping plus structured content.
                let event_bytes=serde_json::to_vec(&event).map_err(|_| invalid())?.len() as u64*3+1;
                if (is_match && matching_lines >= limit)
                    || output_bytes.saturating_add(event_bytes) > self.config.mcp.search_max_bytes
                {
                    if results.is_empty() && output_bytes.saturating_add(event_bytes) > self.config.mcp.search_max_bytes {
                        return Err(LoadError::new("size_limit","search record exceeds output limit"));
                    }
                    interrupted = Some("result_limit");
                    break;
                }
                output_bytes += event_bytes;
                if is_match {matching_lines+=1;}
                results.push(event);
                current += 1;
            }
            Ok(())
            }.await;
            if let Err(error) = stream_result {
                let _ = child.kill().await;
                let _ = child.wait().await;
                return Err(error);
            }
            if let Some(reason) = interrupted {
                let _ = child.kill().await;
                let _ = child.wait().await;
                if reason == "cancelled" {
                    return Err(LoadError::new("cancelled", "operation cancelled"));
                }
                if reason == "record_size_limit" {
                    return Err(LoadError::new(
                        "size_limit",
                        "search record exceeds output limit",
                    ));
                }
                return Ok(output(
                    json!({"results":results,"partial":true,"incomplete_reason":reason,"next_cursor":cursor_for(doc,current)}),
                ));
            }
            let status = tokio::select! { _=cancel.cancelled()=>{let _=child.kill().await;let _=child.wait().await;return Err(LoadError::new("cancelled","operation cancelled"))}, _=tokio::time::sleep_until(deadline)=>{let _=child.kill().await;let _=child.wait().await;return Ok(output(json!({"results":results,"partial":true,"incomplete_reason":"timeout","next_cursor":cursor_for(doc,current)})))}, status=child.wait()=>status.map_err(io_error)? };
            if !matches!(status.code(), Some(0 | 1)) {
                return Err(LoadError::new("search_failed", "search process failed"));
            }
            doc += 1;
            record = 0;
            scanned += 1;
        }
        Ok(output(
            json!({"results":results,"partial":false,"incomplete_reason":null,"next_cursor":null}),
        ))
    }
}
