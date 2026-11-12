//! Versioned, byte-addressed metadata for converted Markdown.
use crate::error::{LoadError, Result};
use pulldown_cmark::{Event, Options, Parser, Tag, TagEnd};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

pub const MAX_INDEX_BYTES: usize = 16 * 1024 * 1024;
pub const MAX_OUTLINE_BYTES: usize = 1024 * 1024;
pub const MAX_ENTRIES: usize = 100_000;
pub const MAX_OUTLINE_ENTRIES: usize = 10_000;
pub const MAX_OUTLINE_DEPTH: usize = 64;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TextIndex {
    pub version: u32,
    pub pages: Vec<PageSpan>,
    pub sections: Vec<TextSpan>,
    pub blocks: Vec<TextSpan>,
    pub structure_status: String,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PageSpan {
    pub page: u32,
    pub start: u64,
    pub end: u64,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TextSpan {
    pub id: String,
    pub kind: String,
    pub title: Option<String>,
    pub parent_id: Option<String>,
    pub start: u64,
    pub end: u64,
    pub start_line: u64,
    pub end_line: u64,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Outline {
    pub version: u32,
    pub status: String,
    pub entries: Vec<OutlineEntry>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OutlineEntry {
    pub title: String,
    pub page: Option<u32>,
    pub children: Vec<OutlineEntry>,
}

pub fn line_count(text: &str) -> u64 {
    if text.is_empty() {
        0
    } else {
        text.bytes().filter(|b| *b == b'\n').count() as u64 + u64::from(!text.ends_with('\n'))
    }
}
struct Lines<'a> {
    text: &'a str,
    counts: Vec<u64>,
}
impl<'a> Lines<'a> {
    fn new(text: &'a str) -> Self {
        let mut counts = vec![0];
        let mut n = 0;
        for chunk in text.as_bytes().chunks(4096) {
            n += chunk.iter().filter(|&&b| b == b'\n').count() as u64;
            counts.push(n);
        }
        Self { text, counts }
    }
    fn at(&self, offset: usize) -> u64 {
        let chunk = offset / 4096;
        1 + self.counts[chunk]
            + self.text.as_bytes()[chunk * 4096..offset]
                .iter()
                .filter(|&&b| b == b'\n')
                .count() as u64
    }
}
fn span(
    lines: &Lines<'_>,
    id: String,
    kind: String,
    title: Option<String>,
    parent_id: Option<String>,
    start: usize,
    end: usize,
) -> TextSpan {
    TextSpan {
        id,
        kind,
        title,
        parent_id,
        start: start as u64,
        end: end as u64,
        start_line: lines.at(start),
        end_line: lines.at(end.saturating_sub(1).max(start)),
    }
}
fn block_kind(tag: &Tag<'_>) -> Option<&'static str> {
    match tag {
        Tag::Paragraph => Some("paragraph"),
        Tag::Heading { .. } => Some("heading"),
        Tag::BlockQuote(_) => Some("blockquote"),
        Tag::CodeBlock(_) => Some("code_block"),
        Tag::HtmlBlock => Some("html_block"),
        Tag::List(_) => Some("list"),
        Tag::Item => Some("item"),
        Tag::FootnoteDefinition(_) => Some("footnote"),
        Tag::Table(_) => Some("table"),
        Tag::TableHead => Some("table_head"),
        Tag::TableRow => Some("table_row"),
        Tag::TableCell => Some("table_cell"),
        _ => None,
    }
}

pub(crate) fn build_index(
    text: &str,
    pages: Vec<PageSpan>,
    contents: &[(usize, usize)],
    max_entries: usize,
    max_bytes: usize,
) -> TextIndex {
    let lines = Lines::new(text);
    let mut index = TextIndex {
        version: 1,
        pages,
        sections: vec![],
        blocks: vec![],
        structure_status: "available".into(),
    };
    let mut headings: Vec<(usize, u32, String)> = Vec::new();
    let in_content = |offset: usize| {
        contents
            .partition_point(|&(start, _)| start <= offset)
            .checked_sub(1)
            .is_some_and(|i| offset < contents[i].1)
    };
    let mut stack: Vec<(TagEnd, Option<usize>)> = Vec::new();
    let mut heading: Option<(usize, u32, String)> = None;
    let options =
        Options::ENABLE_TABLES | Options::ENABLE_STRIKETHROUGH | Options::ENABLE_TASKLISTS;
    for (event, range) in Parser::new_ext(text, options).into_offset_iter() {
        match event {
            Event::Start(tag) => {
                let parent = stack.iter().rev().find_map(|(_, i)| *i);
                if let Tag::Heading { level, .. } = &tag
                    && parent.is_none()
                    && in_content(range.start)
                {
                    heading = Some((range.start, *level as u32, String::new()));
                }
                let block = if in_content(range.start) {
                    block_kind(&tag).map(|kind| {
                        let i = index.blocks.len();
                        index.blocks.push(span(
                            &lines,
                            format!("b{}", i + 1),
                            kind.into(),
                            None,
                            parent.map(|i| index.blocks[i].id.clone()),
                            range.start,
                            range.end,
                        ));
                        i
                    })
                } else {
                    None
                };
                stack.push((tag.to_end(), block));
            }
            Event::End(tag) => {
                if matches!(tag, TagEnd::Heading(_))
                    && let Some(h) = heading.take()
                {
                    headings.push(h);
                }
                if let Some((end, block)) = stack.pop() {
                    debug_assert_eq!(end, tag);
                    if let Some(i) = block {
                        index.blocks[i].end = range.end as u64;
                        index.blocks[i].end_line = lines.at(range
                            .end
                            .saturating_sub(1)
                            .max(index.blocks[i].start as usize));
                    }
                }
            }
            Event::Rule if in_content(range.start) => {
                let i = index.blocks.len();
                let parent = stack
                    .iter()
                    .rev()
                    .find_map(|(_, i)| *i)
                    .map(|i| index.blocks[i].id.clone());
                index.blocks.push(span(
                    &lines,
                    format!("b{}", i + 1),
                    "thematic_break".into(),
                    None,
                    parent,
                    range.start,
                    range.end,
                ));
            }
            Event::Text(t) | Event::Code(t) => {
                if let Some((_, _, title)) = &mut heading {
                    title.push_str(&t);
                }
            }
            Event::SoftBreak | Event::HardBreak => {
                if let Some((_, _, title)) = &mut heading {
                    title.push(' ');
                }
            }
            _ => {}
        }
        if index.blocks.len() + headings.len() > max_entries {
            index.blocks.clear();
            index.sections.clear();
            index.structure_status = "unavailable".into();
            return index;
        }
    }
    let mut ends = vec![text.len(); headings.len()];
    let mut pending: Vec<usize> = Vec::new();
    for (i, (start, level, _)) in headings.iter().enumerate() {
        while pending.last().is_some_and(|&j| headings[j].1 >= *level) {
            ends[pending.pop().unwrap()] = *start;
        }
        pending.push(i);
    }
    let mut parents: Vec<(u32, usize)> = Vec::new();
    for (i, (start, level, title)) in headings.iter().enumerate() {
        while parents.last().is_some_and(|(l, _)| l >= level) {
            parents.pop();
        }
        let end = ends[i];
        let parent = parents.last().map(|(_, n)| format!("s{}", n + 1));
        index.sections.push(span(
            &lines,
            format!("s{}", i + 1),
            format!("heading_{level}"),
            Some(title.clone()),
            parent,
            *start,
            end,
        ));
        parents.push((*level, i));
    }
    if serde_json::to_vec(&index).map_or(true, |v| v.len() > max_bytes) {
        index.sections.clear();
        index.blocks.clear();
        index.structure_status = "unavailable".into();
    }
    index
}

pub fn validate_index(index: &TextIndex, text: &str, pages: &[u32]) -> Result<()> {
    let lines = Lines::new(text);
    let invalid = || LoadError::new("worker_protocol", "invalid conversion metadata");
    if pages.is_empty()
        || pages.contains(&0)
        || pages.windows(2).any(|p| p[0] >= p[1])
        || index.version != 1
        || !matches!(index.structure_status.as_str(), "available" | "unavailable")
        || index.pages.len() != pages.len()
        || index.sections.len() + index.blocks.len() > MAX_ENTRIES
        || (index.structure_status == "unavailable"
            && (!index.sections.is_empty() || !index.blocks.is_empty()))
    {
        return Err(invalid());
    }
    let mut previous = 0usize;
    for (i, p) in index.pages.iter().enumerate() {
        let (Ok(s), Ok(e)) = (usize::try_from(p.start), usize::try_from(p.end)) else {
            return Err(invalid());
        };
        if p.page != pages[i]
            || s > e
            || e > text.len()
            || !text.is_char_boundary(s)
            || !text.is_char_boundary(e)
            || (i == 0 && s != 0)
            || (i > 0 && text.get(previous..s) != Some("\n\n---\n\n"))
            || !text[s..e].starts_with(&format!("<!-- pdf-page: {} -->\n\n", p.page))
        {
            return Err(invalid());
        }
        previous = e;
    }
    if text.get(previous..) != Some("\n") {
        return Err(invalid());
    }
    for (prefix, spans) in [("s", &index.sections), ("b", &index.blocks)] {
        let mut ids: HashMap<String, (usize, usize)> = HashMap::new();
        for (i, s) in spans.iter().enumerate() {
            let (Ok(a), Ok(b)) = (usize::try_from(s.start), usize::try_from(s.end)) else {
                return Err(invalid());
            };
            if s.id != format!("{prefix}{}", i + 1)
                || a >= b
                || b > text.len()
                || !text.is_char_boundary(a)
                || !text.is_char_boundary(b)
                || s.start_line != lines.at(a)
                || s.end_line != lines.at(b - 1)
                || s.parent_id
                    .as_ref()
                    .is_some_and(|p| ids.get(p).is_none_or(|&(start, end)| a < start || b > end))
                || index
                    .pages
                    .partition_point(|p| p.start <= s.start)
                    .checked_sub(1)
                    .is_none_or(|page| {
                        let p = &index.pages[page];
                        a < p.start as usize + format!("<!-- pdf-page: {} -->\n\n", p.page).len()
                            || a >= p.end as usize
                    })
            {
                return Err(invalid());
            }
            ids.insert(s.id.clone(), (a, b));
        }
    }
    Ok(())
}
pub fn validate_outline(outline: &Outline) -> Result<()> {
    fn walk(entries: &[OutlineEntry], depth: usize, count: &mut usize) -> bool {
        if depth > MAX_OUTLINE_DEPTH {
            return entries.is_empty();
        }
        for e in entries {
            *count += 1;
            if *count > MAX_OUTLINE_ENTRIES
                || e.page == Some(0)
                || !walk(&e.children, depth + 1, count)
            {
                return false;
            }
        }
        true
    }
    if outline.version != 1
        || !matches!(
            outline.status.as_str(),
            "available" | "absent" | "unavailable"
        )
        || (outline.status != "available" && !outline.entries.is_empty())
        || !walk(&outline.entries, 1, &mut 0)
    {
        return Err(LoadError::new(
            "worker_protocol",
            "invalid outline metadata",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn structures_respect_generated_boundaries_and_commonmark() {
        let one = "<!-- pdf-page: 1 -->\n\n# Main\n\n<!-- pdf-page: 9 -->\n\n```\n# not a heading\n```\n\n| a | b |\n|---|---|\n| c | d |";
        let two = "<!-- pdf-page: 2 -->\n\n## Sub\n\n- item\n  - nested\n";
        let text = format!("{one}\n\n---\n\n{two}\n");
        let start = one.len() + 7;
        let index = build_index(
            &text,
            vec![
                PageSpan {
                    page: 1,
                    start: 0,
                    end: one.len() as u64,
                },
                PageSpan {
                    page: 2,
                    start: start as u64,
                    end: (start + two.len()) as u64,
                },
            ],
            &[
                ("<!-- pdf-page: 1 -->\n\n".len(), one.len()),
                (start + "<!-- pdf-page: 2 -->\n\n".len(), start + two.len()),
            ],
            MAX_ENTRIES,
            MAX_INDEX_BYTES,
        );
        validate_index(&index, &text, &[1, 2]).unwrap();
        assert_eq!(index.sections.len(), 2);
        assert_eq!(index.sections[1].parent_id.as_deref(), Some("s1"));
        assert!(index.blocks.iter().any(|b| b.kind == "code_block"));
        assert!(index.blocks.iter().any(|b| b.kind == "table"));
        assert!(
            index
                .blocks
                .iter()
                .any(|b| b.kind == "item" && b.parent_id.is_some())
        );
        assert_eq!(index.pages.len(), 2);
        let mut invalid = index.clone();
        invalid.pages[1].start += 1;
        assert!(validate_index(&invalid, &text, &[1, 2]).is_err());
    }
    #[test]
    fn cross_page_code_fence_and_nested_headings_follow_document_context() {
        let a = "<!-- pdf-page: 1 -->\n\n- # Nested\n\n```\ncode";
        let b = "<!-- pdf-page: 2 -->\n\n# inside fence\n```\n\n# Real";
        let text = format!("{a}\n\n---\n\n{b}\n");
        let start = a.len() + 7;
        let index = build_index(
            &text,
            vec![
                PageSpan {
                    page: 1,
                    start: 0,
                    end: a.len() as u64,
                },
                PageSpan {
                    page: 2,
                    start: start as u64,
                    end: (start + b.len()) as u64,
                },
            ],
            &[
                ("<!-- pdf-page: 1 -->\n\n".len(), a.len()),
                (start + "<!-- pdf-page: 2 -->\n\n".len(), start + b.len()),
            ],
            MAX_ENTRIES,
            MAX_INDEX_BYTES,
        );
        validate_index(&index, &text, &[1, 2]).unwrap();
        assert_eq!(index.sections.len(), 1);
        assert_eq!(index.sections[0].title.as_deref(), Some("Real"));
        let code = index
            .blocks
            .iter()
            .find(|b| b.kind == "code_block")
            .unwrap();
        assert!(code.start < a.len() as u64 && code.end > start as u64);
        assert!(!index.blocks.iter().any(|b| b.kind == "thematic_break"));
    }
    #[test]
    fn outline_rejects_invalid_status_and_depth() {
        let mut entry = OutlineEntry {
            title: "x".into(),
            page: Some(1),
            children: vec![],
        };
        for _ in 0..MAX_OUTLINE_DEPTH {
            entry = OutlineEntry {
                title: "x".into(),
                page: None,
                children: vec![entry],
            };
        }
        assert!(
            validate_outline(&Outline {
                version: 1,
                status: "available".into(),
                entries: vec![entry]
            })
            .is_err()
        );
        assert!(
            validate_outline(&Outline {
                version: 1,
                status: "absent".into(),
                entries: vec![]
            })
            .is_ok()
        );
    }
}
