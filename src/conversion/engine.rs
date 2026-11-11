//! In-memory PDF conversion. The caller owns all persistence.
use super::types::{ConversionLimits, ConversionOptions, WorkerSummary};
use crate::error::{LoadError, Result};
use pdf_oxide::{
    PdfDocument,
    converters::ConversionOptions as PdfOptions,
    extractors::images::{PdfFilter, PdfImageHandle},
};

fn failure(code: &str, message: &str) -> LoadError {
    LoadError::new(code, message)
}

fn preflight_image(handle: &PdfImageHandle<'_>, limits: &ConversionLimits) -> Result<()> {
    let pixels = u64::from(handle.width) * u64::from(handle.height);
    if pixels == 0 || pixels > limits.max_image_pixels {
        return Err(failure("image_limit", "image exceeds pixel limit"));
    }
    let jpeg = handle
        .filter_chain
        .iter()
        .any(|f| matches!(f, PdfFilter::DCTDecode));
    if handle
        .filter_chain
        .iter()
        .any(|f| matches!(f, PdfFilter::JPXDecode | PdfFilter::Other(_)))
    {
        return Err(failure("image_failed", "unsupported image filter"));
    }
    if jpeg {
        // Multi-filter streams and encrypted raw streams do not expose a verified JPEG header.
        if handle.filter_chain.as_slice() != [PdfFilter::DCTDecode] {
            return Err(failure("image_failed", "unsupported JPEG filter chain"));
        }
        let raw = handle
            .raw_compressed_bytes()
            .map_err(|_| failure("image_failed", "image metadata unavailable"))?;
        let (width, height) =
            image::ImageReader::with_format(std::io::Cursor::new(raw), image::ImageFormat::Jpeg)
                .into_dimensions()
                .map_err(|_| failure("image_failed", "invalid JPEG metadata"))?;
        if width != handle.width
            || height != handle.height
            || u64::from(width) * u64::from(height) > limits.max_image_pixels
        {
            return Err(failure(
                "image_limit",
                "image dimensions exceed declared bounds",
            ));
        }
    }
    Ok(())
}

pub fn convert(
    bytes: Vec<u8>,
    options: &ConversionOptions,
    limits: &ConversionLimits,
    mut emit: impl FnMut(&str, &[u8]) -> Result<()>,
) -> Result<WorkerSummary> {
    limits.validate()?;
    options.validate()?;
    if bytes.len() as u64 > limits.max_bytes {
        return Err(failure("input_limit", "PDF exceeds input limit"));
    }
    let doc = PdfDocument::from_bytes(bytes)
        .map_err(|_| failure("invalid_pdf", "PDF could not be parsed"))?;
    // An unreadable encrypted PDF otherwise produces successful empty Markdown upstream.
    if !doc.is_authenticated() {
        return Err(failure("encrypted_pdf", "PDF requires authentication"));
    }
    let count = doc
        .page_count()
        .map_err(|_| failure("invalid_pdf", "PDF page count unavailable"))?;
    if count == 0 {
        return Err(failure("invalid_pdf", "PDF has no pages"));
    }
    if count > limits.max_pages as usize {
        return Err(failure("page_limit", "PDF exceeds page limit"));
    }
    let pages: Vec<u32> = match &options.pages {
        None => (1..=count as u32).collect(),
        Some(p)
            if p.windows(2).all(|w| w[0] < w[1])
                && p.iter().all(|&v| v > 0 && v as usize <= count)
                && !p.is_empty() =>
        {
            p.clone()
        }
        Some(_) => return Err(failure("invalid_pages", "page selection is invalid")),
    };
    let mut total = 0u64;
    let mut markdown = String::new();
    let mut assets = 0usize;
    let mut warnings = Vec::new();
    let pdf_options = PdfOptions {
        include_images: false,
        ..Default::default()
    };
    for &page in &pages {
        if !markdown.is_empty() {
            markdown.push_str("\n\n---\n\n");
        }
        // Markdown's empty-page classifier can decode images itself, so preflight
        // before asking upstream to convert the page.
        let handles = doc
            .page_image_handles((page - 1) as usize)
            .map_err(|_| failure("image_failed", "image enumeration failed"))?;
        assets = assets
            .checked_add(handles.len())
            .ok_or_else(|| failure("output_limit", "too many assets"))?;
        if assets > 100_000 {
            return Err(failure("output_limit", "too many assets"));
        }
        for handle in &handles {
            preflight_image(handle, limits)?;
        }
        markdown.push_str(&format!("<!-- pdf-page: {page} -->\n\n"));
        let text = doc
            .to_markdown((page - 1) as usize, &pdf_options)
            .map_err(|_| failure("conversion_failed", "page conversion failed"))?;
        if text.trim().is_empty() {
            warnings.push(format!("no_text_page:{page}"));
        }
        markdown.push_str(text.trim_end());
        if total
            .checked_add(markdown.len() as u64)
            .is_none_or(|n| n > limits.max_output_bytes)
        {
            return Err(failure("output_limit", "conversion exceeds output limit"));
        }
        for (index, handle) in handles.iter().enumerate() {
            let image = handle
                .decode()
                .map_err(|_| failure("image_failed", "image decoding failed"))?;
            if image.width() != handle.width
                || image.height() != handle.height
                || u64::from(image.width()) * u64::from(image.height()) > limits.max_image_pixels
            {
                return Err(failure(
                    "image_limit",
                    "decoded image dimensions exceed bounds",
                ));
            }
            let png = image
                .to_png_bytes()
                .map_err(|_| failure("image_failed", "image encoding failed"))?;
            total = total
                .checked_add(png.len() as u64)
                .ok_or_else(|| failure("output_limit", "conversion exceeds output limit"))?;
            let path = format!("assets/page{page}_{}.png", index + 1);
            markdown.push_str(&format!(
                "\n\n![Image {} from page {page}]({path})",
                index + 1
            ));
            if total
                .checked_add(markdown.len() as u64)
                .is_none_or(|n| n > limits.max_output_bytes)
            {
                return Err(failure("output_limit", "conversion exceeds output limit"));
            }
            emit(&path, &png)?;
        }
    }
    markdown.push('\n');
    if total
        .checked_add(markdown.len() as u64)
        .is_none_or(|n| n > limits.max_output_bytes)
    {
        return Err(failure("output_limit", "conversion exceeds output limit"));
    }
    emit("document.md", markdown.as_bytes())?;
    // Do not expose upstream text, which can contain document content. Classification is explicit.
    if !doc.structured_warnings().is_empty() {
        warnings.push("parser_reported_warnings".to_string());
    }
    Ok(WorkerSummary { pages, warnings })
}
