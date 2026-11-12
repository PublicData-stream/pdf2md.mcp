#![allow(dead_code)]

use std::io::Write;

// Fully synthetic two-page PDF; offsets are generated rather than hard-coded.
pub fn sample_pdf() -> Vec<u8> {
    let page1 = b"BT /F1 12 Tf 40 700 Td (First page) Tj ET\nq 12 0 0 12 50 600 cm BI /W 1 /H 1 /CS /RGB /BPC 8 ID \xff\x00\x00 EI Q";
    let page2 = b"BT /F1 12 Tf 40 700 Td (Second page) Tj ET";
    let mut objects: Vec<Vec<u8>> = vec![
        b"<< /Type /Catalog /Pages 2 0 R >>".to_vec(),
        b"<< /Type /Pages /Kids [3 0 R 4 0 R] /Count 2 >>".to_vec(),
        b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Resources << /Font << /F1 5 0 R >> >> /Contents 6 0 R >>".to_vec(),
        b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Resources << /Font << /F1 5 0 R >> >> /Contents 7 0 R >>".to_vec(),
        b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>".to_vec(),
    ];
    for data in [page1.as_slice(), page2.as_slice()] {
        let mut stream = format!("<< /Length {} >>\nstream\n", data.len()).into_bytes();
        stream.extend_from_slice(data);
        stream.extend_from_slice(b"\nendstream");
        objects.push(stream);
    }
    build_pdf(objects)
}

fn build_pdf(objects: Vec<Vec<u8>>) -> Vec<u8> {
    build_pdf_with_trailer(objects, "")
}

fn build_pdf_with_trailer(objects: Vec<Vec<u8>>, extra: &str) -> Vec<u8> {
    let mut pdf = b"%PDF-1.4\n".to_vec();
    let mut offsets = vec![0usize];
    for (i, object) in objects.iter().enumerate() {
        offsets.push(pdf.len());
        writeln!(pdf, "{} 0 obj", i + 1).unwrap();
        pdf.extend_from_slice(object);
        pdf.extend_from_slice(b"\nendobj\n");
    }
    let xref = pdf.len();
    write!(pdf, "xref\n0 {}\n0000000000 65535 f \n", offsets.len()).unwrap();
    for offset in &offsets[1..] {
        writeln!(pdf, "{offset:010} 00000 n ").unwrap();
    }
    write!(
        pdf,
        "trailer\n<< /Size {} /Root 1 0 R {extra} >>\nstartxref\n{xref}\n%%EOF\n",
        offsets.len()
    )
    .unwrap();
    pdf
}

/// One synthetic Type1 font mapping a byte to a Korean Unicode character.
pub fn unicode_pdf() -> Vec<u8> {
    let content = b"BT /F1 12 Tf 40 700 Td <41> Tj ET";
    let cmap = b"/CIDInit /ProcSet findresource begin\n12 dict begin\nbegincmap\n/CIDSystemInfo << /Registry (Adobe) /Ordering (UCS) /Supplement 0 >> def\n/CMapName /Custom def\n/CMapType 2 def\n1 begincodespacerange\n<00> <FF>\nendcodespacerange\n1 beginbfchar\n<41> <AC00>\nendbfchar\nendcmap\nCMapName currentdict /CMap defineresource pop\nend\nend\n";
    let stream = |data: &[u8]| {
        let mut v = format!("<< /Length {} >>\nstream\n", data.len()).into_bytes();
        v.extend_from_slice(data);
        v.extend_from_slice(b"\nendstream");
        v
    };
    build_pdf(vec![
        b"<< /Type /Catalog /Pages 2 0 R >>".to_vec(),
        b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>".to_vec(),
        b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Resources << /Font << /F1 4 0 R >> >> /Contents 5 0 R >>".to_vec(),
        b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica /ToUnicode 6 0 R >>".to_vec(),
        stream(content), stream(cmap),
    ])
}

/// Text at different sizes and positions, with list and ruled table marks.
pub fn structure_pdf() -> Vec<u8> {
    let content = b"BT /F1 24 Tf 40 740 Td (Heading) Tj ET\nBT /F1 12 Tf 40 700 Td (Body text here.) Tj ET\nBT /F1 12 Tf 40 675 Td (- Item one) Tj ET\nBT /F1 12 Tf 40 655 Td (- Item two) Tj ET\n40 600 m 240 600 l S\n40 580 m 240 580 l S\n40 560 m 240 560 l S\n40 560 m 40 600 l S\n140 560 m 140 600 l S\n240 560 m 240 600 l S\nBT /F1 12 Tf 50 585 Td (Name) Tj ET\nBT /F1 12 Tf 150 585 Td (Value) Tj ET\nBT /F1 12 Tf 50 565 Td (One) Tj ET\nBT /F1 12 Tf 150 565 Td (Two) Tj ET";
    let mut stream = format!("<< /Length {} >>\nstream\n", content.len()).into_bytes();
    stream.extend_from_slice(content);
    stream.extend_from_slice(b"\nendstream");
    build_pdf(vec![
        b"<< /Type /Catalog /Pages 2 0 R >>".to_vec(),
        b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>".to_vec(),
        b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Resources << /Font << /F1 4 0 R >> >> /Contents 5 0 R >>".to_vec(),
        b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>".to_vec(), stream,
    ])
}

/// PDF image dictionary dimensions deliberately disagree with its JPEG header.
pub fn mismatched_jpeg_pdf() -> Vec<u8> {
    let pixels = vec![255u8; 2 * 2 * 3];
    let mut jpeg = Vec::new();
    image::codecs::jpeg::JpegEncoder::new(&mut jpeg)
        .encode(&pixels, 2, 2, image::ExtendedColorType::Rgb8)
        .unwrap();
    let content = b"q 10 0 0 10 10 10 cm /Im1 Do Q";
    let mut stream = format!("<< /Length {} >>\nstream\n", content.len()).into_bytes();
    stream.extend_from_slice(content);
    stream.extend_from_slice(b"\nendstream");
    let mut img = format!("<< /Type /XObject /Subtype /Image /Width 1 /Height 1 /ColorSpace /DeviceRGB /BitsPerComponent 8 /Filter /DCTDecode /Length {} >>\nstream\n", jpeg.len()).into_bytes();
    img.extend_from_slice(&jpeg);
    img.extend_from_slice(b"\nendstream");
    build_pdf(vec![
        b"<< /Type /Catalog /Pages 2 0 R >>".to_vec(),
        b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>".to_vec(),
        b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 100 100] /Resources << /XObject << /Im1 5 0 R >> >> /Contents 4 0 R >>".to_vec(),
        stream, img,
    ])
}

/// Legacy Standard encryption dictionary with a non-matching empty-password verifier.
pub fn encrypted_pdf() -> Vec<u8> {
    let encrypted = format!(
        "<< /Filter /Standard /V 1 /R 2 /O <{}> /U <{}> /P -4 >>",
        "00".repeat(32),
        "00".repeat(32)
    )
    .into_bytes();
    build_pdf_with_trailer(
        vec![
            b"<< /Type /Catalog /Pages 2 0 R >>".to_vec(),
            b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>".to_vec(),
            b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 100 100] /Contents 4 0 R >>".to_vec(),
            b"<< /Length 0 >>\nstream\n\nendstream".to_vec(),
            encrypted,
        ],
        "/Encrypt 5 0 R /ID [<01020304><01020304>]",
    )
}

pub fn outline_pdf() -> Vec<u8> {
    build_pdf(vec![
        b"<< /Type /Catalog /Pages 2 0 R /Outlines 4 0 R >>".to_vec(),
        b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>".to_vec(),
        b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 100 100] /Contents 6 0 R >>".to_vec(),
        b"<< /Type /Outlines /First 5 0 R /Last 5 0 R /Count 1 >>".to_vec(),
        b"<< /Title (Chapter) /Parent 4 0 R /Dest [3 0 R /Fit] /First 7 0 R /Last 7 0 R >>"
            .to_vec(),
        b"<< /Length 0 >>\nstream\n\nendstream".to_vec(),
        b"<< /Title (Section) /Parent 5 0 R /Dest [3 0 R /Fit] >>".to_vec(),
    ])
}
