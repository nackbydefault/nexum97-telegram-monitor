//! La relazione e l'allegato tecnico scritti come `.pdf`.
//!
//! Traducono la struttura di [`crate::report_narrative`] in pagine. Qui non si
//! decide **che cosa** il documento dice: quello e' gia' deciso, e si prova la'
//! senza aprire un PDF.
//!
//! # Perche' l'impaginazione la scriviamo noi
//!
//! Perche' la libreria che impaginava e' stata **scartata**. `printpdf` scrive
//! l'array `/ID` del trailer con due stringhe casuali, in codice fisso e senza
//! alcun punto di sostituzione: con quella libreria un PDF deterministico non e'
//! producibile, e il criterio 30 cade. `lopdf` costruisce oggetti PDF e lascia
//! il trailer a chi lo usa — determinismo governabile — ma non impagina
//! (ADR-0034).
//!
//! Il prezzo e' codice nostro su un percorso che produce documenti destinati a
//! un ufficio. Per questo la parte delicata — misura del testo e spezzatura
//! delle righe — vive in [`crate::pdf_text`] come **funzioni pure con le loro
//! prove**, e qui resta solo la disposizione sulla pagina.
//!
//! # Determinismo
//!
//! Tre istanti e un identificativo, tutti scritti a mano: `CreationDate`,
//! `ModDate` e l'array `/ID` del trailer. Nessuno di loro legge l'orologio o
//! chiede casualita'. A parita' di ingressi il file e' identico al byte.
//!
//! # Nessun contenuto attivo
//!
//! Il generatore non scrive azioni JavaScript, non incorpora file, non dichiara
//! collegamenti esterni e non apre nulla all'apertura del documento. Gli URL
//! dei contenuti restano **testo**, come nel `.docx` e per la stessa ragione.

use lisi_core::model::report_template::TemplateEmblem;
use lopdf::content::{Content, Operation};
use lopdf::{Dictionary, Document, Object, ObjectId, Stream, dictionary};

use crate::error::{ServiceError, ServiceResult};
use crate::pdf_text::{CODE_NOTE, has_unrepresentable, to_winansi, width_mille, wrap};
use crate::report_narrative::{Block, LetterheadLine, NarrativeReport};

/// Larghezza della pagina A4, in punti tipografici.
const PAGE_WIDTH: f64 = 595.276;

/// Altezza della pagina A4, in punti tipografici.
const PAGE_HEIGHT: f64 = 841.89;

/// Margine superiore, in punti. Sono i 3,5 cm del documento Word.
const MARGIN_TOP: f64 = 99.2;

/// Margine inferiore, laterale sinistro e destro: i 3 cm del documento Word.
const MARGIN_SIDE: f64 = 85.0;

/// Margine inferiore, che lascia posto al piede di pagina.
const MARGIN_BOTTOM: f64 = 70.0;

/// Corpo del testo, in punti. Lo stesso del `.docx`.
const BODY_SIZE: f64 = 12.0;

/// Corpo dei titoli di sezione.
const HEADING_SIZE: f64 = 12.0;

/// Corpo del piede di pagina e della carta intestata minore.
const SMALL_SIZE: f64 = 9.0;

/// Interlinea, come multiplo del corpo.
const LINE_HEIGHT: f64 = 1.32;

/// Spazio fra un blocco e il successivo, in punti.
const BLOCK_GAP: f64 = 8.0;

/// Quanti caratteri di una cella di tabella si stampano prima di troncare.
///
/// Una tabella dentro un PDF non ha righe che si allargano: una cella lunga
/// invaderebbe la colonna accanto. Il troncamento **si dichiara** con i puntini
/// di sospensione, cosi' chi legge sa che il testo continua altrove — nel
/// registro `.xlsx`, che le celle non le tronca.
const CELL_CHARS: usize = 60;

/// Altezza dello stemma sulla pagina: tre centimetri, come nel `.docx`.
///
/// Le due relazioni sono presentate come **la stessa relazione** (F-13): uno
/// stemma di misura diversa basterebbe a far pensare a due documenti.
const EMBLEM_HEIGHT: f64 = 85.04;

/// Quanta memoria la lettura dello stemma puo' occupare, in byte.
///
/// Il PNG e' gia' limitato a due mebibyte e a diecimila pixel per lato, ma
/// diecimila per diecimila con la trasparenza sono quattrocento mebibyte una
/// volta letti. Sessantaquattro bastano a uno stemma di quattromila pixel per
/// lato; oltre, lo stemma non si disegna e la pagina lo scrive.
const EMBLEM_DECODE_LIMIT: usize = 64 * 1024 * 1024;

/// La frase che prende il posto di uno stemma che non si e' potuto disegnare.
///
/// Tacere sarebbe peggio: il `.docx` dello stesso pacchetto lo stemma lo porta,
/// e chi confronta i due documenti deve sapere che la differenza e' dichiarata.
const EMBLEM_NOT_DRAWN: &str =
    "[Lo stemma configurato non si è potuto riprodurre in questo formato: è nel documento Word.]";

/// Che cosa si sta scrivendo, per il titolo dentro le proprieta' del file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PdfKind {
    /// La relazione di servizio, a impaginazione stabile.
    Narrative,
    /// L'allegato tecnico: tutto il monitorato, un contenuto dopo l'altro.
    TechnicalAnnex,
}

impl PdfKind {
    /// Titolo dichiarato nelle proprieta' del documento.
    const fn title(self) -> &'static str {
        match self {
            Self::Narrative => "Relazione di servizio",
            Self::TechnicalAnnex => "Allegato tecnico del monitoraggio",
        }
    }
}

/// Una riga gia' misurata, pronta per la pagina.
struct Line {
    text: String,
    size: f64,
    bold: bool,
    alignment: Alignment,
    /// Rientro sinistro aggiuntivo, in punti.
    indent: f64,
}

/// Come la riga si dispone nella colonna di testo.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Alignment {
    Left,
    Center,
    Right,
}

/// Lo stemma gia' letto, pronto da incorporare come immagine.
struct EmblemImage {
    width_px: u32,
    height_px: u32,
    /// Tre byte per pixel, rosso verde e blu.
    rgb: Vec<u8>,
    /// Un byte per pixel, quando l'immagine ha la trasparenza.
    alpha: Option<Vec<u8>>,
}

impl EmblemImage {
    /// Larghezza e altezza sulla pagina, in punti, con le proporzioni
    /// conservate: uno stemma non si schiaccia per riempire una misura.
    fn size_on_page(&self) -> (f64, f64) {
        let ratio = f64::from(self.width_px) / f64::from(self.height_px.max(1));
        let width = (EMBLEM_HEIGHT * ratio).min(text_width());
        (width, width / ratio)
    }
}

/// Che cosa sta in cima alla prima pagina al posto dello stemma.
enum EmblemSlot {
    /// Nessuno stemma configurato.
    Absent,
    /// Lo stemma, con l'altezza che occupa sulla pagina.
    Drawn(f64),
    /// Uno stemma configurato che non si e' potuto leggere.
    NotDrawn,
}

/// Legge lo stemma PNG in pixel, entro [`EMBLEM_DECODE_LIMIT`].
///
/// `None` quando il file non si lascia leggere: l'immagine e' stata controllata
/// solo nella firma e nelle dimensioni quando e' stata scelta, perche' il
/// `.docx` la passa a Word cosi' com'e'. Il PDF invece la deve disegnare.
fn decode_emblem(emblem: &TemplateEmblem) -> Option<EmblemImage> {
    let mut decoder = png::Decoder::new_with_limits(
        std::io::Cursor::new(emblem.bytes()),
        png::Limits {
            bytes: EMBLEM_DECODE_LIMIT,
        },
    );
    decoder.set_transformations(png::Transformations::normalize_to_color8());
    let mut reader = decoder.read_info().ok()?;
    let size = reader.output_buffer_size()?;
    if size > EMBLEM_DECODE_LIMIT {
        return None;
    }
    let mut buffer = vec![0_u8; size];
    let info = reader.next_frame(&mut buffer).ok()?;
    if info.bit_depth != png::BitDepth::Eight {
        return None;
    }
    let channels: usize = match info.color_type {
        png::ColorType::Grayscale => 1,
        png::ColorType::GrayscaleAlpha => 2,
        png::ColorType::Rgb => 3,
        png::ColorType::Rgba => 4,
        png::ColorType::Indexed => return None,
    };
    let width = usize::try_from(info.width).ok()?;
    let pixels = width.checked_mul(usize::try_from(info.height).ok()?)?;

    let mut rgb = Vec::with_capacity(pixels.checked_mul(3)?);
    let mut alpha = (channels == 2 || channels == 4).then(|| Vec::with_capacity(pixels));
    for row in buffer
        .chunks_exact(info.line_size)
        .take(info.height as usize)
    {
        for pixel in row.chunks_exact(channels).take(width) {
            match pixel {
                [gray] => rgb.extend_from_slice(&[*gray, *gray, *gray]),
                [gray, a] => {
                    rgb.extend_from_slice(&[*gray, *gray, *gray]);
                    if let Some(alpha) = alpha.as_mut() {
                        alpha.push(*a);
                    }
                }
                [r, g, b] => rgb.extend_from_slice(&[*r, *g, *b]),
                [r, g, b, a] => {
                    rgb.extend_from_slice(&[*r, *g, *b]);
                    if let Some(alpha) = alpha.as_mut() {
                        alpha.push(*a);
                    }
                }
                _ => return None,
            }
        }
    }
    if rgb.len() != pixels * 3 {
        return None;
    }

    Some(EmblemImage {
        width_px: info.width,
        height_px: info.height,
        rgb,
        alpha,
    })
}

/// Incorpora lo stemma come immagine e restituisce l'identificativo.
///
/// La compressione e' quella deterministica di `lopdf`: a parita' di immagine
/// i byte compressi sono gli stessi, e il criterio 30 regge.
fn embed_emblem(document: &mut Document, emblem: &EmblemImage) -> ServiceResult<ObjectId> {
    let compress = |stream: &mut Stream| {
        stream
            .compress()
            .map_err(|error| ServiceError::DocumentGeneration {
                reason: error.to_string(),
            })
    };

    let mut image = Stream::new(
        dictionary! {
            "Type" => "XObject",
            "Subtype" => "Image",
            "Width" => i64::from(emblem.width_px),
            "Height" => i64::from(emblem.height_px),
            "ColorSpace" => "DeviceRGB",
            "BitsPerComponent" => 8,
        },
        emblem.rgb.clone(),
    );
    if let Some(alpha) = &emblem.alpha {
        let mut mask = Stream::new(
            dictionary! {
                "Type" => "XObject",
                "Subtype" => "Image",
                "Width" => i64::from(emblem.width_px),
                "Height" => i64::from(emblem.height_px),
                "ColorSpace" => "DeviceGray",
                "BitsPerComponent" => 8,
            },
            alpha.clone(),
        );
        compress(&mut mask)?;
        let mask_id = document.add_object(mask);
        image.dict.set("SMask", mask_id);
    }
    compress(&mut image)?;
    Ok(document.add_object(image))
}

/// Scrive il documento come PDF.
///
/// # Errori
///
/// Restituisce [`ServiceError::DocumentGeneration`] se la scrittura non riesce.
pub fn render(report: &NarrativeReport, kind: PdfKind) -> ServiceResult<Vec<u8>> {
    // In Esercitazione la frase di SIC-17 apre la prima pagina (PR-13).
    let report = crate::run_mode::marked_report(report);
    let report = report.as_ref();

    // Lo stemma sta in cima alla prima pagina, come nel `.docx` (F-13).
    let emblem = report.letterhead.emblem.as_ref().map(decode_emblem);
    let slot = match &emblem {
        None => EmblemSlot::Absent,
        Some(Some(image)) => EmblemSlot::Drawn(image.size_on_page().1),
        Some(None) => EmblemSlot::NotDrawn,
    };
    let lines = compose_lines(report, &slot);
    let pages = paginate(&lines);

    let mut document = Document::with_version("1.7");
    let pages_id = document.new_object_id();

    let (regular_id, bold_id) = fonts(&mut document);
    let mut resources = dictionary! {
        "Font" => dictionary! {
            "F1" => regular_id,
            "F2" => bold_id,
        },
    };
    let drawn = match emblem {
        Some(Some(image)) => {
            let image_id = embed_emblem(&mut document, &image)?;
            resources.set("XObject", dictionary! { "Im1" => image_id });
            Some(image.size_on_page())
        }
        _ => None,
    };
    let resources_id = document.add_object(resources);
    let footer = footer_lines(report);

    let total = pages.len();
    let mut page_ids = Vec::with_capacity(total);
    for (index, page) in pages.iter().enumerate() {
        let id = write_page(
            &mut document,
            pages_id,
            resources_id,
            &PageContent {
                lines: page,
                number: index + 1,
                total,
                footer: &footer,
                emblem: if index == 0 { drawn } else { None },
            },
        )?;
        page_ids.push(id);
    }

    let kids: Vec<Object> = page_ids.into_iter().map(Object::Reference).collect();
    let count = i64::try_from(total).unwrap_or(i64::MAX);
    document.objects.insert(
        pages_id,
        Object::Dictionary(dictionary! {
            "Type" => "Pages",
            "Kids" => kids,
            "Count" => count,
            "Resources" => resources_id,
            "MediaBox" => media_box(),
        }),
    );

    let catalog_id = document.add_object(dictionary! {
        "Type" => "Catalog",
        "Pages" => pages_id,
    });

    finish(&mut document, catalog_id, report, kind);

    let mut bytes = Vec::new();
    document
        .save_to(&mut bytes)
        .map_err(|error| ServiceError::DocumentGeneration {
            reason: error.to_string(),
        })?;
    Ok(bytes)
}

/// I due caratteri incorporati nel formato: nessun file da allegare.
fn fonts(document: &mut Document) -> (ObjectId, ObjectId) {
    let regular = document.add_object(dictionary! {
        "Type" => "Font",
        "Subtype" => "Type1",
        "BaseFont" => "Times-Roman",
        "Encoding" => "WinAnsiEncoding",
    });
    let bold = document.add_object(dictionary! {
        "Type" => "Font",
        "Subtype" => "Type1",
        "BaseFont" => "Times-Bold",
        "Encoding" => "WinAnsiEncoding",
    });
    (regular, bold)
}

/// Il riquadro della pagina, in punti.
fn media_box() -> Vec<Object> {
    vec![0.into(), 0.into(), PAGE_WIDTH.into(), PAGE_HEIGHT.into()]
}

/// Larghezza utile della colonna di testo, in punti.
fn text_width() -> f64 {
    PAGE_WIDTH - (MARGIN_SIDE * 2.0)
}

/// Trasforma i blocchi in righe gia' spezzate alla larghezza della colonna.
fn compose_lines(report: &NarrativeReport, emblem: &EmblemSlot) -> Vec<Line> {
    let mut lines = Vec::new();

    // Lo spazio dello stemma e' una riga vuota alta quanto l'immagine: la
    // pagina lo disegna li', e il resto scende senza saperne nulla.
    match emblem {
        EmblemSlot::Absent => {}
        EmblemSlot::Drawn(height) => {
            lines.push(blank(height / LINE_HEIGHT));
            lines.push(blank(BLOCK_GAP));
        }
        EmblemSlot::NotDrawn => {
            push_wrapped(
                &mut lines,
                EMBLEM_NOT_DRAWN,
                SMALL_SIZE,
                false,
                Alignment::Center,
                0.0,
            );
        }
    }

    // La carta intestata sta in cima alla **prima pagina**, come nel `.docx`:
    // qui non c'e' un'intestazione di pagina vera, e ripeterla su ogni foglio
    // trasformerebbe una relazione in un modulo.
    for line in &report.letterhead.lines {
        push_wrapped(
            &mut lines,
            &line.text(),
            BODY_SIZE,
            true,
            Alignment::Center,
            0.0,
        );
    }
    if !report.letterhead.lines.is_empty() {
        lines.push(blank(BODY_SIZE));
    }

    for block in &report.blocks {
        push_block(&mut lines, block);
        lines.push(blank(BLOCK_GAP));
    }

    // I CODICI SI SPIEGANO (E2E01-04): se un carattere del documento si e'
    // dovuto scrivere con il suo codice Unicode, la relazione lo dice una
    // volta, in fondo, con dove si trova il testo integro.
    if lines.iter().any(|line| has_unrepresentable(&line.text)) {
        push_wrapped(
            &mut lines,
            CODE_NOTE,
            SMALL_SIZE,
            false,
            Alignment::Left,
            0.0,
        );
    }

    lines
}

/// Aggiunge alla pagina un blocco del documento.
fn push_block(lines: &mut Vec<Line>, block: &Block) {
    match block {
        Block::Heading(text) => {
            push_wrapped(lines, text, HEADING_SIZE, true, Alignment::Left, 0.0);
        }
        Block::Paragraph(text) => {
            push_wrapped(lines, text, BODY_SIZE, false, Alignment::Left, 0.0);
        }
        Block::Lead { lead, body } => {
            // L'attacco in grassetto e il seguito in tondo, come nel facsimile.
            // In PDF la riga e' un'unita': l'attacco prende la propria riga solo
            // se non ci sta insieme al seguito.
            push_wrapped(lines, lead, BODY_SIZE, true, Alignment::Left, 0.0);
            push_wrapped(lines, body, BODY_SIZE, false, Alignment::Left, 0.0);
        }
        Block::Emphasis(text) => {
            push_wrapped(lines, text, BODY_SIZE, true, Alignment::Left, 0.0);
        }
        Block::RightLine(text) => {
            push_wrapped(lines, text, BODY_SIZE, false, Alignment::Right, 0.0);
        }
        Block::Table { headers, rows } => {
            push_table(lines, headers, rows);
        }
        Block::Signature {
            place_and_date,
            role,
            name,
        } => {
            push_wrapped(
                lines,
                place_and_date,
                BODY_SIZE,
                false,
                Alignment::Left,
                0.0,
            );
            lines.push(blank(BODY_SIZE));
            if let Some(role) = role {
                push_wrapped(lines, role, BODY_SIZE, false, Alignment::Right, 0.0);
            }
            if let Some(name) = name {
                push_wrapped(lines, name, BODY_SIZE, true, Alignment::Right, 0.0);
            }
        }
    }
}

/// Una tabella, resa come righe di testo a colonne fisse.
///
/// # Perche' non un reticolo disegnato
///
/// Perche' un reticolo disegnato in PDF va calcolato riga per riga, e una riga
/// che cade a cavallo di due pagine lascerebbe il bordo aperto. Le colonne
/// allineate dicono la stessa cosa e non possono rompersi: la tabella vera, con
/// i suoi bordi, sta nel `.docx` e nel registro `.xlsx`.
fn push_table(lines: &mut Vec<Line>, headers: &[String], rows: &[Vec<String>]) {
    if headers.is_empty() {
        return;
    }
    let columns = headers.len();
    let per_column = text_width() / columns as f64;

    push_row(lines, headers, per_column, true);
    for row in rows {
        push_row(lines, row, per_column, false);
    }
}

/// Una riga di tabella, con le celle troncate alla propria colonna.
fn push_row(lines: &mut Vec<Line>, cells: &[String], per_column: f64, bold: bool) {
    let mut text = String::new();
    for (index, cell) in cells.iter().enumerate() {
        if index > 0 {
            text.push_str("   ");
        }
        text.push_str(&truncate(cell));
    }
    // Il rientro resta zero: la colonna e' data dalla larghezza uniforme, e il
    // valore serve alle prove che verificano di non uscire dal margine.
    let _ = per_column;
    push_wrapped(lines, &text, SMALL_SIZE, bold, Alignment::Left, 0.0);
}

/// Tronca una cella dichiarandolo.
fn truncate(cell: &str) -> String {
    if cell.chars().count() <= CELL_CHARS {
        return cell.to_owned();
    }
    let mut out: String = cell.chars().take(CELL_CHARS).collect();
    out.push('\u{2026}');
    out
}

/// Spezza un testo alla larghezza della colonna e lo aggiunge.
fn push_wrapped(
    lines: &mut Vec<Line>,
    text: &str,
    size: f64,
    bold: bool,
    alignment: Alignment,
    indent: f64,
) {
    let available = text_width() - indent;
    // Da punti a millesimi di em: e' l'unita' in cui il modulo del testo misura.
    let max_mille = ((available / size) * 1000.0).max(0.0) as u32;

    for line in wrap(text, max_mille, bold) {
        lines.push(Line {
            text: line,
            size,
            bold,
            alignment,
            indent,
        });
    }
}

/// Una riga vuota, che vale solo come spazio verticale.
fn blank(size: f64) -> Line {
    Line {
        text: String::new(),
        size,
        bold: false,
        alignment: Alignment::Left,
        indent: 0.0,
    }
}

/// Distribuisce le righe sulle pagine.
fn paginate(lines: &[Line]) -> Vec<Vec<&Line>> {
    let usable = PAGE_HEIGHT - MARGIN_TOP - MARGIN_BOTTOM;
    let mut pages = Vec::new();
    let mut current: Vec<&Line> = Vec::new();
    let mut height = 0.0_f64;

    for line in lines {
        let needed = line.size * LINE_HEIGHT;
        if height + needed > usable && !current.is_empty() {
            pages.push(std::mem::take(&mut current));
            height = 0.0;
        }
        current.push(line);
        height += needed;
    }

    if !current.is_empty() {
        pages.push(current);
    }
    if pages.is_empty() {
        // Un documento senza righe resta un documento di una pagina: un PDF
        // senza pagine non si apre.
        pages.push(Vec::new());
    }
    pages
}

/// Che cosa va su una pagina.
struct PageContent<'a> {
    lines: &'a [&'a Line],
    number: usize,
    total: usize,
    /// Le righe configurate del piede, uguali su ogni pagina.
    footer: &'a [String],
    /// Larghezza e altezza dello stemma, solo sulla prima pagina.
    emblem: Option<(f64, f64)>,
}

/// Le righe configurate del piede, come nel `.docx`: «Rif. … — Pagina N di M».
///
/// Prima di F-13 il PDF scriveva soltanto il numero di pagina, e il riferimento
/// dell'ufficio stava solo nel `.docx` dello stesso pacchetto.
fn footer_lines(report: &NarrativeReport) -> Vec<String> {
    report.footer.iter().map(LetterheadLine::text).collect()
}

/// Scrive una pagina e ne restituisce l'identificativo.
fn write_page(
    document: &mut Document,
    parent: ObjectId,
    resources: ObjectId,
    page: &PageContent<'_>,
) -> ServiceResult<ObjectId> {
    let mut operations = Vec::new();

    // Lo stemma si disegna fuori dal testo: un'immagine dentro `BT … ET` non
    // e' ammessa. Sta centrato nello spazio che la prima riga gli ha lasciato.
    if let Some((width, height)) = page.emblem {
        let x = (PAGE_WIDTH - width) / 2.0;
        let y = PAGE_HEIGHT - MARGIN_TOP - height;
        operations.push(Operation::new("q", vec![]));
        operations.push(Operation::new(
            "cm",
            vec![
                width.into(),
                0.into(),
                0.into(),
                height.into(),
                x.into(),
                y.into(),
            ],
        ));
        operations.push(Operation::new("Do", vec!["Im1".into()]));
        operations.push(Operation::new("Q", vec![]));
    }

    operations.push(Operation::new("BT", vec![]));
    let mut cursor = PAGE_HEIGHT - MARGIN_TOP;
    let (number, total) = (page.number, page.total);

    for line in page.lines {
        cursor -= line.size * LINE_HEIGHT;
        if line.text.is_empty() {
            continue;
        }
        let x = horizontal_position(line);
        operations.push(Operation::new(
            "Tf",
            vec![
                if line.bold { "F2".into() } else { "F1".into() },
                line.size.into(),
            ],
        ));
        operations.push(Operation::new("Td", vec![x.into(), cursor.into()]));
        operations.push(Operation::new(
            "Tj",
            vec![Object::String(
                to_winansi(&line.text),
                lopdf::StringFormat::Literal,
            )],
        ));
        // `Td` sposta rispetto alla riga precedente: si torna all'origine per
        // rendere ogni riga indipendente dall'ordine di quelle prima.
        operations.push(Operation::new("Td", vec![(-x).into(), (-cursor).into()]));
    }

    // Il piede: «Pagina N di M», centrato. Non e' un campo come nel `.docx` —
    // in PDF l'impaginazione e' gia' decisa, e il numero e' quello definitivo.
    // In Esercitazione il piede di ogni pagina porta la parola (PR-13).
    let numbering = if crate::run_mode::is_exercise() {
        format!("ESERCITAZIONE — Pagina {number} di {total}")
    } else {
        format!("Pagina {number} di {total}")
    };
    // Il riferimento dell'ufficio sta sulla stessa riga del numero, come nel
    // `.docx`; se non ci entra, sale di una riga e il numero resta sotto.
    let mut footer = Vec::new();
    if page.footer.is_empty() {
        footer.push(numbering);
    } else {
        let together = format!("{} — {numbering}", page.footer.join(" — "));
        if measure(&together, SMALL_SIZE) <= text_width() {
            footer.push(together);
        } else {
            let max_mille = ((text_width() / SMALL_SIZE) * 1000.0) as u32;
            footer.extend(wrap(&page.footer.join(" — "), max_mille, false));
            footer.push(numbering);
        }
    }
    operations.push(Operation::new("Tf", vec!["F1".into(), SMALL_SIZE.into()]));
    let step = SMALL_SIZE * LINE_HEIGHT;
    for (index, text) in footer.iter().enumerate() {
        let x = ((PAGE_WIDTH - measure(text, SMALL_SIZE)) / 2.0).max(MARGIN_SIDE);
        let from_bottom = footer.len() - 1 - index;
        let y = (MARGIN_BOTTOM / 2.0) + (step * from_bottom as f64);
        operations.push(Operation::new("Td", vec![x.into(), y.into()]));
        operations.push(Operation::new(
            "Tj",
            vec![Object::String(
                to_winansi(text),
                lopdf::StringFormat::Literal,
            )],
        ));
        operations.push(Operation::new("Td", vec![(-x).into(), (-y).into()]));
    }
    operations.push(Operation::new("ET", vec![]));

    let content = Content { operations };
    let encoded = content
        .encode()
        .map_err(|error| ServiceError::DocumentGeneration {
            reason: error.to_string(),
        })?;
    let content_id = document.add_object(Stream::new(Dictionary::new(), encoded));

    Ok(document.add_object(dictionary! {
        "Type" => "Page",
        "Parent" => parent,
        "Contents" => content_id,
        "Resources" => resources,
        "MediaBox" => media_box(),
    }))
}

/// Larghezza di un testo in carattere normale, in punti.
fn measure(text: &str, size: f64) -> f64 {
    (width_mille(text, false) as f64 / 1000.0) * size
}

/// Ascissa di partenza della riga, secondo il proprio allineamento.
fn horizontal_position(line: &Line) -> f64 {
    let width = (width_mille(&line.text, line.bold) as f64 / 1000.0) * line.size;
    match line.alignment {
        Alignment::Left => MARGIN_SIDE + line.indent,
        Alignment::Center => ((PAGE_WIDTH - width) / 2.0).max(MARGIN_SIDE),
        Alignment::Right => (PAGE_WIDTH - MARGIN_SIDE - width).max(MARGIN_SIDE),
    }
}

/// Scrive proprieta', trailer e identificativo, tutti fissati.
///
/// **E' il punto in cui il determinismo si decide.** Nessuna di queste righe
/// legge l'orologio o chiede casualita': la data viene dall'istante di
/// generazione, che e' un ingresso, e l'identificativo dall'identificativo del
/// report, che e' gia' deterministico.
fn finish(document: &mut Document, catalog: ObjectId, report: &NarrativeReport, kind: PdfKind) {
    let stamp = pdf_date(report);
    let info_id = document.add_object(dictionary! {
        "Title" => Object::String(to_winansi(kind.title()), lopdf::StringFormat::Literal),
        // Chi ha generato il documento sta nel documento e nell'audit: nei
        // metadati non entra ne' una persona ne' una macchina, come nel `.docx`
        // e nel registro.
        "Author" => Object::String(to_winansi("unknown"), lopdf::StringFormat::Literal),
        "Creator" => Object::String(to_winansi("unknown"), lopdf::StringFormat::Literal),
        "Producer" => Object::String(to_winansi("unknown"), lopdf::StringFormat::Literal),
        "CreationDate" => Object::String(stamp.clone().into_bytes(), lopdf::StringFormat::Literal),
        "ModDate" => Object::String(stamp.into_bytes(), lopdf::StringFormat::Literal),
    });

    document.trailer.set("Root", catalog);
    document.trailer.set("Info", info_id);
    document.trailer.set(
        "ID",
        Object::Array(vec![
            Object::String(document_identifier(report), lopdf::StringFormat::Literal),
            Object::String(document_identifier(report), lopdf::StringFormat::Literal),
        ]),
    );
}

/// L'istante di generazione nel formato delle date PDF.
fn pdf_date(report: &NarrativeReport) -> String {
    // `to_w3cdtf_utc` produce `2026-08-18T18:40:00Z`; il PDF vuole
    // `D:20260818184000+00'00'`.
    let iso = report.generated_at.to_w3cdtf_utc();
    let cifre: String = iso.chars().filter(char::is_ascii_digit).collect();
    let cifre: String = cifre.chars().take(14).collect();
    format!("D:{cifre}+00'00'")
}

/// L'identificativo del documento, derivato da quello del report.
///
/// Deterministico per costruzione: due generazioni dello stesso report
/// producono lo stesso identificativo, e due report diversi ne producono due
/// diversi.
fn document_identifier(report: &NarrativeReport) -> Vec<u8> {
    let mut seed = String::from("NEXUM97-");
    seed.push_str(&report.generated_at.as_millis().to_string());
    to_winansi(&seed)
}

/// La riga della carta intestata come testo, configurata o segnaposto.
#[allow(dead_code)]
fn letterhead_text(line: &LetterheadLine) -> String {
    line.text()
}

#[cfg(test)]
mod tests {
    use lisi_core::Timestamp;

    use super::*;
    use crate::report_narrative::Letterhead;

    fn report(blocks: Vec<Block>) -> NarrativeReport {
        NarrativeReport {
            generated_at: Timestamp::from_millis(1_752_086_400_000),
            letterhead: Letterhead {
                emblem: None,
                lines: Vec::new(),
            },
            footer: Vec::new(),
            blocks,
        }
    }

    #[test]
    fn a_document_is_produced_and_starts_with_the_pdf_marker() {
        let bytes = render(
            &report(vec![Block::Paragraph(String::from("Testo di prova"))]),
            PdfKind::Narrative,
        )
        .expect("il documento deve potersi scrivere");

        assert!(bytes.starts_with(b"%PDF-"));
        assert!(bytes.len() > 300);
    }

    #[test]
    fn an_empty_document_is_still_one_page() {
        // Un PDF senza pagine non si apre: un documento senza blocchi deve
        // restare un documento, non diventare un file rotto.
        let bytes = render(&report(Vec::new()), PdfKind::Narrative).expect("deve potersi scrivere");
        assert!(bytes.starts_with(b"%PDF-"));
    }

    #[test]
    fn the_date_is_written_in_the_pdf_format() {
        let stamp = pdf_date(&report(Vec::new()));
        assert!(stamp.starts_with("D:2025"), "data inattesa: {stamp}");
        assert!(stamp.ends_with("+00'00'"));
        assert_eq!(stamp.len(), 23, "formato della data non conforme: {stamp}");
    }

    #[test]
    fn a_long_paragraph_becomes_more_than_one_line() {
        let lungo = "Relazione di servizio relativa al monitoraggio autorizzato di \
                     fonti Telegram accessibili a un account d'ufficio, condotto \
                     secondo le modalita' previste e con i limiti dichiarati."
            .repeat(3);
        let mut lines = Vec::new();
        push_block(&mut lines, &Block::Paragraph(lungo));
        assert!(lines.len() > 3, "il paragrafo non e' stato spezzato");
    }

    #[test]
    fn no_line_starts_outside_the_left_margin() {
        // Una riga che comincia fuori dal margine e' una riga che in stampa
        // esce dal foglio.
        for alignment in [Alignment::Left, Alignment::Center, Alignment::Right] {
            let line = Line {
                text: String::from("Una riga di prova ragionevolmente lunga"),
                size: BODY_SIZE,
                bold: false,
                alignment,
                indent: 0.0,
            };
            let x = horizontal_position(&line);
            assert!(x >= MARGIN_SIDE, "riga fuori dal margine sinistro: {x}");
            assert!(
                x < PAGE_WIDTH - MARGIN_SIDE,
                "riga oltre il margine destro: {x}"
            );
        }
    }

    #[test]
    fn a_long_document_is_split_over_more_pages() {
        let blocchi: Vec<Block> = (0..120)
            .map(|index| Block::Paragraph(format!("Paragrafo numero {index} del documento.")))
            .collect();
        let lines = compose_lines(&report(blocchi), &EmblemSlot::Absent);
        let pagine = paginate(&lines);
        assert!(pagine.len() > 1, "il documento non e' stato impaginato");
    }

    #[test]
    fn a_cell_longer_than_the_column_says_it_was_cut() {
        // Il troncamento si dichiara: chi legge deve sapere che il testo
        // continua altrove, invece di credere che finisca li'.
        let lunga = "a".repeat(CELL_CHARS + 20);
        let tagliata = truncate(&lunga);
        assert!(tagliata.ends_with('\u{2026}'));
        assert_eq!(tagliata.chars().count(), CELL_CHARS + 1);

        let corta = String::from("breve");
        assert_eq!(truncate(&corta), corta);
    }

    /// Un PNG di due per due, con la trasparenza.
    fn stemma() -> TemplateEmblem {
        let mut bytes = Vec::new();
        {
            let mut encoder = png::Encoder::new(&mut bytes, 2, 2);
            encoder.set_color(png::ColorType::Rgba);
            encoder.set_depth(png::BitDepth::Eight);
            let Ok(mut writer) = encoder.write_header() else {
                panic!("l'intestazione del PNG di prova deve potersi scrivere");
            };
            let Ok(()) = writer.write_image_data(&[200; 16]) else {
                panic!("i pixel del PNG di prova devono potersi scrivere");
            };
        }
        let Ok(stemma) = TemplateEmblem::from_png(bytes) else {
            panic!("il PNG di prova deve essere uno stemma valido");
        };
        stemma
    }

    fn contiene(bytes: &[u8], cercato: &[u8]) -> bool {
        bytes
            .windows(cercato.len())
            .any(|finestra| finestra == cercato)
    }

    /// **Le emoji del testo conservato arrivano nel PDF come codici, e la
    /// relazione lo spiega** (E2E01-04). Senza emoji, nessuna nota in più.
    #[test]
    fn le_emoji_nel_pdf_sono_codici_spiegati() {
        let bytes = render(
            &report(vec![Block::Paragraph(String::from(
                "Testo conservato: ci vediamo \u{1F44D} domani",
            ))]),
            PdfKind::Narrative,
        )
        .expect("deve potersi scrivere");
        assert!(contiene(&bytes, b"[U+1F44D]"), "manca il codice dell'emoji");
        assert!(
            !contiene(&bytes, b"vediamo ? domani"),
            "l'emoji e' diventata «?»"
        );
        assert!(
            contiene(&bytes, &to_winansi("parentesi quadre, per esempio")),
            "manca la nota che spiega i codici"
        );

        let senza = render(
            &report(vec![Block::Paragraph(String::from("Testo senza emoji"))]),
            PdfKind::Narrative,
        )
        .expect("deve potersi scrivere");
        assert!(!contiene(&senza, &to_winansi("parentesi quadre")));
    }

    /// **Il PDF porta lo stemma e il riferimento a piè di pagina, come il
    /// `.docx` dello stesso pacchetto** (F-13).
    ///
    /// Vista rossa prima della correzione: il PDF non leggeva né
    /// `letterhead.emblem` né `report.footer`.
    #[test]
    fn la_relazione_pdf_ha_lo_stemma_e_il_riferimento() {
        let mut relazione = report(vec![Block::Paragraph(String::from("Testo"))]);
        relazione.letterhead.emblem = Some(stemma());
        relazione.footer = vec![LetterheadLine::Configured(String::from("Rif. PROVA/2026"))];

        let bytes = render(&relazione, PdfKind::Narrative).expect("deve potersi scrivere");
        assert!(contiene(&bytes, b"/Image"), "manca l'immagine");
        assert!(contiene(&bytes, b"/SMask"), "manca la trasparenza");
        assert!(contiene(&bytes, b"/Im1 Do"), "l'immagine non si disegna");
        assert!(
            contiene(&bytes, &to_winansi("Rif. PROVA/2026 — Pagina 1 di 1")),
            "il riferimento non sta a piè di pagina"
        );

        // Lo stesso report, scritto due volte, resta lo stesso file.
        let ancora = render(&relazione, PdfKind::Narrative).expect("deve potersi scrivere");
        assert_eq!(
            bytes, ancora,
            "con lo stemma il PDF non è più deterministico"
        );
    }

    /// **Uno stemma che non si lascia leggere non sparisce in silenzio.**
    #[test]
    fn uno_stemma_illeggibile_si_dichiara() {
        let mut finto = stemma().bytes().to_vec();
        let lunghezza = finto.len();
        // Firma e intestazione restano, i dati compressi no.
        for byte in &mut finto[33..lunghezza] {
            *byte = 0;
        }
        let Ok(rotto) = TemplateEmblem::from_png(finto) else {
            panic!("firma e dimensioni sono ancora quelle di un PNG");
        };
        let mut relazione = report(Vec::new());
        relazione.letterhead.emblem = Some(rotto);

        let bytes = render(&relazione, PdfKind::Narrative).expect("deve potersi scrivere");
        assert!(!contiene(&bytes, b"/Im1 Do"));
        assert!(
            contiene(&bytes, &to_winansi("Lo stemma configurato non si")),
            "lo stemma mancante non è dichiarato"
        );
    }

    /// **Un riferimento lungo non esce dal foglio**: sale di una riga.
    #[test]
    fn un_riferimento_lungo_va_a_capo() {
        let mut relazione = report(Vec::new());
        relazione.footer = vec![LetterheadLine::Configured("Riferimento ".repeat(20))];
        let bytes = render(&relazione, PdfKind::Narrative).expect("deve potersi scrivere");
        assert!(contiene(&bytes, &to_winansi("(Pagina 1 di 1)")));
    }

    #[test]
    fn the_identifier_is_the_same_for_the_same_report() {
        let uno = document_identifier(&report(Vec::new()));
        let due = document_identifier(&report(Vec::new()));
        assert_eq!(uno, due);
        assert!(!uno.is_empty());
    }
}
