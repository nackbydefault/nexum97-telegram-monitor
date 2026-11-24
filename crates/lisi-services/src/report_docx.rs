//! Da relazione composta a file `.docx`.
//!
//! Motivato in ADR-0031 Decisione 7; l'impostazione tipografica e' stata
//! riconciliata con un modello di riferimento in MP-18C-R, e il confronto
//! sta nell'archivio del progetto.
//!
//! Questo modulo **non decide che cosa il documento dica**: riceve i blocchi che
//! `report_narrative` ha composto e li scrive in OOXML. Se una frase e'
//! sbagliata, il difetto sta di la'; se il file non si apre in Word, il difetto
//! sta qui.
//!
//! # Il documento lo scrive il prodotto (ADR-0180)
//!
//! Fino al 2026-11-04 lo scriveva `docx-rs` (ADR-0032). `docx-rs` 0.4.22, la
//! sua ultima versione, chiede `zip` 8.6, e su `zip` 8.6 sono uscite quattro
//! advisory in un mese: il committente ha scelto di togliere la libreria
//! invece di allargare la deroga di ADR-0148.
//!
//! Qui si scrive **testo XML** di una specifica pubblica (ECMA-376), e soltanto
//! le parti che la relazione usa. Il pacchetto lo chiude `zip` 9: nessun
//! compressore e nessun formato binario sono scritti in casa. L'ordine degli
//! elementi dentro `w:pPr`, `w:rPr`, `w:tblPr`, `w:tcPr` e `w:sectPr` e' quello
//! dello schema, perche' Word, davanti a un ordine diverso, puo' dichiarare il
//! file danneggiato senza dire dove.
//!
//! # Che cosa questo generatore non produce, per divieto esplicito
//!
//! Niente macro o VBA, niente oggetti OLE, niente template remoti, niente
//! immagini remote, **nessuna relazione esterna**, nessun collegamento
//! automatico a risorse Internet. **Nulla viene scaricato dalla rete durante la
//! generazione**: non c'e' un client di rete in questo modulo.
//!
//! # Nessun autore nelle proprieta', ed e' voluto
//!
//! `docx-rs` scriveva `dc:creator` e `cp:lastModifiedBy` a `unknown`. Il
//! generatore nuovo non scrive i due elementi: i metadati viaggiano con **ogni
//! copia** del documento, nessuno li guarda, e sono il posto in cui un nome
//! sopravvive piu' a lungo di chiunque ricordi di averlo messo. Chi sottoscrive
//! e' scritto **nel corpo**, in calce, dove chi legge il documento lo trova e
//! sa perche' c'e'.
//!
//! # Impostazione documentale
//!
//! A4, corpo in Times New Roman 12 pt come stabilito dalla Decisione 4,
//! interlinea 1,15 e 10 pt dopo ogni paragrafo — il respiro del facsimile —
//! testo giustificato, numerazione delle pagine nel piede. Il carattere si
//! nomina, non si incorpora: incorporare un carattere in un documento e' una
//! scelta di licenza, e Times New Roman e' presente su ogni installazione di
//! Word.
//!
//! **Pagina e margini sono dichiarati, non ereditati**: un formato A4 che
//! dipende da un predefinito altrui e' un formato A4 fino al giorno in cui quel
//! predefinito cambia.

use std::fmt::Write as _;
use std::io::Write as _;

use lisi_core::model::report_template::TemplateEmblem;
use zip::write::SimpleFileOptions;
use zip::{CompressionMethod, DateTime, ZipWriter};

use crate::error::{ServiceError, ServiceResult};
use crate::report_narrative::{Block, Letterhead, LetterheadLine, NarrativeReport};

/// Carattere del corpo, come stabilito da ADR-0031 Decisione 4.
const BODY_FONT: &str = "Times New Roman";

/// Corpo del testo in mezzi punti, come vuole OOXML: 24 mezzi punti = 12 pt.
const BODY_SIZE_HALF_POINTS: usize = 24;

/// Corpo del piede di pagina, in mezzi punti: 18 = 9 pt.
const FOOTER_SIZE_HALF_POINTS: usize = 18;

/// Larghezza della pagina A4 in twip: 21,0 cm.
const A4_WIDTH_TWIPS: u32 = 11_906;

/// Altezza della pagina A4 in twip: 29,7 cm.
const A4_HEIGHT_TWIPS: u32 = 16_838;

/// Margine superiore, in twip: 3,5 cm.
const MARGIN_TOP_TWIPS: u32 = 1_985;

/// Margini laterali e inferiore, in twip: 3,0 cm.
const MARGIN_SIDE_TWIPS: u32 = 1_701;

/// Distanza dell'intestazione dal bordo, in twip: 1,5 cm.
const MARGIN_HEADER_TWIPS: u32 = 851;

/// Distanza del piede dal bordo, in twip: 1,75 cm.
const MARGIN_FOOTER_TWIPS: u32 = 992;

/// Larghezza utile della pagina, in twip: cio' che le tabelle si dividono.
const TEXT_WIDTH_TWIPS: u32 = A4_WIDTH_TWIPS - 2 * MARGIN_SIDE_TWIPS;

/// Spazio dopo un paragrafo del corpo, in ventesimi di punto: 200 = 10 pt.
const SPACE_AFTER: u32 = 200;

/// Interlinea del corpo, in ventesimi di punto: 276 su 240 = 1,15 righe.
const LINE_SPACING: u32 = 276;

/// Interlinea singola, per i blocchi che non devono respirare.
const LINE_SINGLE: u32 = 240;

/// Spazio prima di un titolo di sezione: 240 = 12 pt.
const SPACE_BEFORE_HEADING: u32 = 240;

/// Un centimetro in EMU, l'unita' con cui OOXML misura le immagini.
const EMU_PER_CM: u32 = 360_000;

/// Altezza a cui lo stemma viene stampato: **3 cm**.
///
/// # Perche' non 1,5 cm come il facsimile
///
/// Fino al 2026-08-19 valeva 1,5 cm, presa dal facsimile di riferimento.
/// Alla prima relazione prodotta con uno stemma vero l'operatore l'ha
/// giudicata «troppo piccola, quasi invisibile», e aveva ragione per una
/// ragione che il facsimile non poteva mostrare: **l'altezza da sola non
/// determina quanto uno stemma si vede.** La larghezza discende dalle
/// proporzioni, e un'immagine alta e stretta - una fiaccola, un torrione,
/// una spada - a 1,5 cm di altezza resta larga pochi millimetri.
///
/// La misura e' stata scelta da chi quei documenti li firma, davanti al
/// documento vero. E' l'unica autorita' che una misura tipografica possa
/// avere: un facsimile dice come stava bene UN altro stemma.
///
/// La larghezza continua a ricavarsi dalle proporzioni dell'immagine, cosi'
/// che uno stemma non venga mai schiacciato.
///
/// Non invade il corpo della pagina: l'intestazione parte a 1,5 cm dal bordo,
/// il testo a 3,5 cm, ed e' l'intestazione della **sola prima pagina**.
/// Quando cresce, Word fa scendere il corpo — che e' cio' che fa ogni carta
/// intestata.
const EMBLEM_HEIGHT_EMU: u32 = EMU_PER_CM * 3;

/// Identificativo **fisso** della relazione che porta allo stemma.
///
/// Con `docx-rs` andava sovrascritto, perche' la libreria lo prendeva da un
/// contatore globale del processo e due generazioni davano due file diversi.
/// Qui e' una costante fin dall'inizio, come il nome del media: il
/// determinismo (criterio 30) non dipende da nessuno stato.
const EMBLEM_RELATIONSHIP_ID: &str = "Emblem";

/// Percorso dello stemma dentro il pacchetto.
const EMBLEM_PART: &str = "word/media/emblem.png";

/// Gli spazi dei nomi che documento, intestazioni e piedi dichiarano.
const NAMESPACES: &str = concat!(
    r#"xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main" "#,
    r#"xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships" "#,
    r#"xmlns:wp="http://schemas.openxmlformats.org/drawingml/2006/wordprocessingDrawing" "#,
    r#"xmlns:a="http://schemas.openxmlformats.org/drawingml/2006/main" "#,
    r#"xmlns:pic="http://schemas.openxmlformats.org/drawingml/2006/picture""#,
);

/// La dichiarazione che apre ogni parte XML.
const XML_DECLARATION: &str = r#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?>"#;

/// Prefisso dei tipi di relazione del documento.
const RELATIONSHIP_TYPE: &str =
    "http://schemas.openxmlformats.org/officeDocument/2006/relationships";

/// Prefisso dei tipi di contenuto WordprocessingML.
const CONTENT_TYPE: &str = "application/vnd.openxmlformats-officedocument.wordprocessingml";

/// Scrive la relazione come documento `.docx`.
///
/// # Errori
///
/// Restituisce [`ServiceError::DocumentGeneration`] se la scrittura
/// dell'archivio non riesce.
pub fn render(report: &NarrativeReport) -> ServiceResult<Vec<u8>> {
    // In Esercitazione la frase di SIC-17 apre il documento e sta nel piede di
    // ogni pagina (PR-13, ADR-0129).
    let report = crate::run_mode::marked_report(report);
    let report = report.as_ref();

    let footer = page_footer(&report.footer);
    let mut parts: Vec<(&str, Vec<u8>)> = vec![
        ("[Content_Types].xml", content_types().into_bytes()),
        ("_rels/.rels", package_relationships().into_bytes()),
        // L'istante di generazione e' un ingresso: a parita' di istante il file
        // e' identico, e la data nelle proprieta' non e' una bugia.
        (
            "docProps/core.xml",
            core_properties(&report.generated_at.to_w3cdtf_utc()).into_bytes(),
        ),
        ("word/document.xml", document(&report.blocks).into_bytes()),
        (
            "word/_rels/document.xml.rels",
            document_relationships().into_bytes(),
        ),
        ("word/styles.xml", styles().into_bytes()),
        ("word/settings.xml", settings().into_bytes()),
        // L'intestazione ordinaria e' vuota: le pagine dalla seconda in poi
        // restano pulite, ed e' cio' che Word stesso produce quando si spunta
        // «Diversi per la prima pagina».
        ("word/header1.xml", header(&empty_paragraph()).into_bytes()),
        (
            "word/header2.xml",
            header(&letterhead(&report.letterhead)).into_bytes(),
        ),
        // Il piede invece va su **tutte** le pagine, e con `titlePg` la prima
        // ha bisogno del proprio: senza, la pagina 1 resterebbe senza numero.
        ("word/footer1.xml", footer_part(&footer).into_bytes()),
        ("word/footer2.xml", footer_part(&footer).into_bytes()),
    ];
    if let Some(emblem) = &report.letterhead.emblem {
        parts.push((
            "word/_rels/header2.xml.rels",
            emblem_relationships().into_bytes(),
        ));
        parts.push((EMBLEM_PART, emblem.bytes().to_vec()));
    }

    package(&parts).map_err(|error| ServiceError::DocumentGeneration { reason: error })
}

/// Chiude le parti nel pacchetto ZIP.
///
/// La data di ogni voce e' **fissa** (1980-01-01, la prima che il formato
/// ammette): una data presa dall'orologio renderebbe diversi due file
/// altrimenti identici. Le parti XML si comprimono; l'immagine, che e' gia'
/// compressa, si memorizza.
fn package(parts: &[(&str, Vec<u8>)]) -> Result<Vec<u8>, String> {
    // Uno ZIP torna indietro a scrivere il proprio indice: serve qualcosa che
    // sappia riposizionarsi, non un semplice vettore in coda.
    let mut archive = ZipWriter::new(std::io::Cursor::new(Vec::new()));
    let fixed = SimpleFileOptions::default()
        .last_modified_time(DateTime::default())
        .unix_permissions(0o644);
    for (name, bytes) in parts {
        let method = if name.starts_with("word/media/") {
            CompressionMethod::Stored
        } else {
            CompressionMethod::Deflated
        };
        archive
            .start_file(*name, fixed.compression_method(method))
            .map_err(|error| error.to_string())?;
        archive
            .write_all(bytes)
            .map_err(|error| error.to_string())?;
    }
    archive
        .finish()
        .map(std::io::Cursor::into_inner)
        .map_err(|error| error.to_string())
}

/// I tipi di contenuto: uno per ogni parte, o per estensione.
fn content_types() -> String {
    let mut xml = format!(
        "{XML_DECLARATION}<Types xmlns=\"http://schemas.openxmlformats.org/package/2006/content-types\">\
         <Default Extension=\"rels\" ContentType=\"application/vnd.openxmlformats-package.relationships+xml\" />\
         <Default Extension=\"xml\" ContentType=\"application/xml\" />\
         <Default Extension=\"png\" ContentType=\"image/png\" />\
         <Override PartName=\"/docProps/core.xml\" ContentType=\"application/vnd.openxmlformats-package.core-properties+xml\" />"
    );
    for (part, kind) in [
        ("document", "document.main"),
        ("styles", "styles"),
        ("settings", "settings"),
        ("header1", "header"),
        ("header2", "header"),
        ("footer1", "footer"),
        ("footer2", "footer"),
    ] {
        let _ = write!(
            xml,
            "<Override PartName=\"/word/{part}.xml\" ContentType=\"{CONTENT_TYPE}.{kind}+xml\" />"
        );
    }
    xml.push_str("</Types>");
    xml
}

/// Le relazioni del pacchetto: il documento e le sue proprieta'.
fn package_relationships() -> String {
    format!(
        "{XML_DECLARATION}<Relationships xmlns=\"http://schemas.openxmlformats.org/package/2006/relationships\">\
         <Relationship Id=\"rId1\" Type=\"{RELATIONSHIP_TYPE}/officeDocument\" Target=\"word/document.xml\" />\
         <Relationship Id=\"rId2\" Type=\"http://schemas.openxmlformats.org/package/2006/relationships/metadata/core-properties\" Target=\"docProps/core.xml\" />\
         </Relationships>"
    )
}

/// Le relazioni del documento: stili, impostazioni, intestazioni e piedi.
///
/// Tutte interne: nessuna porta `TargetMode="External"`.
fn document_relationships() -> String {
    let mut xml = format!(
        "{XML_DECLARATION}<Relationships xmlns=\"http://schemas.openxmlformats.org/package/2006/relationships\">"
    );
    for (id, kind, target) in [
        ("rIdStyles", "styles", "styles.xml"),
        ("rIdSettings", "settings", "settings.xml"),
        ("rIdHeader1", "header", "header1.xml"),
        ("rIdHeader2", "header", "header2.xml"),
        ("rIdFooter1", "footer", "footer1.xml"),
        ("rIdFooter2", "footer", "footer2.xml"),
    ] {
        let _ = write!(
            xml,
            "<Relationship Id=\"{id}\" Type=\"{RELATIONSHIP_TYPE}/{kind}\" Target=\"{target}\" />"
        );
    }
    xml.push_str("</Relationships>");
    xml
}

/// Le relazioni dell'intestazione di prima pagina: lo stemma.
fn emblem_relationships() -> String {
    format!(
        "{XML_DECLARATION}<Relationships xmlns=\"http://schemas.openxmlformats.org/package/2006/relationships\">\
         <Relationship Id=\"{EMBLEM_RELATIONSHIP_ID}\" Type=\"{RELATIONSHIP_TYPE}/image\" Target=\"media/emblem.png\" />\
         </Relationships>"
    )
}

/// Le proprieta' del documento: soltanto le due date.
fn core_properties(generated_at: &str) -> String {
    format!(
        "{XML_DECLARATION}<cp:coreProperties \
         xmlns:cp=\"http://schemas.openxmlformats.org/package/2006/metadata/core-properties\" \
         xmlns:dc=\"http://purl.org/dc/elements/1.1/\" \
         xmlns:dcterms=\"http://purl.org/dc/terms/\" \
         xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\">\
         <dcterms:created xsi:type=\"dcterms:W3CDTF\">{generated_at}</dcterms:created>\
         <dcterms:modified xsi:type=\"dcterms:W3CDTF\">{generated_at}</dcterms:modified>\
         </cp:coreProperties>"
    )
}

/// Gli stili: carattere e corpo dichiarati **anche** nel predefinito.
///
/// Cosi' un paragrafo che un giorno venisse scritto senza passare da
/// [`Veste`] non uscirebbe in un carattere diverso dal resto del documento.
fn styles() -> String {
    format!(
        "{XML_DECLARATION}<w:styles xmlns:w=\"http://schemas.openxmlformats.org/wordprocessingml/2006/main\">\
         <w:docDefaults><w:rPrDefault><w:rPr>\
         <w:rFonts w:ascii=\"{BODY_FONT}\" w:hAnsi=\"{BODY_FONT}\" />\
         <w:sz w:val=\"{BODY_SIZE_HALF_POINTS}\" /><w:szCs w:val=\"{BODY_SIZE_HALF_POINTS}\" />\
         </w:rPr></w:rPrDefault><w:pPrDefault /></w:docDefaults>\
         <w:style w:type=\"paragraph\" w:default=\"1\" w:styleId=\"Normal\"><w:name w:val=\"Normal\" /><w:qFormat /></w:style>\
         <w:style w:type=\"table\" w:default=\"1\" w:styleId=\"TableNormal\"><w:name w:val=\"Normal Table\" />\
         <w:uiPriority w:val=\"99\" /><w:semiHidden /><w:unhideWhenUsed />\
         <w:tblPr><w:tblInd w:w=\"0\" w:type=\"dxa\" /><w:tblCellMar>\
         <w:top w:w=\"0\" w:type=\"dxa\" /><w:left w:w=\"108\" w:type=\"dxa\" />\
         <w:bottom w:w=\"0\" w:type=\"dxa\" /><w:right w:w=\"108\" w:type=\"dxa\" />\
         </w:tblCellMar></w:tblPr></w:style>\
         </w:styles>"
    )
}

/// Le impostazioni: la tabulazione e la modalita' di compatibilita' attuale.
///
/// Senza `compatibilityMode` 15 Word apre il file in «Modalita'
/// compatibilita'», come se venisse da una versione di dieci anni fa.
fn settings() -> String {
    format!(
        "{XML_DECLARATION}<w:settings xmlns:w=\"http://schemas.openxmlformats.org/wordprocessingml/2006/main\">\
         <w:defaultTabStop w:val=\"709\" />\
         <w:characterSpacingControl w:val=\"doNotCompress\" />\
         <w:compat><w:compatSetting w:name=\"compatibilityMode\" w:uri=\"http://schemas.microsoft.com/office/word\" w:val=\"15\" /></w:compat>\
         </w:settings>"
    )
}

/// Il corpo del documento, seguito dall'impostazione della pagina.
fn document(blocks: &[Block]) -> String {
    let mut body = String::new();
    for block in blocks {
        write_block(&mut body, block);
    }
    // Il corpo di un documento Word finisce con un paragrafo: una tabella
    // in ultima posizione Word la ripara, cioe' la segnala.
    if matches!(blocks.last(), Some(Block::Table { .. })) {
        body.push_str(&empty_paragraph());
    }

    format!(
        "{XML_DECLARATION}<w:document {NAMESPACES}><w:body>{body}<w:sectPr>\
         <w:headerReference w:type=\"default\" r:id=\"rIdHeader1\" />\
         <w:headerReference w:type=\"first\" r:id=\"rIdHeader2\" />\
         <w:footerReference w:type=\"default\" r:id=\"rIdFooter1\" />\
         <w:footerReference w:type=\"first\" r:id=\"rIdFooter2\" />\
         <w:pgSz w:w=\"{A4_WIDTH_TWIPS}\" w:h=\"{A4_HEIGHT_TWIPS}\" />\
         <w:pgMar w:top=\"{MARGIN_TOP_TWIPS}\" w:right=\"{MARGIN_SIDE_TWIPS}\" \
         w:bottom=\"{MARGIN_SIDE_TWIPS}\" w:left=\"{MARGIN_SIDE_TWIPS}\" \
         w:header=\"{MARGIN_HEADER_TWIPS}\" w:footer=\"{MARGIN_FOOTER_TWIPS}\" w:gutter=\"0\" />\
         <w:titlePg />\
         </w:sectPr></w:body></w:document>"
    )
}

/// Un'intestazione di pagina con il contenuto dato.
fn header(content: &str) -> String {
    format!("{XML_DECLARATION}<w:hdr {NAMESPACES}>{content}</w:hdr>")
}

/// Un piede di pagina con il contenuto dato.
fn footer_part(content: &str) -> String {
    format!("{XML_DECLARATION}<w:ftr {NAMESPACES}>{content}</w:ftr>")
}

/// Il piede di pagina: la riga configurata e la numerazione.
///
/// # Perche' la numerazione c'e' anche se il facsimile non ce l'ha
///
/// Il facsimile non ha alcun piede, e su tre pagine spillate insieme si puo'
/// vivere senza. ADR-0031 Decisione 4 la prescrive, e una relazione che venga
/// fotocopiata o scansionata senza numeri di pagina e' una relazione di cui non
/// si sa se manchi un foglio.
///
/// I numeri sono **campi**, non testo: li calcola Word all'apertura, e restano
/// corretti dopo che una persona ha modificato il documento.
fn page_footer(lines: &[LetterheadLine]) -> String {
    let mut runs = String::new();
    for configured in lines {
        runs.push_str(&run(
            Veste::PIEDE,
            &format!("{} \u{2014} ", configured.text()),
        ));
    }
    runs.push_str(&run(Veste::PIEDE, "Pagina "));
    runs.push_str(&field("PAGE"));
    runs.push_str(&run(Veste::PIEDE, " di "));
    runs.push_str(&field("NUMPAGES"));
    paragraph(&Forma::SINGOLA.allineata(Allineamento::Centro), &runs)
}

/// La carta intestata: lo stemma e le righe che identificano l'ufficio.
///
/// È un'**intestazione di pagina vera**, non tre paragrafi in cima al corpo:
/// e' li' che chi apre il documento in Word va a cercare la carta intestata per
/// adattarla, ed e' li' che si aspetta di trovarla.
fn letterhead(letterhead: &Letterhead) -> String {
    let centrata = Forma::SINGOLA.allineata(Allineamento::Centro);
    let mut xml = String::new();

    if let Some(emblem) = &letterhead.emblem {
        xml.push_str(&paragraph(&centrata, &emblem_run(emblem)));
    }

    for line in &letterhead.lines {
        // Configurate e da compilare si scrivono **allo stesso modo**: chi
        // sostituisce un segnaposto ottiene subito l'aspetto definitivo,
        // invece di ritrovarsi una riga formattata diversamente dalle altre.
        xml.push_str(&paragraph(&centrata, &run(Veste::GRASSETTO, &line.text())));
    }

    // Una riga vuota stacca la carta intestata dal corpo della pagina.
    xml.push_str(&empty_paragraph());
    xml
}

/// Lo stemma, alto tre centimetri, con le proporzioni dell'immagine.
///
/// La larghezza si ricava da quelle dichiarate dal PNG, cosi' che uno stemma
/// non venga mai schiacciato per riempire una misura.
fn emblem_run(emblem: &TemplateEmblem) -> String {
    let height = EMBLEM_HEIGHT_EMU;
    let width = u32::try_from(
        u64::from(height) * u64::from(emblem.width_px()) / u64::from(emblem.height_px().max(1)),
    )
    .unwrap_or(height);

    format!(
        "<w:r><w:drawing><wp:inline distT=\"0\" distB=\"0\" distL=\"0\" distR=\"0\">\
         <wp:extent cx=\"{width}\" cy=\"{height}\" />\
         <wp:effectExtent l=\"0\" t=\"0\" r=\"0\" b=\"0\" />\
         <wp:docPr id=\"1\" name=\"Stemma\" />\
         <wp:cNvGraphicFramePr><a:graphicFrameLocks noChangeAspect=\"1\" /></wp:cNvGraphicFramePr>\
         <a:graphic><a:graphicData uri=\"http://schemas.openxmlformats.org/drawingml/2006/picture\">\
         <pic:pic><pic:nvPicPr><pic:cNvPr id=\"0\" name=\"emblem.png\" /><pic:cNvPicPr /></pic:nvPicPr>\
         <pic:blipFill><a:blip r:embed=\"{EMBLEM_RELATIONSHIP_ID}\" /><a:stretch><a:fillRect /></a:stretch></pic:blipFill>\
         <pic:spPr><a:xfrm><a:off x=\"0\" y=\"0\" /><a:ext cx=\"{width}\" cy=\"{height}\" /></a:xfrm>\
         <a:prstGeom prst=\"rect\"><a:avLst /></a:prstGeom></pic:spPr>\
         </pic:pic></a:graphicData></a:graphic></wp:inline></w:drawing></w:r>"
    )
}

/// Un campo di Word — numero di pagina, totale — con il corpo del piede.
///
/// Il campo e' vestito come il resto della riga: un numero con il carattere
/// predefinito uscirebbe a 12 pt accanto a un piede da 9.
fn field(instruction: &str) -> String {
    let veste = Veste::PIEDE.proprieta();
    format!(
        "<w:r>{veste}<w:fldChar w:fldCharType=\"begin\" /></w:r>\
         <w:r>{veste}<w:instrText xml:space=\"preserve\"> {instruction} </w:instrText></w:r>\
         <w:r>{veste}<w:fldChar w:fldCharType=\"separate\" /></w:r>\
         {placeholder}\
         <w:r>{veste}<w:fldChar w:fldCharType=\"end\" /></w:r>",
        // Il segnaposto che Word sostituisce all'apertura: senza, un lettore
        // che non ricalcola i campi non vedrebbe alcun numero.
        placeholder = run(Veste::PIEDE, "1"),
    )
}

/// Traduce un blocco nella sua forma documentale.
fn write_block(body: &mut String, block: &Block) {
    let xml = match block {
        // `keepNext` tiene il titolo attaccato al proprio testo: senza, un
        // salto di pagina puo' lasciare «Risultanze» solo in fondo a un foglio
        // e il suo contenuto sul successivo. E' la stessa cosa che fanno gli
        // stili Titolo di Word, e in un documento stampato si vede.
        Block::Heading(text) => paragraph(&Forma::TITOLO, &run(Veste::GRASSETTO, text)),

        Block::Paragraph(text) => paragraph(&Forma::CORPO, &run(Veste::CORPO, text)),

        // L'attacco in grassetto e il seguito in tondo, **nello stesso
        // paragrafo**: due paragrafi spezzerebbero la giustificazione e
        // farebbero rientrare il seguito a capo.
        Block::Lead { lead, body: text } => paragraph(
            &Forma::CORPO,
            &(run(Veste::GRASSETTO, &format!("{lead} ")) + &run(Veste::CORPO, text)),
        ),

        Block::Emphasis(text) => paragraph(&Forma::CORPO, &run(Veste::GRASSETTO, text)),

        Block::RightLine(text) => paragraph(
            &Forma::CORPO.allineata(Allineamento::Destra),
            &run(Veste::CORPO, text),
        ),

        Block::Table { headers, rows } => table(headers, rows),

        Block::Signature {
            place_and_date,
            role,
            name,
        } => signature(place_and_date, role.as_deref(), name.as_deref()),
    };
    body.push_str(&xml);
}

/// Luogo, data e sottoscrizione.
///
/// Il facsimile spinge la firma a destra con una fila di spazi; qui e' un
/// allineamento, che ottiene lo stesso risultato e non si sposta al cambiare
/// della larghezza del carattere.
fn signature(place_and_date: &str, role: Option<&str>, name: Option<&str>) -> String {
    let mut xml = String::from("<w:p />");
    xml.push_str(&paragraph(
        &Forma::SINGOLA,
        &run(Veste::CORPO, place_and_date),
    ));
    xml.push_str("<w:p />");

    // Senza qualifica ne' nome resta lo spazio bianco, che e' cio' che serve a
    // chi firma a penna. Non si scrive una riga di puntini: una relazione
    // firmata a mano non ne ha bisogno, e una firmata digitalmente non la vuole.
    let a_destra = Forma::SINGOLA.allineata(Allineamento::Destra);
    for line in [role, name].into_iter().flatten() {
        xml.push_str(&paragraph(&a_destra, &run(Veste::CORPO, line)));
    }
    xml
}

/// La tabella: l'intestazione in grassetto, le colonne di pari larghezza.
///
/// Le larghezze sono dichiarate perche' una griglia vuota lascia a ogni
/// programma di videoscrittura la propria idea di come dividere la pagina.
fn table(headers: &[String], rows: &[Vec<String>]) -> String {
    let columns = u32::try_from(headers.len().max(1)).unwrap_or(1);
    let width = TEXT_WIDTH_TWIPS / columns;

    let mut xml = format!(
        "<w:tbl><w:tblPr><w:tblW w:w=\"{}\" w:type=\"dxa\" /><w:tblBorders>",
        width * columns
    );
    for side in ["top", "left", "bottom", "right", "insideH", "insideV"] {
        let _ = write!(
            xml,
            "<w:{side} w:val=\"single\" w:sz=\"4\" w:space=\"0\" w:color=\"auto\" />"
        );
    }
    xml.push_str("</w:tblBorders><w:tblLayout w:type=\"fixed\" /></w:tblPr><w:tblGrid>");
    for _ in 0..columns {
        let _ = write!(xml, "<w:gridCol w:w=\"{width}\" />");
    }
    xml.push_str("</w:tblGrid>");

    let cell = |veste: Veste, text: &str| {
        format!(
            "<w:tc><w:tcPr><w:tcW w:w=\"{width}\" w:type=\"dxa\" /><w:vAlign w:val=\"center\" /></w:tcPr>{}</w:tc>",
            paragraph(&Forma::SINGOLA, &run(veste, text))
        )
    };

    xml.push_str("<w:tr>");
    for header in headers {
        xml.push_str(&cell(Veste::GRASSETTO, header));
    }
    xml.push_str("</w:tr>");
    for row in rows {
        xml.push_str("<w:tr>");
        for value in row {
            xml.push_str(&cell(Veste::CORPO, value));
        }
        xml.push_str("</w:tr>");
    }
    xml.push_str("</w:tbl>");
    xml
}

/// I soli tre allineamenti che il documento usa.
///
/// # `both` e non `justified`, ed e' una correzione
///
/// `justified` non appartiene all'enumerazione `ST_Jc` di ECMA-376; `both`
/// si', ed e' cio' che Word scrive. Il generatore ha usato il primo da MP-18C
/// a MP-18C-R: il file si scriveva e l'archivio si apriva lo stesso, e se ne
/// sarebbe accorto Word, proponendo il ripristino del documento. Qui
/// l'enumerazione e' chiusa, e il valore sbagliato non si puo' scrivere.
#[derive(Clone, Copy)]
enum Allineamento {
    Giustificato,
    Centro,
    Destra,
}

impl Allineamento {
    const fn valore(self) -> &'static str {
        match self {
            Self::Giustificato => "both",
            Self::Centro => "center",
            Self::Destra => "right",
        }
    }
}

/// La forma di un paragrafo: spaziatura, allineamento, aggancio al seguente.
#[derive(Clone, Copy)]
struct Forma {
    prima: u32,
    dopo: u32,
    interlinea: u32,
    allineamento: Option<Allineamento>,
    tieni_col_seguente: bool,
}

impl Forma {
    /// Il corpo: giustificato, interlinea 1,15 e dieci punti dopo.
    const CORPO: Self = Self {
        prima: 0,
        dopo: SPACE_AFTER,
        interlinea: LINE_SPACING,
        allineamento: Some(Allineamento::Giustificato),
        tieni_col_seguente: false,
    };

    /// Un titolo di sezione: dodici punti prima, attaccato al proprio testo.
    const TITOLO: Self = Self {
        prima: SPACE_BEFORE_HEADING,
        dopo: SPACE_AFTER,
        interlinea: LINE_SPACING,
        allineamento: None,
        tieni_col_seguente: true,
    };

    /// Interlinea singola, senza spazio dopo.
    const SINGOLA: Self = Self {
        prima: 0,
        dopo: 0,
        interlinea: LINE_SINGLE,
        allineamento: None,
        tieni_col_seguente: false,
    };

    const fn allineata(self, allineamento: Allineamento) -> Self {
        Self {
            allineamento: Some(allineamento),
            ..self
        }
    }
}

/// Un paragrafo, con le proprieta' nell'ordine dello schema (`CT_PPrBase`):
/// `keepNext`, poi `spacing`, poi `jc`.
fn paragraph(forma: &Forma, runs: &str) -> String {
    let mut proprieta = String::from("<w:pPr>");
    if forma.tieni_col_seguente {
        proprieta.push_str("<w:keepNext />");
    }
    proprieta.push_str("<w:spacing");
    if forma.prima > 0 {
        let _ = write!(proprieta, " w:before=\"{}\"", forma.prima);
    }
    let _ = write!(
        proprieta,
        " w:after=\"{}\" w:line=\"{}\" w:lineRule=\"auto\" />",
        forma.dopo, forma.interlinea
    );
    if let Some(allineamento) = forma.allineamento {
        let _ = write!(proprieta, "<w:jc w:val=\"{}\" />", allineamento.valore());
    }
    proprieta.push_str("</w:pPr>");
    format!("<w:p>{proprieta}{runs}</w:p>")
}

/// Un paragrafo vuoto a interlinea singola.
fn empty_paragraph() -> String {
    paragraph(&Forma::SINGOLA, "")
}

/// La veste di un frammento: corpo del testo o del piede, tondo o grassetto.
#[derive(Clone, Copy)]
struct Veste {
    mezzi_punti: usize,
    grassetto: bool,
}

impl Veste {
    const CORPO: Self = Self {
        mezzi_punti: BODY_SIZE_HALF_POINTS,
        grassetto: false,
    };
    const GRASSETTO: Self = Self {
        mezzi_punti: BODY_SIZE_HALF_POINTS,
        grassetto: true,
    };
    const PIEDE: Self = Self {
        mezzi_punti: FOOTER_SIZE_HALF_POINTS,
        grassetto: false,
    };

    /// Le proprieta' del frammento, nell'ordine dello schema (`CT_RPr`):
    /// `rFonts`, `b`, `sz`, `szCs`.
    fn proprieta(self) -> String {
        format!(
            "<w:rPr><w:rFonts w:ascii=\"{BODY_FONT}\" w:hAnsi=\"{BODY_FONT}\" />{}\
             <w:sz w:val=\"{size}\" /><w:szCs w:val=\"{size}\" /></w:rPr>",
            if self.grassetto { "<w:b />" } else { "" },
            size = self.mezzi_punti,
        )
    }
}

/// Un frammento di testo.
///
/// È l'unico modo in cui il testo entra nel documento.
fn run(veste: Veste, text: &str) -> String {
    format!(
        "<w:r>{}<w:t xml:space=\"preserve\">{}</w:t></w:r>",
        veste.proprieta(),
        testo_xml(text)
    )
}

/// Il testo pronto per stare fra due marcatori: prima ammissibile in XML,
/// poi con i segni della marcatura resi come testo.
fn testo_xml(text: &str) -> String {
    let mut xml = String::with_capacity(text.len());
    for c in xml_sicuro(text).chars() {
        match c {
            '&' => xml.push_str("&amp;"),
            '<' => xml.push_str("&lt;"),
            '>' => xml.push_str("&gt;"),
            '"' => xml.push_str("&quot;"),
            other => xml.push(other),
        }
    }
    xml
}

/// Il testo con ogni carattere che XML 1.0 non ammette sostituito da U+FFFD
/// (FINAL-REVIEW-01, FR-027).
///
/// # Perché
///
/// Il contenuto di un messaggio entra nei documenti così come è stato
/// acquisito. La validazione dell'archivio rifiuta i caratteri di controllo,
/// ma U+FFFE e U+FFFF non lo sono, e XML 1.0 non li ammette: un solo messaggio
/// che li porta rendeva il DOCX o l'XLSX un file che Word ed Excel non aprono,
/// con il manifesto che lo diceva intatto. **L'archivio resta com'è**: si
/// sostituisce solo nel documento, dove la sostituzione è visibile.
#[must_use]
pub(crate) fn xml_sicuro(text: &str) -> std::borrow::Cow<'_, str> {
    let ammesso = |c: char| {
        matches!(c, '\t' | '\n' | '\r')
            || ('\u{20}'..='\u{D7FF}').contains(&c)
            || ('\u{E000}'..='\u{FFFD}').contains(&c)
            || c >= '\u{10000}'
    };
    if text.chars().all(ammesso) {
        return std::borrow::Cow::Borrowed(text);
    }
    std::borrow::Cow::Owned(
        text.chars()
            .map(|c| if ammesso(c) { c } else { '\u{FFFD}' })
            .collect(),
    )
}

#[cfg(test)]
mod xml_tests {
    use super::{testo_xml, xml_sicuro};

    /// **Un carattere che XML non ammette non rompe il documento**
    /// (FINAL-REVIEW-01, FR-027).
    #[test]
    fn a_character_xml_refuses_becomes_a_replacement_mark() {
        assert_eq!(xml_sicuro("a\u{FFFF}b\u{FFFE}c"), "a\u{FFFD}b\u{FFFD}c");
        assert_eq!(xml_sicuro("riga\u{1}"), "riga\u{FFFD}");
        // Ciò che XML ammette resta com'è, accenti ed emoji compresi.
        let ammesso = "Città — \u{1F600}\tfine\r\n";
        assert_eq!(xml_sicuro(ammesso), ammesso);
    }

    /// **Un testo che somiglia a marcatura resta testo** (ADR-0180).
    ///
    /// Con `docx-rs` l'escape lo faceva la libreria; ora lo fa il prodotto, e
    /// un messaggio che contenesse `</w:t>` non deve poter chiudere il
    /// frammento e scrivere marcatura propria nel documento.
    #[test]
    fn text_that_looks_like_markup_stays_text() {
        assert_eq!(
            testo_xml("</w:t><w:b /> & \"x\" \u{FFFF}"),
            "&lt;/w:t&gt;&lt;w:b /&gt; &amp; &quot;x&quot; \u{FFFD}"
        );
        assert_eq!(testo_xml("l'apostrofo resta"), "l'apostrofo resta");
    }

    /// Il testo entra nel documento da una porta sola, e i fogli dalla stessa
    /// regola.
    #[test]
    fn every_text_goes_through_the_xml_check() {
        const DOCX: &str = include_str!("report_docx.rs");
        const XLSX: &str = include_str!("report_xlsx.rs");
        let Some((produzione, _)) = DOCX.split_once("#[cfg(test)]") else {
            panic!("il modulo deve avere le sue prove");
        };
        assert_eq!(
            produzione.matches("<w:t ").count(),
            1,
            "il testo entra solo da `run`"
        );
        assert_eq!(
            produzione.matches("testo_xml(").count(),
            2,
            "`testo_xml` si definisce una volta e si chiama soltanto da `run`"
        );
        assert!(produzione.contains("for c in xml_sicuro(text).chars()"));
        assert!(XLSX.contains(
            ".write_string(row, column, crate::report_docx::xml_sicuro(value.as_str()))"
        ));
    }
}
