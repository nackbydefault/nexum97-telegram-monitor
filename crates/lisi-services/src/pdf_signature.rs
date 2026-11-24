//! La firma dentro una copia del PDF (SIGN-01 parte 3, ADR-0181 decisione 6,
//! DEC-464).
//!
//! # Un aggiornamento incrementale, scritto a mano
//!
//! La copia firmata è il PDF di partenza, **tutti i suoi byte, uguali**, e in
//! fondo un aggiornamento (ISO 32000-1 §7.5.6): il dizionario della firma, il
//! campo invisibile, un `/AcroForm`, il catalogo e la prima pagina riscritti,
//! i riferimenti dei soli oggetti nuovi e cambiati, con `/Prev`. I
//! riferimenti sono un flusso, come quelli che `lopdf` scrive nel PDF di
//! partenza (ISO 32000-1 §7.5.8), senza compressione: un PDF con la tabella
//! classica non è del programma, e non si firma. `lopdf` serve soltanto a
//! leggere il PDF di partenza: il suo
//! aggiornamento incrementale scrive una seconda intestazione `%PDF` a metà
//! del file (DEC-464, decisione 2).
//!
//! # Il `/ByteRange`
//!
//! La firma copre tutto il file tranne il valore di `/Contents`, compresi i
//! suoi `<` e `>` (ISO 32000-1 §12.8.1). Lo spazio di `/Contents` si riserva
//! prima, pieno di zeri, e il `/ByteRange` si scrive con numeri di larghezza
//! fissa: riempirli non sposta niente.
//!
//! Qui non si firma e non si verifica: si prepara il file, si mette la firma
//! nello spazio riservato, e la si rilegge. Firma e verifica le fanno
//! [`crate::document_signing`] e Windows.

use std::fmt::Write as _;
use std::ops::Range;

use lisi_core::Timestamp;
use lopdf::xref::XrefType;
use lopdf::{Dictionary, Document, Object, ObjectId, StringFormat};

/// Lo spazio riservato alla firma, in byte: dentro il file diventa il doppio,
/// in esadecimale. Una firma CMS con il certificato e la sua catena ci sta
/// con largo margine.
pub(crate) const CONTENTS_BYTES: usize = 32 * 1024;

/// Quante cifre ha ciascun numero del `/ByteRange`.
const BYTE_RANGE_DIGITS: usize = 10;

/// Il nome del campo firma, come lo mostra un lettore PDF.
const FIELD_NAME: &str = "Firma dell'ufficio";

/// Perché una copia firmata non si prepara o la firma non ci sta.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Refusal {
    /// Il file non è un PDF che il programma ha scritto.
    NotOurs,
    /// Il PDF ha già dei campi o una firma.
    AlreadySigned,
    /// Il PDF è troppo grande per le misure del `/ByteRange`.
    TooLarge,
    /// La firma è vuota.
    EmptySignature,
    /// La firma non sta nello spazio riservato.
    SignatureTooLarge,
}

impl Refusal {
    /// La frase per l'operatore.
    pub(crate) fn operator_message(self) -> String {
        String::from(match self {
            Self::NotOurs => "il file non è un PDF scritto da questo programma",
            Self::AlreadySigned => {
                "il PDF ha già dei campi o una firma, e non si firma una seconda volta"
            }
            Self::TooLarge => "il PDF è troppo grande per essere firmato",
            Self::EmptySignature => "la firma è vuota",
            Self::SignatureTooLarge => "la firma è troppo grande per stare nel file",
        })
    }
}

/// Il PDF preparato: la copia con lo spazio della firma ancora vuoto.
#[derive(Debug, Clone)]
pub(crate) struct Prepared {
    bytes: Vec<u8>,
    /// Il valore di `/Contents`, dal `<` al `>` compresi.
    contents: Range<usize>,
}

impl Prepared {
    /// I byte che la firma copre: tutto tranne il valore di `/Contents`.
    pub(crate) fn signed_content(&self) -> Vec<u8> {
        let mut coperti = Vec::with_capacity(self.bytes.len() - self.contents.len());
        coperti.extend_from_slice(&self.bytes[..self.contents.start]);
        coperti.extend_from_slice(&self.bytes[self.contents.end..]);
        coperti
    }

    /// Mette la firma nello spazio riservato, e restituisce la copia.
    ///
    /// # Errori
    ///
    /// Una frase per l'operatore se la firma è vuota o non ci sta.
    pub(crate) fn fill(mut self, cms: &[u8]) -> Result<Vec<u8>, Refusal> {
        if cms.is_empty() {
            return Err(Refusal::EmptySignature);
        }
        if cms.len() > CONTENTS_BYTES {
            return Err(Refusal::SignatureTooLarge);
        }
        let mut esadecimale = String::with_capacity(cms.len() * 2);
        for byte in cms {
            let _ = write!(esadecimale, "{byte:02X}");
        }
        let inizio = self.contents.start + 1;
        self.bytes[inizio..inizio + esadecimale.len()].copy_from_slice(esadecimale.as_bytes());
        Ok(self.bytes)
    }
}

/// La firma letta da un PDF: il CMS e i byte che copre.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct EmbeddedSignature {
    /// I byte coperti dal `/ByteRange`, messi in fila.
    pub(crate) signed_content: Vec<u8>,
    /// Il CMS, senza gli zeri che riempivano lo spazio.
    pub(crate) cms: Vec<u8>,
}

/// Prepara la copia da firmare.
///
/// # Errori
///
/// Una frase per l'operatore se il PDF non è uno che il programma sa
/// firmare (DEC-464, decisione 5).
pub(crate) fn prepare(original: &[u8], when: Timestamp) -> Result<Prepared, Refusal> {
    if !original.starts_with(b"%PDF-") || !original.trim_ascii_end().ends_with(b"%%EOF") {
        return Err(Refusal::NotOurs);
    }
    let documento = Document::load_mem(original).map_err(|_| Refusal::NotOurs)?;
    if documento.is_encrypted()
        || !matches!(
            documento.reference_table.cross_reference_type,
            XrefType::CrossReferenceStream
        )
    {
        return Err(Refusal::NotOurs);
    }
    let catalogo_id = documento
        .trailer
        .get(b"Root")
        .and_then(Object::as_reference)
        .map_err(|_| Refusal::NotOurs)?;
    let mut catalogo = documento
        .get_dictionary(catalogo_id)
        .map_err(|_| Refusal::NotOurs)?
        .clone();
    if catalogo.has(b"AcroForm") {
        return Err(Refusal::AlreadySigned);
    }
    let Some(&pagina_id) = documento.get_pages().values().next() else {
        return Err(Refusal::NotOurs);
    };
    let mut pagina = documento
        .get_dictionary(pagina_id)
        .map_err(|_| Refusal::NotOurs)?
        .clone();

    let precedente = documento.xref_start;
    let dichiarati = documento
        .trailer
        .get(b"Size")
        .and_then(Object::as_i64)
        .ok()
        .and_then(|valore| u32::try_from(valore).ok())
        .unwrap_or(0);
    let firma_id: ObjectId = (dichiarati.max(documento.max_id + 1), 0);
    let campo_id: ObjectId = (firma_id.0 + 1, 0);
    let modulo_id: ObjectId = (firma_id.0 + 2, 0);

    let mut annotazioni = match pagina.get(b"Annots") {
        Err(_) => Vec::new(),
        Ok(Object::Array(elenco)) => elenco.clone(),
        Ok(_) => return Err(Refusal::NotOurs),
    };
    annotazioni.push(Object::Reference(campo_id));
    pagina.set("Annots", Object::Array(annotazioni));
    catalogo.set("AcroForm", Object::Reference(modulo_id));

    let mut copia = original.to_vec();
    if copia.last() != Some(&b'\n') {
        copia.push(b'\n');
    }
    let mut posizioni: Vec<(ObjectId, usize)> = Vec::new();

    // La firma: il `/ByteRange` e il `/Contents` si riempiono dopo.
    posizioni.push((firma_id, copia.len()));
    copia.extend_from_slice(
        format!(
            "{} {} obj\n<</Type /Sig /Filter /Adobe.PPKLite /SubFilter /ETSI.CAdES.detached \
             /ByteRange [0 ",
            firma_id.0, firma_id.1
        )
        .as_bytes(),
    );
    let byte_range = copia.len();
    let segnaposto = format!("{0:0>w$} {0:0>w$} {0:0>w$}", 0, w = BYTE_RANGE_DIGITS);
    copia.extend_from_slice(segnaposto.as_bytes());
    copia.extend_from_slice(b"] /Contents ");
    let contenuto_inizio = copia.len();
    copia.push(b'<');
    copia.resize(copia.len() + CONTENTS_BYTES * 2, b'0');
    copia.push(b'>');
    let contenuto_fine = copia.len();
    copia.extend_from_slice(format!(" /M ({})>>\nendobj\n", pdf_date(when)).as_bytes());

    let mut campo = Dictionary::new();
    campo.set("Type", Object::Name(b"Annot".to_vec()));
    campo.set("Subtype", Object::Name(b"Widget".to_vec()));
    campo.set("FT", Object::Name(b"Sig".to_vec()));
    campo.set(
        "T",
        Object::String(FIELD_NAME.as_bytes().to_vec(), StringFormat::Literal),
    );
    campo.set("V", Object::Reference(firma_id));
    campo.set(
        "Rect",
        Object::Array(vec![0.into(), 0.into(), 0.into(), 0.into()]),
    );
    // Stampa (4) e bloccato (128): invisibile, e non si sposta.
    campo.set("F", Object::Integer(132));
    campo.set("P", Object::Reference(pagina_id));

    let mut modulo = Dictionary::new();
    modulo.set("Fields", Object::Array(vec![Object::Reference(campo_id)]));
    // Ci sono firme (1), e il file si cambia soltanto in coda (2).
    modulo.set("SigFlags", Object::Integer(3));

    for (id, oggetto) in [
        (campo_id, campo),
        (modulo_id, modulo),
        (catalogo_id, catalogo),
        (pagina_id, pagina),
    ] {
        posizioni.push((id, copia.len()));
        copia.extend_from_slice(format!("{} {} obj\n", id.0, id.1).as_bytes());
        write_object(&mut copia, &Object::Dictionary(oggetto))?;
        copia.extend_from_slice(b"\nendobj\n");
    }

    // I riferimenti, come il PDF di partenza li scrive: un flusso, senza
    // compressione (ISO 32000-1 §7.5.8). Soltanto gli oggetti nuovi e
    // cambiati, a gruppi di numeri consecutivi, e il flusso stesso.
    let riferimenti_id: ObjectId = (modulo_id.0 + 1, 0);
    let tabella = copia.len();
    posizioni.push((riferimenti_id, tabella));
    posizioni.sort_by_key(|(id, _)| *id);
    let mut gruppi = Vec::new();
    let mut righe = Vec::with_capacity(posizioni.len() * 7);
    let mut indice = 0;
    while indice < posizioni.len() {
        let mut fine = indice + 1;
        while fine < posizioni.len() && posizioni[fine].0.0 == posizioni[fine - 1].0.0 + 1 {
            fine += 1;
        }
        gruppi.push(Object::Integer(i64::from(posizioni[indice].0.0)));
        gruppi.push(Object::Integer(i64::try_from(fine - indice).unwrap_or(0)));
        for (id, posizione) in &posizioni[indice..fine] {
            let posizione = u32::try_from(*posizione).map_err(|_| Refusal::TooLarge)?;
            righe.push(1);
            righe.extend_from_slice(&posizione.to_be_bytes());
            righe.extend_from_slice(&id.1.to_be_bytes());
        }
        indice = fine;
    }

    let mut flusso = Dictionary::new();
    flusso.set("Type", Object::Name(b"XRef".to_vec()));
    flusso.set("Size", Object::Integer(i64::from(riferimenti_id.0) + 1));
    flusso.set("W", Object::Array(vec![1.into(), 4.into(), 2.into()]));
    flusso.set("Index", Object::Array(gruppi));
    // Del trailer di prima restano soltanto il catalogo, le informazioni e
    // l'identificativo: il resto descriveva l'altro flusso.
    for chiave in [b"Root".as_slice(), b"Info", b"ID"] {
        if let Ok(valore) = documento.trailer.get(chiave) {
            flusso.set(chiave.to_vec(), valore.clone());
        }
    }
    flusso.set(
        "Prev",
        Object::Integer(i64::try_from(precedente).unwrap_or(i64::MAX)),
    );
    flusso.set(
        "Length",
        Object::Integer(i64::try_from(righe.len()).unwrap_or(0)),
    );
    copia.extend_from_slice(format!("{} {} obj\n", riferimenti_id.0, riferimenti_id.1).as_bytes());
    write_object(&mut copia, &Object::Dictionary(flusso))?;
    copia.extend_from_slice(b"\nstream\n");
    copia.extend_from_slice(&righe);
    copia.extend_from_slice(b"\nendstream\nendobj\n");
    copia.extend_from_slice(format!("startxref\n{tabella}\n%%EOF\n").as_bytes());

    // Adesso le misure sono note: il `/ByteRange` si riempie al suo posto.
    let numeri = format!(
        "{:0>w$} {:0>w$} {:0>w$}",
        contenuto_inizio,
        contenuto_fine,
        copia.len() - contenuto_fine,
        w = BYTE_RANGE_DIGITS
    );
    if numeri.len() != segnaposto.len() {
        return Err(Refusal::TooLarge);
    }
    copia[byte_range..byte_range + numeri.len()].copy_from_slice(numeri.as_bytes());

    Ok(Prepared {
        bytes: copia,
        contents: contenuto_inizio..contenuto_fine,
    })
}

/// Rilegge la firma dentro un PDF: l'ultima, quella dell'aggiornamento in
/// fondo. `None` se non c'è o se il `/ByteRange` non descrive questo file.
#[must_use]
pub(crate) fn read_signature(bytes: &[u8]) -> Option<EmbeddedSignature> {
    const CHIAVE: &[u8] = b"/ByteRange";
    let posizione = bytes
        .windows(CHIAVE.len())
        .rposition(|finestra| finestra == CHIAVE)?;
    let resto = bytes.get(posizione + CHIAVE.len()..)?;
    let aperta = resto.iter().position(|byte| !byte.is_ascii_whitespace())?;
    if resto[aperta] != b'[' {
        return None;
    }
    let chiusa = resto[aperta..].iter().position(|byte| *byte == b']')? + aperta;
    let testo = std::str::from_utf8(&resto[aperta + 1..chiusa]).ok()?;
    let numeri: Vec<usize> = testo
        .split_ascii_whitespace()
        .map(str::parse)
        .collect::<Result<_, _>>()
        .ok()?;
    let [0, primo, secondo_inizio, secondo] = numeri[..] else {
        return None;
    };
    if primo >= secondo_inizio
        || secondo_inizio.checked_add(secondo)? != bytes.len()
        || bytes.get(primo) != Some(&b'<')
        || bytes.get(secondo_inizio - 1) != Some(&b'>')
    {
        return None;
    }
    let cifre = &bytes[primo + 1..secondo_inizio - 1];
    if !cifre.len().is_multiple_of(2) {
        return None;
    }
    let mut cms = Vec::with_capacity(cifre.len() / 2);
    for coppia in cifre.chunks(2) {
        let coppia = std::str::from_utf8(coppia).ok()?;
        cms.push(u8::from_str_radix(coppia, 16).ok()?);
    }
    cms.truncate(der_length(&cms)?);

    let mut coperti = Vec::with_capacity(primo + secondo);
    coperti.extend_from_slice(&bytes[..primo]);
    coperti.extend_from_slice(&bytes[secondo_inizio..]);
    Some(EmbeddedSignature {
        signed_content: coperti,
        cms,
    })
}

/// La lunghezza di una struttura DER che comincia con una `SEQUENCE`: gli
/// zeri che riempiono lo spazio dopo il CMS non fanno parte della firma.
fn der_length(der: &[u8]) -> Option<usize> {
    if der.first() != Some(&0x30) {
        return None;
    }
    let primo = usize::from(*der.get(1)?);
    let totale = if primo < 0x80 {
        2 + primo
    } else {
        let cifre = primo - 0x80;
        if cifre == 0 || cifre > 4 {
            return None;
        }
        let lunghezza = der
            .get(2..2 + cifre)?
            .iter()
            .fold(0_usize, |somma, byte| (somma << 8) | usize::from(*byte));
        2 + cifre + lunghezza
    };
    (totale <= der.len()).then_some(totale)
}

/// L'istante nel formato delle date PDF, in UTC.
fn pdf_date(when: Timestamp) -> String {
    let cifre: String = when
        .to_w3cdtf_utc()
        .chars()
        .filter(char::is_ascii_digit)
        .take(14)
        .collect();
    format!("D:{cifre}+00'00'")
}

/// Scrive un oggetto PDF. I flussi non servono qui, e si rifiutano.
fn write_object(out: &mut Vec<u8>, object: &Object) -> Result<(), Refusal> {
    match object {
        Object::Null => out.extend_from_slice(b"null"),
        Object::Boolean(valore) => out.extend_from_slice(if *valore { b"true" } else { b"false" }),
        Object::Integer(valore) => out.extend_from_slice(valore.to_string().as_bytes()),
        Object::Real(valore) => out.extend_from_slice(valore.to_string().as_bytes()),
        Object::Name(nome) => write_name(out, nome),
        Object::String(testo, StringFormat::Literal) => {
            out.push(b'(');
            for byte in testo {
                if matches!(byte, b'(' | b')' | b'\\') {
                    out.push(b'\\');
                }
                out.push(*byte);
            }
            out.push(b')');
        }
        Object::String(testo, StringFormat::Hexadecimal) => {
            out.push(b'<');
            for byte in testo {
                out.extend_from_slice(format!("{byte:02X}").as_bytes());
            }
            out.push(b'>');
        }
        Object::Array(elenco) => {
            out.push(b'[');
            for (indice, elemento) in elenco.iter().enumerate() {
                if indice > 0 {
                    out.push(b' ');
                }
                write_object(out, elemento)?;
            }
            out.push(b']');
        }
        Object::Dictionary(dizionario) => {
            out.extend_from_slice(b"<<");
            for (chiave, valore) in dizionario {
                write_name(out, chiave);
                out.push(b' ');
                write_object(out, valore)?;
                out.push(b' ');
            }
            out.extend_from_slice(b">>");
        }
        Object::Reference(id) => out.extend_from_slice(format!("{} {} R", id.0, id.1).as_bytes()),
        Object::Stream(_) => {
            return Err(Refusal::NotOurs);
        }
    }
    Ok(())
}

/// Scrive un nome PDF, con `#` e due cifre per i caratteri che non vanno
/// scritti come sono (ISO 32000-1 §7.3.5).
fn write_name(out: &mut Vec<u8>, nome: &[u8]) {
    out.push(b'/');
    for byte in nome {
        if (0x21..=0x7E).contains(byte) && !b"()<>[]{}/%#".contains(byte) {
            out.push(*byte);
        } else {
            out.extend_from_slice(format!("#{byte:02X}").as_bytes());
        }
    }
}

#[cfg(test)]
mod tests {
    use lisi_core::Timestamp;

    use super::{CONTENTS_BYTES, prepare, read_signature};
    use crate::report_narrative::{Block, Letterhead, NarrativeReport};
    use crate::report_pdf::{PdfKind, render};

    fn relazione() -> Vec<u8> {
        let report = NarrativeReport {
            generated_at: Timestamp::from_millis(1_752_086_400_000),
            letterhead: Letterhead {
                emblem: None,
                lines: Vec::new(),
            },
            footer: Vec::new(),
            blocks: vec![Block::Paragraph(String::from("Relazione di prova"))],
        };
        let Ok(byte) = render(&report, PdfKind::Narrative) else {
            panic!("la relazione deve scriversi");
        };
        byte
    }

    fn adesso() -> Timestamp {
        Timestamp::from_millis(1_762_400_000_000)
    }

    /// Un CMS finto ma con la forma DER: una `SEQUENCE` lunga 300 byte.
    fn cms() -> Vec<u8> {
        let mut cms = vec![0x30, 0x82, 0x01, 0x2C];
        cms.extend((0..300_u16).map(|indice| u8::try_from(indice % 251).unwrap_or(0) + 1));
        cms
    }

    /// **I byte del PDF di partenza restano tutti** (ADR-0181, decisione 6):
    /// la copia comincia con il PDF deterministico, il `/ByteRange` copre
    /// tutto tranne `/Contents`, e la firma si rilegge uguale.
    #[test]
    fn la_copia_comincia_con_il_pdf_e_la_firma_si_rilegge() {
        let originale = relazione();
        let preparato = match prepare(&originale, adesso()) {
            Ok(preparato) => preparato,
            Err(motivo) => panic!("la relazione del programma si prepara: {motivo:?}"),
        };
        let coperti = preparato.signed_content();
        let Ok(copia) = preparato.fill(&cms()) else {
            panic!("la firma ci sta");
        };

        assert!(
            copia.starts_with(&originale),
            "il PDF di partenza è il prefisso"
        );
        assert!(copia.ends_with(b"%%EOF\n"));
        let Some(letta) = read_signature(&copia) else {
            panic!("la firma si rilegge");
        };
        assert_eq!(letta.cms, cms(), "senza gli zeri dello spazio riservato");
        assert_eq!(letta.signed_content, coperti, "gli stessi byte firmati");
        assert_eq!(
            copia.len() - letta.signed_content.len(),
            CONTENTS_BYTES * 2 + 2,
            "fuori resta soltanto il valore di /Contents"
        );

        let testo = String::from_utf8_lossy(&copia[originale.len()..]);
        for atteso in [
            "/SubFilter /ETSI.CAdES.detached",
            "/Filter /Adobe.PPKLite",
            "/M (D:20251106",
            "/FT /Sig",
            "/SigFlags 3",
            "/Rect [0 0 0 0]",
            "/Prev ",
        ] {
            assert!(testo.contains(atteso), "manca «{atteso}»");
        }
        assert!(!testo.contains("%PDF"), "nessuna seconda intestazione");

        // La copia è un PDF che si legge, con il campo firma nel catalogo.
        let Ok(documento) = lopdf::Document::load_mem(&copia) else {
            panic!("la copia si legge come PDF");
        };
        let Ok(catalogo) = documento.catalog() else {
            panic!("il catalogo c'è");
        };
        assert!(catalogo.has(b"AcroForm"));
        assert_eq!(documento.get_pages().len(), 1);
    }

    /// **Una firma che non ci sta non si scrive**, e un PDF già firmato, o
    /// che non è del programma, non si prepara (DEC-464, decisioni 4 e 5).
    #[test]
    fn un_pdf_che_non_e_del_programma_o_gia_firmato_non_si_prepara() {
        let originale = relazione();
        let Ok(preparato) = prepare(&originale, adesso()) else {
            panic!("si prepara");
        };
        assert!(
            preparato
                .clone()
                .fill(&vec![0x30; CONTENTS_BYTES + 1])
                .is_err()
        );
        assert!(preparato.fill(&[]).is_err());

        let Ok(preparato) = prepare(&originale, adesso()) else {
            panic!("si prepara");
        };
        let Ok(firmata) = preparato.fill(&cms()) else {
            panic!("si firma");
        };
        assert!(prepare(&firmata, adesso()).is_err(), "già firmata");
        assert!(prepare(b"non sono un PDF", adesso()).is_err());
        assert!(prepare(&originale[..originale.len() / 2], adesso()).is_err());
    }

    /// **Una firma che non descrive il file non si rilegge**: un byte in più
    /// in fondo, o un PDF senza firma.
    #[test]
    fn una_firma_che_non_descrive_il_file_non_si_rilegge() {
        let originale = relazione();
        assert_eq!(read_signature(&originale), None);
        let Ok(preparato) = prepare(&originale, adesso()) else {
            panic!("si prepara");
        };
        let Ok(mut copia) = preparato.fill(&cms()) else {
            panic!("si firma");
        };
        copia.push(b'\n');
        assert_eq!(read_signature(&copia), None, "un byte in più in fondo");
    }

    /// **Lo stesso PDF e lo stesso istante danno la stessa copia**: niente
    /// orologio e niente caso, come per il PDF di partenza (ADR-0034).
    #[test]
    fn la_copia_preparata_e_deterministica() {
        let originale = relazione();
        let (Ok(una), Ok(altra)) = (prepare(&originale, adesso()), prepare(&originale, adesso()))
        else {
            panic!("si prepara");
        };
        assert_eq!(una.signed_content(), altra.signed_content());
    }
}
