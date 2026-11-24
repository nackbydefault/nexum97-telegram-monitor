//! Il registro analitico scritto come `.xlsx`.
//!
//! Traduce la struttura di [`crate::report_ledger`] in un foglio di calcolo.
//! Qui non si decide **che cosa** il registro dice: quello e' gia' deciso, e si
//! prova la' senza aprire un archivio.
//!
//! # La cosa piu' importante di questo modulo
//!
//! **Ogni cella di testo si scrive con `write_string`, sempre.** Un foglio di
//! calcolo non e' un documento passivo: una cella che comincia con `=`, `+`, `-`
//! o `@` viene interpretata da Excel come formula, e i contenuti che finiscono
//! qui dentro arrivano da Telegram, cioe' da una fonte ostile per definizione
//! (ADR-0031 Decisione 6).
//!
//! `write_string` scrive una cella **tipizzata come stringa** nel file OOXML.
//! Excel non valuta una cella di tipo stringa: ne mostra il testo. La differenza
//! con il CSV — dove l'iniezione di formule e' un problema reale — e' che il CSV
//! non ha tipi, e il programma che lo legge deve indovinare.
//!
//! # Perche' NON si antepone un apostrofo
//!
//! E' la mitigazione che si trova scritta ovunque, e qui sarebbe **sbagliata**.
//! Il file prodotto e' un `.xlsx` vero, con celle tipizzate: la cella non e' una
//! formula perche' e' dichiarata stringa, non perche' comincia in un certo
//! modo. Anteporre un apostrofo o uno spazio significherebbe **alterare il testo
//! acquisito** — e questo registro esiste per dire che cosa la fonte ha
//! pubblicato, non una versione ritoccata perche' faceva paura.
//!
//! Il rischio residuo si dichiara invece di nasconderlo: chi **riesporta** questo
//! foglio in CSV, o ne copia una cella in un altro programma, perde la
//! tipizzazione e riapre il problema. Non e' governabile da qui, e la prova
//! negativa verifica cio' che questo modulo puo' garantire — che nel file
//! prodotto quella cella non sia una formula.
//!
//! # Determinismo
//!
//! La libreria scrive nelle proprieta' del file l'istante corrente, che
//! cambierebbe a ogni generazione e romperebbe il criterio 30. Si fissa con
//! l'istante di generazione, che e' un **ingresso**: a parita' di ingresso il
//! file e' identico, e la data smette di essere una bugia — la stessa scelta
//! fatta per il DOCX.

use rust_xlsxwriter::{DocProperties, ExcelDateTime, Format, Workbook, Worksheet};

use crate::error::{ServiceError, ServiceResult};
use crate::report_ledger::{Cell, Ledger, Sheet};

/// Larghezza minima di una colonna, in caratteri.
const MIN_WIDTH: f64 = 10.0;

/// Larghezza massima di una colonna, in caratteri.
///
/// Il testo di un messaggio puo' essere lungo migliaia di caratteri: una colonna
/// dimensionata sul contenuto piu' lungo renderebbe il foglio illeggibile e
/// impossibile da stampare. Oltre questa misura si lascia che Excel mandi a capo.
const MAX_WIDTH: f64 = 60.0;

/// Quanti caratteri si guardano per decidere la larghezza di una colonna.
///
/// Misurare ogni cella di un foglio da diecimila righe costerebbe piu' della
/// scrittura del file. Le prime righe bastano a dare la misura giusta, e il
/// tetto di [`MAX_WIDTH`] copre il resto.
const WIDTH_SAMPLE_ROWS: usize = 200;

/// Chi risulta autore del file.
///
/// **Non** il nome dell'operatore ne' quello della macchina: chi ha generato il
/// documento sta scritto nel registro di audit e dentro il documento stesso, e
/// ripeterlo nei metadati lo porterebbe fuori insieme al file senza che nessuno
/// l'abbia deciso. La stessa scelta del DOCX.
const AUTHOR: &str = "unknown";

/// Scrive il registro come documento `.xlsx`.
///
/// # Errori
///
/// Restituisce [`ServiceError::DocumentGeneration`] se la scrittura non riesce.
pub fn render(ledger: &Ledger) -> ServiceResult<Vec<u8>> {
    let mut workbook = Workbook::new();

    workbook.set_properties(&document_properties(ledger)?);

    let header_format = Format::new().set_bold();

    // In Esercitazione il primo foglio è la frase di SIC-17, e ogni foglio la
    // porta nell'intestazione di stampa (PR-13, ADR-0129).
    let esercitazione = crate::run_mode::is_exercise();
    if esercitazione {
        let avviso = workbook.add_worksheet();
        avviso.set_name("ESERCITAZIONE").map_err(translate)?;
        avviso
            .write_string_with_format(0, 0, crate::run_mode::EXERCISE_MARK, &header_format)
            .map_err(translate)?;
    }

    for sheet in &ledger.sheets {
        let worksheet = workbook.add_worksheet();
        if esercitazione {
            worksheet.set_header("&CESERCITAZIONE");
        }
        write_sheet(worksheet, sheet, &header_format)?;
    }

    workbook.save_to_buffer().map_err(translate)
}

/// Le proprieta' del file, con l'istante di generazione al posto di «adesso».
fn document_properties(ledger: &Ledger) -> ServiceResult<DocProperties> {
    // `ExcelDateTime` conta in secondi; il dominio in millisecondi.
    let seconds = ledger.generated_at.as_millis() / 1_000;
    let created = ExcelDateTime::from_timestamp(seconds).map_err(translate)?;

    Ok(DocProperties::new()
        .set_author(AUTHOR)
        .set_title("Registro analitico del monitoraggio")
        .set_creation_datetime(&created))
}

/// Scrive un foglio: intestazioni, righe, filtri e larghezze.
fn write_sheet(
    worksheet: &mut Worksheet,
    sheet: &Sheet,
    header_format: &Format,
) -> ServiceResult<()> {
    worksheet.set_name(&sheet.name).map_err(translate)?;

    for (column, header) in sheet.headers.iter().enumerate() {
        let column = column_index(column)?;
        worksheet
            .write_string_with_format(0, column, header.as_str(), header_format)
            .map_err(translate)?;
    }

    for (row, cells) in sheet.rows.iter().enumerate() {
        // Riga 0 e' l'intestazione: i dati cominciano da 1.
        let row = row_index(row + 1)?;
        for (column, cell) in cells.iter().enumerate() {
            let column = column_index(column)?;
            write_cell(worksheet, row, column, cell)?;
        }
    }

    // L'intestazione resta visibile scorrendo: un foglio da mille righe senza
    // questo si legge tenendo a mente l'ordine delle colonne.
    worksheet.set_freeze_panes(1, 0).map_err(translate)?;

    // Il filtro si mette **solo dove c'e' qualcosa da filtrare**: su un foglio
    // di coppie voce/valore sarebbe un comando che non serve a nulla, e su un
    // foglio senza righe Excel segnala un intervallo non valido.
    if sheet.rows.len() > 1 && sheet.headers.len() > 2 {
        let last_row = row_index(sheet.rows.len())?;
        let last_column = column_index(sheet.headers.len().saturating_sub(1))?;
        worksheet
            .autofilter(0, 0, last_row, last_column)
            .map_err(translate)?;
    }

    for (column, header) in sheet.headers.iter().enumerate() {
        let width = column_width(sheet, column, header);
        let column = column_index(column)?;
        worksheet
            .set_column_width(column, width)
            .map_err(translate)?;
    }

    Ok(())
}

/// Scrive una cella secondo il proprio genere.
///
/// **Il punto in cui l'iniezione di formule si neutralizza.** `write_string`
/// produce una cella tipizzata come stringa: Excel ne mostra il testo e non lo
/// valuta, qualunque cosa contenga. Nessun ramo di questa funzione chiama
/// `write_formula`, e non deve mai chiamarlo.
fn write_cell(worksheet: &mut Worksheet, row: u32, column: u16, cell: &Cell) -> ServiceResult<()> {
    match cell {
        // Il corpo di un contenuto si scrive come un testo qualunque: qui non
        // si accorcia nulla, perché una cella di foglio di calcolo tiene
        // trentaduemila caratteri e il registro in Excel è uno dei due posti
        // in cui il testo sta per intero (FINAL-PRODUCT-REVIEW-01, FPR-05).
        Cell::Text(value) | Cell::Body(value) => worksheet
            // Ammissibile in XML (FINAL-REVIEW-01, FR-027): un carattere che il
            // formato non ammette renderebbe il foglio illeggibile.
            .write_string(row, column, crate::report_docx::xml_sicuro(value.as_str()))
            .map_err(translate)?,
        Cell::Number(value) => worksheet
            .write_number(row, column, *value as f64)
            .map_err(translate)?,
    };
    Ok(())
}

/// Larghezza di una colonna, misurata sulle prime righe e limitata.
fn column_width(sheet: &Sheet, column: usize, header: &str) -> f64 {
    let longest = sheet
        .rows
        .iter()
        .take(WIDTH_SAMPLE_ROWS)
        .filter_map(|row| row.get(column))
        .map(|cell| cell.as_text().chars().count())
        .max()
        .unwrap_or(0);

    let measured = longest.max(header.chars().count());
    // Un paio di caratteri di respiro, altrimenti il testo tocca il bordo.
    let width = measured as f64 + 2.0;
    width.clamp(MIN_WIDTH, MAX_WIDTH)
}

/// Indice di riga, rifiutando cio' che Excel non regge.
fn row_index(row: usize) -> ServiceResult<u32> {
    u32::try_from(row).map_err(|_| ServiceError::DocumentGeneration {
        reason: String::from("il registro ha più righe di quante un foglio ne regga"),
    })
}

/// Indice di colonna, rifiutando cio' che Excel non regge.
fn column_index(column: usize) -> ServiceResult<u16> {
    u16::try_from(column).map_err(|_| ServiceError::DocumentGeneration {
        reason: String::from("il registro ha più colonne di quante un foglio ne regga"),
    })
}

/// Traduce un errore della libreria in un errore del servizio.
fn translate(error: rust_xlsxwriter::XlsxError) -> ServiceError {
    ServiceError::DocumentGeneration {
        reason: error.to_string(),
    }
}
