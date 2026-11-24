//! Il testo dentro un PDF: come si codifica e quanto e' largo.
//!
//! Sono le due cose che un generatore di PDF deve saper fare da se', e che
//! nessuna delle due librerie candidate regalava: `lopdf` costruisce oggetti
//! PDF e non impagina (ADR-0034).
//!
//! # Perche' un carattere incorporato nel formato
//!
//! Times Roman e' uno dei **quattordici font che ogni lettore PDF possiede per
//! definizione**. Usarlo significa non incorporare nulla: il documento non
//! porta con se' un file di carattere, non ne eredita la licenza, non cresce di
//! centinaia di kilobyte, e si apre identico ovunque. Ed e' lo stesso carattere
//! del documento Word, quindi relazione `.docx` e relazione `.pdf` si
//! somigliano invece di sembrare due documenti diversi.
//!
//! Il prezzo e' che le misure dei caratteri non si leggono da un file: stanno
//! qui sotto, trascritte dalle metriche del formato.

/// Larghezza attribuita a un carattere che non sappiamo misurare.
///
/// Non zero — una parola invisibile romperebbe il calcolo della riga — e non
/// un valore alto, che sprecherebbe spazio su ogni riga. E' la larghezza della
/// `o` minuscola, cioe' una lettera di corpo medio.
const UNKNOWN_WIDTH: u16 = 500;

/// Codifica un testo in WinAnsi, la codifica dichiarata dal carattere.
///
/// # Perche' WinAnsi e non UTF-8
///
/// Perche' i quattordici font incorporati nel formato PDF sono a **un byte per
/// carattere**: un PDF che li usa dichiara una tabella di codifica, e WinAnsi e'
/// quella che copre l'italiano — lettere accentate comprese — piu' i segni
/// tipografici che questo prodotto usa davvero: trattino lungo, virgolette
/// basse e alte, puntini di sospensione.
///
/// # Cio' che WinAnsi non rappresenta si scrive con il suo codice
///
/// Il testo che arriva qui e' **non fidato**: viene da Telegram, e puo'
/// contenere qualunque carattere Unicode — emoji, alfabeti non latini. Fino al
/// 2026-10-18 ciascuno diventava un punto interrogativo: visibile, ma
/// indistinguibile da un vero «?» e senza dire che cosa c'era (E2E01-04).
///
/// Ora una sequenza di caratteri non rappresentabili si scrive come il suo
/// **codice Unicode** fra parentesi quadre: «👍🏽» diventa `[U+1F44D U+1F3FD]`.
/// Nulla sparisce e nulla si inventa: il codice identifica il carattere senza
/// ambiguita', chiunque lo puo' verificare, e il testo integro resta nel DOCX,
/// nel TXT e nel foglio XLSX. La relazione PDF lo dichiara ([`CODE_NOTE`]).
#[must_use]
pub fn to_winansi(text: &str) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(text.len());
    let mut sequenza: Vec<u32> = Vec::new();

    for character in text.chars() {
        if let Some(byte) = winansi_byte(character) {
            push_codes(&mut bytes, &mut sequenza);
            bytes.push(byte);
        } else {
            sequenza.push(u32::from(character));
        }
    }
    push_codes(&mut bytes, &mut sequenza);
    bytes
}

/// La frase che la relazione PDF porta, una volta, per spiegare i codici.
pub const CODE_NOTE: &str = "I caratteri che il carattere tipografico di questo documento non può \
                             disegnare, come le emoji, sono scritti con il loro codice Unicode fra \
                             parentesi quadre, per esempio [U+1F600]. Il testo integro è nella \
                             relazione modificabile, nel registro testuale e nel foglio di calcolo.";

/// Se il testo contiene almeno un carattere che si scriverà con il codice.
#[must_use]
pub fn has_unrepresentable(text: &str) -> bool {
    text.chars()
        .any(|character| winansi_byte(character).is_none())
}

/// Scrive la sequenza raccolta come `[U+XXXX U+YYYY]` e la svuota.
fn push_codes(bytes: &mut Vec<u8>, sequenza: &mut Vec<u32>) {
    if sequenza.is_empty() {
        return;
    }
    let codici: Vec<String> = sequenza
        .iter()
        .map(|code| format!("U+{code:04X}"))
        .collect();
    bytes.push(b'[');
    bytes.extend_from_slice(codici.join(" ").as_bytes());
    bytes.push(b']');
    sequenza.clear();
}

/// Il byte WinAnsi di un carattere, o `None` se WinAnsi non lo rappresenta.
fn winansi_byte(character: char) -> Option<u8> {
    let byte = match character {
        // I segni tipografici stanno nella zona 0x80-0x9F, che in WinAnsi non
        // e' vuota come in Latin-1: e' proprio la ragione per cui serve WinAnsi.
        '\u{20AC}' => 0x80, // euro
        '\u{201A}' => 0x82,
        '\u{0192}' => 0x83,
        '\u{201E}' => 0x84,
        '\u{2026}' => 0x85, // puntini di sospensione
        '\u{2020}' => 0x86,
        '\u{2021}' => 0x87,
        '\u{02C6}' => 0x88,
        '\u{2030}' => 0x89,
        '\u{0160}' => 0x8A,
        '\u{2039}' => 0x8B,
        '\u{0152}' => 0x8C,
        '\u{017D}' => 0x8E,
        '\u{2018}' => 0x91, // apostrofo tipografico aperto
        '\u{2019}' => 0x92, // apostrofo tipografico chiuso
        '\u{201C}' => 0x93,
        '\u{201D}' => 0x94,
        '\u{2022}' => 0x95,
        '\u{2013}' => 0x96, // trattino medio
        '\u{2014}' => 0x97, // trattino lungo
        '\u{02DC}' => 0x98,
        '\u{2122}' => 0x99,
        '\u{0161}' => 0x9A,
        '\u{203A}' => 0x9B,
        '\u{0153}' => 0x9C,
        '\u{017E}' => 0x9E,
        '\u{0178}' => 0x9F,
        // Il resto di Latin-1 coincide con Unicode, tabulazione e ritorno a
        // capo esclusi: dentro una riga di PDF non hanno senso e diventerebbero
        // caratteri di controllo dentro il flusso.
        '\t' | '\n' | '\r' => b' ',
        other if (other as u32) >= 0x20 && (other as u32) <= 0x7E => other as u8,
        other if (other as u32) >= 0xA0 && (other as u32) <= 0xFF => {
            return u8::try_from(other as u32).ok();
        }
        _ => return None,
    };
    Some(byte)
}

/// Larghezza di un testo in millesimi di em, con il carattere indicato.
///
/// Il risultato si moltiplica per il corpo in punti e si divide per mille per
/// avere la larghezza in punti tipografici.
#[must_use]
pub fn width_mille(text: &str, bold: bool) -> u32 {
    to_winansi(text)
        .into_iter()
        .map(|byte| u32::from(char_width(byte, bold)))
        .sum()
}

/// Larghezza di un singolo byte WinAnsi, in millesimi di em.
fn char_width(byte: u8, bold: bool) -> u16 {
    let index = usize::from(byte);
    let table = if bold { &TIMES_BOLD } else { &TIMES_ROMAN };
    table
        .get(index)
        .copied()
        .filter(|w| *w > 0)
        .unwrap_or(UNKNOWN_WIDTH)
}

/// Metriche di Times Roman, in millesimi di em, indicizzate per byte WinAnsi.
///
/// Trascritte dalle metriche del formato. Uno zero significa «non misurato», e
/// prende [`UNKNOWN_WIDTH`].
static TIMES_ROMAN: [u16; 256] = {
    let mut w = [0_u16; 256];
    w[32] = 250;
    w[33] = 333;
    w[34] = 408;
    w[35] = 500;
    w[36] = 500;
    w[37] = 833;
    w[38] = 778;
    w[39] = 333;
    w[40] = 333;
    w[41] = 333;
    w[42] = 500;
    w[43] = 564;
    w[44] = 250;
    w[45] = 333;
    w[46] = 250;
    w[47] = 278;
    // cifre
    w[48] = 500;
    w[49] = 500;
    w[50] = 500;
    w[51] = 500;
    w[52] = 500;
    w[53] = 500;
    w[54] = 500;
    w[55] = 500;
    w[56] = 500;
    w[57] = 500;
    w[58] = 278;
    w[59] = 278;
    w[60] = 564;
    w[61] = 564;
    w[62] = 564;
    w[63] = 444;
    w[64] = 921;
    // maiuscole
    w[65] = 722;
    w[66] = 667;
    w[67] = 667;
    w[68] = 722;
    w[69] = 611;
    w[70] = 556;
    w[71] = 722;
    w[72] = 722;
    w[73] = 333;
    w[74] = 389;
    w[75] = 722;
    w[76] = 611;
    w[77] = 889;
    w[78] = 722;
    w[79] = 722;
    w[80] = 556;
    w[81] = 722;
    w[82] = 667;
    w[83] = 556;
    w[84] = 611;
    w[85] = 722;
    w[86] = 722;
    w[87] = 944;
    w[88] = 722;
    w[89] = 722;
    w[90] = 611;
    w[91] = 333;
    w[92] = 278;
    w[93] = 333;
    w[94] = 469;
    w[95] = 500;
    w[96] = 333;
    // minuscole
    w[97] = 444;
    w[98] = 500;
    w[99] = 444;
    w[100] = 500;
    w[101] = 444;
    w[102] = 333;
    w[103] = 500;
    w[104] = 500;
    w[105] = 278;
    w[106] = 278;
    w[107] = 500;
    w[108] = 278;
    w[109] = 778;
    w[110] = 500;
    w[111] = 500;
    w[112] = 500;
    w[113] = 500;
    w[114] = 333;
    w[115] = 389;
    w[116] = 278;
    w[117] = 500;
    w[118] = 500;
    w[119] = 722;
    w[120] = 500;
    w[121] = 500;
    w[122] = 444;
    w[123] = 480;
    w[124] = 200;
    w[125] = 480;
    w[126] = 541;
    // segni tipografici
    w[133] = 1000;
    w[145] = 333;
    w[146] = 333;
    w[147] = 444;
    w[148] = 444;
    w[149] = 350;
    w[150] = 500;
    w[151] = 1000;
    // Latin-1 usato dall'italiano
    w[160] = 250;
    w[167] = 500;
    w[171] = 500;
    w[176] = 400;
    w[186] = 300;
    w[187] = 500;
    w[192] = 722;
    w[193] = 722;
    w[194] = 722;
    w[195] = 722;
    w[196] = 722;
    w[197] = 722;
    w[199] = 667;
    w[200] = 611;
    w[201] = 611;
    w[202] = 611;
    w[203] = 611;
    w[204] = 333;
    w[205] = 333;
    w[206] = 333;
    w[207] = 333;
    w[210] = 722;
    w[211] = 722;
    w[212] = 722;
    w[213] = 722;
    w[214] = 722;
    w[217] = 722;
    w[218] = 722;
    w[219] = 722;
    w[220] = 722;
    w[224] = 444;
    w[225] = 444;
    w[226] = 444;
    w[227] = 444;
    w[228] = 444;
    w[229] = 444;
    w[231] = 444;
    w[232] = 444;
    w[233] = 444;
    w[234] = 444;
    w[235] = 444;
    w[236] = 278;
    w[237] = 278;
    w[238] = 278;
    w[239] = 278;
    w[241] = 500;
    w[242] = 500;
    w[243] = 500;
    w[244] = 500;
    w[245] = 500;
    w[246] = 500;
    w[249] = 500;
    w[250] = 500;
    w[251] = 500;
    w[252] = 500;
    w
};

/// Metriche di Times Bold, per i titoli e gli attacchi in grassetto.
static TIMES_BOLD: [u16; 256] = {
    let mut w = [0_u16; 256];
    w[32] = 250;
    w[33] = 333;
    w[34] = 555;
    w[35] = 500;
    w[36] = 500;
    w[37] = 1000;
    w[38] = 833;
    w[39] = 333;
    w[40] = 333;
    w[41] = 333;
    w[42] = 500;
    w[43] = 570;
    w[44] = 250;
    w[45] = 333;
    w[46] = 250;
    w[47] = 278;
    w[48] = 500;
    w[49] = 500;
    w[50] = 500;
    w[51] = 500;
    w[52] = 500;
    w[53] = 500;
    w[54] = 500;
    w[55] = 500;
    w[56] = 500;
    w[57] = 500;
    w[58] = 333;
    w[59] = 333;
    w[60] = 570;
    w[61] = 570;
    w[62] = 570;
    w[63] = 500;
    w[64] = 930;
    w[65] = 722;
    w[66] = 667;
    w[67] = 722;
    w[68] = 722;
    w[69] = 667;
    w[70] = 611;
    w[71] = 778;
    w[72] = 778;
    w[73] = 389;
    w[74] = 500;
    w[75] = 778;
    w[76] = 667;
    w[77] = 944;
    w[78] = 722;
    w[79] = 778;
    w[80] = 611;
    w[81] = 778;
    w[82] = 722;
    w[83] = 556;
    w[84] = 667;
    w[85] = 722;
    w[86] = 722;
    w[87] = 1000;
    w[88] = 722;
    w[89] = 722;
    w[90] = 667;
    w[91] = 333;
    w[92] = 278;
    w[93] = 333;
    w[94] = 581;
    w[95] = 500;
    w[96] = 333;
    w[97] = 500;
    w[98] = 556;
    w[99] = 444;
    w[100] = 556;
    w[101] = 444;
    w[102] = 333;
    w[103] = 500;
    w[104] = 556;
    w[105] = 278;
    w[106] = 333;
    w[107] = 556;
    w[108] = 278;
    w[109] = 833;
    w[110] = 556;
    w[111] = 500;
    w[112] = 556;
    w[113] = 556;
    w[114] = 444;
    w[115] = 389;
    w[116] = 333;
    w[117] = 556;
    w[118] = 500;
    w[119] = 722;
    w[120] = 500;
    w[121] = 500;
    w[122] = 444;
    w[123] = 394;
    w[124] = 220;
    w[125] = 394;
    w[126] = 520;
    w[133] = 1000;
    w[145] = 333;
    w[146] = 333;
    w[147] = 500;
    w[148] = 500;
    w[149] = 350;
    w[150] = 500;
    w[151] = 1000;
    w[160] = 250;
    w[167] = 500;
    w[171] = 500;
    w[176] = 400;
    w[186] = 330;
    w[187] = 500;
    w[192] = 722;
    w[193] = 722;
    w[194] = 722;
    w[195] = 722;
    w[196] = 722;
    w[197] = 722;
    w[199] = 722;
    w[200] = 667;
    w[201] = 667;
    w[202] = 667;
    w[203] = 667;
    w[204] = 389;
    w[205] = 389;
    w[206] = 389;
    w[207] = 389;
    w[210] = 778;
    w[211] = 778;
    w[212] = 778;
    w[213] = 778;
    w[214] = 778;
    w[217] = 722;
    w[218] = 722;
    w[219] = 722;
    w[220] = 722;
    w[224] = 500;
    w[225] = 500;
    w[226] = 500;
    w[227] = 500;
    w[228] = 500;
    w[229] = 500;
    w[231] = 444;
    w[232] = 444;
    w[233] = 444;
    w[234] = 444;
    w[235] = 444;
    w[236] = 278;
    w[237] = 278;
    w[238] = 278;
    w[239] = 278;
    w[241] = 556;
    w[242] = 500;
    w[243] = 500;
    w[244] = 500;
    w[245] = 500;
    w[246] = 500;
    w[249] = 556;
    w[250] = 556;
    w[251] = 556;
    w[252] = 556;
    w
};

/// Spezza un testo in righe che stanno entro la larghezza indicata.
///
/// # Perche' l'impaginazione la scriviamo noi
///
/// Perche' `lopdf` costruisce oggetti PDF e non impagina, e la libreria che
/// impaginava e' stata scartata per il determinismo (ADR-0034). E' codice
/// nostro su un percorso che produce documenti destinati a un ufficio, ed e'
/// per questo che e' una funzione **pura**, con le sue prove, invece di stare
/// dentro il generatore.
///
/// Una parola piu' larga della riga **non si spezza**: esce dal margine invece
/// di essere tagliata a meta'. Un URL tagliato a meta' e' un URL che nessuno
/// puo' piu' seguire, e un identificativo tagliato a meta' e' un identificativo
/// che non si ritrova nell'archivio.
#[must_use]
pub fn wrap(text: &str, max_width_mille: u32, bold: bool) -> Vec<String> {
    let mut lines = Vec::new();
    let mut current = String::new();
    let mut current_width = 0_u32;
    let space = width_mille(" ", bold);

    for word in text.split_whitespace() {
        let word_width = width_mille(word, bold);
        let needed = if current.is_empty() {
            word_width
        } else {
            current_width + space + word_width
        };

        // `mem::take` lascia `current` vuota, quindi il ramo qui sotto
        // riassegna comunque la larghezza: azzerarla qui sarebbe una riga che
        // nessuno legge.
        if !current.is_empty() && needed > max_width_mille {
            lines.push(std::mem::take(&mut current));
        }

        if current.is_empty() {
            current.push_str(word);
            current_width = word_width;
        } else {
            current.push(' ');
            current.push_str(word);
            current_width = needed;
        }
    }

    if !current.is_empty() {
        lines.push(current);
    }
    if lines.is_empty() {
        // Un paragrafo vuoto resta una riga vuota: toglierlo cambierebbe la
        // spaziatura del documento.
        lines.push(String::new());
    }
    lines
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn italian_accents_survive_the_encoding() {
        // Sono le lettere che l'italiano usa di piu', e sono anche quelle che
        // in una codifica sbagliata diventano due caratteri illeggibili.
        let bytes = to_winansi("citta' perche' cosi' e' piu' pero'");
        assert!(!bytes.contains(&b'['), "nessun codice per l'italiano");

        let accentate = to_winansi("à è é ì ò ù");
        assert_eq!(accentate[0], 0xE0);
        assert_eq!(accentate[2], 0xE8);
        assert_eq!(accentate[4], 0xE9);
        assert_eq!(accentate.len(), 11, "un byte per lettera, uno per spazio");
    }

    #[test]
    fn typographic_marks_land_in_the_winansi_range() {
        // Il trattino lungo e le virgolette basse compaiono nei documenti che
        // questo prodotto scrive: in Latin-1 puro non esistono, ed e' la
        // ragione per cui la codifica dichiarata e' WinAnsi.
        assert_eq!(to_winansi("\u{2014}"), vec![0x97]);
        assert_eq!(to_winansi("\u{2019}"), vec![0x92]);
        assert_eq!(to_winansi("\u{2026}"), vec![0x85]);
        assert_eq!(to_winansi("\u{00AB}"), vec![0xAB]);
    }

    #[test]
    fn what_cannot_be_written_becomes_visible_and_not_silent() {
        // Il testo viene da Telegram e puo' contenere qualunque cosa. Un
        // carattere che sparisce cambia il testo senza dirlo; il suo codice si
        // vede, e dice quale era (E2E01-04).
        let bytes = to_winansi("prova \u{4E2D}\u{6587} fine");
        assert_eq!(bytes, b"prova [U+4E2D U+6587] fine".to_vec());
        assert!(
            !bytes.contains(&b'?'),
            "nessun punto interrogativo inventato"
        );
    }

    /// **Le emoji del «Testo conservato» non diventano «??»** (E2E01-04): una
    /// sequenza — base, tono, giunzione, variante — si scrive intera, e un
    /// vero punto interrogativo resta un punto interrogativo.
    #[test]
    fn le_emoji_si_scrivono_con_il_loro_codice() {
        assert_eq!(
            to_winansi("ok \u{1F44D}\u{1F3FD} davvero?"),
            b"ok [U+1F44D U+1F3FD] davvero?".to_vec()
        );
        assert_eq!(
            to_winansi("\u{2764}\u{FE0F}"),
            b"[U+2764 U+FE0F]".to_vec(),
            "il cuore con il selettore di variante"
        );
        assert_eq!(
            to_winansi("a\u{1F600} \u{1F601}b"),
            b"a[U+1F600] [U+1F601]b".to_vec(),
            "lo spazio separa due sequenze"
        );
        // La misura segue i byte scritti: la riga si spezza sul codice vero.
        assert_eq!(
            width_mille("\u{1F600}", false),
            width_mille("[U+1F600]", false)
        );
        assert!(CODE_NOTE.contains("[U+1F600]"));
    }

    #[test]
    fn control_characters_do_not_reach_the_content_stream() {
        // Un ritorno a capo dentro una riga di testo PDF romperebbe il flusso.
        let bytes = to_winansi("prima\nseconda\tterza");
        assert_eq!(bytes, b"prima seconda terza".to_vec());
    }

    #[test]
    fn a_wider_text_measures_wider() {
        assert!(width_mille("mmm", false) > width_mille("iii", false));
        assert!(width_mille("Relazione", true) > width_mille("Relazione", false));
        assert_eq!(width_mille("", false), 0);
    }

    #[test]
    fn wrapping_respects_the_declared_width() {
        let testo = "Relazione di servizio relativa al monitoraggio autorizzato \
                     di fonti Telegram accessibili a un account d'ufficio.";
        let larghezza = 20_000; // circa 40 caratteri a corpo pieno
        let righe = wrap(testo, larghezza, false);

        assert!(righe.len() > 1, "il testo non e' stato spezzato");
        for riga in &righe {
            assert!(
                width_mille(riga, false) <= larghezza,
                "la riga «{riga}» supera la larghezza dichiarata"
            );
        }
    }

    #[test]
    fn a_word_longer_than_the_line_is_not_cut_in_half() {
        // Un URL tagliato a meta' e' un URL che nessuno puo' piu' seguire.
        let url = "https://esempio.invalid/un/percorso/molto/lungo/che/non/entra";
        let righe = wrap(url, 5_000, false);

        assert_eq!(righe.len(), 1);
        assert_eq!(righe[0], url, "la parola e' stata spezzata");
    }

    #[test]
    fn wrapping_loses_no_word() {
        let testo = "una due tre quattro cinque sei sette otto nove dieci undici";
        let righe = wrap(testo, 8_000, false);
        let ricomposto = righe.join(" ");
        assert_eq!(
            ricomposto, testo,
            "l'impaginazione ha perso o spostato parole"
        );
    }

    #[test]
    fn an_empty_paragraph_stays_one_empty_line() {
        assert_eq!(wrap("", 10_000, false), vec![String::new()]);
        assert_eq!(wrap("   ", 10_000, false), vec![String::new()]);
    }
}
