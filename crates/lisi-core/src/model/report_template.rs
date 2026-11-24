//! Il profilo di template: tutto cio' che il prodotto **non** sa di se'.
//!
//! Motivato in ADR-0031 Decisione 15 e verificato dal criterio 22 di
//! accettazione della Milestone 18.
//!
//! # Perche' questo tipo esiste, ed e' vuoto per costruzione
//!
//! Denominazioni di uffici, stemmi, destinatari, qualifiche e luoghi non
//! appartengono al programma: appartengono a chi lo usa. Se stessero nel
//! sorgente, il prodotto smetterebbe di essere uno strumento e diventerebbe il
//! modulo prestampato di un ufficio particolare — e ogni altro ufficio si
//! troverebbe a consegnare documenti con l'intestazione di qualcun altro.
//!
//! [`ReportTemplateProfile::default`] non contiene **nessun** dato
//! istituzionale, e un test lo verifica campo per campo. Un profilo vuoto e'
//! uno stato legittimo: produce documenti senza intestazione, non documenti con
//! un'intestazione inventata.
//!
//! # Il campo che non c'e'
//!
//! Non esiste un campo per il numero di telefono dell'account monitorante. E'
//! il criterio 21 espresso come assenza: un campo che non esiste non si
//! stampa per distrazione.

use crate::error::{DomainError, DomainResult};

/// Un valore testuale del profilo, validato.
///
/// # Perche' la validazione sta qui e non nel generatore
///
/// Questi valori finiscono nell'intestazione di un documento che l'ufficio
/// consegna. Un carattere di controllo, un ritorno a capo inatteso o un
/// carattere che alteri l'ordine di lettura bidirezionale li' non e' un difetto
/// estetico: e' un documento che mostra qualcosa di diverso da cio' che
/// contiene. Validare all'ingresso costa un punto solo; validare in tre
/// generatori costa tre occasioni di dimenticarsene.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct TemplateField(String);

impl TemplateField {
    /// Nome del campo, usato nei messaggi di errore.
    pub const FIELD: &'static str = "campo_profilo_documentale";

    /// Lunghezza massima ammessa, in caratteri.
    ///
    /// Duecento caratteri stanno in una riga di intestazione di un A4 con
    /// margini professionali. Oltre, non e' piu' un'intestazione.
    pub const MAX_CHARS: usize = 200;

    /// Costruisce il valore validandolo.
    ///
    /// # Errori
    ///
    /// Restituisce un [`DomainError`] se il testo e' vuoto dopo la ripulitura
    /// dei bianchi, se supera [`Self::MAX_CHARS`], o se contiene caratteri di
    /// controllo o di alterazione dell'ordine di lettura.
    pub fn try_new(raw: &str) -> DomainResult<Self> {
        let trimmed = raw.trim();
        if trimmed.is_empty() {
            return Err(DomainError::Empty { field: Self::FIELD });
        }

        let length = trimmed.chars().count();
        if length > Self::MAX_CHARS {
            return Err(DomainError::TooLong {
                field: Self::FIELD,
                max: Self::MAX_CHARS,
                actual: length,
            });
        }

        if trimmed.chars().any(is_forbidden) {
            return Err(DomainError::ControlCharacters { field: Self::FIELD });
        }

        Ok(Self(trimmed.to_owned()))
    }

    /// Contenuto validato.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Consuma il valore restituendo la stringa interna.
    #[must_use]
    pub fn into_inner(self) -> String {
        self.0
    }
}

impl core::fmt::Display for TemplateField {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str(&self.0)
    }
}

/// Caratteri che un valore del profilo non puo' contenere.
///
/// Oltre ai caratteri di controllo veri e propri, sono vietati i comandi di
/// alterazione dell'ordine di lettura bidirezionale: sono invisibili e possono
/// far leggere un testo al contrario di come e' scritto.
fn is_forbidden(character: char) -> bool {
    character.is_control()
        || matches!(
            character,
            '\u{200e}'..='\u{200f}' | '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}'
        )
}

/// Lo stemma dell'ufficio: un'immagine **locale**, validata, in memoria.
///
/// # Perche' i byte e non un percorso
///
/// Un percorso dentro il dominio sarebbe un invito a leggere un file da dove il
/// dominio non deve leggere niente. Chi apre il file e' l'applicazione, che sa
/// gia' farlo e ha gia' le proprie regole; qui arrivano **byte gia' letti**, e
/// il dominio si limita a dire se siano utilizzabili.
///
/// # Perche' solo PNG
///
/// Il pacchetto OOXML scrive il media come `media/<id>.png`, e la libreria
/// adottata e' compilata **senza** la propria funzione di conversione
/// (`default-features = false`): un JPEG passato di qui finirebbe dentro un
/// file chiamato `.png`, che Word non aprirebbe.
///
/// La conseguenza buona e' che nessun decodificatore di immagini entra nel
/// binario: di questo file si leggono la firma e **dodici byte di
/// intestazione**, e il resto viene passato a Word senza essere interpretato.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TemplateEmblem {
    bytes: Vec<u8>,
    width_px: u32,
    height_px: u32,
}

/// La firma con cui comincia ogni PNG.
const PNG_SIGNATURE: [u8; 8] = [0x89, b'P', b'N', b'G', 0x0d, 0x0a, 0x1a, 0x0a];

impl TemplateEmblem {
    /// Dimensione massima accettata, in byte.
    ///
    /// Due mebibyte sono molto piu' di quanto serva a uno stemma alto un
    /// centimetro e mezzo, e molto meno di quanto basti a gonfiare un pacchetto
    /// che poi va consegnato.
    pub const MAX_BYTES: usize = 2 * 1024 * 1024;

    /// Lato massimo accettato, in pixel.
    pub const MAX_SIDE_PX: u32 = 10_000;

    /// Costruisce lo stemma da un PNG gia' letto dal disco.
    ///
    /// # Errori
    ///
    /// Restituisce [`DomainError::InvalidImage`] se i byte non sono un PNG, se
    /// l'intestazione non e' leggibile, se le dimensioni sono nulle o assurde,
    /// o se il file supera [`Self::MAX_BYTES`].
    pub fn from_png(bytes: Vec<u8>) -> DomainResult<Self> {
        if bytes.len() > Self::MAX_BYTES {
            return Err(DomainError::InvalidImage {
                reason: "il file supera i due megabyte",
            });
        }
        // 8 di firma + 8 di intestazione del blocco + 8 di dimensioni.
        if bytes.len() < 24 || bytes[..8] != PNG_SIGNATURE {
            return Err(DomainError::InvalidImage {
                reason: "non è un'immagine PNG",
            });
        }
        if &bytes[12..16] != b"IHDR" {
            return Err(DomainError::InvalidImage {
                reason: "l'intestazione del PNG non è leggibile",
            });
        }

        let width_px = u32::from_be_bytes([bytes[16], bytes[17], bytes[18], bytes[19]]);
        let height_px = u32::from_be_bytes([bytes[20], bytes[21], bytes[22], bytes[23]]);

        if width_px == 0 || height_px == 0 {
            return Err(DomainError::InvalidImage {
                reason: "l'immagine dichiara una dimensione nulla",
            });
        }
        if width_px > Self::MAX_SIDE_PX || height_px > Self::MAX_SIDE_PX {
            return Err(DomainError::InvalidImage {
                reason: "l'immagine è troppo grande",
            });
        }

        Ok(Self {
            bytes,
            width_px,
            height_px,
        })
    }

    /// I byte dell'immagine, come vanno scritti nel pacchetto.
    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Larghezza dichiarata dall'immagine, in pixel.
    #[must_use]
    pub const fn width_px(&self) -> u32 {
        self.width_px
    }

    /// Altezza dichiarata dall'immagine, in pixel.
    #[must_use]
    pub const fn height_px(&self) -> u32 {
        self.height_px
    }
}

/// Dati documentali dell'ufficio che usa il prodotto.
///
/// Ogni campo e' facoltativo: il profilo predefinito e' **completamente vuoto**
/// e produce documenti privi di intestazione. Dove un dato manca, il documento
/// tace; non lo inventa e non lo deduce (ADR-0031 Decisione 4).
///
/// Il profilo e' **versionato**: [`ReportSnapshot`](super::report::ReportSnapshot)
/// registra quale versione ha prodotto quale documento, altrimenti un template
/// modificato renderebbe inspiegabile un report vecchio.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ReportTemplateProfile {
    /// Versione del profilo, che cresce a ogni modifica.
    pub version: u32,
    /// Denominazione dell'organizzazione.
    pub organisation: Option<TemplateField>,
    /// Denominazione dell'ufficio o dell'articolazione.
    pub office: Option<TemplateField>,
    /// Riga di intestazione libera, sotto le due precedenti.
    pub header_line: Option<TemplateField>,
    /// Destinatario predefinito della relazione.
    pub recipient: Option<TemplateField>,
    /// Destinatario per conoscenza.
    pub recipient_cc: Option<TemplateField>,
    /// Luogo che compare accanto alla data.
    pub place: Option<TemplateField>,
    /// Qualifica o ruolo di chi sottoscrive.
    pub signer_role: Option<TemplateField>,
    /// Nome di chi sottoscrive, come deve comparire in calce.
    ///
    /// # Perche' non e' l'operatore della richiesta
    ///
    /// [`ReportRequest::requested_by`](super::report::ReportRequest) e' un
    /// identificativo tecnico — un nome di accesso — e in calce a una relazione
    /// di servizio non ci va un nome di accesso. Chi firma lo dichiara qui, e
    /// se non lo dichiara la premessa ripiega sull'identificativo, che e'
    /// l'unico nome che il programma conosce davvero.
    pub signer_name: Option<TemplateField>,
    /// Riga di pie' di pagina.
    pub footer_line: Option<TemplateField>,
    /// Oggetto base, che il documento completa con i dati della sessione.
    pub subject_base: Option<TemplateField>,
    /// Stemma dell'ufficio, quando l'amministratore ne ha configurato uno.
    ///
    /// **Solo un file locale.** Nulla viene scaricato dalla rete durante la
    /// generazione (ADR-0031 Decisione 7), e questo campo porta byte gia' letti
    /// e validati, non un percorso da seguire.
    pub emblem: Option<TemplateEmblem>,
}

impl ReportTemplateProfile {
    /// Se il profilo non porta alcun dato dell'ufficio.
    ///
    /// La versione non conta: un profilo alla versione 7 e senza campi e' vuoto
    /// quanto uno alla versione 0.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.organisation.is_none()
            && self.office.is_none()
            && self.header_line.is_none()
            && self.recipient.is_none()
            && self.recipient_cc.is_none()
            && self.place.is_none()
            && self.signer_role.is_none()
            && self.signer_name.is_none()
            && self.footer_line.is_none()
            && self.subject_base.is_none()
            && self.emblem.is_none()
    }

    /// Quanti campi testuali risultano compilati.
    ///
    /// Serve all'audit, che registra **quanti** campi ci sono e non quali:
    /// i valori stanno gia' nel profilo, e ripeterli nel registro
    /// moltiplicherebbe i posti da proteggere senza aggiungere nulla a «chi ha
    /// fatto che cosa e quando».
    #[must_use]
    pub fn filled_fields(&self) -> usize {
        [
            self.organisation.as_ref(),
            self.office.as_ref(),
            self.header_line.as_ref(),
            self.recipient.as_ref(),
            self.recipient_cc.as_ref(),
            self.place.as_ref(),
            self.signer_role.as_ref(),
            self.signer_name.as_ref(),
            self.footer_line.as_ref(),
            self.subject_base.as_ref(),
        ]
        .into_iter()
        .flatten()
        .count()
    }

    /// Le righe dell'intestazione, nell'ordine in cui vanno stampate.
    ///
    /// Restituisce solo quelle presenti: un profilo senza organizzazione ma con
    /// ufficio stampa una riga sola, non una riga vuota seguita da una piena.
    #[must_use]
    pub fn header_lines(&self) -> Vec<&str> {
        [
            self.organisation.as_ref(),
            self.office.as_ref(),
            self.header_line.as_ref(),
        ]
        .into_iter()
        .flatten()
        .map(TemplateField::as_str)
        .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_default_profile_carries_no_institutional_data() {
        let profile = ReportTemplateProfile::default();

        // Criterio 22: nessun dato istituzionale nel sorgente. Il modo piu'
        // solido di garantirlo e' che il valore predefinito non ne abbia
        // nessuno, campo per campo.
        assert_eq!(profile.version, 0);
        assert!(profile.organisation.is_none());
        assert!(profile.office.is_none());
        assert!(profile.header_line.is_none());
        assert!(profile.recipient.is_none());
        assert!(profile.recipient_cc.is_none());
        assert!(profile.place.is_none());
        assert!(profile.signer_role.is_none());
        assert!(profile.signer_name.is_none());
        assert!(profile.footer_line.is_none());
        assert!(profile.emblem.is_none());
        assert!(profile.subject_base.is_none());
        assert!(profile.is_empty());
    }

    #[test]
    fn an_empty_field_is_refused() {
        assert!(TemplateField::try_new("").is_err());
        assert!(TemplateField::try_new("   ").is_err());
    }

    #[test]
    fn surrounding_whitespace_is_removed() {
        let field = TemplateField::try_new("  Ufficio  ").expect("valore valido");
        assert_eq!(field.as_str(), "Ufficio");
    }

    #[test]
    fn a_field_longer_than_the_limit_is_refused() {
        let long = "a".repeat(TemplateField::MAX_CHARS + 1);
        assert!(TemplateField::try_new(&long).is_err());

        let at_limit = "a".repeat(TemplateField::MAX_CHARS);
        assert!(TemplateField::try_new(&at_limit).is_ok());
    }

    #[test]
    fn control_characters_and_reading_order_overrides_are_refused() {
        // Un ritorno a capo dentro un'intestazione la spezza in due righe che
        // nessuno ha configurato.
        assert!(TemplateField::try_new("Ufficio\nfalso").is_err());
        assert!(TemplateField::try_new("Ufficio\ttabulato").is_err());
        // Questi sono invisibili e cambiano l'ordine di lettura: un documento
        // che li contenesse mostrerebbe qualcosa di diverso da cio' che dice.
        assert!(TemplateField::try_new("Ufficio\u{202e}osrevor").is_err());
        assert!(TemplateField::try_new("Ufficio\u{2066}isolato").is_err());
        assert!(TemplateField::try_new("Ufficio\u{200f}marcato").is_err());
    }

    #[test]
    fn accented_and_ordinary_punctuation_stay_allowed() {
        // La validazione difende da caratteri pericolosi, non dall'italiano.
        assert!(TemplateField::try_new("Comando Città di Sant'Angelo — Sez. 2ª").is_ok());
    }

    #[test]
    fn the_header_only_lists_the_lines_that_exist() {
        let mut profile = ReportTemplateProfile::default();
        assert!(profile.header_lines().is_empty());

        profile.office = Some(TemplateField::try_new("Ufficio Analisi").expect("valore valido"));
        // Manca l'organizzazione: l'intestazione ha una riga sola, non una
        // riga vuota seguita da una piena.
        assert_eq!(profile.header_lines(), vec!["Ufficio Analisi"]);

        profile.organisation = Some(TemplateField::try_new("Ente").expect("valore valido"));
        assert_eq!(profile.header_lines(), vec!["Ente", "Ufficio Analisi"]);
    }

    // ---------------------------------------------------------------- stemma

    /// Un PNG minimo e valido, con le dimensioni indicate nell'intestazione.
    fn png(width: u32, height: u32) -> Vec<u8> {
        let mut bytes = Vec::from(PNG_SIGNATURE);
        bytes.extend_from_slice(&13_u32.to_be_bytes());
        bytes.extend_from_slice(b"IHDR");
        bytes.extend_from_slice(&width.to_be_bytes());
        bytes.extend_from_slice(&height.to_be_bytes());
        // Profondita', tipo di colore e il resto dell'intestazione.
        bytes.extend_from_slice(&[8, 6, 0, 0, 0]);
        bytes
    }

    #[test]
    fn a_png_is_accepted_and_declares_its_own_size() {
        let Ok(emblem) = TemplateEmblem::from_png(png(120, 132)) else {
            panic!("un PNG valido deve essere accettato");
        };
        assert_eq!(emblem.width_px(), 120);
        assert_eq!(emblem.height_px(), 132);
        assert_eq!(&emblem.bytes()[..8], &PNG_SIGNATURE);
    }

    #[test]
    fn anything_that_is_not_a_png_is_refused() {
        // Il pacchetto scrive il media come `.png`: un JPEG finirebbe dentro un
        // file che Word non aprirebbe, ed e' meglio dirlo qui che scoprirlo la'.
        let jpeg = vec![0xff, 0xd8, 0xff, 0xe0, 0, 16, b'J', b'F', b'I', b'F', 0, 0];
        assert!(matches!(
            TemplateEmblem::from_png(jpeg),
            Err(DomainError::InvalidImage { .. })
        ));
        assert!(matches!(
            TemplateEmblem::from_png(Vec::new()),
            Err(DomainError::InvalidImage { .. })
        ));
    }

    #[test]
    fn a_png_without_a_readable_header_is_refused() {
        let mut bytes = png(10, 10);
        bytes[12..16].copy_from_slice(b"XXXX");
        assert!(matches!(
            TemplateEmblem::from_png(bytes),
            Err(DomainError::InvalidImage { .. })
        ));
    }

    #[test]
    fn a_png_with_an_impossible_size_is_refused() {
        assert!(matches!(
            TemplateEmblem::from_png(png(0, 10)),
            Err(DomainError::InvalidImage { .. })
        ));
        assert!(matches!(
            TemplateEmblem::from_png(png(TemplateEmblem::MAX_SIDE_PX + 1, 10)),
            Err(DomainError::InvalidImage { .. })
        ));
    }

    #[test]
    fn a_file_beyond_the_size_limit_is_refused_before_being_read() {
        let mut bytes = png(10, 10);
        bytes.resize(TemplateEmblem::MAX_BYTES + 1, 0);
        assert!(matches!(
            TemplateEmblem::from_png(bytes),
            Err(DomainError::InvalidImage { .. })
        ));
    }

    #[test]
    fn a_profile_with_only_an_emblem_is_not_empty() {
        let profile = ReportTemplateProfile {
            emblem: TemplateEmblem::from_png(png(10, 10)).ok(),
            ..ReportTemplateProfile::default()
        };
        assert!(!profile.is_empty());
    }

    #[test]
    fn a_profile_with_a_version_but_no_fields_is_still_empty() {
        let profile = ReportTemplateProfile {
            version: 7,
            ..ReportTemplateProfile::default()
        };
        assert!(profile.is_empty());
    }
}
