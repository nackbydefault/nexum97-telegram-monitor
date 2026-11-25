//! Valori testuali validati.
//!
//! Ogni testo che entra nel dominio passa da un tipo dedicato che ne verifica
//! lunghezza e caratteri alla costruzione. I contenuti provengono da fonti
//! remote e vanno trattati come ostili: un campo non vincolato finirebbe senza
//! controlli in log, database, report ed export.

use core::fmt;

use crate::error::{
    DomainError, DomainResult, validate_multiline_text, validate_optional_text,
    validate_required_text,
};

macro_rules! text_type {
    (
        $(#[$meta:meta])*
        $name:ident, $field:literal, $max:expr, $validator:path
    ) => {
        $(#[$meta])*
        #[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
        pub struct $name(String);

        impl $name {
            /// Nome del campo, usato nei messaggi di errore.
            pub const FIELD: &'static str = $field;

            /// Lunghezza massima ammessa, in caratteri Unicode.
            pub const MAX_CHARS: usize = $max;

            /// Costruisce il valore validandolo.
            ///
            /// # Errori
            ///
            /// Restituisce un [`DomainError`] se il testo è vuoto quando è
            /// obbligatorio, se supera [`Self::MAX_CHARS`] o se contiene
            /// caratteri di controllo non ammessi.
            pub fn try_new(raw: &str) -> DomainResult<Self> {
                $validator(Self::FIELD, raw, Self::MAX_CHARS).map(Self)
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

        impl fmt::Display for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str(&self.0)
            }
        }

        impl TryFrom<&str> for $name {
            type Error = DomainError;

            fn try_from(raw: &str) -> DomainResult<Self> {
                Self::try_new(raw)
            }
        }
    };
}

text_type!(
    /// Identificativo tecnico della fonte presso la piattaforma.
    SourceIdentifier,
    "identificativo_fonte",
    128,
    validate_required_text
);

text_type!(
    /// Nome leggibile della fonte, mostrato all'operatore.
    DisplayName,
    "nome_visualizzato",
    256,
    validate_required_text
);

text_type!(
    /// Soggetto che compie un'azione: operatore, amministratore o processo.
    Actor,
    "attore",
    128,
    validate_required_text
);

text_type!(
    /// Identificativo del messaggio presso la fonte remota.
    RemoteMessageId,
    "id_messaggio_remoto",
    128,
    validate_required_text
);

text_type!(
    /// Corpo del messaggio acquisito.
    ///
    /// Ammette il testo vuoto, perché un messaggio può contenere solo media, e
    /// conserva le interruzioni di riga, che sono significative. Gli altri
    /// caratteri di controllo restano vietati.
    ContentBody,
    "corpo_contenuto",
    65_536,
    validate_multiline_text
);

text_type!(
    /// Identificativo di una regola del dizionario.
    RuleId,
    "id_regola",
    64,
    validate_required_text
);

text_type!(
    /// Categoria di una regola: territorio, mobilitazione, illecito e simili.
    RuleCategory,
    "categoria_regola",
    64,
    validate_required_text
);

text_type!(
    /// Porzione di testo che ha attivato una regola.
    MatchedText,
    "testo_match",
    512,
    validate_required_text
);

text_type!(
    /// Motivazione leggibile di un alert.
    AlertReason,
    "motivazione_alert",
    1_024,
    validate_required_text
);

text_type!(
    /// Annotazione libera dell'operatore.
    Note,
    "nota",
    4_096,
    validate_optional_text
);

text_type!(
    /// Messaggio descrittivo di un errore registrato.
    FaultMessage,
    "messaggio_errore",
    4_096,
    validate_required_text
);

text_type!(
    /// Azione registrata nell'audit.
    AuditAction,
    "azione_audit",
    128,
    validate_required_text
);

text_type!(
    /// Entità interessata da una voce di audit.
    AuditEntity,
    "entita_audit",
    128,
    validate_required_text
);

text_type!(
    /// Dettaglio facoltativo di una voce di audit.
    AuditDetail,
    "dettaglio_audit",
    4_096,
    validate_optional_text
);

text_type!(
    /// Soggetto di un evento dell'Hub: di che cosa parla.
    HubEventSubject,
    "soggetto_evento",
    128,
    validate_required_text
);

text_type!(
    /// Dettaglio facoltativo di un evento dell'Hub.
    ///
    /// Corto di proposito: un evento dice CHE COSA e' successo, e chi vuole i
    /// particolari li chiede. Un dettaglio lungo diventa un secondo archivio,
    /// che nessuno ha deciso di tenere.
    HubEventDetail,
    "dettaglio_evento",
    512,
    validate_optional_text
);

text_type!(
    /// Percorso di un file prodotto da un export.
    ExportPath,
    "percorso_export",
    4_096,
    validate_required_text
);

text_type!(
    /// Nome di un dizionario.
    DictionaryName,
    "nome_dizionario",
    100,
    validate_required_text
);

text_type!(
    /// Descrizione di un dizionario.
    DictionaryDescription,
    "descrizione_dizionario",
    1_000,
    validate_optional_text
);

text_type!(
    /// Testo di un termine del dizionario.
    ///
    /// Il limite è deliberatamente generoso rispetto a una parola: una
    /// modalità di riscontro per frase deve poter contenere una frase.
    TermText,
    "termine",
    200,
    validate_required_text
);

text_type!(
    /// Nota esplicativa di un termine.
    ///
    /// È il posto in cui si scrive **perché** un termine è nel dizionario. Un
    /// termine senza spiegazione diventa incomprensibile a chi lo eredita.
    TermNote,
    "nota_termine",
    1_000,
    validate_optional_text
);

text_type!(
    /// Categoria di un termine, per esempio «incendio» o «coordinamento».
    TermCategory,
    "categoria_termine",
    64,
    validate_required_text
);

text_type!(
    /// Codice di lingua del termine, per esempio `it` o `en`.
    LanguageTag,
    "lingua",
    16,
    validate_required_text
);

text_type!(
    /// Nome di un profilo di selezione.
    ProfileName,
    "nome_profilo",
    100,
    validate_required_text
);

/// URL sanitizzato di un contenuto.
///
/// Sono ammessi soltanto gli schemi `http` e `https`. Uno schema come
/// `javascript:` o `file:` finirebbe in un report e in una notifica su cui
/// l'operatore può fare clic: la restrizione è una misura di sicurezza, non una
/// convenzione di formato.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ContentUrl(String);

impl ContentUrl {
    /// Nome del campo, usato nei messaggi di errore.
    pub const FIELD: &'static str = "url_contenuto";

    /// Lunghezza massima ammessa, in caratteri.
    pub const MAX_CHARS: usize = 2_048;

    /// Costruisce l'URL applicando la sanitizzazione.
    ///
    /// # Errori
    ///
    /// Restituisce [`DomainError::InvalidUrl`] se lo schema non è ammesso o se
    /// l'URL contiene spazi o caratteri di controllo, e
    /// [`DomainError::TooLong`] oltre [`Self::MAX_CHARS`].
    pub fn try_new(raw: &str) -> DomainResult<Self> {
        let trimmed = raw.trim();
        if trimmed.is_empty() {
            return Err(DomainError::Empty { field: Self::FIELD });
        }

        let actual = trimmed.chars().count();
        if actual > Self::MAX_CHARS {
            return Err(DomainError::TooLong {
                field: Self::FIELD,
                max: Self::MAX_CHARS,
                actual,
            });
        }

        if trimmed
            .chars()
            .any(|character| character.is_control() || character.is_whitespace())
        {
            return Err(DomainError::InvalidUrl {
                reason: "contiene spazi o caratteri di controllo",
            });
        }

        let lowercase = trimmed.to_ascii_lowercase();
        if !(lowercase.starts_with("https://") || lowercase.starts_with("http://")) {
            return Err(DomainError::InvalidUrl {
                reason: "sono ammessi soltanto indirizzi che cominciano con http:// o https://",
            });
        }

        Ok(Self(trimmed.to_owned()))
    }

    /// URL validato.
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

impl fmt::Display for ContentUrl {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl TryFrom<&str> for ContentUrl {
    type Error = DomainError;

    fn try_from(raw: &str) -> DomainResult<Self> {
        Self::try_new(raw)
    }
}

/// Come una schermata nomina chi ha agito (E2E01-19).
///
/// Il segnaposto [`crate::model::identity::LOCAL_OPERATOR`] dice la verità
/// nell'audit — l'atto è avvenuto su questa postazione, e non si sa chi l'ha
/// compiuto — ma a schermo «operatore.locale» si legge come un codice. Qui
/// diventa una frase; ogni altro nome resta com'è. **Solo per lo schermo**:
/// l'audit e i documenti scrivono il valore registrato.
impl Actor {
    /// Il nome a schermo.
    #[must_use]
    pub fn on_screen(&self) -> String {
        if self.as_str() == crate::model::identity::LOCAL_OPERATOR {
            String::from(LOCAL_OPERATOR_ON_SCREEN)
        } else {
            self.as_str().to_owned()
        }
    }
}

/// La frase con cui una schermata nomina l'operatore non identificato.
pub const LOCAL_OPERATOR_ON_SCREEN: &str = "l'operatore di questa postazione (nome non registrato)";

/// Un numero con il nome concordato: «1 fonte», «3 fonti».
///
/// OPERATOR-E2E-04 (F-25) ha letto «1 rapporti», «1 periodi», «mancano 1
/// secondi», «1 fonti»: il numero si scriveva sempre con il plurale. Lo zero e
/// i numeri da due in su vogliono il plurale, l'uno il singolare.
#[must_use]
pub fn counted(numero: usize, singolare: &str, plurale: &str) -> String {
    if numero == 1 {
        format!("1 {singolare}")
    } else {
        format!("{numero} {plurale}")
    }
}

#[cfg(test)]
mod tests {
    /// **Con 1 il singolare, con ogni altro numero il plurale, zero compreso**
    /// (CU01-007).
    #[test]
    fn un_numero_concorda_con_il_suo_nome() {
        use super::counted;

        assert_eq!(
            counted(1, "contenuto acquisito", "contenuti acquisiti"),
            "1 contenuto acquisito"
        );
        assert_eq!(
            counted(2, "contenuto acquisito", "contenuti acquisiti"),
            "2 contenuti acquisiti"
        );
        assert_eq!(counted(0, "riga", "righe"), "0 righe");
        assert_eq!(counted(11, "riga", "righe"), "11 righe");
    }

    use super::{Actor, ContentBody, ContentUrl, DisplayName, Note, counted};
    use crate::error::DomainError;

    /// **«operatore.locale» a schermo è una frase** (E2E01-19); un nome vero
    /// resta com'è.
    #[test]
    fn l_operatore_locale_a_schermo_e_una_frase() {
        let (Ok(locale), Ok(altro)) = (
            Actor::try_new(crate::model::identity::LOCAL_OPERATOR),
            Actor::try_new("m.rossi"),
        ) else {
            panic!("nomi validi");
        };
        assert_eq!(locale.on_screen(), super::LOCAL_OPERATOR_ON_SCREEN);
        assert_eq!(altro.on_screen(), "m.rossi");
    }

    /// **Uno al singolare, gli altri al plurale** (F-25).
    #[test]
    fn un_numero_concorda_con_il_nome() {
        assert_eq!(counted(1, "fonte", "fonti"), "1 fonte");
        assert_eq!(counted(0, "fonte", "fonti"), "0 fonti");
        assert_eq!(counted(3, "fonte", "fonti"), "3 fonti");
    }

    #[test]
    fn a_required_text_is_trimmed() {
        let Ok(name) = DisplayName::try_new("  Canale di prova  ") else {
            panic!("il nome deve essere accettato");
        };
        assert_eq!(name.as_str(), "Canale di prova");
    }

    #[test]
    fn an_empty_required_text_is_rejected() {
        assert_eq!(
            DisplayName::try_new("   "),
            Err(DomainError::Empty {
                field: DisplayName::FIELD
            })
        );
    }

    #[test]
    fn a_text_over_the_limit_is_rejected() {
        let too_long = "a".repeat(DisplayName::MAX_CHARS + 1);
        assert!(matches!(
            DisplayName::try_new(&too_long),
            Err(DomainError::TooLong { .. })
        ));
    }

    #[test]
    fn a_text_at_the_limit_is_accepted() {
        let exact = "a".repeat(DisplayName::MAX_CHARS);
        assert!(DisplayName::try_new(&exact).is_ok());
    }

    #[test]
    fn the_limit_counts_characters_not_bytes() {
        // Ogni emoji occupa quattro byte ma un solo carattere.
        let emoji = "\u{1F600}".repeat(DisplayName::MAX_CHARS);
        assert!(DisplayName::try_new(&emoji).is_ok());
    }

    #[test]
    fn control_characters_are_rejected_in_single_line_fields() {
        assert_eq!(
            Actor::try_new("operatore\u{0}nascosto"),
            Err(DomainError::ControlCharacters {
                field: Actor::FIELD
            })
        );
    }

    #[test]
    fn a_body_may_be_empty_because_a_message_can_contain_only_media() {
        let Ok(body) = ContentBody::try_new("") else {
            panic!("il corpo vuoto deve essere ammesso");
        };
        assert_eq!(body.as_str(), "");
    }

    #[test]
    fn a_body_preserves_line_breaks_and_surrounding_spaces() {
        let raw = "  prima riga\nseconda riga  ";
        let Ok(body) = ContentBody::try_new(raw) else {
            panic!("il corpo multilinea deve essere accettato");
        };
        assert_eq!(body.as_str(), raw);
    }

    #[test]
    fn a_body_rejects_control_characters_other_than_line_breaks() {
        assert!(matches!(
            ContentBody::try_new("testo\u{7}campanello"),
            Err(DomainError::ControlCharacters { .. })
        ));
    }

    #[test]
    fn an_optional_note_may_be_empty() {
        assert!(Note::try_new("").is_ok());
    }

    #[test]
    fn https_and_http_urls_are_accepted() {
        assert!(ContentUrl::try_new("https://t.me/canale/123").is_ok());
        assert!(ContentUrl::try_new("http://example.invalid/x").is_ok());
    }

    #[test]
    fn the_scheme_check_is_case_insensitive() {
        assert!(ContentUrl::try_new("HTTPS://T.ME/canale/1").is_ok());
    }

    #[test]
    fn dangerous_schemes_are_rejected() {
        for dangerous in [
            "javascript:alert(1)",
            "file:///C:/Windows/System32/config/SAM",
            "data:text/html;base64,PHNjcmlwdD4=",
            "ftp://example.invalid/x",
            "\\\\server\\share\\file",
        ] {
            assert!(
                matches!(
                    ContentUrl::try_new(dangerous),
                    Err(DomainError::InvalidUrl { .. })
                ),
                "lo schema di '{dangerous}' doveva essere rifiutato"
            );
        }
    }

    #[test]
    fn urls_with_whitespace_or_control_characters_are_rejected() {
        assert!(matches!(
            ContentUrl::try_new("https://t.me/ca nale"),
            Err(DomainError::InvalidUrl { .. })
        ));
        assert!(matches!(
            ContentUrl::try_new("https://t.me/\u{a}evil"),
            Err(DomainError::InvalidUrl { .. })
        ));
    }

    #[test]
    fn an_empty_url_is_rejected() {
        assert!(matches!(
            ContentUrl::try_new("  "),
            Err(DomainError::Empty { .. })
        ));
    }
}
