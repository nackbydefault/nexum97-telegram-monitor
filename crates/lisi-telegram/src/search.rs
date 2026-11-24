//! Le ricerche nei messaggi: **B** nelle chat dell'account, **C** dentro una
//! chat indicata (NEXUM97-CYBER-SEARCH-01, ADR-0154, DG-06) e **D** nei post dei
//! canali pubblici (CYBER-SEARCH-02, ADR-0161).
//!
//! # Sola lettura, e zero Stelle scritto come un numero
//!
//! `searchMessages` e `searchChatMessages` leggono ciò che l'account vede e non
//! hanno un parametro economico. `searchPublicPosts` ne ha uno, `star_count`:
//! qui è il **numero 0 scritto nella richiesta**, in un solo punto, e la
//! guardia delle Stelle (`prohibitions`) rifiuta qualunque altro valore. Prima
//! di ogni pagina della D i servizi leggono la quota con
//! `getPublicPostSearchLimits` ([`limits_request_tagged`]).
//!
//! # Che cosa non c'è
//!
//! La **E** (ricerche ricorrenti) non è qui: è CYBER-WATCH-02.

use crate::event::IncomingMessage;
use crate::identifier::ChatId;

/// Quanti risultati al più si chiedono per pagina.
pub const MAX_PAGE: u32 = 50;

/// Che cosa si chiede.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SearchQuery {
    /// **B** — nelle chat dell'elenco principale e dell'archivio dell'account,
    /// tranne le segrete: `searchMessages`.
    AccountChats {
        /// Le parole, già controllate dai servizi.
        query: String,
        /// Il cursore della pagina: vuoto per la prima.
        offset: String,
        /// Quanti risultati, al più [`MAX_PAGE`].
        limit: u32,
    },
    /// **C** — dentro una chat indicata: `searchChatMessages`.
    InChat {
        /// Quale chat.
        chat_id: ChatId,
        /// Le parole, già controllate dai servizi.
        query: String,
        /// Da quale messaggio continuare: 0 per la prima pagina.
        from_message_id: i64,
        /// Quanti risultati, al più [`MAX_PAGE`].
        limit: u32,
    },
    /// **D** — nei post dei canali pubblici, anche non seguiti:
    /// `searchPublicPosts`, soltanto gratuita (ADR-0161).
    PublicPosts {
        /// Le parole o l'hashtag, già controllati dai servizi.
        query: String,
        /// Il cursore della pagina: vuoto per la prima.
        offset: String,
        /// Quanti risultati, al più [`MAX_PAGE`].
        limit: u32,
    },
}

impl SearchQuery {
    /// Il nome della funzione di TDLib che la esegue.
    #[must_use]
    pub const fn function_name(&self) -> &'static str {
        match self {
            Self::AccountChats { .. } => "searchMessages",
            Self::InChat { .. } => "searchChatMessages",
            Self::PublicPosts { .. } => "searchPublicPosts",
        }
    }

    /// La richiesta per TDLib, con il segno `@extra`. **Nessun parametro
    /// economico**, tranne `star_count` della D, che vale sempre 0.
    #[must_use]
    pub fn tdlib_request_tagged(&self, tag: &str) -> String {
        let extra = escape(tag);
        match self {
            Self::AccountChats {
                query,
                offset,
                limit,
            } => format!(
                r#"{{"@type":"searchMessages","@extra":"{extra}","chat_list":null,"query":"{}","offset":"{}","limit":{},"filter":null,"chat_type_filter":null,"min_date":0,"max_date":0}}"#,
                escape(query),
                escape(offset),
                (*limit).min(MAX_PAGE)
            ),
            Self::InChat {
                chat_id,
                query,
                from_message_id,
                limit,
            } => format!(
                r#"{{"@type":"searchChatMessages","@extra":"{extra}","chat_id":{},"topic_id":null,"query":"{}","sender_id":null,"from_message_id":{},"offset":0,"limit":{},"filter":null}}"#,
                chat_id.get(),
                escape(query),
                (*from_message_id).max(0),
                (*limit).min(MAX_PAGE)
            ),
            // ZERO STELLE, COME NUMERO (ADR-0161, decisione 1): la sola
            // richiesta del prodotto con un parametro economico.
            Self::PublicPosts {
                query,
                offset,
                limit,
            } => format!(
                r#"{{"@type":"searchPublicPosts","@extra":"{extra}","query":"{}","offset":"{}","limit":{},"star_count":0}}"#,
                escape(query),
                escape(offset),
                (*limit).min(MAX_PAGE)
            ),
        }
    }
}

/// Protegge una stringa dentro un valore JSON: le virgolette e le barre si
/// scappano, i caratteri di controllo si tolgono.
fn escape(testo: &str) -> String {
    let mut sicuro = String::with_capacity(testo.len());
    for carattere in testo.chars() {
        match carattere {
            '"' => sicuro.push_str("\\\""),
            '\\' => sicuro.push_str("\\\\"),
            c if c.is_control() => {}
            c => sicuro.push(c),
        }
    }
    sicuro
}

/// La richiesta della quota della ricerca **D**, con il segno `@extra`
/// (ADR-0161, decisione 2): `getPublicPostSearchLimits` legge, non cerca e non
/// costa.
#[must_use]
pub fn limits_request_tagged(query: &str, tag: &str) -> String {
    format!(
        r#"{{"@type":"getPublicPostSearchLimits","@extra":"{}","query":"{}"}}"#,
        escape(tag),
        escape(query)
    )
}

/// La quota della ricerca nei post pubblici, **come Telegram la dichiara
/// adesso** (`publicPostSearchLimits`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct PublicPostLimits {
    /// Quante query gratuite al giorno.
    pub daily_free: i32,
    /// Quante ne restano oggi.
    pub remaining_free: i32,
    /// Fra quanti secondi la prossima query gratuita.
    pub next_free_in_seconds: i32,
    /// Quante Stelle costerebbe una query non gratuita, come Telegram lo
    /// dichiara. Il prodotto non le spende mai.
    pub star_count: i64,
    /// Se **questa** query è gratuita.
    pub current_query_free: bool,
}

impl PublicPostLimits {
    /// Se la query si può fare gratis adesso. Soltanto allora si cerca.
    #[must_use]
    pub const fn allows_free_search(&self) -> bool {
        self.current_query_free && self.remaining_free > 0
    }
}

/// Una pagina di risultati, **com'è arrivata**.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct SearchPage {
    /// I messaggi trovati, nell'ordine di Telegram.
    pub hits: Vec<IncomingMessage>,
    /// Quanti risultati Telegram dichiara in tutto, se lo dichiara.
    pub total_count: Option<i64>,
    /// Il cursore della pagina successiva per la **B** e la **D**, se c'è.
    pub next_offset: Option<String>,
    /// Il messaggio da cui continuare per la **C**, se c'è.
    pub next_from_message_id: Option<i64>,
    /// La quota dopo questa pagina, per la **D**.
    pub limits: Option<PublicPostLimits>,
    /// Se Telegram dichiara superati i limiti della **D**: la ricerca si ferma.
    pub limits_exceeded: bool,
}

impl SearchPage {
    /// Se Telegram dichiara che ci sono altre pagine.
    #[must_use]
    pub fn has_more(&self) -> bool {
        self.next_offset.as_deref().is_some_and(|o| !o.is_empty())
            || self.next_from_message_id.is_some_and(|id| id > 0)
    }
}

#[cfg(test)]
mod tests {
    use super::{MAX_PAGE, SearchQuery};
    use crate::identifier::ChatId;

    /// **Due richieste, i loro nomi, nessun parametro economico** (criterio 1).
    #[test]
    fn due_richieste_e_nessun_parametro_economico() {
        let Ok(chat) = ChatId::try_new(-1001) else {
            panic!("identificativo valido");
        };
        for (richiesta, funzione) in [
            (
                SearchQuery::AccountChats {
                    query: String::from("ransomware"),
                    offset: String::new(),
                    limit: 500,
                },
                "searchMessages",
            ),
            (
                SearchQuery::InChat {
                    chat_id: chat,
                    query: String::from("ransomware"),
                    from_message_id: 0,
                    limit: 500,
                },
                "searchChatMessages",
            ),
        ] {
            let testo = richiesta.tdlib_request_tagged("7");
            assert!(
                testo.starts_with(&format!(r#"{{"@type":"{funzione}""#)),
                "{testo}"
            );
            assert_eq!(richiesta.function_name(), funzione);
            assert!(!testo.contains("star_count"), "nessun parametro economico");
            assert!(
                testo.contains(&format!(r#""limit":{MAX_PAGE}"#)),
                "il limite non supera il tetto: {testo}"
            );
            assert!(testo.contains(r#""@extra":"7""#));
        }
    }

    /// **La D chiede `searchPublicPosts` con zero Stelle scritto come numero,
    /// e il tetto della pagina** (CYBER-SEARCH-02, criterio 1).
    #[test]
    fn la_d_chiede_zero_stelle_scritto_come_numero() {
        let testo = SearchQuery::PublicPosts {
            query: String::from("#ransomware"),
            offset: String::new(),
            limit: 500,
        }
        .tdlib_request_tagged("9");
        assert!(
            testo.starts_with(r#"{"@type":"searchPublicPosts""#),
            "{testo}"
        );
        assert!(
            testo.contains(r#""star_count":0}"#),
            "le Stelle non sono zero: {testo}"
        );
        assert_eq!(testo.matches("star_count").count(), 1, "{testo}");
        assert!(testo.contains(&format!(r#""limit":{MAX_PAGE}"#)), "{testo}");
        assert!(testo.contains(r##""query":"#ransomware""##), "{testo}");
        assert_eq!(
            SearchQuery::PublicPosts {
                query: String::new(),
                offset: String::new(),
                limit: 1
            }
            .function_name(),
            "searchPublicPosts"
        );
    }

    /// **La quota si chiede con una richiesta che non cerca e non costa, e si
    /// cerca soltanto se la query è gratuita e ne restano** (criterio 2).
    #[test]
    fn la_quota_si_legge_e_decide_se_cercare() {
        let testo = super::limits_request_tagged("x\",\"@type\":\"joinChat", "4");
        assert!(
            testo.starts_with(r#"{"@type":"getPublicPostSearchLimits""#),
            "{testo}"
        );
        assert!(!testo.contains("star_count"), "{testo}");
        assert!(!testo.contains(r#""@type":"joinChat""#), "{testo}");

        let gratuita = super::PublicPostLimits {
            daily_free: 10,
            remaining_free: 3,
            next_free_in_seconds: 0,
            star_count: 10,
            current_query_free: true,
        };
        assert!(gratuita.allows_free_search());
        for chiusa in [
            super::PublicPostLimits {
                remaining_free: 0,
                ..gratuita
            },
            super::PublicPostLimits {
                current_query_free: false,
                ..gratuita
            },
        ] {
            assert!(!chiusa.allows_free_search(), "{chiusa:?}");
        }
    }

    /// **Un ingresso ostile resta dentro il valore** (criterio 1).
    #[test]
    fn un_ingresso_ostile_resta_dentro_il_valore() {
        let testo = SearchQuery::AccountChats {
            query: String::from("x\",\"@type\":\"joinChat"),
            offset: String::from("a\"b"),
            limit: 10,
        }
        .tdlib_request_tagged("1");
        assert!(!testo.contains(r#""@type":"joinChat""#), "{testo}");
        assert!(!testo.contains("a\"b"), "{testo}");
    }
}
