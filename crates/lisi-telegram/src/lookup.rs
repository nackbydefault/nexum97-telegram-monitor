//! La ricerca puntuale ufficiale (PR-09, ADR-0125).
//!
//! # Una capacità sigillata
//!
//! [`OfficialLookup`] è la sola porta da cui passa una ricerca puntuale, e la
//! implementano **soltanto** i connettori del prodotto: quello verso TDLib e
//! quello simulato delle prove. Il suo supertratto non si può nominare fuori da
//! questa crate, quindi un adattatore verso un bot di terze parti, un servizio
//! esterno o una libreria di rete diversa **non può implementarlo** — la prova
//! qui sotto deve non compilare:
//!
//! ```compile_fail
//! use lisi_telegram::lookup::{LookupQuery, LookupReply, OfficialLookup};
//! use lisi_telegram::TelegramResult;
//!
//! struct BotDiTerzi;
//!
//! impl OfficialLookup for BotDiTerzi {
//!     fn lookup(&mut self, _query: &LookupQuery) -> TelegramResult<LookupReply> {
//!         unimplemented!()
//!     }
//! }
//! ```
//!
//! # Un ingresso, una richiesta
//!
//! Ogni [`LookupQuery`] corrisponde a **una** funzione di TDLib, e a nessuna
//! altra. Nessuna richiesta ha un parametro economico: la guardia delle Stars
//! legge anche queste.
//!
//! # Che cosa questo modulo non fa
//!
//! Non classifica. Restituisce ciò che Telegram ha risposto — il profilo, oppure
//! codice e messaggio così come sono — e lascia ai servizi la tabella che dice
//! che cosa significa (`docs/validation/PR-09_IDENTITY_RESOLVER_MATRIX.md`).

use crate::error::TelegramResult;

/// Che cosa si chiede a Telegram: un ingresso **già validato** dai servizi.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum LookupQuery {
    /// Un nome utente, senza `@`: `searchPublicChat`.
    Username(String),
    /// Un numero di telefono, sole cifre: `searchUserByPhoneNumber`.
    PhoneNumber(String),
    /// L'identificativo di una persona: `getUser`.
    UserId(i64),
    /// L'identificativo di una chat: `getChat`.
    ChatId(i64),
    /// L'account d'ufficio stesso: `getMe` (ADR-0153, DG-07). Non cerca
    /// nessuno: chiede a Telegram chi è l'account collegato.
    Me,
}

impl LookupQuery {
    /// Il nome della funzione di TDLib che la esegue.
    #[must_use]
    pub const fn function_name(&self) -> &'static str {
        match self {
            Self::Username(_) => "searchPublicChat",
            Self::PhoneNumber(_) => "searchUserByPhoneNumber",
            Self::UserId(_) => "getUser",
            Self::ChatId(_) => "getChat",
            Self::Me => "getMe",
        }
    }

    /// La richiesta per TDLib. **Nessun parametro economico.**
    #[must_use]
    pub fn tdlib_request(&self) -> String {
        self.compose("")
    }

    /// La stessa richiesta, con il segno `@extra` che TDLib rimanda indietro
    /// con la risposta: è ciò che permette di riconoscerla fra gli
    /// aggiornamenti.
    #[must_use]
    pub fn tdlib_request_tagged(&self, tag: &str) -> String {
        self.compose(&format!(r#","@extra":"{}""#, escape(tag)))
    }

    fn compose(&self, extra: &str) -> String {
        match self {
            Self::Username(nome) => format!(
                r#"{{"@type":"searchPublicChat"{extra},"username":"{}"}}"#,
                escape(nome)
            ),
            // `only_local: false`: la copia locale di TDLib conosce soltanto
            // chi l'account ha già incontrato, e una ricerca per numero
            // chiederebbe altrimenti a un archivio che non sa.
            Self::PhoneNumber(numero) => format!(
                r#"{{"@type":"searchUserByPhoneNumber"{extra},"phone_number":"{}","only_local":false}}"#,
                escape(numero)
            ),
            Self::UserId(id) => format!(r#"{{"@type":"getUser"{extra},"user_id":{id}}}"#),
            Self::ChatId(id) => format!(r#"{{"@type":"getChat"{extra},"chat_id":{id}}}"#),
            Self::Me => format!(r#"{{"@type":"getMe"{extra}}}"#),
        }
    }
}

/// Protegge una stringa dentro un valore JSON.
///
/// Gli ingressi arrivano già validati — lettere, cifre, trattino basso — ma la
/// richiesta non deve dipendere dal fatto che qualcuno se ne sia ricordato.
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

/// Il genere di ciò che Telegram ha restituito.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum LookupKind {
    /// Un account: una persona o un bot, quando la chat da sola non lo dice.
    Account,
    /// Una persona.
    Person,
    /// Un bot.
    Bot,
    /// Un account cancellato.
    DeletedAccount,
    /// Un canale.
    Channel,
    /// Un gruppo.
    Group,
    /// Un supergruppo: lo stesso genere che la schermata Fonti chiama
    /// «Supergruppo». La ricerca diceva «gruppo» per la stessa chat
    /// (FULL-OPERATIONAL-VALIDATION-01, LOOK-01).
    Supergroup,
    /// Qualcosa che il prodotto non sa nominare.
    Other,
}

impl LookupKind {
    /// La parola per l'operatore.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Account => "account",
            Self::Person => "persona",
            Self::Bot => "bot",
            Self::DeletedAccount => "account cancellato",
            Self::Channel => "canale",
            Self::Group => "gruppo",
            Self::Supergroup => "supergruppo",
            Self::Other => "altro",
        }
    }

    /// Il nome stabile, per il registro.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Account => "account",
            Self::Person => "persona",
            Self::Bot => "bot",
            Self::DeletedAccount => "account_cancellato",
            Self::Channel => "canale",
            Self::Group => "gruppo",
            Self::Supergroup => "supergruppo",
            Self::Other => "altro",
        }
    }
}

/// Ciò che Telegram ha restituito, **e nient'altro**.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LookupProfile {
    /// Il genere.
    pub kind: LookupKind,
    /// L'identificativo: della persona per un account, della chat altrimenti.
    pub telegram_id: i64,
    /// Il nome mostrato, così come Telegram lo dà. Può essere vuoto.
    pub name: String,
    /// Il nome utente, quando Telegram ne restituisce uno: il **primo** degli
    /// attivi, che TDLib documenta come principale. È sempre `usernames[0]`.
    pub username: Option<String>,
    /// Il nome proprio, per un account; vuoto per una chat (ADR-0153).
    pub first_name: String,
    /// Il cognome, per un account; vuoto se Telegram non lo dà.
    pub last_name: String,
    /// **Tutti** gli username attivi, nell'ordine di Telegram (DG-07).
    ///
    /// Per una chat trovata per nome utente è il solo nome cercato: la chat
    /// non porta gli altri, e chiederli sarebbe una seconda richiesta.
    pub usernames: Vec<String>,
    /// Il telefono, **soltanto** se Telegram lo restituisce a questo account.
    ///
    /// Non attraversa i servizi in chiaro: chi lo riceve lo maschera subito
    /// (ADR-0153, decisione 2). Sole cifre; un valore con altri caratteri non
    /// è un telefono e non arriva qui.
    pub phone_number: Option<String>,
}

/// La risposta di Telegram a una ricerca puntuale.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LookupReply {
    /// Telegram ha restituito un profilo.
    Found(LookupProfile),
    /// Telegram ha risposto con un errore: codice e messaggio **così come
    /// sono**, perché li classifichi la tabella dei servizi.
    Refused {
        /// Il codice.
        code: i64,
        /// Il messaggio.
        message: String,
    },
}

/// Il supertratto che sigilla [`OfficialLookup`]: non si nomina fuori da questa
/// crate.
pub(crate) mod sealed {
    /// Implementato soltanto dai connettori del prodotto.
    pub trait Sealed {}
}

/// La ricerca puntuale ufficiale. **Sigillata**: la implementano soltanto i
/// connettori del prodotto.
pub trait OfficialLookup: sealed::Sealed {
    /// Esegue **una** richiesta, e una sola.
    ///
    /// # Errori
    ///
    /// Restituisce un errore quando la richiesta non è arrivata a una risposta:
    /// account non pronto, tempo scaduto, rete, connettore arrestato. Un errore
    /// **di Telegram** non è un errore di questa funzione: è una
    /// [`LookupReply::Refused`].
    fn lookup(&mut self, query: &LookupQuery) -> TelegramResult<LookupReply>;
}

#[cfg(test)]
mod tests {
    use super::LookupQuery;

    /// **Una richiesta per ingresso, e nessun parametro economico.**
    #[test]
    fn ogni_ingresso_ha_la_sua_richiesta() {
        let casi = [
            (
                LookupQuery::Username(String::from("canale_prova")),
                "searchPublicChat",
            ),
            (
                LookupQuery::PhoneNumber(String::from("390000000000")),
                "searchUserByPhoneNumber",
            ),
            (LookupQuery::UserId(42), "getUser"),
            (LookupQuery::ChatId(-1_001), "getChat"),
            (LookupQuery::Me, "getMe"),
        ];
        for (richiesta, funzione) in casi {
            let testo = richiesta.tdlib_request();
            assert!(
                testo.starts_with(&format!(r#"{{"@type":"{funzione}""#)),
                "{testo}"
            );
            assert_eq!(richiesta.function_name(), funzione);
            assert!(!testo.contains("star_count"), "nessun parametro economico");
        }
    }

    /// **Un ingresso non può rompere la richiesta.**
    #[test]
    fn un_ingresso_ostile_resta_dentro_il_valore() {
        let testo = LookupQuery::Username(String::from("a\",\"@type\":\"joinChat")).tdlib_request();
        assert!(!testo.contains(r#""@type":"joinChat""#), "{testo}");
    }
}
