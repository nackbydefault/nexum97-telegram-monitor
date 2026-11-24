//! Gli iscritti di un gruppo osservato (MEMBERS-01, ADR-0201).
//!
//! # Che cosa fa
//!
//! Chiede a Telegram, con le richieste ufficiali, l'elenco degli iscritti di
//! **una** fonte già configurata: identificativo, nome, username, stato
//! nell'elenco e, se Telegram lo restituisce, il telefono, **mascherato qui**,
//! prima che esca da questa crate.
//!
//! # Che cosa non fa
//!
//! - Non entra, non esce, non scrive: legge.
//! - Non supera il tetto: al più [`MAX_MEMBERS`] iscritti per richiesta.
//! - Non deduce nulla. Un telefono che Telegram non dà non c'è.

use crate::error::TelegramResult;

/// Quanti iscritti si chiedono per pagina: il massimo che Telegram ammette.
pub const MEMBERS_PER_PAGE: usize = 200;

/// Il tetto di una richiesta: cinque pagine (ADR-0201, decisione 3).
pub const MAX_MEMBERS: usize = 1_000;

/// Quante cifre del telefono restano visibili (ADR-0201, decisione 6).
pub const VISIBLE_PHONE_DIGITS: usize = 2;

/// Il posto di un iscritto nell'elenco, come Telegram lo dichiara.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MemberStatus {
    /// Chi ha creato il gruppo.
    Creator,
    /// Un amministratore.
    Administrator,
    /// Un iscritto.
    Member,
    /// Un iscritto con limitazioni.
    Restricted,
    /// Uscito.
    Left,
    /// Escluso dagli amministratori.
    Banned,
}

impl MemberStatus {
    /// La chiave dell'archivio.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Creator => "creatore",
            Self::Administrator => "amministratore",
            Self::Member => "iscritto",
            Self::Restricted => "limitato",
            Self::Left => "uscito",
            Self::Banned => "escluso",
        }
    }

    /// Lo stato dal tipo TDLib, `None` per un tipo che non si conosce.
    #[must_use]
    pub fn from_tdlib(tipo: &str) -> Option<Self> {
        match tipo {
            "chatMemberStatusCreator" => Some(Self::Creator),
            "chatMemberStatusAdministrator" => Some(Self::Administrator),
            "chatMemberStatusMember" => Some(Self::Member),
            "chatMemberStatusRestricted" => Some(Self::Restricted),
            "chatMemberStatusLeft" => Some(Self::Left),
            "chatMemberStatusBanned" => Some(Self::Banned),
            _ => None,
        }
    }
}

/// Un iscritto, come Telegram lo rende visibile all'account d'ufficio.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Member {
    /// L'identificativo numerico: l'unico dei tre campi che regge nel tempo.
    pub user_id: i64,
    /// Nome e cognome, se ci sono.
    pub display_name: Option<String>,
    /// Lo username attivo principale, senza chiocciola.
    pub username: Option<String>,
    /// Il telefono **mascherato**, se Telegram l'ha dato.
    pub masked_phone: Option<String>,
    /// Il posto nell'elenco.
    pub status: MemberStatus,
    /// Da quando è iscritto, in millisecondi dall'epoca, se Telegram lo dice.
    pub joined_at_millis: Option<i64>,
}

/// Un elenco ottenuto.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MemberList {
    /// Quanti iscritti dichiara Telegram, se lo dichiara.
    pub declared_total: Option<i64>,
    /// Gli iscritti arrivati, nell'ordine di Telegram.
    pub members: Vec<Member>,
    /// Vero se la richiesta si è fermata al tetto con altri iscritti da dare.
    pub stopped_at_cap: bool,
}

/// La risposta di Telegram.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MembersReply {
    /// L'elenco, intero o parziale.
    Found(MemberList),
    /// Telegram ha rifiutato: codice e messaggio così come sono.
    Refused {
        /// Il codice.
        code: i64,
        /// Il messaggio.
        message: String,
    },
    /// La fonte non è un gruppo di cui si possa chiedere l'elenco: la frase
    /// dice perché.
    NotAGroup(String),
}

/// La lettura degli iscritti. **Sigillata** come
/// [`crate::lookup::OfficialLookup`]: la implementano soltanto i connettori
/// del prodotto.
pub trait MembersReader: crate::lookup::sealed::Sealed {
    /// Legge al più `max` iscritti della chat `chat_id` (mai più di
    /// [`MAX_MEMBERS`]).
    ///
    /// # Errori
    ///
    /// Restituisce un errore quando la lettura non è arrivata a una risposta:
    /// account non pronto, tempo scaduto, connettore arrestato. Un rifiuto
    /// **di Telegram** è un [`MembersReply::Refused`].
    fn read_members(&mut self, chat_id: i64, max: usize) -> TelegramResult<MembersReply>;
}

/// Il telefono mascherato: un `+`, un pallino per ogni cifra nascosta e le
/// ultime [`VISIBLE_PHONE_DIGITS`] cifre. `None` per ciò che non è un numero
/// di telefono: sole cifre, da 5 a 20.
#[must_use]
pub fn mask_phone(cifre: &str) -> Option<String> {
    let cifre = cifre.trim().trim_start_matches('+');
    if cifre.len() < 5 || cifre.len() > 20 || !cifre.chars().all(|c| c.is_ascii_digit()) {
        return None;
    }
    let nascoste = cifre.len() - VISIBLE_PHONE_DIGITS;
    let coda = cifre.get(nascoste..)?;
    Some(format!("+{}{coda}", "•".repeat(nascoste)))
}

#[cfg(test)]
mod tests {
    use super::{MemberStatus, VISIBLE_PHONE_DIGITS, mask_phone};

    #[test]
    fn il_telefono_mascherato_lascia_vedere_solo_le_ultime_due_cifre() {
        let Some(mascherato) = mask_phone("393331234567") else {
            panic!("un numero valido si maschera");
        };
        assert_eq!(mascherato, "+••••••••••67");
        let visibili: String = mascherato.chars().filter(char::is_ascii_digit).collect();
        assert_eq!(visibili.len(), VISIBLE_PHONE_DIGITS);
        assert!(!mascherato.contains("3933312345"));
    }

    #[test]
    fn cio_che_non_e_un_telefono_non_si_maschera() {
        assert_eq!(mask_phone(""), None);
        assert_eq!(mask_phone("1234"), None);
        assert_eq!(mask_phone("39 333 1234567"), None);
        assert_eq!(mask_phone("abcdefg"), None);
    }

    #[test]
    fn ogni_stato_ha_la_sua_chiave_e_il_suo_tipo() {
        let tipi = [
            ("chatMemberStatusCreator", MemberStatus::Creator),
            ("chatMemberStatusAdministrator", MemberStatus::Administrator),
            ("chatMemberStatusMember", MemberStatus::Member),
            ("chatMemberStatusRestricted", MemberStatus::Restricted),
            ("chatMemberStatusLeft", MemberStatus::Left),
            ("chatMemberStatusBanned", MemberStatus::Banned),
        ];
        let mut chiavi = Vec::new();
        for (tipo, stato) in tipi {
            assert_eq!(MemberStatus::from_tdlib(tipo), Some(stato));
            chiavi.push(stato.as_str());
        }
        chiavi.sort_unstable();
        chiavi.dedup();
        assert_eq!(chiavi.len(), tipi.len());
        assert_eq!(MemberStatus::from_tdlib("chatMemberStatusAltro"), None);
    }
}
