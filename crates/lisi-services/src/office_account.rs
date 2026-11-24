//! Chi è l'account d'ufficio, **secondo Telegram** (NEXUM97-IDENTITY-02,
//! ADR-0153, DG-07, F-140).
//!
//! # Che cosa fa
//!
//! Chiede a Telegram, con `getMe`, chi è l'account collegato: identificativo,
//! nome, cognome, tutti gli username attivi, e il telefono se Telegram lo
//! restituisce. Lo chiede **su comando**, una volta per comando, e registra la
//! lettura — riuscita o no — con chi e quando, e la sua riga d'audit.
//!
//! # Che cosa non fa
//!
//! Non conserva il telefono pieno: lo maschera appena arriva, come il prodotto
//! fa già con il numero dell'account. Non mescola questa lettura con i
//! risultati della Ricerca puntuale: sono due registri diversi, perché una cosa
//! è chi siamo e un'altra chi cerchiamo. Non chiede nulla da sé: nessun
//! temporizzatore la chiama.

use lisi_core::Timestamp;
use lisi_core::model::{MaskedPhoneNumber, NewAuditEntry};
use lisi_core::text::{Actor, AuditAction, AuditDetail, AuditEntity};
use lisi_storage::Database;
use lisi_storage::repository::office_account::{
    NewOfficeAccountRead, OfficeAccountProfile, StoredOfficeAccountRead,
};
use lisi_telegram::TelegramConnector;
use lisi_telegram::lookup::{LookupQuery, LookupReply};

use crate::error::ServiceResult;
use crate::identity_resolver::connector_fault;

/// L'azione d'audit di una lettura dell'account d'ufficio.
pub const OFFICE_ACCOUNT_AUDIT_ACTION: &str = "lettura_account_ufficio";

/// Una lettura dell'account d'ufficio, com'è stata registrata.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OfficeAccountReading {
    /// La riga registrata.
    pub stored: StoredOfficeAccountRead,
}

impl OfficeAccountReading {
    /// Che cosa Telegram ha detto, in una frase, con l'istante della
    /// richiesta. Ogni campo assente lo dice invece di tacerlo.
    #[must_use]
    pub fn as_sentence(&self) -> String {
        let lettura = &self.stored.read;
        let quando = lettura.read_at.to_readable_local();
        let Some(profilo) = lettura.profile.as_ref() else {
            return format!(
                "Chiesto a Telegram il {quando}, da {}: {}",
                lettura.read_by, lettura.outcome_reason
            );
        };
        let nome = format!("{} {}", profilo.first_name, profilo.last_name);
        let nome = nome.trim();
        let mut frase = format!(
            "Telegram ha risposto il {quando}, a una richiesta di {}: account con \
             identificativo {}",
            lettura.read_by, profilo.telegram_id
        );
        if nome.is_empty() {
            frase.push_str(", senza nome");
        } else {
            frase.push_str(&format!(", nome \u{ab}{nome}\u{bb}"));
        }
        match profilo.usernames.as_slice() {
            [] => frase.push_str(", nessun nome utente attivo"),
            tutti => frase.push_str(&format!(
                ", nomi utente attivi {}",
                tutti
                    .iter()
                    .map(|n| format!("@{n}"))
                    .collect::<Vec<_>>()
                    .join(", ")
            )),
        }
        match profilo.phone_masked.as_deref() {
            Some(telefono) => frase.push_str(&format!(
                ", telefono {telefono}: si conservano soltanto le ultime cifre."
            )),
            None => frase.push_str(", telefono non restituito."),
        }
        frase
    }
}

/// Chiede a Telegram chi è l'account d'ufficio, e registra la lettura.
///
/// Senza account collegato, o se la richiesta non arriva a una risposta, la
/// lettura si registra **non riuscita** con il perché: anche il tentativo è un
/// atto di cui qualcuno risponde.
///
/// # Errori
///
/// Restituisce un errore soltanto se l'archivio non si scrive.
pub fn read(
    connector: Option<&mut dyn TelegramConnector>,
    database: &mut Database,
    operator: &Actor,
    now: Timestamp,
) -> ServiceResult<OfficeAccountReading> {
    let esito = match connector.and_then(|c| c.official_lookup()) {
        None => Err(String::from(
            "Non c'\u{e8} un account collegato a cui chiederlo: la lettura non \u{e8} partita.",
        )),
        Some(ricerca) => match ricerca.lookup(&LookupQuery::Me) {
            Ok(LookupReply::Found(profilo)) => Ok(OfficeAccountProfile {
                telegram_id: profilo.telegram_id,
                first_name: profilo.first_name,
                last_name: profilo.last_name,
                usernames: profilo.usernames,
                // IL TELEFONO SI MASCHERA QUI, APPENA ARRIVA (ADR-0153).
                phone_masked: profilo
                    .phone_number
                    .as_deref()
                    .map(|numero| MaskedPhoneNumber::from_digits(numero).as_str().to_owned()),
            }),
            Ok(LookupReply::Refused { code, .. }) => Err(format!(
                "Telegram ha rifiutato la richiesta (codice {code}): la lettura non \u{e8} riuscita."
            )),
            Err(errore) => Err(format!(
                "La richiesta non \u{e8} arrivata a una risposta: {}.",
                connector_fault(&errore)
            )),
        },
    };

    let (profile, outcome_reason) = match esito {
        Ok(profilo) => (
            Some(profilo),
            String::from("Telegram ha risposto con l'account collegato."),
        ),
        Err(perche) => (None, perche),
    };
    let lettura = NewOfficeAccountRead {
        read_by: operator.as_str().to_owned(),
        read_at: now,
        profile,
        outcome_reason,
    };
    // L'AUDIT NON PORTA DATI: chi, quando, e se e' riuscita. Il telefono, anche
    // mascherato, e i nomi stanno soltanto nella riga della lettura.
    let audit = NewAuditEntry {
        actor: operator.clone(),
        action: AuditAction::try_new(OFFICE_ACCOUNT_AUDIT_ACTION)?,
        entity: AuditEntity::try_new("account_ufficio")?,
        entity_id: None,
        actor_mode: None,
        detail: Some(AuditDetail::try_new(if lettura.profile.is_some() {
            "lettura riuscita"
        } else {
            "lettura non riuscita"
        })?),
        recorded_at: now,
    };
    let id = database.insert_office_account_read(&lettura, &audit)?;
    Ok(OfficeAccountReading {
        stored: StoredOfficeAccountRead { id, read: lettura },
    })
}

/// L'ultima lettura registrata, se c'è.
///
/// # Errori
///
/// Restituisce un errore se l'archivio non si legge.
pub fn latest(database: &Database) -> ServiceResult<Option<OfficeAccountReading>> {
    Ok(database
        .latest_office_account_read()?
        .map(|stored| OfficeAccountReading { stored }))
}

#[cfg(test)]
mod tests {
    use lisi_core::Timestamp;
    use lisi_core::text::Actor;
    use lisi_telegram::lookup::{LookupKind, LookupProfile, LookupQuery, LookupReply};
    use lisi_telegram::{MockTelegramConnector, TelegramConnector};

    use super::{latest, read};

    const NUMERO_PIENO: &str = "390600000099";

    fn operatore() -> Actor {
        let Ok(attore) = Actor::try_new("operatore.prova") else {
            panic!("attore valido");
        };
        attore
    }

    /// Un connettore simulato con l'accesso completato, che risponde a `getMe`.
    fn connettore_pronto(risposta: LookupReply) -> MockTelegramConnector {
        use lisi_telegram::connector::ClientParameters;
        use lisi_telegram::secret::{ApiHash, ApiId, LoginCode, PhoneNumber};

        let mut connettore = MockTelegramConnector::new();
        let (Ok(api_id), Ok(api_hash)) = (ApiId::try_new(1), ApiHash::try_new(&"a".repeat(32)))
        else {
            panic!("i valori di prova devono essere validi");
        };
        let Ok(()) = connettore.start(&ClientParameters {
            api_id,
            api_hash,
            database_directory: std::path::PathBuf::from("."),
            use_test_datacenter: true,
            application_version: String::from("prova"),
            system_language_code: String::from("it"),
        }) else {
            panic!("l'avvio simulato deve riuscire");
        };
        let (Ok(telefono), Ok(codice)) = (
            PhoneNumber::try_new("+390000000000"),
            LoginCode::try_new("12345"),
        ) else {
            panic!("i valori di prova devono essere validi");
        };
        let (Ok(()), Ok(())) = (
            connettore.submit_phone_number(&telefono),
            connettore.submit_code(&codice),
        ) else {
            panic!("l'accesso simulato deve riuscire");
        };
        connettore.set_lookup_reply(LookupQuery::Me, Ok(risposta));
        connettore
    }

    fn profilo() -> LookupProfile {
        LookupProfile {
            kind: LookupKind::Person,
            telegram_id: 777,
            name: String::from("Ufficio Prova"),
            username: Some(String::from("ufficio_prova")),
            first_name: String::from("Ufficio"),
            last_name: String::from("Prova"),
            usernames: vec![String::from("ufficio_prova"), String::from("ufficio_2")],
            phone_number: Some(String::from(NUMERO_PIENO)),
        }
    }

    /// **`getMe` si legge, si registra mascherato, e porta il suo audit**
    /// (A2, A3, A4).
    #[test]
    fn la_lettura_dell_account_d_ufficio_si_registra_mascherata() {
        let Ok(cartella) = tempfile::tempdir() else {
            panic!("cartella temporanea");
        };
        let percorso = cartella.path().join("archivio.db");
        let Ok(mut archivio) = lisi_storage::Database::open(&percorso) else {
            panic!("archivio su file");
        };
        let mut connettore = connettore_pronto(LookupReply::Found(profilo()));
        let Ok(lettura) = read(
            Some(&mut connettore as &mut dyn TelegramConnector),
            &mut archivio,
            &operatore(),
            Timestamp::from_millis(1_760_000_000_000),
        ) else {
            panic!("la lettura deve registrarsi");
        };
        let frase = lettura.as_sentence();
        assert!(frase.contains("identificativo 777"), "{frase}");
        assert!(frase.contains("@ufficio_prova, @ufficio_2"), "{frase}");
        assert!(frase.contains("+**********99"), "{frase}");
        assert!(!frase.contains(NUMERO_PIENO), "{frase}");

        let Ok(Some(ultima)) = latest(&archivio) else {
            panic!("l'ultima lettura deve rileggersi");
        };
        assert_eq!(ultima, lettura);

        // A3: IL NUMERO PIENO NON E' DA NESSUNA PARTE NELL'ARCHIVIO: si cercano
        // i byte del file e del suo diario, dove SQLite scrive il testo in chiaro.
        drop(archivio);
        let mut dump = String::new();
        for nome in ["archivio.db", "archivio.db-wal"] {
            if let Ok(byte) = std::fs::read(cartella.path().join(nome)) {
                dump.push_str(&String::from_utf8_lossy(&byte));
            }
        }
        assert!(
            !dump.contains(NUMERO_PIENO),
            "il numero pieno non deve trovarsi nell'archivio, nell'audit o nel registro"
        );
        assert!(dump.contains("lettura_account_ufficio"), "l'audit c'e'");
    }

    /// **Senza account, la lettura non parte e lo dice.**
    #[test]
    fn senza_account_la_lettura_non_parte_e_lo_dice() {
        let Ok(mut archivio) = crate::sources::open_in_memory_database() else {
            panic!("archivio in memoria");
        };
        let Ok(lettura) = read(None, &mut archivio, &operatore(), Timestamp::from_millis(1)) else {
            panic!("anche il tentativo si registra");
        };
        assert!(lettura.stored.read.profile.is_none());
        assert!(lettura.as_sentence().contains("non \u{e8} partita"));
    }
}
