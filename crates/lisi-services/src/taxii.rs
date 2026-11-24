//! Lo scambio TAXII 2.1: si manda soltanto ciò che si esporta, a chi
//! l'ufficio ha scelto (TAXII-01 parte 2, ADR-0179).
//!
//! # L'ordine non è casuale
//!
//! 1. **Prima di andare in rete, senza toccarla:** non in Esercitazione
//!    (decisione 8), una destinazione scritta dall'amministratore, un nome e
//!    una parola d'ordine (decisione 5), un pacchetto non vuoto (decisione 7).
//!    Ogni mancanza è un errore, e niente esce.
//! 2. **Il corpo:** l'elenco `objects` del pacchetto che l'esportazione STIX
//!    scriverebbe adesso, dallo stesso piano e dalla stessa funzione
//!    (decisione 2). Qui non si compone niente.
//! 3. **La rete:** un solo `POST`, dalla sola porta
//!    (`lisi_platform::https::send_taxii`), all'indirizzo composto dalla
//!    destinazione conservata. Mai da un contenuto, da un pacchetto o dalla
//!    risposta del server (decisione 3).
//! 4. **Il registro:** ogni invio arrivato alla porta lascia una riga e una
//!    riga d'audit, anche quando il server non l'ha preso (decisione 9). Il
//!    corpo non si tiene: resta la sua impronta.
//!
//! # La risposta è dato non fidato
//!
//! Della risorsa di stato si tengono un identificativo, se ha la forma di un
//! identificativo, e tre numeri. Nient'altro: nessun testo del server arriva
//! al registro o allo schermo.
//!
//! # La parola d'ordine non sta nell'archivio
//!
//! Sta in un file protetto con DPAPI per l'utente di Windows (ADR-0009),
//! accanto agli altri segreti. Non entra nell'archivio, nelle sue copie,
//! nell'audit o nei registri. Un altro utente di Windows non la legge, e la
//! riscrive: è la conseguenza voluta.

use std::collections::BTreeMap;
use std::path::PathBuf;

use lisi_core::model::NewAuditEntry;
use lisi_core::text::{Actor, AuditAction, AuditDetail, AuditEntity};
use lisi_core::{OperatingMode, RestrictedAction, SessionId, Sha256Digest, Timestamp};
use lisi_platform::https::{self, BasicCredentials, FetchRefusal, Sent};
use lisi_security::ProtectedStore;
use lisi_storage::Database;
pub use lisi_storage::repository::taxii::StoredTaxiiSubmission;
use lisi_storage::repository::taxii::{NewTaxiiSubmission, StoredTaxiiDestination};

use crate::error::{ServiceError, ServiceResult};
use crate::stix_export::{StixExportService, taxii_envelope};

/// Il file protetto della parola d'ordine, nella cartella dei dati.
pub const TAXII_PASSWORD_FILE: &str = "taxii.protetto";

/// La voce del file protetto.
const PASSWORD_ENTRY: &str = "parola_d_ordine";

/// Quanto può essere lungo l'identificativo della collezione.
pub const MAX_COLLECTION_ID_CHARS: usize = 64;

/// Quanto può essere lungo il nome utente.
pub const MAX_USERNAME_CHARS: usize = 256;

/// Quanto può essere lunga la parola d'ordine.
pub const MAX_PASSWORD_CHARS: usize = 1024;

/// Oltre questo numero un conteggio del server non si crede.
const MAX_STATUS_COUNT: u64 = 1_000_000_000;

/// Dove sta la parola d'ordine, se la cartella dei dati è determinabile.
#[must_use]
pub fn default_password_path() -> Option<PathBuf> {
    crate::data_directory::mode_directory().map(|cartella| cartella.join(TAXII_PASSWORD_FILE))
}

/// La destinazione scritta dall'amministratore.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TaxiiDestination {
    /// La radice dell'API, `https://`.
    pub api_root: String,
    /// L'identificativo della collezione: lettere, cifre e trattini.
    pub collection_id: String,
    /// Il nome utente di HTTP Basic, se scritto.
    pub username: Option<String>,
}

impl TaxiiDestination {
    /// L'indirizzo a cui si manda: `{radice}/collections/{id}/objects/`.
    ///
    /// Si compone qui, e soltanto qui, dalla destinazione conservata.
    #[must_use]
    pub fn objects_url(&self) -> String {
        format!(
            "{}/collections/{}/objects/",
            self.api_root.trim_end_matches('/'),
            self.collection_id
        )
    }
}

impl From<StoredTaxiiDestination> for TaxiiDestination {
    fn from(conservata: StoredTaxiiDestination) -> Self {
        Self {
            api_root: conservata.api_root,
            collection_id: conservata.collection_id,
            username: conservata.username,
        }
    }
}

/// Che cosa uscirebbe adesso, e verso dove, prima di chiedere conferma
/// (decisione 7).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TaxiiPreview {
    /// L'indirizzo a cui si manderebbe.
    pub url: String,
    /// Quanti osservabili uscirebbero.
    pub observables: usize,
    /// Quanti valori restano fuori, come nell'esportazione.
    pub omitted: usize,
}

/// Lo stato TAXII letto dalla risposta: un identificativo e tre numeri.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TaxiiStatus {
    /// L'identificativo dello stato, se ha la forma di un identificativo.
    pub id: Option<String>,
    /// Gli oggetti presi.
    pub success: Option<u64>,
    /// Gli oggetti rifiutati.
    pub failure: Option<u64>,
    /// Gli oggetti ancora in attesa.
    pub pending: Option<u64>,
}

/// Com'è andato un invio arrivato alla porta.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TaxiiSendOutcome {
    /// La destinazione ha risposto `202`: ha preso l'invio.
    Delivered {
        /// Quanti oggetti sono stati mandati.
        objects: u32,
        /// Lo stato, se la risposta si è letta.
        status: Option<TaxiiStatus>,
    },
    /// L'invio non è stato preso.
    NotDelivered {
        /// Perché, in parole per l'operatore.
        reason: String,
    },
}

impl TaxiiSendOutcome {
    /// La frase per l'operatore.
    #[must_use]
    pub fn operator_message(&self) -> String {
        match self {
            Self::Delivered {
                objects,
                status:
                    Some(TaxiiStatus {
                        success: Some(presi),
                        failure: Some(rifiutati),
                        pending: Some(in_attesa),
                        ..
                    }),
            } => format!(
                "La destinazione TAXII ha preso l'invio di {objects} oggetti. Dice: {presi} \
                 accettati, {rifiutati} rifiutati, {in_attesa} in attesa."
            ),
            Self::Delivered { objects, .. } => format!(
                "La destinazione TAXII ha preso l'invio di {objects} oggetti. Non ha detto \
                 quanti ne ha accettati."
            ),
            Self::NotDelivered { reason } => {
                format!("L'invio a TAXII non è stato preso: {reason}.")
            }
        }
    }
}

/// Ciò che serve per mandare, controllato e composto.
///
/// Non è `Debug`: porta la parola d'ordine.
pub(crate) struct Ready {
    url: String,
    username: String,
    password: String,
    session_id: SessionId,
    envelope: Vec<u8>,
    objects: u32,
}

/// Il servizio dello scambio TAXII.
pub struct TaxiiService<'a> {
    database: &'a mut Database,
    secrets: ProtectedStore,
}

impl<'a> TaxiiService<'a> {
    /// Costruisce il servizio sull'archivio e sul file protetto della parola
    /// d'ordine.
    #[must_use]
    pub const fn new(database: &'a mut Database, secrets: ProtectedStore) -> Self {
        Self { database, secrets }
    }

    /// Costruisce il servizio con la parola d'ordine nel file indicato.
    ///
    /// È l'ingresso che usa l'interfaccia: il confine di ADR-0010 le vieta di
    /// nominare `ProtectedStore`, e passare un percorso è tutto ciò che le
    /// serve.
    #[must_use]
    pub fn with_password_file(database: &'a mut Database, path: PathBuf) -> Self {
        Self::new(database, ProtectedStore::at(path))
    }

    /// La destinazione, se configurata.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se la lettura non riesce.
    pub fn destination(&self) -> ServiceResult<Option<TaxiiDestination>> {
        Ok(self
            .database
            .taxii_destination()?
            .map(TaxiiDestination::from))
    }

    /// Scrive la destinazione, o la svuota passando radice e collezione
    /// vuote.
    ///
    /// Nel registro finisce che la destinazione è cambiata, non quale: come
    /// per la fonte dei dizionari, quella di oggi si legge dove è scritta.
    ///
    /// # Errori
    ///
    /// [`ServiceError::ActionReservedToAdministrator`] in modalità operatore,
    /// [`ServiceError::TaxiiDestinationRefused`] per una destinazione non
    /// utilizzabile, o un errore se la scrittura non riesce. Un rifiuto lascia
    /// la destinazione di prima.
    pub fn set_destination(
        &mut self,
        api_root: Option<&str>,
        collection_id: Option<&str>,
        username: Option<&str>,
        mode: OperatingMode,
        actor: &Actor,
        now: Timestamp,
    ) -> ServiceResult<()> {
        richiedi(mode)?;

        let pulito = |valore: Option<&str>| {
            valore
                .map(str::trim)
                .filter(|valore| !valore.is_empty())
                .map(str::to_owned)
        };
        let rifiuto = |reason: &str| ServiceError::TaxiiDestinationRefused {
            reason: reason.to_owned(),
        };

        let destinazione = match (pulito(api_root), pulito(collection_id)) {
            (None, None) => None,
            (Some(api_root), Some(collection_id)) => {
                crate::update::check_url(&api_root)
                    .map_err(|reason| ServiceError::TaxiiDestinationRefused { reason })?;
                if collection_id.chars().count() > MAX_COLLECTION_ID_CHARS
                    || !collection_id
                        .chars()
                        .all(|c| c.is_ascii_alphanumeric() || c == '-')
                {
                    return Err(rifiuto(
                        "l'identificativo della collezione si scrive soltanto con lettere, cifre e trattini",
                    ));
                }
                let username = pulito(username);
                if let Some(nome) = &username
                    && (nome.contains(':')
                        || nome.chars().any(char::is_control)
                        || nome.chars().count() > MAX_USERNAME_CHARS)
                {
                    return Err(rifiuto(
                        "il nome non può contenere i due punti o un a capo, né essere così lungo",
                    ));
                }
                let destinazione = TaxiiDestination {
                    api_root,
                    collection_id,
                    username,
                };
                if destinazione.objects_url().chars().count() > https::MAX_URL_CHARS {
                    return Err(rifiuto("è troppo lungo"));
                }
                Some(destinazione)
            }
            _ => {
                return Err(rifiuto(
                    "l'indirizzo e la collezione si scrivono insieme, o mancano insieme",
                ));
            }
        };

        let audit = audit_entry(
            actor,
            "destinazione_taxii_impostata",
            if destinazione.is_some() {
                "indicata"
            } else {
                "svuotata"
            },
            Some(mode),
            now,
        )?;
        let conservata = destinazione.map(|d| StoredTaxiiDestination {
            api_root: d.api_root,
            collection_id: d.collection_id,
            username: d.username,
        });
        self.database
            .save_taxii_destination(conservata.as_ref(), actor, &audit)?;
        Ok(())
    }

    /// Se una parola d'ordine è stata scritta per questo utente di Windows.
    #[must_use]
    pub fn has_password(&self) -> bool {
        self.secrets.exists()
    }

    /// Scrive la parola d'ordine nel file protetto, o la toglie passando
    /// `None` o una parola vuota.
    ///
    /// Nell'audit finisce che è stata scritta o tolta, mai la parola.
    ///
    /// # Errori
    ///
    /// [`ServiceError::ActionReservedToAdministrator`] in modalità operatore,
    /// [`ServiceError::TaxiiPasswordRefused`] per una parola non utilizzabile
    /// o che Windows non protegge, o un errore se l'audit non si scrive.
    pub fn set_password(
        &self,
        password: Option<&str>,
        mode: OperatingMode,
        actor: &Actor,
        now: Timestamp,
    ) -> ServiceResult<()> {
        richiedi(mode)?;

        let parola = password.filter(|parola| !parola.is_empty());
        if let Some(parola) = parola {
            if parola.chars().any(char::is_control) || parola.chars().count() > MAX_PASSWORD_CHARS {
                return Err(ServiceError::TaxiiPasswordRefused {
                    reason: String::from("non può contenere un a capo, né essere così lunga"),
                });
            }
            let mut voci = BTreeMap::new();
            voci.insert(String::from(PASSWORD_ENTRY), parola.to_owned());
            self.secrets
                .save(&voci)
                .map_err(|_| ServiceError::TaxiiPasswordRefused {
                    reason: String::from("Windows non l'ha protetta"),
                })?;
        } else {
            self.secrets
                .delete()
                .map_err(|_| ServiceError::TaxiiPasswordRefused {
                    reason: String::from("il file che la conserva non si toglie"),
                })?;
        }

        self.database.append_audit(&audit_entry(
            actor,
            "parola_taxii_impostata",
            if parola.is_some() { "scritta" } else { "tolta" },
            Some(mode),
            now,
        )?)?;
        Ok(())
    }

    /// Gli invii, dal più recente.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se la lettura non riesce.
    pub fn submissions(&self) -> ServiceResult<Vec<StoredTaxiiSubmission>> {
        Ok(self.database.taxii_submissions()?)
    }

    /// Che cosa uscirebbe da questo monitoraggio, e verso dove, senza
    /// mandare niente.
    ///
    /// # Errori
    ///
    /// [`ServiceError::TaxiiDestinationMissing`] senza destinazione, o un
    /// errore se l'archivio non si legge.
    pub fn preview(&self, session_id: SessionId) -> ServiceResult<TaxiiPreview> {
        let Some(destinazione) = self.destination()? else {
            return Err(ServiceError::TaxiiDestinationMissing);
        };
        let piano = StixExportService::new(self.database).preview(session_id)?;
        Ok(TaxiiPreview {
            url: destinazione.objects_url(),
            observables: piano.exported.len(),
            omitted: piano.omitted.len(),
        })
    }

    /// Manda gli osservabili di questo monitoraggio alla destinazione, quando
    /// una persona preme dopo aver visto [`Self::preview`] (decisione 7).
    ///
    /// # Errori
    ///
    /// [`ServiceError::TaxiiInExercise`] in Esercitazione,
    /// [`ServiceError::TaxiiDestinationMissing`] senza destinazione,
    /// [`ServiceError::TaxiiCredentialsMissing`] senza nome o parola d'ordine,
    /// [`ServiceError::StixNothingToExport`] con un pacchetto vuoto: in tutti
    /// questi casi non si va in rete. Un errore se l'archivio non si legge o
    /// non si scrive. Ogni altro esito è un [`TaxiiSendOutcome`], già scritto
    /// nel registro.
    pub fn send(
        &mut self,
        session_id: SessionId,
        actor: &Actor,
        now: Timestamp,
    ) -> ServiceResult<TaxiiSendOutcome> {
        let pronto = self.prepare(session_id, crate::run_mode::is_exercise(), now)?;
        let credenziali = BasicCredentials {
            user: &pronto.username,
            password: &pronto.password,
        };
        let esito = https::send_taxii(&pronto.url, &pronto.envelope, &credenziali);
        self.record(&pronto, esito, actor, now)
    }

    /// I controlli che precedono la rete, e il corpo.
    pub(crate) fn prepare(
        &self,
        session_id: SessionId,
        exercise: bool,
        now: Timestamp,
    ) -> ServiceResult<Ready> {
        if exercise {
            return Err(ServiceError::TaxiiInExercise);
        }
        let Some(destinazione) = self.destination()? else {
            return Err(ServiceError::TaxiiDestinationMissing);
        };
        let Some(username) = destinazione.username.clone() else {
            return Err(ServiceError::TaxiiCredentialsMissing);
        };
        let password = self.password()?;

        let piano = StixExportService::new(self.database).preview(session_id)?;
        if piano.is_empty() {
            return Err(ServiceError::StixNothingToExport);
        }
        let (envelope, objects) = taxii_envelope(&piano, now);

        Ok(Ready {
            url: destinazione.objects_url(),
            username,
            password,
            session_id,
            envelope,
            objects: u32::try_from(objects).unwrap_or(u32::MAX),
        })
    }

    /// La parola d'ordine dal file protetto.
    ///
    /// Un file assente, illeggibile o di un altro utente di Windows vuol dire
    /// la stessa cosa a chi sta davanti: va scritta.
    fn password(&self) -> ServiceResult<String> {
        self.secrets
            .load_entry(PASSWORD_ENTRY)
            .ok()
            .filter(|parola| !parola.is_empty())
            .ok_or(ServiceError::TaxiiCredentialsMissing)
    }

    /// Scrive l'esito di un invio arrivato alla porta e lo restituisce.
    pub(crate) fn record(
        &mut self,
        pronto: &Ready,
        esito: Sent,
        actor: &Actor,
        now: Timestamp,
    ) -> ServiceResult<TaxiiSendOutcome> {
        let impronta = Sha256Digest::of_bytes(&pronto.envelope);
        let mut riga = NewTaxiiSubmission {
            requested_by: actor.as_str().to_owned(),
            requested_at: now,
            url: pronto.url.clone(),
            session_id: pronto.session_id.get(),
            objects: pronto.objects,
            body_sha256: impronta.as_str().to_owned(),
            http_status: None,
            outcome: String::from("non_consegnato"),
            outcome_detail: None,
            status_id: None,
            success_count: None,
            failure_count: None,
            pending_count: None,
        };

        let (esito, azione, dettaglio) = match esito {
            Sent::Accepted(risposta) => {
                let stato = read_status(&risposta);
                riga.http_status = Some(202);
                riga.outcome = String::from("consegnato");
                if let Some(stato) = &stato {
                    riga.status_id.clone_from(&stato.id);
                    riga.success_count = stato.success;
                    riga.failure_count = stato.failure;
                    riga.pending_count = stato.pending;
                } else {
                    riga.outcome_detail = Some(String::from("la risposta di stato non si legge"));
                }
                (
                    TaxiiSendOutcome::Delivered {
                        objects: pronto.objects,
                        status: stato,
                    },
                    "taxii_consegnato",
                    format!("{} oggetti, impronta {}", pronto.objects, impronta.as_str()),
                )
            }
            Sent::Refused(motivo) => {
                riga.http_status = match motivo {
                    FetchRefusal::Status { status } | FetchRefusal::Redirected { status }
                        if (100..=599).contains(&status) && status != 202 =>
                    {
                        Some(status)
                    }
                    _ => None,
                };
                let frase = motivo.to_string();
                riga.outcome_detail = Some(frase.clone());
                (
                    TaxiiSendOutcome::NotDelivered {
                        reason: frase.clone(),
                    },
                    "taxii_non_consegnato",
                    frase,
                )
            }
        };

        let audit = audit_entry(actor, azione, &dettaglio, None, now)?;
        self.database.insert_taxii_submission(&riga, &audit)?;
        Ok(esito)
    }
}

/// Il rifiuto in modalità operatore (ADR-0179, decisione 4).
const fn richiedi(mode: OperatingMode) -> ServiceResult<()> {
    if mode.allows(RestrictedAction::ChooseTaxiiDestination) {
        Ok(())
    } else {
        Err(ServiceError::ActionReservedToAdministrator {
            action: RestrictedAction::ChooseTaxiiDestination,
        })
    }
}

/// Lo stato TAXII dalla risposta, letto come dato non fidato.
///
/// Si prende un oggetto JSON, e di quello l'identificativo se è fatto di
/// lettere, cifre e trattini, e tre conteggi se sono numeri credibili. Ogni
/// altro campo — titoli, descrizioni, elenchi di identificativi — si ignora.
fn read_status(risposta: &[u8]) -> Option<TaxiiStatus> {
    let valore: serde_json::Value = serde_json::from_slice(risposta).ok()?;
    let oggetto = valore.as_object()?;
    let conteggio = |chiave: &str| {
        oggetto
            .get(chiave)
            .and_then(serde_json::Value::as_u64)
            .filter(|numero| *numero <= MAX_STATUS_COUNT)
    };
    Some(TaxiiStatus {
        id: oggetto
            .get("id")
            .and_then(serde_json::Value::as_str)
            .filter(|id| {
                !id.is_empty()
                    && id.len() <= 64
                    && id.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
            })
            .map(str::to_owned),
        success: conteggio("success_count"),
        failure: conteggio("failure_count"),
        pending: conteggio("pending_count"),
    })
}

/// Una riga d'audit di questo modulo.
fn audit_entry(
    actor: &Actor,
    action: &str,
    detail: &str,
    mode: Option<OperatingMode>,
    now: Timestamp,
) -> ServiceResult<NewAuditEntry> {
    // Un dettaglio lungo si accorcia: il registro ha la frase intera.
    let dettaglio: String = detail.chars().take(240).collect();
    Ok(NewAuditEntry {
        actor: actor.clone(),
        action: AuditAction::try_new(action)?,
        entity: AuditEntity::try_new("taxii")?,
        entity_id: None,
        actor_mode: mode,
        detail: Some(AuditDetail::try_new(&dettaglio)?),
        recorded_at: now,
    })
}

#[cfg(test)]
mod tests {
    use lisi_core::text::Actor;
    use lisi_core::{OperatingMode, RestrictedAction, SessionId, Timestamp};
    use lisi_platform::https::{FetchRefusal, Sent};
    use lisi_security::ProtectedStore;
    use lisi_storage::Database;

    use super::{Ready, TAXII_PASSWORD_FILE, TaxiiSendOutcome, TaxiiService, read_status};
    use crate::error::ServiceError;

    const RADICE: &str = "https://taxii.esempio.test/api1/";
    const COLLEZIONE: &str = "91a7b528-80eb-42ed-a74d-c6fbd5a26116";
    const PAROLA: &str = "parola-di-prova-7Q";

    fn archivio() -> Database {
        let Ok(database) = crate::sources::open_in_memory_database() else {
            panic!("l'archivio in memoria deve aprirsi");
        };
        database
    }

    fn amministratore() -> Actor {
        let Ok(attore) = Actor::try_new("amministratore.prova") else {
            panic!("attore valido");
        };
        attore
    }

    fn adesso() -> Timestamp {
        Timestamp::from_millis(1_762_000_000_000)
    }

    fn cartella() -> tempfile::TempDir {
        let Ok(cartella) = tempfile::tempdir() else {
            panic!("la cartella temporanea deve crearsi");
        };
        cartella
    }

    fn cassaforte(cartella: &tempfile::TempDir) -> ProtectedStore {
        ProtectedStore::at(cartella.path().join(TAXII_PASSWORD_FILE))
    }

    fn configura(servizio: &mut TaxiiService<'_>, nome: Option<&str>) {
        let Ok(()) = servizio.set_destination(
            Some(RADICE),
            Some(COLLEZIONE),
            nome,
            OperatingMode::Administrator,
            &amministratore(),
            adesso(),
        ) else {
            panic!("la destinazione deve scriversi");
        };
    }

    fn pronto() -> Ready {
        Ready {
            url: format!("{RADICE}collections/{COLLEZIONE}/objects/"),
            username: String::from("ufficio.prova"),
            password: String::from(PAROLA),
            session_id: SessionId::new(4),
            envelope: br#"{"objects":[]}"#.to_vec(),
            objects: 3,
        }
    }

    /// **Destinazione e parola d'ordine sono dell'amministratore** (ADR-0179,
    /// decisione 4): l'operatore riceve il rifiuto dal servizio, e niente si
    /// scrive.
    #[test]
    fn la_destinazione_e_la_parola_sono_dell_amministratore() {
        let mut database = archivio();
        let cartella = cartella();
        let mut servizio = TaxiiService::new(&mut database, cassaforte(&cartella));

        let destinazione = servizio.set_destination(
            Some(RADICE),
            Some(COLLEZIONE),
            Some("ufficio.prova"),
            OperatingMode::Operator,
            &amministratore(),
            adesso(),
        );
        let parola = servizio.set_password(
            Some(PAROLA),
            OperatingMode::Operator,
            &amministratore(),
            adesso(),
        );
        for esito in [destinazione, parola] {
            assert!(matches!(
                esito,
                Err(ServiceError::ActionReservedToAdministrator {
                    action: RestrictedAction::ChooseTaxiiDestination
                })
            ));
        }
        assert_eq!(servizio.destination().ok(), Some(None));
        assert!(!servizio.has_password());
    }

    /// **Una destinazione che non si può usare non si scrive, e resta quella
    /// di prima.**
    #[test]
    fn una_destinazione_inutilizzabile_si_rifiuta_e_lascia_quella_di_prima() {
        let mut database = archivio();
        let cartella = cartella();
        let mut servizio = TaxiiService::new(&mut database, cassaforte(&cartella));
        configura(&mut servizio, Some("ufficio.prova"));
        let prima = servizio.destination().ok();

        for (radice, collezione, nome) in [
            (
                Some("http://taxii.esempio.test/api1/"),
                Some(COLLEZIONE),
                None,
            ),
            (Some(RADICE), Some("collezione/../altra"), None),
            (Some(RADICE), Some("con spazio"), None),
            (Some(RADICE), None, None),
            (None, Some(COLLEZIONE), None),
            (Some(RADICE), Some(COLLEZIONE), Some("nome:altro")),
            (Some(RADICE), Some(COLLEZIONE), Some("nome\naltro")),
        ] {
            let esito = servizio.set_destination(
                radice,
                collezione,
                nome,
                OperatingMode::Administrator,
                &amministratore(),
                adesso(),
            );
            assert!(
                matches!(esito, Err(ServiceError::TaxiiDestinationRefused { .. })),
                "{radice:?} {collezione:?} {nome:?} va rifiutata: {esito:?}"
            );
        }
        assert_eq!(servizio.destination().ok(), prima);
    }

    /// **L'indirizzo si compone dalla radice e dalla collezione, e da
    /// nient'altro**, con o senza la barra in fondo alla radice.
    #[test]
    fn l_indirizzo_si_compone_dalla_radice_e_dalla_collezione() {
        let mut database = archivio();
        let cartella = cartella();
        let mut servizio = TaxiiService::new(&mut database, cassaforte(&cartella));
        for radice in [RADICE, "https://taxii.esempio.test/api1"] {
            let Ok(()) = servizio.set_destination(
                Some(radice),
                Some(COLLEZIONE),
                None,
                OperatingMode::Administrator,
                &amministratore(),
                adesso(),
            ) else {
                panic!("la destinazione deve scriversi");
            };
            let Ok(Some(destinazione)) = servizio.destination() else {
                panic!("la destinazione deve rileggersi");
            };
            assert_eq!(
                destinazione.objects_url(),
                format!("https://taxii.esempio.test/api1/collections/{COLLEZIONE}/objects/")
            );
        }
    }

    /// **La parola d'ordine non entra nell'archivio** (ADR-0179, decisione 5):
    /// né nella destinazione, né nell'audit, né in chiaro nel file protetto.
    #[test]
    fn la_parola_d_ordine_non_entra_nell_archivio() {
        let mut database = archivio();
        let cartella = cartella();
        let percorso = cartella.path().join(TAXII_PASSWORD_FILE);
        {
            let mut servizio = TaxiiService::new(&mut database, cassaforte(&cartella));
            configura(&mut servizio, Some("ufficio.prova"));
            let Ok(()) = servizio.set_password(
                Some(PAROLA),
                OperatingMode::Administrator,
                &amministratore(),
                adesso(),
            ) else {
                panic!("la parola d'ordine deve scriversi");
            };
            assert!(servizio.has_password());
            assert_eq!(servizio.password().ok().as_deref(), Some(PAROLA));
        }

        let Ok(byte) = std::fs::read(&percorso) else {
            panic!("il file protetto deve esistere");
        };
        assert!(
            !String::from_utf8_lossy(&byte).contains(PAROLA),
            "il file protetto non deve contenere la parola in chiaro"
        );
        let Ok(righe) = database.audit_entries() else {
            panic!("l'audit deve leggersi");
        };
        assert!(
            righe
                .iter()
                .any(|riga| riga.action.as_str() == "parola_taxii_impostata"),
            "che la parola sia stata scritta resta nell'audit"
        );
        for riga in &righe {
            let dettaglio = riga.detail.as_ref().map_or("", |d| d.as_str());
            assert!(!dettaglio.contains(PAROLA), "l'audit non porta la parola");
        }

        // Tolta, il file non c'è più e l'invio torna a mancare di credenziali.
        let servizio = TaxiiService::new(&mut database, cassaforte(&cartella));
        let Ok(()) = servizio.set_password(
            None,
            OperatingMode::Administrator,
            &amministratore(),
            adesso(),
        ) else {
            panic!("la parola d'ordine deve togliersi");
        };
        assert!(!percorso.exists());
        assert!(matches!(
            servizio.password(),
            Err(ServiceError::TaxiiCredentialsMissing)
        ));
    }

    /// **Senza ciò che serve, niente va in rete, e il registro resta vuoto**:
    /// l'esercitazione, la destinazione, il nome, la parola d'ordine, un
    /// pacchetto non vuoto, in quest'ordine.
    #[test]
    fn senza_cio_che_serve_non_si_va_in_rete() {
        let mut database = archivio();
        let cartella = cartella();
        let mut servizio = TaxiiService::new(&mut database, cassaforte(&cartella));
        let sessione = SessionId::new(1);

        assert!(matches!(
            servizio.prepare(sessione, false, adesso()),
            Err(ServiceError::TaxiiDestinationMissing)
        ));
        configura(&mut servizio, None);
        assert!(matches!(
            servizio.prepare(sessione, false, adesso()),
            Err(ServiceError::TaxiiCredentialsMissing)
        ));
        configura(&mut servizio, Some("ufficio.prova"));
        assert!(matches!(
            servizio.prepare(sessione, false, adesso()),
            Err(ServiceError::TaxiiCredentialsMissing)
        ));
        let Ok(()) = servizio.set_password(
            Some(PAROLA),
            OperatingMode::Administrator,
            &amministratore(),
            adesso(),
        ) else {
            panic!("la parola d'ordine deve scriversi");
        };
        // Un monitoraggio senza osservabili: il pacchetto vuoto non si manda.
        assert!(matches!(
            servizio.prepare(sessione, false, adesso()),
            Err(ServiceError::StixNothingToExport)
        ));
        // In esercitazione il rifiuto viene prima di tutto il resto.
        assert!(matches!(
            servizio.prepare(sessione, true, adesso()),
            Err(ServiceError::TaxiiInExercise)
        ));
        // Il pubblico `send` fa gli stessi controlli: anche lui si ferma prima.
        assert!(matches!(
            servizio.send(sessione, &amministratore(), adesso()),
            Err(ServiceError::StixNothingToExport)
        ));
        assert_eq!(servizio.submissions().map(|v| v.len()).ok(), Some(0));
    }

    /// **Una consegna si scrive con il suo stato, e dello stato si tengono un
    /// identificativo e tre numeri** (decisioni 6 e 9).
    #[test]
    fn una_consegna_si_scrive_con_il_suo_stato() {
        let mut database = archivio();
        let cartella = cartella();
        let mut servizio = TaxiiService::new(&mut database, cassaforte(&cartella));
        let risposta = br#"{"id":"stato-1","status":"complete","success_count":2,
            "failure_count":1,"pending_count":0,
            "failures":[{"message":"<b>testo del server</b>"}]}"#;

        let Ok(esito) = servizio.record(
            &pronto(),
            Sent::Accepted(risposta.to_vec()),
            &amministratore(),
            adesso(),
        ) else {
            panic!("la consegna deve scriversi");
        };
        assert!(
            esito
                .operator_message()
                .contains("2 accettati, 1 rifiutati, 0 in attesa")
        );

        let Ok(invii) = servizio.submissions() else {
            panic!("il registro deve leggersi");
        };
        assert_eq!(invii.len(), 1);
        let invio = &invii[0];
        assert_eq!(invio.outcome, "consegnato");
        assert_eq!(invio.http_status, Some(202));
        assert_eq!(invio.status_id.as_deref(), Some("stato-1"));
        assert_eq!(
            (
                invio.success_count,
                invio.failure_count,
                invio.pending_count
            ),
            (Some(2), Some(1), Some(0))
        );
        assert_eq!(invio.session_id, 4);
        assert_eq!(invio.objects, 3);
        assert_eq!(
            invio.body_sha256,
            lisi_core::Sha256Digest::of_bytes(br#"{"objects":[]}"#).as_str()
        );
        assert!(
            !format!("{invio:?}").contains("testo del server"),
            "nessun testo del server arriva al registro"
        );
    }

    /// **Un invio che il server non prende si scrive, con lo stato HTTP**, e
    /// la parola d'ordine non compare da nessuna parte.
    #[test]
    fn un_invio_non_preso_si_scrive_con_lo_stato_http() {
        let mut database = archivio();
        let cartella = cartella();
        let mut servizio = TaxiiService::new(&mut database, cassaforte(&cartella));

        let Ok(esito) = servizio.record(
            &pronto(),
            Sent::Refused(FetchRefusal::Status { status: 401 }),
            &amministratore(),
            adesso(),
        ) else {
            panic!("il mancato invio deve scriversi");
        };
        assert!(matches!(esito, TaxiiSendOutcome::NotDelivered { .. }));
        let Ok(invii) = servizio.submissions() else {
            panic!("il registro deve leggersi");
        };
        assert_eq!(invii[0].outcome, "non_consegnato");
        assert_eq!(invii[0].http_status, Some(401));
        assert!(invii[0].status_id.is_none());
        assert!(!format!("{:?}", invii[0]).contains(PAROLA));

        let Ok(righe) = servizio.database.audit_entries() else {
            panic!("l'audit deve leggersi");
        };
        assert!(
            righe
                .iter()
                .any(|riga| riga.action.as_str() == "taxii_non_consegnato"),
            "anche il mancato invio resta nell'audit"
        );
        for riga in &righe {
            let dettaglio = riga.detail.as_ref().map_or("", |d| d.as_str());
            assert!(!dettaglio.contains(PAROLA), "l'audit non porta la parola");
        }
    }

    /// **La risposta di stato è dato non fidato**: un identificativo che non
    /// ne ha la forma, un numero incredibile, un numero negativo, un numero
    /// scritto come testo, un JSON che non è un oggetto non passano.
    #[test]
    fn la_risposta_di_stato_e_dato_non_fidato() {
        let Some(stato) = read_status(
            br#"{"id":"../../altro","success_count":99999999999999,"failure_count":-1,"pending_count":"3"}"#,
        ) else {
            panic!("un oggetto JSON si legge");
        };
        assert_eq!(stato.id, None);
        assert_eq!(stato.success, None);
        assert_eq!(stato.failure, None);
        assert_eq!(stato.pending, None);

        assert!(read_status(b"non JSON").is_none());
        assert!(read_status(b"[1,2,3]").is_none());
        assert!(read_status(b"").is_none());
    }
}
