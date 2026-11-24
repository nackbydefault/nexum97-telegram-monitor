//! L'identità che questa postazione si è data, **conservata**.
//!
//! `lisi-core` definisce che cosa sono un'identità di dispositivo e una di
//! operatore; questo modulo aggiunge la parte che mancava perché valessero fra
//! un avvio e l'altro. Tre scelte toccano questo codice.
//!
//! **L'identità sta in un file protetto proprio**, distinto sia da quello delle
//! credenziali Telegram sia da quello della modalità operativa. Per la stessa
//! ragione per cui la modalità ha il suo: sapere quale dispositivo è questo non
//! deve richiedere che le credenziali siano presenti, né viceversa.
//!
//! **Il segreto non si sovrascrive per sbaglio.** `create` rifiuta se
//! un'identità esiste già. Rigenerarla in silenzio produrrebbe un dispositivo
//! nuovo che si presenta con il vecchio nome nell'audit — e il giorno in cui
//! esisterà un Hub, un dispositivo che l'Hub non riconosce più senza che
//! nessuno abbia revocato nulla.
//!
//! **La revoca registrata qui non è la revoca che conta.** È una copia locale,
//! e serve a spiegare all'operatore perché la postazione ha smesso di provarci.
//! Un Hub che si fidasse di questo file non starebbe controllando niente: chi
//! prende la macchina lo riscrive.
//!
//! # Che cosa questo modulo fa dell'arruolamento, e che cosa no
//!
//! **Prepara** la richiesta e **registra** l'esito. La decisione non è sua: la
//! prende l'Hub, in `crate::hub_enrollment`, ed è l'unica che conta.
//!
//! Il **gettone non si conserva.** Si ricalcola dal segreto sotto DPAPI e dal
//! sale, ogni volta che serve. Una terza copia su disco aggiungerebbe qualcosa
//! da proteggere senza aggiungere niente.
//!
//! Non parla in rete e non autentica: il trasporto è HUB-04.

use std::collections::BTreeMap;
use std::path::PathBuf;

use lisi_core::Timestamp;
use lisi_core::model::NewAuditEntry;
use lisi_core::model::enrollment::{
    DeviceToken, ENROLLMENT_SALT_BYTES, EnrollmentCode, EnrollmentGrant, EnrollmentRequest,
    EnrollmentSalt,
};
use lisi_core::model::identity::{
    DEVICE_ID_BYTES, DEVICE_SECRET_BYTES, DeviceId, DeviceIdentity, DeviceSecret, DeviceState,
    OperatorId,
};
use lisi_core::text::{AuditAction, AuditDetail, AuditEntity, DisplayName, Note};
use lisi_security::{ProtectedStore, SecurityError};

use crate::Database;
use crate::error::{ServiceError, ServiceResult};

/// Nome del file protetto dell'identità di dispositivo.
pub const DEVICE_FILE: &str = "device.protetto";

/// Chiave dell'identificativo pubblico.
const ID_KEY: &str = "device_id";
/// Chiave del segreto, in esadecimale.
const SECRET_KEY: &str = "device_secret";
/// Chiave del nome dato dall'ufficio.
const LABEL_KEY: &str = "device_label";
/// Chiave dell'istante di creazione.
const CREATED_KEY: &str = "device_created_at";
/// Chiave dell'istante di revoca.
const REVOKED_AT_KEY: &str = "device_revoked_at";
/// Chiave della ragione della revoca.
const REVOKED_REASON_KEY: &str = "device_revoked_reason";
/// Chiave del nome dell'Hub che ha ammesso il dispositivo.
const HUB_KEY: &str = "device_hub";
/// Chiave dell'istante di arruolamento.
const ENROLLED_AT_KEY: &str = "device_enrolled_at";
/// Chiave del sale con cui si ricalcola il gettone.
///
/// Non è un segreto e sta accanto agli altri: il suo mestiere è che lo stesso
/// dispositivo, arruolato presso due Hub, presenti due gettoni diversi.
const SALT_KEY: &str = "device_enrollment_salt";

/// Entità dell'audit per le voci di questo modulo.
const AUDIT_ENTITY: &str = "dispositivo";
/// Azione registrata alla creazione.
const AUDIT_CREATED: &str = "identita_dispositivo_creata";
/// Azione registrata alla revoca.
const AUDIT_REVOKED: &str = "identita_dispositivo_revocata";
/// Azione registrata quando un Hub ammette questa postazione.
const AUDIT_ENROLLED: &str = "dispositivo_arruolato";

/// Percorso predefinito del file dell'identità.
///
/// Accanto agli altri file protetti, sotto la stessa cartella dati protetta dal
/// profilo.
///
/// # Errori
///
/// Restituisce un errore se la cartella dati locale non è determinabile.
pub fn default_device_path() -> ServiceResult<PathBuf> {
    let cartella =
        crate::data_directory::mode_directory().ok_or_else(|| ServiceError::DeviceIdentity {
            reason: String::from("cartella dati locale non determinabile"),
        })?;
    Ok(cartella.join(DEVICE_FILE))
}

/// Ciò che serve per chiedere l'arruolamento, tenuto insieme.
///
/// # Perché la richiesta e il sale viaggiano in coppia
///
/// Il sale è ciò con cui è stato derivato il gettone la cui impronta sta nella
/// richiesta. Separarli permetterebbe di conservarne uno e perdere l'altro, e un
/// dispositivo che perde il sale non sa più ricalcolare il proprio gettone: è
/// arruolato e non può presentarsi.
#[derive(Debug)]
pub struct PreparedEnrollment {
    /// Da consegnare all'Hub.
    pub request: EnrollmentRequest,
    /// Da conservare **se** l'Hub accetta.
    pub salt: EnrollmentSalt,
}

/// L'identità di dispositivo conservata su questa postazione.
#[derive(Debug)]
pub struct DeviceIdentityService {
    store: ProtectedStore,
}

impl DeviceIdentityService {
    /// Servizio sul file indicato.
    #[must_use]
    pub const fn at(store: ProtectedStore) -> Self {
        Self { store }
    }

    /// Servizio sul percorso predefinito.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se la cartella dati locale non è determinabile.
    pub fn default_location() -> ServiceResult<Self> {
        Ok(Self::at(ProtectedStore::at(default_device_path()?)))
    }

    /// Vero se questa postazione ha già un'identità.
    #[must_use]
    pub fn exists(&self) -> bool {
        self.store.exists()
    }

    /// Legge l'identità conservata.
    ///
    /// Una postazione senza il file **non ha** un'identità, e non è un errore:
    /// è una postazione che non ne ha ancora avuto bisogno. Un file presente e
    /// illeggibile, o incompleto, **è** un errore: interpretarlo come «nessuna
    /// identità» porterebbe a crearne una seconda accanto alla prima.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se il file esiste ma non è decifrabile con il
    /// profilo corrente, o se il contenuto non è interpretabile.
    pub fn load(&self) -> ServiceResult<Option<DeviceIdentity>> {
        if !self.store.exists() {
            return Ok(None);
        }

        let entries = self.store.load().map_err(map_security_error)?;
        let id = DeviceId::parse(campo(&entries, ID_KEY)?)?;
        let label = DisplayName::try_new(campo(&entries, LABEL_KEY)?)?;
        let created_at = istante(campo(&entries, CREATED_KEY)?)?;

        let mut identity = DeviceIdentity::new(id, label, created_at);

        // L'arruolamento prima del ritiro, e non e' indifferente: un
        // dispositivo puo' essere stato ammesso e poi ritirato, e il ritiro
        // deve prevalere. Nell'ordine opposto una postazione ritirata si
        // rileggerebbe come arruolata.
        if let Some(arruolato) = entries.get(ENROLLED_AT_KEY) {
            let hub = DisplayName::try_new(campo(&entries, HUB_KEY)?)?;
            identity.record_enrollment(hub, istante(arruolato)?)?;
        }
        if let Some(revocata) = entries.get(REVOKED_AT_KEY) {
            let reason = Note::try_new(campo(&entries, REVOKED_REASON_KEY)?)?;
            identity.revoke(istante(revocata)?, reason);
        }
        Ok(Some(identity))
    }

    /// Legge il segreto del dispositivo.
    ///
    /// È separato da [`Self::load`] apposta: leggere di quale dispositivo si
    /// tratta è un'operazione ordinaria, leggerne il segreto no. Chi scrive una
    /// schermata che mostra l'identità non deve avere il segreto in mano senza
    /// averlo chiesto.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se il file non esiste, non è decifrabile, o non
    /// contiene un segreto della lunghezza prevista.
    pub fn load_secret(&self) -> ServiceResult<DeviceSecret> {
        let entries = self.store.load().map_err(map_security_error)?;
        let byte = da_esadecimale(campo(&entries, SECRET_KEY)?)?;
        let byte: [u8; DEVICE_SECRET_BYTES] =
            byte.try_into().map_err(|_| ServiceError::DeviceIdentity {
                reason: String::from("il segreto del dispositivo non ha la lunghezza prevista"),
            })?;
        Ok(DeviceSecret::from_random_bytes(byte))
    }

    /// Crea l'identità di questo dispositivo.
    ///
    /// L'identificativo e il segreto nascono dal generatore crittografico del
    /// sistema. Nulla della macchina vi entra: né indirizzo MAC, né numero di
    /// serie, né impronta di Windows.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se un'identità esiste già, se il generatore
    /// crittografico rifiuta la richiesta, o se la scrittura protetta non
    /// riesce.
    pub fn create(
        &self,
        database: &Database,
        label: &DisplayName,
        operator: &OperatorId,
        now: Timestamp,
    ) -> ServiceResult<DeviceIdentity> {
        if self.store.exists() {
            return Err(ServiceError::DeviceIdentity {
                reason: String::from(
                    "questa postazione ha già un'identità di dispositivo: sostituirla \
                     richiede di revocare quella esistente",
                ),
            });
        }

        let mut byte_id = [0_u8; DEVICE_ID_BYTES];
        lisi_security::random_bytes(&mut byte_id).map_err(map_security_error)?;
        let mut byte_segreto = [0_u8; DEVICE_SECRET_BYTES];
        lisi_security::random_bytes(&mut byte_segreto).map_err(map_security_error)?;

        let identity =
            DeviceIdentity::new(DeviceId::from_random_bytes(&byte_id), label.clone(), now);

        let mut entries = BTreeMap::new();
        entries.insert(String::from(ID_KEY), identity.id.as_str().to_owned());
        entries.insert(String::from(SECRET_KEY), in_esadecimale(&byte_segreto));
        entries.insert(String::from(LABEL_KEY), label.as_str().to_owned());
        entries.insert(String::from(CREATED_KEY), now.as_millis().to_string());
        self.store.save(&entries).map_err(map_security_error)?;

        // L'audit registra l'identificativo pubblico e **non** il segreto:
        // l'audit documenta le azioni, non i dati su cui esse insistono.
        registra(
            database,
            operator,
            AUDIT_CREATED,
            &format!("dispositivo {}", identity.id),
            now,
        )?;

        Ok(identity)
    }

    /// Restituisce l'identità esistente, creandola se non c'è.
    ///
    /// # Errori
    ///
    /// Gli stessi di [`Self::load`] e [`Self::create`].
    pub fn ensure(
        &self,
        database: &Database,
        label: &DisplayName,
        operator: &OperatorId,
        now: Timestamp,
    ) -> ServiceResult<DeviceIdentity> {
        match self.load()? {
            Some(esistente) => Ok(esistente),
            None => self.create(database, label, operator, now),
        }
    }

    /// Registra il ritiro di questo dispositivo.
    ///
    /// # Che cosa questo non fa
    ///
    /// **Non impedisce a nessuno di usare il segreto.** Il segreto resta nel
    /// file, perché cancellarlo renderebbe impossibile spiegare in seguito quale
    /// dispositivo fosse stato ritirato, e perché chi ha accesso al profilo lo
    /// ha già letto comunque. La revoca che ferma davvero un dispositivo la
    /// applica l'Hub, e l'Hub non esiste ancora.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se non esiste un'identità da revocare, o se la
    /// scrittura protetta non riesce.
    pub fn revoke(
        &self,
        database: &Database,
        operator: &OperatorId,
        reason: &Note,
        now: Timestamp,
    ) -> ServiceResult<DeviceIdentity> {
        let Some(mut identity) = self.load()? else {
            return Err(ServiceError::DeviceIdentity {
                reason: String::from("questa postazione non ha un'identità di dispositivo"),
            });
        };
        if identity.is_revoked() {
            return Ok(identity);
        }

        let mut entries = self.store.load().map_err(map_security_error)?;
        entries.insert(String::from(REVOKED_AT_KEY), now.as_millis().to_string());
        entries.insert(String::from(REVOKED_REASON_KEY), reason.as_str().to_owned());
        self.store.save(&entries).map_err(map_security_error)?;

        registra(
            database,
            operator,
            AUDIT_REVOKED,
            &format!("dispositivo {}: {}", identity.id, reason.as_str()),
            now,
        )?;

        identity.revoke(now, reason.clone());
        Ok(identity)
    }

    /// Ciò che questa postazione presenta per essere arruolata.
    ///
    /// # Perché il sale esce di qui insieme alla richiesta
    ///
    /// Perché i due valori sono una coppia: il sale è ciò con cui il gettone
    /// consegnato all'Hub è stato derivato, e senza di esso il dispositivo non
    /// saprebbe più ricalcolarlo. Restituirli separatamente permetterebbe di
    /// conservarne uno e perdere l'altro.
    ///
    /// Il sale **non si conserva ora**: si conserva se e quando l'Hub accetta.
    /// Un sale scritto prima resterebbe su disco anche dopo un rifiuto,
    /// suggerendo un arruolamento che non è avvenuto.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se questa postazione non ha un'identità, se il
    /// generatore crittografico rifiuta la richiesta, o se il segreto non è
    /// leggibile.
    pub fn prepare_enrollment(&self, code: EnrollmentCode) -> ServiceResult<PreparedEnrollment> {
        let Some(identity) = self.load()? else {
            return Err(ServiceError::DeviceIdentity {
                reason: String::from(
                    "questa postazione non ha un'identità di dispositivo da arruolare",
                ),
            });
        };
        if identity.is_revoked() {
            return Err(ServiceError::DeviceIdentity {
                reason: String::from(
                    "questa identità è stata ritirata: per arruolare la postazione serve \
                     un'identità nuova",
                ),
            });
        }

        let mut byte = [0_u8; ENROLLMENT_SALT_BYTES];
        lisi_security::random_bytes(&mut byte).map_err(map_security_error)?;
        let salt = EnrollmentSalt::from_random_bytes(&byte);

        // Il gettone vive solo qui dentro: si deriva, se ne prende l'impronta, e
        // muore alla fine di questa funzione. Non c'e' alcun percorso che lo
        // scriva su disco, ed e' voluto — si ricalcola da cio' che c'e' gia'.
        let token = DeviceToken::derive(&salt, &self.load_secret()?);

        Ok(PreparedEnrollment {
            request: EnrollmentRequest {
                device_id: identity.id,
                label: identity.label,
                code,
                salt: salt.clone(),
                verifier: token.verifier(),
            },
            salt,
        })
    }

    /// Registra che un Hub ha ammesso questa postazione.
    ///
    /// # Perché un secondo Hub è un errore e non una sostituzione
    ///
    /// ADR-0042 si intitola «un'autorità sola», e questo è il punto in cui quel
    /// titolo diventa codice. Una postazione conserva **un** sale, perché il
    /// gettone si ricalcola da quello: registrare l'ammissione di un secondo Hub
    /// sovrascriverebbe il sale del primo, e la postazione perderebbe in
    /// silenzio la capacità di presentarsi là dove era già entrata.
    ///
    /// Sarebbe il peggiore dei guasti da diagnosticare: nulla fallisce adesso, e
    /// settimane dopo un Hub rifiuta un dispositivo che *lui* considera
    /// arruolato.
    ///
    /// Rifiutare non impedisce di cambiare Hub: impedisce di farlo **senza
    /// accorgersene**. Chi lo vuole revoca l'identità e ne crea una nuova, che si
    /// vede nell'audit.
    ///
    /// Registrare di nuovo lo **stesso** Hub è invece ammesso, e aggiorna il
    /// sale: succede quando l'Hub ha perso la propria riga e riammette la
    /// postazione.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se questa postazione non ha un'identità, se
    /// l'identità è stata ritirata, se risulta già arruolata presso un Hub
    /// **diverso**, o se la scrittura protetta non riesce.
    pub fn record_grant(
        &self,
        database: &Database,
        grant: &EnrollmentGrant,
        salt: &EnrollmentSalt,
        operator: &OperatorId,
    ) -> ServiceResult<DeviceIdentity> {
        let Some(mut identity) = self.load()? else {
            return Err(ServiceError::DeviceIdentity {
                reason: String::from("questa postazione non ha un'identità di dispositivo"),
            });
        };
        if let DeviceState::Enrolled { hub, .. } = &identity.state
            && hub != &grant.hub
        {
            return Err(ServiceError::DeviceIdentity {
                reason: format!(
                    "questa postazione è già arruolata presso l'Hub «{}». Per passare a un \
                     altro Hub occorre revocare questa identità e crearne una nuova: così il \
                     passaggio resta leggibile",
                    hub.as_str()
                ),
            });
        }
        identity.record_enrollment(grant.hub.clone(), grant.enrolled_at)?;

        let mut entries = self.store.load().map_err(map_security_error)?;
        entries.insert(String::from(HUB_KEY), grant.hub.as_str().to_owned());
        entries.insert(
            String::from(ENROLLED_AT_KEY),
            grant.enrolled_at.as_millis().to_string(),
        );
        entries.insert(String::from(SALT_KEY), salt.as_str().to_owned());
        self.store.save(&entries).map_err(map_security_error)?;

        registra(
            database,
            operator,
            AUDIT_ENROLLED,
            &format!(
                "dispositivo {} presso «{}»",
                identity.id,
                grant.hub.as_str()
            ),
            grant.enrolled_at,
        )?;

        Ok(identity)
    }

    /// Ricalcola il gettone con cui questa postazione si presenta al suo Hub.
    ///
    /// # Perché si ricalcola invece di essere letto
    ///
    /// Perché non è conservato. Il gettone si ottiene dal segreto — che sta
    /// sotto DPAPI — e dal sale, e tenerne una terza copia su disco
    /// aggiungerebbe qualcosa da proteggere senza aggiungere niente.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se la postazione non risulta arruolata, se il sale
    /// conservato non è leggibile, o se il segreto non è leggibile.
    pub fn token(&self) -> ServiceResult<DeviceToken> {
        let Some(identity) = self.load()? else {
            return Err(ServiceError::DeviceIdentity {
                reason: String::from("questa postazione non ha un'identità di dispositivo"),
            });
        };
        if !identity.is_enrolled() {
            return Err(ServiceError::DeviceIdentity {
                reason: String::from(
                    "questa postazione non è arruolata presso alcun Hub: non c'è gettone da \
                     presentare",
                ),
            });
        }

        let entries = self.store.load().map_err(map_security_error)?;
        let salt = EnrollmentSalt::parse(campo(&entries, SALT_KEY)?)?;
        Ok(DeviceToken::derive(&salt, &self.load_secret()?))
    }

    /// Che cosa mostrare all'operatore su questa postazione.
    ///
    /// # Errori
    ///
    /// Gli stessi di [`Self::load`].
    pub fn operator_message(&self) -> ServiceResult<String> {
        Ok(match self.load()? {
            None => String::from(
                "Questa postazione non ha ancora un'identità di dispositivo. Ne riceverà una \
                 quando servirà, e sarà un valore casuale: nulla della macchina vi entra.",
            ),
            Some(identity) => format!(
                "Dispositivo {} — «{}».\n{}",
                identity.id,
                identity.label.as_str(),
                identity.state.operator_message()
            ),
        })
    }
}

/// Legge un campo obbligatorio dal file protetto.
fn campo<'a>(entries: &'a BTreeMap<String, String>, chiave: &str) -> ServiceResult<&'a str> {
    entries
        .get(chiave)
        .map(String::as_str)
        .ok_or_else(|| ServiceError::DeviceIdentity {
            reason: String::from("l'identità di dispositivo conservata è incompleta"),
        })
}

/// Interpreta un istante conservato come millisecondi.
fn istante(raw: &str) -> ServiceResult<Timestamp> {
    let millis: i64 = raw.parse().map_err(|_| ServiceError::DeviceIdentity {
        reason: String::from("l'identità di dispositivo conservata ha una data illeggibile"),
    })?;
    Ok(Timestamp::from_millis(millis))
}

/// Rende i byte in esadecimale minuscolo.
fn in_esadecimale(byte: &[u8]) -> String {
    let mut testo = String::with_capacity(byte.len() * 2);
    for valore in byte {
        // Due cifre per byte, sempre: senza lo zero iniziale la stringa
        // cambierebbe lunghezza e non si potrebbe rileggere.
        testo.push(cifra_esadecimale(valore >> 4));
        testo.push(cifra_esadecimale(valore & 0x0F));
    }
    testo
}

/// Cifra esadecimale di un valore fra zero e quindici.
fn cifra_esadecimale(valore: u8) -> char {
    match valore {
        0..=9 => char::from(b'0' + valore),
        10..=15 => char::from(b'a' + valore - 10),
        // Il chiamante passa sempre un mezzo byte. La variante esiste per non
        // scrivere un unwrap su un'invariante che il tipo non esprime.
        _ => '0',
    }
}

/// Rilegge byte da una stringa esadecimale.
fn da_esadecimale(testo: &str) -> ServiceResult<Vec<u8>> {
    let cifre: Vec<u8> = testo.bytes().collect();
    if !cifre.len().is_multiple_of(2) {
        return Err(ServiceError::DeviceIdentity {
            reason: String::from("il segreto del dispositivo non è rileggibile"),
        });
    }

    let mut byte = Vec::with_capacity(cifre.len() / 2);
    for coppia in cifre.chunks_exact(2) {
        let alto = valore_esadecimale(coppia[0])?;
        let basso = valore_esadecimale(coppia[1])?;
        byte.push((alto << 4) | basso);
    }
    Ok(byte)
}

/// Valore di una cifra esadecimale.
fn valore_esadecimale(cifra: u8) -> ServiceResult<u8> {
    match cifra {
        b'0'..=b'9' => Ok(cifra - b'0'),
        b'a'..=b'f' => Ok(cifra - b'a' + 10),
        b'A'..=b'F' => Ok(cifra - b'A' + 10),
        _ => Err(ServiceError::DeviceIdentity {
            reason: String::from("il segreto del dispositivo non è rileggibile"),
        }),
    }
}

/// Scrive una voce di audit per un atto sull'identità di dispositivo.
fn registra(
    database: &Database,
    operator: &OperatorId,
    azione: &str,
    dettaglio: &str,
    now: Timestamp,
) -> ServiceResult<()> {
    let entry = NewAuditEntry {
        actor: operator.audit_actor()?,
        action: AuditAction::try_new(azione)?,
        entity: AuditEntity::try_new(AUDIT_ENTITY)?,
        entity_id: None,
        actor_mode: None,
        detail: Some(AuditDetail::try_new(dettaglio)?),
        recorded_at: now,
    };
    database.append_audit(&entry)?;
    Ok(())
}

/// Traduce un errore di `lisi-security` in uno di servizio.
fn map_security_error(error: SecurityError) -> ServiceError {
    ServiceError::DeviceIdentity {
        reason: String::from(error.operator_message()),
    }
}

#[cfg(test)]
mod tests {
    use lisi_core::Timestamp;
    use lisi_core::model::identity::{DEVICE_SECRET_BYTES, OperatorId};
    use lisi_core::text::{DisplayName, Note};
    use lisi_security::ProtectedStore;

    use super::{DeviceIdentityService, in_esadecimale};
    use crate::Database;

    /// Il sorgente di questo modulo, letto a tempo di compilazione.
    const SORGENTE_SERVIZIO: &str = include_str!("device_identity.rs");
    /// Il sorgente del dominio dell'identita', letto a tempo di compilazione.
    const SORGENTE_DOMINIO: &str = include_str!("../../lisi-core/src/model/identity.rs");
    /// Il sorgente del dominio dell'arruolamento.
    const SORGENTE_ARRUOLAMENTO: &str = include_str!("../../lisi-core/src/model/enrollment.rs");
    /// Il sorgente dell'autorita' di arruolamento.
    const SORGENTE_HUB: &str = include_str!("hub_enrollment.rs");

    fn istante() -> Timestamp {
        Timestamp::from_millis(1_756_000_000_000)
    }

    fn archivio() -> Database {
        let Ok(database) = crate::sources::open_in_memory_database() else {
            panic!("l'archivio di prova deve potersi aprire");
        };
        database
    }

    fn servizio() -> (DeviceIdentityService, tempfile::TempDir) {
        let Ok(cartella) = tempfile::tempdir() else {
            panic!("la cartella temporanea deve potersi creare");
        };
        let percorso = cartella.path().join(super::DEVICE_FILE);
        (
            DeviceIdentityService::at(ProtectedStore::at(percorso)),
            cartella,
        )
    }

    fn nome(testo: &str) -> DisplayName {
        let Ok(valore) = DisplayName::try_new(testo) else {
            panic!("il nome di prova deve essere valido");
        };
        valore
    }

    fn nota(testo: &str) -> Note {
        let Ok(valore) = Note::try_new(testo) else {
            panic!("la nota di prova deve essere valida");
        };
        valore
    }

    // -----------------------------------------------------------------
    // Ciclo di vita
    // -----------------------------------------------------------------

    /// **Una postazione nuova non ha un'identita', e non e' un errore.**
    #[test]
    fn una_postazione_nuova_non_ha_identita() {
        let (servizio, _cartella) = servizio();
        assert!(!servizio.exists());
        let Ok(nessuna) = servizio.load() else {
            panic!("la lettura di una postazione nuova non deve fallire");
        };
        assert!(nessuna.is_none());

        let Ok(messaggio) = servizio.operator_message() else {
            panic!("il messaggio deve potersi comporre");
        };
        assert!(
            messaggio.contains("non ha ancora un'identità"),
            "il messaggio non dichiara l'assenza: «{messaggio}»"
        );
    }

    /// **L'identita' creata si rilegge identica, segreto compreso.**
    #[cfg(windows)]
    #[test]
    fn l_identita_creata_si_rilegge_uguale() {
        let (servizio, _cartella) = servizio();
        let archivio = archivio();

        let Ok(creata) = servizio.create(
            &archivio,
            &nome("Postazione 1"),
            &OperatorId::local(),
            istante(),
        ) else {
            panic!("la creazione deve riuscire");
        };
        let Ok(segreto_creato) = servizio.load_secret() else {
            panic!("il segreto deve potersi rileggere");
        };

        let Ok(Some(riletta)) = servizio.load() else {
            panic!("l'identita' appena creata deve rileggersi");
        };
        assert_eq!(riletta, creata);
        assert!(!riletta.is_revoked());

        let Ok(segreto_riletto) = servizio.load_secret() else {
            panic!("il segreto deve potersi rileggere due volte");
        };
        assert_eq!(segreto_creato, segreto_riletto);
    }

    /// **Due identita' create sulla stessa macchina sono diverse.**
    ///
    /// # Il difetto che questa prova impedisce
    ///
    /// E' la verifica sperimentale che l'identita' NON sia derivata dalla
    /// macchina. Se lo fosse — dall'indirizzo MAC, dal numero di serie del
    /// volume, dall'identificativo di installazione di Windows — due creazioni
    /// sulla stessa macchina darebbero lo stesso valore, e la parola «revoca»
    /// perderebbe significato: non si potrebbe sostituire un'identita' ritirata
    /// senza sostituire la macchina.
    #[cfg(windows)]
    #[test]
    fn due_identita_sulla_stessa_macchina_sono_diverse() {
        let archivio = archivio();
        let (primo, _a) = servizio();
        let (secondo, _b) = servizio();

        let Ok(uno) = primo.create(&archivio, &nome("A"), &OperatorId::local(), istante()) else {
            panic!("la prima creazione deve riuscire");
        };
        let Ok(due) = secondo.create(&archivio, &nome("B"), &OperatorId::local(), istante()) else {
            panic!("la seconda creazione deve riuscire");
        };

        assert_ne!(
            uno.id, due.id,
            "due identita' create sulla stessa macchina coincidono: l'identificativo \
             non e' casuale ma deriva dalla macchina"
        );

        let (Ok(segreto_uno), Ok(segreto_due)) = (primo.load_secret(), secondo.load_secret())
        else {
            panic!("entrambi i segreti devono potersi leggere");
        };
        assert_ne!(
            segreto_uno, segreto_due,
            "due segreti creati sulla stessa macchina coincidono"
        );
    }

    /// **Creare due volte non sovrascrive l'identita' esistente.**
    ///
    /// # Il difetto che questa prova impedisce
    ///
    /// Una seconda creazione silenziosa produrrebbe un dispositivo nuovo che
    /// eredita il posto del precedente: l'audit continuerebbe a nominare il
    /// vecchio identificativo, e nessuno saprebbe che la macchina ne ha ora un
    /// altro.
    #[cfg(windows)]
    #[test]
    fn creare_due_volte_non_sovrascrive_l_identita() {
        let (servizio, _cartella) = servizio();
        let archivio = archivio();

        let Ok(prima) = servizio.create(&archivio, &nome("A"), &OperatorId::local(), istante())
        else {
            panic!("la prima creazione deve riuscire");
        };
        let Ok(segreto_prima) = servizio.load_secret() else {
            panic!("il segreto deve potersi leggere");
        };

        assert!(
            servizio
                .create(&archivio, &nome("B"), &OperatorId::local(), istante())
                .is_err(),
            "la seconda creazione e' stata accettata"
        );

        let Ok(Some(ancora)) = servizio.load() else {
            panic!("l'identita' deve essere ancora leggibile");
        };
        assert_eq!(ancora, prima, "l'identita' e' stata sostituita");
        let Ok(segreto_dopo) = servizio.load_secret() else {
            panic!("il segreto deve potersi rileggere");
        };
        assert_eq!(
            segreto_prima, segreto_dopo,
            "il segreto e' stato sostituito"
        );
    }

    /// **`ensure` non crea una seconda identita'.**
    #[cfg(windows)]
    #[test]
    fn ensure_restituisce_quella_che_c_e_gia() {
        let (servizio, _cartella) = servizio();
        let archivio = archivio();

        let Ok(prima) = servizio.ensure(&archivio, &nome("A"), &OperatorId::local(), istante())
        else {
            panic!("la prima chiamata deve creare");
        };
        let Ok(seconda) = servizio.ensure(&archivio, &nome("B"), &OperatorId::local(), istante())
        else {
            panic!("la seconda chiamata deve restituire quella esistente");
        };
        assert_eq!(prima, seconda);
        assert_eq!(seconda.label.as_str(), "A", "il nome e' stato riscritto");
    }

    /// **La revoca si registra, si rilegge, e conserva la prima ragione.**
    #[cfg(windows)]
    #[test]
    fn la_revoca_si_registra_e_conserva_la_prima_ragione() {
        let (servizio, _cartella) = servizio();
        let archivio = archivio();
        let Ok(_) = servizio.create(&archivio, &nome("A"), &OperatorId::local(), istante()) else {
            panic!("la creazione deve riuscire");
        };

        let Ok(revocata) = servizio.revoke(
            &archivio,
            &OperatorId::local(),
            &nota("portatile smarrito"),
            istante(),
        ) else {
            panic!("la revoca deve riuscire");
        };
        assert!(revocata.is_revoked());

        let Ok(_) = servizio.revoke(
            &archivio,
            &OperatorId::local(),
            &nota("ragione seconda"),
            istante(),
        ) else {
            panic!("la seconda revoca non deve fallire");
        };

        let Ok(Some(riletta)) = servizio.load() else {
            panic!("l'identita' revocata deve rileggersi");
        };
        assert!(riletta.is_revoked());
        let messaggio = riletta.state.operator_message();
        assert!(
            messaggio.contains("portatile smarrito"),
            "la prima ragione e' andata persa: «{messaggio}»"
        );
    }

    /// **Revocare cio' che non esiste e' un errore, non un successo silenzioso.**
    #[test]
    fn revocare_senza_identita_e_un_errore() {
        let (servizio, _cartella) = servizio();
        assert!(
            servizio
                .revoke(
                    &archivio(),
                    &OperatorId::local(),
                    &nota("qualunque"),
                    istante()
                )
                .is_err()
        );
    }

    // -----------------------------------------------------------------
    // Il segreto non esce
    // -----------------------------------------------------------------

    /// **L'audit registra l'identificativo pubblico e mai il segreto.**
    ///
    /// # Il difetto che questa prova impedisce
    ///
    /// Il dettaglio di una voce di audit e' una stringa composta a mano.
    /// Scriverci dentro il segreto «per poterlo ritrovare» lo depositerebbe in
    /// chiaro nell'archivio, che finisce nei backup, negli export e nei
    /// pacchetti diagnostici.
    #[cfg(windows)]
    #[test]
    fn l_audit_nomina_il_dispositivo_e_mai_il_suo_segreto() {
        let (servizio, _cartella) = servizio();
        let archivio = archivio();
        let Ok(identita) = servizio.create(&archivio, &nome("A"), &OperatorId::local(), istante())
        else {
            panic!("la creazione deve riuscire");
        };
        let Ok(_) = servizio.revoke(
            &archivio,
            &OperatorId::local(),
            &nota("sostituito"),
            istante(),
        ) else {
            panic!("la revoca deve riuscire");
        };

        let Ok(segreto) = servizio.load_secret() else {
            panic!("il segreto deve potersi leggere");
        };
        let in_chiaro = in_esadecimale(segreto.expose());

        let Ok(voci) = archivio.audit_entries() else {
            panic!("l'audit deve potersi leggere");
        };
        let righe: Vec<String> = voci
            .iter()
            .map(|voce| {
                format!(
                    "{}|{}|{}|{}",
                    voce.actor.as_str(),
                    voce.action.as_str(),
                    voce.entity.as_str(),
                    voce.detail
                        .as_ref()
                        .map_or("", lisi_core::text::AuditDetail::as_str)
                )
            })
            .collect();

        assert!(
            righe.iter().any(|riga| riga.contains("creata")),
            "la creazione non e' stata registrata: {righe:?}"
        );
        assert!(
            righe.iter().any(|riga| riga.contains("revocata")),
            "la revoca non e' stata registrata: {righe:?}"
        );
        assert!(
            righe.iter().any(|riga| riga.contains(identita.id.as_str())),
            "l'audit non nomina il dispositivo: {righe:?}"
        );

        for riga in &righe {
            assert!(
                !riga.contains(&in_chiaro),
                "una voce di audit contiene il segreto del dispositivo"
            );
            // Anche un frammento basterebbe a ridurre lo spazio da provare.
            for pezzo in in_chiaro.as_bytes().chunks(8) {
                let Ok(frammento) = core::str::from_utf8(pezzo) else {
                    continue;
                };
                assert!(
                    !riga.contains(frammento),
                    "una voce di audit contiene un frammento del segreto"
                );
            }
        }
    }

    /// **Il segreto non giace in chiaro nel file.**
    ///
    /// E' cio' che DPAPI deve fare, e va verificato invece che presunto: un
    /// giorno qualcuno potrebbe scrivere il file senza passare da
    /// `ProtectedStore`, e nessun'altra prova se ne accorgerebbe.
    #[cfg(windows)]
    #[test]
    fn il_segreto_non_giace_in_chiaro_nel_file() {
        let Ok(cartella) = tempfile::tempdir() else {
            panic!("la cartella temporanea deve potersi creare");
        };
        let percorso = cartella.path().join(super::DEVICE_FILE);
        let servizio = DeviceIdentityService::at(ProtectedStore::at(percorso.clone()));
        let archivio = archivio();
        let Ok(identita) = servizio.create(&archivio, &nome("A"), &OperatorId::local(), istante())
        else {
            panic!("la creazione deve riuscire");
        };
        let Ok(segreto) = servizio.load_secret() else {
            panic!("il segreto deve potersi leggere");
        };

        let Ok(byte) = std::fs::read(&percorso) else {
            panic!("il file protetto deve potersi leggere");
        };
        let contenuto = String::from_utf8_lossy(&byte).into_owned();

        assert!(
            !contenuto.contains(&in_esadecimale(segreto.expose())),
            "il segreto e' scritto in chiaro nel file"
        );
        assert!(
            !contenuto.contains(identita.id.as_str()),
            "l'identificativo e' scritto in chiaro nel file"
        );
        assert!(
            byte.windows(DEVICE_SECRET_BYTES)
                .all(|finestra| finestra != segreto.expose().as_slice()),
            "i byte grezzi del segreto compaiono nel file"
        );
    }

    // -----------------------------------------------------------------
    // Nessuna impronta della macchina
    // -----------------------------------------------------------------

    // -----------------------------------------------------------------
    // Arruolamento, dal lato della postazione
    // -----------------------------------------------------------------

    /// Un Hub di prova sul proprio archivio.
    #[cfg(windows)]
    fn autorita() -> crate::hub_enrollment::HubEnrollmentService {
        crate::hub_enrollment::HubEnrollmentService::new(archivio(), nome("Hub della centrale"))
    }

    /// **La postazione entra, registra, e ricalcola il proprio gettone.**
    ///
    /// # Che cosa questa prova verifica davvero
    ///
    /// Non che l'arruolamento «funzioni»: che il gettone **ricalcolato dopo**
    /// coincida con quello la cui impronta l'Hub ha conservato. E' l'unica cosa
    /// che rende il gettone utilizzabile domani, ed e' anche la piu' facile da
    /// rompere senza accorgersene — basta conservare un sale diverso da quello
    /// con cui la derivazione e' stata fatta.
    #[cfg(windows)]
    #[test]
    fn la_postazione_entra_e_sa_ricalcolare_il_proprio_gettone() {
        use lisi_core::model::enrollment::EnrollmentCode;

        let (servizio, _cartella) = servizio();
        let archivio_locale = archivio();
        let Ok(_) = servizio.create(
            &archivio_locale,
            &nome("Postazione 1"),
            &OperatorId::local(),
            istante(),
        ) else {
            panic!("la creazione deve riuscire");
        };

        let mut hub = autorita();
        let Ok(emesso) = hub.issue_code(&OperatorId::local(), istante()) else {
            panic!("l'emissione deve riuscire");
        };
        let Ok(codice) = EnrollmentCode::parse(emesso.code.reveal_to_administrator()) else {
            panic!("il codice deve potersi ridigitare");
        };

        let Ok(preparata) = servizio.prepare_enrollment(codice) else {
            panic!("la richiesta deve potersi preparare");
        };
        let impronta_consegnata = preparata.request.verifier.clone();

        let Ok(esito) = hub.admit(&preparata.request, istante()) else {
            panic!("l'ammissione deve produrre un esito");
        };
        let crate::hub_enrollment::EnrollmentOutcome::Admitted(grant) = esito else {
            panic!("il dispositivo doveva entrare: {esito:?}");
        };

        let Ok(arruolata) = servizio.record_grant(
            &archivio_locale,
            &grant,
            &preparata.salt,
            &OperatorId::local(),
        ) else {
            panic!("l'ammissione deve potersi registrare");
        };
        assert!(arruolata.is_enrolled());

        // Il gettone ricalcolato da zero, dopo, dal solo file protetto.
        let Ok(gettone) = servizio.token() else {
            panic!("il gettone deve potersi ricalcolare");
        };
        assert_eq!(
            gettone.verifier(),
            impronta_consegnata,
            "il gettone ricalcolato non coincide con quello consegnato all'Hub: la \
             postazione e' arruolata e non potrebbe presentarsi"
        );

        // E la postazione dice dove e' entrata, senza promettere di piu'.
        let Ok(messaggio) = servizio.operator_message() else {
            panic!("il messaggio deve potersi comporre");
        };
        assert!(
            messaggio.contains("Hub della centrale"),
            "il messaggio non dice presso quale Hub: «{messaggio}»"
        );
        assert!(
            messaggio.contains("se l'Hub l'ha ritirato"),
            "il messaggio promette un riconoscimento attuale: «{messaggio}»"
        );
    }

    /// **Una postazione non arruolata non ha un gettone da presentare.**
    ///
    /// Restituire un valore qualunque sarebbe peggio di un errore: la postazione
    /// si presenterebbe con una credenziale che nessun Hub riconosce, e il
    /// rifiuto arriverebbe dall'altra parte senza spiegare che il problema e'
    /// qui.
    #[cfg(windows)]
    #[test]
    fn una_postazione_non_arruolata_non_ha_gettone() {
        let (servizio, _cartella) = servizio();
        assert!(servizio.token().is_err(), "senza identita' c'e' un gettone");

        let Ok(_) = servizio.create(&archivio(), &nome("A"), &OperatorId::local(), istante())
        else {
            panic!("la creazione deve riuscire");
        };
        assert!(
            servizio.token().is_err(),
            "una postazione creata e non arruolata ha gia' un gettone"
        );
    }

    /// **Un rifiuto non lascia sul disco un sale che suggerisce un arruolamento.**
    ///
    /// # Il difetto che questa prova impedisce
    ///
    /// Se `prepare_enrollment` conservasse il sale, un tentativo rifiutato
    /// lascerebbe su disco meta' di un arruolamento. Non basterebbe a far
    /// funzionare nulla, ma basterebbe a confondere chi legge il file mesi dopo.
    #[cfg(windows)]
    #[test]
    fn una_richiesta_preparata_non_scrive_nulla() {
        use lisi_core::model::enrollment::EnrollmentCode;

        let (servizio, _cartella) = servizio();
        let Ok(_) = servizio.create(&archivio(), &nome("A"), &OperatorId::local(), istante())
        else {
            panic!("la creazione deve riuscire");
        };

        let codice = EnrollmentCode::from_random_bytes(&[0x3C; 10]);
        let Ok(_preparata) = servizio.prepare_enrollment(codice) else {
            panic!("la richiesta deve potersi preparare");
        };

        let Ok(Some(identita)) = servizio.load() else {
            panic!("l'identita' deve rileggersi");
        };
        assert!(
            !identita.is_enrolled(),
            "preparare una richiesta ha registrato un arruolamento"
        );
        assert!(
            servizio.token().is_err(),
            "preparare una richiesta ha lasciato un sale su disco"
        );
    }

    /// **Un'identita' ritirata non si arruola.**
    #[cfg(windows)]
    #[test]
    fn un_identita_ritirata_non_si_arruola() {
        use lisi_core::model::enrollment::EnrollmentCode;

        let (servizio, _cartella) = servizio();
        let archivio_locale = archivio();
        let Ok(_) = servizio.create(
            &archivio_locale,
            &nome("A"),
            &OperatorId::local(),
            istante(),
        ) else {
            panic!("la creazione deve riuscire");
        };
        let Ok(_) = servizio.revoke(
            &archivio_locale,
            &OperatorId::local(),
            &nota("sostituita"),
            istante(),
        ) else {
            panic!("il ritiro deve riuscire");
        };

        assert!(
            servizio
                .prepare_enrollment(EnrollmentCode::from_random_bytes(&[0x4D; 10]))
                .is_err(),
            "un'identita' ritirata ha preparato una richiesta di arruolamento"
        );
    }

    /// **Un errore dell'identita' spiega se stesso, e non manda altrove.**
    ///
    /// # Il difetto che questa prova impedisce, e che c'era davvero
    ///
    /// Tutti gli errori di questo modulo usavano `SessionUnavailable`, la cui
    /// frase per l'operatore e' «I dati dell'accesso non sono leggibili. Usare
    /// "Ripristina accesso"». E' il consiglio giusto per la sessione Telegram e
    /// **il consiglio sbagliato per tutto il resto**: chi non riesce ad
    /// arruolare la postazione finirebbe per rifare l'accesso a Telegram, che
    /// non c'entra e che costa un codice via SMS.
    ///
    /// La ragione scritta nel codice non arrivava a nessuno. Se ne e' accorta
    /// una prova che cercava nel messaggio il nome dell'Hub e trovava un consiglio
    /// su Telegram.
    #[cfg(windows)]
    #[test]
    fn un_errore_dell_identita_spiega_se_stesso() {
        let (servizio, _cartella) = servizio();

        // Una postazione senza identita' che prova ad arruolarsi.
        let Err(errore) = servizio.prepare_enrollment(
            lisi_core::model::enrollment::EnrollmentCode::from_random_bytes(&[0x9C; 10]),
        ) else {
            panic!("senza identita' l'arruolamento deve fallire");
        };

        let messaggio = errore.operator_message();
        assert!(
            messaggio.contains("identità di dispositivo"),
            "il messaggio non dice qual e' il problema: «{messaggio}»"
        );
        assert!(
            !messaggio.contains("Ripristina accesso"),
            "il messaggio manda l'operatore a rifare l'accesso a Telegram, che non \
             c'entra: «{messaggio}»"
        );
        assert_eq!(errore.kind(), "identita_dispositivo");
    }

    /// **Un secondo Hub non sovrascrive in silenzio il primo.**
    ///
    /// # Il difetto che questa prova impedisce
    ///
    /// La postazione conserva **un** sale, perche' il gettone si ricalcola da
    /// quello. Registrare l'ammissione di un secondo Hub sovrascriverebbe il
    /// sale del primo, e la postazione perderebbe **in silenzio** la capacita' di
    /// presentarsi la' dove era gia' entrata.
    ///
    /// Sarebbe il peggiore dei guasti da diagnosticare: nulla fallisce adesso, e
    /// settimane dopo un Hub rifiuta un dispositivo che *lui* considera
    /// arruolato.
    ///
    /// ADR-0042 si intitola «un'autorita' sola», e questa e' la riga in cui quel
    /// titolo diventa codice.
    #[cfg(windows)]
    #[test]
    fn un_secondo_hub_non_sovrascrive_in_silenzio_il_primo() {
        use lisi_core::model::enrollment::{EnrollmentGrant, EnrollmentSalt};

        let (servizio, _cartella) = servizio();
        let archivio_locale = archivio();
        let Ok(_) = servizio.create(
            &archivio_locale,
            &nome("A"),
            &OperatorId::local(),
            istante(),
        ) else {
            panic!("la creazione deve riuscire");
        };

        let primo_sale = EnrollmentSalt::from_random_bytes(&[0x6F; 16]);
        let Ok(_) = servizio.record_grant(
            &archivio_locale,
            &EnrollmentGrant {
                hub: nome("Hub della centrale"),
                enrolled_at: istante(),
            },
            &primo_sale,
            &OperatorId::local(),
        ) else {
            panic!("il primo arruolamento deve riuscire");
        };
        let Ok(primo_gettone) = servizio.token() else {
            panic!("il gettone deve potersi ricalcolare");
        };

        // Un secondo Hub e' un errore, e l'errore dice quale sia il primo.
        let esito = servizio.record_grant(
            &archivio_locale,
            &EnrollmentGrant {
                hub: nome("Hub del distaccamento"),
                enrolled_at: istante(),
            },
            &EnrollmentSalt::from_random_bytes(&[0x7A; 16]),
            &OperatorId::local(),
        );
        let Err(errore) = esito else {
            panic!("il secondo Hub e' stato registrato al posto del primo");
        };
        let messaggio = errore.operator_message();
        assert!(
            messaggio.contains("Hub della centrale"),
            "l'errore non dice presso quale Hub la postazione e' gia' arruolata: \
             «{messaggio}»"
        );

        // E il primo arruolamento e' intatto: stesso Hub, stesso gettone.
        let Ok(Some(riletta)) = servizio.load() else {
            panic!("l'identita' deve rileggersi");
        };
        assert!(riletta.is_enrolled());
        assert!(
            riletta
                .state
                .operator_message()
                .contains("Hub della centrale"),
            "il primo Hub e' stato perso"
        );
        let Ok(ancora) = servizio.token() else {
            panic!("il gettone deve potersi ricalcolare");
        };
        assert_eq!(
            ancora.verifier(),
            primo_gettone.verifier(),
            "il sale del primo Hub e' stato sovrascritto: la postazione non sa piu' \
             presentarsi dove era entrata"
        );

        // Registrare di nuovo lo STESSO Hub e' ammesso: succede quando l'Hub ha
        // perso la propria riga e riammette la postazione.
        let nuovo_sale = EnrollmentSalt::from_random_bytes(&[0x8B; 16]);
        let Ok(_) = servizio.record_grant(
            &archivio_locale,
            &EnrollmentGrant {
                hub: nome("Hub della centrale"),
                enrolled_at: istante(),
            },
            &nuovo_sale,
            &OperatorId::local(),
        ) else {
            panic!("riarruolarsi allo stesso Hub deve riuscire");
        };
        let Ok(aggiornato) = servizio.token() else {
            panic!("il gettone deve potersi ricalcolare");
        };
        assert_ne!(
            aggiornato.verifier(),
            primo_gettone.verifier(),
            "il sale non e' stato aggiornato dal riarruolamento"
        );
    }

    /// **Un ritiro locale prevale su un arruolamento precedente.**
    ///
    /// # Il difetto che questa prova impedisce
    ///
    /// Il file protetto conserva entrambi i fatti: che la postazione e' stata
    /// ammessa e che poi e' stata ritirata. Rileggendoli nell'ordine sbagliato,
    /// una postazione ritirata si rileggerebbe come arruolata, e continuerebbe a
    /// presentarsi.
    #[cfg(windows)]
    #[test]
    fn un_ritiro_locale_prevale_sull_arruolamento() {
        use lisi_core::model::enrollment::{EnrollmentGrant, EnrollmentSalt};

        let (servizio, _cartella) = servizio();
        let archivio_locale = archivio();
        let Ok(_) = servizio.create(
            &archivio_locale,
            &nome("A"),
            &OperatorId::local(),
            istante(),
        ) else {
            panic!("la creazione deve riuscire");
        };

        let grant = EnrollmentGrant {
            hub: nome("Hub della centrale"),
            enrolled_at: istante(),
        };
        let salt = EnrollmentSalt::from_random_bytes(&[0x5E; 16]);
        let Ok(arruolata) =
            servizio.record_grant(&archivio_locale, &grant, &salt, &OperatorId::local())
        else {
            panic!("l'ammissione deve potersi registrare");
        };
        assert!(arruolata.is_enrolled());

        let Ok(_) = servizio.revoke(
            &archivio_locale,
            &OperatorId::local(),
            &nota("portatile smarrito"),
            istante(),
        ) else {
            panic!("il ritiro deve riuscire");
        };

        let Ok(Some(riletta)) = servizio.load() else {
            panic!("l'identita' deve rileggersi");
        };
        assert!(
            riletta.is_revoked(),
            "il ritiro e' stato perso alla rilettura"
        );
        assert!(
            !riletta.is_enrolled(),
            "una postazione ritirata si rilegge come arruolata"
        );
    }

    /// Parte di prodotto di un sorgente: senza commenti e senza il modulo di prova.
    ///
    /// Il taglio e' quello gia' usato dalla guardia degli accenti, e con la
    /// stessa correzione: la riga deve **cominciare** con l'attributo, perche'
    /// un `#[cfg(test)]` citato in un commento nascondeva mezzo file.
    fn parte_di_prodotto(sorgente: &str) -> String {
        sorgente
            .lines()
            .take_while(|riga| !riga.trim_start().starts_with("#[cfg(test)]"))
            .filter(|riga| !riga.trim_start().starts_with("//"))
            .collect::<Vec<_>>()
            .join("\n")
    }

    /// **Nessuna impronta della macchina entra nell'identita'.**
    ///
    /// # Perche' questa prova esiste
    ///
    /// La prova sperimentale — due identita' diverse sulla stessa macchina —
    /// dimostra che oggi non c'e' derivazione. Non impedisce a nessuno di
    /// aggiungerne una domani «per riconoscere il dispositivo dopo una
    /// reinstallazione», che e' esattamente il modo in cui un identificativo
    /// revocabile smette di esserlo.
    ///
    /// La lista e' di nomi di API e di valori di sistema, non di parole: e' il
    /// codice che viene guardato, non i commenti, perche' i commenti dicono
    /// **proprio** che queste cose non si usano.
    #[test]
    fn nessuna_impronta_della_macchina_entra_nell_identita() {
        // I nomi vietati, spezzati per non far trovare a questa prova se' stessa
        // nel proprio sorgente: e' il modo in cui una guardia diventa verde per
        // la ragione sbagliata.
        let vietati: Vec<String> = [
            ["GetAdapters", "Info"],
            ["GetAdapters", "Addresses"],
            ["Machine", "Guid"],
            ["GetVolume", "Information"],
            ["GetSystemFirmware", "Table"],
            ["Win32_ComputerSystem", "Product"],
            ["UuidCreate", "Sequential"],
            ["GetCurrentHw", "Profile"],
            ["COMPUTER", "NAME"],
            ["SM", "BIOS"],
            ["cs", "product"],
            ["wm", "ic"],
        ]
        .iter()
        .map(|pezzi| pezzi.concat())
        .collect();

        for (nome_file, sorgente) in [
            ("lisi-services/device_identity.rs", SORGENTE_SERVIZIO),
            ("lisi-core/model/identity.rs", SORGENTE_DOMINIO),
            // HUB-03 ha aggiunto due file che generano valori casuali destinati
            // a identificare o ad autorizzare. La tentazione di legarli alla
            // macchina e' la stessa, e la guardia deve arrivarci.
            ("lisi-core/model/enrollment.rs", SORGENTE_ARRUOLAMENTO),
            ("lisi-services/hub_enrollment.rs", SORGENTE_HUB),
        ] {
            let codice = parte_di_prodotto(sorgente);
            for vietato in &vietati {
                assert!(
                    !codice.contains(vietato.as_str()),
                    "{nome_file} legge «{vietato}»: un'identita' derivata dalla macchina \
                     non si puo' revocare, perche' revocarla richiederebbe di cambiare \
                     la macchina"
                );
            }
        }
    }

    /// **I byte dell'identita' vengono dal generatore del sistema.**
    ///
    /// L'altra meta' della guardia precedente: quella dice da dove i byte non
    /// vengono, questa dice da dove vengono. Senza, sostituire il generatore con
    /// un contatore non romperebbe nulla.
    #[test]
    fn il_caso_viene_dal_generatore_crittografico_del_sistema() {
        for (nome_file, sorgente) in [
            ("lisi-services/device_identity.rs", SORGENTE_SERVIZIO),
            // L'Hub genera i codici di arruolamento, che sono autorizzazioni:
            // un codice prevedibile non e' un'autorizzazione.
            ("lisi-services/hub_enrollment.rs", SORGENTE_HUB),
        ] {
            let codice = parte_di_prodotto(sorgente);
            assert!(
                codice.contains("lisi_security::random_bytes"),
                "{nome_file} non usa piu' il generatore crittografico del sistema"
            );
        }
    }
}
