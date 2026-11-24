//! Le reti dell'ufficio della postazione, conservate (HUB-SITES-01, ADR-0198).
//!
//! # Dove stanno
//!
//! In un file protetto accanto alla configurazione dell'Hub, come l'indirizzo
//! di ascolto: valgono per la postazione e non sono un dato dell'archivio. Un
//! file assente vuol dire «nessuna dichiarazione»: valgono gli intervalli che
//! Internet non instrada.
//!
//! # Chi le dichiara
//!
//! Chi amministra la postazione: è l'ottava azione riservata,
//! [`RestrictedAction::ChooseOfficeNetworks`], e la dichiarazione resta nel
//! registro delle operazioni con l'elenco intero.

use std::collections::BTreeMap;
use std::net::IpAddr;
use std::path::Path;

use lisi_core::Timestamp;
use lisi_core::error::DomainError;
use lisi_core::model::NewAuditEntry;
use lisi_core::model::identity::OperatorId;
use lisi_core::model::office_network::OfficeNetworks;
use lisi_core::role::{OperatingMode, RestrictedAction};
use lisi_core::text::{AuditAction, AuditDetail, AuditEntity};
use lisi_security::ProtectedStore;

use crate::Database;
use crate::error::{ServiceError, ServiceResult};

/// Il file delle reti dell'ufficio.
pub const OFFICE_NETWORKS_FILE: &str = "reti-ufficio.protetto";

const NETWORKS_KEY: &str = "reti_ufficio";

const AUDIT_ACTION: &str = "reti_ufficio_dichiarate";
const AUDIT_ENTITY: &str = "postazione";

/// Le reti dell'ufficio di questa postazione, conservate.
#[derive(Debug)]
pub struct OfficeNetworksStore {
    store: ProtectedStore,
}

impl OfficeNetworksStore {
    /// Archivio sul file indicato.
    #[must_use]
    pub const fn at(store: ProtectedStore) -> Self {
        Self { store }
    }

    /// Archivio nella cartella indicata, accanto agli altri file protetti.
    #[must_use]
    pub fn in_directory(base: &Path) -> Self {
        Self::at(ProtectedStore::at(base.join(OFFICE_NETWORKS_FILE)))
    }

    /// Archivio sul percorso predefinito della postazione, accanto alla
    /// configurazione dell'Hub.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se la cartella dei dati non è determinabile.
    pub fn default_location() -> ServiceResult<Self> {
        let cartella =
            crate::data_directory::mode_directory().ok_or_else(|| ServiceError::HubServer {
                reason: String::from("cartella dati locale non determinabile"),
            })?;
        Ok(Self::in_directory(&cartella))
    }

    /// Le reti in vigore: le predefinite, più quelle dichiarate se ce ne sono.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se il file esiste ma non si legge o non contiene
    /// reti utilizzabili: una dichiarazione illeggibile non vale come nessuna
    /// dichiarazione, perché toglierebbe in silenzio ciò che l'ufficio ha
    /// deciso.
    pub fn load(&self) -> ServiceResult<OfficeNetworks> {
        if !self.store.exists() {
            return Ok(OfficeNetworks::default());
        }
        let voci = self.store.load().map_err(|_| illeggibile())?;
        let testo = voci.get(NETWORKS_KEY).ok_or_else(illeggibile)?;
        OfficeNetworks::parse(testo).map_err(|_| illeggibile())
    }

    /// Scrive le reti dichiarate.
    fn save(&self, networks: &OfficeNetworks) -> ServiceResult<()> {
        let mut voci = BTreeMap::new();
        voci.insert(String::from(NETWORKS_KEY), networks.to_text());
        self.store.save(&voci).map_err(|_| ServiceError::HubServer {
            reason: String::from("le reti dell'ufficio non si sono potute conservare"),
        })
    }

    /// Dichiara le reti dell'ufficio, sostituendo quelle di prima. Un testo
    /// vuoto torna alle sole predefinite.
    ///
    /// # Errori
    ///
    /// [`ServiceError::ActionReservedToAdministrator`] in modalità operatore;
    /// [`ServiceError::HubServer`] con la ragione per una rete non valida; un
    /// errore se la scrittura o l'audit non riescono.
    pub fn declare(
        &self,
        database: &Database,
        text: &str,
        mode: OperatingMode,
        operator: &OperatorId,
        now: Timestamp,
    ) -> ServiceResult<OfficeNetworks> {
        if !mode.allows(RestrictedAction::ChooseOfficeNetworks) {
            return Err(ServiceError::ActionReservedToAdministrator {
                action: RestrictedAction::ChooseOfficeNetworks,
            });
        }
        let reti = OfficeNetworks::parse(text).map_err(|errore| ServiceError::HubServer {
            reason: match errore {
                DomainError::InvalidOfficeNetwork { reason } => String::from(reason),
                _ => {
                    String::from("le reti dell'ufficio non sono scritte in una forma utilizzabile")
                }
            },
        })?;
        self.save(&reti)?;
        let dettaglio = if reti.declared().is_empty() {
            String::from("nessuna dichiarata: valgono le reti che Internet non instrada")
        } else {
            reti.to_text()
        };
        database.append_audit(&NewAuditEntry {
            actor: operator.audit_actor()?,
            action: AuditAction::try_new(AUDIT_ACTION)?,
            entity: AuditEntity::try_new(AUDIT_ENTITY)?,
            entity_id: None,
            actor_mode: Some(mode),
            detail: Some(AuditDetail::try_new(&dettaglio)?),
            recorded_at: now,
        })?;
        Ok(reti)
    }

    /// Se l'indirizzo è dell'ufficio, secondo le reti in vigore.
    ///
    /// # Errori
    ///
    /// Come [`Self::load`].
    pub fn admits(&self, address: IpAddr) -> ServiceResult<bool> {
        Ok(self.load()?.admits(address))
    }
}

fn illeggibile() -> ServiceError {
    ServiceError::HubServer {
        reason: String::from(
            "le reti dell'ufficio dichiarate non si leggono con il profilo corrente: vanno \
             dichiarate di nuovo",
        ),
    }
}

#[cfg(test)]
mod tests {
    use lisi_core::Timestamp;
    use lisi_core::model::identity::OperatorId;
    use lisi_core::role::OperatingMode;

    use super::OfficeNetworksStore;
    use crate::Database;
    use crate::error::ServiceError;

    fn indirizzo(testo: &str) -> std::net::IpAddr {
        let Ok(ip) = testo.parse() else {
            panic!("indirizzo di prova");
        };
        ip
    }

    fn operatore() -> OperatorId {
        let Ok(operatore) = OperatorId::try_new("amministratore") else {
            panic!("operatore di prova");
        };
        operatore
    }

    #[test]
    fn senza_file_valgono_le_reti_che_internet_non_instrada() {
        let Ok(cartella) = tempfile::tempdir() else {
            panic!("cartella temporanea");
        };
        let reti = OfficeNetworksStore::in_directory(cartella.path());
        assert_eq!(reti.admits(indirizzo("10.0.0.5")).ok(), Some(true));
        assert_eq!(reti.admits(indirizzo("8.8.8.8")).ok(), Some(false));
    }

    #[test]
    fn la_dichiarazione_e_dell_amministratore_e_resta_nel_registro() {
        let Ok(cartella) = tempfile::tempdir() else {
            panic!("cartella temporanea");
        };
        let Ok(archivio) = Database::open_in_memory() else {
            panic!("archivio in memoria");
        };
        let reti = OfficeNetworksStore::in_directory(cartella.path());
        let adesso = Timestamp::from_millis(1_800_000_000_000);

        let rifiuto = reti.declare(
            &archivio,
            "193.204.0.0/16",
            OperatingMode::Operator,
            &operatore(),
            adesso,
        );
        assert!(matches!(
            rifiuto,
            Err(ServiceError::ActionReservedToAdministrator { .. })
        ));
        assert_eq!(reti.admits(indirizzo("193.204.1.1")).ok(), Some(false));

        let Ok(dichiarate) = reti.declare(
            &archivio,
            "193.204.0.0/16",
            OperatingMode::Administrator,
            &operatore(),
            adesso,
        ) else {
            panic!("l'amministratore dichiara");
        };
        assert_eq!(dichiarate.declared().len(), 1);
        assert_eq!(reti.admits(indirizzo("193.204.1.1")).ok(), Some(true));

        let troppo_larga = reti.declare(
            &archivio,
            "0.0.0.0/0",
            OperatingMode::Administrator,
            &operatore(),
            adesso,
        );
        assert!(matches!(troppo_larga, Err(ServiceError::HubServer { .. })));
        // La dichiarazione rifiutata non tocca quella in vigore.
        assert_eq!(reti.admits(indirizzo("193.204.1.1")).ok(), Some(true));

        let Ok(voci) = archivio.audit_entries() else {
            panic!("registro leggibile");
        };
        assert!(
            voci.iter()
                .any(|voce| voce.action.as_str() == "reti_ufficio_dichiarate")
        );
    }
}
