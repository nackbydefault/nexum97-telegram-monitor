//! La distribuzione degli eventi ai client collegati, con i suoi tetti
//! (HUB-BP-01, ADR-0088).
//!
//! # Che cosa garantisce
//!
//! **L'Hub non rallenta mai per un client.** Ogni connessione ha una coda con un
//! tetto: quando è piena, il client viene **lasciato indietro** e la sua
//! connessione va chiusa. Mettere in coda un evento non fallisce, non aspetta e
//! non blocca chi acquisisce (ADR-0042 decisione 6).
//!
//! # Perché lasciarlo indietro non perde niente
//!
//! La storia è persistita e numerata (ADR-0086); chi torna recupera dall'ultimo
//! numero applicato (ADR-0087). Un client lasciato indietro **perde la diretta,
//! non gli eventi**.
//!
//! # Che cosa tiene in memoria
//!
//! **Numeri, non eventi.** Il contenuto sta nell'archivio: tenerne una copia per
//! client moltiplicherebbe per connessione ciò che l'Hub ha già una volta.

use std::collections::BTreeMap;

use lisi_core::Timestamp;
use lisi_core::model::NewAuditEntry;
use lisi_core::model::hub_backpressure::{
    BacklogVerdict, ClientBacklog, PageVerdict, RecoveryBudget,
};
use lisi_core::model::identity::DeviceId;
use lisi_core::text::{Actor, AuditAction, AuditDetail, AuditEntity};

use crate::Database;
use crate::error::ServiceResult;

/// Entità dell'audit di questo modulo.
const AUDIT_ENTITY: &str = "distribuzione_hub";
/// Soggetto degli atti decisi dalla regola.
const AUDIT_AUTHORITY: &str = "hub.distribuzione";

const AUDIT_LEFT_BEHIND: &str = "client_lasciato_indietro";
const AUDIT_BUDGET: &str = "budget_di_recupero_esaurito";

/// Una connessione viva, come la conosce la distribuzione.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct ConnectionId(u64);

#[derive(Debug)]
struct Connessione {
    device: DeviceId,
    backlog: ClientBacklog,
    budget: RecoveryBudget,
}

/// La distribuzione degli eventi ai client collegati.
#[derive(Debug)]
pub struct HubFanout {
    database: Database,
    connessioni: BTreeMap<u64, Connessione>,
    prossima: u64,
}

impl HubFanout {
    /// Costruisce la distribuzione sull'archivio dell'Hub.
    #[must_use]
    pub const fn new(database: Database) -> Self {
        Self {
            database,
            connessioni: BTreeMap::new(),
            prossima: 1,
        }
    }

    /// Archivio sottostante.
    #[must_use]
    pub const fn database(&self) -> &Database {
        &self.database
    }

    /// Registra una connessione appena autenticata.
    pub fn connect(&mut self, device: DeviceId, now: Timestamp) -> ConnectionId {
        let id = self.prossima;
        self.prossima = self.prossima.saturating_add(1);
        self.connessioni.insert(
            id,
            Connessione {
                device,
                backlog: ClientBacklog::default(),
                budget: RecoveryBudget::starting_at(now),
            },
        );
        ConnectionId(id)
    }

    /// Dimentica una connessione chiusa.
    pub fn disconnect(&mut self, connection: ConnectionId) {
        self.connessioni.remove(&connection.0);
    }

    /// Quante connessioni la distribuzione conosce.
    #[must_use]
    pub fn connected(&self) -> usize {
        self.connessioni.len()
    }

    /// Mette un evento in coda per tutti, e dice **chi va disconnesso**.
    ///
    /// Non fallisce per colpa di un client: chi non sta al passo compare
    /// nell'elenco restituito, e chi chiama chiude quelle connessioni.
    ///
    /// # Errori
    ///
    /// Restituisce un errore solo se l'audit non si scrive.
    pub fn publish(&mut self, sequence: u64, now: Timestamp) -> ServiceResult<Vec<ConnectionId>> {
        let mut rimasti_indietro = Vec::new();
        let mut da_registrare = Vec::new();

        for (id, connessione) in &mut self.connessioni {
            if connessione.backlog.is_left_behind() {
                continue;
            }
            if connessione.backlog.push(sequence) == BacklogVerdict::ClientLeftBehind {
                rimasti_indietro.push(ConnectionId(*id));
                da_registrare.push(connessione.device.clone());
            }
        }

        for device in da_registrare {
            self.registra(
                AUDIT_LEFT_BEHIND,
                &format!(
                    "dispositivo {device}: non stava al passo, la connessione si chiude; \
                     tornando recupererà dall'ultimo numero applicato"
                ),
                now,
            )?;
        }
        Ok(rimasti_indietro)
    }

    /// I numeri pronti per una connessione, al più `quanti`.
    pub fn deliverable(&mut self, connection: ConnectionId, quanti: usize) -> Vec<u64> {
        self.connessioni
            .get_mut(&connection.0)
            .map(|connessione| connessione.backlog.take(quanti))
            .unwrap_or_default()
    }

    /// Quanti eventi aspettano su una connessione.
    #[must_use]
    pub fn pending(&self, connection: ConnectionId) -> usize {
        self.connessioni
            .get(&connection.0)
            .map_or(0, |connessione| connessione.backlog.pending())
    }

    /// Se una richiesta di pagina si può servire.
    ///
    /// Una connessione sconosciuta non si serve: è già stata chiusa.
    ///
    /// # Errori
    ///
    /// Restituisce un errore solo se l'audit non si scrive.
    pub fn may_serve_page(
        &mut self,
        connection: ConnectionId,
        now: Timestamp,
    ) -> ServiceResult<PageVerdict> {
        let Some(connessione) = self.connessioni.get_mut(&connection.0) else {
            return Ok(PageVerdict::BudgetExhausted);
        };
        let verdetto = connessione.budget.request(now);
        if verdetto == PageVerdict::BudgetExhausted {
            let device = connessione.device.clone();
            self.registra(
                AUDIT_BUDGET,
                &format!(
                    "dispositivo {device}: troppe pagine di recupero nella finestra, la \
                     connessione si chiude"
                ),
                now,
            )?;
        }
        Ok(verdetto)
    }

    fn registra(&self, azione: &str, dettaglio: &str, now: Timestamp) -> ServiceResult<()> {
        let entry = NewAuditEntry {
            actor: Actor::try_new(AUDIT_AUTHORITY)?,
            action: AuditAction::try_new(azione)?,
            entity: AuditEntity::try_new(AUDIT_ENTITY)?,
            entity_id: None,
            actor_mode: None,
            detail: Some(AuditDetail::try_new(dettaglio)?),
            recorded_at: now,
        };
        self.database.append_audit(&entry)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use lisi_core::Timestamp;
    use lisi_core::model::hub_backpressure::{MAX_BACKLOG_EVENTS, PageVerdict};
    use lisi_core::model::identity::{DEVICE_ID_BYTES, DeviceId};

    use super::HubFanout;

    fn adesso() -> Timestamp {
        Timestamp::from_millis(1_758_600_000_000)
    }

    fn distribuzione() -> HubFanout {
        let Ok(database) = crate::sources::open_in_memory_database() else {
            panic!("archivio di prova");
        };
        HubFanout::new(database)
    }

    fn dispositivo(seme: u8) -> DeviceId {
        DeviceId::from_random_bytes(&[seme; DEVICE_ID_BYTES])
    }

    fn azioni(distribuzione: &HubFanout) -> Vec<String> {
        let Ok(voci) = distribuzione.database().audit_entries() else {
            panic!("audit");
        };
        voci.iter()
            .filter(|voce| voce.entity.as_str() == "distribuzione_hub")
            .map(|voce| voce.action.as_str().to_owned())
            .collect()
    }

    #[test]
    fn everyone_connected_receives_what_is_published() {
        let mut distribuzione = distribuzione();
        let primo = distribuzione.connect(dispositivo(1), adesso());
        let secondo = distribuzione.connect(dispositivo(2), adesso());

        for numero in 1..=3 {
            assert_eq!(distribuzione.publish(numero, adesso()).ok(), Some(vec![]));
        }
        assert_eq!(distribuzione.deliverable(primo, 10), vec![1, 2, 3]);
        assert_eq!(distribuzione.deliverable(secondo, 10), vec![1, 2, 3]);
        assert_eq!(distribuzione.pending(primo), 0);
    }

    #[test]
    fn a_client_that_does_not_read_is_left_behind_and_the_others_keep_receiving() {
        let mut distribuzione = distribuzione();
        let lento = distribuzione.connect(dispositivo(1), adesso());
        let sveglio = distribuzione.connect(dispositivo(2), adesso());

        let mut disconnessi = Vec::new();
        for numero in 1..=(MAX_BACKLOG_EVENTS as u64 + 5) {
            let Ok(indietro) = distribuzione.publish(numero, adesso()) else {
                panic!("pubblicare non deve fallire per colpa di un client");
            };
            disconnessi.extend(indietro);
            // Il client sveglio legge sempre.
            let _ = distribuzione.deliverable(sveglio, 100);
        }

        assert_eq!(disconnessi, vec![lento], "solo il lento resta indietro");
        assert!(azioni(&distribuzione).contains(&String::from("client_lasciato_indietro")));

        // E l'Hub continua a pubblicare per chi legge.
        let Ok(indietro) = distribuzione.publish(1_000, adesso()) else {
            panic!("pubblicare deve continuare a riuscire");
        };
        assert!(indietro.is_empty(), "il lento è già segnato, non si ripete");
        assert_eq!(distribuzione.deliverable(sveglio, 10), vec![1_000]);
    }

    #[test]
    fn publishing_never_blocks_on_a_full_client_and_never_fails() {
        let mut distribuzione = distribuzione();
        let _fermo = distribuzione.connect(dispositivo(3), adesso());
        for numero in 1..=(MAX_BACKLOG_EVENTS as u64 * 3) {
            assert!(
                distribuzione.publish(numero, adesso()).is_ok(),
                "l'acquisizione non si ferma mai per un client"
            );
        }
    }

    #[test]
    fn a_client_that_asks_pages_forever_is_closed_and_it_is_written_down() {
        let mut distribuzione = distribuzione();
        let connessione = distribuzione.connect(dispositivo(4), adesso());
        for _ in 0..60 {
            assert_eq!(
                distribuzione.may_serve_page(connessione, adesso()).ok(),
                Some(PageVerdict::Serve)
            );
        }
        assert_eq!(
            distribuzione.may_serve_page(connessione, adesso()).ok(),
            Some(PageVerdict::BudgetExhausted)
        );
        assert!(azioni(&distribuzione).contains(&String::from("budget_di_recupero_esaurito")));
    }

    #[test]
    fn a_connection_that_is_gone_is_not_served_and_is_forgotten() {
        let mut distribuzione = distribuzione();
        let connessione = distribuzione.connect(dispositivo(5), adesso());
        assert_eq!(distribuzione.connected(), 1);
        distribuzione.disconnect(connessione);
        assert_eq!(distribuzione.connected(), 0);
        assert_eq!(
            distribuzione.may_serve_page(connessione, adesso()).ok(),
            Some(PageVerdict::BudgetExhausted)
        );
        assert!(distribuzione.deliverable(connessione, 10).is_empty());
        // E pubblicare senza nessuno collegato non è un errore.
        assert_eq!(distribuzione.publish(1, adesso()).ok(), Some(vec![]));
    }
}
