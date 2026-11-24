//! Contropressione: chi non sta al passo perde il passo, non l'Hub
//! (HUB-BP-01, ADR-0088).
//!
//! # La regola che viene prima di tutte
//!
//! ADR-0042 decisione 6: *l'acquisizione è la cosa che non deve fermarsi mai —
//! un buco nell'archivio non si recupera.* Ne segue che **nessun client può
//! rallentare l'Hub**: la coda verso ciascuno ha un tetto, e quando il tetto è
//! raggiunto **è il client a essere lasciato indietro**.
//!
//! # Perché lasciarlo indietro non perde niente
//!
//! Perché la storia è persistita e numerata (ADR-0086), e chi torna recupera
//! dall'ultimo numero applicato (ADR-0087). Un client disconnesso perché
//! lento **non perde eventi**: perde la diretta, e la riprende recuperando.
//! È la ragione per cui questa decisione può essere così netta.
//!
//! # Due tetti, non uno
//!
//! - **Il backlog**: quanti eventi si tengono in attesa per un client che non
//!   legge.
//! - **Il budget di recupero**: quante pagine un client può chiedere in una
//!   finestra. Senza, un client potrebbe tenere occupato l'Hub a leggere
//!   l'archivio per sempre, **senza mai** riempire il proprio backlog.
//!
//! Sono due modi diversi di costare, e un tetto solo ne coprirebbe uno.

use crate::time::Timestamp;

/// Quanti eventi si tengono in attesa per un client.
///
/// Scelto da noi, non misurato: in una LAN un client che non legge duecento
/// eventi è un client fermo, non un client lento.
pub const MAX_BACKLOG_EVENTS: usize = 200;

/// Quante pagine di recupero un client può chiedere nella finestra.
pub const MAX_PAGES_PER_WINDOW: u32 = 60;

/// La finestra del budget di recupero, in millisecondi.
pub const RECOVERY_WINDOW_MS: i64 = 60_000;

/// Che cosa succede a un evento destinato a un client.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BacklogVerdict {
    /// Messo in coda: il client lo riceverà.
    Queued,
    /// La coda era piena: **il client viene lasciato indietro** e la sua
    /// connessione va chiusa. Recupererà tornando.
    ClientLeftBehind,
}

/// La coda verso un client, con il suo tetto.
///
/// Tiene **numeri**, non eventi: il contenuto sta nell'archivio, e tenerne una
/// seconda copia in memoria moltiplicherebbe per client ciò che l'Hub ha già.
#[derive(Debug, Clone)]
pub struct ClientBacklog {
    numeri: Vec<u64>,
    tetto: usize,
    lasciato_indietro: bool,
}

impl Default for ClientBacklog {
    fn default() -> Self {
        Self::with_capacity(MAX_BACKLOG_EVENTS)
    }
}

impl ClientBacklog {
    /// Una coda con il tetto indicato.
    ///
    /// Un tetto nullo diventa uno: una coda che non può contenere niente
    /// lascerebbe indietro chiunque al primo evento, ed è un difetto di
    /// configurazione, non una politica.
    #[must_use]
    pub fn with_capacity(tetto: usize) -> Self {
        Self {
            numeri: Vec::new(),
            tetto: tetto.max(1),
            lasciato_indietro: false,
        }
    }

    /// Mette in coda un evento per questo client.
    ///
    /// Una volta lasciato indietro, il client resta tale finché non torna: non
    /// si rimette in coda niente, perché ciò che segue avrebbe comunque un buco.
    pub fn push(&mut self, sequence: u64) -> BacklogVerdict {
        if self.lasciato_indietro || self.numeri.len() >= self.tetto {
            self.lasciato_indietro = true;
            self.numeri.clear();
            return BacklogVerdict::ClientLeftBehind;
        }
        self.numeri.push(sequence);
        BacklogVerdict::Queued
    }

    /// Prende fino a `quanti` numeri da consegnare, in ordine.
    pub fn take(&mut self, quanti: usize) -> Vec<u64> {
        let quanti = quanti.min(self.numeri.len());
        self.numeri.drain(..quanti).collect()
    }

    /// Quanti eventi sono in attesa.
    #[must_use]
    pub fn pending(&self) -> usize {
        self.numeri.len()
    }

    /// Se il client è stato lasciato indietro.
    #[must_use]
    pub const fn is_left_behind(&self) -> bool {
        self.lasciato_indietro
    }
}

/// Che cosa fare di una richiesta di pagina.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PageVerdict {
    /// Si serve.
    Serve,
    /// Il budget della finestra è esaurito: **la connessione si chiude**, e il
    /// client tornerà. Non esiste un «rallenta» da dire, perché dirlo
    /// richiederebbe un messaggio nuovo e quindi una versione nuova del
    /// protocollo (ADR-0084): chiudere è già dicibile, e il recupero ne esce
    /// intatto.
    BudgetExhausted,
}

/// Quante pagine un client ha già chiesto nella finestra corrente.
#[derive(Debug, Clone, Copy)]
pub struct RecoveryBudget {
    inizio: Timestamp,
    chieste: u32,
    massimo: u32,
    finestra_ms: i64,
}

impl RecoveryBudget {
    /// Un budget che comincia adesso, con i valori del prodotto.
    #[must_use]
    pub const fn starting_at(now: Timestamp) -> Self {
        Self {
            inizio: now,
            chieste: 0,
            massimo: MAX_PAGES_PER_WINDOW,
            finestra_ms: RECOVERY_WINDOW_MS,
        }
    }

    /// Un budget con valori propri, per le prove e per i tetti di un ufficio.
    #[must_use]
    pub const fn custom(now: Timestamp, massimo: u32, finestra_ms: i64) -> Self {
        Self {
            inizio: now,
            chieste: 0,
            massimo,
            finestra_ms,
        }
    }

    /// Registra una richiesta di pagina e dice se servirla.
    pub const fn request(&mut self, now: Timestamp) -> PageVerdict {
        if now.as_millis().saturating_sub(self.inizio.as_millis()) >= self.finestra_ms {
            self.inizio = now;
            self.chieste = 0;
        }
        if self.chieste >= self.massimo {
            return PageVerdict::BudgetExhausted;
        }
        self.chieste = self.chieste.saturating_add(1);
        PageVerdict::Serve
    }

    /// Quante pagine sono state chieste nella finestra corrente.
    #[must_use]
    pub const fn requested(&self) -> u32 {
        self.chieste
    }
}

#[cfg(test)]
mod tests {
    use super::{BacklogVerdict, ClientBacklog, MAX_BACKLOG_EVENTS, PageVerdict, RecoveryBudget};
    use crate::time::Timestamp;

    fn adesso() -> Timestamp {
        Timestamp::from_millis(1_758_500_000_000)
    }

    fn fra(ms: i64) -> Timestamp {
        Timestamp::from_millis(adesso().as_millis() + ms)
    }

    #[test]
    fn a_client_that_reads_keeps_receiving() {
        let mut coda = ClientBacklog::default();
        for numero in 1..=MAX_BACKLOG_EVENTS as u64 {
            assert_eq!(coda.push(numero), BacklogVerdict::Queued);
        }
        assert_eq!(coda.pending(), MAX_BACKLOG_EVENTS);

        // Legge: la coda si libera e si continua.
        let presi = coda.take(MAX_BACKLOG_EVENTS);
        assert_eq!(presi.len(), MAX_BACKLOG_EVENTS);
        assert_eq!(presi[0], 1);
        assert_eq!(coda.push(1_000), BacklogVerdict::Queued);
        assert!(!coda.is_left_behind());
    }

    #[test]
    fn a_client_that_does_not_read_is_left_behind_and_stays_behind() {
        let mut coda = ClientBacklog::with_capacity(3);
        for numero in 1..=3 {
            assert_eq!(coda.push(numero), BacklogVerdict::Queued);
        }
        assert_eq!(coda.push(4), BacklogVerdict::ClientLeftBehind);
        assert!(coda.is_left_behind());
        // La coda si svuota: tenere ciò che non si consegnerà è memoria
        // occupata per niente.
        assert_eq!(coda.pending(), 0);
        // E ciò che segue non si rimette in coda: avrebbe comunque un buco.
        assert_eq!(coda.push(5), BacklogVerdict::ClientLeftBehind);
        assert_eq!(coda.pending(), 0);
    }

    #[test]
    fn a_backlog_without_room_is_a_configuration_defect_not_a_policy() {
        let mut coda = ClientBacklog::with_capacity(0);
        assert_eq!(coda.push(1), BacklogVerdict::Queued);
    }

    #[test]
    fn pages_are_counted_in_a_window_and_the_window_rolls() {
        let mut budget = RecoveryBudget::custom(adesso(), 3, 1_000);
        for _ in 0..3 {
            assert_eq!(budget.request(adesso()), PageVerdict::Serve);
        }
        assert_eq!(budget.request(adesso()), PageVerdict::BudgetExhausted);
        assert_eq!(budget.requested(), 3);

        // Finita la finestra si ricomincia: il client che torna domani non
        // paga per ieri.
        assert_eq!(budget.request(fra(1_000)), PageVerdict::Serve);
        assert_eq!(budget.requested(), 1);
    }

    #[test]
    fn the_default_budget_lets_a_real_recovery_finish() {
        // Sessanta pagine da duecento eventi sono dodicimila eventi al minuto:
        // un recupero vero passa, un client che gira a vuoto no.
        let mut budget = RecoveryBudget::starting_at(adesso());
        for _ in 0..60 {
            assert_eq!(budget.request(adesso()), PageVerdict::Serve);
        }
        assert_eq!(budget.request(adesso()), PageVerdict::BudgetExhausted);
    }
}
