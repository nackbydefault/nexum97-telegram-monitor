//! La presenza: chi è connesso all'Hub adesso (TEAM-PRESENCE-01, ADR-0096).
//!
//! # Non si scrive
//!
//! Questo registro vive **in memoria** e muore con l'Hub. Non c'è una
//! migrazione, non c'è una tabella, non c'è un evento della sequenza
//! autorevole: un elenco conservato di chi era collegato e quando diventa
//! settimana dopo settimana un foglio presenze, e nessuno ne ha chiesto uno
//! (ADR-0096, decisione 1).
//!
//! Che questo modulo **non** tocchi [`crate::hub_event`] né l'archivio è il
//! modo in cui la decisione resta vera: non c'è un controllo da ricordarsi di
//! fare, non c'è niente da scrivere.
//!
//! # È un'osservazione, non una dichiarazione
//!
//! Le righe le mette l'Hub quando **lui** autentica una connessione, e le
//! toglie quando quella connessione finisce. Nel protocollo non esiste un
//! messaggio «sono qui»: un client non può aggiungere, togliere o alterare una
//! riga (ADR-0096, decisione 3).
//!
//! # Per dispositivo, non per connessione
//!
//! Una postazione che si riconnette **aggiorna** la sua riga invece di
//! aggiungerne una, e un client che si riconnette in continuazione non fa
//! crescere niente. Quando una postazione ha davvero due connessioni aperte,
//! la riga se ne va **quando finisce l'ultima**: altrimenti la chiusura di una
//! farebbe sparire dall'elenco qualcuno che sta ancora lavorando.

use std::collections::BTreeMap;
use std::sync::{Mutex, MutexGuard, PoisonError};

use lisi_core::Timestamp;
use lisi_core::model::hub_presence::{
    MAX_PRESENCE_PAGE, MAX_PRESENT_STATIONS, PresenceSnapshot, PresentStation,
};
use lisi_core::model::identity::DeviceId;

/// Che cosa l'Hub ricorda di una postazione presente.
#[derive(Debug, Clone, Copy)]
struct Presenza {
    /// Da quando è connessa: l'istante della **prima** connessione aperta.
    connected_since: Timestamp,
    /// Quando l'Hub l'ha vista l'ultima volta.
    last_seen: Timestamp,
    /// Quante connessioni di questa postazione sono aperte.
    ///
    /// Serve a non far sparire dall'elenco chi ne chiude una e ne ha ancora
    /// un'altra.
    connessioni: usize,
}

/// Chi è connesso all'Hub adesso.
#[derive(Debug, Default)]
pub struct PresenceRegistry {
    /// Ordinata per identificativo: l'ordine di una mappa non deve dipendere
    /// da dove la memoria è finita, altrimenti due letture della stessa
    /// presenza darebbero due elenchi.
    postazioni: Mutex<BTreeMap<DeviceId, Presenza>>,
}

impl PresenceRegistry {
    /// Un registro vuoto.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Segna che una postazione è entrata.
    ///
    /// Oltre il tetto la postazione **non viene ricordata**, e basta: la
    /// presenza non è un cancello, e una presenza mancante è meno grave di un
    /// client che non entra (ADR-0096, decisione 6).
    pub fn arrive(&self, device: &DeviceId, now: Timestamp) {
        let mut mappa = self.mappa();
        if let Some(presenza) = mappa.get_mut(device) {
            presenza.last_seen = now;
            presenza.connessioni = presenza.connessioni.saturating_add(1);
            return;
        }
        if mappa.len() >= MAX_PRESENT_STATIONS {
            return;
        }
        mappa.insert(
            device.clone(),
            Presenza {
                connected_since: now,
                last_seen: now,
                connessioni: 1,
            },
        );
    }

    /// Segna che l'Hub ha appena sentito questa postazione.
    ///
    /// Non aggiunge righe: una postazione che l'Hub non ha ricordato entrando
    /// (tetto raggiunto) non compare per il fatto di aver parlato.
    pub fn touch(&self, device: &DeviceId, now: Timestamp) {
        if let Some(presenza) = self.mappa().get_mut(device) {
            presenza.last_seen = now;
        }
    }

    /// Segna che una connessione di questa postazione è finita.
    ///
    /// Va chiamata **comunque la connessione finisca**: per questo chi serve
    /// una connessione tiene una [`Presente`], che toglie la riga anche quando
    /// si esce per un guasto (ADR-0096, decisione 4).
    pub fn depart(&self, device: &DeviceId) {
        let mut mappa = self.mappa();
        let Some(presenza) = mappa.get_mut(device) else {
            return;
        };
        presenza.connessioni = presenza.connessioni.saturating_sub(1);
        if presenza.connessioni == 0 {
            mappa.remove(device);
        }
    }

    /// La presenza come si mostra adesso.
    ///
    /// Le righe più vecchie della soglia **non compaiono**: una fotografia
    /// della presenza dice il presente, non l'ultimo ricordo. Le righe vecchie
    /// vengono anche **dimenticate**, così che una connessione caduta senza
    /// chiudersi non occupi per sempre un posto sotto il tetto.
    ///
    /// L'ordine è **dalla più recentemente vista alla più vecchia**, con
    /// l'identificativo a parità per renderlo totale: due letture della stessa
    /// presenza devono dare lo stesso elenco.
    pub fn snapshot(&self, now: Timestamp, limit: usize) -> PresenceSnapshot {
        let mut mappa = self.mappa();
        let mut righe: Vec<PresentStation> = mappa
            .iter()
            .map(|(device, presenza)| PresentStation {
                device: device.clone(),
                connected_since: presenza.connected_since,
                last_seen: presenza.last_seen,
            })
            .filter(|riga| !riga.is_stale(now))
            .collect();
        if righe.len() < mappa.len() {
            mappa.retain(|_, presenza| {
                now.as_millis()
                    .saturating_sub(presenza.last_seen.as_millis())
                    <= lisi_core::model::hub_presence::PRESENCE_STALE_AFTER_MILLIS
            });
        }
        drop(mappa);

        righe.sort_by(|prima, poi| {
            poi.last_seen
                .as_millis()
                .cmp(&prima.last_seen.as_millis())
                .then_with(|| prima.device.cmp(&poi.device))
        });
        let total = righe.len();
        righe.truncate(limit.clamp(1, MAX_PRESENCE_PAGE));
        PresenceSnapshot {
            stations: righe,
            composed_at: now,
            total,
        }
    }

    /// Quante postazioni l'Hub ricorda, comprese quelle vecchie.
    #[must_use]
    pub fn len(&self) -> usize {
        self.mappa().len()
    }

    /// Se l'Hub non ricorda nessuno.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// La mappa, anche se un altro filo è morto tenendola.
    ///
    /// Qui non c'è un invariante da rompere: la mappa è un insieme di fatti
    /// indipendenti, e una presenza in meno o in più non corrompe nulla.
    /// Propagare il panico spegnerebbe la presenza per sempre, che è peggio.
    fn mappa(&self) -> MutexGuard<'_, BTreeMap<DeviceId, Presenza>> {
        self.postazioni
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
    }
}

/// Una postazione presente finché questo valore vive.
///
/// Esiste perché la rimozione **non deve dipendere dal percorso felice**: il
/// percorso felice è quello che non serve proteggere. Una connessione che cade,
/// che va in errore o che si chiude di colpo toglie la riga lo stesso, perché
/// la toglie `Drop`.
#[derive(Debug)]
pub struct Presente<'registro> {
    registro: &'registro PresenceRegistry,
    device: DeviceId,
}

impl<'registro> Presente<'registro> {
    /// Segna la postazione come presente, e la toglierà uscendo.
    pub fn arriva(
        registro: &'registro PresenceRegistry,
        device: &DeviceId,
        now: Timestamp,
    ) -> Self {
        registro.arrive(device, now);
        Self {
            registro,
            device: device.clone(),
        }
    }

    /// Segna che l'Hub ha appena sentito questa postazione.
    pub fn si_fa_sentire(&self, now: Timestamp) {
        self.registro.touch(&self.device, now);
    }
}

impl Drop for Presente<'_> {
    fn drop(&mut self) {
        self.registro.depart(&self.device);
    }
}

#[cfg(test)]
mod tests {
    use super::{PresenceRegistry, Presente};
    use lisi_core::Timestamp;
    use lisi_core::model::hub_presence::{MAX_PRESENT_STATIONS, PRESENCE_STALE_AFTER_MILLIS};
    use lisi_core::model::identity::{DEVICE_ID_BYTES, DeviceId};

    fn postazione(seme: u8) -> DeviceId {
        DeviceId::from_random_bytes(&[seme; DEVICE_ID_BYTES])
    }

    fn istante(millis: i64) -> Timestamp {
        Timestamp::from_millis(millis)
    }

    #[test]
    fn chi_entra_compare_e_chi_esce_sparisce() {
        let registro = PresenceRegistry::new();
        {
            let _presente = Presente::arriva(&registro, &postazione(1), istante(0));
            let fotografia = registro.snapshot(istante(0), 10);
            assert_eq!(fotografia.total, 1);
            assert_eq!(fotografia.stations[0].device, postazione(1));
            assert_eq!(fotografia.stations[0].connected_since, istante(0));
        }
        assert!(registro.snapshot(istante(0), 10).is_empty());
        assert!(registro.is_empty());
    }

    #[test]
    fn si_esce_anche_uscendo_male() {
        // Il percorso felice e' quello che non serve proteggere: qui si esce
        // per un panico, e la riga se ne va lo stesso.
        let registro = PresenceRegistry::new();
        let esito = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _presente = Presente::arriva(&registro, &postazione(2), istante(0));
            panic!("la connessione si guasta");
        }));
        assert!(esito.is_err());
        assert!(registro.is_empty(), "una riga non deve restare a schermo");
    }

    #[test]
    fn due_connessioni_della_stessa_postazione_sono_una_riga_sola() {
        let registro = PresenceRegistry::new();
        let prima = Presente::arriva(&registro, &postazione(3), istante(0));
        {
            let _seconda = Presente::arriva(&registro, &postazione(3), istante(10));
            assert_eq!(registro.snapshot(istante(10), 10).total, 1);
        }
        // Chiusa una delle due, chi sta ancora lavorando resta a schermo.
        assert_eq!(registro.snapshot(istante(10), 10).total, 1);
        drop(prima);
        assert!(registro.is_empty());
    }

    #[test]
    fn chi_si_riconnette_non_perde_il_da_quando() {
        let registro = PresenceRegistry::new();
        let presente = Presente::arriva(&registro, &postazione(4), istante(100));
        presente.si_fa_sentire(istante(500));
        let fotografia = registro.snapshot(istante(500), 10);
        assert_eq!(fotografia.stations[0].connected_since, istante(100));
        assert_eq!(fotografia.stations[0].last_seen, istante(500));
    }

    #[test]
    fn una_riga_troppo_vecchia_non_si_mostra_e_si_dimentica() {
        let registro = PresenceRegistry::new();
        // Una connessione caduta senza chiudersi: la guardia non e' stata
        // lasciata cadere, quindi la riga resterebbe per sempre.
        let _presente = Presente::arriva(&registro, &postazione(5), istante(0));
        let dopo = istante(PRESENCE_STALE_AFTER_MILLIS + 1);
        assert!(registro.snapshot(dopo, 10).is_empty());
        assert!(
            registro.is_empty(),
            "una riga vecchia non deve occupare un posto sotto il tetto"
        );
    }

    #[test]
    fn oltre_il_tetto_si_lavora_lo_stesso_senza_comparire() {
        let registro = PresenceRegistry::new();
        let mut presenti = Vec::new();
        for seme in 0..MAX_PRESENT_STATIONS {
            let Ok(seme) = u8::try_from(seme) else {
                panic!("il tetto deve stare in un byte per questa prova");
            };
            presenti.push(Presente::arriva(&registro, &postazione(seme), istante(0)));
        }
        assert_eq!(registro.len(), MAX_PRESENT_STATIONS);

        let oltre = Presente::arriva(&registro, &postazione(200), istante(0));
        assert_eq!(
            registro.len(),
            MAX_PRESENT_STATIONS,
            "la presenza non e' un cancello: non ricorda, ma non rifiuta"
        );
        drop(oltre);
        // E uscire non toglie la riga di qualcun altro.
        assert_eq!(registro.len(), MAX_PRESENT_STATIONS);
    }

    #[test]
    fn la_fotografia_dice_quante_ne_restano_fuori() {
        let registro = PresenceRegistry::new();
        let _uno = Presente::arriva(&registro, &postazione(10), istante(0));
        let _due = Presente::arriva(&registro, &postazione(11), istante(1));
        let _tre = Presente::arriva(&registro, &postazione(12), istante(2));
        let fotografia = registro.snapshot(istante(2), 1);
        assert_eq!(fotografia.total, 3);
        assert_eq!(fotografia.stations.len(), 1);
        assert_eq!(fotografia.beyond(), 2);
        assert_eq!(
            fotografia.stations[0].device,
            postazione(12),
            "prima chi e' stato visto piu' di recente"
        );
    }

    #[test]
    fn la_presenza_non_dice_che_cosa_si_sta_guardando() {
        // GUARDIA DI FORMA: una riga porta tre cose, e nessuna in piu'.
        // Aggiungere qui un campo con la schermata aperta o il contenuto in
        // lettura fa fallire questa prova, che e' il punto (ADR-0096,
        // decisione 2).
        let registro = PresenceRegistry::new();
        let _presente = Presente::arriva(&registro, &postazione(20), istante(0));
        let fotografia = registro.snapshot(istante(0), 10);
        let mostrata = format!("{:?}", fotografia.stations[0]);
        for campo in ["device", "connected_since", "last_seen"] {
            assert!(mostrata.contains(campo), "manca «{campo}»: {mostrata}");
        }
        for vietato in ["content", "screen", "page", "idle", "note", "address"] {
            assert!(
                !mostrata.contains(vietato),
                "la presenza non deve portare «{vietato}»: {mostrata}"
            );
        }
    }
}
