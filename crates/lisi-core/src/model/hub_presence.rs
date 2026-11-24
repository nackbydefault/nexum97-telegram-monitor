//! La presenza: chi c'è adesso, e nient'altro (TEAM-PRESENCE-01, ADR-0096).
//!
//! # Che cosa una riga porta
//!
//! Tre cose: **quale postazione**, **da quando** è connessa, **quando l'Hub
//! l'ha vista l'ultima volta**. Non la schermata aperta, non il contenuto in
//! lettura, non un tempo di inattività, non l'indirizzo di rete.
//!
//! «Il contenuto 42 è in esame» è un fatto del lavoro, e sta nella coda
//! condivisa (ADR-0095). «La postazione di qualcuno sta guardando il 42» è un
//! fatto di quella persona, e serve a guardare quella persona: non esiste qui.
//!
//! # Che cosa non esiste in questo modulo
//!
//! Una cronologia. La presenza vive in memoria sull'Hub e muore con la
//! connessione (ADR-0096, decisione 1): un elenco conservato di chi era
//! collegato e quando è un foglio presenze, e nessuno ne ha chiesto uno.
//!
//! Per questo qui non c'è nulla che si possa scrivere in una tabella: i tipi
//! di questo modulo descrivono **una fotografia**, non un registro.

use crate::Timestamp;
use crate::model::identity::DeviceId;

/// Postazioni al più che l'Hub ricorda come presenti.
///
/// Valore scelto da noi, **non misurato**: un ufficio che usa questo prodotto
/// ha unità o decine di postazioni, non centinaia. Il tetto non è un cancello
/// — oltre il tetto una postazione lavora lo stesso e semplicemente non
/// compare (ADR-0096, decisione 6), perché una presenza mancante è meno grave
/// di un client che non entra.
pub const MAX_PRESENT_STATIONS: usize = 64;

/// Righe al più in una pagina della presenza.
///
/// Coincide con il tetto di ciò che l'Hub ricorda: una pagina più corta
/// taglierebbe senza che il conteggio totale lo faccia capire, e il conteggio
/// c'è proprio perché non si tagli in silenzio.
pub const MAX_PRESENCE_PAGE: usize = MAX_PRESENT_STATIONS;

/// Dopo quanti millisecondi senza vedere una postazione la si smette di
/// mostrare.
///
/// **Novanta secondi**, scelti larghi e non misurati: chi sta leggendo un
/// contenuto non manda richieste per minuti, e sparire dall'elenco perché si
/// sta lavorando sarebbe il contrario di ciò che serve. La soglia protegge dal
/// caso opposto — una connessione caduta senza chiudersi, che altrimenti
/// resterebbe a schermo per sempre (ADR-0096, decisione 4).
pub const PRESENCE_STALE_AFTER_MILLIS: i64 = 90_000;

/// Una postazione presente.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PresentStation {
    /// Quale postazione: ciò che l'Hub ha autenticato, mai un nome di persona.
    pub device: DeviceId,
    /// Da quando è connessa.
    pub connected_since: Timestamp,
    /// Quando l'Hub l'ha vista l'ultima volta.
    ///
    /// Sta nella riga perché fra la caduta di una connessione e la soglia
    /// esiste una finestra in cui la riga è ancora mostrata: chi legge deve
    /// poter vedere che è vecchia.
    pub last_seen: Timestamp,
}

impl PresentStation {
    /// Se questa riga è più vecchia della soglia.
    #[must_use]
    pub const fn is_stale(&self, now: Timestamp) -> bool {
        now.as_millis().saturating_sub(self.last_seen.as_millis()) > PRESENCE_STALE_AFTER_MILLIS
    }
}

/// La presenza come l'Hub l'ha composta.
///
/// È una **fotografia**: porta l'istante in cui è stata composta e quante
/// postazioni sono presenti **in tutto**, non solo quante righe viaggiano
/// (ADR-0096, decisione 5).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PresenceSnapshot {
    /// Le righe, dalla più recentemente vista alla più vecchia.
    pub stations: Vec<PresentStation>,
    /// Quando l'Hub l'ha composta.
    pub composed_at: Timestamp,
    /// Quante postazioni sono presenti in tutto.
    pub total: usize,
}

impl PresenceSnapshot {
    /// Quante postazioni restano fuori dalla fotografia.
    #[must_use]
    pub const fn beyond(&self) -> usize {
        self.total.saturating_sub(self.stations.len())
    }

    /// Se non c'è nessuno.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.total == 0
    }
}

#[cfg(test)]
mod tests {
    use super::{
        MAX_PRESENCE_PAGE, MAX_PRESENT_STATIONS, PRESENCE_STALE_AFTER_MILLIS, PresenceSnapshot,
        PresentStation,
    };
    use crate::Timestamp;
    use crate::model::identity::DeviceId;

    fn postazione() -> DeviceId {
        DeviceId::from_random_bytes(&[7; crate::model::identity::DEVICE_ID_BYTES])
    }

    fn riga(last_seen: i64) -> PresentStation {
        PresentStation {
            device: postazione(),
            connected_since: Timestamp::from_millis(0),
            last_seen: Timestamp::from_millis(last_seen),
        }
    }

    #[test]
    fn una_riga_appena_vista_non_e_vecchia() {
        let adesso = Timestamp::from_millis(PRESENCE_STALE_AFTER_MILLIS);
        assert!(!riga(PRESENCE_STALE_AFTER_MILLIS).is_stale(adesso));
    }

    #[test]
    fn sulla_soglia_esatta_una_riga_resta() {
        // La soglia è un «più vecchia di», non un «vecchia quanto»: chi sta
        // leggendo non deve sparire per un millisecondo.
        let adesso = Timestamp::from_millis(PRESENCE_STALE_AFTER_MILLIS);
        assert!(!riga(0).is_stale(adesso));
    }

    #[test]
    fn oltre_la_soglia_una_riga_non_si_mostra() {
        let adesso = Timestamp::from_millis(PRESENCE_STALE_AFTER_MILLIS + 1);
        assert!(riga(0).is_stale(adesso));
    }

    #[test]
    fn un_orologio_che_torna_indietro_non_rende_vecchia_una_riga() {
        // Il tempo del sistema può tornare indietro: la sottrazione satura
        // invece di diventare enorme e far sparire tutti.
        let adesso = Timestamp::from_millis(0);
        assert!(!riga(PRESENCE_STALE_AFTER_MILLIS * 10).is_stale(adesso));
    }

    #[test]
    fn la_fotografia_dice_quante_ne_restano_fuori() {
        let fotografia = PresenceSnapshot {
            stations: vec![riga(0)],
            composed_at: Timestamp::from_millis(0),
            total: 4,
        };
        assert_eq!(fotografia.beyond(), 3);
        assert!(!fotografia.is_empty());
    }

    #[test]
    fn una_fotografia_senza_nessuno_lo_dice() {
        let fotografia = PresenceSnapshot {
            stations: Vec::new(),
            composed_at: Timestamp::from_millis(0),
            total: 0,
        };
        assert!(fotografia.is_empty());
        assert_eq!(fotografia.beyond(), 0);
    }

    #[test]
    fn la_pagina_non_taglia_piu_di_quanto_l_hub_ricordi() {
        // Se la pagina fosse più corta del tetto, taglierebbe senza che il
        // conteggio totale lo faccia capire.
        assert_eq!(MAX_PRESENCE_PAGE, MAX_PRESENT_STATIONS);
    }
}
