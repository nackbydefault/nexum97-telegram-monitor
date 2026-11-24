//! Impostazioni delle notifiche, conservate per postazione.
//!
//! Vivono qui, nel dominio, e non nei servizi, per una ragione di confine: la
//! persistenza le legge e le scrive, e lo storage dipende da `lisi-core` ma non
//! dai servizi. Le scelte sono in DEC-103.
//!
//! Il tipo porta le sue invarianti come costanti (soglia fra 1 e 4); la
//! validazione di chi le salva sta nei servizi, e il vincolo dello schema è la
//! rete di sicurezza.

use crate::model::NotificationPrivacy;

/// Livello minimo che può far scattare una notifica.
///
/// Non 0: il livello 0 è «analizzato e non rilevante», e notificarlo
/// equivarrebbe a notificare tutto, cioè a non notificare nulla.
pub const MIN_NOTIFY_LEVEL: u8 = 1;

/// Livello massimo, cioè il più alto della scala 0–4.
pub const MAX_NOTIFY_LEVEL: u8 = 4;

/// Tetto massimo ammesso per le notifiche di una sessione.
///
/// Un numero grande a piacere non aggiunge nulla: oltre poche decine di
/// notifiche l'operatore ha comunque smesso di guardarle una per una. Il tetto
/// sul tetto evita un valore fuori misura scritto per errore.
pub const MAX_PER_SESSION_CAP: u32 = 1_000;

/// Quanti contenuti minimi può richiedere un grappolo per essere annunciato.
///
/// Non 1: un grappolo **non esiste** con un contenuto solo — il valore della
/// correlazione sta nel ripetersi. Il minimo ammesso è quindi 2, che è la
/// dimensione di un grappolo appena nato.
pub const MIN_CYBER_CONTENTS: u32 = 2;

/// Quante fonti distinte minime può richiedere un grappolo.
///
/// **Una fonte sola è ammessa**, e va detto perché: venti messaggi dallo stesso
/// canale che nominano la stessa CVE sono una ripetizione, non una
/// corroborazione, ma un ufficio può volerli comunque vedere. Alzare questa
/// soglia rende più raro ciò che viene annunciato; **non rende più attendibile
/// ciò che passa**, perché fonti distinte non sono conferme indipendenti.
pub const MIN_CYBER_SOURCES: u32 = 1;

/// Tetto sulle due soglie cyber.
///
/// Come per il tetto delle notifiche: un numero grande a piacere non aggiunge
/// nulla, e il limite evita un valore fuori misura scritto per errore.
pub const MAX_CYBER_THRESHOLD: u32 = 100;

/// Riservatezza e limiti con cui si notifica.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NotificationSettings {
    /// Quanto una notifica rivela.
    pub privacy: NotificationPrivacy,
    /// Livello minimo che fa scattare una notifica, da 1 a 4.
    pub minimum_level: u8,
    /// Numero massimo di notifiche per sessione.
    pub max_per_session: usize,
    /// Se la modalità completa può includere l'URL del contenuto.
    pub include_url: bool,
    /// Se i grappoli di segnali producono un avviso.
    ///
    /// # Perché è spenta per difetto
    ///
    /// Una capacità nuova che si accende da sola cambia il comportamento di una
    /// postazione già in esercizio senza che nessuno lo abbia chiesto. Chi la
    /// vuole la accende, e così la prima notifica cyber che arriva è **attesa**
    /// invece che sorprendente.
    pub cyber_enabled: bool,
    /// Quanti contenuti deve avere un grappolo per essere annunciato.
    pub cyber_minimum_contents: u32,
    /// Da quante fonti distinte.
    ///
    /// Le due soglie rispondono a due domande diverse — quante volte la cosa è
    /// stata detta, e da quante voci — e un ufficio può volerne sorvegliare una
    /// e non l'altra.
    pub cyber_minimum_sources: u32,
}

impl NotificationSettings {
    /// Riconduce i valori entro i limiti ammessi.
    ///
    /// I limiti sono naturali (soglia fra 1 e 4, tetto entro un massimo) e
    /// l'interfaccia li rispetta già; questa è la rete che rende impossibile
    /// scrivere una riga fuori dominio, così che il salvataggio non possa
    /// fallire per un valore fuori scala.
    #[must_use]
    pub fn sanitized(self) -> Self {
        let cap = MAX_PER_SESSION_CAP as usize;
        Self {
            minimum_level: self.minimum_level.clamp(MIN_NOTIFY_LEVEL, MAX_NOTIFY_LEVEL),
            max_per_session: self.max_per_session.min(cap),
            cyber_minimum_contents: self
                .cyber_minimum_contents
                .clamp(MIN_CYBER_CONTENTS, MAX_CYBER_THRESHOLD),
            cyber_minimum_sources: self
                .cyber_minimum_sources
                .clamp(MIN_CYBER_SOURCES, MAX_CYBER_THRESHOLD),
            ..self
        }
    }
}

impl Default for NotificationSettings {
    /// Impostazioni prudenti: riservatezza **ridotta** (adatta a una schermata
    /// bloccata), soglia al livello 1, nessun URL, avvisi cyber **spenti**.
    /// Cambiarle sarà una scelta dell'ufficio, non un valore imposto dal
    /// prodotto.
    fn default() -> Self {
        Self {
            privacy: NotificationPrivacy::Reduced,
            minimum_level: MIN_NOTIFY_LEVEL,
            max_per_session: 50,
            include_url: false,
            cyber_enabled: false,
            // Tre contenuti da due fonti distinte. Un grappolo esiste gia' con
            // due contenuti, e annunciarlo li' significherebbe un avviso per
            // ogni ripetizione.
            cyber_minimum_contents: 3,
            cyber_minimum_sources: 2,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{MAX_NOTIFY_LEVEL, MIN_NOTIFY_LEVEL, NotificationSettings};
    use crate::model::NotificationPrivacy;

    #[test]
    fn the_default_is_prudent() {
        let settings = NotificationSettings::default();
        assert_eq!(settings.privacy, NotificationPrivacy::Reduced);
        assert!((MIN_NOTIFY_LEVEL..=MAX_NOTIFY_LEVEL).contains(&settings.minimum_level));
        assert!(!settings.include_url, "l'URL non compare senza una scelta");
    }

    #[test]
    fn sanitizing_brings_out_of_range_values_back() {
        let wild = NotificationSettings {
            privacy: NotificationPrivacy::Full,
            minimum_level: 9,
            max_per_session: 100_000,
            include_url: true,
            cyber_enabled: true,
            cyber_minimum_contents: 0,
            cyber_minimum_sources: 9_999,
        }
        .sanitized();

        assert_eq!(wild.minimum_level, MAX_NOTIFY_LEVEL);
        assert!(wild.max_per_session <= super::MAX_PER_SESSION_CAP as usize);
        // I valori entro i limiti non vengono toccati.
        assert_eq!(wild.privacy, NotificationPrivacy::Full);
        assert!(wild.include_url);

        // Le soglie cyber tornano dentro. Zero contenuti annuncerebbe un
        // grappolo che non esiste ancora; novemilanovecento fonti distinte non
        // le raggiunge nulla, e sarebbe un modo silenzioso di spegnere gli
        // avvisi lasciandoli accesi.
        assert_eq!(wild.cyber_minimum_contents, super::MIN_CYBER_CONTENTS);
        assert_eq!(wild.cyber_minimum_sources, super::MAX_CYBER_THRESHOLD);
        assert!(
            wild.cyber_enabled,
            "la ricomposizione riporta i valori, non spegne una scelta"
        );

        let low = NotificationSettings {
            minimum_level: 0,
            ..NotificationSettings::default()
        }
        .sanitized();
        assert_eq!(low.minimum_level, MIN_NOTIFY_LEVEL);
    }
}
