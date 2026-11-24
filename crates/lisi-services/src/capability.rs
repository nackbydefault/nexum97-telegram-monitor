//! Che cosa questa postazione sa fare.
//!
//! # Perché si chiede la capacità e non la versione di Windows
//!
//! Confrontare il numero di versione è la forma peggiore di controllo, per tre
//! ragioni indipendenti (ADR-0039):
//!
//! - Windows **mente** sulla versione ai programmi senza il manifest giusto, per
//!   compatibilità: un controllo può leggere 6.2 su Windows 11;
//! - una capacità può essere presente e **disattivata** — è esattamente il caso
//!   delle notifiche, dove Windows accetta la chiamata e non presenta nulla;
//! - una capacità può comparire in un aggiornamento cumulativo senza che la
//!   versione maggiore cambi.
//!
//! Qui si interroga la capacità. Dove l'API non risponde, si tenta l'operazione
//! e si tratta il fallimento come assenza.
//!
//! # I tre livelli, e perché il comportamento è diverso
//!
//! Una capacità **richiesta** che manca ferma il prodotto: senza, non può fare il
//! proprio mestiere in modo sicuro. Una **facoltativa** che manca fa ripiegare e
//! si dichiara.
//!
//! La distinzione non è teorica. *Una capacità di sicurezza mancante non deve
//! mai degradare in silenzio*: se la protezione dei segreti non fosse
//! disponibile, conservarli in chiaro «per non bloccare l'operatore» sarebbe il
//! modo peggiore di fallire.
//!
//! # Che cosa questo modulo NON fa
//!
//! Non interroga nulla di nuovo. Raccoglie in un punto solo ciò che i moduli
//! specializzati già sanno dire — riquadro di avviso, firma, avvio automatico,
//! preferenza sul movimento — perché un amministratore possa leggerlo in una
//! schermata invece che in cinque.

use lisi_platform::motion::{SystemMotion, system_motion};
use lisi_platform::signature::{SignatureState, verify_self};
use lisi_platform::toast::{NotificationState, notification_state};

/// Quanto una capacità è necessaria.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Requirement {
    /// Senza, il prodotto non può lavorare in modo sicuro.
    ///
    /// Se manca si **fallisce in chiuso**: si dice che cosa manca e non si
    /// procede.
    Required,
    /// Aggiunge qualcosa, e la sua assenza non cambia la correttezza di nulla.
    Optional,
    /// Il prodotto continua con meno, e lo dichiara.
    Degradable,
}

impl Requirement {
    /// L'etichetta che l'operatore legge.
    #[must_use]
    pub const fn label(&self) -> &'static str {
        match self {
            Self::Required => "necessaria",
            Self::Optional => "facoltativa",
            Self::Degradable => "riducibile",
        }
    }
}

/// Come sta una singola capacità.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Availability {
    /// Presente e funzionante.
    Available,
    /// Presente ma **disattivata** da una scelta o da un criterio.
    ///
    /// Distinta da `Missing` perché porta a un'azione diversa: qualcosa da
    /// riaccendere invece di qualcosa che non c'è.
    Disabled,
    /// Assente su questa postazione.
    Missing,
    /// Non è stato possibile stabilirlo.
    ///
    /// **Non è «assente».** Dire «manca» quando non si è potuto chiedere manda
    /// chi legge a cercare il problema sbagliato.
    Unknown,
}

impl Availability {
    /// L'etichetta che l'operatore legge.
    #[must_use]
    pub const fn label(&self) -> &'static str {
        match self {
            Self::Available => "disponibile",
            Self::Disabled => "disattivata",
            Self::Missing => "assente",
            Self::Unknown => "non verificabile",
        }
    }

    /// Se lo stato impedisce di contare sulla capacità.
    ///
    /// `Unknown` conta come «non ci si può contare»: davanti a una capacità che
    /// non si è potuta stabilire, la risposta prudente è no.
    #[must_use]
    pub const fn is_usable(&self) -> bool {
        matches!(self, Self::Available)
    }
}

/// Una capacità della postazione, con il proprio stato.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Capability {
    /// Il nome, come l'operatore lo riconosce.
    pub name: &'static str,
    /// Quanto è necessaria.
    pub requirement: Requirement,
    /// Come sta.
    pub availability: Availability,
    /// Che cosa significa, e che cosa fare.
    pub detail: String,
}

impl Capability {
    /// Se questa capacità, mancando, impedisce di lavorare in sicurezza.
    #[must_use]
    pub const fn blocks_work(&self) -> bool {
        matches!(self.requirement, Requirement::Required) && !self.availability.is_usable()
    }
}

/// Lo stato complessivo della postazione.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StationCapabilities {
    /// Le capacità interrogate, nell'ordine in cui si mostrano.
    pub capabilities: Vec<Capability>,
}

impl StationCapabilities {
    /// Le capacità necessarie che mancano.
    ///
    /// Se questo elenco non è vuoto, la postazione **non è idonea** e va detto
    /// prima che qualcuno ci lavori sopra.
    #[must_use]
    pub fn blocking(&self) -> Vec<&Capability> {
        self.capabilities
            .iter()
            .filter(|capability| capability.blocks_work())
            .collect()
    }

    /// Vero se nulla di necessario manca.
    #[must_use]
    pub fn is_fit(&self) -> bool {
        self.blocking().is_empty()
    }

    /// Un riepilogo in una frase.
    #[must_use]
    pub fn operator_message(&self) -> String {
        let mancanti = self.blocking();
        if !mancanti.is_empty() {
            let nomi: Vec<&str> = mancanti.iter().map(|c| c.name).collect();
            return format!(
                "Questa postazione NON è idonea: manca ciò che serve per lavorare in \
                 sicurezza ({}). Non usarla per un monitoraggio finché non è stato \
                 risolto.",
                nomi.join(", ")
            );
        }

        let ridotte = self
            .capabilities
            .iter()
            .filter(|capability| !capability.availability.is_usable())
            .count();

        if ridotte == 0 {
            return String::from("Questa postazione ha tutto ciò che il prodotto sa usare.");
        }
        format!(
            "Questa postazione è idonea. {ridotte} capacità facoltative non sono \
             disponibili: il prodotto lavora lo stesso, con meno."
        )
    }
}

/// Interroga la postazione.
///
/// Non modifica nulla e non mostra nulla: chiede e basta.
#[must_use]
pub fn station_capabilities() -> StationCapabilities {
    StationCapabilities {
        capabilities: vec![
            secrets_capability(),
            notifications_capability(),
            signature_capability(),
            autostart_capability(),
            motion_capability(),
        ],
    }
}

/// La protezione dei segreti.
///
/// # Perché è NECESSARIA e non facoltativa
///
/// Senza, le credenziali dell'account d'ufficio e la parola di sblocco non
/// avrebbero alcuna protezione. Conservarle in chiaro «per non bloccare
/// l'operatore» sarebbe il modo peggiore di fallire: il prodotto continuerebbe a
/// funzionare, e chi lo usa non saprebbe che i propri segreti sono leggibili.
fn secrets_capability() -> Capability {
    // Si prova a proteggere e a rileggere un valore che non e' un segreto.
    // Interrogare la disponibilita' di DPAPI senza usarlo non e' possibile:
    // l'unica prova che conta e' un giro completo.
    let prova = b"nexum97-verifica-capacita";
    let esito = lisi_security::dpapi::protect(prova)
        .and_then(|protetto| lisi_security::dpapi::unprotect(&protetto));

    let (availability, detail) = match esito {
        Ok(riletto) if riletto == prova => (
            Availability::Available,
            String::from(
                "I segreti dell'account sono protetti dal sistema, legati a questo \
                 profilo Windows e a questo computer.",
            ),
        ),
        Ok(_) => (
            Availability::Unknown,
            String::from(
                "La protezione dei segreti ha risposto, ma il valore riletto non \
                 coincide con quello protetto. Non usare questa postazione per un \
                 account reale e segnalarlo.",
            ),
        ),
        Err(errore) => (
            Availability::Missing,
            format!(
                "La protezione dei segreti non è utilizzabile su questa postazione \
                 ({errore}). Senza, le credenziali non avrebbero alcuna protezione."
            ),
        ),
    };

    Capability {
        name: "Protezione dei segreti",
        requirement: Requirement::Required,
        availability,
        detail,
    }
}

/// Il riquadro di avviso di Windows.
fn notifications_capability() -> Capability {
    let stato = notification_state();
    let availability = match stato {
        NotificationState::Enabled => Availability::Available,
        NotificationState::DisabledForApplication
        | NotificationState::DisabledForUser
        | NotificationState::DisabledByGroupPolicy => Availability::Disabled,
        NotificationState::DisabledByManifest => Availability::Missing,
        NotificationState::Undeterminable { .. } => Availability::Unknown,
    };

    Capability {
        name: "Avvisi di Windows",
        requirement: Requirement::Optional,
        availability,
        detail: stato.operator_message(),
    }
}

/// La verifica della firma del programma.
fn signature_capability() -> Capability {
    let stato = verify_self();
    let availability = match stato {
        SignatureState::Trusted => Availability::Available,
        // Il prodotto non e' ancora firmato (HVQ-07): «assente» e' il fatto, non
        // un guasto della postazione.
        SignatureState::Unsigned => Availability::Missing,
        SignatureState::Tampered | SignatureState::Untrusted { .. } => Availability::Disabled,
        SignatureState::Undeterminable { .. } => Availability::Unknown,
    };

    Capability {
        name: "Firma del programma",
        requirement: Requirement::Optional,
        availability,
        detail: stato.operator_message(),
    }
}

/// L'avvio automatico all'accesso a Windows.
fn autostart_capability() -> Capability {
    let (availability, detail) = match lisi_platform::autostart::state() {
        Ok(stato) => (
            Availability::Available,
            format!(
                "Il registro di Windows è leggibile e l'avvio automatico è \
                 governabile. {}",
                stato.operator_message()
            ),
        ),
        Err(errore) => (
            Availability::Unknown,
            format!(
                "Il registro di Windows non è leggibile per l'avvio automatico \
                 ({errore}). L'applicazione funziona lo stesso; semplicemente non \
                 si potrà farla partire da sola."
            ),
        ),
    };

    Capability {
        name: "Avvio automatico",
        requirement: Requirement::Optional,
        availability,
        detail,
    }
}

/// La preferenza di accessibilità sul movimento.
fn motion_capability() -> Capability {
    let stato = system_motion();
    let availability = match stato {
        SystemMotion::Full | SystemMotion::Reduced => Availability::Available,
        SystemMotion::Undeterminable => Availability::Unknown,
    };

    Capability {
        name: "Preferenza sul movimento",
        requirement: Requirement::Optional,
        availability,
        detail: stato.operator_message(),
    }
}

#[cfg(test)]
mod tests {
    use super::{Availability, Capability, Requirement, StationCapabilities, station_capabilities};

    fn capacita(
        name: &'static str,
        requirement: Requirement,
        availability: Availability,
    ) -> Capability {
        Capability {
            name,
            requirement,
            availability,
            detail: String::from("dettaglio di prova sufficientemente lungo da leggersi"),
        }
    }

    /// **Una capacita' necessaria che manca ferma il lavoro.**
    ///
    /// Una capacita' di sicurezza mancante non deve mai degradare in silenzio.
    #[test]
    fn una_capacita_necessaria_che_manca_rende_la_postazione_non_idonea() {
        let stato = StationCapabilities {
            capabilities: vec![
                capacita(
                    "Protezione dei segreti",
                    Requirement::Required,
                    Availability::Missing,
                ),
                capacita("Avvisi", Requirement::Optional, Availability::Available),
            ],
        };
        assert!(!stato.is_fit());
        assert_eq!(stato.blocking().len(), 1);

        let messaggio = stato.operator_message();
        assert!(
            messaggio.contains("NON è idonea"),
            "l'esito deve leggersi a colpo d'occhio: «{messaggio}»"
        );
        assert!(
            messaggio.contains("Protezione dei segreti"),
            "il messaggio deve NOMINARE cio' che manca: «{messaggio}»"
        );
        assert!(
            messaggio.contains("Non usarla"),
            "chi legge deve sapere la cosa da NON fare: «{messaggio}»"
        );
    }

    /// **Una capacita' facoltativa che manca non ferma nulla.**
    #[test]
    fn una_capacita_facoltativa_che_manca_non_ferma_il_lavoro() {
        let stato = StationCapabilities {
            capabilities: vec![
                capacita(
                    "Protezione dei segreti",
                    Requirement::Required,
                    Availability::Available,
                ),
                capacita("Avvisi", Requirement::Optional, Availability::Disabled),
            ],
        };
        assert!(stato.is_fit());
        let messaggio = stato.operator_message();
        assert!(messaggio.contains("idonea"));
        assert!(
            messaggio.contains("con meno"),
            "chi legge deve sapere che lavora ridotto: «{messaggio}»"
        );
    }

    /// **«Non verificabile» non e' «disponibile».**
    ///
    /// Davanti a una capacita' che non si e' potuta stabilire, la risposta
    /// prudente e' no.
    #[test]
    fn non_verificabile_non_e_un_via_libera() {
        assert!(Availability::Available.is_usable());
        for stato in [
            Availability::Disabled,
            Availability::Missing,
            Availability::Unknown,
        ] {
            assert!(!stato.is_usable(), "{stato:?} non e' un via libera");
        }

        // E una NECESSARIA non verificabile blocca, come se mancasse.
        let stato = StationCapabilities {
            capabilities: vec![capacita(
                "Protezione dei segreti",
                Requirement::Required,
                Availability::Unknown,
            )],
        };
        assert!(
            !stato.is_fit(),
            "una capacita' necessaria che non si e' potuta stabilire non deve \
             passare per presente"
        );
    }

    /// **«Disattivata» e «assente» restano distinte.**
    ///
    /// Portano a due azioni diverse: qualcosa da riaccendere invece di qualcosa
    /// che non c'e'.
    #[test]
    fn disattivata_e_assente_non_si_confondono() {
        assert_ne!(Availability::Disabled, Availability::Missing);
        assert_ne!(
            Availability::Disabled.label(),
            Availability::Missing.label()
        );
    }

    /// **Ogni capacita' interrogata dice qualcosa di utile.**
    #[test]
    fn la_postazione_risponde_su_ogni_capacita() {
        let stato = station_capabilities();
        assert!(
            stato.capabilities.len() >= 5,
            "la postazione deve dichiarare almeno cinque capacita'"
        );

        for capacita in &stato.capabilities {
            assert!(!capacita.name.is_empty());
            assert!(
                capacita.detail.len() > 40,
                "«{}» liquida la questione: «{}»",
                capacita.name,
                capacita.detail
            );
        }
    }

    /// **La protezione dei segreti e' dichiarata NECESSARIA.**
    ///
    /// Se un giorno qualcuno la declassasse a facoltativa, il prodotto
    /// continuerebbe a partire su una postazione dove i segreti non sono
    /// protetti — e nessuno lo saprebbe.
    #[test]
    fn la_protezione_dei_segreti_e_necessaria() {
        let stato = station_capabilities();
        let Some(segreti) = stato
            .capabilities
            .iter()
            .find(|capacita| capacita.name.contains("segreti"))
        else {
            panic!("la protezione dei segreti deve essere fra le capacita' interrogate");
        };
        assert_eq!(
            segreti.requirement,
            Requirement::Required,
            "declassarla lascerebbe partire il prodotto su una postazione dove i \
             segreti non sono protetti"
        );
    }

    /// **Su questa postazione la protezione dei segreti funziona davvero.**
    ///
    /// Non e' un'asserzione sull'ambiente: e' il giro completo — proteggi,
    /// rileggi, confronta — che il prodotto fa per ogni credenziale.
    #[cfg(windows)]
    #[test]
    fn su_windows_i_segreti_si_proteggono_e_si_rileggono() {
        let stato = station_capabilities();
        let Some(segreti) = stato
            .capabilities
            .iter()
            .find(|capacita| capacita.name.contains("segreti"))
        else {
            panic!("la protezione dei segreti deve essere interrogata");
        };
        assert!(
            segreti.availability.is_usable(),
            "la protezione dei segreti non funziona su questa postazione: {}",
            segreti.detail
        );
    }
}
