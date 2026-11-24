//! Chi ha il diritto di acquisire da Telegram (TEAM-AUTHORITY-01, ADR-0092).
//!
//! # L'invariante
//!
//! **TDLib sta sull'Hub.** L'acquisizione la esegue una sola autorità, una
//! volta per tutto l'ufficio (freeze §7.10): N client non devono produrre N
//! carichi su Telegram, né N sessioni TDLib per lo stesso account — che
//! Telegram, per lo stesso account, tratterebbe come N dispositivi.
//!
//! # Perché una capacità e non un controllo
//!
//! Un `if` all'inizio della funzione che apre TDLib si può dimenticare in una
//! seconda funzione, e nessuna prova se ne accorgerebbe. [`AcquisitionAuthority`]
//! **non ha un costruttore pubblico**: la produce soltanto
//! [`StationAuthorityService::acquisition_authority`], e aprire il connettore
//! reale la richiede. Una funzione che non si può chiamare senza la cosa giusta
//! non si può chiamare con quella sbagliata — la stessa forma di
//! `AuthenticatedDevice` (ADR-0085) e di `ValidatedDiscoveryPolicy` (ADR-0074).
//!
//! # Che cosa decide il ruolo
//!
//! Soltanto un fatto conservato: **esiste una configurazione dell'Hub su questa
//! postazione?** Se esiste, la postazione segue un Hub e non acquisisce. Se non
//! esiste, la postazione è autorità di sé stessa — Standalone, oppure l'Hub.
//!
//! # Che cosa questo modulo non fa
//!
//! Non parla con l'Hub e non chiede il permesso a nessuno: il rifiuto è una
//! decisione **locale**, e vale anche quando l'Hub è spento o irraggiungibile.
//! Un'autorizzazione che arrivasse dalla rete sarebbe un'autorizzazione che la
//! rete può negare — o concedere.
//!
//! # Una richiesta di recupero senza autorità non compila (PR-07)
//!
//! Il recupero per intervallo (`crate::interval_recovery`) vuole
//! un'[`AcquisitionAuthority`] per costruire la sua richiesta. Fuori da questo
//! modulo il valore non si fabbrica — nemmeno scrivendolo per intero — e la
//! prova qui sotto **deve non compilare**. È il controllo negativo 5 del piano:
//! rendere pubblico il campo la farebbe compilare, e la prova diventerebbe
//! rossa.
//!
//! ```compile_fail
//! use lisi_services::acquisition_authority::AcquisitionAuthority;
//! let _autorita = AcquisitionAuthority { _privato: () };
//! ```

use lisi_core::model::hub_client::StationRole;

use crate::error::ServiceResult;
use crate::hub_client::HubConnectionStore;
use crate::run_mode::{ExerciseMode, OperationalMode};

/// La prova che questa postazione può acquisire da Telegram.
///
/// **Non ha un costruttore pubblico**: la produce soltanto
/// [`StationAuthorityService::acquisition_authority`], dopo aver constatato che
/// la postazione non segue alcun Hub.
#[derive(Debug)]
pub struct AcquisitionAuthority {
    /// Campo privato senza contenuto: rende il tipo **non costruibile** da
    /// fuori, anche con la sintassi letterale.
    _privato: (),
}

/// Chi ha i fatti su cui produrre ciò che esce dall'ufficio.
///
/// Il pacchetto di evidenze (PR-11) nasce dove stanno i fatti: sulla postazione
/// che ha l'autorità di acquisire, e in Esercitazione sull'archivio sintetico,
/// dove nessuno acquisisce e i fatti stanno comunque tutti lì (PR-13). Il
/// tratto è **sigillato**: nessun altro tipo lo implementa, e un client Team
/// non ha né l'una né l'altra prova.
pub trait HoldsTheFacts: sealed::Sealed {}

/// Il sigillo di [`HoldsTheFacts`].
mod sealed {
    /// Implementato soltanto dai due testimoni di questo crate.
    pub trait Sealed {}
}

impl sealed::Sealed for AcquisitionAuthority {}
impl HoldsTheFacts for AcquisitionAuthority {}
impl sealed::Sealed for ExerciseMode {}
impl HoldsTheFacts for ExerciseMode {}

/// L'esito della domanda «questa postazione può acquisire?».
#[derive(Debug)]
pub enum AuthorityOutcome {
    /// Può: la postazione è autorità di sé stessa.
    Granted(AcquisitionAuthority),
    /// Non può, e la frase dice perché e dove il lavoro viene fatto.
    Refused {
        /// Che cosa la postazione è.
        role: StationRole,
        /// La frase per l'operatore.
        message: &'static str,
    },
}

impl AuthorityOutcome {
    /// L'autorità, se concessa.
    #[must_use]
    pub const fn granted(&self) -> Option<&AcquisitionAuthority> {
        match self {
            Self::Granted(autorita) => Some(autorita),
            Self::Refused { .. } => None,
        }
    }

    /// L'autorità, se concessa, portata via dall'esito.
    ///
    /// Serve a chi deve **conservarla** — l'interfaccia la ottiene una volta e
    /// la tiene per la durata della sessione — invece di riottenerla a ogni
    /// apertura di runtime.
    #[must_use]
    pub fn into_granted(self) -> Option<AcquisitionAuthority> {
        match self {
            Self::Granted(autorita) => Some(autorita),
            Self::Refused { .. } => None,
        }
    }

    /// La frase per l'operatore quando è stata rifiutata.
    #[must_use]
    pub const fn refusal_message(&self) -> Option<&'static str> {
        match self {
            Self::Granted(_) => None,
            Self::Refused { message, .. } => Some(*message),
        }
    }
}

/// Che cosa questa postazione è, e che cosa le spetta.
#[derive(Debug)]
pub struct StationAuthorityService {
    connection: HubConnectionStore,
}

impl StationAuthorityService {
    /// Costruisce il servizio sulla configurazione dell'Hub indicata.
    #[must_use]
    pub const fn new(connection: HubConnectionStore) -> Self {
        Self { connection }
    }

    /// Il servizio sulla configurazione dell'Hub che vive nella cartella
    /// indicata, accanto agli altri file protetti della postazione.
    ///
    /// È l'ingresso che usa l'interfaccia: il confine di ADR-0010 le vieta di
    /// nominare `ProtectedStore`, e passare un percorso è tutto ciò che le
    /// serve.
    #[must_use]
    pub fn in_directory(base: &std::path::Path) -> Self {
        Self::new(HubConnectionStore::in_directory(base))
    }

    /// Il ruolo di questa postazione.
    ///
    /// **Il file si legge, non si interpreta**: basta la sua presenza. Leggerne
    /// il contenuto per decidere il ruolo renderebbe «configurazione
    /// illeggibile» indistinguibile da «nessun Hub», cioè farebbe tornare ad
    /// acquisire una postazione che segue un Hub.
    #[must_use]
    pub fn role(&self) -> StationRole {
        StationRole::of_station(self.connection.exists())
    }

    /// Chiede l'autorità di acquisire da Telegram.
    ///
    /// Vuole il **testimone operativo** (PR-13, ADR-0129): in Esercitazione
    /// quel valore non esiste, e l'autorità non si chiede nemmeno.
    ///
    /// # Errori
    ///
    /// Non ne restituisce: il ruolo si decide su un fatto che esiste sempre —
    /// il file c'è o non c'è. La firma resta un `ServiceResult` perché chi
    /// chiama la compone con letture che possono fallire, e perché un domani il
    /// ruolo potrebbe dipendere da altro.
    pub fn acquisition_authority(
        &self,
        _modo: &OperationalMode,
    ) -> ServiceResult<AuthorityOutcome> {
        let ruolo = self.role();
        if ruolo.may_acquire() {
            return Ok(AuthorityOutcome::Granted(AcquisitionAuthority {
                _privato: (),
            }));
        }
        Ok(AuthorityOutcome::Refused {
            role: ruolo,
            message: ruolo.acquisition_message(),
        })
    }
}

#[cfg(test)]
mod tests {
    use lisi_core::model::hub_client::{HubAddress, HubConnection, StationRole};
    use lisi_core::model::hub_identity::{HUB_FINGERPRINT_BYTES, HubExpectation, HubFingerprint};
    use lisi_security::ProtectedStore;

    use super::{AuthorityOutcome, StationAuthorityService};
    use crate::hub_client::HubConnectionStore;

    fn cartella() -> tempfile::TempDir {
        match tempfile::tempdir() {
            Ok(cartella) => cartella,
            Err(errore) => panic!("cartella temporanea: {errore}"),
        }
    }

    fn servizio(cartella: &tempfile::TempDir) -> StationAuthorityService {
        StationAuthorityService::new(HubConnectionStore::at(ProtectedStore::at(
            cartella.path().join("hub-client.protetto"),
        )))
    }

    fn configura(cartella: &tempfile::TempDir) {
        let archivio = HubConnectionStore::at(ProtectedStore::at(
            cartella.path().join("hub-client.protetto"),
        ));
        let Ok(indirizzo) = HubAddress::parse("192.0.2.10:8443") else {
            panic!("indirizzo");
        };
        let impronta = HubFingerprint::from_bytes([5; HUB_FINGERPRINT_BYTES]);
        if archivio
            .save(&HubConnection::new(
                indirizzo,
                HubExpectation::Pinned(impronta),
            ))
            .is_err()
        {
            panic!("la configurazione deve potersi scrivere");
        }
    }

    /// **Il file del client non è il file della chiave dell'Hub.**
    ///
    /// I due vivono nella stessa cartella. Con lo stesso nome, su una
    /// postazione che fa da Hub la presenza della **chiave** si leggerebbe come
    /// «questa postazione segue un Hub», e l'Hub smetterebbe di poter
    /// acquisire. È accaduto: i due nomi coincidevano fino al 2026-09-20.
    #[test]
    fn the_client_configuration_is_not_the_hub_key_file() {
        assert_ne!(
            crate::hub_client::HUB_FILE,
            lisi_security::hub_key::HUB_KEY_FILE,
            "la configurazione del client e la chiave privata dell'Hub non possono avere lo \
             stesso nome: l'Hub si leggerebbe come client di sé stesso"
        );
    }

    #[test]
    fn a_station_without_a_hub_is_the_authority_of_itself() {
        let cartella = cartella();
        let servizio = servizio(&cartella);
        assert_eq!(servizio.role(), StationRole::OwnAuthority);
        let Ok(esito) = servizio.acquisition_authority(&crate::run_mode::operational_for_tests())
        else {
            panic!("l'esito deve esserci");
        };
        assert!(esito.granted().is_some());
        assert_eq!(esito.refusal_message(), None);
    }

    #[test]
    fn a_station_that_follows_a_hub_does_not_acquire() {
        let cartella = cartella();
        configura(&cartella);
        let servizio = servizio(&cartella);
        assert_eq!(servizio.role(), StationRole::HubClient);
        let Ok(esito) = servizio.acquisition_authority(&crate::run_mode::operational_for_tests())
        else {
            panic!("l'esito deve esserci");
        };
        assert!(
            esito.granted().is_none(),
            "una postazione che segue un Hub non deve poter acquisire"
        );
        let Some(frase) = esito.refusal_message() else {
            panic!("il rifiuto deve avere una frase");
        };
        assert!(frase.contains("l'Hub"), "«{frase}»");
        let AuthorityOutcome::Refused { role, .. } = esito else {
            panic!("esito inatteso");
        };
        assert_eq!(role, StationRole::HubClient);
    }

    #[test]
    fn an_unreadable_configuration_does_not_give_the_authority_back() {
        // Un file presente e illeggibile resta un Hub configurato: il ruolo si
        // decide sulla PRESENZA, non sul contenuto. Il contrario farebbe
        // tornare ad acquisire una postazione corrompendole un file.
        let cartella = cartella();
        if std::fs::write(
            cartella.path().join("hub-client.protetto"),
            b"non decifrabile",
        )
        .is_err()
        {
            panic!("il file deve potersi scrivere");
        }
        let servizio = servizio(&cartella);
        assert_eq!(servizio.role(), StationRole::HubClient);
        let Ok(esito) = servizio.acquisition_authority(&crate::run_mode::operational_for_tests())
        else {
            panic!("l'esito deve esserci");
        };
        assert!(esito.granted().is_none());
    }
}
