//! «Scopri NEXUM», il tour guidato (TOUR-01, ADR-0134, DEC-378).
//!
//! # Che cosa fa questo servizio
//!
//! Tre cose, e nient'altro:
//!
//! - **dice quali passaggi mostrare** a chi guarda, secondo la modalità della
//!   postazione e il modo del processo, con i testi già scritti;
//! - **conserva a che punto è il tour** nella riga di `tour_state` (migrazione
//!   0057);
//! - **dice se proporre il tour da sé**, una volta sola.
//!
//! # Che cosa non fa, per costruzione
//!
//! Il tour **mostra e non tocca**. Questo modulo non conosce l'autorità di
//! acquisizione, il connettore di Telegram, il resolver, il pacchetto di
//! evidenze o l'audit: una guardia lo verifica leggendo il sorgente. Le sue sole
//! scritture sono la riga del tour. Che l'interfaccia del tour non prema alcun
//! comando lo verifica un'altra guardia, nel crate dell'interfaccia.
//!
//! # Perché i testi stanno qui
//!
//! Perché sono la parte del tour che cambia con il prodotto, e qui si provano:
//! ogni passo nomina una zona e un luogo, mai coordinate. Dove la zona si trovi
//! sullo schermo lo decide il disegno.

use lisi_core::Timestamp;
use lisi_core::model::tour::{TOUR_VERSION, TourPhase, TourRecord, TourStatus, TourStepKey};
use lisi_storage::Database;

use crate::error::ServiceResult;

/// Il luogo del programma in cui un passo porta. Il crate dell'interfaccia lo
/// traduce nella schermata, come fa per il controllo di avvio.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TourPlace {
    /// Dove si trova la persona: il passo non cambia schermata.
    Here,
    /// QUADRO › Dashboard.
    Dashboard,
    /// AMMINISTRARE › Account.
    Account,
    /// PREPARARE › Fonti.
    Sources,
    /// PREPARARE › Dizionari (COLLAUDO-FIX-01, CU01-002, DEC-511): la novità
    /// delle espressioni e dei codici porta lì.
    Dictionaries,
    /// AMMINISTRARE › Postazione.
    Station,
    /// AMMINISTRARE › Diagnostica.
    Diagnostics,
    /// AMMINISTRARE › Impostazioni.
    Settings,
    /// AIUTO › Guida, dove si apre l'Esercitazione (F-20).
    Guide,
    /// SORVEGLIARE › Nuovo monitoraggio.
    NewMonitoring,
    /// SORVEGLIARE › Monitoraggio.
    Monitoring,
    /// SORVEGLIARE › Coda di lavoro.
    WorkQueue,
    /// SORVEGLIARE › Segnali cyber.
    CyberWatch,
    /// ESAMINARE › Storico.
    History,
    /// ESAMINARE › Raccoglitori.
    Workspace,
    /// APPROFONDIRE › Persone.
    People,
    /// APPROFONDIRE › Ricerca puntuale.
    Lookup,
    /// APPROFONDIRE › Riferimenti informatici.
    References,
    /// PRODURRE › Report.
    Report,
    /// UFFICIO › Live condiviso.
    SharedLive,
}

/// Che cosa si illumina (ADR-0134 §7).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TourZone {
    /// La voce del menu del luogo.
    MenuItem,
    /// La schermata aperta, intera.
    Content,
    /// La voce «Scopri NEXUM».
    DiscoverEntry,
    /// La testata, sopra il menu e la schermata: account, modalità, avvisi e
    /// «Pronto per lavorare».
    Status,
}

/// Per chi è un passo.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TourAudience {
    /// Per chiunque.
    Everyone,
    /// Solo in modalità amministratore (ADR-0134 §12).
    Administrator,
}

/// Che cosa deve esserci, su questa postazione, perché il passo abbia senso.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TourRequirement {
    /// Niente: il luogo esiste sempre.
    Nothing,
    /// I servizi della squadra collegati: in Esercitazione non lo sono.
    TeamServices,
}

/// Un passo del tour.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TourStep {
    /// La chiave stabile, quella che si conserva.
    pub key: &'static str,
    /// Dove porta.
    pub place: TourPlace,
    /// Che cosa si illumina.
    pub zone: TourZone,
    /// Il titolo, corto.
    pub title: &'static str,
    /// Due o tre frasi brevi.
    pub body: &'static str,
    /// Una frase in più, solo in Esercitazione.
    pub exercise_note: &'static str,
    /// Per chi.
    pub audience: TourAudience,
    /// Che cosa deve esserci.
    pub requires: TourRequirement,
}

impl TourStep {
    const fn everyone(
        key: &'static str,
        place: TourPlace,
        zone: TourZone,
        title: &'static str,
        body: &'static str,
    ) -> Self {
        Self {
            key,
            place,
            zone,
            title,
            body,
            exercise_note: "",
            audience: TourAudience::Everyone,
            requires: TourRequirement::Nothing,
        }
    }

    const fn administrator(
        key: &'static str,
        place: TourPlace,
        title: &'static str,
        body: &'static str,
    ) -> Self {
        Self {
            key,
            place,
            zone: TourZone::MenuItem,
            title,
            body,
            exercise_note: "",
            audience: TourAudience::Administrator,
            requires: TourRequirement::Nothing,
        }
    }
}

/// Il percorso comune, nell'ordine del **primo uso** (ADR-0134 §11, rivisto da
/// OPERATOR-E2E-REMEDIATION-01, F-20). L'ultimo passo, [`LAST_STEP`], si
/// aggiunge in fondo, dopo l'estensione dell'amministratore.
///
/// # La forma impersonale (UX-EXCELLENCE-02, SIM3-23)
///
/// Il tour dava del «tu», e il resto del programma parla in forma
/// impersonale («Scegliere…», «Si ritrova…»): chi passava dal fumetto alla
/// schermata cambiava interlocutore. Ora parla come il programma.
///
/// # L'ordine delle dipendenze, non quello del menu (F-20)
///
/// Seguiva il menu, e il menu mette prima ciò che si fa ogni giorno
/// (ADR-0138): così «Nuovo monitoraggio» arrivava al secondo passo, le Fonti al
/// quattordicesimo e l'Account al diciassettesimo, e chi seguiva il tour il
/// primo giorno provava ad avviare un monitoraggio senza fonti né accesso. Ora
/// l'ordine è quello in cui le cose servono: dove esercitarsi, l'accesso, le
/// fonti, poi il monitoraggio e il lavoro che ne viene. L'Account è per tutti,
/// come la sua configurazione (ADR-0140).
pub const COMMON_STEPS: [TourStep; 15] = [
    TourStep::everyone(
        "dashboard",
        TourPlace::Dashboard,
        TourZone::Status,
        "Pronto per lavorare",
        "Il turno comincia da qui. La riga in alto dice se la postazione è pronta e, \
         se manca qualcosa, che cosa fare e dove. Sotto, il Cruscotto riassume il lavoro.",
    ),
    TourStep {
        exercise_note: "Questa finestra è già l'Esercitazione: il comando compare solo \
                        nella finestra di lavoro.",
        ..TourStep::everyone(
            "esercitazione",
            TourPlace::Guide,
            TourZone::MenuItem,
            "Esercitarsi senza rischi",
            "Per imparare c'è l'Esercitazione: messaggi di prova, avvisi e documenti, in \
             un archivio separato e senza Telegram. Si apre dalla Guida, con «Apri \
             l'Esercitazione».",
        )
    },
    TourStep {
        exercise_note: "In Esercitazione l'account non serve.",
        ..TourStep::everyone(
            "account",
            TourPlace::Account,
            TourZone::MenuItem,
            "Account",
            "Qui si collega l'account d'ufficio, il primo passo del lavoro vero. Il \
             programma non mostra mai codici e password.",
        )
    },
    TourStep::everyone(
        "fonti",
        TourPlace::Sources,
        TourZone::MenuItem,
        "Fonti",
        "Qui stanno i canali e i gruppi che l'account d'ufficio può già leggere. Il \
         programma non entra in gruppi e non scrive.",
    ),
    TourStep::everyone(
        "nuovo_monitoraggio",
        TourPlace::NewMonitoring,
        TourZone::MenuItem,
        "Nuovo monitoraggio",
        "Qui si prepara un monitoraggio: le fonti, i dizionari e la durata. Si avvia \
         con «Avvia monitoraggio», all'ultimo passo.",
    ),
    TourStep::everyone(
        "monitoraggio",
        TourPlace::Monitoring,
        TourZone::Content,
        "Monitoraggio",
        "Qui si segue il monitoraggio in corso e lo si arresta. «Sospendi avvisi» fa \
         tacere le notifiche, ma la raccolta continua. «Cerca cosa manca» trova i \
         messaggi arrivati mentre il programma non ascoltava, e li archivia solo dopo \
         una conferma.",
    ),
    TourStep::everyone(
        "coda_di_lavoro",
        TourPlace::WorkQueue,
        TourZone::MenuItem,
        "Coda di lavoro",
        "Qui si vede che cosa guardare, e in che ordine: i messaggi da esaminare di \
         tutti i monitoraggi. Ci sono anche i periodi in cui il programma non \
         ascoltava, se ce ne sono. Recuperarli o no lo decide l'operatore.",
    ),
    TourStep::everyone(
        "storico",
        TourPlace::History,
        TourZone::MenuItem,
        "Storico",
        "Qui stanno tutti i messaggi raccolti, anche quelli di livello 0. «Avvisi» \
         mostra solo quelli dal livello 1 in su.",
    ),
    TourStep::everyone(
        "perche_vedo_questo",
        TourPlace::History,
        TourZone::Content,
        "Perché vedo questo, chi lo dice",
        "Su ogni messaggio, «Perché vedo questo?» spiega che cosa lo ha fatto comparire e \
         che cosa non significa. Ogni dato dice anche chi lo afferma: Osservato è Telegram, \
         Calcolato è una regola del programma, Operatore è una persona.",
    ),
    TourStep::everyone(
        "cyber_watch",
        TourPlace::CyberWatch,
        TourZone::MenuItem,
        "Segnali cyber",
        "Qui il programma raccoglie in gruppi i messaggi che parlano di attacchi \
         informatici. Un gruppo è un invito a guardare, non una conclusione.",
    ),
    TourStep::everyone(
        "workspace",
        TourPlace::Workspace,
        TourZone::MenuItem,
        "Raccoglitori",
        "Un raccoglitore raccoglie il lavoro su un caso. In fondo alla stessa pagina \
         si prepara il pacchetto di evidenze, con i soli messaggi spuntati.",
    ),
    TourStep::everyone(
        "report",
        TourPlace::Report,
        TourZone::MenuItem,
        "Report",
        "Qui si produce la relazione di un monitoraggio. Alla fine, «Apri la cartella» \
         mostra i file prodotti; «Verifica» controlla poi che un documento non sia \
         cambiato.",
    ),
    TourStep::everyone(
        "persone",
        TourPlace::People,
        TourZone::MenuItem,
        "Persone",
        "Qui si apre un fascicolo su un soggetto, sempre con una ragione scritta. Il \
         programma non unisce mai da solo due identità e non dà punteggi di pericolosità.",
    ),
    TourStep {
        // Diceva «In Esercitazione la risposta è inventata»: era falso, in
        // Esercitazione la ricerca non parte (OPERATOR-SIM-01, OS-03).
        exercise_note: "In Esercitazione la ricerca non parte: il programma non \
                        contatta Telegram. Qui si vede soltanto dove si trova.",
        ..TourStep::everyone(
            "ricerca_puntuale",
            TourPlace::Lookup,
            TourZone::MenuItem,
            "Ricerca puntuale",
            "Qui si chiede a Telegram che cosa sa di un nome utente o di un \
             identificativo. Serve sempre una ragione, e la risposta dice anche che \
             cosa manca.",
        )
    },
    TourStep::everyone(
        "consegne",
        TourPlace::Dashboard,
        TourZone::Content,
        "Passaggio di consegne",
        "A fine turno, in fondo al Cruscotto, il riquadro «Passaggio di consegne» \
         compone il riepilogo per chi arriva. Non contiene testi di messaggi né nomi di \
         persone.",
    ),
];

/// L'estensione dell'amministratore: si aggiunge prima dell'ultimo passo, e
/// solo in modalità amministratore (ADR-0134 §12).
pub const ADMINISTRATOR_STEPS: [TourStep; 4] = [
    TourStep::administrator(
        "postazione",
        TourPlace::Station,
        "Postazione",
        "Qui si passa dalla modalità operatore a quella amministratore, e ritorno. Le \
         cinque azioni riservate chiedono la modalità amministratore.",
    ),
    TourStep::administrator(
        "impostazioni",
        TourPlace::Settings,
        "Impostazioni",
        "Qui si scelgono notifiche, blocco, copia di sicurezza, conservazione e \
         aggiornamenti. L'indice in cima porta alla sezione.",
    ),
    TourStep::administrator(
        "diagnostica",
        TourPlace::Diagnostics,
        "Diagnostica",
        "Qui si legge lo stato tecnico della postazione, quando qualcosa non va.",
    ),
    TourStep {
        requires: TourRequirement::TeamServices,
        ..TourStep::administrator(
            "live_condiviso",
            TourPlace::SharedLive,
            "Live condiviso",
            "Se l'ufficio usa un Hub, da qui si collega una postazione con il foglietto \
             di arruolamento.",
        )
    },
];

/// L'ultimo passo: dove rifare il tour. Non cambia schermata.
pub const LAST_STEP: TourStep = TourStep::everyone(
    "scopri_nexum",
    TourPlace::Here,
    TourZone::DiscoverEntry,
    "Scopri NEXUM",
    "Il tour finisce qui. Si può rifare in qualunque momento da questa voce, in fondo \
     al menu. Le parole del programma sono spiegate nella Guida.",
);

/// I fatti della postazione da cui dipende il percorso. Li fornisce chi chiama,
/// dai servizi che li possiedono: questo modulo non li ricava.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TourContext {
    /// La postazione è in modalità amministratore, all'avvio del tour.
    pub administrator: bool,
    /// Il processo è in Esercitazione.
    pub exercise: bool,
    /// I servizi della squadra sono collegati.
    pub team_services: bool,
}

/// Perché un passo non si mostra.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SkipReason {
    /// È un passo dell'amministratore e la postazione è in modalità operatore.
    NotAdministrator,
    /// Il luogo non è collegato su questa postazione.
    NotConnected,
}

/// Se un passo si mostra, e se no perché.
pub fn applies(step: &TourStep, context: &TourContext) -> Result<(), SkipReason> {
    if step.audience == TourAudience::Administrator && !context.administrator {
        return Err(SkipReason::NotAdministrator);
    }
    if step.requires == TourRequirement::TeamServices && !context.team_services {
        return Err(SkipReason::NotConnected);
    }
    Ok(())
}

/// I passi da mostrare, già filtrati, nell'ordine (ADR-0134 §11-§14).
///
/// Un passo che non si applica si salta e il motivo va nel registro tecnico: non
/// si mostra all'operatore, e non si simula una funzione che non c'è.
#[must_use]
pub fn steps(context: &TourContext) -> Vec<TourStep> {
    COMMON_STEPS
        .iter()
        .chain(ADMINISTRATOR_STEPS.iter())
        .chain(core::iter::once(&LAST_STEP))
        .filter(|step| match applies(step, context) {
            Ok(()) => true,
            Err(motivo) => {
                tracing::debug!(passo = step.key, ?motivo, "passo del tour saltato");
                false
            }
        })
        .copied()
        .collect()
}

/// Che cosa offre il pannello di Scopri NEXUM (ADR-0134 §5).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PanelOffer {
    /// «Avvia il tour».
    Start,
    /// «Continua il tour» e «Ricomincia da capo».
    Continue,
    /// «Rifai il tour».
    Redo,
}

/// Il servizio del tour.
#[derive(Debug)]
pub struct TourService {
    database: Database,
}

impl TourService {
    /// Crea il servizio attorno al database indicato.
    #[must_use]
    pub const fn new(database: Database) -> Self {
        Self { database }
    }

    /// Lo stato conservato.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se la lettura non riesce.
    pub fn status(&self) -> ServiceResult<TourStatus> {
        Ok(self.database.tour_state()?)
    }

    /// Se proporre il tour da sé, adesso (ADR-0134 §2, §13).
    ///
    /// Soltanto se **non è mai stato proposto**, e mai in Esercitazione. Che la
    /// domanda del primo avvio abbia una risposta lo verifica l'interfaccia, che
    /// mostra la proposta solo sulla Dashboard operativa: prima della risposta
    /// la Dashboard non c'è.
    #[must_use]
    pub fn should_propose(status: &TourStatus, context: &TourContext) -> bool {
        !context.exercise && *status == TourStatus::NeverProposed
    }

    /// Se mostrare «Nuovo» accanto alla voce: il tour è stato proposto e
    /// nessuno ha ancora scelto (ADR-0134 §3).
    #[must_use]
    pub fn shows_new(status: &TourStatus) -> bool {
        status.phase() == Some(TourPhase::Proposed)
    }

    /// Se chi ha completato il tour ne ha completato una versione precedente:
    /// la base di un futuro «Scopri cosa è cambiato» (ADR-0134 §10). Oggi è
    /// sempre falso, perché esiste una versione sola.
    #[must_use]
    pub fn has_news(status: &TourStatus) -> bool {
        status
            .completed_version()
            .is_some_and(|completata| completata < TOUR_VERSION)
    }

    /// Che cosa offre il pannello.
    #[must_use]
    pub fn panel_offer(status: &TourStatus) -> PanelOffer {
        match status {
            TourStatus::Recorded(TourRecord {
                phase: TourPhase::InProgress,
                last_step: Some(_),
                ..
            }) => PanelOffer::Continue,
            TourStatus::Recorded(TourRecord {
                completed_version: Some(_),
                ..
            }) => PanelOffer::Redo,
            _ => PanelOffer::Start,
        }
    }

    /// Da quale passo continuare: quello conservato, se c'è ancora nell'elenco
    /// di chi guarda; altrimenti dall'inizio (ADR-0134 §10).
    #[must_use]
    pub fn resume_index(status: &TourStatus, steps: &[TourStep]) -> usize {
        let TourStatus::Recorded(TourRecord {
            phase: TourPhase::InProgress,
            last_step: Some(passo),
            ..
        }) = status
        else {
            return 0;
        };
        steps
            .iter()
            .position(|step| step.key == passo.as_str())
            .unwrap_or_else(|| {
                tracing::info!(
                    passo = %passo,
                    "passo del tour conservato non più nell'elenco: si ricomincia"
                );
                0
            })
    }

    /// La proposta del primo avvio è comparsa: da adesso non ricompare da sé.
    ///
    /// Non cambia nulla se una riga esiste già.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se la lettura o la scrittura non riescono.
    pub fn mark_proposed(&self, now: Timestamp) -> ServiceResult<()> {
        if self.status()? == TourStatus::NeverProposed {
            self.write(TourPhase::Proposed, None, None, now)?;
        }
        Ok(())
    }

    /// «Salta per ora», oppure il pannello aperto su un tour proposto: il tour
    /// non si ripropone da sé, e «Nuovo» sparisce.
    ///
    /// Un tour in corso o completato resta com'è: aprire il pannello non deve
    /// perdere il punto in cui si era, né il fatto di averlo finito.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se la lettura o la scrittura non riescono.
    pub fn skip(&self, now: Timestamp) -> ServiceResult<()> {
        let stato = self.status()?;
        match stato.phase() {
            None | Some(TourPhase::Proposed) => {
                self.write(TourPhase::Skipped, None, stato.completed_version(), now)
            }
            Some(TourPhase::Skipped | TourPhase::InProgress | TourPhase::Completed) => Ok(()),
        }
    }

    /// Il tour ha raggiunto un passo: lo si conserva, per «Continua il tour».
    ///
    /// # Errori
    ///
    /// Restituisce un errore se la chiave non ha la forma ammessa o se la
    /// scrittura non riesce.
    pub fn reach(&self, key: &str, now: Timestamp) -> ServiceResult<()> {
        let Some(passo) = TourStepKey::parse(key) else {
            return Err(lisi_core::DomainError::UnknownVariant {
                kind: "passo del tour",
                value: key.chars().take(64).collect(),
            }
            .into());
        };
        let completata = self.status()?.completed_version();
        self.write(TourPhase::InProgress, Some(passo), completata, now)
    }

    /// Il tour è arrivato in fondo.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se la scrittura non riesce.
    pub fn complete(&self, now: Timestamp) -> ServiceResult<()> {
        self.write(TourPhase::Completed, None, Some(TOUR_VERSION), now)
    }

    fn write(
        &self,
        phase: TourPhase,
        last_step: Option<TourStepKey>,
        completed_version: Option<u32>,
        now: Timestamp,
    ) -> ServiceResult<()> {
        let record = TourRecord {
            phase,
            tour_version: TOUR_VERSION,
            last_step,
            completed_version,
        };
        self.database.save_tour_state(&record, now.as_millis())?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use lisi_core::Timestamp;
    use lisi_core::model::tour::{TOUR_VERSION, TourPhase, TourRecord, TourStatus, TourStepKey};
    use lisi_storage::Database;

    use super::{
        ADMINISTRATOR_STEPS, COMMON_STEPS, LAST_STEP, PanelOffer, TourContext, TourService,
        TourZone, steps,
    };

    const OPERATORE: TourContext = TourContext {
        administrator: false,
        exercise: false,
        team_services: true,
    };
    const AMMINISTRATORE: TourContext = TourContext {
        administrator: true,
        exercise: false,
        team_services: true,
    };
    const ESERCITAZIONE: TourContext = TourContext {
        administrator: true,
        exercise: true,
        team_services: false,
    };

    fn servizio() -> TourService {
        let Ok(database) = Database::open_in_memory() else {
            panic!("l'archivio di prova deve aprirsi");
        };
        TourService::new(database)
    }

    fn ora(ms: i64) -> Timestamp {
        Timestamp::from_millis(ms)
    }

    fn chiavi(contesto: &TourContext) -> Vec<&'static str> {
        steps(contesto).iter().map(|step| step.key).collect()
    }

    /// 1 — **Un profilo nuovo propone il tour**; 2 — mai in Esercitazione.
    #[test]
    fn un_profilo_nuovo_propone_il_tour_e_l_esercitazione_no() {
        let servizio = servizio();
        let Ok(stato) = servizio.status() else {
            panic!("lo stato deve leggersi");
        };
        assert!(TourService::should_propose(&stato, &OPERATORE));
        assert!(!TourService::should_propose(&stato, &ESERCITAZIONE));
    }

    /// 3 — **Una volta proposto, non si ripropone**, comunque sia finita:
    /// saltato, chiuso senza scegliere, iniziato, completato.
    #[test]
    fn un_tour_proposto_o_saltato_non_si_ripropone() {
        let servizio = servizio();
        let Ok(()) = servizio.mark_proposed(ora(1)) else {
            panic!("la proposta deve registrarsi");
        };
        let stato = servizio.status().ok();
        assert_eq!(
            stato.as_ref().and_then(TourStatus::phase),
            Some(TourPhase::Proposed)
        );
        assert!(stato.is_some_and(|s| !TourService::should_propose(&s, &OPERATORE)));

        let Ok(()) = servizio.skip(ora(2)) else {
            panic!("«Salta per ora» deve registrarsi");
        };
        // Dieci «avvii»: la proposta non ricompare.
        for _ in 0..10 {
            let Ok(stato) = servizio.status() else {
                panic!("lo stato deve leggersi");
            };
            assert!(!TourService::should_propose(&stato, &OPERATORE));
            assert!(!TourService::shows_new(&stato));
        }
        // Una seconda proposta non riscrive lo stato.
        let Ok(()) = servizio.mark_proposed(ora(3)) else {
            panic!("la seconda proposta deve essere un nulla di fatto");
        };
        assert_eq!(
            servizio.status().ok().as_ref().and_then(TourStatus::phase),
            Some(TourPhase::Skipped)
        );
    }

    /// «Nuovo» compare su un tour proposto e non scelto, e sparisce saltando.
    #[test]
    fn nuovo_compare_finche_nessuno_sceglie() {
        let servizio = servizio();
        let Ok(()) = servizio.mark_proposed(ora(1)) else {
            panic!("la proposta deve registrarsi");
        };
        assert!(servizio.status().is_ok_and(|s| TourService::shows_new(&s)));
        let Ok(()) = servizio.skip(ora(2)) else {
            panic!("il pannello aperto deve valere come salto");
        };
        assert!(servizio.status().is_ok_and(|s| !TourService::shows_new(&s)));
    }

    /// 5, 6, 7, 8 — **Avvia, interrompi, continua, completa**, e lo stato resta.
    #[test]
    fn avvia_continua_e_completa() {
        let servizio = servizio();
        let percorso = steps(&OPERATORE);
        assert_eq!(
            servizio.status().ok().map(|s| TourService::panel_offer(&s)),
            Some(PanelOffer::Start)
        );

        // Avvia e arriva al sesto passo, poi esce.
        for passo in percorso.iter().take(6) {
            let Ok(()) = servizio.reach(passo.key, ora(10)) else {
                panic!("il passo deve conservarsi");
            };
        }
        let Ok(stato) = servizio.status() else {
            panic!("lo stato deve leggersi");
        };
        assert_eq!(TourService::panel_offer(&stato), PanelOffer::Continue);
        assert_eq!(TourService::resume_index(&stato, &percorso), 5);
        assert!(!TourService::should_propose(&stato, &OPERATORE));

        // Il pannello aperto su un tour in corso non perde il passo.
        let Ok(()) = servizio.skip(ora(11)) else {
            panic!("il pannello deve aprirsi");
        };
        assert_eq!(
            servizio
                .status()
                .ok()
                .map(|s| TourService::resume_index(&s, &percorso)),
            Some(5)
        );

        let Ok(()) = servizio.complete(ora(20)) else {
            panic!("il completamento deve conservarsi");
        };
        let Ok(stato) = servizio.status() else {
            panic!("lo stato deve leggersi");
        };
        assert_eq!(TourService::panel_offer(&stato), PanelOffer::Redo);
        // 9 — Dopo il completamento, nessuna proposta.
        assert!(!TourService::should_propose(&stato, &OPERATORE));
        assert!(!TourService::has_news(&stato));

        // Rifare il tour non perde il fatto di averlo completato.
        let Ok(()) = servizio.reach(percorso[0].key, ora(30)) else {
            panic!("il passo deve conservarsi");
        };
        assert_eq!(
            servizio.status().ok().and_then(|s| s.completed_version()),
            Some(TOUR_VERSION)
        );
    }

    /// 10, 11 — **Un operatore non vede i passi dell'amministratore**;
    /// l'amministratore li vede, prima dell'ultimo.
    #[test]
    fn l_operatore_non_vede_l_estensione_e_l_amministratore_si() {
        let operatore = chiavi(&OPERATORE);
        let amministratore = chiavi(&AMMINISTRATORE);
        for passo in ADMINISTRATOR_STEPS {
            assert!(
                !operatore.contains(&passo.key),
                "«{}» all'operatore",
                passo.key
            );
            assert!(amministratore.contains(&passo.key), "«{}» manca", passo.key);
        }
        assert_eq!(operatore.len(), 16);
        assert_eq!(amministratore.len(), 20);
        assert_eq!(operatore.last(), Some(&LAST_STEP.key));
        assert_eq!(amministratore.last(), Some(&LAST_STEP.key));
        assert_eq!(&amministratore[..15], &operatore[..15], "un nucleo comune");
    }

    /// 12, 14 — **In Esercitazione il passo della squadra si salta**, e il
    /// tour non fallisce.
    #[test]
    fn in_esercitazione_il_passo_della_squadra_si_salta() {
        let esercitazione = chiavi(&ESERCITAZIONE);
        assert!(!esercitazione.contains(&"live_condiviso"));
        assert_eq!(esercitazione.len(), 19);
        let ricerca = steps(&ESERCITAZIONE)
            .into_iter()
            .find(|step| step.key == "ricerca_puntuale");
        assert!(ricerca.is_some_and(|step| step.exercise_note.contains("non contatta Telegram")));
        // OS-03: la nota non promette una risposta che in Esercitazione non arriva.
        assert!(
            steps(&ESERCITAZIONE)
                .into_iter()
                .all(|step| !step.exercise_note.contains("inventata"))
        );
    }

    /// 19 — **Una chiave che non c'è più fa ricominciare**, senza errori: un
    /// passo tolto in una versione futura, o un amministratore diventato
    /// operatore.
    #[test]
    fn una_chiave_che_non_c_e_piu_fa_ricominciare() {
        let percorso = steps(&OPERATORE);
        for chiave in ["diagnostica", "passo_di_una_versione_futura"] {
            let stato = TourStatus::Recorded(TourRecord {
                phase: TourPhase::InProgress,
                tour_version: 7,
                last_step: TourStepKey::parse(chiave),
                completed_version: Some(3),
            });
            assert_eq!(TourService::resume_index(&stato, &percorso), 0);
            assert_eq!(TourService::panel_offer(&stato), PanelOffer::Continue);
            assert!(!TourService::should_propose(&stato, &OPERATORE));
        }
    }

    /// La base delle novità: completato una versione precedente.
    #[test]
    fn una_versione_precedente_completata_e_una_novita() {
        let stato = TourStatus::Recorded(TourRecord {
            phase: TourPhase::Completed,
            tour_version: 1,
            last_step: None,
            completed_version: Some(0),
        });
        assert!(TourService::has_news(&stato));
    }

    #[test]
    fn una_chiave_non_ammessa_si_rifiuta() {
        assert!(servizio().reach("Fonti 2", ora(1)).is_err());
    }

    /// **I passi sono pochi, unici e scritti corti** (ADR-0134 §11, PR-01).
    #[test]
    fn i_passi_sono_pochi_unici_e_corti() {
        let tutti: Vec<_> = COMMON_STEPS
            .iter()
            .chain(ADMINISTRATOR_STEPS.iter())
            .chain(core::iter::once(&LAST_STEP))
            .collect();
        let uniche: BTreeSet<&str> = tutti.iter().map(|step| step.key).collect();
        assert_eq!(uniche.len(), tutti.len(), "due passi con la stessa chiave");
        assert!((12..=16).contains(&(COMMON_STEPS.len() + 1)));
        for step in &tutti {
            assert!(TourStepKey::parse(step.key).is_some(), "«{}»", step.key);
            assert!(
                step.title.chars().count() <= 32,
                "titolo lungo: «{}»",
                step.title
            );
            let frasi = step
                .body
                .split_terminator(['.', '?', '!'])
                .filter(|frase| !frase.trim().is_empty())
                .count();
            assert!(
                (1..=4).contains(&frasi),
                "«{}»: {frasi} frasi, il fumetto ne vuole poche",
                step.key
            );
        }
        assert_eq!(LAST_STEP.zone, TourZone::DiscoverEntry);
    }

    /// **Il servizio del tour non conosce ciò che agisce** (ADR-0134 §1,
    /// controllo negativo D): né l'autorità di acquisizione, né il connettore,
    /// né il resolver, né il pacchetto, né l'audit.
    #[test]
    fn il_servizio_del_tour_non_conosce_cio_che_agisce() {
        let sorgente = include_str!("tour.rs");
        let Some((prodotto, _)) = sorgente.split_once("#[cfg(test)]") else {
            panic!("il modulo di prova deve esistere");
        };
        for vietato in [
            "AcquisitionAuthority",
            "acquisition_authority",
            "OperationalMode",
            "telegram_runtime",
            "lisi_telegram",
            "identity_resolver",
            "evidence_package",
            "interval_recovery",
            "monitoring::",
            "NewAuditEntry",
            "append_audit",
        ] {
            assert!(
                !prodotto.contains(vietato),
                "il servizio del tour nomina «{vietato}»: il tour mostra, e non tocca"
            );
        }
    }
}
