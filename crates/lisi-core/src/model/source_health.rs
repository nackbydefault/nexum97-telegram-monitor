//! La salute di una fonte: che cosa è stato **osservato**, e che cosa no.
//!
//! # La domanda a cui questo modulo risponde
//!
//! «Questa fonte è ancora monitorata correttamente?» — che non è la stessa
//! domanda di «questa fonte ha pubblicato qualcosa di recente».
//!
//! # Le quattro confusioni che questo modulo esiste per impedire
//!
//! **1. Fonte silenziosa non è fonte guasta.** Un canale può non pubblicare per
//! settimane ed essere perfettamente raggiungibile. L'istante dell'ultimo
//! contenuto entra in [`HealthEvidence`] perché l'operatore vuole vederlo, ma
//! **non entra nella derivazione dello stato**: una prova lo impone.
//!
//! **2. Assenza di evidenza non è evidenza di salute.** Una fonte mai
//! verificata è [`SourceHealth::Unknown`], non «operativa perché non risultano
//! errori».
//!
//! **3. Non aver potuto verificare non è aver verificato un guasto.** Se
//! l'elenco delle chat non si è potuto leggere — rete assente, sessione non
//! autenticata, errore temporaneo — non si è appreso **nulla** su alcuna fonte.
//! Il tentativo fallito si registra, ma lo stato resta quello dell'ultima
//! osservazione **conclusiva**, e l'evidenza dice quanti tentativi non sono
//! riusciti da allora.
//!
//! **4. Spenta per scelta non è guasta.** Una fonte disattivata
//! dall'operatore è [`SourceHealth::Stopped`], che non è una condizione da
//! attenzionare.
//!
//! # Perché non c'è alcuna soglia di tempo
//!
//! La tentazione è far «scadere» una verifica riuscita dopo N giorni. Non si
//! fa: **N sarebbe inventato**. Nessun fatto del prodotto, di Telegram o
//! dell'ufficio dice quando un'osservazione smetta di valere.
//!
//! Lo stato dice **che cosa è stato osservato**; l'istante dell'osservazione
//! viaggia sempre accanto, e chi legge giudica se sia abbastanza recente. È la
//! stessa scelta di ADR-0051: dichiarare invece di correggere.
//!
//! # Perché la condizione dell'account è evidenza e non stato
//!
//! Un account non autorizzato non cambia ciò che fu osservato della chat:
//! cambia se il monitoraggio possa funzionare **adesso**. La distinzione
//! attraversa tutto questo prodotto, e riscriverla qui la perderebbe. Il
//! pannello lo dichiara in testa; la derivazione non lo usa.

use crate::time::Timestamp;

/// Che cosa una verifica ha appreso di una fonte.
///
/// # Perché un tentativo non riuscito è una variante e non un errore
///
/// Perché è un fatto della storia della fonte: dice che il prodotto **ha
/// provato** e non c'è riuscito. Perderlo farebbe sembrare che nessuno abbia
/// mai provato, che è un'altra cosa.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HealthCheckOutcome {
    /// La chat è fra quelle accessibili all'account e ne è leggibile lo storico.
    Reachable,
    /// La chat è accessibile, ma l'account non può leggerne lo storico.
    ///
    /// Accessibile e inutile: il monitoraggio non può fare il proprio mestiere.
    HistoryUnreadable,
    /// L'elenco è stato letto **e la chat non c'era**.
    ///
    /// Non è un errore di rete: è una risposta. L'account non ha più accesso a
    /// quella chat — può essere stato rimosso, la chat può essere stata
    /// eliminata, o l'identificativo può non essere più risolvibile. Quale dei
    /// tre lo dice il dettaglio, non questa variante.
    NotAccessible,
    /// L'elenco non si è potuto leggere.
    ///
    /// **Non dice nulla della fonte.** Rete assente, sessione non autenticata,
    /// limite di frequenza, errore temporaneo: in tutti questi casi il prodotto
    /// non ha appreso niente, e fingere che abbia appreso un guasto sarebbe la
    /// falsa attribuzione che questo modulo esiste per impedire.
    CheckFailed,
}

impl HealthCheckOutcome {
    /// Forma conservata nell'archivio.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Reachable => "reachable",
            Self::HistoryUnreadable => "history_unreadable",
            Self::NotAccessible => "not_accessible",
            Self::CheckFailed => "check_failed",
        }
    }

    /// Ricostruisce l'esito dalla forma conservata.
    #[must_use]
    pub fn from_stored(value: &str) -> Option<Self> {
        match value {
            "reachable" => Some(Self::Reachable),
            "history_unreadable" => Some(Self::HistoryUnreadable),
            "not_accessible" => Some(Self::NotAccessible),
            "check_failed" => Some(Self::CheckFailed),
            _ => None,
        }
    }

    /// Se l'esito dice qualcosa **della fonte**.
    ///
    /// Un tentativo non riuscito non è conclusivo: aggiorna quando si è
    /// provato, non che cosa si è appreso.
    #[must_use]
    pub const fn is_conclusive(self) -> bool {
        !matches!(self, Self::CheckFailed)
    }

    /// Frase che dice all'operatore che cosa è stato osservato.
    #[must_use]
    pub const fn as_sentence(self) -> &'static str {
        match self {
            Self::Reachable => {
                "la fonte risultava fra le chat accessibili all'account, con lo storico leggibile"
            }
            Self::HistoryUnreadable => {
                "la fonte risultava accessibile, ma l'account non poteva leggerne lo storico"
            }
            Self::NotAccessible => {
                "l'elenco delle chat accessibili è stato letto e la fonte non vi compariva"
            }
            Self::CheckFailed => {
                "la verifica non è riuscita: non è stato possibile leggere l'elenco delle chat"
            }
        }
    }

    /// Che cosa la riga dice **della fonte**, che non è come è andato il
    /// tentativo.
    ///
    /// # Perché [`Self::as_sentence`] non basta
    ///
    /// Perché in un elenco di righe tutte uguali quattro «la verifica non è
    /// riuscita» si leggono come **quattro guasti della fonte**, ed è
    /// esattamente la falsa attribuzione che questo modulo esiste per
    /// impedire. La frase dice come è andato il tentativo; questa dice che
    /// cosa se ne è appreso, e per un tentativo non riuscito la risposta è
    /// **nulla**.
    #[must_use]
    pub const fn note_about_source(self) -> &'static str {
        match self {
            Self::Reachable => "Osservazione conclusiva: la fonte era raggiungibile.",
            Self::HistoryUnreadable => {
                "Osservazione conclusiva: accessibile, ma senza storico leggibile."
            }
            Self::NotAccessible => {
                "Osservazione conclusiva: l'account non aveva accesso alla fonte."
            }
            Self::CheckFailed => {
                "Non conclusiva: non si è appreso nulla di questa fonte, e nessuno \
                 stato è cambiato."
            }
        }
    }
}

/// Stato di salute di una fonte monitorata.
///
/// I cinque stati sono quelli del congelamento di prodotto. Nessuno di essi si
/// assegna senza un criterio verificabile, e nessuno dipende da quanti
/// contenuti la fonte abbia prodotto.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum SourceHealth {
    /// Verificata di recente e senza anomalie da allora.
    Operational,
    /// Verificata, ma qualcosa non funziona come dovrebbe.
    Degraded,
    /// L'account non ha più accesso alla fonte.
    Failed,
    /// Mai verificata in modo conclusivo: non se ne può rispondere.
    Unknown,
    /// Disattivata dall'operatore. **Non è un guasto.**
    Stopped,
}

impl SourceHealth {
    /// Tutti gli stati, nell'ordine in cui si presentano.
    pub const ALL: &'static [Self] = &[
        Self::Operational,
        Self::Degraded,
        Self::Failed,
        Self::Unknown,
        Self::Stopped,
    ];

    /// Parola con cui l'operatore lo legge.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Operational => "Operativa",
            Self::Degraded => "Degradata",
            Self::Failed => "In errore",
            Self::Unknown => "Sconosciuta",
            Self::Stopped => "Ferma",
        }
    }

    /// Se lo stato chiede a una persona di guardare.
    ///
    /// # Perché «Sconosciuta» non chiede attenzione e «Ferma» nemmeno
    ///
    /// Una fonte mai verificata non è un guasto: è una fonte di cui non si sa
    /// ancora nulla, e dipingerla di rosso insegnerebbe a ignorare il rosso.
    /// Una fonte spenta dall'operatore è esattamente ciò che l'operatore ha
    /// voluto.
    #[must_use]
    pub const fn needs_attention(self) -> bool {
        matches!(self, Self::Degraded | Self::Failed)
    }

    /// Se lo stato dipende da una scelta dell'operatore invece che da un fatto
    /// tecnico.
    #[must_use]
    pub const fn is_intentional(self) -> bool {
        matches!(self, Self::Stopped)
    }
}

/// I fatti osservati da cui lo stato deriva.
///
/// # Che cosa NON entra nella derivazione, e perché è qui
///
/// [`Self::last_content_at`] e [`Self::account_authorised`] sono presenti
/// perché l'operatore deve vederli, e **assenti dalla derivazione** perché non
/// dicono nulla della salute della fonte:
///
/// - il silenzio di un canale non è un guasto del canale;
/// - un account non autorizzato non cambia ciò che fu osservato della chat,
///   cambia se il monitoraggio possa funzionare adesso.
///
/// Due prove lo impongono, e due controlli negativi le hanno viste rosse.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HealthEvidence {
    /// Se la fonte è selezionabile per nuove sessioni.
    pub active: bool,
    /// L'ultima verifica che ha appreso qualcosa, con il suo istante.
    pub last_conclusive: Option<(HealthCheckOutcome, Timestamp)>,
    /// L'istante dell'ultimo tentativo, riuscito o no.
    pub last_attempt_at: Option<Timestamp>,
    /// Tentativi non riusciti dopo l'ultima osservazione conclusiva.
    pub failed_attempts_since: u32,
    /// Guasti attribuiti alla fonte dopo l'ultima osservazione conclusiva.
    pub faults_since: u32,
    /// Istante dell'ultimo contenuto acquisito. **Informativo.**
    pub last_content_at: Option<Timestamp>,
    /// Se l'account della fonte risulta autorizzato. **Informativo.**
    ///
    /// `None` quando la fonte non è associata ad alcun account.
    pub account_authorised: Option<bool>,
}

impl HealthEvidence {
    /// Evidenza di una fonte appena configurata, di cui non si sa nulla.
    #[must_use]
    pub const fn never_checked(active: bool) -> Self {
        Self {
            active,
            last_conclusive: None,
            last_attempt_at: None,
            failed_attempts_since: 0,
            faults_since: 0,
            last_content_at: None,
            account_authorised: None,
        }
    }

    /// Istante dell'ultima osservazione conclusiva, quando ce n'è stata una.
    #[must_use]
    pub fn last_conclusive_at(&self) -> Option<Timestamp> {
        self.last_conclusive.map(|(_, instant)| instant)
    }
}

/// Deriva lo stato di salute dai fatti osservati.
///
/// La funzione è **pura**: stessa evidenza, stesso stato. È la proprietà su cui
/// si regge la ripetibilità della schermata, e la ragione per cui una prova può
/// percorrere tutti i casi senza un archivio.
///
/// # L'ordine delle regole, che non è arbitrario
///
/// 1. **Ferma** vince su tutto: una fonte spenta dall'operatore non si giudica.
/// 2. Senza un'osservazione conclusiva è **Sconosciuta**, comunque siano andati
///    i tentativi.
/// 3. Poi conta **che cosa** l'ultima osservazione conclusiva ha appreso.
/// 4. E infine se, da allora, qualcosa è andato storto.
#[must_use]
pub fn derive(evidence: &HealthEvidence) -> SourceHealth {
    // 1. La scelta dell'operatore precede ogni giudizio tecnico.
    if !evidence.active {
        return SourceHealth::Stopped;
    }

    // 2. Nessuna osservazione conclusiva: non se ne puo' rispondere. I
    //    tentativi non riusciti non cambiano nulla — non hanno appreso niente.
    let Some((outcome, _)) = evidence.last_conclusive else {
        return SourceHealth::Unknown;
    };

    match outcome {
        // 3. L'account non ha piu' accesso: e' una risposta, non un errore di
        //    rete, e non decade con il tempo.
        HealthCheckOutcome::NotAccessible => SourceHealth::Failed,
        // Accessibile ma inutile: il monitoraggio non puo' fare il proprio
        // mestiere, e non e' un guasto della rete.
        HealthCheckOutcome::HistoryUnreadable => SourceHealth::Degraded,
        // 4. Raggiungibile. Degradata solo se DOPO quell'osservazione qualcosa
        //    e' andato storto: guasti attribuiti alla fonte, o tentativi di
        //    verifica non riusciti.
        HealthCheckOutcome::Reachable => {
            if evidence.faults_since > 0 || evidence.failed_attempts_since > 0 {
                SourceHealth::Degraded
            } else {
                SourceHealth::Operational
            }
        }
        // Un esito non conclusivo non puo' essere l'ultima osservazione
        // conclusiva. Se ci arriva, l'archivio si contraddice: si dichiara di
        // non sapere invece di indovinare.
        HealthCheckOutcome::CheckFailed => SourceHealth::Unknown,
    }
}

/// Perché la fonte è in quello stato, detto con i fatti che lo hanno prodotto.
///
/// È il principio di PROV-01 applicato alla salute: ogni frase qui nomina
/// un'osservazione registrata e il suo istante. Nessuna narrazione.
#[must_use]
pub fn explain(evidence: &HealthEvidence, health: SourceHealth) -> String {
    let mut frase = match health {
        SourceHealth::Stopped => String::from(
            "Disattivata dall'operatore. Non è un guasto: nessuna verifica \
             tecnica viene tentata su una fonte ferma.",
        ),
        SourceHealth::Unknown => match evidence.last_attempt_at {
            Some(istante) => format!(
                "Mai verificata in modo conclusivo. L'ultimo tentativo, del {}, \
                 non è riuscito: non è stato possibile leggere l'elenco delle chat, \
                 quindi non si è appreso nulla di questa fonte.",
                istante.to_readable_utc()
            ),
            None => String::from(
                "Mai verificata. Non risultano errori, e non risulta nemmeno una \
                 verifica riuscita: non se ne può ancora rispondere.",
            ),
        },
        _ => {
            let Some((outcome, istante)) = evidence.last_conclusive else {
                // Non raggiungibile: gli stati che non siano Ferma o Sconosciuta
                // nascono da un'osservazione conclusiva.
                return String::from(
                    "Stato non ricostruibile: manca l'osservazione che lo ha prodotto.",
                );
            };
            format!(
                "L'ultima verifica conclusiva, del {}, ha stabilito che {}.",
                istante.to_readable_utc(),
                outcome.as_sentence()
            )
        }
    };

    if evidence.faults_since > 0 {
        frase.push_str(&format!(
            " Da allora risultano {} guasto/i attribuito/i a questa fonte.",
            evidence.faults_since
        ));
    }

    if evidence.failed_attempts_since > 0 {
        frase.push_str(&format!(
            " Da allora {} tentativo/i di verifica non è/sono riuscito/i: non hanno \
             appreso nulla, ma rendono l'osservazione qui sopra meno recente.",
            evidence.failed_attempts_since
        ));
    }

    if evidence.account_authorised == Some(false) {
        frase.push_str(
            " L'account a cui questa fonte è associata non risulta autorizzato: \
             finché non lo sarà, nessuna nuova verifica potrà essere eseguita. \
             Ciò non cambia quanto osservato prima.",
        );
    }

    frase
}

/// Frase sul silenzio della fonte, tenuta **separata** dallo stato.
///
/// # Perché è una funzione a parte
///
/// Perché è l'informazione che più facilmente verrebbe scambiata per un
/// giudizio. Sta accanto allo stato, non dentro: una fonte può tacere da mesi
/// ed essere operativa, e il prodotto deve dire entrambe le cose senza far
/// discendere la seconda dalla prima.
#[must_use]
pub fn silence_note(evidence: &HealthEvidence) -> String {
    match evidence.last_content_at {
        Some(istante) => format!(
            "Ultimo contenuto acquisito il {}. Il tempo trascorso da allora non \
             concorre allo stato di salute: una fonte può non pubblicare nulla ed \
             essere raggiungibile.",
            istante.to_readable_utc()
        ),
        None => String::from(
            "Nessun contenuto ancora acquisito da questa fonte. Non è un'anomalia: \
             non concorre allo stato di salute.",
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::{HealthCheckOutcome, HealthEvidence, SourceHealth, derive, explain, silence_note};
    use crate::time::Timestamp;

    fn istante(millis: i64) -> Timestamp {
        Timestamp::from_millis(millis)
    }

    fn verificata(outcome: HealthCheckOutcome) -> HealthEvidence {
        HealthEvidence {
            active: true,
            last_conclusive: Some((outcome, istante(1_700_000_000_000))),
            last_attempt_at: Some(istante(1_700_000_000_000)),
            failed_attempts_since: 0,
            faults_since: 0,
            last_content_at: None,
            account_authorised: Some(true),
        }
    }

    #[test]
    fn a_source_disabled_by_the_operator_is_never_a_fault() {
        // Vale anche quando l'ultima osservazione diceva «non accessibile»: chi
        // ha spento la fonte non deve trovarsela segnalata in rosso.
        let mut evidence = verificata(HealthCheckOutcome::NotAccessible);
        evidence.active = false;

        let health = derive(&evidence);
        assert_eq!(health, SourceHealth::Stopped);
        assert!(!health.needs_attention());
        assert!(health.is_intentional());
        assert!(explain(&evidence, health).contains("Non è un guasto"));
    }

    #[test]
    fn a_source_never_checked_is_unknown_and_not_healthy() {
        // «Non risultano errori» non e' «funziona».
        let evidence = HealthEvidence::never_checked(true);

        let health = derive(&evidence);
        assert_eq!(health, SourceHealth::Unknown);
        assert_ne!(health, SourceHealth::Operational);
        // E non chiede attenzione: non e' un guasto, e' un'assenza di notizie.
        assert!(!health.needs_attention());
        assert!(explain(&evidence, health).contains("non se ne può ancora rispondere"));
    }

    #[test]
    fn a_reachable_source_with_nothing_wrong_since_is_operational() {
        let evidence = verificata(HealthCheckOutcome::Reachable);

        let health = derive(&evidence);
        assert_eq!(health, SourceHealth::Operational);
        assert!(!health.needs_attention());
        assert!(explain(&evidence, health).contains("storico leggibile"));
    }

    #[test]
    fn a_silent_source_stays_operational_however_long_the_silence() {
        // E' la regola centrale: fonte silenziosa NON e' fonte guasta.
        let mut muta = verificata(HealthCheckOutcome::Reachable);
        muta.last_content_at = Some(istante(1_600_000_000_000));

        let mut mutissima = verificata(HealthCheckOutcome::Reachable);
        mutissima.last_content_at = Some(istante(1_000_000_000_000));

        let mut mai = verificata(HealthCheckOutcome::Reachable);
        mai.last_content_at = None;

        for evidence in [&muta, &mutissima, &mai] {
            assert_eq!(
                derive(evidence),
                SourceHealth::Operational,
                "il silenzio non deve produrre un guasto"
            );
        }
    }

    #[test]
    fn the_instant_of_the_last_content_never_changes_the_state() {
        // La stessa evidenza, con l'ultimo contenuto spostato ovunque, produce
        // sempre lo stesso stato. E' il modo meccanico di dire che quel dato
        // e' informativo.
        for outcome in [
            HealthCheckOutcome::Reachable,
            HealthCheckOutcome::HistoryUnreadable,
            HealthCheckOutcome::NotAccessible,
        ] {
            let base = verificata(outcome);
            let atteso = derive(&base);

            for millis in [1_i64, 1_500_000_000_000, 1_700_000_000_000, i64::MAX / 4] {
                let mut variante = base.clone();
                variante.last_content_at = Some(istante(millis));
                assert_eq!(
                    derive(&variante),
                    atteso,
                    "l'istante dell'ultimo contenuto non deve entrare nella derivazione"
                );
            }
        }
    }

    #[test]
    fn the_authorisation_of_the_account_never_changes_the_state() {
        // Un account non autorizzato non cambia cio' che fu osservato della
        // chat: cambia se il monitoraggio possa funzionare adesso.
        for outcome in [
            HealthCheckOutcome::Reachable,
            HealthCheckOutcome::HistoryUnreadable,
            HealthCheckOutcome::NotAccessible,
        ] {
            let base = verificata(outcome);
            let atteso = derive(&base);

            for autorizzato in [None, Some(true), Some(false)] {
                let mut variante = base.clone();
                variante.account_authorised = autorizzato;
                assert_eq!(derive(&variante), atteso);
            }
        }
    }

    #[test]
    fn an_unauthorised_account_is_declared_even_if_it_does_not_change_the_state() {
        let mut evidence = verificata(HealthCheckOutcome::Reachable);
        evidence.account_authorised = Some(false);

        let health = derive(&evidence);
        assert_eq!(health, SourceHealth::Operational);
        let frase = explain(&evidence, health);
        assert!(frase.contains("non risulta autorizzato"));
        assert!(frase.contains("Ciò non cambia quanto osservato prima"));
    }

    #[test]
    fn a_failed_attempt_alone_does_not_make_a_source_faulty() {
        // Non aver potuto verificare NON e' aver verificato un guasto.
        let mut evidence = HealthEvidence::never_checked(true);
        evidence.last_attempt_at = Some(istante(1_700_000_500_000));
        evidence.failed_attempts_since = 1;

        let health = derive(&evidence);
        assert_eq!(health, SourceHealth::Unknown);
        assert!(!health.needs_attention());
        assert!(explain(&evidence, health).contains("non si è appreso nulla"));
    }

    #[test]
    fn many_failed_attempts_never_become_a_fault_by_themselves() {
        // Nessuna soglia trasforma «non ho potuto guardare» in «e' rotto».
        let mut evidence = HealthEvidence::never_checked(true);
        evidence.last_attempt_at = Some(istante(1_700_000_500_000));
        evidence.failed_attempts_since = 1_000;

        assert_eq!(derive(&evidence), SourceHealth::Unknown);
        assert!(!derive(&evidence).needs_attention());
    }

    #[test]
    fn failed_attempts_after_a_good_check_degrade_but_do_not_break() {
        // L'osservazione buona resta; i tentativi non riusciti la rendono meno
        // recente, e questo si dichiara.
        let mut evidence = verificata(HealthCheckOutcome::Reachable);
        evidence.failed_attempts_since = 3;

        let health = derive(&evidence);
        assert_eq!(health, SourceHealth::Degraded);
        assert_ne!(health, SourceHealth::Failed);
        assert!(explain(&evidence, health).contains("meno recente"));
    }

    #[test]
    fn a_source_that_the_account_can_no_longer_reach_is_in_error() {
        let evidence = verificata(HealthCheckOutcome::NotAccessible);

        let health = derive(&evidence);
        assert_eq!(health, SourceHealth::Failed);
        assert!(health.needs_attention());
        assert!(explain(&evidence, health).contains("non vi compariva"));
    }

    #[test]
    fn a_source_whose_history_cannot_be_read_is_degraded_not_failed() {
        // Accessibile e inutile: e' una condizione diversa dal non avere piu'
        // accesso, e l'operatore vi rimedia in modo diverso.
        let evidence = verificata(HealthCheckOutcome::HistoryUnreadable);

        let health = derive(&evidence);
        assert_eq!(health, SourceHealth::Degraded);
        assert_ne!(health, SourceHealth::Failed);
    }

    #[test]
    fn faults_after_a_good_check_degrade_the_source() {
        let mut evidence = verificata(HealthCheckOutcome::Reachable);
        evidence.faults_since = 2;

        let health = derive(&evidence);
        assert_eq!(health, SourceHealth::Degraded);
        assert!(explain(&evidence, health).contains("2 guasto/i"));
    }

    #[test]
    fn a_recovery_returns_the_source_to_operational() {
        // Dopo un ripristino l'ultima osservazione conclusiva e' buona e non c'e'
        // nulla di successivo: lo stato torna operativo senza memoria del guasto.
        let evidence = verificata(HealthCheckOutcome::Reachable);
        assert_eq!(derive(&evidence), SourceHealth::Operational);
    }

    #[test]
    fn only_degraded_and_failed_ask_for_attention() {
        assert!(SourceHealth::Degraded.needs_attention());
        assert!(SourceHealth::Failed.needs_attention());
        assert!(!SourceHealth::Operational.needs_attention());
        assert!(!SourceHealth::Unknown.needs_attention());
        assert!(!SourceHealth::Stopped.needs_attention());
    }

    #[test]
    fn the_silence_note_never_pronounces_on_health() {
        let mut evidence = verificata(HealthCheckOutcome::Reachable);
        evidence.last_content_at = Some(istante(1_500_000_000_000));

        let nota = silence_note(&evidence);
        assert!(nota.contains("non concorre allo stato di salute"));
        for parola in ["guasta", "guasto", "anomalia", "errore"] {
            assert!(
                !nota.to_lowercase().contains(&format!(" {parola}"))
                    || nota.contains("Non è un'anomalia"),
                "la nota sul silenzio non deve suggerire un guasto: «{nota}»"
            );
        }
    }

    #[test]
    fn every_outcome_survives_a_round_trip_through_its_stored_form() {
        for outcome in [
            HealthCheckOutcome::Reachable,
            HealthCheckOutcome::HistoryUnreadable,
            HealthCheckOutcome::NotAccessible,
            HealthCheckOutcome::CheckFailed,
        ] {
            assert_eq!(
                HealthCheckOutcome::from_stored(outcome.as_str()),
                Some(outcome)
            );
        }
        assert_eq!(HealthCheckOutcome::from_stored("inventato"), None);
    }

    #[test]
    fn only_the_failed_attempt_is_inconclusive() {
        assert!(!HealthCheckOutcome::CheckFailed.is_conclusive());
        for outcome in [
            HealthCheckOutcome::Reachable,
            HealthCheckOutcome::HistoryUnreadable,
            HealthCheckOutcome::NotAccessible,
        ] {
            assert!(outcome.is_conclusive());
        }
    }

    /// La nota di una riga dice se quella riga ha appreso qualcosa, e le due
    /// affermazioni non possono divergere.
    ///
    /// È la coerenza che il pannello della storia mostra: la riga colorata
    /// come non conclusiva deve portare una nota che dice «non conclusiva», e
    /// viceversa. Se le due si separassero, il colore direbbe una cosa e il
    /// testo un'altra.
    #[test]
    fn the_note_of_a_row_agrees_with_whether_it_concluded() {
        for outcome in [
            HealthCheckOutcome::Reachable,
            HealthCheckOutcome::HistoryUnreadable,
            HealthCheckOutcome::NotAccessible,
            HealthCheckOutcome::CheckFailed,
        ] {
            let nota = outcome.note_about_source();
            if outcome.is_conclusive() {
                assert!(
                    nota.starts_with("Osservazione conclusiva"),
                    "un esito conclusivo deve dichiararsi tale: «{nota}»"
                );
            } else {
                assert!(
                    nota.starts_with("Non conclusiva"),
                    "un tentativo non riuscito deve dichiararsi non conclusivo: «{nota}»"
                );
            }
        }
    }

    /// Un tentativo non riuscito non attribuisce nulla alla fonte.
    ///
    /// È la prova che protegge la storia dal diventare un elenco di colpe: in
    /// venti righe uguali, quattro tentativi non riusciti si leggerebbero come
    /// quattro guasti della fonte se la nota non dicesse il contrario.
    #[test]
    fn a_failed_attempt_attributes_nothing_to_the_source() {
        let nota = HealthCheckOutcome::CheckFailed.note_about_source();

        assert!(
            nota.contains("non si è appreso nulla di questa fonte"),
            "la riga deve dire che cosa NON si è appreso: «{nota}»"
        );
        for parola in ["guasto", "guasti", "errore della fonte", "non accessibile"] {
            assert!(
                !nota.contains(parola),
                "la nota di un tentativo non riuscito contiene «{parola}»: \
                 non aver potuto guardare non è aver visto un guasto"
            );
        }
    }

    #[test]
    fn every_state_has_a_word_of_its_own() {
        let mut etichette: Vec<&str> = SourceHealth::ALL.iter().map(|s| s.label()).collect();
        etichette.sort_unstable();
        let quante = etichette.len();
        etichette.dedup();
        assert_eq!(
            etichette.len(),
            quante,
            "due stati non devono leggersi uguali"
        );
        assert_eq!(quante, 5);
    }
}
