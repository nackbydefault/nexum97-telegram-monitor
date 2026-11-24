//! Modalità operativa della postazione e ciò che ciascuna consente.
//!
//! Le scelte sono motivate in `docs/adr/ADR-0015-OPERATOR-ROLES.md` e, per ciò
//! che l'operatore può fare, in
//! `docs/adr/ADR-0140-L-OPERATORE-LAVORA-LE-OPERAZIONI-DELICATE-SI-CONFERMANO.md`.
//! Due punti toccano direttamente questo codice.
//!
//! **Il criterio non è più «ciò che vale oltre la propria sessione»** (ADR-0015).
//! Il proprietario ha deciso il 2026-10-15 che il personale autorizzato lavora
//! senza chiedere continuamente l'amministratore, e che un'operazione non si
//! riserva **soltanto perché modifica dati o configurazioni**: le operazioni
//! delicate si proteggono con conferme, validazioni e audit. Restano riservate
//! due sole azioni, ciascuna con una ragione che non è «modifica qualcosa»: il
//! dizionario di un'altra persona, e il canale degli aggiornamenti della
//! postazione. Dal 2026-10-30 una terza con la stessa ragione: la fonte dei
//! dizionari e i loro firmatari (ADR-0178, DEC-455). Dal 2026-11-04 una quarta:
//! la destinazione TAXII, dove escono gli osservabili (ADR-0179, DEC-459). Dal
//! 2026-11-05 una quinta: il certificato con cui firma l'ufficio (ADR-0181,
//! DEC-463).
//!
//! **Non è un confine di sicurezza contro chi controlla la propria macchina.**
//! È una modalità operativa: protegge dall'errore, non dalla determinazione.
//! Chi voglia riprendersi i privilegi sulla propria postazione può farlo, e il
//! prodotto non pretende il contrario — ma lascia nell'audit la traccia di
//! averlo fatto, il che è un fatto diverso dall'impedirglielo.

use crate::error::DomainError;

/// Azione la cui disponibilità dipende dalla modalità.
///
/// Sono elencate le azioni che **sono state** riservate (ADR-0015). Dal
/// 2026-10-15 la postazione in modalità operatore ne consente quattro
/// (ADR-0140); restano qui perché l'Hub le usa per i dispositivi collegati, il
/// cui modello di ruoli è separato e non è cambiato (ADR-0094), e perché il
/// nome stabile serve all'audit.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum RestrictedAction {
    /// Creare o modificare un dizionario condiviso con la postazione.
    ManageSharedDictionary,
    /// Pubblicare una versione, che da quel momento vale per chiunque.
    PublishVersion,
    /// Archiviare o rimuovere un dizionario che non è il proprio.
    RemoveOthersDictionary,
    /// Importare un dizionario da un file.
    ImportDictionary,
    /// Configurare fonti e account.
    ConfigureSources,
    /// Uscire dalla modalità operatore.
    LeaveOperatorMode,
    /// Scegliere il canale degli aggiornamenti della postazione.
    ChooseUpdateChannel,
    /// Scegliere da dove si scaricano i dizionari e chi è ammesso a firmarli
    /// (DICT-NET-01, ADR-0178).
    ChooseDictionarySource,
    /// Scegliere il server TAXII a cui si mandano gli osservabili, e con quali
    /// credenziali (TAXII-01, ADR-0179).
    ChooseTaxiiDestination,
    /// Scegliere il certificato con cui firma l'ufficio (SIGN-01, ADR-0181).
    ChooseSigningCertificate,
    /// Scegliere la pianificazione delle copie di sicurezza: dove, ogni
    /// quanto, quante tenerne (BACKUP-SCHEDULE-01, ADR-0191).
    ChooseBackupSchedule,
    /// Accendere, regolare o spegnere il registro delle consultazioni, e
    /// leggerlo (AUDIT-VIEW-01, ADR-0193).
    ChooseConsultationLog,
    /// Dichiarare le reti dell'ufficio da cui l'Hub si raggiunge e su cui
    /// ascolta (HUB-SITES-01, ADR-0198).
    ChooseOfficeNetworks,
    /// Scegliere se l'Hub accetta comandi a distanza sui propri monitoraggi
    /// (HUB-REMOTE-01, ADR-0200).
    ChooseRemoteCommands,
    /// Abilitare o spegnere l'elenco degli iscritti delle fonti (MEMBERS-01,
    /// ADR-0201).
    ChooseMembersListing,
    /// Abilitare o spegnere la risoluzione degli indicatori dal PC
    /// (IOC-RESOLVE-01, ADR-0202).
    ChooseIndicatorResolution,
    /// Abilitare o spegnere il WHOIS dal PC: chi ha registrato un nome o un
    /// indirizzo (WHOIS-01, ADR-0205).
    ChooseRegistrationLookup,
}

impl RestrictedAction {
    /// Tutte le azioni riservate.
    pub const ALL: [Self; 17] = [
        Self::ManageSharedDictionary,
        Self::PublishVersion,
        Self::RemoveOthersDictionary,
        Self::ImportDictionary,
        Self::ConfigureSources,
        Self::LeaveOperatorMode,
        Self::ChooseUpdateChannel,
        Self::ChooseDictionarySource,
        Self::ChooseTaxiiDestination,
        Self::ChooseSigningCertificate,
        Self::ChooseBackupSchedule,
        Self::ChooseConsultationLog,
        Self::ChooseOfficeNetworks,
        Self::ChooseRemoteCommands,
        Self::ChooseMembersListing,
        Self::ChooseIndicatorResolution,
        Self::ChooseRegistrationLookup,
    ];

    /// Nome stabile per l'audit e per la diagnostica.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ManageSharedDictionary => "gestire_dizionari_condivisi",
            Self::PublishVersion => "pubblicare_versione",
            Self::RemoveOthersDictionary => "rimuovere_dizionario_altrui",
            Self::ImportDictionary => "importare_dizionario",
            Self::ConfigureSources => "configurare_fonti",
            Self::LeaveOperatorMode => "uscire_dalla_modalita_operatore",
            Self::ChooseUpdateChannel => "scegliere_canale_aggiornamenti",
            Self::ChooseDictionarySource => "scegliere_fonte_dizionari",
            Self::ChooseTaxiiDestination => "scegliere_destinazione_taxii",
            Self::ChooseSigningCertificate => "scegliere_certificato_firma",
            Self::ChooseBackupSchedule => "scegliere_copie_pianificate",
            Self::ChooseConsultationLog => "scegliere_registro_consultazioni",
            Self::ChooseOfficeNetworks => "scegliere_reti_ufficio",
            Self::ChooseRemoteCommands => "scegliere_comandi_a_distanza",
            Self::ChooseMembersListing => "scegliere_elenco_iscritti",
            Self::ChooseIndicatorResolution => "scegliere_risoluzione_indicatori",
            Self::ChooseRegistrationLookup => "scegliere_whois",
        }
    }

    /// Perché l'azione è riservata.
    ///
    /// Non basta dire all'operatore che non può: deve capire **quale confine**
    /// sta incontrando, altrimenti il rifiuto sembra arbitrario e la prima
    /// reazione è cercare il modo di aggirarlo.
    #[must_use]
    pub const fn reason(self) -> &'static str {
        match self {
            Self::ManageSharedDictionary => {
                "un dizionario condiviso vale per tutti gli operatori della postazione"
            }
            Self::PublishVersion => {
                "una versione pubblicata non si modifica più e vale per chiunque la usi"
            }
            Self::RemoveOthersDictionary => "il dizionario è stato composto da qualcun altro",
            Self::ImportDictionary => {
                "un file importato porta dentro contenuto che nessuno di questa postazione ha scritto"
            }
            Self::ConfigureSources => "la configurazione delle fonti vale per ogni monitoraggio",
            Self::LeaveOperatorMode => "il ritorno alla modalità amministratore va autorizzato",
            Self::ChooseUpdateChannel => {
                "il canale vale per la postazione: decide quando OGNI operatore riceverà il programma nuovo"
            }
            Self::ChooseDictionarySource => {
                "la fonte e i firmatari valgono per la postazione: decidono quali dizionari possono entrare dalla rete"
            }
            Self::ChooseTaxiiDestination => {
                "la destinazione vale per la postazione: decide dove escono gli osservabili di tutti"
            }
            Self::ChooseSigningCertificate => {
                "il certificato vale per la postazione: decide a nome di chi firmano tutti"
            }
            Self::ChooseConsultationLog => {
                "il registro dice chi ha aperto che cosa: decide se e per quanto si tiene, e lo legge soltanto chi risponde della postazione"
            }
            Self::ChooseBackupSchedule => {
                "la pianificazione vale per la postazione: decide dove escono le copie dell'archivio e quante se ne tolgono"
            }
            Self::ChooseOfficeNetworks => {
                "le reti valgono per la postazione: decidono da dove l'Hub si raggiunge, e mai da Internet"
            }
            Self::ChooseRemoteCommands => {
                "la scelta vale per l'Hub: decide se da un'altra postazione si mettono in pausa o si arrestano i monitoraggi dell'ufficio"
            }
            Self::ChooseMembersListing => {
                "la scelta vale per la postazione: decide se si possono chiedere a Telegram gli iscritti delle fonti, che sono persone"
            }
            Self::ChooseIndicatorResolution => {
                "la scelta vale per la postazione: decide se da questo PC partono richieste sui domini che chi li gestisce può vedere"
            }
            Self::ChooseRegistrationLookup => {
                "la scelta vale per la postazione: decide se da questo PC si chiede ai registri chi ha registrato un nome, e il registro lo vede"
            }
        }
    }
}

/// Modalità operativa della postazione.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub enum OperatingMode {
    /// La postazione è configurabile per intero.
    ///
    /// È lo stato iniziale: qualcuno deve poter predisporre fonti e dizionari
    /// prima che esista un operatore che li usi.
    #[default]
    Administrator,
    /// La postazione è in uso operativo.
    Operator,
}

impl OperatingMode {
    /// Forma conservata nella configurazione.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Administrator => "administrator",
            Self::Operator => "operator",
        }
    }

    /// Nome mostrato all'operatore.
    ///
    /// Dice **modalità**, non «permessi» né «livello di accesso»: chiamarlo
    /// controllo degli accessi sarebbe fuorviante, perché non regge contro chi
    /// controlla la propria macchina.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Administrator => "Modalità amministratore",
            Self::Operator => "Modalità operatore",
        }
    }

    /// Descrizione di che cosa la modalità comporta.
    #[must_use]
    pub const fn description(self) -> &'static str {
        match self {
            Self::Administrator => {
                "La postazione può essere configurata per intero. Oltre a ciò che fa \
                 l'operatore, l'amministratore può togliere i dizionari di altre persone e \
                 scegliere il canale degli aggiornamenti. Sceglie anche la fonte dei \
                 dizionari e la destinazione TAXII."
            }
            Self::Operator => {
                "La postazione è in uso operativo. L'operatore configura fonti e account, \
                 compone e avvia i monitoraggi, gestisce dizionari, regole e modelli, e \
                 pubblica una versione dopo averla confermata. Restano all'amministratore \
                 quattro cose: togliere il dizionario di un'altra persona, scegliere il \
                 canale degli aggiornamenti, la fonte dei dizionari e la destinazione \
                 TAXII."
            }
        }
    }

    /// Se la modalità consente l'azione indicata.
    ///
    /// # Perché quattro azioni non sono più riservate (ADR-0140)
    ///
    /// Configurare fonti e account, gestire i dizionari condivisi, pubblicare
    /// una versione e importare un dizionario sono il lavoro di tutti i giorni
    /// di chi è autorizzato a usare la postazione. Riservarli rimandava
    /// all'amministratore per ogni parola corretta. Si proteggono dove si
    /// eseguono: la pubblicazione con una conferma che dice la conseguenza,
    /// l'importazione con l'ingresso in bozza, tutto con l'audit.
    ///
    /// Restano riservate le due azioni con una ragione che non è «modifica
    /// qualcosa»: il dizionario composto da un'altra persona, che non è
    /// presente a discuterne, e il canale degli aggiornamenti, che decide il
    /// software della postazione per tutti.
    ///
    /// Dal 2026-10-30 se ne aggiunge una terza con la stessa ragione (ADR-0178):
    /// la fonte dei dizionari e chi è ammesso a firmarli decidono che cosa può
    /// entrare dalla rete, per tutti. Dal 2026-11-04 una quarta (ADR-0179): la
    /// destinazione TAXII decide dove escono gli osservabili della postazione.
    #[must_use]
    pub const fn allows(self, action: RestrictedAction) -> bool {
        match (self, action) {
            // Uscire dalla modalita' operatore ha senso solo per chi vi si
            // trova: non e' un privilegio, e' la via di ritorno.
            (Self::Operator, RestrictedAction::LeaveOperatorMode) => true,
            (Self::Administrator, RestrictedAction::LeaveOperatorMode) => false,
            (Self::Administrator, _) => true,
            (
                Self::Operator,
                RestrictedAction::ConfigureSources
                | RestrictedAction::ManageSharedDictionary
                | RestrictedAction::PublishVersion
                | RestrictedAction::ImportDictionary,
            ) => true,
            (
                Self::Operator,
                RestrictedAction::RemoveOthersDictionary
                | RestrictedAction::ChooseUpdateChannel
                | RestrictedAction::ChooseDictionarySource
                | RestrictedAction::ChooseTaxiiDestination
                | RestrictedAction::ChooseSigningCertificate
                | RestrictedAction::ChooseBackupSchedule
                | RestrictedAction::ChooseConsultationLog
                | RestrictedAction::ChooseOfficeNetworks
                | RestrictedAction::ChooseRemoteCommands
                | RestrictedAction::ChooseMembersListing
                | RestrictedAction::ChooseIndicatorResolution
                | RestrictedAction::ChooseRegistrationLookup,
            ) => false,
        }
    }

    /// Interpreta la forma conservata nella configurazione.
    ///
    /// # Errori
    ///
    /// Restituisce [`DomainError::UnknownVariant`] su un valore non conosciuto.
    /// **Non** ricade sull'amministratore: un valore illeggibile che
    /// diventasse silenziosamente la modalità più ampia trasformerebbe un file
    /// corrotto in una promozione.
    pub fn parse(raw: &str) -> Result<Self, DomainError> {
        match raw {
            "administrator" => Ok(Self::Administrator),
            "operator" => Ok(Self::Operator),
            other => Err(DomainError::UnknownVariant {
                kind: "modalita_operativa",
                value: other.chars().take(64).collect(),
            }),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{OperatingMode, RestrictedAction};
    use crate::error::DomainError;

    #[test]
    fn the_administrator_may_do_everything_except_leave_a_mode_it_is_not_in() {
        for action in RestrictedAction::ALL {
            let expected = action != RestrictedAction::LeaveOperatorMode;
            assert_eq!(
                OperatingMode::Administrator.allows(action),
                expected,
                "amministratore e '{}'",
                action.as_str()
            );
        }
    }

    /// **L'operatore lavora, e dodici sole azioni restano riservate**
    /// (ADR-0140, ADR-0178, ADR-0179, ADR-0181, ADR-0191, ADR-0193, ADR-0198,
    /// ADR-0200, ADR-0201, ADR-0202, ADR-0205).
    ///
    /// Questa prova si chiamava `the_operator_may_do_nothing_reserved_except_ask_to_leave`
    /// e diceva che l'operatore non poteva fare nessuna delle azioni elencate.
    /// La regola l'ha cambiata il proprietario il 2026-10-15: la prova è stata
    /// riscritta per dire la regola nuova, azione per azione, e non tolta. Il
    /// 2026-10-30 la terza, la fonte dei dizionari (DEC-455); il 2026-11-04 la
    /// quarta, la destinazione TAXII (DEC-459); il 2026-11-05 la quinta, il
    /// certificato di firma (DEC-463); il 2026-11-07 la sesta, la pianificazione
    /// delle copie (DEC-476); lo stesso giorno la settima, il registro delle
    /// consultazioni (DEC-480); il 2026-11-10 l'ottava, le reti dell'ufficio
    /// (DEC-490); lo stesso giorno la nona, i comandi a distanza (DEC-492); il
    /// 2026-11-11 la decima, l'elenco degli iscritti (DEC-498), e lo stesso
    /// giorno l'undicesima, la risoluzione degli indicatori (DEC-499); il
    /// 2026-11-13 la dodicesima, il WHOIS (DEC-504).
    #[test]
    fn the_operator_works_and_only_twelve_actions_stay_reserved() {
        for action in RestrictedAction::ALL {
            let expected = !matches!(
                action,
                RestrictedAction::RemoveOthersDictionary
                    | RestrictedAction::ChooseUpdateChannel
                    | RestrictedAction::ChooseDictionarySource
                    | RestrictedAction::ChooseTaxiiDestination
                    | RestrictedAction::ChooseSigningCertificate
                    | RestrictedAction::ChooseBackupSchedule
                    | RestrictedAction::ChooseConsultationLog
                    | RestrictedAction::ChooseOfficeNetworks
                    | RestrictedAction::ChooseRemoteCommands
                    | RestrictedAction::ChooseMembersListing
                    | RestrictedAction::ChooseIndicatorResolution
                    | RestrictedAction::ChooseRegistrationLookup
            );
            assert_eq!(
                OperatingMode::Operator.allows(action),
                expected,
                "operatore e '{}'",
                action.as_str()
            );
        }
    }

    /// **Le due azioni che restano riservate sono quelle con una ragione che
    /// non è «modifica qualcosa».**
    #[test]
    fn the_reserved_actions_are_the_other_persons_work_and_the_software() {
        assert!(!OperatingMode::Operator.allows(RestrictedAction::RemoveOthersDictionary));
        assert!(!OperatingMode::Operator.allows(RestrictedAction::ChooseUpdateChannel));
        assert!(
            RestrictedAction::RemoveOthersDictionary
                .reason()
                .contains("qualcun altro")
        );
        assert!(
            RestrictedAction::ChooseUpdateChannel
                .reason()
                .contains("OGNI operatore")
        );
        assert!(!OperatingMode::Operator.allows(RestrictedAction::ChooseDictionarySource));
        assert!(
            RestrictedAction::ChooseDictionarySource
                .reason()
                .contains("dalla rete")
        );
        assert!(!OperatingMode::Operator.allows(RestrictedAction::ChooseTaxiiDestination));
        assert!(
            RestrictedAction::ChooseTaxiiDestination
                .reason()
                .contains("osservabili")
        );
        assert!(!OperatingMode::Operator.allows(RestrictedAction::ChooseSigningCertificate));
        assert!(
            RestrictedAction::ChooseSigningCertificate
                .reason()
                .contains("a nome di chi")
        );
    }

    #[test]
    fn every_reserved_action_says_why_it_is_reserved() {
        // Un rifiuto senza ragione sembra arbitrario, e la prima reazione a un
        // divieto arbitrario e' cercare il modo di aggirarlo.
        for action in RestrictedAction::ALL {
            assert!(!action.as_str().is_empty());
            assert!(
                action.reason().len() > 20,
                "la ragione di '{}' e' troppo breve per spiegare qualcosa",
                action.as_str()
            );
        }
    }

    #[test]
    fn each_reserved_action_has_a_distinct_name() {
        let names: Vec<&str> = RestrictedAction::ALL.iter().map(|a| a.as_str()).collect();
        for (index, name) in names.iter().enumerate() {
            assert!(!names.iter().skip(index + 1).any(|other| other == name));
        }
    }

    #[test]
    fn a_fresh_station_starts_as_administrator() {
        // Qualcuno deve poter configurare fonti e dizionari prima che esista un
        // operatore che li usi.
        assert_eq!(OperatingMode::default(), OperatingMode::Administrator);
    }

    #[test]
    fn the_stored_form_survives_a_round_trip() {
        for mode in [OperatingMode::Administrator, OperatingMode::Operator] {
            assert_eq!(OperatingMode::parse(mode.as_str()), Ok(mode));
        }
    }

    #[test]
    fn an_unreadable_stored_value_is_not_a_promotion() {
        // Ricadere sull'amministratore trasformerebbe un file corrotto in un
        // ampliamento dei privilegi.
        assert!(matches!(
            OperatingMode::parse("amministratore"),
            Err(DomainError::UnknownVariant { .. })
        ));
        assert!(matches!(
            OperatingMode::parse(""),
            Err(DomainError::UnknownVariant { .. })
        ));
    }

    #[test]
    fn the_label_says_mode_and_never_claims_access_control() {
        // Non regge contro chi controlla la propria macchina: chiamarlo
        // controllo degli accessi sarebbe fuorviante.
        for mode in [OperatingMode::Administrator, OperatingMode::Operator] {
            assert!(mode.label().contains("Modalità"));
            let text = format!("{} {}", mode.label(), mode.description()).to_lowercase();
            for claim in ["accesso negato", "protetto", "sicurezza", "autorizzazione"] {
                assert!(
                    !text.contains(claim),
                    "'{claim}' promette piu' di quanto la modalita' garantisca"
                );
            }
        }
    }
}
