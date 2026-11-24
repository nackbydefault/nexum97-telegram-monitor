//! Modelli di monitoraggio riusabili (TEMPLATE-01).
//!
//! # Un modello propone, non applica
//!
//! È la decisione da cui discende tutto il resto, e nasce da un fatto dello
//! schema: la soglia di notifica e la conservazione sono **impostazioni di
//! postazione**, non di sessione — tabelle a riga unica.
//!
//! Un modello che le scrivesse riconfigurerebbe la postazione intera con un
//! gesto che sembra «preparare un monitoraggio». E la conservazione, in
//! particolare, **cancella**: abbassarla in silenzio distruggerebbe materiale
//! che qualcuno si aspettava di ritrovare.
//!
//! Perciò applicare un modello prepara **le fonti e i dizionari**, che sono
//! della sessione, e per le impostazioni di postazione **dichiara la
//! differenza** senza toccarle.
//!
//! # Le versioni dei dizionari non stanno nel modello
//!
//! Un modello nomina un **profilo** di dizionari, e un profilo nomina i
//! dizionari per identità — mai per versione.
//!
//! Se un modello fissasse le versioni, un monitoraggio preparato da quel
//! modello userebbe per sempre i dizionari com'erano il giorno in cui fu
//! creato, e smetterebbe **in silenzio** di raccogliere le correzioni — che
//! sono esattamente ciò per cui FEEDBACK-01 esiste.
//!
//! La versione si risolve **quando il modello si applica**, con la regola che
//! c'era già: l'ultima versione pubblicata. Il costo si dichiara: applicare lo
//! stesso modello due volte può risolvere diversamente, ed è **voluto**.
//!
//! È la stessa forma di SEARCH-01 — rifare non riproduce, e il prodotto lo dice.

use crate::error::{DomainError, DomainResult};
use crate::text::{Actor, DisplayName, Note};
use crate::time::Timestamp;
use crate::{DictionaryProfileId, MonitoringTemplateId, SourceId};

/// Che cosa un modello prevede per una impostazione **di postazione**.
///
/// # Perché non è semplicemente un valore
///
/// Perché «il modello non si esprime» e «il modello prevede questo valore, che
/// per caso è quello corrente» sono due cose diverse, e confonderle farebbe
/// dichiarare una differenza dove non c'è, o tacerla dove c'è.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Prescribed<T> {
    /// Il modello non si esprime: applicandolo, quella impostazione non si
    /// confronta nemmeno.
    Silent,
    /// Il modello prevede questo valore.
    Value(T),
}

impl<T> Prescribed<T> {
    /// Se il modello si esprime.
    #[must_use]
    pub const fn speaks(&self) -> bool {
        matches!(self, Self::Value(_))
    }
}

/// Che cosa un modello prevede per la conservazione.
///
/// # Perché un tipo e non un `Option<u32>`
///
/// Perché «conserva tutto» è un valore che la politica esprime con il proprio
/// `NULL`, e «il modello non si esprime» è un'altra cosa ancora. Due `None`
/// annidati si confondono alla prima lettura distratta, e il difetto sarebbe
/// che ogni modello silenzioso prescriverebbe la conservazione illimitata.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PrescribedRetention {
    /// Il modello non si esprime sulla conservazione.
    Silent,
    /// Conserva tutto, senza limite di giorni.
    KeepEverything,
    /// Conserva per questo numero di giorni.
    KeepDays(u32),
}

impl PrescribedRetention {
    /// Se il modello si esprime.
    #[must_use]
    pub const fn speaks(&self) -> bool {
        !matches!(self, Self::Silent)
    }
}

/// Un modello da creare.
///
/// # Perché i campi sono privati
///
/// Perché il tipo garantisce una cosa che una struttura aperta non
/// garantirebbe: che un modello abbia **almeno una fonte**. Applicarne uno
/// senza fonti non preparerebbe nulla, e chi lo ha salvato crederebbe di avere
/// un modello.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewMonitoringTemplate {
    name: DisplayName,
    description: Option<Note>,
    sources: Vec<SourceId>,
    dictionary_profile: Option<DictionaryProfileId>,
    notification_level: Prescribed<u8>,
    retention: PrescribedRetention,
    created_by: Actor,
}

impl NewMonitoringTemplate {
    /// Prepara un modello.
    ///
    /// # Errori
    ///
    /// Rifiuta un modello **senza fonti**: applicarlo non preparerebbe nulla.
    ///
    /// Rifiuta una soglia di notifica fuori da 1-4: i livelli sono cinque, e lo
    /// zero non è una soglia — è l'assenza di soglia, che si dice tacendo.
    pub fn of(
        name: DisplayName,
        description: Option<Note>,
        sources: Vec<SourceId>,
        dictionary_profile: Option<DictionaryProfileId>,
        notification_level: Prescribed<u8>,
        retention: PrescribedRetention,
        created_by: Actor,
    ) -> DomainResult<Self> {
        if sources.is_empty() {
            return Err(DomainError::Empty {
                field: "template_sources",
            });
        }
        if let Prescribed::Value(livello) = notification_level
            && !(1..=4).contains(&livello)
        {
            return Err(DomainError::Empty {
                field: "template_notification_level",
            });
        }
        Ok(Self {
            name,
            description,
            sources,
            dictionary_profile,
            notification_level,
            retention,
            created_by,
        })
    }

    /// Il nome.
    #[must_use]
    pub const fn name(&self) -> &DisplayName {
        &self.name
    }

    /// A che cosa serve.
    #[must_use]
    pub const fn description(&self) -> Option<&Note> {
        self.description.as_ref()
    }

    /// Le fonti.
    #[must_use]
    pub fn sources(&self) -> &[SourceId] {
        &self.sources
    }

    /// Il profilo di dizionari, se ne prevede uno.
    #[must_use]
    pub const fn dictionary_profile(&self) -> Option<DictionaryProfileId> {
        self.dictionary_profile
    }

    /// La soglia di notifica prevista.
    #[must_use]
    pub const fn notification_level(&self) -> Prescribed<u8> {
        self.notification_level
    }

    /// La conservazione prevista.
    #[must_use]
    pub const fn retention(&self) -> PrescribedRetention {
        self.retention
    }

    /// Chi lo crea.
    #[must_use]
    pub const fn created_by(&self) -> &Actor {
        &self.created_by
    }
}

/// Un modello conservato.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MonitoringTemplate {
    /// Identificativo stabile.
    pub id: MonitoringTemplateId,
    /// Il nome.
    pub name: DisplayName,
    /// A che cosa serve.
    pub description: Option<Note>,
    /// Le fonti che prevede.
    pub sources: Vec<SourceId>,
    /// Il profilo di dizionari, se ne prevede uno.
    pub dictionary_profile: Option<DictionaryProfileId>,
    /// La soglia di notifica prevista.
    pub notification_level: Prescribed<u8>,
    /// La conservazione prevista.
    pub retention: PrescribedRetention,
    /// Chi lo ha creato.
    pub created_by: Actor,
    /// Quando.
    pub created_at: Timestamp,
}

impl MonitoringTemplate {
    /// Che cosa questo modello è, detto a chi legge.
    #[must_use]
    pub fn as_sentence(&self) -> String {
        let dizionari = match self.dictionary_profile {
            Some(_) => "e un profilo di dizionari",
            None => "e nessun profilo di dizionari",
        };
        format!(
            "Creato da {} il {}. Prevede {} {}.",
            self.created_by.on_screen(),
            self.created_at.to_readable_local(),
            crate::text::counted(self.sources.len(), "fonte", "fonti"),
            dizionari
        )
    }
}

/// Che cosa una impostazione di postazione farebbe, se il modello la applicasse.
///
/// # Perché una dichiarazione e non un cambiamento
///
/// Perché la soglia di notifica e la conservazione **non appartengono a una
/// sessione**: appartengono alla postazione, e cambiarle tocca anche i
/// monitoraggi già conclusi. La conservazione, per giunta, **cancella**.
///
/// Un gesto che sembra «preparare un monitoraggio» non può fare questo. Perciò
/// si dichiara, e cambiarle resta un atto deliberato dove le impostazioni si
/// cambiano.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SettingComparison {
    /// Il modello non si esprime: non c'è nulla da confrontare.
    NotPrescribed,
    /// Il modello prevede ciò che è già in vigore.
    Matches {
        /// Il valore, detto a chi legge.
        value: String,
    },
    /// Il modello prevede qualcosa di diverso da ciò che è in vigore.
    Differs {
        /// Che cosa il modello prevede.
        prescribed: String,
        /// Che cosa è in vigore adesso.
        current: String,
        /// Vero quando adottare il valore previsto **cancellerebbe**
        /// materiale: una conservazione più corta di quella in vigore.
        ///
        /// # Perché una domanda e non un confronto scritto altrove
        ///
        /// Perché è l'unica differenza che, se qualcuno la adottasse senza
        /// leggerla, **distruggerebbe qualcosa**. Chi mostra la riga deve poter
        /// chiedere «questa cancella?» senza rifare l'aritmetica dei giorni.
        deletes: bool,
    },
}

impl SettingComparison {
    /// Se c'è una differenza da leggere.
    #[must_use]
    pub const fn differs(&self) -> bool {
        matches!(self, Self::Differs { .. })
    }

    /// Se adottare il valore previsto cancellerebbe materiale.
    #[must_use]
    pub const fn deletes(&self) -> bool {
        matches!(self, Self::Differs { deletes: true, .. })
    }

    /// Che cosa si è confrontato, detto a chi legge.
    #[must_use]
    pub fn as_sentence(&self, what: &str) -> String {
        match self {
            Self::NotPrescribed => format!("{what}: il modello non si esprime, e nulla cambia."),
            Self::Matches { value } => {
                format!("{what}: il modello prevede {value}, che \u{e8} gi\u{e0} in vigore.")
            }
            Self::Differs {
                prescribed,
                current,
                deletes: false,
            } => format!(
                "{what}: il modello prevede {prescribed}, adesso \u{e8} {current}. Applicare \
                 il modello non la cambia: \u{e8} un'impostazione della postazione, e vale anche \
                 per i monitoraggi gi\u{e0} conclusi."
            ),
            Self::Differs {
                prescribed,
                current,
                deletes: true,
            } => format!(
                "{what}: il modello prevede {prescribed}, adesso \u{e8} {current}. Adottarla \
                 cancellerebbe materiale gi\u{e0} acquisito che oggi si conserva. Applicare il \
                 modello non la cambia: se serve cambiarla, si fa dalle impostazioni, dove la \
                 conseguenza \u{e8} scritta."
            ),
        }
    }
}

/// Confronta ciò che il modello prevede per la conservazione con ciò che è in
/// vigore.
///
/// # Perché una funzione e non un confronto scritto dove serve
///
/// Perché la domanda «questo cancellerebbe?» ha una risposta sola, e scriverla
/// in due posti significherebbe scriverla diversa. In particolare: **conservare
/// tutto non cancella mai**, e passare da un limite a nessun limite è un
/// allargamento, non una perdita.
#[must_use]
pub fn compare_retention(
    prescribed: PrescribedRetention,
    current_keep_days: Option<u32>,
) -> SettingComparison {
    let corrente = match current_keep_days {
        None => String::from("conservare tutto"),
        Some(giorni) => format!("{giorni} giorni"),
    };

    match prescribed {
        PrescribedRetention::Silent => SettingComparison::NotPrescribed,
        PrescribedRetention::KeepEverything => {
            if current_keep_days.is_none() {
                SettingComparison::Matches { value: corrente }
            } else {
                // ALLARGARE NON CANCELLA: si conserverebbe di piu', non di meno.
                SettingComparison::Differs {
                    prescribed: String::from("conservare tutto"),
                    current: corrente,
                    deletes: false,
                }
            }
        }
        PrescribedRetention::KeepDays(previsti) => match current_keep_days {
            Some(correnti) if correnti == previsti => {
                SettingComparison::Matches { value: corrente }
            }
            // DA «CONSERVA TUTTO» A UN LIMITE: cancella tutto cio' che e' piu'
            // vecchio del limite, ed e' il caso peggiore.
            None => SettingComparison::Differs {
                prescribed: format!("{previsti} giorni"),
                current: corrente,
                deletes: true,
            },
            Some(correnti) => SettingComparison::Differs {
                prescribed: format!("{previsti} giorni"),
                current: corrente,
                deletes: previsti < correnti,
            },
        },
    }
}

/// Confronta ciò che il modello prevede per la soglia di notifica con ciò che è
/// in vigore.
#[must_use]
pub fn compare_notification_level(prescribed: Prescribed<u8>, current: u8) -> SettingComparison {
    match prescribed {
        Prescribed::Silent => SettingComparison::NotPrescribed,
        Prescribed::Value(previsto) if previsto == current => SettingComparison::Matches {
            value: format!("livello {previsto}"),
        },
        Prescribed::Value(previsto) => SettingComparison::Differs {
            prescribed: format!("livello {previsto}"),
            current: format!("livello {current}"),
            // UNA SOGLIA NON CANCELLA NIENTE: cambia quanto si viene avvisati,
            // non che cosa si conserva.
            deletes: false,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::{
        MonitoringTemplate, NewMonitoringTemplate, Prescribed, PrescribedRetention,
        SettingComparison, compare_notification_level, compare_retention,
    };
    use crate::text::{Actor, DisplayName};
    use crate::time::Timestamp;
    use crate::{MonitoringTemplateId, SourceId};

    /// Questo modulo, per le guardie strutturali.
    const THIS_MODULE: &str = include_str!("monitoring_template.rs");

    const ORA: i64 = 1_700_000_000_000;

    fn attore() -> Actor {
        let Ok(attore) = Actor::try_new("operatore.prova") else {
            panic!("l'attore di prova deve essere valido");
        };
        attore
    }

    fn nome(testo: &str) -> DisplayName {
        let Ok(nome) = DisplayName::try_new(testo) else {
            panic!("il nome di prova deve essere valido");
        };
        nome
    }

    /// **Un modello senza fonti non si crea.**
    ///
    /// # Il difetto che questa prova impedisce
    ///
    /// Un modello che, applicato, non prepara nulla. Chi lo ha salvato crede di
    /// avere una configurazione riusabile, e se ne accorge davanti a un
    /// monitoraggio vuoto.
    #[test]
    fn un_modello_senza_fonti_non_si_crea() {
        assert!(
            NewMonitoringTemplate::of(
                nome("Vuoto"),
                None,
                Vec::new(),
                None,
                Prescribed::Silent,
                PrescribedRetention::Silent,
                attore(),
            )
            .is_err(),
            "applicarlo non preparerebbe nulla"
        );

        assert!(
            NewMonitoringTemplate::of(
                nome("Con una fonte"),
                None,
                vec![SourceId::new(1)],
                None,
                Prescribed::Silent,
                PrescribedRetention::Silent,
                attore(),
            )
            .is_ok()
        );
    }

    /// **Una soglia fuori dai livelli che esistono non si prescrive.**
    #[test]
    fn una_soglia_che_non_esiste_non_si_prescrive() {
        for livello in [0_u8, 5, 9] {
            assert!(
                NewMonitoringTemplate::of(
                    nome("Soglia impossibile"),
                    None,
                    vec![SourceId::new(1)],
                    None,
                    Prescribed::Value(livello),
                    PrescribedRetention::Silent,
                    attore(),
                )
                .is_err(),
                "il livello {livello} non e' una soglia"
            );
        }
        for livello in 1..=4_u8 {
            assert!(
                NewMonitoringTemplate::of(
                    nome("Soglia"),
                    None,
                    vec![SourceId::new(1)],
                    None,
                    Prescribed::Value(livello),
                    PrescribedRetention::Silent,
                    attore(),
                )
                .is_ok()
            );
        }
    }

    /// **«Non si esprime» non è «prevede lo stesso valore».**
    ///
    /// # Il difetto che questa prova impedisce
    ///
    /// Il silenzio letto come un'approvazione. Un modello che non dice nulla
    /// sulla conservazione **non prescrive** la conservazione corrente: non ne
    /// parla, e mostrarne il confronto direbbe che qualcuno ha deciso.
    #[test]
    fn il_silenzio_non_e_un_valore() {
        assert_eq!(
            compare_retention(PrescribedRetention::Silent, Some(30)),
            SettingComparison::NotPrescribed
        );
        assert_eq!(
            compare_notification_level(Prescribed::Silent, 2),
            SettingComparison::NotPrescribed
        );

        // E «prevede lo stesso valore» E' un confronto, con esito «uguale».
        assert!(matches!(
            compare_retention(PrescribedRetention::KeepDays(30), Some(30)),
            SettingComparison::Matches { .. }
        ));
    }

    /// **Solo una conservazione più corta cancella.**
    ///
    /// # Il difetto che questa prova impedisce
    ///
    /// Un avviso che grida al lupo su ogni differenza, o — peggio — che tace
    /// sulla sola che distrugge qualcosa. Passare da «conserva tutto» a un
    /// limite è il caso peggiore, e va riconosciuto: nessun numero è più
    /// piccolo di «nessun limite», e un confronto fra numeri lo mancherebbe.
    #[test]
    fn solo_una_conservazione_piu_corta_cancella() {
        // Da nessun limite a un limite: cancella.
        assert!(compare_retention(PrescribedRetention::KeepDays(30), None).deletes());
        // Piu' corta: cancella.
        assert!(compare_retention(PrescribedRetention::KeepDays(30), Some(90)).deletes());
        // Piu' lunga: non cancella, allarga.
        assert!(!compare_retention(PrescribedRetention::KeepDays(90), Some(30)).deletes());
        // Da un limite a nessun limite: non cancella.
        assert!(!compare_retention(PrescribedRetention::KeepEverything, Some(30)).deletes());
        // Uguale: non e' nemmeno una differenza.
        assert!(!compare_retention(PrescribedRetention::KeepDays(30), Some(30)).differs());

        // E UNA SOGLIA NON CANCELLA MAI: cambia quanto si viene avvisati.
        assert!(!compare_notification_level(Prescribed::Value(4), 1).deletes());
        assert!(compare_notification_level(Prescribed::Value(4), 1).differs());
    }

    /// **La frase di una differenza dice che applicare il modello non la
    /// cambia.**
    ///
    /// # Perché conta
    ///
    /// Perché è il punto della milestone. Chi legge «il modello prevede 30
    /// giorni, adesso sono 90» deve sapere **che cosa succederà premendo
    /// Applica**, e la risposta è: niente, su quella riga.
    #[test]
    fn la_frase_dice_che_applicare_non_cambia_le_impostazioni() {
        let piu_corta = compare_retention(PrescribedRetention::KeepDays(30), Some(90));
        let frase = piu_corta.as_sentence("Conservazione");
        assert!(frase.contains("30 giorni"), "{frase}");
        assert!(frase.contains("90 giorni"), "{frase}");
        assert!(frase.contains("cancellerebbe"), "{frase}");
        assert!(
            frase.contains("Applicare il modello non la cambia"),
            "deve dire che cosa succede premendo Applica \u{2014} {frase}"
        );

        let soglia = compare_notification_level(Prescribed::Value(4), 1);
        let frase = soglia.as_sentence("Soglia di notifica");
        assert!(
            frase.contains("Applicare il modello non la cambia"),
            "{frase}"
        );
        assert!(
            !frase.contains("cancellerebbe"),
            "una soglia non cancella \u{2014} {frase}"
        );
    }

    /// **Il modello non conserva le versioni dei dizionari.**
    ///
    /// # Il difetto che questa prova impedisce
    ///
    /// Un modello che fissa le versioni. Un monitoraggio preparato da quel
    /// modello userebbe per sempre i dizionari com'erano il giorno in cui fu
    /// creato, e smetterebbe **in silenzio** di raccogliere le correzioni — che
    /// sono ciò per cui FEEDBACK-01 esiste.
    #[test]
    fn il_modello_non_conserva_le_versioni_dei_dizionari() {
        let Some((produzione, _)) = THIS_MODULE.split_once("#[cfg(test)]\nmod tests {") else {
            panic!("il modulo deve avere un blocco di prove riconoscibile");
        };
        for tipo in [
            "pub struct NewMonitoringTemplate {",
            "pub struct MonitoringTemplate {",
        ] {
            let Some(inizio) = produzione.find(tipo) else {
                panic!("«{tipo}» deve esistere");
            };
            let campi = &produzione[inizio + tipo.len()..];
            let Some(fine) = campi.find("\n}\n") else {
                panic!("«{tipo}» deve chiudersi");
            };
            for versione in ["DictionaryVersionId", "version_id", "versione"] {
                assert!(
                    !campi[..fine].contains(versione),
                    "«{tipo}» dichiara «{versione}»: fisserebbe le versioni, e il modello \
                     smetterebbe di raccogliere le correzioni dei dizionari"
                );
            }
        }
    }

    /// **La frase del modello dice chi, quando e quanto prevede.**
    #[test]
    fn la_frase_del_modello_dice_chi_quando_e_quanto() {
        let modello = MonitoringTemplate {
            id: MonitoringTemplateId::new(1),
            name: nome("Monitoraggio di marzo"),
            description: None,
            sources: vec![SourceId::new(1), SourceId::new(2)],
            dictionary_profile: None,
            notification_level: Prescribed::Silent,
            retention: PrescribedRetention::Silent,
            created_by: attore(),
            created_at: Timestamp::from_millis(ORA),
        };
        let frase = modello.as_sentence();
        assert!(frase.contains("operatore.prova"), "{frase}");
        assert!(frase.contains("2 fonti"), "{frase}");
        assert!(frase.contains("nessun profilo"), "{frase}");

        // UNA FONTE SOLA SI DICE AL SINGOLARE (E2E01-15): «Prevede 1 fonti» era
        // sullo schermo.
        let una = MonitoringTemplate {
            sources: vec![SourceId::new(1)],
            ..modello
        };
        let frase = una.as_sentence();
        assert!(frase.contains("Prevede 1 fonte "), "{frase}");
    }

    /// **Il modello dice se si esprime.**
    #[test]
    fn il_modello_dice_se_si_esprime() {
        assert!(!Prescribed::<u8>::Silent.speaks());
        assert!(Prescribed::Value(3_u8).speaks());
        assert!(!PrescribedRetention::Silent.speaks());
        assert!(PrescribedRetention::KeepEverything.speaks());
        assert!(PrescribedRetention::KeepDays(30).speaks());
    }
}
