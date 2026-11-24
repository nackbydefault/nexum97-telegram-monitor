//! Cronologia di un'identità osservata (PERS-04).
//!
//! # La cosa che questa milestone deve dire, e che nessuno vedrebbe da sé
//!
//! **Un vuoto nella cronologia non è un silenzio della persona.**
//!
//! Una cronologia mette dei fatti su una linea, e una linea con dei buchi si
//! legge in un modo solo: «qui non ha fatto niente». Ma l'archivio non sa che
//! cosa una persona abbia fatto: sa **che cosa ha visto**, e ha visto soltanto
//! durante i monitoraggi, soltanto nelle fonti di quei monitoraggi.
//!
//! Fra un monitoraggio e l'altro **nessuno stava guardando**, e in quel
//! periodo l'assenza di righe non significa niente. Scrivere in una relazione
//! «dal 3 marzo al 20 aprile non ha scritto nulla» sarebbe un fatto che nessuno
//! ha misurato — ed è il genere di frase che, in un fascicolo, pesa.
//!
//! È ADR-0053 applicato a una persona: **assenza di evidenza non è evidenza di
//! assenza**, la stessa distinzione che vale per la salute di una fonte, dove
//! «silenziosa» non è «guasta».
//!
//! # Come il tipo lo impedisce, invece di ricordarselo
//!
//! [`PersonTimeline`] **non è costruibile senza le sue finestre di
//! osservazione**: il campo è privato, il costruttore le vuole, non c'è
//! `Default` e non c'è un `Option` da passare `None`.
//!
//! Una cronologia senza finestre sarebbe una cronologia che **mente per
//! omissione**, e mentire per omissione è più facile che mentire: nessuno se ne
//! accorge guardandola. È la stessa forma di garanzia della provenienza di
//! PERS-03: il compilatore, non una convenzione.
//!
//! # Che cosa sta sulla linea, e di chi è l'atto
//!
//! Solo **atti della persona** — ha scritto un contenuto — e **osservazioni
//! dell'archivio** — un nome nuovo è stato visto per la prima volta.
//!
//! Un alert **non è un atto della persona**: lo alza il programma su un
//! contenuto. Compare quindi come **proprietà della riga del contenuto**, non
//! come una riga propria: una riga «alert alzato» in mezzo agli atti di qualcuno
//! attribuirebbe a quella persona un gesto del software.
//!
//! # Nessun soggetto, nessun punteggio
//!
//! Come in PERS-02 e PERS-03: qui si parla di un **identificativo osservato**.
//! Il collegamento a un fascicolo è PERS-06, ed è manuale. E una cronologia non
//! ha campi numerici, perché un numero accanto a una persona si legge come un
//! punteggio.

use crate::model::observed_identity::AliasKind;
use crate::time::Timestamp;
use crate::{AlertId, ContentId, SourceId};

/// Che cosa è successo, e di chi è l'atto.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TimelineEvent {
    /// **Atto della persona:** ha scritto un contenuto.
    WroteContent {
        /// Quale contenuto.
        content: ContentId,
        /// Da quale fonte.
        source: SourceId,
        /// L'alert alzato su quel contenuto, se ce n'è uno.
        ///
        /// # Perché qui e non su una riga propria
        ///
        /// Perché alzare un alert **non è un atto della persona**: lo fa il
        /// programma, su un contenuto. Una riga propria, in mezzo agli atti di
        /// qualcuno, glielo attribuirebbe.
        raised_alert: Option<AlertId>,
    },
    /// **Osservazione dell'archivio:** un nome nuovo è stato visto.
    ///
    /// # Perché «osservato» e non «cambiato»
    ///
    /// Perché l'archivio sa quando ha **visto** un nome nuovo, non quando quella
    /// persona lo ha adottato. È la decisione di PERS-02, e su una **linea del
    /// tempo** diventa più pericolosa, non meno: una data messa accanto a
    /// un'altra sembra dire qualcosa.
    AliasFirstObserved {
        /// Nome visualizzato o username.
        kind: AliasKind,
        /// Il valore osservato, oppure niente se in quel periodo non ce n'era.
        value: Option<String>,
        /// In quale contenuto lo si è osservato.
        content: ContentId,
    },
}

impl TimelineEvent {
    /// Che cosa è successo, detto a chi legge.
    ///
    /// # Che cosa queste frasi non dicono
    ///
    /// Nessuna dice che la persona **sia** qualcosa, e nessuna afferma un
    /// istante che l'archivio non ha misurato.
    #[must_use]
    pub fn as_sentence(&self) -> String {
        match self {
            Self::WroteContent {
                content,
                source,
                raised_alert,
            } => {
                let base = format!(
                    "Ha scritto il contenuto #{} nella fonte #{}.",
                    content.get(),
                    source.get()
                );
                match raised_alert {
                    Some(alert) => format!(
                        "{base} Su quel contenuto il programma ha emesso l'avviso n. {}.",
                        alert.get()
                    ),
                    None => base,
                }
            }
            Self::AliasFirstObserved {
                kind,
                value,
                content,
            } => match value {
                Some(valore) => format!(
                    "{}: \u{ab}{valore}\u{bb}, osservato per la prima volta nel contenuto #{}.",
                    kind.as_label(),
                    content.get()
                ),
                None => format!(
                    "{}: nessuno, in ci\u{f2} che si \u{e8} osservato dal contenuto #{}. Non \
                     significa che sia stato tolto.",
                    kind.as_label(),
                    content.get()
                ),
            },
        }
    }
}

/// Una riga della cronologia.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TimelineEntry {
    /// Quando.
    pub at: Timestamp,
    /// Che cosa.
    pub event: TimelineEvent,
}

/// Quando l'archivio **stava guardando**, e dove.
///
/// # Perché la definizione non è più qui
///
/// Perché lo stesso problema si ripresenta ovunque il prodotto disegni una
/// linea del tempo, e CYT-01 lo ha incontrato sui grappoli di segnali. Il tipo
/// vive ora in [`crate::model::observation_window`], **uno solo**: due copie
/// resterebbero d'accordo finché nessuno tocca una delle due, e il giorno in
/// cui una imparasse a dire «fino a oggi» e l'altra no, due schermate direbbero
/// due verità diverse sullo stesso periodo.
///
/// Questo percorso resta valido, e continua a indicare quel tipo.
pub use crate::model::observation_window::ObservationWindow;

/// La cronologia di un'identità osservata, **con le sue finestre**.
///
/// # Perché il campo delle finestre è privato
///
/// Perché una cronologia senza finestre mente per omissione, e mentire per
/// omissione è più facile che mentire: nessuno se ne accorge guardandola.
///
/// Il costruttore le vuole. Non c'è `Default`, non c'è un campo pubblico da
/// lasciare vuoto, e non c'è un `Option` da passare `None`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PersonTimeline {
    /// L'identificativo osservato presso la piattaforma.
    ///
    /// **Non un identificativo di fascicolo**: quello è PERS-06, ed è manuale.
    identifier: String,
    /// Le righe, dalla più antica.
    entries: Vec<TimelineEntry>,
    /// Quando si stava guardando.
    windows: Vec<ObservationWindow>,
}

impl PersonTimeline {
    /// Una cronologia, che **richiede** le sue finestre di osservazione.
    #[must_use]
    pub const fn new(
        identifier: String,
        entries: Vec<TimelineEntry>,
        windows: Vec<ObservationWindow>,
    ) -> Self {
        Self {
            identifier,
            entries,
            windows,
        }
    }

    /// L'identificativo osservato.
    #[must_use]
    pub fn identifier(&self) -> &str {
        &self.identifier
    }

    /// Le righe, dalla più antica.
    #[must_use]
    pub fn entries(&self) -> &[TimelineEntry] {
        &self.entries
    }

    /// Quando si stava guardando.
    #[must_use]
    pub fn windows(&self) -> &[ObservationWindow] {
        &self.windows
    }

    /// L'avvertenza che accompagna la cronologia.
    ///
    /// # Perché compare sempre, e non solo quando c'è un vuoto
    ///
    /// Perché «c'è un vuoto» è già un giudizio: dipende da quanto è lungo il
    /// periodo che qualcuno considera significativo, e quel numero non lo
    /// decide il programma.
    ///
    /// E perché una cronologia **è sempre parziale**, anche fitta: copre le
    /// fonti monitorate e nient'altro. Una persona può aver scritto altrove per
    /// tutto il tempo.
    #[must_use]
    pub fn caveat(&self) -> String {
        if self.windows.is_empty() {
            // NESSUNA FINESTRA: non e' una cronologia vuota, e' una cronologia
            // di cui non si sa nulla. Dirlo e' l'unica cosa onesta.
            return String::from(
                "Non risulta alcun periodo di osservazione: questa cronologia non dice nulla, \
                 nemmeno che non sia successo niente.",
            );
        }
        String::from(
            "Queste righe dicono che cosa si \u{e8} osservato, e si \u{e8} osservato soltanto \
             durante i monitoraggi elencati e soltanto nelle loro fonti. Un periodo senza righe \
             non significa che la persona non abbia scritto: pu\u{f2} significare che nessuno \
             stava guardando.",
        )
    }
}

/// Ciò che serve a comporre una riga: un fatto già nell'archivio.
///
/// # Perché senza il corpo del messaggio
///
/// Per la ragione di PERS-02 e PERS-03: alla composizione non serve il testo, e
/// **una funzione che non riceve una cosa non può usarla**.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TimelineFact {
    /// Quale contenuto.
    pub content: ContentId,
    /// Chi lo ha scritto, presso la piattaforma.
    pub identifier: String,
    /// Da quale fonte.
    pub source: SourceId,
    /// Quando è stato pubblicato.
    pub at: Timestamp,
    /// L'alert alzato su quel contenuto, se ce n'è uno.
    pub alert: Option<AlertId>,
    /// Il nome leggibile annunciato in quel contenuto.
    pub display_name: Option<String>,
    /// Lo username annunciato in quel contenuto.
    pub username: Option<String>,
}

/// Compone la cronologia di ogni identità osservata.
///
/// # Perché una funzione pura
///
/// Perché la composizione è la parte che merita una prova, e una prova non deve
/// costruire un archivio per esercitarla. È la scelta di PERS-02 e PERS-03.
///
/// # Le finestre arrivano da fuori, e non si indovinano
///
/// Perché sono un fatto dei **monitoraggi**, non dei contenuti: un monitoraggio
/// che non ha raccolto niente ha comunque guardato, e dedurre le finestre dai
/// contenuti lo perderebbe — cioè perderebbe esattamente il caso in cui un vuoto
/// va spiegato.
#[must_use]
pub fn timelines_for(facts: &[TimelineFact], windows: &[ObservationWindow]) -> Vec<PersonTimeline> {
    // ORDINE RIPETIBILE.
    //
    // A parita' di istante decide l'identificativo del contenuto: senza un
    // criterio secondario, due letture darebbero due cronologie diverse, e una
    // cronologia che cambia ordine non e' una cronologia.
    let mut ordinati: Vec<&TimelineFact> = facts.iter().collect();
    ordinati.sort_by(|a, b| {
        a.at.cmp(&b.at)
            .then(a.content.get().cmp(&b.content.get()))
            .then(a.identifier.cmp(&b.identifier))
    });

    let mut per_identificativo: std::collections::BTreeMap<&str, Vec<TimelineEntry>> =
        std::collections::BTreeMap::new();
    // L'ultimo valore visto per ogni (identificativo, genere): serve a
    // riconoscere un nome NUOVO, che e' l'unica cosa che merita una riga.
    let mut ultimo: std::collections::BTreeMap<(&str, AliasKind), Option<String>> =
        std::collections::BTreeMap::new();

    for fatto in ordinati {
        let righe = per_identificativo
            .entry(fatto.identifier.as_str())
            .or_default();

        righe.push(TimelineEntry {
            at: fatto.at,
            event: TimelineEvent::WroteContent {
                content: fatto.content,
                source: fatto.source,
                raised_alert: fatto.alert,
            },
        });

        // UN NOME NUOVO MERITA UNA RIGA; LO STESSO NOME NO.
        //
        // Mille righe «si chiama ancora cosi'» sono un elenco che nessuno
        // scorre, e in mezzo al quale il cambiamento vero sparisce. E' la
        // lezione di PERS-02.
        for (kind, valore) in [
            (AliasKind::DisplayName, &fatto.display_name),
            (AliasKind::Username, &fatto.username),
        ] {
            let chiave = (fatto.identifier.as_str(), kind);
            let visto_prima = ultimo.get(&chiave);
            if visto_prima != Some(valore) {
                // La PRIMA osservazione non e' un cambiamento: e' l'inizio.
                // Merita una riga solo se qualcosa era gia' stato visto.
                if visto_prima.is_some() {
                    righe.push(TimelineEntry {
                        at: fatto.at,
                        event: TimelineEvent::AliasFirstObserved {
                            kind,
                            value: valore.clone(),
                            content: fatto.content,
                        },
                    });
                }
                ultimo.insert(chiave, valore.clone());
            }
        }
    }

    per_identificativo
        .into_iter()
        .map(|(identificativo, righe)| {
            PersonTimeline::new(identificativo.to_owned(), righe, windows.to_vec())
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::{ObservationWindow, PersonTimeline, TimelineEvent, TimelineFact, timelines_for};
    use crate::model::observed_identity::AliasKind;
    use crate::time::Timestamp;
    use crate::{AlertId, ContentId, SessionId, SourceId};

    const ORA: Timestamp = Timestamp::from_millis(1_760_000_000_000);

    fn fatto(content: i64, identifier: &str, at: Timestamp) -> TimelineFact {
        TimelineFact {
            content: ContentId::new(content),
            identifier: identifier.to_owned(),
            source: SourceId::new(7),
            at,
            alert: None,
            display_name: Some("Mario Rossi".to_owned()),
            username: None,
        }
    }

    fn finestra(session: i64, from: Timestamp, to: Option<Timestamp>) -> ObservationWindow {
        ObservationWindow {
            session: SessionId::new(session),
            from,
            to,
        }
    }

    /// **Una cronologia porta sempre le sue finestre di osservazione.**
    ///
    /// # Perché è la guardia di questa milestone
    ///
    /// Perché senza di esse un periodo senza righe si legge come «non ha fatto
    /// niente», che è un fatto che nessuno ha misurato.
    #[test]
    fn una_cronologia_porta_sempre_le_sue_finestre() {
        let finestre = vec![finestra(
            1,
            ORA,
            Some(Timestamp::from_millis(ORA.as_millis() + 1_000)),
        )];
        let cronologie = timelines_for(&[fatto(1, "111", ORA)], &finestre);

        assert_eq!(cronologie.len(), 1);
        assert_eq!(
            cronologie[0].windows().len(),
            1,
            "le finestre viaggiano con la cronologia"
        );
    }

    /// **Un vuoto non è un silenzio, e la frase lo dice.**
    #[test]
    fn un_vuoto_non_e_un_silenzio() {
        let finestre = vec![finestra(1, ORA, Some(ORA))];
        let cronologie = timelines_for(&[fatto(1, "111", ORA)], &finestre);
        let frase = cronologie[0].caveat();

        assert!(
            frase.contains("non significa che la persona non abbia scritto"),
            "l'avvertenza deve negare esplicitamente la lettura sbagliata: {frase}"
        );
        assert!(
            frase.contains("nessuno stava guardando"),
            "e deve dire perche': {frase}"
        );
    }

    /// **Senza finestre, la cronologia dichiara di non dire nulla.**
    ///
    /// # Perché non basta un elenco vuoto
    ///
    /// Perché una cronologia senza righe e senza finestre è indistinguibile, a
    /// vista, da una persona che non ha scritto niente — ed è invece una persona
    /// di cui non si sa nulla.
    #[test]
    fn senza_finestre_la_cronologia_dichiara_di_non_dire_nulla() {
        let cronologie = timelines_for(&[fatto(1, "111", ORA)], &[]);
        let frase = cronologie[0].caveat();

        assert!(
            frase.contains("non dice nulla"),
            "deve dichiararlo: {frase}"
        );
        assert!(
            frase.contains("nemmeno che non sia successo niente"),
            "e deve negare la lettura sbagliata: {frase}"
        );
    }

    /// **Un monitoraggio non concluso non è «osservato fino a oggi».**
    #[test]
    fn un_monitoraggio_non_concluso_non_arriva_fino_a_oggi() {
        let aperta = finestra(1, ORA, None);
        let frase = aperta.as_sentence();

        assert!(
            frase.contains("non risulta concluso"),
            "deve dirlo: {frase}"
        );
        assert!(
            frase.contains("Non significa che l'osservazione sia arrivata fino a oggi"),
            "e deve negare la lettura sbagliata: {frase}"
        );
    }

    /// **Un alert non è una riga propria: è una proprietà del contenuto.**
    ///
    /// # Perché conta
    ///
    /// Perché alzare un alert è un atto del **programma**. Una riga «alert
    /// alzato» in mezzo agli atti di qualcuno glielo attribuirebbe.
    #[test]
    fn un_alert_non_e_un_atto_della_persona() {
        let mut f = fatto(1, "111", ORA);
        f.alert = Some(AlertId::new(42));
        let cronologie = timelines_for(&[f], &[finestra(1, ORA, Some(ORA))]);

        let righe = cronologie[0].entries();
        assert_eq!(righe.len(), 1, "una riga sola: il contenuto scritto");

        let TimelineEvent::WroteContent { raised_alert, .. } = &righe[0].event else {
            panic!("la riga deve essere il contenuto scritto");
        };
        assert_eq!(*raised_alert, Some(AlertId::new(42)));

        let frase = righe[0].event.as_sentence();
        assert!(
            frase.contains("il programma ha emesso l'avviso"),
            "la frase deve dire di chi e' l'atto: {frase}"
        );
    }

    /// **Un nome nuovo merita una riga; lo stesso nome no.**
    #[test]
    fn solo_un_nome_nuovo_merita_una_riga() {
        let mut primo = fatto(1, "111", ORA);
        primo.display_name = Some("Mario Rossi".to_owned());
        let mut secondo = fatto(2, "111", Timestamp::from_millis(ORA.as_millis() + 10));
        secondo.display_name = Some("Mario Rossi".to_owned());
        let mut terzo = fatto(3, "111", Timestamp::from_millis(ORA.as_millis() + 20));
        terzo.display_name = Some("Mario R.".to_owned());

        let cronologie = timelines_for(&[primo, secondo, terzo], &[finestra(1, ORA, Some(ORA))]);
        let alias = cronologie[0]
            .entries()
            .iter()
            .filter(|riga| matches!(riga.event, TimelineEvent::AliasFirstObserved { .. }))
            .count();

        assert_eq!(
            alias, 1,
            "tre contenuti, un solo cambiamento: una riga sola, e non la prima"
        );
    }

    /// **La riga di un alias dice «osservato», mai «cambiato».**
    #[test]
    fn la_riga_di_un_alias_dice_osservato() {
        let evento = TimelineEvent::AliasFirstObserved {
            kind: AliasKind::DisplayName,
            value: Some("Mario R.".to_owned()),
            content: ContentId::new(3),
        };
        let frase = evento.as_sentence();

        assert!(frase.contains("osservato"), "{frase}");
        for vietata in ["cambiat", "modificat", "rinominat"] {
            assert!(
                !frase.to_lowercase().contains(vietata),
                "la frase dice «{vietata}»: e' un istante che nessuno ha misurato \u{2014} {frase}"
            );
        }
    }

    /// **L'ordine è ripetibile.**
    #[test]
    fn l_ordine_e_ripetibile() {
        let fatti = vec![
            fatto(9, "111", ORA),
            fatto(3, "111", ORA),
            fatto(5, "111", ORA),
        ];
        let finestre = vec![finestra(1, ORA, Some(ORA))];

        let prima = timelines_for(&fatti, &finestre);
        let seconda = timelines_for(&fatti, &finestre);
        assert_eq!(prima, seconda, "due letture danno la stessa cronologia");

        let contenuti: Vec<i64> = prima[0]
            .entries()
            .iter()
            .filter_map(|riga| match riga.event {
                TimelineEvent::WroteContent { content, .. } => Some(content.get()),
                TimelineEvent::AliasFirstObserved { .. } => None,
            })
            .collect();
        assert_eq!(
            contenuti,
            vec![3, 5, 9],
            "a parita' di istante decide l'identificativo"
        );
    }

    /// **Due persone hanno due cronologie.**
    #[test]
    fn due_persone_hanno_due_cronologie() {
        let cronologie = timelines_for(
            &[
                fatto(1, "111", ORA),
                fatto(2, "222", Timestamp::from_millis(ORA.as_millis() + 10)),
            ],
            &[finestra(1, ORA, Some(ORA))],
        );

        assert_eq!(cronologie.len(), 2);
        let identificativi: Vec<&str> = cronologie.iter().map(PersonTimeline::identifier).collect();
        assert!(identificativi.contains(&"111") && identificativi.contains(&"222"));
    }

    /// **Le finestre non si indovinano dai contenuti.**
    ///
    /// # Perché conta
    ///
    /// Perché un monitoraggio che non ha raccolto niente **ha comunque
    /// guardato**, e dedurre le finestre dai contenuti perderebbe esattamente il
    /// caso in cui un vuoto va spiegato.
    #[test]
    fn le_finestre_non_si_indovinano_dai_contenuti() {
        let produzione = codice_senza_commenti();
        assert!(
            produzione.contains("windows: &[ObservationWindow]"),
            "le finestre arrivano da fuori"
        );
        for dedotta in [
            "fn derive_windows",
            "fn finestre_dai_contenuti",
            "min_by_key",
        ] {
            assert!(
                !produzione.contains(dedotta),
                "«{dedotta}»: una finestra dedotta dai contenuti perde il monitoraggio che non ha \
                 raccolto niente"
            );
        }
    }

    /// **La cronologia non nomina un soggetto, e non ha campi numerici.**
    #[test]
    fn nessun_soggetto_e_nessun_campo_numerico() {
        let produzione = codice_senza_commenti();
        for collegamento in ["PersonId", "NewPerson", "model::person::"] {
            assert!(
                !produzione.contains(collegamento),
                "nomina «{collegamento}»: il collegamento a un fascicolo e' PERS-06"
            );
        }

        const INTESTAZIONE: &str = "pub struct PersonTimeline {";
        let Some(inizio) = produzione.find(INTESTAZIONE) else {
            panic!("la struttura deve esistere");
        };
        let campi = &produzione[inizio + INTESTAZIONE.len()..];
        let Some(fine) = campi.find("\n}\n") else {
            panic!("la struttura deve chiudersi");
        };
        for numerico in ["f32", "f64", "i32", "i64", "u32", "u64", "usize", "isize"] {
            assert!(
                !campi[..fine].contains(numerico),
                "un campo «{numerico}» accanto a una persona si legge come un punteggio"
            );
        }
    }

    /// **Le finestre non sono opzionali, e il campo non è pubblico.**
    #[test]
    fn le_finestre_non_sono_opzionali() {
        let produzione = codice_senza_commenti();

        assert!(
            !produzione.contains("Option<Vec<ObservationWindow>>"),
            "finestre opzionali si passano None, e la cronologia mentirebbe per omissione"
        );
        assert!(
            !produzione.contains("impl Default for PersonTimeline"),
            "un Default costruirebbe una cronologia senza finestre"
        );

        const INTESTAZIONE: &str = "pub struct PersonTimeline {";
        let Some(inizio) = produzione.find(INTESTAZIONE) else {
            panic!("la struttura deve esistere");
        };
        let campi = &produzione[inizio + INTESTAZIONE.len()..];
        let Some(fine) = campi.find("\n}\n") else {
            panic!("la struttura deve chiudersi");
        };
        assert!(
            !campi[..fine].contains("pub "),
            "un campo pubblico si riempie senza passare dal costruttore"
        );
    }

    /// Il codice di produzione di questo modulo, senza commenti.
    ///
    /// # Perché senza commenti
    ///
    /// Perché i commenti **nominano** ciò che le guardie vietano, per spiegare
    /// perché è vietato. Una guardia che li leggesse sarebbe rossa per la
    /// spiegazione invece che per il difetto.
    fn codice_senza_commenti() -> String {
        let sorgente = include_str!("person_timeline.rs");
        let Some(taglio) = sorgente.find("#[cfg(test)]") else {
            panic!("il modulo deve avere una sezione di prove");
        };
        sorgente[..taglio]
            .lines()
            .filter(|riga| !riga.trim_start().starts_with("//"))
            .collect::<Vec<_>>()
            .join("\n")
    }
}
