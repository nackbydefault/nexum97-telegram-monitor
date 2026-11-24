//! Associazioni di un'identità osservata, e la loro provenienza (PERS-03).
//!
//! # Che cosa è un'associazione qui, e che cosa non è
//!
//! È la risposta a una domanda sola: **che cosa risulta collegato a chi ha
//! scritto**, e **per quale fatto**.
//!
//! Non è un giudizio, non è un legame fra persone, non è una rete di contatti.
//! Ogni associazione nasce da un fatto già nell'archivio — questa identità ha
//! scritto quel contenuto, e quel contenuto ha quella proprietà — e porta con sé
//! il contenuto che la stabilisce.
//!
//! # Un'associazione senza provenienza non è costruibile
//!
//! I requisiti di sicurezza lo chiedono con queste parole: «ogni associazione
//! porta una provenienza: quale contenuto, quale fonte, quale istante, quale
//! regola. Un'associazione senza provenienza è la stessa cosa di un arco di
//! grafo senza provenienza, e **non deve essere costruibile**».
//!
//! «Non costruibile» non significa «rifiutata a tempo di esecuzione»: significa
//! che **non esiste la forma**. [`AssociationProvenance`] ha campi privati e un
//! solo costruttore che li vuole tutti e quattro; [`PersonAssociation`] lo
//! richiede per valore, non come opzione. Non c'è `Default`, non c'è un campo
//! pubblico da lasciare vuoto, e non c'è un `Option` da passare `None`.
//!
//! È la stessa forma di garanzia di `ArchiveRef`, che è `Copy` per non poter
//! contenere una copia della prova: il compilatore, non una convenzione.
//!
//! # Perché l'identità osservata, e non il soggetto
//!
//! Perché il collegamento fra un'identità osservata e un fascicolo è **PERS-06**,
//! ed è **manuale**, con operatore, motivo, istante e audit.
//!
//! PERS-02 ha chiuso quella porta di proposito. Se le associazioni parlassero di
//! `PersonId`, la riaprirebbero dalla finestra: chi apre un fascicolo si
//! troverebbe collegate cose che nessuno ha deciso di collegare, e la decisione
//! umana sarebbe stata saltata da un calcolo.
//!
//! Qui si parla di **un identificativo osservato**, che è un fatto della fonte.
//!
//! # Nessuna inferenza, e nessun posto in cui possa stare
//!
//! [`AssociationRule`] è un'enumerazione **chiusa** di cinque regole
//! deterministiche. Non c'è una variante «somiglianza», «probabile», «vicino»:
//! il congelamento vieta la fusione automatica di identità per somiglianza di
//! nome, e qui **non esiste la forma** in cui potrebbe stare.
//!
//! E un'associazione **non ha campi numerici**, per la stessa ragione per cui non
//! ne ha un soggetto (PERS-01): un numero accanto a una persona diventa un
//! punteggio anche quando chi lo ha scritto non lo intendeva così. Chi vuole
//! sapere quanti contenuti conta le righe.

use std::collections::BTreeSet;

use crate::model::indicator::IndicatorKind;
use crate::time::Timestamp;
use crate::{AlertId, ContentId, SourceId, WorkspaceId};

/// Per quale fatto una cosa risulta associata.
///
/// # Perché un'enumerazione chiusa
///
/// Perché l'insieme delle ragioni per cui questo prodotto collega qualcosa a
/// qualcuno deve essere **leggibile per intero in una schermata**, e deve poter
/// essere discusso. Una regola che si aggiunge è una decisione, non un dettaglio
/// di implementazione: passa da qui, e si vede.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum AssociationRule {
    /// Ha scritto questo contenuto.
    ///
    /// È il fatto primo: tutte le altre regole passano da qui.
    AuthoredContent,
    /// Il contenuto che ha scritto proviene da questa fonte.
    ContentFromSource,
    /// Sul contenuto che ha scritto è stato emesso questo avviso.
    ContentRaisedAlert,
    /// Il contenuto che ha scritto porta questo indicatore.
    ContentCarriesIndicator,
    /// Un workspace operativo raccoglie il contenuto che ha scritto.
    WorkspaceHoldsContent,
}

impl AssociationRule {
    /// Etichetta stabile, quella che non cambia con le parole dell'interfaccia.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::AuthoredContent => "ha_scritto_il_contenuto",
            Self::ContentFromSource => "contenuto_dalla_fonte",
            Self::ContentRaisedAlert => "contenuto_ha_alzato_alert",
            Self::ContentCarriesIndicator => "contenuto_porta_indicatore",
            Self::WorkspaceHoldsContent => "workspace_raccoglie_contenuto",
        }
    }

    /// Il fatto, detto a chi legge.
    ///
    /// # Che cosa queste frasi non dicono
    ///
    /// Nessuna dice che la persona **sia** qualcosa, o che **abbia fatto** più di
    /// ciò che l'archivio ha visto. Dicono che ha scritto un contenuto, e che
    /// quel contenuto ha una proprietà.
    #[must_use]
    pub const fn as_sentence(self) -> &'static str {
        match self {
            Self::AuthoredContent => "Ha scritto questo contenuto.",
            Self::ContentFromSource => "Ha scritto in questa fonte.",
            Self::ContentRaisedAlert => {
                "Su un contenuto che ha scritto \u{e8} stato emesso questo avviso."
            }
            Self::ContentCarriesIndicator => "Un contenuto che ha scritto porta questo indicatore.",
            Self::WorkspaceHoldsContent => "Un raccoglitore raccoglie un contenuto che ha scritto.",
        }
    }
}

/// Che cosa risulta associato.
///
/// # Perché non è un secondo `ArchiveRef`
///
/// Perché fanno due mestieri diversi, e confonderli costerebbe caro in una
/// direzione sola.
///
/// [`crate::model::reference::ArchiveRef`] è ciò che si **scrive**
/// nell'archivio — segnalibri, note, elementi di workspace — e per questo è
/// polimorfo su un intero: una tabella conserva `(genere, identificativo)`.
///
/// Questo tipo è **derivato e non si scrive mai**, e deve poter nominare cose
/// che un intero non indirizza: un indicatore non ha un identificativo, la sua
/// chiave è `(contenuto, genere, valore)`. Costringerlo dentro `ArchiveRef`
/// significherebbe inventargli un identificativo che l'archivio non gli dà.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum AssociationTarget {
    /// Un contenuto acquisito.
    Content(ContentId),
    /// Una fonte monitorata.
    Source(SourceId),
    /// Un alert alzato.
    Alert(AlertId),
    /// Un workspace operativo.
    Workspace(WorkspaceId),
    /// Un indicatore estratto, con la sua chiave naturale.
    ///
    /// # Perché genere e valore, e non un identificativo
    ///
    /// Perché gli indicatori non ne hanno uno: la migrazione che li conserva
    /// li chiude su `(contenuto, genere, valore)`. Il valore è quello
    /// **normalizzato**, che è la forma su cui il prodotto correla.
    Indicator {
        /// Che genere di indicatore.
        kind: IndicatorKind,
        /// Il valore normalizzato.
        value: String,
    },
}

impl AssociationTarget {
    /// Come si nomina il genere di cosa associata.
    #[must_use]
    pub const fn kind_label(&self) -> &'static str {
        match self {
            Self::Content(_) => "Contenuto",
            Self::Source(_) => "Fonte",
            Self::Alert(_) => "Alert",
            Self::Workspace(_) => "Raccoglitore",
            Self::Indicator { .. } => "Indicatore",
        }
    }
}

/// Perché questa associazione esiste: il fatto che la stabilisce.
///
/// # Perché i campi sono privati
///
/// Perché un campo pubblico si può lasciare vuoto, e una struttura con campi
/// pubblici si può costruire con la sintassi letterale saltando ogni
/// costruttore. Qui l'unico modo di ottenerne una è [`Self::of`], che li vuole
/// tutti e quattro.
///
/// I requisiti di sicurezza chiedono che un'associazione senza provenienza **non
/// sia costruibile**. Questo è il modo in cui non lo è.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct AssociationProvenance {
    /// Quale contenuto stabilisce il fatto.
    content: ContentId,
    /// Da quale fonte quel contenuto proviene.
    source: SourceId,
    /// Quando quel contenuto è stato pubblicato.
    at: Timestamp,
    /// Quale regola ha prodotto l'associazione.
    rule: AssociationRule,
}

impl AssociationProvenance {
    /// La provenienza di un'associazione: **tutti e quattro** i valori.
    ///
    /// # Perché non ci sono varianti con meno argomenti
    ///
    /// Perché una comodità che ne omettesse uno sarebbe la strada per cui una
    /// provenienza incompleta entra nell'archivio, e nessuno se ne accorge
    /// finché qualcuno non chiede «perché sto vedendo questo?» (ADR-0052).
    #[must_use]
    pub const fn of(
        content: ContentId,
        source: SourceId,
        at: Timestamp,
        rule: AssociationRule,
    ) -> Self {
        Self {
            content,
            source,
            at,
            rule,
        }
    }

    /// Quale contenuto stabilisce il fatto.
    #[must_use]
    pub const fn content(self) -> ContentId {
        self.content
    }

    /// Da quale fonte quel contenuto proviene.
    #[must_use]
    pub const fn source(self) -> SourceId {
        self.source
    }

    /// Quando quel contenuto è stato pubblicato.
    ///
    /// # Che cosa questo istante non è
    ///
    /// **Non è l'istante in cui l'associazione è stata decisa**, perché nessuno
    /// l'ha decisa: è l'istante del contenuto che la stabilisce. È la stessa
    /// distinzione di PERS-02 fra «osservato» e «cambiato», e vale qui per la
    /// stessa ragione.
    #[must_use]
    pub const fn at(self) -> Timestamp {
        self.at
    }

    /// Quale regola l'ha prodotta.
    #[must_use]
    pub const fn rule(self) -> AssociationRule {
        self.rule
    }

    /// La provenienza, detta a chi legge.
    #[must_use]
    pub fn as_sentence(&self) -> String {
        format!(
            "{} Osservato nel contenuto #{}, dalla fonte #{}, pubblicato il {}.",
            self.rule.as_sentence(),
            self.content.get(),
            self.source.get(),
            self.at.to_readable_utc()
        )
    }
}

/// Una cosa associata a un'identità osservata, con il fatto che la stabilisce.
///
/// # Perché non ha campi numerici
///
/// Per la stessa ragione per cui non ne ha un soggetto: un numero accanto a una
/// persona viene letto come un punteggio, comunque si chiami e qualunque cosa
/// intendesse chi lo ha scritto. Chi vuole sapere quanti contenuti, conta le
/// righe.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PersonAssociation {
    /// L'identificativo osservato presso la piattaforma.
    ///
    /// **Non un `PersonId`**: il collegamento a un fascicolo è PERS-06, ed è
    /// manuale.
    identifier: String,
    /// Che cosa risulta associato.
    target: AssociationTarget,
    /// Per quale fatto.
    provenance: AssociationProvenance,
}

impl PersonAssociation {
    /// Un'associazione, che **richiede** una provenienza.
    #[must_use]
    pub const fn new(
        identifier: String,
        target: AssociationTarget,
        provenance: AssociationProvenance,
    ) -> Self {
        Self {
            identifier,
            target,
            provenance,
        }
    }

    /// L'identificativo osservato.
    #[must_use]
    pub fn identifier(&self) -> &str {
        &self.identifier
    }

    /// Che cosa risulta associato.
    #[must_use]
    pub const fn target(&self) -> &AssociationTarget {
        &self.target
    }

    /// Per quale fatto.
    #[must_use]
    pub const fn provenance(&self) -> AssociationProvenance {
        self.provenance
    }
}

/// Ciò che serve per ricavare le associazioni di un contenuto scritto.
///
/// # Perché un tipo proprio, e senza il corpo del messaggio
///
/// Per la ragione di PERS-02: alla derivazione servono pochi valori, e passare
/// il contenuto intero le darebbe accesso al testo, che qui non serve. **Una
/// funzione che non riceve una cosa non può usarla.**
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AssociationFacts {
    /// Quale contenuto.
    pub content: ContentId,
    /// Chi lo ha scritto, presso la piattaforma.
    pub identifier: String,
    /// Da quale fonte proviene.
    pub source: SourceId,
    /// Quando è stato pubblicato.
    pub at: Timestamp,
    /// L'alert alzato su questo contenuto, se ce n'è uno.
    pub alert: Option<AlertId>,
    /// Gli indicatori che questo contenuto porta.
    pub indicators: Vec<(IndicatorKind, String)>,
    /// I workspace che raccolgono questo contenuto.
    pub workspaces: Vec<WorkspaceId>,
}

/// Ricava le associazioni di un'identità osservata dai fatti dei suoi contenuti.
///
/// # Perché una funzione pura
///
/// Perché la derivazione è la parte che merita una prova, e una prova non deve
/// costruire un archivio per esercitarla. È la scelta di PERS-02.
///
/// # Che cosa non si ripete
///
/// Chi ha scritto mille contenuti nella stessa fonte ha **una** riga per quella
/// fonte, non mille: mille righe uguali non sono un'informazione, sono un elenco
/// che nessuno scorre e in mezzo al quale ciò che conta sparisce. È la lezione di
/// PERS-02, «una riga per ogni cambiamento, non per ogni contenuto».
///
/// **Quale contenuto resta come provenienza, allora?** Il **primo** — il più
/// antico fra quelli che stabiliscono il fatto. È una scelta deterministica e
/// dichiarata: a parità di istante decide l'identificativo del contenuto, perché
/// senza un criterio secondario due letture darebbero due provenienze diverse per
/// la stessa associazione.
///
/// Le associazioni al **contenuto** fanno eccezione e non si accorpano: ognuna è
/// un fatto distinto, ed è il fatto primo da cui discendono le altre.
#[must_use]
pub fn associations_for(facts: &[AssociationFacts]) -> Vec<PersonAssociation> {
    // ORDINE RIPETIBILE PRIMA DI TUTTO.
    //
    // La provenienza di un'associazione accorpata e' il contenuto PIU' ANTICO
    // che la stabilisce: senza un ordine stabile, «il primo» cambierebbe a ogni
    // lettura, e due letture darebbero due provenienze diverse per lo stesso
    // fatto.
    let mut ordinati: Vec<&AssociationFacts> = facts.iter().collect();
    ordinati.sort_by(|a, b| {
        a.at.cmp(&b.at)
            .then(a.content.get().cmp(&b.content.get()))
            .then(a.identifier.cmp(&b.identifier))
    });

    let mut associazioni: Vec<PersonAssociation> = Vec::new();
    // Che cosa e' gia' stato detto, per non ripeterlo. La chiave e'
    // (identificativo, cosa associata): la stessa cosa, per la stessa persona,
    // si dice una volta.
    let mut gia_detto: BTreeSet<(String, AssociationTarget)> = BTreeSet::new();

    for fatto in ordinati {
        let provenienza = |regola: AssociationRule| {
            AssociationProvenance::of(fatto.content, fatto.source, fatto.at, regola)
        };

        // IL FATTO PRIMO: ha scritto questo contenuto.
        //
        // Non si accorpa, perche' ogni contenuto e' un fatto distinto ed e' cio'
        // da cui tutto il resto discende.
        associazioni.push(PersonAssociation::new(
            fatto.identifier.clone(),
            AssociationTarget::Content(fatto.content),
            provenienza(AssociationRule::AuthoredContent),
        ));

        let mut aggiungi_una_volta = |bersaglio: AssociationTarget, regola: AssociationRule| {
            let chiave = (fatto.identifier.clone(), bersaglio.clone());
            if gia_detto.insert(chiave) {
                associazioni.push(PersonAssociation::new(
                    fatto.identifier.clone(),
                    bersaglio,
                    provenienza(regola),
                ));
            }
        };

        aggiungi_una_volta(
            AssociationTarget::Source(fatto.source),
            AssociationRule::ContentFromSource,
        );

        if let Some(alert) = fatto.alert {
            aggiungi_una_volta(
                AssociationTarget::Alert(alert),
                AssociationRule::ContentRaisedAlert,
            );
        }

        for (kind, value) in &fatto.indicators {
            aggiungi_una_volta(
                AssociationTarget::Indicator {
                    kind: *kind,
                    value: value.clone(),
                },
                AssociationRule::ContentCarriesIndicator,
            );
        }

        for workspace in &fatto.workspaces {
            aggiungi_una_volta(
                AssociationTarget::Workspace(*workspace),
                AssociationRule::WorkspaceHoldsContent,
            );
        }
    }

    associazioni
}

#[cfg(test)]
mod tests {
    use super::{AssociationFacts, AssociationRule, AssociationTarget, associations_for};
    use crate::model::indicator::IndicatorKind;
    use crate::time::Timestamp;
    use crate::{AlertId, ContentId, SourceId, WorkspaceId};

    const ORA: Timestamp = Timestamp::from_millis(1_760_000_000_000);

    fn fatto(content: i64, identifier: &str, source: i64, at: Timestamp) -> AssociationFacts {
        AssociationFacts {
            content: ContentId::new(content),
            identifier: identifier.to_owned(),
            source: SourceId::new(source),
            at,
            alert: None,
            indicators: Vec::new(),
            workspaces: Vec::new(),
        }
    }

    /// **Ogni associazione porta una provenienza, e non esiste senza.**
    ///
    /// # Perché conta
    ///
    /// Perché è la richiesta esplicita dei requisiti di sicurezza:
    /// un'associazione senza provenienza è come un arco di grafo senza
    /// provenienza, e non deve essere costruibile.
    #[test]
    fn ogni_associazione_porta_una_provenienza() {
        let fatti = vec![fatto(1, "111", 7, ORA)];
        let associazioni = associations_for(&fatti);

        assert!(!associazioni.is_empty(), "deve produrre qualcosa");
        for associazione in &associazioni {
            let provenienza = associazione.provenance();
            assert_eq!(provenienza.content(), ContentId::new(1));
            assert_eq!(provenienza.source(), SourceId::new(7));
            assert_eq!(provenienza.at(), ORA);
        }
    }

    /// **La stessa cosa non si ripete: una fonte, una riga.**
    #[test]
    fn la_stessa_cosa_non_si_ripete() {
        // Dieci contenuti, tutti dalla stessa fonte, tutti della stessa persona.
        let fatti: Vec<AssociationFacts> = (1..=10)
            .map(|i| fatto(i, "111", 7, Timestamp::from_millis(ORA.as_millis() + i)))
            .collect();

        let associazioni = associations_for(&fatti);

        let fonti = associazioni
            .iter()
            .filter(|a| matches!(a.target(), AssociationTarget::Source(_)))
            .count();
        assert_eq!(
            fonti, 1,
            "dieci contenuti dalla stessa fonte fanno una riga"
        );

        let contenuti = associazioni
            .iter()
            .filter(|a| matches!(a.target(), AssociationTarget::Content(_)))
            .count();
        assert_eq!(contenuti, 10, "ogni contenuto resta un fatto distinto");
    }

    /// **La provenienza di una riga accorpata è il contenuto più antico.**
    ///
    /// # Perché conta
    ///
    /// Perché senza un criterio dichiarato «il primo» sarebbe quello che capita,
    /// e due letture darebbero due provenienze diverse per lo stesso fatto.
    #[test]
    fn la_provenienza_accorpata_e_il_contenuto_piu_antico() {
        // Dati in ordine sparso: il piu' antico e' il contenuto 3.
        let fatti = vec![
            fatto(9, "111", 7, Timestamp::from_millis(ORA.as_millis() + 500)),
            fatto(3, "111", 7, ORA),
            fatto(5, "111", 7, Timestamp::from_millis(ORA.as_millis() + 100)),
        ];

        let associazioni = associations_for(&fatti);
        let Some(fonte) = associazioni
            .iter()
            .find(|a| matches!(a.target(), AssociationTarget::Source(_)))
        else {
            panic!("la fonte deve esserci");
        };

        assert_eq!(
            fonte.provenance().content(),
            ContentId::new(3),
            "la provenienza e' il contenuto piu' antico che stabilisce il fatto"
        );
    }

    /// **Due persone nella stessa fonte non si fondono.**
    #[test]
    fn due_persone_nella_stessa_fonte_restano_due() {
        let fatti = vec![
            fatto(1, "111", 7, ORA),
            fatto(2, "222", 7, Timestamp::from_millis(ORA.as_millis() + 10)),
        ];

        let associazioni = associations_for(&fatti);
        let fonti: Vec<&str> = associazioni
            .iter()
            .filter(|a| matches!(a.target(), AssociationTarget::Source(_)))
            .map(super::PersonAssociation::identifier)
            .collect();

        assert_eq!(fonti.len(), 2, "ognuna ha la sua riga");
        assert!(fonti.contains(&"111") && fonti.contains(&"222"));
    }

    /// **Alert, indicatori e workspace arrivano dal contenuto scritto.**
    #[test]
    fn alert_indicatori_e_workspace_passano_dal_contenuto() {
        let mut f = fatto(1, "111", 7, ORA);
        f.alert = Some(AlertId::new(42));
        f.indicators = vec![(IndicatorKind::Domain, "esempio.test".to_owned())];
        f.workspaces = vec![WorkspaceId::new(3)];

        let associazioni = associations_for(&[f]);

        for (bersaglio, regola) in [
            (
                AssociationTarget::Alert(AlertId::new(42)),
                AssociationRule::ContentRaisedAlert,
            ),
            (
                AssociationTarget::Indicator {
                    kind: IndicatorKind::Domain,
                    value: "esempio.test".to_owned(),
                },
                AssociationRule::ContentCarriesIndicator,
            ),
            (
                AssociationTarget::Workspace(WorkspaceId::new(3)),
                AssociationRule::WorkspaceHoldsContent,
            ),
        ] {
            let Some(trovata) = associazioni.iter().find(|a| *a.target() == bersaglio) else {
                panic!("«{}» deve esserci", bersaglio.kind_label());
            };
            assert_eq!(trovata.provenance().rule(), regola);
            assert_eq!(
                trovata.provenance().content(),
                ContentId::new(1),
                "la provenienza e' il contenuto che lo ha mostrato"
            );
        }
    }

    /// **Nessuna regola di somiglianza, e nessun posto in cui possa stare.**
    ///
    /// # Perché conta
    ///
    /// Perché il congelamento vieta la fusione automatica di identità per
    /// somiglianza di nome. Una guardia sui nomi delle varianti non basterebbe da
    /// sola, ma qui l'enumerazione è chiusa: aggiungerne una è una modifica
    /// visibile a questo file, e questa prova la rende rossa.
    #[test]
    fn nessuna_regola_di_somiglianza() {
        let produzione = codice_senza_commenti();
        let Some(inizio) = produzione.find("pub enum AssociationRule {") else {
            panic!("l'enumerazione deve esistere");
        };
        let Some(fine) = produzione[inizio..].find("\n}\n") else {
            panic!("l'enumerazione deve chiudersi");
        };
        let varianti: Vec<&str> = produzione[inizio..inizio + fine]
            .lines()
            .map(str::trim)
            .filter(|riga| riga.ends_with(','))
            .collect();

        assert_eq!(
            varianti.len(),
            5,
            "le regole sono cinque; aggiungerne una e' una decisione, non un dettaglio"
        );

        for vietata in [
            "Similar", "Somigli", "Probable", "Likely", "Nearby", "Fuzzy",
        ] {
            assert!(
                !produzione.contains(vietata),
                "«{vietata}» e' inferenza: il congelamento la vieta"
            );
        }
    }

    /// **Un'associazione non ha campi numerici.**
    ///
    /// # Perché la guardia vieta la forma e non i nomi
    ///
    /// Perché è la lezione di PERS-01: vietare le parole «punteggio» o «rischio»
    /// lascia passare `peso: f64`. Qui si vieta **il genere**, comunque si
    /// chiami il campo.
    #[test]
    fn una_associazione_non_ha_campi_numerici() {
        let produzione = codice_senza_commenti();
        const INTESTAZIONE: &str = "pub struct PersonAssociation {";
        let Some(inizio) = produzione.find(INTESTAZIONE) else {
            panic!("la struttura deve esistere");
        };
        let campi = &produzione[inizio + INTESTAZIONE.len()..];
        let Some(fine) = campi.find("\n}\n") else {
            panic!("la struttura deve chiudersi");
        };

        for numerico in [
            "f32", "f64", "i8", "i16", "i32", "i64", "u8", "u16", "u32", "u64", "usize", "isize",
        ] {
            assert!(
                !campi[..fine].contains(numerico),
                "un campo «{numerico}» accanto a una persona si legge come un punteggio"
            );
        }
    }

    /// **La provenienza non è opzionale, e non ha campi pubblici.**
    ///
    /// # Perché conta
    ///
    /// Perché i requisiti chiedono che un'associazione senza provenienza non sia
    /// **costruibile**. Un `Option<AssociationProvenance>` la renderebbe
    /// costruibile con `None`, e un campo pubblico la renderebbe costruibile con
    /// la sintassi letterale, saltando il costruttore.
    #[test]
    fn la_provenienza_non_e_opzionale_e_non_ha_campi_pubblici() {
        let produzione = codice_senza_commenti();

        assert!(
            !produzione.contains("Option<AssociationProvenance>"),
            "una provenienza opzionale si passa None"
        );

        const INTESTAZIONE: &str = "pub struct AssociationProvenance {";
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

        assert!(
            !produzione.contains("impl Default for AssociationProvenance"),
            "un Default costruirebbe una provenienza che nessun fatto sostiene"
        );
    }

    /// **Il dominio non nomina il soggetto: quello è PERS-06, ed è manuale.**
    #[test]
    fn il_dominio_non_nomina_un_soggetto() {
        let produzione = codice_senza_commenti();
        for collegamento in ["PersonId", "NewPerson", "model::person"] {
            assert!(
                !produzione.contains(collegamento),
                "il dominio nomina «{collegamento}»: il collegamento a un fascicolo e' PERS-06"
            );
        }
    }

    /// Il codice di produzione di questo modulo, senza commenti.
    ///
    /// # Perché senza commenti
    ///
    /// Perché i commenti di questo file **nominano** ciò che le guardie vietano,
    /// per spiegare perché è vietato. Una guardia che leggesse anche i commenti
    /// sarebbe rossa per la spiegazione invece che per il difetto.
    fn codice_senza_commenti() -> String {
        let sorgente = include_str!("association.rs");
        let Some(taglio) = sorgente.find("#[cfg(test)]") else {
            panic!("il modulo deve avere una sezione di prove");
        };
        sorgente[..taglio]
            .lines()
            .filter(|riga| {
                let pulita = riga.trim_start();
                !pulita.starts_with("//")
            })
            .collect::<Vec<_>>()
            .join("\n")
    }
}
