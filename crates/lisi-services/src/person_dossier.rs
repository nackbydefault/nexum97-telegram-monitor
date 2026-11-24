//! Il fascicolo di un soggetto, messo insieme (PERS-07).
//!
//! # Che cosa questa milestone raccoglie, e perché non è una schermata nuova
//!
//! La Fase 6 ha costruito sei cose separate: un fascicolo (PERS-01), le identità
//! osservate (PERS-02), le loro associazioni (PERS-03), la loro cronologia
//! (PERS-04), la valutazione umana (PERS-05) e il legame manuale fra le due parti
//! (PERS-06).
//!
//! Questa le mette insieme **sul fascicolo**, che è il posto in cui qualcuno
//! lavora davvero.
//!
//! # La decisione difficile: un fascicolo non è un monitoraggio
//!
//! PERS-02, PERS-03 e PERS-04 hanno rifiutato **tre volte** di unire monitoraggi
//! diversi, e la ragione è scritta nel modulo dei partecipanti: «un elenco di
//! persone che unisce monitoraggi diversi mette insieme atti diversi, e chi lo
//! consegna non potrebbe più dire a quale dei due si riferisce».
//!
//! Un fascicolo però **attraversa i monitoraggi** per costruzione: qualcuno lo ha
//! aperto e ci lavora nel tempo. Tenere le osservazioni separate per monitoraggio
//! renderebbe il fascicolo inutile — chi lo apre dovrebbe scegliere un
//! monitoraggio per volta per vedere qualcosa.
//!
//! **Si uniscono, e la ragione per cui è lecito è precisa**: il rifiuto proteggeva
//! la **tracciabilità**, non la separazione in sé. Chi consegna deve poter dire da
//! quale monitoraggio viene ciascuna riga — e qui **ogni riga lo dice**.
//!
//! Non è una deroga: è la stessa regola, applicata a un caso in cui l'unione non
//! è automatica ma **decisa** — qualcuno ha aperto quel fascicolo e ha collegato
//! quell'identità, con un motivo scritto.
//!
//! # Ogni cosa che compare dice perché compare
//!
//! Sul fascicolo non arriva niente che il programma abbia trovato da sé. Tutto
//! arriva **da un legame che qualcuno ha deciso**, e ogni blocco porta quel legame
//! con sé: chi ha collegato, quando, perché.
//!
//! Senza, un fascicolo con dentro contenuti, fonti e alert si leggerebbe come se
//! il programma avesse scoperto quelle cose su quella persona — quando invece una
//! persona ha deciso che quell'identità era la sua.
//!
//! # Le avvertenze viaggiano con i dati
//!
//! La cronologia porta la sua — «un vuoto non è un silenzio» — e le associazioni
//! la loro — «un collegamento non è un giudizio». Se restassero nella schermata
//! d'origine, chi legge il fascicolo vedrebbe una linea del tempo senza sapere che
//! è piena di buchi per costruzione.
//!
//! # Che cosa non c'è, e perché
//!
//! **Il grafo.** Il congelamento lo elenca fra le integrazioni di questa
//! milestone, ma l'Evidence Graph è **GRAPH-01**, che dipende da CYT-01 e sta in
//! una fase successiva: oggi non esiste. Costruirne un pezzo qui significherebbe
//! anticipare una decisione di architettura fuori dal suo posto.

use lisi_core::model::association::PersonAssociation;
use lisi_core::model::identity_link::LinkedIdentity;
use lisi_core::model::person_timeline::PersonTimeline;
use lisi_core::{PersonId, SessionId};
use lisi_storage::Database;

use crate::association::AssociationService;
use crate::error::ServiceResult;
use crate::identity_link::IdentityLinkService;
use crate::person_timeline::PersonTimelineService;

/// Ciò che si è osservato di un'identità **durante un monitoraggio**.
///
/// # Perché il monitoraggio sta nel tipo e non a lato
///
/// Perché è la condizione che rende lecita l'unione: chi consegna deve poter
/// dire da quale monitoraggio viene ciascuna riga. Un tipo che lo tenesse fuori
/// permetterebbe di comporre un elenco che non lo dice.
#[derive(Debug, Clone)]
pub struct ObservedInSession {
    /// Quale monitoraggio.
    pub session: SessionId,
    /// Come si chiama, per chi legge.
    pub session_label: String,
    /// Le associazioni osservate lì.
    pub associations: Vec<PersonAssociation>,
    /// La cronologia osservata lì, con le sue finestre.
    pub timeline: Option<PersonTimeline>,
}

/// Che cosa si è osservato di **un'identità collegata**, e perché è sul fascicolo.
#[derive(Debug, Clone)]
pub struct DossierIdentity {
    /// Il legame che l'ha portata qui: chi, quando, perché.
    ///
    /// # Perché il legame viaggia con i dati
    ///
    /// Perché senza, un fascicolo con dentro contenuti e alert si leggerebbe come
    /// se il programma avesse scoperto quelle cose su quella persona — quando
    /// invece **una persona ha deciso** che quell'identità era la sua.
    pub link: LinkedIdentity,
    /// Che cosa si è osservato, monitoraggio per monitoraggio.
    pub observed: Vec<ObservedInSession>,
}

impl DossierIdentity {
    /// Perché questa identità compare sul fascicolo.
    ///
    /// # Perché una frase e non solo i campi
    ///
    /// Perché è la risposta a «perché sto vedendo questo?» (ADR-0052), e chi la
    /// legge deve trovarla scritta, non doverla ricostruire da tre valori.
    #[must_use]
    pub fn why_here(&self) -> String {
        format!(
            "Queste righe sono qui perch\u{e9} {} ha collegato l'identit\u{e0} {} a questo \
             fascicolo il {}, scrivendo: \u{ab}{}\u{bb}. Non le ha trovate il programma.",
            self.link.by.on_screen(),
            self.link.identifier,
            self.link.at.to_readable_local(),
            self.link.reason.as_str()
        )
    }

    /// Se di questa identità non si è osservato nulla.
    ///
    /// # Perché serve dirlo
    ///
    /// Perché un'identità collegata senza righe sotto è ambigua: può voler dire
    /// che non ha scritto, o che nessun monitoraggio l'ha incontrata. La seconda
    /// è la situazione ordinaria, e va detta.
    #[must_use]
    pub fn nothing_observed(&self) -> bool {
        self.observed.is_empty()
    }
}

/// Servizio che compone il fascicolo.
#[derive(Debug)]
pub struct PersonDossierService {
    links: IdentityLinkService,
    associations: AssociationService,
    timelines: PersonTimelineService,
    database: Database,
}

impl PersonDossierService {
    /// Costruisce il servizio sugli archivi indicati.
    #[must_use]
    pub const fn new(
        links: IdentityLinkService,
        associations: AssociationService,
        timelines: PersonTimelineService,
        database: Database,
    ) -> Self {
        Self {
            links,
            associations,
            timelines,
            database,
        }
    }

    /// L'archivio, in sola lettura.
    #[must_use]
    pub const fn database(&self) -> &Database {
        &self.database
    }

    /// Che cosa si è osservato delle identità collegate a un soggetto.
    ///
    /// # Perché attraversa i monitoraggi, e come lo dichiara
    ///
    /// Perché un fascicolo li attraversa per costruzione. Ogni riga porta il
    /// monitoraggio da cui viene, che è la condizione a cui l'unione è lecita.
    ///
    /// # Perché un'identità senza osservazioni resta nell'elenco
    ///
    /// Perché toglierla direbbe che nessuno l'ha collegata, e qualcuno l'ha
    /// fatto: il legame è un atto, e resta visibile anche quando non ha prodotto
    /// nulla.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se l'archivio non è leggibile, o se una ragione
    /// richiesta non è stata registrata.
    pub fn for_person(&self, person: PersonId) -> ServiceResult<Vec<DossierIdentity>> {
        let legami = self.links.current(person)?;
        if legami.is_empty() {
            return Ok(Vec::new());
        }

        // I MONITORAGGI SI LEGGONO UNA VOLTA SOLA, non per ogni identita'.
        let sessioni = self.database.sessions()?;

        let mut fascicolo = Vec::with_capacity(legami.len());
        for legame in legami {
            let mut osservato = Vec::new();

            for sessione in &sessioni {
                // LE ASSOCIAZIONI E LA CRONOLOGIA DI QUESTA IDENTITA', LI'.
                //
                // Se una lettura non riesce, quel monitoraggio resta fuori e
                // il registro lo dice: comporre un fascicolo su una lettura
                // fallita mostrerebbe meno di quello che c'e', senza dirlo.
                let associazioni = self
                    .associations
                    .for_identity(sessione.id, &legame.identifier)
                    .unwrap_or_default();

                let cronologia = self
                    .timelines
                    .for_session(sessione.id)
                    .unwrap_or_default()
                    .into_iter()
                    .find(|c| c.identifier() == legame.identifier);

                // UN MONITORAGGIO CHE NON HA VISTO NIENTE NON COMPARE.
                //
                // Elencare ogni monitoraggio sotto ogni identita', quasi tutti
                // vuoti, sarebbe rumore — ed e' la lezione di PERS-02.
                if associazioni.is_empty() && cronologia.is_none() {
                    continue;
                }

                osservato.push(ObservedInSession {
                    session: sessione.id,
                    session_label: sessione.label.as_str().to_owned(),
                    associations: associazioni,
                    timeline: cronologia,
                });
            }

            fascicolo.push(DossierIdentity {
                link: legame,
                observed: osservato,
            });
        }

        Ok(fascicolo)
    }
}

#[cfg(test)]
mod tests {
    /// Questo modulo, per le guardie strutturali.
    const THIS_MODULE: &str = include_str!("person_dossier.rs");

    /// **Ogni riga del fascicolo porta il suo monitoraggio.**
    ///
    /// # Perché è la guardia di questa milestone
    ///
    /// Perché PERS-02, PERS-03 e PERS-04 hanno rifiutato tre volte di unire
    /// monitoraggi diversi, e la ragione era la **tracciabilità**: «chi lo
    /// consegna non potrebbe più dire a quale dei due si riferisce».
    ///
    /// Qui l'unione è lecita **soltanto** perché ogni riga lo dice. Un tipo che
    /// tenesse il monitoraggio fuori permetterebbe di comporre un elenco che non
    /// lo dice, e la deroga diventerebbe una scorciatoia.
    #[test]
    fn ogni_riga_del_fascicolo_porta_il_suo_monitoraggio() {
        let produzione = codice_senza_commenti();
        const INTESTAZIONE: &str = "pub struct ObservedInSession {";
        let Some(inizio) = produzione.find(INTESTAZIONE) else {
            panic!("la struttura deve esistere");
        };
        let campi = &produzione[inizio + INTESTAZIONE.len()..];
        let Some(fine) = campi.find("\n}\n") else {
            panic!("la struttura deve chiudersi");
        };

        for obbligatorio in ["session: SessionId", "session_label: String"] {
            assert!(
                campi[..fine].contains(obbligatorio),
                "il tipo deve portare «{obbligatorio}»: senza, l'unione dei monitoraggi \
                 perderebbe cio' che il rifiuto proteggeva"
            );
        }
    }

    /// **Ogni identità sul fascicolo porta il legame che ce l'ha messa.**
    ///
    /// # Il difetto che questa prova impedisce
    ///
    /// Un fascicolo con dentro contenuti, fonti e alert che si legge come se il
    /// programma avesse scoperto quelle cose su quella persona — quando invece
    /// **una persona ha deciso** che quell'identità era la sua.
    #[test]
    fn ogni_identita_porta_il_legame_che_ce_l_ha_messa() {
        let produzione = codice_senza_commenti();
        const INTESTAZIONE: &str = "pub struct DossierIdentity {";
        let Some(inizio) = produzione.find(INTESTAZIONE) else {
            panic!("la struttura deve esistere");
        };
        let campi = &produzione[inizio + INTESTAZIONE.len()..];
        let Some(fine) = campi.find("\n}\n") else {
            panic!("la struttura deve chiudersi");
        };
        assert!(
            campi[..fine].contains("link: LinkedIdentity"),
            "il legame viaggia con i dati, e non a lato"
        );

        // E LA FRASE LO DICE, non solo i campi.
        assert!(
            produzione.contains("Non le ha trovate il programma"),
            "la risposta a «perche' sto vedendo questo» deve essere scritta"
        );
    }

    /// **Il servizio non collega, non valuta e non propone.**
    ///
    /// # Perché conta
    ///
    /// Perché questa milestone **raccoglie**. Se raccogliendo potesse anche
    /// collegare, sarebbe la scorciatoia che PERS-06 ha evitato: un fascicolo che
    /// si popola da sé.
    #[test]
    fn il_servizio_raccoglie_e_basta() {
        let produzione = codice_senza_commenti();
        for scrittura in [
            "insert_",
            "update_",
            "delete_",
            "append_audit",
            "&mut self",
            "fn record",
            "fn link",
            "fn assess",
            "suggest",
            "candidate",
            "similar",
        ] {
            assert!(
                !produzione.contains(scrittura),
                "il servizio nomina «{scrittura}»: raccogliere e' una lettura, e un fascicolo che \
                 si popola da se' e' cio' che PERS-06 ha evitato"
            );
        }
    }

    /// **Il grafo non c'è, e la ragione è scritta.**
    ///
    /// # Perché una prova su un'assenza
    ///
    /// Perché il congelamento elenca il grafo fra le integrazioni di questa
    /// milestone, e non averlo potrebbe sembrare una dimenticanza. È invece una
    /// decisione: l'Evidence Graph è GRAPH-01, dipende da CYT-01 e sta in una
    /// fase successiva.
    #[test]
    fn il_grafo_non_c_e_e_la_ragione_e_scritta() {
        assert!(
            THIS_MODULE.contains("GRAPH-01"),
            "l'assenza del grafo va dichiarata, con il nome della milestone che lo porta"
        );

        let produzione = codice_senza_commenti();
        for grafo in ["EvidenceGraph", "graph::", "fn edges", "fn nodes"] {
            assert!(
                !produzione.contains(grafo),
                "«{grafo}»: il grafo e' GRAPH-01, e anticiparlo qui deciderebbe la sua \
                 architettura fuori dal suo posto"
            );
        }
    }

    /// Il codice di produzione di questo modulo, senza commenti.
    fn codice_senza_commenti() -> String {
        let Some(taglio) = THIS_MODULE.find("#[cfg(test)]") else {
            panic!("il modulo deve avere una sezione di prove");
        };
        THIS_MODULE[..taglio]
            .lines()
            .filter(|riga| !riga.trim_start().starts_with("//"))
            .collect::<Vec<_>>()
            .join("\n")
    }
}
