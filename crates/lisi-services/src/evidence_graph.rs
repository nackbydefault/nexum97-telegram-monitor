//! Gli archi del grafo, ricavati da ciò che sta nell'archivio (GRAPH-01).
//!
//! # Che cosa fa questo modulo, e che cosa non fa
//!
//! Legge righe e chiama la derivazione del dominio, che è pura. Non decide
//! nulla, non collega nulla, non calcola nulla: **raccoglie**.
//!
//! In particolare **non cerca percorsi**, e non c'è un posto in cui possa
//! farlo: la ragione sta nella nota di
//! [`lisi_core::model::evidence_graph`], ed è la decisione centrale di questa
//! milestone. Due nodi che risultano collegati attraverso un terzo non hanno
//! per questo a che fare l'uno con l'altro, e un programma che rispondesse
//! «sì» a quella domanda affermerebbe qualcosa che nessuno ha osservato.
//!
//! # Perché la ragione operativa è richiesta
//!
//! Perché un grafo che parte da un'identità osservata è **la stessa domanda**
//! degli elenchi di persone e delle associazioni: che cosa risulta collegato a
//! chi ha scritto. ADR-0024 chiede che sia motivata, e non se ne inventa una
//! seconda per il grafo — la ragione registrata vale per tutte le funzioni che
//! producono elenchi di persone.
//!
//! # Il tetto
//!
//! Un monitoraggio con molte migliaia di contenuti produrrebbe altrettanti
//! archi. Chi guarda un grafo vuole vederne la forma, non caricarne l'archivio,
//! e **ciò che resta fuori si dichiara**: [`lisi_core::model::evidence_graph::Neighbourhood`]
//! lo porta con sé, e non esiste il modo di comporne uno che lo taccia.

use lisi_core::model::evidence_graph::{
    ContentFacts, EventFacts, GraphEdge, GraphNode, LinkFacts, Neighbourhood, edge_of_link,
    edges_of_content, edges_of_event, neighbourhood_of,
};
use lisi_core::{ContentId, PersonId, SessionId};
use lisi_storage::Database;

use crate::error::{ServiceError, ServiceResult};

/// Quanti archi si mostrano al massimo attorno a un nodo.
///
/// Chi guarda un vicinato vuole vederne la forma. Ciò che resta fuori è
/// dichiarato dal vicinato stesso.
pub const EDGES_PER_NODE: usize = 60;

/// Il servizio del grafo: **legge e basta**.
#[derive(Debug)]
pub struct EvidenceGraphService {
    database: Database,
}
impl EvidenceGraphService {
    /// Costruisce il servizio sull'archivio indicato.
    #[must_use]
    pub const fn new(database: Database) -> Self {
        Self { database }
    }

    /// L'archivio, in sola lettura.
    #[must_use]
    pub const fn database(&self) -> &Database {
        &self.database
    }

    /// L'archivio in scrittura, per chi deve preparare le prove.
    pub const fn database_mut(&mut self) -> &mut Database {
        &mut self.database
    }

    /// Se una ragione operativa è già stata registrata.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se l'audit non è leggibile.
    pub fn basis_recorded(&self) -> ServiceResult<bool> {
        basis_recorded_on(&self.database)
    }

    /// Tutti gli archi che i fatti di un monitoraggio stabiliscono.
    ///
    /// # Errori
    ///
    /// Quelli di [`edges_of_session_on`].
    pub fn edges_of_session(&self, session_id: SessionId) -> ServiceResult<Vec<GraphEdge>> {
        edges_of_session_on(&self.database, session_id)
    }

    /// Gli archi dei grappoli di segnali di un monitoraggio.
    ///
    /// # Errori
    ///
    /// Quelli di [`edges_of_events_on`].
    pub fn edges_of_events(&self, session_id: SessionId) -> ServiceResult<Vec<GraphEdge>> {
        edges_of_events_on(&self.database, session_id)
    }

    /// Gli archi che **una persona ha deciso**, per un soggetto.
    ///
    /// # Errori
    ///
    /// Quelli di [`edges_of_subject_on`].
    pub fn edges_of_subject(&self, person: PersonId) -> ServiceResult<Vec<GraphEdge>> {
        edges_of_subject_on(&self.database, person)
    }

    /// Il vicinato di un nodo dentro un monitoraggio, con il suo taglio.
    ///
    /// # Errori
    ///
    /// Quelli di [`neighbourhood_of_session`].
    pub fn neighbourhood(
        &self,
        session_id: SessionId,
        node: &GraphNode,
    ) -> ServiceResult<Neighbourhood> {
        neighbourhood_of_session(&self.database, session_id, node)
    }
}

// ---------------------------------------------------------------------------
// Le funzioni libere, su un archivio **prestato**.
//
// PERCHE' ESISTONO, e perché i metodi del servizio le chiamano invece di
// ripetere il lavoro: chi ha già un archivio aperto — i servizi dello Storico,
// per esempio — dovrebbe aprirne un altro solo per costruire un servizio. E'
// la scelta di `cyber_watch::events_of`, e la ragione è la stessa: la
// composizione resta **una**, e due composizioni della stessa cosa divergono
// alla prima modifica.
// ---------------------------------------------------------------------------

/// Se una ragione operativa è già stata registrata.
///
/// # Errori
///
/// Restituisce un errore se l'audit non è leggibile.
pub fn basis_recorded_on(database: &Database) -> ServiceResult<bool> {
    Ok(database.operational_basis_recorded()?)
}

/// Tutti gli archi che i fatti di un monitoraggio stabiliscono.
///
/// # Perché un monitoraggio alla volta
///
/// Perché unire monitoraggi diversi metterebbe insieme atti diversi, e chi
/// consegna una figura non potrebbe più dire a quale dei due si riferisce. È il
/// rifiuto di PERS-02, PERS-03 e PERS-04, e in una figura vale a maggior
/// ragione: un grafo non porta con sé la propria didascalia.
///
/// L'unico arco che attraversa i monitoraggi è quello che **una persona ha
/// deciso**, e lo dichiara.
///
/// # Errori
///
/// Restituisce [`ServiceError::MissingParticipantBasis`] se nessuna ragione è
/// stata registrata, o un errore se l'archivio non è leggibile.
pub fn edges_of_session_on(
    database: &Database,
    session_id: SessionId,
) -> ServiceResult<Vec<GraphEdge>> {
    // LA RAGIONE E' QUELLA DEGLI ELENCHI DI PERSONE, non una seconda.
    if !basis_recorded_on(database)? {
        return Err(ServiceError::MissingParticipantBasis);
    }

    let contents = database.session_contents(session_id)?;

    let mut archi: Vec<GraphEdge> = Vec::new();
    for content in &contents {
        // SI RACCOLGONO I FATTI, NON IL CONTENUTO.
        //
        // Alla derivazione non serve il testo del messaggio, e una funzione che
        // non lo riceve non puo' usarlo.
        let indicators = database
            .content_indicators(content.id)?
            .into_iter()
            .map(|indicatore| (indicatore.kind, indicatore.value))
            .collect();

        archi.extend(edges_of_content(&ContentFacts {
            content: content.id,
            source: content.source_id,
            at: content.published_at,
            // UN MESSAGGIO DI CANALE NON HA UN AUTORE INDIVIDUALE, e senza
            // autore non si disegna un arco verso nessuno: e' la scelta di
            // PERS-02, e in una figura costerebbe di piu'.
            identifier: content.author_identifier.clone(),
            indicators,
        }));
    }

    Ok(archi)
}

/// Gli archi dei grappoli di segnali di un monitoraggio.
///
/// # Errori
///
/// Gli stessi di [`edges_of_session_on`].
pub fn edges_of_events_on(
    database: &Database,
    session_id: SessionId,
) -> ServiceResult<Vec<GraphEdge>> {
    if !basis_recorded_on(database)? {
        return Err(ServiceError::MissingParticipantBasis);
    }

    let grappoli = crate::cyber_watch::events_of(database, session_id)?;

    let mut archi: Vec<GraphEdge> = Vec::new();
    for grappolo in &grappoli {
        let lisi_core::model::cyber_event::CorrelationReason::SameIndicator { kind, value } =
            &grappolo.event.reason;

        let members = grappolo
            .event
            .members
            .iter()
            .map(|membro| {
                (
                    lisi_core::ContentId::new(membro.content_id),
                    lisi_core::SourceId::new(membro.source_id),
                    membro.published_at,
                )
            })
            .collect();

        archi.extend(edges_of_event(&EventFacts {
            kind: *kind,
            value: value.clone(),
            members,
        }));
    }

    Ok(archi)
}

/// Gli archi che **una persona ha deciso**, per un soggetto.
///
/// # Perché soltanto i legami in essere
///
/// Perché un legame sciolto **non collega più**, e disegnarlo direbbe che quel
/// fascicolo riguarda ancora quell'identità. Che sia esistito resta scritto
/// nella storia degli atti, che PERS-06 non cancella: è là che si legge, non in
/// una figura di oggi.
///
/// # Errori
///
/// Restituisce un errore se l'archivio non è leggibile.
pub fn edges_of_subject_on(database: &Database, person: PersonId) -> ServiceResult<Vec<GraphEdge>> {
    let storia = database.identity_link_history(person)?;
    let in_essere = lisi_core::model::identity_link::current_links(&storia);

    Ok(in_essere
        .iter()
        .map(|legame| {
            edge_of_link(&LinkFacts {
                person,
                identifier: legame.identifier.clone(),
                by: legame.by.clone(),
                at: legame.at,
                reason: legame.reason.clone(),
            })
        })
        .collect())
}

/// In quale monitoraggio sta un contenuto, se esiste (OPERATOR-E2E-REMEDIATION-01,
/// F-02).
///
/// # Perché serve prima di comporre il vicinato
///
/// Perché il vicinato di un contenuto che non c'è è un vicinato vuoto, e la
/// figura lo disegnava lo stesso: un riquadro «Contenuto n. 999» per un
/// contenuto che l'archivio non ha. Chi guardava leggeva un nodo esistente senza
/// collegamenti, che è un'altra cosa. Questa domanda sta fuori dalle funzioni
/// che decidono gli archi, e non ne cambia nessuna.
///
/// # Errori
///
/// Restituisce un errore se la lettura non riesce per una ragione diversa
/// dall'assenza.
pub fn content_session(
    database: &Database,
    content_id: ContentId,
) -> ServiceResult<Option<SessionId>> {
    match database.content(content_id) {
        Ok(contenuto) => Ok(Some(contenuto.session_id)),
        Err(lisi_storage::StorageError::NotFound { .. }) => Ok(None),
        Err(altro) => Err(ServiceError::Storage(altro)),
    }
}

/// Il vicinato di un nodo dentro un monitoraggio, con il suo taglio.
///
/// # Che cosa mette insieme, e perché è lecito
///
/// Gli archi osservati del monitoraggio, quelli dei suoi grappoli, e quelli che
/// una persona ha deciso. Ogni arco dichiara da quale delle due cose viene, e
/// quella dichiarazione è ciò che rende lecito metterli sulla stessa figura: è
/// la stessa condizione che ha reso lecita l'unione dei monitoraggi sul
/// fascicolo (PERS-07).
///
/// # Errori
///
/// Gli stessi di [`edges_of_session_on`].
pub fn neighbourhood_of_session(
    database: &Database,
    session_id: SessionId,
    node: &GraphNode,
) -> ServiceResult<Neighbourhood> {
    let mut archi = edges_of_session_on(database, session_id)?;
    archi.extend(edges_of_events_on(database, session_id)?);

    // GLI ARCHI DECISI DA UNA PERSONA si leggono per OGNI fascicolo aperto, non
    // solo per quello del nodo richiesto.
    //
    // Costa una lettura per fascicolo a ogni vicinato, e si paga volentieri:
    // un'identita' osservata puo' essere collegata a un fascicolo che chi guarda
    // non ha in mente, e chiedere il vicinato di quell'identita' senza mostrarlo
    // direbbe che nessuno l'ha collegata a niente. I fascicoli sono pochi perche'
    // qualcuno deve averli aperti a mano; i contenuti no, ed e' li' che il tetto
    // conta.
    for soggetto in database.persons()? {
        archi.extend(edges_of_subject_on(database, soggetto.id)?);
    }

    Ok(neighbourhood_of(node, &archi, EDGES_PER_NODE))
}

#[cfg(test)]
mod tests {
    use lisi_core::model::evidence_graph::{EdgeRule, GraphNode};
    use lisi_core::model::indicator::extract;
    use lisi_core::{ContentId, SessionId};

    use super::EvidenceGraphService;
    use crate::sources::open_in_memory_database;

    /// Il testo di questo modulo, per la guardia che guarda la forma del codice.
    const THIS_MODULE: &str = include_str!("evidence_graph.rs");

    const ORA: i64 = 1_700_000_000_000;

    /// Prepara un archivio con i contenuti indicati, gia' analizzati, e la
    /// ragione operativa gia' registrata.
    fn archivio(testi: &[&str]) -> (EvidenceGraphService, SessionId) {
        use lisi_core::model::audit::NewAuditEntry;
        use lisi_core::model::{NewSession, NewSource, SessionDuration, SourceKind};
        use lisi_core::text::{
            Actor, AuditAction, AuditDetail, AuditEntity, DisplayName, SourceIdentifier,
        };

        let Ok(mut database) = open_in_memory_database() else {
            panic!("l'archivio di prova deve potersi aprire");
        };
        let adesso = lisi_core::Timestamp::from_millis(ORA);

        let (Ok(identifier), Ok(nome), Ok(attore)) = (
            SourceIdentifier::try_new("canale_prova"),
            DisplayName::try_new("Canale di prova"),
            Actor::try_new("responsabile.prova"),
        ) else {
            panic!("i valori della fonte di prova devono essere validi");
        };
        let Ok(source_id) = database.insert_source(
            &NewSource {
                kind: SourceKind::Channel,
                identifier,
                display_name: nome,
                authorized_by: attore,
                active: true,
            },
            adesso,
        ) else {
            panic!("la fonte deve potersi registrare");
        };

        let (Ok(etichetta), Ok(avviata_da)) = (
            DisplayName::try_new("Sessione di prova"),
            Actor::try_new("operatore.prova"),
        ) else {
            panic!("i valori della sessione di prova devono essere validi");
        };
        let Ok(session_id) = database.insert_session(
            &NewSession {
                label: etichetta,
                started_by: avviata_da,
                duration: SessionDuration::Manual,
                source_ids: vec![source_id],
            },
            adesso,
        ) else {
            panic!("la sessione deve potersi creare");
        };

        for (numero, testo) in testi.iter().enumerate() {
            let (Ok(corpo), Ok(remote)) = (
                lisi_core::text::ContentBody::try_new(testo),
                lisi_core::text::RemoteMessageId::try_new(&format!("m-{numero}")),
            ) else {
                panic!("i valori del contenuto di prova devono essere validi");
            };
            let contenuto = lisi_core::model::NewContent {
                session_id,
                source_id,
                remote_message_id: remote,
                author: None,
                author_identifier: Some(format!("id-{numero}")),
                author_username: None,
                body: corpo,
                url: None,
                published_at: lisi_core::Timestamp::from_millis(ORA + numero as i64),
                acquired_at: adesso,
                origin: lisi_core::model::AcquisitionOrigin::Observed,
                analysis_level: lisi_core::model::analysis::AnalysisLevel::NOT_RELEVANT,
            };
            let Ok(inserimento) = database.insert_content(&contenuto) else {
                panic!("il contenuto deve potersi registrare");
            };
            let estrazione = extract(testo);
            let Ok(_) = database
                .insert_content_indicators(inserimento.content_id(), &estrazione.indicators)
            else {
                panic!("gli indicatori devono potersi registrare");
            };
        }

        // LA RAGIONE OPERATIVA, che il grafo richiede come gli elenchi di
        // persone: non se ne inventa una seconda.
        let (Ok(azione), Ok(entita), Ok(dettaglio), Ok(operatore)) = (
            AuditAction::try_new("elenco_persone_motivato"),
            AuditEntity::try_new("session"),
            AuditDetail::try_new("verifica autorizzata di una fonte d'ufficio"),
            Actor::try_new("operatore.prova"),
        ) else {
            panic!("i valori dell'audit devono essere validi");
        };
        let Ok(_) = database.append_audit(&NewAuditEntry {
            actor: operatore,
            action: azione,
            entity: entita,
            entity_id: None,
            actor_mode: None,
            detail: Some(dettaglio),
            recorded_at: adesso,
        }) else {
            panic!("la ragione deve potersi registrare");
        };

        (EvidenceGraphService::new(database), session_id)
    }

    /// **Il grafo non si produce senza una ragione registrata.**
    ///
    /// # Il difetto che questa prova impedisce
    ///
    /// Che una figura su chi ha scritto si componga senza che nessuno abbia
    /// scritto perche' la sta guardando. E' la stessa guardia degli elenchi di
    /// persone (ADR-0024), e qui non se ne inventa una seconda.
    #[test]
    fn il_grafo_non_si_produce_senza_una_ragione() {
        let Ok(database) = open_in_memory_database() else {
            panic!("l'archivio di prova deve potersi aprire");
        };
        let servizio = EvidenceGraphService::new(database);

        let esito = servizio.edges_of_session(SessionId::new(1));
        assert!(
            matches!(
                esito,
                Err(crate::error::ServiceError::MissingParticipantBasis)
            ),
            "senza ragione registrata il grafo non si produce"
        );
    }

    /// **Un contenuto che non c'è non è un contenuto senza collegamenti**
    /// (F-02): la domanda «di quale monitoraggio è?» dice `None`, e la
    /// schermata non disegna nulla. Prima il Grafo disegnava «Contenuto n. 999».
    #[test]
    fn un_contenuto_che_non_c_e_si_distingue() {
        let (servizio, session_id) = archivio(&["Un messaggio senza indicatori."]);
        let Ok(esiste) = super::content_session(servizio.database(), ContentId::new(1)) else {
            panic!("la lettura deve riuscire");
        };
        assert_eq!(esiste, Some(session_id));
        let Ok(manca) = super::content_session(servizio.database(), ContentId::new(999)) else {
            panic!("un contenuto assente non è un errore di lettura");
        };
        assert_eq!(manca, None);
    }

    /// **Gli archi arrivano dalle righe, e ognuno porta la sua provenienza.**
    #[test]
    fn gli_archi_arrivano_dalle_righe() {
        let (servizio, session_id) = archivio(&[
            "Allarme: la CVE-2026-1234 riguarda esempio.it.",
            "Segnalata la CVE-2026-1234 anche altrove.",
        ]);

        let Ok(archi) = servizio.edges_of_session(session_id) else {
            panic!("gli archi devono potersi ricavare");
        };
        assert!(!archi.is_empty());

        for arco in &archi {
            assert!(
                !arco.provenance().is_a_human_act(),
                "un arco ricavato dalle righe e' osservato, non deciso: {}",
                arco.why()
            );
            assert!(
                arco.why().contains("Osservato nel contenuto"),
                "{}",
                arco.why()
            );
        }
        assert!(
            archi
                .iter()
                .any(|arco| arco.rule() == EdgeRule::IdentityAuthoredContent),
            "un autore dichiarato produce il suo arco"
        );
        assert!(
            archi
                .iter()
                .any(|arco| arco.rule() == EdgeRule::ContentCarriesIndicator),
            "un indicatore nominato produce il suo arco"
        );
    }

    /// **Nessun arco osservato raggiunge un fascicolo.**
    ///
    /// La porta che quattro milestone della Fase 6 hanno tenuto chiusa resta
    /// chiusa anche qui: al soggetto si arriva soltanto per decisione di una
    /// persona.
    #[test]
    fn nessun_arco_letto_dall_archivio_raggiunge_un_soggetto() {
        let (servizio, session_id) = archivio(&[
            "Allarme: la CVE-2026-1234 riguarda esempio.it.",
            "Segnalata la CVE-2026-1234 anche altrove.",
        ]);

        let Ok(mut archi) = servizio.edges_of_session(session_id) else {
            panic!("gli archi devono potersi ricavare");
        };
        let Ok(dei_gruppi) = servizio.edges_of_events(session_id) else {
            panic!("gli archi dei gruppi devono potersi ricavare");
        };
        archi.extend(dei_gruppi);

        for arco in &archi {
            assert!(
                !matches!(arco.from(), GraphNode::Subject(_))
                    && !matches!(arco.to(), GraphNode::Subject(_)),
                "un arco letto dall'archivio non tocca un fascicolo: {}",
                arco.why()
            );
        }
    }

    /// **Il vicinato di un contenuto porta la sua avvertenza.**
    #[test]
    fn il_vicinato_porta_la_sua_avvertenza() {
        let (servizio, session_id) = archivio(&[
            "Allarme: la CVE-2026-1234 riguarda esempio.it.",
            "Segnalata la CVE-2026-1234 anche altrove.",
        ]);

        let Ok(vicinato) =
            servizio.neighbourhood(session_id, &GraphNode::Content(ContentId::new(1)))
        else {
            panic!("il vicinato deve potersi comporre");
        };

        assert!(!vicinato.edges().is_empty());
        assert!(
            vicinato
                .caveat()
                .contains("non hanno per questo a che fare l'uno con l'altro"),
            "{}",
            vicinato.caveat()
        );
    }

    /// **Il servizio non cerca percorsi, e non ha un posto in cui farlo.**
    ///
    /// # Il controllo negativo
    ///
    /// Aggiungendo al servizio una funzione che cerchi un cammino fra due nodi,
    /// questa prova diventa rossa.
    #[test]
    fn il_servizio_non_cerca_percorsi() {
        let Some((produzione, _)) = THIS_MODULE.split_once("#[cfg(test)]\nmod tests {") else {
            panic!("il modulo deve avere un blocco di prove riconoscibile");
        };
        let codice = produzione
            .lines()
            .filter(|riga| !riga.trim_start().starts_with("//"))
            .collect::<Vec<&str>>()
            .join("\n")
            .to_lowercase();

        for vietata in [
            "fn path",
            "fn shortest",
            "fn reachab",
            "fn transitive",
            "fn connected_",
            "fn traverse",
            "fn bfs",
            "fn dfs",
            "fn are_connected",
        ] {
            assert!(
                !codice.contains(vietata),
                "il servizio non deve poter rispondere a «A e B sono collegati?»: trovato \
                 «{vietata}»"
            );
        }
    }

    /// **Soggetto, evento e indicatore sono nodi del Grafo, con la loro
    /// ragione, e ci si ricentra su ciascuno** (NEXUM97-MINOR-FIX-01, GAP-21).
    ///
    /// L'audit delle capacità li dava per «non visti»: il servizio li produceva,
    /// ma nessuna prova lo mostrava. Qui un soggetto collegato a mano compare
    /// accanto all'identità osservata con la ragione di chi l'ha collegato, due
    /// contenuti con lo stesso indicatore fanno un evento, e il vicinato di
    /// ciascuno dei tre si compone.
    #[test]
    fn soggetto_evento_e_indicatore_sono_nodi_con_la_loro_ragione() {
        use lisi_core::model::identity_link::{LinkAct, NewIdentityLink};
        use lisi_core::model::person::NewPerson;
        use lisi_core::model::reason::OperationalReason;
        use lisi_core::text::{Actor, DisplayName};

        let (servizio, session_id) = archivio(&[
            "Allarme: la CVE-2026-1234 riguarda esempio.it.",
            "Segnalata la CVE-2026-1234 anche altrove.",
        ]);
        let adesso = lisi_core::Timestamp::from_millis(ORA);
        let (Ok(etichetta), Ok(ragione), Ok(chi)) = (
            DisplayName::try_new("Soggetto di prova"),
            OperationalReason::try_new("riscontro documentale con l'autorita' procedente"),
            Actor::try_new("operatore.prova"),
        ) else {
            panic!("valori validi");
        };
        let Ok(soggetto) = servizio.database().insert_person(
            &NewPerson::open(etichetta, ragione.clone()),
            &chi,
            adesso,
        ) else {
            panic!("il soggetto deve potersi aprire");
        };
        let Ok(_) = servizio.database().insert_identity_link(&NewIdentityLink {
            person: soggetto,
            identifier: String::from("id-0"),
            act: LinkAct::Link,
            reason: ragione,
            by: chi,
            at: adesso,
            resolution: None,
        }) else {
            panic!("il legame deve potersi registrare");
        };
        let vicinato = |nodo: &GraphNode| {
            let Ok(vicinato) =
                super::neighbourhood_of_session(servizio.database(), session_id, nodo)
            else {
                panic!("il vicinato deve potersi comporre");
            };
            vicinato
        };

        // IL SOGGETTO, accanto all'identità osservata, con la ragione della
        // persona che l'ha collegato.
        let identita = vicinato(&GraphNode::ObservedIdentity(String::from("id-0")));
        let Some(legame) = identita
            .edges()
            .iter()
            .find(|arco| arco.rule() == EdgeRule::PersonLinkedIdentityToSubject)
        else {
            panic!("il soggetto collegato a mano deve comparire");
        };
        assert!(legame.provenance().is_a_human_act());
        assert!(
            legame.why().contains("riscontro documentale"),
            "{}",
            legame.why()
        );
        // E ci si ricentra sul soggetto.
        let dal_soggetto = vicinato(&GraphNode::Subject(soggetto));
        assert!(
            dal_soggetto
                .edges()
                .iter()
                .any(|arco| arco.rule() == EdgeRule::PersonLinkedIdentityToSubject),
            "dal soggetto si torna all'identità"
        );

        // L'INDICATORE, dal contenuto, e ci si ricentra su di lui.
        let dal_contenuto = vicinato(&GraphNode::Content(ContentId::new(1)));
        // La CVE, che i due contenuti nominano entrambi: il dominio sta in uno solo.
        let Some(indicatore) = dal_contenuto.edges().iter().find_map(|arco| {
            [arco.from(), arco.to()]
                .into_iter()
                .find(|nodo| {
                    matches!(nodo, GraphNode::Indicator { value, .. }
                        if value.to_lowercase().contains("2026-1234"))
                })
                .cloned()
        }) else {
            panic!("il contenuto nomina la CVE");
        };
        let dall_indicatore = vicinato(&indicatore);
        assert!(!dall_indicatore.edges().is_empty());

        // L'EVENTO: due contenuti con lo stesso indicatore, con la sua ragione.
        let Some(evento) = dall_indicatore
            .edges()
            .iter()
            .find(|arco| arco.rule() == EdgeRule::EventTurnsOnIndicator)
        else {
            panic!("due contenuti con la stessa CVE fanno un evento");
        };
        assert!(!evento.why().is_empty());
        let Some(nodo_evento) = [evento.from(), evento.to()]
            .into_iter()
            .find(|nodo| matches!(nodo, GraphNode::CyberEvent { .. }))
            .cloned()
        else {
            panic!("l'arco porta il nodo dell'evento");
        };
        let dall_evento = vicinato(&nodo_evento);
        assert!(
            dall_evento
                .edges()
                .iter()
                .any(|arco| arco.rule() == EdgeRule::EventGroupsContent),
            "dall'evento si vedono i contenuti che raggruppa"
        );
    }

    /// Un nodo che nessun arco tocca ha un vicinato vuoto, e non inventa archi.
    #[test]
    fn un_nodo_estraneo_ha_un_vicinato_vuoto() {
        let (servizio, session_id) = archivio(&["Allarme: la CVE-2026-1234 riguarda esempio.it."]);

        let Ok(vicinato) =
            servizio.neighbourhood(session_id, &GraphNode::Content(ContentId::new(999)))
        else {
            panic!("il vicinato deve potersi comporre");
        };

        assert!(vicinato.edges().is_empty());
        assert_eq!(vicinato.omitted(), 0);
    }
}
