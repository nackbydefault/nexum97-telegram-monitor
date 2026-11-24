//! Che cosa vale la pena guardare insieme.
//!
//! # Perché questo modulo esiste
//!
//! CY-01 estrae gli indicatori, CY-02 li raggruppa, CY-05 dice dove ricade ciò
//! che nominano. Sono tre pezzi che si guardano da lontano: **serve qualcuno che
//! li componga**, altrimenti restano tre capacità costruite e mai invocate — che
//! è il difetto che CY-01 esisteva per chiudere, e che si ricrea alla prima
//! distrazione.
//!
//! # Che cosa compone, e che cosa tiene separato
//!
//! Compone: il grappolo, la sua valutazione, i segnali di rilevanza per
//! l'Italia, i settori delle organizzazioni dichiarate.
//!
//! Tiene separato: **il livello**. Un grappolo con dieci contenuti che nominano
//! un dominio istituzionale italiano non è per questo grave — il livello lo
//! decide il motore 0-4 sui dizionari, e questo modulo non lo tocca (ADR-0035
//! Decisione 10).
//!
//! # Che cosa non dice, mai
//!
//! Che un attacco sia avvenuto. Che una fonte sia attendibile. Che qualcuno
//! abbia fatto qualcosa. Dice **che cosa ha trovato**, e chi legge decide.

use lisi_core::model::cyber_candidate::{ARCHIVE_WINDOW_DAYS, CandidateEvent, candidate_events};
use lisi_core::model::cyber_event::{
    CorrelationReason, CyberEvent, EventAssessment, ReviewSummary,
};
use lisi_core::model::cyber_timeline::{CyberTimeline, timeline_for};
use lisi_core::model::indicator::{CyberIndicator, IndicatorKind};
use lisi_core::model::relevance::{ItalyRelevance, SectorRelevance, assess_italy, assess_sectors};
use lisi_core::{SessionId, Timestamp};
use lisi_storage::Database;

use crate::error::{ServiceError, ServiceResult};

/// Quanti membri si caricano al massimo per ogni grappolo.
///
/// Chi guarda un grappolo vuole vederne la forma, non caricarne l'archivio.
pub const MEMBERS_PER_EVENT: usize = 50;

/// Quanti indicatori dell'archivio si guardano al più per gli eventi candidati.
pub const ARCHIVE_KEYS: usize = 200;

/// Un grappolo, con tutto ciò che se ne può dire.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WatchEvent {
    /// Il grappolo.
    pub event: CyberEvent,
    /// Che cosa il grappolo permette di dire.
    pub assessment: EventAssessment,
    /// I segnali di rilevanza per l'Italia, se ce ne sono.
    pub italy: ItalyRelevance,
    /// I settori a cui i contenuti del grappolo sono stati ricondotti.
    ///
    /// # Perche' non alza la gravita'
    ///
    /// Un grappolo che nomina un'organizzazione dell'energia non e' per questo
    /// grave: il livello lo decide il motore 0-4 sui dizionari, e questo campo
    /// dice **in quale ambito ricadrebbe il fatto, se fosse vero**
    /// (ADR-0035 Decisione 10).
    ///
    /// Vuoto quando nessuna organizzazione e' stata dichiarata, che e' lo stato
    /// di una postazione appena installata.
    pub sectors: SectorRelevance,
    /// Gli indicatori tecnici che i contenuti del grappolo nominano, **oltre**
    /// a quello che li tiene insieme.
    ///
    /// # Perché servono, e perché non sono la ragione del grappolo
    ///
    /// La ragione è **una**: «questi contenuti nominano CVE-2026-1234». Gli
    /// altri indicatori — domini, indirizzi, impronte — sono ciò che chi guarda
    /// troverebbe aprendo i contenuti uno per uno, raccolto in un posto.
    ///
    /// Non sono una prova di nulla e non aumentano la gravità: un contenuto che
    /// nomina otto domini non è più grave di uno che ne nomina uno.
    pub indicators: Vec<CyberIndicator>,
    /// Che cosa una persona ha deciso sui contenuti del grappolo.
    pub review: ReviewSummary,
    /// Quando il primo e l'ultimo contenuto sono stati pubblicati.
    pub seen_between: Option<(Timestamp, Timestamp)>,
}

impl WatchEvent {
    /// Il grappolo, in una frase.
    ///
    /// # Perché la ragione viene prima
    ///
    /// Chi legge deve sapere **perché** questi contenuti stanno insieme prima di
    /// sapere quanti sono: un numero senza una ragione è un numero che non si
    /// può contestare.
    #[must_use]
    pub fn as_sentence(&self) -> String {
        let mut testo = format!(
            "{} contenuti che {}. {}",
            self.assessment.contents,
            self.event.reason.as_sentence(),
            self.assessment.as_sentence()
        );

        if !self.italy.is_empty() {
            testo.push(' ');
            testo.push_str(&self.italy.as_sentence());
        }
        testo
    }
}

/// Servizio della sorveglianza cyber.
#[derive(Debug)]
pub struct CyberWatchService {
    database: Database,
}

impl CyberWatchService {
    /// Crea il servizio attorno all'archivio indicato.
    #[must_use]
    pub const fn new(database: Database) -> Self {
        Self { database }
    }

    /// Archivio sottostante, per i test e la diagnostica.
    #[must_use]
    pub const fn database(&self) -> &Database {
        &self.database
    }

    /// Archivio sottostante in scrittura.
    ///
    /// Serve a chi deve preparare l'archivio - le prove - senza aprirne un
    /// secondo sullo stesso file.
    pub const fn database_mut(&mut self) -> &mut Database {
        &mut self.database
    }

    /// I grappoli di una sessione, con la loro valutazione.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se la lettura non riesce.
    pub fn events(&self, session_id: SessionId) -> ServiceResult<Vec<WatchEvent>> {
        events_of(&self.database, session_id)
    }

    /// La cronologia di un grappolo di questa sessione.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se la lettura non riesce, o se il monitoraggio non
    /// risulta avviato e quindi non ha un periodo di osservazione.
    pub fn timeline(
        &self,
        session_id: SessionId,
        reason: &CorrelationReason,
    ) -> ServiceResult<CyberTimeline> {
        timeline_of(&self.database, session_id, reason)
    }

    /// Quanti grappoli meritano uno sguardo, in una sessione.
    ///
    /// È la cifra che la Dashboard mostra: non un allarme, un invito a guardare.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se la lettura non riesce.
    pub fn count(&self, session_id: SessionId) -> ServiceResult<usize> {
        Ok(self.events(session_id)?.len())
    }

    /// Gli eventi candidati di **tutto l'archivio**, negli ultimi
    /// [`ARCHIVE_WINDOW_DAYS`] giorni (CYBER-EVENTS-02, ADR-0189).
    ///
    /// # Errori
    ///
    /// Restituisce un errore se la lettura non riesce.
    pub fn archive_candidates(&self, now: Timestamp) -> ServiceResult<Vec<CandidateEvent>> {
        candidates_of(&self.database, now)
    }
}

/// Gli eventi candidati di tutto l'archivio, su un archivio **prestato**.
///
/// # Errori
///
/// Restituisce un errore se la lettura non riesce.
pub fn candidates_of(database: &Database, now: Timestamp) -> ServiceResult<Vec<CandidateEvent>> {
    let dal = Timestamp::from_millis(
        now.as_millis()
            .saturating_sub(ARCHIVE_WINDOW_DAYS.saturating_mul(24 * 3_600_000)),
    );
    let grappoli = database.archive_clusters_by_indicator(dal, ARCHIVE_KEYS, MEMBERS_PER_EVENT)?;
    Ok(candidate_events(grappoli))
}

/// I grappoli di una sessione, con la loro valutazione, su un archivio
/// **prestato**.
///
/// # Perché una funzione libera e non solo un metodo
///
/// [`CyberWatchService`] possiede il proprio archivio, e chi ne ha già uno —
/// il servizio dei rapporti, per esempio — dovrebbe aprirne un altro solo per
/// costruirne uno.
///
/// L'alternativa sarebbe stata rifare la composizione dove serve, ed è
/// esattamente il difetto che CY-06 esiste per chiudere: tre capacità che si
/// guardano da lontano e nessuno che le componga, o peggio, due composizioni
/// che divergono al primo cambiamento. La composizione resta **una**, e il
/// metodo del servizio la chiama.
///
/// # Errori
///
/// Restituisce un errore se la lettura non riesce.
pub fn events_of(database: &Database, session_id: SessionId) -> ServiceResult<Vec<WatchEvent>> {
    let grappoli = database.correlate_by_indicator(session_id, MEMBERS_PER_EVENT)?;

    // Le organizzazioni dichiarate si leggono **una volta** per l'intera
    // composizione, non per grappolo: sono le stesse per tutti, e rileggerle
    // costerebbe il numero dei grappoli in interrogazioni.
    let watchlist = database.watched_organisations()?;

    let mut esiti = Vec::with_capacity(grappoli.len());
    for grappolo in grappoli {
        let assessment = grappolo.assess();

        // Gli indicatori del grappolo, letti UNA volta e usati due: per la
        // rilevanza italiana e per l'elenco che la schermata mostra. Si
        // prendono da cio' che e' gia' stato estratto: rifare l'estrazione
        // qui creerebbe due verita' da tenere allineate.
        let mut indicators = Vec::new();
        for membro in &grappolo.members {
            let indicatori =
                database.content_indicators(lisi_core::ContentId::new(membro.content_id))?;
            indicators.extend(indicatori);
        }

        // Ordine stabile e nessun doppione: lo stesso dominio nominato da sei
        // contenuti e' UN dominio, e ripeterlo sei volte in un elenco farebbe
        // sembrare piu' grande cio' che il grappolo contiene.
        indicators.sort_by(|primo, secondo| {
            primo
                .kind
                .as_str()
                .cmp(secondo.kind.as_str())
                .then_with(|| primo.value.cmp(&secondo.value))
        });
        indicators.dedup();

        let domini: Vec<String> = indicators
            .iter()
            .filter(|indicatore| indicatore.kind == IndicatorKind::Domain)
            .map(|indicatore| indicatore.value.clone())
            .collect();

        // La lingua non entra: un grappolo raccoglie contenuti che possono
        // essere in lingue diverse, e dichiararne una sola sarebbe una
        // semplificazione che nessuno ha chiesto.
        let italy = assess_italy(&domini, None);

        // Il settore, dalle organizzazioni che l'amministratore ha dichiarato.
        //
        // I corpi dei membri si rileggono **solo se c'e' qualcosa da cercare**:
        // su una postazione senza organizzazioni dichiarate — che e' lo stato
        // di ogni installazione nuova — questo blocco non tocca l'archivio.
        //
        // Quando invece c'e' una watchlist, la lettura e' limitata dai membri
        // gia' caricati (MEMBERS_PER_EVENT), non dall'archivio intero.
        let sectors = if watchlist.is_empty() {
            SectorRelevance::default()
        } else {
            let mut corpi = String::new();
            for membro in &grappolo.members {
                let contenuto = database.content(lisi_core::ContentId::new(membro.content_id))?;
                corpi.push_str(contenuto.body.as_str());
                corpi.push('\n');
            }
            assess_sectors(&corpi, &domini, &watchlist)
        };

        let review = grappolo.review_summary();
        let seen_between = grappolo.seen_between();

        esiti.push(WatchEvent {
            event: grappolo,
            assessment,
            italy,
            sectors,
            indicators,
            review,
            seen_between,
        });
    }

    Ok(esiti)
}

/// La cronologia di un grappolo, su un archivio **prestato**.
///
/// # Perché prende la ragione e non il grappolo
///
/// Perché la ragione è ciò che identifica il grappolo dentro un monitoraggio —
/// «questi contenuti nominano CVE-2026-1234» — mentre i membri sono il risultato
/// di una lettura. Passando il grappolo intero si userebbero membri letti prima,
/// e una cronologia costruita su una lettura vecchia racconterebbe un archivio
/// che non c'è più.
///
/// # Perché rifiuta invece di comporre una cronologia senza finestra
///
/// Perché una linea del tempo con dei buchi si legge in un modo solo — «qui non
/// è successo niente» — e la finestra di osservazione è l'unica cosa che la
/// rende leggibile. Un monitoraggio mai avviato non ha osservato nulla, e
/// mostrarne la cronologia consegnerebbe a chi legge una successione di vuoti
/// senza il fatto che li spiega (ADR-0053).
///
/// # Errori
///
/// Restituisce un errore se la lettura non riesce, o se il monitoraggio non
/// risulta avviato.
pub fn timeline_of(
    database: &Database,
    session_id: SessionId,
    reason: &CorrelationReason,
) -> ServiceResult<CyberTimeline> {
    let Some(window) = database.observation_window(session_id)? else {
        return Err(ServiceError::NoObservationWindow {
            session: session_id.get(),
        });
    };

    let CorrelationReason::SameIndicator { kind, value } = reason;
    let facts = database.event_facts(session_id, *kind, value, MEMBERS_PER_EVENT)?;

    Ok(timeline_for(reason.clone(), &facts, window))
}

#[cfg(test)]
mod tests {
    use lisi_core::model::indicator::extract;

    use super::CyberWatchService;
    use crate::sources::open_in_memory_database;

    /// Prepara un archivio con i contenuti indicati, gia' analizzati.
    fn archivio(testi: &[&str]) -> (CyberWatchService, lisi_core::SessionId) {
        use lisi_core::model::{NewSession, NewSource, SessionDuration, SourceKind};
        use lisi_core::text::{Actor, DisplayName, SourceIdentifier};

        let Ok(mut database) = open_in_memory_database() else {
            panic!("l'archivio di prova deve potersi aprire");
        };
        let adesso = lisi_core::Timestamp::from_millis(1_700_000_000_000);

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
            let Ok(corpo) = lisi_core::text::ContentBody::try_new(testo) else {
                panic!("il corpo di prova deve essere valido");
            };
            let Ok(remote) = lisi_core::text::RemoteMessageId::try_new(&format!("m-{numero}"))
            else {
                panic!("l'identificativo di prova deve essere valido");
            };
            let contenuto = lisi_core::model::NewContent {
                session_id,
                source_id,
                remote_message_id: remote,
                author: None,
                author_identifier: None,
                author_username: None,
                body: corpo,
                url: None,
                published_at: adesso,
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

        (CyberWatchService::new(database), session_id)
    }

    /// **Gli eventi candidati guardano tutto l'archivio, nella sua finestra**
    /// (CYBER-EVENTS-02, ADR-0189).
    #[test]
    fn i_candidati_dell_archivio_chiedono_due_fonti_e_la_finestra() {
        use lisi_core::model::{NewSource, SourceKind};
        use lisi_core::text::{Actor, DisplayName, SourceIdentifier};

        let adesso = lisi_core::Timestamp::from_millis(1_700_000_000_000);
        let (mut servizio, _) = archivio(&["la CVE-2026-7777 circola", "ancora la CVE-2026-7777"]);
        let Ok(nessuno) = servizio.archive_candidates(adesso) else {
            panic!("i candidati devono potersi leggere");
        };
        assert!(nessuno.is_empty(), "una fonte sola non fa un candidato");

        let (Ok(identifier), Ok(nome), Ok(attore)) = (
            SourceIdentifier::try_new("canale_altro"),
            DisplayName::try_new("Altro canale"),
            Actor::try_new("responsabile.prova"),
        ) else {
            panic!("i valori della fonte di prova devono essere validi");
        };
        let database = servizio.database_mut();
        let Ok(altra) = database.insert_source(
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
            DisplayName::try_new("Altro monitoraggio"),
            Actor::try_new("operatore.prova"),
        ) else {
            panic!("i valori della sessione di prova devono essere validi");
        };
        let Ok(altra_sessione) = database.insert_session(
            &lisi_core::model::NewSession {
                label: etichetta,
                started_by: avviata_da,
                duration: lisi_core::model::SessionDuration::Manual,
                source_ids: vec![altra],
            },
            adesso,
        ) else {
            panic!("la seconda sessione deve potersi creare");
        };
        let testo = "anche qui la CVE-2026-7777";
        let (Ok(corpo), Ok(remote)) = (
            lisi_core::text::ContentBody::try_new(testo),
            lisi_core::text::RemoteMessageId::try_new("altro-1"),
        ) else {
            panic!("i valori del contenuto di prova devono essere validi");
        };
        let Ok(inserimento) = database.insert_content(&lisi_core::model::NewContent {
            session_id: altra_sessione,
            source_id: altra,
            remote_message_id: remote,
            author: None,
            author_identifier: None,
            author_username: None,
            body: corpo,
            url: None,
            published_at: adesso,
            acquired_at: adesso,
            origin: lisi_core::model::AcquisitionOrigin::Observed,
            analysis_level: lisi_core::model::analysis::AnalysisLevel::NOT_RELEVANT,
        }) else {
            panic!("il contenuto deve potersi registrare");
        };
        let Ok(_) = database
            .insert_content_indicators(inserimento.content_id(), &extract(testo).indicators)
        else {
            panic!("gli indicatori devono potersi registrare");
        };

        let Ok(candidati) = servizio.archive_candidates(adesso) else {
            panic!("i candidati devono potersi leggere");
        };
        assert_eq!(candidati.len(), 1);
        assert_eq!(candidati[0].assess().contents, 3);
        assert_eq!(candidati[0].assess().distinct_sources, 2);

        let fuori = lisi_core::Timestamp::from_millis(
            adesso.as_millis()
                + (lisi_core::model::cyber_candidate::ARCHIVE_WINDOW_DAYS + 1) * 86_400_000,
        );
        let Ok(vecchi) = servizio.archive_candidates(fuori) else {
            panic!("i candidati devono potersi leggere");
        };
        assert!(vecchi.is_empty(), "oltre la finestra non si guarda");
    }

    /// **I tre pezzi si compongono davvero.**
    ///
    /// Estrazione, correlazione e rilevanza sono tre capacita' che si guardano
    /// da lontano: senza qualcuno che le componga resterebbero costruite e mai
    /// invocate.
    #[test]
    fn i_grappoli_arrivano_composti_con_la_loro_valutazione() {
        let (servizio, session_id) = archivio(&[
            "allarme su ministero.gov.it per la CVE-2026-1234",
            "anche noi vediamo la CVE-2026-1234 in giro",
            "nulla di rilevante oggi",
        ]);

        let Ok(eventi) = servizio.events(session_id) else {
            panic!("i grappoli devono potersi leggere");
        };

        assert_eq!(eventi.len(), 1, "una sola CVE compare due volte");
        let evento = &eventi[0];
        assert_eq!(evento.assessment.contents, 2);

        let frase = evento.as_sentence();
        assert!(
            frase.contains("2026-1234"),
            "la frase deve dire PERCHE' stanno insieme: «{frase}»"
        );
    }

    /// **La rilevanza per l'Italia arriva, e resta separata dalla gravita'.**
    #[test]
    fn la_rilevanza_italiana_compare_senza_diventare_un_giudizio() {
        let (servizio, session_id) = archivio(&[
            "problema su ministero.gov.it per la CVE-2026-5555",
            "confermo il problema su ministero.gov.it, CVE-2026-5555",
        ]);

        let Ok(eventi) = servizio.events(session_id) else {
            panic!("i grappoli devono potersi leggere");
        };
        let Some(evento) = eventi.first() else {
            panic!("il grappolo deve esistere");
        };

        assert!(
            !evento.italy.is_empty(),
            "il dominio istituzionale italiano deve produrre un segnale"
        );

        let frase = evento.as_sentence().to_lowercase();
        for vietata in ["grave", "attacco", "confermato", "pericolo", "urgente"] {
            assert!(
                !frase.contains(vietata),
                "la frase contiene un giudizio («{vietata}»): «{frase}»"
            );
        }
    }

    /// **Un archivio senza ricorrenze non produce grappoli.**
    ///
    /// E' la condizione ordinaria, e un elenco che mostrasse qualcosa comunque
    /// insegnerebbe a ignorarlo.
    #[test]
    fn senza_ricorrenze_non_c_e_nulla_da_guardare() {
        let (servizio, session_id) = archivio(&[
            "una CVE-2026-1111 sola",
            "un dominio esempio.test solo",
            "niente di tecnico qui",
        ]);

        let Ok(quanti) = servizio.count(session_id) else {
            panic!("il conteggio deve riuscire");
        };
        assert_eq!(quanti, 0);
    }

    #[test]
    fn una_sessione_vuota_non_esplode() {
        let (servizio, session_id) = archivio(&[]);
        let Ok(quanti) = servizio.count(session_id) else {
            panic!("il conteggio deve riuscire anche su una sessione vuota");
        };
        assert_eq!(quanti, 0);
    }

    /// **Il grappolo dice QUANDO, e sono due date.**
    ///
    /// «Nell'arco di tre giorni» nasconde quando, e quando e' la meta' della
    /// domanda: tre giorni del mese scorso e tre giorni iniziati stamattina
    /// meritano due reazioni diverse.
    ///
    /// Le date sono di **pubblicazione**, non di acquisizione: il grappolo
    /// racconta quando la cosa e' stata detta, non quando questo programma se
    /// n'e' accorto.
    #[test]
    fn il_grappolo_dice_fra_quando_e_quando() {
        let (servizio, session_id) = archivio(&[
            "allarme su ministero.gov.it per la CVE-2026-1234",
            "anche noi vediamo la CVE-2026-1234 in giro",
        ]);

        let Ok(eventi) = servizio.events(session_id) else {
            panic!("i grappoli devono potersi leggere");
        };
        let Some(evento) = eventi.first() else {
            panic!("il grappolo deve esistere");
        };

        let Some((primo, ultimo)) = evento.seen_between else {
            panic!("un grappolo con due membri deve avere due date");
        };
        assert!(primo <= ultimo, "il primo non puo' venire dopo l'ultimo");
    }

    /// **Gli indicatori arrivano senza doppioni.**
    ///
    /// Lo stesso dominio nominato da sei contenuti e' UN dominio. Ripeterlo sei
    /// volte in un elenco farebbe sembrare piu' grande cio' che il grappolo
    /// contiene, ed e' esattamente il genere di gonfiatura che questa parte del
    /// prodotto esiste per evitare.
    #[test]
    fn gli_indicatori_del_grappolo_non_si_ripetono() {
        let (servizio, session_id) = archivio(&[
            "problema su ministero.gov.it per la CVE-2026-5555",
            "confermo il problema su ministero.gov.it, CVE-2026-5555",
            "sempre ministero.gov.it, CVE-2026-5555",
        ]);

        let Ok(eventi) = servizio.events(session_id) else {
            panic!("i grappoli devono potersi leggere");
        };
        let Some(evento) = eventi.first() else {
            panic!("il grappolo deve esistere");
        };

        let mut valori: Vec<&str> = evento
            .indicators
            .iter()
            .map(|indicatore| indicatore.value.as_str())
            .collect();
        let quanti = valori.len();
        valori.sort_unstable();
        valori.dedup();

        assert_eq!(
            quanti,
            valori.len(),
            "un indicatore compare una volta sola: {valori:?}"
        );
        assert!(
            valori
                .iter()
                .any(|valore| valore.contains("ministero.gov.it")),
            "il dominio nominato da tre contenuti deve comparire: {valori:?}"
        );
    }

    /// **La revisione si conta per contenuto, e non diventa uno stato del
    /// grappolo.**
    ///
    /// Un grappolo puo' contenere due messaggi giudicati rilevanti e otto mai
    /// guardati. Riassumerli in una parola cancellerebbe proprio la differenza
    /// che chi legge deve vedere.
    #[test]
    fn la_revisione_si_conta_per_contenuto() {
        let (servizio, session_id) =
            archivio(&["allarme per la CVE-2026-7777", "anche qui la CVE-2026-7777"]);

        let Ok(eventi) = servizio.events(session_id) else {
            panic!("i grappoli devono potersi leggere");
        };
        let Some(evento) = eventi.first() else {
            panic!("il grappolo deve esistere");
        };

        // Nessuna revisione registrata: nessuno ha deciso nulla.
        assert_eq!(evento.review.decided, 0);
        assert_eq!(evento.review.in_progress, 0);
        assert_eq!(evento.review.untouched, 2);

        let frase = evento.review.as_sentence();
        assert!(
            frase.contains("Nessuno") && frase.contains("2"),
            "la frase deve dire che nessuno dei due e' stato esaminato: «{frase}»"
        );
    }

    /// **Nessuna frase del grappolo dichiara un attacco o fonti indipendenti.**
    ///
    /// E' la regola che ADR-0035 Decisione 6 fissa, e vale su OGNI frase che il
    /// servizio produce — non solo su quella che qualcuno si e' ricordato di
    /// controllare.
    #[test]
    fn nessuna_frase_del_servizio_dichiara_un_attacco() {
        let (servizio, session_id) = archivio(&[
            "attacco a ministero.gov.it, CVE-2026-9999",
            "confermato l'attacco, CVE-2026-9999",
        ]);

        let Ok(eventi) = servizio.events(session_id) else {
            panic!("i grappoli devono potersi leggere");
        };
        let Some(evento) = eventi.first() else {
            panic!("il grappolo deve esistere");
        };

        // Il TESTO DEI CONTENUTI puo' dire qualunque cosa: e' materiale
        // acquisito, e il prodotto non lo corregge. Sono le frasi che il
        // PRODOTTO scrive a non poter dichiarare nulla.
        for frase in [
            evento.as_sentence(),
            evento.assessment.as_sentence(),
            evento.italy.as_sentence(),
            evento.review.as_sentence(),
        ] {
            let minuscola = frase.to_lowercase();
            for vietata in [
                "fonti indipendenti",
                "attacco confermato",
                "incidente confermato",
            ] {
                assert!(
                    !minuscola.contains(vietata),
                    "una frase del servizio contiene «{vietata}»: «{frase}»"
                );
            }
        }
    }

    /// Dichiara un'organizzazione sull'archivio del servizio.
    ///
    /// I nomi sono inventati: il prodotto non contiene alcun elenco di enti, e
    /// nemmeno le sue prove ne costruiscono uno.
    fn dichiara(
        servizio: &mut CyberWatchService,
        nome: &str,
        settore: lisi_core::model::relevance::Sector,
        alias: &[&str],
        domini: &[&str],
    ) {
        use lisi_core::model::organisation::{
            NewWatchedOrganisation, OrganisationAlias, OrganisationDomain,
        };
        use lisi_core::text::{Actor, DisplayName};

        let (Ok(name), Ok(declared_by)) = (
            DisplayName::try_new(nome),
            Actor::try_new("amministratore.prova"),
        ) else {
            panic!("i valori di prova devono essere validi");
        };

        let aliases = alias
            .iter()
            .map(|voce| match OrganisationAlias::try_new(voce) {
                Ok(valore) => valore,
                Err(_) => panic!("alias di prova non valido: {voce}"),
            })
            .collect();
        let domains = domini
            .iter()
            .map(|voce| match OrganisationDomain::try_new(voce) {
                Ok(valore) => valore,
                Err(_) => panic!("dominio di prova non valido: {voce}"),
            })
            .collect();

        let Ok(dichiarazione) = NewWatchedOrganisation::try_new(
            name,
            settore,
            aliases,
            domains,
            None,
            declared_by,
            lisi_core::Timestamp::from_millis(1_700_000_000_000),
        ) else {
            panic!("la dichiarazione di prova deve essere valida");
        };

        let Ok(_) = servizio
            .database_mut()
            .insert_watched_organisation(&dichiarazione)
        else {
            panic!("la dichiarazione deve potersi scrivere");
        };
    }

    /// **Il settore arriva fino al grappolo, con la sua provenienza.**
    ///
    /// E' la prova che DEC-235 chiedeva: `Sector` non e' piu' una capacita'
    /// costruita e mai invocata, ed e' invocata attraverso una regola che una
    /// persona ha scritto.
    #[test]
    fn il_settore_dichiarato_arriva_fino_al_grappolo() {
        use lisi_core::model::relevance::Sector;

        let (mut servizio, session_id) = archivio(&[
            "disservizio su portale.esempio-ente.example per la CVE-2026-7777",
            "confermo il disservizio su portale.esempio-ente.example, CVE-2026-7777",
        ]);

        dichiara(
            &mut servizio,
            "Ente di prova",
            Sector::Energia,
            &["Ente di prova"],
            &["esempio-ente.example"],
        );

        let Ok(eventi) = servizio.events(session_id) else {
            panic!("i grappoli devono potersi leggere");
        };
        let Some(evento) = eventi.first() else {
            panic!("il grappolo deve esistere");
        };

        assert_eq!(evento.sectors.sectors(), vec![Sector::Energia]);

        let Some(attribuzione) = evento.sectors.attributions.first() else {
            panic!("l'attribuzione deve esistere");
        };
        assert_eq!(attribuzione.organisation, "Ente di prova");
        assert_eq!(attribuzione.declared_by, "amministratore.prova");
        assert!(
            attribuzione.as_sentence().contains("Settore dichiarato da"),
            "l'attribuzione deve dire chi ha scritto la regola"
        );
    }

    /// **Senza dichiarazioni non compare alcun settore.**
    ///
    /// E' lo stato di ogni postazione appena installata, e il prodotto non deve
    /// riempirlo indovinando.
    #[test]
    fn senza_organizzazioni_dichiarate_il_grappolo_non_porta_settori() {
        let (servizio, session_id) = archivio(&[
            "disservizio su portale.esempio-ente.example per la CVE-2026-7777",
            "confermo il disservizio su portale.esempio-ente.example, CVE-2026-7777",
        ]);

        let Ok(eventi) = servizio.events(session_id) else {
            panic!("i grappoli devono potersi leggere");
        };
        let Some(evento) = eventi.first() else {
            panic!("il grappolo deve esistere");
        };

        assert!(evento.sectors.is_empty());
    }

    /// **Un'organizzazione sospesa smette di produrre il settore.**
    ///
    /// Controllo negativo sul percorso completo: la stessa dichiarazione che
    /// produce un settore, disattivata, non ne produce piu'.
    #[test]
    fn controllo_negativo_unorganizzazione_sospesa_non_porta_piu_il_settore() {
        use lisi_core::model::relevance::Sector;

        let (mut servizio, session_id) = archivio(&[
            "disservizio su portale.esempio-ente.example per la CVE-2026-7777",
            "confermo il disservizio su portale.esempio-ente.example, CVE-2026-7777",
        ]);

        dichiara(
            &mut servizio,
            "Ente di prova",
            Sector::Sanita,
            &[],
            &["esempio-ente.example"],
        );

        let Ok(prima) = servizio.events(session_id) else {
            panic!("i grappoli devono potersi leggere");
        };
        let Some(evento) = prima.first() else {
            panic!("il grappolo deve esistere");
        };
        let Some(attribuzione) = evento.sectors.attributions.first() else {
            panic!("l'attribuzione deve esistere prima della sospensione");
        };
        let id = lisi_core::WatchedOrganisationId::new(attribuzione.organisation_id);

        let Ok(()) = servizio.database().set_watched_organisation_active(
            id,
            false,
            lisi_core::Timestamp::from_millis(1_700_000_001_000),
        ) else {
            panic!("la sospensione deve riuscire");
        };

        let Ok(dopo) = servizio.events(session_id) else {
            panic!("i grappoli devono potersi rileggere");
        };
        let Some(evento) = dopo.first() else {
            panic!("il grappolo deve esistere ancora");
        };

        assert!(
            evento.sectors.is_empty(),
            "un'organizzazione sospesa non deve produrre attribuzioni"
        );
    }

    /// **Il settore non entra nella frase che riassume il grappolo.**
    ///
    /// La frase dice quanti contenuti, perche' stanno insieme e la rilevanza
    /// italiana. Il settore si legge accanto, non dentro: fonderlo li'
    /// suggerirebbe che un settore dell'allegato I renda il grappolo piu' grave,
    /// che e' esattamente la confusione che ADR-0035 Decisione 10 vieta.
    #[test]
    fn il_settore_non_diventa_un_giudizio_nella_frase_del_grappolo() {
        use lisi_core::model::relevance::Sector;

        let (mut servizio, session_id) = archivio(&[
            "disservizio su portale.esempio-ente.example per la CVE-2026-7777",
            "confermo il disservizio su portale.esempio-ente.example, CVE-2026-7777",
        ]);

        dichiara(
            &mut servizio,
            "Ente di prova",
            Sector::Energia,
            &[],
            &["esempio-ente.example"],
        );

        let Ok(eventi) = servizio.events(session_id) else {
            panic!("i grappoli devono potersi leggere");
        };
        let Some(evento) = eventi.first() else {
            panic!("il grappolo deve esistere");
        };

        let frase = evento.as_sentence().to_lowercase();
        for vietata in ["grave", "attacco", "confermato", "pericolo", "urgente"] {
            assert!(
                !frase.contains(vietata),
                "la frase contiene un giudizio («{vietata}»): «{frase}»"
            );
        }

        // E la frase del settore, letta a parte, dichiara da se' che l'allegato
        // I non e' una gravita'.
        assert!(
            evento
                .sectors
                .as_sentence()
                .contains("non rende grave nulla")
        );
    }

    // ------------------------------------------------------------------
    // La cronologia del grappolo (CYT-01).
    // ------------------------------------------------------------------

    /// Avvia il monitoraggio dell'archivio di prova, dandogli una finestra.
    fn avvia(servizio: &mut CyberWatchService, session_id: lisi_core::SessionId, quando: i64) {
        use lisi_core::model::SessionState;

        let Ok(()) = servizio.database_mut().update_session_state(
            session_id,
            SessionState::Running,
            lisi_core::Timestamp::from_millis(quando),
        ) else {
            panic!("il monitoraggio di prova deve potersi avviare");
        };
    }

    /// La ragione del grappolo su una CVE.
    fn ragione_cve(valore: &str) -> lisi_core::model::cyber_event::CorrelationReason {
        lisi_core::model::cyber_event::CorrelationReason::SameIndicator {
            kind: lisi_core::model::indicator::IndicatorKind::Cve,
            value: String::from(valore),
        }
    }

    /// **La cronologia di un grappolo si legge dall'archivio.**
    ///
    /// Non e' una prova della composizione — quella e' del dominio, ed e' pura.
    /// E' la prova che i fatti che la composizione riceve arrivano davvero dalle
    /// righe, e con i rimandi attaccati.
    #[test]
    fn la_cronologia_di_un_grappolo_arriva_dalle_righe() {
        let (mut servizio, session_id) = archivio(&[
            "Allarme: la CVE-2026-1234 e' sfruttata attivamente.",
            "Segnalata la CVE-2026-1234 su esempio.it.",
        ]);
        avvia(&mut servizio, session_id, 1_700_000_000_000);

        let Ok(cronologia) = servizio.timeline(session_id, &ragione_cve("CVE-2026-1234")) else {
            panic!("la cronologia deve potersi comporre");
        };

        assert!(
            !cronologia.entries().is_empty(),
            "due contenuti che nominano la stessa CVE fanno una cronologia"
        );
        for riga in cronologia.entries() {
            assert!(
                riga.reference().content().get() > 0,
                "ogni riga rimanda a un contenuto vero"
            );
            assert!(
                !riga.reference().remote_message_id().as_str().is_empty(),
                "ogni riga porta l'identificativo del messaggio originale"
            );
        }
        assert_eq!(
            cronologia.window().session,
            session_id,
            "la finestra e' quella del monitoraggio"
        );
    }

    /// **Un contenuto mai fotografato lo dichiara, e non tace.**
    #[test]
    fn senza_fotografia_la_cronologia_lo_dice() {
        let (mut servizio, session_id) = archivio(&[
            "Allarme: la CVE-2026-1234 e' sfruttata attivamente.",
            "Segnalata la CVE-2026-1234 su esempio.it.",
        ]);
        avvia(&mut servizio, session_id, 1_700_000_000_000);

        let Ok(cronologia) = servizio.timeline(session_id, &ragione_cve("CVE-2026-1234")) else {
            panic!("la cronologia deve potersi comporre");
        };

        let prima = cronologia.entries()[0].reference().as_sentence();
        assert!(
            prima.contains("nessuno ha fotografato"),
            "un contesto mai fotografato si dichiara: {prima}"
        );
    }

    /// **Un monitoraggio mai avviato non ha una cronologia.**
    ///
    /// # Il difetto che questa prova impedisce
    ///
    /// Che a chi legge venga consegnata una successione di vuoti senza il fatto
    /// che li spiega. Una linea del tempo senza il periodo in cui si e'
    /// osservato si legge in un modo solo: «qui non e' successo niente».
    ///
    /// # Il controllo negativo
    ///
    /// Sostituendo il rifiuto con una finestra costruita dall'istante di
    /// creazione del monitoraggio, questa prova diventa rossa.
    #[test]
    fn un_monitoraggio_mai_avviato_non_ha_una_cronologia() {
        let (servizio, session_id) = archivio(&[
            "Allarme: la CVE-2026-1234 e' sfruttata attivamente.",
            "Segnalata la CVE-2026-1234 su esempio.it.",
        ]);

        let esito = servizio.timeline(session_id, &ragione_cve("CVE-2026-1234"));
        let Err(errore) = esito else {
            panic!("senza avvio non c'e' finestra, e senza finestra non c'e' cronologia");
        };
        assert!(
            matches!(
                errore,
                crate::error::ServiceError::NoObservationWindow { .. }
            ),
            "l'errore deve dire che manca il periodo di osservazione: {errore}"
        );
        assert!(
            errore.operator_message().contains("non risulta avviato"),
            "il messaggio per l'operatore deve dire perche': {}",
            errore.operator_message()
        );
    }

    /// **Un monitoraggio avviato e non concluso non dichiara di arrivare a
    /// oggi.**
    #[test]
    fn una_finestra_ancora_aperta_lo_dichiara() {
        let (mut servizio, session_id) = archivio(&[
            "Allarme: la CVE-2026-1234 e' sfruttata attivamente.",
            "Segnalata la CVE-2026-1234 su esempio.it.",
        ]);
        avvia(&mut servizio, session_id, 1_700_000_000_000);

        let Ok(cronologia) = servizio.timeline(session_id, &ragione_cve("CVE-2026-1234")) else {
            panic!("la cronologia deve potersi comporre");
        };

        let frase = cronologia.window().as_sentence();
        assert!(
            frase.contains("non risulta concluso"),
            "un monitoraggio in corso lo dice: {frase}"
        );
        assert!(
            frase.contains("Non significa che l'osservazione sia arrivata fino a oggi"),
            "{frase}"
        );
    }

    /// **Un indicatore che nessun contenuto nomina non inventa una cronologia.**
    #[test]
    fn una_ragione_senza_contenuti_non_inventa_righe() {
        let (mut servizio, session_id) =
            archivio(&["Allarme: la CVE-2026-1234 e' sfruttata attivamente."]);
        avvia(&mut servizio, session_id, 1_700_000_000_000);

        let Ok(cronologia) = servizio.timeline(session_id, &ragione_cve("CVE-2099-0001")) else {
            panic!("la cronologia deve potersi comporre anche a vuoto");
        };

        assert!(cronologia.entries().is_empty());
        assert!(
            cronologia.caveat().contains("nessuno stava guardando"),
            "l'avvertenza resta anche quando non c'e' nulla da mostrare"
        );
    }
}
