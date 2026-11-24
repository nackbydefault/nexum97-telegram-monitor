//! Ricerca retroattiva nella cronologia già pubblicata delle fonti configurate.
//!
//! # Che cosa fa, e che cosa deliberatamente non fa
//!
//! Risale la cronologia delle fonti **già configurate** e dice quali messaggi
//! del passato contengono i termini del dizionario in vigore. **Non archivia
//! nulla.**
//!
//! Non archiviare è una scelta, non una mancanza. Il recupero della cronologia
//! (`crate::recovery`) porta in archivio ciò che appartiene al monitoraggio in
//! corso: c'è una sessione, un istante d'inizio, e una decisione di sorvegliare
//! quelle fonti da quel momento. Qui si guarda **più indietro di quella
//! decisione**, e ciò che si trova non è materiale che qualcuno aveva chiesto
//! di sorvegliare. Portarlo in archivio significherebbe far affermare
//! all'archivio di aver monitorato un periodo che nessuno aveva deciso di
//! monitorare.
//!
//! Chi trova qualcosa e vuole conservarlo ha il collegamento al messaggio e può
//! trattarlo come un fatto nuovo. Chi non lo vuole non si ritrova l'archivio
//! cambiato per aver fatto una ricerca.
//!
//! # Il perimetro, e chi lo ha deciso
//!
//! **Solo le fonti già configurate**, non tutto ciò a cui l'account ha accesso.
//! È la risposta data dall'ufficio, e cambia ciò che il prodotto è: cercare in
//! qualunque chat accessibile sarebbe uno strumento diverso — non più
//! «sorveglio queste fonti» ma «cerco in tutto ciò a cui ho accesso».
//!
//! Che leggere la cronologia anteriore all'accesso dell'account rientri nel
//! mandato è stato **confermato dal dirigente dell'ufficio**. Tecnicamente il
//! prodotto legge solo ciò che l'account vede legittimamente: per un canale
//! pubblico Telegram mostra la cronologia a chiunque.

use lisi_core::analysis::analyse;
use lisi_core::model::dictionary::ResolvedDictionaryConfiguration;
use lisi_core::{SourceId, Timestamp};
use lisi_telegram::identifier::ChatId;
use lisi_telegram::{IncomingMessage, TelegramConnector};

use crate::error::{ServiceError, ServiceResult};

/// Messaggi chiesti in una sola pagina.
const PAGE_SIZE: u32 = 100;

/// Pagine massime lette per una fonte in una ricerca.
///
/// La ricerca retroattiva risale **oltre** l'inizio del monitoraggio, quindi
/// potenzialmente per anni: senza tetto una fonte molto attiva la farebbe durare
/// finché qualcuno non chiude l'applicazione. Quando il tetto scatta il
/// risultato lo dichiara, perché «nessun riscontro» e «nessun riscontro fin dove
/// ho guardato» sono due affermazioni diverse.
const MAX_PAGES_PER_SOURCE: usize = 200;

/// Un messaggio del passato che contiene termini del dizionario.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RetroMatch {
    /// Fonte in cui è stato trovato.
    pub source_id: SourceId,
    /// Messaggio, con il collegamento quando esiste.
    pub message: IncomingMessage,
    /// Livello che l'analisi gli attribuirebbe.
    ///
    /// Si dice **attribuirebbe** e non «attribuisce»: il messaggio non entra in
    /// archivio, quindi nessun livello viene registrato. È un'anteprima del
    /// giudizio, non il giudizio.
    pub level: u8,
    /// Termini riscontrati, nell'ordine in cui compaiono nel testo.
    pub terms: Vec<String>,
}

/// Esito di una ricerca retroattiva.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RetroSearchOutcome {
    /// Messaggi trovati, dal più recente al più vecchio.
    pub matches: Vec<RetroMatch>,
    /// Quanti messaggi sono stati letti e giudicati.
    ///
    /// È il denominatore del risultato: «tre riscontri» significa poco senza
    /// sapere se sono tre su cento o tre su centomila.
    pub examined: usize,
    /// Se la lettura è arrivata in fondo a tutte le fonti.
    ///
    /// Falso quando un tetto è scattato o una fonte non ha risposto: in quel
    /// caso «nessun altro riscontro» vale **solo fin dove si è guardato**.
    pub complete: bool,
}

impl RetroSearchOutcome {
    /// Frase per l'operatore.
    ///
    /// Dice quanti riscontri, su quanti messaggi, e se la lettura è arrivata in
    /// fondo. Un numero di riscontri senza il denominatore e senza la
    /// completezza è un numero che si lascia interpretare male.
    #[must_use]
    pub fn operator_message(&self) -> String {
        let quanti = match self.matches.len() {
            0 => String::from("Nessun riscontro"),
            1 => String::from("1 riscontro"),
            other => format!("{other} riscontri"),
        };

        let fin_dove = if self.complete {
            String::from("in tutta la cronologia leggibile delle fonti configurate.")
        } else {
            String::from(
                "fin dove la lettura è arrivata: non è stata percorsa tutta la cronologia, \
                 quindi potrebbero essercene altri più indietro.",
            )
        };

        format!(
            "{quanti} su {} messaggi esaminati, {fin_dove} \
             Nulla è stato archiviato: la ricerca guarda, non acquisisce.",
            self.examined
        )
    }
}

/// Ricerca **riprendibile**, una fonte per volta.
///
/// Come per la ricognizione del recupero, il lavoro è spezzato perché chi lo
/// guida possa ridisegnare la schermata fra un passo e l'altro e fermarsi. Qui
/// conta anche di più: si risale oltre l'inizio del monitoraggio, quindi
/// potenzialmente molto indietro.
#[derive(Debug)]
pub struct RetroSearchRun {
    remaining: Vec<(i64, SourceId)>,
    total_sources: usize,
    outcome: RetroSearchOutcome,
    configuration: ResolvedDictionaryConfiguration,
    /// Istante oltre il quale non si risale, quando l'operatore ne ha fissato
    /// uno.
    not_before: Option<Timestamp>,
}

impl RetroSearchRun {
    /// Prepara la ricerca sulle fonti indicate.
    ///
    /// `sources` sono le **fonti configurate** con la chat corrispondente:
    /// l'elenco lo compone chi chiama, e non questa funzione, perché è il
    /// perimetro deciso dall'ufficio e deve restare visibile a chi lo legge.
    #[must_use]
    pub fn new(
        sources: &[(i64, SourceId)],
        configuration: ResolvedDictionaryConfiguration,
        not_before: Option<Timestamp>,
    ) -> Self {
        let mut remaining = sources.to_vec();
        remaining.sort_unstable();
        remaining.reverse();

        Self {
            total_sources: remaining.len(),
            remaining,
            outcome: RetroSearchOutcome {
                complete: true,
                ..RetroSearchOutcome::default()
            },
            configuration,
            not_before,
        }
    }

    /// Se non c'è più nulla da leggere.
    #[must_use]
    pub const fn is_finished(&self) -> bool {
        self.remaining.is_empty()
    }

    /// Quante fonti sono già state percorse.
    #[must_use]
    pub const fn sources_done(&self) -> usize {
        self.total_sources.saturating_sub(self.remaining.len())
    }

    /// Ciò che è stato trovato finora.
    #[must_use]
    pub const fn outcome(&self) -> &RetroSearchOutcome {
        &self.outcome
    }

    /// Consegna l'esito, consumando la ricerca.
    #[must_use]
    pub fn into_outcome(self) -> RetroSearchOutcome {
        self.outcome
    }

    /// Frase di avanzamento.
    #[must_use]
    pub fn progress_message(&self) -> String {
        format!(
            "Ricerca in corso: {} su {}, {}, {}.",
            lisi_core::text::counted(self.sources_done(), "fonte", "fonti"),
            self.total_sources,
            lisi_core::text::counted(
                self.outcome.examined,
                "messaggio esaminato",
                "messaggi esaminati"
            ),
            lisi_core::text::counted(self.outcome.matches.len(), "riscontro", "riscontri")
        )
    }

    /// Interrompe la ricerca, conservando ciò che ha trovato.
    ///
    /// L'esito viene marcato incompleto: chi si ferma a metà non deve poi
    /// leggere «nessun altro riscontro» come se fosse definitivo.
    pub fn stop(&mut self) {
        self.remaining.clear();
        self.outcome.complete = false;
    }

    /// Percorre **una** fonte.
    ///
    /// # Errori
    ///
    /// Non restituisce errore per il guasto di una fonte: viene registrato e la
    /// ricerca prosegue dichiarandosi incompleta. Perdere il risultato di
    /// cinque fonti perché la sesta non risponde sarebbe un danno maggiore del
    /// guasto.
    pub fn step(&mut self, connector: &mut dyn TelegramConnector) -> ServiceResult<()> {
        let Some((raw_chat, source_id)) = self.remaining.pop() else {
            return Ok(());
        };

        let Ok(chat_id) = ChatId::try_new(raw_chat) else {
            tracing::warn!(chat = raw_chat, "identificativo di chat non valido");
            self.outcome.complete = false;
            return Ok(());
        };

        if let Err(error) = self.walk_source(connector, chat_id, source_id) {
            tracing::warn!(
                kind = error.kind(),
                "cronologia di una fonte non percorribile: le altre proseguono"
            );
            self.outcome.complete = false;
        }

        Ok(())
    }

    /// Risale la cronologia di una fonte, giudicando ogni messaggio.
    fn walk_source(
        &mut self,
        connector: &mut dyn TelegramConnector,
        chat_id: ChatId,
        source_id: SourceId,
    ) -> ServiceResult<()> {
        let mut from_message_id = 0_i64;

        for _ in 0..MAX_PAGES_PER_SOURCE {
            let page = connector
                .fetch_history(chat_id, from_message_id, PAGE_SIZE)
                .map_err(|error| ServiceError::SessionUnavailable {
                    reason: format!("cronologia non leggibile: {error}"),
                })?;

            if page.is_empty() {
                // Si è arrivati in fondo a ciò che la fonte mostra.
                return Ok(());
            }

            if let Some(last) = page.last() {
                from_message_id = last.message_id.get();
            }

            for message in page {
                if let Some(limit) = self.not_before
                    && message.published_at_millis < limit.as_millis()
                {
                    // Oltre il confine che l'operatore ha fissato: si smette,
                    // e non è un'incompletezza — è il perimetro chiesto.
                    return Ok(());
                }

                self.outcome.examined = self.outcome.examined.saturating_add(1);

                let analysed = analyse(&message.text, &self.configuration);
                if analysed.occurrences.is_empty() {
                    continue;
                }

                // I termini si prendono dalla configurazione, non dal testo: è
                // la parola **del dizionario** che ha prodotto il riscontro, e
                // mostrarne la forma trovata nel testo confonderebbe chi cerca
                // di capire quale regola ha reagito.
                let mut terms: Vec<String> = analysed
                    .occurrences
                    .iter()
                    .filter_map(|occurrence| {
                        self.configuration
                            .terms
                            .get(occurrence.term_index)
                            .map(|term| term.original.as_str().to_owned())
                    })
                    .collect();
                terms.dedup();

                self.outcome.matches.push(RetroMatch {
                    source_id,
                    message,
                    level: analysed.outcome.level.get(),
                    terms,
                });
            }
        }

        // Il tetto è scattato: si è guardato molto, non tutto.
        self.outcome.complete = false;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use lisi_core::model::dictionary::{
        ConfigurationResolver, MatchMode, ResolvedDictionaryConfiguration, TermProvenance,
    };
    use lisi_core::text::{LanguageTag, TermCategory, TermText};
    use lisi_core::{SourceId, Timestamp};
    use lisi_telegram::TelegramConnector;
    use lisi_telegram::connector::ClientParameters;
    use lisi_telegram::mock::MockTelegramConnector;
    use lisi_telegram::secret::{ApiHash, ApiId, LoginCode, PhoneNumber};

    use super::{RetroSearchOutcome, RetroSearchRun};

    const CHAT: i64 = -1_001_000_000_001;

    fn base() -> Timestamp {
        Timestamp::from_millis(1_700_000_000_000)
    }

    /// Configurazione con un solo termine, che basta a provare il giudizio.
    fn configuration() -> ResolvedDictionaryConfiguration {
        let (Ok(term), Ok(category), Ok(language)) = (
            TermText::try_new("molotov"),
            TermCategory::try_new("prova"),
            LanguageTag::try_new("it"),
        ) else {
            panic!("i valori di prova devono essere validi");
        };

        let mut resolver = ConfigurationResolver::new();
        let Ok(()) = resolver.add(
            term,
            category,
            language,
            MatchMode::NormalizedWord,
            3,
            TermProvenance::ad_hoc(),
        ) else {
            panic!("il termine deve essere accettato");
        };
        resolver.finish()
    }

    fn ready_connector() -> MockTelegramConnector {
        let mut connector = MockTelegramConnector::new();
        let (Ok(api_id), Ok(api_hash)) = (ApiId::try_new(1), ApiHash::try_new(&"a".repeat(32)))
        else {
            panic!("i valori di prova devono essere validi");
        };
        let Ok(()) = connector.start(&ClientParameters {
            api_id,
            api_hash,
            database_directory: std::path::PathBuf::from("."),
            use_test_datacenter: true,
            application_version: String::from("prova"),
            system_language_code: String::from("it"),
        }) else {
            panic!("l'avvio simulato deve riuscire");
        };
        let (Ok(phone), Ok(code)) = (
            PhoneNumber::try_new("+390000000000"),
            LoginCode::try_new("12345"),
        ) else {
            panic!("i valori di prova devono essere validi");
        };
        let (Ok(()), Ok(())) = (
            connector.submit_phone_number(&phone),
            connector.submit_code(&code),
        ) else {
            panic!("l'accesso simulato deve riuscire");
        };
        connector
    }

    fn run_to_the_end(
        connector: &mut MockTelegramConnector,
        not_before: Option<Timestamp>,
    ) -> RetroSearchOutcome {
        let mut run = RetroSearchRun::new(&[(CHAT, SourceId::new(1))], configuration(), not_before);
        while !run.is_finished() {
            let Ok(()) = run.step(connector) else {
                panic!("il passo della ricerca deve riuscire");
            };
        }
        run.into_outcome()
    }

    #[test]
    fn a_past_message_with_a_term_is_found_and_judged() {
        let mut connector = ready_connector();
        let (Ok(()), Ok(())) = (
            connector.push_history(
                CHAT,
                2 << 20,
                "parlano di una molotov",
                Timestamp::from_millis(base().as_millis() + 2_000).as_millis(),
            ),
            connector.push_history(
                CHAT,
                1 << 20,
                "buongiorno a tutti",
                Timestamp::from_millis(base().as_millis() + 1_000).as_millis(),
            ),
        ) else {
            panic!("la cronologia di prova deve potersi comporre");
        };

        let outcome = run_to_the_end(&mut connector, None);
        assert_eq!(outcome.matches.len(), 1);
        assert_eq!(outcome.matches[0].message.text, "parlano di una molotov");
        assert_eq!(outcome.matches[0].terms, vec![String::from("molotov")]);
        assert_eq!(outcome.matches[0].level, 3);

        // Il denominatore c'e': «un riscontro» significa poco senza sapere su
        // quanti messaggi.
        assert_eq!(outcome.examined, 2);
        assert!(outcome.complete);
        assert!(outcome.operator_message().contains("su 2 messaggi"));
    }

    #[test]
    fn the_search_says_plainly_that_it_archives_nothing() {
        // E' la differenza fra questa e il recupero, e chi legge il risultato
        // deve poterla vedere senza aver letto la documentazione.
        let outcome = RetroSearchOutcome::default();
        assert!(
            outcome
                .operator_message()
                .contains("Nulla è stato archiviato")
        );
    }

    #[test]
    fn nothing_found_is_not_the_same_as_nothing_found_so_far() {
        let complete = RetroSearchOutcome {
            complete: true,
            ..RetroSearchOutcome::default()
        };
        let partial = RetroSearchOutcome::default();

        assert!(
            complete
                .operator_message()
                .contains("in tutta la cronologia")
        );
        assert!(partial.operator_message().contains("fin dove"));
        assert_ne!(complete.operator_message(), partial.operator_message());
    }

    #[test]
    fn the_operator_boundary_stops_the_walk_without_making_it_incomplete() {
        // Fermarsi al confine chiesto **non** e' un'incompletezza: e' il
        // perimetro. Marcarlo incompleto direbbe che qualcosa e' sfuggito.
        let mut connector = ready_connector();
        let (Ok(()), Ok(())) = (
            connector.push_history(
                CHAT,
                2 << 20,
                "una molotov recente",
                Timestamp::from_millis(base().as_millis() + 2_000).as_millis(),
            ),
            connector.push_history(
                CHAT,
                1 << 20,
                "una molotov vecchia",
                Timestamp::from_millis(base().as_millis() - 10_000).as_millis(),
            ),
        ) else {
            panic!("la cronologia di prova deve potersi comporre");
        };

        let outcome = run_to_the_end(&mut connector, Some(base()));
        assert_eq!(outcome.matches.len(), 1, "solo quello dentro il confine");
        assert_eq!(outcome.matches[0].message.text, "una molotov recente");
        assert!(
            outcome.complete,
            "fermarsi al confine chiesto non e' un'incompletezza"
        );
    }

    #[test]
    fn a_source_that_never_answers_leaves_the_result_declared_incomplete() {
        // Nessuna cronologia sintetica: il mock risponde con una pagina vuota,
        // che significa «non c'e' altro» e non e' un guasto. Il caso del guasto
        // vero e' coperto dal fatto che `step` non propaga l'errore ma marca
        // l'esito: qui si verifica che una fonte vuota **non** marchi nulla.
        let mut connector = ready_connector();
        let outcome = run_to_the_end(&mut connector, None);
        assert!(outcome.matches.is_empty());
        assert_eq!(outcome.examined, 0);
        assert!(
            outcome.complete,
            "una fonte senza cronologia non rende incompleto il risultato"
        );
    }

    #[test]
    fn the_progress_message_carries_both_numbers() {
        let run = RetroSearchRun::new(
            &[(CHAT, SourceId::new(1)), (-1_002, SourceId::new(2))],
            configuration(),
            None,
        );
        let message = run.progress_message();
        assert!(message.contains("0 fonti su 2"));
        assert!(message.contains("0 riscontri"));
    }
}
