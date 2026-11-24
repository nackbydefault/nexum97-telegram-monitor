//! Chi ha scritto in una sessione di monitoraggio.
//!
//! # Da dove viene l'elenco, e perché non da Telegram
//!
//! Dall'**archivio**, non dalla piattaforma. L'elenco si ricava dai messaggi
//! già acquisiti: chi compare come autore, quante volte, dalla prima all'ultima
//! comparsa.
//!
//! È la risposta alla richiesta dell'ufficio — *«id, username ed eventuali
//! numeri dei supergruppi e degli utenti che chattano o scrivono»* — con il
//! perimetro che l'ufficio ha indicato: **chi fa qualcosa**, non gli iscritti
//! silenziosi. E ha tre proprietà che nessuna interrogazione a Telegram
//! avrebbe:
//!
//! - **non costa alcuna richiesta**, quindi nessuna esposizione ai limiti di
//!   frequenza e nessun rischio di limitazione dell'account;
//! - **non chiede nulla che l'account non abbia già visto**: sono i messaggi
//!   che il monitoraggio ha acquisito, non una lista di iscritti richiesta alla
//!   piattaforma;
//! - **è verificabile**: ogni riga rimanda a contenuti che stanno in archivio,
//!   e chi contesta l'elenco può risalire ai messaggi che lo compongono.
//!
//! Chiedere a Telegram l'elenco completo degli iscritti — compresi quelli che
//! non hanno mai scritto — è un'altra cosa: costa richieste, espone l'account,
//! e produce un archivio di persone che non hanno fatto nulla. Non è costruito
//! qui, e la ragione è in `docs/adr/ADR-0024-PARTICIPANTS.md`.
//!
//! # Perché serve una ragione scritta
//!
//! Un elenco di persone non è un elenco di contenuti. Chi lo custodisce
//! risponde di averlo, e «l'ho tirato fuori perché il programma lo permetteva»
//! non è una risposta. Per questo l'elenco **non si produce** finché non è
//! registrata una ragione: non è un ostacolo burocratico, è la differenza fra
//! un atto documentato e un atto e basta.

use std::collections::BTreeMap;

use lisi_core::model::reason::OperationalReason;
use lisi_core::model::{Content, NewAuditEntry};
use lisi_core::text::{Actor, AuditAction, AuditDetail, AuditEntity};
use lisi_core::{SessionId, SourceId, Timestamp};
use lisi_storage::Database;

use crate::error::{ServiceError, ServiceResult};

// LA REGOLA SU CHE COSA SIA UNA RAGIONE E. UNA SOLA, e da PERS-01 vive in
// `lisi_core::model::reason`.
//
// Stava qui, come due costanti private. Aprire un soggetto ne richiede una
// anch'esso, e ricopiarla avrebbe prodotto due soglie e due messaggi: il giorno
// in cui una si muovesse senza l'altra, nessuno se ne accorgerebbe.

/// Una persona che ha scritto durante il monitoraggio.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Participant {
    /// Identificativo presso la piattaforma.
    ///
    /// È l'**unico** dei tre campi che regge nel tempo, ed è per questo la
    /// chiave con cui le comparse vengono raggruppate: raggrupparle per nome
    /// unirebbe due persone omonime e separerebbe una che ha cambiato nome.
    pub identifier: String,
    /// Nome leggibile, quando la piattaforma lo ha annunciato.
    pub display_name: Option<String>,
    /// Username, quando ne ha uno. **Non è un'identità**: può cambiare padrone.
    pub username: Option<String>,
    /// Quanti messaggi acquisiti gli sono attribuiti.
    pub messages: usize,
    /// Fonti in cui è comparso.
    pub sources: Vec<SourceId>,
    /// Prima comparsa fra i contenuti acquisiti.
    pub first_seen: Timestamp,
    /// Ultima comparsa.
    pub last_seen: Timestamp,
}

/// Elenco dei partecipanti di una sessione.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ParticipantList {
    /// Persone, dalla più attiva alla meno attiva.
    pub participants: Vec<Participant>,
    /// Contenuti esaminati per comporre l'elenco.
    pub examined: usize,
    /// Contenuti **senza autore individuale**, cioè pubblicati dalle fonti.
    ///
    /// Non sono un residuo: sono la parte del monitoraggio che non riguarda
    /// persone, e dichiararla evita che l'elenco venga letto come se coprisse
    /// tutto ciò che è stato acquisito.
    pub without_author: usize,
}

impl ParticipantList {
    /// Frase per l'operatore.
    #[must_use]
    pub fn operator_message(&self) -> String {
        // Il verbo concorda con il numero (F-25): «3 persone ha scritto».
        let quante = match self.participants.len() {
            0 => String::from("Nessuna persona ha"),
            1 => String::from("1 persona ha"),
            other => format!("{other} persone hanno"),
        };

        format!(
            "{quante} scritto durante questo monitoraggio, su {} contenuti esaminati. \
             Altri {} sono stati pubblicati dalle fonti e non hanno un autore individuale. \
             L'elenco viene dall'archivio: non è stata fatta alcuna richiesta a Telegram.",
            self.examined, self.without_author
        )
    }
}

/// Servizio che compone l'elenco dei partecipanti.
#[derive(Debug)]
pub struct ParticipantService {
    database: Database,
}

impl ParticipantService {
    /// Crea il servizio attorno al database indicato.
    #[must_use]
    pub const fn new(database: Database) -> Self {
        Self { database }
    }

    /// Database sottostante, per i test e la diagnostica.
    #[must_use]
    pub const fn database(&self) -> &Database {
        &self.database
    }

    /// Registra la ragione per cui l'ufficio compone elenchi di persone.
    ///
    /// Va fatto **una volta**, e resta nell'audit. Non è una formalità: chi
    /// custodisce un archivio di persone risponde di averlo, e la ragione è ciò
    /// che distingue un atto documentato da un atto e basta.
    ///
    /// # Errori
    ///
    /// Restituisce [`ServiceError::MissingParticipantBasis`] se la ragione è
    /// assente o troppo breve, e un errore se la registrazione non riesce.
    pub fn record_basis(&self, basis: &str, actor: &Actor, now: Timestamp) -> ServiceResult<()> {
        // LA REGOLA E' QUELLA CONDIVISA (PERS-01): «ok» non e' una ragione.
        //
        // L'errore resta questo, e non quello del dominio, perche' la FRASE
        // conta: qui si sta parlando di elenchi di persone, e il consiglio da
        // dare e' quello.
        let Ok(ragione) = OperationalReason::try_new(basis) else {
            return Err(ServiceError::MissingParticipantBasis);
        };
        let trimmed = ragione.as_str();

        self.database.append_audit(&NewAuditEntry {
            actor: actor.clone(),
            action: AuditAction::try_new("elenco_persone_motivato")?,
            entity: AuditEntity::try_new("session")?,
            entity_id: None,
            actor_mode: None,
            // La ragione **è** il dettaglio: sta nell'audit, dove nessuno la
            // può cambiare senza lasciare traccia, e non in un'impostazione che
            // si riscrive.
            detail: Some(AuditDetail::try_new(trimmed)?),
            recorded_at: now,
        })?;
        Ok(())
    }

    /// Se una ragione è già stata registrata.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se l'audit non è leggibile.
    pub fn basis_recorded(&self) -> ServiceResult<bool> {
        Ok(self.database.operational_basis_recorded()?)
    }

    /// Compone l'elenco delle persone che hanno scritto in una sessione.
    ///
    /// # Errori
    ///
    /// Restituisce [`ServiceError::MissingParticipantBasis`] se nessuna ragione
    /// è stata registrata: l'elenco **non si produce** prima. Restituisce un
    /// errore se l'archivio non è leggibile.
    pub fn list(&self, session_id: SessionId) -> ServiceResult<ParticipantList> {
        if !self.basis_recorded()? {
            return Err(ServiceError::MissingParticipantBasis);
        }

        let contents = self.database.session_contents(session_id)?;
        Ok(compose(&contents))
    }
}

/// Riduce i contenuti acquisiti all'elenco delle persone che li hanno scritti.
///
/// Funzione pura, separata dal servizio: il raggruppamento è la parte che
/// merita un test, e un test non deve costruire un archivio per esercitarla.
fn compose(contents: &[Content]) -> ParticipantList {
    let mut by_identifier: BTreeMap<&str, Participant> = BTreeMap::new();
    let mut without_author = 0_usize;

    for content in contents {
        // I messaggi di canale non hanno un autore individuale. Contarli fra le
        // persone attribuirebbe a qualcuno ciò che una persona non ha scritto.
        let Some(identifier) = content.author_identifier.as_deref() else {
            without_author = without_author.saturating_add(1);
            continue;
        };

        let entry = by_identifier
            .entry(identifier)
            .or_insert_with(|| Participant {
                identifier: identifier.to_owned(),
                display_name: None,
                username: None,
                messages: 0,
                sources: Vec::new(),
                first_seen: content.published_at,
                last_seen: content.published_at,
            });

        entry.messages = entry.messages.saturating_add(1);

        // Il nome e lo username si prendono dall'occorrenza **più recente**: se
        // qualcuno li ha cambiati durante il monitoraggio, l'elenco mostra
        // quelli attuali. I precedenti restano nei contenuti, che non cambiano.
        if content.published_at >= entry.last_seen {
            entry.last_seen = content.published_at;
            if let Some(name) = content.author.as_ref() {
                entry.display_name = Some(name.as_str().to_owned());
            }
            if let Some(username) = content.author_username.as_ref() {
                entry.username = Some(username.clone());
            }
        }
        if content.published_at < entry.first_seen {
            entry.first_seen = content.published_at;
        }

        if !entry.sources.contains(&content.source_id) {
            entry.sources.push(content.source_id);
        }
    }

    let mut participants: Vec<Participant> = by_identifier.into_values().collect();
    // Dal più attivo, e a parità di messaggi per identificativo: l'ordine deve
    // essere lo stesso a ogni esecuzione, altrimenti due elenchi dello stesso
    // monitoraggio non si possono confrontare.
    participants.sort_by(|left, right| {
        right
            .messages
            .cmp(&left.messages)
            .then_with(|| left.identifier.cmp(&right.identifier))
    });

    ParticipantList {
        participants,
        examined: contents.len(),
        without_author,
    }
}

#[cfg(test)]
mod tests {
    use lisi_core::model::{AcquisitionOrigin, AnalysisLevel, Content};
    use lisi_core::text::{Actor, ContentBody, RemoteMessageId};
    use lisi_core::{ContentId, SessionId, SourceId, Timestamp};

    use super::{ParticipantService, compose};
    use crate::sources::open_in_memory_database;

    fn at(offset: i64) -> Timestamp {
        Timestamp::from_millis(1_700_000_000_000 + offset)
    }

    fn content(
        id: i64,
        identifier: Option<&str>,
        name: Option<&str>,
        username: Option<&str>,
        source: i64,
        published: Timestamp,
    ) -> Content {
        let (Ok(remote), Ok(body)) = (
            RemoteMessageId::try_new(&id.to_string()),
            ContentBody::try_new("testo"),
        ) else {
            panic!("i valori di prova devono essere validi");
        };

        Content {
            id: ContentId::new(id),
            engine_version: Some(lisi_core::analysis::ENGINE_VERSION),
            session_id: SessionId::new(1),
            source_id: SourceId::new(source),
            remote_message_id: remote,
            author: name.and_then(|value| Actor::try_new(value).ok()),
            author_identifier: identifier.map(str::to_owned),
            author_username: username.map(str::to_owned),
            body,
            url: None,
            published_at: published,
            acquired_at: published,
            origin: AcquisitionOrigin::Observed,
            analysis_level: AnalysisLevel::NOT_RELEVANT,
            body_sha256: lisi_core::Sha256Digest::of_text("testo"),
            duplicate_of_id: None,
        }
    }

    #[test]
    fn people_are_grouped_by_identifier_and_not_by_name() {
        // Raggruppare per nome unirebbe due omonimi e separerebbe chi ha
        // cambiato nome. L'identificativo e' l'unico dei tre campi che regge.
        let contents = vec![
            content(1, Some("100"), Some("Mario Rossi"), None, 1, at(0)),
            content(2, Some("200"), Some("Mario Rossi"), None, 1, at(1_000)),
            content(3, Some("100"), Some("Mario R."), None, 1, at(2_000)),
        ];

        let list = compose(&contents);
        assert_eq!(list.participants.len(), 2, "due persone, non una");

        let first = &list.participants[0];
        assert_eq!(first.identifier, "100");
        assert_eq!(first.messages, 2);
        // Il nome e' quello dell'occorrenza piu' recente.
        assert_eq!(first.display_name.as_deref(), Some("Mario R."));
    }

    #[test]
    fn channel_messages_are_counted_apart_and_not_attributed_to_anyone() {
        let contents = vec![
            content(1, Some("100"), None, None, 1, at(0)),
            content(2, None, None, None, 1, at(1_000)),
            content(3, None, None, None, 1, at(2_000)),
        ];

        let list = compose(&contents);
        assert_eq!(list.participants.len(), 1);
        assert_eq!(list.without_author, 2);
        assert_eq!(list.examined, 3);

        // La frase dice entrambe le cose: un elenco di una persona su tre
        // contenuti si leggerebbe male senza sapere che gli altri due non
        // hanno un autore.
        let message = list.operator_message();
        assert!(message.contains("1 persona"));
        assert!(message.contains("su 3 contenuti"));
        // La frase deve dire **da dove viene** l'elenco: chi lo legge deve
        // sapere che non e' una lista chiesta alla piattaforma.
        assert!(message.contains("alcuna richiesta a Telegram"));
        assert!(message.contains("viene dall'archivio"));
    }

    #[test]
    fn the_order_is_the_same_on_every_run() {
        // Due elenchi dello stesso monitoraggio devono potersi confrontare.
        let contents = vec![
            content(1, Some("100"), None, None, 1, at(0)),
            content(2, Some("200"), None, None, 1, at(1_000)),
            content(3, Some("200"), None, None, 1, at(2_000)),
            content(4, Some("300"), None, None, 1, at(3_000)),
        ];

        let first = compose(&contents);
        let second = compose(&contents);
        assert_eq!(first, second);

        // Dal piu' attivo.
        assert_eq!(first.participants[0].identifier, "200");
        assert_eq!(first.participants[0].messages, 2);
    }

    #[test]
    fn a_person_seen_in_two_sources_carries_both() {
        let contents = vec![
            content(1, Some("100"), None, None, 1, at(0)),
            content(2, Some("100"), None, None, 2, at(1_000)),
            content(3, Some("100"), None, None, 1, at(2_000)),
        ];

        let list = compose(&contents);
        assert_eq!(list.participants[0].sources.len(), 2);
        assert_eq!(list.participants[0].messages, 3);
        assert_eq!(list.participants[0].first_seen, at(0));
        assert_eq!(list.participants[0].last_seen, at(2_000));
    }

    fn service() -> ParticipantService {
        let Ok(database) = open_in_memory_database() else {
            panic!("l'archivio in memoria deve potersi aprire");
        };
        ParticipantService::new(database)
    }

    fn operator() -> Actor {
        let Ok(actor) = Actor::try_new("operatore.prova") else {
            panic!("l'attore di prova deve essere valido");
        };
        actor
    }

    #[test]
    fn without_a_recorded_reason_the_list_is_not_produced() {
        // E' il controllo per cui questo servizio esiste in questa forma: un
        // archivio di persone senza una ragione registrata e' un problema di
        // chi lo custodisce.
        let service = service();
        assert!(service.list(SessionId::new(1)).is_err());
    }

    #[test]
    fn a_reason_too_short_is_not_a_reason() {
        let service = service();
        assert!(service.record_basis("ok", &operator(), at(0)).is_err());
        assert!(service.record_basis("   ", &operator(), at(0)).is_err());
        assert!(!service.basis_recorded().unwrap_or(true));
    }

    #[test]
    fn once_the_reason_is_recorded_the_list_can_be_produced_and_the_reason_stays() {
        let service = service();
        let basis =
            "Accertamenti delegati dall'autorita' giudiziaria, fascicolo di riferimento agli atti.";

        let Ok(()) = service.record_basis(basis, &operator(), at(0)) else {
            panic!("una ragione adeguata deve essere accettata");
        };
        let Ok(recorded) = service.basis_recorded() else {
            panic!("l'audit deve potersi leggere");
        };
        assert!(recorded);

        // La ragione resta nell'audit, dove nessuno la cambia senza lasciare
        // traccia.
        let Ok(audit) = service.database().audit_entries() else {
            panic!("l'audit deve potersi leggere");
        };
        let found = audit
            .iter()
            .find(|entry| entry.action.as_str() == "elenco_persone_motivato");
        let Some(found) = found else {
            panic!("la ragione deve essere registrata");
        };
        assert_eq!(
            found.detail.as_ref().map(|detail| detail.as_str()),
            Some(basis)
        );

        // E l'elenco ora si produce, anche se vuoto.
        assert!(service.list(SessionId::new(1)).is_ok());
    }

    /// **Uno username che passa da una persona a un'altra non le fonde, e un
    /// contenuto senza identificativo non si attribuisce per nome**
    /// (IDENTITY-03, criteri 1 e 3).
    #[test]
    fn uno_username_che_passa_di_mano_non_fonde_due_persone() {
        let contents = vec![
            content(1, Some("100"), Some("Anna"), Some("alfa_uno"), 1, at(0)),
            content(
                2,
                Some("200"),
                Some("Bruno"),
                Some("beta_due"),
                1,
                at(1_000),
            ),
            content(3, Some("100"), Some("Anna"), Some("beta_due"), 1, at(2_000)),
            content(
                4,
                Some("200"),
                Some("Bruno"),
                Some("alfa_uno"),
                1,
                at(3_000),
            ),
            // Lo stesso nome e lo stesso username, ma senza identificativo: non
            // è di nessuno dei due.
            content(5, None, Some("Anna"), Some("beta_due"), 1, at(4_000)),
        ];
        let list = compose(&contents);
        assert_eq!(
            list.participants.len(),
            2,
            "due identificativi, due persone"
        );
        for (identificativo, nome) in [("100", "Anna"), ("200", "Bruno")] {
            let Some(persona) = list
                .participants
                .iter()
                .find(|persona| persona.identifier == identificativo)
            else {
                panic!("l'identificativo {identificativo} deve esserci");
            };
            assert_eq!(persona.messages, 2, "{identificativo}: due messaggi suoi");
            assert_eq!(
                persona.display_name.as_deref(),
                Some(nome),
                "{identificativo} resta {nome}: lo username passato di mano non porta con sé la persona"
            );
        }
        assert_eq!(
            list.without_author, 1,
            "il contenuto senza identificativo resta a parte"
        );
    }
}
