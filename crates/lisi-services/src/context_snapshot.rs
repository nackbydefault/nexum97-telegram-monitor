//! Conservare un contesto: un atto esplicito, con un nome e una ragione.
//!
//! # La regola che questa milestone poteva tradire
//!
//! Il congelamento la scrive da CTX-02: «scorrere la vista **non** trasforma
//! ciò che si vede in prova operativa». Fino a CTX-05 il modo di rispettarla
//! era che **nessuno scrivesse niente**, e una prova cercava nel sorgente ogni
//! scrittura del servizio del contesto.
//!
//! CTX-06 scrive per forza. La guardia di CTX-02 **non è stata tolta**: è
//! rimasta dov'era, e sorveglia ancora che leggere un contesto non scriva.
//! Questo modulo è l'altra metà, e vive separato proprio perché quella guardia
//! continui a valere su ciò che sorvegliava.
//!
//! # La garanzia: conservare non può osservare
//!
//! Sono due capacità, e **non stanno mai nella stessa funzione**.
//!
//! [`crate::context::read`] riceve `&Database` — sola lettura — e un
//! connettore: può osservare, e il compilatore non gli lascia scrivere.
//! [`take`] riceve `&mut Database` e **nessun connettore**: può conservare, e
//! non ha nulla a cui chiedere.
//!
//! Ne segue ciò che serve davvero: una fotografia contiene **soltanto** ciò che
//! era già stato mostrato a una persona. Non esiste un percorso che chieda
//! qualcosa a Telegram e lo archivi senza che nessuno l'abbia visto.
//!
//! Una prova elenca i parametri di [`take`] e fallisce se ne compare uno che
//! sappia parlare con Telegram.
//!
//! # Che cosa una fotografia richiede
//!
//! Un operatore, una ragione, un istante — e l'audit, come ogni atto di cui
//! qualcuno risponde in questo prodotto.
//!
//! La ragione non è una cortesia: il tipo la pretende, la colonna è `NOT NULL`,
//! e il servizio traduce il rifiuto in una frase che dice perché.

use lisi_core::model::audit::NewAuditEntry;
use lisi_core::model::context_snapshot::{
    ContextSnapshot, NewContextSnapshot, SnapshotComparison, SnapshotMessage,
};
use lisi_core::text::{Actor, AuditAction, AuditDetail, AuditEntity, Note};
use lisi_core::{ContentId, ContextSnapshotId, Timestamp};
use lisi_storage::Database;

use crate::context::MessageContext;
use crate::error::{ServiceError, ServiceResult};

/// Conserva ciò che una persona sta guardando.
///
/// # Che cosa riceve, e che cosa non riceve
///
/// Riceve l'archivio scrivibile, il contesto **già letto** e mostrato, chi
/// conserva e perché. **Non riceve un connettore**: non può chiedere nulla a
/// Telegram, e quindi non può conservare ciò che nessuno ha visto.
///
/// # Errori
///
/// Restituisce [`ServiceError::SnapshotWithoutAnswer`] quando Telegram non è
/// stato chiesto o non ha risposto (DEC-508),
/// [`ServiceError::SnapshotNeedsReason`] quando la ragione è vuota o fatta di
/// soli spazi, e un errore di archivio se la scrittura non riesce.
pub fn take(
    database: &mut Database,
    context: &MessageContext,
    taken_by: &Actor,
    reason: &Note,
    now: Timestamp,
) -> ServiceResult<ContextSnapshotId> {
    // SI CONSERVA SOLTANTO CIO' CHE TELEGRAM HA DATO (CU01-013, DEC-508).
    //
    // Senza una risposta la fotografia conserverebbe zero messaggi, e la
    // conferma e i documenti direbbero che Telegram non ne ha restituiti:
    // un'osservazione mai avvenuta, dentro un atto. Si rifiuta prima di
    // scrivere, e l'audit non registra un atto che non c'e' stato.
    if !context.telegram_answered() {
        return Err(ServiceError::SnapshotWithoutAnswer);
    }

    // LA FONTE VIENE DALL'ARCHIVIO, NON DAL CHIAMANTE.
    //
    // Il congelamento chiede che una fotografia porti la sua provenienza.
    // Farsela passare significherebbe fidarsi che chi chiama sappia quale sia,
    // e una provenienza sbagliata e' peggio di una assente.
    let content = database.content(context.anchor.content_id)?;

    let messages: Vec<SnapshotMessage> = context
        .surrounding
        .iter()
        .map(|messaggio| SnapshotMessage {
            remote_message_id: messaggio.remote_message_id.clone(),
            published_at: messaggio.published_at,
            body: messaggio.text.clone(),
            // LE FRASI SI CONSERVANO COM'ERANO.
            //
            // Ricomporle domani, con il codice di domani, direbbe che quel
            // giorno si era letta una frase che non si era letta.
            author_sentence: messaggio.who.clone(),
            relations_sentence: messaggio.relations.clone(),
            is_anchor: messaggio.is_anchor,
        })
        .collect();

    // IL CONFRONTO SI CONSERVA COME FU OSSERVATO.
    //
    // E' un'osservazione datata: rifarla al momento della fotografia darebbe un
    // esito che nessuno ha visto, calcolato su testi che nessuno ha guardato
    // insieme.
    let comparison = context.comparison.map(|confronto| SnapshotComparison {
        change: confronto.change(),
        divergence: confronto.divergence(),
    });

    // L'ISTANTE DICHIARATO DA TELEGRAM, quando l'ancora era tornata.
    let declared_edit_at = context
        .surrounding
        .iter()
        .find(|messaggio| messaggio.is_anchor)
        .and_then(|ancora| ancora.declared_edit);

    let snapshot = NewContextSnapshot::prepare(
        context.anchor.content_id,
        content.source_id,
        taken_by,
        reason,
        now,
        context.observed_at,
        context.anchor.remote_message_id.as_str(),
        context.anchor.body.as_str(),
        comparison,
        declared_edit_at,
        messages,
    )
    .map_err(|_| ServiceError::SnapshotNeedsReason)?;

    let id = database.insert_context_snapshot(&snapshot)?;

    // L'AUDIT: un atto di cui qualcuno risponde lascia traccia.
    //
    // Il dettaglio dice **quante** righe e **per quale contenuto**, e non che
    // cosa dicessero: l'audit documenta le azioni, non i dati su cui insistono.
    database.append_audit(&NewAuditEntry {
        actor: taken_by.clone(),
        action: AuditAction::try_new("fotografia_contesto_presa")?,
        entity: AuditEntity::try_new("context_snapshot")?,
        entity_id: Some(id.get()),
        actor_mode: None,
        detail: Some(AuditDetail::try_new(&format!(
            "contenuto {}, {} messaggi conservati",
            context.anchor.content_id.get(),
            snapshot.messages().len()
        ))?),
        recorded_at: now,
    })?;

    Ok(id)
}

/// La conferma di una fotografia, in una frase (ADR-0166, CA02-03).
///
/// Una fotografia senza messaggi intorno a quello dell'avviso si conserva,
/// perché è un'osservazione vera; ma lo si dice, invece di confermarla con la
/// stessa frase di una fotografia piena.
#[must_use]
pub fn taken_sentence(context: &MessageContext) -> String {
    let intorno = context
        .surrounding
        .iter()
        .filter(|messaggio| !messaggio.is_anchor)
        .count();
    if intorno == 0 {
        String::from(
            "Contesto conservato con 0 messaggi intorno a quello dell'avviso: la fotografia \
             conserva che, in quel momento, Telegram non ne ha restituiti. Non sostituisce la \
             prova: il testo dell'archivio resta quello che \u{e8}.",
        )
    } else {
        String::from(
            "Contesto conservato. La fotografia compare qui sotto, e non sostituisce la prova: il \
             testo dell'archivio resta quello che \u{e8}.",
        )
    }
}

/// Le fotografie prese di un contenuto, dalla più recente.
///
/// # Perché la verifica avviene qui e non a richiesta
///
/// Perché una fotografia che non si verifica va **detta**, e chi la legge non
/// deve ricordarsi di chiederlo. Ogni fotografia riletta porta con sé se sia
/// ancora quella che fu presa.
///
/// # Errori
///
/// Restituisce un errore se la lettura dell'archivio non riesce.
pub fn taken_of(
    database: &Database,
    content_id: ContentId,
) -> ServiceResult<Vec<VerifiedSnapshot>> {
    let fotografie = database.context_snapshots_of(content_id)?;
    Ok(fotografie
        .into_iter()
        .map(|fotografia| VerifiedSnapshot {
            intact: fotografia.verify(),
            snapshot: fotografia,
        })
        .collect())
}

/// Una fotografia riletta, con l'esito della sua verifica.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedSnapshot {
    /// La fotografia.
    pub snapshot: ContextSnapshot,
    /// Se l'impronta ricalcolata coincide con quella registrata.
    ///
    /// **Falso non accusa nessuno.** Un'impronta che non torna riconosce una
    /// differenza; non dice chi l'abbia introdotta né quando.
    pub intact: bool,
}

impl VerifiedSnapshot {
    /// Che cosa questa fotografia è, e se sia ancora quella che fu presa.
    #[must_use]
    pub fn as_sentence(&self) -> String {
        if self.intact {
            return self.snapshot.as_sentence();
        }
        format!(
            "{} L'impronta non corrisponde: questa copia non \u{e8} pi\u{f9} quella su cui \
             l'impronta fu calcolata. Non dice chi l'abbia alterata n\u{e9} quando: \
             un'impronta riconosce una differenza, non prova una responsabilit\u{e0}.",
            self.snapshot.as_sentence()
        )
    }
}

#[cfg(test)]
mod tests {
    use lisi_core::model::content_history::VersionChange;
    use lisi_core::model::context_state::{
        AcquiredText, ContextComparison, CurrentText, Divergence,
    };
    use lisi_core::model::{AcquisitionOrigin, NewSession, NewSource, SessionDuration, SourceKind};
    use lisi_core::text::{
        Actor, ContentBody, DisplayName, Note, RemoteMessageId, SourceIdentifier,
    };
    use lisi_core::{ContentId, Timestamp};
    use lisi_storage::Database;

    use crate::analysis::{AnalysisService, NewContentDraft};
    use crate::context::{
        AnchorMessage, AnchorPresence, ContextGap, MessageContext, ObservedMessage,
    };
    use crate::error::ServiceError;

    const ORA: i64 = 1_700_000_000_000;

    /// Questo modulo, per le guardie strutturali.
    const THIS_MODULE: &str = include_str!("context_snapshot.rs");

    /// Il servizio che **legge** il contesto: la sua guardia deve restare.
    const LETTURA: &str = include_str!("context.rs");

    fn operatore() -> Actor {
        let Ok(attore) = Actor::try_new("operatore.prova") else {
            panic!("l'attore di prova deve essere valido");
        };
        attore
    }

    fn ragione(testo: &str) -> Note {
        let Ok(nota) = Note::try_new(testo) else {
            panic!("la ragione di prova deve essere valida");
        };
        nota
    }

    /// Il codice di produzione senza i commenti.
    ///
    /// Rifiuta anche il codice messo **dopo** il blocco di prova: là sarebbe
    /// invisibile a ogni guardia di questo modulo (la lezione di LINK-01).
    fn codice_senza_commenti() -> String {
        let Some((produzione, prove)) = THIS_MODULE.split_once("#[cfg(test)]\nmod tests {") else {
            panic!("il modulo deve avere un blocco di prove riconoscibile");
        };
        for riga in prove.lines() {
            let e_codice = ["impl ", "fn ", "struct ", "enum ", "const ", "use ", "pub "]
                .iter()
                .any(|inizio| riga.starts_with(inizio));
            assert!(
                !e_codice,
                "c'e' del codice dopo il blocco di prove, invisibile a ogni guardia: «{riga}»"
            );
        }
        produzione
            .lines()
            .filter(|riga| !riga.trim_start().starts_with("//"))
            .collect::<Vec<_>>()
            .join("\n")
    }

    /// **Conservare non può osservare.**
    ///
    /// # La garanzia che questa prova sorveglia
    ///
    /// Che nessuna funzione di questo modulo riceva qualcosa con cui parlare a
    /// Telegram. Una fotografia deve contenere **soltanto** ciò che era già
    /// stato mostrato a una persona: se questo modulo potesse chiedere, potrebbe
    /// conservare ciò che nessuno ha visto — e sarebbe esattamente «scorrere la
    /// vista trasforma in prova ciò che si vede», dal lato opposto.
    #[test]
    fn conservare_non_puo_osservare() {
        let codice = codice_senza_commenti();
        for capacita in [
            "TelegramConnector",
            "connector",
            "fetch_context",
            "fetch_history",
        ] {
            assert!(
                !codice.contains(capacita),
                "il modulo che conserva nomina «{capacita}»: potrebbe conservare cio' che \
                 nessuno ha visto"
            );
        }
    }

    /// **La guardia di CTX-02 è rimasta dov'era.**
    ///
    /// # Perché questa prova esiste
    ///
    /// Perché la strada facile, arrivando a CTX-06, era togliere la guardia che
    /// vieta le scritture nel servizio del contesto — «adesso serve scrivere».
    /// Toglierla sarebbe stata la fine della regola.
    ///
    /// È rimasta, e sorveglia ancora ciò che sorvegliava: **leggere** un
    /// contesto non scrive. Scrivere è un altro modulo, e un altro atto.
    #[test]
    fn la_guardia_che_vieta_le_scritture_alla_lettura_e_rimasta() {
        assert!(
            LETTURA.contains("fn guardare_un_contesto_non_scrive_niente()"),
            "la guardia di CTX-02 deve restare dov'era: toglierla sarebbe la fine della regola"
        );

        // La ricerca si restringe alla PARTE DI PRODUZIONE: il blocco di prove
        // di `context.rs` nomina «&mut Database» perche' e' proprio la stringa
        // che la guardia di CTX-02 vieta, e cercarla in tutto il file
        // troverebbe la guardia stessa.
        let Some((produzione_della_lettura, _)) = LETTURA.split_once("#[cfg(test)]\nmod tests {")
        else {
            panic!("il servizio che legge deve avere un blocco di prove riconoscibile");
        };
        assert!(
            !produzione_della_lettura.contains("&mut Database"),
            "il servizio che legge un contesto non deve poter scrivere"
        );
    }

    /// **Non esiste una fotografia senza una ragione, e il servizio lo dice.**
    #[test]
    fn una_ragione_vuota_produce_una_frase_che_spiega() {
        let errore = crate::error::ServiceError::SnapshotNeedsReason;
        let frase = errore.operator_message();
        assert!(frase.contains("ragione"), "{frase}");
        assert!(
            frase.contains("chi") || frase.contains("risponde"),
            "la frase deve dire perche' serve \u{2014} {frase}"
        );
    }

    /// **La fonte si legge dall'archivio, non dal chiamante.**
    ///
    /// Una provenienza passata da fuori è una provenienza di cui ci si fida, e
    /// una provenienza sbagliata è peggio di una assente.
    #[test]
    fn la_fonte_si_legge_dall_archivio() {
        let codice = codice_senza_commenti();
        assert!(
            codice.contains("let content = database.content(context.anchor.content_id)?;"),
            "la fonte deve venire dall'archivio"
        );
        let Some(inizio) = codice.find("pub fn take(") else {
            panic!("la funzione deve esistere");
        };
        let Some(fine) = codice[inizio..].find(") -> ServiceResult<ContextSnapshotId> {") else {
            panic!("la firma deve chiudersi");
        };
        assert!(
            !codice[inizio..inizio + fine].contains("SourceId"),
            "la fonte non deve essere un parametro"
        );
    }

    /// **Prendere una fotografia lascia traccia nell'audit.**
    #[test]
    fn prendere_una_fotografia_si_registra() {
        let codice = codice_senza_commenti();
        assert!(
            codice.contains("append_audit("),
            "un atto di cui qualcuno risponde lascia traccia"
        );
        assert!(
            codice.contains("fotografia_contesto_presa"),
            "l'azione deve avere un nome stabile"
        );
    }

    /// **L'audit non porta il contenuto dei messaggi.**
    ///
    /// L'audit documenta le azioni, non i dati su cui esse insistono.
    #[test]
    fn l_audit_non_porta_i_testi() {
        let codice = codice_senza_commenti();
        let Some(inizio) = codice.find("database.append_audit(&NewAuditEntry {") else {
            panic!("l'audit deve esistere");
        };
        let Some(fine) = codice[inizio..].find("})?;") else {
            panic!("il blocco deve chiudersi");
        };
        let blocco = &codice[inizio..inizio + fine];
        for testo in [".body", ".text", "author_sentence", "relations_sentence"] {
            assert!(
                !blocco.contains(testo),
                "l'audit porta «{testo}»: documenta le azioni, non i dati"
            );
        }
    }

    /// **Una fotografia che non si verifica lo dichiara, e non accusa.**
    #[test]
    fn una_fotografia_alterata_lo_dichiara_senza_accusare() {
        let codice = codice_senza_commenti();
        assert!(
            codice.contains("L'impronta non corrisponde"),
            "una copia alterata deve dirlo"
        );
        for parola in ["manomes", "falsific", "colpevol", "responsabile di"] {
            assert!(
                !codice.to_lowercase().contains(parola),
                "la frase scrive «{parola}»: un'impronta riconosce una differenza, non prova \
                 una responsabilita'"
            );
        }
        // E la variante di `Divergence` resta quella del modello: qui non se ne
        // costruisce una seconda.
        let _ = Divergence::None;
    }

    /// Un archivio con un contenuto acquisito, e il suo identificativo.
    fn archivio_con_contenuto() -> (Database, ContentId) {
        let Ok(mut database) = crate::sources::open_in_memory_database() else {
            panic!("il database in memoria deve potersi aprire");
        };
        let (Ok(identifier), Ok(title), Ok(label)) = (
            SourceIdentifier::try_new("-1001"),
            DisplayName::try_new("Canale di prova"),
            DisplayName::try_new("Sessione di prova"),
        ) else {
            panic!("i valori di prova devono essere validi");
        };
        let Ok(source_id) = database.insert_source(
            &NewSource {
                kind: SourceKind::Channel,
                identifier,
                display_name: title,
                authorized_by: operatore(),
                active: true,
            },
            Timestamp::from_millis(ORA),
        ) else {
            panic!("la fonte deve potersi registrare");
        };
        let Ok(session_id) = database.insert_session(
            &NewSession {
                label,
                started_by: operatore(),
                duration: SessionDuration::Preset { seconds: 3_600 },
                source_ids: vec![source_id],
            },
            Timestamp::from_millis(ORA),
        ) else {
            panic!("la sessione deve potersi creare");
        };

        let (Ok(remote), Ok(body)) = (
            RemoteMessageId::try_new("500"),
            ContentBody::try_new("il testo acquisito"),
        ) else {
            panic!("i valori del contenuto devono essere validi");
        };

        let mut analysis = AnalysisService::new(database);
        let Ok(record) = analysis.analyse_and_record(
            &NewContentDraft {
                session_id,
                source_id,
                remote_message_id: remote,
                author: None,
                author_identifier: None,
                author_username: None,
                body,
                url: None,
                published_at: Timestamp::from_millis(ORA),
                acquired_at: Timestamp::from_millis(ORA),
                origin: AcquisitionOrigin::Observed,
            },
            &lisi_core::model::dictionary::ResolvedDictionaryConfiguration::from_terms(Vec::new()),
            &operatore(),
            Timestamp::from_millis(ORA),
        ) else {
            panic!("il contenuto deve potersi registrare");
        };
        let Some(content_id) = record.content_id else {
            panic!("il contenuto registrato deve avere un identificativo");
        };

        (analysis.into_database(), content_id)
    }

    /// Un contesto già letto, come la vista lo avrebbe mostrato.
    fn contesto_gia_visto(content_id: ContentId, testo_corrente: &str) -> MessageContext {
        MessageContext {
            anchor: AnchorMessage {
                content_id,
                remote_message_id: String::from("500"),
                body: String::from("il testo acquisito"),
                published_at: Timestamp::from_millis(ORA),
                acquired_at: Timestamp::from_millis(ORA),
            },
            surrounding: vec![
                ObservedMessage {
                    remote_message_id: String::from("499"),
                    text: String::from("prima"),
                    published_at: Timestamp::from_millis(ORA - 60_000),
                    is_anchor: false,
                    who: String::from("Scritto da qualcuno."),
                    relations: None,
                    declared_edit: None,
                    attachment_kind: None,
                },
                ObservedMessage {
                    remote_message_id: String::from("500"),
                    text: String::from(testo_corrente),
                    published_at: Timestamp::from_millis(ORA),
                    is_anchor: true,
                    who: String::from("Scritto da qualcun altro."),
                    relations: Some(String::from("In risposta al messaggio 499.")),
                    declared_edit: None,
                    attachment_kind: None,
                },
            ],
            observed_at: Timestamp::from_millis(ORA + 30_000),
            gap: None,
            anchor_presence: Some(AnchorPresence::Returned),
            comparison: Some(ContextComparison::between(
                AcquiredText::from_the_archive("il testo acquisito"),
                CurrentText::read_now(testo_corrente),
                Timestamp::from_millis(ORA),
                Timestamp::from_millis(ORA + 30_000),
                None,
            )),
        }
    }

    /// **Una fotografia conserva ciò che si vedeva, e si rilegge.**
    #[test]
    fn una_fotografia_conserva_cio_che_si_vedeva() {
        let (mut database, content_id) = archivio_con_contenuto();
        let contesto = contesto_gia_visto(content_id, "il testo acquisito");

        let Ok(id) = super::take(
            &mut database,
            &contesto,
            &operatore(),
            &ragione("serve al fascicolo 12/2026"),
            Timestamp::from_millis(ORA + 90_000),
        ) else {
            panic!("la fotografia deve potersi prendere");
        };
        assert!(id.get() > 0);

        let Ok(fotografie) = super::taken_of(&database, content_id) else {
            panic!("le fotografie devono potersi rileggere");
        };
        assert_eq!(fotografie.len(), 1);

        let riletta = &fotografie[0];
        assert!(riletta.intact, "una fotografia appena presa si verifica");
        assert_eq!(riletta.snapshot.taken_by.as_str(), "operatore.prova");
        assert_eq!(
            riletta.snapshot.reason.as_str(),
            "serve al fascicolo 12/2026"
        );
        assert_eq!(riletta.snapshot.messages.len(), 2);
        // L'ordine e' quello in cui furono visti: l'ordine e' il discorso.
        assert_eq!(riletta.snapshot.messages[0].remote_message_id, "499");
        assert_eq!(riletta.snapshot.messages[1].remote_message_id, "500");
        assert!(riletta.snapshot.messages[1].is_anchor);
        // Le frasi si conservano com'erano.
        assert_eq!(
            riletta.snapshot.messages[1].relations_sentence.as_deref(),
            Some("In risposta al messaggio 499.")
        );
        // I due istanti restano distinti.
        assert_eq!(riletta.snapshot.taken_at.as_millis(), ORA + 90_000);
        assert_eq!(riletta.snapshot.observed_at.as_millis(), ORA + 30_000);
    }

    /// **Il confronto si conserva come fu osservato.**
    #[test]
    fn il_confronto_si_conserva_come_fu_osservato() {
        let (mut database, content_id) = archivio_con_contenuto();
        let contesto = contesto_gia_visto(content_id, "il testo acquisito, e una coda");

        let Ok(_) = super::take(
            &mut database,
            &contesto,
            &operatore(),
            &ragione("il testo risulta diverso"),
            Timestamp::from_millis(ORA + 90_000),
        ) else {
            panic!("la fotografia deve potersi prendere");
        };

        let Ok(fotografie) = super::taken_of(&database, content_id) else {
            panic!("le fotografie devono potersi rileggere");
        };
        let Some(confronto) = fotografie[0].snapshot.comparison else {
            panic!("il confronto osservato deve essere conservato");
        };
        assert_eq!(confronto.change, VersionChange::Appended);
        assert_eq!(confronto.divergence, Divergence::Undeclared);
    }

    /// **Senza una ragione la fotografia non si prende.**
    #[test]
    fn senza_una_ragione_non_si_conserva_nulla() {
        let (mut database, content_id) = archivio_con_contenuto();
        let contesto = contesto_gia_visto(content_id, "il testo acquisito");

        let Ok(vuota) = Note::try_new("   ") else {
            // Se il tipo rifiuta gia' una nota di soli spazi, la protezione c'e'
            // un passo prima e va benissimo.
            let Ok(fotografie) = super::taken_of(&database, content_id) else {
                panic!("la lettura deve riuscire");
            };
            assert!(fotografie.is_empty());
            return;
        };

        let esito = super::take(
            &mut database,
            &contesto,
            &operatore(),
            &vuota,
            Timestamp::from_millis(ORA + 90_000),
        );
        assert!(
            matches!(esito, Err(ServiceError::SnapshotNeedsReason)),
            "una ragione fatta di spazi non e' una ragione"
        );

        // E NULLA E' STATO SCRITTO: un atto rifiutato non lascia meta' atto.
        let Ok(fotografie) = super::taken_of(&database, content_id) else {
            panic!("la lettura deve riuscire");
        };
        assert!(fotografie.is_empty());
    }

    /// **Prendere una fotografia lascia una voce nell'audit.**
    #[test]
    fn l_audit_registra_la_fotografia() {
        let (mut database, content_id) = archivio_con_contenuto();
        let contesto = contesto_gia_visto(content_id, "il testo acquisito");
        let Ok(_) = super::take(
            &mut database,
            &contesto,
            &operatore(),
            &ragione("una ragione"),
            Timestamp::from_millis(ORA + 90_000),
        ) else {
            panic!("la fotografia deve potersi prendere");
        };

        let Ok(voci) = database.audit_entries() else {
            panic!("l'audit deve potersi leggere");
        };
        let trovata = voci
            .iter()
            .any(|voce| voce.action.as_str() == "fotografia_contesto_presa");
        assert!(trovata, "l'atto deve comparire nell'audit");
    }

    /// **Due fotografie dello stesso contenuto convivono, dalla più recente.**
    ///
    /// Una fotografia non sostituisce la precedente: sono due osservazioni in
    /// due istanti, e la seconda non cancella ciò che si vedeva nella prima.
    #[test]
    fn due_fotografie_convivono_dalla_piu_recente() {
        let (mut database, content_id) = archivio_con_contenuto();

        let prima = contesto_gia_visto(content_id, "il testo acquisito");
        let Ok(_) = super::take(
            &mut database,
            &prima,
            &operatore(),
            &ragione("prima osservazione"),
            Timestamp::from_millis(ORA + 60_000),
        ) else {
            panic!("la prima fotografia deve potersi prendere");
        };

        let seconda = contesto_gia_visto(content_id, "il testo acquisito, riscritto");
        let Ok(_) = super::take(
            &mut database,
            &seconda,
            &operatore(),
            &ragione("seconda osservazione"),
            Timestamp::from_millis(ORA + 120_000),
        ) else {
            panic!("la seconda fotografia deve potersi prendere");
        };

        let Ok(fotografie) = super::taken_of(&database, content_id) else {
            panic!("le fotografie devono potersi rileggere");
        };
        assert_eq!(fotografie.len(), 2);
        assert_eq!(
            fotografie[0].snapshot.reason.as_str(),
            "seconda osservazione"
        );
        assert_eq!(fotografie[1].snapshot.reason.as_str(), "prima osservazione");
        // E la prima conserva ancora cio' che si vedeva allora.
        assert_eq!(
            fotografie[1].snapshot.messages[1].body,
            "il testo acquisito"
        );
    }

    /// **Una fotografia senza messaggi intorno si conferma con le sue parole**
    /// (SUBJECT-02, CA02-03).
    #[test]
    fn una_fotografia_vuota_si_conferma_con_le_sue_parole() {
        let piena = contesto_gia_visto(ContentId::new(1), "il testo acquisito");
        assert!(super::taken_sentence(&piena).starts_with("Contesto conservato. "));
        let mut vuota = piena.clone();
        vuota.surrounding.retain(|messaggio| messaggio.is_anchor);
        let frase = super::taken_sentence(&vuota);
        assert!(frase.contains("con 0 messaggi"), "{frase}");
        assert!(frase.contains("non ne ha restituiti"), "{frase}");
        vuota.surrounding.clear();
        assert!(super::taken_sentence(&vuota).contains("con 0 messaggi"));
    }

    /// Un contesto in cui Telegram **non è stato chiesto**, per quel motivo.
    fn contesto_non_chiesto(content_id: ContentId, lacuna: ContextGap) -> MessageContext {
        let mut contesto = contesto_gia_visto(content_id, "il testo acquisito");
        contesto.surrounding.clear();
        contesto.anchor_presence = None;
        contesto.comparison = None;
        contesto.gap = Some(lacuna);
        contesto
    }

    /// **Senza aver chiesto a Telegram, la fotografia non si prende**
    /// (COLLAUDO-FIX-01, CU01-013, DEC-508).
    ///
    /// Nel collaudo, in Esercitazione, la fotografia si prendeva e diceva che
    /// «in quel momento Telegram non ne ha restituiti»: Telegram non era stato
    /// chiesto. Un'osservazione che non è avvenuta non entra in un atto.
    #[test]
    fn senza_aver_chiesto_a_telegram_la_fotografia_non_si_prende() {
        for lacuna in [
            ContextGap::ConnectorUnavailable,
            ContextGap::RequestFailed,
            ContextGap::NotAddressable,
        ] {
            let (mut database, content_id) = archivio_con_contenuto();
            let esito = super::take(
                &mut database,
                &contesto_non_chiesto(content_id, lacuna),
                &operatore(),
                &ragione("serve al fascicolo 12/2026"),
                Timestamp::from_millis(ORA + 90_000),
            );
            let Err(errore) = esito else {
                panic!(
                    "{lacuna:?}: la fotografia si è presa, e direbbe che Telegram non ha \
                     restituito messaggi senza che gli si sia chiesto nulla (CU01-013)"
                );
            };
            assert!(
                matches!(errore, ServiceError::SnapshotWithoutAnswer),
                "{lacuna:?}: {errore:?}"
            );
            let frase = errore.operator_message();
            assert!(!frase.contains("non ne ha restituiti"), "{frase}");
            assert!(
                frase.contains("Telegram"),
                "la frase deve dire che cosa manca: {frase}"
            );

            // E NULLA E' STATO SCRITTO: né la fotografia né l'audit.
            let Ok(fotografie) = super::taken_of(&database, content_id) else {
                panic!("le fotografie devono potersi rileggere");
            };
            assert!(fotografie.is_empty(), "{lacuna:?}");
            let Ok(voci) = database.audit_entries() else {
                panic!("l'audit deve potersi leggere");
            };
            assert!(
                !voci
                    .iter()
                    .any(|voce| voce.action.as_str() == "fotografia_contesto_presa"),
                "{lacuna:?}: un atto rifiutato non lascia traccia di un atto"
            );
        }
    }

    /// **Quando Telegram è stato chiesto e non ha restituito nulla, la
    /// fotografia si prende ancora** (ADR-0166, CA02-03): è un'osservazione
    /// vera, e la conferma la dice con le sue parole.
    #[test]
    fn se_telegram_ha_risposto_vuoto_la_fotografia_si_prende() {
        let (mut database, content_id) = archivio_con_contenuto();
        let contesto = contesto_non_chiesto(content_id, ContextGap::NothingReturned);
        let Ok(_) = super::take(
            &mut database,
            &contesto,
            &operatore(),
            &ragione("serve al fascicolo 12/2026"),
            Timestamp::from_millis(ORA + 90_000),
        ) else {
            panic!("una risposta vuota di Telegram è un'osservazione, e si conserva");
        };
        assert!(super::taken_sentence(&contesto).contains("non ne ha restituiti"));
    }
}
