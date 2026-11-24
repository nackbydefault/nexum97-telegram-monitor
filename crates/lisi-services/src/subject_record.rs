//! Note, riferimenti e nomi osservati sulla scheda del soggetto
//! (NEXUM97-IDENTITY-02, ADR-0153, DG-08, F-136, GAP-13).
//!
//! # Tre cose, e tre origini
//!
//! - Le **note** e i **riferimenti** sono atti dell'operatore: chi, quando, e
//!   per un riferimento perché. Si ritirano con una ragione, non si cancellano.
//! - I **nomi osservati** sono osservazioni: si ricavano dai contenuti in cui
//!   un'identità collegata è comparsa, con le date e i monitoraggi. **Non sono
//!   identità**: non cambiano l'etichetta del soggetto, non collegano nulla, e
//!   la frase lo dice.
//!
//! # Che cosa non fa
//!
//! Non deduce nulla. Non apre soggetti, non collega identità, non attribuisce
//! un nome civile a un profilo.

use std::collections::BTreeMap;

use lisi_core::model::NewAuditEntry;
use lisi_core::model::reason::OperationalReason;
use lisi_core::text::{Actor, AuditAction, AuditEntity, Note};
use lisi_core::{PersonId, Timestamp};
use lisi_storage::Database;
pub use lisi_storage::repository::person_entry::EntryTarget;
use lisi_storage::repository::person_entry::{EntryWithdrawal, NewPersonEntry, StoredPersonEntry};

use crate::error::{ServiceError, ServiceResult};

/// L'azione d'audit di una voce scritta.
pub const ENTRY_AUDIT_ACTION: &str = "voce_soggetto";
/// L'azione d'audit di un ritiro.
pub const WITHDRAWAL_AUDIT_ACTION: &str = "ritiro_voce_soggetto";

/// Quante osservazioni di un'identità si leggono al più.
const MAX_SIGHTINGS: u32 = 5_000;

/// Una voce della scheda, come si mostra.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SubjectEntry {
    /// La voce registrata.
    pub stored: StoredPersonEntry,
}

impl SubjectEntry {
    /// Che cosa è, chi l'ha scritta, quando, e se è ritirata.
    #[must_use]
    pub fn as_sentence(&self) -> String {
        let voce = &self.stored.entry;
        let chi = format!(
            "{}, {}",
            voce.written_by,
            voce.written_at.to_readable_local()
        );
        let testo = match voce.target.as_ref() {
            None => format!("Nota di {chi}: \u{ab}{}\u{bb}", voce.body),
            Some(bersaglio) => format!(
                "Riferimento a {} aggiunto da {chi}, perch\u{e9}: \u{ab}{}\u{bb}",
                target_in_words(bersaglio),
                voce.body
            ),
        };
        match self.stored.withdrawal.as_ref() {
            None => testo,
            Some(ritiro) => format!(
                "{testo}. Ritirata da {}, {}, perch\u{e9}: \u{ab}{}\u{bb}",
                ritiro.by,
                ritiro.at.to_readable_local(),
                ritiro.reason
            ),
        }
    }

    /// Se la voce è ritirata.
    #[must_use]
    pub const fn is_withdrawn(&self) -> bool {
        self.stored.withdrawal.is_some()
    }

    /// Il contenuto dell'archivio a cui la voce rimanda, se rimanda a un
    /// contenuto: è l'ingresso alla conversazione da Persone (ADR-0165).
    #[must_use]
    pub const fn content_target(&self) -> Option<i64> {
        match self.stored.entry.target {
            Some(lisi_storage::repository::person_entry::EntryTarget::Content(numero)) => {
                Some(numero)
            }
            _ => None,
        }
    }
}

/// Il bersaglio di un riferimento dalla scelta della schermata: il genere da un
/// elenco chiuso (0 contenuto, 1 fonte, 2 rapporto, 3 documento esterno) e ciò
/// che è stato scritto. Un numero che non si legge non si indovina: `None`.
#[must_use]
pub fn target_from_choice(genere: i32, scritto: &str) -> Option<EntryTarget> {
    let scritto = scritto.trim();
    let numero = scritto.parse::<i64>().ok().filter(|numero| *numero > 0);
    match (genere, numero) {
        (0, Some(n)) => Some(EntryTarget::Content(n)),
        (1, Some(n)) => Some(EntryTarget::Source(n)),
        (2, Some(n)) => Some(EntryTarget::Report(n)),
        (3, _) if !scritto.is_empty() => Some(EntryTarget::Document(scritto.to_owned())),
        _ => None,
    }
}

/// Il bersaglio di un riferimento, a parole.
fn target_in_words(bersaglio: &EntryTarget) -> String {
    match bersaglio {
        EntryTarget::Content(id) => format!("contenuto n. {id}"),
        EntryTarget::Source(id) => format!("fonte n. {id}"),
        EntryTarget::Report(id) => format!("rapporto n. {id}"),
        EntryTarget::Document(testo) => format!("documento esterno \u{ab}{testo}\u{bb}"),
    }
}

/// Rifiuta se il soggetto non c'è o è chiuso: una scheda chiusa non riceve
/// voci nuove, come un raccoglitore chiuso.
fn open_subject(database: &Database, person: PersonId) -> ServiceResult<()> {
    let soggetto = database.person(person)?;
    if !soggetto.is_open() {
        return Err(ServiceError::SubjectEntryRefused {
            reason: String::from(
                "Il soggetto \u{e8} chiuso: la sua scheda non riceve voci nuove. Se il lavoro \
                 riprende, se ne apre uno nuovo.",
            ),
        });
    }
    Ok(())
}

fn audit(operator: &Actor, azione: &str, now: Timestamp) -> ServiceResult<NewAuditEntry> {
    Ok(NewAuditEntry {
        actor: operator.clone(),
        action: AuditAction::try_new(azione)?,
        entity: AuditEntity::try_new("soggetto")?,
        entity_id: None,
        actor_mode: None,
        // L'AUDIT NON PORTA IL TESTO: dice chi ha agito e quando, non che cosa
        // ha scritto su una persona.
        detail: None,
        recorded_at: now,
    })
}

/// Scrive una nota sul soggetto.
///
/// # Errori
///
/// Restituisce [`ServiceError::SubjectEntryRefused`] per un testo vuoto o
/// troppo lungo o per un soggetto chiuso; un errore se l'archivio non si
/// scrive.
pub fn write_note(
    database: &mut Database,
    person: PersonId,
    testo: &str,
    operator: &Actor,
    now: Timestamp,
) -> ServiceResult<i64> {
    // SPAZI SOLTANTO NON SONO UNA NOTA: si guarda il testo senza i bordi.
    if testo.trim().is_empty() {
        return Err(ServiceError::SubjectEntryRefused {
            reason: String::from(
                "Una nota vuota non si scrive. Una riga con autore e istante deve dire qualcosa.",
            ),
        });
    }
    let Ok(nota) = Note::try_new(testo.trim()) else {
        return Err(ServiceError::SubjectEntryRefused {
            reason: String::from("Una nota troppo lunga non si scrive: si scrivono due note."),
        });
    };
    open_subject(database, person)?;
    let voce = NewPersonEntry {
        person_id: person,
        body: nota.as_str().to_owned(),
        target: None,
        written_by: operator.as_str().to_owned(),
        written_at: now,
    };
    Ok(database.insert_person_entry(&voce, &audit(operator, ENTRY_AUDIT_ACTION, now)?)?)
}

/// Aggiunge un riferimento, con la sua ragione.
///
/// # Errori
///
/// Restituisce [`ServiceError::SubjectEntryRefused`] per un documento senza
/// indicazione o un soggetto chiuso; un errore se l'archivio non si scrive.
pub fn add_reference(
    database: &mut Database,
    person: PersonId,
    target: EntryTarget,
    reason: &OperationalReason,
    operator: &Actor,
    now: Timestamp,
) -> ServiceResult<i64> {
    if let EntryTarget::Document(testo) = &target
        && testo.trim().is_empty()
    {
        return Err(ServiceError::SubjectEntryRefused {
            reason: String::from(
                "Un documento esterno si indica: protocollo, atto, data. Senza indicazione il \
                 riferimento non porta a nulla.",
            ),
        });
    }
    if matches!(
        target,
        EntryTarget::Content(id) | EntryTarget::Source(id) | EntryTarget::Report(id) if id <= 0
    ) {
        return Err(ServiceError::SubjectEntryRefused {
            reason: String::from(
                "Il numero dell'archivio parte da uno: si legge accanto a ogni riga.",
            ),
        });
    }
    open_subject(database, person)?;
    let voce = NewPersonEntry {
        person_id: person,
        body: reason.as_str().to_owned(),
        target: Some(target),
        written_by: operator.as_str().to_owned(),
        written_at: now,
    };
    Ok(database.insert_person_entry(&voce, &audit(operator, ENTRY_AUDIT_ACTION, now)?)?)
}

/// Ritira una voce, con la sua ragione.
///
/// # Errori
///
/// Restituisce [`ServiceError::SubjectEntryRefused`] se la voce non esiste o è
/// già ritirata; un errore se l'archivio non si scrive.
pub fn withdraw(
    database: &mut Database,
    id: i64,
    reason: &OperationalReason,
    operator: &Actor,
    now: Timestamp,
) -> ServiceResult<()> {
    let ritiro = EntryWithdrawal {
        by: operator.as_str().to_owned(),
        at: now,
        reason: reason.as_str().to_owned(),
    };
    match database.withdraw_person_entry(
        id,
        &ritiro,
        &audit(operator, WITHDRAWAL_AUDIT_ACTION, now)?,
    ) {
        Ok(true) => Ok(()),
        Ok(false) => Err(ServiceError::SubjectEntryRefused {
            reason: String::from(
                "Questa voce non c'\u{e8} nell'archivio: non si \u{e8} ritirato nulla.",
            ),
        }),
        Err(_) => Err(ServiceError::SubjectEntryRefused {
            reason: String::from(
                "Questa voce \u{e8} gi\u{e0} ritirata. Un ritiro resta, e non si annulla.",
            ),
        }),
    }
}

/// Le voci di un soggetto, dalla più antica.
///
/// # Errori
///
/// Restituisce un errore se l'archivio non si legge.
pub fn entries(database: &Database, person: PersonId) -> ServiceResult<Vec<SubjectEntry>> {
    Ok(database
        .person_entries(person)?
        .into_iter()
        .map(|stored| SubjectEntry { stored })
        .collect())
}

/// Un soggetto a cui **una persona** ha collegato un identificativo (GAP-12).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinkedSubject {
    /// Quale soggetto.
    pub person: PersonId,
    /// Come l'ufficio lo chiama.
    pub label: String,
    /// Se la scheda è aperta.
    pub open: bool,
}

/// I soggetti a cui un identificativo è collegato **adesso**, per decisione di
/// una persona (PERS-06). In ordine di nome: nessun altro ordine, perché un
/// ordine diverso sarebbe un suggerimento.
///
/// **Non collega nulla e non suggerisce nulla**: se nessuno ha collegato
/// quell'identificativo, l'elenco è vuoto.
///
/// # Errori
///
/// Restituisce un errore se l'archivio non si legge.
pub fn subjects_linked_to(
    database: &Database,
    identifier: &str,
) -> ServiceResult<Vec<LinkedSubject>> {
    let cercato = identifier.trim();
    if cercato.is_empty() {
        return Ok(Vec::new());
    }
    let mut soggetti = Vec::new();
    for soggetto in database.persons()? {
        let storia = database.identity_link_history(soggetto.id)?;
        if lisi_core::model::identity_link::current_links(&storia)
            .iter()
            .any(|legame| legame.identifier == cercato)
        {
            soggetti.push(LinkedSubject {
                person: soggetto.id,
                label: soggetto.label.as_str().to_owned(),
                open: soggetto.is_open(),
            });
        }
    }
    soggetti.sort_by(|a, b| a.label.cmp(&b.label));
    Ok(soggetti)
}

/// Un nome o uno username con cui un'identità è comparsa nei contenuti.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObservedName {
    /// «nome» o «nome utente».
    pub kind: &'static str,
    /// Il valore, com'era.
    pub value: String,
    /// La prima volta.
    pub first_seen: Timestamp,
    /// L'ultima volta.
    pub last_seen: Timestamp,
    /// In quanti contenuti.
    pub contents: usize,
    /// In quali monitoraggi, per nome.
    pub sessions: Vec<String>,
}

impl ObservedName {
    /// La frase, che dice che è un'osservazione e non un'identità.
    #[must_use]
    pub fn as_sentence(&self) -> String {
        let quante = if self.contents == 1 {
            String::from("1 contenuto")
        } else {
            format!("{} contenuti", self.contents)
        };
        let valore = if self.kind == "nome utente" {
            format!("@{}", self.value)
        } else {
            format!("\u{ab}{}\u{bb}", self.value)
        };
        format!(
            "{} {valore}: osservato dal {} al {}, in {quante} (monitoraggi: {}). \u{c8} \
             un'osservazione, non un'identit\u{e0}.",
            if self.kind == "nome utente" {
                "Nome utente"
            } else {
                "Nome"
            },
            self.first_seen.to_readable_local(),
            self.last_seen.to_readable_local(),
            self.sessions.join(", ")
        )
    }
}

/// I nomi e gli username con cui un identificativo è comparso nei contenuti.
///
/// # Errori
///
/// Restituisce [`ServiceError::MissingParticipantBasis`] se la ragione degli
/// elenchi di persone non è registrata: i nomi osservati **sono** una storia
/// degli alias, e valgono le stesse condizioni (ADR-0024, PERS-02). Un errore
/// se l'archivio non si legge.
pub fn observed_names(database: &Database, identifier: &str) -> ServiceResult<Vec<ObservedName>> {
    if !database.operational_basis_recorded()? {
        return Err(ServiceError::MissingParticipantBasis);
    }
    let avvistamenti = database.author_sightings(identifier, MAX_SIGHTINGS)?;
    let mut per_valore: BTreeMap<(&'static str, String), ObservedName> = BTreeMap::new();
    for avvistamento in &avvistamenti {
        let valori = [
            ("nome", avvistamento.display_name.clone()),
            ("nome utente", avvistamento.username.clone()),
        ];
        for (genere, valore) in valori {
            let Some(valore) = valore.filter(|v| !v.trim().is_empty()) else {
                continue;
            };
            let voce = per_valore
                .entry((genere, valore.clone()))
                .or_insert_with(|| ObservedName {
                    kind: genere,
                    value: valore,
                    first_seen: avvistamento.published_at,
                    last_seen: avvistamento.published_at,
                    contents: 0,
                    sessions: Vec::new(),
                });
            voce.contents += 1;
            if avvistamento.published_at < voce.first_seen {
                voce.first_seen = avvistamento.published_at;
            }
            if avvistamento.published_at > voce.last_seen {
                voce.last_seen = avvistamento.published_at;
            }
            if !voce.sessions.contains(&avvistamento.session_label) {
                voce.sessions.push(avvistamento.session_label.clone());
            }
        }
    }
    let mut nomi: Vec<ObservedName> = per_valore.into_values().collect();
    nomi.sort_by(|a, b| a.first_seen.cmp(&b.first_seen).then(a.value.cmp(&b.value)));
    Ok(nomi)
}

#[cfg(test)]
mod tests {
    use lisi_core::model::reason::OperationalReason;
    use lisi_core::model::{AcquisitionOrigin, NewSession, NewSource, SessionDuration, SourceKind};
    use lisi_core::text::{Actor, ContentBody, DisplayName, RemoteMessageId, SourceIdentifier};
    use lisi_core::{PersonId, Timestamp};
    use lisi_storage::Database;
    use lisi_storage::repository::person_entry::EntryTarget;

    use super::{add_reference, entries, observed_names, withdraw, write_note};
    use crate::analysis::{AnalysisService, NewContentDraft};
    use crate::error::ServiceError;

    fn operatore() -> Actor {
        let Ok(attore) = Actor::try_new("operatore.prova") else {
            panic!("attore valido");
        };
        attore
    }

    fn ragione(testo: &str) -> OperationalReason {
        let Ok(ragione) = OperationalReason::try_new(testo) else {
            panic!("ragione valida");
        };
        ragione
    }

    fn con_soggetto() -> (Database, PersonId) {
        let Ok(archivio) = crate::sources::open_in_memory_database() else {
            panic!("archivio in memoria");
        };
        let Ok(label) = DisplayName::try_new("Soggetto A") else {
            panic!("etichetta valida");
        };
        let Ok(id) = archivio.insert_person(
            &lisi_core::model::person::NewPerson::open(
                label,
                ragione("richiesta dell'autorita' procedente"),
            ),
            &operatore(),
            Timestamp::from_millis(1),
        ) else {
            panic!("il soggetto deve aprirsi");
        };
        (archivio, id)
    }

    /// **Note e riferimenti con chi, quando, perché; il ritiro resta** (B2, B3).
    #[test]
    fn note_e_riferimenti_con_chi_quando_e_perche() {
        let (mut archivio, soggetto) = con_soggetto();
        let Ok(_) = write_note(
            &mut archivio,
            soggetto,
            "Firma i messaggi con la stessa sigla.",
            &operatore(),
            Timestamp::from_millis(2),
        ) else {
            panic!("la nota deve scriversi");
        };
        let Ok(riferimento) = add_reference(
            &mut archivio,
            soggetto,
            EntryTarget::Document(String::from("prot. 1234/2026")),
            &ragione("segnalazione dell'ufficio territoriale"),
            &operatore(),
            Timestamp::from_millis(3),
        ) else {
            panic!("il riferimento deve aggiungersi");
        };
        let Ok(()) = withdraw(
            &mut archivio,
            riferimento,
            &ragione("protocollo riportato per errore"),
            &operatore(),
            Timestamp::from_millis(4),
        ) else {
            panic!("il ritiro deve riuscire");
        };
        let Ok(voci) = entries(&archivio, soggetto) else {
            panic!("le voci devono leggersi");
        };
        assert_eq!(voci.len(), 2);
        assert!(voci[0].as_sentence().starts_with("Nota di operatore.prova"));
        assert!(voci[1].is_withdrawn());
        assert!(
            voci[1]
                .as_sentence()
                .contains("documento esterno \u{ab}prot. 1234/2026\u{bb}")
        );
        assert!(
            voci[1]
                .as_sentence()
                .contains("Ritirata da operatore.prova")
        );

        // Un secondo ritiro non riesce, e lo dice.
        assert!(matches!(
            withdraw(
                &mut archivio,
                riferimento,
                &ragione("protocollo riportato per errore"),
                &operatore(),
                Timestamp::from_millis(5),
            ),
            Err(ServiceError::SubjectEntryRefused { .. })
        ));
        // Una nota vuota non si scrive.
        assert!(matches!(
            write_note(
                &mut archivio,
                soggetto,
                "   ",
                &operatore(),
                Timestamp::from_millis(6)
            ),
            Err(ServiceError::SubjectEntryRefused { .. })
        ));
    }

    /// **La scelta della schermata non si indovina** (B3): un numero che non si
    /// legge, o un documento senza indicazione, non diventano un riferimento.
    #[test]
    fn la_scelta_della_schermata_non_si_indovina() {
        use super::target_from_choice;
        assert_eq!(
            target_from_choice(0, " 12 "),
            Some(EntryTarget::Content(12))
        );
        assert_eq!(target_from_choice(2, "7"), Some(EntryTarget::Report(7)));
        assert_eq!(
            target_from_choice(3, "prot. 9/2026"),
            Some(EntryTarget::Document(String::from("prot. 9/2026")))
        );
        for (genere, scritto) in [
            (0, "dodici"),
            (1, "0"),
            (1, "-3"),
            (3, "  "),
            (4, "5"),
            (-1, "5"),
        ] {
            assert_eq!(
                target_from_choice(genere, scritto),
                None,
                "({genere}, «{scritto}») non e' un riferimento"
            );
        }
    }

    /// **Dall'autore al soggetto, solo per decisione di una persona** (C1).
    ///
    /// Un identificativo mai collegato non porta a nessuna scheda; collegato,
    /// porta alla sua; sciolto, non porta più.
    #[test]
    fn dall_autore_al_soggetto_solo_se_qualcuno_lo_ha_collegato() {
        use lisi_core::model::identity_link::{LinkAct, NewIdentityLink};

        use super::subjects_linked_to;

        let (archivio, soggetto) = con_soggetto();
        let Ok(nessuno) = subjects_linked_to(&archivio, "4242") else {
            panic!("la lettura deve riuscire");
        };
        assert!(nessuno.is_empty(), "nessun suggerimento senza un legame");

        let atto = |act, quando| NewIdentityLink {
            person: soggetto,
            identifier: String::from("4242"),
            act,
            reason: ragione("riscontro documentale con gli atti"),
            by: operatore(),
            at: Timestamp::from_millis(quando),
            resolution: None,
        };
        let Ok(_) = archivio.insert_identity_link(&atto(LinkAct::Link, 10)) else {
            panic!("il legame deve registrarsi");
        };
        let Ok(collegati) = subjects_linked_to(&archivio, " 4242 ") else {
            panic!("la lettura deve riuscire");
        };
        assert_eq!(collegati.len(), 1);
        assert_eq!(collegati[0].person, soggetto);
        assert_eq!(collegati[0].label, "Soggetto A");

        let Ok(_) = archivio.insert_identity_link(&atto(LinkAct::Unlink, 20)) else {
            panic!("lo scioglimento deve registrarsi");
        };
        let Ok(sciolti) = subjects_linked_to(&archivio, "4242") else {
            panic!("la lettura deve riuscire");
        };
        assert!(
            sciolti.is_empty(),
            "un legame sciolto non porta più alla scheda"
        );
        assert!(matches!(subjects_linked_to(&archivio, "  "), Ok(v) if v.is_empty()));
    }

    /// **Un soggetto chiuso non riceve voci nuove.**
    #[test]
    fn un_soggetto_chiuso_non_riceve_voci() {
        let (mut archivio, soggetto) = con_soggetto();
        let Ok(()) = archivio.close_person(
            soggetto,
            &operatore(),
            &ragione("il procedimento si e' concluso"),
            Timestamp::from_millis(2),
        ) else {
            panic!("il soggetto deve chiudersi");
        };
        assert!(matches!(
            write_note(
                &mut archivio,
                soggetto,
                "nota",
                &operatore(),
                Timestamp::from_millis(3)
            ),
            Err(ServiceError::SubjectEntryRefused { .. })
        ));
    }

    /// **I nomi osservati vengono dai contenuti, e non sono identità** (B4).
    #[test]
    fn i_nomi_osservati_vengono_dai_contenuti() {
        let (mut archivio, soggetto) = con_soggetto();
        // Senza la ragione degli elenchi di persone, nulla.
        assert!(matches!(
            observed_names(&archivio, "4242"),
            Err(ServiceError::MissingParticipantBasis)
        ));
        let (Ok(azione), Ok(entita), Ok(dettaglio)) = (
            lisi_core::text::AuditAction::try_new("elenco_persone_motivato"),
            lisi_core::text::AuditEntity::try_new("session"),
            lisi_core::text::AuditDetail::try_new("verifica disposta dall'autorita' procedente"),
        ) else {
            panic!("valori d'audit validi");
        };
        let Ok(_) = archivio.append_audit(&lisi_core::model::NewAuditEntry {
            actor: operatore(),
            action: azione,
            entity: entita,
            entity_id: None,
            actor_mode: None,
            detail: Some(dettaglio),
            recorded_at: Timestamp::from_millis(1),
        }) else {
            panic!("la ragione deve registrarsi");
        };

        let (Ok(identifier), Ok(title), Ok(label)) = (
            SourceIdentifier::try_new("-1001"),
            DisplayName::try_new("Canale"),
            DisplayName::try_new("Monitoraggio Alfa"),
        ) else {
            panic!("valori validi");
        };
        let Ok(fonte) = archivio.insert_source(
            &NewSource {
                kind: SourceKind::Supergroup,
                identifier,
                display_name: title,
                authorized_by: operatore(),
                active: true,
            },
            Timestamp::from_millis(1),
        ) else {
            panic!("la fonte deve registrarsi");
        };
        let Ok(sessione) = archivio.insert_session(
            &NewSession {
                label,
                started_by: operatore(),
                duration: SessionDuration::Preset { seconds: 3_600 },
                source_ids: vec![fonte],
            },
            Timestamp::from_millis(1),
        ) else {
            panic!("la sessione deve crearsi");
        };
        let mut analisi = AnalysisService::new(archivio);
        for (numero, nome, quando) in [(1, "Mario", 10), (2, "Mario R.", 20), (3, "Mario", 30)] {
            let (Ok(remoto), Ok(corpo), Ok(autore)) = (
                RemoteMessageId::try_new(&numero.to_string()),
                ContentBody::try_new("testo"),
                Actor::try_new(nome),
            ) else {
                panic!("valori validi");
            };
            let Ok(_) = analisi.analyse_and_record(
                &NewContentDraft {
                    session_id: sessione,
                    source_id: fonte,
                    remote_message_id: remoto,
                    author: Some(autore),
                    author_identifier: Some(String::from("4242")),
                    author_username: Some(String::from("mrossi")),
                    body: corpo,
                    url: None,
                    published_at: Timestamp::from_millis(quando),
                    acquired_at: Timestamp::from_millis(quando),
                    origin: AcquisitionOrigin::Observed,
                },
                &lisi_core::model::dictionary::ResolvedDictionaryConfiguration::from_terms(
                    Vec::new(),
                ),
                &operatore(),
                Timestamp::from_millis(quando),
            ) else {
                panic!("il contenuto deve registrarsi");
            };
        }
        let archivio = analisi.into_database();
        let Ok(nomi) = observed_names(&archivio, "4242") else {
            panic!("i nomi osservati devono comporsi");
        };
        let valori: Vec<(&str, &str, usize)> = nomi
            .iter()
            .map(|n| (n.kind, n.value.as_str(), n.contents))
            .collect();
        assert_eq!(
            valori,
            vec![
                ("nome", "Mario", 2),
                ("nome utente", "mrossi", 3),
                ("nome", "Mario R.", 1)
            ]
        );
        assert!(nomi[0].as_sentence().contains("non un'identit\u{e0}"));
        assert!(nomi[0].as_sentence().contains("Monitoraggio Alfa"));
        // L'ETICHETTA DEL SOGGETTO NON CAMBIA, e nessun legame nasce.
        let Ok(dopo) = archivio.person(soggetto) else {
            panic!("il soggetto deve leggersi");
        };
        assert_eq!(dopo.label.as_str(), "Soggetto A");
        let Ok(legami) = archivio.identity_link_history(soggetto) else {
            panic!("i legami devono leggersi");
        };
        assert!(legami.is_empty(), "un nome osservato non collega nulla");
    }
}
