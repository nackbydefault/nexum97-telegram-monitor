//! Il passaggio di consegne (PR-12, ADR-0128).
//!
//! # Sei sezioni, sempre
//!
//! Che cosa si guardava, che cosa è arrivato, che cosa è stato deciso, che cosa
//! resta aperto, che cosa è andato storto, da dove cominciare. **Sempre sei**, e
//! una sezione vuota lo dice: una sezione assente è indistinguibile da una
//! vuota, e la differenza conta.
//!
//! # Composto da fatti, e nient'altro
//!
//! Nessun riassunto generativo, nessuna raccomandazione investigativa (ADR-0048).
//! Ogni riga dice chi l'afferma (PR-03): i conteggi sono **Calcolato**, le
//! decisioni **Operatore**, con i nomi di chi le ha prese. «Da dove cominciare»
//! è l'ordine della coda di lavoro, un confronto fra fatti registrati, e il
//! criterio si dichiara.
//!
//! # Non più della somma delle schermate
//!
//! Nessun corpo di messaggio e **nessun soggetto nominato**: l'elenco delle
//! persone si vede soltanto con una ragione registrata (ADR-0024), e un foglio
//! di consegna non la aggira. Delle valutazioni e dei legami si dice quanti e da
//! chi, mai di chi; delle ricerche puntuali, quante, mai che cosa.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use lisi_core::Timestamp;
use lisi_core::model::origin::Origin;
use lisi_core::model::{NewAuditEntry, Session};
use lisi_core::text::{Actor, AuditAction, AuditDetail, AuditEntity};
use lisi_storage::Database;

use crate::error::{ServiceError, ServiceResult};
use crate::protected_output::{Delivery, Existing, REFUSED_AUDIT_ACTION, record_refusal};
use crate::report_narrative::{Block, Letterhead, NarrativeReport};
use crate::work_queue::WorkQueueService;

/// Ciò che si dice quando il foglio non si scrive per i permessi.
const HANDOVER_NOT_WRITTEN: &str = "Il passaggio di consegne NON è stato scritto";

/// Le durate che si possono chiedere, in ore, fino a adesso.
pub const HANDOVER_SPANS_HOURS: [i64; 3] = [8, 24, 24 * 7];

/// Quanti elementi della coda si propongono come punto di partenza.
pub const START_ITEMS: usize = 5;

/// Quanti contenuti per interrogazione, contando le assegnazioni.
const ASSIGNMENT_CHUNK: usize = 500;

/// La frase di una sezione senza nulla da dire.
pub const EMPTY_SECTION: &str = "Nulla da segnalare in questo intervallo.";

/// Il criterio di «Da dove cominciare», dichiarato.
pub const START_CRITERION: &str = "L'ordine è quello della coda di lavoro. Prima ciò che nessuno \
     ha mai esaminato, poi il livello più alto. Poi ciò che sta in un grappolo, poi il più vecchio. \
     È un confronto fra fatti registrati, non un giudizio.";

/// Che cosa il foglio non è.
pub const NOT_A_RECOMMENDATION: &str = "Questo foglio è composto da fatti registrati. Non \
     raccomanda indagini e non dice chi sia sospetto: dice che cosa è successo e dove riprendere.";

/// La nota di una postazione che segue un Hub.
pub const TEAM_NOTE: &str = "Questo è il riepilogo di questa postazione. Quello dell'ufficio lo \
     compone l'Hub, che ha i fatti di tutti.";

/// L'azione d'audit di un'esportazione.
pub const HANDOVER_AUDIT_ACTION: &str = "passaggio_di_consegne_esportato";

/// I titoli delle sei sezioni, nell'ordine.
pub const SECTION_TITLES: [&str; 6] = [
    "1. Che cosa si guardava",
    "2. Che cosa è arrivato",
    "3. Che cosa è stato deciso",
    "4. Che cosa resta aperto",
    "5. Che cosa è andato storto",
    "6. Da dove cominciare",
];

/// Le decisioni che il foglio conta: l'azione d'audit e come si dice, al
/// singolare e al plurale (UX-EXCELLENCE-02, SIM3-17: «1 revisioni registrate»).
const DECISIONS: [(&str, &str, &str); 13] = [
    (
        "revisione_registrata",
        "revisione registrata",
        "revisioni registrate",
    ),
    (
        "soggetto_valutato",
        "valutazione di un soggetto",
        "valutazioni di soggetti",
    ),
    (
        "identita_associata",
        "atto sui legami fra identità e soggetti",
        "atti sui legami fra identità e soggetti",
    ),
    (
        "versione_pubblicata",
        "pubblicazione di dizionario",
        "pubblicazioni di dizionario",
    ),
    (
        "periodo_non_coperto_deciso",
        "decisione su un periodo non coperto",
        "decisioni su periodi non coperti",
    ),
    (
        "recupero_archiviato",
        "recupero dall'inizio del monitoraggio",
        "recuperi dall'inizio del monitoraggio",
    ),
    (
        "recupero_per_intervallo_archiviato",
        "recupero di un periodo",
        "recuperi di periodi",
    ),
    (
        "storico_precedente_archiviato",
        "storico precedente all'avvio",
        "storici precedenti all'avvio",
    ),
    (
        "pacchetto_di_evidenze_prodotto",
        "pacchetto di evidenze uscito",
        "pacchetti di evidenze usciti",
    ),
    ("nota_scritta", "nota scritta", "note scritte"),
    (
        "decisione_candidato",
        "decisione su una fonte candidata",
        "decisioni su fonti candidate",
    ),
    ("soggetto_aperto", "fascicolo aperto", "fascicoli aperti"),
    ("ricerca_puntuale", "ricerca puntuale", "ricerche puntuali"),
];

/// Un conteggio con la parola concordata: «1 guasto registrato», «3 guasti
/// registrati» (UX-EXCELLENCE-02, SIM3-17). Lo zero non arriva qui: le righe
/// con conteggio nullo non si scrivono.
fn quanti(numero: usize, singolare: &str, plurale: &str) -> String {
    if numero == 1 {
        format!("1 {singolare}")
    } else {
        format!("{numero} {plurale}")
    }
}

/// Una riga del foglio, con chi l'afferma.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HandoverLine {
    /// Il testo.
    pub text: String,
    /// Chi l'afferma (PR-03).
    pub origin: Origin,
}

impl HandoverLine {
    fn calcolato(text: String) -> Self {
        Self {
            text,
            origin: Origin::Computed,
        }
    }

    fn operatore(text: String) -> Self {
        Self {
            text,
            origin: Origin::Operator,
        }
    }

    /// La riga con l'origine accanto.
    #[must_use]
    pub fn as_sentence(&self) -> String {
        format!("{} [{}]", self.text, self.origin.label())
    }
}

/// Una sezione: il titolo e le righe. **Mai assente**; vuota, lo dice.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HandoverSection {
    /// Il titolo, fra i sei.
    pub title: &'static str,
    /// Le righe, eventualmente nessuna.
    pub lines: Vec<HandoverLine>,
}

impl HandoverSection {
    /// Le righe da mostrare: quelle della sezione, o la frase della sezione
    /// vuota.
    #[must_use]
    pub fn shown_lines(&self) -> Vec<String> {
        if self.lines.is_empty() {
            return vec![String::from(EMPTY_SECTION)];
        }
        self.lines.iter().map(HandoverLine::as_sentence).collect()
    }
}

/// Il passaggio di consegne di un intervallo.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Handover {
    /// Da quando.
    pub from: Timestamp,
    /// Fino a quando: l'istante in cui si compone.
    pub until: Timestamp,
    /// Le sei sezioni, sempre, nell'ordine.
    pub sections: [HandoverSection; 6],
}

impl Handover {
    /// Il foglio in testo, per lo schermo e per il file.
    #[must_use]
    pub fn as_text(&self, in_team: bool) -> String {
        let mut testo = format!(
            "NEXUM/97 — passaggio di consegne\n\
             Ideazione e progettazione: Giuseppe LISI\n\n\
             Dal {} al {}.\n{NOT_A_RECOMMENDATION}\n",
            self.from.to_readable_local(),
            self.until.to_readable_local()
        );
        if in_team {
            testo.push_str(TEAM_NOTE);
            testo.push('\n');
        }
        for sezione in &self.sections {
            testo.push('\n');
            testo.push_str(sezione.title);
            testo.push('\n');
            for riga in sezione.shown_lines() {
                testo.push_str("- ");
                testo.push_str(&riga);
                testo.push('\n');
            }
        }
        testo
    }

    /// Il foglio come documento Word, con la stessa composizione.
    #[must_use]
    pub fn as_report(&self, in_team: bool, generated_at: Timestamp) -> NarrativeReport {
        let mut blocchi = vec![
            Block::Heading(String::from("Passaggio di consegne")),
            Block::Paragraph(format!(
                "Dal {} al {}.",
                self.from.to_readable_local(),
                self.until.to_readable_local()
            )),
            Block::Paragraph(String::from(NOT_A_RECOMMENDATION)),
        ];
        if in_team {
            blocchi.push(Block::Paragraph(String::from(TEAM_NOTE)));
        }
        for sezione in &self.sections {
            blocchi.push(Block::Heading(String::from(sezione.title)));
            for riga in sezione.shown_lines() {
                blocchi.push(Block::Paragraph(riga));
            }
        }
        NarrativeReport {
            generated_at,
            letterhead: Letterhead {
                emblem: None,
                lines: Vec::new(),
            },
            footer: Vec::new(),
            blocks: blocchi,
        }
    }
}

/// Il servizio: la coda di lavoro e il suo archivio.
#[derive(Debug)]
pub struct HandoverService {
    queue: WorkQueueService,
}

impl HandoverService {
    /// Costruisce il servizio sull'archivio indicato.
    #[must_use]
    pub const fn new(database: Database) -> Self {
        Self {
            queue: WorkQueueService::new(database),
        }
    }

    fn database(&self) -> &Database {
        self.queue.database()
    }

    /// La cartella dei documenti dell'ufficio, in cui escono i fogli.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se la cartella non è determinabile.
    pub fn destination(&self) -> ServiceResult<PathBuf> {
        crate::export::resolved_destination(self.database())
    }

    /// Compone il foglio delle ultime `ore` ore, fino a `now`. **Legge
    /// soltanto**, e a parità di archivio e di istante dà lo stesso foglio.
    ///
    /// # Errori
    ///
    /// Restituisce un errore per una durata non dichiarata, o se una lettura non
    /// riesce.
    pub fn compose(&self, ore: i64, now: Timestamp) -> ServiceResult<Handover> {
        if !HANDOVER_SPANS_HOURS.contains(&ore) {
            return Err(ServiceError::ExportNotWritten {
                reason: String::from(
                    "la durata del passaggio di consegne non è fra quelle dichiarate",
                ),
            });
        }
        let from = now.plus_seconds(-ore * 3_600);
        let coda = self.queue.compose(now)?;
        let in_corso = self.running()?;
        Ok(Handover {
            from,
            until: now,
            sections: [
                HandoverSection {
                    title: SECTION_TITLES[0],
                    lines: self.watched(from, now)?,
                },
                HandoverSection {
                    title: SECTION_TITLES[1],
                    lines: self.arrived(from, now, &coda)?,
                },
                HandoverSection {
                    title: SECTION_TITLES[2],
                    lines: self.decided(from, now)?,
                },
                HandoverSection {
                    title: SECTION_TITLES[3],
                    lines: self.still_open(now, &coda, &in_corso)?,
                },
                HandoverSection {
                    title: SECTION_TITLES[4],
                    lines: self.went_wrong(from, now)?,
                },
                HandoverSection {
                    title: SECTION_TITLES[5],
                    lines: start_here(&coda, &in_corso, now),
                },
            ],
        })
    }

    /// Sezione 1, che cosa si guardava: la copertura delle fonti, e i periodi
    /// prioritari dell'intervallo.
    fn watched(&self, from: Timestamp, until: Timestamp) -> ServiceResult<Vec<HandoverLine>> {
        let mut righe = Vec::new();
        for fonte in crate::coverage::for_sources(self.database(), from, until)? {
            righe.push(HandoverLine::calcolato(format!(
                "«{}»: {}",
                fonte.name,
                crate::coverage::totals_in_words(&fonte.coverage)
            )));
        }
        let periodi = crate::gap::assess(self.database(), until)?;
        let nell_intervallo: Vec<_> = periodi
            .listed
            .iter()
            .filter(|periodo| periodo.to > from && periodo.from < until)
            .collect();
        if !nell_intervallo.is_empty() {
            righe.push(HandoverLine::calcolato(format!(
                "{} nell'intervallo. La priorità è tecnica: non dice che nel periodo la fonte \
                 abbia pubblicato qualcosa.",
                quanti(
                    nell_intervallo.len(),
                    "periodo non coperto prioritario",
                    "periodi non coperti prioritari"
                )
            )));
        }
        Ok(righe)
    }

    /// Sezione 2, che cosa è arrivato: contenuti per fonte, con avviso, in un
    /// grappolo.
    fn arrived(
        &self,
        from: Timestamp,
        until: Timestamp,
        coda: &crate::work_queue::WorkQueue,
    ) -> ServiceResult<Vec<HandoverLine>> {
        let mut per_fonte: BTreeMap<String, (usize, usize)> = BTreeMap::new();
        for sessione in self.database().sessions()? {
            for contenuto in self.database().session_contents(sessione.id)? {
                if contenuto.acquired_at < from || contenuto.acquired_at >= until {
                    continue;
                }
                let nome = self.database().source(contenuto.source_id).map_or_else(
                    |_| String::from("fonte non più disponibile"),
                    |fonte| fonte.display_name.as_str().to_owned(),
                );
                let voce = per_fonte.entry(nome).or_default();
                voce.0 += 1;
                if contenuto.analysis_level.get() > 0 {
                    voce.1 += 1;
                }
            }
        }
        let mut righe: Vec<HandoverLine> = per_fonte
            .into_iter()
            .map(|(nome, (tutti, con_avviso))| {
                // Concordato col numero (BUG-UX-1: «1 contenuti acquisiti»).
                HandoverLine::calcolato(format!(
                    "«{nome}»: {}, {con_avviso} con avviso.",
                    lisi_core::text::counted(tutti, "contenuto acquisito", "contenuti acquisiti")
                ))
            })
            .collect();
        let in_grappolo = coda
            .items
            .iter()
            .filter(|elemento| {
                elemento.in_cyber_event && elemento.raised_at >= from && elemento.raised_at < until
            })
            .count();
        if in_grappolo > 0 {
            righe.push(HandoverLine::calcolato(format!(
                "{} nell'intervallo in un gruppo di segnali cyber.",
                quanti(
                    in_grappolo,
                    "contenuto arrivato sta",
                    "contenuti arrivati stanno"
                )
            )));
        }
        Ok(righe)
    }

    /// Sezione 3, che cosa è stato deciso: quante decisioni, e da chi. **Mai di chi.**
    fn decided(&self, from: Timestamp, until: Timestamp) -> ServiceResult<Vec<HandoverLine>> {
        let mut conteggi: BTreeMap<&'static str, (usize, BTreeSet<String>)> = BTreeMap::new();
        for voce in self.database().audit_entries()? {
            if voce.recorded_at < from || voce.recorded_at >= until {
                continue;
            }
            let Some((_, _, detto)) = DECISIONS
                .iter()
                .find(|(azione, _, _)| *azione == voce.action.as_str())
            else {
                continue;
            };
            let conteggio = conteggi.entry(detto).or_default();
            conteggio.0 += 1;
            conteggio.1.insert(voce.actor.as_str().to_owned());
        }
        Ok(DECISIONS
            .iter()
            .filter_map(|(_, uno, detto)| {
                let (quante, chi) = conteggi.get(detto)?;
                let detto = if *quante == 1 { uno } else { detto };
                Some(HandoverLine::operatore(format!(
                    "{quante} {detto}, da {}.",
                    chi.iter().cloned().collect::<Vec<_>>().join(", ")
                )))
            })
            .collect())
    }

    /// I monitoraggi che l'archivio registra come ancora aperti.
    ///
    /// «In corso» è lo stato registrato, non la prova che si stia acquisendo:
    /// dopo un riavvio l'account può essere scollegato (F-04). Il foglio lo
    /// dice con queste parole, e rimanda al Cruscotto.
    fn running(&self) -> ServiceResult<Vec<Session>> {
        Ok(self
            .database()
            .sessions()?
            .into_iter()
            .filter(|sessione| !sessione.state.is_final() && sessione.started_at.is_some())
            .collect())
    }

    /// Sezione 4, che cosa resta aperto: per primo il monitoraggio ancora in
    /// corso, che chi arriva deve seguire (F-19).
    fn still_open(
        &self,
        now: Timestamp,
        coda: &crate::work_queue::WorkQueue,
        in_corso: &[Session],
    ) -> ServiceResult<Vec<HandoverLine>> {
        let mut righe: Vec<HandoverLine> = in_corso.iter().map(open_monitoring).collect();
        if !coda.items.is_empty() {
            righe.push(HandoverLine::calcolato(format!(
                "Coda di lavoro: {}",
                coda.as_sentence()
            )));
        }
        // Le assegnazioni vivono sull'Hub (ADR-0098): su una postazione sola
        // il conto è zero e la riga non c'è. A blocchi, perché la coda non ha
        // un tetto e i segnaposto di SQLite sì.
        let identificativi: Vec<_> = coda
            .items
            .iter()
            .map(|elemento| elemento.content_id)
            .collect();
        let mut assegnati = 0;
        for blocco in identificativi.chunks(ASSIGNMENT_CHUNK) {
            assegnati += self.database().hub_assignments_of(blocco)?.len();
        }
        if assegnati > 0 {
            righe.push(HandoverLine::operatore(format!(
                "{} a una persona dell'ufficio.",
                quanti(
                    assegnati,
                    "elemento della coda è già assegnato",
                    "elementi della coda sono già assegnati"
                )
            )));
        }
        let periodi = crate::gap::assess(self.database(), now)?;
        if !periodi.listed.is_empty() {
            righe.push(HandoverLine::calcolato(format!(
                "{} ancora da decidere. La priorità è tecnica: non dice che nel periodo la \
                 fonte abbia pubblicato qualcosa.",
                quanti(
                    periodi.listed.len(),
                    "periodo non coperto prioritario",
                    "periodi non coperti prioritari"
                )
            )));
        }
        let da_recuperare = crate::interval_recovery::candidates(self.database(), now)?
            .iter()
            .filter(|candidato| candidato.target.is_ok() && candidato.done.is_empty())
            .count();
        if da_recuperare > 0 {
            righe.push(HandoverLine::operatore(format!(
                "{} per un recupero, non ancora {}.",
                quanti(
                    da_recuperare,
                    "periodo deciso da valutare",
                    "periodi decisi da valutare"
                ),
                if da_recuperare == 1 {
                    "recuperato"
                } else {
                    "recuperati"
                }
            )));
        }
        Ok(righe)
    }

    /// Sezione 5, che cosa è andato storto.
    fn went_wrong(&self, from: Timestamp, until: Timestamp) -> ServiceResult<Vec<HandoverLine>> {
        let mut righe = Vec::new();
        for aperta in self.database().open_interruptions()? {
            righe.push(HandoverLine::calcolato(
                lisi_core::model::interruption::as_sentence(
                    &aperta.interruption,
                    Timestamp::to_readable_local,
                ),
            ));
        }
        for fonte in crate::source_health::overview_of(self.database())? {
            if fonte.needs_attention() {
                righe.push(HandoverLine::calcolato(format!(
                    "«{}» da guardare: {}",
                    fonte.display_name.as_str(),
                    fonte.why()
                )));
            }
        }
        let mut per_genere: BTreeMap<&'static str, usize> = BTreeMap::new();
        for guasto in self.database().faults()? {
            if guasto.occurred_at < from || guasto.occurred_at >= until {
                continue;
            }
            *per_genere.entry(guasto.kind.label()).or_default() += 1;
        }
        for (genere, numero) in per_genere {
            righe.push(HandoverLine::calcolato(format!(
                "{} di genere «{genere}».",
                quanti(numero, "guasto registrato", "guasti registrati")
            )));
        }
        Ok(righe)
    }

    /// Esporta il foglio in testo o in Word nella cartella indicata, e lo
    /// scrive nell'audit.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se la cartella non è assoluta, se il file esiste
    /// già o non si scrive, o se l'audit non si aggiorna.
    pub fn export(
        &self,
        foglio: &Handover,
        formato: HandoverFormat,
        cartella: &Path,
        in_team: bool,
        chi: &Actor,
        now: Timestamp,
    ) -> ServiceResult<PathBuf> {
        if !cartella.is_absolute() {
            return Err(ServiceError::ExportNotWritten {
                reason: String::from(
                    "la cartella di destinazione deve essere un percorso completo",
                ),
            });
        }
        std::fs::create_dir_all(cartella).map_err(|errore| ServiceError::ExportNotWritten {
            reason: format!("la cartella non si crea: {}", errore.kind()),
        })?;
        let (byte, estensione) = match formato {
            HandoverFormat::Text => (
                crate::run_mode::marked_text(foglio.as_text(in_team)).into_bytes(),
                "txt",
            ),
            HandoverFormat::Word => (
                crate::report_docx::render(&foglio.as_report(in_team, now))?,
                "docx",
            ),
        };
        let cifre: String = now
            .to_w3cdtf_utc()
            .chars()
            .filter(char::is_ascii_digit)
            .collect();
        // In Esercitazione il nome porta il prefisso, e il testo si apre con la
        // frase di SIC-17 (PR-13, ADR-0129); il Word la riceve dal suo generatore.
        let nome =
            crate::run_mode::file_name(&format!("passaggio-di-consegne-{cifre}.{estensione}"));
        // DEL SOLO UTENTE, O NIENTE (SEC-02, ADR-0157): il foglio dice chi ha
        // fatto che cosa nelle ultime ore, e nasce leggibile dal solo utente.
        let consegnati = Delivery::begin(cartella, &nome, HANDOVER_NOT_WRITTEN)
            .and_then(|mut consegna| {
                consegna.write(&nome, &byte)?;
                consegna.deliver(Existing::Refuse)
            })
            .inspect_err(|errore| {
                record_refusal(
                    self.database(),
                    chi,
                    now,
                    REFUSED_AUDIT_ACTION,
                    "passaggio_di_consegne",
                    errore,
                );
            })?;
        let percorso = consegnati
            .files
            .into_iter()
            .next()
            .unwrap_or_else(|| cartella.join(&nome));
        self.database().append_audit(&NewAuditEntry {
            actor: chi.clone(),
            action: AuditAction::try_new(HANDOVER_AUDIT_ACTION)?,
            entity: AuditEntity::try_new("passaggio_di_consegne")?,
            entity_id: None,
            actor_mode: None,
            detail: Some(AuditDetail::try_new(&format!(
                "dal {} al {}, in {estensione}",
                foglio.from.to_readable_local(),
                foglio.until.to_readable_local()
            ))?),
            recorded_at: now,
        })?;
        Ok(percorso)
    }
}

/// Il formato di un'esportazione.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HandoverFormat {
    /// Testo semplice.
    Text,
    /// Documento Word.
    Word,
}

/// La riga di un monitoraggio ancora aperto, per «Che cosa resta aperto».
fn open_monitoring(sessione: &Session) -> HandoverLine {
    let dal = sessione.started_at.map_or_else(String::new, |inizio| {
        format!(" dal {}", inizio.to_readable_local())
    });
    HandoverLine::calcolato(format!(
        "Il monitoraggio «{}» risulta «{}»{dal}: resta aperto finché qualcuno non lo arresta \
         o la durata non trascorre.",
        sessione.label.as_str(),
        sessione.state.label()
    ))
}

/// Sezione 6, da dove cominciare: prima il monitoraggio da seguire, poi i primi
/// elementi della coda, **nel suo ordine**, con i fatti che li collocano.
/// Riferimenti, mai il testo.
fn start_here(
    coda: &crate::work_queue::WorkQueue,
    in_corso: &[Session],
    now: Timestamp,
) -> Vec<HandoverLine> {
    // Il monitoraggio viene prima della coda: se non sta acquisendo, la coda
    // smette di crescere e nessuno se ne accorge (F-19).
    let mut righe: Vec<HandoverLine> = in_corso
        .iter()
        .map(|sessione| {
            HandoverLine::calcolato(format!(
                "Il monitoraggio «{}»: dal Cruscotto si controlla che l'acquisizione stia \
                 davvero avvenendo. Lo stato registrato non basta a dirlo.",
                sessione.label.as_str()
            ))
        })
        .collect();
    if coda.items.is_empty() {
        return righe;
    }
    righe.push(HandoverLine::calcolato(String::from(START_CRITERION)));
    righe.extend(coda.items.iter().take(START_ITEMS).map(|elemento| {
        HandoverLine::calcolato(format!(
            "Contenuto {}, fonte «{}», monitoraggio «{}»: {}.",
            elemento.content_id.get(),
            elemento.source_name,
            elemento.session_label,
            elemento.why_here(now)
        ))
    }));
    righe
}

#[cfg(test)]
mod tests {
    use lisi_core::Timestamp;
    use lisi_core::model::NewAuditEntry;
    use lisi_core::model::dictionary::{ConfigurationResolver, MatchMode, TermProvenance};
    use lisi_core::model::person::NewPerson;
    use lisi_core::model::reason::OperationalReason;
    use lisi_core::model::{NewSession, NewSource, SessionDuration, SessionState, SourceKind};
    use lisi_core::text::{
        Actor, AuditAction, AuditDetail, AuditEntity, DisplayName, LanguageTag, SourceIdentifier,
        TermCategory, TermText,
    };
    use lisi_storage::Database;
    use lisi_telegram::{ChatId, ConnectorEvent, IncomingMessage, MessageId};

    use super::{EMPTY_SECTION, HandoverFormat, HandoverService, SECTION_TITLES, START_CRITERION};
    use crate::acquisition::AcquisitionService;

    const CHAT: i64 = -1_001_000_000_004;

    /// **Uno al singolare, gli altri al plurale** (UX-EXCELLENCE-02, SIM3-17):
    /// il foglio scriveva «1 revisioni registrate».
    #[test]
    fn un_conteggio_concorda_con_la_parola() {
        assert_eq!(
            super::quanti(1, "revisione registrata", "revisioni registrate"),
            "1 revisione registrata"
        );
        assert_eq!(
            super::quanti(2, "revisione registrata", "revisioni registrate"),
            "2 revisioni registrate"
        );
        assert_eq!(
            super::quanti(0, "revisione registrata", "revisioni registrate"),
            "0 revisioni registrate"
        );
        // Ogni decisione contata ha le due forme, e sono diverse.
        for (azione, uno, tanti) in super::DECISIONS {
            assert_ne!(uno, tanti, "«{azione}»: singolare e plurale coincidono");
        }
    }

    fn t(minuti: i64) -> Timestamp {
        Timestamp::from_millis(1_790_294_400_000 + minuti * 60_000)
    }

    fn operatore() -> Actor {
        let Ok(attore) = Actor::try_new("operatore.prova") else {
            panic!("l'attore di prova deve essere valido");
        };
        attore
    }

    fn vuoto() -> Database {
        let Ok(database) = crate::sources::open_in_memory_database() else {
            panic!("l'archivio in memoria deve potersi aprire");
        };
        database
    }

    /// Un archivio con tre contenuti segnalati, di livello e istante diversi.
    fn con_lavoro() -> Database {
        let mut database = vuoto();
        let (Ok(identificativo), Ok(nome), Ok(etichetta)) = (
            SourceIdentifier::try_new(&CHAT.to_string()),
            DisplayName::try_new("Canale di prova"),
            DisplayName::try_new("Monitoraggio di prova"),
        ) else {
            panic!("i valori di prova devono essere validi");
        };
        let Ok(fonte) = database.insert_source(
            &NewSource {
                kind: SourceKind::Channel,
                identifier: identificativo,
                display_name: nome,
                authorized_by: operatore(),
                active: true,
            },
            t(-10),
        ) else {
            panic!("la fonte deve potersi registrare");
        };
        let Ok(sessione) = database.insert_session(
            &NewSession {
                label: etichetta,
                started_by: operatore(),
                duration: SessionDuration::Preset { seconds: 360_000 },
                source_ids: vec![fonte],
            },
            t(-10),
        ) else {
            panic!("la sessione deve potersi creare");
        };
        let mut risolutore = ConfigurationResolver::new();
        for (termine, livello) in [("molotov", 3_i8), ("corteo", 1_i8)] {
            let (Ok(testo), Ok(categoria), Ok(lingua)) = (
                TermText::try_new(termine),
                TermCategory::try_new("prova"),
                LanguageTag::try_new("it"),
            ) else {
                panic!("i valori del termine devono essere validi");
            };
            let Ok(()) = risolutore.add(
                testo,
                categoria,
                lingua,
                MatchMode::NormalizedWord,
                livello,
                TermProvenance::ad_hoc(),
            ) else {
                panic!("il termine deve essere accettato");
            };
        }
        let Ok(()) = database.save_resolved_configuration(sessione, &risolutore.finish()) else {
            panic!("la configurazione deve potersi salvare");
        };
        let Ok(()) = database.update_session_state(sessione, SessionState::Running, t(-5)) else {
            panic!("il monitoraggio deve avviarsi");
        };
        let mut acquisizione = AcquisitionService::new(database);
        let Ok(contesto) = acquisizione.load_context(sessione, operatore()) else {
            panic!("il contesto deve potersi costruire");
        };
        for (id, testo, minuti) in [
            (1, "un corteo annunciato, testo riservato del messaggio", 10),
            (2, "una molotov nel testo riservato del messaggio", 20),
            (3, "un altro corteo nel testo riservato del messaggio", 5),
        ] {
            let (Ok(chat), Ok(messaggio)) = (ChatId::try_new(CHAT), MessageId::try_new(id)) else {
                panic!("identificativi validi");
            };
            let Ok(_) = acquisizione.ingest(
                &ConnectorEvent::MessageReceived(IncomingMessage {
                    chat_id: chat,
                    message_id: messaggio,
                    author: None,
                    author_identifier: None,
                    author_username: None,
                    text: String::from(testo),
                    published_at_millis: t(minuti).as_millis(),
                    url: None,
                    attachment: None,
                }),
                &contesto,
                t(minuti),
            ) else {
                panic!("il messaggio deve entrare");
            };
        }
        acquisizione.into_database()
    }

    /// **Sei sezioni, sempre, anche vuote, e la sezione vuota lo dice**
    /// (controllo negativo 1).
    #[test]
    fn sei_sezioni_sempre_anche_vuote() {
        let servizio = HandoverService::new(vuoto());
        let Ok(foglio) = servizio.compose(24, t(60)) else {
            panic!("il foglio deve comporsi");
        };
        let testo = foglio.as_text(false);
        for titolo in SECTION_TITLES {
            assert!(testo.contains(titolo), "manca la sezione «{titolo}»");
        }
        assert_eq!(testo.matches(EMPTY_SECTION).count(), 6, "{testo}");
        let Ok(documento) = crate::report_docx::render(&foglio.as_report(false, t(60))) else {
            panic!("il documento Word deve comporsi");
        };
        assert!(!documento.is_empty());
    }

    /// **«Da dove cominciare» segue l'ordine della coda, e dichiara il
    /// criterio** (controllo negativo 2).
    #[test]
    fn da_dove_cominciare_segue_la_coda() {
        let servizio = HandoverService::new(con_lavoro());
        let Ok(foglio) = servizio.compose(24, t(60)) else {
            panic!("il foglio deve comporsi");
        };
        let Ok(coda) = servizio.queue.compose(t(60)) else {
            panic!("la coda deve comporsi");
        };
        let righe = &foglio.sections[5].lines;
        // Prima il monitoraggio in corso (F-19), poi il criterio della coda.
        assert!(
            righe[0].text.contains("«Monitoraggio di prova»"),
            "{}",
            righe[0].text
        );
        assert_eq!(
            righe[1].text, START_CRITERION,
            "il criterio si dichiara prima della coda"
        );
        let ordine: Vec<String> = coda
            .items
            .iter()
            .map(|elemento| format!("Contenuto {},", elemento.content_id.get()))
            .collect();
        assert_eq!(righe.len(), ordine.len() + 2);
        for (riga, atteso) in righe[2..].iter().zip(&ordine) {
            assert!(
                riga.text.starts_with(atteso),
                "{} invece di {atteso}",
                riga.text
            );
        }
    }

    /// **Il monitoraggio in corso resta aperto e si segue per primo** (F-19).
    ///
    /// Vista rossa prima della correzione: né «Che cosa resta aperto» né «Da
    /// dove cominciare» nominavano il monitoraggio; arrestato, non compare più.
    #[test]
    fn il_monitoraggio_in_corso_si_consegna() {
        let database = con_lavoro();
        let Ok(sessioni) = database.sessions() else {
            panic!("i monitoraggi devono potersi leggere");
        };
        let servizio = HandoverService::new(database);
        let Ok(foglio) = servizio.compose(24, t(60)) else {
            panic!("il foglio deve comporsi");
        };
        let aperto = &foglio.sections[3].lines;
        assert!(
            aperto[0]
                .text
                .contains("«Monitoraggio di prova» risulta «In corso»"),
            "{}",
            aperto[0].text
        );
        assert!(foglio.sections[5].lines[0].text.contains("Cruscotto"));

        // Lo stesso archivio, con il monitoraggio arrestato.
        let Some(sessione) = sessioni.first() else {
            panic!("il monitoraggio di prova esiste");
        };
        let mut arrestato = con_lavoro();
        let Ok(()) = arrestato.update_session_state(sessione.id, SessionState::Stopped, t(61))
        else {
            panic!("il monitoraggio deve potersi arrestare");
        };
        let servizio = HandoverService::new(arrestato);
        let Ok(dopo) = servizio.compose(24, t(62)) else {
            panic!("il foglio deve comporsi");
        };
        assert!(
            !dopo.as_text(false).contains("risulta «"),
            "un monitoraggio arrestato è ancora consegnato come aperto"
        );
    }

    /// **Nessun corpo di messaggio nel foglio** (controllo negativo 3), e il
    /// foglio è lo stesso a parità di archivio e di istante.
    #[test]
    fn nessun_corpo_e_lo_stesso_foglio() {
        let servizio = HandoverService::new(con_lavoro());
        let (Ok(primo), Ok(secondo)) = (servizio.compose(24, t(60)), servizio.compose(24, t(60)))
        else {
            panic!("il foglio deve comporsi");
        };
        assert_eq!(primo, secondo, "deterministico");
        let testo = primo.as_text(false);
        assert!(
            !testo.contains("testo riservato"),
            "un corpo è finito nel foglio"
        );
        assert!(
            testo.contains("3 contenuti acquisiti, 3 con avviso"),
            "{testo}"
        );
    }

    /// **Il foglio non nomina soggetti** (controllo negativo 4): delle
    /// valutazioni dice quante e da chi, mai di chi.
    #[test]
    fn nessun_soggetto_nominato() {
        let database = con_lavoro();
        let (Ok(etichetta), Ok(ragione)) = (
            DisplayName::try_new("Soggetto Riservato"),
            OperationalReason::try_new("richiesta dell'autorità procedente del 4 marzo"),
        ) else {
            panic!("valori validi");
        };
        let Ok(_) =
            database.insert_person(&NewPerson::open(etichetta, ragione), &operatore(), t(30))
        else {
            panic!("il soggetto deve aprirsi");
        };
        let (Ok(azione), Ok(entita), Ok(dettaglio)) = (
            AuditAction::try_new("soggetto_valutato"),
            AuditEntity::try_new("person"),
            AuditDetail::try_new("Soggetto Riservato: priorità alta"),
        ) else {
            panic!("valori d'audit validi");
        };
        let Ok(_) = database.append_audit(&NewAuditEntry {
            actor: operatore(),
            action: azione,
            entity: entita,
            entity_id: Some(1),
            actor_mode: None,
            detail: Some(dettaglio),
            recorded_at: t(31),
        }) else {
            panic!("la voce d'audit deve registrarsi");
        };
        let servizio = HandoverService::new(database);
        let Ok(foglio) = servizio.compose(24, t(60)) else {
            panic!("il foglio deve comporsi");
        };
        let testo = foglio.as_text(false);
        assert!(
            !testo.contains("Soggetto Riservato"),
            "un soggetto è stato nominato"
        );
        // Una valutazione, al singolare (SIM3-17). La prova chiedeva «valutazioni
        // di soggetti» anche per una sola: fissava l'errore di concordanza che
        // OPERATOR-SIM-03 ha trovato sullo schermo.
        assert!(
            testo.contains("1 valutazione di un soggetto, da operatore.prova"),
            "{testo}"
        );
    }

    /// **SEC-02: il passaggio di consegne del solo utente, o niente**
    /// (ADR-0157). Vista rossa il 2026-10-22 con la protezione tolta (mutazione di SEC-02).
    #[cfg(windows)]
    #[test]
    fn il_passaggio_di_consegne_e_del_solo_utente_o_non_si_scrive() {
        let servizio = HandoverService::new(con_lavoro());
        let Ok(foglio) = servizio.compose(8, t(60)) else {
            panic!("il foglio deve comporsi");
        };
        crate::permessi_di_prova::prova_un_uscita("passaggio di consegne", |cartella| {
            servizio
                .export(
                    &foglio,
                    HandoverFormat::Text,
                    cartella,
                    true,
                    &operatore(),
                    t(61),
                )
                .map(|percorso| vec![percorso])
        });
    }

    /// **Esportare in testo e in Word scrive un file nuovo e lo registra**; lo
    /// stesso istante non sovrascrive.
    #[test]
    fn esportare_non_sovrascrive_e_si_registra() {
        let servizio = HandoverService::new(con_lavoro());
        let Ok(foglio) = servizio.compose(8, t(60)) else {
            panic!("il foglio deve comporsi");
        };
        let Ok(cartella) = tempfile::tempdir() else {
            panic!("la cartella temporanea deve potersi creare");
        };
        for formato in [HandoverFormat::Text, HandoverFormat::Word] {
            let Ok(percorso) =
                servizio.export(&foglio, formato, cartella.path(), true, &operatore(), t(61))
            else {
                panic!("l'esportazione deve riuscire");
            };
            assert!(percorso.exists());
        }
        assert!(
            servizio
                .export(
                    &foglio,
                    HandoverFormat::Text,
                    cartella.path(),
                    true,
                    &operatore(),
                    t(61)
                )
                .is_err(),
            "lo stesso istante non sovrascrive"
        );
        let Ok(voci) = servizio.database().audit_entries() else {
            panic!("l'audit deve leggersi");
        };
        assert_eq!(
            voci.iter()
                .filter(|voce| voce.action.as_str() == super::HANDOVER_AUDIT_ACTION)
                .count(),
            2
        );
        let Ok(elenco) = std::fs::read_dir(cartella.path()) else {
            panic!("la cartella deve leggersi");
        };
        let testi: Vec<_> = elenco
            .flatten()
            .filter(|voce| voce.path().extension().is_some_and(|e| e == "txt"))
            .collect();
        assert_eq!(testi.len(), 1);
        let Ok(testo) = std::fs::read_to_string(testi[0].path()) else {
            panic!("il testo deve leggersi");
        };
        assert!(
            testo.contains(super::TEAM_NOTE),
            "in Team il foglio lo dice"
        );
    }

    /// **Soltanto le durate dichiarate.**
    #[test]
    fn soltanto_le_durate_dichiarate() {
        let servizio = HandoverService::new(vuoto());
        assert!(servizio.compose(5, t(60)).is_err());
    }

    /// **Una fonte non più accessibile sta in «che cosa è andato storto»**,
    /// con la ragione della sua salute.
    #[test]
    fn una_fonte_da_guardare_sta_fra_cio_che_e_andato_storto() {
        let database = con_lavoro();
        let Ok(fonti) = database.sources() else {
            panic!("le fonti devono leggersi");
        };
        let Ok(_) = database.insert_health_check(
            &lisi_storage::repository::source_health::NewHealthCheck {
                source_id: fonti[0].id,
                account_id: None,
                outcome: lisi_core::model::source_health::HealthCheckOutcome::NotAccessible,
                detail: None,
            },
            t(40),
        ) else {
            panic!("la verifica deve registrarsi");
        };
        let servizio = HandoverService::new(database);
        let Ok(foglio) = servizio.compose(24, t(60)) else {
            panic!("il foglio deve comporsi");
        };
        let righe = &foglio.sections[4].lines;
        assert!(
            righe
                .iter()
                .any(|riga| riga.text.starts_with("«Canale di prova» da guardare: ")),
            "{righe:?}"
        );
    }
}
