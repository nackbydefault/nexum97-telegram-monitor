//! Il rapporto complessivo su più monitoraggi (REPORT-MULTI-01, ADR-0192,
//! DEC-478).
//!
//! # Di chi è questo documento
//!
//! Del **responsabile** che chi lo genera nomina: senza nome e qualifica non si
//! produce, e il documento lo dice in testa e nella sottoscrizione (ADR-0192,
//! decisione 3).
//!
//! # Che cosa dice, e che cosa no
//!
//! Per ogni monitoraggio, in una sezione sua: il nome, chi l'ha avviato, il
//! periodo, lo stato, la copertura di ciascuna fonte con le frasi di sempre,
//! quanti contenuti e quanti avvisi per livello, le relazioni già prodotte.
//! **Non** contiene i testi dei messaggi, e **non** somma i numeri di due
//! monitoraggi: sono due decisioni, e un messaggio può stare in entrambe
//! (decisioni 1 e 2).

use std::io::Write as _;
use std::path::{Path, PathBuf};

use lisi_core::model::NewAuditEntry;
use lisi_core::model::report_template::ReportTemplateProfile;
use lisi_core::text::{Actor, AuditAction, AuditDetail, AuditEntity};
use lisi_core::{SessionId, Sha256Digest, Timestamp};
use lisi_storage::repository::overview_report::NewOverviewReport;

use crate::error::{ServiceError, ServiceResult};
use crate::protected_output::ProtectedFolder;
use crate::report::ReportService;
use crate::report_narrative::{Block, Letterhead, LetterheadLine, NarrativeReport};

/// Quanti monitoraggi almeno.
pub const MIN_MONITORINGS: usize = 2;
/// Quanti monitoraggi al più.
pub const MAX_MONITORINGS: usize = 20;
/// L'azione d'audit di un rapporto complessivo prodotto.
pub const OVERVIEW_AUDIT_ACTION: &str = "rapporto_complessivo_prodotto";
/// Il rapporto, in PDF.
pub const PDF_NAME: &str = "rapporto-complessivo.pdf";
/// Il rapporto, in testo.
pub const TXT_NAME: &str = "rapporto-complessivo.txt";
/// L'elenco delle impronte, nella forma dei pacchetti.
pub const MANIFEST_NAME: &str = "elenco-delle-impronte.txt";

/// Ciò che si dice quando la cartella non nasce del solo utente.
const NOT_WRITTEN: &str = "Il rapporto complessivo NON è stato scritto";

/// La frase che impedisce di confondere le coperture (ADR-0192, decisione 2).
pub const DISTINCT_COVERAGES: &str = "Ogni monitoraggio è una decisione distinta, con il suo \
     responsabile, il suo periodo e la sua copertura. I numeri dei monitoraggi non si sommano: \
     se due monitoraggi si sovrappongono, lo stesso messaggio può comparire in entrambi.";

/// Il responsabile del documento, scritto da chi lo genera.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DocumentResponsible {
    /// Nome e cognome.
    pub name: String,
    /// Qualifica.
    pub role: String,
}

/// La richiesta.
#[derive(Debug, Clone)]
pub struct OverviewRequest<'a> {
    /// I monitoraggi, nell'ordine scelto.
    pub sessions: Vec<SessionId>,
    /// Il responsabile del documento.
    pub responsible: DocumentResponsible,
    /// I dati documentali dell'ufficio.
    pub profile: &'a ReportTemplateProfile,
    /// La cartella dentro la quale nasce quella del rapporto.
    pub destination: &'a Path,
    /// Chi lo chiede.
    pub requested_by: Actor,
    /// Quando.
    pub requested_at: Timestamp,
}

/// Che cosa è uscito.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GeneratedOverview {
    /// L'identificativo, che è anche il nome della cartella.
    pub reference: String,
    /// La cartella.
    pub directory: PathBuf,
    /// L'elenco delle impronte.
    pub manifest: PathBuf,
}

impl GeneratedOverview {
    /// L'esito, in una frase.
    #[must_use]
    pub fn operator_message(&self) -> String {
        format!(
            "Rapporto complessivo {} scritto in «{}», in PDF e in testo, con l'elenco delle \
             impronte.",
            self.reference,
            self.directory.display()
        )
    }
}

/// Una sezione: un monitoraggio, con ciò che il registro ne sa.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MonitoringSection {
    /// Il nome del monitoraggio.
    pub label: String,
    /// Chi l'ha avviato.
    pub responsible: String,
    /// Inizio.
    pub started_at: Timestamp,
    /// Fine, se è concluso.
    pub ended_at: Option<Timestamp>,
    /// Lo stato, nella parola dell'operatore.
    pub state: String,
    /// La copertura di ciascuna fonte.
    pub coverage: Vec<crate::coverage::CoverageLine>,
    /// Quanti contenuti.
    pub contents: usize,
    /// Quanti avvisi per livello, da 1 a 4.
    pub alerts_by_level: [usize; 4],
    /// Le relazioni prodotte: identificativo e stato.
    pub reports: Vec<(String, String)>,
}

/// Compone il documento: una funzione pura, provata senza aprire un PDF.
#[must_use]
pub fn compose(
    reference: &str,
    responsible: &DocumentResponsible,
    profile: &ReportTemplateProfile,
    sections: &[MonitoringSection],
    generated_at: Timestamp,
) -> NarrativeReport {
    let riga = |valore: Option<&str>, che_cosa: &str| {
        valore.map_or_else(
            || LetterheadLine::Placeholder(che_cosa.to_owned()),
            |valore| LetterheadLine::Configured(valore.to_owned()),
        )
    };
    let letterhead = Letterhead {
        emblem: profile.emblem.clone(),
        lines: vec![
            riga(
                profile.organisation.as_ref().map(|f| f.as_str()),
                "Denominazione dell'amministrazione",
            ),
            riga(
                profile.office.as_ref().map(|f| f.as_str()),
                "Ufficio o articolazione",
            ),
            riga(
                profile.header_line.as_ref().map(|f| f.as_str()),
                "Sede, indirizzo e recapiti",
            ),
        ],
    };
    let footer = vec![riga(
        profile.footer_line.as_ref().map(|f| f.as_str()),
        "Riferimenti dell'ufficio",
    )];

    let mut blocks = vec![
        Block::Lead {
            lead: String::from("Oggetto:"),
            body: format!(
                "Rapporto complessivo {reference} su {} monitoraggi.",
                sections.len()
            ),
        },
        Block::Lead {
            lead: String::from("Responsabile del documento:"),
            body: format!("{}, {}.", responsible.name, responsible.role),
        },
        Block::Paragraph(String::from(DISTINCT_COVERAGES)),
        Block::Paragraph(String::from(
            "Il rapporto non contiene i testi dei messaggi: per ciascun monitoraggio li \
             contiene la sua relazione, indicata nella sua sezione.",
        )),
        Block::Table {
            headers: vec![
                String::from("Monitoraggio"),
                String::from("Responsabile"),
                String::from("Periodo"),
            ],
            rows: sections
                .iter()
                .map(|sezione| {
                    vec![
                        sezione.label.clone(),
                        sezione.responsible.clone(),
                        periodo(sezione),
                    ]
                })
                .collect(),
        },
    ];

    for (numero, sezione) in sections.iter().enumerate() {
        blocks.push(Block::Heading(format!(
            "{}. Monitoraggio «{}»",
            numero + 1,
            sezione.label
        )));
        blocks.push(Block::Lead {
            lead: String::from("Responsabile del monitoraggio:"),
            body: format!("{} (chi lo ha avviato).", sezione.responsible),
        });
        blocks.push(Block::Lead {
            lead: String::from("Periodo:"),
            body: format!("{}. Stato: {}.", periodo(sezione), sezione.state),
        });
        crate::report_narrative::push_coverage(&mut blocks, &sezione.coverage);
        let [uno, due, tre, quattro] = sezione.alerts_by_level;
        blocks.push(Block::Lead {
            lead: String::from("Contenuti e avvisi di questo monitoraggio:"),
            body: format!(
                "{}; avvisi di livello 1: {uno}, 2: {due}, 3: {tre}, 4: {quattro}.",
                lisi_core::text::counted(sezione.contents, "contenuto", "contenuti")
            ),
        });
        if sezione.reports.is_empty() {
            blocks.push(Block::Lead {
                lead: String::from("Relazioni prodotte:"),
                body: String::from("nessuna, al momento di questo rapporto."),
            });
        } else {
            blocks.push(Block::Lead {
                lead: String::from("Relazioni prodotte:"),
                body: format!(
                    "{}.",
                    sezione
                        .reports
                        .iter()
                        .map(|(id, stato)| format!("{id} ({stato})"))
                        .collect::<Vec<_>>()
                        .join(", ")
                ),
            });
        }
    }

    blocks.push(Block::Signature {
        place_and_date: format!(
            "{}, {}",
            profile
                .place
                .as_ref()
                .map_or("[Luogo]", |luogo| luogo.as_str()),
            generated_at.to_readable_local()
        ),
        role: Some(responsible.role.clone()),
        name: Some(responsible.name.clone()),
    });

    NarrativeReport {
        generated_at,
        letterhead,
        footer,
        blocks,
    }
}

fn periodo(sezione: &MonitoringSection) -> String {
    sezione.ended_at.map_or_else(
        || {
            format!(
                "dal {}, non concluso",
                sezione.started_at.to_readable_local()
            )
        },
        |fine| {
            format!(
                "dal {} al {}",
                sezione.started_at.to_readable_local(),
                fine.to_readable_local()
            )
        },
    )
}

/// Un testo da scrivere: senza spazi ai lati, non vuoto, su una riga, al più
/// 200 caratteri.
fn campo(testo: &str, che_cosa: &str) -> ServiceResult<String> {
    let pulito = testo.trim();
    if pulito.is_empty() || pulito.chars().count() > 200 || pulito.contains(['\n', '\r']) {
        return Err(ServiceError::OverviewRefused {
            reason: format!("{che_cosa} va scritto, su una riga, in non più di 200 caratteri"),
        });
    }
    Ok(pulito.to_owned())
}

impl ReportService {
    /// Le sezioni dei monitoraggi, lette dall'archivio.
    fn overview_sections(
        &self,
        sessions: &[SessionId],
        until: Timestamp,
    ) -> ServiceResult<Vec<MonitoringSection>> {
        let database = self.database();
        let mut sezioni = Vec::with_capacity(sessions.len());
        for &session_id in sessions {
            let session = database.session(session_id)?;
            let mut contenuti = 0_usize;
            let mut avvisi = [0_usize; 4];
            for contenuto in database.session_contents(session_id)? {
                contenuti += 1;
                if let Some(avviso) = database.content_alert(contenuto.id)?
                    && let Some(casella) =
                        avvisi.get_mut(usize::from(avviso.level.get()).saturating_sub(1))
                {
                    *casella += 1;
                }
            }
            let copertura = crate::coverage::for_monitoring(database, session_id, until)?;
            let relazioni = database
                .session_report_packages(session_id)?
                .into_iter()
                .map(|pacchetto| {
                    (
                        pacchetto.report_id.as_str().to_owned(),
                        pacchetto.status.operator_label().to_owned(),
                    )
                })
                .collect();
            sezioni.push(MonitoringSection {
                label: session.label.as_str().to_owned(),
                responsible: session.started_by.as_str().to_owned(),
                started_at: session.started_at.unwrap_or(session.created_at),
                ended_at: session.ended_at,
                state: session.state.label().to_owned(),
                coverage: copertura
                    .sources
                    .into_iter()
                    .map(|(_, source, coverage)| crate::coverage::CoverageLine { source, coverage })
                    .collect(),
                contents: contenuti,
                alerts_by_level: avvisi,
                reports: relazioni,
            });
        }
        Ok(sezioni)
    }

    /// Produce il rapporto complessivo, lo consegna del solo utente e lo
    /// registra.
    ///
    /// # Errori
    ///
    /// [`ServiceError::OverviewRefused`] per meno di due o più di venti
    /// monitoraggi, uno ripetuto, o un responsabile non scritto;
    /// [`ServiceError::ProtectionNotGuaranteed`] se la cartella non nasce del
    /// solo utente; un errore se una lettura, la composizione o una
    /// scrittura non riescono. In ogni errore dopo la creazione della
    /// cartella, ciò che era stato scritto si toglie.
    pub fn generate_overview(
        &mut self,
        request: &OverviewRequest<'_>,
    ) -> ServiceResult<GeneratedOverview> {
        let quanti = request.sessions.len();
        if !(MIN_MONITORINGS..=MAX_MONITORINGS).contains(&quanti) {
            return Err(ServiceError::OverviewRefused {
                reason: format!(
                    "servono da {MIN_MONITORINGS} a {MAX_MONITORINGS} monitoraggi, ne sono stati \
                     scelti {quanti}"
                ),
            });
        }
        let mut distinti = request.sessions.clone();
        distinti.sort_unstable();
        distinti.dedup();
        if distinti.len() != quanti {
            return Err(ServiceError::OverviewRefused {
                reason: String::from("lo stesso monitoraggio è stato scelto due volte"),
            });
        }
        let responsabile = DocumentResponsible {
            name: campo(&request.responsible.name, "il nome del responsabile")?,
            role: campo(&request.responsible.role, "la qualifica del responsabile")?,
        };

        let sezioni = self.overview_sections(&request.sessions, request.requested_at)?;
        let anno = request.requested_at.year_utc();
        let progressivo = self.database().next_overview_sequence(anno)?;
        let riferimento = format!("RC-{anno}-{progressivo:04}");
        let documento = compose(
            &riferimento,
            &responsabile,
            request.profile,
            &sezioni,
            request.requested_at,
        );
        let pdf = crate::report_pdf::render(&documento, crate::report_pdf::PdfKind::Narrative)?;
        let testo = crate::run_mode::marked_text(documento.text()).into_bytes();

        std::fs::create_dir_all(request.destination).map_err(|errore| {
            ServiceError::ExportNotWritten {
                reason: format!("{}: {errore}", request.destination.display()),
            }
        })?;
        let cartella = ProtectedFolder::create(
            &request.destination.join(&riferimento),
            NOT_WRITTEN,
            |errore| ServiceError::ExportNotWritten {
                reason: format!("la cartella {riferimento} non si crea: {errore}"),
            },
        )?;
        let directory = cartella.path().to_path_buf();
        let mut scritti: Vec<PathBuf> = Vec::new();
        let esito = (|| -> ServiceResult<(PathBuf, Sha256Digest)> {
            let mut voci = Vec::new();
            for (nome, byte) in [(PDF_NAME, &pdf), (TXT_NAME, &testo)] {
                let percorso = directory.join(nome);
                scrivi_nuovo(&percorso, byte)?;
                scritti.push(percorso);
                voci.push((nome, byte.len(), Sha256Digest::of_bytes(byte)));
            }
            let elenco = manifest_text(
                &riferimento,
                request.requested_at,
                &request.requested_by,
                &voci,
            );
            let elenco = crate::run_mode::marked_text(elenco);
            let manifest = directory.join(MANIFEST_NAME);
            scrivi_nuovo(&manifest, elenco.as_bytes())?;
            scritti.push(manifest.clone());
            cartella.seal()?;
            Ok((manifest, Sha256Digest::of_bytes(elenco.as_bytes())))
        })();
        let (manifest, impronta) = match esito {
            Ok(esito) => esito,
            Err(errore) => {
                for file in &scritti {
                    let _ = std::fs::remove_file(file);
                }
                if let Err(resto) = cartella.remove() {
                    tracing::warn!(%resto, "cartella del rapporto complessivo non tolta");
                }
                return Err(errore);
            }
        };
        cartella.release();

        let audit = NewAuditEntry {
            actor: request.requested_by.clone(),
            action: AuditAction::try_new(OVERVIEW_AUDIT_ACTION)?,
            entity: AuditEntity::try_new("rapporto")?,
            entity_id: None,
            actor_mode: None,
            detail: Some(AuditDetail::try_new(&format!(
                "{riferimento}: {quanti} monitoraggi, responsabile {}",
                responsabile
                    .name
                    .chars()
                    .filter(|carattere| !carattere.is_control())
                    .take(120)
                    .collect::<String>()
            ))?),
            recorded_at: request.requested_at,
        };
        self.database_mut().insert_overview_report(
            &NewOverviewReport {
                year: anno,
                sequence: progressivo,
                requested_by: request.requested_by.as_str().to_owned(),
                requested_at: request.requested_at,
                responsible_name: responsabile.name.clone(),
                responsible_role: responsabile.role.clone(),
                session_ids: request.sessions.iter().map(|id| id.get()).collect(),
                manifest_sha256: impronta.as_str().to_owned(),
            },
            &audit,
        )?;
        Ok(GeneratedOverview {
            reference: riferimento,
            directory,
            manifest,
        })
    }
}

/// L'elenco delle impronte, nella forma dei pacchetti: nomi e impronte che la
/// verifica confronta.
fn manifest_text(
    riferimento: &str,
    quando: Timestamp,
    chi: &Actor,
    voci: &[(&str, usize, Sha256Digest)],
) -> String {
    let mut elenco = format!(
        "NEXUM/97 — elenco delle impronte del rapporto complessivo\n\
         Ideazione e progettazione: Giuseppe LISI\n\n\
         Pacchetto:    {riferimento}\n\
         Prodotto:     {}\n\
         Richiesto da: {}\n\
         {}\
         Quanti file:  {}\n\n",
        quando.to_readable_utc(),
        chi.as_str(),
        crate::report_package::program_lines(lisi_platform::launch_volume::of_current_executable()),
        voci.len()
    );
    for (nome, dimensione, impronta) in voci {
        elenco.push_str(&format!(
            "File:       {nome}\nDimensione: {dimensione} byte\nSHA-256:    {}\n\n",
            impronta.as_str()
        ));
    }
    elenco
}

/// Scrive un file nuovo: uno che c'è già non si sovrascrive.
fn scrivi_nuovo(percorso: &Path, byte: &[u8]) -> ServiceResult<()> {
    std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(percorso)
        .and_then(|mut file| file.write_all(byte))
        .map_err(|errore| ServiceError::ExportNotWritten {
            reason: format!("{}: {errore}", percorso.display()),
        })
}

#[cfg(test)]
mod tests {
    use lisi_core::Timestamp;
    use lisi_core::model::report_template::ReportTemplateProfile;

    use super::{DISTINCT_COVERAGES, DocumentResponsible, MonitoringSection, compose};

    fn sezione(nome: &str, contenuti: usize) -> MonitoringSection {
        MonitoringSection {
            label: String::from(nome),
            responsible: String::from("operatore.uno"),
            started_at: Timestamp::from_millis(1_762_300_000_000),
            ended_at: None,
            state: String::from("In corso"),
            coverage: Vec::new(),
            contents: contenuti,
            alerts_by_level: [3, 2, 1, 0],
            reports: vec![(String::from("2026-0007"), String::from("Completato"))],
        }
    }

    fn responsabile() -> DocumentResponsible {
        DocumentResponsible {
            name: String::from("Mario Rossi"),
            role: String::from("Responsabile dell'ufficio"),
        }
    }

    #[test]
    fn ogni_monitoraggio_ha_la_sua_sezione_e_i_numeri_non_si_sommano() {
        let documento = compose(
            "RC-2026-0001",
            &responsabile(),
            &ReportTemplateProfile::default(),
            &[sezione("Primo", 10), sezione("Secondo", 5)],
            Timestamp::from_millis(1_762_300_000_000),
        );
        let testo = documento.text();
        assert!(testo.contains("Responsabile del documento"));
        assert!(testo.contains("Mario Rossi"));
        assert!(testo.contains(DISTINCT_COVERAGES));
        assert!(testo.contains("1. Monitoraggio «Primo»"));
        assert!(testo.contains("2. Monitoraggio «Secondo»"));
        assert!(testo.contains("10 contenuti"));
        assert!(testo.contains("5 contenuti"));
        assert!(!testo.contains("15 contenuti"), "i numeri non si sommano");
        assert!(testo.contains("2026-0007 (Completato)"));
        // La copertura di ogni monitoraggio è detta nella sua sezione.
        assert_eq!(
            testo
                .matches("Che cosa questa postazione ha guardato:")
                .count(),
            2
        );
    }

    fn archivio_con_due_monitoraggi() -> (crate::report::ReportService, Vec<lisi_core::SessionId>) {
        use lisi_core::model::{NewSession, NewSource, SessionDuration, SourceKind};
        use lisi_core::text::{Actor, DisplayName, SourceIdentifier};

        let Ok(mut database) = crate::sources::open_in_memory_database() else {
            panic!("l'archivio in memoria deve aprirsi");
        };
        let adesso = Timestamp::from_millis(1_762_300_000_000);
        let mut monitoraggi = Vec::new();
        for (numero, nome) in ["Primo", "Secondo"].iter().enumerate() {
            let (Ok(identificativo), Ok(etichetta), Ok(attore), Ok(sessione)) = (
                SourceIdentifier::try_new(&format!("canale_{numero}")),
                DisplayName::try_new(&format!("Canale {nome}")),
                Actor::try_new("operatore.prova"),
                DisplayName::try_new(nome),
            ) else {
                panic!("i valori di prova devono essere validi");
            };
            let Ok(fonte) = database.insert_source(
                &NewSource {
                    kind: SourceKind::Channel,
                    identifier: identificativo,
                    display_name: etichetta,
                    authorized_by: attore.clone(),
                    active: true,
                },
                adesso,
            ) else {
                panic!("la fonte deve registrarsi");
            };
            let Ok(id) = database.insert_session(
                &NewSession {
                    label: sessione,
                    started_by: attore,
                    duration: SessionDuration::Manual,
                    source_ids: vec![fonte],
                },
                adesso,
            ) else {
                panic!("il monitoraggio deve crearsi");
            };
            monitoraggi.push(id);
        }
        (crate::report::ReportService::new(database), monitoraggi)
    }

    #[test]
    fn il_rapporto_complessivo_si_scrive_si_verifica_e_si_registra() {
        use lisi_core::text::Actor;

        use super::{MANIFEST_NAME, OverviewRequest, PDF_NAME, TXT_NAME};
        use crate::error::ServiceError;

        let (mut servizio, monitoraggi) = archivio_con_due_monitoraggi();
        let Ok(cartella) = tempfile::tempdir() else {
            panic!("la cartella temporanea deve crearsi");
        };
        let profilo = ReportTemplateProfile::default();
        let Ok(chi) = Actor::try_new("operatore.prova") else {
            panic!("attore valido");
        };
        let richiesta = |sessioni: Vec<lisi_core::SessionId>, nome: &str| OverviewRequest {
            sessions: sessioni,
            responsible: DocumentResponsible {
                name: nome.to_owned(),
                role: String::from("Responsabile dell'ufficio"),
            },
            profile: &profilo,
            destination: cartella.path(),
            requested_by: chi.clone(),
            requested_at: Timestamp::from_millis(1_762_300_000_000),
        };

        // Rifiuti: un monitoraggio solo, uno ripetuto, nessun responsabile.
        for sbagliata in [
            richiesta(vec![monitoraggi[0]], "Mario Rossi"),
            richiesta(vec![monitoraggi[0], monitoraggi[0]], "Mario Rossi"),
            richiesta(monitoraggi.clone(), "   "),
        ] {
            assert!(matches!(
                servizio.generate_overview(&sbagliata),
                Err(ServiceError::OverviewRefused { .. })
            ));
        }

        let Ok(primo) = servizio.generate_overview(&richiesta(monitoraggi.clone(), "Mario Rossi"))
        else {
            panic!("il rapporto complessivo si deve scrivere");
        };
        assert_eq!(primo.reference, "RC-2025-0001");
        for nome in [PDF_NAME, TXT_NAME, MANIFEST_NAME] {
            assert!(primo.directory.join(nome).is_file(), "{nome}");
        }
        assert!(
            crate::report_package::verify_package_manifest(&primo.manifest).is_intact(),
            "la verifica dei pacchetti lo legge come gli altri"
        );
        let Ok(testo) = std::fs::read_to_string(primo.directory.join(TXT_NAME)) else {
            panic!("il testo si deve leggere");
        };
        assert!(testo.contains("Monitoraggio «Primo»") && testo.contains("Monitoraggio «Secondo»"));

        let Ok(secondo) =
            servizio.generate_overview(&richiesta(monitoraggi.clone(), "Mario Rossi"))
        else {
            panic!("il secondo rapporto si deve scrivere");
        };
        assert_eq!(secondo.reference, "RC-2025-0002");
        let Ok(registro) = servizio.database().overview_reports(10) else {
            panic!("il registro si deve leggere");
        };
        assert_eq!(registro.len(), 2);
        assert_eq!(registro[0].report.responsible_name, "Mario Rossi");
    }

    #[test]
    fn la_stessa_composizione_produce_lo_stesso_documento() {
        let fai = || {
            compose(
                "RC-2026-0002",
                &responsabile(),
                &ReportTemplateProfile::default(),
                &[sezione("Primo", 1), sezione("Secondo", 2)],
                Timestamp::from_millis(1_762_300_000_000),
            )
        };
        assert_eq!(fai(), fai());
        let Ok(primo) = crate::report_pdf::render(&fai(), crate::report_pdf::PdfKind::Narrative)
        else {
            panic!("il PDF si deve comporre");
        };
        let Ok(secondo) = crate::report_pdf::render(&fai(), crate::report_pdf::PdfKind::Narrative)
        else {
            panic!("il PDF si deve comporre");
        };
        assert_eq!(primo, secondo, "a parità di ingressi, lo stesso PDF");
    }
}
