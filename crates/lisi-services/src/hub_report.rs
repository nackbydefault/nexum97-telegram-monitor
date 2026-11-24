//! Le relazioni dell'ufficio, dal lato dell'Hub (TEAM-REPORT-01, ADR-0100).
//!
//! # Che cosa una postazione può fare
//!
//! **Leggere** l'elenco delle relazioni dell'ufficio, e **chiedere che una
//! fotografia venga congelata** per una sessione, indicando che cosa
//! rappresentare.
//!
//! # Che cosa non può fare
//!
//! **Produrre il documento.** La scelta di che cosa rappresentare è di chi ha
//! guardato, e chi ha guardato può essere su una postazione; i fatti sono
//! dell'Hub, e il documento nasce dove stanno i fatti (ADR-0100,
//! decisione 1).
//!
//! # Nomi e impronte, non byte
//!
//! L'elenco porta come si chiamano i documenti e la loro impronta. Il
//! protocollo dell'Hub non trasporta documenti: farli passare da un canale
//! pensato per messaggi brevi vorrebbe dire inventare qui un trasferimento di
//! file con le sue interruzioni e i suoi riavvii.

use lisi_core::model::hub_access::HubAction;
use lisi_core::model::hub_command::{CommandId, CommandKey, CommandOutcome, CommandVerdict};
use lisi_core::model::hub_report::{
    MAX_REPORT_SELECTION, MAX_SHARED_REPORTS_PAGE, SharedArtifact, SharedReport,
};
use lisi_core::model::report::{ReportId, ReportRequest, ReportSelection};
use lisi_core::text::{Actor, HubEventDetail};
use lisi_core::{ContentId, SessionId, Timestamp};

use crate::Database;
use crate::error::{ServiceError, ServiceResult};
use crate::hub_access::AuthenticatedDevice;
use crate::hub_commands::HubCommandService;
use crate::hub_people::AuthenticatedOperator;
use crate::report::ReportService;

/// Quante volte si riprova un identificativo già preso.
///
/// Lo stesso numero della generazione su una postazione sola: il progressivo
/// letto dall'archivio non è una prenotazione.
const IDENTIFIER_ATTEMPTS: u32 = 8;

/// Le relazioni dell'ufficio, servite dall'Hub.
#[derive(Debug)]
pub struct HubReportService {
    commands: HubCommandService,
    /// Il servizio che sa congelare una fotografia, con una connessione sua:
    /// SQLite serializza chi scrive, e una connessione per mestiere è il modo
    /// in cui va usato.
    relazioni: ReportService,
}

impl HubReportService {
    /// Costruisce il servizio sull'archivio dell'Hub.
    #[must_use]
    pub fn new(per_i_comandi: Database, per_le_relazioni: Database) -> Self {
        Self {
            commands: HubCommandService::new(per_i_comandi),
            relazioni: ReportService::new(per_le_relazioni),
        }
    }

    /// L'archivio dell'Hub.
    #[must_use]
    pub const fn database(&self) -> &Database {
        self.commands.database()
    }

    /// Le relazioni dell'ufficio, dalla più recente.
    ///
    /// # Errori
    ///
    /// Un errore di lettura, o se una riga conservata non è interpretabile.
    pub fn reports(&self, limit: usize) -> ServiceResult<Vec<SharedReport>> {
        let pacchetti = self
            .database()
            .recent_report_packages(limit.clamp(1, MAX_SHARED_REPORTS_PAGE))?;

        let mut relazioni = Vec::with_capacity(pacchetti.len());
        for pacchetto in &pacchetti {
            // La fotografia dice quanti erano e quanti se ne rappresentano: è
            // il numero di **allora**, ed è la ragione per cui la fotografia
            // esiste (DEC-152).
            let fotografia = self.database().report_snapshot(pacchetto.id)?;
            relazioni.push(SharedReport {
                report_id: String::from(pacchetto.report_id.as_str()),
                session_id: pacchetto.session_id,
                requested_by: String::from(pacchetto.requested_by.as_str()),
                status: pacchetto.status,
                requested_at: pacchetto.requested_at,
                completed_at: pacchetto.completed_at,
                monitored: fotografia.monitored_count(),
                selected: fotografia.selected_count(),
                artifacts: pacchetto
                    .artifacts
                    .iter()
                    .map(|artefatto| SharedArtifact {
                        file_name: String::from(artefatto.file_name.as_str()),
                        size_bytes: artefatto.size_bytes,
                        sha256: String::from(artefatto.sha256.as_str()),
                    })
                    .collect(),
            });
        }
        Ok(relazioni)
    }

    /// Congela una fotografia per una sessione.
    ///
    /// **Non produce il documento**: apre il pacchetto e fissa i fatti di
    /// adesso. Da quel momento il documento parlerà di **quel** momento
    /// (ADR-0100, decisione 3).
    ///
    /// # Errori
    ///
    /// Un errore se una lettura o una scrittura non riescono. Un comando
    /// **rifiutato non è un errore**: è un esito, e si ricorda.
    pub fn freeze(
        &mut self,
        device: &AuthenticatedDevice,
        operator: &AuthenticatedOperator,
        command_id: CommandId,
        session_id: SessionId,
        contents: &[i64],
        now: Timestamp,
    ) -> ServiceResult<CommandVerdict> {
        // LA MEMORIA DEL COMANDO VIENE PRIMA DI TUTTO (ADR-0094): chi riprova
        // dopo una risposta persa non deve aprire un secondo pacchetto.
        let chiave = CommandKey {
            device: device.device().clone(),
            command_id: command_id.clone(),
        };
        if let Some(esito) = self.commands.outcome(&chiave)? {
            return Ok(CommandVerdict::Replay(esito));
        }

        if contents.len() > MAX_REPORT_SELECTION {
            return Err(ServiceError::HubServer {
                reason: format!(
                    "una relazione non rappresenta più di {MAX_REPORT_SELECTION} contenuti"
                ),
            });
        }
        let selezione =
            ReportSelection::from_contents(contents.iter().copied().map(ContentId::new));
        let attore = Actor::try_new(&operator.actor())?;
        let anno = now.year_utc();
        let primo = self.database().next_report_sequence(anno)?;

        self.commands
            .execute(
                device,
                command_id,
                HubAction::ShareNotes,
                now,
                |transaction| {
                    let _ = transaction;
                    Ok(CommandOutcome::Done {
                        detail: Some(HubEventDetail::try_new("fotografia da congelare")?),
                    })
                },
            )
            .and_then(|verdetto| {
                // IL COMANDO SI RICORDA PRIMA, LA FOTOGRAFIA SI CONGELA DOPO.
                //
                // La preparazione legge e scrive su piu' tabelle con il suo
                // servizio, e farla dentro la transazione del comando
                // vorrebbe dire duplicarla qui. Il prezzo e' dichiarato: se
                // l'Hub cade fra le due, il comando risulta fatto e la
                // fotografia non c'e'. Chi riprova riceve «ripetuta» e non
                // vede il pacchetto: lo vede l'elenco, che e' dove si guarda.
                if !matches!(
                    verdetto,
                    CommandVerdict::Applied(CommandOutcome::Done { .. })
                ) {
                    return Ok(verdetto);
                }
                match self.congela(&attore, session_id, &selezione, anno, primo, now) {
                    Ok(report_id) => Ok(CommandVerdict::Applied(CommandOutcome::Done {
                        detail: Some(HubEventDetail::try_new(&format!(
                            "fotografia congelata: {report_id}"
                        ))?),
                    })),
                    Err(ServiceError::ReportSelectionOutsideSession) => {
                        Ok(CommandVerdict::Applied(CommandOutcome::Refused {
                            reason: HubEventDetail::try_new(
                                "la selezione contiene contenuti che questa sessione non ha \
                                 monitorato",
                            )?,
                        }))
                    }
                    Err(errore) => Err(errore),
                }
            })
    }

    /// Apre il pacchetto e fissa i fatti, riprovando l'identificativo preso.
    fn congela(
        &mut self,
        requested_by: &Actor,
        session_id: SessionId,
        selection: &ReportSelection,
        anno: i32,
        primo: u32,
        now: Timestamp,
    ) -> ServiceResult<ReportId> {
        let mut ultimo = None;
        for tentativo in 0..IDENTIFIER_ATTEMPTS {
            let report_id = ReportId::from_sequence(anno, primo.saturating_add(tentativo));
            let richiesta = ReportRequest {
                report_id: report_id.clone(),
                session_id,
                requested_by: requested_by.clone(),
                selection: selection.clone(),
                // Nessun genere: i documenti li produce chi sta sull'Hub,
                // quando li produce. Qui si congela la fotografia.
                requested_kinds: Vec::new(),
                // Nessun profilo salvato: la versione 0 lo dice invece di
                // inventarne una.
                template_version: 0,
                requested_at: now,
            };

            match self.relazioni.prepare(&richiesta) {
                Ok(_) => return Ok(report_id),
                Err(ServiceError::ReportSelectionOutsideSession) => {
                    return Err(ServiceError::ReportSelectionOutsideSession);
                }
                Err(errore) => ultimo = Some(errore),
            }
        }
        Err(ultimo.unwrap_or(ServiceError::HubServer {
            reason: String::from("l'identificativo della relazione non si è lasciato assegnare"),
        }))
    }
}
