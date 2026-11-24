//! «Questa fonte è ancora monitorata correttamente?»
//!
//! # Da dove viene l'osservazione
//!
//! Da `accessible_chats()`, l'operazione ufficiale che elenca le chat a cui
//! l'account **ha già** accesso — la stessa già usata quando si aggiunge una
//! fonte. Non cerca nulla, non fa entrare in alcun gruppo, e **una sola
//! chiamata verifica tutte le fonti configurate**: il costo verso Telegram non
//! cresce con il numero di fonti, e non c'è nulla da limitare in frequenza
//! oltre a quel che l'operatore chiede.
//!
//! # Che cosa si scrive, e che cosa si deriva
//!
//! Si scrivono **osservazioni**; lo stato si **deriva** da esse ogni volta che
//! serve. È la scelta di PROV-01 applicata alla salute: conservare lo stato
//! significherebbe avere una seconda copia che può divergere dai fatti che la
//! producono, e nessuno saprebbe quale credere.
//!
//! # Il costo della lettura
//!
//! L'elenco delle fonti con il loro stato costa **quattro interrogazioni in
//! tutto**, non quattro per fonte: le verifiche, i guasti, l'ultimo contenuto e
//! le fonti stesse si leggono in blocco.
//!
//! Il dettaglio di una fonte ne aggiunge **due**, e solo quando l'operatore lo
//! apre: la storia delle verifiche e gli account. Gli account si leggono qui e
//! non nell'elenco, perché sono l'evidenza che solo il pannello mostra: fino a
//! HEALTH-02 l'elenco li leggeva a ogni composizione e ne ignorava il
//! risultato, ed era una quinta interrogazione per un dato che nessuna riga
//! mostrava.

use std::collections::BTreeMap;

pub use lisi_core::model::source_health::{HealthCheckOutcome, HealthEvidence, SourceHealth};

use lisi_core::model::source_health::{derive, explain, silence_note};
use lisi_core::model::telegram_account::PersistedAuthStatus;
use lisi_core::model::{NewAuditEntry, Source, TelegramAccount};
use lisi_core::text::{Actor, AuditAction, AuditDetail, AuditEntity, DisplayName, counted};
use lisi_core::{SourceId, TelegramAccountId, Timestamp};
use lisi_storage::Database;
use lisi_storage::repository::source_health::{HealthCheck, NewHealthCheck};
use lisi_telegram::TelegramConnector;

use crate::error::ServiceResult;

/// Entità con cui la salute compare nell'audit.
const ENTITY_SOURCE: &str = "source";

/// Azione: l'account non ha più accesso a una fonte.
const ACTION_ACCESS_LOST: &str = "fonte.accesso_perduto";
/// Azione: l'accesso a una fonte è tornato.
const ACTION_ACCESS_REGAINED: &str = "fonte.accesso_ripristinato";

/// Quante verifiche si mostrano nel dettaglio di una fonte.
///
/// La storia può essere lunga; chi guarda vuole sapere che cosa è successo di
/// recente, non rileggere un anno di controlli riusciti.
pub const HISTORY_DEPTH: u32 = 20;

/// La salute di una fonte, con i fatti che l'hanno prodotta.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SourceHealthView {
    /// Fonte a cui lo stato appartiene.
    pub source_id: SourceId,
    /// Nome con cui l'operatore la conosce.
    pub display_name: DisplayName,
    /// Stato derivato.
    pub health: SourceHealth,
    /// I fatti da cui deriva.
    pub evidence: HealthEvidence,
}

impl SourceHealthView {
    /// Perché la fonte è in quello stato.
    #[must_use]
    pub fn why(&self) -> String {
        explain(&self.evidence, self.health)
    }

    /// Il silenzio della fonte, detto **separatamente** dallo stato.
    #[must_use]
    pub fn silence(&self) -> String {
        silence_note(&self.evidence)
    }

    /// Se lo stato chiede a una persona di guardare.
    #[must_use]
    pub const fn needs_attention(&self) -> bool {
        self.health.needs_attention()
    }
}

/// Riepilogo dell'insieme delle fonti configurate.
///
/// # Perché conta quante ne sono state verificate
///
/// Perché «tutte operative» detto di un insieme in cui metà non è mai stata
/// verificata è una frase falsa. Il congelamento di prodotto lo dice: si scrive
/// «14/15 fonti configurate operative», **mai** «copertura al 100%».
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct HealthSummary {
    /// Fonti configurate in tutto.
    pub total: usize,
    /// Operative.
    pub operational: usize,
    /// Degradate.
    pub degraded: usize,
    /// In errore.
    pub failed: usize,
    /// Mai verificate in modo conclusivo.
    pub unknown: usize,
    /// Ferme per scelta dell'operatore.
    pub stopped: usize,
}

impl HealthSummary {
    /// Quante fonti chiedono attenzione.
    #[must_use]
    pub const fn needing_attention(&self) -> usize {
        self.degraded + self.failed
    }

    /// Frase del riepilogo, nella forma che il congelamento prescrive.
    ///
    /// Dice **su quante** fonti si sta parlando, e non nasconde le sconosciute
    /// dietro una percentuale.
    #[must_use]
    pub fn as_sentence(&self) -> String {
        if self.total == 0 {
            return String::from("Nessuna fonte configurata.");
        }

        let mut frase = format!(
            "{}/{} fonti configurate operative",
            self.operational, self.total
        );
        if self.unknown > 0 {
            frase.push_str(&format!(
                ", {}",
                counted(
                    self.unknown,
                    "non ancora verificata",
                    "non ancora verificate"
                )
            ));
        }
        if self.needing_attention() > 0 {
            frase.push_str(&format!(", {} da guardare", self.needing_attention()));
        }
        if self.stopped > 0 {
            frase.push_str(&format!(
                ", {}",
                counted(self.stopped, "ferma per scelta", "ferme per scelta")
            ));
        }
        frase.push('.');
        frase
    }
}

/// Esito di una campagna di verifica.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct VerificationReport {
    /// Fonti osservate raggiungibili.
    pub reachable: usize,
    /// Fonti accessibili ma con lo storico non leggibile.
    pub history_unreadable: usize,
    /// Fonti che non compaiono più fra quelle accessibili.
    pub not_accessible: usize,
    /// Fonti per cui la verifica non è riuscita.
    pub check_failed: usize,
    /// Fonti ferme, che non si verificano.
    pub skipped_stopped: usize,
}

impl VerificationReport {
    /// Quante fonti sono state effettivamente osservate.
    #[must_use]
    pub const fn observed(&self) -> usize {
        self.reachable + self.history_unreadable + self.not_accessible
    }

    /// Frase che dice com'è andata, senza dichiarare più di quanto sia stato
    /// osservato.
    #[must_use]
    pub fn as_sentence(&self) -> String {
        if self.check_failed > 0 && self.observed() == 0 {
            return String::from(
                "La verifica non è riuscita: non è stato possibile leggere l'elenco delle \
                 chat accessibili. Nessuna fonte è stata osservata, e nessuno stato è \
                 cambiato.",
            );
        }

        let mut frase = counted(self.observed(), "fonte osservata", "fonti osservate");
        if self.reachable > 0 {
            frase.push_str(&format!(
                ", {}",
                counted(self.reachable, "raggiungibile", "raggiungibili")
            ));
        }
        if self.history_unreadable > 0 {
            frase.push_str(&format!(
                ", {} con lo storico non leggibile",
                self.history_unreadable
            ));
        }
        if self.not_accessible > 0 {
            frase.push_str(&format!(
                ", {}",
                counted(
                    self.not_accessible,
                    "non più accessibile",
                    "non più accessibili"
                )
            ));
        }
        if self.skipped_stopped > 0 {
            frase.push_str(&format!(
                ". {} verificate",
                lisi_core::text::counted(
                    self.skipped_stopped,
                    "fonte ferma non è stata",
                    "fonti ferme non sono state"
                )
            ));
        }
        frase.push('.');
        frase
    }
}

/// Un'osservazione registrata, con chi l'ha fatta.
///
/// # Perché l'autore sta sulla riga e non sulla fonte
///
/// Perché chi ha guardato lo dice l'osservazione. Se due account osservassero
/// la stessa fonte, la storia mostrerebbe entrambi invece di un finto stato
/// globale (ADR-0053 Decisione 7).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObservedCheck {
    /// Istante dell'osservazione.
    pub observed_at: Timestamp,
    /// Che cosa la verifica ha appreso.
    pub outcome: HealthCheckOutcome,
    /// Classe dell'errore o precisazione dell'esito.
    ///
    /// **Mai un testo remoto**: chi scrive queste righe registra la classe
    /// dell'errore, non il messaggio che Telegram ha restituito.
    pub detail: Option<String>,
    /// Etichetta locale dell'account che ha osservato.
    ///
    /// `None` quando l'osservazione non ne nomina uno, o quando quell'account
    /// non è più registrato sulla postazione.
    pub observer: Option<DisplayName>,
}

impl ObservedCheck {
    /// Se questa riga ha appreso qualcosa **della fonte**.
    #[must_use]
    pub const fn is_conclusive(&self) -> bool {
        self.outcome.is_conclusive()
    }

    /// La riga come l'operatore la legge: quando, e che cosa è successo.
    #[must_use]
    pub fn headline(&self) -> String {
        format!(
            "{} — {}",
            self.observed_at.to_readable_local(),
            self.outcome.as_sentence()
        )
    }

    /// Che cosa la riga dice **della fonte**, che non è la stessa cosa.
    #[must_use]
    pub const fn note(&self) -> &'static str {
        self.outcome.note_about_source()
    }

    /// Chi ha osservato, detto per esteso.
    #[must_use]
    pub fn observer_note(&self) -> String {
        self.observer.as_ref().map_or_else(
            || String::from("L'osservazione non nomina un account ancora registrato."),
            |label| format!("Osservata dall'account «{}».", label.as_str()),
        )
    }
}

/// L'account che ha fatto l'osservazione più recente, e la sua condizione.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObservingAccount {
    /// Etichetta locale con cui l'ufficio lo conosce.
    pub label: DisplayName,
    /// Se risulta autorizzato **adesso**.
    pub authorised: bool,
}

/// Il dettaglio di una fonte: lo stato che l'elenco mostra, e i fatti sotto.
///
/// # Che cosa questa struttura non fa
///
/// **Non deriva alcuno stato.** La vista arriva già composta da
/// [`SourceHealthService::overview`], e il dettaglio vi aggiunge la storia e
/// l'account. È la ragione per cui la riga dell'elenco e il pannello che si
/// apre da essa non possono dire due cose diverse.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SourceHealthDetail {
    /// La vista che l'elenco ha composto. Non ricomposta qui.
    pub view: SourceHealthView,
    /// Le ultime osservazioni, dalla più recente.
    pub checks: Vec<ObservedCheck>,
    /// L'account dell'osservazione più recente, quando ce n'è una.
    pub observer: Option<ObservingAccount>,
}

impl SourceHealthDetail {
    /// La condizione dell'account, **dichiarata** e non fatta valere.
    ///
    /// # Perché è una dichiarazione e non uno stato
    ///
    /// Un account non autorizzato non cambia ciò che fu osservato della chat:
    /// cambia se il monitoraggio possa funzionare **adesso**. La frase dice
    /// entrambe le cose e tiene separate le due, perché confonderle
    /// riscriverebbe il passato con il presente (ADR-0053 Decisione 7).
    #[must_use]
    pub fn account_note(&self) -> String {
        match &self.observer {
            Some(account) if account.authorised => format!(
                "Osservata dall'account «{}», che risulta autorizzato. La condizione \
                 dell'account non concorre allo stato: dice se una nuova verifica sia \
                 possibile adesso.",
                account.label.as_str()
            ),
            Some(account) => format!(
                "L'account «{}», che ha fatto l'ultima osservazione, non risulta \
                 autorizzato: finché non lo sarà, nessuna nuova verifica potrà essere \
                 eseguita. Ciò non cambia quanto è stato osservato prima.",
                account.label.as_str()
            ),
            None if self.checks.is_empty() => String::from(
                "Nessuna osservazione registrata: non risulta che alcun account abbia \
                 ancora guardato questa fonte.",
            ),
            None => String::from(
                "L'ultima osservazione non nomina un account ancora registrato sulla \
                 postazione: non si può dire se una nuova verifica sia possibile adesso.",
            ),
        }
    }

    /// Che cosa la storia mostra, e che cosa non mostra.
    ///
    /// Dichiara la profondità: un elenco troncato che non dica di esserlo
    /// farebbe credere che prima non sia successo nulla.
    #[must_use]
    pub fn history_note(&self) -> String {
        if self.checks.is_empty() {
            return String::from(
                "Nessuna verifica registrata per questa fonte. Non è un guasto: è \
                 l'assenza di osservazioni.",
            );
        }
        if self.checks.len() < HISTORY_DEPTH as usize {
            // Concordato col numero (BUG-UX-1: «1 verifiche registrate»).
            return format!(
                "{}, tutte mostrate.",
                lisi_core::text::counted(
                    self.checks.len(),
                    "verifica registrata",
                    "verifiche registrate"
                )
            );
        }
        format!("Le ultime {HISTORY_DEPTH} verifiche. Le precedenti non sono mostrate.")
    }

    /// Quante fra le righe mostrate non hanno appreso nulla della fonte.
    #[must_use]
    pub fn inconclusive(&self) -> usize {
        self.checks
            .iter()
            .filter(|riga| !riga.is_conclusive())
            .count()
    }
}

/// Compone e aggiorna la salute delle fonti.
#[derive(Debug)]
pub struct SourceHealthService {
    database: Database,
}

impl SourceHealthService {
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

    /// Database sottostante in scrittura, per la preparazione dei test.
    #[must_use]
    pub const fn database_mut(&mut self) -> &mut Database {
        &mut self.database
    }

    /// Restituisce il database, per riusarlo altrove.
    #[must_use]
    pub fn into_database(self) -> Database {
        self.database
    }

    /// Lo stato di tutte le fonti configurate.
    ///
    /// **Quattro interrogazioni in tutto**, non quattro per fonte.
    ///
    /// # Errori
    ///
    /// Restituisce l'errore della persistenza se una lettura non riesce.
    pub fn overview(&self) -> ServiceResult<Vec<SourceHealthView>> {
        overview_of(&self.database)
    }

    /// Riepilogo dell'insieme, contato sugli stati derivati.
    ///
    /// # Errori
    ///
    /// Come [`Self::overview`].
    pub fn summary(&self) -> ServiceResult<HealthSummary> {
        let views = self.overview()?;

        let mut summary = HealthSummary {
            total: views.len(),
            ..HealthSummary::default()
        };
        for view in &views {
            match view.health {
                SourceHealth::Operational => summary.operational += 1,
                SourceHealth::Degraded => summary.degraded += 1,
                SourceHealth::Failed => summary.failed += 1,
                SourceHealth::Unknown => summary.unknown += 1,
                SourceHealth::Stopped => summary.stopped += 1,
            }
        }
        Ok(summary)
    }

    /// Le ultime verifiche di una fonte, dalla più recente.
    ///
    /// **Non scrive nulla.** Aprire il dettaglio è una lettura.
    ///
    /// # Errori
    ///
    /// Come [`Self::overview`].
    pub fn history(&self, source_id: SourceId) -> ServiceResult<Vec<HealthCheck>> {
        Ok(self
            .database
            .source_health_checks(source_id, HISTORY_DEPTH)?)
    }

    /// Il dettaglio di **una** fonte, per il pannello che l'operatore apre.
    ///
    /// # Perché riceve la vista invece di ricomporla
    ///
    /// Perché la riga dell'elenco e il pannello che si apre da quella riga
    /// **non devono poter dire due cose diverse** sulla stessa fonte.
    /// Ricomporre lo stato qui creerebbe una seconda derivazione: nel tempo che
    /// separa il disegno dell'elenco dall'apertura del pannello, un'altra
    /// verifica potrebbe essere stata registrata, e l'operatore leggerebbe
    /// «Operativa» nella riga e «In errore» nel pannello senza sapere quale
    /// delle due valga.
    ///
    /// Il pannello **aggiunge** fatti; non ne rivede nessuno.
    ///
    /// # Che cosa costa
    ///
    /// **Due letture**, e solo all'apertura: le ultime
    /// [`HISTORY_DEPTH`] osservazioni, e gli account — che si leggono qui e
    /// **non** nell'elenco, perché sono l'evidenza che solo il pannello mostra
    /// (ADR-0053 Decisione 7).
    ///
    /// # Non scrive nulla
    ///
    /// Consultare è una lettura: se aprire il pannello registrasse
    /// un'osservazione, la storia di una fonte si riempirebbe di righe che
    /// nessuno ha chiesto, proprio nella schermata che quella storia mostra.
    ///
    /// # Errori
    ///
    /// Restituisce l'errore della persistenza se una lettura non riesce.
    pub fn detail(&self, view: &SourceHealthView) -> ServiceResult<SourceHealthDetail> {
        let righe = self.history(view.source_id)?;
        let account = self.accounts()?;

        // L'account di cui il pannello dichiara la condizione è quello
        // dell'osservazione **più recente**: è l'unico che dica qualcosa su
        // che cosa possa essere verificato adesso. Le osservazioni più
        // vecchie restano nella storia con il proprio autore accanto.
        let observer = righe
            .first()
            .and_then(|riga| riga.account_id)
            .and_then(|id| account.get(&id))
            .map(|(label, autorizzato)| ObservingAccount {
                label: label.clone(),
                authorised: *autorizzato,
            });

        let checks: Vec<ObservedCheck> = righe
            .into_iter()
            .map(|riga| ObservedCheck {
                observed_at: riga.observed_at,
                outcome: riga.outcome,
                detail: riga.detail,
                observer: riga
                    .account_id
                    .and_then(|id| account.get(&id).map(|(label, _)| label.clone())),
            })
            .collect();

        Ok(SourceHealthDetail {
            view: view.clone(),
            checks,
            observer,
        })
    }

    /// Etichetta e condizione di ogni account, per identificativo.
    fn accounts(&self) -> ServiceResult<BTreeMap<i64, (DisplayName, bool)>> {
        let accounts: Vec<TelegramAccount> = self.database.telegram_accounts()?;
        Ok(accounts
            .into_iter()
            .map(|account| {
                (
                    account.id.get(),
                    (
                        account.label,
                        matches!(account.auth_status, PersistedAuthStatus::Authorized),
                    ),
                )
            })
            .collect())
    }

    /// Verifica tutte le fonti configurate con **una sola** chiamata a Telegram.
    ///
    /// # Che cosa succede quando l'elenco non si può leggere
    ///
    /// Si registra un tentativo non riuscito per ciascuna fonte attiva, e
    /// **nessuno stato cambia**: non aver potuto guardare non è aver visto un
    /// guasto. La differenza è il cuore di questa milestone.
    ///
    /// # Le fonti ferme non si verificano
    ///
    /// Una fonte disattivata dall'operatore è esattamente ciò che l'operatore
    /// ha voluto: interrogare Telegram per essa spenderebbe una richiesta per
    /// confermare una scelta già presa.
    ///
    /// # Errori
    ///
    /// Restituisce l'errore della persistenza se una scrittura non riesce. Un
    /// errore del connettore **non** è un errore di questa funzione: diventa un
    /// tentativo non riuscito, registrato.
    pub fn verify_all(
        &self,
        connector: &mut dyn TelegramConnector,
        account_id: Option<TelegramAccountId>,
        actor: &Actor,
        now: Timestamp,
    ) -> ServiceResult<VerificationReport> {
        let sources = self.database.sources()?;
        let precedenti = self.database.health_facts()?;

        let elenco = connector.accessible_chats();
        let mut report = VerificationReport::default();

        for source in &sources {
            if !source.active {
                report.skipped_stopped += 1;
                continue;
            }

            let (outcome, detail) = match &elenco {
                Ok(chats) => observe(source, chats),
                // La classe dell'errore, non il suo testo: un messaggio remoto
                // non entra nell'archivio.
                Err(_) => (
                    HealthCheckOutcome::CheckFailed,
                    Some(String::from("elenco delle chat non leggibile")),
                ),
            };

            match outcome {
                HealthCheckOutcome::Reachable => report.reachable += 1,
                HealthCheckOutcome::HistoryUnreadable => report.history_unreadable += 1,
                HealthCheckOutcome::NotAccessible => report.not_accessible += 1,
                HealthCheckOutcome::CheckFailed => report.check_failed += 1,
            }

            self.database.insert_health_check(
                &NewHealthCheck {
                    source_id: source.id,
                    account_id: account_id.map(TelegramAccountId::get),
                    outcome,
                    detail,
                },
                now,
            )?;

            self.audit_transition(
                source,
                precedenti
                    .get(&source.id.get())
                    .and_then(|f| f.last_conclusive),
                outcome,
                actor,
                now,
            )?;
        }

        Ok(report)
    }

    /// Registra nell'audit **solo** i passaggi che una persona deve sapere.
    ///
    /// # Perché non ogni verifica
    ///
    /// Perché una verifica riuscita che conferma una verifica riuscita non è un
    /// fatto: è la normalità. Registrarla gonfierebbe il registro con righe che
    /// nessuno leggerà, rendendo più difficile trovarci le azioni vere — la
    /// stessa ragione di ADR-0051 Decisione 5.
    ///
    /// Restano due passaggi, e sono quelli che cambiano che cosa l'ufficio può
    /// fare: **l'accesso perduto** e **l'accesso ripristinato**.
    fn audit_transition(
        &self,
        source: &Source,
        precedente: Option<(HealthCheckOutcome, Timestamp)>,
        adesso: HealthCheckOutcome,
        actor: &Actor,
        now: Timestamp,
    ) -> ServiceResult<()> {
        let prima = precedente.map(|(outcome, _)| outcome);

        let azione = match (prima, adesso) {
            // Perdita d'accesso: prima si poteva, adesso no.
            (
                Some(HealthCheckOutcome::Reachable | HealthCheckOutcome::HistoryUnreadable),
                HealthCheckOutcome::NotAccessible,
            ) => ACTION_ACCESS_LOST,
            // Ripristino: prima non si poteva, adesso sì.
            (Some(HealthCheckOutcome::NotAccessible), HealthCheckOutcome::Reachable) => {
                ACTION_ACCESS_REGAINED
            }
            // Tutto il resto non e' un passaggio da registrare, compresa la
            // prima verifica in assoluto: scoprire com'e' fatta una fonte non
            // e' un cambiamento.
            _ => return Ok(()),
        };

        let entry = NewAuditEntry {
            actor: actor.clone(),
            action: AuditAction::try_new(azione)?,
            entity: AuditEntity::try_new(ENTITY_SOURCE)?,
            entity_id: Some(source.id.get()),
            // La salute delle fonti non conosce la modalita' operativa, che
            // vive nel servizio dei dizionari: registrarne una qui sarebbe
            // inventarla.
            actor_mode: None,
            detail: Some(AuditDetail::try_new(&format!(
                "fonte {}: {}",
                source.id.get(),
                adesso.as_sentence()
            ))?),
            recorded_at: now,
        };
        self.database.append_audit(&entry)?;
        Ok(())
    }
}

/// Che cosa l'elenco dice di questa fonte.
fn observe(
    source: &Source,
    chats: &[lisi_telegram::AccessibleChat],
) -> (HealthCheckOutcome, Option<String>) {
    // L'identificativo della fonte e' l'identificativo della chat presso la
    // piattaforma. Se non e' un numero, la fonte non e' confrontabile con
    // l'elenco: non si e' appreso nulla di essa.
    let Ok(chat_id) = source.identifier.as_str().parse::<i64>() else {
        return (
            HealthCheckOutcome::CheckFailed,
            Some(String::from("identificativo della fonte non confrontabile")),
        );
    };

    let Some(chat) = chats
        .iter()
        .find(|candidate| candidate.chat_id.get() == chat_id)
    else {
        return (
            HealthCheckOutcome::NotAccessible,
            Some(String::from("non presente fra le chat accessibili")),
        );
    };

    if chat.is_monitorable() {
        (HealthCheckOutcome::Reachable, None)
    } else {
        (
            HealthCheckOutcome::HistoryUnreadable,
            Some(String::from("storico non leggibile dall'account")),
        )
    }
}

/// Lo stato di tutte le fonti configurate, sull'archivio indicato: la stessa
/// derivazione di [`SourceHealthService::overview`], per chi ha già l'archivio
/// (il passaggio di consegne, PR-12).
///
/// **Quattro interrogazioni in tutto**, non quattro per fonte.
///
/// # Errori
///
/// Restituisce l'errore della persistenza se una lettura non riesce.
pub(crate) fn overview_of(database: &Database) -> ServiceResult<Vec<SourceHealthView>> {
    let sources = database.sources()?;
    let verifiche = database.health_facts()?;
    let guasti = database.faults_per_source_since()?;
    let contenuti = database.last_content_per_source()?;

    // Gli account NON si leggono qui. La condizione dell'account non entra
    // nella derivazione (ADR-0053 Decisione 7) e non compare nell'elenco:
    // leggerla per ogni composizione dell'elenco sarebbe una quinta
    // interrogazione per un dato che nessuna riga mostra. La legge il
    // pannello, quando l'operatore lo apre.
    Ok(sources
        .into_iter()
        .map(|source| {
            let evidence = compose_evidence(
                &source,
                verifiche.get(&source.id.get()),
                guasti.get(&source.id.get()),
                contenuti.get(&source.id.get()).copied(),
            );
            SourceHealthView {
                source_id: source.id,
                display_name: source.display_name,
                health: derive(&evidence),
                evidence,
            }
        })
        .collect())
}

/// Mette insieme i fatti di una fonte.
fn compose_evidence(
    source: &Source,
    verifiche: Option<&lisi_storage::repository::source_health::StoredHealthFacts>,
    guasti: Option<&Vec<Timestamp>>,
    ultimo_contenuto: Option<Timestamp>,
) -> HealthEvidence {
    let last_conclusive = verifiche.and_then(|f| f.last_conclusive);

    // I guasti che contano sono quelli avvenuti DOPO l'ultima osservazione
    // conclusiva: quelli di prima sono gia' stati superati da essa.
    let faults_since = last_conclusive.map_or(0, |(_, istante)| {
        guasti.map_or(0, |elenco| {
            u32::try_from(elenco.iter().filter(|guasto| **guasto > istante).count())
                .unwrap_or(u32::MAX)
        })
    });

    HealthEvidence {
        active: source.active,
        last_conclusive,
        last_attempt_at: verifiche.and_then(|f| f.last_attempt_at),
        failed_attempts_since: verifiche.map_or(0, |f| f.failed_attempts_since),
        faults_since,
        last_content_at: ultimo_contenuto,
        // La fonte non porta un account nei dati odierni: la colonna esiste
        // dalla migrazione 0009 e nessuna riga di codice la valorizza. Chi ha
        // osservato lo dice la VERIFICA, non la fonte, ed e' li' che il
        // pannello lo legge.
        account_authorised: None,
    }
}

#[cfg(test)]
mod tests {
    use lisi_core::model::source_health::{HealthCheckOutcome, SourceHealth};
    use lisi_core::model::{NewFault, NewSource, SourceKind};
    use lisi_core::text::{Actor, DisplayName, SourceIdentifier};
    use lisi_core::{SourceId, Timestamp};
    use lisi_storage::Database;
    use lisi_storage::repository::source_health::NewHealthCheck;
    use lisi_telegram::{
        AccessibleChat, ApiHash, ApiId, ChatId, ChatKind, ClientParameters, LoginCode,
        MockTelegramConnector, PhoneNumber, TelegramConnector,
    };

    use super::{HISTORY_DEPTH, SourceHealthService, SourceHealthView};
    use crate::sources::open_in_memory_database;

    fn now() -> Timestamp {
        Timestamp::from_millis(1_700_000_000_000)
    }

    fn operator() -> Actor {
        let Ok(value) = Actor::try_new("operatore.prova") else {
            panic!("l'attore di prova deve essere valido");
        };
        value
    }

    /// Servizio con le fonti indicate, identificate dal proprio chat id.
    fn service_with(sources: &[(i64, &str, bool)]) -> (SourceHealthService, Vec<SourceId>) {
        let Ok(database) = open_in_memory_database() else {
            panic!("il database in memoria deve potersi aprire");
        };
        let database: Database = database;

        let mut identificativi = Vec::new();
        for (chat_id, nome, attiva) in sources {
            let (Ok(identifier), Ok(display_name)) = (
                SourceIdentifier::try_new(&chat_id.to_string()),
                DisplayName::try_new(nome),
            ) else {
                panic!("i valori di prova devono essere validi");
            };
            let Ok(id) = database.insert_source(
                &NewSource {
                    kind: SourceKind::Channel,
                    identifier,
                    display_name,
                    authorized_by: operator(),
                    active: *attiva,
                },
                now(),
            ) else {
                panic!("la fonte deve potersi registrare");
            };
            identificativi.push(id);
        }

        (SourceHealthService::new(database), identificativi)
    }

    /// Connettore simulato, autorizzato, che espone le chat indicate.
    fn connector_with(chats: &[(i64, bool)]) -> MockTelegramConnector {
        let accessibili: Vec<AccessibleChat> = chats
            .iter()
            .map(|(chat_id, leggibile)| {
                let Ok(chat_id) = ChatId::try_new(*chat_id) else {
                    panic!("l'identificativo di prova deve essere valido");
                };
                AccessibleChat {
                    chat_id,
                    title: String::from("Canale di prova"),
                    kind: ChatKind::Channel,
                    username: None,
                    can_read_history: *leggibile,
                }
            })
            .collect();

        let mut connector = MockTelegramConnector::new().with_accessible_chats(accessibili);
        autorizza(&mut connector);
        connector
    }

    /// Porta il connettore simulato allo stato autorizzato.
    fn autorizza(connector: &mut MockTelegramConnector) {
        let (Ok(api_id), Ok(api_hash)) = (
            ApiId::try_new(1),
            ApiHash::try_new("00000000000000000000000000000000"),
        ) else {
            panic!("i valori fittizi devono essere validi");
        };
        let parameters = ClientParameters {
            api_id,
            api_hash,
            database_directory: std::path::PathBuf::from("prova"),
            use_test_datacenter: true,
            application_version: String::from("0.1.0"),
            system_language_code: String::from("it"),
        };
        let (Ok(phone), Ok(code)) = (
            PhoneNumber::try_new("+390612345678"),
            LoginCode::try_new("12345"),
        ) else {
            panic!("i valori fittizi devono essere validi");
        };
        let (Ok(()), Ok(()), Ok(())) = (
            connector.start(&parameters),
            connector.submit_phone_number(&phone),
            connector.submit_code(&code),
        ) else {
            panic!("l'accesso simulato deve riuscire");
        };
    }

    #[test]
    fn una_fonte_appena_configurata_e_sconosciuta_non_operativa() {
        // «Non risultano errori» non e' «funziona».
        let (service, _) = service_with(&[(-1_001, "Canale", true)]);

        let Ok(viste) = service.overview() else {
            panic!("l'elenco deve potersi comporre");
        };
        assert_eq!(viste.len(), 1);
        assert_eq!(viste[0].health, SourceHealth::Unknown);
        assert!(!viste[0].needs_attention());
        assert!(viste[0].why().contains("Mai verificata"));
    }

    #[test]
    fn una_verifica_riuscita_rende_la_fonte_operativa() {
        let (service, _) = service_with(&[(-1_001, "Canale", true)]);
        let mut connector = connector_with(&[(-1_001, true)]);

        let Ok(report) = service.verify_all(&mut connector, None, &operator(), now()) else {
            panic!("la verifica deve riuscire");
        };
        assert_eq!(report.reachable, 1);
        assert_eq!(report.observed(), 1);

        let Ok(viste) = service.overview() else {
            panic!("l'elenco deve potersi comporre");
        };
        assert_eq!(viste[0].health, SourceHealth::Operational);
        assert!(viste[0].why().contains("storico leggibile"));
    }

    #[test]
    fn una_fonte_che_non_compare_piu_nell_elenco_va_in_errore() {
        let (service, _) = service_with(&[(-1_001, "Canale", true)]);
        // L'elenco si legge, e la fonte NON c'e': e' una risposta, non un
        // errore di rete.
        let mut connector = connector_with(&[(-1_999, true)]);

        let Ok(report) = service.verify_all(&mut connector, None, &operator(), now()) else {
            panic!("la verifica deve riuscire");
        };
        assert_eq!(report.not_accessible, 1);

        let Ok(viste) = service.overview() else {
            panic!("l'elenco deve potersi comporre");
        };
        assert_eq!(viste[0].health, SourceHealth::Failed);
        assert!(viste[0].needs_attention());
        assert!(viste[0].why().contains("non vi compariva"));
    }

    #[test]
    fn una_fonte_con_lo_storico_non_leggibile_e_degradata_non_in_errore() {
        let (service, _) = service_with(&[(-1_001, "Canale", true)]);
        let mut connector = connector_with(&[(-1_001, false)]);

        let Ok(report) = service.verify_all(&mut connector, None, &operator(), now()) else {
            panic!("la verifica deve riuscire");
        };
        assert_eq!(report.history_unreadable, 1);

        let Ok(viste) = service.overview() else {
            panic!("l'elenco deve potersi comporre");
        };
        assert_eq!(viste[0].health, SourceHealth::Degraded);
        assert_ne!(viste[0].health, SourceHealth::Failed);
    }

    #[test]
    fn quando_l_elenco_non_si_legge_nessuno_stato_cambia() {
        // E' il cuore della milestone: non aver potuto guardare NON e' aver
        // visto un guasto.
        let (service, _) = service_with(&[(-1_001, "Canale", true)]);

        // Prima una verifica riuscita.
        let mut buono = connector_with(&[(-1_001, true)]);
        let Ok(_) = service.verify_all(&mut buono, None, &operator(), now()) else {
            panic!("la prima verifica deve riuscire");
        };

        // Poi un connettore NON autorizzato: l'elenco non si legge.
        let mut rotto = MockTelegramConnector::new();
        let Ok(report) = service.verify_all(
            &mut rotto,
            None,
            &operator(),
            Timestamp::from_millis(1_700_000_100_000),
        ) else {
            panic!("la funzione non deve fallire quando fallisce il connettore");
        };
        assert_eq!(report.check_failed, 1);
        assert_eq!(report.observed(), 0);
        assert!(report.as_sentence().contains("nessuno stato è cambiato"));

        let Ok(viste) = service.overview() else {
            panic!("l'elenco deve potersi comporre");
        };
        // Lo stato scende a «degradata» perche' l'osservazione buona e' meno
        // recente — ma NON diventa «in errore», e la ragione lo dice.
        assert_eq!(viste[0].health, SourceHealth::Degraded);
        assert_ne!(viste[0].health, SourceHealth::Failed);
        assert!(viste[0].why().contains("non hanno appreso nulla"));
    }

    #[test]
    fn una_fonte_ferma_non_si_verifica_e_non_e_un_guasto() {
        let (service, _) = service_with(&[(-1_001, "Canale spento", false)]);
        // L'elenco non contiene la fonte: se la si verificasse, risulterebbe
        // «in errore». Non la si verifica.
        let mut connector = connector_with(&[(-1_999, true)]);

        let Ok(report) = service.verify_all(&mut connector, None, &operator(), now()) else {
            panic!("la verifica deve riuscire");
        };
        assert_eq!(report.skipped_stopped, 1);
        assert_eq!(report.observed(), 0);

        let Ok(viste) = service.overview() else {
            panic!("l'elenco deve potersi comporre");
        };
        assert_eq!(viste[0].health, SourceHealth::Stopped);
        assert!(!viste[0].needs_attention());
    }

    #[test]
    fn un_ripristino_riporta_la_fonte_operativa() {
        let (service, _) = service_with(&[(-1_001, "Canale", true)]);

        // Accesso perduto.
        let mut assente = connector_with(&[(-1_999, true)]);
        let Ok(_) = service.verify_all(&mut assente, None, &operator(), now()) else {
            panic!("la verifica deve riuscire");
        };
        let Ok(viste) = service.overview() else {
            panic!("l'elenco deve potersi comporre");
        };
        assert_eq!(viste[0].health, SourceHealth::Failed);

        // Accesso ripristinato.
        let mut tornato = connector_with(&[(-1_001, true)]);
        let Ok(_) = service.verify_all(
            &mut tornato,
            None,
            &operator(),
            Timestamp::from_millis(1_700_000_100_000),
        ) else {
            panic!("la verifica deve riuscire");
        };
        let Ok(viste) = service.overview() else {
            panic!("l'elenco deve potersi comporre");
        };
        assert_eq!(viste[0].health, SourceHealth::Operational);
    }

    #[test]
    fn solo_la_perdita_e_il_ripristino_dell_accesso_entrano_nell_audit() {
        // Una verifica riuscita che conferma una verifica riuscita non e' un
        // fatto: e' la normalita'.
        let (service, _) = service_with(&[(-1_001, "Canale", true)]);
        let mut presente = connector_with(&[(-1_001, true)]);
        let mut assente = connector_with(&[(-1_999, true)]);

        let Ok(prima) = service.database().audit_entries().map(|e| e.len()) else {
            panic!("l'audit deve potersi leggere");
        };

        // Prima verifica: scoprire com'e' fatta una fonte non e' un cambiamento.
        let Ok(_) = service.verify_all(&mut presente, None, &operator(), now()) else {
            panic!("la verifica deve riuscire");
        };
        // Seconda verifica identica: nemmeno.
        let Ok(_) = service.verify_all(
            &mut presente,
            None,
            &operator(),
            Timestamp::from_millis(1_700_000_100_000),
        ) else {
            panic!("la verifica deve riuscire");
        };
        let Ok(dopo_due_buone) = service.database().audit_entries().map(|e| e.len()) else {
            panic!("l'audit deve potersi leggere");
        };
        assert_eq!(
            prima, dopo_due_buone,
            "due verifiche riuscite non devono lasciare righe di audit"
        );

        // Perdita d'accesso: QUESTA si registra.
        let Ok(_) = service.verify_all(
            &mut assente,
            None,
            &operator(),
            Timestamp::from_millis(1_700_000_200_000),
        ) else {
            panic!("la verifica deve riuscire");
        };
        let Ok(dopo_perdita) = service.database().audit_entries().map(|e| e.len()) else {
            panic!("l'audit deve potersi leggere");
        };
        assert_eq!(dopo_perdita, dopo_due_buone + 1);

        // Ripristino: anche questo.
        let Ok(_) = service.verify_all(
            &mut presente,
            None,
            &operator(),
            Timestamp::from_millis(1_700_000_300_000),
        ) else {
            panic!("la verifica deve riuscire");
        };
        let Ok(dopo_ripristino) = service.database().audit_entries().map(|e| e.len()) else {
            panic!("l'audit deve potersi leggere");
        };
        assert_eq!(dopo_ripristino, dopo_perdita + 1);
    }

    #[test]
    fn consultare_la_salute_non_scrive_nulla() {
        let (service, identificativi) = service_with(&[(-1_001, "Canale", true)]);
        let mut connector = connector_with(&[(-1_001, true)]);
        let Ok(_) = service.verify_all(&mut connector, None, &operator(), now()) else {
            panic!("la verifica deve riuscire");
        };

        let (Ok(audit_prima), Ok(verifiche_prima)) = (
            service.database().audit_entries().map(|e| e.len()),
            service
                .database()
                .source_health_checks(identificativi[0], 100),
        ) else {
            panic!("le letture devono riuscire");
        };

        for _ in 0..3 {
            let Ok(_) = service.overview() else {
                panic!("l'elenco deve potersi comporre");
            };
            let Ok(_) = service.summary() else {
                panic!("il riepilogo deve potersi comporre");
            };
            let Ok(_) = service.history(identificativi[0]) else {
                panic!("la storia deve potersi leggere");
            };
        }

        let (Ok(audit_dopo), Ok(verifiche_dopo)) = (
            service.database().audit_entries().map(|e| e.len()),
            service
                .database()
                .source_health_checks(identificativi[0], 100),
        ) else {
            panic!("le letture devono riuscire");
        };
        assert_eq!(audit_prima, audit_dopo, "consultare non tocca l'audit");
        assert_eq!(
            verifiche_prima.len(),
            verifiche_dopo.len(),
            "consultare non aggiunge verifiche"
        );
    }

    #[test]
    fn un_guasto_dopo_una_verifica_buona_degrada_la_fonte() {
        let (service, identificativi) = service_with(&[(-1_001, "Canale", true)]);
        let mut connector = connector_with(&[(-1_001, true)]);
        let Ok(_) = service.verify_all(&mut connector, None, &operator(), now()) else {
            panic!("la verifica deve riuscire");
        };

        let Ok(_) = service.database().insert_fault(&NewFault {
            session_id: None,
            source_id: Some(identificativi[0]),
            kind: lisi_core::model::FaultKind::Network,
            message: lisi_core::text::FaultMessage::try_new("errore di prova")
                .expect("messaggio valido"),
            occurred_at: Timestamp::from_millis(1_700_000_500_000),
        }) else {
            panic!("il guasto deve potersi registrare");
        };

        let Ok(viste) = service.overview() else {
            panic!("l'elenco deve potersi comporre");
        };
        assert_eq!(viste[0].health, SourceHealth::Degraded);
        assert!(viste[0].why().contains("guasto/i"));
    }

    #[test]
    fn un_guasto_anteriore_alla_verifica_non_degrada_nulla() {
        // La verifica buona e' successiva: ha gia' superato quel guasto.
        let (service, identificativi) = service_with(&[(-1_001, "Canale", true)]);

        let Ok(_) = service.database().insert_fault(&NewFault {
            session_id: None,
            source_id: Some(identificativi[0]),
            kind: lisi_core::model::FaultKind::Network,
            message: lisi_core::text::FaultMessage::try_new("errore anteriore")
                .expect("messaggio valido"),
            occurred_at: Timestamp::from_millis(1_600_000_000_000),
        }) else {
            panic!("il guasto deve potersi registrare");
        };

        let mut connector = connector_with(&[(-1_001, true)]);
        let Ok(_) = service.verify_all(&mut connector, None, &operator(), now()) else {
            panic!("la verifica deve riuscire");
        };

        let Ok(viste) = service.overview() else {
            panic!("l'elenco deve potersi comporre");
        };
        assert_eq!(viste[0].health, SourceHealth::Operational);
    }

    #[test]
    fn il_riepilogo_non_nasconde_le_fonti_mai_verificate() {
        // «Tutte operative» detto di un insieme in cui meta' non e' mai stata
        // verificata e' una frase falsa.
        let (service, _) = service_with(&[
            (-1_001, "Verificata", true),
            (-1_002, "Mai vista", true),
            (-1_003, "Spenta", false),
        ]);
        // Solo la prima entra nell'elenco delle accessibili; la seconda resta
        // non verificata perche' la si verifica ma... no: verify_all le verifica
        // tutte le attive. Si verifica quindi con un elenco che contiene solo
        // la prima, e la seconda risultera' non accessibile.
        //
        // Per avere una fonte MAI verificata si registra la verifica soltanto
        // per la prima, a mano.
        let Ok(viste) = service.overview() else {
            panic!("l'elenco deve potersi comporre");
        };
        let Some(prima) = viste.first() else {
            panic!("la prima fonte deve esserci");
        };
        let Ok(_) = service.database().insert_health_check(
            &NewHealthCheck {
                source_id: prima.source_id,
                account_id: None,
                outcome: HealthCheckOutcome::Reachable,
                detail: None,
            },
            now(),
        ) else {
            panic!("la verifica deve potersi registrare");
        };

        let Ok(riepilogo) = service.summary() else {
            panic!("il riepilogo deve potersi comporre");
        };
        assert_eq!(riepilogo.total, 3);
        assert_eq!(riepilogo.operational, 1);
        assert_eq!(riepilogo.unknown, 1);
        assert_eq!(riepilogo.stopped, 1);

        let frase = riepilogo.as_sentence();
        assert!(frase.contains("1/3 fonti configurate operative"));
        // UN NUMERO, IL SUO NOME (E2E01-15): «1 ferme per scelta» era sullo
        // schermo, e questa prova lo chiedeva.
        assert!(frase.contains("1 non ancora verificata"), "{frase}");
        assert!(frase.contains("1 ferma per scelta"), "{frase}");
        // E non dichiara mai una copertura.
        assert!(!frase.contains("100%"));
        assert!(!frase.contains("copertura"));
    }

    /// **Una fonte sola si dice al singolare** (E2E01-15): «1 raggiungibili» era
    /// sullo schermo.
    #[test]
    fn la_verifica_di_una_fonte_si_dice_al_singolare() {
        let esito = super::VerificationReport {
            reachable: 1,
            not_accessible: 1,
            ..super::VerificationReport::default()
        };
        let frase = esito.as_sentence();
        assert!(frase.contains("1 raggiungibile,"), "{frase}");
        assert!(frase.contains("1 non più accessibile."), "{frase}");
    }

    #[test]
    fn la_storia_di_una_fonte_si_legge_dalla_piu_recente() {
        let (service, identificativi) = service_with(&[(-1_001, "Canale", true)]);

        for (millis, outcome) in [
            (1_700_000_000_000_i64, HealthCheckOutcome::Reachable),
            (1_700_000_100_000, HealthCheckOutcome::NotAccessible),
            (1_700_000_200_000, HealthCheckOutcome::Reachable),
        ] {
            let Ok(_) = service.database().insert_health_check(
                &NewHealthCheck {
                    source_id: identificativi[0],
                    account_id: None,
                    outcome,
                    detail: None,
                },
                Timestamp::from_millis(millis),
            ) else {
                panic!("la verifica deve potersi registrare");
            };
        }

        let Ok(storia) = service.history(identificativi[0]) else {
            panic!("la storia deve potersi leggere");
        };
        assert_eq!(storia.len(), 3);
        assert_eq!(storia[0].outcome, HealthCheckOutcome::Reachable);
        assert_eq!(
            storia[0].observed_at,
            Timestamp::from_millis(1_700_000_200_000)
        );
        assert_eq!(storia[2].outcome, HealthCheckOutcome::Reachable);
    }

    #[test]
    fn la_verifica_registra_quale_account_ha_osservato() {
        // Chi ha osservato lo dice la VERIFICA, non la fonte: e' il principio
        // di PROV-01 applicato alla salute.
        let (mut service, identificativi) = service_with(&[(-1_001, "Canale", true)]);
        let mut connector = connector_with(&[(-1_001, true)]);

        // Un account vero: la chiave esterna rifiuta un osservatore che non
        // esiste, ed e' giusto — registrare un'osservazione fatta da nessuno
        // sarebbe provenienza inventata.
        let (Ok(etichetta), Ok(uuid)) = (
            DisplayName::try_new("Account di prova"),
            lisi_core::model::telegram_account::AccountUuid::from_hex(
                "0123456789abcdef0123456789abcdef",
            ),
        ) else {
            panic!("i valori di prova devono essere validi");
        };
        let Ok(profile_id) = service.database_mut().insert_api_profile(
            &lisi_core::model::telegram_account::NewApiCredentialProfile {
                label: DisplayName::try_new("Profilo").expect("etichetta valida"),
            },
            now(),
        ) else {
            panic!("il profilo deve potersi registrare");
        };
        let Ok(account_id) = service.database_mut().insert_telegram_account(
            &lisi_core::model::telegram_account::NewTelegramAccount {
                uuid,
                label: etichetta,
                profile_id,
            },
            now(),
        ) else {
            panic!("l'account deve potersi registrare");
        };

        let Ok(_) = service.verify_all(&mut connector, Some(account_id), &operator(), now()) else {
            panic!("la verifica deve riuscire");
        };

        let Ok(storia) = service.history(identificativi[0]) else {
            panic!("la storia deve potersi leggere");
        };
        assert_eq!(storia[0].account_id, Some(account_id.get()));
    }

    // ------------------------------------------------------------------
    // HEALTH-02 — il pannello di dettaglio
    // ------------------------------------------------------------------

    /// Registra un account sulla postazione e ne fissa la condizione.
    fn register_account(
        service: &mut SourceHealthService,
        label: &str,
        autorizzato: bool,
    ) -> lisi_core::TelegramAccountId {
        let (Ok(etichetta), Ok(uuid)) = (
            DisplayName::try_new(label),
            lisi_core::model::telegram_account::AccountUuid::from_hex(
                "0123456789abcdef0123456789abcdef",
            ),
        ) else {
            panic!("i valori di prova devono essere validi");
        };
        let Ok(profile_id) = service.database_mut().insert_api_profile(
            &lisi_core::model::telegram_account::NewApiCredentialProfile {
                label: DisplayName::try_new("Profilo").expect("etichetta valida"),
            },
            now(),
        ) else {
            panic!("il profilo deve potersi registrare");
        };
        let Ok(account_id) = service.database_mut().insert_telegram_account(
            &lisi_core::model::telegram_account::NewTelegramAccount {
                uuid,
                label: etichetta,
                profile_id,
            },
            now(),
        ) else {
            panic!("l'account deve potersi registrare");
        };

        if autorizzato {
            let Ok(()) = service.database_mut().update_account_state(
                account_id,
                lisi_core::model::telegram_account::PersistedAuthStatus::Authorized,
                lisi_core::model::telegram_account::PersistedConnectionStatus::Connected,
                None,
                None,
                now(),
            ) else {
                panic!("la condizione dell'account deve potersi scrivere");
            };
        }

        account_id
    }

    /// La vista della prima fonte, come l'elenco la compone.
    fn prima_vista(service: &SourceHealthService) -> SourceHealthView {
        let Ok(viste) = service.overview() else {
            panic!("l'elenco deve potersi comporre");
        };
        let Some(vista) = viste.into_iter().next() else {
            panic!("deve esserci almeno una fonte");
        };
        vista
    }

    /// Il pannello non ricompone lo stato: mostra quello della riga da cui è
    /// stato aperto.
    ///
    /// # Il controllo negativo
    ///
    /// Fra la composizione della vista e l'apertura del pannello si registra
    /// **una nuova osservazione conclusiva**, che cambierebbe lo stato. Se il
    /// pannello ricomponesse, direbbe «In errore» mentre la riga dietro dice
    /// «Operativa», e l'operatore non saprebbe quale delle due valga.
    #[test]
    fn il_pannello_non_ricompone_lo_stato_che_la_riga_mostra() {
        let (service, identificativi) = service_with(&[(-1_001, "Canale", true)]);
        let mut connector = connector_with(&[(-1_001, true)]);
        let Ok(_) = service.verify_all(&mut connector, None, &operator(), now()) else {
            panic!("la verifica deve riuscire");
        };

        let vista = prima_vista(&service);
        assert_eq!(vista.health, SourceHealth::Operational);

        // Il mondo cambia sotto la riga già disegnata.
        let Ok(_) = service.database().insert_health_check(
            &NewHealthCheck {
                source_id: identificativi[0],
                account_id: None,
                outcome: HealthCheckOutcome::NotAccessible,
                detail: None,
            },
            Timestamp::from_millis(1_700_000_500_000),
        ) else {
            panic!("l'osservazione deve potersi registrare");
        };

        let Ok(dettaglio) = service.detail(&vista) else {
            panic!("il dettaglio deve potersi comporre");
        };
        assert_eq!(
            dettaglio.view, vista,
            "il pannello deve mostrare la vista che ha ricevuto, non una nuova"
        );
        assert_eq!(
            dettaglio.view.health,
            SourceHealth::Operational,
            "ricomporre lo stato farebbe dire al pannello una cosa diversa dalla riga"
        );
        // E la storia, che è ciò che il pannello aggiunge, contiene comunque
        // il fatto nuovo: aggiungere non è rivedere.
        assert_eq!(dettaglio.checks.len(), 2);
        assert_eq!(
            dettaglio.checks[0].outcome,
            HealthCheckOutcome::NotAccessible
        );
    }

    /// Un tentativo non riuscito resta un tentativo, anche nella storia.
    ///
    /// È la confusione che ADR-0053 esiste per impedire, portata dove è più
    /// facile ricaderci: in un elenco di venti righe uguali.
    #[test]
    fn un_tentativo_non_riuscito_non_diventa_un_guasto_della_fonte() {
        let (service, _) = service_with(&[(-1_001, "Canale", true)]);
        // Un connettore non autorizzato: l'elenco delle chat non si legge, e
        // non si apprende nulla di alcuna fonte.
        let mut connector = MockTelegramConnector::new();

        let Ok(_) = service.verify_all(&mut connector, None, &operator(), now()) else {
            panic!("la verifica deve registrare il tentativo");
        };

        let vista = prima_vista(&service);
        let Ok(dettaglio) = service.detail(&vista) else {
            panic!("il dettaglio deve potersi comporre");
        };

        assert_eq!(dettaglio.checks.len(), 1);
        assert!(
            !dettaglio.checks[0].is_conclusive(),
            "il tentativo non riuscito non è un'osservazione conclusiva"
        );
        assert_eq!(dettaglio.inconclusive(), 1);
        assert!(
            dettaglio.checks[0]
                .note()
                .contains("non si è appreso nulla di questa fonte"),
            "la riga deve dichiarare che cosa NON ha appreso"
        );
        assert_eq!(
            dettaglio.view.health,
            SourceHealth::Unknown,
            "un tentativo non riuscito non porta la fonte in errore"
        );
        assert!(!dettaglio.view.needs_attention());
    }

    /// Il pannello nomina l'account che ha osservato e ne dichiara la
    /// condizione, **senza** farla valere sullo stato.
    #[test]
    fn il_pannello_dichiara_la_condizione_dell_account_senza_farla_valere() {
        let (mut service, _) = service_with(&[(-1_001, "Canale", true)]);
        let account_id = register_account(&mut service, "Ufficio prova", true);
        let mut connector = connector_with(&[(-1_001, true)]);
        let Ok(_) = service.verify_all(&mut connector, Some(account_id), &operator(), now()) else {
            panic!("la verifica deve riuscire");
        };

        let vista = prima_vista(&service);
        let Ok(dettaglio) = service.detail(&vista) else {
            panic!("il dettaglio deve potersi comporre");
        };

        let nota = dettaglio.account_note();
        assert!(
            nota.contains("Ufficio prova"),
            "l'account va nominato: «{nota}»"
        );
        assert!(
            nota.contains("non concorre allo stato"),
            "la condizione dell'account va dichiarata come evidenza: «{nota}»"
        );
        assert_eq!(
            dettaglio.checks[0]
                .observer
                .as_ref()
                .map(DisplayName::as_str),
            Some("Ufficio prova"),
            "chi ha osservato lo dice l'osservazione"
        );

        // La condizione cambia; lo stato no.
        let stato_prima = dettaglio.view.health;
        let Ok(()) = service.database_mut().update_account_state(
            account_id,
            lisi_core::model::telegram_account::PersistedAuthStatus::LoggedOut,
            lisi_core::model::telegram_account::PersistedConnectionStatus::Unknown,
            None,
            None,
            now(),
        ) else {
            panic!("la condizione dell'account deve potersi scrivere");
        };

        let vista_dopo = prima_vista(&service);
        let Ok(dopo) = service.detail(&vista_dopo) else {
            panic!("il dettaglio deve potersi comporre");
        };
        assert_eq!(
            dopo.view.health, stato_prima,
            "lo stato della fonte non deve cambiare al variare dell'autorizzazione"
        );
        let nota = dopo.account_note();
        assert!(
            nota.contains("non risulta") && nota.contains("non cambia quanto è stato osservato"),
            "la nota deve dire che cosa impedisce ADESSO senza riscrivere il passato: «{nota}»"
        );
    }

    /// Senza osservazioni il pannello dichiara l'assenza, non un guasto.
    #[test]
    fn senza_osservazioni_il_pannello_dichiara_l_assenza() {
        let (service, _) = service_with(&[(-1_001, "Canale", true)]);
        let vista = prima_vista(&service);
        let Ok(dettaglio) = service.detail(&vista) else {
            panic!("il dettaglio deve potersi comporre");
        };

        assert!(dettaglio.checks.is_empty());
        assert!(dettaglio.observer.is_none());
        let storia = dettaglio.history_note();
        assert!(
            storia.contains("Non è un guasto"),
            "l'assenza di verifiche non è un guasto: «{storia}»"
        );
        assert!(
            dettaglio.account_note().contains("Nessuna osservazione"),
            "senza osservazioni non si può dire chi abbia guardato"
        );
    }

    /// Una storia troncata dichiara di esserlo.
    ///
    /// Un elenco tagliato che non lo dica farebbe credere che prima non sia
    /// successo nulla.
    #[test]
    fn una_storia_troncata_dichiara_di_esserlo() {
        let (service, identificativi) = service_with(&[(-1_001, "Canale", true)]);
        for indice in 0..=u64::from(HISTORY_DEPTH) {
            let Ok(_) = service.database().insert_health_check(
                &NewHealthCheck {
                    source_id: identificativi[0],
                    account_id: None,
                    outcome: HealthCheckOutcome::Reachable,
                    detail: None,
                },
                Timestamp::from_millis(
                    1_700_000_000_000 + i64::try_from(indice).unwrap_or(0) * 1_000,
                ),
            ) else {
                panic!("l'osservazione deve potersi registrare");
            };
        }

        let vista = prima_vista(&service);
        let Ok(dettaglio) = service.detail(&vista) else {
            panic!("il dettaglio deve potersi comporre");
        };

        assert_eq!(dettaglio.checks.len(), HISTORY_DEPTH as usize);
        let nota = dettaglio.history_note();
        assert!(
            nota.contains("Le precedenti non sono mostrate"),
            "una storia troncata deve dirlo: «{nota}»"
        );
    }

    /// Aprire il pannello è una lettura.
    ///
    /// Se consultare scrivesse, la storia si riempirebbe di righe che nessuno
    /// ha chiesto proprio nella schermata che quella storia mostra.
    #[test]
    fn aprire_il_pannello_non_scrive_nulla() {
        let (service, identificativi) = service_with(&[(-1_001, "Canale", true)]);
        let mut connector = connector_with(&[(-1_001, true)]);
        let Ok(_) = service.verify_all(&mut connector, None, &operator(), now()) else {
            panic!("la verifica deve riuscire");
        };

        let vista = prima_vista(&service);
        let (Ok(audit_prima), Ok(verifiche_prima)) = (
            service.database().audit_entries().map(|e| e.len()),
            service
                .database()
                .source_health_checks(identificativi[0], 100)
                .map(|righe| righe.len()),
        ) else {
            panic!("le letture devono riuscire");
        };

        for _ in 0..3 {
            let Ok(_) = service.detail(&vista) else {
                panic!("il dettaglio deve potersi comporre");
            };
        }

        let (Ok(audit_dopo), Ok(verifiche_dopo)) = (
            service.database().audit_entries().map(|e| e.len()),
            service
                .database()
                .source_health_checks(identificativi[0], 100)
                .map(|righe| righe.len()),
        ) else {
            panic!("le letture devono riuscire");
        };
        assert_eq!(
            audit_prima, audit_dopo,
            "aprire il pannello non tocca l'audit"
        );
        assert_eq!(
            verifiche_prima, verifiche_dopo,
            "aprire il pannello non registra osservazioni"
        );
    }
}
