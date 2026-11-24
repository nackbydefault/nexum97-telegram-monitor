#![forbid(unsafe_code)]

//! Servizi applicativi di LISI Telegram Monitor.
//!
//! È il livello che sta fra l'interfaccia grafica e i crate di dominio,
//! persistenza e connettore. L'interfaccia dipende **soltanto** da qui e non
//! conosce TDLib: il confine è motivato in
//! `docs/adr/ADR-0010-APPLICATION-SERVICES.md` ed è verificato da un test che
//! ispeziona il manifest.
//!
//! I servizi non stampano nulla e non conoscono il toolkit grafico: producono
//! stati osservabili che l'interfaccia si limita a mostrare. In particolare
//! **l'insieme dei comandi ammessi è calcolato qui**, perché un pulsante
//! disabilitato è una decisione di sicurezza e deve essere coperta da test.
//!
//! Qui vivono anche le **politiche** che la persistenza deliberatamente non
//! impone. Lo schema difende l'integrità: che una versione pubblicata non si
//! modifichi, che una fotografia non si alteri. Se una versione vuota si possa
//! pubblicare, o se una selezione senza alcun termine sia una sessione
//! sensata, sono decisioni di prodotto, e stanno qui.

pub mod accounts;
pub mod acquisition;
pub mod acquisition_authority;
pub mod acquisition_mode;
pub mod analysis;
pub mod analysis_configuration;
pub mod app_credentials;
pub mod assessment;
pub mod association;
pub mod attachment_keeping;
pub mod attack_guidance;
pub mod attack_mapping;
pub mod attack_snapshot;
pub mod auth;
pub mod background;
pub mod backup;
pub mod backup_schedule;
pub mod bookmark;
pub mod candidate_decision;
pub mod capability;
pub mod config;
pub mod consultation_log;
pub mod context;
pub mod context_snapshot;
pub mod conversation;
pub mod coverage;
pub mod cross_search;
pub mod cve_scores;
pub mod cve_snapshot;
pub mod cyber_notification;
pub mod cyber_recurring;
pub mod cyber_search;
pub mod cyber_watch;
pub mod dashboard;
pub mod data_directory;
pub mod device_identity;
pub mod diagnostics;
pub mod dictionaries;
pub mod dictionary_download;
pub mod dictionary_io;
pub mod discovery;
pub mod discovery_gate;
pub mod document_signing;
pub mod emerging;
pub mod error;
pub mod evidence_graph;
pub mod evidence_package;
pub mod exercise;
pub mod export;
pub mod feedback;
pub mod gap;
pub mod graph_figure;
pub mod handover;
pub mod history;
pub mod hub_access;
pub mod hub_assignment;
pub mod hub_backup;
pub mod hub_catchup;
pub mod hub_client;
pub mod hub_commands;
pub mod hub_cyber;
pub mod hub_enrollment;
pub mod hub_events;
pub mod hub_fanout;
pub mod hub_live;
pub mod hub_notes;
pub mod hub_people;
pub mod hub_presence;
pub mod hub_report;
pub mod hub_review;
pub mod hub_server;
pub mod identity_link;
pub mod identity_resolver;
pub mod indicator_resolution;
pub mod instance;
pub mod interruption;
pub mod interval_recovery;
pub mod kev_snapshot;
pub mod links;
pub mod live_diagnostics;
pub mod lock;
pub mod members_listing;
pub mod message_link;
pub mod monitoring;
pub mod monitoring_template;
pub mod news;
pub mod note;
pub mod notification;
pub mod observed_identity;
pub mod office_account;
pub mod office_networks;
pub mod organisations;
pub mod participants;
pub mod passphrase;
pub(crate) mod pdf_signature;
pub mod pdf_text;
#[cfg(windows)]
#[cfg(test)]
pub(crate) mod permessi_di_prova;
pub mod person;
pub mod person_dossier;
pub mod person_timeline;
pub mod preflight;
pub mod profile_media;
pub mod protected_output;
pub mod provenance;
pub mod recipient_copy;
pub mod recovery;
pub mod registration_lookup;
pub mod remote_commands;
pub mod replay;
pub mod report;
pub mod report_annex;
pub mod report_docx;
pub mod report_ledger;
pub mod report_narrative;
pub mod report_overview;
pub mod report_package;
pub mod report_pdf;
pub mod report_profile;
pub mod report_txt;
pub mod report_xlsx;
pub mod reset;
pub mod retention;
pub mod retro_search;
pub mod review;
pub mod rule_lab;
pub mod rule_versions;
pub mod run_mode;
pub mod saved_search;
pub mod sealed_backup;
pub mod session;
pub mod settings;
pub mod similarity;
pub mod snapshot_download;
pub mod source_health;
pub mod source_history;
pub mod source_reliability;
pub mod source_suggestion;
pub mod sources;
pub mod spike;
pub mod station;
pub mod stix_export;
pub mod subject_record;
pub mod taxii;
pub mod team;
pub mod telegram_runtime;
pub mod tour;
pub mod tray;
pub mod trend;
pub mod update;
pub mod update_review;
pub mod why;
pub mod wizard;
pub mod work_queue;
pub mod workspace;

pub use crate::accounts::AccountService;
pub use crate::auth::{AuthCommand, AuthStage, AuthenticationService, AuthenticationView};
pub use crate::dictionaries::{
    DictionaryProposal, DictionaryService, LibraryEntry, SelectedDictionary,
};
pub use crate::dictionary_io::SeedOutcome;
pub use crate::error::{ServiceError, ServiceResult};
pub use crate::live_diagnostics::{LiveDiagnostic, LiveStartupPhase};

/// Archivio locale, riesportato perché l'interfaccia possa passarlo ai servizi.
///
/// L'interfaccia **non deve dipendere da `lisi-storage`**: il confine è posto da
/// ADR-0010 ed è verificato da un test. Riesportare il solo tipo necessario lo
/// lascia intatto, come già fatto per i tipi riservati del connettore.
pub use lisi_storage::Database;

pub use crate::telegram_runtime::{
    AccountPaths, AccountRuntime, RuntimeMode, TELEGRAM_RUNTIME_AVAILABLE,
    TELEGRAM_RUNTIME_MISSING_DETAIL, TELEGRAM_RUNTIME_MISSING_REASON,
};

/// Configurazione della modalità reale, disponibile solo con la feature che
/// carica TDLib.
#[cfg(feature = "tdlib-runtime")]
pub use crate::telegram_runtime::LiveRuntimeConfig;

pub use crate::wizard::{MonitoringWizard, WizardDuration, WizardStep, WizardView};

/// Tipi riservati che l'interfaccia deve poter costruire dal testo digitato.
///
/// Sono riesportati da qui perché l'interfaccia **non deve dipendere da
/// `lisi-telegram`**: il confine è posto da ADR-0010. Riesportare i soli tipi
/// necessari lascia il confine intatto e non costringe la GUI a conoscere il
/// connettore.
pub mod secrets {
    pub use lisi_telegram::{LoginCode, PhoneNumber, TwoFactorPassword};
}
