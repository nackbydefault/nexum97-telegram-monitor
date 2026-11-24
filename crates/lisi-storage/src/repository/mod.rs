//! Operazioni di lettura e scrittura sulle entità.
//!
//! Ogni modulo raccoglie le operazioni di una entità come metodi di
//! [`crate::Database`]. Tutte le istruzioni SQL sono letterali con parametri
//! associati: nessun valore viene mai interpolato nel testo della query.
//!
//! La conversione dalle righe del database ai tipi di dominio avviene in due
//! passi. La chiusura di `rusqlite` può restituire soltanto un errore del
//! motore, quindi legge i valori grezzi; la validazione di dominio avviene
//! subito dopo e un valore non valido diventa
//! [`crate::StorageError::CorruptedValue`], perché indica un database alterato e
//! non un errore del chiamante.

pub mod acquisition_pause;
pub mod alert;
pub mod assessment;
pub mod attachment;
pub mod attachment_keeping;
pub mod attack;
pub mod attack_association;
pub mod attack_guidance;
pub mod audit;
pub mod background;
pub mod backup;
pub mod backup_schedule;
pub mod bookmark;
pub mod consultation;
pub mod content;
pub mod context_snapshot;
pub mod cve;
pub mod cve_scores;
pub mod cyber_search;
pub mod cyber_timeline;
pub mod dictionary;
pub mod dictionary_download;
pub mod dictionary_session;
pub mod discovery;
pub mod document_signing;
pub mod enrollment;
pub mod evidence_package;
pub mod export;
pub mod fault;
pub mod gap_decision;
pub mod hub_assignment;
pub mod hub_command;
pub mod hub_cursor;
pub mod hub_event;
pub mod hub_live_feed;
pub mod hub_notes;
pub mod hub_person;
pub mod hub_review;
pub mod identity_link;
pub mod identity_resolution;
pub mod inbox;
pub mod indicator;
pub mod indicator_resolution;
pub mod integrity;
pub mod interruption;
pub mod kev;
pub mod match_;
pub mod members_listing;
pub mod monitoring_template;
pub mod news;
pub mod note;
pub mod notification;
pub mod office_account;
pub mod organisation;
pub mod overview_report;
pub mod person;
pub mod person_entry;
pub mod profile_media;
pub mod recipient_copy;
pub mod recovery_operation;
pub mod recurring_search;
pub mod reference;
pub mod registration_lookup;
pub mod remote_command;
pub mod report;
pub mod retention;
pub mod review;
pub mod saved_search;
pub mod schedule;
pub mod session;
pub mod session_account;
pub mod settings;
pub mod similarity;
pub mod source;
pub mod source_address;
pub mod source_health;
pub mod source_reliability;
pub mod source_suggestion;
pub mod taxii;
pub mod telegram_account;
pub mod tour;
pub mod trend;
pub mod update_signers;
pub mod work_queue;
pub mod workspace;

use lisi_core::Timestamp;

/// Converte un istante nel valore intero conservato nel database.
pub(crate) const fn millis(timestamp: Timestamp) -> i64 {
    timestamp.as_millis()
}

/// Converte il valore intero conservato nel database in un istante.
pub(crate) const fn instant(millis: i64) -> Timestamp {
    Timestamp::from_millis(millis)
}
