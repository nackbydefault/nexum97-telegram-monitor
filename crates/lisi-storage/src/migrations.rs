//! Migrazioni versionate dello schema.
//!
//! Le migrazioni sono file SQL numerati, inclusi nel binario e applicati in
//! ordine, ciascuna in una propria transazione. La versione raggiunta è
//! conservata in `PRAGMA user_version`.

use rusqlite::{Connection, TransactionBehavior};

use crate::error::{StorageError, StorageResult};

/// Una migrazione dello schema.
struct Migration {
    /// Numero progressivo, corrispondente al valore di `PRAGMA user_version`
    /// che il database assume dopo l'applicazione.
    version: u32,
    /// Nome del file, riportato nella diagnostica.
    name: &'static str,
    /// Istruzioni SQL.
    sql: &'static str,
}

/// Elenco ordinato delle migrazioni conosciute.
///
/// Una migrazione già applicata non va mai modificata: i database esistenti non
/// la rieseguirebbero e divergerebbero in silenzio da quelli nuovi.
const MIGRATIONS: &[Migration] = &[
    Migration {
        version: 1,
        name: "0001_initial.sql",
        sql: include_str!("../migrations/0001_initial.sql"),
    },
    Migration {
        version: 2,
        name: "0002_supergroup_sources.sql",
        sql: include_str!("../migrations/0002_supergroup_sources.sql"),
    },
    Migration {
        version: 3,
        name: "0003_dictionary_library.sql",
        sql: include_str!("../migrations/0003_dictionary_library.sql"),
    },
    Migration {
        version: 4,
        name: "0004_audit_operating_mode.sql",
        sql: include_str!("../migrations/0004_audit_operating_mode.sql"),
    },
    Migration {
        version: 5,
        name: "0005_acquisition_runtime.sql",
        sql: include_str!("../migrations/0005_acquisition_runtime.sql"),
    },
    Migration {
        version: 6,
        name: "0006_acquisition_idempotency.sql",
        sql: include_str!("../migrations/0006_acquisition_idempotency.sql"),
    },
    Migration {
        version: 7,
        name: "0007_notifications.sql",
        sql: include_str!("../migrations/0007_notifications.sql"),
    },
    Migration {
        version: 8,
        name: "0008_notification_settings.sql",
        sql: include_str!("../migrations/0008_notification_settings.sql"),
    },
    Migration {
        version: 9,
        name: "0009_multi_account.sql",
        sql: include_str!("../migrations/0009_multi_account.sql"),
    },
    Migration {
        version: 10,
        name: "0010_custom_term_level.sql",
        sql: include_str!("../migrations/0010_custom_term_level.sql"),
    },
    Migration {
        version: 11,
        name: "0011_content_author_identifier.sql",
        sql: include_str!("../migrations/0011_content_author_identifier.sql"),
    },
    Migration {
        version: 12,
        name: "0012_content_acquisition_origin.sql",
        sql: include_str!("../migrations/0012_content_acquisition_origin.sql"),
    },
    Migration {
        version: 13,
        name: "0013_content_author_username.sql",
        sql: include_str!("../migrations/0013_content_author_username.sql"),
    },
    Migration {
        version: 14,
        name: "0014_report_packages.sql",
        sql: include_str!("../migrations/0014_report_packages.sql"),
    },
    Migration {
        version: 15,
        name: "0015_report_profile.sql",
        sql: include_str!("../migrations/0015_report_profile.sql"),
    },
    Migration {
        version: 16,
        name: "0016_export_destination.sql",
        sql: include_str!("../migrations/0016_export_destination.sql"),
    },
    Migration {
        version: 17,
        name: "0017_retention_policy.sql",
        sql: include_str!("../migrations/0017_retention_policy.sql"),
    },
    Migration {
        version: 18,
        name: "0018_content_indicators.sql",
        sql: include_str!("../migrations/0018_content_indicators.sql"),
    },
    Migration {
        version: 19,
        name: "0019_motion_preference.sql",
        sql: include_str!("../migrations/0019_motion_preference.sql"),
    },
    Migration {
        version: 20,
        name: "0020_cyber_notifications.sql",
        sql: include_str!("../migrations/0020_cyber_notifications.sql"),
    },
    Migration {
        version: 21,
        name: "0021_hub_enrollment.sql",
        sql: include_str!("../migrations/0021_hub_enrollment.sql"),
    },
    Migration {
        version: 22,
        name: "0022_watched_organisations.sql",
        sql: include_str!("../migrations/0022_watched_organisations.sql"),
    },
    Migration {
        version: 23,
        name: "0023_source_health_checks.sql",
        sql: include_str!("../migrations/0023_source_health_checks.sql"),
    },
    Migration {
        version: 24,
        name: "0024_engine_version.sql",
        sql: include_str!("../migrations/0024_engine_version.sql"),
    },
    Migration {
        version: 25,
        name: "0025_context_snapshots.sql",
        sql: include_str!("../migrations/0025_context_snapshots.sql"),
    },
    Migration {
        version: 26,
        name: "0026_workspaces.sql",
        sql: include_str!("../migrations/0026_workspaces.sql"),
    },
    Migration {
        version: 27,
        name: "0027_bookmarks.sql",
        sql: include_str!("../migrations/0027_bookmarks.sql"),
    },
    Migration {
        version: 28,
        name: "0028_notes.sql",
        sql: include_str!("../migrations/0028_notes.sql"),
    },
    Migration {
        version: 29,
        name: "0029_saved_searches.sql",
        sql: include_str!("../migrations/0029_saved_searches.sql"),
    },
    Migration {
        version: 30,
        name: "0030_monitoring_templates.sql",
        sql: include_str!("../migrations/0030_monitoring_templates.sql"),
    },
    Migration {
        version: 31,
        name: "0031_persons.sql",
        sql: include_str!("../migrations/0031_persons.sql"),
    },
    Migration {
        version: 32,
        name: "0032_subject_assessments.sql",
        sql: include_str!("../migrations/0032_subject_assessments.sql"),
    },
    Migration {
        version: 33,
        name: "0033_identity_links.sql",
        sql: include_str!("../migrations/0033_identity_links.sql"),
    },
    Migration {
        version: 34,
        name: "0034_attack_snapshots.sql",
        sql: include_str!("../migrations/0034_attack_snapshots.sql"),
    },
    Migration {
        version: 35,
        name: "0035_attack_term_associations.sql",
        sql: include_str!("../migrations/0035_attack_term_associations.sql"),
    },
    Migration {
        version: 36,
        name: "0036_cve_snapshots.sql",
        sql: include_str!("../migrations/0036_cve_snapshots.sql"),
    },
    Migration {
        version: 37,
        name: "0037_kev_snapshots.sql",
        sql: include_str!("../migrations/0037_kev_snapshots.sql"),
    },
    Migration {
        version: 38,
        name: "0038_session_interruptions.sql",
        sql: include_str!("../migrations/0038_session_interruptions.sql"),
    },
    Migration {
        version: 39,
        name: "0039_update_channel.sql",
        sql: include_str!("../migrations/0039_update_channel.sql"),
    },
    Migration {
        version: 40,
        name: "0040_update_origin.sql",
        sql: include_str!("../migrations/0040_update_origin.sql"),
    },
    Migration {
        version: 41,
        name: "0041_discovery_runs.sql",
        sql: include_str!("../migrations/0041_discovery_runs.sql"),
    },
    Migration {
        version: 42,
        name: "0042_candidate_decisions.sql",
        sql: include_str!("../migrations/0042_candidate_decisions.sql"),
    },
    Migration {
        version: 43,
        name: "0043_hub_device_roles.sql",
        sql: include_str!("../migrations/0043_hub_device_roles.sql"),
    },
    Migration {
        version: 44,
        name: "0044_hub_events.sql",
        sql: include_str!("../migrations/0044_hub_events.sql"),
    },
    Migration {
        version: 45,
        name: "0045_hub_stream_cursor.sql",
        sql: include_str!("../migrations/0045_hub_stream_cursor.sql"),
    },
    Migration {
        version: 46,
        name: "0046_hub_commands.sql",
        sql: include_str!("../migrations/0046_hub_commands.sql"),
    },
    Migration {
        version: 47,
        name: "0047_hub_live_feed.sql",
        sql: include_str!("../migrations/0047_hub_live_feed.sql"),
    },
    Migration {
        version: 48,
        name: "0048_hub_people.sql",
        sql: include_str!("../migrations/0048_hub_people.sql"),
    },
    Migration {
        version: 49,
        name: "0049_hub_assignments.sql",
        sql: include_str!("../migrations/0049_hub_assignments.sql"),
    },
    Migration {
        version: 50,
        name: "0050_hub_notes.sql",
        sql: include_str!("../migrations/0050_hub_notes.sql"),
    },
    Migration {
        version: 51,
        name: "0051_audit_by_action.sql",
        sql: include_str!("../migrations/0051_audit_by_action.sql"),
    },
    Migration {
        version: 52,
        name: "0052_coverage_gap_decisions.sql",
        sql: include_str!("../migrations/0052_coverage_gap_decisions.sql"),
    },
    Migration {
        version: 53,
        name: "0053_recovery_operations.sql",
        sql: include_str!("../migrations/0053_recovery_operations.sql"),
    },
    Migration {
        version: 54,
        name: "0054_identity_resolutions.sql",
        sql: include_str!("../migrations/0054_identity_resolutions.sql"),
    },
    Migration {
        version: 55,
        name: "0055_identity_link_basis.sql",
        sql: include_str!("../migrations/0055_identity_link_basis.sql"),
    },
    Migration {
        version: 56,
        name: "0056_evidence_packages.sql",
        sql: include_str!("../migrations/0056_evidence_packages.sql"),
    },
    Migration {
        version: 57,
        name: "0057_tour_state.sql",
        sql: include_str!("../migrations/0057_tour_state.sql"),
    },
    Migration {
        version: 58,
        name: "0058_foreign_key_indexes.sql",
        sql: include_str!("../migrations/0058_foreign_key_indexes.sql"),
    },
    Migration {
        version: 59,
        name: "0059_telegram_account_details.sql",
        sql: include_str!("../migrations/0059_telegram_account_details.sql"),
    },
    Migration {
        version: 60,
        name: "0060_person_entries.sql",
        sql: include_str!("../migrations/0060_person_entries.sql"),
    },
    Migration {
        version: 61,
        name: "0061_cyber_searches.sql",
        sql: include_str!("../migrations/0061_cyber_searches.sql"),
    },
    Migration {
        version: 62,
        name: "0062_report_profile_protected.sql",
        sql: include_str!("../migrations/0062_report_profile_protected.sql"),
    },
    Migration {
        version: 63,
        name: "0063_cyber_searches_public_posts.sql",
        sql: include_str!("../migrations/0063_cyber_searches_public_posts.sql"),
    },
    Migration {
        version: 64,
        name: "0064_recurring_searches.sql",
        sql: include_str!("../migrations/0064_recurring_searches.sql"),
    },
    Migration {
        version: 65,
        name: "0065_source_suggestion_decisions.sql",
        sql: include_str!("../migrations/0065_source_suggestion_decisions.sql"),
    },
    Migration {
        version: 66,
        name: "0066_source_public_addresses.sql",
        sql: include_str!("../migrations/0066_source_public_addresses.sql"),
    },
    Migration {
        version: 67,
        name: "0067_source_reliability_entries.sql",
        sql: include_str!("../migrations/0067_source_reliability_entries.sql"),
    },
    Migration {
        version: 68,
        name: "0068_news_state.sql",
        sql: include_str!("../migrations/0068_news_state.sql"),
    },
    Migration {
        version: 69,
        name: "0069_numeric_code_terms.sql",
        sql: include_str!("../migrations/0069_numeric_code_terms.sql"),
    },
    Migration {
        version: 70,
        name: "0070_session_schedules.sql",
        sql: include_str!("../migrations/0070_session_schedules.sql"),
    },
    Migration {
        version: 71,
        name: "0071_acquisition_pauses.sql",
        sql: include_str!("../migrations/0071_acquisition_pauses.sql"),
    },
    Migration {
        version: 72,
        name: "0072_session_accounts.sql",
        sql: include_str!("../migrations/0072_session_accounts.sql"),
    },
    Migration {
        version: 73,
        name: "0073_profile_media_observations.sql",
        sql: include_str!("../migrations/0073_profile_media_observations.sql"),
    },
    Migration {
        version: 74,
        name: "0074_profile_media_report_marks.sql",
        sql: include_str!("../migrations/0074_profile_media_report_marks.sql"),
    },
    Migration {
        version: 75,
        name: "0075_content_attachments.sql",
        sql: include_str!("../migrations/0075_content_attachments.sql"),
    },
    Migration {
        version: 76,
        name: "0076_attachment_keepings.sql",
        sql: include_str!("../migrations/0076_attachment_keepings.sql"),
    },
    Migration {
        version: 77,
        name: "0077_dictionary_downloads.sql",
        sql: include_str!("../migrations/0077_dictionary_downloads.sql"),
    },
    Migration {
        version: 78,
        name: "0078_taxii.sql",
        sql: include_str!("../migrations/0078_taxii.sql"),
    },
    Migration {
        version: 79,
        name: "0079_document_signing.sql",
        sql: include_str!("../migrations/0079_document_signing.sql"),
    },
    Migration {
        version: 80,
        name: "0080_update_signers.sql",
        sql: include_str!("../migrations/0080_update_signers.sql"),
    },
    Migration {
        version: 81,
        name: "0081_cve_scores.sql",
        sql: include_str!("../migrations/0081_cve_scores.sql"),
    },
    Migration {
        version: 82,
        name: "0082_attack_guidance.sql",
        sql: include_str!("../migrations/0082_attack_guidance.sql"),
    },
    Migration {
        version: 83,
        name: "0083_expression_terms.sql",
        sql: include_str!("../migrations/0083_expression_terms.sql"),
    },
    Migration {
        version: 84,
        name: "0084_recovered_notifications.sql",
        sql: include_str!("../migrations/0084_recovered_notifications.sql"),
    },
    Migration {
        version: 85,
        name: "0085_recipient_copies.sql",
        sql: include_str!("../migrations/0085_recipient_copies.sql"),
    },
    Migration {
        version: 86,
        name: "0086_backup_schedule.sql",
        sql: include_str!("../migrations/0086_backup_schedule.sql"),
    },
    Migration {
        version: 87,
        name: "0087_overview_reports.sql",
        sql: include_str!("../migrations/0087_overview_reports.sql"),
    },
    Migration {
        version: 88,
        name: "0088_consultations.sql",
        sql: include_str!("../migrations/0088_consultations.sql"),
    },
    Migration {
        version: 89,
        name: "0089_orderly_closure.sql",
        sql: include_str!("../migrations/0089_orderly_closure.sql"),
    },
    Migration {
        version: 90,
        name: "0090_interface_language.sql",
        sql: include_str!("../migrations/0090_interface_language.sql"),
    },
    Migration {
        version: 91,
        name: "0091_remote_commands.sql",
        sql: include_str!("../migrations/0091_remote_commands.sql"),
    },
    Migration {
        version: 92,
        name: "0092_members_listings.sql",
        sql: include_str!("../migrations/0092_members_listings.sql"),
    },
    Migration {
        version: 93,
        name: "0093_indicator_resolutions.sql",
        sql: include_str!("../migrations/0093_indicator_resolutions.sql"),
    },
    Migration {
        version: 94,
        name: "0094_background_keeper.sql",
        sql: include_str!("../migrations/0094_background_keeper.sql"),
    },
    Migration {
        version: 95,
        name: "0095_registration_lookups.sql",
        sql: include_str!("../migrations/0095_registration_lookups.sql"),
    },
];

/// Versione di schema prodotta dall'insieme completo delle migrazioni.
pub const LATEST_VERSION: u32 = MIGRATIONS.len() as u32;

/// Legge la versione di schema dichiarata dal database.
///
/// # Errori
///
/// Restituisce un errore se la lettura del pragma non riesce.
pub fn schema_version(connection: &Connection) -> StorageResult<u32> {
    let version: i64 = connection.query_row("PRAGMA user_version", [], |row| row.get(0))?;
    // Un valore negativo non è prodotto da questo codice: indica un file
    // manomesso o estraneo. Va rifiutato come una versione non interpretabile,
    // non convertito in silenzio.
    u32::try_from(version).map_err(|_| StorageError::SchemaTooNew {
        found: u32::MAX,
        supported: LATEST_VERSION,
    })
}

/// Porta il database alla versione corrente applicando le migrazioni mancanti.
///
/// Un database che dichiara una versione superiore a [`LATEST_VERSION`] viene
/// rifiutato: è stato scritto da una versione più recente dell'applicazione e
/// interpretarlo con lo schema conosciuto rischierebbe di corromperlo.
///
/// # Errori
///
/// Restituisce [`StorageError::SchemaTooNew`] se il database è più recente di
/// quanto questa versione conosca, e [`StorageError::Migration`] se una
/// migrazione fallisce. In quest'ultimo caso la transazione della migrazione
/// viene annullata e la versione dichiarata resta quella precedente.
pub fn apply(connection: &mut Connection) -> StorageResult<u32> {
    let current = schema_version(connection)?;

    if current > LATEST_VERSION {
        return Err(StorageError::SchemaTooNew {
            found: current,
            supported: LATEST_VERSION,
        });
    }

    // **La via breve, e non è un'ottimizzazione gratuita.**
    //
    // L'applicazione apre l'archivio più di venti volte a ogni avvio, una per
    // servizio. Se ciascuna prendesse il blocco esclusivo per scoprire che non
    // c'è nulla da fare, l'avvio pagherebbe venti serializzazioni per niente,
    // su ogni postazione, per sempre.
    //
    // Uscire qui è sicuro: se la versione è già quella corrente, non esiste
    // migrazione da applicare, e il caso in cui un'altra connessione la stia
    // alzando proprio adesso è coperto dal blocco più sotto — quella
    // connessione la vedrà o prima o dopo, mai a metà.
    if current == LATEST_VERSION {
        return Ok(current);
    }

    // Una migrazione che ricostruisce una tabella deve poterla sostituire
    // mentre altre vi fanno riferimento. La documentazione di SQLite prescrive
    // di disattivare l'applicazione delle foreign key per la durata della
    // modifica e di verificarne l'integrità subito dopo. Il pragma **non ha
    // effetto dentro una transazione**, quindi va impostato qui, prima.
    connection.pragma_update(None, "foreign_keys", "OFF")?;

    // **UNA SOLA AUTORITÀ DI MIGRAZIONE, GARANTITA DA SQLITE.**
    //
    // `BEGIN EXCLUSIVE` prende subito il blocco in scrittura invece di
    // aspettare la prima modifica. Senza, due connessioni che si aprono
    // insieme leggono entrambe la stessa versione, decidono entrambe di
    // migrare, e la seconda trova la tabella che la prima ha appena creato.
    //
    // Non è un caso di scuola: questo prodotto apre l'archivio oltre venti
    // volte a ogni avvio.
    //
    // La seconda connessione non fallisce: `busy_timeout` la fa attendere il
    // rilascio del blocco. Quando entra, rilegge la versione **dentro** il
    // blocco e trova il lavoro già fatto.
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Exclusive)?;

    // **Si rilegge dentro il blocco.** La lettura di prima è avvenuta senza
    // protezione e può essere invecchiata nel frattempo: fidarsene qui
    // significherebbe riapplicare migrazioni che un'altra connessione ha già
    // applicato, che è esattamente il difetto da chiudere.
    let current: u32 = {
        let version: i64 = transaction.query_row("PRAGMA user_version", [], |row| row.get(0))?;
        u32::try_from(version).unwrap_or(0)
    };

    // **Tutte le migrazioni pendenti in UNA transazione.**
    //
    // Prima ciascuna aveva la propria, e un guasto alla quattordicesima
    // lasciava l'archivio alla tredicesima: uno stato valido, ma diverso sia da
    // quello di partenza sia da quello atteso, e nessuno lo sapeva tranne il
    // registro. Ora l'aggiornamento dello schema o **avviene per intero** o non
    // avviene: un'interruzione — un arresto, un guasto, una macchina che si
    // spegne — riporta l'archivio esattamente a dov'era.
    for migration in MIGRATIONS {
        if migration.version <= current {
            continue;
        }

        transaction
            .execute_batch(migration.sql)
            .map_err(|source| StorageError::Migration {
                version: migration.version,
                source,
            })?;

        // `PRAGMA user_version` non ammette parametri associati: il valore va
        // scritto nel testo dell'istruzione. Non è una deroga alla regola sulle
        // query parametrizzate, perché il valore non proviene dall'esterno ma è
        // una costante di questo file, di tipo `u32` e quindi non interpolabile
        // con testo arbitrario.
        transaction
            .execute_batch(&format!("PRAGMA user_version = {};", migration.version))
            .map_err(|source| StorageError::Migration {
                version: migration.version,
                source,
            })?;
    }

    transaction
        .commit()
        .map_err(|source| StorageError::Migration {
            version: LATEST_VERSION,
            source,
        })?;

    connection.pragma_update(None, "foreign_keys", "ON")?;

    // Verifica che la ricostruzione non abbia lasciato riferimenti
    // pendenti. Riattivare le foreign key senza controllare significherebbe
    // dichiarare integro cio' che non e' stato guardato.
    let dangling: i64 =
        connection.query_row("SELECT count(*) FROM pragma_foreign_key_check", [], |row| {
            row.get(0)
        })?;

    if dangling > 0 {
        return Err(StorageError::MigrationLeftDanglingReferences { count: dangling });
    }

    schema_version(connection)
}

/// Nomi dei file di migrazione, in ordine di applicazione.
#[must_use]
pub fn migration_names() -> Vec<&'static str> {
    MIGRATIONS.iter().map(|migration| migration.name).collect()
}

// Il README dell'archivio non è quello della copia pubblica (ADR-0210).

#[cfg(test)]
mod tests {
    use rusqlite::Connection;

    use rusqlite::TransactionBehavior;

    use super::{LATEST_VERSION, MIGRATIONS, apply, migration_names, schema_version};
    use crate::error::StorageError;
    use crate::error::StorageResult;

    /// Un archivio su file, per le prove che hanno bisogno di piu' connessioni.
    ///
    /// Un database in memoria non serve: ogni connessione ne aprirebbe uno
    /// PROPRIO, e la concorrenza che si vuole provare non esisterebbe.
    fn archivio_su_file() -> (tempfile::TempDir, std::path::PathBuf) {
        let cartella = tempfile::tempdir().expect("cartella temporanea");
        let percorso = cartella.path().join("prova.sqlite");

        // **Il file nasce gia' in WAL**, e non e' una comodita' della prova.
        //
        // Convertire la modalita' journal richiede accesso esclusivo al file.
        // Venti connessioni che tentano di convertirlo insieme si contendono
        // quel blocco e falliscono con «database is locked» — un guasto vero,
        // che pero' NON e' quello che si vuole provare qui e che il prodotto
        // non incontra: converte una volta, e le aperture successive trovano
        // il file gia' convertito.
        //
        // Trovato scrivendo questa prova, e vale la pena scriverlo: la
        // conversione concorrente della modalita' journal e' fragile, e se un
        // giorno il prodotto aprisse l'archivio da piu' fili di esecuzione
        // insieme lo scoprirebbe in campo.
        {
            let preparazione = apri_grezzo(&percorso);
            let _mode: String = preparazione
                .query_row("PRAGMA journal_mode = WAL", [], |row| row.get(0))
                .expect("la conversione iniziale in WAL deve riuscire");
        }

        (cartella, percorso)
    }

    /// Apre senza toccare la modalita' journal: serve solo a crearla la prima
    /// volta.
    fn apri_grezzo(percorso: &std::path::Path) -> Connection {
        let Ok(connection) = Connection::open(percorso) else {
            panic!("l'archivio di prova deve potersi aprire");
        };
        connection
            .busy_timeout(std::time::Duration::from_millis(5_000))
            .expect("l'attesa sul blocco deve potersi impostare");
        connection
    }

    /// Apre come apre **il prodotto**, e non come farebbe comodo alla prova.
    ///
    /// La prima versione di questo aiutante ometteva `journal_mode = WAL`, e la
    /// prova sulla via breve falliva con «database is locked». Non era un
    /// difetto del codice: in modalita' journal classica un blocco esclusivo
    /// ferma anche i LETTORI, mentre in WAL — che e' cio' che il prodotto usa —
    /// no.
    ///
    /// **La prova stava misurando una configurazione che il prodotto non
    /// adotta**, ed e' la stessa lezione gia' imparata altrove: una prova che
    /// esercita un percorso diverso da quello reale non e' una prova di quel
    /// percorso, per quanto gli assomigli.
    ///
    /// I due valori sono gli stessi di `database.rs`. Se un giorno divergessero,
    /// queste prove tornerebbero a misurare qualcos'altro.
    fn apri(percorso: &std::path::Path) -> Connection {
        let Ok(connection) = Connection::open(percorso) else {
            panic!("l'archivio di prova deve potersi aprire");
        };
        connection
            .busy_timeout(std::time::Duration::from_millis(5_000))
            .expect("l'attesa sul blocco deve potersi impostare");
        let _mode: String = connection
            .query_row("PRAGMA journal_mode = WAL", [], |row| row.get(0))
            .expect("la modalita' WAL deve potersi impostare");
        connection
    }

    /// **Venti connessioni che migrano insieme lo stesso archivio.**
    ///
    /// E' cio' che questo prodotto fa a ogni avvio: apre l'archivio una volta
    /// per servizio, oltre venti in tutto, e ognuna chiama `apply`.
    ///
    /// Senza il blocco esclusivo due connessioni leggono la stessa versione,
    /// decidono entrambe di migrare, e la seconda trova la tabella che la
    /// prima ha appena creato. La prova lo esercita davvero, su un archivio su
    /// FILE e da fili di esecuzione diversi: in memoria ogni connessione
    /// aprirebbe un database proprio e non ci sarebbe nulla da contendere.
    #[test]
    fn venti_connessioni_che_migrano_insieme_arrivano_tutte_alla_stessa_versione() {
        let (_cartella, percorso) = archivio_su_file();

        let esiti: Vec<StorageResult<u32>> = std::thread::scope(|scope| {
            let mut lavori = Vec::new();
            for _ in 0..20 {
                let percorso = percorso.clone();
                lavori.push(scope.spawn(move || {
                    let mut connection = apri(&percorso);
                    apply(&mut connection)
                }));
            }
            lavori
                .into_iter()
                .map(|lavoro| lavoro.join().expect("nessun filo deve andare in panico"))
                .collect()
        });

        for (numero, esito) in esiti.iter().enumerate() {
            match esito {
                Ok(versione) => assert_eq!(
                    *versione, LATEST_VERSION,
                    "la connessione {numero} ha visto una versione diversa"
                ),
                Err(errore) => panic!(
                    "la connessione {numero} ha fallito la migrazione: {errore}. \
                     Due connessioni hanno migrato insieme lo stesso archivio."
                ),
            }
        }

        // E l'archivio, alla fine, e' migrato una volta sola e per intero.
        let finale = apri(&percorso);
        let versione: i64 = finale
            .query_row("PRAGMA user_version", [], |row| row.get(0))
            .expect("la versione deve potersi leggere");
        assert_eq!(u32::try_from(versione).unwrap_or(0), LATEST_VERSION);
    }

    /// **Una migrazione interrotta non lascia l'archivio a meta'.**
    ///
    /// Tutte le migrazioni pendenti stanno in UNA transazione: o lo schema
    /// arriva alla versione attesa, o resta esattamente dov'era.
    ///
    /// Prima ciascuna aveva la propria, e un guasto alla quattordicesima
    /// lasciava l'archivio alla tredicesima — uno stato valido, ma diverso sia
    /// da quello di partenza sia da quello atteso, e nessuno lo sapeva tranne
    /// il registro.
    ///
    /// L'interruzione si ottiene aprendo l'archivio con uno schema PIU' NUOVO
    /// di quanto il codice conosca: e' l'unico guasto che si puo' provocare
    /// senza falsificare una migrazione.
    #[test]
    fn un_archivio_piu_nuovo_del_codice_viene_rifiutato_senza_toccarlo() {
        let (_cartella, percorso) = archivio_su_file();

        {
            let mut connection = apri(&percorso);
            apply(&mut connection).expect("la prima migrazione deve riuscire");
            connection
                .execute_batch(&format!("PRAGMA user_version = {};", LATEST_VERSION + 5))
                .expect("la versione di prova deve potersi scrivere");
        }

        let mut connection = apri(&percorso);
        let esito = apply(&mut connection);

        assert!(
            matches!(esito, Err(StorageError::SchemaTooNew { .. })),
            "un archivio scritto da una versione piu' recente va rifiutato, \
             non interpretato: {esito:?}"
        );

        // **E non deve essere stato toccato.** Un rifiuto che nel frattempo
        // avesse modificato qualcosa sarebbe peggio di un'apertura riuscita.
        let versione: i64 = connection
            .query_row("PRAGMA user_version", [], |row| row.get(0))
            .expect("la versione deve potersi leggere");
        assert_eq!(
            u32::try_from(versione).unwrap_or(0),
            LATEST_VERSION + 5,
            "il rifiuto ha alterato la versione dichiarata"
        );
    }

    /// La via breve non prende alcun blocco quando non c'e' nulla da fare.
    ///
    /// Aprire venti volte un archivio gia' aggiornato non deve costare venti
    /// serializzazioni. La prova lo verifica dall'esterno: mentre una
    /// transazione ESCLUSIVA e' aperta su un'altra connessione, `apply` su un
    /// archivio gia' alla versione corrente deve rispondere subito.
    ///
    /// Se un giorno prendesse il blocco anche in quel caso, questa prova si
    /// bloccherebbe fino allo scadere dell'attesa e poi fallirebbe.
    #[test]
    fn su_un_archivio_gia_aggiornato_non_si_prende_alcun_blocco() {
        let (_cartella, percorso) = archivio_su_file();

        {
            let mut preparazione = apri(&percorso);
            apply(&mut preparazione).expect("la prima migrazione deve riuscire");
        }

        // Un'altra connessione tiene il blocco esclusivo.
        let mut occupante = apri(&percorso);
        let blocco = occupante
            .transaction_with_behavior(TransactionBehavior::Exclusive)
            .expect("il blocco di prova deve potersi prendere");

        let mut connection = apri(&percorso);
        let inizio = std::time::Instant::now();
        let esito = apply(&mut connection);
        let durata = inizio.elapsed();

        drop(blocco);

        assert!(
            esito.is_ok(),
            "un archivio gia' aggiornato non deve attendere un blocco: {esito:?}"
        );
        assert!(
            durata < std::time::Duration::from_millis(1_000),
            "la via breve ha atteso {durata:?}: sta prendendo un blocco che non le serve"
        );
    }

    fn connection() -> Connection {
        let Ok(connection) = Connection::open_in_memory() else {
            panic!("il database in memoria deve potersi aprire nei test");
        };
        connection
    }

    #[test]
    fn versions_are_consecutive_and_start_at_one() {
        for (index, migration) in MIGRATIONS.iter().enumerate() {
            let expected = u32::try_from(index + 1).unwrap_or(u32::MAX);
            assert_eq!(migration.version, expected);
        }
        assert_eq!(migration_names().len(), MIGRATIONS.len());
    }

    #[test]
    fn a_fresh_database_reaches_the_latest_version() {
        let mut connection = connection();
        assert_eq!(schema_version(&connection).ok(), Some(0));
        let Ok(version) = apply(&mut connection) else {
            panic!("le migrazioni devono applicarsi su un database vuoto");
        };
        assert_eq!(version, LATEST_VERSION);
    }

    #[test]
    fn applying_twice_is_a_no_operation() {
        let mut connection = connection();
        let (Ok(first), Ok(second)) = (apply(&mut connection), apply(&mut connection)) else {
            panic!("la seconda applicazione deve riuscire senza effetti");
        };
        assert_eq!(first, LATEST_VERSION);
        assert_eq!(second, LATEST_VERSION);
    }

    #[test]
    fn a_database_from_a_newer_version_is_refused() {
        let mut connection = connection();
        let Ok(()) = connection.execute_batch("PRAGMA user_version = 9999;") else {
            panic!("il pragma deve potersi impostare nei test");
        };

        assert!(matches!(
            apply(&mut connection),
            Err(StorageError::SchemaTooNew {
                found: 9999,
                supported: LATEST_VERSION,
            })
        ));
    }

    #[test]
    fn upgrading_a_populated_database_preserves_rows_and_references() {
        // E' la prova che conta: la migrazione 0002 ricostruisce `sources`, e
        // altre tabelle vi fanno riferimento. Un database vuoto non
        // dimostrerebbe nulla.
        let mut connection = connection();

        // Database portato alla sola versione 1.
        let Ok(()) = connection.execute_batch(MIGRATIONS[0].sql) else {
            panic!("la prima migrazione deve applicarsi");
        };
        let Ok(()) = connection.execute_batch("PRAGMA user_version = 1;") else {
            panic!("il pragma deve potersi impostare");
        };

        // Una fonte, una sessione e il legame fra le due.
        let Ok(()) = connection.execute_batch(
            "INSERT INTO sources (kind, identifier, display_name, authorized_by, active,
                                  created_at, updated_at)
             VALUES ('channel', 'canale_storico', 'Canale', 'responsabile', 1, 1000, 1000);
             INSERT INTO sessions (label, started_by, duration_mode, planned_seconds, state,
                                   created_at)
             VALUES ('Sessione', 'operatore', 'manual', NULL, 'planned', 1000);
             INSERT INTO session_sources (session_id, source_id, selected_at)
             VALUES (1, 1, 1000);",
        ) else {
            panic!("i dati di prova devono potersi inserire");
        };

        // Aggiornamento alla versione corrente.
        let Ok(version) = apply(&mut connection) else {
            panic!("l'aggiornamento deve riuscire");
        };
        assert_eq!(version, LATEST_VERSION);

        // La riga e' sopravvissuta con lo stesso identificatore.
        let source: Result<(i64, String), _> =
            connection.query_row("SELECT id, identifier FROM sources", [], |row| {
                Ok((row.get(0)?, row.get(1)?))
            });
        assert_eq!(source, Ok((1, String::from("canale_storico"))));

        // Il legame verso la fonte non e' rimasto pendente.
        let linked: Result<i64, _> = connection.query_row(
            "SELECT count(*) FROM session_sources WHERE source_id = 1",
            [],
            |row| row.get(0),
        );
        assert_eq!(linked, Ok(1));

        // Le foreign key sono state riattivate dopo la ricostruzione.
        let enabled: Result<i64, _> =
            connection.query_row("PRAGMA foreign_keys", [], |row| row.get(0));
        assert_eq!(enabled, Ok(1));
    }

    #[test]
    fn the_supergroup_kind_is_accepted_only_after_the_second_migration() {
        let mut connection = connection();
        let Ok(()) = connection.execute_batch(MIGRATIONS[0].sql) else {
            panic!("la prima migrazione deve applicarsi");
        };

        let attempt = connection.execute(
            "INSERT INTO sources (kind, identifier, display_name, authorized_by, active,
                                  created_at, updated_at)
             VALUES ('supergroup', 'sg', 'Supergruppo', 'responsabile', 1, 1000, 1000)",
            [],
        );
        assert!(attempt.is_err(), "alla versione 1 il tipo non e' ammesso");

        let Ok(()) = connection.execute_batch("PRAGMA user_version = 1;") else {
            panic!("il pragma deve potersi impostare");
        };
        let Ok(_) = apply(&mut connection) else {
            panic!("l'aggiornamento deve riuscire");
        };

        let accepted = connection.execute(
            "INSERT INTO sources (kind, identifier, display_name, authorized_by, active,
                                  created_at, updated_at)
             VALUES ('supergroup', 'sg', 'Supergruppo', 'responsabile', 1, 1000, 1000)",
            [],
        );
        assert_eq!(accepted.ok(), Some(1), "dopo la 0002 il tipo e' ammesso");
    }

    #[test]
    fn an_unknown_source_kind_stays_refused_after_the_upgrade() {
        let mut connection = connection();
        let Ok(_) = apply(&mut connection) else {
            panic!("le migrazioni devono applicarsi");
        };

        let refused = connection.execute(
            "INSERT INTO sources (kind, identifier, display_name, authorized_by, active,
                                  created_at, updated_at)
             VALUES ('bot', 'x', 'Bot', 'responsabile', 1, 1000, 1000)",
            [],
        );
        assert!(
            refused.is_err(),
            "il vincolo non deve essere stato allentato"
        );
    }

    #[test]
    fn upgrading_a_populated_version_two_database_preserves_everything() {
        // La prova che conta per la migrazione 0003: un database vuoto non
        // dimostrerebbe nulla.
        let mut connection = connection();

        let Ok(()) = connection.execute_batch(MIGRATIONS[0].sql) else {
            panic!("la prima migrazione deve applicarsi");
        };
        let Ok(()) = connection.execute_batch(MIGRATIONS[1].sql) else {
            panic!("la seconda migrazione deve applicarsi");
        };
        let Ok(()) = connection.execute_batch("PRAGMA user_version = 2;") else {
            panic!("il pragma deve potersi impostare");
        };

        // Dati di una installazione gia' in uso: fonte, sessione, legame,
        // contenuto e voce di audit.
        let Ok(()) = connection.execute_batch(
            "INSERT INTO sources (kind, identifier, display_name, authorized_by, active,
                                  created_at, updated_at)
             VALUES ('supergroup', 'sg_storico', 'Supergruppo', 'responsabile', 1, 1000, 1000);
             INSERT INTO sessions (label, started_by, duration_mode, planned_seconds, state,
                                   created_at)
             VALUES ('Sessione storica', 'operatore', 'manual', NULL, 'planned', 1000);
             INSERT INTO session_sources (session_id, source_id, selected_at)
             VALUES (1, 1, 1000);
             INSERT INTO contents (session_id, source_id, remote_message_id, body,
                                   published_at, acquired_at, analysis_level, body_sha256)
             VALUES (1, 1, '77', 'testo storico', 1000, 1001, 0,
                     'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa');
             INSERT INTO audit (actor, action, entity, entity_id, recorded_at)
             VALUES ('operatore', 'sessione_creata', 'session', 1, 1000);",
        ) else {
            panic!("i dati di prova devono potersi inserire");
        };

        let Ok(version) = apply(&mut connection) else {
            panic!("l'aggiornamento alla versione 3 deve riuscire");
        };
        assert_eq!(version, LATEST_VERSION);

        // Nulla si e' perso.
        for (table, expected) in [
            ("sources", 1_i64),
            ("sessions", 1),
            ("session_sources", 1),
            ("contents", 1),
            ("audit", 1),
        ] {
            let found: Result<i64, _> =
                connection.query_row(&format!("SELECT count(*) FROM {table}"), [], |row| {
                    row.get(0)
                });
            assert_eq!(
                found,
                Ok(expected),
                "la tabella {table} doveva conservare le righe"
            );
        }

        // La colonna nuova esiste ed e' vuota per le sessioni preesistenti.
        let digest: Result<Option<String>, _> = connection.query_row(
            "SELECT dictionary_digest FROM sessions WHERE id = 1",
            [],
            |row| row.get(0),
        );
        assert_eq!(digest, Ok(None));

        // Nessun riferimento e' rimasto pendente.
        let dangling: Result<i64, _> =
            connection.query_row("SELECT count(*) FROM pragma_foreign_key_check", [], |row| {
                row.get(0)
            });
        assert_eq!(dangling, Ok(0));
    }

    #[test]
    fn upgrading_a_populated_audit_keeps_its_entries_and_adds_the_mode_as_absent() {
        // La colonna nuova e' nullable proprio perche' le voci gia' scritte non
        // hanno una modalita' registrata: attribuirne una a posteriori sarebbe
        // inventare un fatto.
        let mut connection = connection();

        // Si porta il database alla versione 3 e vi si scrive una voce, come
        // avrebbe fatto una installazione precedente.
        for migration in MIGRATIONS.iter().take(3) {
            let Ok(()) = connection.execute_batch(migration.sql) else {
                panic!("la migrazione {} deve applicarsi", migration.name);
            };
        }
        let Ok(()) = connection.execute_batch(
            "PRAGMA user_version = 3;
             INSERT INTO audit (actor, action, entity, entity_id, detail, recorded_at)
             VALUES ('operatore.storico', 'fonte_aggiunta', 'source', 1, 'prima del cambio', 100);",
        ) else {
            panic!("la voce storica deve potersi scrivere");
        };

        let Ok(version) = apply(&mut connection) else {
            panic!("l'aggiornamento deve riuscire");
        };
        assert_eq!(version, LATEST_VERSION);

        let read: Result<(String, Option<String>), _> = connection.query_row(
            "SELECT actor, actor_mode FROM audit WHERE id = 1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        );
        assert_eq!(
            read,
            Ok((String::from("operatore.storico"), None)),
            "la voce storica resta, con la modalita' assente"
        );
    }

    #[test]
    fn every_dictionary_table_exists_after_the_third_migration() {
        let mut connection = connection();
        let Ok(_) = apply(&mut connection) else {
            panic!("le migrazioni devono applicarsi");
        };

        for table in [
            "dictionaries",
            "dictionary_versions",
            "dictionary_terms",
            "dictionary_profiles",
            "dictionary_profile_items",
            "session_dictionary_selections",
            "session_custom_terms",
            "session_resolved_terms",
        ] {
            let found: Result<i64, _> = connection.query_row(
                "SELECT count(*) FROM sqlite_master WHERE type = 'table' AND name = ?1",
                [table],
                |row| row.get(0),
            );
            assert_eq!(found, Ok(1), "la tabella {table} doveva esistere");
        }
    }

    #[test]
    fn every_expected_table_exists_after_the_migrations() {
        let mut connection = connection();
        let Ok(_) = apply(&mut connection) else {
            panic!("le migrazioni devono applicarsi");
        };

        for table in [
            "sources",
            "sessions",
            "session_sources",
            "contents",
            "matches",
            "alerts",
            "reviews",
            "faults",
            "exports",
            "audit",
            "inbox",
            "content_versions",
            "content_deletions",
            "notifications",
            "notification_settings",
            "api_credential_profiles",
            "telegram_accounts",
            "source_health_checks",
        ] {
            let found: Result<i64, _> = connection.query_row(
                "SELECT count(*) FROM sqlite_master WHERE type = 'table' AND name = ?1",
                [table],
                |row| row.get(0),
            );
            assert_eq!(found, Ok(1), "la tabella {table} doveva esistere");
        }
    }

    #[test]
    fn the_acquisition_schema_enforces_its_invariants() {
        let mut connection = connection();
        let Ok(_) = apply(&mut connection) else {
            panic!("le migrazioni devono applicarsi");
        };

        // La chiave di idempotenza e' unica: e' cio' che rende l'accodamento
        // dello stesso evento innocuo senza un controllo applicativo.
        let unique: Result<i64, _> = connection.query_row(
            "SELECT count(*) FROM sqlite_master
             WHERE type = 'index' AND name = 'inbox_idempotency'",
            [],
            |row| row.get(0),
        );
        assert_eq!(
            unique,
            Ok(1),
            "l'indice unico dell'idempotenza deve esistere"
        );

        // Le versioni sono immutabili: i due trigger devono esserci.
        for trigger in [
            "content_versions_are_immutable",
            "content_versions_are_not_deleted",
        ] {
            let found: Result<i64, _> = connection.query_row(
                "SELECT count(*) FROM sqlite_master WHERE type = 'trigger' AND name = ?1",
                [trigger],
                |row| row.get(0),
            );
            assert_eq!(found, Ok(1), "il trigger {trigger} doveva esistere");
        }

        // Il checkpoint di ripresa e' stato aggiunto alle sessioni.
        for column in ["last_completed_inbox_id", "checkpoint_at"] {
            let present: Result<i64, _> = connection.query_row(
                &format!(
                    "SELECT count(*) FROM pragma_table_info('sessions') WHERE name = '{column}'"
                ),
                [],
                |row| row.get(0),
            );
            assert_eq!(present, Ok(1), "la colonna {column} doveva esistere");
        }
    }

    /// Una parola gia' presente in un archivio anteriore alla decima migrazione
    /// deve **sopravvivere** e prendere il livello 1.
    ///
    /// Fino al 2026-07-31 una parola aggiunta a una sessione entrava nella
    /// risoluzione con livello 0, cioe' «non rilevante»: il solo livello che
    /// non produce un avviso e quindi nemmeno una notifica. Le righe gia'
    /// scritte non portano una gravita' perche' allora non esisteva; darle
    /// d'ufficio un livello alto significherebbe attribuire all'operatore un
    /// giudizio che non ha mai dato, mentre lasciarle a zero manterrebbe il
    /// difetto. Il valore predefinito e' quindi il minimo che rende vera la
    /// promessa del wizard.
    #[test]
    fn a_word_written_before_the_tenth_migration_survives_it_with_the_weakest_alerting_level() {
        let connection = connection();
        for migration in &MIGRATIONS[..9] {
            let Ok(()) = connection.execute_batch(migration.sql) else {
                panic!("la migrazione {} deve applicarsi", migration.name);
            };
        }

        // Una sessione e una parola come le scriveva la versione precedente,
        // cioe' senza alcuna colonna del livello.
        let Ok(_) = connection.execute(
            "INSERT INTO sessions (id, label, started_by, duration_mode, planned_seconds,
                                   state, created_at)
             VALUES (1, 'Sessione anteriore', 'responsabile', 'manual', NULL, 'planned', 1000)",
            [],
        ) else {
            panic!("la sessione anteriore deve potersi scrivere");
        };
        let Ok(_) = connection.execute(
            "INSERT INTO session_custom_terms (session_id, text, normalised, match_mode, added_at)
             VALUES (1, 'incendio', 'incendio', 'normalized_word', 1000)",
            [],
        ) else {
            panic!("la parola anteriore deve potersi scrivere");
        };

        let Ok(()) = connection.execute_batch(MIGRATIONS[9].sql) else {
            panic!("la decima migrazione deve applicarsi su un archivio popolato");
        };

        let level: Result<i64, _> = connection.query_row(
            "SELECT suggested_level FROM session_custom_terms WHERE session_id = 1",
            [],
            |row| row.get(0),
        );
        assert_eq!(
            level,
            Ok(1),
            "una parola gia' scritta deve prendere il livello piu' debole che produce un avviso, \
             mai zero: a zero non segnalerebbe nulla, e a un livello superiore le si attribuirebbe \
             una gravita' che nessuno ha dichiarato"
        );
    }

    /// **La 0053 non riscrive i contenuti** (PR-07, controllo negativo 7).
    ///
    /// # Il difetto che questa prova impedisce
    ///
    /// Una migrazione che desse a ogni riga esistente un modo «dal vivo» — con
    /// una colonna nuova e un valore predefinito, o riscrivendo la colonna della
    /// 0012 — affermerebbe per tutte le righe la cosa più forte, senza un fatto
    /// che la dimostri. Il modo si **ricava**; la migrazione aggiunge soltanto il
    /// registro dei recuperi.
    #[test]
    fn la_cinquantatreesima_migrazione_non_riscrive_i_contenuti() {
        let mut connection = connection();
        for migration in &MIGRATIONS[..52] {
            let Ok(()) = connection.execute_batch(migration.sql) else {
                panic!("la migrazione {} deve applicarsi", migration.name);
            };
        }
        if let Err(errore) = connection.execute_batch(
            "PRAGMA user_version = 52;
             INSERT INTO sources (kind, identifier, display_name, authorized_by, active,
                                  created_at, updated_at)
             VALUES ('channel', '-1001', 'Canale di prova', 'operatore.prova', 1, 1, 1);
             INSERT INTO sessions (label, started_by, duration_mode, planned_seconds, state,
                                   created_at, started_at)
             VALUES ('Prova', 'operatore.prova', 'manual', NULL, 'running', 1, 1);
             INSERT INTO session_sources (session_id, source_id, selected_at) VALUES (1, 1, 1);
             INSERT INTO contents (session_id, source_id, remote_message_id, body, published_at,
                                   acquired_at, analysis_level, body_sha256, acquisition_origin)
             VALUES (1, 1, '1', 'dal percorso dal vivo', 5, 6, 0,
                     '0000000000000000000000000000000000000000000000000000000000000000',
                     'osservato'),
                    (1, 1, '2', 'dal recupero', 5, 60, 0,
                     '1111111111111111111111111111111111111111111111111111111111111111',
                     'recuperato');",
        ) {
            panic!("l'archivio di prova deve popolarsi: {errore}");
        }

        let fotografia = |connection: &Connection| -> (Vec<String>, Vec<(i64, String)>) {
            let mut colonne = Vec::new();
            if let Ok(mut statement) = connection.prepare("PRAGMA table_info(contents)")
                && let Ok(righe) = statement.query_map([], |row| row.get::<_, String>(1))
            {
                colonne = righe.filter_map(Result::ok).collect();
            }
            let mut righe = Vec::new();
            if let Ok(mut statement) =
                connection.prepare("SELECT id, acquisition_origin FROM contents ORDER BY id")
                && let Ok(lette) =
                    statement.query_map([], |row| Ok((row.get::<_, i64>(0)?, row.get(1)?)))
            {
                righe = lette.filter_map(Result::ok).collect();
            }
            (colonne, righe)
        };
        let prima = fotografia(&connection);
        assert_eq!(
            prima.1.len(),
            2,
            "l'archivio di prova deve avere due contenuti"
        );

        let Ok(_) = apply(&mut connection) else {
            panic!("la cinquantatreesima migrazione deve applicarsi su un archivio popolato");
        };
        assert_eq!(
            fotografia(&connection),
            prima,
            "la migrazione non tocca i contenuti: né colonne nuove né valori riscritti"
        );
    }

    /// **La 0055 non riscrive i legami esistenti** (PR-10): si aggiunge la
    /// colonna della base, vuota, e nessun valore cambia.
    #[test]
    fn la_cinquantacinquesima_migrazione_non_riscrive_i_legami() {
        let mut connection = connection();
        for migration in &MIGRATIONS[..54] {
            let Ok(()) = connection.execute_batch(migration.sql) else {
                panic!("la migrazione {} deve applicarsi", migration.name);
            };
        }
        if let Err(errore) = connection.execute_batch(
            "PRAGMA user_version = 54;
             INSERT INTO persons (label, reason, opened_by, opened_at)
             VALUES ('Soggetto', 'richiesta dell''autorita'' procedente', 'operatore.prova', 1);
             INSERT INTO identity_links (person_id, identifier, act, reason, linked_by, linked_at)
             VALUES (1, '111', 'collegata', 'riscontro documentale con gli atti', 'operatore.prova', 2);",
        ) {
            panic!("l'archivio di prova deve popolarsi: {errore}");
        }
        let fotografia = |connection: &Connection| -> Vec<(i64, String, String, String, i64)> {
            let mut righe = Vec::new();
            if let Ok(mut statement) = connection.prepare(
                "SELECT id, identifier, act, reason, linked_at FROM identity_links ORDER BY id",
            ) && let Ok(lette) = statement.query_map([], |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                ))
            }) {
                righe = lette.filter_map(Result::ok).collect();
            }
            righe
        };
        let prima = fotografia(&connection);
        assert_eq!(prima.len(), 1, "l'archivio di prova deve avere un legame");

        let Ok(_) = apply(&mut connection) else {
            panic!("la cinquantacinquesima migrazione deve applicarsi su un archivio popolato");
        };
        assert_eq!(fotografia(&connection), prima, "nessun legame riscritto");
        let Ok(vuote) = connection.query_row(
            "SELECT COUNT(*) FROM identity_links WHERE resolution_id IS NULL",
            [],
            |row| row.get::<_, i64>(0),
        ) else {
            panic!("la base deve leggersi");
        };
        assert_eq!(vuote, 1, "la base dei legami di sempre resta vuota");
    }

    /// **La 0061 aggiunge il registro delle ricerche e non tocca altro**
    /// (CYBER-SEARCH-01, criterio 5).
    #[test]
    fn la_sessantunesima_migrazione_aggiunge_e_non_tocca() {
        let mut connection = connection();
        for migration in &MIGRATIONS[..60] {
            let Ok(()) = connection.execute_batch(migration.sql) else {
                panic!("la migrazione {} deve applicarsi", migration.name);
            };
        }
        if let Err(errore) = connection.execute_batch(
            "PRAGMA user_version = 60;
             INSERT INTO persons (label, reason, opened_by, opened_at)
             VALUES ('Soggetto', 'richiesta dell''autorita'' procedente', 'operatore.prova', 1);
             INSERT INTO person_entries (person_id, entry_kind, body, written_by, written_at)
             VALUES (1, 'nota', 'una nota di prima', 'operatore.prova', 2);",
        ) {
            panic!("l'archivio di prova deve popolarsi: {errore}");
        }
        let conta = |connection: &Connection, sql: &str| -> i64 {
            connection
                .query_row(sql, [], |row| row.get(0))
                .unwrap_or(-1)
        };
        let Ok(_) = apply(&mut connection) else {
            panic!("la sessantunesima migrazione deve applicarsi su un archivio popolato");
        };
        assert_eq!(conta(&connection, "SELECT COUNT(*) FROM person_entries"), 1);
        assert_eq!(conta(&connection, "SELECT COUNT(*) FROM persons"), 1);
        assert_eq!(conta(&connection, "SELECT COUNT(*) FROM cyber_searches"), 0);
    }

    /// **La 0076 aggiunge le conservazioni degli allegati, che non cambiano,
    /// non si cancellano e trattengono il loro contenuto** (ATTACH-01 parte 2,
    /// ADR-0177; prova negativa: un esito che non esiste, byte su un rifiuto,
    /// una conservazione senza byte o con un'impronta malformata, una seconda
    /// conservazione, una riscrittura, una cancellazione → rifiutate).
    #[test]
    fn la_settantaseiesima_migrazione_aggiunge_e_non_tocca() {
        let mut connection = connection();
        for migration in &MIGRATIONS[..75] {
            let Ok(()) = connection.execute_batch(migration.sql) else {
                panic!("la migrazione {} deve applicarsi", migration.name);
            };
        }
        if let Err(errore) = connection.execute_batch(
            "PRAGMA user_version = 75;
             PRAGMA foreign_keys = ON;
             INSERT INTO sources (kind, identifier, display_name, authorized_by, active,
                                  created_at, updated_at)
             VALUES ('channel', '-1001', 'Canale di prova', 'operatore.prova', 1, 1, 1);
             INSERT INTO sessions (label, started_by, duration_mode, planned_seconds, state,
                                   created_at, started_at)
             VALUES ('Prova', 'operatore.prova', 'manual', NULL, 'running', 1, 1);
             INSERT INTO session_sources (session_id, source_id, selected_at) VALUES (1, 1, 1);
             INSERT INTO contents (session_id, source_id, remote_message_id, body, published_at,
                                   acquired_at, analysis_level, body_sha256)
             VALUES (1, 1, '1', 'ecco il documento', 5, 6, 0,
                     '0000000000000000000000000000000000000000000000000000000000000000');
             INSERT INTO content_attachments (content_id, kind) VALUES (1, 'documento');",
        ) {
            panic!("l'archivio di prova deve popolarsi: {errore}");
        }
        let Ok(_) = apply(&mut connection) else {
            panic!("la settantaseiesima migrazione deve applicarsi su un archivio popolato");
        };
        let impronta = "a".repeat(64);
        let inserisci = |valori: &str| {
            connection.execute(
                &format!(
                    "INSERT INTO attachment_keepings (content_id, requested_by, reason,
                         requested_at, outcome, bytes, sha256) VALUES (1, 'operatore.prova',
                         'Il documento della minaccia', 10, {valori})"
                ),
                [],
            )
        };
        for sbagliato in [
            "'aperto', NULL, NULL".to_owned(),
            format!("'rifiutato', x'01', '{impronta}'"),
            "'conservato', NULL, NULL".to_owned(),
            "'conservato', x'01', 'ZZ'".to_owned(),
        ] {
            assert!(inserisci(&sbagliato).is_err(), "{sbagliato} va rifiutato");
        }
        let Ok(_) = inserisci("'rifiutato', NULL, NULL") else {
            panic!("un rifiuto si registra");
        };
        let Ok(_) = inserisci(&format!("'conservato', x'01', '{impronta}'")) else {
            panic!("una conservazione valida si registra");
        };
        assert!(
            inserisci(&format!("'conservato', x'02', '{impronta}'")).is_err(),
            "lo stesso allegato non si conserva due volte"
        );
        for istruzione in [
            "UPDATE attachment_keepings SET reason = 'altro'",
            "DELETE FROM attachment_keepings",
            "DELETE FROM contents",
        ] {
            assert!(
                connection.execute(istruzione, []).is_err(),
                "«{istruzione}» va rifiutata"
            );
        }
    }

    /// **La 0077 aggiunge la fonte dei dizionari, i firmatari ammessi e il
    /// registro degli scaricamenti** (DICT-NET-01 parte 2, ADR-0178; prova
    /// negativa: una fonte in chiaro, una fonte cancellata, un'impronta
    /// malformata, un nono firmatario, un esito che non esiste, un ingresso
    /// senza firmatario, una riscrittura, una cancellazione → rifiutati).
    #[test]
    fn la_settantasettesima_migrazione_aggiunge_e_non_tocca() {
        let mut connection = connection();
        for migration in &MIGRATIONS[..76] {
            let Ok(()) = connection.execute_batch(migration.sql) else {
                panic!("la migrazione {} deve applicarsi", migration.name);
            };
        }
        if let Err(errore) = connection.execute_batch("PRAGMA user_version = 76;") {
            panic!("la versione di prova deve scriversi: {errore}");
        }
        let Ok(_) = apply(&mut connection) else {
            panic!("la settantasettesima migrazione deve applicarsi");
        };

        // La fonte: vuota di fabbrica, soltanto https, mai cancellata.
        let Ok(fonte) = connection.query_row(
            "SELECT url FROM dictionary_network_source WHERE id = 1",
            [],
            |row| row.get::<_, Option<String>>(0),
        ) else {
            panic!("la riga della fonte deve esistere da subito");
        };
        assert_eq!(fonte, None, "di fabbrica non c'è una fonte");
        for istruzione in [
            "UPDATE dictionary_network_source SET url = 'http://esempio.test/d.json'",
            "DELETE FROM dictionary_network_source",
            "INSERT INTO dictionary_network_source (id, url, updated_at, updated_by)
             VALUES (2, NULL, 0, 'x')",
        ] {
            assert!(
                connection.execute(istruzione, []).is_err(),
                "«{istruzione}» va rifiutata"
            );
        }
        assert!(
            connection
                .execute(
                    "UPDATE dictionary_network_source SET url = 'https://esempio.test/d.json'",
                    [],
                )
                .is_ok(),
            "una fonte https si scrive"
        );

        // I firmatari: impronte esadecimali minuscole, al più otto.
        let firmatario = |impronta: &str| {
            connection.execute(
                "INSERT INTO dictionary_signers (fingerprint, added_at, added_by)
                 VALUES (?1, 1, 'amministratore.prova')",
                [impronta],
            )
        };
        assert!(
            firmatario(&"A".repeat(64)).is_err(),
            "le maiuscole non passano"
        );
        assert!(
            firmatario(&"a".repeat(63)).is_err(),
            "un'impronta corta non passa"
        );
        for cifra in ["0", "1", "2", "3", "4", "5", "6", "7"] {
            let Ok(_) = firmatario(&cifra.repeat(64)) else {
                panic!("l'ottavo firmatario si ammette ancora");
            };
        }
        assert!(
            firmatario(&"8".repeat(64)).is_err(),
            "il nono firmatario no"
        );

        // Gli scaricamenti: un esito noto, un ingresso completo, nessuna modifica.
        let impronta = "a".repeat(64);
        let scaricamento = |valori: &str| {
            connection.execute(
                &format!(
                    "INSERT INTO dictionary_downloads (requested_by, requested_at, url,
                         content_sha256, signer_sha256, declared_name, declared_version,
                         outcome, outcome_detail, dictionary_id, version_id)
                     VALUES ('operatore.prova', 1, 'https://esempio.test/d.json', {valori})"
                ),
                [],
            )
        };
        for sbagliato in [
            "NULL, NULL, NULL, NULL, 'aperto', NULL, NULL, NULL".to_owned(),
            format!("'{impronta}', NULL, 'Prova', 2, 'importato', NULL, 1, 1"),
            format!("'{impronta}', '{impronta}', 'Prova', 2, 'rifiutato', NULL, 1, 1"),
            format!("'{impronta}', '{impronta}', 'Prova', 0, 'importato', NULL, 1, 1"),
            "'ZZ', NULL, NULL, NULL, 'rifiutato', NULL, NULL, NULL".to_owned(),
        ] {
            assert!(
                scaricamento(&sbagliato).is_err(),
                "{sbagliato} va rifiutato"
            );
        }
        let Ok(_) =
            scaricamento("NULL, NULL, NULL, NULL, 'non_riuscito', 'nessuna risposta', NULL, NULL")
        else {
            panic!("un tentativo non riuscito si registra");
        };
        let Ok(_) = scaricamento(&format!(
            "'{impronta}', '{impronta}', 'Prova', 2, 'importato', NULL, 1, 1"
        )) else {
            panic!("un ingresso completo si registra");
        };
        for istruzione in [
            "UPDATE dictionary_downloads SET outcome_detail = 'altro'",
            "DELETE FROM dictionary_downloads",
        ] {
            assert!(
                connection.execute(istruzione, []).is_err(),
                "«{istruzione}» va rifiutata"
            );
        }
    }

    /// **La 0091 tiene l'Hub sordo ai comandi a distanza di fabbrica, e un
    /// comando registrato non cambia e non si toglie** (HUB-REMOTE-01,
    /// ADR-0200; prova negativa: un atto sconosciuto, una modifica, una
    /// cancellazione, lo stesso identificativo due volte → rifiutati).
    #[test]
    fn la_novantunesima_migrazione_tiene_i_comandi_a_distanza() {
        let mut connection = connection();
        let Ok(_) = apply(&mut connection) else {
            panic!("le migrazioni devono applicarsi");
        };
        let Ok(accettati) = connection.query_row(
            "SELECT accepted FROM remote_command_settings WHERE id = 1",
            [],
            |row| row.get::<_, i64>(0),
        ) else {
            panic!("la scelta si deve leggere");
        };
        assert_eq!(
            accettati, 0,
            "di fabbrica l'Hub non accetta comandi a distanza"
        );
        let inserisci = |identificativo: &str, atto: &str| {
            connection.execute(
                "INSERT INTO remote_commands (command_id, device, person, session_id, action,
                     reason, outcome, detail, received_at)
                 VALUES (?1, 'ABCD-EFGH', 'mrossi', 1, ?2, 'motivo', 'rifiutato', 'detto', 1)",
                rusqlite::params![identificativo, atto],
            )
        };
        assert!(inserisci("cmd-00000001", "pausa").is_ok());
        assert!(
            inserisci("cmd-00000001", "pausa").is_err(),
            "ripetere non raddoppia"
        );
        assert!(inserisci("cmd-00000002", "avvio").is_err());
        for istruzione in [
            "UPDATE remote_commands SET outcome = 'eseguito'",
            "DELETE FROM remote_commands",
            "DELETE FROM remote_command_settings",
            "UPDATE remote_command_settings SET accepted = 2",
        ] {
            assert!(
                connection.execute(istruzione, []).is_err(),
                "«{istruzione}» va rifiutata"
            );
        }
    }

    /// **La 0088 tiene il registro delle consultazioni spento di fabbrica**
    /// (AUDIT-VIEW-01, ADR-0193; prova negativa: una conservazione di 10 giorni
    /// o un genere sconosciuto → rifiutati).
    #[test]
    fn l_ottantottesima_migrazione_tiene_il_registro_spento() {
        let mut connection = connection();
        let Ok(_) = apply(&mut connection) else {
            panic!("le migrazioni devono applicarsi");
        };
        let Ok(spento) = connection.query_row(
            "SELECT retention_days IS NULL FROM consultation_settings",
            [],
            |row| row.get::<_, bool>(0),
        ) else {
            panic!("la scelta si deve leggere");
        };
        assert!(spento);
        assert!(
            connection
                .execute("UPDATE consultation_settings SET retention_days = 10", [])
                .is_err()
        );
        assert!(
            connection
                .execute(
                    "INSERT INTO consultations (actor, kind, entity_id, viewed_at) VALUES ('a', 'scheda', 1, 1)",
                    [],
                )
                .is_err()
        );
    }

    /// **La 0087 registra i rapporti complessivi, e non li cambia**
    /// (REPORT-MULTI-01, ADR-0192; prova negativa: un responsabile vuoto, un
    /// elenco di monitoraggi con lettere, una modifica → rifiutati).
    #[test]
    fn l_ottantasettesima_migrazione_registra_i_rapporti_complessivi() {
        let mut connection = connection();
        let Ok(_) = apply(&mut connection) else {
            panic!("le migrazioni devono applicarsi");
        };
        let impronta = "e".repeat(64);
        let inserisci = |progressivo: i64, nome: &str, monitoraggi: &str| {
            connection.execute(
                "INSERT INTO overview_reports (year, sequence, requested_by, requested_at,
                     responsible_name, responsible_role, session_ids, manifest_sha256)
                 VALUES (2026, ?1, 'operatore', 1, ?2, 'Responsabile', ?3, ?4)",
                rusqlite::params![progressivo, nome, monitoraggi, impronta],
            )
        };
        assert!(inserisci(1, "Mario Rossi", "1,2").is_ok());
        assert!(inserisci(2, " ", "1,2").is_err());
        assert!(inserisci(3, "Mario Rossi", "1,x").is_err());
        assert!(
            connection
                .execute("UPDATE overview_reports SET responsible_name = 'altro'", [])
                .is_err()
        );
    }

    /// **La 0086 tiene la pianificazione spenta di fabbrica** (BACKUP-SCHEDULE-01,
    /// ADR-0191; prova negativa: una cartella senza intervallo → rifiutata; la
    /// riga della pianificazione non si cancella).
    #[test]
    fn l_ottantaseiesima_migrazione_tiene_la_pianificazione_spenta() {
        let mut connection = connection();
        let Ok(_) = apply(&mut connection) else {
            panic!("le migrazioni devono applicarsi");
        };
        let Ok(spenta) = connection.query_row(
            "SELECT destination IS NULL AND interval_days IS NULL AND keep IS NULL FROM backup_schedule",
            [],
            |row| row.get::<_, bool>(0),
        ) else {
            panic!("la pianificazione si deve leggere");
        };
        assert!(spenta);
        assert!(
            connection
                .execute("UPDATE backup_schedule SET destination = 'D:/copie'", [])
                .is_err()
        );
        assert!(
            connection
                .execute("DELETE FROM backup_schedule", [])
                .is_err()
        );
    }

    /// **La 0085 registra le copie per il destinatario, e non le cambia**
    /// (ENCRYPT-02, ADR-0190; prova negativa: un rifiuto senza motivo, una
    /// copia senza impronta, un percorso al posto del nome, una modifica e una
    /// cancellazione → rifiutati).
    #[test]
    fn l_ottantacinquesima_migrazione_registra_le_copie_e_non_le_cambia() {
        let mut connection = connection();
        let Ok(_) = apply(&mut connection) else {
            panic!("le migrazioni devono applicarsi");
        };
        let impronta = "a".repeat(64);
        let inserisci = |nome: &str,
                         copia: Option<&str>,
                         impronta_copia: Option<&str>,
                         esito: &str,
                         motivo: Option<&str>| {
            connection.execute(
                "INSERT INTO recipient_copies (requested_by, requested_at, package_name,
                     manifest_sha256, recipient_subject, recipient_sha256, copy_name,
                     copy_sha256, outcome, outcome_detail)
                 VALUES ('operatore', 1, ?1, ?2, 'Ufficio destinatario', ?2, ?3, ?4, ?5, ?6)",
                rusqlite::params![nome, impronta, copia, impronta_copia, esito, motivo],
            )
        };
        assert!(
            inserisci(
                "pacchetto-1",
                Some("pacchetto-1.zip.p7m"),
                Some(&impronta),
                "cifrata",
                None
            )
            .is_ok()
        );
        assert!(
            inserisci(
                "pacchetto-1",
                None,
                None,
                "non_cifrata",
                Some("certificato scaduto")
            )
            .is_ok()
        );
        assert!(inserisci("pacchetto-1", None, None, "non_cifrata", None).is_err());
        assert!(
            inserisci(
                "pacchetto-1",
                Some("pacchetto-1.zip.p7m"),
                None,
                "cifrata",
                None
            )
            .is_err()
        );
        assert!(
            inserisci(
                r"C:\dati\pacchetto-1",
                Some("x.zip.p7m"),
                Some(&impronta),
                "cifrata",
                None
            )
            .is_err()
        );
        assert!(
            connection
                .execute("UPDATE recipient_copies SET outcome_detail = 'x'", [])
                .is_err()
        );
        assert!(
            connection
                .execute("DELETE FROM recipient_copies", [])
                .is_err()
        );
    }

    /// **La 0084 dice se una notifica riguarda un recuperato** (NOTIFY-BACKFILL-01,
    /// ADR-0188; prova negativa: un valore diverso da 0 e 1 → rifiutato; una
    /// notifica di prima resta dal vivo).
    #[test]
    fn l_ottantaquattresima_migrazione_aggiunge_e_non_tocca() {
        let mut connection = connection();
        for migration in &MIGRATIONS[..83] {
            let Ok(()) = connection.execute_batch(migration.sql) else {
                panic!("la migrazione {} deve applicarsi", migration.name);
            };
        }
        if let Err(errore) = connection.execute_batch("PRAGMA user_version = 83;") {
            panic!("la versione di prova deve scriversi: {errore}");
        }
        let Ok(_) = apply(&mut connection) else {
            panic!("l'ottantaquattresima migrazione deve applicarsi");
        };
        let Ok(colonne) = connection
            .prepare("SELECT name, dflt_value FROM pragma_table_info('notifications') WHERE name = 'recovered'")
            .and_then(|mut richiesta| {
                richiesta
                    .query_map([], |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)))
                    .and_then(Iterator::collect::<Result<Vec<_>, _>>)
            })
        else {
            panic!("le colonne si leggono");
        };
        assert_eq!(colonne, [(String::from("recovered"), String::from("0"))]);
        let Ok(schema) = connection.query_row(
            "SELECT sql FROM sqlite_master WHERE name = 'notifications'",
            [],
            |row| row.get::<_, String>(0),
        ) else {
            panic!("lo schema si legge");
        };
        assert!(schema.contains("CHECK (recovered IN (0, 1))"), "{schema}");
    }

    /// **La 0083 ammette le espressioni fra i modi di un termine** (DICT-REGEX-01,
    /// ADR-0187; prova negativa: un'espressione oltre 200 caratteri o su due
    /// righe → rifiutata; un termine di prima resta con il suo numero).
    #[test]
    fn l_ottantatreesima_migrazione_ammette_le_espressioni() {
        let mut connection = connection();
        for migration in &MIGRATIONS[..82] {
            let Ok(()) = connection.execute_batch(migration.sql) else {
                panic!("la migrazione {} deve applicarsi", migration.name);
            };
        }
        if let Err(errore) = connection.execute_batch("PRAGMA user_version = 82;") {
            panic!("la versione di prova deve scriversi: {errore}");
        }
        if let Err(errore) = connection.execute_batch(
            "INSERT INTO dictionaries (name, description, scope, origin, visibility, status,
                 created_by, created_at, updated_at)
             VALUES ('Prova', 'prova', 'custom', 'operator', 'personal', 'active',
                 'operatore', 1, 1);
             INSERT INTO dictionary_versions (dictionary_id, number, note, created_by,
                 created_at, published_at)
             VALUES (1, 1, 'bozza', 'operatore', 1, NULL);
             INSERT INTO dictionary_terms (id, version_id, text, normalised, category,
                 language, match_mode, suggested_level, note)
             VALUES (7, 1, 'molotov', 'molotov', 'prova', 'it', 'normalized_word', 2, '');",
        ) {
            panic!("l'archivio di prova deve popolarsi: {errore}");
        }
        let Ok(_) = apply(&mut connection) else {
            panic!("l'ottantatreesima migrazione deve applicarsi");
        };
        let termine = |id: i64, testo: &str| {
            connection.execute(
                "INSERT INTO dictionary_terms (id, version_id, text, normalised, category,
                     language, match_mode, suggested_level, note)
                 VALUES (?1, 1, ?2, ?2, 'prova', 'it', 'expression', 2, '')",
                rusqlite::params![id, testo],
            )
        };
        let Ok(_) = termine(8, r"vend[eo]\s+armi") else {
            panic!("un'espressione entra");
        };
        assert!(termine(9, &"a".repeat(201)).is_err(), "oltre 200 caratteri");
        assert!(termine(10, "una\nriga").is_err(), "su due righe");
        let Ok(primo) = connection.query_row(
            "SELECT match_mode FROM dictionary_terms WHERE id = 7",
            [],
            |row| row.get::<_, String>(0),
        ) else {
            panic!("il termine di prima resta");
        };
        assert_eq!(primo, "normalized_word");
    }

    /// **La 0082 aggiunge mitigazioni e rilevazioni di ATT&CK** (ATTACK-03,
    /// ADR-0185; prova negativa: un identificativo che non è né M né DET, un
    /// genere che non corrisponde, un nome vuoto, un legame a una voce che non
    /// c'è, una riscrittura, una cancellazione → rifiutati).
    #[test]
    fn l_ottantaduesima_migrazione_aggiunge_e_non_tocca() {
        let mut connection = connection();
        for migration in &MIGRATIONS[..81] {
            let Ok(()) = connection.execute_batch(migration.sql) else {
                panic!("la migrazione {} deve applicarsi", migration.name);
            };
        }
        if let Err(errore) = connection.execute_batch("PRAGMA user_version = 81;") {
            panic!("la versione di prova deve scriversi: {errore}");
        }
        let Ok(_) = apply(&mut connection) else {
            panic!("l'ottantaduesima migrazione deve applicarsi");
        };
        let Ok(_) = connection.execute(
            "INSERT INTO attack_snapshots (domain, attack_version, spec_version, source_sha256,
                 attribution, license_text, imported_by, imported_at, technique_count, tactic_count)
             VALUES ('enterprise-attack', '19.2', '3.3.0', ?1, 'MITRE', 'Licenza', 'operatore.prova', 1, 0, 0)",
            ["a".repeat(64)],
        ) else {
            panic!("una fotografia di prova si scrive");
        };
        let voce = |valori: &str| {
            connection.execute(
                &format!(
                    "INSERT INTO attack_guidance (snapshot_id, guidance_id, kind, name, description)
                     VALUES (1, {valori})"
                ),
                [],
            )
        };
        for sbagliata in [
            "'X1038', 'mitigazione', 'Nome', ''",
            "'M1038', 'rilevazione', 'Nome', ''",
            "'DET0001', 'mitigazione', 'Nome', ''",
            "'M1038', 'mitigazione', ' ', ''",
        ] {
            assert!(voce(sbagliata).is_err(), "{sbagliata} va rifiutata");
        }
        let Ok(_) = voce("'M1038', 'mitigazione', 'Execution Prevention', 'Bloccare.'") else {
            panic!("una mitigazione si conserva");
        };
        let legame = |valori: &str| {
            connection.execute(
                &format!(
                    "INSERT INTO attack_guidance_techniques (snapshot_id, guidance_id, technique_id)
                     VALUES (1, {valori})"
                ),
                [],
            )
        };
        assert!(
            legame("'M9999', 'T1059'").is_err(),
            "un legame a una voce che non c'è"
        );
        let Ok(_) = legame("'M1038', 'T1059'") else {
            panic!("un legame si conserva");
        };
        for istruzione in [
            "UPDATE attack_guidance SET name = 'altro'",
            "DELETE FROM attack_guidance",
            "UPDATE attack_guidance_techniques SET technique_id = 'T1003'",
            "DELETE FROM attack_guidance_techniques",
        ] {
            assert!(
                connection.execute(istruzione, []).is_err(),
                "«{istruzione}» va rifiutata"
            );
        }
    }

    /// **La 0081 aggiunge i punteggi CVSS accanto alle voci** (CVSS-01,
    /// ADR-0184; prova negativa: una versione che non esiste, un punteggio
    /// oltre 10, un vettore con caratteri inattesi, una severità su due righe,
    /// una riscrittura, una cancellazione → rifiutati).
    #[test]
    fn l_ottantunesima_migrazione_aggiunge_e_non_tocca() {
        let mut connection = connection();
        for migration in &MIGRATIONS[..80] {
            let Ok(()) = connection.execute_batch(migration.sql) else {
                panic!("la migrazione {} deve applicarsi", migration.name);
            };
        }
        if let Err(errore) = connection.execute_batch("PRAGMA user_version = 80;") {
            panic!("la versione di prova deve scriversi: {errore}");
        }
        let Ok(_) = apply(&mut connection) else {
            panic!("l'ottantunesima migrazione deve applicarsi");
        };
        let Ok(_) = connection.execute(
            "INSERT INTO cve_snapshots (source, attribution, imported_by, imported_at)
             VALUES ('NVD_CVE 2.0', 'CVE MITRE', 'operatore.prova', 1)",
            [],
        ) else {
            panic!("una fotografia di prova si scrive");
        };
        let punteggio = |valori: &str| {
            connection.execute(
                &format!(
                    "INSERT INTO cve_scores (snapshot_id, cve_id, version, vector, base_tenths,
                         severity, source)
                     VALUES (1, {valori})"
                ),
                [],
            )
        };
        for sbagliato in [
            "'CVE-2026-1234', '5.0', 'AV:N', 98, 'CRITICAL', 'nvd'",
            "'CVE-2026-1234', '3.1', 'AV:N', 101, 'CRITICAL', 'nvd'",
            "'CVE-2026-1234', '3.1', 'AV:N <b>', 98, 'CRITICAL', 'nvd'",
            "'CVE-2026-1234', '3.1', 'AV:N', 98, 'CRI' || char(10) || 'TICAL', 'nvd'",
            "'non una CVE', '3.1', 'AV:N', 98, 'CRITICAL', 'nvd'",
        ] {
            assert!(punteggio(sbagliato).is_err(), "{sbagliato} va rifiutato");
        }
        let Ok(_) = punteggio(
            "'CVE-2026-1234', '3.1', 'CVSS:3.1/AV:N/AC:L', 98, 'CRITICAL', 'nvd@nist.gov'",
        ) else {
            panic!("un punteggio di NVD si conserva");
        };
        for istruzione in [
            "UPDATE cve_scores SET base_tenths = 10",
            "DELETE FROM cve_scores",
        ] {
            assert!(
                connection.execute(istruzione, []).is_err(),
                "«{istruzione}» va rifiutata"
            );
        }
    }

    /// **La 0080 aggiunge i firmatari degli aggiornamenti** (UPDATE-SIGN-01
    /// parte 1, ADR-0183; prova negativa: un'impronta maiuscola, un nome
    /// vuoto o su due righe, un ritiro senza chi, un nome cambiato, un
    /// ritirato che torna ammesso, una cancellazione, il nono ammesso →
    /// rifiutati).
    #[test]
    fn l_ottantesima_migrazione_aggiunge_e_non_tocca() {
        let mut connection = connection();
        for migration in &MIGRATIONS[..79] {
            let Ok(()) = connection.execute_batch(migration.sql) else {
                panic!("la migrazione {} deve applicarsi", migration.name);
            };
        }
        if let Err(errore) = connection.execute_batch("PRAGMA user_version = 79;") {
            panic!("la versione di prova deve scriversi: {errore}");
        }
        let Ok(_) = apply(&mut connection) else {
            panic!("l'ottantesima migrazione deve applicarsi");
        };

        let ammetti = |impronta: &str, nome: &str| {
            connection.execute(
                &format!(
                    "INSERT INTO update_signers (fingerprint, name, added_at, added_by)
                     VALUES ('{impronta}', {nome}, 1, 'amministratore.prova')"
                ),
                [],
            )
        };
        let a = "a".repeat(64);
        for (impronta, nome) in [
            ("A".repeat(64), "'Produttore'"),
            (a.clone(), "' '"),
            (a.clone(), "'Produt' || char(10) || 'tore'"),
        ] {
            assert!(
                ammetti(&impronta, nome).is_err(),
                "{impronta} {nome} va rifiutato"
            );
        }
        let Ok(_) = ammetti(&a, "'Produttore, chiave 2026'") else {
            panic!("un firmatario con il suo nome si ammette");
        };
        for istruzione in [
            String::from("UPDATE update_signers SET retired_at = 2"),
            String::from("UPDATE update_signers SET name = 'altro'"),
            String::from("DELETE FROM update_signers"),
        ] {
            assert!(
                connection.execute(&istruzione, []).is_err(),
                "«{istruzione}» va rifiutata"
            );
        }
        let Ok(_) = connection.execute(
            "UPDATE update_signers SET retired_at = 2, retired_by = 'amministratore.prova'",
            [],
        ) else {
            panic!("un firmatario si ritira");
        };
        assert!(
            connection
                .execute(
                    "UPDATE update_signers SET retired_at = NULL, retired_by = NULL",
                    [],
                )
                .is_err(),
            "un ritirato non torna ammesso"
        );

        for numero in 0..8 {
            let Ok(_) = ammetti(&format!("{numero:064x}"), "'Chiave'") else {
                panic!("otto firmatari ammessi ci stanno");
            };
        }
        assert!(
            ammetti(&"f".repeat(64), "'La nona'").is_err(),
            "il nono ammesso va rifiutato"
        );
    }

    /// **La 0079 aggiunge il certificato di firma e il registro delle firme**
    /// (SIGN-01 parte 2, ADR-0181, DEC-463; prova negativa: un'impronta in
    /// maiuscolo, un'impronta senza titolare, un titolare con un a capo, il
    /// certificato cancellato, un genere che non esiste, un percorso al posto
    /// del nome, una firma fatta senza la revoca, un rifiuto senza motivo, una
    /// riscrittura, una cancellazione → rifiutati).
    #[test]
    fn la_settantanovesima_migrazione_aggiunge_e_non_tocca() {
        let mut connection = connection();
        for migration in &MIGRATIONS[..78] {
            let Ok(()) = connection.execute_batch(migration.sql) else {
                panic!("la migrazione {} deve applicarsi", migration.name);
            };
        }
        if let Err(errore) = connection.execute_batch("PRAGMA user_version = 78;") {
            panic!("la versione di prova deve scriversi: {errore}");
        }
        let Ok(_) = apply(&mut connection) else {
            panic!("la settantanovesima migrazione deve applicarsi");
        };

        // Il certificato: nessuno di fabbrica, impronta e titolare insieme.
        let Ok(impronta) = connection.query_row(
            "SELECT sha256 FROM signing_certificate WHERE id = 1",
            [],
            |row| row.get::<_, Option<String>>(0),
        ) else {
            panic!("la riga del certificato deve esistere da subito");
        };
        assert_eq!(impronta, None, "di fabbrica non c'è un certificato scelto");
        let minuscola = "a".repeat(64);
        let maiuscola = "A".repeat(64);
        for istruzione in [
            format!("UPDATE signing_certificate SET sha256 = '{maiuscola}', subject = 'Ufficio'"),
            format!("UPDATE signing_certificate SET sha256 = '{minuscola}'"),
            format!(
                "UPDATE signing_certificate SET sha256 = '{minuscola}', subject = 'Uff' || char(10) || 'icio'"
            ),
            String::from("DELETE FROM signing_certificate"),
            String::from(
                "INSERT INTO signing_certificate (id, sha256, subject, updated_at, updated_by)
                 VALUES (2, NULL, NULL, 0, 'x')",
            ),
        ] {
            assert!(
                connection.execute(&istruzione, []).is_err(),
                "«{istruzione}» va rifiutata"
            );
        }
        assert!(
            connection
                .execute(
                    &format!(
                        "UPDATE signing_certificate SET sha256 = '{minuscola}', subject = 'Ufficio di prova'"
                    ),
                    [],
                )
                .is_ok(),
            "un certificato con il suo titolare si sceglie"
        );

        // Le firme: un genere noto, un nome e non un percorso, nessuna modifica.
        let firma = |valori: &str| {
            connection.execute(
                &format!(
                    "INSERT INTO document_signatures (requested_by, requested_at, kind,
                         file_name, file_sha256, certificate_sha256, revocation, outcome,
                         outcome_detail)
                     VALUES ('operatore.prova', 1, {valori})"
                ),
                [],
            )
        };
        let b = "b".repeat(64);
        for sbagliata in [
            format!("'contratto', 'manifest.txt', '{b}', '{b}', 'non_saputo', 'firmato', NULL"),
            format!(
                "'manifest', 'C:\\pacchetti\\manifest.txt', '{b}', '{b}', 'non_saputo', 'firmato', NULL"
            ),
            format!("'manifest', '../manifest.txt', '{b}', '{b}', 'non_saputo', 'firmato', NULL"),
            format!("'manifest', 'manifest.txt', '{b}', '{b}', NULL, 'firmato', NULL"),
            format!("'manifest', 'manifest.txt', '{b}', '{b}', 'non_revocato', 'non_firmato', 'x'"),
            format!("'manifest', 'manifest.txt', '{b}', '{b}', NULL, 'non_firmato', NULL"),
            format!("'manifest', 'manifest.txt', 'ZZ', '{b}', 'non_saputo', 'firmato', NULL"),
        ] {
            assert!(firma(&sbagliata).is_err(), "{sbagliata} va rifiutata");
        }
        let Ok(_) = firma(&format!(
            "'manifest', 'manifest.txt', '{b}', '{b}', 'non_saputo', 'firmato', NULL"
        )) else {
            panic!("una firma fatta si registra");
        };
        let Ok(_) = firma(&format!(
            "'dizionario', 'parole.txt', '{b}', '{b}', NULL, 'non_firmato', 'revocato'"
        )) else {
            panic!("un rifiuto con il suo motivo si registra");
        };
        for istruzione in [
            "UPDATE document_signatures SET outcome_detail = 'altro'",
            "DELETE FROM document_signatures",
        ] {
            assert!(
                connection.execute(istruzione, []).is_err(),
                "«{istruzione}» va rifiutata"
            );
        }
    }

    /// **La 0078 aggiunge la destinazione TAXII e il registro degli invii**
    /// (TAXII-01 parte 2, ADR-0179; prova negativa: una radice in chiaro, una
    /// collezione con una barra, un nome con i due punti, una radice senza
    /// collezione, una destinazione cancellata, un esito che non esiste, una
    /// consegna senza 202, uno stato TAXII su un mancato invio, una
    /// riscrittura, una cancellazione → rifiutati).
    #[test]
    fn la_settantottesima_migrazione_aggiunge_e_non_tocca() {
        let mut connection = connection();
        for migration in &MIGRATIONS[..77] {
            let Ok(()) = connection.execute_batch(migration.sql) else {
                panic!("la migrazione {} deve applicarsi", migration.name);
            };
        }
        if let Err(errore) = connection.execute_batch("PRAGMA user_version = 77;") {
            panic!("la versione di prova deve scriversi: {errore}");
        }
        let Ok(_) = apply(&mut connection) else {
            panic!("la settantottesima migrazione deve applicarsi");
        };

        // La destinazione: vuota di fabbrica, soltanto https, mai cancellata.
        let Ok(radice) = connection.query_row(
            "SELECT api_root FROM taxii_destination WHERE id = 1",
            [],
            |row| row.get::<_, Option<String>>(0),
        ) else {
            panic!("la riga della destinazione deve esistere da subito");
        };
        assert_eq!(radice, None, "di fabbrica non c'è una destinazione");
        for istruzione in [
            "UPDATE taxii_destination SET api_root = 'http://esempio.test/api/', collection_id = 'c1'",
            "UPDATE taxii_destination SET api_root = 'https://esempio.test/api/', collection_id = 'c/1'",
            "UPDATE taxii_destination SET api_root = 'https://esempio.test/api/'",
            "UPDATE taxii_destination SET username = 'nome:altro'",
            "DELETE FROM taxii_destination",
            "INSERT INTO taxii_destination (id, api_root, collection_id, username, updated_at, updated_by)
             VALUES (2, NULL, NULL, NULL, 0, 'x')",
        ] {
            assert!(
                connection.execute(istruzione, []).is_err(),
                "«{istruzione}» va rifiutata"
            );
        }
        assert!(
            connection
                .execute(
                    "UPDATE taxii_destination SET api_root = 'https://esempio.test/api/',
                         collection_id = '91a7b528-80eb-42ed-a74d-c6fbd5a26116',
                         username = 'ufficio.prova'",
                    [],
                )
                .is_ok(),
            "una destinazione completa si scrive"
        );

        // Gli invii: un esito noto, la consegna soltanto con 202, nessuna modifica.
        let impronta = "b".repeat(64);
        let invio = |valori: &str| {
            connection.execute(
                &format!(
                    "INSERT INTO taxii_submissions (requested_by, requested_at, url, session_id,
                         objects, body_sha256, http_status, outcome, outcome_detail,
                         status_id, success_count, failure_count, pending_count)
                     VALUES ('operatore.prova', 1,
                         'https://esempio.test/api/collections/c1/objects/', 1, {valori})"
                ),
                [],
            )
        };
        for sbagliato in [
            format!("3, '{impronta}', 202, 'spedito', NULL, NULL, NULL, NULL, NULL"),
            format!("3, '{impronta}', 200, 'consegnato', NULL, NULL, NULL, NULL, NULL"),
            format!("3, '{impronta}', 401, 'non_consegnato', NULL, 's1', 3, 0, 0"),
            format!("0, '{impronta}', 202, 'consegnato', NULL, NULL, NULL, NULL, NULL"),
            "3, 'ZZ', 202, 'consegnato', NULL, NULL, NULL, NULL, NULL".to_owned(),
            format!("3, '{impronta}', 202, 'consegnato', NULL, 'a b', 3, 0, 0"),
        ] {
            assert!(invio(&sbagliato).is_err(), "{sbagliato} va rifiutato");
        }
        let Ok(_) = invio(&format!(
            "3, '{impronta}', NULL, 'non_consegnato', 'nessuna risposta', NULL, NULL, NULL, NULL"
        )) else {
            panic!("un invio non consegnato si registra");
        };
        let Ok(_) = invio(&format!(
            "3, '{impronta}', 202, 'consegnato', NULL, 'stato-1', 3, 0, 0"
        )) else {
            panic!("una consegna con il suo stato si registra");
        };
        for istruzione in [
            "UPDATE taxii_submissions SET outcome_detail = 'altro'",
            "DELETE FROM taxii_submissions",
        ] {
            assert!(
                connection.execute(istruzione, []).is_err(),
                "«{istruzione}» va rifiutata"
            );
        }
    }

    /// **La 0075 aggiunge le descrizioni degli allegati, che non cambiano e se
    /// ne vanno con il loro contenuto** (ATTACH-01, ADR-0177; prova negativa:
    /// un genere che non esiste, un nome vuoto, un tipo senza barra, una
    /// dimensione nulla, una seconda descrizione, una riscrittura → rifiutati).
    #[test]
    fn la_settantacinquesima_migrazione_aggiunge_e_non_tocca() {
        let mut connection = connection();
        for migration in &MIGRATIONS[..74] {
            let Ok(()) = connection.execute_batch(migration.sql) else {
                panic!("la migrazione {} deve applicarsi", migration.name);
            };
        }
        if let Err(errore) = connection.execute_batch(
            "PRAGMA user_version = 74;
             PRAGMA foreign_keys = ON;
             INSERT INTO sources (kind, identifier, display_name, authorized_by, active,
                                  created_at, updated_at)
             VALUES ('channel', '-1001', 'Canale di prova', 'operatore.prova', 1, 1, 1);
             INSERT INTO sessions (label, started_by, duration_mode, planned_seconds, state,
                                   created_at, started_at)
             VALUES ('Prova', 'operatore.prova', 'manual', NULL, 'running', 1, 1);
             INSERT INTO session_sources (session_id, source_id, selected_at) VALUES (1, 1, 1);
             INSERT INTO contents (session_id, source_id, remote_message_id, body, published_at,
                                   acquired_at, analysis_level, body_sha256)
             VALUES (1, 1, '1', 'guarda qui', 5, 6, 0,
                     '0000000000000000000000000000000000000000000000000000000000000000');",
        ) {
            panic!("l'archivio di prova deve popolarsi: {errore}");
        }
        let Ok(_) = apply(&mut connection) else {
            panic!("la settantacinquesima migrazione deve applicarsi su un archivio popolato");
        };
        let inserisci = |valori: &str| {
            connection.execute(
                &format!(
                    "INSERT INTO content_attachments (content_id, kind, declared_name,
                         declared_size, declared_mime) VALUES (1, {valori})"
                ),
                [],
            )
        };
        for sbagliato in [
            "'eseguibile', NULL, NULL, NULL",
            "'documento', '  ', NULL, NULL",
            "'documento', NULL, NULL, 'pdf'",
            "'documento', NULL, 0, NULL",
        ] {
            assert!(inserisci(sbagliato).is_err(), "{sbagliato} va rifiutato");
        }
        let Ok(_) = inserisci("'documento', 'rapporto.pdf', 73728, 'application/pdf'") else {
            panic!("una descrizione valida si registra");
        };
        assert!(inserisci("'foto', NULL, NULL, NULL").is_err());
        assert!(
            connection
                .execute("UPDATE content_attachments SET kind = 'foto'", [])
                .is_err()
        );
        let Ok(_) = connection.execute("DELETE FROM contents", []) else {
            panic!("il contenuto si toglie");
        };
        let rimaste: i64 = connection
            .query_row("SELECT COUNT(*) FROM content_attachments", [], |row| {
                row.get(0)
            })
            .unwrap_or(-1);
        assert_eq!(rimaste, 0);
    }

    /// **La 0074 aggiunge il registro delle scelte per i documenti, che non
    /// cambia né si cancella** (PERSON-MEDIA-01 parte 3, ADR-0174; prova
    /// negativa: una scelta che non è 0 o 1, senza chi, per un'osservazione
    /// che non c'è, una riscrittura → rifiutate).
    #[test]
    fn la_settantaquattresima_migrazione_aggiunge_e_non_tocca() {
        let mut connection = connection();
        for migration in &MIGRATIONS[..73] {
            let Ok(()) = connection.execute_batch(migration.sql) else {
                panic!("la migrazione {} deve applicarsi", migration.name);
            };
        }
        if let Err(errore) = connection.execute_batch(
            "PRAGMA user_version = 73;
             PRAGMA foreign_keys = ON;
             INSERT INTO sessions (label, started_by, duration_mode, planned_seconds, state,
                 created_at, started_at)
             VALUES ('Sessione', 'operatore', 'manual', NULL, 'running', 1000, 1000);
             INSERT INTO profile_media_observations (session_id, author_identifier,
                 requested_by, reason, requested_at, outcome)
             VALUES (1, '42', 'op', 'motivo', 2000, 'osservato');",
        ) {
            panic!("l'archivio di prova deve popolarsi: {errore}");
        }
        let Ok(_) = apply(&mut connection) else {
            panic!("la settantaquattresima migrazione deve applicarsi su un archivio popolato");
        };
        let inserisci = |valori: &str| {
            connection.execute(
                &format!(
                    "INSERT INTO profile_media_report_marks (observation_id, chosen, marked_by,
                         marked_at) VALUES ({valori})"
                ),
                [],
            )
        };
        for sbagliato in ["1, 2, 'op', 3000", "1, 1, ' ', 3000", "99, 1, 'op', 3000"] {
            assert!(inserisci(sbagliato).is_err(), "{sbagliato} va rifiutato");
        }
        let Ok(_) = inserisci("1, 1, 'op', 3000") else {
            panic!("una scelta valida si registra");
        };
        assert!(
            connection
                .execute("UPDATE profile_media_report_marks SET chosen = 0", [])
                .is_err()
        );
        assert!(
            connection
                .execute("DELETE FROM profile_media_report_marks", [])
                .is_err()
        );
    }

    /// **La 0073 aggiunge le osservazioni di foto, biografia e stato, e
    /// un'osservazione non cambia né si cancella** (PERSON-MEDIA-01, ADR-0174;
    /// prova negativa: un rifiuto con una biografia, una foto senza impronta,
    /// un autore che non è un numero, una riscrittura → rifiutati).
    #[test]
    fn la_settantatreesima_migrazione_aggiunge_e_non_tocca() {
        let mut connection = connection();
        for migration in &MIGRATIONS[..72] {
            let Ok(()) = connection.execute_batch(migration.sql) else {
                panic!("la migrazione {} deve applicarsi", migration.name);
            };
        }
        if let Err(errore) = connection.execute_batch(
            "PRAGMA user_version = 72;
             INSERT INTO sessions (label, started_by, duration_mode, planned_seconds, state,
                 created_at, started_at)
             VALUES ('Sessione', 'operatore', 'manual', NULL, 'running', 1000, 1000);",
        ) {
            panic!("l'archivio di prova deve popolarsi: {errore}");
        }
        let Ok(_) = apply(&mut connection) else {
            panic!("la settantatreesima migrazione deve applicarsi su un archivio popolato");
        };
        let inserisci = |valori: &str| {
            connection.execute(
                &format!(
                    "INSERT INTO profile_media_observations (session_id, author_identifier,
                         account_uuid, requested_by, reason, requested_at, outcome, bio, status,
                         photo, photo_sha256) VALUES (1, {valori})"
                ),
                [],
            )
        };
        let impronta = "a".repeat(64);
        for sbagliato in [
            "'abc', NULL, 'op', 'motivo', 2000, 'osservato', NULL, NULL, NULL, NULL".to_owned(),
            "'42', NULL, 'op', '  ', 2000, 'osservato', NULL, NULL, NULL, NULL".to_owned(),
            "'42', NULL, 'op', 'motivo', 2000, 'rifiutato', 'bio', NULL, NULL, NULL".to_owned(),
            "'42', NULL, 'op', 'motivo', 2000, 'osservato', NULL, NULL, X'FF', NULL".to_owned(),
            format!(
                "'42', NULL, 'op', 'motivo', 2000, 'osservato', NULL, NULL, NULL, '{impronta}'"
            ),
            "'42', NULL, 'op', 'motivo', 2000, 'osservato', NULL, 'attivo', NULL, NULL".to_owned(),
        ] {
            assert!(inserisci(&sbagliato).is_err(), "{sbagliato} va rifiutato");
        }
        let Ok(_) = inserisci(&format!(
            "'42', 'a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1', 'op', 'motivo', 2000, 'osservato', 'bio',
             'di_recente', X'FF', '{impronta}'"
        )) else {
            panic!("un'osservazione valida si registra");
        };
        assert!(
            connection
                .execute("UPDATE profile_media_observations SET bio = 'altra'", [])
                .is_err(),
            "un'osservazione non cambia"
        );
        assert!(
            connection
                .execute("DELETE FROM profile_media_observations", [])
                .is_err(),
            "un'osservazione non si cancella"
        );
    }

    /// **La 0072 aggiunge l'account dei monitoraggi, non tocca le sessioni, e
    /// il legame non cambia né si cancella** (MULTI-ACCOUNT-02 parte 2,
    /// ADR-0173, criterio 2; prova negativa: il divieto di riscrittura tolto →
    /// rossa).
    #[test]
    fn la_settantaduesima_migrazione_aggiunge_e_non_tocca() {
        let mut connection = connection();
        for migration in &MIGRATIONS[..71] {
            let Ok(()) = connection.execute_batch(migration.sql) else {
                panic!("la migrazione {} deve applicarsi", migration.name);
            };
        }
        if let Err(errore) = connection.execute_batch(
            "PRAGMA user_version = 71;
             INSERT INTO sessions (label, started_by, duration_mode, planned_seconds, state,
                 created_at, started_at)
             VALUES ('Sessione', 'operatore', 'manual', NULL, 'running', 1000, 1000);",
        ) {
            panic!("l'archivio di prova deve popolarsi: {errore}");
        }
        let Ok(_) = apply(&mut connection) else {
            panic!("la settantaduesima migrazione deve applicarsi su un archivio popolato");
        };
        let conta = |sql: &str| -> i64 {
            connection
                .query_row(sql, [], |row| row.get(0))
                .unwrap_or(-1)
        };
        assert_eq!(
            conta("SELECT COUNT(*) FROM sessions WHERE state = 'running'"),
            1
        );
        assert_eq!(conta("SELECT COUNT(*) FROM session_accounts"), 0);
        // Un UUID che non ha la forma, o un nome vuoto, si rifiutano.
        for sbagliato in [
            "'ABCDEFABCDEFABCDEFABCDEFABCDEFAB', 'Ufficio', 2000",
            "'a1a1', 'Ufficio', 2000",
            "'a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1', '  ', 2000",
        ] {
            assert!(
                connection
                    .execute(
                        &format!(
                            "INSERT INTO session_accounts (session_id, account_uuid,
                                 account_label, bound_at) VALUES (1, {sbagliato})"
                        ),
                        [],
                    )
                    .is_err(),
                "{sbagliato} va rifiutato"
            );
        }
        let Ok(_) = connection.execute(
            "INSERT INTO session_accounts (session_id, account_uuid, account_label, bound_at)
             VALUES (1, 'a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1', 'Ufficio', 2000)",
            [],
        ) else {
            panic!("un legame valido si registra");
        };
        assert!(
            connection
                .execute(
                    "UPDATE session_accounts
                     SET account_uuid = 'b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2'",
                    [],
                )
                .is_err(),
            "un monitoraggio non passa a un altro account"
        );
        assert!(
            connection
                .execute("DELETE FROM session_accounts", [])
                .is_err()
        );
        assert!(
            connection
                .execute("DELETE FROM sessions WHERE id = 1", [])
                .is_err(),
            "il monitoraggio di un account non sparisce lasciando il legame orfano"
        );
    }

    /// **La 0071 aggiunge le pause dell'acquisizione e non tocca le sessioni**
    /// (PAUSE-01, ADR-0172, criterio 3).
    #[test]
    fn la_settantunesima_migrazione_aggiunge_e_non_tocca() {
        let mut connection = connection();
        for migration in &MIGRATIONS[..70] {
            let Ok(()) = connection.execute_batch(migration.sql) else {
                panic!("la migrazione {} deve applicarsi", migration.name);
            };
        }
        if let Err(errore) = connection.execute_batch(
            "PRAGMA user_version = 70;
             INSERT INTO sessions (label, started_by, duration_mode, planned_seconds, state,
                 created_at, started_at)
             VALUES ('Sessione', 'operatore', 'manual', NULL, 'running', 1000, 1000);",
        ) {
            panic!("l'archivio di prova deve popolarsi: {errore}");
        }
        let Ok(_) = apply(&mut connection) else {
            panic!("la settantunesima migrazione deve applicarsi su un archivio popolato");
        };
        let conta = |sql: &str| -> i64 {
            connection
                .query_row(sql, [], |row| row.get(0))
                .unwrap_or(-1)
        };
        assert_eq!(
            conta("SELECT COUNT(*) FROM sessions WHERE state = 'running'"),
            1
        );
        assert_eq!(conta("SELECT COUNT(*) FROM acquisition_pauses"), 0);
        // Un motivo troppo corto, o una ripresa senza chi, si rifiutano.
        assert!(
            connection
                .execute(
                    "INSERT INTO acquisition_pauses (session_id, paused_at, paused_by, reason)
                     VALUES (1, 2000, 'operatore', 'breve')",
                    [],
                )
                .is_err()
        );
        assert!(
            connection
                .execute(
                    "INSERT INTO acquisition_pauses (session_id, paused_at, paused_by, reason,
                         resumed_at) VALUES (1, 2000, 'operatore', 'un motivo abbastanza lungo', 3000)",
                    [],
                )
                .is_err()
        );
    }

    /// **La 0070 aggiunge gli inizi programmati e non tocca le sessioni**
    /// (SCHEDULE-01, ADR-0171, criterio 4).
    #[test]
    fn la_settantesima_migrazione_aggiunge_e_non_tocca() {
        let mut connection = connection();
        for migration in &MIGRATIONS[..69] {
            let Ok(()) = connection.execute_batch(migration.sql) else {
                panic!("la migrazione {} deve applicarsi", migration.name);
            };
        }
        if let Err(errore) = connection.execute_batch(
            "PRAGMA user_version = 69;
             INSERT INTO sessions (label, started_by, duration_mode, planned_seconds, state,
                 created_at)
             VALUES ('Sessione', 'operatore', 'manual', NULL, 'planned', 1000);",
        ) {
            panic!("l'archivio di prova deve popolarsi: {errore}");
        }
        let Ok(_) = apply(&mut connection) else {
            panic!("la settantesima migrazione deve applicarsi su un archivio popolato");
        };
        let conta = |sql: &str| -> i64 {
            connection
                .query_row(sql, [], |row| row.get(0))
                .unwrap_or(-1)
        };
        assert_eq!(
            conta("SELECT COUNT(*) FROM sessions WHERE state = 'planned'"),
            1
        );
        assert_eq!(conta("SELECT COUNT(*) FROM session_schedules"), 0);
        // L'inizio segue la programmazione, e una ragione sconosciuta no.
        assert!(
            connection
                .execute(
                    "INSERT INTO session_schedules (session_id, start_at, scheduled_by,
                         scheduled_at) VALUES (1, 1000, 'operatore', 2000)",
                    [],
                )
                .is_err()
        );
        assert!(
            connection
                .execute(
                    "INSERT INTO session_schedules (session_id, start_at, scheduled_by,
                         scheduled_at, missed_at, missed_reason)
                     VALUES (1, 3000, 'operatore', 2000, 4000, 'per_caso')",
                    [],
                )
                .is_err()
        );
    }

    /// **La 0069 ammette il codice numerico, conserva i termini e i divieti, e
    /// vincola la forma del codice** (DICT-CODES-01, ADR-0170, criterio 4;
    /// prova negativa: il vincolo sulla forma tolto → rossa).
    #[test]
    fn la_sessantanovesima_migrazione_ricostruisce_senza_perdere() {
        let mut connection = connection();
        for migration in &MIGRATIONS[..68] {
            let Ok(()) = connection.execute_batch(migration.sql) else {
                panic!("la migrazione {} deve applicarsi", migration.name);
            };
        }
        if let Err(errore) = connection.execute_batch(
            "PRAGMA user_version = 68;
             INSERT INTO dictionaries (name, description, scope, origin, visibility, status,
                 created_by, created_at, updated_at)
             VALUES ('Prova', 'prova', 'custom', 'operator', 'personal', 'active',
                 'operatore', 1, 1);
             INSERT INTO dictionary_versions (dictionary_id, number, note, created_by,
                 created_at, published_at)
             VALUES (1, 1, 'pubblicata', 'operatore', 1, 2);
             INSERT INTO dictionary_versions (dictionary_id, number, note, created_by,
                 created_at, published_at)
             VALUES (1, 2, 'bozza', 'operatore', 3, NULL);
             INSERT INTO dictionary_terms (id, version_id, text, normalised, category,
                 language, match_mode, suggested_level, note)
             VALUES (7, 2, '88', '88', 'prova', 'it', 'normalized_word', 2, '');
             INSERT INTO sessions (label, started_by, duration_mode, planned_seconds, state,
                 created_at)
             VALUES ('Sessione', 'operatore', 'manual', NULL, 'planned', 1000);
             INSERT INTO session_resolved_terms (id, session_id, normalised, original,
                 category, language, match_mode, suggested_level, provenances)
             VALUES (9, 1, 'molotov', 'molotov', 'oggetto', 'it', 'normalized_word', 3,
                 'adhoc');
             UPDATE dictionary_versions SET published_at = 4 WHERE id = 2;",
        ) {
            panic!("l'archivio di prova deve popolarsi: {errore}");
        }
        let Ok(_) = apply(&mut connection) else {
            panic!("la sessantanovesima migrazione deve applicarsi su un archivio popolato");
        };
        let conta = |sql: &str| -> i64 {
            connection
                .query_row(sql, [], |row| row.get(0))
                .unwrap_or(-1)
        };
        // I termini di prima restano, con il loro numero e il loro modo.
        assert_eq!(
            conta(
                "SELECT COUNT(*) FROM dictionary_terms
                 WHERE id = 7 AND match_mode = 'normalized_word'"
            ),
            1
        );
        assert_eq!(
            conta("SELECT COUNT(*) FROM session_resolved_terms WHERE id = 9"),
            1
        );

        // I divieti restano: la versione 2 è pubblicata.
        assert!(
            connection
                .execute("DELETE FROM dictionary_terms WHERE id = 7", [])
                .is_err(),
            "un termine di una versione pubblicata non si cancella"
        );
        assert!(
            connection
                .execute("DELETE FROM session_resolved_terms WHERE id = 9", [])
                .is_err(),
            "la fotografia di una sessione non si cancella"
        );

        // Il codice numerico entra con due-dodici cifre e il livello 1.
        let Ok(_) = connection.execute(
            "INSERT INTO dictionary_versions (dictionary_id, number, note, created_by,
                 created_at, published_at)
             VALUES (1, 3, 'bozza', 'operatore', 5, NULL)",
            [],
        ) else {
            panic!("la bozza di prova deve nascere");
        };
        let termine = |testo: &str, livello: i64| {
            connection.execute(
                "INSERT INTO dictionary_terms (version_id, text, normalised, category,
                     language, match_mode, suggested_level, note)
                 VALUES (3, ?1, ?1, 'codice', 'it', 'numeric_code', ?2, '')",
                rusqlite::params![testo, livello],
            )
        };
        assert!(termine("1488", 1).is_ok());
        for (testo, livello) in [("8", 1), ("88a", 1), ("1234567890123", 1), ("14", 2)] {
            assert!(
                termine(testo, livello).is_err(),
                "«{testo}» con livello {livello} non è un codice numerico"
            );
        }
        let fotografia = |testo: &str, livello: i64| {
            connection.execute(
                "INSERT INTO session_resolved_terms (session_id, normalised, original,
                     category, language, match_mode, suggested_level, provenances)
                 VALUES (1, ?1, ?1, 'codice', 'it', 'numeric_code', ?2, 'adhoc')",
                rusqlite::params![testo, livello],
            )
        };
        assert!(fotografia("88", 1).is_ok());
        assert!(fotografia("88x", 1).is_err());
        assert!(fotografia("14", 3).is_err());
    }

    /// **La 0068 aggiunge l'edizione delle novità vista e non tocca il tour**
    /// (NEWS-01, criterio 3).
    #[test]
    fn la_sessantottesima_migrazione_aggiunge_e_non_tocca() {
        let mut connection = connection();
        for migration in &MIGRATIONS[..67] {
            let Ok(()) = connection.execute_batch(migration.sql) else {
                panic!("la migrazione {} deve applicarsi", migration.name);
            };
        }
        if let Err(errore) = connection.execute_batch(
            "PRAGMA user_version = 67;
             INSERT INTO tour_state (id, state, tour_version, updated_at)
             VALUES (1, 'saltato', 2, 1);",
        ) {
            panic!("l'archivio di prova deve popolarsi: {errore}");
        }
        let Ok(_) = apply(&mut connection) else {
            panic!("la sessantottesima migrazione deve applicarsi su un archivio popolato");
        };
        let conta = |sql: &str| -> i64 {
            connection
                .query_row(sql, [], |row| row.get(0))
                .unwrap_or(-1)
        };
        assert_eq!(conta("SELECT COUNT(*) FROM tour_state"), 1);
        assert_eq!(conta("SELECT COUNT(*) FROM news_state"), 0);
    }

    /// **La 0067 aggiunge gli atti sull'affidabilità delle fonti e non tocca le
    /// fonti** (SOURCE-RELIABILITY-01, criterio 4).
    #[test]
    fn la_sessantasettesima_migrazione_aggiunge_e_non_tocca() {
        let mut connection = connection();
        for migration in &MIGRATIONS[..66] {
            let Ok(()) = connection.execute_batch(migration.sql) else {
                panic!("la migrazione {} deve applicarsi", migration.name);
            };
        }
        if let Err(errore) = connection.execute_batch(
            "PRAGMA user_version = 66;
             INSERT INTO sources (kind, identifier, display_name, authorized_by, active,
                 created_at, updated_at)
             VALUES ('channel', '-1001', 'Canale', 'operatore.prova', 1, 1, 1);",
        ) {
            panic!("l'archivio di prova deve popolarsi: {errore}");
        }
        let Ok(_) = apply(&mut connection) else {
            panic!("la sessantasettesima migrazione deve applicarsi su un archivio popolato");
        };
        let conta = |sql: &str| -> i64 {
            connection
                .query_row(sql, [], |row| row.get(0))
                .unwrap_or(-1)
        };
        assert_eq!(conta("SELECT COUNT(*) FROM sources"), 1);
        assert_eq!(conta("SELECT COUNT(*) FROM source_reliability_entries"), 0);
    }

    /// **La 0066 aggiunge l'indirizzo pubblico delle fonti e non tocca le fonti**
    /// (CONTEXT-02, criterio 3).
    #[test]
    fn la_sessantaseiesima_migrazione_aggiunge_e_non_tocca() {
        let mut connection = connection();
        for migration in &MIGRATIONS[..65] {
            let Ok(()) = connection.execute_batch(migration.sql) else {
                panic!("la migrazione {} deve applicarsi", migration.name);
            };
        }
        if let Err(errore) = connection.execute_batch(
            "PRAGMA user_version = 65;
             INSERT INTO sources (kind, identifier, display_name, authorized_by, active,
                 created_at, updated_at)
             VALUES ('channel', '-1001', 'Canale', 'operatore.prova', 1, 1, 1);",
        ) {
            panic!("l'archivio di prova deve popolarsi: {errore}");
        }
        let Ok(_) = apply(&mut connection) else {
            panic!("la sessantaseiesima migrazione deve applicarsi su un archivio popolato");
        };
        let conta = |sql: &str| -> i64 {
            connection
                .query_row(sql, [], |row| row.get(0))
                .unwrap_or(-1)
        };
        assert_eq!(conta("SELECT COUNT(*) FROM sources"), 1);
        assert_eq!(conta("SELECT COUNT(*) FROM source_public_addresses"), 0);
    }

    /// **La 0065 aggiunge le decisioni sui suggerimenti e non tocca le fonti**
    /// (SOURCE-SUGGEST-01, criterio 4).
    #[test]
    fn la_sessantacinquesima_migrazione_aggiunge_e_non_tocca() {
        let mut connection = connection();
        for migration in &MIGRATIONS[..64] {
            let Ok(()) = connection.execute_batch(migration.sql) else {
                panic!("la migrazione {} deve applicarsi", migration.name);
            };
        }
        if let Err(errore) = connection.execute_batch(
            "PRAGMA user_version = 64;
             INSERT INTO sources (kind, identifier, display_name, authorized_by, active,
                 created_at, updated_at)
             VALUES ('channel', '-1001', 'Canale', 'operatore.prova', 1, 1, 1);",
        ) {
            panic!("l'archivio di prova deve popolarsi: {errore}");
        }
        let Ok(_) = apply(&mut connection) else {
            panic!("la sessantacinquesima migrazione deve applicarsi su un archivio popolato");
        };
        let conta = |sql: &str| -> i64 {
            connection
                .query_row(sql, [], |row| row.get(0))
                .unwrap_or(-1)
        };
        assert_eq!(conta("SELECT COUNT(*) FROM sources"), 1);
        assert_eq!(conta("SELECT COUNT(*) FROM source_suggestion_decisions"), 0);
        assert!(
            connection
                .execute("DELETE FROM sources WHERE identifier = '-1001'", [])
                .is_ok(),
            "una fonte si toglie ancora: la decisione non la trattiene"
        );
    }

    /// **La 0064 aggiunge le ricerche ricorrenti e non tocca le ricerche già
    /// registrate** (CYBER-WATCH-02, criterio 1).
    #[test]
    fn la_sessantaquattresima_migrazione_aggiunge_e_non_tocca() {
        let mut connection = connection();
        for migration in &MIGRATIONS[..63] {
            let Ok(()) = connection.execute_batch(migration.sql) else {
                panic!("la migrazione {} deve applicarsi", migration.name);
            };
        }
        if let Err(errore) = connection.execute_batch(
            "PRAGMA user_version = 63;
             INSERT INTO cyber_searches (searched_by, searched_at, branch, query, scope, page,
                 outcome, results, outcome_reason)
             VALUES ('operatore.prova', 1, 'D', 'ransomware', 'perimetro', 1,
                 'rifiutata', 0, 'quota finita');",
        ) {
            panic!("l'archivio di prova deve popolarsi: {errore}");
        }
        let conta = |connection: &Connection, sql: &str| -> i64 {
            connection
                .query_row(sql, [], |row| row.get(0))
                .unwrap_or(-1)
        };
        let Ok(_) = apply(&mut connection) else {
            panic!("la sessantaquattresima migrazione deve applicarsi su un archivio popolato");
        };
        assert_eq!(conta(&connection, "SELECT COUNT(*) FROM cyber_searches"), 1);
        assert_eq!(
            conta(&connection, "SELECT COUNT(*) FROM recurring_searches"),
            0
        );
        assert_eq!(
            conta(&connection, "SELECT COUNT(*) FROM recurring_search_runs"),
            0
        );
    }

    /// **La 0063 ammette il ramo D e conserva le ricerche di prima, con il loro
    /// numero e i due divieti** (CYBER-SEARCH-02, criterio 5).
    #[test]
    fn la_sessantatreesima_migrazione_ammette_la_d_e_conserva() {
        let mut connection = connection();
        for migration in &MIGRATIONS[..62] {
            let Ok(()) = connection.execute_batch(migration.sql) else {
                panic!("la migrazione {} deve applicarsi", migration.name);
            };
        }
        let riga = |id: i64, ramo: &str, chat: &str| {
            format!(
                "INSERT INTO cyber_searches (id, searched_by, searched_at, branch, query, scope,
                     chat_id, page, outcome, results, outcome_reason)
                 VALUES ({id}, 'operatore.prova', {id}, '{ramo}', 'ransomware', 'perimetro',
                     {chat}, 1, 'nessun_risultato', 0, 'nessun messaggio');"
            )
        };
        if let Err(errore) = connection.execute_batch(&format!(
            "PRAGMA user_version = 62; {} {}",
            riga(4, "B", "NULL"),
            riga(9, "C", "-1001")
        )) {
            panic!("l'archivio di prova deve popolarsi: {errore}");
        }
        assert!(
            connection.execute_batch(&riga(10, "D", "NULL")).is_err(),
            "prima della 0063 la D non si registra"
        );
        let fotografia = |connection: &Connection| -> Vec<String> {
            let Ok(mut statement) = connection.prepare(
                "SELECT id || '|' || branch || '|' || ifnull(chat_id, '-') || '|' || searched_at
                 FROM cyber_searches ORDER BY id",
            ) else {
                return Vec::new();
            };
            statement
                .query_map([], |row| row.get::<_, String>(0))
                .map(|righe| righe.filter_map(Result::ok).collect())
                .unwrap_or_default()
        };
        let prima = fotografia(&connection);
        assert_eq!(prima.len(), 2);

        let Ok(_) = apply(&mut connection) else {
            panic!("la sessantatreesima migrazione deve applicarsi su un archivio popolato");
        };
        assert_eq!(
            fotografia(&connection),
            prima,
            "le ricerche di prima restano"
        );
        if let Err(errore) = connection.execute_batch(&riga(10, "D", "NULL")) {
            panic!("dopo la 0063 la D si registra: {errore}");
        }
        assert!(
            connection.execute_batch(&riga(11, "D", "-1001")).is_err(),
            "la D non indica una chat"
        );
        assert!(
            connection.execute_batch(&riga(12, "E", "NULL")).is_err(),
            "la E non si registra"
        );
        let Ok(()) = connection.execute_batch(
            "INSERT INTO cyber_searches (searched_by, searched_at, branch, query, scope, page,
                 outcome, results, outcome_reason)
             VALUES ('operatore.prova', 20, 'B', 'ransomware', 'perimetro', 1,
                 'nessun_risultato', 0, 'nessun messaggio');",
        ) else {
            panic!("una ricerca nuova si registra");
        };
        let Ok(ultimo) = connection.query_row("SELECT MAX(id) FROM cyber_searches", [], |row| {
            row.get::<_, i64>(0)
        }) else {
            panic!("il registro deve leggersi");
        };
        assert_eq!(
            ultimo, 11,
            "la numerazione continua dopo le ricerche di prima"
        );
        for sql in [
            "UPDATE cyber_searches SET query = 'altro'",
            "DELETE FROM cyber_searches",
        ] {
            assert!(
                connection.execute(sql, []).is_err(),
                "i divieti restano: {sql}"
            );
        }
    }

    /// **La 0060 non tocca note, soggetti e legami esistenti** (IDENTITY-02,
    /// B1): aggiunge una tabella, e un archivio alla versione 59 con una nota
    /// scritta, una ritirata, un soggetto e un legame resta identico.
    #[test]
    fn la_sessantesima_migrazione_non_tocca_cio_che_esiste() {
        let mut connection = connection();
        for migration in &MIGRATIONS[..59] {
            let Ok(()) = connection.execute_batch(migration.sql) else {
                panic!("la migrazione {} deve applicarsi", migration.name);
            };
        }
        if let Err(errore) = connection.execute_batch(
            "PRAGMA user_version = 59;
             INSERT INTO notes (kind, target_id, body, author, created_at)
             VALUES ('contenuto', 3, 'nota scritta', 'operatore.prova', 1);
             INSERT INTO notes (kind, target_id, body, author, created_at, withdrawn_by, withdrawn_at)
             VALUES ('fonte', 4, 'nota ritirata', 'operatore.prova', 2, 'operatore.prova', 3);
             INSERT INTO persons (label, reason, opened_by, opened_at)
             VALUES ('Soggetto', 'richiesta dell''autorita'' procedente', 'operatore.prova', 4);
             INSERT INTO identity_links (person_id, identifier, act, reason, linked_by, linked_at)
             VALUES (1, '111', 'collegata', 'riscontro documentale con gli atti', 'operatore.prova', 5);",
        ) {
            panic!("l'archivio di prova deve popolarsi: {errore}");
        }
        let fotografia = |connection: &Connection| -> Vec<String> {
            let mut righe = Vec::new();
            for sql in [
                "SELECT id || '|' || kind || '|' || target_id || '|' || body || '|' || author || '|'
                     || created_at || '|' || ifnull(withdrawn_by, '-') || '|'
                     || ifnull(withdrawn_at, '-') FROM notes ORDER BY id",
                "SELECT id || '|' || label || '|' || reason || '|' || opened_at FROM persons",
                "SELECT id || '|' || person_id || '|' || identifier || '|' || act FROM identity_links",
            ] {
                if let Ok(mut statement) = connection.prepare(sql)
                    && let Ok(lette) = statement.query_map([], |row| row.get::<_, String>(0))
                {
                    righe.extend(lette.filter_map(Result::ok));
                }
            }
            righe
        };
        let prima = fotografia(&connection);
        assert_eq!(prima.len(), 4, "l'archivio di prova ha quattro righe");

        let Ok(_) = apply(&mut connection) else {
            panic!("la sessantesima migrazione deve applicarsi su un archivio popolato");
        };
        assert_eq!(
            fotografia(&connection),
            prima,
            "nulla di esistente riscritto"
        );
        // I trigger di NOTE-01 rifiutano ancora riscrittura e cancellazione.
        for sql in ["UPDATE notes SET body = 'altro'", "DELETE FROM notes"] {
            assert!(
                connection.execute(sql, []).is_err(),
                "«{sql}» deve essere rifiutato"
            );
        }
        // E la tabella nuova accetta una nota sul soggetto di prima.
        assert!(
            connection
                .execute(
                    "INSERT INTO person_entries (person_id, entry_kind, body, written_by, written_at)
                     VALUES (1, 'nota', 'prima nota sul soggetto', 'operatore.prova', 6)",
                    [],
                )
                .is_ok()
        );
    }

    /// **La 0059 non riscrive le ricerche già registrate** (IDENTITY-02, A5):
    /// su un archivio alla versione 58 con una ricerca «trovato», la riga resta
    /// identica e le colonne nuove valgono NULL — «non registrato allora».
    #[test]
    fn la_cinquantanovesima_migrazione_non_riscrive_le_ricerche() {
        let mut connection = connection();
        for migration in &MIGRATIONS[..58] {
            let Ok(()) = connection.execute_batch(migration.sql) else {
                panic!("la migrazione {} deve applicarsi", migration.name);
            };
        }
        if let Err(errore) = connection.execute_batch(
            "PRAGMA user_version = 58;
             INSERT INTO identity_resolutions (requested_by, reason, input_kind, input_value,
                 requested_at, executed, outcome, outcome_reason, found_kind, found_telegram_id,
                 found_name, found_username, table_version)
             VALUES ('operatore.prova', 'verifica disposta dall''autorita''', 'identificativo',
                 '42', 1, 1, 'trovato', 'Nessuna assenza da segnalare.', 'persona', 42,
                 'Mario Rossi', 'mrossi', 1);",
        ) {
            panic!("l'archivio di prova deve popolarsi: {errore}");
        }
        let fotografia = |connection: &Connection| -> Vec<(i64, String, String, Option<String>)> {
            let mut righe = Vec::new();
            if let Ok(mut statement) = connection
                .prepare("SELECT id, outcome, found_name, found_username FROM identity_resolutions")
                && let Ok(lette) = statement.query_map([], |row| {
                    Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?))
                })
            {
                righe = lette.filter_map(Result::ok).collect();
            }
            righe
        };
        let prima = fotografia(&connection);
        assert_eq!(prima.len(), 1);

        let Ok(_) = apply(&mut connection) else {
            panic!("la cinquantanovesima migrazione deve applicarsi su un archivio popolato");
        };
        assert_eq!(fotografia(&connection), prima, "nessuna ricerca riscritta");
        let Ok(vuote) = connection.query_row(
            "SELECT COUNT(*) FROM identity_resolutions WHERE found_usernames IS NULL
                 AND found_first_name IS NULL AND found_phone_masked IS NULL",
            [],
            |row| row.get::<_, i64>(0),
        ) else {
            panic!("la base deve leggersi");
        };
        assert_eq!(
            vuote, 1,
            "le colonne nuove restano vuote sulle righe di prima"
        );
        // Il telefono pieno resta fuori anche da una riga nuova.
        assert!(
            connection
                .execute(
                    "INSERT INTO identity_resolutions (requested_by, reason, input_kind,
                         input_value, requested_at, executed, outcome, outcome_reason,
                         found_kind, found_telegram_id, table_version, found_phone_masked)
                     VALUES ('o', 'r', 'identificativo', '43', 2, 1, 'trovato', 'x', 'persona',
                         43, 1, '+393401234567')",
                    [],
                )
                .is_err(),
            "un telefono con tutte le cifre deve essere rifiutato"
        );
    }

    /// **La 0057 non trasforma un aggiornamento in un tour obbligatorio**
    /// (TOUR-01, ADR-0134 §3): su un archivio che aveva già risposto alla
    /// domanda del primo avvio il tour risulta proposto — nessuna finestra, la
    /// parola «Nuovo» — e su uno che non vi aveva risposto non c'è riga, così
    /// che il tour si proponga dopo la risposta.
    #[test]
    fn la_cinquantasettesima_migrazione_non_impone_il_tour_a_chi_aggiorna() {
        let stato_dopo = |profilo: bool| -> Vec<(String, Option<String>)> {
            let mut connection = connection();
            for migration in &MIGRATIONS[..56] {
                let Ok(()) = connection.execute_batch(migration.sql) else {
                    panic!("la migrazione {} deve applicarsi", migration.name);
                };
            }
            let Ok(()) = connection.execute_batch("PRAGMA user_version = 56;") else {
                panic!("il pragma deve potersi impostare");
            };
            if profilo {
                let Ok(_) = connection.execute(
                    "INSERT INTO report_profile (id, version, updated_at, updated_by)
                     VALUES (1, 1, 5, 'operatore.prova')",
                    [],
                ) else {
                    panic!("il profilo di prova deve scriversi");
                };
            }
            let Ok(_) = apply(&mut connection) else {
                panic!("la cinquantasettesima migrazione deve applicarsi");
            };
            let mut righe = Vec::new();
            if let Ok(mut statement) = connection.prepare("SELECT state, last_step FROM tour_state")
                && let Ok(lette) = statement.query_map([], |row| Ok((row.get(0)?, row.get(1)?)))
            {
                righe = lette.filter_map(Result::ok).collect();
            }
            righe
        };

        assert_eq!(
            stato_dopo(true),
            vec![("proposto".to_owned(), None)],
            "chi aggiorna trova il tour già proposto, senza un passo"
        );
        assert!(
            stato_dopo(false).is_empty(),
            "chi non ha ancora risposto al primo avvio non ha una riga: il tour si proporrà dopo"
        );
    }

    #[test]
    fn la_ventitreesima_migrazione_non_inventa_alcuna_verifica() {
        // E' la garanzia che l'archivio non racconti osservazioni mai avvenute.
        // Le fonti gia' configurate restano SCONOSCIUTE finche' qualcuno non le
        // guarda davvero: scrivere "raggiungibile" per quelle che hanno
        // prodotto contenuti direbbe che qualcuno ha guardato quando nessuno ha
        // guardato.
        let mut connection = connection();

        // Un archivio popolato PRIMA della migrazione 23: si applicano le
        // prime ventidue e si dichiara la versione raggiunta.
        for migration in &MIGRATIONS[..22] {
            let Ok(()) = connection.execute_batch(migration.sql) else {
                panic!("la migrazione {} deve applicarsi", migration.name);
            };
        }
        let Ok(()) = connection.execute_batch("PRAGMA user_version = 22;") else {
            panic!("il pragma deve potersi impostare");
        };
        let Ok(_) = connection.execute(
            "INSERT INTO sources (kind, identifier, display_name, authorized_by, active,
                                  created_at, updated_at)
             VALUES ('channel', '-1001', 'Canale di prova', 'operatore.prova', 1, 1, 1)",
            [],
        ) else {
            panic!("la fonte deve potersi inserire");
        };

        let Ok(_) = apply(&mut connection) else {
            panic!("la ventitreesima migrazione deve applicarsi su un archivio popolato");
        };

        // La fonte c'e' ancora.
        let fonti: Result<i64, _> =
            connection.query_row("SELECT count(*) FROM sources", [], |row| row.get(0));
        assert_eq!(fonti, Ok(1), "la migrazione non deve perdere le fonti");

        // E NESSUNA verifica e' stata inventata per essa.
        let verifiche: Result<i64, _> =
            connection.query_row("SELECT count(*) FROM source_health_checks", [], |row| {
                row.get(0)
            });
        assert_eq!(
            verifiche,
            Ok(0),
            "nessuna verifica deve essere scritta dalla migrazione: le fonti \
             preesistenti restano sconosciute"
        );
    }

    #[test]
    fn una_verifica_di_salute_non_si_modifica_e_non_si_cancella() {
        let mut connection = connection();
        let Ok(_) = apply(&mut connection) else {
            panic!("le migrazioni devono applicarsi");
        };

        // I due trigger esistono.
        for trigger in [
            "source_health_checks_are_immutable",
            "source_health_checks_are_not_deleted",
        ] {
            let found: Result<i64, _> = connection.query_row(
                "SELECT count(*) FROM sqlite_master WHERE type = 'trigger' AND name = ?1",
                [trigger],
                |row| row.get(0),
            );
            assert_eq!(found, Ok(1), "il trigger {trigger} doveva esistere");
        }

        let Ok(_) = connection.execute(
            "INSERT INTO sources (kind, identifier, display_name, authorized_by, active,
                                  created_at, updated_at)
             VALUES ('channel', '-1001', 'Canale di prova', 'operatore.prova', 1, 1, 1)",
            [],
        ) else {
            panic!("la fonte deve potersi inserire");
        };
        let Ok(_) = connection.execute(
            "INSERT INTO source_health_checks (source_id, outcome, observed_at)
             VALUES (1, 'reachable', 1000)",
            [],
        ) else {
            panic!("la verifica deve potersi inserire");
        };

        // E ABORTISCONO DAVVERO: un trigger che esiste e non scatta non
        // protegge nulla.
        assert!(
            connection
                .execute(
                    "UPDATE source_health_checks SET outcome = 'not_accessible'",
                    [],
                )
                .is_err(),
            "una verifica registrata non si modifica"
        );
        assert!(
            connection
                .execute("DELETE FROM source_health_checks", [])
                .is_err(),
            "una verifica registrata non si cancella"
        );

        // E la riga e' rimasta com'era.
        let esito: Result<String, _> =
            connection.query_row("SELECT outcome FROM source_health_checks", [], |row| {
                row.get(0)
            });
        assert_eq!(esito.as_deref(), Ok("reachable"));
    }

    #[test]
    fn un_esito_di_verifica_inventato_e_rifiutato_dallo_schema() {
        let mut connection = connection();
        let Ok(_) = apply(&mut connection) else {
            panic!("le migrazioni devono applicarsi");
        };
        let Ok(_) = connection.execute(
            "INSERT INTO sources (kind, identifier, display_name, authorized_by, active,
                                  created_at, updated_at)
             VALUES ('channel', '-1001', 'Canale di prova', 'operatore.prova', 1, 1, 1)",
            [],
        ) else {
            panic!("la fonte deve potersi inserire");
        };

        assert!(
            connection
                .execute(
                    "INSERT INTO source_health_checks (source_id, outcome, observed_at)
                     VALUES (1, 'inventato', 1000)",
                    [],
                )
                .is_err(),
            "lo schema deve rifiutare un esito che il dominio non conosce"
        );
    }

    /// **La migrazione 0024 non attribuisce una versione di motore ai
    /// contenuti che trova.**
    ///
    /// # Perché la prova applica davvero le migrazioni
    ///
    /// Perché su un archivio vuoto non dimostrerebbe nulla, e su un contenuto
    /// inserito **dopo** l'aggiornamento nemmeno: il rischio è precisamente che
    /// la migrazione riempia la colonna nuova sulle righe che trova.
    ///
    /// Qui l'archivio viene portato alla versione 23, gli si mette dentro un
    /// contenuto come farebbe un'installazione in uso, e **poi** si applica il
    /// resto. La colonna deve restare vuota.
    ///
    /// # Perché deve restare vuota
    ///
    /// Perché quel contenuto fu analizzato da un motore di cui non si sa quale
    /// fosse: la formula è cambiata due volte in questo progetto. Scrivergli
    /// accanto la versione corrente sarebbe comodo e falso.
    #[test]
    fn upgrading_a_populated_database_leaves_the_engine_version_empty() {
        let mut connection = connection();

        // Fino alla 23 compresa: e' lo stato di un'installazione in uso il
        // giorno prima di ENGINE-01.
        for migration in MIGRATIONS.iter().take(23) {
            let Ok(()) = connection.execute_batch(migration.sql) else {
                panic!("la migrazione {} deve applicarsi", migration.name);
            };
        }
        let Ok(()) = connection.execute_batch("PRAGMA user_version = 23;") else {
            panic!("il pragma deve potersi impostare");
        };

        let Ok(()) = connection.execute_batch(
            "INSERT INTO sources (kind, identifier, display_name, authorized_by, active,
                                  created_at, updated_at)
             VALUES ('channel', 'c_storico', 'Canale', 'responsabile', 1, 1000, 1000);
             INSERT INTO sessions (label, started_by, duration_mode, planned_seconds, state,
                                   created_at)
             VALUES ('Sessione storica', 'operatore', 'manual', NULL, 'completed', 1000);
             INSERT INTO session_sources (session_id, source_id, selected_at)
             VALUES (1, 1, 1000);
             INSERT INTO contents (session_id, source_id, remote_message_id, body,
                                   published_at, acquired_at, analysis_level, body_sha256)
             VALUES (1, 1, '99', 'testo di prima', 1000, 1001, 3,
                     'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb');",
        ) else {
            panic!("i dati di prova devono potersi inserire");
        };

        let Ok(version) = apply(&mut connection) else {
            panic!("l'aggiornamento deve riuscire");
        };
        assert_eq!(version, LATEST_VERSION);

        let versione_motore: Result<Option<i64>, _> = connection.query_row(
            "SELECT engine_version FROM contents WHERE id = 1",
            [],
            |row| row.get(0),
        );
        assert_eq!(
            versione_motore,
            Ok(None),
            "la migrazione non deve attribuire una versione di motore a un contenuto \
             analizzato prima che il motore avesse un numero"
        );

        // E il livello non e' stato toccato: la migrazione aggiunge, non riscrive.
        let livello: Result<i64, _> = connection.query_row(
            "SELECT analysis_level FROM contents WHERE id = 1",
            [],
            |row| row.get(0),
        );
        assert_eq!(livello, Ok(3));
    }
}

#[cfg(test)]
mod foreign_key_index_tests {
    use rusqlite::Connection;

    use super::apply;

    /// **Ogni chiave esterna ha un indice sulla colonna che punta**
    /// (FINAL-REVIEW-01, FR-006).
    ///
    /// Senza, ogni riga tolta dalla tabella madre obbliga SQLite a percorrere
    /// per intero la tabella figlia per applicare `ON DELETE`. Fino al
    /// 2026-10-03 `contents.duplicate_of_id` e `inbox.correlated_content_id`
    /// non lo avevano, e la conservazione di un archivio grande teneva il
    /// lucchetto di scrittura per minuti: l'acquisizione falliva nel frattempo.
    /// La guardia guarda lo schema **migrato**, non i file: vale anche per le
    /// chiavi che verranno.
    #[test]
    fn ogni_chiave_esterna_ha_un_indice_sulla_colonna_figlia() {
        let Ok(mut connection) = Connection::open_in_memory() else {
            panic!("il database in memoria deve aprirsi");
        };
        let Ok(_) = apply(&mut connection) else {
            panic!("le migrazioni devono applicarsi");
        };

        let Ok(mut tabelle) = connection.prepare(
            "SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%'",
        ) else {
            panic!("elenco delle tabelle");
        };
        let Ok(nomi) = tabelle
            .query_map([], |row| row.get::<_, String>(0))
            .and_then(Iterator::collect::<Result<Vec<_>, _>>)
        else {
            panic!("lettura delle tabelle");
        };

        // LE TABELLE LE CUI RIGHE SI CANCELLANO IN MASSA: i contenuti, che la
        // conservazione toglie a migliaia, e ciò che li segue per `CASCADE`.
        // Solo lì una chiave esterna senza indice costa una scansione per riga
        // tolta; una fonte o un account si tolgono uno alla volta, e la
        // scansione di una volta non è il difetto che questa guardia cerca.
        let mut cancellate_in_massa = vec![String::from("contents")];
        loop {
            let mut aggiunte = Vec::new();
            for tabella in &nomi {
                if cancellate_in_massa.contains(tabella) {
                    continue;
                }
                let segue: bool = connection
                    .query_row(
                        &format!(
                            "SELECT count(*) FROM pragma_foreign_key_list('{tabella}') \
                             WHERE on_delete = 'CASCADE' AND \"table\" IN ({})",
                            cancellate_in_massa
                                .iter()
                                .map(|nome| format!("'{nome}'"))
                                .collect::<Vec<_>>()
                                .join(",")
                        ),
                        [],
                        |row| row.get::<_, i64>(0),
                    )
                    .is_ok_and(|quante| quante > 0);
                if segue {
                    aggiunte.push(tabella.clone());
                }
            }
            if aggiunte.is_empty() {
                break;
            }
            cancellate_in_massa.extend(aggiunte);
        }

        let mut senza_indice = Vec::new();
        for tabella in &nomi {
            let colonne_figlie: Vec<String> = connection
                .prepare(&format!(
                    "SELECT \"from\" FROM pragma_foreign_key_list('{tabella}') \
                     WHERE seq = 0 AND \"table\" IN ({})",
                    cancellate_in_massa
                        .iter()
                        .map(|nome| format!("'{nome}'"))
                        .collect::<Vec<_>>()
                        .join(",")
                ))
                .and_then(|mut s| {
                    s.query_map([], |row| row.get::<_, String>(0))
                        .and_then(Iterator::collect::<Result<Vec<_>, _>>)
                })
                .unwrap_or_default();
            if colonne_figlie.is_empty() {
                continue;
            }
            // Le colonne che stanno in testa a un indice (o alla chiave primaria).
            let in_testa: Vec<String> = connection
                .prepare(&format!(
                    "SELECT ii.name FROM pragma_index_list('{tabella}') il \
                     JOIN pragma_index_info(il.name) ii WHERE ii.seqno = 0"
                ))
                .and_then(|mut s| {
                    s.query_map([], |row| row.get::<_, String>(0))
                        .and_then(Iterator::collect::<Result<Vec<_>, _>>)
                })
                .unwrap_or_default();
            let chiave_primaria: Vec<String> = connection
                .prepare(&format!(
                    "SELECT name FROM pragma_table_info('{tabella}') WHERE pk = 1"
                ))
                .and_then(|mut s| {
                    s.query_map([], |row| row.get::<_, String>(0))
                        .and_then(Iterator::collect::<Result<Vec<_>, _>>)
                })
                .unwrap_or_default();
            for colonna in colonne_figlie {
                if !in_testa.contains(&colonna) && !chiave_primaria.contains(&colonna) {
                    senza_indice.push(format!("{tabella}.{colonna}"));
                }
            }
        }

        assert!(
            senza_indice.is_empty(),
            "chiavi esterne senza indice sulla colonna figlia: {senza_indice:?}"
        );
    }
}
