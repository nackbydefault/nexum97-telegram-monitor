//! Verifica dei vincoli dello schema dei dizionari.
//!
//! I vincoli che contano stanno **nello schema**, non nel codice applicativo:
//! un vincolo scritto solo nel codice viene aggirato dal primo percorso che
//! dimentica di controllarlo. Questi test li provano contro il motore, con
//! istruzioni SQL dirette, non attraverso i repository: se passassero solo dai
//! repository dimostrerebbero che i repository si comportano bene, non che lo
//! schema difende.

use lisi_storage::Database;
use rusqlite::Connection;

/// Database migrato, con l'accesso diretto alla connessione per le prove.
fn connection() -> Connection {
    let Ok(mut connection) = Connection::open_in_memory() else {
        panic!("il database in memoria deve potersi aprire");
    };
    let Ok(_) = lisi_storage::migrations::apply(&mut connection) else {
        panic!("le migrazioni devono applicarsi");
    };
    // Le foreign key sono disattivate per impostazione predefinita in SQLite e
    // vanno abilitate per connessione: senza questo i vincoli di integrita'
    // proverebbero soltanto che i trigger funzionano, non le foreign key.
    let Ok(()) = connection.pragma_update(None, "foreign_keys", "ON") else {
        panic!("il pragma deve potersi impostare");
    };
    connection
}

/// Inserisce un dizionario e restituisce il suo identificatore.
fn insert_dictionary(connection: &Connection, name: &str, visibility: &str) -> i64 {
    let Ok(()) = connection.execute_batch(&format!(
        "INSERT INTO dictionaries (name, description, scope, origin, visibility, status,
                                   created_by, created_at, updated_at)
         VALUES ('{name}', 'descrizione', 'thematic', 'system', '{visibility}', 'active',
                 'sistema', 1000, 1000);"
    )) else {
        panic!("il dizionario di prova deve potersi inserire");
    };
    connection.last_insert_rowid()
}

/// Inserisce una versione e restituisce il suo identificatore.
fn insert_version(connection: &Connection, dictionary_id: i64, published: bool) -> i64 {
    let published_at = if published { "2000" } else { "NULL" };
    let Ok(()) = connection.execute_batch(&format!(
        "INSERT INTO dictionary_versions (dictionary_id, number, note, created_by,
                                          created_at, published_at)
         VALUES ({dictionary_id}, 1, 'nota', 'sistema', 1000, {published_at});"
    )) else {
        panic!("la versione di prova deve potersi inserire");
    };
    connection.last_insert_rowid()
}

/// Inserisce un termine nella versione indicata.
fn insert_term(connection: &Connection, version_id: i64, text: &str) -> rusqlite::Result<usize> {
    connection.execute(
        "INSERT INTO dictionary_terms (version_id, text, normalised, category, language,
                                       match_mode, suggested_level, note)
         VALUES (?1, ?2, ?2, 'categoria', 'it', 'normalized_word', 1, '')",
        rusqlite::params![version_id, text],
    )
}

// ------------------------------------------------------- versioni immutabili

#[test]
fn a_draft_version_accepts_terms() {
    let connection = connection();
    let dictionary = insert_dictionary(&connection, "Bozza", "personal");
    let version = insert_version(&connection, dictionary, false);

    assert_eq!(insert_term(&connection, version, "incendio").ok(), Some(1));
}

#[test]
fn a_published_version_refuses_new_terms() {
    let connection = connection();
    let dictionary = insert_dictionary(&connection, "Pubblicato", "personal");
    let version = insert_version(&connection, dictionary, true);

    assert!(
        insert_term(&connection, version, "incendio").is_err(),
        "aggiungere un termine a una versione pubblicata deve fallire nel motore"
    );
}

#[test]
fn the_terms_of_a_published_version_cannot_be_modified() {
    let connection = connection();
    let dictionary = insert_dictionary(&connection, "Da pubblicare", "personal");
    let version = insert_version(&connection, dictionary, false);
    let Ok(_) = insert_term(&connection, version, "incendio") else {
        panic!("il termine deve potersi inserire in bozza");
    };

    // Pubblicazione: consentita, perche' porta published_at da NULL a un valore.
    let Ok(_) = connection.execute(
        "UPDATE dictionary_versions SET published_at = 2000 WHERE id = ?1",
        [version],
    ) else {
        panic!("la pubblicazione deve essere consentita");
    };

    assert!(
        connection
            .execute(
                "UPDATE dictionary_terms SET text = 'alterato' WHERE version_id = ?1",
                [version]
            )
            .is_err(),
        "modificare un termine pubblicato deve fallire"
    );
    assert!(
        connection
            .execute(
                "DELETE FROM dictionary_terms WHERE version_id = ?1",
                [version]
            )
            .is_err(),
        "cancellare un termine pubblicato deve fallire"
    );
}

#[test]
fn a_published_version_cannot_be_modified_or_deleted() {
    let connection = connection();
    let dictionary = insert_dictionary(&connection, "Pubblicato", "personal");
    let version = insert_version(&connection, dictionary, true);

    assert!(
        connection
            .execute(
                "UPDATE dictionary_versions SET note = 'alterata' WHERE id = ?1",
                [version]
            )
            .is_err()
    );
    assert!(
        connection
            .execute("DELETE FROM dictionary_versions WHERE id = ?1", [version])
            .is_err()
    );
}

#[test]
fn a_draft_version_can_still_be_corrected() {
    // L'immutabilita' riguarda cio' che e' pubblicato, non cio' che e' in
    // lavorazione: altrimenti non si potrebbe compilare un dizionario.
    let connection = connection();
    let dictionary = insert_dictionary(&connection, "Bozza", "personal");
    let version = insert_version(&connection, dictionary, false);
    let Ok(_) = insert_term(&connection, version, "incendio") else {
        panic!("il termine deve potersi inserire");
    };

    assert!(
        connection
            .execute(
                "UPDATE dictionary_terms SET note = 'spiegazione' WHERE version_id = ?1",
                [version]
            )
            .is_ok()
    );
    assert!(
        connection
            .execute(
                "DELETE FROM dictionary_terms WHERE version_id = ?1",
                [version]
            )
            .is_ok()
    );
}

// ------------------------------------------------------ dizionari di sistema

#[test]
fn a_built_in_dictionary_cannot_be_renamed_or_deleted() {
    let connection = connection();
    let dictionary = insert_dictionary(&connection, "Globale", "built_in");

    assert!(
        connection
            .execute(
                "UPDATE dictionaries SET name = 'Rinominato' WHERE id = ?1",
                [dictionary]
            )
            .is_err(),
        "un dizionario di sistema non si rinomina: va duplicato"
    );
    assert!(
        connection
            .execute("DELETE FROM dictionaries WHERE id = ?1", [dictionary])
            .is_err()
    );
}

#[test]
fn the_status_of_a_built_in_dictionary_can_still_change() {
    // Un seed piu' recente puo' rendere superata una versione precedente:
    // l'identita' e' bloccata, lo stato no.
    let connection = connection();
    let dictionary = insert_dictionary(&connection, "Globale", "built_in");

    assert!(
        connection
            .execute(
                "UPDATE dictionaries SET status = 'superseded', updated_at = 3000 WHERE id = ?1",
                [dictionary]
            )
            .is_ok()
    );
}

#[test]
fn a_personal_dictionary_can_be_renamed_and_deleted() {
    let connection = connection();
    let dictionary = insert_dictionary(&connection, "Mio", "personal");

    assert!(
        connection
            .execute(
                "UPDATE dictionaries SET name = 'Mio nuovo' WHERE id = ?1",
                [dictionary]
            )
            .is_ok()
    );
    assert!(
        connection
            .execute("DELETE FROM dictionaries WHERE id = ?1", [dictionary])
            .is_ok()
    );
}

// ------------------------------------------------------------- unicita' e FK

#[test]
fn the_same_term_cannot_appear_twice_in_the_same_version_with_the_same_mode() {
    let connection = connection();
    let dictionary = insert_dictionary(&connection, "Bozza", "personal");
    let version = insert_version(&connection, dictionary, false);

    let Ok(_) = insert_term(&connection, version, "incendio") else {
        panic!("il primo inserimento deve riuscire");
    };
    assert!(insert_term(&connection, version, "incendio").is_err());
}

#[test]
fn the_same_term_may_appear_with_a_different_mode() {
    let connection = connection();
    let dictionary = insert_dictionary(&connection, "Bozza", "personal");
    let version = insert_version(&connection, dictionary, false);

    let Ok(_) = insert_term(&connection, version, "incendio") else {
        panic!("il primo inserimento deve riuscire");
    };
    assert!(
        connection
            .execute(
                "INSERT INTO dictionary_terms (version_id, text, normalised, category, language,
                                               match_mode, suggested_level, note)
                 VALUES (?1, 'incendio', 'incendio', 'categoria', 'it', 'phrase', 1, '')",
                [version]
            )
            .is_ok(),
        "parola esatta e frase sono due cose diverse"
    );
}

#[test]
fn a_term_cannot_reference_a_missing_version() {
    let connection = connection();
    assert!(insert_term(&connection, 9_999, "orfano").is_err());
}

#[test]
fn two_versions_of_the_same_dictionary_cannot_share_a_number() {
    let connection = connection();
    let dictionary = insert_dictionary(&connection, "Bozza", "personal");
    let _ = insert_version(&connection, dictionary, false);

    assert!(
        connection
            .execute(
                "INSERT INTO dictionary_versions (dictionary_id, number, note, created_by,
                                                  created_at, published_at)
                 VALUES (?1, 1, 'duplicata', 'sistema', 1000, NULL)",
                [dictionary]
            )
            .is_err()
    );
}

#[test]
fn a_suggested_level_outside_the_range_is_refused_by_the_schema() {
    let connection = connection();
    let dictionary = insert_dictionary(&connection, "Bozza", "personal");
    let version = insert_version(&connection, dictionary, false);

    for level in [-5, 5, 100] {
        assert!(
            connection
                .execute(
                    "INSERT INTO dictionary_terms (version_id, text, normalised, category,
                                                   language, match_mode, suggested_level, note)
                     VALUES (?1, 'x', 'x', 'c', 'it', 'exact_word', ?2, '')",
                    rusqlite::params![version, level]
                )
                .is_err(),
            "il livello {level} doveva essere rifiutato"
        );
    }
}

#[test]
fn an_unknown_match_mode_is_refused_by_the_schema() {
    let connection = connection();
    let dictionary = insert_dictionary(&connection, "Bozza", "personal");
    let version = insert_version(&connection, dictionary, false);

    // La regex non esiste fra le modalita': lo schema la rifiuta come
    // qualunque altro valore sconosciuto.
    assert!(
        connection
            .execute(
                "INSERT INTO dictionary_terms (version_id, text, normalised, category, language,
                                               match_mode, suggested_level, note)
                 VALUES (?1, 'x', 'x', 'c', 'it', 'regex', 1, '')",
                [version]
            )
            .is_err()
    );
}

// -------------------------------------------- configurazione di sessione

#[test]
fn the_resolved_configuration_of_a_session_is_immutable() {
    let connection = connection();
    let Ok(()) = connection.execute_batch(
        "INSERT INTO sessions (label, started_by, duration_mode, planned_seconds, state,
                               created_at)
         VALUES ('Sessione', 'operatore', 'manual', NULL, 'planned', 1000);
         INSERT INTO session_resolved_terms (session_id, normalised, original, category,
                                             language, match_mode, suggested_level, provenances)
         VALUES (1, 'incendio', 'incendio', 'c', 'it', 'normalized_word', 2, 'd1v1');",
    ) else {
        panic!("i dati di prova devono potersi inserire");
    };

    assert!(
        connection
            .execute(
                "UPDATE session_resolved_terms SET suggested_level = 4 WHERE session_id = 1",
                []
            )
            .is_err()
    );
    assert!(
        connection
            .execute(
                "DELETE FROM session_resolved_terms WHERE session_id = 1",
                []
            )
            .is_err()
    );
}

#[test]
fn a_session_with_a_resolved_configuration_cannot_be_deleted() {
    // Conseguenza voluta e dichiarata nella migrazione: la cascata incontra il
    // trigger di immutabilita'. Il test esiste perche' nessuno lo scopra per
    // caso cercando di capire perche' una cancellazione fallisce.
    let connection = connection();
    let Ok(()) = connection.execute_batch(
        "INSERT INTO sessions (label, started_by, duration_mode, planned_seconds, state,
                               created_at)
         VALUES ('Sessione', 'operatore', 'manual', NULL, 'planned', 1000);
         INSERT INTO session_resolved_terms (session_id, normalised, original, category,
                                             language, match_mode, suggested_level, provenances)
         VALUES (1, 'incendio', 'incendio', 'c', 'it', 'normalized_word', 2, 'd1v1');",
    ) else {
        panic!("i dati di prova devono potersi inserire");
    };

    assert!(
        connection
            .execute("DELETE FROM sessions WHERE id = 1", [])
            .is_err()
    );
}

#[test]
fn a_selection_cannot_reference_a_missing_dictionary_or_version() {
    let connection = connection();
    let Ok(()) = connection.execute_batch(
        "INSERT INTO sessions (label, started_by, duration_mode, planned_seconds, state,
                               created_at)
         VALUES ('Sessione', 'operatore', 'manual', NULL, 'planned', 1000);",
    ) else {
        panic!("la sessione di prova deve potersi inserire");
    };

    assert!(
        connection
            .execute(
                "INSERT INTO session_dictionary_selections (session_id, dictionary_id,
                                                            version_id, selected_at)
                 VALUES (1, 999, 999, 1000)",
                []
            )
            .is_err()
    );
}

#[test]
fn a_dictionary_used_by_a_session_cannot_be_deleted() {
    let connection = connection();
    let dictionary = insert_dictionary(&connection, "Usato", "personal");
    let version = insert_version(&connection, dictionary, true);
    let Ok(()) = connection.execute_batch(
        "INSERT INTO sessions (label, started_by, duration_mode, planned_seconds, state,
                               created_at)
         VALUES ('Sessione', 'operatore', 'manual', NULL, 'planned', 1000);",
    ) else {
        panic!("la sessione di prova deve potersi inserire");
    };
    let Ok(_) = connection.execute(
        "INSERT INTO session_dictionary_selections (session_id, dictionary_id, version_id,
                                                    selected_at)
         VALUES (1, ?1, ?2, 1000)",
        rusqlite::params![dictionary, version],
    ) else {
        panic!("la selezione deve potersi inserire");
    };

    assert!(
        connection
            .execute("DELETE FROM dictionaries WHERE id = ?1", [dictionary])
            .is_err(),
        "cancellarlo renderebbe la sessione non piu' interpretabile"
    );
}

#[test]
fn the_database_opens_normally_after_the_third_migration() {
    // Verifica che l'apertura ordinaria continui a funzionare: e' il percorso
    // che l'applicazione usa davvero.
    let Ok(database) = Database::open_in_memory() else {
        panic!("il database deve potersi aprire");
    };
    assert_eq!(
        database.schema_version().ok(),
        Some(lisi_storage::LATEST_VERSION)
    );
    assert_eq!(database.foreign_keys_enabled().ok(), Some(true));
}
