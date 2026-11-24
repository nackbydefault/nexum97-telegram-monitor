-- PR-10, ADR-0126: la base di un legame fra un'identita' e un soggetto.
--
-- IN SOLA AGGIUNTA. Il legame resta quello di PERS-06 (0033): soggetto,
-- identificativo, atto, motivo, chi, quando. Si aggiunge SOLTANTO la base:
-- `resolution_id`, la ricerca puntuale (PR-09) da cui il legame nasce. Vuota,
-- come in ogni riga gia' scritta, vuol dire la base di sempre: un'identita'
-- osservata nei monitoraggi. Nessuna riga esistente cambia.
ALTER TABLE identity_links
    ADD COLUMN resolution_id INTEGER REFERENCES identity_resolutions (id) ON DELETE RESTRICT;

-- Un legame con una base si scrive soltanto se quella ricerca e' un «trovato»,
-- se l'identificativo e' QUELLO che Telegram ha restituito, e se il profilo e'
-- di una persona o di un account. Un «dato non disponibile» o un errore
-- collegati a un soggetto diventerebbero un'informazione che non c'e'; un
-- canale o un gruppo non sono l'identita' di una persona.
CREATE TRIGGER identity_links_basis_is_a_found_person
    BEFORE INSERT ON identity_links
    WHEN NEW.resolution_id IS NOT NULL
BEGIN
    SELECT RAISE(ABORT, 'un legame nasce soltanto da una ricerca che ha trovato una persona, e con il suo identificativo')
    WHERE NOT EXISTS (
        SELECT 1 FROM identity_resolutions
        WHERE id = NEW.resolution_id
          AND outcome = 'trovato'
          AND found_kind IN ('persona', 'account')
          AND CAST(found_telegram_id AS TEXT) = NEW.identifier
    );
END;
