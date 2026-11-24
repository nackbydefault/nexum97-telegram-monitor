-- 0090 — La lingua dell'interfaccia (I18N-01, ADR-0197, DEC-486).
--
-- # Perche' esiste
--
-- L'interfaccia parla anche inglese: la lingua si sceglie per postazione, in
-- Impostazioni, e si conserva qui con chi l'ha scelta e quando, come la
-- preferenza sul movimento (0019).
--
-- # Che cosa non cambia
--
-- L'italiano e' la lingua di partenza: i documenti consegnati, il registro
-- delle operazioni e i valori in archivio restano in italiano qualunque sia
-- la scelta. Questa riga decide soltanto che cosa legge l'operatore.

CREATE TABLE interface_language (
    id         INTEGER PRIMARY KEY CHECK (id = 1),
    -- 'it' | 'en': il nome della cartella del catalogo.
    --
    -- Il vincolo sta qui e non solo nel codice: un valore inventato a mano
    -- verrebbe letto come italiano dal dominio, ma non deve poter entrare.
    choice     TEXT    NOT NULL CHECK (choice IN ('it', 'en')),
    updated_at INTEGER NOT NULL,
    updated_by TEXT    NOT NULL
);

-- La riga predefinita esiste da subito, cosi' chi legge non gestisce l'assenza.
INSERT INTO interface_language (id, choice, updated_at, updated_by)
VALUES (1, 'it', 0, 'sistema');
