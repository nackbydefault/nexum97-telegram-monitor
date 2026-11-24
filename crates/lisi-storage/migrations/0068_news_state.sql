-- 0068 — L'ultima edizione delle novita' vista su questa postazione (NEWS-01,
-- ADR-0169, DEC-434).
--
-- # Che cosa registra
--
-- Un numero, in una riga sola: l'ultima edizione del registro delle novita'
-- che il giro «Scopri che cosa e' cambiato» ha mostrato, o che una postazione
-- nuova ha registrato senza mostrare. Nessuna riga vuol dire che non e' mai
-- stata registrata un'edizione.
--
-- # Che cosa non registra
--
-- Chi ha guardato, per quanto, che cosa ha aperto: il giro non e' un atto sul
-- lavoro, e non ha audit.
--
-- # Additiva
--
-- Una tabella nuova; nessuna tabella esistente cambia.

CREATE TABLE news_state (
    id           INTEGER PRIMARY KEY CHECK (id = 1),
    seen_edition INTEGER NOT NULL CHECK (seen_edition >= 1),
    updated_at   INTEGER NOT NULL
);
