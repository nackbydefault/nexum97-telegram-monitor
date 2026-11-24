-- 0066 — L'indirizzo pubblico di una fonte, come e' stato visto
-- (CONTEXT-02, ADR-0165, DEC-429).
--
-- # Che cosa registra
--
-- Il nome utente pubblico di una chat accessibile, quando ne ha uno, e
-- l'istante in cui e' stato visto. Serve a «Apri la fonte» quando il
-- collegamento al messaggio non c'e'. Non e' un'identita': un nome puo'
-- cambiare padrone, e l'identita' della fonte resta il suo numero.
--
-- # Additiva
--
-- Una tabella nuova; `sources` non cambia. Se la fonte si toglie, il suo
-- indirizzo se ne va con lei.

CREATE TABLE source_public_addresses (
    source_id   INTEGER PRIMARY KEY REFERENCES sources (id) ON DELETE CASCADE,
    -- La forma di un indirizzo pubblico: da 5 a 32 caratteri, lettere, cifre
    -- e trattini bassi, che comincia con una lettera.
    address     TEXT NOT NULL CHECK (length(address) BETWEEN 5 AND 32
        AND address NOT GLOB '*[^A-Za-z0-9_]*'
        AND substr(address, 1, 1) GLOB '[A-Za-z]'),
    observed_at INTEGER NOT NULL
);
