-- Fin dove questa postazione ha seguito la storia dell'Hub.
--
-- Motivata in ADR-0087 e DEC-325 (HUB-CATCHUP-01).
--
-- ===========================================================================
-- E' IL CURSORE DEL CLIENT, NON DELL'HUB.
--
-- `hub_events` (migrazione 0044) e' la storia, e sta sull'Hub. Questa riga dice
-- dove una POSTAZIONE e' arrivata a leggerla, e sta sulla postazione. Su una
-- macchina che non segue nessun Hub la tabella resta vuota.
--
-- Una riga sola, garantita dal CHECK sulla chiave: ADR-0047 decisione 8 dice
-- che una postazione appartiene a un Hub solo.
--
-- ===========================================================================
-- SI SEGNA CIO' CHE E' STATO APPLICATO, NON CIO' CHE E' STATO RICEVUTO.
--
-- Il numero qui e' l'ultimo evento APPLICATO. Scriverlo prima di applicarlo
-- significherebbe, dopo un arresto improvviso, ripartire OLTRE un evento mai
-- applicato: perso per sempre, e in silenzio. Il prezzo e' che un evento puo'
-- arrivare due volte, e applicarlo due volte non deve fare danno.
--
-- ===========================================================================
-- IL NOME DELLA STORIA STA QUI ACCANTO AL NUMERO.
--
-- Un numero senza il nome della storia non significa niente: e' esattamente il
-- caso dell'Hub reinstallato (ADR-0086, decisione 6). Le due colonne si leggono
-- e si scrivono insieme.

CREATE TABLE hub_stream_cursor (
    id           INTEGER PRIMARY KEY,
    stream_id    TEXT NOT NULL,
    last_applied INTEGER NOT NULL,
    updated_at   INTEGER NOT NULL,

    CHECK (id = 1),
    CHECK (length(stream_id) = 32),
    CHECK (last_applied >= 0)
);
