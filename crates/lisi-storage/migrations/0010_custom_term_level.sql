-- Livello suggerito delle parole aggiunte per una singola sessione.
--
-- Fino al 2026-07-31 una parola aggiunta dall'operatore entrava nella
-- risoluzione con livello suggerito 0, cioe' «non rilevante»: il solo livello
-- che non produce un avviso e quindi non produce mai una notifica. Il wizard
-- offriva pero' esplicitamente «scegliere almeno un dizionario, **oppure**
-- aggiungere una parola», e chi seguiva la seconda strada otteneva un
-- monitoraggio che non poteva segnalare nulla, senza che nulla lo dicesse
-- (osservato nel pilot del 2026-07-31: un messaggio contenente la parola
-- sorvegliata compariva nello storico come «non rilevante»).
--
-- Chi aggiunge una parola dice ora anche quanto sia grave, da 1 a 4, come per
-- un termine di dizionario.
--
-- Le righe gia' presenti prendono il livello 1 («debole»): e' il valore piu'
-- prudente che rende vera la promessa del wizard, e non inventa una gravita'
-- che l'operatore non ha mai espresso. Alzarlo d'ufficio a un livello
-- superiore significherebbe attribuirgli un giudizio che non ha dato.
ALTER TABLE session_custom_terms
    ADD COLUMN suggested_level INTEGER NOT NULL DEFAULT 1
    CHECK (suggested_level BETWEEN 1 AND 4);
