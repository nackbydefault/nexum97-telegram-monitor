-- Migrazione 0018 - gli indicatori tecnici estratti da un contenuto.
--
-- CVE, indirizzi, domini, URL e impronte. L'estrattore esisteva da tempo in
-- lisi-core, era esportato, ed era chiamato da NESSUNO: costruito, collaudato e
-- mai invocato. E' la firma di un difetto che questo progetto ha gia'
-- incontrato piu' volte, e qui si chiude.
--
-- =============================================================================
-- PERCHE' UNA TABELLA E NON UN CALCOLO A OGNI LETTURA
-- =============================================================================
--
-- L'estrazione e' pura: dallo stesso testo esce sempre lo stesso elenco, e
-- ricalcolarla non darebbe mai un risultato diverso. Se servisse solo a
-- MOSTRARE gli indicatori di un contenuto, una tabella sarebbe peso inutile.
--
-- Serve invece a CORRELARE: «quali altri contenuti nominano questa stessa
-- CVE», «quali altri contenuti puntano a questo dominio». Sono domande che
-- vanno nella direzione opposta — dall'indicatore ai contenuti — e senza un
-- indice si risponderebbero rileggendo e rianalizzando ogni corpo in archivio.
--
-- =============================================================================
-- LA CHIAVE E' LA DEDUPLICAZIONE
-- =============================================================================
--
-- (content_id, kind, value) e' la chiave primaria: un contenuto che nomina tre
-- volte lo stesso dominio produce UNA riga. La deduplica non e' affidata al
-- codice che inserisce, dove si dimenticherebbe, ma allo schema.
--
-- `value` e' la forma **normalizzata** prodotta dal dominio: e' quella su cui
-- si correla, e conservare la forma originale accanto significherebbe due
-- verita' e la tentazione di correlare sulla sbagliata.
--
-- =============================================================================
-- CHE COSA QUESTA TABELLA NON E'
-- =============================================================================
--
--   * NON e' una lista di minacce. Un dominio estratto da un messaggio e' un
--     dominio che qualcuno ha scritto, non un dominio pericoloso.
--
--   * NON viene contattata. Nessuna risoluzione DNS, nessuna connessione,
--     nessun prelievo: l'indicatore si estrae e non si contatta (ADR-0035
--     Decisione 8). Contattarlo significherebbe due cose ugualmente
--     inaccettabili — eseguire codice altrui su una postazione d'ufficio, e
--     dire a chi ha pubblicato quel contenuto che qualcuno lo sta guardando.
--
--   * NON sopravvive al contenuto. `ON DELETE CASCADE`: se la conservazione
--     toglie un contenuto, i suoi indicatori se ne vanno con lui. Un indicatore
--     orfano sarebbe un dato che nessuna schermata sa mostrare e nessun
--     documento sa citare.
--
-- =============================================================================

CREATE TABLE content_indicators (
    content_id INTEGER NOT NULL REFERENCES contents (id) ON DELETE CASCADE,
    -- Il genere, nella forma dichiarata dal dominio ('cve', 'ipv4', ...).
    -- Non un numero: un archivio che si legge con uno strumento generico deve
    -- restare comprensibile senza il codice che lo ha scritto.
    kind       TEXT    NOT NULL,
    -- Il valore normalizzato.
    value      TEXT    NOT NULL,

    PRIMARY KEY (content_id, kind, value)
) WITHOUT ROWID;

-- L'indice che rende possibile la domanda inversa: dall'indicatore ai
-- contenuti. E' l'intera ragione per cui questa tabella esiste.
CREATE INDEX idx_content_indicators_lookup
    ON content_indicators (kind, value);
