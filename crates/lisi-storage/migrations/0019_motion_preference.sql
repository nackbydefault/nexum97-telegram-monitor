-- Migrazione 0019 - la preferenza sul movimento.
--
-- Il movimento del prodotto e' deliberato: il radar che ruota dice a colpo
-- d'occhio se il monitoraggio sta girando, e ADR-0026 lo tratta come
-- informazione e non come decorazione.
--
-- Per una parte delle persone pero' il movimento NON e' un'informazione, e' un
-- sintomo. Chi ha un disturbo vestibolare, chi soffre di emicrania con aura,
-- chi ha una sensibilita' al movimento periferico paga un prezzo reale per
-- un'animazione che continua nel campo visivo mentre lavora ad altro.
--
-- Windows ha una preferenza per questo (UISettings.AnimationsEnabled) e il
-- prodotto non la leggeva.
--
-- =============================================================================
-- PERCHE' TRE VALORI E NON UN INTERRUTTORE
-- =============================================================================
--
-- 'sistema' NON e' riducibile ne' a 'pieno' ne' a 'ridotto'. Se una persona
-- sposta l'interruttore di Windows domani, chi ha scelto 'sistema' deve vederlo
-- cambiare e chi ha scelto 'pieno' no. Un booleano perderebbe proprio quella
-- differenza, e la perderebbe in silenzio.
--
-- =============================================================================
-- PERCHE' IL PREDEFINITO E' 'sistema'
-- =============================================================================
--
-- Due ragioni che puntano nella stessa direzione.
--
-- Chi ha gia' chiesto a Windows di ridurre le animazioni lo ottiene subito,
-- senza dover scoprire che questo prodotto ha un'impostazione sua: una
-- preferenza di accessibilita' che va riconfigurata applicazione per
-- applicazione non e' una preferenza, e' un compito.
--
-- E chi non ha chiesto nulla non vede cambiare l'aspetto del prodotto per un
-- aggiornamento: 'sistema' su una postazione che non chiede riduzione si
-- comporta esattamente come il prodotto si comportava prima.
--
-- =============================================================================
-- CHE COSA IL MOVIMENTO RIDOTTO NON FA
-- =============================================================================
--
-- Non toglie l'informazione: la sposta. Lo stato del monitoraggio resta scritto
-- e colorato. Togliere l'animazione senza dire dove quell'informazione sia
-- finita lascerebbe l'operatore senza, ed e' il modo in cui una funzione di
-- accessibilita' diventa una funzione che nessuno accende.

CREATE TABLE motion_preference (
    id         INTEGER PRIMARY KEY CHECK (id = 1),
    -- 'sistema' | 'pieno' | 'ridotto'.
    --
    -- Il vincolo sta qui e non solo nel codice: un valore inventato a mano
    -- verrebbe letto come 'sistema' dal dominio, ma non deve poter entrare.
    choice     TEXT    NOT NULL CHECK (choice IN ('sistema', 'pieno', 'ridotto')),
    updated_at INTEGER NOT NULL,
    updated_by TEXT    NOT NULL
);

-- La riga predefinita esiste da subito, cosi' chi legge non gestisce l'assenza.
INSERT INTO motion_preference (id, choice, updated_at, updated_by)
VALUES (1, 'sistema', 0, 'sistema');
