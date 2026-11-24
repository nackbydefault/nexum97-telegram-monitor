-- Segnalibri e raccolte (BOOK-01).
--
-- # Che cos'e' un segnalibro, e perche' non e' un workspace
--
-- E' un segno: «questo lo ritrovo». Un gesto solo, senza cerimonia.
--
-- Un workspace e' un contenitore di LAVORO: ha un nome, una descrizione, un
-- ciclo di vita, e per metterci qualcosa bisogna prima averlo aperto. Se
-- segnare una cosa richiedesse tutto questo, nessuno segnerebbe niente — e un
-- segnalibro che nessuno mette non serve a nulla.
--
-- La differenza e' la CERIMONIA, ed e' la ragione per cui i due meccanismi
-- restano due. Il congelamento li elenca separati, e dice anche che un
-- workspace puo' riferire un segnalibro: sono due cose, e una puo' contenere
-- l'altra.
--
-- # Che cosa NON distingue i due: il modo di riferire
--
-- Quello e' UNO SOLO, e da BOOK-01 vive in `lisi-core::model::reference`. Due
-- nozioni di riferimento avrebbero significato due elenchi di generi ammessi,
-- due convalide, due punti in cui aggiungere «persona» il giorno in cui le
-- persone esisteranno — e il giorno in cui uno dei due si muovesse senza
-- l'altro, nessuno se ne accorgerebbe.
--
-- # Riferimenti, mai copie della prova
--
-- Il congelamento lo scrive con queste parole. Come per i workspace, il modo di
-- rispettarlo non e' ricordarsene: in `bookmarks` NON ESISTE UNA COLONNA in cui
-- una copia possa stare. Non un `body`, non un `titolo`, non un'anteprima.
--
-- # Perche' un segnalibro non ha un testo proprio
--
-- Perche' le parole dell'operatore sono NOTE-01, e darne un pezzo anche qui
-- creerebbe due posti in cui scrivere la stessa cosa. Un segnalibro e' un
-- segno: che cosa, quale, chi, quando, ed eventualmente in quale raccolta.

-- Le raccolte: un modo di raggruppare i segnalibri.
--
-- # Perche' senza ciclo di vita
--
-- Perche' una raccolta non e' un lavoro che si conclude: e' un'etichetta. Darle
-- uno stato aperto/chiuso sarebbe copiare il workspace cambiandogli nome, e due
-- meccanismi uguali con nomi diversi divergono.
CREATE TABLE bookmark_collections (
    id INTEGER PRIMARY KEY,
    -- Il nome con cui la si sceglie. Unico: due raccolte omonime sono una
    -- trappola, e qui non c'e' un ciclo di vita che ne liberi il nome.
    name TEXT NOT NULL UNIQUE,
    created_by TEXT NOT NULL,
    created_at INTEGER NOT NULL
);

CREATE TABLE bookmarks (
    id INTEGER PRIMARY KEY,
    -- Che genere di cosa e' segnata.
    --
    -- 'segnalibro' NON e' ammesso: un segnalibro su un segnalibro non
    -- significa nulla, e il giorno in cui qualcuno ne creasse una catena
    -- nessuna lettura saprebbe dove fermarsi. Il genere condiviso ne ha
    -- quattro; qui ne valgono tre, e la differenza e' un fatto del dominio,
    -- non una dimenticanza.
    kind TEXT NOT NULL CHECK (kind IN ('fonte', 'contenuto', 'rapporto')),
    -- Quale. Senza chiave esterna: il riferimento e' polimorfico, come per i
    -- workspace, e il costo e' lo stesso — un riferimento puo' restare appeso,
    -- e chi legge riceve la dichiarazione invece del silenzio.
    target_id INTEGER NOT NULL,
    -- In quale raccolta, se in una. NULL significa «nessuna», ed e' il caso
    -- ordinario: obbligare una raccolta sarebbe reintrodurre la cerimonia che
    -- un segnalibro esiste per non avere.
    collection_id INTEGER REFERENCES bookmark_collections (id) ON DELETE RESTRICT,
    created_by TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    -- La stessa persona non segna due volte la stessa cosa: due righe identiche
    -- non direbbero nulla di piu', e chi legge conterebbe due volte lo stesso
    -- oggetto.
    UNIQUE (kind, target_id, created_by)
);

CREATE INDEX bookmarks_by_collection ON bookmark_collections (name);
CREATE INDEX bookmarks_by_target ON bookmarks (kind, target_id);

-- UNA RACCOLTA CON DENTRO QUALCOSA NON SI CANCELLA.
--
-- `ON DELETE RESTRICT` sulla colonna lo impone gia'. Il trigger esiste per
-- dirlo con parole: un vincolo violato produce un messaggio che parla di chiavi
-- esterne, e chi lo legge non sa che cosa fare.
CREATE TRIGGER bookmark_collections_with_bookmarks_stay
    BEFORE DELETE ON bookmark_collections
    WHEN EXISTS (SELECT 1 FROM bookmarks WHERE collection_id = OLD.id)
BEGIN
    SELECT RAISE(ABORT, 'una raccolta che contiene segnalibri non si cancella: prima si tolgono');
END;
