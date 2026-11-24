-- Identificativo dell'autore di un contenuto acquisito.
--
-- Richiesta dell'ufficio: da un avviso si deve poter risalire a **chi** ha
-- scritto, non solo a che cosa e' stato scritto.
--
-- Perche' una colonna nuova invece di riusare `author`.
--
-- `author` esiste dal primo giorno ed e' sempre rimasta vuota: il connettore
-- reale non risolveva il mittente. E' pensata per un **nome leggibile** - lo
-- username, o il nome mostrato - mentre questa conserva l'**identificativo
-- numerico** che Telegram assegna a un utente.
--
-- Sono due cose diverse e vanno tenute distinte:
--
--   - il nome cambia. Un utente puo' cambiare username quando vuole, e un
--     archivio che conservasse solo quello direbbe, riletto fra un anno, che a
--     scrivere e' stato qualcun altro;
--   - l'identificativo numerico **non cambia** finche' l'account esiste, ma non
--     dice nulla a chi legge un rapporto.
--
-- Conservarli in una sola colonna costringerebbe a indovinare quale dei due si
-- sta guardando. Con due colonne, un contenuto puo' avere l'identificativo
-- senza il nome - che e' esattamente lo stato di oggi, finche' la risoluzione
-- dello username non esiste - e dirlo invece di lasciarlo intendere.
--
-- Ammette NULL, e deve: i contenuti gia' acquisiti non hanno un autore
-- registrato, e inventarne uno sarebbe peggio che lasciarlo assente. Anche in
-- futuro restera' assente per i canali, dove i messaggi sono firmati dal canale
-- e non da una persona.

ALTER TABLE contents ADD COLUMN author_identifier TEXT;

-- L'indice serve alla domanda che l'ufficio ha posto: «che cosa ha scritto
-- questo autore». Senza, quella ricerca scorrerebbe l'intero storico.
CREATE INDEX contents_by_author ON contents (author_identifier)
WHERE author_identifier IS NOT NULL;
