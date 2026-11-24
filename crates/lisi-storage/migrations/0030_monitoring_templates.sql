-- Modelli di monitoraggio riusabili (TEMPLATE-01).
--
-- # Che cos'e' un modello
--
-- Una configurazione che qualcuno ha gia' messo a punto e vuole riusare: quali
-- fonti guardare, con quali dizionari, e che cosa prevede per la soglia di
-- notifica e per la conservazione.
--
-- # UN MODELLO PROPONE, NON APPLICA
--
-- E' la decisione da cui discende tutto il resto, e nasce da un fatto dello
-- schema: `notification_settings` e `retention_policy` sono tabelle A RIGA
-- UNICA. Non appartengono a una sessione: appartengono alla POSTAZIONE.
--
-- Un modello che le scrivesse riconfigurerebbe la postazione intera — comprese
-- le sessioni in corso e quelle gia' concluse — con un gesto che sembra
-- «preparare un monitoraggio». E la conservazione, in particolare, CANCELLA:
-- abbassarla in silenzio distruggerebbe materiale che qualcuno si aspettava di
-- ritrovare.
--
-- Percio' i valori qui sotto sono cio' che il modello PREVEDE. Applicarlo
-- prepara le fonti e i dizionari — che sono della sessione — e per le
-- impostazioni di postazione DICHIARA LA DIFFERENZA, senza toccarle. Cambiarle
-- resta un atto deliberato, dove le impostazioni si cambiano.
--
-- # LE VERSIONI DEI DIZIONARI NON STANNO QUI
--
-- Un modello nomina un PROFILO di dizionari, e un profilo nomina i dizionari
-- per identita' — mai per versione. Non e' una scorciatoia: e' la sola scelta
-- che tiene insieme due cose che il prodotto vuole entrambe.
--
-- Se un modello fissasse le versioni, un monitoraggio preparato da quel modello
-- userebbe per sempre i dizionari com'erano il giorno in cui fu creato, e
-- smetterebbe in silenzio di raccogliere le correzioni — che sono esattamente
-- cio' per cui FEEDBACK-01 esiste.
--
-- La versione si risolve QUANDO IL MODELLO SI APPLICA, con la regola che
-- c'era gia': l'ultima versione pubblicata del dizionario. E cio' a cui si e'
-- risolta viene registrato sulla sessione, dove gia' si registra.
--
-- Il costo si dichiara: applicare lo stesso modello due volte puo' risolvere
-- diversamente. E' voluto, e il prodotto lo DICE — come SEARCH-01 dice che
-- rifare una ricerca non riproduce il risultato.
CREATE TABLE monitoring_templates (
    id INTEGER PRIMARY KEY,
    -- Il nome con cui lo si ritrova. Unico: due modelli omonimi sono una
    -- trappola, e preparare un monitoraggio con quello sbagliato non si vede.
    name TEXT NOT NULL UNIQUE,
    -- A che cosa serve. Facoltativa: obbligarla produrrebbe descrizioni finte.
    description TEXT,

    -- IL PROFILO DI DIZIONARI, per identita'.
    --
    -- NULL significa «nessun profilo»: un modello puo' prescrivere solo le
    -- fonti, e chi lo applica sceglie i dizionari come farebbe senza modello.
    --
    -- RESTRICT e non CASCADE: se qualcuno cancella un profilo usato da un
    -- modello, il modello NON deve sparire con lui — sparirebbe una
    -- configurazione che qualcuno usava, senza che nulla lo dica.
    dictionary_profile_id INTEGER REFERENCES dictionary_profiles (id) ON DELETE RESTRICT,

    -- CIO' CHE IL MODELLO PREVEDE per le impostazioni di postazione.
    --
    -- NULL significa «il modello non si esprime»: applicandolo, quella
    -- impostazione non viene nemmeno confrontata. E' diverso da un valore
    -- uguale a quello corrente, che invece e' un confronto con esito «uguale».
    prescribed_notification_level INTEGER
        CHECK (prescribed_notification_level IS NULL
               OR prescribed_notification_level BETWEEN 1 AND 4),
    -- Giorni di conservazione previsti. NULL qui significa «il modello non si
    -- esprime», e NON «conserva tutto»: quest'ultimo e' un valore che la
    -- politica esprime con il proprio NULL, e confonderli farebbe prescrivere
    -- la conservazione illimitata a ogni modello che tace.
    --
    -- Percio' il «conserva tutto» prescritto si scrive con lo zero, che la
    -- politica non ammette: e' un valore che li' non puo' esistere, quindi non
    -- si confonde con nessuno.
    prescribed_keep_days INTEGER
        CHECK (prescribed_keep_days IS NULL OR prescribed_keep_days >= 0),

    created_by TEXT NOT NULL,
    created_at INTEGER NOT NULL,

    -- Un modello che non prescrive niente non e' un modello: non avrebbe fonti,
    -- ne' dizionari, ne' impostazioni da confrontare. Le fonti stanno in
    -- un'altra tabella e non si possono controllare da qui; il resto si'.
    --
    -- Un modello di sole fonti e' legittimo, e per quello c'e' il trigger piu'
    -- sotto, che sa contarle.
    CHECK (length(trim(name)) > 0)
);

-- LE FONTI DEL MODELLO.
--
-- Per identita', come i dizionari. Se una fonte viene cancellata, il modello
-- resta e applicandolo si scopre che quella fonte non e' piu' nell'archivio:
-- farlo sparire direbbe che nessuno l'aveva mai messa nel modello.
CREATE TABLE monitoring_template_sources (
    template_id INTEGER NOT NULL REFERENCES monitoring_templates (id) ON DELETE CASCADE,
    source_id INTEGER NOT NULL,
    PRIMARY KEY (template_id, source_id)
);

CREATE INDEX monitoring_templates_by_name ON monitoring_templates (name);

-- UN MODELLO NON SI MODIFICA.
--
-- Porta chi lo ha creato e quando: se le fonti o i dizionari potessero cambiare
-- dopo, quei due valori direbbero che quella persona ha preparato QUELLA
-- configurazione quel giorno, e sarebbe falso. E' la disciplina delle note
-- (NOTE-01) e delle ricerche salvate (SEARCH-01).
--
-- Si cancella, come una ricerca salvata e per la stessa ragione: un modello e'
-- uno STRUMENTO, e nessuna decisione poggia sulla sua esistenza. Cio' che un
-- modello ha prodotto — le fonti e i dizionari di una sessione — resta scritto
-- sulla sessione, e non se ne va con lui.
CREATE TRIGGER monitoring_templates_are_written_once
    BEFORE UPDATE ON monitoring_templates
BEGIN
    SELECT RAISE(ABORT, 'un modello di monitoraggio non si modifica: se ne crea un altro');
END;

-- E NEMMENO LE SUE FONTI.
--
-- Senza questo, il modello sarebbe immutabile e il suo contenuto no: si
-- cambierebbero le fonti lasciando intatta la riga che dice chi e quando.
CREATE TRIGGER monitoring_template_sources_are_written_once
    BEFORE UPDATE ON monitoring_template_sources
BEGIN
    SELECT RAISE(ABORT, 'le fonti di un modello non si modificano: se ne crea un altro');
END;

-- UN MODELLO SENZA FONTI NON SI CREA.
--
-- Non e' pignoleria: applicarlo non preparerebbe nulla, e chi lo ha salvato
-- crederebbe di avere un modello. Il controllo sta in un trigger perche' le
-- fonti vivono in un'altra tabella, e un vincolo di riga non le vede.
--
-- Il momento in cui si controlla e' la CANCELLAZIONE DELL'ULTIMA FONTE: alla
-- creazione le fonti non ci sono ancora, e pretenderle prima le renderebbe
-- impossibili da inserire.
CREATE TRIGGER monitoring_templates_keep_at_least_one_source
    BEFORE DELETE ON monitoring_template_sources
    WHEN (
        SELECT COUNT(*) FROM monitoring_template_sources
        WHERE template_id = OLD.template_id
    ) = 1
    AND EXISTS (SELECT 1 FROM monitoring_templates WHERE id = OLD.template_id)
BEGIN
    SELECT RAISE(ABORT, 'un modello senza fonti non preparerebbe nulla: si cancella il modello');
END;
