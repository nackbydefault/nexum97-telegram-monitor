-- 0084 — Le notifiche dei contenuti recuperati dallo storico
-- (NOTIFY-BACKFILL-01, ADR-0188, DEC-471).
--
-- # Che cosa registra
--
-- Una notifica dice se riguarda un contenuto recuperato dallo storico. I
-- recuperati si annunciano con un avviso solo che li raggruppa, e ciascuno
-- resta registrato qui come notificato, perche' non torni da solo (ADR-0188,
-- decisioni 2 e 3).
--
-- # Perche' serve
--
-- Il tetto delle notifiche per sessione conta le righe: centinaia di
-- recuperati lo esaurirebbero, e un avviso dal vivo arrivato dopo verrebbe
-- soppresso. I recuperati non contano nel tetto (decisione 4).
--
-- # Additiva
--
-- Una colonna nuova, zero di fabbrica: le notifiche di prima restano dal vivo.

ALTER TABLE notifications
ADD COLUMN recovered INTEGER NOT NULL DEFAULT 0 CHECK (recovered IN (0, 1));
