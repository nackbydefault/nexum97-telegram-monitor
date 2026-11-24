-- Il ruolo di un dispositivo presso l'Hub.
--
-- Motivata in ADR-0085 e DEC-323 (HUB-AUTHZ-01).
--
-- ===========================================================================
-- I PERMESSI SI APPLICANO NELL'HUB (ADR-0042 decisione 3), E SI APPLICANO
-- ALLA MACCHINA AUTENTICATA, NON ALLA PERSONA DICHIARATA.
--
-- L'operatore che un dispositivo dichiara e' un'attribuzione di quella macchina
-- (ADR-0082 decisione 6): nessun permesso lo puo' trattare come autenticato.
-- Quello che l'Hub sa per certo e' QUALE DISPOSITIVO sta parlando, e il ruolo
-- sta li'.
--
-- ===========================================================================
-- IL PRIVILEGIO SI CONCEDE, NON SI TROVA.
--
-- Il valore iniziale e' 'operatore', anche per i dispositivi gia' arruolati
-- prima di questa migrazione: nessuno di loro ha mai avuto un ruolo, e dargli
-- 'amministratore' significherebbe concedere un potere che nessuno ha deciso.
-- Chi amministra lo assegna con un atto, e l'atto va nell'audit.
--
-- Il vincolo CHECK chiude l'elenco: un ruolo scritto a mano nel file non
-- diventa un ruolo nuovo, diventa un errore.

ALTER TABLE enrolled_devices
    ADD COLUMN role TEXT NOT NULL DEFAULT 'operatore'
    CHECK (role IN ('operatore', 'amministratore'));
