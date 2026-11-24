-- 0062 — I campi personali del profilo documentale, cifrati (OPERATOR-DPAPI-01,
-- ADR-0160, DEC-424).
--
-- # Che cosa aggiunge
--
-- Tre colonne per i valori cifrati con DPAPI del firmatario, della qualifica e
-- della riga «sede, indirizzo e recapiti». L'archivio li conserva come byte
-- opachi: cifra e decifra il servizio, che conosce l'utente Windows.
--
-- # Additiva
--
-- Le colonne in chiaro restano, perché una migrazione non puo' chiamare DPAPI:
-- i valori gia' scritti si cifrano alla prima lettura, e le colonne in chiaro
-- si svuotano. Da qui in poi la scrittura del profilo rifiuta un valore in
-- chiaro in quei tre campi.

ALTER TABLE report_profile ADD COLUMN signer_name_protected BLOB;
ALTER TABLE report_profile ADD COLUMN signer_role_protected BLOB;
ALTER TABLE report_profile ADD COLUMN header_line_protected BLOB;
