-- Migrazione 0004 - modalita' operativa nell'audit.
--
-- Aggiunge all'audit la modalita' con cui un'azione e' stata compiuta, cosi'
-- che il registro dica non solo chi ha fatto che cosa, ma con quali privilegi.
--
-- La colonna e' NULLABLE, e per una ragione: le voci gia' scritte non hanno una
-- modalita' registrata, e attribuirne una a posteriori sarebbe inventare un
-- fatto. NULL significa "modalita' non registrata", che e' la verita' per le
-- voci precedenti e per i servizi che non conoscono la modalita'.
--
-- ALTER TABLE ADD COLUMN non riscrive la tabella e non tocca i trigger di
-- append-only: le voci esistenti restano intatte.

ALTER TABLE audit ADD COLUMN actor_mode TEXT
    CHECK (actor_mode IS NULL OR actor_mode IN ('administrator', 'operator'));
