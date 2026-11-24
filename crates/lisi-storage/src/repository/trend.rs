//! Le occorrenze osservabili in un periodo, per l'analisi temporale.
//!
//! # Che cosa questo modulo legge, e che cosa non calcola
//!
//! Legge **occorrenze**: a un istante, una certa cosa compariva. Non conta e
//! non confronta: il conteggio e il confronto stanno in
//! `lisi_services::trend`, che non conosce l'archivio ed è provato da solo.
//!
//! Contare in SQL avrebbe messo l'aritmetica dove nessuna prova la guarda, e
//! avrebbe reso impossibile verificare le regole del confronto senza un
//! database.
//!
//! # Perché non si tronca
//!
//! Un elenco troncato mostra meno righe; un **conteggio** troncato mostra
//! numeri falsi. Perciò la lettura chiede una riga in più del limite: chi
//! chiama vede che il limite è stato superato e **rifiuta il confronto**
//! invece di eseguirlo su una parte.
//!
//! # Quale orologio
//!
//! L'istante di **pubblicazione** dichiarato dalla fonte, non quello di
//! acquisizione: la domanda è quando una cosa è stata detta, non quando NEXUM
//! è passato a guardare.

use lisi_core::Timestamp;
use rusqlite::Row;

use crate::database::Database;
use crate::error::{StorageError, StorageResult};
use crate::repository::{instant, millis};

/// Una occorrenza letta dall'archivio.
///
/// Il genere è la forma testuale che `lisi_services::trend` conosce: la
/// traduzione nel tipo di dominio avviene lì, perché è lì che le regole del
/// confronto vivono.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObservationRow {
    /// Genere: `term`, `cve`, `domain`, `url`, `fingerprint`, `address`,
    /// `source`.
    pub kind: String,
    /// Il valore, nella forma su cui si conta.
    pub key: String,
    /// Istante di pubblicazione del contenuto in cui compariva.
    pub at: Timestamp,
}

impl ObservationRow {
    fn read(row: &Row<'_>) -> rusqlite::Result<Self> {
        Ok(Self {
            kind: row.get(0)?,
            key: row.get(1)?,
            at: instant(row.get(2)?),
        })
    }
}

impl Database {
    /// Il primo istante di pubblicazione presente nell'archivio.
    ///
    /// `None` quando non c'è alcun contenuto. Serve a `lisi_services::trend`
    /// per rifiutare un confronto con un periodo in cui NEXUM non guardava:
    /// senza quel rifiuto, il giorno dopo il primo monitoraggio ogni cosa
    /// risulterebbe emergente.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se la lettura non riesce.
    pub fn earliest_publication(&self) -> StorageResult<Option<Timestamp>> {
        let primo: Option<i64> =
            self.connection
                .query_row("SELECT MIN(published_at) FROM contents", [], |row| {
                    row.get(0)
                })?;
        Ok(primo.map(instant))
    }

    /// Le occorrenze pubblicate nell'intervallo `[from, to)`.
    ///
    /// I sette generi vengono da tre tabelle: i termini dai riscontri, gli
    /// indicatori dalla loro tabella, il volume dai contenuti stessi. Sono
    /// una lettura sola perché il confronto ne ha bisogno tutte insieme, e
    /// sette letture separate attraverserebbero sette volte lo stesso indice.
    ///
    /// Vengono restituite **al più `limit + 1`** righe: la riga in più è il
    /// modo con cui chi chiama scopre che il limite è stato superato, e a quel
    /// punto rifiuta il confronto invece di contarne una parte.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se la lettura non riesce.
    pub fn observations_between(
        &self,
        from: Timestamp,
        to: Timestamp,
        limit: u32,
    ) -> StorageResult<Vec<ObservationRow>> {
        if from.as_millis() >= to.as_millis() {
            return Err(StorageError::InvalidRange {
                what: "intervallo_osservazioni",
            });
        }

        let mut statement = self.connection.prepare(
            "SELECT 'term' AS kind, m.rule_id AS key, c.published_at AS at
               FROM matches m
               JOIN contents c ON c.id = m.content_id
              WHERE c.published_at >= ?1 AND c.published_at < ?2
             UNION ALL
             SELECT CASE ci.kind
                        WHEN 'md5' THEN 'fingerprint'
                        WHEN 'sha1' THEN 'fingerprint'
                        WHEN 'sha256' THEN 'fingerprint'
                        WHEN 'ipv4' THEN 'address'
                        WHEN 'ipv6' THEN 'address'
                        ELSE ci.kind
                    END AS kind,
                    ci.value AS key,
                    c.published_at AS at
               FROM content_indicators ci
               JOIN contents c ON c.id = ci.content_id
              WHERE c.published_at >= ?1 AND c.published_at < ?2
             UNION ALL
             SELECT 'source' AS kind,
                    COALESCE(s.display_name, 'fonte ' || c.source_id) AS key,
                    c.published_at AS at
               FROM contents c
               LEFT JOIN sources s ON s.id = c.source_id
              WHERE c.published_at >= ?1 AND c.published_at < ?2
             LIMIT ?3",
        )?;

        let rows = statement.query_map(
            rusqlite::params![millis(from), millis(to), i64::from(limit) + 1],
            ObservationRow::read,
        )?;

        let mut osservazioni = Vec::new();
        for row in rows {
            osservazioni.push(row?);
        }
        Ok(osservazioni)
    }
}

#[cfg(test)]
mod tests {
    use lisi_core::model::{CyberIndicator, IndicatorKind, MatchRange, NewMatch};
    use lisi_core::text::{MatchedText, RuleCategory, RuleId};
    use lisi_core::{ContentId, SessionId, SourceId, Timestamp};

    use crate::Database;
    use crate::test_support::{database_with_session, level, new_content};

    const GIORNO: i64 = 24 * 60 * 60 * 1_000;
    const ORA_ZERO: i64 = 1_700_000_000_000;

    fn istante(millis: i64) -> Timestamp {
        Timestamp::from_millis(millis)
    }

    /// Un contenuto pubblicato `giorni_fa` giorni prima dell'ora zero, con un
    /// riscontro e, quando indicato, un indicatore.
    fn contenuto(
        database: &mut Database,
        session_id: SessionId,
        source_id: SourceId,
        remote: &str,
        giorni_fa: i64,
        termine: &str,
        indicatore: Option<(IndicatorKind, &str)>,
    ) -> ContentId {
        let quando = istante(ORA_ZERO - giorni_fa * GIORNO);

        let mut bozza = new_content(session_id, source_id, remote, "corpo di prova");
        bozza.published_at = quando;
        bozza.acquired_at = quando;

        let Ok(inserimento) = database.insert_content(&bozza) else {
            panic!("il contenuto deve potersi registrare");
        };
        let content_id = inserimento.content_id();

        let (Ok(rule_id), Ok(rule_category), Ok(matched_text), Ok(range)) = (
            RuleId::try_new(termine),
            RuleCategory::try_new("prova"),
            MatchedText::try_new(termine),
            MatchRange::try_new(0, termine.len()),
        ) else {
            panic!("i valori del riscontro devono essere validi");
        };
        let Ok(_) = database.insert_match(
            &NewMatch {
                content_id,
                rule_id,
                rule_category,
                matched_text,
                range,
                level: level(0),
            },
            quando,
        ) else {
            panic!("il riscontro deve potersi registrare");
        };

        if let Some((kind, value)) = indicatore {
            let Ok(_) = database.insert_content_indicators(
                content_id,
                &[CyberIndicator {
                    kind,
                    value: value.to_owned(),
                }],
            ) else {
                panic!("l'indicatore deve potersi registrare");
            };
        }

        content_id
    }

    #[test]
    fn senza_contenuti_non_esiste_un_primo_istante() {
        let (database, _, _) = database_with_session();
        assert_eq!(database.earliest_publication().ok(), Some(None));
    }

    #[test]
    fn il_primo_istante_e_quello_del_contenuto_piu_vecchio() {
        let (mut database, source, session) = database_with_session();
        contenuto(&mut database, session, source, "m1", 3, "assalto", None);
        contenuto(&mut database, session, source, "m2", 10, "corteo", None);

        assert_eq!(
            database.earliest_publication().ok(),
            Some(Some(istante(ORA_ZERO - 10 * GIORNO)))
        );
    }

    /// Un contenuto produce almeno due occorrenze: il termine e il volume della
    /// fonte. Con un indicatore, tre.
    #[test]
    fn un_contenuto_produce_il_termine_il_volume_e_l_indicatore() {
        let (mut database, source, session) = database_with_session();
        contenuto(
            &mut database,
            session,
            source,
            "m1",
            3,
            "assalto",
            Some((IndicatorKind::Cve, "cve-2026-1234")),
        );

        let Ok(righe) =
            database.observations_between(istante(ORA_ZERO - 7 * GIORNO), istante(ORA_ZERO), 1_000)
        else {
            panic!("la lettura deve riuscire");
        };

        let generi: Vec<&str> = righe.iter().map(|riga| riga.kind.as_str()).collect();
        assert_eq!(righe.len(), 3, "{generi:?}");
        assert!(generi.contains(&"term"));
        assert!(generi.contains(&"cve"));
        assert!(generi.contains(&"source"));
    }

    /// Le impronte e gli indirizzi si raccolgono sotto un genere solo.
    ///
    /// Tre algoritmi diversi restano tre impronte: chi legge non deve sapere
    /// quale funzione le abbia prodotte per accorgersi che una compare spesso.
    #[test]
    fn le_impronte_e_gli_indirizzi_hanno_un_genere_solo() {
        let (mut database, source, session) = database_with_session();
        contenuto(
            &mut database,
            session,
            source,
            "m1",
            3,
            "a",
            Some((IndicatorKind::Sha256, &"a".repeat(64))),
        );
        contenuto(
            &mut database,
            session,
            source,
            "m2",
            3,
            "b",
            Some((IndicatorKind::Md5, &"b".repeat(32))),
        );
        contenuto(
            &mut database,
            session,
            source,
            "m3",
            3,
            "c",
            Some((IndicatorKind::Ipv4, "203.0.113.7")),
        );

        let Ok(righe) =
            database.observations_between(istante(ORA_ZERO - 7 * GIORNO), istante(ORA_ZERO), 1_000)
        else {
            panic!("la lettura deve riuscire");
        };

        assert_eq!(
            righe
                .iter()
                .filter(|riga| riga.kind == "fingerprint")
                .count(),
            2
        );
        assert_eq!(
            righe.iter().filter(|riga| riga.kind == "address").count(),
            1
        );
    }

    /// L'intervallo è semiaperto: l'inizio è compreso, la fine è esclusa.
    ///
    /// È la stessa forma delle due finestre del confronto, e deve esserlo: se
    /// la lettura comprendesse la fine, l'occorrenza di quell'istante entrerebbe
    /// nell'insieme letto e non in nessuna delle due finestre.
    #[test]
    fn l_intervallo_comprende_l_inizio_ed_esclude_la_fine() {
        let (mut database, source, session) = database_with_session();
        contenuto(&mut database, session, source, "m1", 7, "inizio", None);
        contenuto(&mut database, session, source, "m2", 0, "fine", None);

        let Ok(righe) =
            database.observations_between(istante(ORA_ZERO - 7 * GIORNO), istante(ORA_ZERO), 1_000)
        else {
            panic!("la lettura deve riuscire");
        };

        let chiavi: Vec<&str> = righe.iter().map(|riga| riga.key.as_str()).collect();
        assert!(chiavi.contains(&"inizio"), "{chiavi:?}");
        assert!(!chiavi.contains(&"fine"), "{chiavi:?}");
    }

    /// **Superato il limite si restituisce una riga in più**, così chi chiama sa
    /// di non avere tutto e rifiuta il confronto invece di contarne una parte.
    #[test]
    fn oltre_il_limite_si_restituisce_una_riga_in_piu() {
        let (mut database, source, session) = database_with_session();
        for i in 0..5 {
            contenuto(
                &mut database,
                session,
                source,
                &format!("m{i}"),
                3,
                "assalto",
                None,
            );
        }

        // Cinque contenuti, dieci occorrenze: termine e volume per ciascuno.
        let Ok(righe) =
            database.observations_between(istante(ORA_ZERO - 7 * GIORNO), istante(ORA_ZERO), 4)
        else {
            panic!("la lettura deve riuscire");
        };

        assert_eq!(
            righe.len(),
            5,
            "quattro righe piu' quella che rivela il taglio"
        );
    }

    /// Un intervallo rovesciato non è un intervallo, e non si legge come
    /// «nessuna occorrenza in quel periodo».
    #[test]
    fn un_intervallo_rovesciato_si_rifiuta() {
        let (database, _, _) = database_with_session();
        assert!(
            database
                .observations_between(istante(ORA_ZERO), istante(ORA_ZERO - GIORNO), 10)
                .is_err()
        );
    }
}
