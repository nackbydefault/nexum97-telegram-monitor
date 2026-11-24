//! Gli indicatori tecnici estratti dai contenuti.
//!
//! # Che cosa si conserva, e perché
//!
//! CVE, indirizzi, domini, URL e impronte, nella forma **normalizzata** che il
//! dominio produce. È quella su cui si correla, e conservare accanto la forma
//! originale significherebbe due verità e la tentazione di correlare sulla
//! sbagliata.
//!
//! # La domanda che questa tabella esiste per rispondere
//!
//! Non «quali indicatori ha questo contenuto» — quella si risponderebbe
//! riestraendo, perché l'estrazione è pura. Ma **«quali altri contenuti nominano
//! questa stessa CVE»**, che va nella direzione opposta e senza un indice
//! costerebbe rileggere ogni corpo in archivio.
//!
//! # Che cosa non si fa, mai
//!
//! Non si contatta nulla. Nessuna risoluzione DNS, nessuna connessione, nessun
//! prelievo (ADR-0035 Decisione 8). Questo modulo legge e scrive righe: non ha
//! accesso alla rete e non deve averlo.

use lisi_core::model::cyber_candidate::{ArchiveCluster, ArchiveMember};
use lisi_core::model::cyber_event::{
    CorrelationReason, CyberEvent, EventMember, body_fingerprint, correlate,
};
use lisi_core::model::indicator::{CyberIndicator, IndicatorKind};
use lisi_core::model::review::ReviewState;
use lisi_core::{ContentId, SessionId, Timestamp};

use crate::Database;
use crate::error::{StorageError, StorageResult};

/// Un contenuto che nomina un indicatore.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IndicatorMention {
    /// Il contenuto.
    pub content_id: ContentId,
    /// Il genere dell'indicatore.
    pub kind: IndicatorKind,
    /// Il valore normalizzato.
    pub value: String,
}

/// Un indicatore distinto di un monitoraggio, con il proprio peso.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionIndicator {
    /// Il genere e il valore normalizzato.
    pub indicator: CyberIndicator,
    /// Quanti contenuti del monitoraggio lo nominano.
    ///
    /// **Non è una misura di importanza né di pericolo.** Dice quante volte
    /// una stringa è comparsa, e un elenco automatico ripubblicato dieci volte
    /// pesa dieci come dieci persone che ne parlano.
    pub mentioning_contents: u64,
}

impl Database {
    /// Registra gli indicatori di un contenuto.
    ///
    /// # Perché è idempotente
    ///
    /// La stessa ragione dei riscontri: se un arresto è avvenuto fra
    /// l'inserimento del contenuto e i suoi indicatori, la ripresa dell'evento
    /// deve **completarlo**, non saltarlo. `INSERT OR IGNORE` sulla chiave
    /// primaria rende la ripetizione innocua.
    ///
    /// Tutto in una transazione: un contenuto con metà dei propri indicatori
    /// darebbe risposte sbagliate alla correlazione senza che nulla lo segnali.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se la scrittura non riesce.
    pub fn insert_content_indicators(
        &mut self,
        content_id: ContentId,
        indicators: &[CyberIndicator],
    ) -> StorageResult<usize> {
        if indicators.is_empty() {
            return Ok(0);
        }

        let transaction = self.connection.transaction()?;
        let mut scritti = 0_usize;
        {
            let mut statement = transaction.prepare(
                "INSERT OR IGNORE INTO content_indicators (content_id, kind, value)
                 VALUES (?1, ?2, ?3)",
            )?;
            for indicator in indicators {
                scritti += statement.execute(rusqlite::params![
                    content_id.get(),
                    indicator.kind.as_str(),
                    indicator.value.as_str(),
                ])?;
            }
        }
        transaction.commit()?;
        Ok(scritti)
    }

    /// Gli indicatori di un contenuto, in ordine stabile.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se la lettura non riesce o se una riga porta un
    /// genere che il dominio non conosce.
    pub fn content_indicators(&self, content_id: ContentId) -> StorageResult<Vec<CyberIndicator>> {
        let mut statement = self.connection.prepare(
            "SELECT kind, value FROM content_indicators
             WHERE content_id = ?1
             ORDER BY kind, value",
        )?;
        let righe = statement.query_map(rusqlite::params![content_id.get()], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
        })?;

        let mut trovati = Vec::new();
        for riga in righe {
            let (kind, value) = riga?;
            trovati.push(CyberIndicator {
                kind: parse_kind(&kind)?,
                value,
            });
        }
        Ok(trovati)
    }

    /// Gli indicatori distinti di un monitoraggio, con quanti contenuti li
    /// nominano.
    ///
    /// # A che cosa serve, dato che c'è già la lettura per contenuto
    ///
    /// Perché un'esportazione ragiona per **valore**, non per contenuto: lo
    /// stesso dominio nominato in dieci messaggi è un dominio, non dieci. La
    /// domanda per contenuto risponderebbe con dieci righe uguali, e chi
    /// esporta dovrebbe deduplicarle — cioè rifare qui fuori ciò che l'archivio
    /// sa fare in una riga.
    ///
    /// Il conteggio esce insieme al valore perché è **provenienza interna**:
    /// dice quanto pesa un valore dentro il monitoraggio, e resta in ufficio.
    ///
    /// L'ordine è stabile, per genere e valore: due letture della stessa
    /// sessione danno lo stesso elenco, che è ciò che serve a un'esportazione
    /// riproducibile.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se la lettura non riesce o se una riga porta un
    /// genere che il dominio non conosce.
    pub fn distinct_session_indicators(
        &self,
        session_id: SessionId,
    ) -> StorageResult<Vec<SessionIndicator>> {
        let mut statement = self.connection.prepare(
            "SELECT i.kind, i.value, count(*)
             FROM content_indicators AS i
             JOIN contents AS c ON c.id = i.content_id
             WHERE c.session_id = ?1
             GROUP BY i.kind, i.value
             ORDER BY i.kind, i.value",
        )?;
        let righe = statement.query_map(rusqlite::params![session_id.get()], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, i64>(2)?,
            ))
        })?;

        let mut trovati = Vec::new();
        for riga in righe {
            let (kind, value, quanti) = riga?;
            trovati.push(SessionIndicator {
                indicator: CyberIndicator {
                    kind: parse_kind(&kind)?,
                    value,
                },
                mentioning_contents: u64::try_from(quanti).unwrap_or(0),
            });
        }
        Ok(trovati)
    }

    /// I contenuti che nominano l'indicatore indicato.
    ///
    /// È la domanda inversa, quella per cui la tabella esiste.
    ///
    /// # Perché c'è un tetto
    ///
    /// Un indicatore comunissimo — `8.8.8.8`, un dominio di uso generale —
    /// potrebbe comparire in migliaia di contenuti. Chi correla vuole sapere
    /// **se** c'è ricorrenza e vederne un campione, non caricare l'archivio in
    /// memoria per scoprirlo.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se la lettura non riesce.
    pub fn contents_mentioning(
        &self,
        kind: IndicatorKind,
        value: &str,
        limit: usize,
    ) -> StorageResult<Vec<ContentId>> {
        let tetto = i64::try_from(limit).unwrap_or(i64::MAX);
        let mut statement = self.connection.prepare(
            "SELECT content_id FROM content_indicators
             WHERE kind = ?1 AND value = ?2
             ORDER BY content_id
             LIMIT ?3",
        )?;
        let righe = statement.query_map(rusqlite::params![kind.as_str(), value, tetto], |row| {
            row.get::<_, i64>(0)
        })?;

        let mut trovati = Vec::new();
        for riga in righe {
            trovati.push(ContentId::new(riga?));
        }
        Ok(trovati)
    }

    /// Quanti contenuti nominano l'indicatore indicato.
    ///
    /// Separato da [`Self::contents_mentioning`] perché il conteggio non ha
    /// tetto: sapere che un dominio compare in millecinquecento contenuti è
    /// un'informazione, caricarli tutti no.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se il conteggio non riesce.
    pub fn count_mentioning(&self, kind: IndicatorKind, value: &str) -> StorageResult<u64> {
        let quanti: i64 = self.connection.query_row(
            "SELECT count(*) FROM content_indicators WHERE kind = ?1 AND value = ?2",
            rusqlite::params![kind.as_str(), value],
            |row| row.get(0),
        )?;
        Ok(u64::try_from(quanti).unwrap_or(0))
    }
}

/// Traduce il genere conservato nel tipo del dominio.
///
/// Una riga con un genere sconosciuto è un archivio scritto da una versione che
/// non conosciamo, o modificato a mano: si rifiuta invece di indovinare.
fn parse_kind(raw: &str) -> StorageResult<IndicatorKind> {
    IndicatorKind::parse(raw).ok_or(StorageError::CorruptedRow {
        detail: "genere di indicatore sconosciuto in content_indicators",
    })
}

impl Database {
    /// Costruisce i grappoli di segnali che condividono un indicatore.
    ///
    /// # Perche' l'impronta si calcola qui e non si conserva
    ///
    /// L'impronta del corpo normalizzato serve a riconoscere le
    /// ripubblicazioni, e dipende **dalla regola di normalizzazione**. Se un
    /// giorno quella regola cambiasse, un'impronta conservata direbbe ancora la
    /// vecchia verita' su contenuti vecchi e la nuova su quelli nuovi, e i due
    /// gruppi non si confronterebbero piu'.
    ///
    /// Ricalcolarla costa una passata sul corpo, che e' gia' in memoria.
    ///
    /// # Il tetto
    ///
    /// Un indicatore comunissimo potrebbe legare migliaia di contenuti. Chi
    /// guarda un grappolo vuole vederne la forma, non caricarne l'archivio.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se la lettura non riesce.
    pub fn correlate_by_indicator(
        &self,
        session_id: SessionId,
        members_per_event: usize,
    ) -> StorageResult<Vec<CyberEvent>> {
        let tetto = i64::try_from(members_per_event).unwrap_or(i64::MAX);

        // Gli indicatori nominati da PIU' di un contenuto della sessione: sono
        // gli unici che possano produrre un grappolo.
        let mut ricorrenti = self.connection.prepare(
            "SELECT i.kind, i.value
             FROM content_indicators i
             JOIN contents c ON c.id = i.content_id
             WHERE c.session_id = ?1
             GROUP BY i.kind, i.value
             HAVING count(*) > 1
             ORDER BY i.kind, i.value",
        )?;
        let chiavi: Vec<(String, String)> = ricorrenti
            .query_map(rusqlite::params![session_id.get()], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
            })?
            .collect::<Result<Vec<_>, _>>()?;
        drop(ricorrenti);

        let mut grappoli = Vec::new();
        for (kind, value) in chiavi {
            let Some(genere) = IndicatorKind::parse(&kind) else {
                return Err(StorageError::CorruptedRow {
                    detail: "genere di indicatore sconosciuto in content_indicators",
                });
            };

            // La revisione arriva con una LEFT JOIN sulla piu' recente, non con
            // una lettura per contenuto: un grappolo di cinquanta membri
            // costerebbe cinquanta interrogazioni, e la piu' recente e' l'unica
            // che dica lo stato corrente.
            let mut membri = self.connection.prepare(
                "SELECT c.id, c.source_id, c.body, c.published_at,
                        (SELECT r.state FROM reviews r
                         WHERE r.content_id = c.id
                         ORDER BY r.decided_at DESC, r.id DESC
                         LIMIT 1)
                 FROM content_indicators i
                 JOIN contents c ON c.id = i.content_id
                 WHERE c.session_id = ?1 AND i.kind = ?2 AND i.value = ?3
                 ORDER BY c.source_id, c.id
                 LIMIT ?4",
            )?;
            let righe = membri.query_map(
                rusqlite::params![session_id.get(), kind, value, tetto],
                |row| {
                    Ok((
                        row.get::<_, i64>(0)?,
                        row.get::<_, i64>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, i64>(3)?,
                        row.get::<_, Option<String>>(4)?,
                    ))
                },
            )?;

            let mut raccolti = Vec::new();
            for riga in righe {
                let (content_id, source_id, body, published_at, stato) = riga?;

                // Uno stato illeggibile e' una riga corrotta, non un contenuto
                // «mai esaminato»: trattarlo come assente cancellerebbe una
                // decisione presa da una persona.
                let review_state = review_state_of(stato)?;

                raccolti.push(EventMember {
                    content_id,
                    source_id,
                    body_fingerprint: body_fingerprint(&body),
                    published_at: Timestamp::from_millis(published_at),
                    review_state,
                });
            }
            drop(membri);

            grappoli.push(CyberEvent {
                reason: CorrelationReason::SameIndicator {
                    kind: genere,
                    value,
                },
                members: raccolti,
            });
        }

        Ok(correlate(grappoli))
    }

    /// I contenuti di **tutto l'archivio** pubblicati da `since` in poi,
    /// raggruppati per indicatore, con il monitoraggio di ciascuno
    /// (CYBER-EVENTS-02, ADR-0189).
    ///
    /// Si guardano soltanto gli indicatori nominati da almeno due fonti
    /// distinte, i più nominati prima, al più `max_keys`; per ciascuno al più
    /// `members_per_event` contenuti, i più recenti.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se la lettura non riesce o una riga è corrotta.
    pub fn archive_clusters_by_indicator(
        &self,
        since: Timestamp,
        max_keys: usize,
        members_per_event: usize,
    ) -> StorageResult<Vec<ArchiveCluster>> {
        let chiavi_massime = i64::try_from(max_keys).unwrap_or(i64::MAX);
        let tetto = i64::try_from(members_per_event).unwrap_or(i64::MAX);

        let mut ricorrenti = self.connection.prepare(
            "SELECT i.kind, i.value
             FROM content_indicators i
             JOIN contents c ON c.id = i.content_id
             WHERE c.published_at >= ?1
             GROUP BY i.kind, i.value
             HAVING count(DISTINCT c.source_id) > 1
             ORDER BY count(*) DESC, i.kind, i.value
             LIMIT ?2",
        )?;
        let chiavi: Vec<(String, String)> = ricorrenti
            .query_map(
                rusqlite::params![since.as_millis(), chiavi_massime],
                |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
            )?
            .collect::<Result<Vec<_>, _>>()?;
        drop(ricorrenti);

        let mut grappoli = Vec::new();
        for (kind, value) in chiavi {
            let genere = parse_kind(&kind)?;
            let mut membri = self.connection.prepare(
                "SELECT c.id, c.source_id, c.session_id, c.body, c.published_at,
                        (SELECT r.state FROM reviews r
                         WHERE r.content_id = c.id
                         ORDER BY r.decided_at DESC, r.id DESC
                         LIMIT 1)
                 FROM content_indicators i
                 JOIN contents c ON c.id = i.content_id
                 WHERE c.published_at >= ?1 AND i.kind = ?2 AND i.value = ?3
                 ORDER BY c.published_at DESC, c.id DESC
                 LIMIT ?4",
            )?;
            let righe = membri.query_map(
                rusqlite::params![since.as_millis(), kind, value, tetto],
                |row| {
                    Ok((
                        row.get::<_, i64>(0)?,
                        row.get::<_, i64>(1)?,
                        row.get::<_, i64>(2)?,
                        row.get::<_, String>(3)?,
                        row.get::<_, i64>(4)?,
                        row.get::<_, Option<String>>(5)?,
                    ))
                },
            )?;
            let mut raccolti = Vec::new();
            for riga in righe {
                let (content_id, source_id, session_id, body, published_at, stato) = riga?;
                raccolti.push(ArchiveMember {
                    member: EventMember {
                        content_id,
                        source_id,
                        body_fingerprint: body_fingerprint(&body),
                        published_at: Timestamp::from_millis(published_at),
                        review_state: review_state_of(stato)?,
                    },
                    session_id,
                });
            }
            drop(membri);
            grappoli.push(ArchiveCluster {
                reason: CorrelationReason::SameIndicator {
                    kind: genere,
                    value,
                },
                members: raccolti,
            });
        }
        Ok(grappoli)
    }
}

/// Lo stato di revisione più recente, letto.
///
/// Uno stato illeggibile è una riga corrotta, non un contenuto «mai
/// esaminato»: trattarlo come assente cancellerebbe una decisione presa da una
/// persona.
fn review_state_of(stato: Option<String>) -> StorageResult<Option<ReviewState>> {
    stato
        .map(|raw| {
            raw.parse::<ReviewState>()
                .map_err(|_| StorageError::CorruptedRow {
                    detail: "stato di revisione sconosciuto in reviews",
                })
        })
        .transpose()
}

#[cfg(test)]
mod tests {
    use lisi_core::model::indicator::{CyberIndicator, IndicatorKind};

    use crate::test_support::{database_with_session, new_content};

    fn indicatore(kind: IndicatorKind, value: &str) -> CyberIndicator {
        CyberIndicator {
            kind,
            value: String::from(value),
        }
    }

    #[test]
    fn gli_indicatori_si_scrivono_e_si_rileggono() {
        let (mut database, source_id, session_id) = database_with_session();
        let contenuto = new_content(session_id, source_id, "m-1", "testo");
        let Ok(inserimento) = database.insert_content(&contenuto) else {
            panic!("il contenuto deve potersi registrare");
        };
        let content_id = inserimento.content_id();

        let trovati = vec![
            indicatore(IndicatorKind::Cve, "CVE-2026-1234"),
            indicatore(IndicatorKind::Domain, "esempio.test"),
        ];
        let Ok(scritti) = database.insert_content_indicators(content_id, &trovati) else {
            panic!("gli indicatori devono potersi registrare");
        };
        assert_eq!(scritti, 2);

        let Ok(riletti) = database.content_indicators(content_id) else {
            panic!("gli indicatori devono potersi rileggere");
        };
        assert_eq!(riletti.len(), 2);
        assert!(riletti.iter().any(|i| i.value == "CVE-2026-1234"));
    }

    /// **Registrare due volte non duplica.**
    ///
    /// E' la stessa ragione dei riscontri: se un arresto e' avvenuto fra
    /// l'inserimento del contenuto e i suoi indicatori, la ripresa deve
    /// completarlo senza raddoppiare nulla.
    #[test]
    fn registrare_due_volte_non_duplica() {
        let (mut database, source_id, session_id) = database_with_session();
        let contenuto = new_content(session_id, source_id, "m-1", "testo");
        let Ok(inserimento) = database.insert_content(&contenuto) else {
            panic!("il contenuto deve potersi registrare");
        };
        let content_id = inserimento.content_id();

        let trovati = vec![indicatore(IndicatorKind::Cve, "CVE-2026-1234")];
        let Ok(_) = database.insert_content_indicators(content_id, &trovati) else {
            panic!("la prima registrazione deve riuscire");
        };
        let Ok(secondi) = database.insert_content_indicators(content_id, &trovati) else {
            panic!("la seconda registrazione deve riuscire");
        };
        assert_eq!(secondi, 0, "la ripetizione non deve scrivere nulla");

        let Ok(riletti) = database.content_indicators(content_id) else {
            panic!("gli indicatori devono potersi rileggere");
        };
        assert_eq!(riletti.len(), 1, "l'indicatore e' stato duplicato");
    }

    /// **La domanda inversa: quali contenuti nominano lo stesso indicatore.**
    ///
    /// E' l'intera ragione per cui questa tabella esiste.
    #[test]
    fn la_domanda_inversa_trova_i_contenuti_che_condividono_un_indicatore() {
        let (mut database, source_id, session_id) = database_with_session();

        let mut ids = Vec::new();
        for numero in 0..3_u32 {
            let contenuto = new_content(session_id, source_id, &format!("m-{numero}"), "testo");
            let Ok(inserimento) = database.insert_content(&contenuto) else {
                panic!("il contenuto deve potersi registrare");
            };
            ids.push(inserimento.content_id());
        }

        // I primi due nominano la stessa CVE, il terzo un'altra.
        let condivisa = vec![indicatore(IndicatorKind::Cve, "CVE-2026-1111")];
        let altra = vec![indicatore(IndicatorKind::Cve, "CVE-2026-9999")];
        let Ok(_) = database.insert_content_indicators(ids[0], &condivisa) else {
            panic!("registrazione fallita");
        };
        let Ok(_) = database.insert_content_indicators(ids[1], &condivisa) else {
            panic!("registrazione fallita");
        };
        let Ok(_) = database.insert_content_indicators(ids[2], &altra) else {
            panic!("registrazione fallita");
        };

        let Ok(trovati) = database.contents_mentioning(IndicatorKind::Cve, "CVE-2026-1111", 50)
        else {
            panic!("la ricerca deve riuscire");
        };
        assert_eq!(trovati.len(), 2);
        assert!(trovati.contains(&ids[0]) && trovati.contains(&ids[1]));
        assert!(!trovati.contains(&ids[2]));

        let Ok(quanti) = database.count_mentioning(IndicatorKind::Cve, "CVE-2026-1111") else {
            panic!("il conteggio deve riuscire");
        };
        assert_eq!(quanti, 2);
    }

    /// **Il tetto vale, e il conteggio no.**
    ///
    /// Sapere che un dominio compare in molti contenuti e' un'informazione;
    /// caricarli tutti in memoria per scoprirlo no.
    #[test]
    fn il_tetto_limita_i_risultati_ma_non_il_conteggio() {
        let (mut database, source_id, session_id) = database_with_session();

        for numero in 0..10_u32 {
            let contenuto = new_content(session_id, source_id, &format!("m-{numero}"), "testo");
            let Ok(inserimento) = database.insert_content(&contenuto) else {
                panic!("il contenuto deve potersi registrare");
            };
            let Ok(_) = database.insert_content_indicators(
                inserimento.content_id(),
                &[indicatore(IndicatorKind::Domain, "comune.test")],
            ) else {
                panic!("registrazione fallita");
            };
        }

        let Ok(trovati) = database.contents_mentioning(IndicatorKind::Domain, "comune.test", 3)
        else {
            panic!("la ricerca deve riuscire");
        };
        assert_eq!(trovati.len(), 3, "il tetto non e' stato rispettato");

        let Ok(quanti) = database.count_mentioning(IndicatorKind::Domain, "comune.test") else {
            panic!("il conteggio deve riuscire");
        };
        assert_eq!(
            quanti, 10,
            "il conteggio non deve essere limitato dal tetto"
        );
    }

    /// **Un indicatore non sopravvive al proprio contenuto.**
    ///
    /// Un indicatore orfano sarebbe un dato che nessuna schermata sa mostrare e
    /// nessun documento sa citare.
    #[test]
    fn cancellare_il_contenuto_porta_via_i_suoi_indicatori() {
        let (mut database, source_id, session_id) = database_with_session();
        let contenuto = new_content(session_id, source_id, "m-1", "testo");
        let Ok(inserimento) = database.insert_content(&contenuto) else {
            panic!("il contenuto deve potersi registrare");
        };
        let content_id = inserimento.content_id();

        let Ok(_) = database.insert_content_indicators(
            content_id,
            &[indicatore(IndicatorKind::Ipv4, "203.0.113.7")],
        ) else {
            panic!("registrazione fallita");
        };

        let Ok(_) = database.connection.execute(
            "DELETE FROM contents WHERE id = ?1",
            rusqlite::params![content_id.get()],
        ) else {
            panic!("il contenuto deve potersi cancellare");
        };

        let rimasti: i64 = database
            .connection
            .query_row("SELECT count(*) FROM content_indicators", [], |row| {
                row.get(0)
            })
            .expect("il conteggio deve riuscire");
        assert_eq!(
            rimasti, 0,
            "un indicatore e' sopravvissuto al proprio contenuto"
        );
    }

    #[test]
    fn un_genere_sconosciuto_viene_rifiutato_invece_che_indovinato() {
        let (mut database, source_id, session_id) = database_with_session();
        let contenuto = new_content(session_id, source_id, "m-1", "testo");
        let Ok(inserimento) = database.insert_content(&contenuto) else {
            panic!("il contenuto deve potersi registrare");
        };
        let content_id = inserimento.content_id();

        let Ok(_) = database.connection.execute(
            "INSERT INTO content_indicators (content_id, kind, value)
             VALUES (?1, 'genere_inventato', 'x')",
            rusqlite::params![content_id.get()],
        ) else {
            panic!("la riga di prova deve potersi scrivere");
        };

        assert!(
            database.content_indicators(content_id).is_err(),
            "un genere che il dominio non conosce non deve essere indovinato"
        );
    }

    /// **Il grappolo si costruisce dall'archivio vero.**
    ///
    /// Due contenuti che nominano la stessa CVE finiscono insieme; uno che ne
    /// nomina un'altra resta fuori.
    #[test]
    fn la_correlazione_raggruppa_chi_nomina_lo_stesso_indicatore() {
        let (mut database, source_id, session_id) = database_with_session();

        let testi = [
            ("m-1", "riferimento a CVE-2026-1111"),
            ("m-2", "anche qui CVE-2026-1111, ma scritto diversamente"),
            ("m-3", "un'altra vulnerabilita': CVE-2026-9999"),
        ];
        for (id, corpo) in testi {
            let contenuto = new_content(session_id, source_id, id, corpo);
            let Ok(inserimento) = database.insert_content(&contenuto) else {
                panic!("il contenuto deve potersi registrare");
            };
            let estrazione = lisi_core::model::indicator::extract(corpo);
            let Ok(_) = database
                .insert_content_indicators(inserimento.content_id(), &estrazione.indicators)
            else {
                panic!("gli indicatori devono potersi registrare");
            };
        }

        let Ok(grappoli) = database.correlate_by_indicator(session_id, 50) else {
            panic!("la correlazione deve riuscire");
        };

        assert_eq!(
            grappoli.len(),
            1,
            "solo la CVE nominata due volte produce un grappolo"
        );
        let valutazione = grappoli[0].assess();
        assert_eq!(valutazione.contents, 2);
        assert_eq!(valutazione.distinct_sources, 1);
        assert!(
            grappoli[0].reason.as_sentence().contains("2026-1111"),
            "la ragione deve nominare l'indicatore"
        );
    }

    /// **Cinque copie dello stesso testo si riconoscono come tali.**
    ///
    /// E' la distinzione che il prodotto non deve sbagliare: cinque canali che
    /// ripubblicano lo stesso messaggio sono cinque copie, non cinque
    /// testimoni.
    #[test]
    fn le_ripubblicazioni_si_riconoscono_sull_archivio_vero() {
        let (mut database, source_id, session_id) = database_with_session();
        let corpo = "URGENTE: CVE-2026-2222 sfruttata attivamente!";

        for numero in 0..3_u32 {
            let contenuto = new_content(session_id, source_id, &format!("m-{numero}"), corpo);
            let Ok(inserimento) = database.insert_content(&contenuto) else {
                panic!("il contenuto deve potersi registrare");
            };
            let estrazione = lisi_core::model::indicator::extract(corpo);
            let Ok(_) = database
                .insert_content_indicators(inserimento.content_id(), &estrazione.indicators)
            else {
                panic!("gli indicatori devono potersi registrare");
            };
        }

        let Ok(grappoli) = database.correlate_by_indicator(session_id, 50) else {
            panic!("la correlazione deve riuscire");
        };
        assert_eq!(grappoli.len(), 1);

        let valutazione = grappoli[0].assess();
        assert_eq!(valutazione.contents, 3);
        assert_eq!(
            valutazione.apparent_reposts, 2,
            "tre copie sono due ripubblicazioni"
        );
    }

    /// **Una sessione diversa non entra nel grappolo.**
    ///
    /// Un monitoraggio e' un atto: mettere insieme contenuti di due sessioni
    /// diverse produrrebbe un grappolo che non appartiene a nessuna delle due.
    #[test]
    fn i_contenuti_di_un_altra_sessione_restano_fuori() {
        let (mut database, source_id, session_id) = database_with_session();
        let corpo = "CVE-2026-3333";

        let contenuto = new_content(session_id, source_id, "m-1", corpo);
        let Ok(inserimento) = database.insert_content(&contenuto) else {
            panic!("il contenuto deve potersi registrare");
        };
        let estrazione = lisi_core::model::indicator::extract(corpo);
        let Ok(_) =
            database.insert_content_indicators(inserimento.content_id(), &estrazione.indicators)
        else {
            panic!("gli indicatori devono potersi registrare");
        };

        // Una sola voce nella sessione: nessun grappolo.
        let Ok(grappoli) = database.correlate_by_indicator(session_id, 50) else {
            panic!("la correlazione deve riuscire");
        };
        assert!(grappoli.is_empty(), "un contenuto solo non e' un grappolo");
    }

    /// **In tutto l'archivio, con il monitoraggio di ciascuno** (CYBER-EVENTS-02).
    ///
    /// Lo stesso indicatore in due monitoraggi, da due fonti, ricorre: una
    /// sola fonte non basta, e i contenuti piu' vecchi della finestra restano
    /// fuori.
    #[test]
    fn l_archivio_intero_raggruppa_oltre_il_monitoraggio() {
        use crate::test_support::{new_session, new_source, now};

        let (mut database, source_id, session_id) = database_with_session();
        let Ok(altra_fonte) = database.insert_source(&new_source("canale_due"), now()) else {
            panic!("la seconda fonte deve potersi registrare");
        };
        let Ok(altra_sessione) = database.insert_session(&new_session(vec![altra_fonte]), now())
        else {
            panic!("la seconda sessione deve potersi creare");
        };

        let voci = [
            (
                session_id,
                source_id,
                "m-1",
                "CVE-2026-5555 e CVE-2026-6666",
            ),
            (altra_sessione, altra_fonte, "m-2", "di nuovo CVE-2026-5555"),
            (session_id, source_id, "m-3", "ancora CVE-2026-6666"),
        ];
        for (sessione, fonte, id, corpo) in voci {
            let contenuto = new_content(sessione, fonte, id, corpo);
            let Ok(inserimento) = database.insert_content(&contenuto) else {
                panic!("il contenuto deve potersi registrare");
            };
            let estrazione = lisi_core::model::indicator::extract(corpo);
            let Ok(_) = database
                .insert_content_indicators(inserimento.content_id(), &estrazione.indicators)
            else {
                panic!("gli indicatori devono potersi registrare");
            };
        }

        let Ok(grappoli) = database.archive_clusters_by_indicator(now(), 10, 50) else {
            panic!("la lettura dell'archivio deve riuscire");
        };
        assert_eq!(grappoli.len(), 1, "la CVE di una fonte sola resta fuori");
        assert!(grappoli[0].reason.as_sentence().contains("2026-5555"));
        let mut sessioni: Vec<i64> = grappoli[0].members.iter().map(|m| m.session_id).collect();
        sessioni.sort_unstable();
        assert_eq!(sessioni, vec![session_id.get(), altra_sessione.get()]);

        let dopo = lisi_core::Timestamp::from_millis(now().as_millis() + 1);
        let Ok(nessuno) = database.archive_clusters_by_indicator(dopo, 10, 50) else {
            panic!("la lettura dell'archivio deve riuscire");
        };
        assert!(
            nessuno.is_empty(),
            "i contenuti fuori dalla finestra restano fuori"
        );
    }
}
