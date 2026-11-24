//! L'account d'ufficio di un monitoraggio (MULTI-ACCOUNT-02 parte 2,
//! ADR-0173, migrazione 0072).
//!
//! Una riga per monitoraggio, scritta una volta quando nasce. Lo schema
//! impedisce di riscriverla e di cancellarla.

use std::collections::BTreeMap;

use lisi_core::SessionId;
use lisi_core::model::monitoring_account::{MonitoringAccount, SourceAccount};
use lisi_core::model::telegram_account::AccountUuid;
use lisi_core::text::DisplayName;
use lisi_core::time::Timestamp;
use rusqlite::OptionalExtension;

use crate::Database;
use crate::error::StorageResult;
use crate::repository::{instant, millis};

impl Database {
    /// Registra con quale account lavora un monitoraggio.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se il monitoraggio ha già un account, se non
    /// esiste, o se la scrittura non riesce.
    pub fn insert_session_account(
        &self,
        session_id: SessionId,
        account_uuid: &AccountUuid,
        account_label: &DisplayName,
        at: Timestamp,
    ) -> StorageResult<()> {
        self.connection.execute(
            "INSERT INTO session_accounts (session_id, account_uuid, account_label, bound_at)
             VALUES (?1, ?2, ?3, ?4)",
            rusqlite::params![
                session_id.get(),
                account_uuid.as_str(),
                account_label.as_str(),
                millis(at)
            ],
        )?;
        Ok(())
    }

    /// L'account di un monitoraggio, se registrato.
    ///
    /// `None` è un monitoraggio nato prima della migrazione 0072, o
    /// dimostrativo.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se la lettura non riesce, o
    /// [`crate::StorageError::CorruptedValue`] se la riga non ha la forma che
    /// lo schema impone.
    pub fn session_account(
        &self,
        session_id: SessionId,
    ) -> StorageResult<Option<MonitoringAccount>> {
        let riga: Option<(String, String, i64)> = self
            .connection
            .query_row(
                "SELECT account_uuid, account_label, bound_at FROM session_accounts
                 WHERE session_id = ?1",
                [session_id.get()],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .optional()?;
        let Some((uuid, label, at)) = riga else {
            return Ok(None);
        };
        Ok(Some(MonitoringAccount {
            session_id,
            account_uuid: AccountUuid::from_hex(&uuid)?,
            account_label: DisplayName::try_new(&label)?,
            bound_at: instant(at),
        }))
    }

    /// Per ogni fonte, gli account con cui è stata seguita (DEC-441): quelli
    /// dei monitoraggi che la includono, ordinati per UUID.
    ///
    /// Una fonte inclusa soltanto in monitoraggi senza account non compare.
    /// Il nome è quello del legame più recente, perché l'ufficio può aver
    /// rinominato l'account fra un monitoraggio e l'altro.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se la lettura non riesce, o
    /// [`crate::StorageError::CorruptedValue`] se una riga non ha la forma che
    /// lo schema impone.
    pub fn source_accounts(&self) -> StorageResult<BTreeMap<i64, Vec<SourceAccount>>> {
        // In SQLite, con `max()` le colonne non aggregate vengono dalla riga
        // del massimo: il nome è quello del legame più recente.
        let mut statement = self.connection.prepare(
            "SELECT ss.source_id, sa.account_uuid, sa.account_label, max(sa.bound_at)
             FROM session_sources ss
             JOIN session_accounts sa ON sa.session_id = ss.session_id
             GROUP BY ss.source_id, sa.account_uuid
             ORDER BY ss.source_id, sa.account_uuid",
        )?;
        let righe = statement.query_map([], |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, i64>(3)?,
            ))
        })?;
        let mut per_fonte: BTreeMap<i64, Vec<SourceAccount>> = BTreeMap::new();
        for riga in righe {
            let (fonte, uuid, nome, quando) = riga?;
            per_fonte.entry(fonte).or_default().push(SourceAccount {
                account_uuid: AccountUuid::from_hex(&uuid)?,
                account_label: DisplayName::try_new(&nome)?,
                last_bound_at: instant(quando),
            });
        }
        Ok(per_fonte)
    }

    /// Quanti monitoraggi in corso non hanno un account registrato (nati
    /// prima della migrazione 0072, o dimostrativi).
    ///
    /// Con più account collegati non ricevono niente (ADR-0173): la schermata
    /// Account lo dice soltanto se ce n'è almeno uno.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se la lettura non riesce.
    pub fn running_sessions_without_account(&self) -> StorageResult<usize> {
        let quanti: i64 = self.connection.query_row(
            "SELECT count(*) FROM sessions s
             WHERE s.state = 'running'
               AND NOT EXISTS (SELECT 1 FROM session_accounts sa WHERE sa.session_id = s.id)",
            [],
            |row| row.get(0),
        )?;
        Ok(usize::try_from(quanti).unwrap_or(0))
    }
}

#[cfg(test)]
mod tests {
    use lisi_core::model::telegram_account::AccountUuid;
    use lisi_core::text::DisplayName;

    use crate::test_support::{
        database, database_with_session, later, new_session, new_source, now,
    };

    /// **Il legame si scrive una volta e si rilegge com'era** (criterio 2).
    #[test]
    fn il_legame_si_scrive_una_volta() {
        let (database, _, session_id) = database_with_session();
        let Ok(None) = database.session_account(session_id) else {
            panic!("un monitoraggio senza legame non ha account");
        };
        let (primo, secondo) = (
            AccountUuid::from_bytes([0xa1; 16]),
            AccountUuid::from_bytes([0xb2; 16]),
        );
        let Ok(nome) = DisplayName::try_new("Ufficio A") else {
            panic!("nome valido");
        };
        let Ok(()) = database.insert_session_account(session_id, &primo, &nome, later(1)) else {
            panic!("il legame si registra");
        };
        assert!(
            database
                .insert_session_account(session_id, &secondo, &nome, later(2))
                .is_err(),
            "un monitoraggio non ha due account"
        );
        let Ok(Some(letto)) = database.session_account(session_id) else {
            panic!("il legame si rilegge");
        };
        assert_eq!(letto.account_uuid, primo);
        assert_eq!(letto.account_label.as_str(), "Ufficio A");
        assert_eq!(letto.bound_at, later(1));
    }

    /// **Una fonte seguita da due account ha due account, e uno rinominato
    /// porta il nome più recente** (MULTI-ACCOUNT-02 parte 2, criterio 6,
    /// DEC-441). Prova negativa: una fonte dei soli monitoraggi senza account
    /// non ne ha nessuno, e un account non diventa di una fonte che non ha
    /// seguito.
    #[test]
    fn una_fonte_ha_gli_account_dei_monitoraggi_che_la_seguono() {
        let mut database = database();
        let mut fonti = Vec::new();
        for nome in ["comune", "sola_b", "senza"] {
            let Ok(id) = database.insert_source(&new_source(nome), now()) else {
                panic!("la fonte di prova si registra");
            };
            fonti.push(id);
        }
        let [comune, sola_b, senza] = fonti[..] else {
            panic!("tre fonti di prova");
        };
        let mut sessioni = Vec::new();
        for elenco in [
            vec![comune],
            vec![comune, sola_b],
            vec![comune],
            vec![senza],
        ] {
            let Ok(id) = database.insert_session(&new_session(elenco), now()) else {
                panic!("il monitoraggio di prova nasce");
            };
            sessioni.push(id);
        }
        let [primo, secondo, terzo, _senza_account] = sessioni[..] else {
            panic!("quattro monitoraggi di prova");
        };
        let (a, b) = (
            AccountUuid::from_bytes([0xa1; 16]),
            AccountUuid::from_bytes([0xb2; 16]),
        );
        let nome = |testo: &str| {
            let Ok(nome) = DisplayName::try_new(testo) else {
                panic!("nome valido");
            };
            nome
        };
        for (sessione, account, etichetta, quando) in [
            (primo, &a, "Ufficio A", 1),
            (secondo, &b, "Ufficio B", 2),
            (terzo, &a, "Ufficio A rinominato", 3),
        ] {
            let Ok(()) =
                database.insert_session_account(sessione, account, &nome(etichetta), later(quando))
            else {
                panic!("il legame si registra");
            };
        }

        let Ok(per_fonte) = database.source_accounts() else {
            panic!("gli account delle fonti si leggono");
        };
        let letti = |fonte: lisi_core::SourceId| -> Vec<(AccountUuid, String)> {
            per_fonte
                .get(&fonte.get())
                .map(|elenco| {
                    elenco
                        .iter()
                        .map(|voce| {
                            (
                                voce.account_uuid.clone(),
                                voce.account_label.as_str().to_owned(),
                            )
                        })
                        .collect()
                })
                .unwrap_or_default()
        };
        assert_eq!(
            letti(comune),
            vec![
                (a.clone(), String::from("Ufficio A rinominato")),
                (b.clone(), String::from("Ufficio B")),
            ],
            "la stessa chat seguita da due account è una fonte con due account"
        );
        assert_eq!(
            letti(sola_b),
            vec![(b, String::from("Ufficio B"))],
            "l'account A non ha mai seguito questa fonte"
        );
        assert!(
            !per_fonte.contains_key(&senza.get()),
            "un monitoraggio senza account non lega la fonte a nessun account"
        );
        assert_eq!(per_fonte.len(), 2);
    }

    /// **Si contano i monitoraggi in corso senza account, e soltanto quelli**
    /// (MULTI-ACCOUNT-02 parte 3). Prova negativa: uno legato, o non avviato,
    /// non conta.
    #[test]
    fn si_contano_i_monitoraggi_in_corso_senza_account() {
        use lisi_core::model::SessionState;

        let (mut database, fonte, pianificato) = database_with_session();
        let mut in_corso = Vec::new();
        for _ in 0..2 {
            let Ok(id) = database.insert_session(&new_session(vec![fonte]), now()) else {
                panic!("il monitoraggio di prova nasce");
            };
            let Ok(()) = database.update_session_state(id, SessionState::Running, later(1)) else {
                panic!("il monitoraggio di prova parte");
            };
            in_corso.push(id);
        }
        let Ok(2) = database.running_sessions_without_account() else {
            panic!("due in corso senza account");
        };
        let (Some(&legato), Ok(nome)) = (in_corso.first(), DisplayName::try_new("Ufficio A"))
        else {
            panic!("valori di prova validi");
        };
        let Ok(()) = database.insert_session_account(
            legato,
            &AccountUuid::from_bytes([0xa1; 16]),
            &nome,
            later(2),
        ) else {
            panic!("il legame si registra");
        };
        assert_eq!(
            database.running_sessions_without_account().ok(),
            Some(1),
            "il monitoraggio legato non conta, e quello pianificato {pianificato:?} nemmeno"
        );
    }

    /// **L'account di una fonte non si scrive sulla fonte** (DEC-441). La
    /// colonna `sources.account_id` della 0009 resta vuota: scriverla farebbe
    /// una seconda verità che può divergere dai monitoraggi, e con una chat
    /// seguita da due account direbbe soltanto uno dei due. Prova negativa:
    /// un aggiornamento della fonte che ne scrive l'account, in un sorgente
    /// qualunque → rossa.
    #[test]
    fn nessun_codice_scrive_l_account_sulla_fonte() {
        fn sorgenti(cartella: &std::path::Path, trovati: &mut Vec<std::path::PathBuf>) {
            let Ok(voci) = std::fs::read_dir(cartella) else {
                return;
            };
            for voce in voci.flatten() {
                let percorso = voce.path();
                if percorso.is_dir() {
                    sorgenti(&percorso, trovati);
                } else if percorso
                    .extension()
                    .is_some_and(|estensione| estensione == "rs")
                {
                    trovati.push(percorso);
                }
            }
        }
        let crates = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("..");
        let mut file = Vec::new();
        let Ok(voci) = std::fs::read_dir(&crates) else {
            panic!("le crate del prodotto si leggono");
        };
        for voce in voci.flatten() {
            sorgenti(&voce.path().join("src"), &mut file);
        }
        assert!(
            file.len() > 50,
            "la guardia deve vedere i sorgenti del prodotto"
        );
        for percorso in file {
            let Ok(testo) = std::fs::read_to_string(&percorso) else {
                panic!("{} si legge", percorso.display());
            };
            let testo = testo.to_lowercase();
            for inizio in ["update sources", "insert into sources ("] {
                for (posizione, _) in testo.match_indices(inizio) {
                    let fine = testo.len().min(posizione + 400);
                    let istruzione = testo
                        .get(posizione..fine)
                        .and_then(|pezzo| pezzo.split('"').next())
                        .unwrap_or_default();
                    assert!(
                        !istruzione.contains("account_id"),
                        "{} scrive l'account sulla fonte: «{istruzione}»",
                        percorso.display()
                    );
                }
            }
        }
    }
}
