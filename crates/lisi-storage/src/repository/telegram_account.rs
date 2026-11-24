//! Profili di credenziali API e account Telegram.
//!
//! Solo metadati non segreti (ADR-0019): l'API hash, il numero pieno, i codici e
//! le chiavi non passano da qui. Il numero e' conservato mascherato; l'identita'
//! stabile e' l'UUID.

use lisi_core::model::{
    AccountUuid, ApiCredentialProfile, MaskedPhoneNumber, NewApiCredentialProfile,
    NewTelegramAccount, PersistedAuthStatus, PersistedConnectionStatus, TelegramAccount,
};
use lisi_core::text::DisplayName;
use lisi_core::{ApiCredentialProfileId, TelegramAccountId, Timestamp};
use rusqlite::{OptionalExtension, Row};

use crate::database::Database;
use crate::error::{StorageError, StorageResult};
use crate::repository::{instant, millis};

fn read_profile(row: &Row<'_>) -> StorageResult<ApiCredentialProfile> {
    Ok(ApiCredentialProfile {
        id: ApiCredentialProfileId::new(row.get(0)?),
        label: DisplayName::try_new(&row.get::<_, String>(1)?)?,
        configured: row.get::<_, i64>(2)? != 0,
        created_at: instant(row.get(3)?),
        updated_at: instant(row.get(4)?),
    })
}

fn read_account(row: &Row<'_>) -> StorageResult<TelegramAccount> {
    let masked_phone = match row.get::<_, Option<String>>(3)? {
        Some(raw) => Some(MaskedPhoneNumber::from_stored(&raw)?),
        None => None,
    };
    Ok(TelegramAccount {
        id: TelegramAccountId::new(row.get(0)?),
        uuid: AccountUuid::from_hex(&row.get::<_, String>(1)?)?,
        label: DisplayName::try_new(&row.get::<_, String>(2)?)?,
        masked_phone,
        profile_id: ApiCredentialProfileId::new(row.get(4)?),
        auth_status: PersistedAuthStatus::parse(&row.get::<_, String>(5)?)?,
        connection_status: PersistedConnectionStatus::parse(&row.get::<_, String>(6)?)?,
        last_connected_at: row.get::<_, Option<i64>>(7)?.map(instant),
        created_at: instant(row.get(8)?),
        updated_at: instant(row.get(9)?),
    })
}

const ACCOUNT_COLUMNS: &str = "id, uuid, label, masked_phone, profile_id, auth_status, \
     connection_status, last_connected_at, created_at, updated_at";

impl Database {
    /// Registra un profilo di credenziali API (non configurato: il segreto si
    /// salva a parte).
    ///
    /// # Errori
    ///
    /// Restituisce un errore se la scrittura non riesce.
    pub fn insert_api_profile(
        &self,
        profile: &NewApiCredentialProfile,
        now: Timestamp,
    ) -> StorageResult<ApiCredentialProfileId> {
        let id = self.connection.query_row(
            "INSERT INTO api_credential_profiles (label, configured, created_at, updated_at)
             VALUES (?1, 0, ?2, ?2) RETURNING id",
            rusqlite::params![profile.label.as_str(), millis(now)],
            |row| row.get(0),
        )?;
        Ok(ApiCredentialProfileId::new(id))
    }

    /// Segna un profilo come configurato (o non) e ne aggiorna l'istante.
    ///
    /// # Errori
    ///
    /// Restituisce [`StorageError::NotFound`] se il profilo non esiste.
    pub fn set_api_profile_configured(
        &self,
        id: ApiCredentialProfileId,
        configured: bool,
        now: Timestamp,
    ) -> StorageResult<()> {
        let changed = self.connection.execute(
            "UPDATE api_credential_profiles SET configured = ?1, updated_at = ?2 WHERE id = ?3",
            rusqlite::params![i64::from(configured), millis(now), id.get()],
        )?;
        if changed == 0 {
            return Err(StorageError::NotFound {
                entity: "profilo_api",
                id: id.get(),
            });
        }
        Ok(())
    }

    /// Legge un profilo API.
    ///
    /// # Errori
    ///
    /// Restituisce [`StorageError::NotFound`] se il profilo non esiste.
    pub fn api_profile(&self, id: ApiCredentialProfileId) -> StorageResult<ApiCredentialProfile> {
        self.connection
            .query_row(
                "SELECT id, label, configured, created_at, updated_at
                 FROM api_credential_profiles WHERE id = ?1",
                [id.get()],
                |row| Ok(read_profile(row)),
            )
            .optional()?
            .transpose()?
            .ok_or(StorageError::NotFound {
                entity: "profilo_api",
                id: id.get(),
            })
    }

    /// Tutti i profili API, dal piu' recente.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se la lettura non riesce.
    pub fn api_profiles(&self) -> StorageResult<Vec<ApiCredentialProfile>> {
        let mut statement = self.connection.prepare(
            "SELECT id, label, configured, created_at, updated_at
             FROM api_credential_profiles ORDER BY id DESC",
        )?;
        let rows = statement.query_map([], |row| Ok(read_profile(row)))?;
        let mut profiles = Vec::new();
        for row in rows {
            profiles.push(row??);
        }
        Ok(profiles)
    }

    /// Registra un account Telegram nello stato iniziale (`fresh`/`unknown`).
    ///
    /// # Errori
    ///
    /// Restituisce un errore se l'UUID e' gia' usato, se il profilo non esiste,
    /// o se la scrittura non riesce.
    pub fn insert_telegram_account(
        &self,
        account: &NewTelegramAccount,
        now: Timestamp,
    ) -> StorageResult<TelegramAccountId> {
        let id = self
            .connection
            .query_row(
                "INSERT INTO telegram_accounts
                     (uuid, label, masked_phone, profile_id, auth_status,
                      connection_status, last_connected_at, created_at, updated_at)
                 VALUES (?1, ?2, NULL, ?3, 'fresh', 'unknown', NULL, ?4, ?4)
                 RETURNING id",
                rusqlite::params![
                    account.uuid.as_str(),
                    account.label.as_str(),
                    account.profile_id.get(),
                    millis(now),
                ],
                |row| row.get(0),
            )
            .map_err(map_account_write_error)?;
        Ok(TelegramAccountId::new(id))
    }

    /// Aggiorna gli stati (autorizzazione, connessione) e il numero mascherato.
    ///
    /// Il numero mascherato si scrive solo se `Some`: un `None` non cancella un
    /// numero gia' noto.
    ///
    /// # Errori
    ///
    /// Restituisce [`StorageError::NotFound`] se l'account non esiste.
    pub fn update_account_state(
        &self,
        id: TelegramAccountId,
        auth: PersistedAuthStatus,
        connection: PersistedConnectionStatus,
        masked_phone: Option<&MaskedPhoneNumber>,
        connected_at: Option<Timestamp>,
        now: Timestamp,
    ) -> StorageResult<()> {
        let changed = self.connection.execute(
            "UPDATE telegram_accounts
             SET auth_status = ?1,
                 connection_status = ?2,
                 masked_phone = COALESCE(?3, masked_phone),
                 last_connected_at = COALESCE(?4, last_connected_at),
                 updated_at = ?5
             WHERE id = ?6",
            rusqlite::params![
                auth.as_str(),
                connection.as_str(),
                masked_phone.map(MaskedPhoneNumber::as_str),
                connected_at.map(millis),
                millis(now),
                id.get(),
            ],
        )?;
        if changed == 0 {
            return Err(StorageError::NotFound {
                entity: "account",
                id: id.get(),
            });
        }
        Ok(())
    }

    /// Legge un account.
    ///
    /// # Errori
    ///
    /// Restituisce [`StorageError::NotFound`] se l'account non esiste.
    pub fn telegram_account(&self, id: TelegramAccountId) -> StorageResult<TelegramAccount> {
        self.connection
            .query_row(
                &format!("SELECT {ACCOUNT_COLUMNS} FROM telegram_accounts WHERE id = ?1"),
                [id.get()],
                |row| Ok(read_account(row)),
            )
            .optional()?
            .transpose()?
            .ok_or(StorageError::NotFound {
                entity: "account",
                id: id.get(),
            })
    }

    /// Tutti gli account, dal piu' recente.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se la lettura non riesce.
    pub fn telegram_accounts(&self) -> StorageResult<Vec<TelegramAccount>> {
        let mut statement = self.connection.prepare(&format!(
            "SELECT {ACCOUNT_COLUMNS} FROM telegram_accounts ORDER BY id DESC"
        ))?;
        let rows = statement.query_map([], |row| Ok(read_account(row)))?;
        let mut accounts = Vec::new();
        for row in rows {
            accounts.push(row??);
        }
        Ok(accounts)
    }

    /// Rimuove un profilo di credenziali API.
    ///
    /// Gli account che vi fanno riferimento lo impediscono: un profilo rimosso
    /// mentre un account lo usa lascerebbe quell'account senza credenziali,
    /// cioe' inservibile e senza che nulla lo dica. Chi azzera deve rimuovere
    /// prima gli account.
    ///
    /// **Non tocca il file protetto** con le credenziali cifrate: quello vive
    /// sul disco e lo rimuove il chiamante, che conosce la cartella base.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se il profilo non esiste o se un account vi fa
    /// ancora riferimento.
    pub fn delete_api_profile(&self, id: ApiCredentialProfileId) -> StorageResult<()> {
        let changed = self
            .connection
            .execute(
                "DELETE FROM api_credential_profiles WHERE id = ?1",
                [id.get()],
            )
            .map_err(map_account_write_error)?;
        if changed == 0 {
            return Err(StorageError::NotFound {
                entity: "profilo_api",
                id: id.get(),
            });
        }
        Ok(())
    }

    /// Rimuove un account. Le fonti associate lo impediscono (ON DELETE RESTRICT).
    ///
    /// # Errori
    ///
    /// Restituisce un errore se l'account ha fonti associate o non esiste.
    pub fn delete_telegram_account(&self, id: TelegramAccountId) -> StorageResult<()> {
        let changed = self
            .connection
            .execute("DELETE FROM telegram_accounts WHERE id = ?1", [id.get()])
            .map_err(map_account_write_error)?;
        if changed == 0 {
            return Err(StorageError::NotFound {
                entity: "account",
                id: id.get(),
            });
        }
        Ok(())
    }
}

/// Traduce i conflitti di vincolo di scrittura di un account.
fn map_account_write_error(error: rusqlite::Error) -> StorageError {
    use crate::error::{ConstraintKind, constraint_kind};
    match constraint_kind(&error) {
        Some(ConstraintKind::Unique) => StorageError::DuplicateAccountUuid,
        Some(ConstraintKind::ForeignKey) => StorageError::AccountProfileMissing,
        _ => StorageError::Sqlite(error),
    }
}

#[cfg(test)]
mod tests {
    use lisi_core::model::{
        AccountUuid, MaskedPhoneNumber, NewApiCredentialProfile, NewTelegramAccount,
        PersistedAuthStatus, PersistedConnectionStatus,
    };
    use lisi_core::text::DisplayName;
    use lisi_core::{ApiCredentialProfileId, Timestamp};

    use crate::error::StorageError;
    use crate::test_support::database;

    fn now() -> Timestamp {
        Timestamp::from_millis(1_700_000_000_000)
    }

    fn profile(database: &crate::Database) -> ApiCredentialProfileId {
        database
            .insert_api_profile(
                &NewApiCredentialProfile {
                    label: DisplayName::try_new("Profilo ufficio").unwrap(),
                },
                now(),
            )
            .expect("profilo inserito")
    }

    #[test]
    fn a_profile_round_trips_and_starts_unconfigured() {
        let db = database();
        let id = profile(&db);
        let read = db.api_profile(id).expect("profilo leggibile");
        assert_eq!(read.label.as_str(), "Profilo ufficio");
        assert!(!read.configured, "un profilo nasce non configurato");

        db.set_api_profile_configured(id, true, now()).unwrap();
        assert!(db.api_profile(id).unwrap().configured);
    }

    #[test]
    fn an_account_round_trips_with_its_uuid_and_starts_fresh() {
        let db = database();
        let profile_id = profile(&db);
        let uuid = AccountUuid::from_bytes([0xab; 16]);
        let id = db
            .insert_telegram_account(
                &NewTelegramAccount {
                    uuid: uuid.clone(),
                    label: DisplayName::try_new("Account di prova").unwrap(),
                    profile_id,
                },
                now(),
            )
            .expect("account inserito");

        let read = db.telegram_account(id).expect("account leggibile");
        assert_eq!(read.uuid, uuid);
        assert_eq!(read.auth_status, PersistedAuthStatus::Fresh);
        assert_eq!(read.connection_status, PersistedConnectionStatus::Unknown);
        assert!(read.masked_phone.is_none());
        assert!(read.last_connected_at.is_none());
    }

    #[test]
    fn updating_state_sets_the_masked_phone_and_statuses() {
        let db = database();
        let profile_id = profile(&db);
        let id = db
            .insert_telegram_account(
                &NewTelegramAccount {
                    uuid: AccountUuid::from_bytes([0x01; 16]),
                    label: DisplayName::try_new("Account").unwrap(),
                    profile_id,
                },
                now(),
            )
            .unwrap();

        let masked = MaskedPhoneNumber::from_digits("+39 340 1234599");
        db.update_account_state(
            id,
            PersistedAuthStatus::Authorized,
            PersistedConnectionStatus::Connected,
            Some(&masked),
            Some(now()),
            now(),
        )
        .unwrap();

        let read = db.telegram_account(id).unwrap();
        assert_eq!(read.auth_status, PersistedAuthStatus::Authorized);
        assert_eq!(read.connection_status, PersistedConnectionStatus::Connected);
        // 12 cifre, 2 in chiaro, 10 mascherate.
        assert_eq!(
            read.masked_phone.as_ref().map(MaskedPhoneNumber::as_str),
            Some("+**********99")
        );
        assert!(read.last_connected_at.is_some());

        // Un aggiornamento successivo con numero None non cancella quello noto.
        db.update_account_state(
            id,
            PersistedAuthStatus::Authorized,
            PersistedConnectionStatus::Offline,
            None,
            None,
            now(),
        )
        .unwrap();
        assert!(db.telegram_account(id).unwrap().masked_phone.is_some());
    }

    #[test]
    fn a_duplicate_uuid_is_refused() {
        let db = database();
        let profile_id = profile(&db);
        let uuid = AccountUuid::from_bytes([0x02; 16]);
        let account = NewTelegramAccount {
            uuid,
            label: DisplayName::try_new("A").unwrap(),
            profile_id,
        };
        db.insert_telegram_account(&account, now()).unwrap();
        assert!(matches!(
            db.insert_telegram_account(&account, now()),
            Err(StorageError::DuplicateAccountUuid)
        ));
    }

    #[test]
    fn an_account_referencing_a_missing_profile_is_refused() {
        let db = database();
        let account = NewTelegramAccount {
            uuid: AccountUuid::from_bytes([0x03; 16]),
            label: DisplayName::try_new("A").unwrap(),
            profile_id: ApiCredentialProfileId::new(999),
        };
        assert!(matches!(
            db.insert_telegram_account(&account, now()),
            Err(StorageError::AccountProfileMissing)
        ));
    }

    #[test]
    fn reading_a_missing_account_is_not_found() {
        let db = database();
        assert!(matches!(
            db.telegram_account(lisi_core::TelegramAccountId::new(1)),
            Err(StorageError::NotFound { .. })
        ));
    }
}
