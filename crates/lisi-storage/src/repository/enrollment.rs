//! I dispositivi arruolati presso questo Hub, e le autorizzazioni che li hanno
//! fatti entrare.
//!
//! # Che cosa questo modulo custodisce, e che cosa deliberatamente no
//!
//! Custodisce **impronte**: del codice di arruolamento e del gettone del
//! dispositivo. Non custodisce né l'uno né l'altro. Chi legge questo archivio
//! non trova credenziali utilizzabili — trova la prova che qualcuno le
//! possedeva.
//!
//! # L'uso unico non è un controllo, è una scrittura
//!
//! Un codice vale una volta sola. Il modo sbagliato di garantirlo è leggere se
//! sia libero e poi consumarlo: fra le due operazioni c'è una finestra, e in
//! quella finestra due richieste possono decidere entrambe che è libero.
//!
//! Il modo giusto è consumarlo con una condizione, e **leggere quante righe si
//! sono toccate**. Chi ne tocca zero ha perso la corsa, e lo scopre dalla
//! scrittura invece che da un controllo che non c'entra più nulla.

use lisi_core::model::enrollment::EnrollmentRequest;
use lisi_core::text::{DisplayName, Note};
use lisi_core::{Sha256Digest, Timestamp};
use rusqlite::{OptionalExtension, params};

use crate::database::Database;
use crate::error::{StorageError, StorageResult};
use crate::repository::{instant, millis};

/// Un'autorizzazione emessa, per come l'Hub la ricorda.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredEnrollmentCode {
    /// Riga dell'autorizzazione.
    pub id: i64,
    /// Chi l'ha emessa.
    pub issued_by: String,
    /// Quando.
    pub issued_at: Timestamp,
    /// Fino a quando vale.
    pub expires_at: Timestamp,
    /// Quale dispositivo l'ha usata, se qualcuno l'ha usata.
    pub consumed_by: Option<String>,
}

/// Un dispositivo ammesso da questo Hub.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnrolledDevice {
    /// Il nome pubblico del dispositivo.
    pub device_id: String,
    /// Come lo chiama l'ufficio.
    pub label: DisplayName,
    /// Quando è stato ammesso.
    pub enrolled_at: Timestamp,
    /// Quando è stato ritirato, se lo è stato.
    pub revoked_at: Option<Timestamp>,
    /// Perché è stato ritirato.
    pub revoked_reason: Option<Note>,
}

impl EnrolledDevice {
    /// Vero se l'Hub non lo riconosce più.
    #[must_use]
    pub const fn is_revoked(&self) -> bool {
        self.revoked_at.is_some()
    }
}

/// Esito dell'ammissione di un dispositivo.
///
/// Distingue i casi che il chiamante deve poter distinguere per spiegare il
/// rifiuto, e **non** distingue quelli che non deve: un codice inesistente e un
/// codice sbagliato producono entrambi [`Self::CodeNotFound`], perché dirlo
/// direbbe a chi tenta se è vicino.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Admission {
    /// Il dispositivo è ammesso, e l'autorizzazione è consumata.
    Admitted {
        /// Riga dell'autorizzazione consumata.
        code_id: i64,
    },
    /// Nessuna autorizzazione con quell'impronta.
    CodeNotFound,
    /// L'autorizzazione esisteva, ed è scaduta.
    CodeExpired,
    /// L'autorizzazione esisteva, e qualcuno l'ha già usata.
    CodeAlreadyUsed,
    /// Questo Hub conosce già il dispositivo.
    DeviceAlreadyEnrolled,
    /// Questo Hub conosceva il dispositivo e lo ha ritirato.
    DeviceRevoked {
        /// Perché era stato ritirato.
        reason: Note,
    },
}

impl Database {
    /// Registra un'autorizzazione appena emessa.
    ///
    /// Riceve l'**impronta**, non il codice: il codice non entra mai qui.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se la scrittura non riesce, o se un'autorizzazione
    /// con la stessa impronta esiste già — che con ottanta bit di caso significa
    /// un difetto del generatore, non una coincidenza.
    pub fn record_enrollment_code(
        &self,
        fingerprint: &Sha256Digest,
        issued_by: &str,
        issued_at: Timestamp,
        expires_at: Timestamp,
    ) -> StorageResult<i64> {
        let id: i64 = self.connection.query_row(
            "INSERT INTO enrollment_codes (code_hash, issued_by, issued_at, expires_at)
             VALUES (?1, ?2, ?3, ?4)
             RETURNING id",
            params![
                fingerprint.as_str(),
                issued_by,
                millis(issued_at),
                millis(expires_at)
            ],
            |row| row.get(0),
        )?;
        Ok(id)
    }

    /// Ammette un dispositivo, consumando l'autorizzazione, in un atto solo.
    ///
    /// # Perché è un metodo solo e non due
    ///
    /// Perché consumare l'autorizzazione e ammettere il dispositivo devono
    /// riuscire o fallire insieme. Due metodi separati avrebbero permesso di
    /// chiamarne uno e non l'altro — e l'esito sarebbe stato il peggiore
    /// possibile: un codice bruciato che non ha fatto entrare nessuno, e una
    /// riga che dice che qualcuno è entrato con un'autorizzazione che non lo
    /// nomina.
    ///
    /// La transazione lo rende impossibile per costruzione, invece che
    /// improbabile per attenzione.
    ///
    /// # Perché la condizione sta nella scrittura
    ///
    /// `consumed_by IS NULL` dentro l'aggiornamento è ciò che rende l'uso unico
    /// una proprietà e non una speranza. Due richieste concorrenti eseguono
    /// entrambe questa istruzione; **una sola** tocca una riga, e l'altra lo
    /// scopre dal conteggio invece che da un controllo che nel frattempo è
    /// diventato vecchio.
    ///
    /// Le letture che seguono un fallimento servono soltanto a **spiegarlo**: la
    /// decisione è già stata presa dalla scrittura.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se la transazione non riesce.
    pub fn admit_device(
        &mut self,
        request: &EnrollmentRequest,
        verifier: &Sha256Digest,
        now: Timestamp,
    ) -> StorageResult<Admission> {
        // **IMMEDIATE, non la transazione predefinita.**
        //
        // Quella predefinita e' `DEFERRED`: prende il lucchetto alla prima
        // scrittura. Qui si legge prima e si scrive dopo, e due richieste
        // concorrenti finiscono entrambe a leggere, poi entrambe a voler
        // scrivere. SQLite non puo' far attendere la seconda — attendere
        // sarebbe uno stallo, perche' ciascuna tiene una lettura che l'altra
        // deve superare — e risponde **subito** `SQLITE_BUSY`, senza consultare
        // il timeout di attesa configurato all'apertura.
        //
        // L'esito sarebbe un arruolamento fallito con un errore tecnico invece
        // che con un esito, e a caso: dipende da quale delle due arriva prima.
        //
        // `IMMEDIATE` prende il lucchetto di scrittura all'inizio. La seconda
        // richiesta aspetta il proprio turno — li' il timeout vale — e poi
        // trova il codice gia' consumato, che e' la risposta giusta.
        //
        // Lo ha trovato la prova di concorrenza, e non alla prima esecuzione:
        // e' rimasta verde finche' la macchina non era carica.
        let transaction = self
            .connection
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        let fingerprint = request.code.fingerprint();
        let device_id = request.device_id.as_str();

        // Il dispositivo prima del codice.
        //
        // A NON bruciare l'autorizzazione non e' quest'ordine: e' la
        // transazione. Ogni uscita anticipata da qui abbandona la transazione,
        // che ritira quanto scritto. Un controllo negativo lo ha verificato -
        // riordinando i blocchi la prova resta verde, mentre spostando il
        // consumo in una scrittura propria diventa rossa.
        //
        // L'ordine resta questo per una ragione piu' modesta e vera: il
        // controllo costa una lettura, e un dispositivo che non puo' entrare non
        // fa scrivere nulla.
        let esistente: Option<(Option<i64>, Option<String>)> = transaction
            .query_row(
                "SELECT revoked_at, revoked_reason FROM enrolled_devices WHERE device_id = ?1",
                params![device_id],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()?;

        match esistente {
            Some((Some(_), ragione)) => {
                let reason = Note::try_new(ragione.as_deref().unwrap_or("ritirato"))?;
                return Ok(Admission::DeviceRevoked { reason });
            }
            Some((None, _)) => return Ok(Admission::DeviceAlreadyEnrolled),
            None => {}
        }

        let toccate = transaction.execute(
            "UPDATE enrollment_codes
                SET consumed_by = ?2, consumed_at = ?3
              WHERE code_hash = ?1
                AND consumed_by IS NULL
                AND expires_at > ?3",
            params![fingerprint.as_str(), device_id, millis(now)],
        )?;

        if toccate != 1 {
            let stato: Option<Option<String>> = transaction
                .query_row(
                    "SELECT consumed_by FROM enrollment_codes WHERE code_hash = ?1",
                    params![fingerprint.as_str()],
                    |row| row.get(0),
                )
                .optional()?;
            return Ok(match stato {
                None => Admission::CodeNotFound,
                Some(Some(_)) => Admission::CodeAlreadyUsed,
                Some(None) => Admission::CodeExpired,
            });
        }

        let code_id: i64 = transaction.query_row(
            "SELECT id FROM enrollment_codes WHERE code_hash = ?1",
            params![fingerprint.as_str()],
            |row| row.get(0),
        )?;

        transaction.execute(
            "INSERT INTO enrolled_devices
                 (device_id, label, token_verifier, enrolled_at, enrolled_with)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![
                device_id,
                request.label.as_str(),
                verifier.as_str(),
                millis(now),
                code_id
            ],
        )?;

        transaction.commit()?;
        Ok(Admission::Admitted { code_id })
    }

    /// Legge un dispositivo ammesso, se questo Hub lo conosce.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se la lettura non riesce o se una riga conservata
    /// non è interpretabile.
    pub fn enrolled_device(&self, device_id: &str) -> StorageResult<Option<EnrolledDevice>> {
        self.connection
            .query_row(
                "SELECT device_id, label, enrolled_at, revoked_at, revoked_reason
                   FROM enrolled_devices
                  WHERE device_id = ?1",
                params![device_id],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, i64>(2)?,
                        row.get::<_, Option<i64>>(3)?,
                        row.get::<_, Option<String>>(4)?,
                    ))
                },
            )
            .optional()?
            .map(leggi_dispositivo)
            .transpose()
    }

    /// Tutti i dispositivi che questo Hub ha ammesso, ritirati compresi.
    ///
    /// # Perché anche i ritirati
    ///
    /// Perché «non è mai entrato» e «è entrato ed è stato ritirato» sono due
    /// fatti diversi, e un elenco che mostrasse solo i vivi renderebbe il
    /// secondo indistinguibile dal primo.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se la lettura non riesce o se una riga conservata
    /// non è interpretabile.
    pub fn enrolled_devices(&self) -> StorageResult<Vec<EnrolledDevice>> {
        let mut statement = self.connection.prepare(
            "SELECT device_id, label, enrolled_at, revoked_at, revoked_reason
               FROM enrolled_devices
              ORDER BY enrolled_at DESC, id DESC",
        )?;
        let righe = statement.query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, i64>(2)?,
                row.get::<_, Option<i64>>(3)?,
                row.get::<_, Option<String>>(4)?,
            ))
        })?;

        let mut lette = Vec::new();
        for riga in righe {
            lette.push(leggi_dispositivo(riga?)?);
        }
        Ok(lette)
    }

    /// Ritira un dispositivo su questo Hub.
    ///
    /// **È la revoca che conta.** Quella registrata sulla postazione è una copia
    /// che spiega; questa è quella che il dispositivo non può riscrivere.
    ///
    /// Ritirare due volte non cambia nulla: prevale la prima ragione, che è
    /// quella che spiega perché il dispositivo ha smesso di funzionare.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se la scrittura non riesce.
    pub fn revoke_enrolled_device(
        &self,
        device_id: &str,
        reason: &Note,
        now: Timestamp,
    ) -> StorageResult<bool> {
        let toccate = self.connection.execute(
            "UPDATE enrolled_devices
                SET revoked_at = ?2, revoked_reason = ?3
              WHERE device_id = ?1
                AND revoked_at IS NULL",
            params![device_id, millis(now), reason.as_str()],
        )?;
        Ok(toccate == 1)
    }

    /// Registra un tentativo di arruolamento andato a vuoto.
    ///
    /// Conserva la ragione e l'istante. **Non il codice tentato**, nemmeno in
    /// impronta: un archivio dei codici tentati sarebbe un elenco di cose che
    /// qualcuno ha creduto potessero funzionare.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se la scrittura non riesce.
    pub fn record_enrollment_failure(&self, reason: &str, now: Timestamp) -> StorageResult<()> {
        self.connection.execute(
            "INSERT INTO enrollment_failures (reason, happened_at) VALUES (?1, ?2)",
            params![reason, millis(now)],
        )?;
        Ok(())
    }

    /// Quanti tentativi a vuoto sono avvenuti dall'istante indicato.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se la lettura non riesce.
    pub fn enrollment_failures_since(&self, since: Timestamp) -> StorageResult<u32> {
        let quanti: i64 = self.connection.query_row(
            "SELECT COUNT(*) FROM enrollment_failures WHERE happened_at >= ?1",
            params![millis(since)],
            |row| row.get(0),
        )?;
        // Un conteggio che non entra in trentadue bit significa piu' di quattro
        // miliardi di tentativi in un quarto d'ora: non succedera', e se
        // succedesse la risposta giusta e' comunque «troppi». Ripiegare sul
        // massimo sbaglia dalla parte del chiudere, non da quella dell'aprire.
        Ok(u32::try_from(quanti).unwrap_or(u32::MAX))
    }

    /// Il tentativo a vuoto più vecchio dall'istante indicato.
    ///
    /// Serve a dire fra quanto si potrà riprovare: la finestra scorre, e il
    /// blocco finisce quando il più vecchio dei tentativi ne esce.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se la lettura non riesce.
    pub fn oldest_enrollment_failure_since(
        &self,
        since: Timestamp,
    ) -> StorageResult<Option<Timestamp>> {
        let quando: Option<i64> = self.connection.query_row(
            "SELECT MIN(happened_at) FROM enrollment_failures WHERE happened_at >= ?1",
            params![millis(since)],
            |row| row.get(0),
        )?;
        Ok(quando.map(instant))
    }

    /// Un'autorizzazione, per come l'Hub la ricorda.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se la lettura non riesce.
    pub fn enrollment_code(&self, code_id: i64) -> StorageResult<Option<StoredEnrollmentCode>> {
        self.connection
            .query_row(
                "SELECT id, issued_by, issued_at, expires_at, consumed_by
                   FROM enrollment_codes
                  WHERE id = ?1",
                params![code_id],
                |row| {
                    Ok(StoredEnrollmentCode {
                        id: row.get(0)?,
                        issued_by: row.get(1)?,
                        issued_at: instant(row.get(2)?),
                        expires_at: instant(row.get(3)?),
                        consumed_by: row.get(4)?,
                    })
                },
            )
            .optional()
            .map_err(StorageError::from)
    }
}

/// Interpreta una riga di dispositivo ammesso.
fn leggi_dispositivo(
    riga: (String, String, i64, Option<i64>, Option<String>),
) -> StorageResult<EnrolledDevice> {
    let (device_id, label, enrolled_at, revoked_at, revoked_reason) = riga;
    Ok(EnrolledDevice {
        device_id,
        label: DisplayName::try_new(&label)?,
        enrolled_at: instant(enrolled_at),
        revoked_at: revoked_at.map(instant),
        revoked_reason: revoked_reason.as_deref().map(Note::try_new).transpose()?,
    })
}

impl Database {
    /// Ciò che l'Hub conserva per riconoscere un dispositivo: l'impronta del
    /// gettone, se è ritirato, il ruolo (HUB-AUTHZ-01).
    ///
    /// `None` se questo Hub non conosce il dispositivo.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se la lettura non riesce o se l'impronta o il
    /// ruolo conservati non sono interpretabili.
    pub fn device_credential(
        &self,
        device_id: &str,
    ) -> StorageResult<Option<lisi_core::model::hub_access::StoredCredential>> {
        self.connection
            .query_row(
                "SELECT token_verifier, revoked_at IS NOT NULL, role
                   FROM enrolled_devices
                  WHERE device_id = ?1",
                params![device_id],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, bool>(1)?,
                        row.get::<_, String>(2)?,
                    ))
                },
            )
            .optional()?
            .map(|(verifier, revoked, role)| {
                Ok(lisi_core::model::hub_access::StoredCredential {
                    verifier: Sha256Digest::from_hex(&verifier)?,
                    revoked,
                    role: lisi_core::model::hub_access::HubRole::parse(&role)?,
                })
            })
            .transpose()
    }

    /// Assegna il ruolo a un dispositivo **non ritirato**.
    ///
    /// Restituisce `true` se il ruolo è cambiato; `false` se il dispositivo non
    /// esiste, è ritirato, o aveva già quel ruolo. Un dispositivo ritirato non
    /// riceve poteri: il ritiro è una decisione su quell'identità (ADR-0047
    /// decisione 7).
    ///
    /// # Errori
    ///
    /// Restituisce un errore se la scrittura non riesce.
    pub fn set_enrolled_device_role(
        &self,
        device_id: &str,
        role: lisi_core::model::hub_access::HubRole,
    ) -> StorageResult<bool> {
        let toccate = self.connection.execute(
            "UPDATE enrolled_devices
                SET role = ?2
              WHERE device_id = ?1
                AND revoked_at IS NULL
                AND role <> ?2",
            params![device_id, role.as_str()],
        )?;
        Ok(toccate == 1)
    }
}
