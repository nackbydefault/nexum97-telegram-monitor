//! Le uscite del solo utente: ciò che il programma scrive fuori
//! dall'archivio nasce leggibile dal solo utente Windows che lo scrive, o non
//! nasce affatto (SEC-01, SEC-02; ADR-0157, ADR-0159).
//!
//! # Perché un modulo solo
//!
//! SEC-01 ha protetto la copia di sicurezza e il pacchetto di relazione, ma il
//! programma scrive altre nove cose fuori dall'archivio: il rapporto di una
//! sessione, l'esportazione STIX, il pacchetto di evidenze, il passaggio di
//! consegne, il dizionario esportato, il pacchetto per l'assistenza, il
//! fascicolo condivisibile, il registro delle operazioni archiviato prima di un
//! azzeramento, la copia dell'ufficio. Ripetere in ciascuna la stessa sequenza
//! — cartella privata, restrizione, rilettura, arrivo, seconda rilettura,
//! pulizia — significherebbe nove occasioni di sbagliarne un passo. Qui la
//! sequenza è scritta una volta.
//!
//! # Le due forme
//!
//! - [`Delivery`]: uno o più **file sciolti** che arrivano in una cartella che
//!   ne contiene altri (la cartella dei documenti, una cartella scelta). Si
//!   scrivono in una cartella di lavoro privata creata lì, ciascuno riceve un
//!   DACL esplicito e protetto del solo utente, e arrivano con un rinomino; i
//!   permessi si rileggono prima e dopo l'arrivo.
//! - [`ProtectedFolder`]: una **cartella nuova** che è essa stessa l'uscita (un
//!   pacchetto): ristretta appena creata, prima del primo file, che ne eredita
//!   i permessi; si rilegge prima di dichiararla completa.
//!
//! # Il rifiuto
//!
//! Se la protezione non si può applicare **e verificare** — una chiavetta
//! FAT32 o exFAT, una cartella di rete che rifiuta i permessi, una voce
//! inattesa nel DACL riletto — l'uscita non si scrive, e ciò che il programma
//! aveva cominciato a scrivere si toglie: l'errore è
//! [`ServiceError::ProtectionNotGuaranteed`]. Un supporto senza permessi resta
//! escluso finché non esiste una cifratura verificata (ENCRYPT-01).
//!
//! Il successo di Windows non è mai la prova: lo è ciò che si rilegge.

use std::path::{Path, PathBuf};

use lisi_core::Timestamp;
use lisi_core::model::NewAuditEntry;
use lisi_core::text::{Actor, AuditAction, AuditDetail, AuditEntity};
pub use lisi_security::owner_only::CurrentUser;
use lisi_security::owner_only::{
    Access, PrivateDirectory, restrict_to_current_user, verify_current_user_only,
};
use lisi_storage::Database;

use crate::error::{ServiceError, ServiceResult};

/// Estensione della cartella di lavoro in cui un'uscita nasce.
///
/// Se il programma si interrompe a metà, nella cartella scelta resta una
/// cartella con questo nome: del solo utente, e con un nome che dice
/// «interrotta».
pub(crate) const WORK_EXTENSION: &str = "parziale";

/// Azione dell'audit di un'uscita rifiutata per i permessi.
///
/// La copia di sicurezza ha la propria
/// ([`crate::backup::REFUSED_AUDIT_ACTION`]), perché la fascia di prontezza
/// legge le azioni della copia; tutte le altre uscite usano questa, e l'entità
/// dice quale.
pub const REFUSED_AUDIT_ACTION: &str = "uscita_rifiutata";

/// Che cosa fare se un nome definitivo esiste già.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Existing {
    /// Nessuna sostituzione: un'uscita non ne cancella un'altra (ADR-0043).
    Refuse,
    /// Sostituire: l'operatore ha scelto quel nome in una finestra che glielo
    /// ha chiesto (il dizionario esportato, il fascicolo).
    Replace,
}

/// Il solo utente, o l'errore che ferma l'uscita.
///
/// # Errori
///
/// [`ServiceError::ProtectionNotGuaranteed`] se i permessi non sono del solo
/// utente, con la ragione.
pub(crate) fn owner_or_refuse(access: Access, what: &'static str) -> ServiceResult<CurrentUser> {
    match access {
        Access::OwnerOnly(utente) => Ok(utente),
        Access::NotRestricted { reason } => {
            Err(ServiceError::ProtectionNotGuaranteed { what, reason })
        }
    }
}

/// Rilegge i permessi di un percorso, senza cambiarli.
///
/// # Errori
///
/// [`ServiceError::ProtectionNotGuaranteed`] se non sono del solo utente.
pub(crate) fn confirm(path: &Path, what: &'static str) -> ServiceResult<CurrentUser> {
    owner_or_refuse(verify_current_user_only(path), what)
}

/// Registra nell'audit un'uscita rifiutata per i permessi.
///
/// Dice il fatto, l'uscita e la ragione, mai un percorso. Se l'audit stesso
/// non si scrive, il rifiuto resta l'esito: tacerlo per dire un errore
/// dell'archivio farebbe credere a un guasto diverso da quello vero.
pub(crate) fn record_refusal(
    database: &Database,
    actor: &Actor,
    now: Timestamp,
    action: &str,
    entity: &str,
    error: &ServiceError,
) {
    let ServiceError::ProtectionNotGuaranteed { reason, .. } = error else {
        return;
    };
    let registrato = AuditAction::try_new(action)
        .and_then(|action| {
            Ok((
                action,
                AuditEntity::try_new(entity)?,
                AuditDetail::try_new(&format!("permessi del solo utente non garantiti: {reason}"))?,
            ))
        })
        .map_err(ServiceError::from)
        .and_then(|(action, entity, detail)| {
            database
                .append_audit(&NewAuditEntry {
                    actor: actor.clone(),
                    action,
                    entity,
                    entity_id: None,
                    actor_mode: None,
                    detail: Some(detail),
                    recorded_at: now,
                })
                .map_err(ServiceError::from)
        });
    if let Err(errore) = registrato {
        tracing::warn!(
            errore = errore.kind(),
            "rifiuto di un'uscita non registrato nell'audit"
        );
    }
}

/// Uno o più file che arrivano, del solo utente, in una cartella.
///
/// Si usa così: [`Self::begin`] nella cartella di destinazione; una
/// [`Self::write`] per ogni file — o, se il file lo scrive qualcun altro (come
/// `VACUUM INTO`), [`Self::staging_path`] e poi [`Self::adopt`]; infine
/// [`Self::deliver`]. **Se la consegna non arriva in fondo** — un errore, un
/// `?` del chiamante, un rifiuto — quando il valore si scarta si toglie ciò
/// che era stato scritto o era già arrivato, e la cartella di lavoro.
#[derive(Debug)]
pub struct Delivery {
    destination: PathBuf,
    work: Option<PrivateDirectory>,
    owner: CurrentUser,
    what: &'static str,
    staged: Vec<String>,
    extra: Vec<String>,
    arrived: Vec<PathBuf>,
}

/// Che cosa è arrivato.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Delivered {
    /// I file, nella cartella di destinazione, nell'ordine in cui sono
    /// arrivati.
    pub files: Vec<PathBuf>,
    /// L'utente Windows che solo può aprirli: permessi applicati e riletti.
    pub owner: CurrentUser,
}

impl Delivery {
    /// Prepara la cartella di lavoro privata nella cartella di destinazione.
    ///
    /// `work_name` dà il nome alla cartella di lavoro
    /// (`.<work_name>.parziale`): di solito la radice del nome dei file.
    /// `what` è la frase che dice che cosa non è stato scritto, se non lo
    /// sarà.
    ///
    /// # Errori
    ///
    /// [`ServiceError::ExportNotWritten`] se la destinazione non è una
    /// cartella o la cartella di lavoro non si crea (anche perché ne esiste
    /// già una con quel nome, o al suo posto c'è un collegamento);
    /// [`ServiceError::ProtectionNotGuaranteed`] se la cartella di lavoro non
    /// si restringe al solo utente: in quel caso è già stata tolta.
    pub fn begin(destination: &Path, work_name: &str, what: &'static str) -> ServiceResult<Self> {
        if !destination.is_dir() {
            return Err(ServiceError::ExportNotWritten {
                reason: format!("«{}» non è una cartella", destination.display()),
            });
        }
        let lavoro =
            PrivateDirectory::create(&destination.join(format!(".{work_name}.{WORK_EXTENSION}")))
                .map_err(|errore| ServiceError::ExportNotWritten {
                reason: format!("la cartella di lavoro non si è potuta preparare: {errore}"),
            })?;

        // LA PROTEZIONE PRIMA DEL PRIMO BYTE, O NIENTE.
        let owner = match lavoro.access() {
            Access::OwnerOnly(utente) => utente.clone(),
            Access::NotRestricted { reason } => {
                let reason = reason.clone();
                if let Err(resto) = lavoro.remove() {
                    tracing::warn!(%resto, "cartella di lavoro non tolta");
                }
                return Err(ServiceError::ProtectionNotGuaranteed { what, reason });
            }
        };

        Ok(Self {
            destination: destination.to_path_buf(),
            work: Some(lavoro),
            owner,
            what,
            staged: Vec::new(),
            extra: Vec::new(),
            arrived: Vec::new(),
        })
    }

    /// L'utente a cui la cartella di lavoro è stata ristretta.
    #[must_use]
    pub const fn owner(&self) -> &CurrentUser {
        &self.owner
    }

    /// Dove scrivere, nella cartella di lavoro, un file che poi si
    /// [`adotta`](Self::adopt).
    #[must_use]
    pub fn staging_path(&self, name: &str) -> PathBuf {
        self.work.as_ref().map_or_else(
            || self.destination.join(name),
            |lavoro| lavoro.path().join(name),
        )
    }

    /// Un nome che qualcun altro può aver lasciato nella cartella di lavoro
    /// (il giornale di `SQLite` di una copia riletta): si toglie con il
    /// resto, se la consegna non arriva in fondo.
    pub fn clean_also(&mut self, name: &str) {
        self.extra.push(name.to_owned());
    }

    /// Prende in carico un file scritto da qualcun altro nella cartella di
    /// lavoro: gli dà un DACL esplicito e protetto del solo utente, e lo
    /// rilegge.
    ///
    /// # Perché un DACL esplicito, oltre a quello ereditato
    ///
    /// Il rinomino porta le voci ereditate così come sono, ma la prima
    /// propagazione dei permessi della cartella di destinazione le
    /// riscriverebbe. Una voce esplicita in un DACL protetto non si riscrive.
    ///
    /// # Errori
    ///
    /// [`ServiceError::ProtectionNotGuaranteed`] se i permessi non reggono.
    pub fn adopt(&mut self, name: &str) -> ServiceResult<()> {
        self.staged.push(name.to_owned());
        owner_or_refuse(
            restrict_to_current_user(&self.staging_path(name)),
            self.what,
        )
        .map(|_| ())
    }

    /// Scrive un file nella cartella di lavoro e lo prende in carico.
    ///
    /// # Errori
    ///
    /// [`ServiceError::ExportNotWritten`] se il file non si scrive;
    /// [`ServiceError::ProtectionNotGuaranteed`] se i permessi non reggono.
    pub fn write(&mut self, name: &str, bytes: &[u8]) -> ServiceResult<()> {
        let percorso = self.staging_path(name);
        // Nella cartella di lavoro nessun altro crea file; `create_new` resta,
        // perché non costa nulla e un file non deve finire dentro uno altrui.
        let scritto = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&percorso)
            .and_then(|mut file| std::io::Write::write_all(&mut file, bytes));
        if let Err(errore) = scritto {
            // Un file creato a meta' si toglie con il resto.
            self.extra.push(name.to_owned());
            return Err(ServiceError::ExportNotWritten {
                reason: format!("«{name}» non è stato scritto: {}", errore.kind()),
            });
        }
        self.adopt(name)
    }

    /// Porta i file nella cartella di destinazione, nell'ordine in cui sono
    /// stati scritti, e li rilegge dove l'operatore li troverà.
    ///
    /// # Errori
    ///
    /// [`ServiceError::ExportNotWritten`] se un nome definitivo esiste già e
    /// `existing` è [`Existing::Refuse`], o se un rinomino non riesce;
    /// [`ServiceError::ProtectionNotGuaranteed`] se la rilettura dopo
    /// l'arrivo non regge. In ogni caso ciò che era arrivato si toglie.
    pub fn deliver(mut self, existing: Existing) -> ServiceResult<Delivered> {
        if existing == Existing::Refuse {
            for nome in &self.staged {
                let definitivo = self.destination.join(nome);
                if definitivo.exists() {
                    return Err(ServiceError::ExportNotWritten {
                        reason: format!(
                            "«{}» esiste già: un'uscita non ne sostituisce un'altra",
                            definitivo.display()
                        ),
                    });
                }
            }
        }

        let nomi = self.staged.clone();
        for nome in &nomi {
            let da = self.staging_path(nome);
            let a = self.destination.join(nome);
            std::fs::rename(&da, &a).map_err(|errore| ServiceError::ExportNotWritten {
                reason: format!(
                    "«{nome}»: il passaggio nella cartella scelta non è riuscito ({})",
                    errore.kind()
                ),
            })?;
            self.arrived.push(a);
        }

        // IL RINOMINO PORTA I PERMESSI, E LO SI VERIFICA invece di presumerlo.
        let arrivati = self.arrived.clone();
        for arrivato in &arrivati {
            confirm(arrivato, self.what)?;
        }

        // Arrivati e verificati: da qui in poi nulla si toglie.
        if let Some(lavoro) = self.work.take()
            && let Err(resto) = lavoro.remove()
        {
            // I file sono gia' arrivati: la cartella vuota che resta non
            // toglie nulla a cio' che l'operatore ha in mano.
            tracing::warn!(%resto, "cartella di lavoro non tolta");
        }
        Ok(Delivered {
            files: std::mem::take(&mut self.arrived),
            owner: self.owner.clone(),
        })
    }
}

impl Drop for Delivery {
    /// Una consegna non arrivata in fondo non lascia nulla.
    ///
    /// Si toglie per nome, non per elenco: soltanto ciò che questa consegna ha
    /// scritto o portato.
    fn drop(&mut self) {
        let Some(lavoro) = self.work.take() else {
            return;
        };
        for arrivato in &self.arrived {
            let _ = std::fs::remove_file(arrivato);
        }
        for nome in self.staged.iter().chain(self.extra.iter()) {
            let _ = std::fs::remove_file(lavoro.path().join(nome));
        }
        if let Err(resto) = lavoro.remove() {
            tracing::warn!(%resto, "cartella di lavoro non tolta dopo un'uscita non riuscita");
        }
    }
}

/// Una cartella nuova che è essa stessa l'uscita: un pacchetto.
///
/// Ristretta al solo utente appena creata, prima del primo file, che ne
/// eredita i permessi; tenuta aperta senza condividere l'eliminazione finché
/// serve; riletta prima di dichiararla completa.
#[derive(Debug)]
pub struct ProtectedFolder {
    directory: PrivateDirectory,
    owner: CurrentUser,
    what: &'static str,
}

impl ProtectedFolder {
    /// Crea la cartella e la restringe.
    ///
    /// `on_io` traduce un errore di creazione — per esempio una cartella che
    /// esiste già — nell'errore che il chiamante vuole dire.
    ///
    /// # Errori
    ///
    /// L'errore di `on_io` se la cartella non si crea;
    /// [`ServiceError::ProtectionNotGuaranteed`] se non si restringe: in quel
    /// caso, ancora vuota, è già stata tolta.
    pub fn create(
        path: &Path,
        what: &'static str,
        on_io: impl FnOnce(std::io::Error) -> ServiceError,
    ) -> ServiceResult<Self> {
        let directory = PrivateDirectory::create(path).map_err(on_io)?;
        let owner = match directory.access() {
            Access::OwnerOnly(utente) => utente.clone(),
            Access::NotRestricted { reason } => {
                let reason = reason.clone();
                if let Err(resto) = directory.remove() {
                    tracing::warn!(%resto, "cartella non tolta dopo il rifiuto");
                }
                return Err(ServiceError::ProtectionNotGuaranteed { what, reason });
            }
        };
        Ok(Self {
            directory,
            owner,
            what,
        })
    }

    /// Il percorso della cartella.
    #[must_use]
    pub fn path(&self) -> &Path {
        self.directory.path()
    }

    /// L'utente a cui la cartella è stata ristretta.
    #[must_use]
    pub const fn owner(&self) -> &CurrentUser {
        &self.owner
    }

    /// Rilegge i permessi della cartella prima di dichiararla completa.
    ///
    /// # Errori
    ///
    /// [`ServiceError::ProtectionNotGuaranteed`] se non sono più del solo
    /// utente. Togliere i file è compito di chi li ha scritti.
    pub fn seal(&self) -> ServiceResult<()> {
        confirm(self.directory.path(), self.what).map(|_| ())
    }

    /// Smette di tenerla aperta, e la lascia dov'è.
    pub fn release(self) {
        self.directory.release();
    }

    /// Smette di tenerla aperta e la toglie, **se è vuota**.
    ///
    /// # Errori
    ///
    /// Un errore se la cartella non è vuota o non si toglie.
    pub fn remove(self) -> std::io::Result<()> {
        self.directory.remove()
    }
}

#[cfg(test)]
mod tests {
    use super::{Delivery, Existing, ProtectedFolder};
    use crate::error::ServiceError;

    fn nomi_in(cartella: &std::path::Path) -> Vec<String> {
        let Ok(voci) = std::fs::read_dir(cartella) else {
            panic!("la cartella deve potersi elencare");
        };
        let mut nomi: Vec<String> = voci
            .filter_map(Result::ok)
            .map(|voce| voce.file_name().to_string_lossy().into_owned())
            .collect();
        nomi.sort();
        nomi
    }

    /// Una cartella che toglie all'utente il diritto di cambiare i permessi
    /// di ciò che vi crea (voce `OWNER RIGHTS`, S-1-3-4): il rifiuto di una
    /// chiavetta FAT32, ottenuto su NTFS, con la premessa controllata.
    #[cfg(windows)]
    fn cartella_che_rifiuta_i_permessi() -> tempfile::TempDir {
        crate::permessi_di_prova::cartella_che_rifiuta_i_permessi()
    }

    /// **Una consegna arriva del solo utente, anche in una cartella aperta, e
    /// non lascia altro.**
    #[cfg(windows)]
    #[test]
    fn una_consegna_arriva_del_solo_utente_e_non_lascia_altro() {
        use crate::permessi_di_prova::{afferma_del_solo_utente, apri_come_nel_collaudo};

        let Ok(cartella) = tempfile::tempdir() else {
            panic!("la cartella temporanea deve potersi creare");
        };
        apri_come_nel_collaudo(cartella.path());

        let Ok(mut consegna) =
            Delivery::begin(cartella.path(), "prova", "La prova NON è stata scritta")
        else {
            panic!("la consegna deve potersi cominciare");
        };
        assert!(consegna.write("prova.txt", b"rapporto").is_ok());
        assert!(consegna.write("prova.manifest.txt", b"manifest").is_ok());
        let Ok(arrivati) = consegna.deliver(Existing::Refuse) else {
            panic!("la consegna deve arrivare");
        };
        assert_eq!(arrivati.files.len(), 2);
        for file in &arrivati.files {
            afferma_del_solo_utente(file);
        }
        assert_eq!(
            nomi_in(cartella.path()),
            vec![
                String::from("prova.manifest.txt"),
                String::from("prova.txt")
            ],
            "nella cartella e' rimasto altro"
        );
    }

    /// **Una destinazione che rifiuta i permessi: nessun file, nessuna
    /// cartella di lavoro.**
    #[cfg(windows)]
    #[test]
    fn una_destinazione_che_rifiuta_i_permessi_non_riceve_nulla() {
        let cartella = cartella_che_rifiuta_i_permessi();
        let esito = Delivery::begin(cartella.path(), "prova", "La prova NON è stata scritta");
        assert!(
            matches!(esito, Err(ServiceError::ProtectionNotGuaranteed { .. })),
            "una consegna e' cominciata in una cartella che rifiuta i permessi: {esito:?}"
        );
        assert!(
            nomi_in(cartella.path()).is_empty(),
            "il rifiuto ha lasciato qualcosa"
        );
    }

    /// **Una consegna interrotta — scartata prima di arrivare, come dopo un
    /// errore del chiamante — non lascia nulla.**
    #[cfg(windows)]
    #[test]
    fn una_consegna_interrotta_non_lascia_nulla() {
        let Ok(cartella) = tempfile::tempdir() else {
            panic!("la cartella temporanea deve potersi creare");
        };
        {
            let Ok(mut consegna) =
                Delivery::begin(cartella.path(), "prova", "La prova NON è stata scritta")
            else {
                panic!("la consegna deve potersi cominciare");
            };
            assert!(consegna.write("prova.txt", b"rapporto").is_ok());
            consegna.clean_also("prova.txt-wal");
            if std::fs::write(consegna.staging_path("prova.txt-wal"), b"giornale").is_err() {
                panic!("il giornale di prova deve potersi scrivere");
            }
        }
        assert!(
            nomi_in(cartella.path()).is_empty(),
            "l'interruzione ha lasciato qualcosa"
        );
    }

    /// **Un nome che esiste già non si sostituisce, salvo che l'operatore lo
    /// abbia scelto; e il rifiuto non lascia nulla.**
    #[cfg(windows)]
    #[test]
    fn un_nome_esistente_si_sostituisce_solo_se_scelto() {
        let Ok(cartella) = tempfile::tempdir() else {
            panic!("la cartella temporanea deve potersi creare");
        };
        let altrui = cartella.path().join("prova.txt");
        if std::fs::write(&altrui, b"di prima").is_err() {
            panic!("il file di prima deve potersi scrivere");
        }

        let Ok(mut consegna) =
            Delivery::begin(cartella.path(), "prova", "La prova NON è stata scritta")
        else {
            panic!("la consegna deve potersi cominciare");
        };
        assert!(consegna.write("prova.txt", b"nuovo").is_ok());
        assert!(consegna.deliver(Existing::Refuse).is_err());
        assert_eq!(std::fs::read(&altrui).ok(), Some(b"di prima".to_vec()));
        assert_eq!(nomi_in(cartella.path()), vec![String::from("prova.txt")]);

        let Ok(mut consegna) =
            Delivery::begin(cartella.path(), "prova", "La prova NON è stata scritta")
        else {
            panic!("la consegna deve potersi cominciare");
        };
        assert!(consegna.write("prova.txt", b"nuovo").is_ok());
        assert!(consegna.deliver(Existing::Replace).is_ok());
        assert_eq!(std::fs::read(&altrui).ok(), Some(b"nuovo".to_vec()));
    }

    /// **Una cartella protetta che non si può restringere non resta.**
    #[cfg(windows)]
    #[test]
    fn una_cartella_protetta_che_non_si_restringe_non_resta() {
        let cartella = cartella_che_rifiuta_i_permessi();
        let esito = ProtectedFolder::create(
            &cartella.path().join("pacchetto"),
            "Il pacchetto NON è stato scritto",
            |errore| ServiceError::ExportNotWritten {
                reason: errore.to_string(),
            },
        );
        assert!(matches!(
            esito,
            Err(ServiceError::ProtectionNotGuaranteed { .. })
        ));
        assert!(
            nomi_in(cartella.path()).is_empty(),
            "la cartella del pacchetto e' rimasta"
        );
    }

    /// **Una cartella protetta si rilegge e dice di chi è.**
    #[cfg(windows)]
    #[test]
    fn una_cartella_protetta_si_rilegge() {
        let Ok(cartella) = tempfile::tempdir() else {
            panic!("la cartella temporanea deve potersi creare");
        };
        let Ok(pacchetto) = ProtectedFolder::create(
            &cartella.path().join("pacchetto"),
            "Il pacchetto NON è stato scritto",
            |errore| ServiceError::ExportNotWritten {
                reason: errore.to_string(),
            },
        ) else {
            panic!("la cartella protetta deve potersi creare");
        };
        assert!(pacchetto.seal().is_ok());
        assert!(pacchetto.owner().sid.starts_with("S-1-5-"));
        pacchetto.release();
    }
}
