//! Rendere un file o una cartella accessibile al **solo utente corrente**, e
//! dimostrarlo rileggendo (SEC-01, ADR-0157).
//!
//! # Perché esiste
//!
//! L'archivio vivo sta in una cartella del solo utente. La copia di sicurezza e
//! i pacchetti di relazione escono in una cartella scelta dall'operatore, e ne
//! ereditavano i permessi: nel collaudo con il profilo reale la copia —
//! l'archivio intero, non cifrato — era leggibile da `BUILTIN\Users` e
//! modificabile da `Authenticated Users` (BAK-03).
//!
//! # Come
//!
//! Con le API di Windows (ADR-0206, che modifica il «come» di ADR-0157):
//!
//! - l'utente è quello del **token del processo**, indicato dal suo SID: un
//!   nome non qualificato, su una postazione in dominio, si risolve prima fra
//!   gli account locali e può indicare un'altra persona;
//! - il DACL si scrive con `SetNamedSecurityInfoW`, **protetto**, con la sola
//!   voce dell'utente;
//! - l'esito **non si presume**: il DACL si rilegge con
//!   `GetNamedSecurityInfoW` e si esamina in forma binaria, voce per voce, con
//!   i SID confrontati da `EqualSid` (`check_entries`). Niente SDDL, niente
//!   nomi brevi come `LA` o `SY`, niente lingua di Windows;
//! - un fallimento **non si tace**: diventa [`Access::NotRestricted`] con la
//!   ragione, e chi chiama lo dice all'operatore. Dal 2026-10-22 la copia di
//!   sicurezza e il pacchetto di relazione, davanti a un fallimento, **non si
//!   scrivono** (ADR-0157, integrazione): una copia leggibile da altri non
//!   resta sul disco.
//!
//! Fino al 2026-11-18 lo strumento era `icacls`, con `whoami` per il SID. Sul
//! runner di GitHub `icacls /inheritance:r` ha lasciato voci di SYSTEM e
//! Administrators: il controllo ha rifiutato, e aveva ragione (CI-FIX-01).
//!
//! # Solo l'utente
//!
//! Niente `SYSTEM` e niente `Administrators`, come la cartella dei dati. Un
//! amministratore può comunque prendere possesso di un file: è un limite di
//! Windows, dichiarato nell'ADR.

use std::path::{Path, PathBuf};

/// L'utente Windows per conto del quale gira il programma.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CurrentUser {
    /// Nome leggibile, `DOMINIO\nome`: serve alle frasi, non ai permessi.
    pub name: String,
    /// Identificativo di sicurezza: è ciò che i permessi nominano.
    pub sid: String,
}

/// Chi può aprire un file che il programma ha scritto.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Access {
    /// Il solo utente indicato: permessi applicati **e riletti**.
    OwnerOnly(CurrentUser),
    /// Permessi non ristretti, o non verificati, e perché.
    ///
    /// La ragione è una frase per l'operatore, senza percorsi.
    NotRestricted {
        /// Perché.
        reason: String,
    },
}

impl Access {
    /// Se i permessi sono del solo utente, verificati.
    #[must_use]
    pub const fn is_owner_only(&self) -> bool {
        matches!(self, Self::OwnerOnly(_))
    }

    /// L'esito di due file insieme: ristretto solo se lo sono entrambi.
    ///
    /// Se uno dei due non lo è, vale la sua ragione: dire «ristretti» di una
    /// coppia in cui un file non lo è sarebbe dire il falso di quel file.
    #[must_use]
    pub fn and(self, other: Self) -> Self {
        match (&self, &other) {
            (Self::OwnerOnly(_), Self::NotRestricted { .. }) => other,
            _ => self,
        }
    }
}

/// Ragione detta quando Windows rifiuta i permessi.
///
/// Le cause tipiche si nominano perché sono ciò che l'operatore può
/// riconoscere: una chiavetta o un disco esterno formattati FAT32 o exFAT, che
/// i permessi non li conservano, e una cartella di rete. A schermo si dicono
/// senza il nome del formato.
///
/// Le ragioni sono frasi intere, senza il punto finale: chi le mostra le mette
/// in una frase sua.
const REFUSED: &str = "Windows non ha accettato i nuovi permessi, come succede con alcune \
                       chiavette, alcuni dischi esterni e alcune cartelle di rete";

/// L'utente corrente, letto una volta per esecuzione.
///
/// # Errori
///
/// Restituisce la ragione, in una frase, se l'utente non si può determinare.
pub fn current_user() -> Result<CurrentUser, String> {
    imp::current_user()
}

/// Rende il file o la cartella del solo utente corrente, e lo verifica.
///
/// Su una cartella il permesso è **ereditabile** da file e sottocartelle: ciò
/// che vi nasce dopo è del solo utente fin dal primo byte. Su un file è
/// esplicito. In entrambi i casi il DACL diventa **protetto**: non eredita più
/// dalla cartella che lo contiene, e una propagazione dei permessi di quella
/// cartella non lo riscrive.
///
/// Non restituisce un errore: restituisce l'esito, e chi chiama decide che
/// cosa farne. La copia di sicurezza e il pacchetto di relazione, davanti a
/// [`Access::NotRestricted`], **non si scrivono** e non lasciano nulla sul
/// disco (ADR-0157, integrazione del 2026-10-22).
#[must_use]
pub fn restrict_to_current_user(path: &Path) -> Access {
    imp::restrict(path)
}

/// Rilegge i permessi di un file o di una cartella **senza cambiarli**, e dice
/// se sono del solo utente corrente.
///
/// Serve dopo un rinomino: i permessi applicati nella cartella di lavoro
/// viaggiano con il file sullo stesso volume, e questa rilettura lo verifica
/// invece di presumerlo. Lo stesso controllo di `check_entries`: una cartella
/// deve concedere il controllo completo in modo ereditabile.
#[must_use]
pub fn verify_current_user_only(path: &Path) -> Access {
    imp::verify(path)
}

/// Una cartella **nuova**, del solo utente, tenuta aperta finché serve.
///
/// # Perché aperta
///
/// Il programma la tiene aperta **senza condividere il permesso di
/// eliminazione**: finché esiste questo valore nessuno può rinominarla,
/// cancellarla o sostituirla con un'altra. Se qualcuno ne tenesse già un
/// handle con quel permesso — aperto nell'istante fra la creazione e
/// l'apertura — l'apertura fallisce e la cartella non si usa.
///
/// # Che cosa controlla prima di restringerla
///
/// Che sia una cartella vera, non un collegamento, e che sia vuota: chi ci
/// avesse depositato qualcosa nell'istante prima della restrizione lo avrebbe
/// fatto con i permessi della cartella scelta.
#[derive(Debug)]
pub struct PrivateDirectory {
    path: PathBuf,
    access: Access,
    guard: Option<std::fs::File>,
}

impl PrivateDirectory {
    /// Crea la cartella, la apre, la controlla e la restringe.
    ///
    /// # Errori
    ///
    /// Un errore se la cartella esiste già — non si riusa una cartella che non
    /// abbiamo creato noi — se non si crea, se non si apre in esclusiva per
    /// l'eliminazione, se non è una cartella vera o se non è vuota. Una
    /// restrizione **non riuscita** non è un errore: è [`Self::access`].
    pub fn create(path: &Path) -> std::io::Result<Self> {
        std::fs::create_dir(path)?;
        let guard = match imp::hold_directory(path) {
            Ok(guard) => guard,
            Err(error) => {
                // La cartella e' nostra solo se l'abbiamo potuta tenere: se no
                // si prova a toglierla, ed e' tutto quello che si puo' fare.
                let _ = std::fs::remove_dir(path);
                return Err(error);
            }
        };
        let access = restrict_to_current_user(path);
        Ok(Self {
            path: path.to_path_buf(),
            access,
            guard,
        })
    }

    /// Il percorso della cartella.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Chi può aprire ciò che vi nasce.
    #[must_use]
    pub const fn access(&self) -> &Access {
        &self.access
    }

    /// Smette di tenerla aperta, e la lascia dov'è.
    pub fn release(mut self) {
        self.guard = None;
    }

    /// Smette di tenerla aperta e la toglie, **se è vuota**.
    ///
    /// # Errori
    ///
    /// Un errore se la cartella non è vuota o non si toglie. Non è ricorsiva,
    /// ed è voluto: se dentro è rimasto qualcosa, la cartella resta, e resta a
    /// ragione.
    pub fn remove(mut self) -> std::io::Result<()> {
        self.guard = None;
        std::fs::remove_dir(&self.path)
    }
}

/// Chi è il titolare di una voce, confrontato da Windows con `EqualSid`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Holder {
    /// L'utente del processo.
    CurrentUser,
    /// Chiunque altro: un'altra persona, un gruppo, un account di sistema.
    Other,
}

/// Il tipo di una voce del DACL.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum AceKind {
    /// `ACCESS_ALLOWED_ACE_TYPE`: concede.
    Allow,
    /// `ACCESS_DENIED_ACE_TYPE`: nega.
    Deny,
    /// Qualunque altro tipo (a oggetto, condizionale, di controllo…).
    Other(u8),
}

/// Una voce del DACL, come Windows la restituisce.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Entry {
    pub(crate) kind: AceKind,
    pub(crate) holder: Holder,
    pub(crate) mask: u32,
    pub(crate) flags: u8,
}

/// Il DACL di un oggetto, riletto da Windows.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct DaclView {
    /// Falso per un DACL nullo, che non limita nessuno.
    pub(crate) present: bool,
    /// `SE_DACL_PROTECTED`: il DACL non eredita dalla cartella.
    pub(crate) protected: bool,
    pub(crate) entries: Vec<Entry>,
}

/// `OBJECT_INHERIT_ACE`, `CONTAINER_INHERIT_ACE`, `INHERIT_ONLY_ACE`,
/// `INHERITED_ACE` di `winnt.h`: i contrassegni stanno in un byte.
const OBJECT_INHERIT: u8 = 0x01;
const CONTAINER_INHERIT: u8 = 0x02;
const INHERIT_ONLY: u8 = 0x08;
const INHERITED: u8 = 0x10;
/// `FILE_ALL_ACCESS` e `GENERIC_ALL`: il controllo completo.
const FILE_ALL_ACCESS: u32 = 0x001F_01FF;
const GENERIC_ALL: u32 = 0x1000_0000;

/// Accetta un DACL riletto solo se è del solo utente corrente.
///
/// Si accetta **soltanto** ciò che si riconosce:
///
/// - il DACL esiste (non è nullo) ed è protetto;
/// - nessuna voce è ereditata;
/// - ogni voce che concede è dell'utente; le voci che negano non concedono
///   nulla e passano;
/// - ogni altro tipo di voce vale «non verificato»;
/// - l'utente ha il controllo completo che vale per l'oggetto stesso e, se è
///   una cartella, si eredita da file e sottocartelle.
///
/// Le ragioni non nominano il titolare di una voce: non si porta nel registro
/// il SID di un altro account della postazione.
///
/// # Errori
///
/// La ragione, in una frase, se il DACL non è del solo utente.
pub(crate) fn check_entries(vista: &DaclView, directory: bool) -> Result<(), String> {
    if !vista.present {
        return Err(String::from(
            "non c'è alcun limite agli accessi: chiunque può aprire il file",
        ));
    }
    if !vista.protected {
        return Err(String::from(
            "i permessi ereditano ancora da quelli della cartella",
        ));
    }
    let mut controllo_completo = false;
    for voce in &vista.entries {
        if voce.flags & INHERITED != 0 {
            return Err(String::from(
                "una voce dei permessi è ereditata dalla cartella",
            ));
        }
        match voce.kind {
            AceKind::Allow => {}
            AceKind::Deny => continue,
            AceKind::Other(tipo) => {
                return Err(format!(
                    "una voce dei permessi è di un tipo che il controllo non riconosce ({tipo})"
                ));
            }
        }
        if voce.holder != Holder::CurrentUser {
            return Err(String::from(
                "i permessi concedono l'accesso anche a un altro utente o gruppo",
            ));
        }
        let completo =
            voce.mask & FILE_ALL_ACCESS == FILE_ALL_ACCESS || voce.mask & GENERIC_ALL != 0;
        let vale_qui = voce.flags & INHERIT_ONLY == 0;
        let si_eredita =
            !directory || (voce.flags & OBJECT_INHERIT != 0 && voce.flags & CONTAINER_INHERIT != 0);
        if completo && vale_qui && si_eredita {
            controllo_completo = true;
        }
    }
    if !controllo_completo {
        return Err(String::from(
            "l'utente non ha il controllo completo del file",
        ));
    }
    Ok(())
}

#[cfg(windows)]
mod imp {
    use std::os::windows::fs::{MetadataExt, OpenOptionsExt};
    use std::path::Path;
    use std::sync::OnceLock;

    use super::{Access, CurrentUser, REFUSED, check_entries};
    use crate::acl::{Sid, apply_owner_only, current_user_sid, read_dacl};

    /// Necessario per aprire una cartella.
    const FILE_FLAG_BACKUP_SEMANTICS: u32 = 0x0200_0000;
    /// Apre il collegamento, se lo è, invece di ciò a cui punta.
    const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
    const FILE_SHARE_READ: u32 = 0x0000_0001;
    const FILE_SHARE_WRITE: u32 = 0x0000_0002;
    const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0000_0400;

    static UTENTE: OnceLock<(CurrentUser, Sid)> = OnceLock::new();

    fn non_determinabile() -> String {
        String::from("L'utente Windows corrente non si è potuto determinare")
    }

    /// L'utente del token del processo: il SID per i permessi, il nome per le
    /// frasi. Letto una volta per esecuzione.
    fn utente() -> Result<(CurrentUser, Sid), String> {
        if let Some(utente) = UTENTE.get() {
            return Ok(utente.clone());
        }
        let sid = current_user_sid().ok_or_else(non_determinabile)?;
        let testo = sid.to_text().ok_or_else(non_determinabile)?;
        // Il nome serve solo alle frasi: quello delle variabili d'ambiente è in
        // Unicode. Se manca, la frase dice il SID.
        let name = match (std::env::var("USERDOMAIN"), std::env::var("USERNAME")) {
            (Ok(dominio), Ok(nome)) if !dominio.is_empty() && !nome.is_empty() => {
                format!("{dominio}\\{nome}")
            }
            _ => testo.clone(),
        };
        let coppia = (CurrentUser { name, sid: testo }, sid);
        let _ = UTENTE.set(coppia.clone());
        Ok(coppia)
    }

    pub(super) fn current_user() -> Result<CurrentUser, String> {
        utente().map(|(utente, _)| utente)
    }

    pub(super) fn restrict(path: &Path) -> Access {
        let (_, sid) = match utente() {
            Ok(coppia) => coppia,
            Err(reason) => return Access::NotRestricted { reason },
        };
        if apply_owner_only(path, &sid, path.is_dir()).is_err() {
            return Access::NotRestricted {
                reason: String::from(REFUSED),
            };
        }
        // IL SUCCESSO DI WINDOWS NON E' LA PROVA. Lo e' cio' che si rilegge.
        verify(path)
    }

    pub(super) fn verify(path: &Path) -> Access {
        let (utente, sid) = match utente() {
            Ok(coppia) => coppia,
            Err(reason) => return Access::NotRestricted { reason },
        };
        let Some(vista) = read_dacl(path, &sid) else {
            return Access::NotRestricted {
                reason: String::from("I permessi applicati non si sono potuti rileggere"),
            };
        };
        match check_entries(&vista, path.is_dir()) {
            Ok(()) => Access::OwnerOnly(utente),
            Err(dettaglio) => Access::NotRestricted {
                reason: format!("I permessi riletti non sono quelli attesi: {dettaglio}"),
            },
        }
    }

    pub(super) fn hold_directory(path: &Path) -> std::io::Result<Option<std::fs::File>> {
        // Lettura e scrittura si condividono, l'eliminazione no: finche'
        // questo handle e' aperto, nessuno rinomina ne' cancella la cartella.
        let guard = std::fs::OpenOptions::new()
            .read(true)
            .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
            .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
            .open(path)?;

        let dati = guard.metadata()?;
        if !dati.is_dir() || dati.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            return Err(std::io::Error::other(
                "al posto della cartella appena creata c'è un collegamento",
            ));
        }
        if std::fs::read_dir(path)?.next().is_some() {
            return Err(std::io::Error::other(
                "la cartella appena creata non è vuota",
            ));
        }
        Ok(Some(guard))
    }
}

#[cfg(not(windows))]
mod imp {
    use std::path::Path;

    use super::{Access, CurrentUser};

    const ONLY_WINDOWS: &str = "I permessi di Windows non esistono su questo sistema";

    pub(super) fn current_user() -> Result<CurrentUser, String> {
        Err(String::from(ONLY_WINDOWS))
    }

    pub(super) fn restrict(_path: &Path) -> Access {
        Access::NotRestricted {
            reason: String::from(ONLY_WINDOWS),
        }
    }

    pub(super) fn verify(_path: &Path) -> Access {
        Access::NotRestricted {
            reason: String::from(ONLY_WINDOWS),
        }
    }

    pub(super) fn hold_directory(_path: &Path) -> std::io::Result<Option<std::fs::File>> {
        Ok(None)
    }
}

#[cfg(test)]
mod tests {
    use super::{Access, AceKind, CurrentUser, DaclView, Entry, Holder, check_entries};

    const PIENO: u32 = 0x001F_01FF;
    const LETTURA: u32 = 0x0012_00A9;
    const OI: u8 = 0x01;
    const CI: u8 = 0x02;
    const IO: u8 = 0x08;
    const ID: u8 = 0x10;

    fn voce(kind: AceKind, holder: Holder, mask: u32, flags: u8) -> Entry {
        Entry {
            kind,
            holder,
            mask,
            flags,
        }
    }

    fn protetto(entries: Vec<Entry>) -> DaclView {
        DaclView {
            present: true,
            protected: true,
            entries,
        }
    }

    fn mio(mask: u32, flags: u8) -> Entry {
        voce(AceKind::Allow, Holder::CurrentUser, mask, flags)
    }

    /// **Ciò che la restrizione scrive è accettato**, per un file e per una
    /// cartella.
    #[test]
    fn i_permessi_del_solo_utente_sono_accettati() {
        assert_eq!(check_entries(&protetto(vec![mio(PIENO, 0)]), false), Ok(()));
        assert_eq!(
            check_entries(&protetto(vec![mio(PIENO, OI | CI)]), true),
            Ok(())
        );
        // GENERIC_ALL vale controllo completo come FILE_ALL_ACCESS.
        assert_eq!(
            check_entries(&protetto(vec![mio(0x1000_0000, 0)]), false),
            Ok(())
        );
    }

    /// **I permessi ereditati sono rifiutati**: è la forma della copia nel
    /// collaudo (BAK-03), e quella lasciata da `icacls` sul runner.
    #[test]
    fn i_permessi_ereditati_sono_rifiutati() {
        let collaudo = DaclView {
            present: true,
            protected: false,
            entries: vec![
                voce(AceKind::Allow, Holder::Other, LETTURA, ID),
                voce(AceKind::Allow, Holder::Other, PIENO, ID),
                mio(PIENO, ID),
            ],
        };
        assert!(check_entries(&collaudo, false).is_err());
        // Protetto ma con una voce ancora segnata come ereditata.
        assert!(check_entries(&protetto(vec![mio(PIENO, ID)]), false).is_err());
    }

    /// **Una concessione a chiunque altro è rifiutata**, anche se l'utente ha
    /// la sua, e la ragione non nomina il titolare. È la forma lasciata da
    /// `icacls` sul runner: SYSTEM, Administrators e l'utente, esplicite.
    #[test]
    fn una_concessione_ad_altri_e_rifiutata() {
        for altro in [LETTURA, PIENO] {
            let vista = protetto(vec![
                voce(AceKind::Allow, Holder::Other, altro, 0),
                voce(AceKind::Allow, Holder::Other, PIENO, 0),
                mio(PIENO, 0),
            ]);
            let Err(ragione) = check_entries(&vista, false) else {
                panic!("una concessione ad altri e' stata accettata");
            };
            assert!(ragione.contains("un altro utente o gruppo"), "{ragione}");
        }
        // Anche dopo quella dell'utente.
        let vista = protetto(vec![
            mio(PIENO, 0),
            voce(AceKind::Allow, Holder::Other, LETTURA, 0),
        ]);
        assert!(check_entries(&vista, false).is_err());
    }

    /// **Un DACL nullo, non protetto o vuoto è rifiutato, e un tipo di voce
    /// che il controllo non conosce vale «non verificato»** — anche se è
    /// dell'utente.
    #[test]
    fn le_forme_non_riconosciute_sono_rifiutate() {
        let nullo = DaclView {
            present: false,
            protected: true,
            entries: Vec::new(),
        };
        let non_protetto = DaclView {
            present: true,
            protected: false,
            entries: vec![mio(PIENO, 0)],
        };
        let vuoto = protetto(Vec::new());
        // Una voce a oggetto (5) o condizionale (9) dell'utente.
        let a_oggetto = protetto(vec![
            mio(PIENO, 0),
            voce(AceKind::Other(5), Holder::CurrentUser, PIENO, 0),
        ]);
        let condizionale = protetto(vec![
            voce(AceKind::Other(9), Holder::Other, 0, 0),
            mio(PIENO, 0),
        ]);
        for vista in [nullo, non_protetto, vuoto, a_oggetto, condizionale] {
            assert!(
                check_entries(&vista, false).is_err(),
                "accettato: {vista:?}"
            );
        }
    }

    /// **L'utente deve avere il controllo completo**, che valga per l'oggetto
    /// e, su una cartella, si erediti.
    #[test]
    fn l_utente_deve_avere_il_controllo_completo() {
        assert!(check_entries(&protetto(vec![mio(LETTURA, 0)]), false).is_err());
        assert!(check_entries(&protetto(vec![mio(PIENO, OI | CI | IO)]), false).is_err());
        assert!(check_entries(&protetto(vec![mio(PIENO, 0)]), true).is_err());
        assert!(check_entries(&protetto(vec![mio(PIENO, OI)]), true).is_err());
    }

    /// **Una voce che nega non concede nulla**, a chiunque sia.
    #[test]
    fn una_voce_che_nega_ad_altri_e_ammessa() {
        let vista = protetto(vec![
            voce(AceKind::Deny, Holder::Other, PIENO, 0),
            mio(PIENO, 0),
        ]);
        assert_eq!(check_entries(&vista, false), Ok(()));
        // Ma una voce che nega non sostituisce il controllo completo.
        let solo_nega = protetto(vec![voce(AceKind::Deny, Holder::Other, PIENO, 0)]);
        assert!(check_entries(&solo_nega, false).is_err());
    }

    #[test]
    fn due_esiti_insieme_valgono_quanto_il_peggiore() {
        let ristretto = Access::OwnerOnly(CurrentUser {
            name: String::from("D\\u"),
            sid: String::from("S-1-5-21-1-2-3-1001"),
        });
        let aperto = Access::NotRestricted {
            reason: String::from("perche'"),
        };
        assert!(ristretto.clone().and(ristretto.clone()).is_owner_only());
        assert_eq!(ristretto.clone().and(aperto.clone()), aperto);
        assert_eq!(aperto.clone().and(ristretto), aperto);
    }

    #[cfg(windows)]
    mod su_windows {
        use super::super::{PrivateDirectory, current_user, restrict_to_current_user};

        /// **Un file e una cartella si restringono, e la rilettura lo
        /// conferma.**
        #[test]
        fn un_file_e_una_cartella_si_restringono() {
            let Ok(cartella) = tempfile::tempdir() else {
                panic!("cartella temporanea");
            };
            let file = cartella.path().join("dato.txt");
            if std::fs::write(&file, b"dato").is_err() {
                panic!("il file deve potersi scrivere");
            }
            let esito = restrict_to_current_user(&file);
            assert!(esito.is_owner_only(), "{esito:?}");
            assert_eq!(std::fs::read(&file).ok(), Some(b"dato".to_vec()));

            let interna = cartella.path().join("interna");
            if std::fs::create_dir(&interna).is_err() {
                panic!("la cartella deve potersi creare");
            }
            let esito = restrict_to_current_user(&interna);
            assert!(esito.is_owner_only(), "{esito:?}");
            assert!(std::fs::write(interna.join("dopo.txt"), b"dopo").is_ok());
        }

        /// **La rilettura senza cambiare nulla distingue un file ristretto da
        /// uno che eredita**: è la verifica dopo il rinomino.
        #[test]
        fn la_rilettura_distingue_un_file_ristretto_da_uno_che_eredita() {
            use super::super::verify_current_user_only;

            let Ok(cartella) = tempfile::tempdir() else {
                panic!("cartella temporanea");
            };
            let file = cartella.path().join("eredita.txt");
            if std::fs::write(&file, b"dato").is_err() {
                panic!("il file deve potersi scrivere");
            }
            // Appena scritto, il file eredita dalla cartella: non e' del solo
            // utente nel senso di ADR-0157, anche se la cartella e' sua.
            let prima = verify_current_user_only(&file);
            assert!(
                !prima.is_owner_only(),
                "un file che eredita e' stato accettato"
            );

            assert!(restrict_to_current_user(&file).is_owner_only());
            let dopo = verify_current_user_only(&file);
            assert!(dopo.is_owner_only(), "{dopo:?}");
        }

        #[test]
        fn l_utente_corrente_ha_un_sid() {
            let Ok(utente) = current_user() else {
                panic!("l'utente corrente deve potersi leggere");
            };
            assert!(utente.sid.starts_with("S-1-5-"), "{utente:?}");
            assert!(!utente.name.is_empty());
        }

        /// **Una cartella privata: non si riusa, non si sostituisce, si
        /// lavora dentro, si toglie.**
        #[test]
        fn la_cartella_privata_non_si_riusa_ne_si_sostituisce() {
            let Ok(cartella) = tempfile::tempdir() else {
                panic!("cartella temporanea");
            };
            let percorso = cartella.path().join(".lavoro.parziale");
            let Ok(privata) = PrivateDirectory::create(&percorso) else {
                panic!("la cartella privata deve potersi creare");
            };
            assert!(privata.access().is_owner_only(), "{:?}", privata.access());

            // Una seconda volta sullo stesso percorso: rifiutata.
            assert!(PrivateDirectory::create(&percorso).is_err());

            // Finche' e' tenuta, non si rinomina e non si cancella.
            let altrove = cartella.path().join("altrove");
            assert!(std::fs::rename(&percorso, &altrove).is_err());
            assert!(std::fs::remove_dir(&percorso).is_err());

            // Dentro si lavora: un file nasce, e si porta fuori con un rinomino.
            let dentro = percorso.join("copia.txt");
            assert!(std::fs::write(&dentro, b"copia").is_ok());
            let fuori = cartella.path().join("copia.txt");
            assert!(std::fs::rename(&dentro, &fuori).is_ok());

            assert!(privata.remove().is_ok());
            assert!(!percorso.exists());
            assert_eq!(std::fs::read(&fuori).ok(), Some(b"copia".to_vec()));
        }

        /// **Una cartella che non si svuota resta** quando la si toglie.
        #[test]
        fn una_cartella_privata_non_vuota_resta() {
            let Ok(cartella) = tempfile::tempdir() else {
                panic!("cartella temporanea");
            };
            let percorso = cartella.path().join(".lavoro.parziale");
            let Ok(privata) = PrivateDirectory::create(&percorso) else {
                panic!("la cartella privata deve potersi creare");
            };
            assert!(std::fs::write(percorso.join("resto.txt"), b"resto").is_ok());
            assert!(privata.remove().is_err());
            assert!(percorso.join("resto.txt").exists());
        }
    }
}
