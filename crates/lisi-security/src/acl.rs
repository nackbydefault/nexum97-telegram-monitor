// Secondo modulo del crate autorizzato a contenere `unsafe`, dopo `dpapi.rs`
// (ADR-0206). Il resto del crate resta sotto `#![deny(unsafe_code)]`: questa
// deroga e' esplicita, circoscritta a questo file e visibile in diff.
#![allow(unsafe_code)]

//! I permessi di un file o di una cartella, **applicati e riletti con le API
//! di Windows** (CI-FIX-01, ADR-0206).
//!
//! # Perché non `icacls`
//!
//! Sul runner di GitHub, nella cartella temporanea del profilo, `icacls
//! /inheritance:r` ha lasciato le voci ereditate di SYSTEM e Administrators
//! convertite in voci esplicite: il file non era del solo utente. E la
//! rilettura in SDDL scrive alcuni SID con un nome breve (`LA` per
//! l'Administrator predefinito), che nessun confronto di stringhe riconosce.
//! Qui il DACL si scrive con `SetNamedSecurityInfoW`, si rilegge con
//! `GetNamedSecurityInfoW`, e i SID si confrontano con `EqualSid`: in binario,
//! senza testo e senza lingua.
//!
//! # Invarianti
//!
//! 1. Ogni memoria che Windows restituisce (descrittore, SID convertito, testo
//!    del SID) si libera con `LocalFree`, una volta, su ogni percorso.
//! 2. Ogni handle aperto (il token del processo) si chiude su ogni percorso.
//! 3. I buffer che contengono un SID, un ACL o le informazioni del token sono
//!    vettori di `u32` o `u64`: allineati come le strutture che contengono.
//! 4. Il SID di una voce letta si usa soltanto se è valido e sta per intero
//!    dentro la voce, che a sua volta sta dentro l'ACL: altrimenti il DACL vale
//!    «non si legge», e il chiamante lo tratta come non verificato.
//! 5. Nessun puntatore di Windows esce da questo modulo: escono copie.

use std::ffi::OsStr;
use std::os::windows::ffi::OsStrExt;
use std::path::Path;

use windows_sys::Win32::Foundation::{CloseHandle, HANDLE, LocalFree};
use windows_sys::Win32::Security::Authorization::{
    ConvertSidToStringSidW, GetNamedSecurityInfoW, SE_FILE_OBJECT, SetNamedSecurityInfoW,
};
use windows_sys::Win32::Security::{
    ACCESS_ALLOWED_ACE, ACE_HEADER, ACL, ACL_REVISION, AddAccessAllowedAceEx,
    CONTAINER_INHERIT_ACE, DACL_SECURITY_INFORMATION, EqualSid, GetAce, GetLengthSid,
    GetSecurityDescriptorControl, GetTokenInformation, InitializeAcl, IsValidSid,
    OBJECT_INHERIT_ACE, PROTECTED_DACL_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, PSID,
    SE_DACL_PROTECTED, TOKEN_QUERY, TOKEN_USER, TokenUser, UNPROTECTED_DACL_SECURITY_INFORMATION,
};
use windows_sys::Win32::Storage::FileSystem::FILE_ALL_ACCESS;
use windows_sys::Win32::System::SystemServices::{ACCESS_ALLOWED_ACE_TYPE, ACCESS_DENIED_ACE_TYPE};
use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

use crate::owner_only::{AceKind, DaclView, Entry, Holder};

/// Un SID copiato in memoria nostra, allineato a 4 byte (invariante 3).
#[derive(Debug, Clone)]
pub(crate) struct Sid {
    words: Vec<u32>,
}

impl Sid {
    /// Copia un SID valido di cui Windows ha dato il puntatore.
    ///
    /// # Sicurezza
    ///
    /// `sid` deve puntare a un SID valido (`IsValidSid` vero) leggibile per
    /// `GetLengthSid(sid)` byte per tutta la chiamata.
    unsafe fn copy_from(sid: PSID) -> Option<Self> {
        // SAFETY: il chiamante garantisce un SID valido e leggibile.
        let length = unsafe { GetLengthSid(sid) } as usize;
        if length == 0 {
            return None;
        }
        let mut words = vec![0_u32; length.div_ceil(4)];
        // SAFETY: `words` ha almeno `length` byte scrivibili; la sorgente ne ha
        // `length` leggibili per contratto; le due aree non si sovrappongono.
        unsafe {
            core::ptr::copy_nonoverlapping(
                sid.cast::<u8>().cast_const(),
                words.as_mut_ptr().cast::<u8>(),
                length,
            );
        }
        Some(Self { words })
    }

    /// Il puntatore da passare a Windows. Le funzioni a cui si passa non lo
    /// modificano: la firma lo vuole mutabile, il cast non implica scrittura.
    fn as_psid(&self) -> PSID {
        self.words.as_ptr().cast_mut().cast()
    }

    /// Se due SID indicano la stessa identità, confrontati da Windows.
    /// Il prodotto confronta dentro `read_dacl`; qui serve alle prove.
    #[cfg(test)]
    pub(crate) fn same_as(&self, other: &Self) -> bool {
        // SAFETY: entrambi i SID sono copie valide nate da `copy_from`.
        unsafe { EqualSid(self.as_psid(), other.as_psid()) != 0 }
    }

    /// La forma testuale standard (`S-1-5-…`), per le frasi e il foglio.
    pub(crate) fn to_text(&self) -> Option<String> {
        let mut testo: windows_sys::core::PWSTR = core::ptr::null_mut();
        // SAFETY: il SID è una copia valida; Windows alloca il testo e ne
        // scrive l'indirizzo in `testo`, che si libera qui sotto (invariante 1).
        if unsafe { ConvertSidToStringSidW(self.as_psid(), &raw mut testo) } == 0 || testo.is_null()
        {
            return None;
        }
        let mut lunghezza = 0_usize;
        // SAFETY: il testo restituito da Windows termina con lo zero.
        while unsafe { *testo.add(lunghezza) } != 0 {
            lunghezza += 1;
        }
        // SAFETY: `lunghezza` unità sono leggibili, appena contate.
        let unita = unsafe { core::slice::from_raw_parts(testo, lunghezza) };
        let risultato = String::from_utf16(unita).ok();
        // SAFETY: memoria allocata da ConvertSidToStringSidW, liberata una volta.
        let _ = unsafe { LocalFree(testo.cast()) };
        risultato
    }

    /// Il SID scritto nella forma standard. Soltanto per le prove: il prodotto
    /// non ricava mai un SID da un testo.
    #[cfg(test)]
    pub(crate) fn from_text(testo: &str) -> Option<Self> {
        use windows_sys::Win32::Security::Authorization::ConvertStringSidToSidW;

        let largo: Vec<u16> = testo.encode_utf16().chain(Some(0)).collect();
        let mut sid: PSID = core::ptr::null_mut();
        // SAFETY: `largo` termina con lo zero; Windows alloca il SID e ne
        // scrive l'indirizzo in `sid`, liberato qui sotto (invariante 1).
        if unsafe { ConvertStringSidToSidW(largo.as_ptr(), &raw mut sid) } == 0 || sid.is_null() {
            return None;
        }
        // SAFETY: Windows ha appena restituito un SID valido.
        let copia = unsafe { Self::copy_from(sid) };
        // SAFETY: memoria allocata da ConvertStringSidToSidW, liberata una volta.
        let _ = unsafe { LocalFree(sid.cast()) };
        copia
    }
}

/// Il SID dell'utente per conto del quale gira il processo, dal suo token.
pub(crate) fn current_user_sid() -> Option<Sid> {
    let mut token: HANDLE = core::ptr::null_mut();
    // SAFETY: lo pseudo-handle del processo corrente non va chiuso; il token
    // aperto si chiude qui sotto su ogni percorso (invariante 2).
    if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &raw mut token) } == 0 {
        return None;
    }
    let sid = token_user(token);
    // SAFETY: `token` è un handle aperto qui sopra, chiuso una volta.
    let _ = unsafe { CloseHandle(token) };
    sid
}

fn token_user(token: HANDLE) -> Option<Sid> {
    let mut necessari = 0_u32;
    // SAFETY: la prima chiamata chiede solo la dimensione: buffer nullo e
    // lunghezza zero sono ammessi, e fallisce per contratto.
    let _ = unsafe {
        GetTokenInformation(
            token,
            TokenUser,
            core::ptr::null_mut(),
            0,
            &raw mut necessari,
        )
    };
    if necessari == 0 {
        return None;
    }
    // Vettore di u64: allineato per TOKEN_USER, che contiene un puntatore.
    let mut buffer = vec![0_u64; (necessari as usize).div_ceil(8)];
    let lunghezza = u32::try_from(buffer.len() * 8).ok()?;
    // SAFETY: `buffer` ha `lunghezza` byte scrivibili e allineati.
    if unsafe {
        GetTokenInformation(
            token,
            TokenUser,
            buffer.as_mut_ptr().cast(),
            lunghezza,
            &raw mut necessari,
        )
    } == 0
    {
        return None;
    }
    // SAFETY: Windows ha scritto un TOKEN_USER all'inizio del buffer; il SID a
    // cui punta sta dentro lo stesso buffer, vivo fino alla copia.
    let sid = unsafe { (*buffer.as_ptr().cast::<TOKEN_USER>()).User.Sid };
    // SAFETY: si controlla la validità prima di copiarlo.
    if sid.is_null() || unsafe { IsValidSid(sid) } == 0 {
        return None;
    }
    // SAFETY: SID valido dentro `buffer`, ancora vivo.
    unsafe { Sid::copy_from(sid) }
}

fn wide(path: &Path) -> Vec<u16> {
    OsStr::new(path).encode_wide().chain(Some(0)).collect()
}

/// Scrive sull'oggetto un DACL protetto con la sola voce di `sid`, controllo
/// completo; su una cartella la voce si eredita da file e sottocartelle.
///
/// # Errori
///
/// Il codice di Windows, se il DACL non si costruisce o non si applica.
pub(crate) fn apply_owner_only(path: &Path, sid: &Sid, directory: bool) -> Result<(), u32> {
    let flags = if directory {
        OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE
    } else {
        0
    };
    let acl = build_acl(&[(sid, FILE_ALL_ACCESS, flags)])?;
    set_dacl(path, Some(&acl), true)
}

/// Un ACL costruito in memoria nostra, allineato a 4 byte (invariante 3).
pub(crate) struct OwnedAcl {
    words: Vec<u32>,
}

/// Costruisce un ACL di sole voci che concedono.
pub(crate) fn build_acl(voci: &[(&Sid, u32, u32)]) -> Result<OwnedAcl, u32> {
    let mut dimensione = size_of::<ACL>();
    for (sid, _, _) in voci {
        // SAFETY: SID valido, copia nostra.
        let lunghezza = unsafe { GetLengthSid(sid.as_psid()) } as usize;
        // La voce: intestazione e maschera, poi il SID al posto di `SidStart`.
        dimensione += size_of::<ACCESS_ALLOWED_ACE>() - size_of::<u32>() + lunghezza;
    }
    let dimensione = dimensione.next_multiple_of(4);
    let Ok(dimensione_u32) = u32::try_from(dimensione) else {
        return Err(u32::MAX);
    };
    let mut words = vec![0_u32; dimensione / 4];
    let acl = words.as_mut_ptr().cast::<ACL>();
    // SAFETY: `words` ha `dimensione` byte allineati a 4, vivi per la chiamata.
    if unsafe { InitializeAcl(acl, dimensione_u32, ACL_REVISION) } == 0 {
        return Err(last_error());
    }
    for (sid, maschera, contrassegni) in voci {
        // SAFETY: l'ACL è stato inizializzato con lo spazio per questa voce;
        // il SID è una copia valida.
        if unsafe {
            AddAccessAllowedAceEx(acl, ACL_REVISION, *contrassegni, *maschera, sid.as_psid())
        } == 0
        {
            return Err(last_error());
        }
    }
    Ok(OwnedAcl { words })
}

/// Applica un DACL (o un DACL nullo), protetto o no.
///
/// Senza l'uno o l'altro contrassegno Windows lascerebbe la protezione com'era:
/// si dice sempre esplicitamente quale si vuole. Non protetto, il DACL riceve
/// di nuovo le voci ereditabili della cartella.
pub(crate) fn set_dacl(path: &Path, acl: Option<&OwnedAcl>, protected: bool) -> Result<(), u32> {
    let nome = wide(path);
    let informazioni = DACL_SECURITY_INFORMATION
        | if protected {
            PROTECTED_DACL_SECURITY_INFORMATION
        } else {
            UNPROTECTED_DACL_SECURITY_INFORMATION
        };
    let puntatore = acl.map_or(core::ptr::null(), |acl| acl.words.as_ptr().cast::<ACL>());
    // SAFETY: `nome` termina con lo zero; l'ACL, se c'è, è valido e vivo per
    // tutta la chiamata; proprietario, gruppo e SACL non si toccano (nulli).
    let esito = unsafe {
        SetNamedSecurityInfoW(
            nome.as_ptr(),
            SE_FILE_OBJECT,
            informazioni,
            core::ptr::null_mut(),
            core::ptr::null_mut(),
            puntatore,
            core::ptr::null(),
        )
    };
    if esito == 0 { Ok(()) } else { Err(esito) }
}

fn last_error() -> u32 {
    // SAFETY: nessun parametro; legge l'ultimo errore del thread.
    unsafe { windows_sys::Win32::Foundation::GetLastError() }
}

/// Rilegge il DACL dell'oggetto e lo descrive, confrontando ogni SID con
/// `user`. `None` se il descrittore non si legge o una voce non si legge per
/// intero (invariante 4).
pub(crate) fn read_dacl(path: &Path, user: &Sid) -> Option<DaclView> {
    let nome = wide(path);
    let mut dacl: *mut ACL = core::ptr::null_mut();
    let mut descrittore: PSECURITY_DESCRIPTOR = core::ptr::null_mut();
    // SAFETY: `nome` termina con lo zero; Windows alloca il descrittore e vi fa
    // puntare `dacl`; il descrittore si libera qui sotto (invariante 1).
    let esito = unsafe {
        GetNamedSecurityInfoW(
            nome.as_ptr(),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION,
            core::ptr::null_mut(),
            core::ptr::null_mut(),
            &raw mut dacl,
            core::ptr::null_mut(),
            &raw mut descrittore,
        )
    };
    if esito != 0 || descrittore.is_null() {
        return None;
    }
    let vista = describe(descrittore, dacl, user);
    // SAFETY: memoria allocata da GetNamedSecurityInfoW, liberata una volta;
    // `dacl` puntava dentro di essa e non si usa più.
    let _ = unsafe { LocalFree(descrittore) };
    vista
}

fn describe(descrittore: PSECURITY_DESCRIPTOR, dacl: *mut ACL, user: &Sid) -> Option<DaclView> {
    let mut controllo = 0_u16;
    let mut revisione = 0_u32;
    // SAFETY: descrittore valido restituito da GetNamedSecurityInfoW.
    if unsafe { GetSecurityDescriptorControl(descrittore, &raw mut controllo, &raw mut revisione) }
        == 0
    {
        return None;
    }
    let protected = controllo & SE_DACL_PROTECTED != 0;
    if dacl.is_null() {
        return Some(DaclView {
            present: false,
            protected,
            entries: Vec::new(),
        });
    }
    // SAFETY: `dacl` punta a un ACL dentro il descrittore, ancora vivo.
    let intestazione = unsafe { &*dacl };
    let fine_acl = dacl as usize + usize::from(intestazione.AclSize);
    let mut entries = Vec::with_capacity(usize::from(intestazione.AceCount));
    for indice in 0..u32::from(intestazione.AceCount) {
        let mut voce: *mut core::ffi::c_void = core::ptr::null_mut();
        // SAFETY: indice entro il numero di voci dichiarato dall'ACL.
        if unsafe { GetAce(dacl, indice, &raw mut voce) } == 0 || voce.is_null() {
            return None;
        }
        // SAFETY: GetAce restituisce l'indirizzo di una voce dentro l'ACL, che
        // comincia con ACE_HEADER.
        let testa = unsafe { *voce.cast::<ACE_HEADER>() };
        let inizio = voce as usize;
        let fine = inizio.checked_add(usize::from(testa.AceSize))?;
        if fine > fine_acl {
            return None;
        }
        let tipo = u32::from(testa.AceType);
        let kind = if tipo == ACCESS_ALLOWED_ACE_TYPE {
            AceKind::Allow
        } else if tipo == ACCESS_DENIED_ACE_TYPE {
            AceKind::Deny
        } else {
            entries.push(Entry {
                kind: AceKind::Other(testa.AceType),
                holder: Holder::Other,
                mask: 0,
                flags: testa.AceFlags,
            });
            continue;
        };
        // Voce semplice, che concede o nega: stessa forma di ACCESS_ALLOWED_ACE.
        let minimo = size_of::<ACCESS_ALLOWED_ACE>();
        if usize::from(testa.AceSize) < minimo {
            return None;
        }
        let semplice = voce.cast::<ACCESS_ALLOWED_ACE>();
        // SAFETY: la voce è lunga almeno quanto la struttura, verificato sopra.
        let mask = unsafe { (*semplice).Mask };
        // SAFETY: `SidStart` è il primo campo del SID dentro la voce.
        let sid: PSID = unsafe { (&raw const (*semplice).SidStart) }
            .cast_mut()
            .cast();
        // SAFETY: si controlla la validità del SID, poi che stia nella voce.
        if unsafe { IsValidSid(sid) } == 0 {
            return None;
        }
        // SAFETY: SID valido.
        let lunghezza = unsafe { GetLengthSid(sid) } as usize;
        if (sid as usize).checked_add(lunghezza)? > fine {
            return None;
        }
        // SAFETY: entrambi validi; `sid` sta per intero dentro la voce.
        let suo = unsafe { EqualSid(sid, user.as_psid()) } != 0;
        entries.push(Entry {
            kind,
            holder: if suo {
                Holder::CurrentUser
            } else {
                Holder::Other
            },
            mask,
            flags: testa.AceFlags,
        });
    }
    Some(DaclView {
        present: true,
        protected,
        entries,
    })
}

#[cfg(test)]
mod tests {
    use super::{Sid, apply_owner_only, build_acl, current_user_sid, read_dacl, set_dacl};
    use crate::owner_only::{Holder, check_entries};

    const PIENO: u32 = 0x001F_01FF;
    const LETTURA: u32 = 0x0012_00A9;

    fn utente() -> Sid {
        let Some(sid) = current_user_sid() else {
            panic!("il SID dell'utente del processo deve potersi leggere");
        };
        sid
    }

    fn sid(testo: &str) -> Sid {
        let Some(sid) = Sid::from_text(testo) else {
            panic!("SID di prova non valido: {testo}");
        };
        sid
    }

    fn file_di_prova(cartella: &tempfile::TempDir) -> std::path::PathBuf {
        let file = cartella.path().join("sintetico.txt");
        if std::fs::write(&file, b"dato sintetico").is_err() {
            panic!("il file di prova deve potersi scrivere");
        }
        file
    }

    /// **Rappresentazioni equivalenti, identità distinte.** Il SID del token,
    /// passato per la sua forma testuale e ritorno, è lo stesso per
    /// `EqualSid`; SYSTEM, Administrators, Users e un SID di dominio inventato
    /// no. Sul runner l'utente è l'Administrator predefinito, che SDDL scrive
    /// `LA`: qui non conta, perché il confronto è in binario.
    #[test]
    fn il_sid_si_confronta_in_binario() {
        let mio = utente();
        let Some(testo) = mio.to_text() else {
            panic!("il SID deve avere una forma testuale");
        };
        assert!(testo.starts_with("S-1-5-"), "{testo}");
        assert!(sid(&testo).same_as(&mio));
        for altro in [
            "S-1-5-18",
            "S-1-5-32-544",
            "S-1-5-32-545",
            "S-1-5-21-1-2-3-1003",
        ] {
            assert!(!sid(altro).same_as(&mio), "{altro} confuso con l'utente");
        }
        // `LA` è il nome breve SDDL dell'Administrator predefinito (RID 500):
        // la stessa identità dell'utente se e solo se l'utente è quell'account.
        // Sulla postazione di sviluppo non lo è; sul runner di GitHub sì — ed è
        // il caso che faceva fallire il confronto fra stringhe. `SY` è SYSTEM,
        // mai l'utente di un processo interattivo o del runner.
        let Some(amministratore) = Sid::from_text("LA") else {
            panic!("Windows deve risolvere LA");
        };
        assert_eq!(amministratore.same_as(&mio), testo.ends_with("-500"));
        let Some(sistema) = Sid::from_text("SY") else {
            panic!("Windows deve risolvere SY");
        };
        assert!(sistema.same_as(&sid("S-1-5-18")));
        assert!(!sistema.same_as(&mio));
    }

    /// **Il DACL del solo utente, scritto con le API, si rilegge accettato**;
    /// su una cartella la voce si eredita e ciò che vi nasce non porta altri.
    #[test]
    fn la_restrizione_nativa_si_rilegge_accettata() {
        let Ok(cartella) = tempfile::tempdir() else {
            panic!("cartella temporanea");
        };
        let mio = utente();
        let file = file_di_prova(&cartella);
        assert!(apply_owner_only(&file, &mio, false).is_ok());
        let Some(vista) = read_dacl(&file, &mio) else {
            panic!("il DACL deve rileggersi");
        };
        assert_eq!(check_entries(&vista, false), Ok(()));

        let interna = cartella.path().join("interna");
        assert!(std::fs::create_dir(&interna).is_ok());
        assert!(apply_owner_only(&interna, &mio, true).is_ok());
        let Some(vista) = read_dacl(&interna, &mio) else {
            panic!("il DACL della cartella deve rileggersi");
        };
        assert_eq!(check_entries(&vista, true), Ok(()));

        let nato = interna.join("nato-dopo.txt");
        assert!(std::fs::write(&nato, b"dopo").is_ok());
        let Some(vista) = read_dacl(&nato, &mio) else {
            panic!("il DACL del file nato dopo deve rileggersi");
        };
        assert!(!vista.entries.is_empty());
        assert!(
            vista
                .entries
                .iter()
                .all(|voce| voce.holder == Holder::CurrentUser),
            "il file nato nella cartella ristretta porta altri titolari: {vista:?}"
        );
    }

    /// **Prova negativa sul file vero: chi non è l'utente fa rifiutare.** Un
    /// DACL protetto che concede anche a SYSTEM, ad Administrators, a Users o
    /// a un altro account è rifiutato; senza quella voce è accettato. La
    /// correzione non autorizza nessuno che prima fosse escluso.
    #[test]
    fn un_dacl_che_concede_ad_altri_si_rifiuta() {
        let Ok(cartella) = tempfile::tempdir() else {
            panic!("cartella temporanea");
        };
        let mio = utente();
        let file = file_di_prova(&cartella);
        for (altro, maschera) in [
            ("S-1-5-18", PIENO),
            ("S-1-5-32-544", PIENO),
            ("S-1-5-32-545", LETTURA),
            ("S-1-5-21-1-2-3-1003", LETTURA),
        ] {
            let estraneo = sid(altro);
            let Ok(acl) = build_acl(&[(&mio, PIENO, 0), (&estraneo, maschera, 0)]) else {
                panic!("l'ACL di prova deve costruirsi");
            };
            assert!(set_dacl(&file, Some(&acl), true).is_ok());
            let Some(vista) = read_dacl(&file, &mio) else {
                panic!("il DACL deve rileggersi");
            };
            assert!(
                check_entries(&vista, false).is_err(),
                "una concessione a {altro} e' stata accettata"
            );
        }
        let Ok(solo_mio) = build_acl(&[(&mio, PIENO, 0)]) else {
            panic!("l'ACL di prova deve costruirsi");
        };
        assert!(set_dacl(&file, Some(&solo_mio), true).is_ok());
        let Some(vista) = read_dacl(&file, &mio) else {
            panic!("il DACL deve rileggersi");
        };
        assert_eq!(check_entries(&vista, false), Ok(()));
    }

    /// **Le forme che non si possono verificare si rifiutano**: un DACL nullo
    /// (nessun limite), un DACL non protetto, un DACL senza il controllo
    /// completo dell'utente.
    #[test]
    fn le_forme_non_verificabili_si_rifiutano_sul_file_vero() {
        let Ok(cartella) = tempfile::tempdir() else {
            panic!("cartella temporanea");
        };
        let mio = utente();
        let file = file_di_prova(&cartella);

        assert!(set_dacl(&file, None, true).is_ok());
        let Some(vista) = read_dacl(&file, &mio) else {
            panic!("il descrittore deve rileggersi");
        };
        assert!(!vista.present);
        assert!(check_entries(&vista, false).is_err());

        let Ok(solo_mio) = build_acl(&[(&mio, PIENO, 0)]) else {
            panic!("l'ACL di prova deve costruirsi");
        };
        assert!(set_dacl(&file, Some(&solo_mio), false).is_ok());
        let Some(vista) = read_dacl(&file, &mio) else {
            panic!("il DACL deve rileggersi");
        };
        assert!(
            check_entries(&vista, false).is_err(),
            "non protetto: {vista:?}"
        );

        let Ok(lettura) = build_acl(&[(&mio, LETTURA, 0)]) else {
            panic!("l'ACL di prova deve costruirsi");
        };
        assert!(set_dacl(&file, Some(&lettura), true).is_ok());
        let Some(vista) = read_dacl(&file, &mio) else {
            panic!("il DACL deve rileggersi");
        };
        assert!(
            check_entries(&vista, false).is_err(),
            "senza controllo completo"
        );

        // Si rimette il controllo completo, perché la cartella si possa togliere.
        assert!(apply_owner_only(&file, &mio, false).is_ok());
    }

    /// **Un file che eredita dalla cartella si rifiuta**, così com'è nato.
    #[test]
    fn un_file_che_eredita_si_rifiuta() {
        let Ok(cartella) = tempfile::tempdir() else {
            panic!("cartella temporanea");
        };
        let mio = utente();
        let file = file_di_prova(&cartella);
        let Some(vista) = read_dacl(&file, &mio) else {
            panic!("il DACL deve rileggersi");
        };
        assert!(check_entries(&vista, false).is_err(), "{vista:?}");
    }
}
