//! I permessi di un file letti da un lettore che non è quello del prodotto
//! (SEC-01, ADR-0157). Solo per le prove, solo su Windows.
//!
//! # Perché un altro lettore
//!
//! Il prodotto applica e rilegge i permessi con le API di Windows (ADR-0206).
//! Una prova che li rileggesse con lo stesso codice, e con lo stesso
//! controllo, sbaglierebbe insieme al prodotto e direbbe verde. Qui li legge
//! .NET (`Get-Acl`, attraverso PowerShell), con i SID e non con i nomi, che
//! cambiano con la lingua di Windows.

use std::path::Path;

/// SID di `BUILTIN\Users`.
pub(crate) const USERS: &str = "S-1-5-32-545";

/// SID di `NT AUTHORITY\Authenticated Users`.
pub(crate) const AUTHENTICATED_USERS: &str = "S-1-5-11";

/// SID di `OWNER RIGHTS`.
pub(crate) const OWNER_RIGHTS: &str = "S-1-3-4";

/// Una voce del DACL.
#[derive(Debug, Clone)]
pub(crate) struct Voce {
    pub(crate) sid: String,
    pub(crate) ereditata: bool,
    pub(crate) concede: bool,
}

/// I permessi di un file o di una cartella.
#[derive(Debug, Clone)]
pub(crate) struct Permessi {
    pub(crate) utente: String,
    pub(crate) protetti: bool,
    pub(crate) voci: Vec<Voce>,
}

impl Permessi {
    /// Le voci che concedono qualcosa a qualcuno che non è l'utente corrente.
    pub(crate) fn concessi_ad_altri(&self) -> Vec<&Voce> {
        self.voci
            .iter()
            .filter(|voce| voce.concede && voce.sid != self.utente)
            .collect()
    }
}

/// Esegue uno script PowerShell con il percorso passato per variabile
/// d'ambiente: nessun apice da proteggere, nessuna composizione di comandi.
///
/// `PSModulePath` non passa. Se il processo delle prove discende da
/// PowerShell 7 (`pwsh`, la shell predefinita dei runner GitHub), la variabile
/// porta le cartelle dei moduli di PowerShell 7, e Windows PowerShell 5.1 non
/// carica più `Microsoft.PowerShell.Security`, né quindi `Get-Acl`
/// (`CouldNotAutoloadMatchingModule`). `pwsh` toglie da sé quelle cartelle
/// quando avvia `powershell.exe` direttamente, non quando lo avvia un altro
/// programma (DEC-513, corsa 44320320324). Senza la variabile, 5.1 usa le sue.
fn powershell(script: &str, percorso: &Path) -> String {
    let Ok(uscita) = std::process::Command::new("powershell.exe")
        .args([
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "Bypass",
            "-Command",
            script,
        ])
        .env("NEXUM_PROVA_PERCORSO", percorso)
        .env_remove("PSModulePath")
        .output()
    else {
        panic!("PowerShell deve potersi avviare per leggere i permessi");
    };
    assert!(
        uscita.status.success(),
        "lettura dei permessi di «{}» non riuscita: {}",
        percorso.display(),
        String::from_utf8_lossy(&uscita.stderr)
    );
    String::from_utf8_lossy(&uscita.stdout).into_owned()
}

/// Legge i permessi di un percorso.
pub(crate) fn leggi(percorso: &Path) -> Permessi {
    let testo = powershell(
        "$ErrorActionPreference = 'Stop'; \
         $a = Get-Acl -LiteralPath $env:NEXUM_PROVA_PERCORSO; \
         'UTENTE|' + [System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value; \
         'PROTETTI|' + $a.AreAccessRulesProtected; \
         foreach ($r in $a.GetAccessRules($true, $true, \
             [System.Security.Principal.SecurityIdentifier])) { \
           'VOCE|' + $r.IdentityReference.Value + '|' + $r.IsInherited + '|' + \
             $r.AccessControlType }",
        percorso,
    );

    let mut permessi = Permessi {
        utente: String::new(),
        protetti: false,
        voci: Vec::new(),
    };
    for riga in testo.lines() {
        let campi: Vec<&str> = riga.trim().split('|').collect();
        match campi.as_slice() {
            ["UTENTE", sid] => permessi.utente = (*sid).to_owned(),
            ["PROTETTI", valore] => permessi.protetti = *valore == "True",
            ["VOCE", sid, ereditata, tipo] => permessi.voci.push(Voce {
                sid: (*sid).to_owned(),
                ereditata: *ereditata == "True",
                concede: *tipo == "Allow",
            }),
            _ => {}
        }
    }
    assert!(
        permessi.utente.starts_with("S-1-"),
        "l'utente corrente non si e' letto: la prova non sta guardando nulla ({testo})"
    );
    permessi
}

/// Apre una cartella come quella del collaudo (BAK-03): lettura per
/// `BUILTIN\Users`, modifica per `Authenticated Users`, ereditabili.
pub(crate) fn apri_come_nel_collaudo(cartella: &Path) {
    let Ok(uscita) = std::process::Command::new("icacls")
        .arg(cartella)
        .args([
            "/grant",
            &format!("*{USERS}:(OI)(CI)(RX)"),
            "/grant",
            &format!("*{AUTHENTICATED_USERS}:(OI)(CI)(M)"),
        ])
        .output()
    else {
        panic!("icacls deve potersi avviare per preparare la cartella");
    };
    assert!(
        uscita.status.success(),
        "la cartella di prova non si e' aperta: {}",
        String::from_utf8_lossy(&uscita.stdout)
    );

    // LA PREMESSA SI CONTROLLA. Un file scritto senza cure in questa cartella
    // deve risultare leggibile dagli altri: se non lo fosse, la prova che segue
    // misurerebbe una cartella gia' chiusa e direbbe verde per niente.
    let testimone = cartella.join("testimone.txt");
    if std::fs::write(&testimone, b"testimone").is_err() {
        panic!("il file testimone deve potersi scrivere");
    }
    let permessi = leggi(&testimone);
    assert!(
        permessi
            .concessi_ad_altri()
            .iter()
            .any(|voce| voce.sid == USERS || voce.sid == AUTHENTICATED_USERS),
        "la premessa non regge: un file scritto nella cartella aperta non e' \
         leggibile dagli altri ({permessi:?})"
    );
    if std::fs::remove_file(&testimone).is_err() {
        panic!("il file testimone deve potersi togliere");
    }
}

/// Afferma che un percorso è del solo utente corrente: DACL protetto, nessuna
/// voce ereditata, nessuna concessione ad altri, una concessione all'utente.
pub(crate) fn afferma_del_solo_utente(percorso: &Path) {
    let permessi = leggi(percorso);
    let nome = percorso.display();
    assert!(
        permessi.concessi_ad_altri().is_empty(),
        "«{nome}» concede l'accesso anche ad altri: {:?}",
        permessi.concessi_ad_altri()
    );
    assert!(
        permessi.protetti,
        "«{nome}» eredita i permessi della cartella: la prima propagazione li \
         riscriverebbe ({permessi:?})"
    );
    assert!(
        permessi.voci.iter().all(|voce| !voce.ereditata),
        "«{nome}» ha voci ereditate ({permessi:?})"
    );
    assert!(
        permessi
            .voci
            .iter()
            .any(|voce| voce.concede && voce.sid == permessi.utente),
        "«{nome}» non concede nulla nemmeno all'utente: non si aprirebbe piu' \
         ({permessi:?})"
    );
}

/// Afferma che nessuno, oltre all'utente corrente, apre un percorso: nessuna
/// concessione ad altri e una concessione all'utente, **anche ereditata**.
///
/// È la forma dei documenti dentro la cartella del pacchetto: ereditano dalla
/// cartella, che è del solo utente con un DACL protetto.
pub(crate) fn afferma_che_nessun_altro_apre(percorso: &Path) {
    let permessi = leggi(percorso);
    let nome = percorso.display();
    assert!(
        permessi.concessi_ad_altri().is_empty(),
        "«{nome}» concede l'accesso anche ad altri: {:?}",
        permessi.concessi_ad_altri()
    );
    assert!(
        permessi
            .voci
            .iter()
            .any(|voce| voce.concede && voce.sid == permessi.utente),
        "«{nome}» non concede nulla nemmeno all'utente ({permessi:?})"
    );
}

/// Lo script di [`rifiuta_i_permessi`].
///
/// Il DACL si scrive con .NET, protetto, con due sole voci ereditabili:
/// modifica per l'utente e modifica per `OWNER RIGHTS`, che toglie al
/// proprietario il diritto implicito di cambiare i permessi. Non con `icacls`:
/// sul runner GitHub, nella cartella temporanea del profilo, `icacls
/// /inheritance:r` lascia SYSTEM e Administrators come voci esplicite, e un
/// utente amministratore cambia i permessi lo stesso (DEC-513, corsa
/// 44320123227).
const SCRIPT_RIFIUTA: &str = "$ErrorActionPreference = 'Stop'; \
     $p = $env:NEXUM_PROVA_PERCORSO; \
     $ds = New-Object System.Security.AccessControl.DirectorySecurity; \
     $ds.SetAccessRuleProtection($true, $false); \
     foreach ($s in @([System.Security.Principal.WindowsIdentity]::GetCurrent().User, \
         (New-Object System.Security.Principal.SecurityIdentifier('S-1-3-4')))) { \
       $ds.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule( \
         $s, 'Modify', 'ContainerInherit,ObjectInherit', 'None', 'Allow'))) }; \
     [System.IO.Directory]::SetAccessControl($p, $ds); \
     $t = [System.IO.Path]::Combine($p, 'testimone.txt'); \
     [System.IO.File]::WriteAllText($t, 'testimone'); \
     $cambiati = $true; \
     try { $f = [System.IO.File]::GetAccessControl($t); \
           $f.SetAccessRuleProtection($true, $true); \
           [System.IO.File]::SetAccessControl($t, $f) } catch { $cambiati = $false }; \
     [System.IO.File]::Delete($t); \
     'TESTIMONE|' + $cambiati";

/// Chiude una cartella come una chiavetta FAT32 o exFAT, che non conserva i
/// permessi: l'utente vi crea e modifica, ma non può cambiare i permessi di
/// ciò che vi crea (voce `OWNER RIGHTS`, S-1-3-4). Ottenuto su NTFS.
///
/// LA PREMESSA SI CONTROLLA, come in [`apri_come_nel_collaudo`]: un file
/// testimone nato nella cartella non deve poter cambiare i propri permessi, e
/// la cartella deve avere soltanto le due voci, protette. Altrimenti la prova
/// che segue misurerebbe una cartella che i permessi li accetta.
pub(crate) fn rifiuta_i_permessi(cartella: &Path) {
    let testo = powershell(SCRIPT_RIFIUTA, cartella);
    assert!(
        testo.lines().any(|riga| riga.trim() == "TESTIMONE|False"),
        "la premessa non regge: nella cartella che rifiuta i permessi un file \
         ha potuto cambiare i propri ({testo})"
    );
    let permessi = leggi(cartella);
    assert!(
        permessi.protetti
            && !permessi.voci.is_empty()
            && permessi.voci.iter().all(|voce| {
                !voce.ereditata && (voce.sid == permessi.utente || voce.sid == OWNER_RIGHTS)
            }),
        "la premessa non regge: la cartella che rifiuta i permessi ha altre \
         voci ({permessi:?})"
    );
}

/// Una cartella temporanea chiusa con [`rifiuta_i_permessi`].
pub(crate) fn cartella_che_rifiuta_i_permessi() -> tempfile::TempDir {
    let Ok(cartella) = tempfile::tempdir() else {
        panic!("la cartella temporanea deve potersi creare");
    };
    rifiuta_i_permessi(cartella.path());
    cartella
}

/// I nomi in una cartella, ordinati.
pub(crate) fn nomi_in(cartella: &Path) -> Vec<String> {
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

/// **Prova un'uscita nelle due cartelle di SEC-02** (ADR-0157, ADR-0159).
///
/// `produci` scrive l'uscita nella cartella che riceve, e restituisce ciò che
/// ha scritto **in quella cartella**: file sciolti o la cartella di un
/// pacchetto.
///
/// 1. In una cartella **aperta come nel collaudo**: ogni file è del solo
///    utente (DACL protetto, nessuna voce ereditata, nessuna concessione ad
///    altri); la cartella di un pacchetto lo è, e i file che contiene non
///    concedono nulla ad altri; nella cartella non resta altro.
/// 2. In una cartella **che rifiuta i permessi**: l'esito è
///    [`crate::ServiceError::ProtectionNotGuaranteed`], e nella cartella non
///    resta nulla.
pub(crate) fn prova_un_uscita(
    nome: &str,
    produci: impl Fn(&Path) -> crate::ServiceResult<Vec<std::path::PathBuf>>,
) {
    let Ok(aperta) = tempfile::tempdir() else {
        panic!("la cartella temporanea deve potersi creare");
    };
    apri_come_nel_collaudo(aperta.path());
    let prodotti = match produci(aperta.path()) {
        Ok(prodotti) => prodotti,
        Err(errore) => {
            panic!("{nome}: l'uscita in una cartella aperta non si è scritta: {errore:?}")
        }
    };
    assert!(
        !prodotti.is_empty(),
        "{nome}: l'uscita non dice che cosa ha scritto"
    );
    let mut attesi = Vec::new();
    for prodotto in &prodotti {
        afferma_del_solo_utente(prodotto);
        if prodotto.is_dir() {
            for interno in nomi_in(prodotto) {
                afferma_che_nessun_altro_apre(&prodotto.join(interno));
            }
        }
        if let Some(nome_file) = prodotto.file_name() {
            attesi.push(nome_file.to_string_lossy().into_owned());
        }
    }
    attesi.sort();
    assert_eq!(
        nomi_in(aperta.path()),
        attesi,
        "{nome}: nella cartella aperta è rimasto altro accanto all'uscita"
    );

    let chiusa = cartella_che_rifiuta_i_permessi();
    match produci(chiusa.path()) {
        Err(crate::ServiceError::ProtectionNotGuaranteed { .. }) => {}
        Ok(prodotti) => panic!(
            "{nome}: in una cartella che rifiuta i permessi l'uscita si è scritta: {prodotti:?}"
        ),
        Err(altro) => panic!("{nome}: il rifiuto non è quello dei permessi: {altro:?}"),
    }
    assert!(
        nomi_in(chiusa.path()).is_empty(),
        "{nome}: il rifiuto ha lasciato qualcosa: {:?}",
        nomi_in(chiusa.path())
    );
}
