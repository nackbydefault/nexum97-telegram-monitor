//! Il profilo documentale con i campi personali cifrati (OPERATOR-DPAPI-01,
//! ADR-0160, DEC-424).
//!
//! # Perché un modulo solo
//!
//! Firmatario, qualifica e riga «sede, indirizzo e recapiti» sono dati di una
//! persona. L'archivio li conserva soltanto cifrati con DPAPI per l'utente
//! Windows, e rifiuta di scriverli in chiaro; qui si cifra prima di scrivere e
//! si decifra dopo aver letto. Chiunque nel programma legga o scriva il
//! profilo passa da qui: la relazione, il fascicolo, la schermata.
//!
//! # Un valore che non si decifra
//!
//! Un archivio ripristinato su un'altra postazione, o aperto da un altro
//! utente, porta i campi cifrati per chi li aveva scritti. Non si inventano:
//! il campo si legge vuoto, e [`LoadedProfile::unreadable`] dice quale, perché
//! la schermata chieda di reinserirlo.

use lisi_core::Timestamp;
use lisi_core::model::report_template::{ReportTemplateProfile, TemplateField};
use lisi_core::text::Actor;
use lisi_security::dpapi;
use lisi_storage::Database;
use lisi_storage::repository::report::{PlainConversion, ProtectedProfileFields};

use crate::error::ServiceResult;

/// Il nome con cui un campo personale si dice all'operatore.
pub const SIGNER_NAME: &str = "Nome di chi firma";
/// Il nome con cui un campo personale si dice all'operatore.
pub const SIGNER_ROLE: &str = "Qualifica di chi firma";
/// Il nome con cui un campo personale si dice all'operatore.
pub const HEADER_LINE: &str = "Sede, indirizzo e recapiti";

/// Il profilo letto, e i campi personali che su questa postazione non si
/// aprono.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LoadedProfile {
    /// Il profilo, con i campi personali decifrati dove si può.
    pub profile: ReportTemplateProfile,
    /// I campi personali cifrati per un altro utente o un'altra postazione:
    /// letti vuoti, da reinserire.
    pub unreadable: Vec<&'static str>,
}

impl LoadedProfile {
    /// La frase per l'operatore quando qualche campo non si apre.
    ///
    /// Vuota quando tutto si apre.
    #[must_use]
    pub fn unreadable_message(&self) -> String {
        if self.unreadable.is_empty() {
            return String::new();
        }
        format!(
            "Questi dati di chi firma sono stati inseriti con un altro utente Windows o su \
             un'altra postazione, e qui non si aprono: {}. Vanno reinseriti e salvati. Finché \
             non lo sono, le relazioni non li riportano.",
            self.unreadable.join(", ")
        )
    }
}

/// Legge il profilo, decifrando i campi personali.
///
/// **Se trova i campi personali ancora in chiaro** — un archivio di prima
/// dell'aggiornamento — li cifra, li scrive nelle colonne cifrate e svuota
/// quelle in chiaro, senza far crescere la versione (ADR-0160, decisione 4).
/// Se quella scrittura non riesce, il profilo si legge lo stesso e il
/// tentativo si ripete la volta dopo.
///
/// # Errori
///
/// Restituisce un errore se la lettura dell'archivio non riesce.
pub fn load(database: &Database) -> ServiceResult<Option<LoadedProfile>> {
    // LA CONVERSIONE DEI VALORI DI PRIMA: la fa l'archivio, con la cifratura
    // di qui. Se non riesce ora, si riprova alla prossima lettura, e intanto
    // il profilo si legge con i valori di prima.
    let cifra = |testo: &str| dpapi::protect(testo.as_bytes()).ok();
    match database.protect_plain_profile_fields(&cifra) {
        Ok(PlainConversion::NotNow) => tracing::warn!(
            "campi personali del profilo non ancora cifrati: si riprova alla prossima lettura"
        ),
        Err(errore) => tracing::warn!(
            errore = %errore,
            "campi personali del profilo non ancora cifrati: si riprova alla prossima lettura"
        ),
        Ok(PlainConversion::NothingToDo | PlainConversion::Converted(_)) => {}
    }

    let Some(mut profile) = database.report_profile()? else {
        return Ok(None);
    };
    let in_chiaro = profile.signer_name.is_some()
        || profile.signer_role.is_some()
        || profile.header_line.is_some();
    if in_chiaro {
        // La conversione e' rimandata: i valori in chiaro appena letti sono
        // quelli dell'operatore, e si mostrano.
        return Ok(Some(LoadedProfile {
            profile,
            unreadable: Vec::new(),
        }));
    }

    let protected = database.report_profile_protected()?.unwrap_or_default();
    let mut unreadable = Vec::new();
    profile.signer_name = open(
        protected.signer_name.as_deref(),
        SIGNER_NAME,
        &mut unreadable,
    );
    profile.signer_role = open(
        protected.signer_role.as_deref(),
        SIGNER_ROLE,
        &mut unreadable,
    );
    profile.header_line = open(
        protected.header_line.as_deref(),
        HEADER_LINE,
        &mut unreadable,
    );
    Ok(Some(LoadedProfile {
        profile,
        unreadable,
    }))
}

/// Conserva il profilo: i campi personali cifrati, gli altri come sono.
///
/// Restituisce la versione assegnata dall'archivio.
///
/// # Errori
///
/// Restituisce un errore se la cifratura non riesce — in quel caso non si
/// scrive nulla, perché il chiaro non entra nell'archivio — o se la scrittura
/// non riesce.
pub fn save(
    database: &Database,
    profile: &ReportTemplateProfile,
    actor: &Actor,
    now: Timestamp,
) -> ServiceResult<u32> {
    let protected = protect_fields(profile)?;
    let mut senza_personali = profile.clone();
    senza_personali.signer_name = None;
    senza_personali.signer_role = None;
    senza_personali.header_line = None;
    Ok(database.save_report_profile(&senza_personali, &protected, actor, now)?)
}

/// Cifra i tre campi personali del profilo.
fn protect_fields(profile: &ReportTemplateProfile) -> ServiceResult<ProtectedProfileFields> {
    let cifra = |campo: Option<&TemplateField>| -> ServiceResult<Option<Vec<u8>>> {
        campo
            .map(|valore| dpapi::protect(valore.as_str().as_bytes()))
            .transpose()
            .map_err(crate::error::ServiceError::from)
    };
    Ok(ProtectedProfileFields {
        signer_name: cifra(profile.signer_name.as_ref())?,
        signer_role: cifra(profile.signer_role.as_ref())?,
        header_line: cifra(profile.header_line.as_ref())?,
    })
}

/// Decifra un campo, o lo segna come non apribile su questa postazione.
fn open(
    cifrato: Option<&[u8]>,
    nome: &'static str,
    unreadable: &mut Vec<&'static str>,
) -> Option<TemplateField> {
    let byte = cifrato?;
    let aperto = dpapi::unprotect(byte)
        .ok()
        .and_then(|chiaro| String::from_utf8(chiaro).ok())
        .and_then(|testo| TemplateField::try_new(&testo).ok());
    if aperto.is_none() {
        unreadable.push(nome);
    }
    aperto
}

#[cfg(test)]
mod tests {
    use lisi_core::Timestamp;
    use lisi_core::model::report_template::{ReportTemplateProfile, TemplateField};
    use lisi_core::text::Actor;
    use lisi_storage::repository::report::ProtectedProfileFields;

    use super::{HEADER_LINE, SIGNER_NAME, load, save};

    const FIRMATARIO: &str = "Mario PROVAFIRMA";
    const QUALIFICA: &str = "Ispettore di prova";
    const RECAPITI: &str = "Via Sintetica 1, telefono 000 000000";

    fn attore() -> Actor {
        let Ok(attore) = Actor::try_new("operatore.prova") else {
            panic!("attore di prova");
        };
        attore
    }

    fn adesso() -> Timestamp {
        Timestamp::from_millis(1_700_000_000_000)
    }

    /// **Il nome di chi firma non è nel file dell'archivio, e si rilegge
    /// uguale** (OPERATOR-DPAPI-01, criterio 1).
    ///
    /// L'archivio si chiude prima di leggerne i byte: chiudendolo, SQLite
    /// riversa il giornale nel file.
    #[cfg(windows)]
    #[test]
    fn i_campi_personali_non_sono_in_chiaro_nel_file_e_si_rileggono() {
        let Ok(cartella) = tempfile::tempdir() else {
            panic!("cartella temporanea");
        };
        let percorso = cartella.path().join("archivio.sqlite3");
        {
            let Ok(database) = lisi_storage::Database::open(&percorso) else {
                panic!("l'archivio di prova deve aprirsi");
            };
            let campo = |valore: &str| TemplateField::try_new(valore).ok();
            let profilo = ReportTemplateProfile {
                organisation: campo("Ente di prova"),
                signer_name: campo(FIRMATARIO),
                signer_role: campo(QUALIFICA),
                header_line: campo(RECAPITI),
                ..ReportTemplateProfile::default()
            };
            let Ok(versione) = save(&database, &profilo, &attore(), adesso()) else {
                panic!("il profilo deve salvarsi");
            };
            assert_eq!(versione, 1);
        }

        let mut byte = std::fs::read(&percorso).unwrap_or_default();
        byte.extend(
            std::fs::read(cartella.path().join("archivio.sqlite3-wal")).unwrap_or_default(),
        );
        let contiene = |ago: &str| {
            byte.windows(ago.len())
                .any(|finestra| finestra == ago.as_bytes())
        };
        for valore in [FIRMATARIO, QUALIFICA, RECAPITI] {
            assert!(
                !contiene(valore),
                "«{valore}» è in chiaro nel file dell'archivio"
            );
        }
        assert!(
            contiene("Ente di prova"),
            "la prova non sta guardando i byte giusti"
        );

        let Ok(database) = lisi_storage::Database::open(&percorso) else {
            panic!("l'archivio di prova deve riaprirsi");
        };
        let Ok(Some(letto)) = load(&database) else {
            panic!("il profilo deve leggersi");
        };
        assert!(letto.unreadable.is_empty(), "{:?}", letto.unreadable);
        assert_eq!(
            letto
                .profile
                .signer_name
                .as_ref()
                .map(TemplateField::as_str),
            Some(FIRMATARIO)
        );
        assert_eq!(
            letto
                .profile
                .signer_role
                .as_ref()
                .map(TemplateField::as_str),
            Some(QUALIFICA)
        );
        assert_eq!(
            letto
                .profile
                .header_line
                .as_ref()
                .map(TemplateField::as_str),
            Some(RECAPITI)
        );
        assert_eq!(
            letto.profile.version, 1,
            "la lettura ha fatto crescere la versione"
        );
    }

    /// **Il profilo si legge e si scrive soltanto da qui** (criterio 4).
    ///
    /// Un secondo punto che leggesse l'archivio direttamente vedrebbe i campi
    /// personali vuoti, e uno che scrivesse direttamente dovrebbe cifrare da
    /// sé: la guardia guarda il codice di produzione dei servizi e
    /// dell'interfaccia.
    #[test]
    fn il_profilo_si_legge_e_si_scrive_soltanto_da_qui() {
        let Some(crate_dir) = option_env!("CARGO_MANIFEST_DIR") else {
            panic!("la guardia legge i sorgenti: serve la cartella della crate");
        };
        let Some(crates) = std::path::Path::new(crate_dir).parent() else {
            panic!("la cartella delle crate non si trova");
        };
        let mut punti = Vec::new();
        let mut guardati = 0_usize;
        for crate_nome in ["lisi-services", "lisi-app"] {
            let Ok(voci) = std::fs::read_dir(crates.join(crate_nome).join("src")) else {
                panic!("i sorgenti di «{crate_nome}» non si leggono");
            };
            for voce in voci.flatten() {
                let percorso = voce.path();
                if percorso.extension().is_none_or(|ext| ext != "rs")
                    || percorso
                        .file_name()
                        .is_some_and(|nome| nome == "report_profile.rs")
                {
                    continue;
                }
                let Ok(testo) = std::fs::read_to_string(&percorso) else {
                    continue;
                };
                guardati += 1;
                let produzione = testo
                    .split_once("\n#[cfg(test)]")
                    .map_or(testo.as_str(), |(prima, _)| prima);
                for chiamata in [
                    ".report_profile()",
                    ".save_report_profile(",
                    ".report_profile_protected(",
                ] {
                    if produzione.contains(chiamata) {
                        punti.push(format!("{} usa {chiamata}", percorso.display()));
                    }
                }
            }
        }
        assert!(
            guardati > 50,
            "la guardia non ha guardato abbastanza sorgenti: {guardati}"
        );
        assert!(
            punti.is_empty(),
            "il profilo si legge o si scrive fuori da report_profile: {punti:#?}"
        );
    }

    /// **Un campo cifrato per un altro utente non si inventa: si legge vuoto e
    /// si dice** (criterio 3).
    ///
    /// Si simula con byte che DPAPI non apre: è ciò che vede un altro utente,
    /// o un'altra postazione, davanti a un valore cifrato altrove.
    #[test]
    fn un_campo_che_non_si_apre_si_legge_vuoto_e_si_dice() {
        let Ok(database) = crate::sources::open_in_memory_database() else {
            panic!("archivio in memoria");
        };
        let estranei = ProtectedProfileFields {
            signer_name: Some(vec![0x42; 64]),
            signer_role: None,
            header_line: Some(vec![0x17; 32]),
        };
        let Ok(_) = database.save_report_profile(
            &ReportTemplateProfile::default(),
            &estranei,
            &attore(),
            adesso(),
        ) else {
            panic!("il profilo deve salvarsi");
        };
        let Ok(Some(letto)) = load(&database) else {
            panic!("il profilo deve leggersi anche se un campo non si apre");
        };
        assert!(letto.profile.signer_name.is_none());
        assert!(letto.profile.header_line.is_none());
        assert_eq!(letto.unreadable, vec![SIGNER_NAME, HEADER_LINE]);
        let frase = letto.unreadable_message();
        assert!(frase.contains("altro utente Windows"), "{frase}");
        assert!(frase.contains("Vanno reinseriti"), "{frase}");
    }
}
