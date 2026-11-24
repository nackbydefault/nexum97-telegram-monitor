//! I marcatori della copia pubblica sono in coppia (PUBLIC-SOURCE-BASELINE-01,
//! ADR-0210, DEC-522).
//!
//! Nei sorgenti dell'archivio le parti che non vanno nella copia pubblica stanno
//! fra i marcatori «archivio-interno» di apertura e di chiusura; quelle che
//! esistono soltanto nella copia pubblica, commentate, fra i marcatori
//! «pubblico». Lo script di esportazione toglie le prime e scommenta le
//! seconde, e si ferma se una coppia non torna. Questa guardia lo dice prima,
//! nelle prove dell'archivio.
//!
//! Nella copia pubblica i marcatori non ci sono più: la guardia controlla che non
//! ne sia rimasto nessuno a metà. Le stringhe dei marcatori qui si compongono a
//! pezzi, perché questo file non ne contenga uno intero: l'esportazione
//! rifiuta una copia in cui ne resta anche uno.

#[cfg(test)]
mod tests {
    use std::path::{Path, PathBuf};

    const ARCHIVIO: &str = concat!("<", "archivio-interno", ">");
    const FINE_ARCHIVIO: &str = concat!("</", "archivio-interno", ">");
    const PUBBLICO: &str = concat!("<", "pubblico", ">");
    const FINE_PUBBLICO: &str = concat!("</", "pubblico", ">");

    /// Che cosa non torna in un testo, oppure quanti blocchi ha.
    fn controlla(testo: &str, commento: &str) -> Result<usize, String> {
        let apri_archivio = format!("{commento} {ARCHIVIO}");
        let chiudi_archivio = format!("{commento} {FINE_ARCHIVIO}");
        let apri_pubblico = format!("{commento} {PUBBLICO}");
        let chiudi_pubblico = format!("{commento} {FINE_PUBBLICO}");
        let mut stato = "normale";
        let mut blocchi = 0;
        for (indice, riga) in testo.lines().enumerate() {
            let numero = indice + 1;
            let pulita = riga.trim();
            if pulita == apri_archivio || pulita == apri_pubblico {
                if stato != "normale" {
                    return Err(format!("riga {numero}: marcatore annidato"));
                }
                stato = if pulita == apri_archivio {
                    "archivio"
                } else {
                    "pubblico"
                };
                continue;
            }
            if pulita == chiudi_archivio || pulita == chiudi_pubblico {
                let atteso = if pulita == chiudi_archivio {
                    "archivio"
                } else {
                    "pubblico"
                };
                if stato != atteso {
                    return Err(format!("riga {numero}: chiusura senza apertura"));
                }
                stato = "normale";
                blocchi += 1;
                continue;
            }
            if stato == "pubblico" && !pulita.is_empty() && !pulita.starts_with(commento) {
                return Err(format!(
                    "riga {numero}: una riga di un blocco pubblico non è commentata"
                ));
            }
        }
        if stato != "normale" {
            return Err(String::from("un blocco non si chiude"));
        }
        Ok(blocchi)
    }

    fn radice() -> PathBuf {
        let Some(radice) = Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .and_then(Path::parent)
        else {
            panic!("la radice del workspace deve trovarsi");
        };
        radice.to_path_buf()
    }

    fn sorgenti(cartella: &Path, trovati: &mut Vec<PathBuf>) {
        let Ok(voci) = std::fs::read_dir(cartella) else {
            return;
        };
        for voce in voci.flatten() {
            let percorso = voce.path();
            if percorso.is_dir() {
                sorgenti(&percorso, trovati);
            } else if percorso
                .extension()
                .is_some_and(|e| e == "rs" || e == "slint")
            {
                trovati.push(percorso);
            }
        }
    }

    /// **Ogni marcatore dei sorgenti e del manifest è in coppia.**
    #[test]
    fn ogni_marcatore_e_in_coppia() {
        let radice = radice();
        let mut file = Vec::new();
        sorgenti(&radice.join("crates"), &mut file);
        assert!(
            file.len() > 300,
            "letti {} sorgenti: la guardia non ha guardato nulla",
            file.len()
        );
        for percorso in &file {
            let Ok(testo) = std::fs::read_to_string(percorso) else {
                panic!("«{}» non si legge", percorso.display());
            };
            if let Err(difetto) = controlla(&testo, "//") {
                panic!("{}: {difetto}", percorso.display());
            }
        }
        let manifest = radice.join("Cargo.toml");
        let Ok(testo) = std::fs::read_to_string(&manifest) else {
            panic!("il manifest del workspace non si legge");
        };
        if let Err(difetto) = controlla(&testo, "#") {
            panic!("Cargo.toml: {difetto}");
        }
    }

    /// **La guardia riconosce una coppia che non torna** (prova negativa).
    #[test]
    fn una_coppia_che_non_torna_si_vede() {
        let a = format!("// {ARCHIVIO}");
        let fa = format!("// {FINE_ARCHIVIO}");
        let p = format!("// {PUBBLICO}");
        let fp = format!("// {FINE_PUBBLICO}");
        assert_eq!(controlla(&format!("x\n{a}\ny\n{fa}\nz\n"), "//"), Ok(1));
        assert!(controlla(&format!("{a}\ny\n"), "//").is_err());
        assert!(controlla(&format!("y\n{fa}\n"), "//").is_err());
        assert!(controlla(&format!("{a}\n{p}\n{fp}\n{fa}\n"), "//").is_err());
        assert!(controlla(&format!("{p}\nconst X: u8 = 1;\n{fp}\n"), "//").is_err());
        assert_eq!(
            controlla(&format!("{p}\n// const X: u8 = 1;\n{fp}\n"), "//"),
            Ok(1)
        );
        assert!(controlla(&format!("# {ARCHIVIO}\n\"x\",\n"), "#").is_err());
    }
}
