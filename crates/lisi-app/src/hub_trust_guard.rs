//! Fissa la decisione 3 di ADR-0082: **la verifica TLS non ha una chiave di
//! scorta**, né nel prodotto né nelle prove.
//!
//! # Perché esiste prima del trasporto
//!
//! Il trasporto dell'Hub non esiste ancora (HUB-TLS-01). Una guardia scritta
//! **dopo** arriverebbe quando la riga «provvisoria» è già lì, e verrebbe
//! scritta attorno a lei. Scritta prima, è la riga provvisoria a dover passare
//! di qui.
//!
//! # Che cosa cerca, e perché anche nelle prove
//!
//! I gesti con cui, nelle pile TLS più probabili, si **sospende** la verifica
//! del certificato. Li cerca **in tutti i sorgenti delle crate, prove comprese**:
//! un indebolimento che esiste solo nelle prove è un indebolimento che esiste
//! (ADR-0069, ADR-0081).
//!
//! Alcuni gesti **si possono** usare legittimamente — una validazione manuale
//! richiede di sospendere quella predefinita — ma solo nella stessa funzione
//! che confronta l'impronta dell'Hub. Chi ne ha bisogno entra nell'elenco
//! `CHI_PUO_SOSPENDERE`, che da HUB-TLS-01 contiene **un file solo** — il
//! verificatore del trasporto dell'Hub — e la modifica si vede.
//!
//! # Il limite, dichiarato
//!
//! La guardia legge del testo: una sospensione scritta in una forma che
//! l'elenco non nomina le sfugge. HUB-TLS-01 ha riletto l'elenco contro la pila
//! scelta, rustls: un solo gesto spostato, nessuno allargato per far passare una riga.
//!
//! Il modulo non contribuisce al binario: è interamente sotto `cfg(test)`.

#[cfg(test)]
mod tests {
    use std::path::{Path, PathBuf};

    /// Gesti che fanno accettare un certificato **senza alcuna verifica**.
    ///
    /// Nessuno li può usare: non c'è un elenco di autorizzati.
    const ACCETTARE_TUTTO: &[&str] = &[
        // reqwest, native-tls
        "danger_accept_invalid_certs",
        "danger_accept_invalid_hostnames",
        // rustls: i nomi usuali dei verificatori che accettano tutto. Il ramo
        // delle configurazioni pericolose stava qui fino a HUB-TLS-01: con le
        // chiavi nude è l'UNICO modo di installare il confronto dell'impronta,
        // e ADR-0083 decisione 4 lo ha spostato fra i gesti che sospendono.
        "NoCertificateVerification",
        "AcceptAnyServerCert",
        "AcceptAnyCert",
        // openssl
        "SslVerifyMode::NONE",
        // WinHTTP: i flag che ignorano autorita', nome, data o tutto
        "SECURITY_FLAG_IGNORE_",
    ];

    /// Gesti che **sospendono** la validazione predefinita per farne una
    /// manuale (SChannel).
    ///
    /// Leciti solo accanto al confronto dell'impronta dell'Hub (ADR-0082,
    /// decisione 3), e solo in un file scritto in `CHI_PUO_SOSPENDERE`.
    const SOSPENDERE: &[&str] = &[
        // SChannel
        "ISC_REQ_MANUAL_CRED_VALIDATION",
        "SCH_CRED_MANUAL_CRED_VALIDATION",
        // rustls: il solo modo di installare un verificatore proprio
        ".dangerous()",
    ];

    /// Chi può sospendere la validazione predefinita.
    ///
    /// **Un file solo**, scritto da HUB-TLS-01 (ADR-0083, decisione 4): il
    /// verificatore del trasporto dell'Hub, dove la sospensione sta accanto al
    /// confronto dell'impronta e alla verifica della firma. Questa riga è la
    /// cosa da rileggere.
    const CHI_PUO_SOSPENDERE: [&str; 1] = ["lisi-hub-transport/src/verifier.rs"];

    /// Ciò che il file autorizzato deve contenere **insieme** alla sospensione.
    ///
    /// Un nome nell'elenco è un'autorizzazione a sospendere **per confrontare**:
    /// se il confronto o la firma sparissero dal file, l'autorizzazione
    /// resterebbe a coprire un verificatore che non verifica.
    const INSIEME_ALLA_SOSPENSIONE: &[&str] = &[
        // il confronto dell'impronta con ciò che la postazione sa dell'Hub
        "self.expected.accepts(",
        // la firma dell'handshake verificata con la chiave presentata
        "verify_tls13_signature_with_raw_key(",
        // il ramo che non deve accadere e non restituisce «valido»
        "PeerIncompatible::Tls12NotOffered",
    ];

    /// Questo file nomina i gesti per poterli cercare.
    const QUESTA_GUARDIA: &str = "lisi-app/src/hub_trust_guard.rs";

    fn radice_delle_crate() -> PathBuf {
        let percorso = Path::new(env!("CARGO_MANIFEST_DIR"));
        let Some(crates) = percorso.parent() else {
            panic!("la cartella delle crate deve esistere sopra questa crate");
        };
        crates.to_path_buf()
    }

    fn sorgenti(cartella: &Path, trovati: &mut Vec<PathBuf>) {
        let Ok(voci) = std::fs::read_dir(cartella) else {
            return;
        };
        for voce in voci.flatten() {
            let percorso = voce.path();
            if percorso.is_dir() {
                if percorso.file_name().is_some_and(|nome| nome == "target") {
                    continue;
                }
                sorgenti(&percorso, trovati);
            } else if percorso.extension().is_some_and(|ext| ext == "rs") {
                trovati.push(percorso);
            }
        }
    }

    /// Il percorso relativo alla radice, con un separatore uniforme.
    fn relativo(radice: &Path, percorso: &Path) -> Option<String> {
        let relativo = percorso.strip_prefix(radice).ok()?;
        Some(
            relativo
                .components()
                .map(|parte| parte.as_os_str().to_string_lossy())
                .collect::<Vec<_>>()
                .join("/"),
        )
    }

    /// I file del prodotto che contengono uno dei gesti, esclusa la guardia.
    fn chi_contiene(gesti: &[&str]) -> Vec<String> {
        let radice = radice_delle_crate();
        let mut file = Vec::new();
        sorgenti(&radice, &mut file);
        assert!(
            file.len() > 100,
            "trovati solo {} sorgenti: la guardia non sta percorrendo il prodotto",
            file.len()
        );

        let mut trovati = Vec::new();
        for percorso in file {
            let Some(nome) = relativo(&radice, &percorso) else {
                continue;
            };
            if nome == QUESTA_GUARDIA {
                continue;
            }
            let Ok(testo) = std::fs::read_to_string(&percorso) else {
                continue;
            };
            for gesto in gesti {
                if testo.contains(gesto) {
                    trovati.push(format!("{nome}: {gesto}"));
                }
            }
        }
        trovati
    }

    /// **Nessun punto del prodotto, prove comprese, accetta un certificato
    /// senza verificarlo.**
    #[test]
    fn nessun_verificatore_accetta_tutto() {
        let trovati = chi_contiene(ACCETTARE_TUTTO);
        assert!(
            trovati.is_empty(),
            "questi punti accettano un certificato senza verificarlo: {trovati:#?}. \
             Un gettone presentato su quel canale e' un gettone consegnato a \
             chiunque risponda (ADR-0082, decisione 3). Non esiste una versione \
             «solo per le prove»."
        );
    }

    /// **Sospendere la validazione predefinita è lecito solo dove si confronta
    /// l'impronta dell'Hub, e quel posto è uno solo.**
    #[test]
    fn sospendere_la_verifica_richiede_un_nome_nell_elenco() {
        let non_autorizzati: Vec<String> = chi_contiene(SOSPENDERE)
            .into_iter()
            .filter(|riga| {
                !CHI_PUO_SOSPENDERE
                    .iter()
                    .any(|autorizzato| riga.starts_with(&format!("{autorizzato}:")))
            })
            .collect();
        assert!(
            non_autorizzati.is_empty(),
            "questi punti sospendono la validazione TLS predefinita: \
             {non_autorizzati:#?}. E' lecito solo nella funzione che confronta \
             l'impronta dell'Hub, e quel modulo va scritto in \
             «CHI_PUO_SOSPENDERE», che esiste per essere letto (ADR-0082)."
        );
    }

    /// **Chi sospende, confronta** (ADR-0083, decisione 4).
    ///
    /// Il file autorizzato deve davvero sospendere — altrimenti il nome
    /// nell'elenco è un'autorizzazione orfana, pronta per il prossimo che la
    /// trova — e deve contenere il confronto dell'impronta, la verifica della
    /// firma e il rifiuto del ramo TLS 1.2. **I commenti non contano**: una
    /// guardia che legge la documentazione verifica ciò che il codice dice di
    /// fare, non ciò che fa (lezione di `no_ai_guard`).
    #[test]
    fn chi_sospende_confronta_l_impronta_e_verifica_la_firma() {
        let radice = radice_delle_crate();
        for autorizzato in CHI_PUO_SOSPENDERE {
            let Ok(testo) = std::fs::read_to_string(radice.join(autorizzato)) else {
                panic!(
                    "«{autorizzato}» e' nell'elenco di chi puo' sospendere ma non si \
                     legge: un'autorizzazione orfana va tolta, non lasciata"
                );
            };
            let codice: String = testo
                .lines()
                .filter(|riga| !riga.trim_start().starts_with("//"))
                .collect::<Vec<&str>>()
                .join("\n");

            assert!(
                SOSPENDERE.iter().any(|gesto| codice.contains(gesto)),
                "«{autorizzato}» e' autorizzato a sospendere ma non sospende: \
                 l'autorizzazione va tolta dall'elenco"
            );
            for necessario in INSIEME_ALLA_SOSPENSIONE {
                assert!(
                    codice.contains(necessario),
                    "«{autorizzato}» sospende la validazione predefinita senza \
                     «{necessario}»: un verificatore proprio che non confronta \
                     l'impronta, non verifica la firma o non rifiuta TLS 1.2 e' un \
                     verificatore che accetta (ADR-0083, decisione 4)"
                );
            }
        }
    }
}
