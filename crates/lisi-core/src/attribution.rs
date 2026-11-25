//! Attribuzione dei componenti di terze parti.
//!
//! L'elenco vive qui e non nel file di interfaccia perché per almeno un
//! componente l'attribuzione è una **condizione di licenza** e non una cortesia:
//! la licenza Slint Royalty-free 2.0 subordina la distribuzione alla presenza
//! dell'attribuzione in una schermata "Informazioni" raggiungibile dal menu di
//! primo livello. Un obbligo di conformità deve poter essere verificato da un
//! test, e un testo scritto a mano nel file `.slint` non lo sarebbe.
//!
//! Gli identificatori di licenza sono quelli dichiarati dai pacchetti e sono
//! stati letti da `cargo metadata`, non trascritti a memoria.
//!
//! Vedere `docs/adr/ADR-0005-SLINT-LICENSING.md` e
//! `docs/adr/ADR-0007-PRODUCT-LICENSE.md`.

/// Identificatore SPDX della licenza del prodotto.
///
/// Dal 2026-11-25 il prodotto è software libero con la Apache License 2.0
/// (ADR-0211, che sostituisce ADR-0007): il testo integrale è nel file
/// `LICENSE`, il copyright e le terze parti nel file `NOTICE`.
pub const PRODUCT_LICENSE: &str = "Apache-2.0";

/// Componente di terze parti incorporato nell'applicazione.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ThirdPartyComponent {
    /// Nome con cui il componente è conosciuto.
    pub name: &'static str,
    /// Versione incorporata.
    pub version: &'static str,
    /// Identificatore di licenza dichiarato dal componente.
    pub license: &'static str,
    /// Nota mostrata all'operatore.
    pub note: &'static str,
    /// Se l'attribuzione è una condizione della licenza e non una cortesia.
    ///
    /// Per i componenti così marcati la schermata "Informazioni e licenze" non
    /// è rimovibile senza violare la licenza.
    pub attribution_required: bool,
}

/// Componenti di terze parti incorporati nella build corrente.
pub const THIRD_PARTY_COMPONENTS: &[ThirdPartyComponent] = &[
    ThirdPartyComponent {
        name: "Slint",
        version: "1.17.1",
        license: "LicenseRef-Slint-Royalty-free-2.0",
        note: "Toolkit dell'interfaccia grafica. Distribuito con licenza multipla; \
               per questo prodotto è adottata la licenza royalty-free per applicazioni \
               desktop, che richiede la presente attribuzione.",
        attribution_required: true,
    },
    ThirdPartyComponent {
        name: "SQLite",
        version: "incorporato in libsqlite3-sys 0.38.1",
        license: "Public Domain",
        note: "Motore del database locale, compilato staticamente nell'applicazione.",
        attribution_required: false,
    },
    ThirdPartyComponent {
        name: "regex",
        version: "1.13.1",
        license: "MIT OR Apache-2.0",
        note: "Le espressioni regolari dei dizionari (DICT-REGEX-01, ADR-0187): un motore \
               senza ritorni all'indietro, in tempo lineare per costruzione, compilato con un \
               tetto di memoria. Porta con sé regex-automata, regex-syntax, aho-corasick e \
               memchr: le loro licenze sono elencate in NOTICE.md.",
        attribution_required: false,
    },
    ThirdPartyComponent {
        name: "rusqlite",
        version: "0.40.1",
        license: "MIT",
        note: "Interfaccia Rust verso SQLite.",
        attribution_required: false,
    },
    ThirdPartyComponent {
        name: "RustCrypto sha2",
        version: "0.11.0",
        license: "MIT OR Apache-2.0",
        note: "Calcolo delle impronte SHA-256.",
        attribution_required: false,
    },
    ThirdPartyComponent {
        name: "RustCrypto argon2",
        version: "0.6.0",
        license: "MIT OR Apache-2.0",
        note: "Argon2id per le frasi di accesso delle persone. Una funzione LENTA APPOSTA: il \
               gettone di un dispositivo è casuale a 256 bit e un'impronta veloce basta, una \
               frase scelta da una persona non lo è (TEAM-ASSIGN-01, ADR-0097).",
        attribution_required: false,
    },
    ThirdPartyComponent {
        name: "RustCrypto aes-gcm",
        version: "0.11.1",
        license: "Apache-2.0 OR MIT",
        note: "AES-256-GCM per la copia cifrata dell'archivio (ENCRYPT-01, ADR-0175): la chiave \
               della copia avvolta dalla frase e i blocchi del contenuto.",
        attribution_required: false,
    },
    ThirdPartyComponent {
        name: "zeroize",
        version: "1.9.0",
        license: "Apache-2.0 OR MIT",
        note: "Azzera in memoria la chiave e la frase derivata di una copia cifrata quando non \
               servono più (ENCRYPT-01, ADR-0175).",
        attribution_required: false,
    },
    ThirdPartyComponent {
        name: "thiserror",
        version: "2.0.19",
        license: "MIT OR Apache-2.0",
        note: "Definizione degli errori tipizzati.",
        attribution_required: false,
    },
    ThirdPartyComponent {
        name: "tracing",
        version: "0.1.44",
        license: "MIT",
        note: "Registrazione degli eventi applicativi su file locale.",
        attribution_required: false,
    },
    ThirdPartyComponent {
        name: "tracing-appender",
        version: "0.2.5",
        license: "MIT",
        note: "Scrittura del registro applicativo su file con rotazione.",
        attribution_required: false,
    },
    ThirdPartyComponent {
        name: "tracing-subscriber",
        version: "0.3.23",
        license: "MIT",
        note: "Filtro e formattazione degli eventi registrati.",
        attribution_required: false,
    },
    ThirdPartyComponent {
        name: "serde",
        version: "1.0.229",
        license: "MIT OR Apache-2.0",
        note: "Struttura del formato di scambio dei dizionari.",
        attribution_required: false,
    },
    ThirdPartyComponent {
        name: "serde_json",
        version: "1.0.151",
        license: "MIT OR Apache-2.0",
        note: "Lettura e scrittura dei file JSON dei dizionari.",
        attribution_required: false,
    },
    ThirdPartyComponent {
        name: "unicode-normalization",
        version: "0.1.25",
        license: "MIT OR Apache-2.0",
        note: "Forma Unicode NFC, applicata prima del confronto fra termini.",
        attribution_required: false,
    },
    // I due caratteri sono incorporati nell'eseguibile, non installati sulla
    // postazione: la SIL Open Font License chiede che la nota di copyright e il
    // testo della licenza siano distribuiti **con** il carattere, e per un
    // carattere incorporato quel «con» e' il prodotto. Da qui
    // `attribution_required: true`.
    ThirdPartyComponent {
        name: "Sora",
        version: "variabile sull'asse wght",
        license: "OFL-1.1",
        note: "Carattere dell'interfaccia, incorporato nell'eseguibile. Porta la lingua: \
               titoli, testo e voci di menu. Il testo integrale della licenza è \
               distribuito con l'applicazione.",
        attribution_required: true,
    },
    ThirdPartyComponent {
        name: "IBM Plex Mono",
        version: "2.005",
        license: "OFL-1.1",
        note: "Carattere monospaziato, incorporato nell'eseguibile. Porta ciò che ha \
               prodotto una macchina: orari, contatori, identificativi e codici di \
               livello. Il testo integrale della licenza è distribuito con \
               l'applicazione.",
        attribution_required: true,
    },
    ThirdPartyComponent {
        name: "windows-sys",
        version: "0.61.2",
        license: "MIT OR Apache-2.0",
        note: "Dichiarazioni delle API di Windows usate per la protezione locale \
               dei segreti e per la generazione di casualità.",
        attribution_required: false,
    },
    ThirdPartyComponent {
        name: "zip",
        version: "9.3.0",
        license: "MIT",
        note: "Chiusura nel pacchetto delle parti della relazione .docx, che il \
               prodotto scrive da sé dal 2026-11-04 (ADR-0180, al posto di \
               docx-rs), e del registro .xlsx attraverso rust_xlsxwriter. Usata \
               soltanto in scrittura: il prodotto non legge archivi. Porta con \
               sé zopfli, typed-path, bumpalo e zlib-rs: le loro licenze sono \
               elencate in NOTICE.md.",
        attribution_required: false,
    },
    ThirdPartyComponent {
        name: "flate2",
        version: "1.1.9",
        license: "MIT OR Apache-2.0",
        note: "Decompressione dei file .json.gz di NVD scaricati dal programma (SNAP-NET-01, \
               ADR-0186): soltanto gzip, su file, entro la misura dichiarata dal .meta. Era già \
               compilata nel prodotto attraverso lopdf.",
        attribution_required: false,
    },
    ThirdPartyComponent {
        name: "lopdf",
        version: "0.44.0",
        license: "MIT",
        note: "Scrittura della relazione e dell'allegato tecnico in formato .pdf. Adottata con \
               ADR-0034 DOPO aver scartato printpdf, che scrive l'identificativo del documento con \
               due stringhe casuali e non permette di fissarlo: con quella un PDF deterministico \
               non è producibile. Costruisce oggetti PDF e non impagina: l'impaginazione è \
               codice del prodotto.",
        attribution_required: false,
    },
    ThirdPartyComponent {
        name: "png",
        version: "0.18.1",
        license: "MIT OR Apache-2.0",
        note: "Scrittura della figura del grafo delle prove, che entra nei \
               documenti come immagine. Adottata con ADR-0056, e non aggiunge \
               codice al programma: era già nel file di blocco come dipendenza \
               transitiva di Slint. L'alternativa era scrivere il formato a \
               mano — un PNG ammette blocchi deflate memorizzati — ed è stata \
               scartata: un codificatore di formato scritto in casa è codice \
               nuovo che nessuno ha esercitato, dentro un prodotto che produce \
               atti, e se sbaglia sbaglia in silenzio.",
        attribution_required: false,
    },
    ThirdPartyComponent {
        name: "uuid",
        version: "1.24.0",
        license: "Apache-2.0 OR MIT",
        note: "Calcolo degli identificativi STIX 2.1, che lo standard vuole \
               deterministici e costruiti su un UUID versione 5. Adottata con \
               ADR-0057, con la sola feature `v5` accesa. Era già nel file di \
               blocco come dipendenza transitiva di accesskit; porta con sé \
               `sha1_smol`, che è l'unico pacchetto nuovo di quella milestone. \
               Una primitiva crittografica scritta in casa sarebbe stata codice \
               nuovo che nessuno ha esercitato, dentro un prodotto che produce \
               atti.",
        attribution_required: false,
    },
    ThirdPartyComponent {
        name: "sha1_smol",
        version: "1.0.1",
        license: "BSD-3-Clause",
        note: "Impronta SHA-1, richiesta dall'UUID versione 5 degli \
               identificativi STIX. Arriva con `uuid` e non ha dipendenze \
               proprie. SHA-1 è qui una funzione di derivazione di \
               identificativi imposta dallo standard, NON una garanzia di \
               integrità: le impronte dei documenti di questo prodotto sono \
               SHA-256.",
        attribution_required: false,
    },
    ThirdPartyComponent {
        name: "rust_xlsxwriter",
        version: "0.102.0",
        license: "MIT OR Apache-2.0",
        note: "Scrittura del registro analitico in formato .xlsx. Adottata con \
               ADR-0033, dopo le sette prove che ADR-0031 pretendeva. NON porta \
               con sé alcun crate nuovo: la sua unica dipendenza è zip, la \
               stessa che chiude il pacchetto .docx.",
        attribution_required: false,
    },
    // I tre che seguono non sono crate Rust: sono **librerie native
    // ridistribuite** dentro l'installer. Compaiono qui da quando l'MSI le
    // contiene, e non prima: finché non venivano distribuite non c'era nulla da
    // attribuire. Le versioni e le licenze vengono da `tdlib.lock.json`, che le
    // registra dalla build reale e non da una fonte trascritta a mano.
    ThirdPartyComponent {
        name: "TDLib",
        version: "1.8.66",
        license: "BSL-1.0",
        note: "Libreria ufficiale di Telegram, l'unica via per accedere alla \
               piattaforma. Compilata da sorgente dal commit fissato in \
               tdlib.lock.json: TDLib non pubblica binari ufficiali.",
        attribution_required: false,
    },
    ThirdPartyComponent {
        name: "OpenSSL",
        version: "3.6.3",
        license: "Apache-2.0",
        note: "Dipendenza nativa di TDLib per la crittografia di trasporto. \
               Le sue vulnerabilità vanno seguite fuori dagli strumenti Rust: \
               cargo audit non ispeziona una DLL C.",
        attribution_required: false,
    },
    ThirdPartyComponent {
        name: "zlib",
        version: "1.3.2",
        license: "Zlib",
        note: "Dipendenza nativa di TDLib per la compressione. Sul triplet \
               x64-windows il file si chiama z.dll, non zlib1.dll.",
        attribution_required: false,
    },
    ThirdPartyComponent {
        name: "libloading",
        version: "0.8.9",
        license: "ISC",
        note: "Caricamento esplicito della libreria TDLib. Presente soltanto nelle \
               build con il proof of concept abilitato.",
        attribution_required: false,
    },
    ThirdPartyComponent {
        name: "rustls",
        version: "0.23.46",
        license: "Apache-2.0 OR ISC OR MIT",
        note: "Unica pila TLS del prodotto, usata dal collegamento fra postazione e \
               Hub: solo TLS 1.3, con la chiave pubblica nuda dell'Hub. Entra nel \
               binario dal 2026-09-20, quando la modalità client ha aperto quel \
               collegamento. Ognuna delle tre licenze chiede che la nota di \
               copyright accompagni le copie.",
        attribution_required: true,
    },
    ThirdPartyComponent {
        name: "ring",
        version: "0.17.14",
        license: "Apache-2.0 AND ISC",
        note: "Provider crittografico di rustls. Entra nel binario per la stessa \
               ragione, e la ISC chiede che la nota di copyright accompagni le copie.",
        attribution_required: true,
    },
];

/// Dipendenze dirette che **non** compaiono nell'elenco, e perché.
///
/// Serve al test che impedisce all'elenco di divergere dai manifest: una
/// dipendenza assente dev'essere assente **di proposito**, non per
/// dimenticanza. Aggiungere un nome qui è una decisione da motivare.
#[cfg(test)]
const NOT_DISTRIBUTED: &[(&str, &str)] = &[
    (
        "slint-build",
        "agisce a tempo di compilazione e non entra nel binario distribuito",
    ),
    (
        "rspolib",
        "legge il catalogo delle traduzioni a tempo di compilazione e non entra nel binario \
         distribuito",
    ),
    // rustls e ring NON sono più qui: dal 2026-09-20 (TEAM-CLIENT-01,
    // ADR-0091) `lisi-services` usa il trasporto dell'Hub, quindi entrano nel
    // binario consegnato e sono attribuiti fra i componenti. La prova che lo ha
    // chiesto — `no_ai_guard` — è stata vista diventare rossa quel giorno.
];

/// Componenti per i quali l'attribuzione è una condizione di licenza.
pub fn components_requiring_attribution() -> impl Iterator<Item = &'static ThirdPartyComponent> {
    THIRD_PARTY_COMPONENTS
        .iter()
        .filter(|component| component.attribution_required)
}

#[cfg(test)]
mod tests {
    use super::{PRODUCT_LICENSE, THIRD_PARTY_COMPONENTS, components_requiring_attribution};

    #[test]
    fn slint_is_listed_because_its_licence_requires_the_attribution() {
        let slint = THIRD_PARTY_COMPONENTS
            .iter()
            .find(|component| component.name == "Slint");

        let Some(slint) = slint else {
            panic!(
                "l'attribuzione di Slint e' una condizione della licenza \
                 royalty-free: rimuoverla dall'elenco viola la licenza"
            );
        };
        assert!(slint.attribution_required);
        assert_eq!(slint.license, "LicenseRef-Slint-Royalty-free-2.0");
    }

    // Il documento della catena di fornitura sta soltanto nell'archivio
    // (ADR-0210): le due prove che lo leggono non sono nella copia pubblica.

    #[test]
    fn at_least_one_component_requires_the_attribution_screen() {
        // Se questo test cadesse a zero, la schermata "Informazioni e licenze"
        // diventerebbe facoltativa. Finche' resta positivo, non lo e'.
        assert!(components_requiring_attribution().count() >= 1);
    }

    #[test]
    fn no_component_is_declared_without_a_licence() {
        for component in THIRD_PARTY_COMPONENTS {
            assert!(
                !component.license.trim().is_empty(),
                "il componente {} non dichiara una licenza",
                component.name
            );
            assert!(!component.name.trim().is_empty());
            assert!(!component.version.trim().is_empty());
            assert!(!component.note.trim().is_empty());
        }
    }

    /// **La licenza del prodotto è la Apache 2.0, e il file LICENSE ne porta il
    /// testo ufficiale** (ADR-0211). Fino al 2026-11-24 questa prova chiedeva
    /// l'identificatore proprietario di ADR-0007, sostituito.
    #[test]
    fn la_licenza_del_prodotto_e_la_apache_2_0() {
        const LICENSE: &str = include_str!("../../../LICENSE");
        const MANIFEST: &str = include_str!("../../../Cargo.toml");
        assert_eq!(PRODUCT_LICENSE, "Apache-2.0");
        assert!(LICENSE.contains("Apache License"));
        assert!(LICENSE.contains("Version 2.0, January 2004"));
        assert!(LICENSE.contains("END OF TERMS AND CONDITIONS"));
        assert!(MANIFEST.contains("license = \"Apache-2.0\""));
        assert!(!MANIFEST.contains("LicenseRef-LISI-Proprietary"));
    }

    /// Nomi delle dipendenze dirette dichiarate nei manifest del workspace.
    ///
    /// I manifest sono inclusi nel binario di test con `include_str!`: il
    /// controllo confronta l'elenco con la **fonte**, non con una copia
    /// aggiornata a mano che avrebbe lo stesso difetto che deve prevenire.
    fn declared_dependencies() -> Vec<String> {
        const MANIFESTS: &[&str] = &[
            include_str!("../../../Cargo.toml"),
            include_str!("../../lisi-security/Cargo.toml"),
            include_str!("../../lisi-telegram/Cargo.toml"),
        ];

        let mut names = Vec::new();
        for manifest in MANIFESTS {
            let mut in_dependencies = false;
            for line in manifest.lines() {
                let trimmed = line.trim();

                if trimmed.starts_with('[') {
                    // Le sezioni di sviluppo non entrano nel prodotto
                    // distribuito e non richiedono attribuzione.
                    in_dependencies = trimmed.contains("dependencies")
                        && !trimmed.contains("dev-dependencies")
                        && !trimmed.contains("build-dependencies");
                    continue;
                }
                if !in_dependencies || trimmed.is_empty() || trimmed.starts_with('#') {
                    continue;
                }

                let Some((key, _)) = trimmed.split_once('=') else {
                    continue;
                };
                // Due forme convivono nei manifest: `nome = { … }` e
                // `nome.workspace = true`. Il nome di un pacchetto non contiene
                // punti, quindi il primo segmento è sempre il nome.
                let name = key
                    .trim()
                    .trim_matches('"')
                    .split('.')
                    .next()
                    .unwrap_or_default()
                    .trim();

                // I crate del workspace non sono componenti di terze parti.
                if name.starts_with("lisi-") || name.is_empty() {
                    continue;
                }
                if !names.iter().any(|existing| existing == name) {
                    names.push(name.to_owned());
                }
            }
        }
        names
    }

    #[test]
    fn every_direct_dependency_is_either_attributed_or_declared_as_not_distributed() {
        // Il difetto che questo test previene e' gia' accaduto: `serde`,
        // `serde_json` e `unicode-normalization` sono stati aggiunti al
        // workspace senza comparire nella schermata che dichiara di elencare i
        // componenti di terze parti. Per un elenco che assolve un obbligo di
        // licenza, la divergenza silenziosa e' il modo peggiore di sbagliare.
        for dependency in declared_dependencies() {
            let attributed = THIRD_PARTY_COMPONENTS.iter().any(|component| {
                let name = component.name.to_lowercase();
                name == dependency || name.contains(&dependency)
            });
            let excluded = super::NOT_DISTRIBUTED
                .iter()
                .any(|(name, _)| *name == dependency);

            assert!(
                attributed || excluded,
                "la dipendenza '{dependency}' non compare fra i componenti attribuiti \
                 e non e' dichiarata come non distribuita"
            );
        }
    }

    #[test]
    fn the_dependencies_read_from_the_manifests_are_not_an_empty_set() {
        // Se la lettura dei manifest smettesse di funzionare, il test
        // precedente passerebbe sempre senza verificare nulla.
        let declared = declared_dependencies();
        assert!(
            declared.len() >= 8,
            "lette solo {} dipendenze",
            declared.len()
        );
        assert!(declared.iter().any(|name| name == "slint"));
        assert!(declared.iter().any(|name| name == "serde_json"));
    }

    #[test]
    fn every_exclusion_carries_the_reason_it_is_excluded() {
        for (name, reason) in super::NOT_DISTRIBUTED {
            assert!(!name.trim().is_empty());
            assert!(
                reason.len() > 20,
                "l'esclusione di '{name}' non e' motivata"
            );
        }
    }

    #[test]
    fn components_are_listed_only_once() {
        for (index, component) in THIRD_PARTY_COMPONENTS.iter().enumerate() {
            let duplicate = THIRD_PARTY_COMPONENTS
                .iter()
                .skip(index + 1)
                .any(|other| other.name == component.name);
            assert!(
                !duplicate,
                "{} compare due volte nell'elenco",
                component.name
            );
        }
    }
}
