//! Fissa il vincolo di ADR-0048: NEXUM/97 non usa intelligenza artificiale.
//!
//! Le due guardie non hanno la stessa forza, e l'ADR lo dichiara.
//!
//! **La guardia forte** non è un elenco di cose vietate: è un'**assenza di
//! capacità**. Il grafo delle dipendenze del workspace non contiene alcun
//! client HTTP, alcuna libreria TLS in Rust, alcun runtime asincrono e alcun
//! crate di socket. Nessun percorso di codice Rust del prodotto può spedire un
//! byte a un servizio di inferenza, perché nessun percorso di codice Rust del
//! prodotto può spedire un byte a nessuno: tutto ciò che esce dalla postazione
//! esce attraverso lo stack di rete nativo di TDLib, verso Telegram.
//!
//! **La guardia debole**, e si dichiara debole, è l'elenco dei motori di
//! inferenza più probabili. Ferma l'aggiunta distratta e nient'altro: un elenco
//! è una guardia che si dimentica, e in questo progetto lo ha già dimostrato
//! UX-02, dove un elenco chiuso lasciava passare esattamente il difetto che
//! esisteva per fermare.
//!
//! **Il giorno previsto è arrivato: UPDATE-02, 2026-09-12.** Il prodotto ha una
//! porta verso la rete (ADR-0067), e la frase «non può parlare con nessuno» non
//! è più vera.
//!
//! **E c'è stata una trappola.** La guardia forte legge il **lockfile**, e la
//! porta è WinHTTP — la rete del sistema operativo, nessuna dipendenza nuova.
//! Quindi la guardia **non è diventata rossa**: sarebbe rimasta verde
//! raccontando ogni giorno una cosa che non è più vera. Una guardia così è
//! **peggio di una rossa**, perché una rossa costringe qualcuno a guardarla.
//!
//! È stata sostituita **di proposito**, senza aspettare che qualcosa fallisse.
//! Al posto di «il prodotto non può parlare con nessuno» restano tre proprietà,
//! tutte verificabili e tutte più deboli:
//!
//! 1. **Nessuna seconda pila di rete**: il lockfile continua a non contenere
//!    client HTTP, pile TLS o runtime asincroni in Rust. La porta è una.
//! 2. **Una sola porta**: un solo modulo dell'intero prodotto nomina WinHTTP, ed
//!    è il modulo `unsafe` autorizzato di `lisi-platform`.
//! 3. **La destinazione viene dalla configurazione**: chi apre la porta le passa
//!    l'origine conservata in archivio, e non conosce i tipi del contenuto
//!    monitorato.
//!
//! La terza è la più debole e la più importante: è ciò che resta della frase
//! «nessun contenuto monitorato viene inviato a un sistema di inferenza» quando
//! la capacità di inviare esiste.
//!
//! **UPDATE-03 è passata di qui, ed è la prova che la trappola si ripete.** Lo
//! scaricamento dell'artefatto ha aggiunto una seconda lettura —
//! `fetch_to_file` — che la terza proprietà **non cercava**: cercava
//! `https::fetch(`, e sarebbe rimasta verde mentre esisteva una seconda uscita
//! con un'altra destinazione. È stata estesa **prima**, non dopo.
//!
//! E la destinazione dell'artefatto **non viene dalla configurazione**: viene dal
//! manifesto, che è dato non fidato. Il vincolo che tiene in piedi la terza
//! proprietà è ADR-0068: l'artefatto deve stare sullo **stesso host**
//! dell'origine configurata, e la prova verifica che il confronto ci sia e
//! preceda la richiesta.
//!
//! **HUB-TLS-01 è passata di qui, 2026-09-17** (ADR-0083, decisione 8). Il
//! prodotto ha una seconda pila di rete — rustls con ring, per il trasporto
//! verso l'Hub — e le prime due proprietà sono state **sostituite di
//! proposito**, prima che qualcosa fallisse:
//!
//! 1. **Una pila TLS, in una crate**: `rustls` e `ring` compaiono nel file di
//!    blocco solo come dipendenze di `lisi-hub-transport` (e di sé stesse), e
//!    il grafo continua a non contenere client HTTP né runtime asincroni.
//! 2. **Due porte, con un nome ciascuna**: WinHTTP nel modulo `unsafe` di
//!    `lisi-platform` verso l'origine degli aggiornamenti; i socket e TLS nella
//!    sola `lisi-hub-transport`, verso la LAN.
//!
//! La terza proprietà ha **due destinazioni** da TEAM-CLIENT-01 (ADR-0091):
//! l'origine degli aggiornamenti, e l'Hub. Per entrambe vale la stessa regola —
//! l'indirizzo viene dalla configurazione conservata, **mai** da un contenuto
//! monitorato — e per l'Hub si aggiunge che a raggiungerlo è una sola crate, da
//! un solo modulo. La prova dei chiamanti assenti è stata **vista diventare
//! rossa** e sostituita, non tolta.
//!
//! Il modulo non contribuisce al binario: è interamente sotto `cfg(test)`.

/// Grafo delle dipendenze risolte, letto a tempo di compilazione.
///
/// Si legge il lockfile e non i manifest: una dipendenza indesiderata arriva
/// quasi sempre in modo **transitivo**, e i manifest non la mostrerebbero.
#[cfg(test)]
const LOCKFILE: &str = include_str!("../../../Cargo.lock");

#[cfg(test)]
const ADR_NO_AI: &str =
    include_str!("../../../docs/adr/ADR-0048-NESSUNA-INTELLIGENZA-ARTIFICIALE.md");

#[cfg(test)]
mod tests {
    use super::{ADR_NO_AI, LOCKFILE};

    /// Capacità di parlare con un servizio remoto dal codice Rust.
    ///
    /// Non è un elenco di librerie «cattive»: sono le librerie con cui in Rust
    /// si fa una richiesta di rete. Senza una di queste, o senza qualcosa che
    /// faccia il loro mestiere, l'inferenza remota non è raggiungibile.
    const CAPACITA_DI_RETE: &[&str] = &[
        "reqwest",
        "hyper",
        "ureq",
        "curl",
        "isahc",
        "surf",
        "attohttpc",
        "native-tls",
        "openssl",
        "tokio",
        "async-std",
        "tungstenite",
        "tonic",
    ];

    /// Motori di inferenza, runtime di modelli e librerie di embedding.
    ///
    /// La guardia debole. Vedere la nota del modulo.
    const MOTORI_DI_INFERENZA: &[&str] = &[
        "async-openai",
        "openai-api-rs",
        "anthropic-sdk",
        "llm",
        "llama-cpp-2",
        "llama_cpp",
        "candle-core",
        "candle-nn",
        "candle-transformers",
        "ort",
        "onnxruntime",
        "tract-core",
        "tract-onnx",
        "tch",
        "burn",
        "tokenizers",
        "rust-bert",
        "fastembed",
        "hf-hub",
        "qdrant-client",
        "instant-distance",
        "hnsw_rs",
    ];

    /// Nomi dei pacchetti nel lockfile.
    fn pacchetti_risolti() -> Vec<&'static str> {
        LOCKFILE
            .lines()
            .filter_map(|line| line.strip_prefix("name = \""))
            .filter_map(|rest| rest.strip_suffix('"'))
            .collect()
    }

    /// Le dipendenze dirette di ciascun pacchetto del lockfile.
    ///
    /// Le voci del lockfile hanno la forma `"nome"` o `"nome versione"`: si
    /// tiene il nome.
    fn dipendenze_per_pacchetto() -> Vec<(&'static str, Vec<&'static str>)> {
        let mut pacchetti = Vec::new();
        for blocco in LOCKFILE.split("[[package]]").skip(1) {
            let Some(nome) = blocco
                .lines()
                .find_map(|riga| riga.strip_prefix("name = \""))
                .and_then(|resto| resto.strip_suffix('"'))
            else {
                continue;
            };
            let dipendenze = blocco
                .split_once("dependencies = [")
                .and_then(|(_, coda)| coda.split_once(']'))
                .map(|(elenco, _)| {
                    elenco
                        .lines()
                        .filter_map(|riga| {
                            let voce = riga.trim().trim_end_matches(',').trim_matches('"');
                            voce.split(' ').next().filter(|nome| !nome.is_empty())
                        })
                        .collect()
                })
                .unwrap_or_default();
            pacchetti.push((nome, dipendenze));
        }
        pacchetti
    }

    /// La sola crate del prodotto autorizzata a dipendere da una pila TLS.
    const CRATE_DEL_TRASPORTO: &str = "lisi-hub-transport";

    /// Le crate della pila stessa, che dipendono l'una dall'altra.
    const PILA_TLS: &[&str] = &["rustls", "rustls-webpki", "ring"];

    /// **Una pila TLS, in una crate** (ADR-0083, decisione 8, che sostituisce la
    /// proprietà 1 di ADR-0067).
    ///
    /// Fino a HUB-TLS-01 questa prova diceva «nessuna pila TLS in Rust». Ora
    /// dice due cose, entrambe verificate sul file di blocco, che guarda anche
    /// le dipendenze transitive:
    ///
    /// - il grafo **continua a non contenere** client HTTP, runtime asincroni,
    ///   altre pile TLS (`native-tls`, `openssl`) né librerie di socket;
    /// - `rustls` e `ring` sono dipendenze **soltanto** della crate del
    ///   trasporto dell'Hub, e delle crate della pila stessa.
    #[test]
    fn una_sola_pila_tls_in_una_sola_crate() {
        let risolti = pacchetti_risolti();
        assert!(
            risolti.len() > 50,
            "letti solo {} pacchetti dal lockfile: il formato e' cambiato e la \
             guardia non sta piu' leggendo cio' che crede di leggere",
            risolti.len()
        );

        let trovati: Vec<&str> = CAPACITA_DI_RETE
            .iter()
            .copied()
            .filter(|vietato| risolti.contains(vietato))
            .collect();
        assert!(
            trovati.is_empty(),
            "il grafo delle dipendenze contiene ora {trovati:?}: un client HTTP, un \
             runtime asincrono o una TERZA pila di rete. La pila TLS ammessa e' una \
             sola, rustls con ring, dentro «{CRATE_DEL_TRASPORTO}» (ADR-0083)."
        );

        let pacchetti = dipendenze_per_pacchetto();
        assert!(
            pacchetti
                .iter()
                .any(|(nome, dipendenze)| *nome == CRATE_DEL_TRASPORTO
                    && dipendenze.contains(&"rustls")),
            "la lettura delle dipendenze non trova rustls in «{CRATE_DEL_TRASPORTO}»: \
             il formato del lockfile e' cambiato, e la prova non sta guardando il \
             grafo che crede"
        );

        let abusivi: Vec<&str> = pacchetti
            .iter()
            .filter(|(nome, dipendenze)| {
                *nome != CRATE_DEL_TRASPORTO
                    && !PILA_TLS.contains(nome)
                    && dipendenze
                        .iter()
                        .any(|dipendenza| PILA_TLS.contains(dipendenza))
            })
            .map(|(nome, _)| *nome)
            .collect();
        assert!(
            abusivi.is_empty(),
            "questi pacchetti dipendono direttamente da rustls o ring: {abusivi:?}. \
             Una sola crate parla TLS (ADR-0083, decisione 8): un secondo punto \
             sarebbe un secondo verificatore da ragionare, e un cambio di provider \
             non si farebbe piu' in un posto solo."
        );
    }

    /// I termini con cui un sorgente apre un socket o parla TLS.
    const TERMINI_DI_TRASPORTO: &[&str] = &["TcpStream", "TcpListener", "UdpSocket", "rustls::"];

    /// **Tre porte, con un nome ciascuna** (ADR-0083, decisione 8, che
    /// sostituisce la proprietà 2 di ADR-0067; ADR-0205, decisione 4).
    ///
    /// Un solo modulo nomina WinHTTP, ed è il modulo `unsafe` autorizzato di
    /// `lisi-platform`. Una sola **crate** nomina socket e TLS, ed è il
    /// trasporto dell'Hub. E un solo modulo, `lisi-platform/src/whois.rs`, apre
    /// un socket in uscita verso la porta 43 (WHOIS-01), senza TLS e senza
    /// ascolto.
    ///
    /// Questa prova si chiamava `due_porte_con_un_nome_ciascuna`: WHOIS-01
    /// l'ha resa rossa di proposito, e la terza porta ha ora il suo nome. Una
    /// quarta sarebbe un punto senza le regole delle prime tre.
    #[test]
    fn tre_porte_con_un_nome_ciascuna() {
        let mut porte_winhttp = Vec::new();
        let mut porte_lan = Vec::new();
        let mut porte_whois = Vec::new();
        let mut file_visti = 0_usize;
        for file in sorgenti(&crates()) {
            let Ok(testo) = std::fs::read_to_string(&file) else {
                continue;
            };
            file_visti += 1;
            // Questo modulo nomina i termini per poterli cercare, e
            // `model/indicator.rs` li nomina per vietarli a se stesso: nessuno
            // dei due e' una porta.
            if file.ends_with("no_ai_guard.rs") || file.ends_with("indicator.rs") {
                continue;
            }
            let percorso = file.display().to_string();
            if testo.contains("WinHttp") {
                porte_winhttp.push(percorso.clone());
            }
            let separatore = std::path::MAIN_SEPARATOR;
            if percorso.ends_with(&format!("lisi-platform{separatore}src{separatore}whois.rs")) {
                porte_whois.push(percorso);
                assert!(
                    !testo.contains("TcpListener")
                        && !testo.contains("UdpSocket")
                        && !testo.contains("rustls::"),
                    "il client WHOIS si collega alla porta 43 in chiaro, e basta"
                );
                continue;
            }
            if TERMINI_DI_TRASPORTO
                .iter()
                .any(|termine| testo.contains(termine))
            {
                porte_lan.push(percorso);
            }
        }

        assert!(
            file_visti > 50,
            "trovati solo {file_visti} sorgenti: la guardia non sta percorrendo il prodotto"
        );

        assert_eq!(
            porte_winhttp.len(),
            1,
            "WinHTTP deve avere UNA SOLA porta, e ne ha {}: {porte_winhttp:#?} (ADR-0067)",
            porte_winhttp.len()
        );
        assert!(
            porte_winhttp[0].ends_with("https.rs"),
            "la porta WinHTTP deve essere il modulo unsafe autorizzato di \
             lisi-platform, e invece e' {}",
            porte_winhttp[0]
        );

        assert!(
            !porte_lan.is_empty(),
            "nessun sorgente nomina socket o TLS: il trasporto dell'Hub non e' dove \
             questa prova lo cerca, e la prova non sta guardando nulla"
        );
        let separatore = std::path::MAIN_SEPARATOR;
        let cartella = format!("{separatore}{CRATE_DEL_TRASPORTO}{separatore}");
        let fuori: Vec<&String> = porte_lan
            .iter()
            .filter(|percorso| !percorso.contains(&cartella))
            .collect();
        assert!(
            fuori.is_empty(),
            "questi sorgenti aprono socket o parlano TLS fuori da \
             «{CRATE_DEL_TRASPORTO}»: {fuori:#?}. La porta verso la LAN e' una, e \
             ha un nome (ADR-0083, decisione 8)."
        );
        assert_eq!(
            porte_whois.len(),
            1,
            "la porta 43 deve essere UNA, il modulo whois di lisi-platform (ADR-0205)"
        );
    }

    /// La sola crate del prodotto che raggiunge il trasporto dell'Hub.
    const CRATE_DEL_CLIENT: &str = "lisi-services";

    /// I soli moduli di quella crate che lo nominano, e che cosa fa ciascuno.
    ///
    /// Due, da TEAM-LIVE-01 (ADR-0093): uno si **collega** all'Hub, l'altro
    /// **ascolta** quando una persona attiva la modalità Hub. Un terzo sarebbe
    /// un punto senza le regole di questi.
    const MODULI_DEL_TRASPORTO: [&str; 2] = ["hub_client.rs", "hub_server.rs"];

    /// I tipi dell'**acquisizione**, che chi apre la porta non deve conoscere.
    ///
    /// # Che cosa e' cambiato con TEAM-REVIEW-01, e perche' non e' un
    /// indebolimento
    ///
    /// Fino a oggi l'elenco conteneva anche `SourceIdentifier`, perche' nulla
    /// di cio' che riguardava il materiale sorvegliato doveva sfiorare il
    /// modulo che apre la porta. ADR-0094 ha deciso che un contenuto **si
    /// chiede, uno per volta**: il nome della fonte da cui proviene attraversa
    /// quindi il client per essere mostrato a chi rivede.
    ///
    /// La proprieta' che conta resta intatta, ed e' verificata qui sotto
    /// separatamente: **l'indirizzo dell'Hub viene dalla configurazione
    /// conservata**, e nessun dato ricevuto puo' diventarlo. Cio' che resta
    /// vietato e' l'**acquisizione**: il connettore, i tipi con cui un
    /// contenuto entra nell'archivio, la piattaforma.
    const TIPI_DEL_CONTENUTO: &[&str] =
        &["lisi_telegram", "model::content", "NewContent", "MessageId"];

    /// **Il trasporto dell'Hub ha una sola seconda destinazione** (ADR-0067,
    /// proprietà 3, estesa da ADR-0083 e attuata da ADR-0091).
    ///
    /// Fino a TEAM-CLIENT-01 questa prova diceva «nessuna crate del prodotto
    /// dipende dal trasporto», ed è stata **vista diventare rossa** il giorno
    /// in cui `lisi-services` ha aperto la porta. Non è stata tolta: dice
    /// adesso le tre cose che la sostituiscono.
    ///
    /// 1. **Un solo manifesto** del prodotto nomina il trasporto, e si sa
    ///    quale.
    /// 2. **Due moduli** di quella crate lo nominano, e si sa quali: uno si
    ///    collega all'Hub, l'altro ascolta quando una persona attiva la
    ///    modalità Hub (ADR-0093). Un terzo sarebbe un punto senza le regole
    ///    di questi.
    /// 3. **L'indirizzo viene dalla configurazione conservata**, e chi apre la
    ///    porta **non conosce i tipi del contenuto monitorato**: se un
    ///    messaggio potesse diventare l'indirizzo contattato, un canale
    ///    monitorato sarebbe il modo per far parlare la postazione con chi
    ///    vuole chi scrive nel canale.
    #[test]
    fn il_trasporto_dell_hub_ha_una_sola_seconda_destinazione() {
        let Ok(voci) = std::fs::read_dir(crates()) else {
            panic!("la cartella dei crate deve potersi leggere");
        };
        let mut esaminati = 0_usize;
        let mut chiamanti = Vec::new();
        for voce in voci.flatten() {
            let manifesto = voce.path().join("Cargo.toml");
            let Ok(testo) = std::fs::read_to_string(&manifesto) else {
                continue;
            };
            esaminati += 1;
            if voce.file_name() == CRATE_DEL_TRASPORTO {
                continue;
            }
            if testo.contains(CRATE_DEL_TRASPORTO) {
                chiamanti.push(voce.file_name().to_string_lossy().into_owned());
            }
        }
        assert!(
            esaminati >= 8,
            "esaminati solo {esaminati} manifesti: la prova non sta guardando tutto il \
             prodotto"
        );
        assert_eq!(
            chiamanti,
            vec![String::from(CRATE_DEL_CLIENT)],
            "il trasporto dell'Hub deve avere UNA SOLA seconda destinazione, ed è \
             «{CRATE_DEL_CLIENT}» (ADR-0091, decisione 1)"
        );

        let mut moduli = Vec::new();
        for file in sorgenti(&crates().join(CRATE_DEL_CLIENT)) {
            let Ok(testo) = std::fs::read_to_string(&file) else {
                continue;
            };
            // I COMMENTI NON SONO CODICE: una nota che spiega il trasporto non
            // e' una porta che lo apre.
            let codice: String = testo
                .lines()
                .filter(|riga| !riga.trim_start().starts_with("//"))
                .collect::<Vec<&str>>()
                .join("\n");
            if codice.contains("lisi_hub_transport") {
                moduli.push(file.display().to_string());
            }
        }
        assert_eq!(
            moduli.len(),
            MODULI_DEL_TRASPORTO.len(),
            "il trasporto dell'Hub deve essere nominato SOLTANTO da {:?} di \
             «{CRATE_DEL_CLIENT}», e invece lo nominano {moduli:#?}",
            MODULI_DEL_TRASPORTO
        );
        for atteso in MODULI_DEL_TRASPORTO {
            assert!(
                moduli.iter().any(|modulo| modulo.ends_with(atteso)),
                "«{atteso}» non è fra i moduli che nominano il trasporto: {moduli:#?}"
            );
        }

        let client = codice_di_produzione(&moduli, "hub_client.rs");
        let server = codice_di_produzione(&moduli, "hub_server.rs");

        // CHI SI COLLEGA: l'indirizzo viene dalla configurazione conservata,
        // oppure — UNA volta, all'arruolamento — dal modulo che una persona
        // compila con il foglietto, riconosciuto come IP letterale con la sua
        // porta e mai come nome (ADR-0091 decisione 2, ADR-0132).
        //
        // Fino al 2026-10-02 la guardia guardava soltanto la PRIMA chiamata a
        // `connect(`: una seconda, con un indirizzo qualunque, sarebbe passata.
        // Ora guarda TUTTE, e ciascuna deve avere una delle due origini.
        let chiamate: Vec<&str> = client.split("connect(").skip(1).collect();
        assert!(
            chiamate.len() >= 2,
            "il modulo del client deve aprire la connessione all'Hub: la guardia non ha \
             trovato le chiamate"
        );
        for chiamata in &chiamate {
            let argomento = chiamata.trim_start();
            assert!(
                argomento.starts_with("configurazione.address.as_socket_addr()")
                    || argomento.starts_with("address.as_socket_addr(),\n            HubExpectation::Enrollment(fingerprint)"),
                "all'Hub si va con l'indirizzo della configurazione conservata, o con quello \
                 del foglietto all'arruolamento, e non con altro (ADR-0091 decisione 2, \
                 ADR-0132): {}",
                argomento.lines().next().unwrap_or_default()
            );
        }
        assert_eq!(
            chiamate
                .iter()
                .filter(|chiamata| chiamata.trim_start().starts_with("address."))
                .count(),
            1,
            "l'indirizzo scritto a mano apre UNA connessione sola, quella dell'arruolamento"
        );
        assert!(
            client.contains("HubAddress::parse(address.trim())"),
            "l'indirizzo del foglietto deve essere riconosciuto come IP letterale con la \
             sua porta, mai come nome (ADR-0091, decisione 2)"
        );
        assert!(
            client.contains("self.connection.load()"),
            "la configurazione dell'Hub deve venire dall'archivio protetto, non da \
             altrove"
        );

        // CHI ASCOLTA: anche l'indirizzo di ascolto viene dalla configurazione,
        // e non da un valore predefinito che nessuno ha scelto (ADR-0093,
        // decisione 4).
        let Some(dopo) = server.split("HubListener::bind(").nth(1) else {
            panic!("il modulo dell'Hub deve mettersi in ascolto");
        };
        assert!(
            dopo.trim_start().starts_with("indirizzo.as_socket_addr()"),
            "si ascolta sull'indirizzo scritto da una persona, non su altro"
        );
        assert!(
            server.contains("self.listen.load()"),
            "l'indirizzo di ascolto deve venire dall'archivio protetto"
        );

        for (dove, codice) in [("client", &client), ("Hub", &server)] {
            let conosciuti: Vec<&str> = TIPI_DEL_CONTENUTO
                .iter()
                .copied()
                .filter(|tipo| codice.contains(tipo))
                .collect();
            assert!(
                conosciuti.is_empty(),
                "il modulo del {dove} nomina i tipi del contenuto monitorato \
                 {conosciuti:?}: un contenuto monitorato non deve poter diventare \
                 l'indirizzo contattato né ciò che viaggia (ADR-0067, ADR-0093)"
            );
        }
    }

    /// Il codice di produzione del modulo indicato, senza commenti.
    fn codice_di_produzione(moduli: &[String], nome: &str) -> String {
        let Some(percorso) = moduli.iter().find(|modulo| modulo.ends_with(nome)) else {
            panic!("«{nome}» non è fra i moduli trovati");
        };
        let Ok(sorgente) = std::fs::read_to_string(percorso) else {
            panic!("«{nome}» deve potersi leggere");
        };
        let produzione = sorgente
            .split_once("\n#[cfg(test)]")
            .map_or(sorgente.as_str(), |(prima, _)| prima)
            .to_owned();
        produzione
            .lines()
            .filter(|riga| !riga.trim_start().starts_with("//"))
            .collect::<Vec<&str>>()
            .join("\n")
    }

    /// **La destinazione viene dalla configurazione** (ADR-0067, proprietà 3).
    ///
    /// È la più debole delle tre e la più importante: è ciò che resta della
    /// frase «nessun contenuto monitorato viene inviato» quando la capacità di
    /// inviare esiste.
    ///
    /// Un messaggio Telegram, un profilo, un allegato o un fascicolo importato
    /// **non devono poter diventare** l'indirizzo che il prodotto contatta: se
    /// potessero, un canale monitorato sarebbe il modo per far parlare la
    /// postazione con chi vuole chi scrive nel canale.
    ///
    /// **Le letture sono due, e la prova le conta entrambe.** UPDATE-03 ha
    /// aggiunto `fetch_to_file`, e cercare solo `fetch(` avrebbe lasciato questa
    /// prova verde accanto a un'uscita che non guardava.
    ///
    /// **Da DICT-NET-01 sono tre** (ADR-0178, decisione 5): `fetch_within`
    /// scarica il dizionario e la sua firma dalla fonte configurata. La prova
    /// è stata estesa insieme alla lettura, e ora rifiuta anche una quarta
    /// lettura che nessuno ha ancora nominato qui.
    ///
    /// **Da TAXII-01 la porta sa anche mandare** (ADR-0179, decisioni 2, 3 e
    /// 6): un solo `https::send_taxii`, verso l'indirizzo composto dalla
    /// destinazione conservata, con un corpo che viene soltanto dalla busta
    /// dell'esportazione STIX. È la prima volta che qualcosa esce: la prova
    /// controlla da dove viene l'indirizzo e da dove viene il corpo.
    #[test]
    fn la_destinazione_viene_dalla_configurazione() {
        // Il manifesto va dove dice la configurazione, e basta.
        let (dove, sorgente) = unico_chiamante("https::fetch(");
        assert_eq!(
            argomento_di(&sorgente, "https::fetch("),
            "origine",
            "al manifesto si va con l'origine conservata, e non con altro: in {dove}"
        );
        assert!(
            sorgente.contains("self.origin()?"),
            "in {dove} l'origine deve venire dall'archivio, non da altrove"
        );
        // LA FIRMA DEL MANIFESTO (UPDATE-SIGN-01, ADR-0183, decisione 1): lo
        // stesso indirizzo dell'origine con `.p7s` in fondo, e nessun'altra
        // destinazione. Ogni lettura del servizio va all'origine o alla firma.
        assert!(
            sorgente.contains("let firma = format!(\"{origine}{SIGNATURE_SUFFIX}\");"),
            "in {dove} la firma del manifesto deve stare allo stesso indirizzo dell'origine"
        );
        for (posizione, _) in sorgente.match_indices("self.fetch_bytes(") {
            let dopo = &sorgente[posizione + "self.fetch_bytes(".len()..];
            assert!(
                dopo.starts_with("origine)") || dopo.starts_with("&firma)"),
                "in {dove} una lettura va altrove che all'origine o alla sua firma"
            );
        }

        // L'ARTEFATTO È IL CASO DIFFICILE: il suo indirizzo viene dal manifesto,
        // che è dato non fidato. Il vincolo di ADR-0068 è che stia sullo stesso
        // host dell'origine, e il confronto deve PRECEDERE la richiesta.
        let (dove, sorgente) = unico_chiamante("https::fetch_to_file(");
        assert_eq!(
            argomento_di(&sorgente, "https::fetch_to_file("),
            "&manifesto.artifact_url",
            "in {dove} l'artefatto si prende dall'indirizzo del manifesto, che è \
             proprio il motivo per cui serve il vincolo dell'host"
        );

        let Some(confronto) = sorgente.find("UpdateArtifactElsewhere") else {
            panic!(
                "in {dove} manca il rifiuto dell'artefatto su un altro host: senza, \
                 chi controlla il manifesto sceglie dove la postazione va a bussare \
                 (ADR-0068)"
            );
        };
        let Some(richiesta) = sorgente.find("https::fetch_to_file(") else {
            panic!("la richiesta dell'artefatto non si trova in {dove}");
        };
        assert!(
            confronto < richiesta,
            "in {dove} il confronto fra gli host deve venire PRIMA della richiesta: \
             dopo, la postazione avrebbe già parlato"
        );
        assert!(
            sorgente.contains("https::host_of("),
            "in {dove} l'host si deve leggere con l'unica funzione che lo legge"
        );

        for monitorato in [
            "ContentBody",
            "ContentId",
            "SourceId",
            "TelegramEvent",
            "MessageId",
        ] {
            assert!(
                !sorgente.contains(monitorato),
                "chi apre la porta verso la rete non deve conoscere «{monitorato}»: \
                 e' il tipo di un contenuto monitorato, e la destinazione non puo' \
                 venire da li' (ADR-0067)"
            );
        }

        // IL DIZIONARIO E LA SUA FIRMA: la fonte conservata, e la firma allo
        // stesso indirizzo con `.p7s` in fondo (ADR-0178, decisione 5).
        let (dove, sorgente) = unico_chiamante("https::fetch_within(");
        assert_eq!(
            sorgente.matches("https::fetch_within(").count(),
            2,
            "in {dove} si scaricano due cose sole: il dizionario e la sua firma"
        );
        for chiamata in [
            "https::fetch_within(&fonte, BodyLimit::Dictionary)",
            "https::fetch_within(&firma, BodyLimit::Small)",
        ] {
            assert!(
                sorgente.contains(chiamata),
                "in {dove} manca «{chiamata}»: la destinazione deve essere la fonte \
                 conservata, o la sua firma"
            );
        }
        assert!(
            sorgente.contains("let Some(fonte) = self.dictionary_source()? else"),
            "in {dove} la fonte deve venire dall'archivio, non da altrove"
        );
        assert!(
            sorgente.contains("let firma = format!(\"{fonte}{SIGNATURE_SUFFIX}\");"),
            "in {dove} la firma deve stare allo stesso indirizzo della fonte"
        );
        for monitorato in [
            "ContentBody",
            "ContentId",
            "SourceId",
            "TelegramEvent",
            "MessageId",
        ] {
            assert!(
                !sorgente.contains(monitorato),
                "in {dove} chi scarica il dizionario non deve conoscere «{monitorato}» \
                 (ADR-0067, ADR-0178)"
            );
        }

        // L'INVIO TAXII: un punto solo, l'indirizzo dalla destinazione
        // conservata, il corpo dalla busta dell'esportazione (ADR-0179).
        let (dove, sorgente) = unico_chiamante("https::send_taxii(");
        assert_eq!(
            sorgente.matches("https::send_taxii(").count(),
            1,
            "in {dove} si manda da un punto solo"
        );
        for necessario in [
            "https::send_taxii(&pronto.url, &pronto.envelope, &credenziali)",
            "let pronto = self.prepare(session_id, crate::run_mode::is_exercise(), now)?;",
            "let Some(destinazione) = self.destination()? else",
            "url: destinazione.objects_url(),",
            "let piano = StixExportService::new(self.database).preview(session_id)?;",
            "let (envelope, objects) = taxii_envelope(&piano, now);",
        ] {
            assert!(
                sorgente.contains(necessario),
                "in {dove} manca «{necessario}»: l'indirizzo deve venire dalla destinazione \
                 conservata e il corpo dalla busta dell'esportazione STIX, dopo i controlli"
            );
        }
        for monitorato in [
            "ContentBody",
            "ContentId",
            "SourceId",
            "TelegramEvent",
            "MessageId",
        ] {
            assert!(
                !sorgente.contains(monitorato),
                "in {dove} chi manda a TAXII non deve conoscere «{monitorato}»: escono gli \
                 osservabili del pacchetto, non i contenuti (ADR-0057, ADR-0179)"
            );
        }

        // NESSUNA QUARTA LETTURA: ogni `https::fetch` del prodotto è una delle
        // tre qui sopra, e nessuno le importa per chiamarle senza il prefisso.
        // E NESSUN SECONDO INVIO: `send_taxii` si nomina soltanto con il
        // prefisso della porta, fuori dalla porta stessa.
        // LE FOTOGRAFIE DALLE FONTI UFFICIALI (SNAP-NET-01, ADR-0186): il
        // servizio riceve le letture come funzioni, per le prove, e quindi non
        // le chiama per nome. Le sue destinazioni vengono soltanto dai tre file
        // di blocco compilati nel programma, e nessun indirizzo è scritto lì.
        let Some(scaricamento) = sorgenti(&crates())
            .into_iter()
            .find(|file| file.ends_with("snapshot_download.rs"))
        else {
            panic!("il servizio che scarica le fotografie non si trova");
        };
        let Ok(scaricamento_testo) = std::fs::read_to_string(&scaricamento) else {
            panic!("il servizio che scarica le fotografie non si legge");
        };
        let scaricamento_codice = scaricamento_testo
            .split_once("\n#[cfg(test)]")
            .map_or(scaricamento_testo.as_str(), |(prima, _)| prima);
        for atteso in [
            "include_str!(\"../../../attack.lock.json\")",
            "include_str!(\"../../../kev.lock.json\")",
            "include_str!(\"../../../cve.lock.json\")",
            "read: https::fetch_within,",
            "read_file: https::fetch_to_file,",
            "let indirizzo = lock.text(\"/fonte/catalogo_url\")?;",
            "let base = lock.text(\"/fonte/base_url\")?;",
        ] {
            assert!(
                scaricamento_codice.contains(atteso),
                "nel servizio delle fotografie manca «{atteso}»: le destinazioni vengono dai blocchi"
            );
        }
        assert!(
            !scaricamento_codice.contains("\"https://")
                && !scaricamento_codice.contains("\"http://"),
            "nel servizio delle fotografie c'è un indirizzo scritto a mano"
        );
        assert!(
            !scaricamento_codice.contains("send_taxii"),
            "il servizio delle fotografie non manda niente"
        );

        // IL WHOIS (WHOIS-01, ADR-0205, decisione 2): le letture e le domande
        // arrivano come funzioni, per le prove. Gli unici indirizzi scritti a
        // mano sono gli elenchi di IANA e `whois.iana.org`; il registro RDAP
        // viene da un elenco IANA, quello WHOIS dalla risposta di IANA. Il
        // contenuto monitorato decide quale nome si chiede, mai a chi.
        let Some(registro_whois) = sorgenti(&crates()).into_iter().find(|file| {
            file.ends_with("registration_lookup.rs")
                && file.to_string_lossy().contains("lisi-services")
        }) else {
            panic!("il servizio del WHOIS non si trova");
        };
        let Ok(whois_testo) = std::fs::read_to_string(&registro_whois) else {
            panic!("il servizio del WHOIS non si legge");
        };
        let whois_codice = whois_testo
            .split_once("\n#[cfg(test)]")
            .map_or(whois_testo.as_str(), |(prima, _)| prima);
        for atteso in [
            "read: https::fetch_within,",
            "ask: whois::ask,",
            "pub const IANA_RDAP_DOMAINS: &str = \"https://data.iana.org/rdap/dns.json\";",
            "pub const IANA_RDAP_IPV4: &str = \"https://data.iana.org/rdap/ipv4.json\";",
            "pub const IANA_RDAP_IPV6: &str = \"https://data.iana.org/rdap/ipv6.json\";",
            "pub const IANA_WHOIS: &str = \"whois.iana.org\";",
            "if let Some(base) = rdap_base_for_suffix(&elenco, suffisso) {",
            "return chiedi_rdap(rete, format!(\"{base}domain/{nome}\"));",
            "Some(base) => chiedi_rdap(rete, format!(\"{base}ip/{indirizzo}\")),",
            "WhoisOutcome::Answer(risposta) => match whois_server_from_iana(&risposta) {",
        ] {
            assert!(
                whois_codice.contains(atteso),
                "nel servizio del WHOIS manca «{atteso}»: le destinazioni vengono da IANA"
            );
        }
        assert_eq!(
            whois_codice
                .replace("starts_with(\"https://\")", "")
                .matches("\"https://")
                .count(),
            3,
            "nel servizio del WHOIS c'è un indirizzo scritto a mano oltre agli elenchi di IANA"
        );
        assert!(
            !whois_codice.contains("\"http://"),
            "nel servizio del WHOIS c'è un indirizzo in chiaro"
        );
        for (posizione, _) in whois_codice.match_indices("(rete.read)(") {
            let dopo = &whois_codice[posizione + "(rete.read)(".len()..];
            assert!(
                ["IANA_RDAP_DOMAINS,", "elenco_iana,", "&indirizzo,"]
                    .iter()
                    .any(|ammesso| dopo.starts_with(ammesso)),
                "nel servizio del WHOIS una lettura va altrove che a IANA o al registro dell'elenco"
            );
        }
        for (posizione, _) in whois_codice.match_indices("(rete.ask)(") {
            let dopo = &whois_codice[posizione + "(rete.ask)(".len()..];
            assert!(
                dopo.starts_with("IANA_WHOIS, suffisso)") || dopo.starts_with("&server, nome)"),
                "nel servizio del WHOIS una domanda va altrove che a IANA o al server indicato da IANA"
            );
        }
        assert!(
            whois_codice.contains("let server = match (rete.ask)(IANA_WHOIS, suffisso) {"),
            "nel servizio del WHOIS il server viene dalla risposta di IANA"
        );
        for vietato in [
            "send_taxii",
            "ContentBody",
            "ContentId",
            "SourceId",
            "TelegramEvent",
            "MessageId",
        ] {
            assert!(
                !whois_codice.contains(vietato),
                "il servizio del WHOIS non deve conoscere «{vietato}»"
            );
        }

        for file in sorgenti(&crates()) {
            if file.ends_with("no_ai_guard.rs")
                || file.ends_with("snapshot_download.rs")
                || file == registro_whois
            {
                continue;
            }
            if let Ok(testo) = std::fs::read_to_string(&file)
                && !file.ends_with("whois.rs")
            {
                assert!(
                    !testo.contains("whois::ask"),
                    "{} chiede il WHOIS fuori dal servizio che sceglie a chi: questa prova \
                     non lo vedrebbe",
                    file.display()
                );
            }
            let Ok(testo) = std::fs::read_to_string(&file) else {
                continue;
            };
            for (posizione, _) in testo.match_indices("https::fetch") {
                let dopo = &testo[posizione + "https::fetch".len()..];
                assert!(
                    ["(", "_to_file(", "_within("]
                        .iter()
                        .any(|seguito| dopo.starts_with(seguito)),
                    "{} nomina una lettura della rete che questa prova non conosce: \
                     va estesa prima, non dopo",
                    file.display()
                );
            }
            assert!(
                !testo.contains("use lisi_platform::https::fetch"),
                "{} importa una lettura della rete per chiamarla senza prefisso: \
                 questa prova non la vedrebbe",
                file.display()
            );
            if !file.ends_with("lisi-platform/src/https.rs") {
                for (posizione, _) in testo.match_indices("send_taxii") {
                    assert!(
                        testo[..posizione].ends_with("https::"),
                        "{} nomina l'invio TAXII senza il prefisso della porta: questa \
                         prova non lo vedrebbe",
                        file.display()
                    );
                }
            }
        }
    }

    /// **Solo la consegna esegue, e solo con un verdetto positivo in mano**
    /// (ADR-0068 decisione 5, **ristretta** da ADR-0072).
    ///
    /// # Che cosa è cambiato, e perché non è stata tolta
    ///
    /// Fino a UPDATE-06 questa prova diceva «**nulla** esegue ciò che è stato
    /// scaricato», ed era vera: non esisteva un consumatore. UPDATE-07 ne ha
    /// costruito uno, ed è **l'unico punto di questo prodotto che esegue
    /// qualcosa arrivato dalla rete**.
    ///
    /// La risposta comoda sarebbe stata cancellare la prova, perché il
    /// comportamento che vietava adesso esiste. Sarebbe stata **la fine
    /// silenziosa della sola prova che lega l'esecuzione alla verifica**: da quel
    /// momento nulla impedirebbe a un secondo punto di eseguire, e nessuno se ne
    /// accorgerebbe.
    ///
    /// La prova si **restringe**: l'esecuzione può esistere in **un solo punto**,
    /// e quel punto deve avere in mano il file verificato — non un percorso, che
    /// si può ri-risolvere su un file diverso.
    #[test]
    fn solo_la_consegna_esegue_cio_che_e_stato_verificato() {
        const ESECUZIONE: &[&str] = &[
            "Command::new",
            "ShellExecuteW",
            "CreateProcessW",
            "browser::open",
            "telegram_link::open",
        ];

        let mut punti = Vec::new();
        for file in sorgenti(&crates()) {
            let Ok(testo) = std::fs::read_to_string(&file) else {
                continue;
            };
            let produzione = testo
                .split_once("\n#[cfg(test)]")
                .map_or(testo.as_str(), |(prima, _)| prima);

            // Solo i file che sanno dove sta l'artefatto possono eseguirlo.
            if !produzione.contains("staging_directory")
                && !produzione.contains("NOME_ARTEFATTO")
                && !produzione.contains("StagedArtifact")
            {
                continue;
            }
            for esecuzione in ESECUZIONE {
                if produzione.contains(esecuzione) {
                    punti.push((file.display().to_string(), String::from(produzione)));
                }
            }
        }

        assert_eq!(
            punti.len(),
            1,
            "l'esecuzione di cio' che e' stato scaricato deve esistere in UN SOLO \
             punto, e ne ha {}: {:#?}. Un secondo punto sarebbe un punto senza la \
             verifica (ADR-0072).",
            punti.len(),
            punti.iter().map(|(dove, _)| dove).collect::<Vec<&String>>()
        );

        let (dove, sorgente) = &punti[0];
        let codice: String = sorgente
            .lines()
            .filter(|riga| !riga.trim_start().starts_with("//"))
            .collect::<Vec<&str>>()
            .join("\n");

        // L'ESECUZIONE STA DENTRO UNA FUNZIONE CHE RICEVE IL FILE VERIFICATO.
        //
        // Non un percorso: un percorso si ri-risolve, e ri-risolverlo puo' dare
        // un file diverso da quello di cui la catena ha detto di si'.
        let Some(consegna) = codice
            .split("fn avvia_l_installatore(file: &std::sync::Arc<std::fs::File>)")
            .nth(1)
        else {
            panic!(
                "in {dove} la funzione che esegue non prende piu' il file \
                 verificato: se la firma e' cambiata, questa guardia va riscritta \
                 insieme (ADR-0072)"
            );
        };
        let Some(consegna) = consegna.split("\n}\n").next() else {
            panic!("il corpo della consegna non si delimita in {dove}");
        };
        assert!(
            consegna.contains("Command::new"),
            "in {dove} l'esecuzione deve stare DENTRO la funzione che riceve il \
             file verificato"
        );

        // E CHI LA CHIAMA DEVE AVERE UN VERDETTO POSITIVO.
        //
        // Si guardano le DUE COSE che devono esserci e il loro ORDINE, non la
        // forma esatta in cui sono scritte: un controllo negativo ha mostrato
        // che ancorarsi a una riga precisa rende la guardia rossa anche su una
        // riscrittura EQUIVALENTE — e una guardia che punisce le riscritture
        // innocue e' una guardia che qualcuno prima o poi allenta.
        let Some(positivo) = codice.find("ArtifactVerdict::Verified") else {
            panic!(
                "in {dove} la consegna non passa piu' da un verdetto positivo: \
                 senza, l'esecuzione non e' piu' legata alla verifica (ADR-0072)"
            );
        };
        let Some(rifiuto) = codice.find("ServiceError::UpdateNotVerified") else {
            panic!(
                "in {dove} manca il rifiuto di cio' che non ha superato la \
                 verifica: offrire di procedere comunque significherebbe che la \
                 verifica e' decorativa (ADR-0037)"
            );
        };
        let Some(avvio) = codice.find("avvia_l_installatore(") else {
            panic!("in {dove} la consegna non avvia piu' l'installatore");
        };
        assert!(
            positivo < avvio && rifiuto < avvio,
            "in {dove} il verdetto positivo e il rifiuto devono venire PRIMA \
             dell'avvio: dopo, il programma sarebbe gia' partito"
        );
        assert!(
            codice.contains("ServiceError::UpdateMonitoringRunning"),
            "in {dove} manca il rifiuto con un monitoraggio in corso: sostituire \
             il programma mentre osserva interrompe un'osservazione (ADR-0037)"
        );
    }

    /// Il solo chiamante di una funzione, con il sorgente di produzione che lo
    /// contiene.
    /// Il solo chiamante di una funzione, con il sorgente di produzione che lo
    /// contiene.
    fn unico_chiamante(chiamata: &str) -> (String, String) {
        let mut chiamanti = Vec::new();
        for file in sorgenti(&crates()) {
            let Ok(testo) = std::fs::read_to_string(&file) else {
                continue;
            };
            let produzione = testo
                .split_once("\n#[cfg(test)]")
                .map_or(testo.as_str(), |(prima, _)| prima);
            // QUESTO MODULO NOMINA LE CHIAMATE PER CERCARLE, e la sua nota le
            // spiega: senza questa riga la guardia troverebbe se stessa. E' la
            // stessa lezione di sempre — una guardia che cerca parole trovera'
            // anche la spiegazione di cio' che cerca.
            if file.ends_with("no_ai_guard.rs") {
                continue;
            }
            // I COMMENTI NON SONO CODICE, e vanno tolti prima di cercare.
            //
            // Trovato da un controllo negativo: togliendo il rifiuto
            // dell'artefatto su un altro host, questa prova restava VERDE —
            // perche' il nome del rifiuto compariva ancora nella sua
            // DOCUMENTAZIONE. Una guardia che legge i commenti verifica cio'
            // che il codice dice di fare, non cio' che fa.
            let codice: String = produzione
                .lines()
                .filter(|riga| !riga.trim_start().starts_with("//"))
                .collect::<Vec<&str>>()
                .join("\n");
            if codice.contains(chiamata) {
                chiamanti.push((file.display().to_string(), codice));
            }
        }

        assert_eq!(
            chiamanti.len(),
            1,
            "«{chiamata}» deve avere UN SOLO chiamante, e ne ha {}: {:#?}",
            chiamanti.len(),
            chiamanti
                .iter()
                .map(|(dove, _)| dove)
                .collect::<Vec<&String>>()
        );

        let (dove, sorgente) = &chiamanti[0];
        (dove.clone(), sorgente.clone())
    }

    /// Il primo argomento di una chiamata, come sta scritto.
    fn argomento_di(sorgente: &str, chiamata: &str) -> String {
        let Some(dopo) = sorgente.split(chiamata).nth(1) else {
            panic!("«{chiamata}» non si trova");
        };
        let Some(argomento) = dopo.split([',', ')']).next() else {
            panic!("l'argomento di «{chiamata}» non si delimita");
        };
        String::from(argomento.trim())
    }

    /// La cartella dei crate del prodotto.
    /// La cartella dei crate del prodotto.
    fn crates() -> std::path::PathBuf {
        let crates = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .map(std::path::Path::to_path_buf);
        let Some(crates) = crates else {
            panic!("la cartella dei crate deve esistere sopra questo crate");
        };
        crates
    }

    /// Tutti i sorgenti Rust sotto un percorso.
    fn sorgenti(percorso: &std::path::Path) -> Vec<std::path::PathBuf> {
        let mut trovati = Vec::new();
        let Ok(voci) = std::fs::read_dir(percorso) else {
            return trovati;
        };
        for voce in voci.flatten() {
            let percorso = voce.path();
            if percorso.is_dir() {
                if percorso.file_name().is_some_and(|nome| nome == "target") {
                    continue;
                }
                trovati.extend(sorgenti(&percorso));
            } else if percorso
                .extension()
                .is_some_and(|estensione| estensione == "rs")
            {
                trovati.push(percorso);
            }
        }
        trovati
    }

    #[test]
    fn nessun_motore_di_inferenza_nel_grafo_delle_dipendenze() {
        let risolti = pacchetti_risolti();

        let trovati: Vec<&str> = MOTORI_DI_INFERENZA
            .iter()
            .copied()
            .filter(|vietato| risolti.contains(vietato))
            .collect();

        assert!(
            trovati.is_empty(),
            "il grafo delle dipendenze contiene {trovati:?}: ADR-0048 vieta \
             inferenza, modelli, embedding e classificazione appresa nel prodotto"
        );
    }

    /// L'ADR deve continuare a dire le cose su cui le prove qui sopra poggiano.
    ///
    /// Serve perche' una prova che rimanda a un documento e un documento
    /// riscritto sono due cose che divergono in silenzio: la prova resterebbe
    /// verde citando una decisione che nel frattempo dice altro.
    #[test]
    fn ladr_dichiara_ancora_il_vincolo_e_il_giorno_in_cui_la_guardia_cade() {
        for frase in [
            "non usa intelligenza artificiale",
            "Nessun contenuto monitorato viene inviato a un sistema di inferenza",
            "UPDATE-02",
            "HUB-TLS-01",
            // La sostituzione e' avvenuta: l'ADR deve dirlo, altrimenti chi lo
            // legge continua a credere che il prodotto non possa parlare.
            "ADR-0067",
        ] {
            assert!(
                ADR_NO_AI.contains(frase),
                "ADR-0048 non contiene piu' «{frase}»: le prove di questo modulo \
                 poggiano su quel testo"
            );
        }
    }
}
