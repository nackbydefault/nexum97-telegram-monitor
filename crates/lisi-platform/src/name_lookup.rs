// Modulo del crate autorizzato a contenere `unsafe`, dopo quelli elencati in
// `lib.rs`. Vedere ADR-0009 per la regola e ADR-0202 per la decisione che ha
// portato qui.
#![cfg_attr(windows, allow(unsafe_code))]

//! La risoluzione di un nome o di un indirizzo, chiesta al risolutore di
//! Windows (IOC-RESOLVE-01, ADR-0202).
//!
//! # Perché il risolutore di Windows
//!
//! Il committente ha deciso che la richiesta parte **direttamente dal PC**:
//! `DnsQuery_W` usa i server DNS configurati sulla postazione, la stessa via
//! di ogni altro programma. Nessun servizio di terzi, nessuna libreria nuova.
//!
//! # Il prezzo, detto prima
//!
//! **Una richiesta DNS si vede.** Il server DNS dell'ufficio la registra, e
//! chi gestisce il dominio chiesto può vederla arrivare: può capire che
//! qualcuno lo sta guardando. Questo modulo non lo nasconde e non lo
//! attenua; la schermata lo dice prima del pulsante.
//!
//! # Che cosa questo modulo NON fa
//!
//! Non si collega all'indirizzo trovato, non preleva nulla, non segue un
//! indirizzo web. Chiede soltanto i record `A`, `AAAA` (un nome) o `PTR` (un
//! indirizzo), e solo al DNS: niente NetBIOS e niente multicast sulla rete
//! locale.
//!
//! # Le invarianti dell'FFI
//!
//! 1. Il nome passa in UTF-16 terminato da zero, posseduto dalla funzione e
//!    vivo per l'intera chiamata; un nome con caratteri fuori dall'ASCII
//!    stampabile si rifiuta prima.
//! 2. L'elenco dei record si legge **solo** se la chiamata ha restituito zero,
//!    e si libera con `DnsFree` una volta sola, dopo averlo copiato.
//! 3. Per ogni record si legge il campo dell'unione che corrisponde al suo
//!    `wType`, e nessun altro.

use std::net::IpAddr;

/// Quante risposte si conservano al più, per richiesta.
pub const MAX_ANSWERS: usize = 32;

/// La lunghezza massima di un nome di dominio (RFC 1035).
const MAX_NAME_CHARS: usize = 253;

/// Com'è andata una richiesta.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LookupOutcome {
    /// Il risolutore ha risposto con questi valori.
    Found(Vec<String>),
    /// Il nome esiste, ma non ha record del genere chiesto.
    NoRecords,
    /// Il nome non esiste.
    NotFound,
    /// Il nome non è chiedibile: non è partita nessuna richiesta.
    Refused,
    /// Il risolutore non ha risposto, o ha risposto con un errore.
    Failed {
        /// Il codice restituito da Windows.
        code: u32,
    },
}

/// Il nome chiesto per un indirizzo: `in-addr.arpa` o `ip6.arpa`.
#[must_use]
pub fn reverse_name(address: IpAddr) -> String {
    match address {
        IpAddr::V4(v4) => {
            let [a, b, c, d] = v4.octets();
            format!("{d}.{c}.{b}.{a}.in-addr.arpa")
        }
        IpAddr::V6(v6) => {
            let mut nome = String::with_capacity(72);
            for byte in v6.octets().iter().rev() {
                for mezzo in [byte & 0x0f, byte >> 4] {
                    nome.push(char::from_digit(u32::from(mezzo), 16).unwrap_or('0'));
                    nome.push('.');
                }
            }
            nome.push_str("ip6.arpa");
            nome
        }
    }
}

/// Se un nome si può chiedere: ASCII, etichette di lettere, cifre e trattini,
/// almeno un punto, non oltre 253 caratteri.
#[must_use]
pub fn is_queryable_name(name: &str) -> bool {
    let nome = name.strip_suffix('.').unwrap_or(name);
    if nome.is_empty() || nome.len() > MAX_NAME_CHARS || !nome.contains('.') {
        return false;
    }
    nome.split('.').all(|etichetta| {
        !etichetta.is_empty()
            && etichetta.len() <= 63
            && !etichetta.starts_with('-')
            && !etichetta.ends_with('-')
            && etichetta
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
    })
}

/// Gli indirizzi di un nome: record `A` e `AAAA`.
#[must_use]
pub fn addresses_of(name: &str) -> LookupOutcome {
    if !is_queryable_name(name) {
        return LookupOutcome::Refused;
    }
    #[cfg(windows)]
    {
        windows_impl::addresses(name)
    }
    #[cfg(not(windows))]
    {
        LookupOutcome::Failed { code: 0 }
    }
}

/// I nomi di un indirizzo: record `PTR`.
#[must_use]
pub fn names_of(address: IpAddr) -> LookupOutcome {
    #[cfg(windows)]
    {
        windows_impl::names(&reverse_name(address))
    }
    #[cfg(not(windows))]
    {
        let _ = address;
        LookupOutcome::Failed { code: 0 }
    }
}

#[cfg(windows)]
mod windows_impl {
    use std::net::{Ipv4Addr, Ipv6Addr};

    use windows_sys::Win32::NetworkManagement::Dns::{
        DNS_QUERY_NO_MULTICAST, DNS_QUERY_NO_NETBT, DNS_RECORDA, DNS_RECORDW, DNS_TYPE, DNS_TYPE_A,
        DNS_TYPE_AAAA, DNS_TYPE_PTR, DnsFree, DnsFreeRecordList, DnsQuery_W,
    };

    use super::{LookupOutcome, MAX_ANSWERS};

    /// `DNS_ERROR_RCODE_NAME_ERROR`: il nome non esiste.
    const NOME_INESISTENTE: u32 = 9003;
    /// `DNS_INFO_NO_RECORDS`: il nome esiste, i record no.
    const NESSUN_RECORD: u32 = 9501;
    /// La sezione «risposta» nei bit bassi di `Flags`.
    const SEZIONE_RISPOSTA: u32 = 1;

    enum Esito {
        Valori(Vec<String>),
        Codice(u32),
    }

    pub fn addresses(name: &str) -> LookupOutcome {
        let mut trovati = Vec::new();
        let mut codici = Vec::new();
        for genere in [DNS_TYPE_A, DNS_TYPE_AAAA] {
            match chiedi(name, genere) {
                Esito::Valori(valori) => trovati.extend(valori),
                Esito::Codice(codice) => codici.push(codice),
            }
        }
        concludi(trovati, &codici)
    }

    pub fn names(reverse: &str) -> LookupOutcome {
        match chiedi(reverse, DNS_TYPE_PTR) {
            Esito::Valori(valori) => concludi(valori, &[]),
            Esito::Codice(codice) => concludi(Vec::new(), &[codice]),
        }
    }

    fn concludi(mut trovati: Vec<String>, codici: &[u32]) -> LookupOutcome {
        trovati.sort();
        trovati.dedup();
        trovati.truncate(MAX_ANSWERS);
        if !trovati.is_empty() {
            return LookupOutcome::Found(trovati);
        }
        if codici.contains(&NOME_INESISTENTE) {
            return LookupOutcome::NotFound;
        }
        if let Some(codice) = codici
            .iter()
            .copied()
            .find(|codice| *codice != NESSUN_RECORD)
        {
            return LookupOutcome::Failed { code: codice };
        }
        LookupOutcome::NoRecords
    }

    fn chiedi(name: &str, genere: DNS_TYPE) -> Esito {
        let wide: Vec<u16> = name.encode_utf16().chain(std::iter::once(0)).collect();
        let mut elenco: *mut DNS_RECORDA = std::ptr::null_mut();

        // SAFETY: `wide` è posseduto da questa funzione, terminato da zero e
        // privo di zeri interni (il nome è ASCII stampabile, verificato dal
        // chiamante), e resta vivo per l'intera chiamata. `elenco` è una
        // variabile locale che Windows scrive; i due puntatori facoltativi
        // sono nulli, come la documentazione ammette.
        let esito = unsafe {
            DnsQuery_W(
                wide.as_ptr(),
                genere,
                DNS_QUERY_NO_NETBT | DNS_QUERY_NO_MULTICAST,
                std::ptr::null_mut(),
                &raw mut elenco,
                std::ptr::null_mut(),
            )
        };
        if esito != 0 {
            return Esito::Codice(esito);
        }

        let mut valori = Vec::new();
        let mut corrente = elenco.cast::<DNS_RECORDW>();
        while !corrente.is_null() && valori.len() < MAX_ANSWERS {
            // SAFETY: `corrente` viene dall'elenco che Windows ha appena
            // restituito, che resta valido fino a `DnsFree` più sotto; con
            // `DnsQuery_W` i record sono nella forma «W», e la dichiarazione
            // generata li chiama «A» per un difetto noto dei metadati.
            let record = unsafe { &*corrente };
            // SAFETY: `Flags` è un'unione di due viste dello stesso intero a
            // 32 bit; `DW` è sempre leggibile.
            // I record che Windows compone da sé, come quelli di
            // `localhost`, arrivano con la sezione a zero: si tengono anche
            // quelli. Si scartano le sezioni «autorità» e «aggiuntivi».
            let sezione = unsafe { record.Flags.DW } & 0x3;
            if sezione <= SEZIONE_RISPOSTA
                && record.wType == genere
                && let Some(valore) = leggi(record)
            {
                valori.push(valore);
            }
            corrente = record.pNext;
        }

        // SAFETY: `elenco` è quello restituito da `DnsQuery_W`, non ancora
        // liberato, e non si usa più dopo questa chiamata. Si libera anche se
        // è vuoto: `DnsFree` accetta un puntatore nullo.
        unsafe { DnsFree(elenco.cast(), DnsFreeRecordList) };
        Esito::Valori(valori)
    }

    fn leggi(record: &DNS_RECORDW) -> Option<String> {
        match record.wType {
            DNS_TYPE_A => {
                // SAFETY: il record è di tipo A, e il campo `A` dell'unione è
                // quello che Windows ha scritto.
                let ip = unsafe { record.Data.A.IpAddress };
                // L'indirizzo è nell'ordine della rete, letto come intero
                // nell'ordine della macchina.
                Some(Ipv4Addr::from(ip.to_ne_bytes()).to_string())
            }
            DNS_TYPE_AAAA => {
                // SAFETY: il record è di tipo AAAA, e il campo `AAAA`
                // dell'unione è quello che Windows ha scritto; `IP6Byte` è
                // sempre leggibile.
                let byte = unsafe { record.Data.AAAA.Ip6Address.IP6Byte };
                Some(Ipv6Addr::from(byte).to_string())
            }
            DNS_TYPE_PTR => {
                // SAFETY: il record è di tipo PTR; il nome è una stringa
                // UTF-16 terminata da zero che appartiene all'elenco, ancora
                // vivo.
                let nome = unsafe { record.Data.PTR.pNameHost };
                if nome.is_null() {
                    return None;
                }
                let mut lunghezza = 0usize;
                // SAFETY: la stringa è terminata da zero; ci si ferma al
                // primo zero, entro la lunghezza massima di un nome.
                while lunghezza < 1024 && unsafe { *nome.add(lunghezza) } != 0 {
                    lunghezza += 1;
                }
                // SAFETY: `lunghezza` unità sono state appena lette, quindi
                // sono valide.
                let unita_utf16 = unsafe { std::slice::from_raw_parts(nome, lunghezza) };
                Some(String::from_utf16_lossy(unita_utf16))
            }
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::net::IpAddr;

    use super::{LookupOutcome, addresses_of, is_queryable_name, reverse_name};

    #[test]
    fn il_nome_inverso_si_compone_al_contrario() {
        let Ok(v4) = "192.0.2.10".parse::<IpAddr>() else {
            panic!("indirizzo di prova");
        };
        assert_eq!(reverse_name(v4), "10.2.0.192.in-addr.arpa");
        let Ok(v6) = "2001:db8::1".parse::<IpAddr>() else {
            panic!("indirizzo di prova");
        };
        let nome = reverse_name(v6);
        assert!(nome.starts_with("1.0.0.0."), "{nome}");
        assert!(nome.ends_with(".8.b.d.0.1.0.0.2.ip6.arpa"), "{nome}");
        assert_eq!(nome.split('.').count(), 34);
    }

    #[test]
    fn si_chiedono_soltanto_nomi_ben_formati() {
        assert!(is_queryable_name("esempio.invalid"));
        assert!(is_queryable_name("a-b.esempio.invalid."));
        for cattivo in [
            "",
            "localhost",
            "esempio..invalid",
            "-a.invalid",
            "a b.invalid",
            "città.invalid",
            "a\0.invalid",
        ] {
            assert!(!is_queryable_name(cattivo), "{cattivo:?}");
        }
        assert!(!is_queryable_name(&format!("{}.invalid", "a".repeat(64))));
        assert_eq!(addresses_of("a b.invalid"), LookupOutcome::Refused);
    }

    /// La chiamata vera, senza uscire dalla postazione: `localhost` lo
    /// risolve il client DNS di Windows da sé.
    #[cfg(windows)]
    #[test]
    fn windows_risolve_localhost_senza_la_rete() {
        let esito = super::windows_impl::addresses("localhost");
        let LookupOutcome::Found(indirizzi) = esito else {
            panic!("localhost deve risolversi: {esito:?}");
        };
        assert!(
            indirizzi
                .iter()
                .any(|indirizzo| indirizzo == "127.0.0.1" || indirizzo == "::1"),
            "{indirizzi:?}"
        );
    }
}
