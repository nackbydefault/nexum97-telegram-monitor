//! Il WHOIS classico: una domanda in chiaro alla porta 43 (WHOIS-01,
//! ADR-0205).
//!
//! # Perché esiste una terza porta
//!
//! Il prodotto aveva due porte verso la rete, con un nome ciascuna: WinHTTP
//! (ADR-0067) e il trasporto dell'Hub (ADR-0083, decisione 8). Il WHOIS dei
//! registri nazionali che non offrono RDAP — `.it`, `.de`, `.ru` e molti altri
//! — passa soltanto dalla porta 43, e WinHTTP non sa parlarle. Questo modulo è
//! la terza porta, e la sola fuori dal trasporto dell'Hub che apre un socket.
//!
//! # Che cosa non è negoziabile
//!
//! Soltanto in uscita, soltanto alla porta [`WHOIS_PORT`], una riga di domanda
//! e una risposta entro [`MAX_ANSWER_BYTES`], con un tempo su ogni fase e uno
//! in tutto. Nessuno di questi è un parametro: un parametro sarebbe il modo in
//! cui un giorno smetterebbero di valere.
//!
//! # Che cosa questo modulo NON fa
//!
//! Non sceglie il server: lo riceve da chi lo chiama, che lo prende da IANA
//! (ADR-0205, decisione 2). Non sa che cosa sta chiedendo, e restituisce testo
//! che è **dato non fidato**: viaggia in chiaro, e chiunque stia sulla strada
//! lo può cambiare.

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream, ToSocketAddrs};
use std::time::{Duration, Instant};

/// La porta del WHOIS (RFC 3912). L'unica.
pub const WHOIS_PORT: u16 = 43;

/// Il limite della risposta, in byte. Una risposta WHOIS è qualche decina di
/// righe.
pub const MAX_ANSWER_BYTES: usize = 64 * 1024;

/// La lunghezza massima della domanda: un nome di dominio, un indirizzo o un
/// suffisso.
pub const MAX_QUERY_CHARS: usize = 255;

/// Quanto si aspetta per collegarsi.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
/// Quanto si aspetta ogni lettura e la scrittura.
const IO_TIMEOUT: Duration = Duration::from_secs(15);
/// Quanto dura, al più, l'intera richiesta.
const TOTAL_TIMEOUT: Duration = Duration::from_secs(30);

/// Com'è andata.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WhoisOutcome {
    /// Il server ha risposto. Testo **non fidato**, decodificato senza
    /// perdere la riga se un byte non è UTF-8.
    Answer(String),
    /// Non ha risposto, e il motivo è questo.
    Refused(WhoisRefusal),
}

/// Perché una domanda non ha avuto risposta.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WhoisRefusal {
    /// Il nome del server non è un nome di rete: nessuna richiesta è partita.
    UnusableServer,
    /// La domanda è vuota, troppo lunga o ha caratteri di controllo: nessuna
    /// richiesta è partita.
    UnusableQuery,
    /// Il nome del server non ha indirizzi.
    NotResolved,
    /// Nessun indirizzo del server ha accettato la connessione, o la
    /// connessione si è interrotta.
    Unreachable {
        /// Che cosa ha detto il sistema.
        reason: String,
    },
    /// Il server non ha finito entro il tempo.
    TimedOut,
    /// La risposta supera il limite.
    TooLarge,
    /// Il server ha chiuso senza rispondere.
    Empty,
}

impl core::fmt::Display for WhoisRefusal {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::UnusableServer => write!(
                formatter,
                "il nome del registro da interrogare non si può usare"
            ),
            Self::UnusableQuery => write!(formatter, "la domanda non si può mandare"),
            Self::NotResolved => write!(formatter, "il nome del registro non ha indirizzi"),
            Self::Unreachable { reason } => {
                write!(formatter, "il registro non è stato raggiunto: {reason}")
            }
            Self::TimedOut => write!(formatter, "il registro non ha risposto in tempo"),
            Self::TooLarge => write!(
                formatter,
                "la risposta supera {MAX_ANSWER_BYTES} byte e non è stata letta oltre"
            ),
            Self::Empty => write!(formatter, "il registro ha chiuso senza rispondere"),
        }
    }
}

/// Se un nome di server si può usare: ASCII, etichette di lettere, cifre e
/// trattini, almeno un punto.
#[must_use]
pub fn is_server_name(server: &str) -> bool {
    !server.is_empty()
        && server.len() <= 253
        && server.contains('.')
        && server.split('.').all(|etichetta| {
            !etichetta.is_empty()
                && etichetta.len() <= 63
                && !etichetta.starts_with('-')
                && !etichetta.ends_with('-')
                && etichetta
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-')
        })
}

/// Se una domanda si può mandare: non vuota, entro [`MAX_QUERY_CHARS`],
/// ASCII stampabile senza spazi. Una domanda con un a capo sarebbe due
/// domande.
#[must_use]
pub fn is_query(query: &str) -> bool {
    !query.is_empty()
        && query.len() <= MAX_QUERY_CHARS
        && query.bytes().all(|b| b.is_ascii_graphic())
}

/// Chiede `query` al server WHOIS `server`, sulla porta 43.
#[must_use]
pub fn ask(server: &str, query: &str) -> WhoisOutcome {
    if !is_server_name(server) {
        return WhoisOutcome::Refused(WhoisRefusal::UnusableServer);
    }
    if !is_query(query) {
        return WhoisOutcome::Refused(WhoisRefusal::UnusableQuery);
    }
    let inizio = Instant::now();
    let indirizzi: Vec<SocketAddr> = match (server, WHOIS_PORT).to_socket_addrs() {
        Ok(indirizzi) => indirizzi.collect(),
        Err(_) => return WhoisOutcome::Refused(WhoisRefusal::NotResolved),
    };
    if indirizzi.is_empty() {
        return WhoisOutcome::Refused(WhoisRefusal::NotResolved);
    }

    let mut ultimo = String::new();
    for indirizzo in indirizzi {
        if inizio.elapsed() >= TOTAL_TIMEOUT {
            return WhoisOutcome::Refused(WhoisRefusal::TimedOut);
        }
        match TcpStream::connect_timeout(&indirizzo, CONNECT_TIMEOUT) {
            Ok(connessione) => return conversa(connessione, query, inizio),
            Err(errore) => ultimo = errore.to_string(),
        }
    }
    WhoisOutcome::Refused(WhoisRefusal::Unreachable { reason: ultimo })
}

/// Una riga di domanda, poi la risposta fino alla chiusura.
fn conversa(mut connessione: TcpStream, query: &str, inizio: Instant) -> WhoisOutcome {
    let interrotta = |errore: std::io::Error| {
        if matches!(
            errore.kind(),
            std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock
        ) {
            WhoisOutcome::Refused(WhoisRefusal::TimedOut)
        } else {
            WhoisOutcome::Refused(WhoisRefusal::Unreachable {
                reason: errore.to_string(),
            })
        }
    };
    if let Err(errore) = connessione
        .set_read_timeout(Some(IO_TIMEOUT))
        .and_then(|()| connessione.set_write_timeout(Some(IO_TIMEOUT)))
    {
        return interrotta(errore);
    }
    if let Err(errore) = connessione.write_all(format!("{query}\r\n").as_bytes()) {
        return interrotta(errore);
    }

    let mut risposta = Vec::new();
    let mut blocco = [0_u8; 4096];
    loop {
        if inizio.elapsed() >= TOTAL_TIMEOUT {
            return WhoisOutcome::Refused(WhoisRefusal::TimedOut);
        }
        match connessione.read(&mut blocco) {
            Ok(0) => break,
            Ok(letti) => {
                if risposta.len() + letti > MAX_ANSWER_BYTES {
                    return WhoisOutcome::Refused(WhoisRefusal::TooLarge);
                }
                risposta.extend_from_slice(&blocco[..letti]);
            }
            Err(errore) if errore.kind() == std::io::ErrorKind::Interrupted => {}
            Err(errore) => return interrotta(errore),
        }
    }
    if risposta.iter().all(u8::is_ascii_whitespace) {
        return WhoisOutcome::Refused(WhoisRefusal::Empty);
    }
    WhoisOutcome::Answer(String::from_utf8_lossy(&risposta).into_owned())
}

#[cfg(test)]
mod tests {
    use super::{WhoisOutcome, WhoisRefusal, ask, is_query, is_server_name};

    #[test]
    fn il_server_e_un_nome_di_rete() {
        assert!(is_server_name("whois.iana.org"));
        assert!(is_server_name("whois.nic.it"));
        for cattivo in [
            "",
            "localhost",
            "whois.iana.org:80",
            "http://whois.iana.org",
            "whois iana.org",
            "-whois.iana.org",
            "whois..org",
        ] {
            assert!(!is_server_name(cattivo), "«{cattivo}» non è un server");
        }
    }

    #[test]
    fn la_domanda_e_una_riga_sola() {
        assert!(is_query("esempio.it"));
        assert!(is_query("it"));
        assert!(is_query("2001:db8::1"));
        for cattiva in ["", "a b", "esempio.it\r\naltro", "esempio.it\n", "città.it"] {
            assert!(!is_query(cattiva), "«{cattiva:?}» non si manda");
        }
        assert!(!is_query(&"a".repeat(256)));
    }

    /// Le domande che non si possono mandare non fanno partire niente: il
    /// rifiuto arriva prima di cercare il server.
    #[test]
    fn una_domanda_sbagliata_non_parte() {
        assert_eq!(
            ask("whois.esempio.invalid", "a\r\nb"),
            WhoisOutcome::Refused(WhoisRefusal::UnusableQuery)
        );
        assert_eq!(
            ask("non un server", "esempio.it"),
            WhoisOutcome::Refused(WhoisRefusal::UnusableServer)
        );
    }
}
