//! Codici che una persona legge ad alta voce e un'altra ricopia.
//!
//! # Perché esiste una sola implementazione, e questo modulo è la ragione
//!
//! Due valori del prodotto vengono letti ad alta voce e ridigitati:
//! l'identificativo di un dispositivo ([`crate::model::identity::DeviceId`]) e
//! il codice di arruolamento ([`crate::model::enrollment::EnrollmentCode`]).
//!
//! Una seconda copia di questo codice sarebbe una seconda occasione di
//! sbagliarlo — un'ambiguità risolta qui e non là, un gruppo di quattro cifre
//! da una parte e di cinque dall'altra — e la differenza non la vedrebbe alcuna
//! prova, perché ciascuna metà resterebbe coerente con sé stessa. È la stessa
//! ragione per cui `lisi-services::passphrase` esiste.
//!
//! # Perché mancano I, L, O e U
//!
//! È l'alfabeto base32 di Crockford. `0` e `O`, `1` e `I` e `l` si confondono
//! ad alta voce e sulla carta, e una cifra confusa non produce un errore
//! leggibile: produce **un valore diverso**, che il destinatario non riconosce
//! senza sapere perché. La `U` è esclusa perché senza di essa l'alfabeto non
//! compone parole che nessuno vuole ritrovarsi in un documento d'ufficio.
//!
//! La lettura risolve le confusioni previste invece di rifiutarle: chi ricopia
//! `O` dove c'era `0` ottiene il valore giusto.

/// Alfabeto base32 di Crockford.
pub(crate) const ALFABETO: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";

/// Perché una forma ricopiata non è stata riconosciuta.
///
/// Il motivo è una costante e non il valore ricevuto: questi codici arrivano
/// anche dalla rete, e un messaggio composto da un dato d'ingresso è un
/// messaggio che un dato d'ingresso può riscrivere.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum FormaScorretta {
    /// Un carattere non appartiene all'alfabeto.
    CarattereEstraneo,
    /// Le cifre non sono quante devono essere.
    Lunghezza,
}

/// Rende i byte come cifre raggruppate.
///
/// # Panics
///
/// Va invocata con `bytes.len() * 8 == cifre * 5`: i bit devono entrare nelle
/// cifre **senza avanzi**, così che ogni forma ben scritta sia un valore valido
/// e non esista una categoria di stringhe «quasi valide» che qualcuno debba
/// ricordarsi di rifiutare. L'invariante è dei chiamanti, che sono due e usano
/// costanti; l'asserzione la rende un errore di compilazione delle prove invece
/// che un difetto silenzioso.
pub(crate) fn encode(bytes: &[u8], cifre: usize, gruppo: usize) -> String {
    assert!(
        bytes.len() * 8 == cifre * 5,
        "i bit devono entrare nelle cifre senza avanzi"
    );

    let mut testo = String::with_capacity(cifre + cifre / gruppo);
    for cifra in 0..cifre {
        if cifra > 0 && cifra.is_multiple_of(gruppo) {
            testo.push('-');
        }
        let indice = cinque_bit(bytes, cifra * 5);
        testo.push(char::from(ALFABETO[indice]));
    }
    testo
}

/// Riconosce una forma ricopiata e la riporta alla forma canonica.
///
/// Accetta minuscole, separatori mancanti o in eccesso e le confusioni previste
/// dall'alfabeto: chi ridigita un valore letto al telefono non deve indovinare
/// dove cadono i trattini.
///
/// # Errori
///
/// [`FormaScorretta::CarattereEstraneo`] se un carattere non appartiene
/// all'alfabeto, [`FormaScorretta::Lunghezza`] se le cifre non sono quante
/// devono essere.
pub(crate) fn canonicalize(
    raw: &str,
    cifre: usize,
    gruppo: usize,
) -> Result<String, FormaScorretta> {
    let mut lette = String::with_capacity(cifre);
    for carattere in raw.chars() {
        if carattere == '-' || carattere == ' ' {
            continue;
        }
        let normalizzato = normalizza(carattere).ok_or(FormaScorretta::CarattereEstraneo)?;
        if lette.len() == cifre {
            return Err(FormaScorretta::Lunghezza);
        }
        lette.push(normalizzato);
    }
    if lette.len() != cifre {
        return Err(FormaScorretta::Lunghezza);
    }

    let mut canonico = String::with_capacity(cifre + cifre / gruppo);
    for (posizione, cifra) in lette.chars().enumerate() {
        if posizione > 0 && posizione.is_multiple_of(gruppo) {
            canonico.push('-');
        }
        canonico.push(cifra);
    }
    Ok(canonico)
}

/// Riporta una forma **canonica** ai byte da cui è stata composta.
///
/// È l'inverso di [`encode`], e serve dove il valore ricopiato va **confrontato
/// con dei byte** — l'impronta dell'Hub (ADR-0082) — e non soltanto ridetto.
///
/// Restituisce `None` se la forma non è canonica o se le cifre non contengono
/// esattamente `N` byte senza avanzi: i chiamanti la invocano dopo
/// [`canonicalize`], quindi `None` segnala un difetto del chiamante, e diventa
/// un rifiuto invece che un valore sbagliato.
pub(crate) fn decode<const N: usize>(canonico: &str) -> Option<[u8; N]> {
    let mut bytes = [0_u8; N];
    let mut bit = 0_usize;
    for carattere in canonico.bytes() {
        if carattere == b'-' {
            continue;
        }
        let valore = ALFABETO.iter().position(|&cifra| cifra == carattere)?;
        for spostamento in (0..5).rev() {
            if (valore >> spostamento) & 1 == 1 {
                *bytes.get_mut(bit / 8)? |= 0x80 >> (bit % 8);
            }
            bit += 1;
        }
    }
    (bit == N * 8).then_some(bytes)
}

/// Estrae cinque bit a partire dalla posizione indicata.
///
/// Cinque bit stanno in due byte al massimo, mai in tre: la finestra di sedici
/// bit li contiene sempre per intero.
fn cinque_bit(bytes: &[u8], da: usize) -> usize {
    let indice = da / 8;
    let scarto = da % 8;
    let alto = usize::from(bytes[indice]);
    let basso = if indice + 1 < bytes.len() {
        usize::from(bytes[indice + 1])
    } else {
        0
    };
    (((alto << 8) | basso) >> (11 - scarto)) & 0b1_1111
}

/// Porta un carattere alla sua cifra canonica, se ne ha una.
fn normalizza(carattere: char) -> Option<char> {
    let corretto = match carattere.to_ascii_uppercase() {
        'O' => '0',
        'I' | 'L' => '1',
        altro => altro,
    };
    ALFABETO
        .contains(&u8::try_from(corretto).ok()?)
        .then_some(corretto)
}

#[cfg(test)]
mod tests {
    use super::{FormaScorretta, canonicalize, decode, encode};

    /// **Tutti i bit entrano nelle cifre, e nessuno si perde.**
    ///
    /// # Il difetto che questa prova impedisce
    ///
    /// L'estrazione dei cinque bit attraversa i confini fra i byte. Uno scarto
    /// sbagliato di un bit non produce un errore: produce un valore che
    /// **ignora** parte del caso, cioe' un codice con meno entropia di quella
    /// dichiarata, e nessuno se ne accorgerebbe leggendolo.
    #[test]
    fn ogni_bit_dell_ingresso_cambia_l_uscita() {
        for (byte, cifre) in [(5_usize, 8_usize), (10, 16), (15, 24)] {
            let base = vec![0_u8; byte];
            let atteso = encode(&base, cifre, 4);

            for posizione in 0..byte {
                for bit in 0..8_u32 {
                    let mut variante = base.clone();
                    variante[posizione] = 1_u8 << bit;
                    assert_ne!(
                        encode(&variante, cifre, 4),
                        atteso,
                        "il bit {bit} del byte {posizione} non compare in un codice di \
                         {cifre} cifre: il valore ha meno caso di quanto dichiara"
                    );
                }
            }
        }
    }

    /// **La forma canonica e' quella dichiarata.**
    #[test]
    fn la_forma_ha_le_cifre_e_i_gruppi_previsti() {
        assert_eq!(encode(&[0x00; 5], 8, 4), "0000-0000");
        assert_eq!(encode(&[0xFF; 10], 16, 4), "ZZZZ-ZZZZ-ZZZZ-ZZZZ");
        assert_eq!(encode(&[0x00; 15], 24, 4), "0000-0000-0000-0000-0000-0000");
    }

    /// **Ricopiare a mano non produce un altro valore.**
    #[test]
    fn le_confusioni_di_lettura_si_risolvono() {
        let Ok(canonico) = canonicalize("0J2K-M3NP", 8, 4) else {
            panic!("la forma canonica deve essere riconosciuta");
        };
        for ricopiato in ["0j2km3np", "0J2K M3NP", "OJ2K-M3NP", "0-J-2-K-M-3-N-P"] {
            assert_eq!(
                canonicalize(ricopiato, 8, 4),
                Ok(canonico.clone()),
                "«{ricopiato}» ha prodotto un valore diverso"
            );
        }
    }

    /// **Una forma storta e' rifiutata, e dice quale delle due cose non va.**
    #[test]
    fn una_forma_storta_e_rifiutata() {
        assert_eq!(canonicalize("", 8, 4), Err(FormaScorretta::Lunghezza));
        assert_eq!(canonicalize("0J2K", 8, 4), Err(FormaScorretta::Lunghezza));
        assert_eq!(
            canonicalize("0J2K-M3NPQ", 8, 4),
            Err(FormaScorretta::Lunghezza)
        );
        assert_eq!(
            canonicalize("0J2K-M3NU", 8, 4),
            Err(FormaScorretta::CarattereEstraneo)
        );
        assert_eq!(
            canonicalize("0J2K-M3N!", 8, 4),
            Err(FormaScorretta::CarattereEstraneo)
        );
    }

    /// **Un ingresso con avanzi non passa in silenzio.**
    ///
    /// Sarebbe il difetto peggiore fra quelli possibili qui: un codice che
    /// dichiara ottanta bit e ne porta settantacinque, senza che nulla lo dica.
    #[test]
    #[should_panic(expected = "senza avanzi")]
    fn un_ingresso_con_avanzi_non_passa() {
        let _ = encode(&[0x00; 8], 12, 4);
    }

    /// **Leggere e scrivere sono l'una l'inverso dell'altra**, per ogni bit.
    ///
    /// L'impronta dell'Hub si confronta come byte: una lettura che sbagliasse
    /// un bit farebbe rifiutare l'Hub vero, o — peggio, se sbagliasse in modo
    /// simmetrico con la scrittura — accettare la forma sbagliata.
    #[test]
    fn leggere_e_l_inverso_di_scrivere() {
        for bit in 0..120 {
            let mut bytes = [0_u8; 15];
            bytes[bit / 8] |= 0x80 >> (bit % 8);
            let scritto = encode(&bytes, 24, 4);
            assert_eq!(decode::<15>(&scritto), Some(bytes), "bit {bit}");
        }
        let tutti = [0xFF_u8; 15];
        assert_eq!(decode::<15>(&encode(&tutti, 24, 4)), Some(tutti));

        // Cifre che non riempiono i byte richiesti, o un carattere estraneo.
        assert_eq!(decode::<15>("0000-0000"), None);
        assert_eq!(decode::<5>("0000-000U"), None);
    }
}
