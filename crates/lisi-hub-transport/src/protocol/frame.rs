//! I frame: una lunghezza, poi il contenuto, e un tetto che agisce **prima**.
//!
//! # La forma
//!
//! ```text
//! +--------------------+---------------------------+
//! | lunghezza: u32 BE  | contenuto: lunghezza byte |
//! +--------------------+---------------------------+
//! ```
//!
//! # Perché una lunghezza e non un ritorno a capo
//!
//! Il PoC delimitava i messaggi con un ritorno a capo, e ha misurato il difetto
//! che ne segue (ADR-0044, misura 5): chi non lo manda mai fa crescere il buffer
//! dell'Hub senza mandare un messaggio valido. Con una lunghezza dichiarata il
//! tetto si controlla sui **quattro byte d'intestazione**, prima di allocare
//! anche un solo byte del contenuto.
//!
//! # Che cosa rende un frame inaccettabile
//!
//! - una lunghezza **zero**: nessun messaggio del protocollo è vuoto, e un frame
//!   vuoto ripetuto è un ciclo che non consuma nulla dell'avversario;
//! - una lunghezza **oltre il tetto** del momento;
//! - una connessione che **si chiude a metà** frame.
//!
//! In tutti e tre i casi la connessione non si può più leggere in modo
//! affidabile: il flusso ha perso l'allineamento, e **si chiude**.
//!
//! # La scadenza
//!
//! Il frame si legge entro una scadenza **unica**: chi manda un byte al secondo
//! non allunga la lettura oltre quella, perché prima di ogni lettura il tempo
//! massimo del socket si riduce a ciò che resta.

use std::io::{self, Read, Write};
use std::time::{Duration, Instant};

/// Il tetto assoluto di un frame: nessuna configurazione lo supera.
///
/// Un mebibyte. I messaggi di controllo stanno sotto il kibibyte; il tetto
/// esiste per le milestone che porteranno eventi e comandi (HUB-EVENT-01,
/// HUB-CMD-01), che lo **ridurranno** per tipo di messaggio, mai alzeranno.
pub const ABSOLUTE_MAX_FRAME_BYTES: u32 = 1024 * 1024;

/// Byte dell'intestazione.
pub const FRAME_HEADER_BYTES: usize = 4;

/// Un flusso che sa ridurre il proprio tempo massimo di lettura e scrittura.
///
/// Serve alla scadenza unica: i flussi TLS del trasporto lo implementano sul
/// socket che li porta.
pub trait TimedStream: Read + Write {
    /// Imposta il tempo massimo di ogni singola lettura e scrittura.
    ///
    /// # Errori
    ///
    /// L'errore del sistema, se il socket lo rifiuta.
    fn set_io_timeout(&mut self, timeout: Duration) -> io::Result<()>;
}

/// Perché un frame non si è potuto leggere o scrivere.
///
/// Nessuna variante porta i byte ricevuti.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FrameError {
    /// Lunghezza zero.
    Empty,
    /// Lunghezza oltre il tetto indicato.
    TooLarge,
    /// La connessione si è chiusa prima della fine del frame, o prima del suo
    /// inizio.
    Closed,
    /// La scadenza è passata.
    TimedOut,
    /// Un altro errore del flusso.
    Io(io::ErrorKind),
}

/// Scrive un frame.
///
/// # Errori
///
/// [`FrameError::Empty`] o [`FrameError::TooLarge`] se il contenuto non è un
/// frame ammesso; gli errori del flusso.
pub fn write_frame<W: Write + ?Sized>(
    writer: &mut W,
    payload: &[u8],
    max: u32,
) -> Result<(), FrameError> {
    let max = max.min(ABSOLUTE_MAX_FRAME_BYTES);
    if payload.is_empty() {
        return Err(FrameError::Empty);
    }
    let length = u32::try_from(payload.len()).map_err(|_| FrameError::TooLarge)?;
    if length > max {
        return Err(FrameError::TooLarge);
    }
    writer.write_all(&length.to_be_bytes()).map_err(io_kind)?;
    writer.write_all(payload).map_err(io_kind)?;
    writer.flush().map_err(io_kind)
}

/// Legge un frame entro `deadline`, rifiutando ciò che supera `max`.
///
/// # Errori
///
/// Vedere [`FrameError`].
pub fn read_frame<S: TimedStream + ?Sized>(
    stream: &mut S,
    max: u32,
    deadline: Instant,
) -> Result<Vec<u8>, FrameError> {
    let max = max.min(ABSOLUTE_MAX_FRAME_BYTES);

    let mut header = [0_u8; FRAME_HEADER_BYTES];
    read_exact_until(stream, &mut header, deadline)?;
    let length = u32::from_be_bytes(header);
    if length == 0 {
        return Err(FrameError::Empty);
    }
    // IL TETTO PRIMA DELL'ALLOCAZIONE.
    if length > max {
        return Err(FrameError::TooLarge);
    }

    let length = usize::try_from(length).map_err(|_| FrameError::TooLarge)?;
    let mut payload = vec![0_u8; length];
    read_exact_until(stream, &mut payload, deadline)?;
    Ok(payload)
}

/// Legge esattamente `buffer.len()` byte entro la scadenza.
fn read_exact_until<S: TimedStream + ?Sized>(
    stream: &mut S,
    buffer: &mut [u8],
    deadline: Instant,
) -> Result<(), FrameError> {
    let mut letti = 0;
    while letti < buffer.len() {
        let resta = deadline.saturating_duration_since(Instant::now());
        if resta.is_zero() {
            return Err(FrameError::TimedOut);
        }
        // Una durata nulla, per un socket, toglie il limite: mai sotto il
        // millisecondo.
        stream
            .set_io_timeout(resta.max(Duration::from_millis(1)))
            .map_err(io_kind)?;
        match stream.read(&mut buffer[letti..]) {
            Ok(0) => return Err(FrameError::Closed),
            Ok(n) => letti += n,
            Err(errore) => match errore.kind() {
                io::ErrorKind::Interrupted => {}
                io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut => {
                    if Instant::now() >= deadline {
                        return Err(FrameError::TimedOut);
                    }
                }
                altro => return Err(io_kind_of(altro)),
            },
        }
    }
    Ok(())
}

fn io_kind(errore: io::Error) -> FrameError {
    io_kind_of(errore.kind())
}

fn io_kind_of(kind: io::ErrorKind) -> FrameError {
    match kind {
        io::ErrorKind::UnexpectedEof
        | io::ErrorKind::ConnectionReset
        | io::ErrorKind::ConnectionAborted
        | io::ErrorKind::BrokenPipe => FrameError::Closed,
        io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut => FrameError::TimedOut,
        altro => FrameError::Io(altro),
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use std::io::{self, Read, Write};
    use std::time::{Duration, Instant};

    use super::{ABSOLUTE_MAX_FRAME_BYTES, FrameError, TimedStream, read_frame, write_frame};

    /// Un generatore deterministico di **byte**.
    ///
    /// # Perché non è quello del dominio
    ///
    /// Perché genera una cosa diversa. Il generatore di `lisi-core` produce
    /// **testo**, e per farlo deve produrre UTF-8 valido: è ciò che serve a
    /// esercitare un'estrazione che legge parole. Qui l'ingresso interessante è
    /// l'opposto — byte qualunque, **compreso ciò che UTF-8 non è** — perché è
    /// ciò che arriva da un socket quando dall'altra parte non c'è un client di
    /// questo prodotto.
    ///
    /// Un generatore solo, costretto a fare entrambe le cose, non ne farebbe
    /// bene nessuna.
    struct Byte {
        stato: u64,
    }

    impl Byte {
        const fn dal_seme(seme: u64) -> Self {
            Self {
                stato: if seme == 0 {
                    0x9e37_79b9_7f4a_7c15
                } else {
                    seme
                },
            }
        }

        const fn prossimo(&mut self) -> u64 {
            let mut x = self.stato;
            x ^= x >> 12;
            x ^= x << 25;
            x ^= x >> 27;
            self.stato = x;
            x.wrapping_mul(0x2545_f491_4f6c_dd1d)
        }

        fn quanti(&mut self, quanti: usize) -> Vec<u8> {
            (0..quanti)
                .map(|_| (self.prossimo() & 0xff) as u8)
                .collect()
        }
    }

    /// **Il lettore dei frame non si guasta su nessuna sequenza di byte, e non
    /// alloca mai più del tetto.**
    ///
    /// # Perché proprio qui, e perché una proprietà
    ///
    /// Perché è **l'unica superficie di questo prodotto che legge byte da una
    /// rete**, e dall'altra parte può non esserci un client di questo prodotto.
    /// Un'intestazione è quattro byte: dichiara una lunghezza, e quella
    /// lunghezza decide un'allocazione. È la forma classica in cui un lettore di
    /// protocollo si fa esaurire la memoria da una riga di quattro byte.
    ///
    /// Un elenco di esempi verifica i casi a cui qualcuno ha pensato. Qui i casi
    /// a cui pensare sono 2^32 lunghezze per qualunque coda, e la proprietà è
    /// enunciabile in una riga: **o restituisce un frame che sta nel tetto, o
    /// restituisce un errore**. Mai altro, e mai un panico.
    ///
    /// # Che cosa questa prova NON è
    ///
    /// Un fuzzer. Mille casi da un seme scritto non esplorano come esplora
    /// libFuzzer, e non ne hanno la pretesa: coprono la **forma** dell'ingresso
    /// in un cancello che deve finire. Che un fuzzer vero non sia mai stato
    /// eseguito su questa funzione è dichiarato (HVQ-83).
    #[test]
    fn il_lettore_dei_frame_regge_qualunque_sequenza_di_byte() {
        const SEME: u64 = 0x4e45_5855_4d39_37e5;
        const CASI: usize = 1_000;
        const TETTO: u32 = 4 * 1024;

        let mut generatore = Byte::dal_seme(SEME);

        for caso in 0..CASI {
            // TRE FORME DI CASO, e la terza e' quella che il primo tentativo non
            // aveva.
            //
            // Con le sole prime due il flusso finiva sempre prima di poter
            // consegnare un frame piu' lungo del tetto: un tetto sbagliato non
            // produceva un `Ok` troppo lungo, produceva `Closed`. La proprieta'
            // passava, e non poteva vedere il difetto — e' la stessa forma di
            // guardia che non guarda niente (ADR-0111), comparsa in una prova
            // scritta per impedirla.
            //
            // La terza forma dichiara una lunghezza SOPRA IL TETTO e fornisce
            // davvero quei byte: e' l'unico caso in cui un tetto applicato al
            // limite sbagliato si vede.
            let (dichiarata, coda): (u32, Vec<u8>) = match caso % 3 {
                0 => {
                    let quanti = usize::try_from(generatore.prossimo() % 64).unwrap_or(0);
                    let byte = generatore.quanti(quanti + 96);
                    (u32::try_from(quanti).unwrap_or(0), byte)
                }
                1 => {
                    let dichiarata =
                        u32::try_from(generatore.prossimo() & 0xffff_ffff).unwrap_or(u32::MAX);
                    let quanti = usize::try_from(generatore.prossimo() % 96).unwrap_or(0);
                    (dichiarata, generatore.quanti(quanti))
                }
                _ => {
                    let oltre = TETTO + u32::try_from(generatore.prossimo() % 512).unwrap_or(1) + 1;
                    let byte = generatore.quanti(usize::try_from(oltre).unwrap_or(0));
                    (oltre, byte)
                }
            };

            let mut byte = dichiarata.to_be_bytes().to_vec();
            byte.extend_from_slice(&coda);

            let mut flusso = Memoria::con(byte);
            let esito = read_frame(&mut flusso, TETTO, Instant::now() + Duration::from_secs(2));

            // UN ERRORE E' UNA RISPOSTA VALIDA, ed e' meta' del valore di questa
            // proprieta': cio' che conta e' che non ce ne sia una terza, e che
            // non si passi mai per un panico.
            if let Ok(frame) = esito {
                assert!(
                    frame.len() <= TETTO as usize,
                    "caso {caso}: il lettore ha restituito {} byte, oltre il tetto di \
                     {TETTO}. Riproducibile dal seme {SEME:#x}",
                    frame.len()
                );
                assert_eq!(
                    frame.len(),
                    dichiarata as usize,
                    "caso {caso}: il frame restituito non e' lungo quanto l'intestazione \
                     dichiarava. Riproducibile dal seme {SEME:#x}"
                );
            }
        }
    }

    /// Un flusso in memoria: legge da `input` a pezzi di `chunk` byte, e
    /// risponde `WouldBlock` quando è finito ma non chiuso.
    pub(crate) struct Memoria {
        pub(crate) input: Vec<u8>,
        pub(crate) posizione: usize,
        pub(crate) chunk: usize,
        pub(crate) chiuso: bool,
        pub(crate) output: Vec<u8>,
        pub(crate) letture: usize,
    }

    impl Memoria {
        pub(crate) fn con(input: Vec<u8>) -> Self {
            Self {
                input,
                posizione: 0,
                chunk: usize::MAX,
                chiuso: true,
                output: Vec::new(),
                letture: 0,
            }
        }
    }

    impl Read for Memoria {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            self.letture += 1;
            if self.posizione >= self.input.len() {
                if self.chiuso {
                    return Ok(0);
                }
                std::thread::sleep(Duration::from_millis(5));
                return Err(io::Error::from(io::ErrorKind::WouldBlock));
            }
            let n = buf
                .len()
                .min(self.chunk)
                .min(self.input.len() - self.posizione);
            buf[..n].copy_from_slice(&self.input[self.posizione..self.posizione + n]);
            self.posizione += n;
            Ok(n)
        }
    }

    impl Write for Memoria {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.output.extend_from_slice(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    impl TimedStream for Memoria {
        fn set_io_timeout(&mut self, _timeout: Duration) -> io::Result<()> {
            Ok(())
        }
    }

    fn fra_poco() -> Instant {
        Instant::now() + Duration::from_secs(2)
    }

    #[test]
    fn a_frame_round_trips_even_when_it_arrives_one_byte_at_a_time() {
        let mut scritto = Vec::new();
        assert_eq!(write_frame(&mut scritto, b"ciao", 16), Ok(()));
        assert_eq!(&scritto[..4], &[0, 0, 0, 4]);

        let mut flusso = Memoria::con(scritto);
        flusso.chunk = 1;
        assert_eq!(
            read_frame(&mut flusso, 16, fra_poco()),
            Ok(b"ciao".to_vec())
        );
    }

    #[test]
    fn the_limit_is_checked_on_the_header_before_reading_the_payload() {
        // Intestazione che dichiara quattro gigabyte, e nessun contenuto: se il
        // tetto venisse controllato dopo, la lettura proverebbe ad allocarli.
        let mut flusso = Memoria::con(u32::MAX.to_be_bytes().to_vec());
        assert_eq!(
            read_frame(&mut flusso, 1024, fra_poco()),
            Err(FrameError::TooLarge)
        );
        assert_eq!(
            flusso.posizione, 4,
            "il contenuto non deve essere nemmeno cercato"
        );

        // Esattamente al tetto passa, un byte oltre no.
        let mut al_tetto = 8_u32.to_be_bytes().to_vec();
        al_tetto.extend_from_slice(&[7; 8]);
        assert!(read_frame(&mut Memoria::con(al_tetto), 8, fra_poco()).is_ok());
        let mut oltre = 9_u32.to_be_bytes().to_vec();
        oltre.extend_from_slice(&[7; 9]);
        assert_eq!(
            read_frame(&mut Memoria::con(oltre), 8, fra_poco()),
            Err(FrameError::TooLarge)
        );
    }

    #[test]
    fn no_configuration_raises_the_absolute_ceiling() {
        let oltre = (ABSOLUTE_MAX_FRAME_BYTES + 1).to_be_bytes().to_vec();
        assert_eq!(
            read_frame(&mut Memoria::con(oltre), u32::MAX, fra_poco()),
            Err(FrameError::TooLarge)
        );
        let grande = vec![1_u8; usize::try_from(ABSOLUTE_MAX_FRAME_BYTES).unwrap_or(0) + 1];
        assert_eq!(
            write_frame(&mut Vec::new(), &grande, u32::MAX),
            Err(FrameError::TooLarge)
        );
    }

    #[test]
    fn empty_truncated_and_silent_frames_are_refused() {
        assert_eq!(
            read_frame(&mut Memoria::con(vec![0, 0, 0, 0]), 16, fra_poco()),
            Err(FrameError::Empty)
        );
        assert_eq!(
            write_frame(&mut Vec::new(), b"", 16),
            Err(FrameError::Empty)
        );

        let mut troncato = 10_u32.to_be_bytes().to_vec();
        troncato.extend_from_slice(b"abc");
        assert_eq!(
            read_frame(&mut Memoria::con(troncato), 16, fra_poco()),
            Err(FrameError::Closed)
        );
        assert_eq!(
            read_frame(&mut Memoria::con(vec![0, 0]), 16, fra_poco()),
            Err(FrameError::Closed)
        );

        // Un interlocutore che non chiude e non manda: la scadenza vince.
        let mut muto = Memoria::con(vec![0, 0, 0, 5, b'a']);
        muto.chiuso = false;
        let inizio = Instant::now();
        assert_eq!(
            read_frame(&mut muto, 16, Instant::now() + Duration::from_millis(100)),
            Err(FrameError::TimedOut)
        );
        assert!(inizio.elapsed() < Duration::from_secs(1));
    }
}
