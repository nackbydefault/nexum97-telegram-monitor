//! L'arruolamento di un dispositivo presso un Hub.
//!
//! HUB-02 ha dato a ogni postazione un'identità propria e ha dichiarato, in ogni
//! testo, che **nessun Hub la conosce**. Questo modulo è il momento in cui un Hub
//! comincia a conoscerla — e le tre condizioni perché quel momento sia sicuro.
//!
//! # Chi autorizza
//!
//! Non il dispositivo. Un dispositivo che si arruolasse da solo renderebbe
//! l'arruolamento una formalità: chiunque raggiunga l'Hub entrerebbe.
//!
//! Autorizza una **persona**, dall'Hub, emettendo un [`EnrollmentCode`] che
//! consegna fuori banda — a voce, di persona, su un canale che non è quello che
//! si sta autorizzando. Il codice vale **una volta sola** e **per poco tempo**.
//!
//! # Che cosa l'arruolamento stabilisce
//!
//! Il dispositivo deriva dal proprio segreto — quello di HUB-02, che non lascia
//! mai la macchina — un **gettone** legato a quell'Hub, e consegna all'Hub
//! soltanto l'**impronta** del gettone.
//!
//! Ne seguono tre proprietà, e vanno lette insieme al limite che le accompagna:
//!
//! - **l'Hub non conserva nulla di riutilizzabile.** Chi rubasse il suo archivio
//!   troverebbe impronte, non credenziali;
//! - **il segreto del dispositivo non attraversa mai la rete**, nemmeno durante
//!   l'arruolamento: attraversa il gettone, che è derivato;
//! - **il gettone vale per quell'Hub soltanto.** Un dispositivo arruolato presso
//!   due Hub ha due gettoni diversi, perché il sale è diverso, e nessuno dei due
//!   serve altrove.
//!
//! **Il limite:** il gettone, quando verrà presentato, attraverserà la rete. È
//! la stessa forma di una parola d'accesso, ed è sicura **solo sotto TLS**. Il
//! trasporto è HUB-04, e finché non esiste nessuno deve presentare un gettone su
//! una rete. ADR-0047 lo scrive, e dice anche quale schema — una firma
//! asimmetrica — toglierebbe quel vincolo, e perché non è stato preso adesso.
//!
//! # Che cosa questo modulo non fa
//!
//! Non parla in rete, non apre porte, non cifra. Non autentica una richiesta
//! successiva all'arruolamento: decide **chi entra**, non **chi sta parlando
//! adesso**.

use core::fmt;

use crate::digest::Sha256Digest;
use crate::error::{DomainError, DomainResult};
use crate::model::identity::{DeviceId, DeviceSecret, SECRET_REDACTED};
use crate::model::readable_code;
use crate::text::{DisplayName, Note};
use crate::time::Timestamp;

// ---------------------------------------------------------------------------
// Il codice di autorizzazione
// ---------------------------------------------------------------------------

/// Byte casuali di un codice di arruolamento.
///
/// Ottanta bit, che entrano in sedici cifre **senza avanzi**. Non è una scelta
/// di prudenza esagerata: il codice si legge ad alta voce una volta per
/// dispositivo, per sempre, e la lunghezza si paga una volta sola.
pub const ENROLLMENT_CODE_BYTES: usize = 10;

/// Cifre di un codice di arruolamento, separatori esclusi.
pub const ENROLLMENT_CODE_DIGITS: usize = 16;

/// Cifre per gruppo nella forma canonica.
const CIFRE_PER_GRUPPO: usize = 4;

/// Quanto vale un codice di arruolamento, in minuti.
///
/// # Perché breve
///
/// Un codice è un'autorizzazione che cammina: viene detto a voce, scritto su un
/// foglietto, mandato in un messaggio. Più a lungo vale, più a lungo quel
/// foglietto è una chiave. Un quarto d'ora basta a raggiungere la postazione
/// accanto e non basta a dimenticarsene.
pub const ENROLLMENT_CODE_MINUTES: i64 = 15;

/// Il codice che una persona emette dall'Hub e consegna fuori banda.
///
/// # Perché è un segreto, e perché si mostra lo stesso
///
/// Chi conosce il codice può arruolare un dispositivo. È quindi un segreto:
/// `Debug` non lo rende, e `Display` **non è implementato**.
///
/// Ma esiste per essere letto ad alta voce, e quindi una via per leggerlo deve
/// esserci. Si chiama [`Self::reveal_to_administrator`], ed è scomoda apposta:
/// ogni chiamata è un punto in cui il codice esce, e deve risultare tale a chi
/// legge il codice sorgente.
#[derive(Clone, PartialEq, Eq)]
pub struct EnrollmentCode(String);

impl EnrollmentCode {
    /// Costruisce il codice dai byte casuali forniti.
    ///
    /// I byte devono venire dal generatore crittografico del sistema. Vale
    /// l'osservazione di [`DeviceId::from_random_bytes`]: `lisi-core` non ne
    /// possiede uno, e uno scritto qui sarebbe scritto in casa.
    #[must_use]
    pub fn from_random_bytes(bytes: &[u8; ENROLLMENT_CODE_BYTES]) -> Self {
        Self(readable_code::encode(
            bytes,
            ENROLLMENT_CODE_DIGITS,
            CIFRE_PER_GRUPPO,
        ))
    }

    /// Riconosce un codice ridigitato da chi l'ha ricevuto.
    ///
    /// Accetta minuscole, separatori mancanti e le confusioni di lettura
    /// previste dall'alfabeto.
    ///
    /// # Errori
    ///
    /// Restituisce [`DomainError::InvalidEnrollmentCode`] se le cifre non sono
    /// sedici o se una di esse non appartiene all'alfabeto.
    pub fn parse(raw: &str) -> DomainResult<Self> {
        readable_code::canonicalize(raw, ENROLLMENT_CODE_DIGITS, CIFRE_PER_GRUPPO)
            .map(Self)
            .map_err(|forma| DomainError::InvalidEnrollmentCode {
                reason: match forma {
                    readable_code::FormaScorretta::CarattereEstraneo => {
                        "contiene un carattere che non appartiene all'alfabeto"
                    }
                    readable_code::FormaScorretta::Lunghezza => "non ha sedici cifre",
                },
            })
    }

    /// Mostra il codice alla persona che lo deve consegnare.
    ///
    /// Il nome è scomodo apposta. Non usarla per registrare, esportare o
    /// confrontare: per confrontare c'è [`Self::fingerprint`].
    #[must_use]
    pub fn reveal_to_administrator(&self) -> &str {
        &self.0
    }

    /// Impronta con cui l'Hub riconosce il codice senza conservarlo.
    ///
    /// # Perché senza sale, a differenza delle parole di sblocco
    ///
    /// `lisi-services::passphrase` sala, e deve: una parola scelta da una persona
    /// sta in un dizionario, e senza sale due postazioni con la stessa parola
    /// mostrerebbero la stessa impronta.
    ///
    /// Un codice di arruolamento **non sta in nessun dizionario**: sono ottanta
    /// bit del generatore crittografico. Non c'è nulla da provare per tentativi,
    /// e non c'è collisione di significato da nascondere. Il sale
    /// aggiungerebbe una colonna e nessuna protezione, e una protezione
    /// apparente è peggio di nessuna.
    #[must_use]
    pub fn fingerprint(&self) -> Sha256Digest {
        Sha256Digest::of_text(&self.0)
    }
}

impl fmt::Debug for EnrollmentCode {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(SECRET_REDACTED)
    }
}

// ---------------------------------------------------------------------------
// Il gettone e la sua impronta
// ---------------------------------------------------------------------------

/// Byte del sale con cui un dispositivo lega il proprio gettone a un Hub.
pub const ENROLLMENT_SALT_BYTES: usize = 16;

/// Il sale che rende il gettone valido per un Hub soltanto.
///
/// **Non è un segreto**: si conserva in chiaro e non protegge nulla da solo. Il
/// suo mestiere è che lo stesso dispositivo, arruolato presso due Hub, presenti
/// due gettoni diversi — così che il gettone rubato a un Hub non apra l'altro.
///
/// # Perché lo sceglie il dispositivo e non l'Hub
///
/// Perché così l'arruolamento è **un giro solo**. Se il sale venisse dall'Hub
/// servirebbe un secondo scambio per riportarne l'impronta.
///
/// Non indebolisce nulla: un dispositivo ostile controlla comunque la propria
/// credenziale — può mandare l'impronta che vuole — e un sale scelto male
/// danneggia soltanto sé stesso.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnrollmentSalt(String);

impl EnrollmentSalt {
    /// Costruisce il sale dai byte casuali forniti.
    #[must_use]
    pub fn from_random_bytes(bytes: &[u8; ENROLLMENT_SALT_BYTES]) -> Self {
        let mut testo = String::with_capacity(ENROLLMENT_SALT_BYTES * 2);
        for valore in bytes {
            testo.push(cifra_esadecimale(valore >> 4));
            testo.push(cifra_esadecimale(valore & 0x0F));
        }
        Self(testo)
    }

    /// Riconosce un sale conservato.
    ///
    /// # Errori
    ///
    /// Restituisce [`DomainError::InvalidEnrollmentCode`] se il testo non è
    /// esadecimale della lunghezza prevista.
    pub fn parse(raw: &str) -> DomainResult<Self> {
        let giusto = raw.len() == ENROLLMENT_SALT_BYTES * 2
            && raw.bytes().all(|byte| byte.is_ascii_hexdigit());
        if !giusto {
            return Err(DomainError::InvalidEnrollmentCode {
                reason: "il sale dell'arruolamento non ha la forma prevista",
            });
        }
        Ok(Self(raw.to_ascii_lowercase()))
    }

    /// Forma testuale, esadecimale minuscola.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Cifra esadecimale di un valore fra zero e quindici.
fn cifra_esadecimale(valore: u8) -> char {
    match valore {
        0..=9 => char::from(b'0' + valore),
        10..=15 => char::from(b'a' + valore - 10),
        // Il chiamante passa sempre un mezzo byte. La variante esiste per non
        // scrivere un unwrap su un'invariante che il tipo non esprime.
        _ => '0',
    }
}

/// Il gettone con cui un dispositivo si presenterà a **quell'**Hub.
///
/// # Perché non si conserva
///
/// Non c'è alcun metodo che lo scriva su disco, e non è una dimenticanza. Il
/// gettone si **ricalcola** da ciò che il dispositivo ha già — il segreto sotto
/// DPAPI e il sale — ogni volta che serve. Conservarlo aggiungerebbe una seconda
/// copia da proteggere senza aggiungere niente.
///
/// Come [`DeviceSecret`]: niente `Display`, niente `Clone`, niente
/// serializzazione, `Debug` redatto, confronto che non esce in anticipo.
pub struct DeviceToken([u8; 32]);

impl DeviceToken {
    /// Deriva il gettone dal segreto del dispositivo e dal sale dell'Hub.
    ///
    /// # Perché SHA-256 e non una derivazione lenta
    ///
    /// Per la stessa ragione per cui l'impronta del codice non è salata: una
    /// derivazione lenta serve contro chi prova per tentativi, e un segreto di
    /// trentadue byte uniformi non si prova per tentativi. Contro un ingresso
    /// senza dizionario, Argon2 costerebbe una dipendenza e non aggiungerebbe
    /// protezione.
    #[must_use]
    pub fn derive(salt: &EnrollmentSalt, secret: &DeviceSecret) -> Self {
        use sha2::{Digest, Sha256};

        let mut hasher = Sha256::new();
        // Il sale entra come byte del suo testo, e un separatore lo chiude.
        //
        // Oggi l'ambiguita' non e' possibile: il sale ha lunghezza fissa per
        // costruzione e il segreto e' un array di trentadue byte. Il separatore
        // non costa nulla e la esclude anche se una delle due lunghezze
        // cambiasse — che e' il momento in cui nessuno ripenserebbe a questo
        // punto.
        hasher.update(salt.as_str().as_bytes());
        hasher.update(b"|");
        hasher.update(secret.expose());
        Self(hasher.finalize().into())
    }

    /// Impronta che l'Hub conserva al posto del gettone.
    #[must_use]
    pub fn verifier(&self) -> Sha256Digest {
        Sha256Digest::of_bytes(&self.0)
    }

    /// Espone i byte del gettone.
    ///
    /// Il nome è scomodo apposta: ogni chiamata è un punto in cui il gettone
    /// esce, e sotto TLS quel punto è la rete.
    #[must_use]
    pub const fn expose(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Debug for DeviceToken {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(SECRET_REDACTED)
    }
}

impl PartialEq for DeviceToken {
    /// Confronto scritto per non uscire in anticipo sulla prima differenza,
    /// con lo stesso limite dichiarato di [`DeviceSecret`]: il linguaggio non
    /// garantisce che resti tale dopo l'ottimizzazione.
    fn eq(&self, other: &Self) -> bool {
        let mut differenze = 0_u8;
        for (mio, suo) in self.0.iter().zip(other.0.iter()) {
            differenze |= mio ^ suo;
        }
        differenze == 0
    }
}

impl Eq for DeviceToken {}

impl Drop for DeviceToken {
    fn drop(&mut self) {
        // Sovrascrittura best-effort, con lo stesso limite dichiarato per
        // DeviceSecret: cancella la copia che si conosce, non quelle che il
        // sistema puo' aver fatto.
        self.0.fill(0);
    }
}

// ---------------------------------------------------------------------------
// La richiesta e il suo esito
// ---------------------------------------------------------------------------

/// Ciò che un dispositivo presenta per essere arruolato.
///
/// `Debug` è derivato e resta sicuro perché il codice si redige da sé: è il
/// vantaggio di aver messo la redazione nel tipo invece che nella disciplina di
/// chi scrive.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnrollmentRequest {
    /// Quale dispositivo chiede di entrare.
    pub device_id: DeviceId,
    /// Come lo chiama l'ufficio, perché l'amministratore lo riconosca.
    pub label: DisplayName,
    /// L'autorizzazione ricevuta fuori banda.
    pub code: EnrollmentCode,
    /// Il sale scelto dal dispositivo.
    pub salt: EnrollmentSalt,
    /// L'impronta del gettone. **Non è il gettone.**
    pub verifier: Sha256Digest,
}

/// Ciò che l'Hub restituisce quando accetta.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnrollmentGrant {
    /// Come si chiama l'Hub che ha accettato, perché l'operatore sappia dove è
    /// entrato.
    pub hub: DisplayName,
    /// Quando.
    pub enrolled_at: Timestamp,
}

/// Perché l'Hub non ha accettato.
///
/// # Perché il rifiuto dice quale controllo è fallito
///
/// «Arruolamento rifiutato» senza altro manda chi indaga a leggere il codice
/// sorgente, e in un ufficio manda a rifare il giro con lo stesso errore. È lo
/// stesso criterio già fissato per gli aggiornamenti (ADR-0045, requisito 4).
///
/// # E perché dirlo non aiuta chi tenta
///
/// Nessuna di queste ragioni distingue *un codice sbagliato* da *un codice che
/// non esiste*: [`Self::CodeNotRecognised`] copre entrambi. Chi prova a
/// indovinare non impara nulla dal rifiuto; chi ha ricevuto un codice vero
/// impara che cosa è andato storto.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EnrollmentRefusal {
    /// Il codice non corrisponde a nessuna autorizzazione viva.
    ///
    /// Copre di proposito due casi diversi — codice inesistente e codice
    /// sbagliato — perché distinguerli direbbe a chi tenta se è vicino.
    CodeNotRecognised,
    /// Il codice era valido e non lo è più.
    CodeExpired,
    /// Il codice ha già arruolato un dispositivo.
    CodeAlreadyUsed,
    /// Il dispositivo risulta già arruolato presso questo Hub.
    DeviceAlreadyEnrolled,
    /// Il dispositivo era arruolato ed è stato ritirato.
    DeviceRevoked {
        /// Perché era stato ritirato.
        reason: Note,
    },
    /// Troppi tentativi falliti di recente, su questo Hub.
    TooManyRecentFailures {
        /// Fra quanti minuti si potrà riprovare.
        retry_in_minutes: i64,
    },
}

impl EnrollmentRefusal {
    /// Frase da mostrare a chi sta arruolando.
    #[must_use]
    pub fn operator_message(&self) -> String {
        match self {
            Self::CodeNotRecognised => String::from(
                "Il codice non è stato riconosciuto. Controllare di averlo ricopiato per \
                 intero, oppure farsene emettere uno nuovo dall'Hub.",
            ),
            Self::CodeExpired => format!(
                "Il codice è scaduto: vale {ENROLLMENT_CODE_MINUTES} minuti dall'emissione. \
                 Farsene emettere uno nuovo dall'Hub."
            ),
            Self::CodeAlreadyUsed => String::from(
                "Il codice ha già arruolato un dispositivo. Ogni codice vale una volta sola: \
                 per un secondo dispositivo ne serve un altro.",
            ),
            Self::DeviceAlreadyEnrolled => String::from(
                "Questo dispositivo è già arruolato presso questo Hub. Non serve rifarlo.",
            ),
            Self::DeviceRevoked { reason } => format!(
                "Questo dispositivo è stato ritirato dall'Hub: {}. Un dispositivo ritirato \
                 non si riarruola: chi amministra l'Hub deve deciderlo, e la postazione \
                 deve ricevere un'identità nuova.",
                reason.as_str()
            ),
            Self::TooManyRecentFailures { retry_in_minutes } => format!(
                "Troppi tentativi falliti di recente su questo Hub. Riprovare fra \
                 {retry_in_minutes} minuti, oppure verificare con chi amministra l'Hub che \
                 nessun altro stia tentando."
            ),
        }
    }

    /// Ragione breve e stabile, per l'audit e per il conteggio dei tentativi.
    #[must_use]
    pub const fn audit_detail(&self) -> &'static str {
        match self {
            Self::CodeNotRecognised => "codice_non_riconosciuto",
            Self::CodeExpired => "codice_scaduto",
            Self::CodeAlreadyUsed => "codice_gia_usato",
            Self::DeviceAlreadyEnrolled => "dispositivo_gia_arruolato",
            Self::DeviceRevoked { .. } => "dispositivo_ritirato",
            Self::TooManyRecentFailures { .. } => "troppi_tentativi",
        }
    }

    /// Vero se il rifiuto è un tentativo andato a vuoto e va contato.
    ///
    /// # Perché non tutti i rifiuti si contano
    ///
    /// Il conteggio serve a fermare chi prova a indovinare. Un dispositivo già
    /// arruolato che riprova non sta indovinando niente: contarlo permetterebbe
    /// a un errore ripetuto in buona fede di bloccare l'arruolamento di tutti,
    /// che è un guasto costruito con le proprie mani.
    #[must_use]
    pub const fn counts_as_attempt(&self) -> bool {
        matches!(self, Self::CodeNotRecognised | Self::CodeExpired)
    }
}

/// Quanti tentativi falliti fermano l'arruolamento, e per quanto.
///
/// # Il compromesso, dichiarato
///
/// Il blocco è **dell'Hub e del solo arruolamento**, non del dispositivo: chi
/// tenta non sa quale dispositivo sta bloccando, e non può quindi prendere di
/// mira qualcuno.
///
/// Il rovescio è che chi tenta **può impedire un arruolamento legittimo** per la
/// durata della finestra. È un guasto accettabile perché l'arruolamento è un
/// atto raro e programmato, non un'operazione quotidiana: un amministratore che
/// lo trova bloccato aspetta un quarto d'ora, e nel frattempo ha imparato che
/// qualcuno sta tentando — che è un'informazione che senza il blocco non
/// avrebbe.
pub const MAX_RECENT_FAILURES: u32 = 10;

/// Ampiezza della finestra dei tentativi, in minuti.
pub const FAILURE_WINDOW_MINUTES: i64 = 15;

#[cfg(test)]
mod tests {
    use super::{
        DeviceToken, ENROLLMENT_CODE_BYTES, ENROLLMENT_SALT_BYTES, EnrollmentCode,
        EnrollmentRefusal, EnrollmentSalt,
    };
    use crate::model::identity::{DEVICE_SECRET_BYTES, DeviceSecret, SECRET_REDACTED};
    use crate::text::Note;

    fn segreto(riempimento: u8) -> DeviceSecret {
        DeviceSecret::from_random_bytes([riempimento; DEVICE_SECRET_BYTES])
    }

    fn sale(riempimento: u8) -> EnrollmentSalt {
        EnrollmentSalt::from_random_bytes(&[riempimento; ENROLLMENT_SALT_BYTES])
    }

    fn nota(testo: &str) -> Note {
        let Ok(valore) = Note::try_new(testo) else {
            panic!("la nota di prova deve essere valida");
        };
        valore
    }

    // -----------------------------------------------------------------
    // Il codice
    // -----------------------------------------------------------------

    /// **Il codice non compare in un registro nemmeno per distrazione.**
    ///
    /// # Il difetto che questa prova impedisce
    ///
    /// Chi conosce il codice puo' arruolare un dispositivo. Un
    /// `tracing::info!(?richiesta)` scritto senza pensarci scriverebbe
    /// un'autorizzazione viva in un file di registro che finisce in un pacchetto
    /// diagnostico — e il codice vale un quarto d'ora, che e' abbondantemente
    /// piu' di quanto serva a leggerlo.
    #[test]
    fn il_codice_non_si_legge_nella_resa_di_debug() {
        let codice = EnrollmentCode::from_random_bytes(&[0xAB; ENROLLMENT_CODE_BYTES]);
        let reso = format!("{codice:?}");
        assert_eq!(reso, SECRET_REDACTED);
        assert!(
            !reso.contains(codice.reveal_to_administrator()),
            "la resa di Debug lascia leggere il codice: «{reso}»"
        );

        // E anche annidato: e' il caso che conta, perche' e' cosi' che finisce
        // nei registri.
        let annidato = (1_u8, codice);
        let reso = format!("{annidato:?}");
        assert!(
            reso.contains(SECRET_REDACTED),
            "il codice annidato non e' redatto: «{reso}»"
        );
    }

    /// **Il codice si mostra a chi lo deve consegnare, e ha la forma prevista.**
    #[test]
    fn il_codice_si_mostra_in_sedici_cifre_e_quattro_gruppi() {
        let codice = EnrollmentCode::from_random_bytes(&[0x00; ENROLLMENT_CODE_BYTES]);
        assert_eq!(codice.reveal_to_administrator(), "0000-0000-0000-0000");

        let codice = EnrollmentCode::from_random_bytes(&[0xFF; ENROLLMENT_CODE_BYTES]);
        assert_eq!(codice.reveal_to_administrator(), "ZZZZ-ZZZZ-ZZZZ-ZZZZ");
    }

    /// **Ricopiare male non produce un codice diverso.**
    #[test]
    fn un_codice_ridigitato_a_mano_resta_lo_stesso() {
        let Ok(atteso) = EnrollmentCode::parse("0J2K-M3NP-4QRS-5TVW") else {
            panic!("la forma canonica deve essere riconosciuta");
        };

        for ricopiato in [
            "0j2k-m3np-4qrs-5tvw",
            "0J2KM3NP4QRS5TVW",
            "0J2K M3NP 4QRS 5TVW",
            "OJ2K-M3NP-4QRS-5TVW",
        ] {
            let Ok(letto) = EnrollmentCode::parse(ricopiato) else {
                panic!("«{ricopiato}» doveva essere riconosciuto");
            };
            assert_eq!(letto, atteso, "«{ricopiato}» ha prodotto un codice diverso");
            assert_eq!(
                letto.fingerprint(),
                atteso.fingerprint(),
                "«{ricopiato}» ha prodotto un'impronta diversa: l'Hub non lo \
                 riconoscerebbe"
            );
        }
    }

    /// **Un codice storto e' rifiutato.**
    #[test]
    fn un_codice_storto_e_rifiutato() {
        for storto in [
            "",
            "0J2K-M3NP",
            "0J2K-M3NP-4QRS-5TVW-6XYZ",
            "0J2K-M3NP-4QRS-5TVU",
            "0J2K-M3NP-4QRS-5TV!",
        ] {
            assert!(
                EnrollmentCode::parse(storto).is_err(),
                "«{storto}» e' stato accettato come codice"
            );
        }
    }

    /// **L'impronta non contiene il codice.**
    ///
    /// E' cio' che permette all'Hub di riconoscere un codice senza conservarne
    /// uno utilizzabile: chi legge l'archivio dell'Hub non trova
    /// autorizzazioni vive.
    #[test]
    fn l_impronta_del_codice_non_contiene_il_codice() {
        let codice = EnrollmentCode::from_random_bytes(&[0x5C; ENROLLMENT_CODE_BYTES]);
        let impronta = codice.fingerprint();
        let cifre: String = codice
            .reveal_to_administrator()
            .chars()
            .filter(|carattere| *carattere != '-')
            .collect();

        assert!(
            !impronta.as_str().contains(&cifre.to_lowercase()),
            "l'impronta contiene il codice"
        );
        assert_ne!(impronta.as_str(), cifre.to_lowercase());

        // Due codici diversi hanno impronte diverse: senza, l'Hub scambierebbe
        // un'autorizzazione per un'altra.
        let altro = EnrollmentCode::from_random_bytes(&[0x5D; ENROLLMENT_CODE_BYTES]);
        assert_ne!(impronta, altro.fingerprint());
    }

    // -----------------------------------------------------------------
    // Il sale e il gettone
    // -----------------------------------------------------------------

    /// **Il sale si rilegge, e una forma storta e' rifiutata.**
    #[test]
    fn il_sale_si_rilegge_e_rifiuta_le_forme_storte() {
        let originale = sale(0x3F);
        let Ok(riletto) = EnrollmentSalt::parse(originale.as_str()) else {
            panic!("il sale deve potersi rileggere");
        };
        assert_eq!(riletto, originale);

        // Maiuscolo e minuscolo sono lo stesso sale: un sale ricopiato in
        // maiuscolo darebbe altrimenti un gettone diverso, e il dispositivo non
        // entrerebbe piu' senza che nulla spieghi perche'.
        let Ok(maiuscolo) = EnrollmentSalt::parse(&originale.as_str().to_uppercase()) else {
            panic!("il sale in maiuscolo deve potersi rileggere");
        };
        assert_eq!(maiuscolo, originale);

        for storto in ["", "abc", &"z".repeat(32), &"a".repeat(31), &"a".repeat(33)] {
            assert!(
                EnrollmentSalt::parse(storto).is_err(),
                "«{storto}» e' stato accettato come sale"
            );
        }
    }

    /// **Il gettone cambia se cambia il sale, e se cambia il segreto.**
    ///
    /// # Perche' entrambe le meta' contano
    ///
    /// Se il gettone non dipendesse dal **sale**, lo stesso dispositivo
    /// arruolato presso due Hub presenterebbe lo stesso valore, e il gettone
    /// rubato a un Hub aprirebbe l'altro.
    ///
    /// Se non dipendesse dal **segreto**, due dispositivi che scegliessero lo
    /// stesso sale avrebbero la stessa credenziale, e l'identita' non
    /// significherebbe nulla.
    #[test]
    fn il_gettone_dipende_dal_sale_e_dal_segreto() {
        let base = DeviceToken::derive(&sale(0x11), &segreto(0x22));

        assert_eq!(
            base,
            DeviceToken::derive(&sale(0x11), &segreto(0x22)),
            "la derivazione non e' ripetibile: il dispositivo non potrebbe \
             ricalcolare il proprio gettone"
        );
        assert_ne!(
            base,
            DeviceToken::derive(&sale(0x12), &segreto(0x22)),
            "il gettone non dipende dal sale: due Hub avrebbero lo stesso valore"
        );
        assert_ne!(
            base,
            DeviceToken::derive(&sale(0x11), &segreto(0x23)),
            "il gettone non dipende dal segreto: due dispositivi avrebbero la \
             stessa credenziale"
        );
    }

    /// **Il gettone non compare in un registro, e la sua impronta non e' lui.**
    #[test]
    fn il_gettone_e_redatto_e_la_sua_impronta_non_lo_rivela() {
        let gettone = DeviceToken::derive(&sale(0x44), &segreto(0x55));
        assert_eq!(format!("{gettone:?}"), SECRET_REDACTED);

        let impronta = gettone.verifier();
        let mut in_chiaro = String::new();
        for byte in gettone.expose() {
            in_chiaro.push_str(&format!("{byte:02x}"));
        }
        assert_ne!(
            impronta.as_str(),
            in_chiaro,
            "l'impronta e' il gettone stesso: l'Hub conserverebbe una credenziale \
             utilizzabile"
        );
        assert!(!impronta.as_str().contains(&in_chiaro[..16]));
    }

    /// **Una differenza in qualunque posizione del gettone si vede.**
    #[test]
    fn il_confronto_del_gettone_vede_ogni_posizione() {
        let uno = DeviceToken::derive(&sale(0x01), &segreto(0x02));
        let due = DeviceToken::derive(&sale(0x01), &segreto(0x03));
        assert_ne!(uno, due);
        assert_eq!(uno, DeviceToken::derive(&sale(0x01), &segreto(0x02)));
    }

    // -----------------------------------------------------------------
    // I rifiuti
    // -----------------------------------------------------------------

    /// **Ogni rifiuto dice quale controllo e' fallito, con parole diverse.**
    #[test]
    fn ogni_rifiuto_ha_una_ragione_propria() {
        let rifiuti = [
            EnrollmentRefusal::CodeNotRecognised,
            EnrollmentRefusal::CodeExpired,
            EnrollmentRefusal::CodeAlreadyUsed,
            EnrollmentRefusal::DeviceAlreadyEnrolled,
            EnrollmentRefusal::DeviceRevoked {
                reason: nota("sostituito"),
            },
            EnrollmentRefusal::TooManyRecentFailures {
                retry_in_minutes: 7,
            },
        ];

        let mut ragioni = std::collections::BTreeSet::new();
        let mut messaggi = std::collections::BTreeSet::new();
        for rifiuto in &rifiuti {
            assert!(
                ragioni.insert(rifiuto.audit_detail()),
                "due rifiuti condividono la ragione «{}»: nell'audit non si \
                 distinguerebbero",
                rifiuto.audit_detail()
            );
            let messaggio = rifiuto.operator_message();
            assert!(
                messaggio.len() > 30,
                "il messaggio di «{}» non spiega nulla",
                rifiuto.audit_detail()
            );
            assert!(
                messaggi.insert(messaggio),
                "due rifiuti mostrano lo stesso messaggio"
            );
        }
    }

    /// **Il rifiuto non dice a chi tenta se e' vicino.**
    ///
    /// # Il difetto che questa prova impedisce
    ///
    /// Distinguere «questo codice non esiste» da «questo codice esisteva ma e'
    /// sbagliato» trasformerebbe il rifiuto in un aiuto: chi prova per tentativi
    /// saprebbe quando ha imboccato la strada giusta.
    #[test]
    fn il_rifiuto_di_un_codice_non_dice_se_esisteva() {
        let messaggio = EnrollmentRefusal::CodeNotRecognised.operator_message();
        for rivelazione in ["non esiste", "inesistente", "sbagliat", "quasi", "vicino"] {
            assert!(
                !messaggio.to_lowercase().contains(rivelazione),
                "il rifiuto contiene «{rivelazione}»: distingue due casi che devono \
                 restare indistinguibili"
            );
        }
    }

    /// **Non ogni rifiuto conta come tentativo.**
    ///
    /// # Il difetto che questa prova impedisce
    ///
    /// Se un dispositivo gia' arruolato che riprova contasse come tentativo, un
    /// errore ripetuto in buona fede — una postazione configurata per riprovare
    /// da sola — bloccherebbe l'arruolamento di tutti gli altri. Sarebbe un
    /// guasto costruito con le proprie mani.
    #[test]
    fn solo_i_tentativi_a_vuoto_si_contano() {
        assert!(EnrollmentRefusal::CodeNotRecognised.counts_as_attempt());
        assert!(EnrollmentRefusal::CodeExpired.counts_as_attempt());

        assert!(!EnrollmentRefusal::CodeAlreadyUsed.counts_as_attempt());
        assert!(!EnrollmentRefusal::DeviceAlreadyEnrolled.counts_as_attempt());
        assert!(
            !EnrollmentRefusal::DeviceRevoked {
                reason: nota("sostituito")
            }
            .counts_as_attempt()
        );
        assert!(
            !EnrollmentRefusal::TooManyRecentFailures {
                retry_in_minutes: 3
            }
            .counts_as_attempt(),
            "il blocco che si autoalimenta non finirebbe mai"
        );
    }
}
