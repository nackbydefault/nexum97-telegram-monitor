//! Identità di **dispositivo** e identità di **operatore**.
//!
//! # Perché sono due cose e non una
//!
//! ADR-0042, decisione 2, lo dice per intero: il dispositivo dice *quale
//! macchina sta parlando*, l'operatore dice *chi sta agendo*. Confonderle
//! produce due danni opposti — un dispositivo condiviso da due persone
//! attribuirebbe a una gli atti dell'altra, e un operatore che si sposta di
//! macchina perderebbe i propri.
//!
//! Qui la separazione non è una raccomandazione: sono due tipi distinti, e il
//! compilatore rifiuta di usare l'uno dove serve l'altro.
//!
//! # Che cosa questo modulo NON fa, e conta saperlo
//!
//! Non arruola nulla. Un'identità creata qui è un nome che questa postazione si
//! è data, e nasce **non nota ad alcun Hub**: lo stato iniziale è
//! [`DeviceState::Local`], e il testo che l'accompagna lo dice.
//!
//! L'arruolamento — chi autorizza, che cosa stabilisce, che cosa l'Hub conserva
//! — è in [`crate::model::enrollment`], costruito da HUB-03. Qui c'è soltanto
//! lo **stato** che ne risulta.
//!
//! Non autentica nessuno. Non applica permessi. Non parla in rete.
//!
//! # Che cosa l'identificativo NON contiene
//!
//! Nessun indirizzo MAC. Nessun numero di serie. Nessuna impronta
//! dell'hardware, del volume, della scheda madre o dell'installazione di
//! Windows. L'identificativo è **casuale e basta**, e nasce dal generatore
//! crittografico del sistema.
//!
//! La ragione non è di riservatezza soltanto. Un identificativo derivato dalla
//! macchina non si può revocare: cambiarlo richiederebbe di cambiare la
//! macchina. Un identificativo casuale si ritira e se ne crea un altro, che è
//! l'unica cosa che rende sensata la parola «revoca».

use core::fmt;

use crate::error::{DomainError, DomainResult};
use crate::model::readable_code;
use crate::text::{Actor, DisplayName, Note};
use crate::time::Timestamp;

// ---------------------------------------------------------------------------
// Identità dell'operatore
// ---------------------------------------------------------------------------

/// Identificativo dell'operatore locale finché nessuno viene autenticato.
///
/// # Perché esiste un segnaposto invece di un nome vero
///
/// Questa versione non autentica persone: chi apre il programma è chiunque
/// abbia accesso al profilo Windows. Scrivere nell'audit il nome dell'utente di
/// Windows farebbe **sembrare** che una persona sia stata identificata, e non lo
/// è stata; scrivere un campo vuoto perderebbe l'informazione che l'atto è
/// avvenuto in locale.
///
/// Il segnaposto dice la verità: l'atto è avvenuto su questa postazione, e non
/// si sa chi lo ha compiuto.
pub const LOCAL_OPERATOR: &str = "operatore.locale";

/// Chi ha agito: una persona, non una macchina.
///
/// È un tipo distinto da [`DeviceId`] apposta. Uno scambio fra i due
/// attribuirebbe a una macchina gli atti di una persona, o viceversa, e il
/// compilatore lo impedisce prima che qualcuno lo scriva.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct OperatorId(String);

impl OperatorId {
    /// L'operatore locale non autenticato di questa postazione.
    ///
    /// Non è un'identità: è la dichiarazione che non ce n'è una.
    #[must_use]
    pub fn local() -> Self {
        Self(LOCAL_OPERATOR.to_owned())
    }

    /// Costruisce l'identificativo di un operatore autenticato.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se il valore è vuoto, troppo lungo o contiene
    /// caratteri di controllo, e se coincide con il segnaposto locale: un
    /// operatore autenticato che si chiamasse come il segnaposto renderebbe
    /// indistinguibile un atto identificato da uno che non lo è.
    pub fn try_new(raw: &str) -> DomainResult<Self> {
        let actor = Actor::try_new(raw)?;
        if actor.as_str() == LOCAL_OPERATOR {
            return Err(DomainError::InvalidDeviceId {
                reason: "l'identificativo riservato all'operatore locale non è assegnabile",
            });
        }
        Ok(Self(actor.as_str().to_owned()))
    }

    /// Forma testuale dell'identificativo.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Vero quando nessuna persona è stata identificata.
    #[must_use]
    pub fn is_local_placeholder(&self) -> bool {
        self.0 == LOCAL_OPERATOR
    }

    /// Soggetto da scrivere nell'audit.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se il valore non supera la validazione di
    /// [`Actor`]. Per un identificativo costruito da questo modulo non può
    /// accadere: entrambe le vie di costruzione lo hanno già superato.
    pub fn audit_actor(&self) -> DomainResult<Actor> {
        Actor::try_new(&self.0)
    }
}

impl fmt::Display for OperatorId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

// ---------------------------------------------------------------------------
// Identificativo del dispositivo
// ---------------------------------------------------------------------------

/// Byte casuali che compongono un identificativo di dispositivo.
///
/// Centoventi bit. Non è una scelta di comodo: centoventi bit stanno in
/// ventiquattro cifre dell'alfabeto usato **senza avanzi**, così che ogni
/// stringa ben formata sia un identificativo valido e non esista una categoria
/// di stringhe «quasi valide» che qualcuno debba ricordarsi di rifiutare.
pub const DEVICE_ID_BYTES: usize = 15;

/// Cifre dell'identificativo, separatori esclusi.
pub const DEVICE_ID_DIGITS: usize = 24;

/// Cifre per gruppo nella forma canonica.
const CIFRE_PER_GRUPPO: usize = 4;

/// Nome pubblico di un dispositivo.
///
/// **Non è un segreto e non prova nulla.** È un nome: dice di quale dispositivo
/// si sta parlando, non che chi lo pronuncia sia quel dispositivo. La prova è
/// il segreto, ed è un'altra cosa ([`DeviceSecret`]).
///
/// La forma leggibile — l'alfabeto, i gruppi, le confusioni risolte in lettura —
/// è in [`crate::model::readable_code`], in una copia sola, condivisa con il
/// codice di arruolamento.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct DeviceId(String);

impl DeviceId {
    /// Costruisce l'identificativo dai byte casuali forniti.
    ///
    /// I byte devono venire da un generatore crittografico. Questo modulo non
    /// ne possiede uno apposta: `lisi-core` non tocca il sistema operativo, e un
    /// generatore scritto qui sarebbe un generatore scritto in casa. Chi chiama
    /// passa `lisi_security::random_bytes`.
    #[must_use]
    pub fn from_random_bytes(bytes: &[u8; DEVICE_ID_BYTES]) -> Self {
        Self(readable_code::encode(
            bytes,
            DEVICE_ID_DIGITS,
            CIFRE_PER_GRUPPO,
        ))
    }

    /// Riconosce un identificativo scritto o conservato.
    ///
    /// Accetta minuscole, separatori mancanti o in eccesso e le confusioni di
    /// lettura previste, e normalizza alla forma canonica.
    ///
    /// # Errori
    ///
    /// Restituisce [`DomainError::InvalidDeviceId`] se le cifre non sono
    /// ventiquattro o se una di esse non appartiene all'alfabeto.
    pub fn parse(raw: &str) -> DomainResult<Self> {
        readable_code::canonicalize(raw, DEVICE_ID_DIGITS, CIFRE_PER_GRUPPO)
            .map(Self)
            .map_err(|forma| DomainError::InvalidDeviceId {
                reason: match forma {
                    readable_code::FormaScorretta::CarattereEstraneo => {
                        "contiene un carattere che non appartiene all'alfabeto"
                    }
                    readable_code::FormaScorretta::Lunghezza => "non ha ventiquattro cifre",
                },
            })
    }

    /// Forma canonica, con i separatori.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for DeviceId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

// ---------------------------------------------------------------------------
// Segreto del dispositivo
// ---------------------------------------------------------------------------

/// Lunghezza del segreto di un dispositivo, in byte.
///
/// # Perché trentadue byte, e perché la scelta non decide nulla d'altro
///
/// Come il dispositivo dimostri di essere sé stesso è una decisione di HUB-03,
/// e prenderla adesso significherebbe deciderla sulla carta invece che davanti
/// al problema. Trentadue byte uniformi la lasciano aperta: sono un segreto
/// condiviso valido, e sono anche **esattamente** la forma di una chiave privata
/// Ed25519, che è trentadue byte uniformi e nient'altro.
///
/// Chi sceglierà in HUB-03 non dovrà tornare qui.
pub const DEVICE_SECRET_BYTES: usize = 32;

/// Testo mostrato al posto del segreto.
pub const SECRET_REDACTED: &str = "«redatto»";

/// Il segreto che un dispositivo custodisce.
///
/// Non implementa `Display`, `Clone`, `Serialize` né alcuna conversione
/// implicita: ogni via che porti il valore fuori di qui è esplicita e si vede
/// nel codice. `Debug` è scritto a mano e non mostra i byte, così che un
/// `tracing::info!(?identita)` scritto per distrazione non finisca in un
/// registro con dentro il segreto.
pub struct DeviceSecret([u8; DEVICE_SECRET_BYTES]);

impl DeviceSecret {
    /// Costruisce il segreto dai byte casuali forniti.
    ///
    /// Vale l'osservazione di [`DeviceId::from_random_bytes`]: i byte devono
    /// venire dal generatore crittografico del sistema.
    #[must_use]
    pub const fn from_random_bytes(bytes: [u8; DEVICE_SECRET_BYTES]) -> Self {
        Self(bytes)
    }

    /// Espone i byte del segreto.
    ///
    /// Il nome è scomodo apposta: ogni chiamata è un punto in cui il segreto
    /// esce, e deve risultare tale a chi legge il codice.
    #[must_use]
    pub const fn expose(&self) -> &[u8; DEVICE_SECRET_BYTES] {
        &self.0
    }
}

impl fmt::Debug for DeviceSecret {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(SECRET_REDACTED)
    }
}

impl PartialEq for DeviceSecret {
    /// Confronto scritto per non uscire in anticipo sulla prima differenza.
    ///
    /// **Limite dichiarato:** il linguaggio non garantisce che resti tale dopo
    /// l'ottimizzazione. È scritto così perché in HUB-03 questo confronto
    /// potrebbe decidere un'autenticazione, e un confronto che si ferma alla
    /// prima differenza racconta a chi misura quante cifre ha indovinato.
    fn eq(&self, other: &Self) -> bool {
        let mut differenze = 0_u8;
        for (mio, suo) in self.0.iter().zip(other.0.iter()) {
            differenze |= mio ^ suo;
        }
        differenze == 0
    }
}

impl Eq for DeviceSecret {}

impl Drop for DeviceSecret {
    fn drop(&mut self) {
        // Sovrascrittura **best-effort**, come per gli altri segreti del
        // prodotto. Non e' una garanzia: il valore puo' essere stato copiato
        // durante la costruzione, e il sistema operativo puo' averlo scritto in
        // un file di paginazione. Cancella la copia che si conosce.
        self.0.fill(0);
    }
}

// ---------------------------------------------------------------------------
// Identità del dispositivo
// ---------------------------------------------------------------------------

/// Stato di un dispositivo per quanto ne sa **questa postazione**.
///
/// # La variante «arruolato» è arrivata con il codice che la rende vera
///
/// HUB-02 non l'aveva, e una prova ne dichiarava l'assenza: darne il vocabolario
/// alla schermata prima che esistesse un arruolamento avrebbe permesso di dire
/// una cosa mai accaduta. HUB-03 costruisce l'arruolamento
/// ([`crate::model::enrollment`]), e la variante compare qui insieme a esso.
///
/// La prova che ne vietava la comparsa è stata tolta **passando di qui e
/// leggendo perché c'era**, che è ciò che il suo messaggio chiedeva.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DeviceState {
    /// Creata su questa postazione e mai presentata ad alcun Hub.
    Local,
    /// Ammessa da un Hub, che ne conserva l'impronta del gettone.
    ///
    /// # Che cosa questo stato non è
    ///
    /// **Non è una prova che l'Hub la riconosca ancora.** È ciò che questa
    /// postazione ha visto accadere il giorno dell'arruolamento. L'Hub può
    /// averla ritirata da allora, e questa riga non lo saprebbe: chi decide è
    /// l'Hub, ogni volta che il dispositivo si presenta.
    Enrolled {
        /// Come si chiama l'Hub che l'ha ammessa.
        hub: DisplayName,
        /// Quando.
        at: Timestamp,
    },
    /// Ritirata da chi amministra questa postazione.
    ///
    /// # Che cosa questo stato non è
    ///
    /// **Non è l'applicazione della revoca.** Un Hub che accettasse un
    /// dispositivo perché il dispositivo dice di non essere revocato non
    /// starebbe controllando nulla: chi prende la macchina riscrive il file. La
    /// revoca che conta la tiene l'Hub, e questo stato è la copia che serve a
    /// spiegare all'operatore perché la postazione ha smesso di provarci.
    Revoked {
        /// Quando è stata registrata la revoca.
        at: Timestamp,
        /// Perché, nelle parole di chi l'ha decisa.
        reason: Note,
    },
}

impl DeviceState {
    /// Vero se il dispositivo risulta ritirato.
    #[must_use]
    pub const fn is_revoked(&self) -> bool {
        matches!(self, Self::Revoked { .. })
    }

    /// Vero se questa postazione ha visto un Hub ammetterla.
    #[must_use]
    pub const fn is_enrolled(&self) -> bool {
        matches!(self, Self::Enrolled { .. })
    }

    /// Riga da mostrare a un operatore.
    #[must_use]
    pub fn operator_message(&self) -> String {
        match self {
            Self::Local => "Questo dispositivo ha un'identità propria. Nessun Hub la conosce: \
                 in questa versione il collegamento non esiste."
                .to_owned(),
            Self::Enrolled { hub, at: _ } => format!(
                "Questo dispositivo è stato ammesso dall'Hub «{}». È ciò che questa \
                 postazione ha visto allora: se l'Hub l'ha ritirato da allora, lo dirà \
                 quando il dispositivo si presenterà.",
                hub.as_str()
            ),
            Self::Revoked { reason, .. } => format!(
                "Questo dispositivo è stato ritirato: {}. L'identità resta registrata perché \
                 resti leggibile che cosa è stato fatto e quando.",
                reason.as_str()
            ),
        }
    }
}

/// L'identità che questa postazione si è data.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceIdentity {
    /// Nome pubblico del dispositivo.
    pub id: DeviceId,
    /// Come lo chiama l'ufficio.
    pub label: DisplayName,
    /// Quando è stata creata.
    pub created_at: Timestamp,
    /// Che cosa se ne sa qui.
    pub state: DeviceState,
}

impl DeviceIdentity {
    /// Crea l'identità di un dispositivo appena nato.
    #[must_use]
    pub const fn new(id: DeviceId, label: DisplayName, created_at: Timestamp) -> Self {
        Self {
            id,
            label,
            created_at,
            state: DeviceState::Local,
        }
    }

    /// Registra il ritiro del dispositivo.
    ///
    /// Registrare due volte non è un errore: prevale la prima ragione, perché è
    /// quella che spiega perché il dispositivo ha smesso di funzionare.
    pub fn revoke(&mut self, at: Timestamp, reason: Note) {
        if self.state.is_revoked() {
            return;
        }
        self.state = DeviceState::Revoked { at, reason };
    }

    /// Registra che un Hub ha ammesso questo dispositivo.
    ///
    /// # Perché un dispositivo ritirato non si riarruola
    ///
    /// Perché il ritiro è una decisione presa su **quell'**identità. Riportarla
    /// in servizio la svuoterebbe: chi la avesse ritirata scoprirebbe che il
    /// dispositivo è tornato senza che nessuno lo abbia deciso di nuovo. La via
    /// giusta è un'identità nuova, che si vede nell'audit ed è distinguibile
    /// dalla precedente.
    ///
    /// # Errori
    ///
    /// Restituisce [`DomainError::DeviceStateTransition`] se il dispositivo è
    /// stato ritirato.
    pub fn record_enrollment(&mut self, hub: DisplayName, at: Timestamp) -> DomainResult<()> {
        if self.state.is_revoked() {
            return Err(DomainError::DeviceStateTransition {
                reason: "un dispositivo ritirato non si riarruola: serve un'identità nuova",
            });
        }
        self.state = DeviceState::Enrolled { hub, at };
        Ok(())
    }

    /// Vero se il dispositivo risulta ritirato.
    #[must_use]
    pub const fn is_revoked(&self) -> bool {
        self.state.is_revoked()
    }

    /// Vero se questa postazione ha visto un Hub ammetterla.
    #[must_use]
    pub const fn is_enrolled(&self) -> bool {
        self.state.is_enrolled()
    }
}

#[cfg(test)]
mod tests {
    use super::{
        DEVICE_ID_BYTES, DEVICE_ID_DIGITS, DEVICE_SECRET_BYTES, DeviceId, DeviceIdentity,
        DeviceSecret, DeviceState, LOCAL_OPERATOR, OperatorId, SECRET_REDACTED,
    };
    use crate::text::{DisplayName, Note};
    use crate::time::Timestamp;

    fn istante() -> Timestamp {
        Timestamp::from_millis(1_756_000_000_000)
    }

    fn nome(testo: &str) -> DisplayName {
        let Ok(valore) = DisplayName::try_new(testo) else {
            panic!("il nome di prova deve essere valido");
        };
        valore
    }

    fn nota(testo: &str) -> Note {
        let Ok(valore) = Note::try_new(testo) else {
            panic!("la nota di prova deve essere valida");
        };
        valore
    }

    // -----------------------------------------------------------------
    // Identificativo del dispositivo
    // -----------------------------------------------------------------

    /// **La forma dell'identificativo e' quella dichiarata.**
    #[test]
    fn l_identificativo_ha_ventiquattro_cifre_in_sei_gruppi() {
        let identificativo = DeviceId::from_random_bytes(&[0x00; DEVICE_ID_BYTES]);
        assert_eq!(identificativo.as_str(), "0000-0000-0000-0000-0000-0000");

        let identificativo = DeviceId::from_random_bytes(&[0xFF; DEVICE_ID_BYTES]);
        assert_eq!(identificativo.as_str(), "ZZZZ-ZZZZ-ZZZZ-ZZZZ-ZZZZ-ZZZZ");

        let cifre = identificativo
            .as_str()
            .chars()
            .filter(|carattere| *carattere != '-')
            .count();
        assert_eq!(cifre, DEVICE_ID_DIGITS, "le cifre non sono ventiquattro");
    }

    /// **Ogni byte casuale finisce nell'identificativo.**
    ///
    /// # Il difetto che questa prova impedisce
    ///
    /// L'estrazione dei cinque bit attraversa i confini fra i byte. Uno scarto
    /// sbagliato di un bit non produce un errore: produce un identificativo che
    /// **ignora** parte del caso, cioe' un'identita' con meno entropia di quella
    /// dichiarata, e nessuno se ne accorgerebbe leggendola.
    ///
    /// Cambiando un bit alla volta e verificando che l'esito cambi sempre, si
    /// dimostra che tutti e centoventi i bit sono usati.
    #[test]
    fn ogni_bit_del_caso_cambia_l_identificativo() {
        let base = [0x00; DEVICE_ID_BYTES];
        let atteso = DeviceId::from_random_bytes(&base);

        for posizione in 0..DEVICE_ID_BYTES {
            for bit in 0..8_u32 {
                let mut variante = base;
                variante[posizione] = 1_u8 << bit;
                assert_ne!(
                    DeviceId::from_random_bytes(&variante),
                    atteso,
                    "il bit {bit} del byte {posizione} non compare nell'identificativo: \
                     l'identita' ha meno caso di quanto dichiara"
                );
            }
        }
    }

    /// **Ricopiare a mano non produce un altro dispositivo.**
    #[test]
    fn le_confusioni_di_lettura_portano_allo_stesso_dispositivo() {
        let Ok(canonico) = DeviceId::parse("0J2K-M3NP-4QRS-5TVW-6XYZ-7089") else {
            panic!("la forma canonica deve essere riconosciuta");
        };

        for ricopiato in [
            "0j2k-m3np-4qrs-5tvw-6xyz-7089",
            "0J2KM3NP4QRS5TVW6XYZ7089",
            "0J2K M3NP 4QRS 5TVW 6XYZ 7089",
            "OJ2K-M3NP-4QRS-5TVW-6XYZ-7O89",
        ] {
            let Ok(letto) = DeviceId::parse(ricopiato) else {
                panic!("«{ricopiato}» doveva essere riconosciuto");
            };
            assert_eq!(
                letto, canonico,
                "«{ricopiato}» ha prodotto un dispositivo diverso"
            );
        }
    }

    /// **Un identificativo malformato e' rifiutato, e non a meta'.**
    #[test]
    fn un_identificativo_malformato_e_rifiutato() {
        for storto in [
            "",
            "0J2K-M3NP",
            "0J2K-M3NP-4QRS-5TVW-6XYZ-70890",
            "0J2K-M3NP-4QRS-5TVW-6XYZ-708U",
            "0J2K-M3NP-4QRS-5TVW-6XYZ-70!9",
        ] {
            assert!(
                DeviceId::parse(storto).is_err(),
                "«{storto}» e' stato accettato come identificativo"
            );
        }
    }

    // -----------------------------------------------------------------
    // Segreto
    // -----------------------------------------------------------------

    /// **Il segreto non compare in un registro nemmeno per distrazione.**
    ///
    /// # Il difetto che questa prova impedisce
    ///
    /// `tracing::info!(?identita)` e' una riga che si scrive senza pensarci. Se
    /// `Debug` fosse derivato, quella riga scriverebbe trentadue byte di segreto
    /// in un file di registro che finisce in un pacchetto diagnostico.
    #[test]
    fn il_segreto_non_si_legge_nella_resa_di_debug() {
        let segreto = DeviceSecret::from_random_bytes([0xAB; DEVICE_SECRET_BYTES]);
        let reso = format!("{segreto:?}");
        assert_eq!(reso, SECRET_REDACTED);
        assert!(
            !reso.contains("171") && !reso.to_ascii_lowercase().contains("ab"),
            "la resa di Debug lascia intravedere i byte: «{reso}»"
        );

        // E anche dentro una struttura che lo contiene.
        let contenitore = (nome("postazione"), segreto);
        let reso = format!("{contenitore:?}");
        assert!(
            reso.contains(SECRET_REDACTED),
            "il segreto annidato non e' redatto: «{reso}»"
        );
    }

    /// **Due segreti diversi non risultano uguali, ovunque cada la differenza.**
    #[test]
    fn il_confronto_vede_la_differenza_in_ogni_posizione() {
        let riferimento = DeviceSecret::from_random_bytes([0x11; DEVICE_SECRET_BYTES]);
        assert_eq!(
            riferimento,
            DeviceSecret::from_random_bytes([0x11; DEVICE_SECRET_BYTES])
        );

        for posizione in 0..DEVICE_SECRET_BYTES {
            let mut byte = [0x11; DEVICE_SECRET_BYTES];
            byte[posizione] = 0x12;
            assert_ne!(
                riferimento,
                DeviceSecret::from_random_bytes(byte),
                "una differenza in posizione {posizione} non e' stata vista"
            );
        }
    }

    // -----------------------------------------------------------------
    // Operatore
    // -----------------------------------------------------------------

    /// **Un operatore autenticato non puo' chiamarsi come il segnaposto.**
    ///
    /// Altrimenti nell'audit un atto identificato e uno non identificato
    /// sarebbero la stessa riga.
    #[test]
    fn il_segnaposto_locale_non_e_assegnabile() {
        assert!(OperatorId::local().is_local_placeholder());
        assert_eq!(OperatorId::local().as_str(), LOCAL_OPERATOR);
        assert!(
            OperatorId::try_new(LOCAL_OPERATOR).is_err(),
            "il segnaposto e' stato assegnato a un operatore"
        );

        let Ok(persona) = OperatorId::try_new("r.bianchi") else {
            panic!("un identificativo ordinario deve essere accettato");
        };
        assert!(!persona.is_local_placeholder());
        let Ok(attore) = persona.audit_actor() else {
            panic!("l'attore dell'audit deve potersi costruire");
        };
        assert_eq!(attore.as_str(), "r.bianchi");
    }

    // -----------------------------------------------------------------
    // Stato del dispositivo
    // -----------------------------------------------------------------

    /// **La prima ragione della revoca e' quella che resta.**
    #[test]
    fn la_revoca_conserva_la_prima_ragione() {
        let mut identita = DeviceIdentity::new(
            DeviceId::from_random_bytes(&[0x07; DEVICE_ID_BYTES]),
            nome("Postazione 2"),
            istante(),
        );
        assert!(!identita.is_revoked());

        identita.revoke(istante(), nota("portatile smarrito"));
        identita.revoke(istante(), nota("sostituito"));

        assert!(identita.is_revoked());
        let DeviceState::Revoked { reason, .. } = &identita.state else {
            panic!("il dispositivo doveva risultare ritirato");
        };
        assert_eq!(reason.as_str(), "portatile smarrito");
    }

    /// **La postazione non dichiara un collegamento che non esiste.**
    ///
    /// # Il difetto che questa prova impedisce
    ///
    /// Un'identita' di dispositivo appena creata assomiglia a un arruolamento
    /// riuscito: c'e' un identificativo, c'e' un segreto, sembra che qualcuno
    /// dall'altra parte li conosca. Nessuno li conosce. Un testo che lasciasse
    /// credere il contrario farebbe cercare a un amministratore un dispositivo
    /// che sull'Hub non c'e' mai stato.
    #[test]
    fn lo_stato_locale_dice_che_nessun_hub_conosce_questa_identita() {
        let messaggio = DeviceState::Local.operator_message();
        assert!(
            messaggio.contains("Nessun Hub la conosce"),
            "il messaggio non dichiara l'assenza di collegamento: «{messaggio}»"
        );
        for promessa in [
            "arruolat",
            "connesso",
            "riconosciuto dall",
            "registrato presso",
        ] {
            assert!(
                !messaggio.to_lowercase().contains(promessa),
                "il messaggio contiene «{promessa}»: promette un collegamento inesistente"
            );
        }
    }

    /// **Lo stato «arruolato» non promette piu' di quanto sappia.**
    ///
    /// # Che cosa e' successo alla prova che stava qui
    ///
    /// Fino a HUB-02 questa posizione ospitava una prova che **vietava** la
    /// variante di arruolamento, e che diceva: «chi la aggiunge deve passare di
    /// qui, leggere perche' mancava, e togliermi con cognizione». HUB-03 ha
    /// costruito l'arruolamento; la variante e' arrivata insieme al codice che
    /// la rende vera, e la prova e' stata tolta cosi' com'era previsto.
    ///
    /// Al suo posto serve l'altra meta': ora che lo stato esiste, non deve dire
    /// piu' di quanto sappia. Questa postazione sa **che un Hub l'ha ammessa
    /// quel giorno**; non sa se l'Hub la riconosca ancora, perche' un ritiro
    /// deciso sull'Hub non arriva qui da solo.
    ///
    /// Un testo che dicesse «collegato» o «riconosciuto» inviterebbe a fidarsi
    /// di una riga vecchia.
    #[test]
    fn lo_stato_arruolato_non_promette_un_riconoscimento_attuale() {
        let mut identita = DeviceIdentity::new(
            DeviceId::from_random_bytes(&[0x11; DEVICE_ID_BYTES]),
            nome("Postazione 3"),
            istante(),
        );
        let Ok(()) = identita.record_enrollment(nome("Hub della centrale"), istante()) else {
            panic!("un dispositivo locale deve potersi arruolare");
        };
        assert!(identita.is_enrolled());

        let messaggio = identita.state.operator_message();
        assert!(
            messaggio.contains("Hub della centrale"),
            "il messaggio non dice presso quale Hub: «{messaggio}»"
        );
        assert!(
            messaggio.contains("se l'Hub l'ha ritirato"),
            "il messaggio non dichiara che il riconoscimento non e' attuale: «{messaggio}»"
        );
        for promessa in ["è collegato", "risulta connesso", "riconosciuto dall'Hub"] {
            assert!(
                !messaggio.contains(promessa),
                "il messaggio contiene «{promessa}»: invita a fidarsi di una riga vecchia"
            );
        }
    }

    /// **Un dispositivo ritirato non torna in servizio arruolandosi di nuovo.**
    ///
    /// # Il difetto che questa prova impedisce
    ///
    /// Chi ha ritirato un'identita' ha preso una decisione su **quella**
    /// identita'. Se un riarruolamento la riportasse in servizio, quella
    /// decisione si potrebbe annullare senza che nessuno la prendesse di nuovo,
    /// e nell'audit i due periodi si confonderebbero perche' portano lo stesso
    /// identificativo.
    #[test]
    fn un_dispositivo_ritirato_non_si_riarruola() {
        let mut identita = DeviceIdentity::new(
            DeviceId::from_random_bytes(&[0x22; DEVICE_ID_BYTES]),
            nome("Postazione 4"),
            istante(),
        );
        identita.revoke(istante(), nota("portatile smarrito"));

        assert!(
            identita
                .record_enrollment(nome("Hub della centrale"), istante())
                .is_err(),
            "un dispositivo ritirato e' stato riportato in servizio"
        );
        assert!(identita.is_revoked(), "lo stato di ritiro e' stato perso");
        assert!(!identita.is_enrolled());
    }
}
