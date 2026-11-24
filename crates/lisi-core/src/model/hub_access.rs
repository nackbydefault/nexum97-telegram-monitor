//! Chi può entrare nell'Hub, e che cosa può fare una volta dentro
//! (HUB-AUTHZ-01, ADR-0085).
//!
//! # Il dispositivo, non la persona
//!
//! Questo modulo autentica **la macchina** e le dà un **ruolo**. Non autentica
//! l'operatore: l'operatore che un dispositivo dichiara resta un'attribuzione di
//! quella macchina, e **nessun permesso qui lo tratta come autenticato**
//! (ADR-0082 decisione 6).
//!
//! # Tre esiti, e che cosa ciascuno rivela
//!
//! - **Accettato**: dispositivo arruolato, non ritirato, gettone corretto.
//! - **Non riconosciuto**: dispositivo sconosciuto **oppure** gettone
//!   sbagliato. I due casi non si distinguono (ADR-0047 decisione 5), e nemmeno
//!   il tempo li distingue: con un dispositivo sconosciuto il confronto si fa
//!   lo stesso, contro un'impronta che non corrisponde a nulla.
//! - **Ritirato**: dispositivo ritirato **con il gettone corretto**. Con un
//!   gettone sbagliato un dispositivo ritirato è «non riconosciuto»: dire
//!   «ritirato» a chi non ha il gettone rivelerebbe che quell'identificativo è
//!   esistito.
//!
//! # Il freno per indirizzo, e ciò che non può fare
//!
//! Duecentocinquantasei bit non si indovinano: il freno **non è la difesa**.
//! Protegge l'**audit** da una connessione ostile che ripete l'autenticazione
//! (ADR-0082 decisione 4). Per questo agisce **solo sui tentativi falliti** e
//! solo sulla loro registrazione: un dispositivo con il gettone giusto entra
//! anche da un indirizzo frenato, perché un indirizzo in LAN si condivide e si
//! riassegna, e un freno che bloccasse i legittimi sarebbe un guasto costruito
//! con le proprie mani.

use crate::digest::Sha256Digest;
use crate::error::{DomainError, DomainResult};
use crate::role::RestrictedAction;
use crate::time::Timestamp;

/// Il ruolo di un dispositivo presso l'Hub.
///
/// Gli stessi due della postazione (ADR-0015), perché l'ufficio ne conosce
/// due: chi lavora e chi amministra. **Il ruolo iniziale è `Operator`**: il
/// privilegio si concede con un atto, non si trova.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum HubRole {
    /// Lavora: legge, rivede, annota, secondo ciò che i comandi consentiranno.
    #[default]
    Operator,
    /// Amministra l'Hub: fonti, dizionari condivisi, dispositivi, ruoli.
    Administrator,
}

impl HubRole {
    /// Forma conservata nell'archivio.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Operator => "operatore",
            Self::Administrator => "amministratore",
        }
    }

    /// Nome per l'operatore.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Operator => "Operatore",
            Self::Administrator => "Amministratore",
        }
    }

    /// Riconosce la forma conservata.
    ///
    /// # Errori
    ///
    /// [`DomainError::InvalidHubRole`] se il testo non è un ruolo.
    pub fn parse(raw: &str) -> DomainResult<Self> {
        match raw {
            "operatore" => Ok(Self::Operator),
            "amministratore" => Ok(Self::Administrator),
            _ => Err(DomainError::InvalidHubRole {
                reason: "non è un ruolo conosciuto dall'Hub",
            }),
        }
    }

    /// Se il ruolo consente l'azione.
    ///
    /// Un elenco **chiuso** e senza ramo predefinito: un'azione nuova non
    /// compila finché qualcuno non ha deciso chi può compierla.
    #[must_use]
    pub const fn permits(self, action: HubAction) -> bool {
        match (self, action) {
            (Self::Administrator, _) => true,
            (
                Self::Operator,
                HubAction::Restricted(_)
                | HubAction::AdministerDevices
                | HubAction::AssignWork
                | HubAction::AdministerPeople,
            ) => false,
            // LA PRIMA AZIONE CHE SPETTA A UN OPERATORE (ADR-0094, decisione
            // 5). Fino a TEAM-REVIEW-01 il ruolo Operatore non poteva fare
            // nulla sull'Hub: rivedere e' il lavoro per cui quel ruolo esiste.
            (
                Self::Operator,
                HubAction::ReadContent
                | HubAction::ReviewContent
                | HubAction::TakeCharge
                | HubAction::ShareNotes,
            ) => true,
        }
    }
}

/// Un'azione che l'Hub autorizza lato server.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HubAction {
    /// Le azioni riservate della postazione (ADR-0015), che sull'Hub valgono
    /// per tutti i dispositivi collegati.
    Restricted(RestrictedAction),
    /// Cambiare il ruolo di un dispositivo o ritirarlo.
    AdministerDevices,
    /// Leggere **un** contenuto sorvegliato conservato dall'Hub
    /// (TEAM-REVIEW-01, ADR-0094, decisione 1).
    ///
    /// Non è una copia dell'archivio: è la lettura di un elemento per volta, e
    /// l'Hub registra quale dispositivo l'ha chiesta.
    ReadContent,
    /// Registrare la revisione umana di un contenuto (ADR-0094, decisione 4).
    ReviewContent,
    /// Prendere in carico un contenuto: **assegnarlo a sé stessi**
    /// (TEAM-ASSIGN-01, ADR-0098, decisione 2).
    TakeCharge,
    /// Assegnare un contenuto **a un'altra persona**, o revocarglielo.
    ///
    /// Dare lavoro a qualcun altro è una decisione sull'ufficio, non sul
    /// contenuto.
    AssignWork,
    /// Creare, sospendere o rimettere la frase di una persona dell'ufficio
    /// (ADR-0097, decisione 1).
    AdministerPeople,
    /// Scrivere note e tenere raccoglitori dell'ufficio (TEAM-WS-01,
    /// ADR-0099).
    ///
    /// Chi ritira le parole di un altro e' una regola piu' fine, e vive nel
    /// dominio: e' di chi le ha scritte e di chi amministra.
    ShareNotes,
}

impl HubAction {
    /// Nome stabile per l'audit.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Restricted(action) => action.as_str(),
            Self::AdministerDevices => "amministrare_dispositivi",
            Self::ReadContent => "leggere_contenuto",
            Self::ReviewContent => "rivedere_contenuto",
            Self::TakeCharge => "prendere_in_carico",
            Self::AssignWork => "assegnare_lavoro",
            Self::AdministerPeople => "amministrare_persone",
            Self::ShareNotes => "scrivere_insieme",
        }
    }

    /// Perché l'azione è riservata: ciò che il rifiuto dice (ADR-0042
    /// decisione 3).
    #[must_use]
    pub const fn reason(self) -> &'static str {
        match self {
            Self::Restricted(action) => action.reason(),
            Self::AdministerDevices => {
                "chi entra nell'Hub e con quali poteri lo decide chi amministra"
            }
            Self::ReadContent => {
                "leggere il materiale sorvegliato è consentito ai dispositivi arruolati, e ogni \
                 lettura resta registrata"
            }
            Self::ReviewContent => {
                "la revisione è il lavoro di chi opera, e ogni decisione resta registrata"
            }
            Self::TakeCharge => {
                "prendere in carico è il lavoro di chi opera, e ogni cambio resta registrato"
            }
            Self::AssignWork => {
                "dare lavoro a un'altra persona è una decisione sull'ufficio, e la prende chi \
                 amministra"
            }
            Self::AdministerPeople => {
                "chi sono le persone dell'ufficio e come si dimostrano lo decide chi amministra"
            }
            Self::ShareNotes => {
                "annotare e raccogliere è il lavoro di chi opera, e ogni nota resta registrata"
            }
        }
    }
}

/// Ciò che l'Hub conserva di un dispositivo per riconoscerlo.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredCredential {
    /// SHA-256 del gettone, conservato all'arruolamento.
    pub verifier: Sha256Digest,
    /// Se il dispositivo è stato ritirato.
    pub revoked: bool,
    /// Il ruolo assegnato.
    pub role: HubRole,
}

/// L'esito dell'autenticazione di un dispositivo.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeviceAccess {
    /// Entra, con questo ruolo.
    Accepted(HubRole),
    /// Sconosciuto o gettone sbagliato.
    NotRecognized,
    /// Ritirato, e ha dimostrato di essere lui.
    Revoked,
}

/// Decide l'accesso di un dispositivo.
///
/// Il confronto dell'impronta **non esce in anticipo**, e si esegue anche
/// quando il dispositivo non è conosciuto.
#[must_use]
pub fn decide_device_access(
    stored: Option<&StoredCredential>,
    presented: &Sha256Digest,
) -> DeviceAccess {
    // Un'impronta che nessun gettone produce: il confronto si fa comunque, e
    // non coincide.
    const NESSUNO: &str = "----------------------------------------------------------------";
    let conservata = stored.map_or(NESSUNO, |credenziale| credenziale.verifier.as_str());
    let coincide = uguali_senza_uscire_prima(conservata.as_bytes(), presented.as_str().as_bytes());

    match stored {
        Some(credenziale) if coincide && credenziale.revoked => DeviceAccess::Revoked,
        Some(credenziale) if coincide => DeviceAccess::Accepted(credenziale.role),
        _ => DeviceAccess::NotRecognized,
    }
}

fn uguali_senza_uscire_prima(primo: &[u8], secondo: &[u8]) -> bool {
    if primo.len() != secondo.len() {
        return false;
    }
    let mut differenze = 0_u8;
    for (mio, suo) in primo.iter().zip(secondo.iter()) {
        differenze |= mio ^ suo;
    }
    differenze == 0
}

// ---------------------------------------------------------------------------
// Il freno per indirizzo
// ---------------------------------------------------------------------------

/// Tentativi falliti registrati uno per uno, per indirizzo, nella finestra.
pub const ACCESS_BRAKE_THRESHOLD: u32 = 10;

/// La finestra del freno, in minuti: la stessa dell'arruolamento (ADR-0047).
pub const ACCESS_BRAKE_WINDOW_MINUTES: i64 = 15;

/// Quanti indirizzi il freno ricorda. Oltre, dimentica il più vecchio: un
/// avversario con molti indirizzi non fa crescere la memoria dell'Hub.
pub const ACCESS_BRAKE_CAPACITY: usize = 1024;

/// Quanto può essere lunga la forma di un indirizzo.
const MAX_ADDRESS_LEN: usize = 64;

/// Che cosa fare della registrazione di un tentativo fallito.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BrakeVerdict {
    /// Si registra, come ogni tentativo.
    Record,
    /// Si registra, e si registra anche che da qui in avanti, per questo
    /// indirizzo e fino a fine finestra, i tentativi non si registrano più uno
    /// per uno.
    RecordAndEngage,
    /// Non si registra: il freno è già stato registrato.
    Suppress,
}

#[derive(Debug, Clone)]
struct Finestra {
    indirizzo: String,
    inizio: Timestamp,
    tentativi: u32,
}

/// Il freno per indirizzo. Vive in memoria: un riavvio dell'Hub lo azzera, ed è
/// accettabile, perché protegge l'audit e non l'accesso.
#[derive(Debug, Clone, Default)]
pub struct AccessBrake {
    finestre: Vec<Finestra>,
    soppressi: u64,
}

impl AccessBrake {
    /// Conta un tentativo fallito da `address` e dice come registrarlo.
    ///
    /// Un indirizzo più lungo del consentito si tronca: è un'etichetta del
    /// trasporto, e un'etichetta lunga non deve diventare memoria.
    pub fn record_failure(&mut self, address: &str, now: Timestamp) -> BrakeVerdict {
        let indirizzo = tronca(address);
        let finestra_ms = ACCESS_BRAKE_WINDOW_MINUTES * 60_000;

        let posizione = self
            .finestre
            .iter()
            .position(|finestra| finestra.indirizzo == indirizzo);
        let finestra = match posizione {
            Some(indice) => &mut self.finestre[indice],
            None => {
                if self.finestre.len() >= ACCESS_BRAKE_CAPACITY {
                    // Dimentica la finestra cominciata per prima.
                    if let Some(piu_vecchia) = self
                        .finestre
                        .iter()
                        .enumerate()
                        .min_by_key(|(_, finestra)| finestra.inizio.as_millis())
                        .map(|(indice, _)| indice)
                    {
                        self.finestre.swap_remove(piu_vecchia);
                    }
                }
                self.finestre.push(Finestra {
                    indirizzo: String::from(indirizzo),
                    inizio: now,
                    tentativi: 0,
                });
                let ultimo = self.finestre.len() - 1;
                &mut self.finestre[ultimo]
            }
        };

        if now.as_millis().saturating_sub(finestra.inizio.as_millis()) >= finestra_ms {
            finestra.inizio = now;
            finestra.tentativi = 0;
        }
        finestra.tentativi = finestra.tentativi.saturating_add(1);

        match finestra.tentativi {
            n if n < ACCESS_BRAKE_THRESHOLD => BrakeVerdict::Record,
            n if n == ACCESS_BRAKE_THRESHOLD => BrakeVerdict::RecordAndEngage,
            _ => {
                self.soppressi = self.soppressi.saturating_add(1);
                BrakeVerdict::Suppress
            }
        }
    }

    /// Quanti tentativi non sono stati registrati uno per uno, da quando l'Hub
    /// è partito. Un numero da mostrare, non da nascondere.
    #[must_use]
    pub const fn suppressed(&self) -> u64 {
        self.soppressi
    }

    /// Quanti indirizzi il freno sta ricordando.
    #[must_use]
    pub fn tracked_addresses(&self) -> usize {
        self.finestre.len()
    }
}

fn tronca(address: &str) -> &str {
    if address.len() <= MAX_ADDRESS_LEN {
        return address;
    }
    let mut fine = MAX_ADDRESS_LEN;
    while !address.is_char_boundary(fine) {
        fine -= 1;
    }
    &address[..fine]
}

#[cfg(test)]
mod tests {
    use super::{
        ACCESS_BRAKE_CAPACITY, ACCESS_BRAKE_THRESHOLD, AccessBrake, BrakeVerdict, DeviceAccess,
        HubAction, HubRole, StoredCredential, decide_device_access,
    };
    use crate::digest::Sha256Digest;
    use crate::role::RestrictedAction;
    use crate::time::Timestamp;

    fn credenziale(gettone: &[u8], revoked: bool, role: HubRole) -> StoredCredential {
        StoredCredential {
            verifier: Sha256Digest::of_bytes(gettone),
            revoked,
            role,
        }
    }

    #[test]
    fn the_right_token_enters_with_its_role() {
        let giusta = credenziale(b"gettone", false, HubRole::Administrator);
        assert_eq!(
            decide_device_access(Some(&giusta), &Sha256Digest::of_bytes(b"gettone")),
            DeviceAccess::Accepted(HubRole::Administrator)
        );
    }

    #[test]
    fn unknown_device_and_wrong_token_are_the_same_answer() {
        let giusta = credenziale(b"gettone", false, HubRole::Operator);
        let sbagliato = Sha256Digest::of_bytes(b"altro");
        assert_eq!(
            decide_device_access(Some(&giusta), &sbagliato),
            DeviceAccess::NotRecognized
        );
        assert_eq!(
            decide_device_access(None, &sbagliato),
            DeviceAccess::NotRecognized
        );
    }

    #[test]
    fn revoked_is_said_only_to_who_proves_to_be_that_device() {
        let ritirato = credenziale(b"gettone", true, HubRole::Administrator);
        assert_eq!(
            decide_device_access(Some(&ritirato), &Sha256Digest::of_bytes(b"gettone")),
            DeviceAccess::Revoked
        );
        assert_eq!(
            decide_device_access(Some(&ritirato), &Sha256Digest::of_bytes(b"altro")),
            DeviceAccess::NotRecognized,
            "a chi non ha il gettone non si dice che quel dispositivo e' esistito"
        );
    }

    #[test]
    fn the_operator_role_is_the_default_and_permits_nothing_reserved() {
        assert_eq!(HubRole::default(), HubRole::Operator);
        for azione in RestrictedAction::ALL {
            assert!(!HubRole::Operator.permits(HubAction::Restricted(azione)));
            assert!(HubRole::Administrator.permits(HubAction::Restricted(azione)));
        }
        assert!(!HubRole::Operator.permits(HubAction::AdministerDevices));
        assert!(HubRole::Administrator.permits(HubAction::AdministerDevices));
    }

    #[test]
    fn roles_round_trip_and_unknown_text_is_refused() {
        for ruolo in [HubRole::Operator, HubRole::Administrator] {
            assert_eq!(HubRole::parse(ruolo.as_str()), Ok(ruolo));
        }
        assert!(HubRole::parse("Amministratore").is_err());
        assert!(HubRole::parse("").is_err());
    }

    #[test]
    fn the_brake_records_up_to_the_threshold_then_says_so_once_then_stays_quiet() {
        let mut freno = AccessBrake::default();
        let adesso = Timestamp::from_millis(1_000_000);
        for _ in 1..ACCESS_BRAKE_THRESHOLD {
            assert_eq!(
                freno.record_failure("192.0.2.7", adesso),
                BrakeVerdict::Record
            );
        }
        assert_eq!(
            freno.record_failure("192.0.2.7", adesso),
            BrakeVerdict::RecordAndEngage
        );
        assert_eq!(
            freno.record_failure("192.0.2.7", adesso),
            BrakeVerdict::Suppress
        );
        assert_eq!(freno.suppressed(), 1);

        // Un altro indirizzo non ne risente.
        assert_eq!(
            freno.record_failure("192.0.2.8", adesso),
            BrakeVerdict::Record
        );

        // Finita la finestra, si ricomincia a registrare.
        let dopo = Timestamp::from_millis(adesso.as_millis() + 15 * 60_000);
        assert_eq!(
            freno.record_failure("192.0.2.7", dopo),
            BrakeVerdict::Record
        );
    }

    #[test]
    fn many_addresses_do_not_grow_the_memory() {
        let mut freno = AccessBrake::default();
        for indice in 0..(ACCESS_BRAKE_CAPACITY * 3) {
            let _ = freno.record_failure(
                &format!("indirizzo-{indice}"),
                Timestamp::from_millis(i64::try_from(indice).unwrap_or(0)),
            );
        }
        assert_eq!(freno.tracked_addresses(), ACCESS_BRAKE_CAPACITY);
        let lungo = "x".repeat(10_000);
        let _ = freno.record_failure(&lungo, Timestamp::from_millis(0));
        assert!(freno.tracked_addresses() <= ACCESS_BRAKE_CAPACITY);
    }
}
