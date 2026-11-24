//! Versioni e capacità: che cosa due estremità possono dirsi.
//!
//! # Le regole di compatibilità
//!
//! 1. **La versione è un intero**, e una versione nuova esiste solo quando cambia
//!    il **significato** di qualcosa che esiste già: un campo che cambia senso,
//!    un messaggio che cambia forma, una garanzia che si toglie.
//! 2. **Dentro una versione si aggiunge soltanto per capacità.** Un
//!    comportamento nuovo e facoltativo ha un nome, lo si offre, e lo si usa solo
//!    se l'altro capo lo ha accettato.
//! 3. **Ogni estremità dichiara un intervallo** `[min, max]`. Si usa **la
//!    versione più alta in comune**, e nessun'altra.
//! 4. **Nessuna intersezione, nessuna connessione**: la risposta dice
//!    l'intervallo dell'Hub, perché la frase all'operatore possa dire *che cosa*
//!    va aggiornato.
//!
//! # Il rifiuto della retrocessione
//!
//! Dentro TLS verificato nessuno in mezzo può riscrivere l'offerta, quindi la
//! retrocessione che resta possibile è quella **fra le due estremità**: un Hub
//! che sceglie una versione più bassa di quella che entrambi sanno parlare, o un
//! client che, fallito un tentativo, ne fa un altro offrendo meno. Il client
//! quindi **ricalcola** la versione attesa dall'intervallo che l'Hub dichiara e
//! rifiuta qualunque altra; e l'offerta è una costante del programma, che
//! nessun ramo di codice riduce dopo un fallimento.

use serde::{Deserialize, Serialize};

/// La versione più bassa che questo programma parla.
pub const MIN_SUPPORTED_VERSION: u16 = 1;

/// La versione più alta che questo programma parla.
///
/// **Due da TEAM-REVIEW-01** (ADR-0094, decisione 6): la versione 2 porta i
/// messaggi della revisione condivisa — chiedere la coda, chiedere un
/// contenuto, mandare una decisione — che nella versione 1 **non esistono**.
/// Un client che li mandasse a un Hub versione 1 gli farebbe leggere un frame
/// che non sa interpretare, e la connessione si chiuderebbe come se il client
/// fosse rotto: per questo si negozia, e chi ha negoziato 1 non li manda.
pub const MAX_SUPPORTED_VERSION: u16 = 2;

/// Quante capacità un messaggio può nominare.
pub const MAX_CAPABILITIES: usize = 32;

/// Quanto può essere lungo il nome di una capacità.
pub const MAX_CAPABILITY_LEN: usize = 48;

/// Il nome della capacità della **coda di lavoro condivisa**
/// (TEAM-WQ-01, ADR-0095).
pub const CAPABILITY_WORK_QUEUE: &str = "coda-di-lavoro";

/// Il nome della capacità della **presenza** (TEAM-PRESENCE-01, ADR-0096).
pub const CAPABILITY_PRESENCE: &str = "presenza";

/// Il nome della capacità dell'**identità di persona** (TEAM-ASSIGN-01,
/// ADR-0097).
pub const CAPABILITY_PERSON: &str = "persona";

/// Il nome della capacità dell'**assegnazione del lavoro** (TEAM-ASSIGN-01,
/// ADR-0098).
///
/// Separata dalla precedente apposta: un Hub può sapere chi sono le persone
/// senza ancora saper assegnare, e il contrario non ha senso — assegnare
/// senza persone non ha a chi.
pub const CAPABILITY_ASSIGNMENT: &str = "assegnazione";

/// Il nome della capacità delle **note condivise** (TEAM-WS-01, ADR-0099).
pub const CAPABILITY_SHARED_NOTES: &str = "blocco-condiviso";

/// Il nome della capacità dei **raccoglitori condivisi** (TEAM-WS-01,
/// ADR-0099).
///
/// Separata dalle note apposta: un Hub può portare l'una senza l'altra, e un
/// client deve poterlo **scoprire** invece di dedurlo.
pub const CAPABILITY_SHARED_WORKSPACES: &str = "raccoglitore-condiviso";

/// Il nome della capacità delle **relazioni dell'ufficio** (TEAM-REPORT-01,
/// ADR-0100).
pub const CAPABILITY_SHARED_REPORTS: &str = "relazione-condivisa";

/// Il nome della capacità del **Cyber Watch condiviso** (TEAM-CYBER-01,
/// ADR-0102).
pub const CAPABILITY_SHARED_CYBER: &str = "cyber-condiviso";

/// Il nome della capacità dell'**elenco dei monitoraggi dell'ufficio**
/// (TEAM-CYBER-01, ADR-0102).
///
/// Separata, perché serve a più cose: senza sapere **quali monitoraggi**
/// l'ufficio ha, una postazione non può chiedere né i grappoli di una
/// sessione né che se ne congeli una fotografia.
pub const CAPABILITY_SHARED_SESSIONS: &str = "sessioni-condivise";

/// Il nome della capacità della **copertura dell'ufficio** (HUB-COVERAGE-01,
/// ADR-0199): che cosa l'ufficio stava guardando, monitoraggio per
/// monitoraggio, calcolato dall'Hub sul proprio archivio.
pub const CAPABILITY_SHARED_COVERAGE: &str = "copertura-condivisa";

/// Il nome della capacità dei **comandi a distanza** (HUB-REMOTE-01,
/// ADR-0200): una persona entrata mette in pausa, riprende o arresta un
/// monitoraggio dell'Hub, con un motivo. L'Hub la offre sempre: se accettarli
/// lo decide chi lo amministra, e il rifiuto si dice.
pub const CAPABILITY_REMOTE_COMMANDS: &str = "comando-a-distanza";

/// Le capacità che questa versione del programma **conosce e sa usare**.
///
/// **La prima arriva con TEAM-WQ-01** (ADR-0095, decisione 5): la coda
/// dell'ufficio è una funzione in più, che può mancare senza rendere sbagliato
/// il resto — un Hub che non la conosce serve comunque il live e la revisione.
/// È il caso per cui ADR-0084 ha previsto le capacità.
///
/// Il criterio: **versione nuova** quando cambia ciò che l'altro capo deve
/// capire per servire correttamente; **capacità** quando si aggiunge qualcosa
/// che può mancare. Dichiarare una capacità che nessun codice realizza
/// resterebbe una promessa falsa, e non si fa.
pub const KNOWN_CAPABILITIES: &[&str] = &[
    CAPABILITY_WORK_QUEUE,
    CAPABILITY_PRESENCE,
    CAPABILITY_PERSON,
    CAPABILITY_ASSIGNMENT,
    CAPABILITY_SHARED_NOTES,
    CAPABILITY_SHARED_WORKSPACES,
    CAPABILITY_SHARED_REPORTS,
    CAPABILITY_SHARED_CYBER,
    CAPABILITY_SHARED_SESSIONS,
    CAPABILITY_SHARED_COVERAGE,
    CAPABILITY_REMOTE_COMMANDS,
];

/// Un intervallo di versioni, estremi compresi.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VersionRange {
    /// La versione più bassa.
    pub min: u16,
    /// La versione più alta.
    pub max: u16,
}

impl VersionRange {
    /// L'intervallo di questo programma.
    pub const SUPPORTED: Self = Self {
        min: MIN_SUPPORTED_VERSION,
        max: MAX_SUPPORTED_VERSION,
    };

    /// Se l'intervallo è ben formato: nessuno zero, minimo non oltre il massimo.
    #[must_use]
    pub const fn is_well_formed(&self) -> bool {
        self.min >= 1 && self.min <= self.max
    }

    /// Se la versione sta nell'intervallo.
    #[must_use]
    pub const fn contains(&self, version: u16) -> bool {
        version >= self.min && version <= self.max
    }
}

/// La versione più alta in comune, se c'è.
#[must_use]
pub fn highest_common(first: VersionRange, second: VersionRange) -> Option<u16> {
    if !first.is_well_formed() || !second.is_well_formed() {
        return None;
    }
    let alto = first.max.min(second.max);
    let basso = first.min.max(second.min);
    (basso <= alto).then_some(alto)
}

/// Se il nome di una capacità è ammesso: ASCII minuscolo, cifre, `-` e `.`.
///
/// Un nome è un identificativo, non un testo: nessuno spazio, nessun carattere
/// che una riga di diagnostica potrebbe interpretare.
#[must_use]
pub fn is_valid_capability_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= MAX_CAPABILITY_LEN
        && name.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-' || byte == b'.'
        })
}

/// Se un elenco di capacità è ammesso: pochi nomi, validi, senza ripetizioni.
#[must_use]
pub fn is_valid_capability_list(names: &[String]) -> bool {
    names.len() <= MAX_CAPABILITIES
        && names.iter().all(|name| is_valid_capability_name(name))
        && names
            .iter()
            .enumerate()
            .all(|(indice, name)| !names[..indice].contains(name))
}

/// Le capacità che l'Hub accetta: quelle offerte che conosce, nell'ordine
/// dell'offerta. Le sconosciute si ignorano, senza errore — è ciò che permette
/// a un client più nuovo di parlare con un Hub più vecchio.
#[must_use]
pub fn accept_capabilities(offered: &[String], known: &[&str]) -> Vec<String> {
    offered
        .iter()
        .filter(|name| known.contains(&name.as_str()))
        .cloned()
        .collect()
}

#[cfg(test)]
mod tests {
    use super::{
        MAX_CAPABILITIES, VersionRange, accept_capabilities, highest_common,
        is_valid_capability_list, is_valid_capability_name,
    };

    const fn r(min: u16, max: u16) -> VersionRange {
        VersionRange { min, max }
    }

    #[test]
    fn the_highest_common_version_is_chosen_and_nothing_else() {
        assert_eq!(highest_common(r(1, 1), r(1, 1)), Some(1));
        assert_eq!(highest_common(r(1, 3), r(2, 5)), Some(3));
        assert_eq!(highest_common(r(2, 5), r(1, 3)), Some(3));
        assert_eq!(highest_common(r(1, 4), r(4, 9)), Some(4));
        assert_eq!(highest_common(r(1, 2), r(3, 4)), None);
    }

    #[test]
    fn malformed_ranges_have_nothing_in_common() {
        assert_eq!(highest_common(r(0, 1), r(1, 1)), None);
        assert_eq!(highest_common(r(3, 2), r(1, 5)), None);
        assert!(!r(0, 0).is_well_formed());
    }

    #[test]
    fn capability_names_are_identifiers_not_text() {
        for buono in ["events", "catch-up", "cmd.v2", "a1"] {
            assert!(is_valid_capability_name(buono), "{buono}");
        }
        for cattivo in ["", "Events", "con spazio", "a\nb", "è", &"x".repeat(49)] {
            assert!(!is_valid_capability_name(cattivo), "{cattivo:?}");
        }
    }

    #[test]
    fn capability_lists_are_bounded_and_without_repetitions() {
        let troppe: Vec<String> = (0..=MAX_CAPABILITIES).map(|i| format!("c{i}")).collect();
        assert!(!is_valid_capability_list(&troppe));
        assert!(!is_valid_capability_list(&["a".into(), "a".into()]));
        assert!(is_valid_capability_list(&[]));
    }

    #[test]
    fn unknown_capabilities_are_ignored_not_refused() {
        let offerte = vec![String::from("futura"), String::from("nota")];
        assert_eq!(
            accept_capabilities(&offerte, &["nota"]),
            vec![String::from("nota")]
        );
        assert!(accept_capabilities(&offerte, &[]).is_empty());
    }
}
