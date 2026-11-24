//! La porta della scoperta pubblica: l'unico posto da cui può uscire una
//! politica validata.
//!
//! # La regola che governa questo modulo
//!
//! **Un cancello che si controlla è un cancello che si dimentica.**
//!
//! Il cancello non è un `if` scritto da qualche parte: è **l'assenza di una
//! chiave**. `ValidatedDiscoveryPolicy` non ha un costruttore, e l'unico modo di
//! averne una è ottenerla da limiti **osservati** — che nessuno ha ancora
//! misurato (ADR-0074, HVQ-03).
//!
//! Questo modulo non aggiunge un secondo cancello alla **stessa** domanda:
//! aggiungerlo significherebbe ammettere che il primo non basta, e da quel
//! momento sarebbero due cose da tenere allineate. Aggiunge **una porta con un
//! nome**, perché «non c'è modo di ottenerla» è una proprietà che nessuno può
//! verificare guardando: va resa un posto che si possa nominare in una prova.
//!
//! # Due chiavi, per due domande diverse
//!
//! Dal 2026-09-22 la porta richiede anche l'**autorità dell'acquisizione**
//! (TEAM-DISCOVERY-01, ADR-0103). Non è un secondo cancello sulla stessa
//! domanda: la politica validata risponde a «**si può** cercare?», l'autorità
//! risponde a «**chi** può cercare?».
//!
//! Oggi la prima è chiusa per tutti. Il giorno in cui POC-02 misurerà i
//! limiti, quella si aprirà — e senza la seconda si aprirebbe per **tutti**,
//! cioè anche per una postazione che segue un Hub: N postazioni che cercano
//! sono gli N carichi su Telegram che il congelamento vieta.
//!
//! # Che cosa qui dentro NON esiste
//!
//! Nessun ramo `cfg(test)`, nessuna variabile d'ambiente, nessun interruttore,
//! nessuna costante «per comodità di prova». È la regola della catena di
//! verifica degli aggiornamenti (ADR-0069): **un indebolimento che esiste solo
//! nelle prove è un indebolimento che esiste**.
//!
//! La decisione completa sta in
//! `docs/adr/ADR-0081-UN-CANCELLO-CHE-SI-CONTROLLA-E-UN-CANCELLO-CHE-SI-DIMENTICA.md`.

use lisi_core::model::discovery::ValidatedDiscoveryPolicy;

use crate::acquisition_authority::AcquisitionAuthority;

/// Perché il cancello è chiuso, e che cosa manca perché non lo sia.
///
/// Non è un divieto: è **un'impossibilità**, e si dichiara con il nome di ciò
/// che manca invece di lasciare intendere un guasto.
pub const PERCHE_IL_CANCELLO_E_CHIUSO: &str = "Nessuna ricerca pubblica può essere eseguita: richiede una politica \
     validata, e una politica si convalida soltanto davanti ai limiti che \
     Telegram dichiara davvero. Quei limiti non sono ancora stati misurati su un \
     account reale. Manca la misura, non il permesso.";

/// Perché una postazione che segue un Hub non cercherebbe comunque.
///
/// Si dichiara invece di lasciare un'assenza muta: un'assenza non spiegata si
/// legge come una mancanza, e chi la nota chiede di colmarla (ADR-0079). Detta
/// con la ragione, diventa una scelta (ADR-0103).
pub const PERCHE_NON_CERCA_CHI_SEGUE: &str = "Se anche i limiti fossero misurati, la ricerca non \
     partirebbe da qui: la scoperta pubblica è dell'Hub, e la fa una volta sola. Dieci \
     postazioni che cercano sarebbero dieci carichi sullo stesso account Telegram, e il limite \
     lo vede l'account, non la postazione.";

/// Che cosa manca, in una parola che si possa nominare altrove.
pub const COSA_MANCA: &str = "limiti osservati";

/// Il cancello è chiuso, e dice perché.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GateClosed {
    /// Che cosa manca.
    pub missing: &'static str,
    /// Perché, in ciò che una persona legge.
    pub reason: &'static str,
}

/// L'unica porta da cui può uscire una politica validata.
///
/// # Perché oggi restituisce sempre il rifiuto
///
/// Perché **non esiste una misura dei limiti di Telegram**, e una politica
/// validata si ottiene solo da lì. Non è una scelta prudenziale scritta qui:
/// è ciò che i tipi già impongono, e questa funzione lo rende dicibile.
///
/// # Errori
///
/// Restituisce sempre [`GateClosed`] finché i limiti non sono stati osservati.
/// **Il giorno in cui lo saranno, il cancello non si toglie: si sposta** — un
/// modulo, uno solo, entrerà nell'elenco di chi può comporre dei limiti
/// osservati, e la modifica si vedrà perché quell'elenco esiste per essere letto.
pub fn validated_policy(
    authority: &AcquisitionAuthority,
) -> Result<ValidatedDiscoveryPolicy, GateClosed> {
    // L'AUTORITA' NON SI GUARDA: SI RICHIEDE (ADR-0103, decisione 1).
    //
    // Non c'e' niente da controllare, perche' `AcquisitionAuthority` non ha
    // un costruttore pubblico: chi non e' l'Hub non ne ha una, e quindi non
    // puo' nemmeno chiamare questa funzione. Il parametro si consuma qui
    // perche' il compilatore non lo veda inutilizzato, e resta il motivo per
    // cui questa firma e' com'e'.
    let _ = authority;

    Err(GateClosed {
        missing: COSA_MANCA,
        reason: PERCHE_IL_CANCELLO_E_CHIUSO,
    })
}

#[cfg(test)]
mod tests {
    use std::path::{Path, PathBuf};

    use lisi_security::ProtectedStore;

    use super::{COSA_MANCA, PERCHE_IL_CANCELLO_E_CHIUSO, validated_policy};
    use crate::acquisition_authority::{AcquisitionAuthority, StationAuthorityService};
    use crate::hub_client::HubConnectionStore;

    /// L'autorita' di una postazione che acquisisce, ottenuta dal percorso vero.
    ///
    /// Nessuna scorciatoia: il tipo non ha costruttore pubblico, e questa
    /// funzione passa da dove ci passa il prodotto. La cartella e' vuota, quindi
    /// la postazione non segue nessun Hub, quindi acquisisce.
    fn autorita_di_chi_acquisisce(cartella: &Path) -> AcquisitionAuthority {
        let servizio = StationAuthorityService::new(HubConnectionStore::at(ProtectedStore::at(
            cartella.join("hub-client.protetto"),
        )));
        let Ok(esito) = servizio.acquisition_authority(&crate::run_mode::operational_for_tests())
        else {
            panic!("l'esito dell'autorita' deve esserci");
        };
        let Some(autorita) = esito.into_granted() else {
            panic!("una postazione senza Hub configurato deve poter acquisire");
        };
        autorita
    }

    /// **La porta non si apre senza l'autorità che acquisisce.**
    ///
    /// # Il difetto che questa prova impedisce
    ///
    /// Il cancello di ADR-0081 risponde a «si può cercare?». Non risponde a
    /// «**chi** può cercare?». Il giorno in cui POC-02 misurerà i limiti,
    /// quella porta si aprirà — e senza la seconda chiave si aprirebbe per
    /// **tutti**, cioè anche per una postazione che segue un Hub: N postazioni
    /// che cercano sono N carichi su Telegram, che il congelamento vieta
    /// (TEAM-DISCOVERY-01, ADR-0103).
    ///
    /// La prova legge la **firma**: un parametro che non si può fabbricare non
    /// si può passare, e toglierlo è l'unico modo di aprire la porta a tutti.
    #[test]
    fn la_porta_non_si_apre_senza_l_autorita_che_acquisisce() {
        const QUESTO_MODULO: &str = include_str!("discovery_gate.rs");
        let Some((_, firma)) = QUESTO_MODULO.split_once("pub fn validated_policy(") else {
            panic!("la porta deve esistere");
        };
        let Some((parametri, _)) = firma.split_once(')') else {
            panic!("la firma della porta deve chiudersi");
        };
        assert!(
            parametri.contains("AcquisitionAuthority"),
            "la porta si apre senza l'autorità dell'acquisizione: cercare non è più un atto \
             dell'Hub, ed N postazioni diventerebbero N carichi su Telegram"
        );
    }

    /// I moduli autorizzati a comporre dei limiti osservati o a validare una
    /// politica.
    ///
    /// **Oggi ce n'è uno solo, ed è la porta che li rifiuta.** Il giorno in cui
    /// POC-02 misurerà i limiti veri, il modulo che li misura entrerà qui — e
    /// quella riga sarà la cosa che qualcuno rileggerà per sapere chi ha la
    /// chiave.
    ///
    /// Si nomina il **percorso** relativo alla radice delle crate, non il solo
    /// nome del file: un nome di file si ripete, e un secondo
    /// `discovery_gate.rs` altrove non deve ereditare la chiave.
    const CHI_PUO_APRIRE: [&str; 1] = ["lisi-services/src/discovery_gate.rs"];

    /// I due gesti che aprirebbero il cancello.
    ///
    /// Comporre dei limiti osservati, e chiedere a una politica di validarsi.
    /// Non ce n'è un terzo: `ValidatedDiscoveryPolicy` non ha un costruttore.
    const GESTI_CHE_APRONO: [&str; 2] = ["ObservedLimits::observed", ".validate("];

    /// La radice delle crate.
    ///
    /// La guardia legge **l'albero dei sorgenti**: fuori dal repository non gira,
    /// e lo dichiara invece di passare in silenzio.
    fn radice_delle_crate() -> PathBuf {
        let Some(crate_dir) = option_env!("CARGO_MANIFEST_DIR") else {
            panic!("la guardia legge i sorgenti: serve la cartella della crate");
        };
        let percorso = Path::new(crate_dir);
        let Some(crates) = percorso.parent() else {
            panic!("la cartella delle crate non si trova");
        };
        crates.to_path_buf()
    }

    /// Tutti i file Rust sotto la radice indicata.
    fn sorgenti(radice: &Path, trovati: &mut Vec<PathBuf>) {
        let Ok(voci) = std::fs::read_dir(radice) else {
            return;
        };
        for voce in voci.flatten() {
            let percorso = voce.path();
            if percorso.is_dir() {
                sorgenti(&percorso, trovati);
            } else if percorso.extension().is_some_and(|ext| ext == "rs") {
                trovati.push(percorso);
            }
        }
    }

    /// La parte di un sorgente che finisce nel prodotto consegnato.
    ///
    /// Toglie i moduli di prova e tiene **tutto il resto**: ciò che sta sotto
    /// `cfg(test)` non viene consegnato a nessuno, e la proprietà da difendere
    /// riguarda **il prodotto**.
    ///
    /// # Il difetto che una guardia sorella ha già avuto
    ///
    /// Tagliare al **primo** modulo di prova e tenere ciò che sta prima rende
    /// invisibile il codice scritto **dopo** quel modulo (ADR-0044, decisione
    /// 4). Qui si salta ogni modulo di prova fino alla sua graffa in prima
    /// colonna — la convenzione di questo progetto — e si continua a leggere.
    ///
    /// Si riconosce solo `#[cfg(test)]` seguito da `mod`: un singolo elemento
    /// marcato `cfg(test)` resta visibile. Sbagliare in quella direzione produce
    /// un rosso da leggere, non un silenzio.
    fn produzione(sorgente: &str) -> String {
        const INIZIO: &str = "\n#[cfg(test)]\nmod ";
        const FINE: &str = "\n}\n";

        let mut fuori = String::new();
        let mut resto = sorgente;
        while let Some((prima, dopo)) = resto.split_once(INIZIO) {
            fuori.push_str(prima);
            fuori.push('\n');
            match dopo.split_once(FINE) {
                Some((_, coda)) => resto = coda,
                None => return fuori,
            }
        }
        fuori.push_str(resto);
        fuori
    }

    /// **Oggi il cancello e' chiuso, e dice che cosa manca — anche a chi ha
    /// l'autorita' dell'acquisizione.**
    ///
    /// Le due chiavi rispondono a due domande diverse: l'autorita' dice **chi**
    /// puo' cercare, la politica validata dice **se** si puo' cercare. Avere la
    /// prima non risponde alla seconda, e questa prova lo mostra tenendo in mano
    /// un'autorita' vera (ADR-0103).
    #[test]
    fn oggi_il_cancello_e_chiuso_e_dice_cosa_manca() {
        let Ok(cartella) = tempfile::tempdir() else {
            panic!("la cartella temporanea deve potersi creare");
        };
        let autorita = autorita_di_chi_acquisisce(cartella.path());

        let Err(chiuso) = validated_policy(&autorita) else {
            panic!(
                "il cancello e' aperto: esiste una politica validata senza che \
                 nessuno abbia misurato i limiti di Telegram (ADR-0081)"
            );
        };

        assert_eq!(chiuso.missing, COSA_MANCA);
        assert_eq!(chiuso.reason, PERCHE_IL_CANCELLO_E_CHIUSO);
        assert!(
            chiuso.reason.contains("Manca la misura, non il permesso"),
            "un'impossibilita' non si traveste da divieto: «{}»",
            chiuso.reason
        );
    }

    /// **Il cancello non ha una chiave di scorta.**
    ///
    /// Nessun ramo di prova, nessuna variabile d'ambiente, nessun interruttore.
    /// Un indebolimento che esiste solo nelle prove e' un indebolimento che
    /// esiste (ADR-0069, ADR-0081).
    #[test]
    fn il_cancello_non_ha_una_chiave_di_scorta() {
        const QUESTO_MODULO: &str = include_str!("discovery_gate.rs");

        let codice = produzione(QUESTO_MODULO);
        let senza_note: String = codice
            .lines()
            .filter(|riga| !riga.trim_start().starts_with("//"))
            .collect::<Vec<&str>>()
            .join("\n");

        for vietato in [
            "cfg(test)",
            "cfg(debug_assertions)",
            "env::var",
            "option_env!",
            "feature =",
            "if ",
        ] {
            assert!(
                !senza_note.contains(vietato),
                "«{vietato}» nella porta: il cancello non ha rami, e non ha una \
                 chiave di scorta (ADR-0081)"
            );
        }
    }

    /// **In tutto il prodotto consegnato non esiste un punto in cui una politica
    /// validata possa nascere.**
    ///
    /// E' la proprieta' che conta, ed e' una proprieta' del PRODOTTO: una
    /// guardia che leggesse soltanto il proprio file dimostrerebbe qualcosa del
    /// proprio file. Questa legge tutti i sorgenti delle crate.
    #[test]
    fn nessun_modulo_di_produzione_fabbrica_dei_limiti_osservati() {
        let radice = radice_delle_crate();
        let mut file = Vec::new();
        sorgenti(&radice, &mut file);

        assert!(
            file.len() > 100,
            "la guardia non ha trovato i sorgenti delle crate: se l'albero e' \
             cambiato, va aggiornata insieme a lui ({} file)",
            file.len()
        );

        let mut colpevoli: Vec<String> = Vec::new();
        for percorso in file {
            let Ok(relativo) = percorso.strip_prefix(&radice) else {
                continue;
            };
            // Separatore uniforme: su Windows i componenti arrivano con «\».
            let nome = relativo
                .components()
                .map(|parte| parte.as_os_str().to_string_lossy())
                .collect::<Vec<_>>()
                .join("/");
            if CHI_PUO_APRIRE.contains(&nome.as_str()) {
                continue;
            }
            let Ok(sorgente) = std::fs::read_to_string(&percorso) else {
                continue;
            };
            let codice = produzione(&sorgente);
            for gesto in GESTI_CHE_APRONO {
                if codice.contains(gesto) {
                    colpevoli.push(format!("{nome}: {gesto}"));
                }
            }
        }

        assert!(
            colpevoli.is_empty(),
            "questi punti del prodotto consegnato aprirebbero il cancello della \
             scoperta pubblica: {colpevoli:?}. Se uno di essi deve poterlo fare, \
             va scritto in «CHI_PUO_APRIRE», che esiste per essere letto \
             (ADR-0081)"
        );
    }

    /// **La dichiarazione che l'operatore legge continua a esistere.**
    ///
    /// Il cancello non e' quella frase - il cancello e' l'assenza della chiave -
    /// ma un cancello chiuso che non si dichiara e' indistinguibile da un
    /// guasto.
    #[test]
    fn la_porta_chiusa_resta_dichiarata_a_chi_guarda() {
        let dichiarazione = crate::discovery::PERCHE_NON_SI_CERCA;

        assert!(
            dichiarazione.contains("politica validata"),
            "la dichiarazione nomina cio' che serve"
        );
        assert!(
            dichiarazione.contains("limiti"),
            "e nomina cio' che manca: «{dichiarazione}»"
        );
    }
}
