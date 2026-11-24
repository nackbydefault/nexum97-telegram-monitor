//! Manda **una sola** notifica di Windows, e dice che cosa ha risposto il
//! sistema.
//!
//! # Perché esiste
//!
//! Il 2026-08-20, durante il pilot, le notifiche arrivavano nel centro notifiche
//! di Windows ma **non comparivano come riquadro e non producevano suono**. Le
//! impostazioni del sistema sono state lette e non sopprimevano nulla.
//!
//! Restavano due spiegazioni che dall'esterno si somigliano:
//!
//! 1. il modello dell'avviso non viene presentato (era `ToastText02`, deprecato);
//! 2. Windows aveva raggruppato una **raffica** di notifiche, mostrando la prima
//!    e mandando le altre dritte al centro notifiche.
//!
//! Un monitoraggio dimostrativo ne produce diverse insieme, e con diverse
//! notifiche in volo le due ipotesi non si distinguono. **Questo programma ne
//! manda una e una sola**: se il riquadro non compare, l'ipotesi 2 cade.
//!
//! # Che cosa questo programma NON prova
//!
//! Non prova che il riquadro sia comparso. Nessun programma può saperlo:
//! Windows accetta la chiamata e non dice se l'ha presentata — è la ragione per
//! cui il prodotto registra «consegnato» e non «mostrato». La conferma è in
//! `docs/HUMAN_VALIDATION_QUEUE.md`, voce HVQ-02, e la dà una persona guardando
//! lo schermo.
//!
//! # Uso
//!
//! ```text
//! cargo run --bin toast_probe
//! ```
//!
//! Poi **non toccare nulla per dieci secondi** e guardare l'angolo in basso a
//! destra.
//!
//! # Perché il testo è finto e dichiarato tale
//!
//! Non tocca l'archivio, non legge contenuti acquisiti, non ha bisogno di un
//! account. Il testo dell'avviso dice apertamente di essere una prova: un
//! riquadro che sembrasse un avviso vero comparirebbe su una postazione di
//! servizio e qualcuno potrebbe agirvi sopra.

fn main() {
    println!("Sonda del riquadro di avviso di Windows — UNA notifica sola.");
    println!();

    // La stessa identità che il processo dichiara di sé e che l'installer
    // scrive sul collegamento del menu Start. Senza, Windows non ha nulla a cui
    // attribuire l'avviso e il riquadro non compare — senza alcun errore.
    match lisi_platform::app_identity::declare() {
        Ok(()) => println!("  identita' dichiarata : OK"),
        Err(errore) => {
            println!("  identita' dichiarata : FALLITA — {errore}");
            println!();
            println!("  Senza identita' l'avviso non puo' comparire. Ci si ferma qui.");
            return;
        }
    }

    println!("  identificativo       : {}", APP_USER_MODEL_ID);
    println!();

    // Si CHIEDE A WINDOWS prima di mandare, non dopo.
    //
    // Se Windows ha gli avvisi disattivati per questa applicazione, mandare la
    // notifica e poi chiedere all'operatore se l'ha vista sarebbe fargli
    // guardare uno schermo dove non comparira' nulla, per una ragione che il
    // sistema era pronto a dichiarare.
    let consenso = lisi_platform::toast::notification_state();
    println!(
        "  consenso di Windows  : {}",
        if consenso.is_enabled() {
            "ACCORDATO"
        } else {
            "NEGATO O INCERTO"
        }
    );
    println!("  {}", consenso.operator_message());
    println!();

    if !consenso.is_enabled() {
        println!("  La sonda manda l'avviso lo stesso: un sistema che dichiara di");
        println!("  sopprimere puo' comunque registrarlo nel centro notifiche, e");
        println!("  saperlo distingue due guasti diversi.");
        println!();
    }

    let esito = lisi_platform::show_toast(
        "NEXUM/97 — prova del riquadro",
        "Questa e' una notifica di prova. Non riguarda alcun contenuto monitorato.",
    );

    match esito {
        Ok(()) => {
            println!("  consegna al sistema  : ACCETTATA");
            println!();
            println!("  ATTENZIONE: «accettata» non vuol dire «mostrata».");
            println!("  Windows accetta la chiamata anche quando poi non presenta nulla.");
            println!();
            println!("  Guardare ora l'angolo in basso a destra, per dieci secondi.");
            println!();
            println!("  Da riferire, quattro cose:");
            println!("    1. e' comparso il RIQUADRO?");
            println!("    2. si e' sentito un SUONO?");
            println!("    3. l'avviso e' finito nel centro notifiche (clic sull'orologio)?");
            println!("    4. porta il nome e l'icona di NEXUM/97?");
            println!();
            println!("  Se il riquadro NON compare con una notifica sola, l'ipotesi della");
            println!("  raffica cade e il difetto e' nel modello dell'avviso.");
        }
        Err(errore) => {
            println!("  consegna al sistema  : RIFIUTATA — {errore}");
            println!();
            println!("  Il sistema ha rifiutato la chiamata. Questo si' che e' un difetto");
            println!("  nostro o di configurazione, ed e' diverso da «accettata e non");
            println!("  mostrata».");
        }
    }
}

/// Ripetuto qui per stamparlo: il valore autorevole vive in `lisi-platform`.
const APP_USER_MODEL_ID: &str = lisi_platform::app_identity::APP_USER_MODEL_ID;
