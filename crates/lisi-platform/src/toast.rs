//! Il riquadro di avviso di Windows.
//!
//! È l'avviso che scivola in basso a destra e resta nel centro notifiche **di
//! Windows**, non in quello dell'applicazione. Le scelte sono in
//! `docs/adr/ADR-0025-WINDOWS-TOAST.md`.
//!
//! # Che cosa questo modulo fa, e che cosa non decide
//!
//! Mostra un titolo e un corpo già composti. **Non** decide se notificare, che
//! cosa scrivere, o quanto rivelare: quelle sono decisioni del motore delle
//! notifiche (Milestone 8), che le prende secondo la riservatezza scelta
//! dall'operatore. Qui arriva un testo pronto, e questo modulo lo consegna al
//! sistema.
//!
//! La separazione non è formale. In modalità riservata il corpo è generico
//! apposta, perché l'avviso può comparire su una schermata bloccata: se questo
//! modulo componesse il testo da sé — per esempio aggiungendo il livello, che
//! pure conosce — riporterebbe in vista proprio ciò che quella modalità esiste
//! per nascondere.
//!
//! # Perché non c'è `unsafe`
//!
//! Le notifiche di Windows sono API **WinRT**, non Win32. La crate `windows`
//! le espone come oggetti Rust sicuri: non ci sono puntatori da passare né
//! buffer da dimensionare, quindi non c'è alcuna invariante da difendere a
//! mano. È il primo modulo di questo crate che parla con il sistema senza un
//! blocco `unsafe`, e non è un caso: è la differenza fra un'API C e una
//! progettata per essere richiamata da altri linguaggi.
//!
//! # Perché il testo non viene messo in una stringa XML
//!
//! Il toast si descrive con un frammento XML, e comporlo per concatenazione
//! sarebbe stato più breve. Ma il corpo dell'avviso contiene **un estratto di
//! un messaggio acquisito**, cioè testo che ha scritto qualcun altro: un
//! frammento come `</text><actions>…` uscirebbe dal proprio nodo e
//! aggiungerebbe pulsanti all'avviso. È iniezione, con la stessa forma che
//! avrebbe in una pagina web.
//!
//! Il testo entra quindi **come nodo di testo del DOM**, dove il sistema lo
//! tratta come dato e non come struttura. È la stessa regola per cui i valori
//! non si concatenano in una query SQL.

#[cfg(windows)]
use crate::app_identity::APP_USER_MODEL_ID;
use crate::error::{PlatformError, PlatformResult};

/// Lunghezza massima di una riga dell'avviso.
///
/// Windows tronca da sé ciò che non entra nel riquadro. Il taglio qui non serve
/// alla resa: serve a non consegnare al sistema una stringa di dimensione
/// arbitraria proveniente da materiale remoto.
const MAX_LINE_CHARS: usize = 300;

/// Ripulisce una riga prima di consegnarla al sistema.
///
/// I caratteri di controllo diventano spazi: in un riquadro alto due righe un
/// «a capo» inserito da chi ha scritto il messaggio sposterebbe fuori vista il
/// resto del testo, ed è un modo semplice per far sparire da un avviso la parte
/// che conta.
fn single_line(value: &str) -> String {
    let flattened: String = value
        .chars()
        .map(|character| {
            if character.is_control() {
                ' '
            } else {
                character
            }
        })
        .collect();
    let trimmed = flattened.trim();

    if trimmed.chars().count() <= MAX_LINE_CHARS {
        return String::from(trimmed);
    }

    let head: String = trimmed.chars().take(MAX_LINE_CHARS).collect();
    format!("{head}\u{2026}")
}

/// Consegna a Windows un avviso con il titolo e il corpo indicati.
///
/// # Consegnare non è mostrare
///
/// `Ok(())` significa che **il sistema ha accettato la richiesta**, non che il
/// riquadro sia comparso. Windows accetta anche quando poi non mostra nulla: a
/// un'applicazione priva di collegamento nel menu Start con il proprio
/// `AppUserModelID`, o quando l'utente ha disattivato gli avvisi di questa
/// applicazione, o durante l'assistente di concentrazione.
///
/// Non è una svista dell'API: nessuna funzione può restituire «l'operatore lo
/// ha visto». Chi chiama non deve quindi trarre da `Ok(())` più di quanto dica,
/// e in particolare non deve scriverlo in un registro come se fosse una
/// conferma.
///
/// Che il riquadro compaia davvero si verifica **guardandolo**, sul prodotto
/// installato: è la sezione N di `docs/PILOT_MP15E.md`.
///
/// # Errori
///
/// Restituisce [`PlatformError::ToastRefused`] se il sistema respinge la
/// richiesta, e [`PlatformError::Unsupported`] fuori da Windows. Un rifiuto non
/// è fatale: la decisione di notificare è già stata presa e registrata, e chi
/// chiama deve ripiegare invece di perderla.
/// Lo scheletro del riquadro, **senza testo dentro**.
///
/// # Perché una costante e non più un modello di sistema
///
/// Fino al 2026-08-20 questo modulo chiedeva a Windows il modello
/// `ToastText02`, introdotto con Windows 8. Quella scelta aveva una buona
/// ragione — il sistema porta la struttura corretta per la versione in
/// esecuzione — e una conseguenza che si è vista soltanto usando il prodotto:
/// i modelli `ToastTemplateType` sono **deprecati**, e la documentazione
/// corrente di Windows indica `ToastGeneric` come la forma sostenuta.
///
/// Il 2026-08-20, durante il pilot, le notifiche arrivavano nel centro
/// notifiche di Windows — quindi l'identificativo dell'applicazione era
/// corretto e il sistema le accettava — ma **non comparivano come riquadro e
/// non producevano suono**. Le impostazioni di Windows sono state lette e non
/// sopprimevano nulla. Il modello legacy è l'ipotesi che resta.
///
/// **Questo modulo non dichiara risolto quel problema.** Nessun programma può
/// sapere se Windows abbia mostrato un riquadro: il sistema accetta la chiamata
/// e non lo dice. La conferma è in `HUMAN_VALIDATION_QUEUE.md`, voce HVQ-02.
///
/// # Perché lo scheletro è una costante e il testo no
///
/// Lo scheletro è **nostro**: nessuna parte proviene da materiale acquisito, e
/// caricarlo come XML è sicuro perché non contiene nulla che qualcun altro
/// abbia scritto. Il testo dell'avviso invece contiene un estratto di un
/// messaggio remoto, e continua a entrare **come nodo di testo del DOM**, mai
/// per concatenazione.
///
/// È la stessa regola di prima, applicata allo stesso punto: cambia il modello,
/// non cambia il confine fra dato e struttura.
///
/// # L'elemento audio
///
/// `ms-winsoundevent:Notification.Default` è il suono predefinito di Windows.
/// Dichiararlo non cambia il comportamento — è ciò che il sistema userebbe
/// comunque — ma rende visibile l'intenzione: questo avviso **deve** suonare, e
/// se non suona il difetto non è un'omissione nostra.
#[cfg(windows)]
const TOAST_SKELETON: &str = concat!(
    "<toast>",
    "<visual>",
    "<binding template=\"ToastGeneric\">",
    "<text></text>",
    "<text></text>",
    "</binding>",
    "</visual>",
    "<audio src=\"ms-winsoundevent:Notification.Default\" loop=\"false\"/>",
    "</toast>",
);

/// Compone il documento dell'avviso a partire da titolo e corpo.
///
/// Sta in una funzione propria perché è **la parte che si può sbagliare in
/// silenzio**: se il testo finisse per essere interpretato come struttura,
/// nulla fallirebbe e il riquadro mostrerebbe qualcosa che nessuno ha deciso.
/// Separata, si può provare senza mostrare alcun avviso.
#[cfg(windows)]
fn toast_document(title: &str, body: &str) -> PlatformResult<windows::Data::Xml::Dom::XmlDocument> {
    use windows::Data::Xml::Dom::XmlDocument;
    use windows::core::HSTRING;

    let document = XmlDocument::new().map_err(|error| refused(&error))?;
    document
        .LoadXml(&HSTRING::from(TOAST_SKELETON))
        .map_err(|error| refused(&error))?;

    let lines = document
        .GetElementsByTagName(&HSTRING::from("text"))
        .map_err(|error| refused(&error))?;

    for (position, value) in [title, body].iter().enumerate() {
        let Ok(node) = lines.Item(u32::try_from(position).unwrap_or(u32::MAX)) else {
            // Uno scheletro con meno nodi di testo del previsto non è un guasto
            // da segnalare: l'avviso esce con le righe che ha.
            break;
        };

        // `CreateTextNode` + `AppendChild`, non una stringa XML: il testo entra
        // come DATO nel documento, e un frammento di markup dentro un messaggio
        // acquisito resta il testo che è invece di diventare struttura.
        let text = document
            .CreateTextNode(&HSTRING::from(single_line(value)))
            .map_err(|error| refused(&error))?;
        node.AppendChild(&text).map_err(|error| refused(&error))?;
    }

    Ok(document)
}

/// Traduce un errore di WinRT nel rifiuto che questo crate dichiara.
#[cfg(windows)]
fn refused(error: &windows::core::Error) -> PlatformError {
    PlatformError::ToastRefused {
        code: error.code().0,
    }
}

#[cfg(windows)]
pub fn show(title: &str, body: &str) -> PlatformResult<()> {
    use windows::UI::Notifications::{ToastNotification, ToastNotificationManager};
    use windows::core::HSTRING;

    let document = toast_document(title, body)?;

    let toast =
        ToastNotification::CreateToastNotification(&document).map_err(|error| refused(&error))?;

    // L'identità è la stessa che il processo dichiara di sé e che l'installer
    // scrive sul collegamento del menu Start. Deve coincidere in tutti e tre i
    // punti: se divergesse, Windows attribuirebbe l'avviso a un'applicazione
    // che non esiste e **il riquadro semplicemente non comparirebbe**, senza
    // alcun errore.
    let notifier =
        ToastNotificationManager::CreateToastNotifierWithId(&HSTRING::from(APP_USER_MODEL_ID))
            .map_err(|error| refused(&error))?;

    notifier.Show(&toast).map_err(|error| refused(&error))?;

    Ok(())
}

/// Fuori da Windows non c'è alcun riquadro di avviso da mostrare.
#[cfg(not(windows))]
pub fn show(_title: &str, _body: &str) -> PlatformResult<()> {
    Err(PlatformError::Unsupported)
}

/// Che cosa Windows dice degli avvisi di questa applicazione.
///
/// # Perché questa domanda esiste
///
/// Il 2026-08-20, durante il pilot, gli avvisi arrivavano nel centro notifiche
/// ma **non comparivano come riquadro e non producevano suono**. Il prodotto
/// non aveva modo di dire perché: `Show` riesce anche quando Windows ha deciso
/// di non mostrare nulla, e nessun errore lo segnala.
///
/// Windows però **lo dichiara**, e nessuno glielo chiedeva. `ToastNotifier`
/// espone lo stato: abilitato, disattivato dall'utente per questa applicazione,
/// disattivato per l'utente in generale, disattivato da criteri di gruppo.
///
/// Chiederlo trasforma una domanda che richiedeva una persona — «vai nelle
/// impostazioni di Windows e guarda» — in qualcosa che il prodotto sa dire da
/// sé, nella schermata dove l'operatore configura gli avvisi.
///
/// # Che cosa NON risolve
///
/// `Enabled` significa che Windows non ha una ragione **dichiarata** per
/// sopprimere l'avviso. Non significa che il riquadro sia comparso: l'Assistente
/// notifiche, l'ora di silenzio e la soppressione dei gruppi ravvicinati agiscono
/// dopo, e il sistema non li riporta qui. La conferma visiva resta HVQ-02.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NotificationState {
    /// Windows non ha alcuna ragione dichiarata per sopprimere gli avvisi.
    Enabled,
    /// L'utente ha disattivato gli avvisi **per questa applicazione**.
    DisabledForApplication,
    /// L'utente ha disattivato gli avvisi per sé, in generale.
    DisabledForUser,
    /// Un criterio di gruppo li ha disattivati.
    ///
    /// Su una postazione d'ufficio è il caso che l'operatore non può risolvere
    /// da solo, e va detto invece di lasciarlo indovinare.
    DisabledByGroupPolicy,
    /// L'applicazione non si dichiara capace di notificare.
    ///
    /// Se comparisse, l'identità registrata dall'installer sarebbe incompleta.
    DisabledByManifest,
    /// Lo stato non è stato leggibile.
    ///
    /// **Non è «disattivato».** Un sistema che non risponde e un sistema che
    /// dice di no sono due cose diverse, e dire la seconda al posto della prima
    /// manderebbe l'operatore a cercare un interruttore che è già acceso.
    Undeterminable {
        /// Il codice restituito da Windows.
        code: i32,
    },
}

impl NotificationState {
    /// Vero solo quando Windows non dichiara alcuna soppressione.
    #[must_use]
    pub const fn is_enabled(&self) -> bool {
        matches!(self, Self::Enabled)
    }

    /// Lo stato, in una frase che una persona legge.
    ///
    /// Ogni caso dice **che cosa fare**, non solo che cosa succede: un guasto
    /// che non si sa come affrontare produce o panico o indifferenza.
    #[must_use]
    pub fn operator_message(&self) -> String {
        match self {
            Self::Enabled => String::from(
                "Windows accetta gli avvisi di questa applicazione. Questo non \
                 garantisce che il riquadro compaia: l'Assistente notifiche e le \
                 ore di silenzio agiscono dopo, e il sistema non li dichiara qui.",
            ),
            Self::DisabledForApplication => String::from(
                "Windows ha gli avvisi DISATTIVATI per questa applicazione. \
                 Aprire Impostazioni di Windows › Sistema › Notifiche, trovare \
                 NEXUM/97 e riattivare «Mostra banner di notifica» e «Riproduci \
                 un suono»: sono due interruttori distinti.",
            ),
            Self::DisabledForUser => String::from(
                "Windows ha gli avvisi DISATTIVATI per questo profilo utente, per \
                 tutte le applicazioni. Aprire Impostazioni di Windows › Sistema › \
                 Notifiche e riattivarli.",
            ),
            Self::DisabledByGroupPolicy => String::from(
                "Un criterio dell'organizzazione ha disattivato gli avvisi su \
                 questa postazione. Non è modificabile dall'operatore: serve chi \
                 amministra il dominio.",
            ),
            Self::DisabledByManifest => String::from(
                "Questa copia dell'applicazione non risulta a Windows capace di \
                 notificare. È un difetto dell'installazione: reinstallare dal \
                 Setup.exe e, se persiste, segnalarlo.",
            ),
            Self::Undeterminable { code } => format!(
                "Non è stato possibile chiedere a Windows se gli avvisi siano \
                 attivi (codice {code:#010x}). Questo NON significa che siano \
                 disattivati."
            ),
        }
    }
}

/// Chiede a Windows che cosa sa degli avvisi di questa applicazione.
///
/// Non mostra nulla e non modifica nulla: interroga e basta.
#[cfg(windows)]
#[must_use]
pub fn notification_state() -> NotificationState {
    use windows::UI::Notifications::ToastNotificationManager;
    use windows::core::HSTRING;

    let notifier = match ToastNotificationManager::CreateToastNotifierWithId(&HSTRING::from(
        APP_USER_MODEL_ID,
    )) {
        Ok(notifier) => notifier,
        Err(error) => {
            return NotificationState::Undeterminable {
                code: error.code().0,
            };
        }
    };

    match notifier.Setting() {
        Err(error) => NotificationState::Undeterminable {
            code: error.code().0,
        },
        Ok(setting) => interpret_setting(setting.0),
    }
}

/// Traduce il valore di Windows nello stato del dominio.
///
/// Sta in una funzione a sé perché è la parte **provabile senza Windows**: i
/// valori sono numeri documentati, e una prova può percorrerli tutti senza
/// mostrare alcun avviso né dipendere dalla configurazione della macchina.
#[cfg(windows)]
const fn interpret_setting(raw: i32) -> NotificationState {
    match raw {
        0 => NotificationState::Enabled,
        1 => NotificationState::DisabledForApplication,
        2 => NotificationState::DisabledForUser,
        3 => NotificationState::DisabledByGroupPolicy,
        4 => NotificationState::DisabledByManifest,
        // Un valore che Windows non documenta non e' «attivo»: davanti a una
        // risposta che non si capisce, dire «va tutto bene» sarebbe la bugia
        // piu' comoda.
        code => NotificationState::Undeterminable { code },
    }
}

/// Fuori da Windows non esiste alcun centro notifiche da interrogare.
#[cfg(not(windows))]
#[must_use]
pub fn notification_state() -> NotificationState {
    NotificationState::Undeterminable { code: 0 }
}

#[cfg(test)]
mod tests {
    use super::{MAX_LINE_CHARS, NotificationState, single_line};

    #[cfg(windows)]
    use super::{TOAST_SKELETON, toast_document};

    /// **Ogni ragione di soppressione dichiarata da Windows e' distinta.**
    ///
    /// «Disattivato per questa applicazione» e «disattivato da un criterio
    /// dell'organizzazione» portano a due azioni diverse: la prima la risolve
    /// l'operatore in trenta secondi, la seconda non la risolve affatto.
    /// Appiattirle toglierebbe a chi legge l'unica cosa utile.
    #[cfg(windows)]
    #[test]
    fn ogni_ragione_di_soppressione_resta_distinta() {
        use super::interpret_setting;

        assert_eq!(interpret_setting(0), NotificationState::Enabled);
        assert_eq!(
            interpret_setting(1),
            NotificationState::DisabledForApplication
        );
        assert_eq!(interpret_setting(2), NotificationState::DisabledForUser);
        assert_eq!(
            interpret_setting(3),
            NotificationState::DisabledByGroupPolicy
        );
        assert_eq!(interpret_setting(4), NotificationState::DisabledByManifest);
    }

    /// **Un valore che Windows non documenta non e' «attivo».**
    #[cfg(windows)]
    #[test]
    fn una_risposta_sconosciuta_non_diventa_un_via_libera() {
        use super::interpret_setting;

        for sconosciuto in [5, 99, -1] {
            let stato = interpret_setting(sconosciuto);
            assert!(
                !stato.is_enabled(),
                "il valore {sconosciuto} e' stato scambiato per un via libera"
            );
            assert!(matches!(stato, NotificationState::Undeterminable { .. }));
        }
    }

    /// **Solo `Enabled` e' un via libera.**
    #[test]
    fn davanti_a_uno_stato_incerto_la_risposta_e_no() {
        assert!(NotificationState::Enabled.is_enabled());
        for stato in [
            NotificationState::DisabledForApplication,
            NotificationState::DisabledForUser,
            NotificationState::DisabledByGroupPolicy,
            NotificationState::DisabledByManifest,
            NotificationState::Undeterminable { code: 0 },
        ] {
            assert!(!stato.is_enabled(), "{stato:?} non e' un via libera");
        }
    }

    /// **Ogni stato dice che cosa fare, non solo che cosa succede.**
    ///
    /// Un guasto che non si sa come affrontare produce o panico o
    /// indifferenza, e nessuna delle due e' la reazione giusta.
    #[test]
    fn ogni_stato_dice_che_cosa_fare() {
        for stato in [
            NotificationState::Enabled,
            NotificationState::DisabledForApplication,
            NotificationState::DisabledForUser,
            NotificationState::DisabledByGroupPolicy,
            NotificationState::DisabledByManifest,
            NotificationState::Undeterminable { code: 1 },
        ] {
            let messaggio = stato.operator_message();
            assert!(
                messaggio.len() > 60,
                "{stato:?} liquida la questione: «{messaggio}»"
            );
        }

        // Il caso che l'operatore puo' risolvere da solo deve dire DOVE.
        let suo = NotificationState::DisabledForApplication.operator_message();
        assert!(suo.contains("Impostazioni di Windows"));
        assert!(
            suo.contains("due interruttori distinti"),
            "banner e suono sono due interruttori separati, e chi ne accende \
             uno solo crede di aver finito: «{suo}»"
        );

        // Il caso che NON puo' risolvere deve dirlo, invece di mandarlo a
        // cercare un interruttore che non trovera'.
        let criterio = NotificationState::DisabledByGroupPolicy.operator_message();
        assert!(criterio.contains("amministra"));
    }

    /// **«Non lo so» non deve somigliare a «disattivato».**
    #[test]
    fn non_leggibile_non_significa_disattivato() {
        let messaggio = NotificationState::Undeterminable { code: 7 }.operator_message();
        assert!(
            messaggio.contains("NON significa"),
            "un sistema che non risponde e uno che dice di no sono due cose \
             diverse: «{messaggio}»"
        );
    }

    /// **`Enabled` non promette che il riquadro sia comparso.**
    ///
    /// L'Assistente notifiche, l'ora di silenzio e la soppressione dei gruppi
    /// ravvicinati agiscono dopo, e il sistema non li dichiara qui. Un
    /// messaggio che promettesse di piu' farebbe cercare il difetto nel posto
    /// sbagliato.
    #[test]
    fn attivo_non_promette_che_il_riquadro_sia_comparso() {
        let messaggio = NotificationState::Enabled.operator_message();
        assert!(
            messaggio.contains("non garantisce"),
            "il messaggio promette piu' di quanto Windows dica: «{messaggio}»"
        );
    }

    /// Lo scheletro dichiara **esattamente due** righe di testo.
    ///
    /// Il numero non e' decorativo: `toast_document` vi inserisce titolo e
    /// corpo per posizione. Se lo scheletro ne dichiarasse una sola, il corpo
    /// sparirebbe **in silenzio** — il ciclo esce dal `break` senza errore, ed
    /// e' il comportamento giusto per uno scheletro malformato ma pessimo per
    /// uno scheletro sbagliato.
    #[cfg(windows)]
    #[test]
    fn lo_scheletro_dichiara_due_righe_e_un_suono() {
        assert_eq!(
            TOAST_SKELETON.matches("<text>").count(),
            2,
            "titolo e corpo si inseriscono per posizione: le righe devono essere due"
        );
        assert!(
            TOAST_SKELETON.contains("ToastGeneric"),
            "il modello deve essere quello sostenuto, non un ToastTemplateType"
        );
        assert!(
            TOAST_SKELETON.contains("ms-winsoundevent:Notification.Default"),
            "il suono e' dichiarato apposta: se non suona, il difetto non e' \
             un'omissione nostra"
        );
    }

    /// **Il markup dentro un messaggio acquisito resta testo.**
    ///
    /// E' la garanzia per cui questo modulo non compone XML per
    /// concatenazione. Un frammento come `</text><actions>...` uscirebbe dal
    /// proprio nodo e aggiungerebbe pulsanti all'avviso: e' iniezione, con la
    /// stessa forma che avrebbe in una pagina web.
    ///
    /// La prova legge il documento **finito** e verifica due cose insieme: che
    /// non sia nata struttura nuova, e che il testo sia ancora tutto li'. Un
    /// avviso sicuro che ha perso per strada meta' del messaggio non serve a
    /// nessuno.
    #[cfg(windows)]
    #[test]
    fn il_markup_in_un_messaggio_acquisito_resta_testo() {
        let ostile = "</text></binding></visual><actions><action content=\"Premi\"/></actions>";

        let Ok(document) = toast_document("Fonte X", ostile) else {
            panic!("il documento dell'avviso deve potersi comporre");
        };

        // Nessun elemento `action` deve essere nato dal testo.
        let Ok(azioni) = document.GetElementsByTagName(&windows::core::HSTRING::from("action"))
        else {
            panic!("l'interrogazione del documento deve riuscire");
        };
        assert_eq!(
            azioni.Length().unwrap_or(u32::MAX),
            0,
            "il markup del messaggio e' diventato struttura: e' iniezione"
        );

        // E le righe restano due: nessuna e' stata chiusa dal testo.
        let Ok(righe) = document.GetElementsByTagName(&windows::core::HSTRING::from("text")) else {
            panic!("l'interrogazione del documento deve riuscire");
        };
        assert_eq!(righe.Length().unwrap_or(u32::MAX), 2);

        // Il testo ostile e' ancora leggibile per intero dentro il documento:
        // sicuro e mutilato sarebbe un altro difetto.
        let Ok(xml) = document.GetXml() else {
            panic!("il documento deve potersi rileggere");
        };
        let xml = xml.to_string();
        assert!(
            xml.contains("&lt;/text&gt;") || xml.contains("&lt;actions&gt;"),
            "il markup deve comparire ESCAPATO, cioe' trattato come dato: {xml}"
        );
        assert!(
            xml.contains("Premi"),
            "il testo non deve essere stato perso per strada"
        );
    }

    /// Titolo e corpo finiscono nell'ordine dichiarato.
    ///
    /// Invertirli metterebbe l'estratto del messaggio nella riga in grassetto
    /// e la fonte in quella piccola: nessun errore, e un avviso che dice le
    /// cose al contrario.
    #[cfg(windows)]
    #[test]
    fn il_titolo_precede_il_corpo() {
        let Ok(document) = toast_document("PRIMA", "SECONDA") else {
            panic!("il documento dell'avviso deve potersi comporre");
        };
        let Ok(xml) = document.GetXml() else {
            panic!("il documento deve potersi rileggere");
        };
        let xml = xml.to_string();

        let prima = xml.find("PRIMA").unwrap_or(usize::MAX);
        let seconda = xml.find("SECONDA").unwrap_or(0);
        assert!(
            prima < seconda,
            "titolo e corpo sono invertiti nel documento: {xml}"
        );
    }

    /// Un «a capo» non sopravvive nemmeno dentro il documento.
    ///
    /// `single_line` lo toglie, e questa prova verifica che la ripulitura sia
    /// applicata **sul percorso vero** e non soltanto quando la si chiama a
    /// mano: e' la differenza fra una funzione corretta e una funzione
    /// corretta che nessuno usa.
    #[cfg(windows)]
    #[test]
    fn la_ripulitura_e_applicata_sul_percorso_vero() {
        let Ok(document) = toast_document("Fonte", "prima\nseconda") else {
            panic!("il documento dell'avviso deve potersi comporre");
        };
        let Ok(xml) = document.GetXml() else {
            panic!("il documento deve potersi rileggere");
        };
        let xml = xml.to_string();

        assert!(
            xml.contains("prima seconda"),
            "l'a capo non e' stato appiattito sul percorso vero: {xml}"
        );
    }

    #[test]
    fn a_line_break_inside_an_acquired_message_cannot_push_the_rest_out_of_sight() {
        // Il riquadro è alto due righe. Un «a capo» scritto da chi ha
        // pubblicato il messaggio sposterebbe fuori vista tutto ciò che segue,
        // ed è il modo più semplice per far sparire da un avviso la parte che
        // conta.
        let flattened = single_line("prima riga\ndopo\r\nancora\tdopo");

        assert!(!flattened.contains('\n'));
        assert!(!flattened.contains('\r'));
        assert!(!flattened.contains('\t'));
        assert_eq!(flattened, "prima riga dopo  ancora dopo");
    }

    #[test]
    fn a_very_long_message_is_cut_and_declares_the_cut() {
        let long = "a".repeat(MAX_LINE_CHARS * 3);
        let cut = single_line(&long);

        // Il taglio si dichiara: un testo troncato in silenzio farebbe credere
        // completo un messaggio che non lo è.
        assert_eq!(cut.chars().count(), MAX_LINE_CHARS + 1);
        assert!(cut.ends_with('\u{2026}'));
    }

    #[test]
    fn a_message_that_fits_is_handed_over_unchanged() {
        // Il caso normale non deve subire alcuna trasformazione: un avviso che
        // riscrive il proprio testo direbbe qualcosa di diverso da ciò che il
        // motore ha deciso di dire.
        assert_eq!(
            single_line("Fonte X: termine trovato"),
            "Fonte X: termine trovato"
        );
    }
}
