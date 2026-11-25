//! Nome pubblico del prodotto e identificatori persistenti.
//!
//! # La distinzione che questo modulo esiste per tenere
//!
//! Il prodotto ha un **nome pubblico**, che si legge nella finestra e nei
//! documenti, e degli **identificatori persistenti**, che nessuno legge e da cui
//! dipendono dati già scritti sul disco delle postazioni.
//!
//! Cambiare il primo è una decisione di prodotto. Cambiare i secondi rende
//! irraggiungibile ciò che è già stato salvato: la cartella sotto
//! `%LOCALAPPDATA%` contiene la configurazione protetta con DPAPI, e un
//! rinominare la cartella equivale a cancellarla per chi la stava usando.
//!
//! Le due cose stanno qui accanto, con un test che verifica che gli
//! identificatori non siano cambiati, perché il modo più probabile di sbagliare
//! è rinominare tutto insieme durante un rebranding.
//!
//! Le scelte sono motivate in
//! `docs/adr/ADR-0011-PUBLIC-NAME-AND-IDENTIFIERS.md`.

/// Nome pubblico del prodotto.
pub const PRODUCT_NAME: &str = "NEXUM/97";

/// Sottotitolo che dice che cosa il prodotto fa.
///
/// Il nome da solo non lo dice, e un operatore che apre la finestra per la
/// prima volta deve poterlo capire senza chiedere.
pub const PRODUCT_SUBTITLE: &str = "Telegram Intelligence Monitor";

/// Descrizione breve, per l'intestazione e la schermata informativa.
pub const PRODUCT_DESCRIPTION: &str = "Monitoraggio autorizzato di fonti Telegram";

/// Formula di attribuzione del prodotto. **È l'unica.**
///
/// Vale ovunque: interfaccia, intestazioni dei rapporti, documentazione,
/// binari. Resta invariata dal rebranding — cambiare il nome del prodotto non
/// cambia chi lo ha ideato.
///
/// # Perché è una sola
///
/// Ne sono convissute quattro, nate una alla volta e ciascuna con la propria
/// buona ragione locale: una per l'interfaccia, una per la responsabilità
/// tecnica, una estesa per la documentazione, una compatta per gli spazi
/// stretti. Il risultato era che il prodotto diceva quattro cose diverse su
/// chi lo firma, a seconda di dove lo si leggeva, e chi aggiungeva una
/// superficie nuova doveva indovinare quale usare.
///
/// Una formula editoriale non è un dato che si declina per contesto: è una
/// dichiarazione, e ammette una forma sola. Il test
/// `the_attribution_is_the_only_one` esiste perché la quinta variante non
/// nasca nello stesso modo delle prime quattro. La decisione è in DEC-120.
pub const ATTRIBUTION: &str = "Ideazione e progettazione: Giuseppe LISI";

/// Editore, come Windows lo mostra nelle proprietà di file e in «App
/// installate».
///
/// **Non è la formula di attribuzione, e la distinzione è deliberata.** Windows
/// chiede qui un *nome di editore*: un campo di catalogo, che compare accanto
/// alla versione e alla dimensione, e che gli strumenti di sistema usano per
/// raggruppare e ordinare. Mettervi [`ATTRIBUTION`] significherebbe far
/// comparire la formula editoriale in un elenco di installazioni, cioè creare
/// la quinta variante nello stesso modo in cui erano nate le prime quattro
/// (DEC-120) — non riscrivendola, ma usandola dove non è una dichiarazione.
///
/// La formula resta unica e vive dove è una dichiarazione: la pagina
/// «Informazioni e licenze» e i rapporti esportati.
pub const PUBLISHER: &str = "Giuseppe LISI";

/// La riga di copyright dell'eseguibile (proprietà `LegalCopyright` di
/// Windows), identica alla seconda riga del `NOTICE` (INSTALLED-APP-E2E-01,
/// E2E01-24: la proprietà era vuota). Il `LICENSE` porta il testo ufficiale
/// della Apache 2.0, senza righe del titolare (ADR-0211).
///
/// Solo ASCII: lo script di risorse è letto nella tabella 1252, e un «©»
/// cambierebbe forma passando di lì.
pub const COPYRIGHT: &str = "Copyright (c) 2026 Giuseppe LISI. Licenza Apache 2.0.";

/// Nome della cartella dei dati sotto `%LOCALAPPDATA%`.
///
/// **Identificatore persistente: non si rinomina.** Vi risiede la
/// configurazione protetta con DPAPI; cambiarlo la renderebbe irraggiungibile
/// sui profili esistenti senza che nulla lo segnali, e l'operatore vedrebbe
/// un'applicazione che si comporta come al primo avvio.
pub const DATA_DIRECTORY: &str = "LISI Telegram Monitor";

/// Variabile d'ambiente da cui si legge l'API ID di Telegram.
///
/// **Identificatore persistente: non si rinomina.** È scritto nelle
/// configurazioni delle postazioni già predisposte.
pub const API_ID_VARIABLE: &str = "LISI_TELEGRAM_API_ID";

/// Variabile d'ambiente da cui si legge l'API hash di Telegram.
///
/// **Identificatore persistente: non si rinomina.**
pub const API_HASH_VARIABLE: &str = "LISI_TELEGRAM_API_HASH";

/// Titolo della finestra principale.
#[must_use]
pub fn window_title() -> String {
    format!("{PRODUCT_NAME} — {PRODUCT_SUBTITLE}")
}

/// Sorgente di questo modulo, letta a tempo di compilazione.
///
/// Serve al solo controllo che le formule di attribuzione restino una.
#[cfg(test)]
const SOURCE: &str = include_str!("branding.rs");

#[cfg(test)]
mod tests {
    use super::{
        API_HASH_VARIABLE, API_ID_VARIABLE, ATTRIBUTION, DATA_DIRECTORY, PRODUCT_DESCRIPTION,
        PRODUCT_NAME, PRODUCT_SUBTITLE, PUBLISHER, SOURCE, window_title,
    };

    #[test]
    fn the_constants_keep_the_shape_the_build_script_reads() {
        // `crates/lisi-app/build.rs` legge questi tre valori **dal sorgente**
        // per riempire le proprieta' del file dell'eseguibile: nome, editore e
        // descrizione. Li legge da qui invece di riscriverli perche' una
        // seconda copia del nome del prodotto e' esattamente il modo in cui
        // erano nate le quattro varianti dell'attribuzione (DEC-120).
        //
        // Il prezzo e' che la **forma** della riga diventa un contratto. Se un
        // giorno una di queste costanti venisse spezzata su piu' righe, o
        // costruita con `concat!`, lo script non la troverebbe piu' e le
        // proprieta' del file sparirebbero **in silenzio**: l'eseguibile
        // continuerebbe a compilare e a funzionare, e nessuno collegherebbe la
        // scheda «Dettagli» vuota a una riformattazione di questo file.
        for name in ["PRODUCT_NAME", "PRODUCT_DESCRIPTION", "PUBLISHER"] {
            let needle = format!("pub const {name}: &str = \"");
            assert!(
                SOURCE.contains(&needle),
                "{name} non ha piu' la forma che build.rs sa leggere: \
                 le proprieta' del file dell'eseguibile sparirebbero in silenzio"
            );
        }
    }

    /// **La riga di copyright è quella del NOTICE** (E2E01-24, ADR-0211), e lo
    /// script di risorse la può portare: solo ASCII, senza virgolette.
    #[test]
    fn la_riga_di_copyright_e_quella_della_licenza() {
        const NOTICE: &str = include_str!("../../../NOTICE");
        assert!(
            NOTICE.lines().any(|riga| riga.trim() == super::COPYRIGHT),
            "la riga deve comparire identica nel NOTICE"
        );
        assert!(NOTICE.contains("Ideazione e progettazione: Giuseppe LISI"));
        assert!(super::COPYRIGHT.is_ascii());
        assert!(!super::COPYRIGHT.contains('"'));
    }

    #[test]
    fn the_publisher_is_not_the_attribution_formula() {
        // L'editore e' un campo di catalogo che Windows mostra accanto alla
        // versione; la formula e' una dichiarazione. Farli coincidere
        // creerebbe la quinta variante nello stesso modo in cui erano nate le
        // prime quattro: non riscrivendola, ma usandola dove non e' una
        // dichiarazione.
        assert_ne!(PUBLISHER, ATTRIBUTION);
        assert!(!ATTRIBUTION.contains(PUBLISHER) || ATTRIBUTION != PUBLISHER);
        assert!(
            !PUBLISHER.contains("Ideazione"),
            "l'editore non deve portare la formula di attribuzione"
        );
    }

    #[test]
    fn the_persistent_identifiers_have_not_been_renamed() {
        // Il modo piu' probabile di sbagliare un rebranding e' rinominare tutto
        // insieme. Questi tre valori non sono testo mostrato: sono il percorso
        // di dati gia' scritti e le variabili gia' configurate sulle
        // postazioni. Se questo test fallisce, la modifica va annullata, non
        // il test aggiornato.
        assert_eq!(DATA_DIRECTORY, "LISI Telegram Monitor");
        assert_eq!(API_ID_VARIABLE, "LISI_TELEGRAM_API_ID");
        assert_eq!(API_HASH_VARIABLE, "LISI_TELEGRAM_API_HASH");
    }

    #[test]
    fn the_public_name_is_separate_from_the_data_directory() {
        // Se coincidessero, il prossimo cambio di nome trascinerebbe con se'
        // la cartella dei dati.
        assert_ne!(PRODUCT_NAME, DATA_DIRECTORY);
    }

    #[test]
    fn the_window_title_says_both_the_name_and_what_the_product_does() {
        let title = window_title();
        assert!(title.contains(PRODUCT_NAME));
        assert!(title.contains(PRODUCT_SUBTITLE));
    }

    #[test]
    fn every_public_text_is_present_and_names_the_author() {
        for text in [PRODUCT_NAME, PRODUCT_SUBTITLE, PRODUCT_DESCRIPTION] {
            assert!(!text.trim().is_empty());
        }
        assert!(ATTRIBUTION.contains("Giuseppe LISI"));
    }

    #[test]
    fn the_attribution_shown_to_the_operator_is_the_prescribed_one() {
        // Il rebranding cambia il nome del prodotto, non chi lo ha ideato.
        // Se questo test fallisce, la modifica va annullata: la formula e'
        // prescritta dalle istruzioni permanenti del progetto.
        assert_eq!(ATTRIBUTION, "Ideazione e progettazione: Giuseppe LISI");
    }

    #[test]
    fn the_attribution_is_the_only_one() {
        // Le formule erano quattro, nate una alla volta e ciascuna con la
        // propria buona ragione locale: il prodotto finiva per dire quattro
        // cose diverse su chi lo firma a seconda di dove lo si leggeva.
        //
        // Questo controllo fallisce quando ne compare una quinta. Se serve
        // davvero una formula in piu', la domanda da porsi prima di aggiornare
        // il test e' perche' l'unica non basti (DEC-120).
        // Il controllo contava le costanti che portano il **nome**. Da quando
        // l'eseguibile dichiara le proprie proprieta' di file, il nome compare
        // anche come *editore*, che Windows mostra in «App installate» accanto
        // alla versione. Contarlo come una quinta formula sarebbe stato uno
        // sbaglio nell'altro senso: un campo di catalogo non e' una
        // dichiarazione, e Windows in quel campo non accetta una frase.
        //
        // L'alternativa era mettere il nome del prodotto come editore. E' la
        // convenzione di molti programmi a un solo autore, ed e' stata scartata:
        // farebbe intendere che esista un'organizzazione chiamata NEXUM/97, e
        // questo prodotto ha una regola contro il dichiarare cio' che non e'.
        //
        // Il controllo ora conta le **dichiarazioni**, che restano una sola. Il
        // nome puo' comparire altrove solo come campo di catalogo, e la
        // distinzione la fa la forma: una dichiarazione ha un verbo e due punti,
        // un campo di catalogo e' il nome e basta.
        let declarations = SOURCE
            .lines()
            .filter(|line| line.trim_start().starts_with("pub const"))
            .filter(|line| line.contains("Ideazione e progettazione"))
            .count();

        assert_eq!(
            declarations, 1,
            "l'attribuzione del prodotto e' una sola formula, non una famiglia"
        );

        // E il campo di catalogo deve restare un campo di catalogo: se un
        // giorno diventasse una frase, sarebbe la quinta variante entrata dalla
        // porta di servizio.
        assert!(
            !PUBLISHER.contains(':'),
            "l'editore e' un nome, non una dichiarazione"
        );
        assert!(
            PUBLISHER.split_whitespace().count() <= 4,
            "l'editore e' un nome, non una frase"
        );

        // Ogni altra costante che porti il nome dovrebbe passare da qui. Se ne
        // compare una terza, la domanda da porsi prima di aggiornare il test e'
        // perche' le due non bastino.
        let carrying_the_name = SOURCE
            .lines()
            .filter(|line| line.trim_start().starts_with("pub const"))
            .filter(|line| line.contains("Giuseppe LISI"))
            .count();
        // IL TERZO PUNTO, MOTIVATO (INSTALLED-APP-E2E-01, E2E01-24): la riga di
        // copyright dell'eseguibile. Non è una formula: è la riga legale del
        // NOTICE, copiata identica, che Windows chiede in `LegalCopyright`, e
        // una prova la tiene uguale al NOTICE. Non porta «Ideazione».
        assert!(!super::COPYRIGHT.contains("Ideazione"));
        assert_eq!(
            carrying_the_name, 3,
            "il nome compare nella formula, nell'editore e nel copyright: un quarto punto va motivato"
        );
    }

    #[test]
    fn no_public_text_claims_an_institutional_authority() {
        // Il prodotto non e' emanazione di alcuna istituzione, e nulla di cio'
        // che l'operatore legge deve lasciarlo intendere.
        let all = format!("{PRODUCT_NAME} {PRODUCT_SUBTITLE} {PRODUCT_DESCRIPTION} {ATTRIBUTION}")
            .to_lowercase();

        for claim in [
            "polizia",
            "ministero",
            "stato",
            "ufficiale",
            "certificato",
            "autorizzato da",
        ] {
            assert!(
                !all.contains(claim),
                "il testo pubblico non deve contenere '{claim}'"
            );
        }
    }
}
