//! **Contesto acquisito** e **contesto corrente**: due concetti, e due tipi.
//!
//! # Che cosa questo modulo esiste per impedire
//!
//! Il congelamento lo scrive in una riga: «lo stato remoto corrente **non
//! sostituisce mai in silenzio** la prova storica».
//!
//! Le milestone precedenti hanno costruito la separazione dove si vede:
//! `AnchorMessage` viene dall'archivio e `ObservedMessage` da Telegram, senza
//! alcuna conversione fra loro (CTX-02); la prova sta in un riquadro suo e in
//! cima (CTX-03). Ma finché nessuno **confrontava** i due testi, la separazione
//! non era mai messa alla prova.
//!
//! Confrontarli la mette alla prova nel punto più delicato: la relazione fra
//! due testi **dipende da quale sia il primo**.
//!
//! # La garanzia: i due testi non si possono scambiare
//!
//! [`crate::model::content_history::VersionChange::between`] è sensibile
//! all'ordine, e deve esserlo: se il secondo testo comincia con il primo, il
//! testo è stato **aggiunto in coda**; se il primo comincia con il secondo, è
//! stato **accorciato**.
//!
//! Scambiare i due argomenti non produce un errore. Produce una frase che si
//! legge benissimo e dice **il contrario**: «la parte finale non c'è più» dove
//! qualcuno aveva aggiunto del testo. In un archivio che finisce in un
//! fascicolo, è la peggior specie di difetto — plausibile, silenzioso, e
//! sbagliato.
//!
//! Per questo [`AcquiredText`] e [`CurrentText`] sono **due tipi**. Non si
//! possono scambiare: il progetto non compilerebbe. È la stessa forma di
//! garanzia di CTX-04, dove il testo di una risposta non entra in un tipo
//! `Copy`.
//!
//! # La seconda garanzia: il confronto non restituisce un testo
//!
//! [`ContextComparison`] non ha alcun accessore che restituisca un corpo. Non
//! si può chiedergli «che cosa dice questo messaggio», perché quella domanda ha
//! **due** risposte e il punto di questo modulo è che siano due.
//!
//! Chi deve mostrare la prova la prende dall'archivio; chi deve mostrare lo
//! stato corrente lo prende dal contorno. Il confronto dice soltanto **in che
//! relazione stanno**.
//!
//! # «Differisce» non è «è stato modificato»
//!
//! Sono due affermazioni diverse, e il prodotto non deve confonderle.
//!
//! Che Telegram **dichiari** una modifica è un fatto che Telegram espone
//! (CTX-04 lo legge). Che i due testi **differiscano** è un fatto che si
//! osserva qui. Possono darsi separatamente:
//!
//! - i testi differiscono e Telegram dichiara una modifica: le due cose
//!   concordano, e si dice così;
//! - i testi differiscono e Telegram **non** dichiara nulla: si dice che
//!   differiscono, e si elencano le ragioni possibili senza sceglierne una.
//!   **Non significa che qualcuno abbia alterato qualcosa**, e il modo di non
//!   farlo intendere è non dirlo;
//! - i testi coincidono: lo si dice, perché «non è stato confrontato» e «è
//!   stato confrontato e coincide» sono due esiti diversi (ADR-0053).
//!
//! # Che cosa questo modulo NON fa
//!
//! **Non conserva nulla.** Un confronto è un'osservazione fatta adesso, e
//! rifarlo domani può dare un altro esito. Fotografarlo è un gesto esplicito,
//! ed è CTX-06.
//!
//! **Non introduce una seconda nozione di differenza.** Quella esatta esiste
//! già da CTX-01 (ADR-0051) e si riusa qui identica: due nozioni divergono, e
//! la prima volta che lo fanno nessuno se ne accorge.

use crate::model::content_history::VersionChange;
use crate::time::Timestamp;

/// Il testo **acquisito**: quello che l'archivio conserva.
///
/// # Perché è un tipo e non una stringa
///
/// Perché la relazione fra due testi dipende da quale sia il primo, e passarli
/// nell'ordine sbagliato non produce un errore: produce una frase che dice il
/// contrario. Due tipi rendono lo scambio **impossibile da compilare**.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AcquiredText<'a>(&'a str);

impl<'a> AcquiredText<'a> {
    /// Il testo come l'archivio lo conserva.
    ///
    /// Il nome del costruttore dice **da dove viene**: è l'unica cosa che
    /// distingue una prova da uno stato, e in un'espressione lunga è ciò che
    /// chi rilegge vede.
    #[must_use]
    pub const fn from_the_archive(body: &'a str) -> Self {
        Self(body)
    }
}

/// Il testo **corrente**: quello che Telegram mostra adesso.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CurrentText<'a>(&'a str);

impl<'a> CurrentText<'a> {
    /// Il testo come si legge adesso su Telegram.
    #[must_use]
    pub const fn read_now(body: &'a str) -> Self {
        Self(body)
    }
}

/// Se i due testi differiscano, e se Telegram lo dichiari.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Divergence {
    /// I due testi coincidono.
    None,
    /// Differiscono, e Telegram dichiara una modifica.
    Declared {
        /// Quando Telegram dichiara che il messaggio è stato modificato.
        at: Timestamp,
    },
    /// Differiscono, e Telegram non dichiara alcuna modifica.
    ///
    /// **Non è un'accusa.** È un'osservazione, e le ragioni possibili sono più
    /// d'una: sceglierne una sarebbe inventare.
    Undeclared,
}

impl Divergence {
    /// Se i due testi differiscono, comunque sia.
    #[must_use]
    pub const fn texts_differ(self) -> bool {
        !matches!(self, Self::None)
    }
}

/// In che relazione stanno il contesto acquisito e quello corrente.
///
/// # Perché non restituisce un testo
///
/// Perché «che cosa dice questo messaggio» ha **due** risposte, e il punto di
/// questo tipo è che siano due. Chi mostra la prova la prende dall'archivio;
/// chi mostra lo stato corrente lo prende dal contorno. Se questo tipo
/// restituisse un corpo, prima o poi una schermata userebbe quello, e la
/// sostituzione che il congelamento vieta avverrebbe da sé.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ContextComparison {
    /// La relazione esatta fra i due testi, nella nozione di ADR-0051.
    change: VersionChange,
    /// Se differiscano, e se Telegram lo dichiari.
    divergence: Divergence,
    /// Quando la prova è stata acquisita.
    acquired_at: Timestamp,
    /// Quando lo stato corrente è stato letto.
    observed_at: Timestamp,
}

impl ContextComparison {
    /// Confronta la prova con ciò che Telegram mostra adesso.
    ///
    /// # Perché i parametri sono tipi e non stringhe
    ///
    /// Perché [`VersionChange::between`] è sensibile all'ordine: scambiare i due
    /// testi trasforma «è stato aggiunto del testo in coda» in «la parte finale
    /// non c'è più». Nessuna prova può sorvegliare tutti i punti di chiamata
    /// futuri; due tipi sì.
    ///
    /// `declared_edit` è ciò che **Telegram dichiara** (CTX-04), e non ciò che
    /// si osserva qui: le due cose restano distinte anche nel risultato.
    #[must_use]
    pub fn between(
        acquired: AcquiredText<'_>,
        current: CurrentText<'_>,
        acquired_at: Timestamp,
        observed_at: Timestamp,
        declared_edit: Option<Timestamp>,
    ) -> Self {
        // LA NOZIONE DI DIFFERENZA E' UNA SOLA, ed e' quella di ADR-0051.
        //
        // Costruirne una seconda qui — anche solo un `==` scritto a mano —
        // significherebbe che due punti del prodotto rispondono alla stessa
        // domanda, e che il giorno in cui uno dei due cambia nessuno se ne
        // accorge.
        let change = VersionChange::between(acquired.0, current.0);

        let divergence = match (change, declared_edit) {
            (VersionChange::Identical, _) => Divergence::None,
            (_, Some(at)) => Divergence::Declared { at },
            (_, None) => Divergence::Undeclared,
        };

        Self {
            change,
            divergence,
            acquired_at,
            observed_at,
        }
    }

    /// La relazione esatta fra i due testi.
    #[must_use]
    pub const fn change(self) -> VersionChange {
        self.change
    }

    /// Se differiscano, e se Telegram lo dichiari.
    #[must_use]
    pub const fn divergence(self) -> Divergence {
        self.divergence
    }

    /// L'esito in tre parole, per una riga di intestazione.
    ///
    /// # Perché un'etichetta oltre alla frase
    ///
    /// Perché la frase dice tutto e va letta; l'etichetta si vede. Chi scorre
    /// un contesto deve accorgersi **a colpo d'occhio** che i due testi non
    /// coincidono, e poi leggere perché.
    ///
    /// # Perché non basta un colore
    ///
    /// Perché un colore da solo non è leggibile da tutti, e perché il colore
    /// non si stampa in un registro. L'etichetta è testo, e il testo arriva
    /// ovunque arrivi il resto.
    #[must_use]
    pub const fn as_label(self) -> &'static str {
        match self.divergence {
            Divergence::None => "I TESTI COINCIDONO",
            Divergence::Declared { .. } => "I TESTI NON COINCIDONO \u{2014} MODIFICA DICHIARATA",
            Divergence::Undeclared => "I TESTI NON COINCIDONO \u{2014} NESSUNA MODIFICA DICHIARATA",
        }
    }

    /// Che cosa si è osservato, detto a chi legge.
    ///
    /// # Perché la frase non dice mai che qualcuno abbia alterato qualcosa
    ///
    /// Perché non lo si sa. Due testi che differiscono senza una modifica
    /// dichiarata possono essere il risultato di una modifica anteriore a ciò
    /// che Telegram espone, di un'acquisizione che aveva letto una forma
    /// diversa dello stesso messaggio, o di un messaggio che oggi occupa quel
    /// posto e non è quello acquisito.
    ///
    /// Elencarle senza sceglierne una è l'unica cosa vera che si possa dire.
    #[must_use]
    pub fn as_sentence(self) -> String {
        let quando = format!(
            "La prova \u{e8} stata acquisita il {}; lo stato corrente \u{e8} stato letto il {}.",
            self.acquired_at.to_readable_utc(),
            self.observed_at.to_readable_utc()
        );

        match self.divergence {
            Divergence::None => format!(
                "Il testo dell'archivio e quello che Telegram mostra adesso coincidono. \
                 {quando}"
            ),
            Divergence::Declared { at } => format!(
                "Il testo dell'archivio e quello che Telegram mostra adesso non coincidono, e \
                 Telegram dichiara una modifica il {}. {} Resta prova il testo dell'archivio: \
                 \u{e8} quello su cui l'analisi \u{e8} stata fatta. L'analisi non viene rifatta \
                 su una modifica. {quando}",
                at.to_readable_utc(),
                self.change.as_sentence()
            ),
            Divergence::Undeclared => format!(
                "Il testo dell'archivio e quello che Telegram mostra adesso non coincidono, e \
                 Telegram non dichiara alcuna modifica. Non significa che qualcuno abbia \
                 alterato qualcosa. La modifica pu\u{f2} essere anteriore a ci\u{f2} che Telegram \
                 mostra. L'acquisizione pu\u{f2} aver letto una forma diversa dello stesso \
                 messaggio. Oppure il messaggio che oggi occupa quel posto pu\u{f2} non essere \
                 quello acquisito. Ci\u{f2} che si \u{e8} osservato \u{e8} che i due testi differiscono. \
                 {} Resta prova il testo dell'archivio. {quando}",
                self.change.as_sentence()
            ),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{AcquiredText, ContextComparison, CurrentText, Divergence};
    use crate::model::content_history::VersionChange;
    use crate::time::Timestamp;

    /// Questo modulo, per le guardie strutturali.
    const THIS_MODULE: &str = include_str!("context_state.rs");

    const ACQUISITO: i64 = 1_700_000_000_000;
    const OSSERVATO: i64 = 1_700_009_000_000;

    fn istante(millis: i64) -> Timestamp {
        Timestamp::from_millis(millis)
    }

    fn confronta(archivio: &str, adesso: &str, modifica: Option<i64>) -> ContextComparison {
        ContextComparison::between(
            AcquiredText::from_the_archive(archivio),
            CurrentText::read_now(adesso),
            istante(ACQUISITO),
            istante(OSSERVATO),
            modifica.map(istante),
        )
    }

    /// **Due testi uguali coincidono, e lo si dice.**
    ///
    /// «Non è stato confrontato» e «è stato confrontato e coincide» sono due
    /// esiti diversi (ADR-0053).
    #[test]
    fn due_testi_uguali_coincidono() {
        let confronto = confronta("il testo", "il testo", None);
        assert_eq!(confronto.divergence(), Divergence::None);
        assert!(!confronto.divergence().texts_differ());
        assert!(confronto.as_sentence().contains("coincidono"));
    }

    /// **Un testo aggiunto in coda si dice «aggiunto», non «accorciato».**
    ///
    /// # Il difetto che questa prova impedisce
    ///
    /// Lo scambio dei due argomenti. È l'unico modo in cui questa funzione può
    /// mentire, e mente in modo plausibile: la frase si legge benissimo e dice
    /// il contrario di ciò che è successo.
    ///
    /// Il tipo lo rende impossibile da scrivere; questa prova dice che
    /// l'orientamento è quello giusto, cioè che i due tipi non sono stati
    /// scambiati **una volta sola**, qui dentro.
    #[test]
    fn un_testo_aggiunto_non_diventa_un_testo_accorciato() {
        let confronto = confronta("inizio", "inizio e seguito", None);
        assert_eq!(confronto.change(), VersionChange::Appended);
        assert!(
            confronto
                .as_sentence()
                .contains("ne \u{e8} stato aggiunto altro in coda"),
            "{}",
            confronto.as_sentence()
        );

        // E il caso opposto, che e' quello che uno scambio produrrebbe.
        let opposto = confronta("inizio e seguito", "inizio", None);
        assert_eq!(opposto.change(), VersionChange::Truncated);
    }

    /// **Una modifica dichiarata si distingue da una differenza osservata.**
    #[test]
    fn una_modifica_dichiarata_si_distingue_da_una_differenza_osservata() {
        let dichiarata = confronta("prima", "dopo", Some(ACQUISITO + 60_000));
        assert!(matches!(
            dichiarata.divergence(),
            Divergence::Declared { .. }
        ));

        let osservata = confronta("prima", "dopo", None);
        assert_eq!(osservata.divergence(), Divergence::Undeclared);
    }

    /// **Una differenza non dichiarata non accusa nessuno.**
    ///
    /// # Il difetto che questa prova impedisce
    ///
    /// Che una riga di questo prodotto insinui un'alterazione. Due testi che
    /// differiscono senza una modifica dichiarata hanno più spiegazioni
    /// possibili, e sceglierne una sarebbe inventare — in un documento che
    /// qualcuno firma.
    #[test]
    fn una_differenza_non_dichiarata_non_accusa_nessuno() {
        let frase = confronta("prima", "dopo", None).as_sentence();
        assert!(
            frase.contains("Non significa che qualcuno abbia alterato qualcosa"),
            "{frase}"
        );
        assert!(
            frase.contains("Ci\u{f2} che si \u{e8} osservato \u{e8} che i due testi differiscono"),
            "{frase}"
        );
        for parola in [
            "manomes",
            "alterato da",
            "falsific",
            "occultat",
            "nascost",
            "sospett",
            "colpevol",
        ] {
            assert!(
                !frase.to_lowercase().contains(parola),
                "la frase scrive «{parola}»: e' un'osservazione, non un'accusa \u{2014} {frase}"
            );
        }
    }

    /// **La prova resta la prova, in ogni esito in cui i testi differiscono.**
    #[test]
    fn in_ogni_divergenza_la_prova_resta_quella_dell_archivio() {
        for modifica in [None, Some(ACQUISITO + 60_000)] {
            let frase = confronta("prima", "dopo", modifica).as_sentence();
            assert!(
                frase.contains("Resta prova il testo dell'archivio"),
                "{frase}"
            );
        }
    }

    /// **La nozione di differenza è una sola.**
    ///
    /// # Perché una guardia testuale, qui
    ///
    /// Perché la seconda nozione non nasce come una funzione nuova: nasce come
    /// un `==` scritto a mano, o un `starts_with`, dentro una funzione che
    /// sembra fare altro. CTX-01 ha già una relazione esatta e versionata
    /// (ADR-0051), e questa milestone la **riusa**.
    #[test]
    fn la_nozione_di_differenza_e_una_sola() {
        let Some((produzione, _)) = THIS_MODULE.split_once("#[cfg(test)]\nmod tests {") else {
            panic!("il modulo deve avere un blocco di prove riconoscibile");
        };
        assert!(
            produzione.contains("VersionChange::between(acquired.0, current.0)"),
            "il confronto deve riusare la relazione esatta di ADR-0051"
        );
        for artigianale in [
            "acquired.0 ==",
            "current.0 ==",
            "acquired.0 !=",
            "current.0 !=",
            ".starts_with(",
            ".contains(",
            "levenshtein",
            "similarity",
        ] {
            assert!(
                !produzione.contains(artigianale),
                "il modulo confronta i testi con «{artigianale}»: sarebbe una seconda nozione \
                 di differenza accanto a quella di ADR-0051, e due nozioni divergono"
            );
        }
    }

    /// **Il confronto non restituisce alcun testo.**
    ///
    /// # Il difetto che questa prova impedisce
    ///
    /// Che una schermata chieda al confronto «che cosa dice questo messaggio».
    /// Quella domanda ha due risposte, e un tipo che ne desse una sola
    /// deciderebbe quale — cioè farebbe esattamente la sostituzione che il
    /// congelamento vieta.
    #[test]
    fn il_confronto_non_restituisce_alcun_testo() {
        let Some((produzione, _)) = THIS_MODULE.split_once("#[cfg(test)]\nmod tests {") else {
            panic!("il modulo deve avere un blocco di prove riconoscibile");
        };
        let Some(inizio) = produzione.find("impl ContextComparison {") else {
            panic!("l'implementazione deve esistere");
        };
        let Some(fine) = produzione[inizio..].find("\n}\n") else {
            panic!("l'implementazione deve chiudersi");
        };

        for firma in produzione[inizio..inizio + fine]
            .lines()
            .map(str::trim)
            .filter(|riga| riga.starts_with("pub fn ") || riga.starts_with("pub const fn "))
        {
            // `&'static str` e' ammesso, e la distinzione non e' formale: una
            // stringa `'static` e' un letterale di questo modulo — un'etichetta,
            // una frase — e NON puo' essere uno dei due corpi confrontati, che
            // arrivano con la durata del chiamante. Un prestito con qualunque
            // altra durata, invece, potrebbe esserlo.
            let restituisce_un_prestito_dal_chiamante = firma.contains("-> &str")
                || (firma.contains("-> &'") && !firma.contains("-> &'static str"))
                || firma.contains("Option<&str>")
                || firma.contains("AcquiredText")
                || firma.contains("CurrentText");
            assert!(
                !restituisce_un_prestito_dal_chiamante,
                "il confronto dichiara «{firma}»: restituirebbe un testo, e chi lo usa userebbe \
                 quello invece della prova"
            );
        }
    }

    /// **I due tipi non sono scambiabili, e lo impone il compilatore.**
    ///
    /// # Perché questa prova non può fallire in esecuzione
    ///
    /// Perché non deve. Se [`AcquiredText`] e [`CurrentText`] diventassero lo
    /// stesso tipo — o due alias della stessa cosa — questa riga
    /// **non compilerebbe più** con l'errore che ci si aspetta. La prova serve
    /// a dire, a chi legge, che il vincolo è del compilatore.
    #[test]
    fn i_due_testi_non_sono_lo_stesso_tipo() {
        let archivio = AcquiredText::from_the_archive("x");
        let adesso = CurrentText::read_now("x");
        // Se fossero lo stesso tipo, questo confronto compilerebbe. Non essendolo,
        // il solo modo di metterli in relazione e' passare per `between`, che li
        // vuole nell'ordine giusto e in nessun altro.
        let confronto = ContextComparison::between(
            archivio,
            adesso,
            istante(ACQUISITO),
            istante(OSSERVATO),
            None,
        );
        assert_eq!(confronto.divergence(), Divergence::None);
    }

    /// **Un testo acquisito vuoto non produce una relazione senza senso.**
    ///
    /// È il caso dei media senza didascalia: il corpo è vuoto, e Telegram oggi
    /// può mostrare una didascalia aggiunta dopo.
    #[test]
    fn un_testo_acquisito_vuoto_si_comporta_come_ci_si_aspetta() {
        let confronto = confronta("", "una didascalia aggiunta", None);
        assert_eq!(confronto.change(), VersionChange::Appended);
        assert_eq!(confronto.divergence(), Divergence::Undeclared);
    }

    /// **L'etichetta dice l'esito senza bisogno del colore.**
    ///
    /// Un colore non è leggibile da tutti, e non si stampa in un registro.
    #[test]
    fn l_etichetta_dice_l_esito_a_parole() {
        assert_eq!(confronta("x", "x", None).as_label(), "I TESTI COINCIDONO");
        assert!(
            confronta("a", "b", None)
                .as_label()
                .contains("NESSUNA MODIFICA DICHIARATA")
        );
        assert!(
            confronta("a", "b", Some(ACQUISITO + 1))
                .as_label()
                .contains("MODIFICA DICHIARATA")
        );
        // E l'etichetta non e' mai vuota: uno spazio bianco al posto dell'esito
        // si leggerebbe come «non c'e' nulla da dire».
        for etichetta in [
            confronta("x", "x", None).as_label(),
            confronta("a", "b", None).as_label(),
            confronta("a", "b", Some(ACQUISITO + 1)).as_label(),
        ] {
            assert!(!etichetta.trim().is_empty());
        }
    }

    /// **Due testi vuoti coincidono.**
    #[test]
    fn due_testi_vuoti_coincidono() {
        assert_eq!(confronta("", "", None).divergence(), Divergence::None);
    }

    /// **Una modifica dichiarata su testi identici non è una divergenza.**
    ///
    /// Telegram segnala una modifica anche quando cambia qualcosa che non è il
    /// testo: un allegato, un'anteprima, la formattazione. Dire «i testi non
    /// coincidono» in quel caso sarebbe falso.
    #[test]
    fn una_modifica_su_qualcosa_che_non_e_testo_non_e_una_divergenza() {
        let confronto = confronta("uguale", "uguale", Some(ACQUISITO + 60_000));
        assert_eq!(confronto.divergence(), Divergence::None);
        assert_eq!(confronto.change(), VersionChange::Identical);
    }
}
