//! Il contrasto della palette, misurato dal cancello.
//!
//! # Perché questo modulo esiste
//!
//! La misura c'era già, e si chiamava `scripts/verify-contrast.ps1`. Leggeva i
//! token veri, calcolava i rapporti secondo la norma, e nessun cancello la
//! eseguiva: non `scripts/quality.ps1`, non `cargo test`, niente.
//!
//! `docs/ux/RETRO_DESIGN_SYSTEM.md` impone la riverifica **a ogni modifica
//! della palette**, e l'unico modo di rispettarla era **ricordarsene**.
//!
//! **Un controllo che nessun cancello esegue non è un controllo automatico: è
//! un promemoria**, e un promemoria vale finché qualcuno se lo ricorda — cioè
//! finché non serve (ADR-0116).
//!
//! # Che cosa è cambiato, e che cosa no
//!
//! Il calcolo, le coppie e le loro classificazioni sono quelli dello script, e
//! le ragioni scritte accanto a ciascuna sono state portate qui insieme ai
//! numeri: sono la parte che serve a chi un domani vorrà cambiare una riga.
//!
//! Lo script resta come porta d'ingresso per chi lavora al progetto grafico,
//! ma **non misura più**: chiama questa prova. Due misure della stessa cosa
//! divergerebbero, ciascuna coerente con sé stessa (ADR-0114).
//!
//! # Che cosa questa prova non dice
//!
//! Che l'interfaccia si legga. Dice che due colori dichiarati stanno alla
//! distanza che la norma chiede; non sa quale colore finisca davvero sopra
//! quale sfondo a schermo. Quello lo dice un occhio, e resta da fare.

/// Il sorgente dei token, letto a tempo di compilazione.
#[cfg(test)]
const TOKENS: &str = include_str!("../ui/tokens.slint");

#[cfg(test)]
mod tests {
    use super::TOKENS;

    /// A che cosa serve una coppia, e quindi quale soglia la giudica.
    ///
    /// - `Testo` porta parole: **4,5:1**.
    /// - `Interfaccia` identifica un componente o uno stato — la cornice di un
    ///   pannello, il bordo di un riquadro incassato, l'anello di fuoco: **3:1**.
    /// - `Decorazione` **non porta informazione**: un separatore fra righe che
    ///   si distinguono già per il proprio fondo. Nessuna soglia.
    ///
    /// Le prime due sono le soglie della norma, applicate a ciò cui la norma le
    /// applica. La terza **non è una scappatoia**: è la constatazione che
    /// togliendo un separatore decorativo non si perde alcuna informazione, e
    /// va usata **solo** quando questo è vero. Un bordo che sia l'unico confine
    /// di un riquadro è `Interfaccia`, non `Decorazione`.
    #[derive(Clone, Copy, PartialEq, Eq)]
    enum Genere {
        Testo,
        Interfaccia,
        Decorazione,
    }

    impl Genere {
        /// La soglia, o nessuna.
        const fn soglia(self) -> Option<f64> {
            match self {
                Self::Testo => Some(4.5),
                Self::Interfaccia => Some(3.0),
                Self::Decorazione => None,
            }
        }

        const fn nome(self) -> &'static str {
            match self {
                Self::Testo => "testo",
                Self::Interfaccia => "interfaccia",
                Self::Decorazione => "decorazione",
            }
        }
    }

    /// Le coppie misurate, con la classificazione di ciascuna.
    ///
    /// # Le righe che meritano una spiegazione
    ///
    /// **I tre pesi di linea** (`line-hairline`, `line-divider`,
    /// `line-strong`). `line-divider` è il bordo dei pannelli e il righello
    /// degli elenchi, e vale circa 1,2 contro `panel`: è la **regressione
    /// dichiarata** di DEC-133, adottata su decisione dell'ufficio perché è ciò
    /// che il riferimento prescrive. Resta `Decorazione` perché **raggruppa e
    /// non identifica**: dentro un pannello l'informazione è il contenuto, non
    /// il suo bordo. Ciò che deve essere identificabile continua a non
    /// affidarsi a questa linea: il bordo di un comando è `frame-dim`.
    ///
    /// **La rampa dei livelli** (`level-0` … `level-4`) è misurata come **non
    /// testuale** perché colora **aree e mai parole**: il binario di livello da
    /// 4px e il bordo della targhetta. Il nome scritto — «Livello 4 -
    /// prioritario» — sta dentro la targhetta in colore di testo, quindi il
    /// livello non dipende mai dal colore soltanto. **La riclassificazione non
    /// è un'affermazione libera**: la tiene
    /// `accessibility::tests::a_level_colour_never_paints_text`, che fallisce
    /// se una riga assegna `color:` con un colore della rampa. Senza quel
    /// controllo questa riga sarebbe barare: `level-4` vale 4,43, e sotto la
    /// soglia del testo ci sta (DEC-137).
    ///
    /// **I due toni dei riquadri** (`panel-raised`, `selected` contro `panel`)
    /// valgono quasi nulla — 1,13 e 1,48 — e sono `Decorazione` perché
    /// raggruppano: dentro un contatore l'informazione è la cifra, dentro uno
    /// stato vuoto è il testo. La misura di queste due coppie è proprio ciò che
    /// ha imposto al bordo dei comandi di essere `frame-dim`, e resta qui
    /// perché chi cambiasse i toni se ne accorga.
    const COPPIE: &[(&str, &str, Genere)] = &[
        ("text", "void", Genere::Testo),
        ("text", "panel", Genere::Testo),
        ("text", "panel-raised", Genere::Testo),
        ("text", "panel-inset", Genere::Testo),
        ("text", "selected", Genere::Testo),
        ("text-muted", "panel", Genere::Testo),
        ("text-muted", "panel-raised", Genere::Testo),
        ("text-muted", "panel-inset", Genere::Testo),
        ("cyan", "panel", Genere::Testo),
        ("cyan", "panel-inset", Genere::Testo),
        ("azure", "panel", Genere::Testo),
        ("green", "panel", Genere::Testo),
        ("green", "success-surface", Genere::Testo),
        ("amber", "panel", Genere::Testo),
        ("amber", "warning-surface", Genere::Testo),
        ("amber", "panel-inset", Genere::Testo),
        ("coral", "panel", Genere::Testo),
        ("coral", "danger-surface", Genere::Testo),
        ("text", "info-surface", Genere::Testo),
        ("text", "accent-surface", Genere::Testo),
        ("text", "chrome", Genere::Testo),
        ("text-muted", "chrome", Genere::Testo),
        ("focus", "panel", Genere::Interfaccia),
        ("frame", "panel", Genere::Interfaccia),
        ("frame", "void", Genere::Interfaccia),
        ("frame-dim", "panel", Genere::Interfaccia),
        ("frame-dim", "panel-inset", Genere::Interfaccia),
        ("text-disabled", "panel", Genere::Interfaccia),
        ("level-0", "panel", Genere::Interfaccia),
        ("level-1", "panel", Genere::Interfaccia),
        ("level-2", "panel", Genere::Interfaccia),
        ("level-3", "panel", Genere::Interfaccia),
        ("level-4", "panel", Genere::Interfaccia),
        ("line-hairline", "panel", Genere::Decorazione),
        ("line-divider", "panel", Genere::Decorazione),
        ("line-strong", "panel", Genere::Decorazione),
        ("panel-raised", "panel", Genere::Decorazione),
        ("selected", "panel", Genere::Decorazione),
    ];

    /// Deviazioni accettate, con il motivo scritto accanto.
    ///
    /// Una coppia elencata qui **viene misurata e stampata come tutte le
    /// altre**: non è un'esclusione, è un'accettazione con la ragione sotto gli
    /// occhi. Cambiare la soglia o riclassificare la coppia per farla passare
    /// sarebbe barare; registrarla qui no, e chi ne aggiunge una deve poterla
    /// motivare in `DECISION_LOG.md`.
    ///
    /// **Va tenuto vuoto finché si può.** Ha ospitato una voce sola,
    /// `level-4`/`panel`, per il tempo fra la scoperta e la decisione
    /// dell'ufficio — che non è stata «accettiamo 4,43 sul testo» ma
    /// **riservare la rampa alle aree**, cioè togliere la causa invece di
    /// registrare l'eccezione.
    const ACCETTATE: &[(&str, &str, &str)] = &[];

    /// I colori dichiarati, letti dal sorgente dei token e non da un elenco.
    ///
    /// Il nome ammette le cifre: la rampa si chiama `level-0` … `level-4`, e
    /// con un'espressione senza cifre **era invisibile**. Lo script non
    /// falliva: taceva, e cinque coppie non sono state misurate da nessuno fino
    /// a quando qualcuno non ha guardato (DEC-137).
    fn colori() -> std::collections::BTreeMap<String, String> {
        let mut trovati = std::collections::BTreeMap::new();

        for riga in TOKENS.lines() {
            let riga = riga.trim();
            let Some(resto) = riga.strip_prefix("out property <color> ") else {
                continue;
            };
            let Some((nome, valore)) = resto.split_once(':') else {
                continue;
            };
            // La riga puo' portare un commento in coda: «#93A4C4; // non rilevante».
            // Senza toglierlo il colore non si riconosce, e la coppia non si misura
            // senza che nulla fallisca.
            let valore = valore.split("//").next().unwrap_or(valore);
            let valore = valore.trim().trim_end_matches(';').trim();
            if valore.len() != 7 || !valore.starts_with('#') {
                continue;
            }
            if !valore[1..].chars().all(|c| c.is_ascii_hexdigit()) {
                continue;
            }
            trovati.insert(nome.trim().to_owned(), valore.to_owned());
        }

        assert!(
            trovati.len() >= 30,
            "dai token sono stati letti solo {} colori: se la forma della dichiarazione e' \
             cambiata questa guardia smette di misurare senza fallire, che e' il modo in cui \
             la rampa dei livelli e' rimasta invisibile per settimane",
            trovati.len()
        );
        trovati
    }

    /// La luminanza relativa, secondo la norma.
    fn luminanza(esadecimale: &str) -> f64 {
        let canale = |inizio: usize| -> f64 {
            let Ok(valore) = u8::from_str_radix(&esadecimale[inizio..inizio + 2], 16) else {
                panic!("«{esadecimale}» non e' un colore leggibile");
            };
            let normalizzato = f64::from(valore) / 255.0;
            if normalizzato <= 0.03928 {
                normalizzato / 12.92
            } else {
                ((normalizzato + 0.055) / 1.055).powf(2.4)
            }
        };

        0.2126 * canale(1) + 0.7152 * canale(3) + 0.0722 * canale(5)
    }

    /// Il rapporto di contrasto fra due colori, arrotondato ai centesimi come
    /// nella misura che questa prova sostituisce.
    fn rapporto(primo: &str, secondo: &str) -> f64 {
        let a = luminanza(primo);
        let b = luminanza(secondo);
        let alto = a.max(b);
        let basso = a.min(b);
        (((alto + 0.05) / (basso + 0.05)) * 100.0).round() / 100.0
    }

    /// **Il calcolo è quello della norma, e lo si prova su valori noti.**
    ///
    /// Una misura che nessuno verifica può essere sbagliata in modo coerente:
    /// darebbe numeri plausibili a tutte le coppie, e nessuna prova
    /// fallirebbe. Bianco su nero vale 21, un colore su sé stesso vale 1.
    #[test]
    fn il_calcolo_del_contrasto_e_quello_della_norma() {
        assert!(
            (rapporto("#FFFFFF", "#000000") - 21.0).abs() < 0.01,
            "bianco su nero deve valere 21, vale {}",
            rapporto("#FFFFFF", "#000000")
        );
        assert!(
            (rapporto("#4A7B9D", "#4A7B9D") - 1.0).abs() < 0.01,
            "un colore su se' stesso deve valere 1, vale {}",
            rapporto("#4A7B9D", "#4A7B9D")
        );
        // Una coppia di riferimento della norma: #777777 su bianco vale 4,48,
        // cioe' NON regge la soglia del testo per un soffio. Se questo numero
        // cambiasse, il calcolo sarebbe cambiato.
        assert!(
            (rapporto("#777777", "#FFFFFF") - 4.48).abs() < 0.01,
            "grigio 777777 su bianco deve valere 4,48, vale {}",
            rapporto("#777777", "#FFFFFF")
        );
    }

    /// **Ogni coppia destinata al testo o all'interfaccia regge la propria
    /// soglia.**
    ///
    /// # Perché sta nel cancello e non in uno script
    ///
    /// Perché la misura esisteva già, corretta, e **nessuno la eseguiva**. Il
    /// documento di sistema grafico impone la riverifica a ogni modifica della
    /// palette, e l'unico modo di rispettarla era ricordarsene (ADR-0116).
    #[test]
    fn ogni_coppia_regge_la_propria_soglia() {
        let colori = colori();
        let mut misurate = 0;

        for (primo_piano, sfondo, genere) in COPPIE {
            let Some(colore_primo) = colori.get(*primo_piano) else {
                panic!(
                    "il token «{primo_piano}» non esiste piu': una coppia che nomina un colore \
                     assente non misura niente"
                );
            };
            let Some(colore_sfondo) = colori.get(*sfondo) else {
                panic!("il token «{sfondo}» non esiste piu'");
            };

            let valore = rapporto(colore_primo, colore_sfondo);
            misurate += 1;

            let Some(soglia) = genere.soglia() else {
                continue;
            };

            let accettata = ACCETTATE
                .iter()
                .any(|(a, b, _)| a == primo_piano && b == sfondo);
            if accettata {
                continue;
            }

            assert!(
                valore >= soglia,
                "«{primo_piano}» su «{sfondo}» vale {valore} contro una soglia di {soglia} \
                 ({}): non si alza la soglia e non si riclassifica la coppia per farla \
                 passare, si cambia il colore o si registra la deviazione con la sua ragione \
                 (ADR-0116)",
                genere.nome()
            );
        }

        assert_eq!(
            misurate,
            COPPIE.len(),
            "non tutte le coppie sono state misurate"
        );
    }

    /// **Nessuna deviazione accettata resta senza ragione scritta.**
    ///
    /// L'elenco è vuoto e va tenuto vuoto finché si può; se un giorno non lo
    /// sarà, ogni riga porterà con sé perché.
    #[test]
    fn ogni_deviazione_accettata_porta_la_propria_ragione() {
        for (primo_piano, sfondo, ragione) in ACCETTATE {
            assert!(
                ragione.len() > 40,
                "la deviazione «{primo_piano}» su «{sfondo}» non porta una ragione leggibile: \
                 un'eccezione senza motivo scritto e' indistinguibile da una soglia abbassata"
            );
        }
    }
}
