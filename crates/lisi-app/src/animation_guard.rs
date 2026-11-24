//! Verifica che nessuna animazione pretenda di ripetersi da sola.
//!
//! # Il difetto che questo modulo esiste per impedire
//!
//! In Slint un'animazione scatta quando il valore di una proprietà **cambia**.
//! Una proprietà che nasce già al valore d'arrivo non cambia mai, e la sua
//! animazione non parte: il compilatore non se ne lamenta, la prova non
//! fallisce, e a schermo si vede un elemento immobile.
//!
//! Il 19 e il 20 agosto 2026 questo è successo **due volte nello stesso
//! componente**, il radar della Dashboard:
//!
//! 1. Il respiro del nucleo. Da fermo il valore vale già quello giusto al primo
//!    calcolo, e da fermo è lo stato in cui il pannello nasce. Non ha mai
//!    respirato.
//! 2. La spazzata. Chi avvia un monitoraggio e poi apre la Dashboard trova un
//!    pannello **nuovo**, in cui la fase nasce già a destinazione. Il fascio
//!    restava puntato in alto, fermo.
//!
//! La seconda è sfuggita anche dopo aver corretto la prima, perché le due
//! avarie si somigliavano: `0.0` e `1.0` sono lo stesso angolo, a un giro di
//! distanza, quindi il fascio fermo appariva identico in entrambi i casi.
//!
//! # La regola
//!
//! **In questo prodotto un'animazione non si ripete da sola.** Ciò che deve
//! ripetersi lo muove un `Timer`, che a ogni battuta cambia un valore — e un
//! valore che cambia è l'unica cosa su cui un'animazione possa scattare.
//!
//! `iteration-count` non è difettoso: è una funzione di Slint che presuppone un
//! cambio di valore all'origine. In un'interfaccia dove i pannelli nascono e
//! muoiono con la pagina che li contiene, quel presupposto è falso più spesso
//! di quanto sembri, e quando è falso non lo dice nessuno.
//!
//! # Che cosa questa prova NON fa
//!
//! Non verifica che le animazioni si vedano: quello lo può dire solo un occhio
//! su un prodotto in funzione, ed è così che entrambi i difetti sono stati
//! trovati. Fissa l'invariante che la verifica a vista ha appena confermato,
//! perché non regredisca in silenzio.

/// I due file di interfaccia, letti a tempo di compilazione.
#[cfg(test)]
const COMPONENTI: &str = include_str!("../ui/components.slint");

/// Il sorgente dei token, dove vivono le misure derivate dalla preferenza.
#[cfg(test)]
const TOKENS: &str = include_str!("../ui/tokens.slint");

#[cfg(test)]
const FINESTRA: &str = include_str!("../ui/app-window.slint");

#[cfg(test)]
mod tests {
    use super::{COMPONENTI, FINESTRA, TOKENS};

    /// Le righe che dichiarano davvero la proprietà, non quelle che la
    /// nominano in un commento.
    ///
    /// La distinzione conta: la spiegazione del difetto vive in un commento
    /// accanto alla correzione, e cercare il nome senza guardare se la riga sia
    /// codice renderebbe questa guardia perennemente rossa proprio dove è stata
    /// applicata.
    fn dichiarazioni(sorgente: &str) -> Vec<(usize, &str)> {
        sorgente
            .lines()
            .enumerate()
            .filter(|(_, riga)| {
                let riga = riga.trim_start();
                !riga.starts_with("//") && riga.contains("iteration-count")
            })
            .map(|(numero, riga)| (numero + 1, riga.trim()))
            .collect()
    }

    /// I quattro ruoli del movimento, più le due misure già filtrate dalla
    /// preferenza e il fotogramma di assestamento.
    ///
    /// Sono i nomi dichiarati in `tokens.slint`: l'elenco non si scrive qui a
    /// mano, si legge da lì, perché un ruolo aggiunto e non aggiunto a questo
    /// elenco sfuggirebbe alla guardia che lo pretende usato.
    fn ruoli_del_movimento() -> Vec<String> {
        let Some(inizio) = TOKENS.find("export global Motion {") else {
            panic!(
                "i token non dichiarano piu' il blocco «Motion»: questa guardia non sta piu' guardando cio' che crede"
            );
        };
        let resto = &TOKENS[inizio..];
        let Some(fine) = resto.find("\n}") else {
            panic!(
                "il blocco «Motion» non si chiude: questa guardia non sta piu' guardando cio' che crede"
            );
        };

        let mut nomi = Vec::new();
        for riga in resto[..fine].lines() {
            let riga = riga.trim();
            if riga.starts_with("//") {
                continue;
            }
            let Some(resto) = riga.strip_prefix("out property <duration> ") else {
                continue;
            };
            let Some((nome, _)) = resto.split_once(':') else {
                continue;
            };
            nomi.push(nome.trim().to_owned());
        }

        assert!(
            nomi.len() >= 4,
            "i ruoli del movimento dichiarati sono {}: il sistema approvato ne prescrive quattro, e se la forma della dichiarazione e' cambiata questa guardia va aggiornata insieme",
            nomi.len()
        );
        nomi
    }

    /// **Nessuna durata è scritta a mano nell'interfaccia.**
    ///
    /// # Il difetto che questa prova impedisce
    ///
    /// Il blocco dei token dichiara **quattro ruoli e nient'altro**, «così che
    /// nessuna transizione ne introduca una quinta». Il respiro del radar ne
    /// aveva introdotta una: `2600ms`, scritti a mano, mentre il ruolo che
    /// avrebbe dovuto governarlo — `Motion.breath` — ne dichiarava **2400** e
    /// **non aveva un solo chiamante**.
    ///
    /// Non falliva niente. Il prodotto respirava, semplicemente respirava con
    /// un ritmo che nessun documento prescriveva, e il ruolo che lo prescriveva
    /// era **prosa senza effetto**.
    ///
    /// Una durata scritta a mano in mezzo all'interfaccia è indistinguibile da
    /// un ruolo dimenticato: si legge come una scelta (ADR-0116).
    #[test]
    fn nessuna_durata_e_scritta_a_mano_nell_interfaccia() {
        for (nome, sorgente) in [
            ("components.slint", COMPONENTI),
            ("app-window.slint", FINESTRA),
        ] {
            for (numero, riga) in sorgente.lines().enumerate() {
                let riga_pulita = riga.trim_start();
                if riga_pulita.starts_with("//") {
                    continue;
                }
                for campo in ["duration:", "interval:"] {
                    let Some(valore) = riga_pulita.split_once(campo).map(|(_, coda)| coda.trim())
                    else {
                        continue;
                    };
                    assert!(
                        !valore.starts_with(|carattere: char| carattere.is_ascii_digit()),
                        "{nome}:{} scrive una durata a mano: «{}». Ogni durata viene da un ruolo \
                         di «Motion», altrimenti il prodotto si muove con un ritmo che nessun \
                         documento prescrive e il ruolo che lo prescriveva resta prosa senza \
                         effetto (ADR-0116)",
                        numero + 1,
                        riga_pulita
                    );
                }
            }
        }
    }

    /// **Ogni ruolo del movimento ha almeno un chiamante.**
    ///
    /// Un ruolo dichiarato e mai usato è una promessa che nessuno mantiene, e
    /// **si legge come se fosse in vigore**: chi apre `tokens.slint` per sapere
    /// con che ritmo respira l'indicatore trova 2400ms, e il prodotto ne fa
    /// 2600.
    ///
    /// È la stessa forma di HARDEN-05 — due fonti della stessa verità che
    /// divergono, ciascuna coerente con sé stessa — in un posto dove non se ne
    /// accorge nessuno, perché **il movimento non ha un esito da sbagliare**.
    #[test]
    fn ogni_ruolo_del_movimento_ha_almeno_un_chiamante() {
        for ruolo in ruoli_del_movimento() {
            let chiamata = format!("Motion.{ruolo}");
            let chiamanti = [COMPONENTI, FINESTRA]
                .iter()
                .map(|sorgente| sorgente.matches(chiamata.as_str()).count())
                .sum::<usize>();

            assert!(
                chiamanti > 0,
                "«Motion.{ruolo}» e' dichiarato e non lo chiama nessuno: chi legge i token \
                 crede che sia in vigore, e il prodotto si muove con un altro ritmo (ADR-0116)"
            );
        }
    }

    #[test]
    fn nessuna_animazione_pretende_di_ripetersi_da_sola() {
        for (nome, sorgente) in [
            ("components.slint", COMPONENTI),
            ("app-window.slint", FINESTRA),
        ] {
            let trovate = dichiarazioni(sorgente);
            assert!(
                trovate.is_empty(),
                "«{nome}» dichiara {} animazione/i con `iteration-count`: {trovate:?}.\n\
                 In questo prodotto un'animazione non si ripete da sola — un valore che \
                 nasce gia' al proprio valore d'arrivo non cambia mai, e l'animazione non \
                 parte. E' successo due volte nel radar della Dashboard, e a schermo si \
                 vedeva un elemento immobile senza che nulla fallisse.\n\
                 Cio' che deve ripetersi lo muove un `Timer`.",
                trovate.len()
            );
        }
    }

    /// Ogni radar deve girare perche' si sta ACQUISENDO, non per decorazione.
    ///
    /// Il 2026-08-20 il radar della schermata Monitoraggio aveva `running`
    /// legato alle sole anomalie: girava a sessione ferma purche' non ci
    /// fossero problemi. Il commento accanto diceva gia' la cosa giusta -
    /// «il monitoraggio in corso senza anomalie» - e la riga sotto ne
    /// implementava meta'.
    ///
    /// **Un commento che descrive un'intenzione non la impone.** Questa prova
    /// la impone.
    ///
    /// Non si era mai visto perche' l'animazione non partiva affatto, per un
    /// difetto diverso: due difetti sovrapposti in cui il primo nascondeva il
    /// secondo, ed e' la ragione per cui correggerne uno non chiude il caso.
    #[test]
    fn ogni_radar_gira_solo_mentre_si_acquisisce() {
        let mut visti = 0;
        let mut resto = FINESTRA;

        while let Some(inizio) = resto.find("RadarPanel {") {
            resto = &resto[inizio + "RadarPanel {".len()..];
            // La didascalia segue sempre `running`: e' il confine del blocco
            // che interessa, e non dipende da come le righe sono spezzate.
            let fine = resto
                .find("caption:")
                .expect("ogni radar dichiara una didascalia");
            let dichiarazione = &resto[..fine];

            assert!(
                dichiarazione.contains("monitoring-active"),
                "un `RadarPanel` non lega la propria rotazione a \
                 `monitoring-active`:\n{dichiarazione}\n\
                 Un radar che gira mentre non si acquisisce racconta \
                 un'attivita' che non c'e', e un indicatore che gira sempre \
                 smette di dire qualcosa."
            );
            visti += 1;
        }

        // Se un giorno i radar sparissero, questa prova resterebbe verde per
        // il motivo sbagliato.
        assert_eq!(
            visti, 2,
            "i radar dichiarati sono {visti}, attesi 2 (Dashboard e Monitoraggio)"
        );
    }

    /// **Nessuna schermata offre cio' che questo binario non sa fare.**
    ///
    /// La modalita' «Telegram reale» esiste soltanto se il binario e' stato
    /// compilato con il componente che carica TDLib. Fino al 2026-08-20
    /// l'interfaccia offriva la scelta comunque, e l'operatore lo scopriva
    /// premendo «Avvia accesso».
    ///
    /// Un prodotto che offre una funzione che non ha promette una cosa falsa,
    /// e dirlo dopo non ripara la promessa: chi ha scelto quella modalita' ha
    /// gia' preso una decisione basandosi su di essa.
    ///
    /// **E' gia' costato due installer.** Il 2026-08-18 e il 2026-08-19 sono
    /// stati costruiti due pacchetti senza TDLib, e nulla lo dichiarava.
    ///
    /// Questa guardia sta qui, accanto a quelle sulle animazioni, perche' e'
    /// la stessa famiglia: **cose che il prodotto dice e che non corrispondono
    /// a cio' che fa**. E' la categoria che il pilot ha trovato nove volte su
    /// ventidue, e che nessuna asserzione ordinaria coglie.
    #[test]
    fn la_modalita_reale_non_si_offre_se_il_binario_non_la_possiede() {
        let inizio = FINESTRA
            .find("@tr(\"✓ Telegram reale\") : @tr(\"Telegram reale\")")
            .expect("la scelta della modalita' reale deve esistere");

        // Il corpo del comando finisce dove comincia il gestore del clic.
        let corpo = &FINESTRA[inizio..];
        let fine = corpo
            .find("clicked =>")
            .expect("il comando deve avere un gestore");
        let dichiarazione = &corpo[..fine];

        assert!(
            dichiarazione.contains("telegram-runtime-available"),
            "il comando «Telegram reale» non e' governato dalla capacita' del \
             binario:\n{dichiarazione}\n\
             Un pacchetto costruito senza il componente di Telegram offrirebbe \
             una modalita' che non sa eseguire."
        );
        assert!(
            dichiarazione.contains("reason:"),
            "un comando spento senza motivo lascia l'operatore a indovinare se \
             sia un divieto o un guasto"
        );
    }

    /// La guardia ha senso solo se il costrutto che vieta è ancora quello che
    /// Slint userebbe: se un domani sparisse dal linguaggio, questa prova
    /// resterebbe verde per il motivo sbagliato.
    ///
    /// Si verifica quindi che il rimedio prescritto **esista e sia in uso**: se
    /// i `Timer` sparissero dal radar, la regola sarebbe stata aggirata in un
    /// altro modo e va riesaminata.
    #[test]
    fn il_rimedio_prescritto_e_davvero_in_uso() {
        let timer = COMPONENTI.matches("Timer {").count();
        assert!(
            timer >= 2,
            "i `Timer` che muovono le animazioni del radar sono {timer}, attesi almeno 2 \
             (il respiro del nucleo e la spazzata). Se sono spariti, o la regola e' stata \
             aggirata o il radar non si muove piu': in entrambi i casi va guardato."
        );
    }

    /// **Il radar non ridisegna la finestra a ogni fotogramma** (PERF-02).
    ///
    /// Un `animate` sulla fase o sul respiro cambia il valore sessanta volte
    /// al secondo, e ogni cambio ridisegna l'intera finestra: il collaudo ha
    /// misurato il 22,6% di un core sulla Dashboard (OBS-PERF-1). Il radar
    /// avanza a passi del suo `Timer`, venti al secondo mentre gira e dieci
    /// mentre respira.
    #[test]
    fn il_radar_non_ridisegna_a_ogni_fotogramma() {
        let Some(inizio) = COMPONENTI.find("export component RadarPanel") else {
            panic!("il radar non e' piu' dove questa guardia lo cerca");
        };
        let resto = &COMPONENTI[inizio..];
        let fine = resto[1..]
            .find("\nexport component ")
            .map_or(resto.len(), |fine| fine + 1);
        let radar = &resto[..fine];

        let animate: Vec<&str> = radar
            .lines()
            .map(str::trim)
            .filter(|riga| !riga.starts_with("//") && riga.starts_with("animate "))
            .collect();
        assert!(
            animate.is_empty(),
            "il radar torna ad animare un valore a ogni fotogramma: {animate:?}. Ogni \
             fotogramma ridisegna l'intera finestra (OBS-PERF-1): il radar avanza a passi \
             del suo `Timer`"
        );
        for passi in [
            "private property <int> sweep-steps: 40;",
            "private property <int> breath-steps: 24;",
        ] {
            assert!(
                radar.contains(passi),
                "il passo del radar e' cambiato senza questa guardia: manca «{passi}»"
            );
        }
    }

    /// **Ogni animazione decorativa deve obbedire alla preferenza.**
    ///
    /// Un'impostazione di accessibilita' che qualche animazione ignora e' un
    /// interruttore che non fa quello che dice — e chi lo accende per una
    /// ragione medica continua a pagarne il prezzo credendo di averlo risolto.
    #[test]
    fn ogni_animazione_decorativa_obbedisce_alla_preferenza() {
        // Il radar in entrambi i suoi stati: quello che gira e quello che
        // respira in quiete.
        let quante = COMPONENTI.matches("Appearance.motion-enabled").count();
        assert!(
            quante >= 2,
            "solo {quante} animazioni leggono la preferenza: il radar ha due \
             stati e devono obbedire entrambi"
        );

        // Le transizioni e l'entrata delle viste.
        for legato in ["transition-effective", "enter-rise"] {
            assert!(
                TOKENS.contains(legato),
                "«{legato}» non esiste piu': le transizioni non obbedirebbero \
                 alla preferenza"
            );
        }
        let derivati = TOKENS.matches("Appearance.motion-enabled").count();
        assert!(
            derivati >= 2,
            "solo {derivati} misure derivano dalla preferenza"
        );
    }

    /// **La scelta deve essere a tre valori, non un interruttore.**
    ///
    /// «Come Windows» non e' riducibile ne' a «pieno» ne' a «ridotto»: se
    /// qualcuno sposta la preferenza di sistema domani, chi ha scelto «come
    /// Windows» deve vederlo cambiare e chi ha scelto «pieno» no.
    #[test]
    fn la_scelta_sul_movimento_e_a_tre_valori() {
        assert_eq!(
            lisi_core::model::motion::MotionPreference::all().len(),
            3,
            "un interruttore perderebbe la differenza fra «segui il sistema» e \
             una scelta esplicita"
        );
        assert!(
            FINESTRA.contains("motion-chosen"),
            "la schermata non offre la scelta"
        );
        assert!(
            !FINESTRA.contains("checked <=> Appearance.motion-enabled"),
            "la schermata offre ancora un interruttore booleano, che non sa \
             dire «come Windows»"
        );
    }
}
