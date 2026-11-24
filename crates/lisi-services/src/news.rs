//! «Scopri che cosa è cambiato» (NEWS-01, ADR-0169, DEC-434).
//!
//! # Che cosa fa questo servizio
//!
//! - **Tiene il registro delle novità**, scritto qui e diviso in edizioni: non
//!   si scarica, non si aggiorna da solo, non apre alcuna rete.
//! - **Dice se aprire il giro da sé**, una volta per edizione, e registra
//!   l'edizione vista nella riga di `news_state` (migrazione 0068).
//!
//! # Che cosa non fa, per costruzione
//!
//! Il giro mostra e non fa: il suo solo gesto è aprire una schermata, e lo
//! compie l'interfaccia, come il tour. Questo modulo non conosce Telegram, i
//! contenuti monitorati o l'audit: una guardia lo verifica leggendo il
//! sorgente.
//!
//! # Edizione, non versione
//!
//! Il numero della prossima versione si decide alla distribuzione
//! (INSTALLER-NEXT). Chi aggiunge una novità aggiunge un'edizione; la versione
//! che la contiene lo dice nelle note di rilascio.

use lisi_core::Timestamp;
use lisi_core::model::tour::TourStatus;
use lisi_storage::Database;

use crate::error::ServiceResult;
use crate::tour::TourPlace;

/// L'ultima edizione del registro delle novità.
pub const NEWS_EDITION: u32 = 2;

/// Una novità.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NewsItem {
    /// La chiave stabile, per le prove.
    pub key: &'static str,
    /// Il titolo, corto.
    pub title: &'static str,
    /// Una o due frasi brevi: che cosa c'è, e che cosa non fa.
    pub sentence: &'static str,
    /// Dove si trova.
    pub place: TourPlace,
}

/// Un'edizione del registro.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NewsEdition {
    /// Il numero, da uno, senza buchi.
    pub edition: u32,
    /// Le novità, nell'ordine in cui si mostrano.
    pub items: &'static [NewsItem],
}

/// Il registro. **Un'edizione si aggiunge in fondo, e non si riscrive**: chi
/// l'ha vista non la rivede.
pub const EDITIONS: &[NewsEdition] = &[
    NewsEdition {
        edition: 1,
        items: &[
            NewsItem {
                key: "uscite_protette",
                title: "Copie e documenti del solo utente",
                sentence: "Copie di sicurezza, relazioni ed esportazioni nascono leggibili soltanto \
                       dall'utente di Windows che le produce. Se la protezione non si può \
                       garantire, l'operazione si ferma senza lasciare copie.",
                place: TourPlace::Settings,
            },
            NewsItem {
                key: "profilo_cifrato",
                title: "Il nome e i recapiti, cifrati",
                sentence: "Il nome, la qualifica e i recapiti che compaiono nei documenti si \
                       conservano cifrati con la protezione di Windows.",
                place: TourPlace::Report,
            },
            NewsItem {
                key: "ricerca_post_pubblici",
                title: "La ricerca nei post pubblici",
                sentence: "In Segnali cyber si cerca anche nei post pubblici di Telegram. Il \
                       programma legge la quota gratuita prima di ogni ricerca e non spende \
                       Stelle.",
                place: TourPlace::CyberWatch,
            },
            NewsItem {
                key: "ricerche_ricorrenti",
                title: "Le ricerche ricorrenti",
                sentence: "Una ricerca cyber si salva e si ripete a intervalli dichiarati, soltanto \
                       a programma aperto e dentro limiti che il programma fa rispettare. Si \
                       sospende o si ritira quando si vuole.",
                place: TourPlace::CyberWatch,
            },
            NewsItem {
                key: "ricerca_su_piu_rami",
                title: "Una domanda su più rami",
                sentence: "Una ricerca cyber interroga insieme più rami, dall'archivio ai post \
                       pubblici, e unisce i risultati senza contarli due volte.",
                place: TourPlace::CyberWatch,
            },
            NewsItem {
                key: "fonti_suggerite",
                title: "Le fonti citate nell'archivio",
                sentence: "La pagina Fonti propone le fonti citate nei messaggi già acquisiti, con \
                       il motivo. Il programma non entra in nulla da sé: una fonte si aggiunge a \
                       mano.",
                place: TourPlace::Sources,
            },
            NewsItem {
                key: "affidabilita_fonti",
                title: "L'affidabilità di una fonte",
                sentence: "Ogni fonte può avere una valutazione dell'ufficio, data a mano con il \
                       motivo. Il programma non la calcola, e la relazione la riporta con chi \
                       l'ha data.",
                place: TourPlace::Sources,
            },
            NewsItem {
                key: "collegamenti",
                title: "Il collegamento di un contenuto",
                sentence: "Nella conversazione si copia il collegamento di un messaggio, o si apre \
                       la pagina pubblica della fonte. La relazione può chiedere i collegamenti a \
                       Telegram, e lo dichiara.",
                place: TourPlace::Report,
            },
            NewsItem {
                key: "ora_di_windows",
                title: "Come Windows tiene l'ora",
                sentence: "La riga «Pronto per lavorare» dice anche se Windows sincronizza l'ora. \
                       Se non la sincronizza lo dice, senza fermare il lavoro.",
                place: TourPlace::Dashboard,
            },
        ],
    },
    NewsEdition {
        edition: 2,
        items: &[
            NewsItem {
                key: "pausa_acquisizione",
                title: "La pausa dell'acquisizione",
                sentence: "In Monitoraggio, con un motivo, si mette in pausa l'acquisizione: il \
                           periodo resta non coperto, e i documenti lo dicono. «Sospendi avvisi» \
                           invece ferma soltanto le notifiche.",
                place: TourPlace::Monitoring,
            },
            NewsItem {
                key: "avvio_programmato",
                title: "Un monitoraggio che parte più tardi",
                sentence: "In Nuovo monitoraggio si sceglie «Parte più tardi». Il monitoraggio \
                           parte all'ora indicata se il programma è aperto e l'account \
                           collegato; altrimenti lo dice, e non parte da sé.",
                place: TourPlace::NewMonitoring,
            },
            NewsItem {
                key: "piu_account",
                title: "Più account collegati insieme",
                sentence: "«Tienilo collegato» tiene collegato un account anche quando se ne \
                           sceglie un altro, fino a tre. Ogni monitoraggio riceve soltanto \
                           dall'account con cui è nato.",
                place: TourPlace::Account,
            },
            NewsItem {
                key: "configurazione_di_distribuzione",
                title: "Niente da scrivere per collegare il programma",
                sentence: "Ciò che serve al programma per presentarsi a Telegram arriva con \
                           l'installazione: nessuna schermata lo chiede. Se manca, Account lo \
                           dice.",
                place: TourPlace::Account,
            },
            NewsItem {
                key: "copie_cifrate_e_pianificate",
                title: "Copia cifrata e copie pianificate",
                sentence: "Una copia cifrata con una frase si può portare anche su una \
                           chiavetta. Le copie pianificate dall'amministratore partono a \
                           programma aperto.",
                place: TourPlace::Settings,
            },
            NewsItem {
                key: "firma_e_rapporto_complessivo",
                title: "La firma dell'ufficio e il rapporto complessivo",
                sentence: "In Report un documento si firma con il certificato scelto \
                           dall'amministratore, e si compone un rapporto su più monitoraggi, da \
                           due a venti.",
                place: TourPlace::Report,
            },
            NewsItem {
                key: "espressioni_e_codici",
                title: "Un'espressione o un codice nei dizionari",
                sentence: "Un termine può essere un'espressione, che riconosce più parole con una \
                           sola riga, o un codice numerico, che conta soltanto insieme ad altri \
                           termini. Si provano nel Laboratorio regole prima di pubblicare.",
                place: TourPlace::Dictionaries,
            },
            NewsItem {
                key: "indicatori_dal_pc",
                title: "Un indicatore, chiesto dal PC",
                sentence: "Nella cronologia di un gruppo si risolve un indicatore e si chiede chi \
                           ha registrato un nome, se l'amministratore lo abilita. La richiesta \
                           parte da questo PC, e si vede fuori.",
                place: TourPlace::CyberWatch,
            },
            NewsItem {
                key: "punteggio_cve_e_taxii",
                title: "Il punteggio delle CVE e l'invio a TAXII",
                sentence: "La scheda di una CVE mostra il punteggio pubblicato da NVD. Gli \
                           osservabili si possono mandare al servizio TAXII scelto \
                           dall'amministratore; nulla si riceve.",
                place: TourPlace::References,
            },
            NewsItem {
                key: "iscritti_e_allegati",
                title: "Gli iscritti di una fonte e gli allegati",
                sentence: "Se l'amministratore l'ha abilitato, «Iscritti» chiede l'elenco di una \
                           fonte, con un motivo. Sotto un messaggio, «Conserva l'allegato» lo \
                           conserva senza aprirlo.",
                place: TourPlace::Sources,
            },
            NewsItem {
                key: "lingua_servizio_registro",
                title: "Lingua, servizio e registro delle consultazioni",
                sentence: "Si sceglie la lingua dell'interfaccia; i documenti restano in \
                           italiano. Il servizio di Windows continua il monitoraggio quando si \
                           esce da Windows; il registro delle consultazioni lo attiva \
                           l'amministratore.",
                place: TourPlace::Settings,
            },
            NewsItem {
                key: "comandi_a_distanza",
                title: "I comandi a distanza fra sedi",
                sentence: "Da una postazione collegata all'Hub si mette in pausa, si riprende o \
                           si arresta un monitoraggio dell'Hub, con un motivo. L'Hub lo fa \
                           soltanto se chi lo amministra lo accetta.",
                place: TourPlace::SharedLive,
            },
        ],
    },
];

/// Il nome del luogo, come lo legge chi guarda: la voce del menu.
#[must_use]
pub const fn place_label(place: TourPlace) -> &'static str {
    match place {
        TourPlace::Here | TourPlace::Dashboard => "Cruscotto",
        TourPlace::Account => "Account",
        TourPlace::Sources => "Fonti",
        TourPlace::Dictionaries => "Dizionari",
        TourPlace::Station => "Postazione",
        TourPlace::Diagnostics => "Diagnostica",
        TourPlace::Settings => "Impostazioni",
        TourPlace::Guide => "Guida",
        TourPlace::NewMonitoring => "Nuovo monitoraggio",
        TourPlace::Monitoring => "Monitoraggio",
        TourPlace::WorkQueue => "Coda di lavoro",
        TourPlace::CyberWatch => "Segnali cyber",
        TourPlace::History => "Storico",
        TourPlace::Workspace => "Raccoglitori",
        TourPlace::People => "Persone",
        TourPlace::Lookup => "Ricerca puntuale",
        TourPlace::References => "Riferimenti informatici",
        TourPlace::Report => "Report",
        TourPlace::SharedLive => "Live condiviso",
    }
}

/// Le novità delle edizioni successive a quella indicata, in ordine.
#[must_use]
pub fn items_after(edition: u32) -> Vec<NewsItem> {
    EDITIONS
        .iter()
        .filter(|voce| voce.edition > edition)
        .flat_map(|voce| voce.items.iter().copied())
        .collect()
}

/// Le novità dell'ultima edizione: quelle che «Che cosa è cambiato» mostra
/// quando lo si chiede.
#[must_use]
pub fn latest_items() -> Vec<NewsItem> {
    items_after(NEWS_EDITION.saturating_sub(1))
}

/// Il servizio delle novità.
#[derive(Debug)]
pub struct NewsService {
    database: Database,
}

impl NewsService {
    /// Crea il servizio attorno al database indicato.
    #[must_use]
    pub const fn new(database: Database) -> Self {
        Self { database }
    }

    /// All'avvio: le novità da mostrare da sé, o nessuna (ADR-0169 §3, §4).
    ///
    /// Mai in Esercitazione, e senza scrivere. Una postazione su cui il tour
    /// non è mai stato proposto è nuova: l'ultima edizione si registra come
    /// vista, e non si mostra nulla. Su una postazione già usata si mostrano
    /// le novità delle edizioni non viste; si registrano **quando compaiono**
    /// ([`Self::mark_shown`]).
    ///
    /// # Errori
    ///
    /// Restituisce un errore se la lettura o la scrittura non riescono.
    pub fn on_start(&self, exercise: bool, now: Timestamp) -> ServiceResult<Vec<NewsItem>> {
        if exercise {
            return Ok(Vec::new());
        }
        let vista = self.database.news_seen_edition()?;
        if self.database.tour_state()? == TourStatus::NeverProposed {
            if vista.is_none_or(|vista| vista < NEWS_EDITION) {
                self.mark_shown(now)?;
            }
            return Ok(Vec::new());
        }
        Ok(items_after(vista.unwrap_or(0)))
    }

    /// Il giro è comparso: l'ultima edizione è vista, e non ricompare da sé.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se la scrittura non riesce.
    pub fn mark_shown(&self, now: Timestamp) -> ServiceResult<()> {
        self.database
            .record_news_seen_edition(NEWS_EDITION, now.as_millis())?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use lisi_core::Timestamp;
    use lisi_core::model::tour::{TOUR_VERSION, TourPhase, TourRecord};
    use lisi_storage::Database;

    use super::{EDITIONS, NEWS_EDITION, NewsService, items_after, latest_items, place_label};

    /// Il sorgente del modulo, per le prove sulla forma.
    const THIS_MODULE: &str = include_str!("news.rs");

    fn servizio() -> NewsService {
        let Ok(database) = Database::open_in_memory() else {
            panic!("l'archivio di prova deve aprirsi");
        };
        NewsService::new(database)
    }

    fn ora(ms: i64) -> Timestamp {
        Timestamp::from_millis(ms)
    }

    /// Una postazione già usata: il tour è stato proposto e saltato.
    fn gia_usata(servizio: &NewsService) {
        let record = TourRecord {
            phase: TourPhase::Skipped,
            tour_version: TOUR_VERSION,
            last_step: None,
            completed_version: None,
        };
        let Ok(()) = servizio.database.save_tour_state(&record, 1) else {
            panic!("lo stato del tour deve scriversi");
        };
    }

    /// **Le edizioni crescono da uno senza buchi, l'ultima è quella
    /// dichiarata, e nessuna è vuota** (NEWS-01, criterio 1).
    #[test]
    fn le_edizioni_crescono_senza_buchi() {
        for (indice, voce) in EDITIONS.iter().enumerate() {
            assert_eq!(
                usize::try_from(voce.edition).ok(),
                Some(indice + 1),
                "edizione {}",
                voce.edition
            );
            assert!(!voce.items.is_empty(), "edizione {}", voce.edition);
        }
        assert_eq!(EDITIONS.last().map(|voce| voce.edition), Some(NEWS_EDITION));
        let mut chiavi: Vec<&str> = EDITIONS
            .iter()
            .flat_map(|voce| voce.items.iter().map(|novita| novita.key))
            .collect();
        let quante = chiavi.len();
        chiavi.sort_unstable();
        chiavi.dedup();
        assert_eq!(chiavi.len(), quante, "una chiave ripetuta");
    }

    /// **Ogni novità ha un titolo, una frase e un luogo con un nome** (criterio
    /// 1).
    #[test]
    fn ogni_novita_ha_titolo_frase_e_luogo() {
        for novita in items_after(0) {
            assert!(!novita.title.is_empty(), "{}", novita.key);
            assert!(novita.sentence.ends_with('.'), "{}", novita.key);
            assert!(!place_label(novita.place).is_empty(), "{}", novita.key);
        }
        assert_eq!(latest_items().len(), items_after(NEWS_EDITION - 1).len());
        assert!(items_after(NEWS_EDITION).is_empty());
    }

    /// **Su una postazione già usata il giro si apre una volta per edizione**
    /// (criterio 2; prova negativa: l'edizione non registrata quando compare →
    /// il giro si riapre, rossa).
    #[test]
    fn su_una_postazione_gia_usata_si_apre_una_volta() {
        let servizio = servizio();
        gia_usata(&servizio);
        let Ok(prime) = servizio.on_start(false, ora(10)) else {
            panic!("le novità devono leggersi");
        };
        assert_eq!(prime, items_after(0));
        // Non si registrano da sole: soltanto quando compaiono.
        assert_eq!(servizio.on_start(false, ora(11)).ok(), Some(items_after(0)));

        let Ok(()) = servizio.mark_shown(ora(12)) else {
            panic!("la comparsa deve registrarsi");
        };
        for istante in 13..20 {
            assert_eq!(
                servizio.on_start(false, ora(istante)).ok(),
                Some(Vec::new()),
                "il giro si è riaperto da sé"
            );
        }
    }

    /// **Una postazione nuova non ha novità: ha il tour** (criterio 2; prova
    /// negativa: la postazione nuova che riceve il giro al secondo avvio →
    /// rossa).
    #[test]
    fn una_postazione_nuova_non_ha_novita() {
        let servizio = servizio();
        assert_eq!(servizio.on_start(false, ora(1)).ok(), Some(Vec::new()));
        assert_eq!(
            servizio.database.news_seen_edition().ok(),
            Some(Some(NEWS_EDITION))
        );
        // Il tour viene proposto al primo avvio; al secondo, niente giro.
        gia_usata(&servizio);
        assert_eq!(servizio.on_start(false, ora(2)).ok(), Some(Vec::new()));
    }

    /// **In Esercitazione nessun giro e nessuna scrittura** (criterio 2).
    #[test]
    fn in_esercitazione_nessun_giro() {
        let servizio = servizio();
        gia_usata(&servizio);
        assert_eq!(servizio.on_start(true, ora(1)).ok(), Some(Vec::new()));
        assert_eq!(servizio.database.news_seen_edition().ok(), Some(None));
    }

    /// **La seconda edizione racconta la 0.2.x** (COLLAUDO-FIX-01, CU01-002,
    /// DEC-511).
    ///
    /// Nel collaudo, dopo l'aggiornamento dalla 0.1.2, il giro mostrava le nove
    /// novità di NEWS-01 e nessuna parola sulla pausa dell'acquisizione,
    /// sull'avvio programmato, sui più account e sul resto delle milestone
    /// successive. Ogni funzione che cambia l'uso ha una voce, raggruppata
    /// perché il giro resti breve.
    #[test]
    fn la_seconda_edizione_racconta_la_0_2() {
        let Some(seconda) = EDITIONS.iter().find(|voce| voce.edition == 2) else {
            panic!("manca l'edizione delle novità della 0.2.x (CU01-002)");
        };
        let chiavi: Vec<&str> = seconda.items.iter().map(|novita| novita.key).collect();
        for attesa in [
            "pausa_acquisizione",
            "avvio_programmato",
            "piu_account",
            "configurazione_di_distribuzione",
            "copie_cifrate_e_pianificate",
            "firma_e_rapporto_complessivo",
            "espressioni_e_codici",
            "indicatori_dal_pc",
            "punteggio_cve_e_taxii",
            "iscritti_e_allegati",
            "lingua_servizio_registro",
            "comandi_a_distanza",
        ] {
            assert!(chiavi.contains(&attesa), "manca «{attesa}» (CU01-002)");
        }
        assert!(
            seconda.items.len() <= 14,
            "il giro deve restare breve: {} voci",
            seconda.items.len()
        );
        // «Sospendi avvisi» non è la pausa: la voce lo dice.
        let Some(pausa) = seconda
            .items
            .iter()
            .find(|novita| novita.key == "pausa_acquisizione")
        else {
            panic!("la voce della pausa deve esserci");
        };
        assert!(
            pausa.sentence.contains("Sospendi avvisi"),
            "{}",
            pausa.sentence
        );
    }

    /// **Il servizio non conosce Telegram, i contenuti o l'audit, e non apre
    /// rete** (criterio 4; prova negativa: una lettura dei contenuti aggiunta
    /// al modulo → rossa).
    #[test]
    fn il_servizio_non_conosce_il_lavoro() {
        let Some((produzione, _)) = THIS_MODULE.split_once("#[cfg(test)]\nmod tests {") else {
            panic!("il modulo deve avere un blocco di prove riconoscibile");
        };
        for vietato in [
            "lisi_telegram",
            "session_contents",
            "NewAuditEntry",
            "AuditAction",
            "https",
            "lisi_platform",
        ] {
            assert!(
                !produzione.contains(vietato),
                "«{vietato}» nel servizio delle novità"
            );
        }
    }
}
