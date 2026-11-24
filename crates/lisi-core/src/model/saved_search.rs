//! Ricerche salvate, **con la configurazione in forza quando lo furono**
//! (SEARCH-01).
//!
//! # Una sola nozione di ricerca
//!
//! Cercare nello storico esiste da prima di questa milestone: è il filtro della
//! schermata Storico — testo, livello minimo, solo ciò che attende una
//! decisione — applicato a un ambito.
//!
//! [`SavedQuery`] conserva **quel** filtro, campo per campo, e non ne inventa un
//! secondo. Il rischio era concreto e dichiarato da NOTE-01: «costruire qui una
//! ricerca sarebbe la seconda nozione di ricerca del prodotto».
//!
//! Il filtro vero vive nei servizi, perché sa interrogare l'archivio; qui c'è
//! che cosa se ne conserva. Una prova conta i campi delle due parti: **un campo
//! di filtro che non si potesse salvare sarebbe una ricerca che non si può
//! rifare**, e nessuno se ne accorgerebbe finché qualcuno non la rifà.
//!
//! # Rifare una ricerca non riproduce il risultato
//!
//! È il fatto centrale di questa milestone, e va detto invece che lasciato
//! scoprire.
//!
//! I livelli **non si ricalcolano a ogni lettura**: sono stati prodotti
//! dall'analisi al momento dell'acquisizione, da una versione del motore. Se
//! quella versione cambia, una ricerca «livello almeno 3» rifatta oggi mette
//! insieme righe valutate da motori diversi.
//!
//! Perciò una ricerca salvata porta con sé **la versione del motore in forza
//! quando fu salvata**, e rifarla produce un confronto: [`EngineDrift`].
//!
//! Non è un avvertimento generico. È la stessa disciplina di ADR-0051 — le
//! relazioni esatte fra due versioni, mai un allarme vago — e di ADR-0053: **ciò
//! che non è stato misurato non è «a posto», è non misurato.**

use crate::analysis::ENGINE_VERSION;
use crate::error::{DomainError, DomainResult};
use crate::text::{Actor, DisplayName};
use crate::time::Timestamp;
use crate::{SavedSearchId, SessionId};

/// Che cosa si cerca: i campi del filtro dello Storico, conservati.
///
/// # Perché i campi sono pubblici
///
/// Perché sono **esattamente** i campi del filtro, e nasconderli dietro
/// accessori darebbe l'impressione che questo tipo decida qualcosa. Non decide:
/// conserva. La convalida — che una ricerca chieda almeno qualcosa — appartiene
/// a [`NewSavedSearch`], che è ciò che si costruisce.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SavedQuery {
    /// Il testo cercato. Può essere vuoto.
    pub query: String,
    /// Livello minimo mostrato; `0` non esclude nulla.
    pub minimum_level: u8,
    /// Solo i contenuti che attendono una decisione umana.
    pub only_pending: bool,
    /// L'ambito: una sessione, oppure tutte.
    pub session: Option<SessionId>,
}

impl SavedQuery {
    /// Se questa ricerca chiede qualcosa.
    ///
    /// # Perché conta
    ///
    /// Una ricerca senza testo, senza livello minimo e senza attesa di
    /// decisione restituisce **tutto**, che è ciò che lo Storico mostra già
    /// senza salvare nulla. Salvarla darebbe a chi la rilegge l'impressione che
    /// selezioni qualcosa.
    ///
    /// L'ambito da solo **non basta**: «tutti i contenuti di quella sessione» è
    /// ciò che si ottiene scegliendo la sessione nell'elenco.
    #[must_use]
    pub fn asks_something(&self) -> bool {
        !self.query.trim().is_empty() || self.minimum_level > 0 || self.only_pending
    }

    /// Che cosa questa ricerca chiede, detto a chi legge.
    ///
    /// # Perché la frase la compone il modello
    ///
    /// DEC-252: una schermata **riceve** frasi già composte invece di
    /// ricomporle. Due schermate che compongono la stessa frase la compongono
    /// diversa, e la differenza si vede solo mettendole vicine.
    #[must_use]
    pub fn as_sentence(&self) -> String {
        let mut pezzi = Vec::new();
        if !self.query.trim().is_empty() {
            pezzi.push(format!("che contengono «{}»", self.query.trim()));
        }
        if self.minimum_level > 0 {
            pezzi.push(format!("di livello almeno {}", self.minimum_level));
        }
        if self.only_pending {
            pezzi.push(String::from("che attendono una decisione"));
        }
        let dove = match self.session {
            Some(_) => "in una sola sessione",
            None => "in tutte le sessioni",
        };
        if pezzi.is_empty() {
            return format!("Tutti i contenuti, {dove}.");
        }
        format!("Contenuti {}, {dove}.", pezzi.join(", "))
    }
}

/// Una ricerca da salvare.
///
/// # Perché i campi sono privati
///
/// Perché il tipo garantisce una cosa che una struttura aperta non
/// garantirebbe: che una ricerca salvata **chieda qualcosa**.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewSavedSearch {
    name: DisplayName,
    query: SavedQuery,
    created_by: Actor,
}

impl NewSavedSearch {
    /// Salva una ricerca.
    ///
    /// # Errori
    ///
    /// Rifiuta una ricerca che **non chiede niente**: restituirebbe tutto, che
    /// è ciò che lo Storico mostra già.
    pub fn of(name: DisplayName, query: SavedQuery, created_by: Actor) -> DomainResult<Self> {
        if !query.asks_something() {
            return Err(DomainError::Empty {
                field: "saved_query",
            });
        }
        Ok(Self {
            name,
            query,
            created_by,
        })
    }

    /// Il nome.
    #[must_use]
    pub const fn name(&self) -> &DisplayName {
        &self.name
    }

    /// Che cosa cerca.
    #[must_use]
    pub const fn query(&self) -> &SavedQuery {
        &self.query
    }

    /// Chi la salva.
    #[must_use]
    pub const fn created_by(&self) -> &Actor {
        &self.created_by
    }
}

/// Una ricerca salvata, riletta.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SavedSearch {
    /// Identificativo stabile.
    pub id: SavedSearchId,
    /// Il nome con cui la si ritrova.
    pub name: DisplayName,
    /// Che cosa cerca.
    pub query: SavedQuery,
    /// La versione del motore **in forza quando fu salvata**.
    pub engine_version: u32,
    /// Chi l'ha salvata.
    pub created_by: Actor,
    /// Quando.
    pub created_at: Timestamp,
}

impl SavedSearch {
    /// Che cosa questa ricerca è, detto a chi legge.
    #[must_use]
    pub fn as_sentence(&self) -> String {
        format!(
            "Salvata da {} il {}. {}",
            self.created_by.as_str(),
            self.created_at.to_readable_utc(),
            self.query.as_sentence()
        )
    }
}

/// Che cosa è cambiato, fra il motore di allora e quello di adesso.
///
/// # Perché non è un `bool`
///
/// Perché «è cambiato» e «non è cambiato» non sono i soli due esiti che
/// contano. Il terzo è che **alcune righe non registrano affatto** quale motore
/// le abbia valutate — i contenuti anteriori a ENGINE-01 — e quello non è né
/// «uguale» né «diverso»: è **non misurato**, e chi legge deve saperlo
/// (ADR-0053).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EngineDrift {
    /// La versione in forza quando la ricerca fu salvata.
    pub at_save: u32,
    /// La versione in forza adesso.
    pub now: u32,
    /// Quante righe del risultato sono state valutate da una versione
    /// **diversa** da quella in forza al salvataggio.
    pub graded_differently: usize,
    /// Quante righe **non registrano** quale motore le abbia valutate.
    pub not_recorded: usize,
    /// Quante righe ha restituito la riesecuzione, in tutto.
    pub total: usize,
}

impl EngineDrift {
    /// Confronta la configurazione di allora con quella delle righe trovate.
    ///
    /// # Perché il conteggio sta qui e non in chi riesegue
    ///
    /// Perché **qui si può esercitare**. Il servizio inserisce ogni contenuto
    /// con la versione del motore che sta girando: una prova che passi da lì
    /// non può costruire una riga valutata da una versione diversa, né una
    /// senza versione, e ogni conteggio le risulterebbe zero.
    ///
    /// Era esattamente così: il conteggio viveva nel servizio, e togliendogli
    /// il ramo che conta le righe **non registrate** nessuna prova diventava
    /// rossa. Spostarlo qui non è un riordino — è la differenza fra una regola
    /// sorvegliata e una che nessuno controlla.
    ///
    /// # Che cosa distingue i tre casi
    ///
    /// `None` è **non registrato**, e non è né «uguale» né «diverso»: sono i
    /// contenuti anteriori a ENGINE-01, che nessuno sa da quale motore siano
    /// stati valutati. Contarli come concordi direbbe una cosa che nessuno sa
    /// (ADR-0053).
    pub fn between(at_save: u32, now: u32, recorded: impl Iterator<Item = Option<u32>>) -> Self {
        let mut graded_differently = 0_usize;
        let mut not_recorded = 0_usize;
        let mut total = 0_usize;

        for versione in recorded {
            total += 1;
            match versione {
                None => not_recorded += 1,
                Some(versione) if versione != at_save => graded_differently += 1,
                Some(_) => {}
            }
        }

        Self {
            at_save,
            now,
            graded_differently,
            not_recorded,
            total,
        }
    }

    /// Se questa riesecuzione è confrontabile con quella di allora.
    ///
    /// # Perché una domanda e non un confronto scritto altrove
    ///
    /// Perché il giorno in cui si aggiungesse un terzo motivo di
    /// incomparabilità — una configurazione che oggi non esiste — un confronto
    /// scritto in una schermata direbbe la cosa sbagliata in silenzio.
    #[must_use]
    pub const fn is_comparable(&self) -> bool {
        self.at_save == self.now && self.graded_differently == 0 && self.not_recorded == 0
    }

    /// Che cosa è cambiato, detto a chi legge.
    ///
    /// # Perché dice i numeri e non «attenzione»
    ///
    /// Perché un avviso generico non si può usare. ADR-0051 lo ha già stabilito
    /// per le versioni di un contenuto: **la relazione esatta**, mai un allarme
    /// vago. Qui la relazione esatta è quante righe, e per quale ragione.
    #[must_use]
    pub fn as_sentence(&self) -> String {
        if self.is_comparable() {
            return format!(
                "Le {} righe sono state valutate dal motore versione {}, lo stesso in forza \
                 quando la ricerca fu salvata.",
                self.total, self.now
            );
        }

        let mut motivi = Vec::new();
        if self.at_save != self.now {
            motivi.push(format!(
                "il motore era la versione {} e adesso \u{e8} la {}",
                self.at_save, self.now
            ));
        }
        if self.graded_differently > 0 {
            motivi.push(format!(
                "{} righe su {} sono state valutate da una versione diversa da quella di allora",
                self.graded_differently, self.total
            ));
        }
        if self.not_recorded > 0 {
            motivi.push(format!(
                "{} righe su {} non registrano quale motore le abbia valutate",
                self.not_recorded, self.total
            ));
        }

        format!(
            "Questa riesecuzione non \u{e8} confrontabile con quella di allora: {}. Non \
             significa che i risultati siano sbagliati: significa che due esecuzioni della stessa \
             domanda hanno misurato con metri diversi.",
            motivi.join("; ")
        )
    }
}

/// La versione del motore in forza adesso.
///
/// # Perché una funzione e non la costante nuda
///
/// Perché chi salva una ricerca deve registrare **ciò che è in forza**, e
/// leggere la costante da ogni chiamante darebbe tanti punti da cui leggerla.
#[must_use]
pub const fn engine_in_force() -> u32 {
    ENGINE_VERSION
}

#[cfg(test)]
mod tests {
    use super::{EngineDrift, NewSavedSearch, SavedQuery, SavedSearch, engine_in_force};
    use crate::text::{Actor, DisplayName};
    use crate::time::Timestamp;
    use crate::{SavedSearchId, SessionId};

    /// Questo modulo, per le guardie strutturali.
    const THIS_MODULE: &str = include_str!("saved_search.rs");

    const ORA: i64 = 1_700_000_000_000;

    fn attore() -> Actor {
        let Ok(attore) = Actor::try_new("operatore.prova") else {
            panic!("l'attore di prova deve essere valido");
        };
        attore
    }

    fn nome(testo: &str) -> DisplayName {
        let Ok(nome) = DisplayName::try_new(testo) else {
            panic!("il nome di prova deve essere valido");
        };
        nome
    }

    fn query(testo: &str, livello: u8, pendenti: bool) -> SavedQuery {
        SavedQuery {
            query: String::from(testo),
            minimum_level: livello,
            only_pending: pendenti,
            session: None,
        }
    }

    /// **Una ricerca che non chiede niente non si salva.**
    ///
    /// # Il difetto che questa prova impedisce
    ///
    /// Una ricerca salvata che restituisce tutto. Chi la rilegge crede che
    /// selezioni qualcosa, e non se ne accorge finché non conta le righe.
    #[test]
    fn una_ricerca_che_non_chiede_niente_non_si_salva() {
        assert!(
            NewSavedSearch::of(nome("Vuota"), query("   ", 0, false), attore()).is_err(),
            "restituirebbe tutto, che e' cio' che lo Storico mostra gia'"
        );

        // NEMMENO L'AMBITO BASTA: «tutti i contenuti di quella sessione» e' cio'
        // che si ottiene scegliendo la sessione nell'elenco.
        let mut solo_ambito = query("", 0, false);
        solo_ambito.session = Some(SessionId::new(1));
        assert!(NewSavedSearch::of(nome("Solo ambito"), solo_ambito, attore()).is_err());

        for chiede in [
            query("droga", 0, false),
            query("", 3, false),
            query("", 0, true),
        ] {
            assert!(
                NewSavedSearch::of(nome("Chiede"), chiede, attore()).is_ok(),
                "questa chiede qualcosa"
            );
        }
    }

    /// **La frase dice che cosa la ricerca chiede, per esteso.**
    #[test]
    fn la_frase_dice_che_cosa_la_ricerca_chiede() {
        let frase = query("droga", 3, true).as_sentence();
        assert!(frase.contains("droga"), "{frase}");
        assert!(frase.contains("livello almeno 3"), "{frase}");
        assert!(frase.contains("attendono una decisione"), "{frase}");
        assert!(frase.contains("tutte le sessioni"), "{frase}");

        let mut in_sessione = query("droga", 0, false);
        in_sessione.session = Some(SessionId::new(7));
        assert!(
            in_sessione.as_sentence().contains("una sola sessione"),
            "l'ambito si dice"
        );
    }

    /// **Il confronto fra i motori distingue tre esiti, non due.**
    ///
    /// # Il difetto che questa prova impedisce
    ///
    /// Un `bool`. «Confrontabile» e «non confrontabile» lascerebbero fuori il
    /// terzo caso, che è il più insidioso: righe che **non registrano** quale
    /// motore le abbia valutate. Non sono né uguali né diverse — sono **non
    /// misurate**, e trattarle come uguali direbbe una cosa che nessuno sa
    /// (ADR-0053).
    #[test]
    fn il_confronto_distingue_tre_esiti() {
        let uguale = EngineDrift {
            at_save: 1,
            now: 1,
            graded_differently: 0,
            not_recorded: 0,
            total: 42,
        };
        assert!(uguale.is_comparable());
        assert!(uguale.as_sentence().contains("lo stesso in forza"));

        let diverso = EngineDrift {
            at_save: 1,
            now: 2,
            graded_differently: 5,
            not_recorded: 0,
            total: 42,
        };
        assert!(!diverso.is_comparable());
        let frase = diverso.as_sentence();
        assert!(frase.contains("versione 1"), "{frase}");
        assert!(frase.contains("5 righe su 42"), "{frase}");

        // IL TERZO ESITO: la versione non e' cambiata, ma alcune righe non
        // dicono da chi siano state valutate.
        let non_misurato = EngineDrift {
            at_save: 1,
            now: 1,
            graded_differently: 0,
            not_recorded: 7,
            total: 42,
        };
        assert!(
            !non_misurato.is_comparable(),
            "«non registrato» non e' «uguale»"
        );
        assert!(
            non_misurato.as_sentence().contains("non registrano"),
            "{}",
            non_misurato.as_sentence()
        );
    }

    /// **Il conteggio distingue registrato-diverso da non registrato.**
    ///
    /// # Il difetto che questa prova impedisce
    ///
    /// Che le righe **senza** versione registrata vengano contate come
    /// concordi. Direbbe che quelle righe sono state valutate dallo stesso
    /// motore, e nessuno lo sa: sono i contenuti anteriori a ENGINE-01.
    ///
    /// # Perché questa prova esiste qui e non nel servizio
    ///
    /// Perché nel servizio **non si può costruire il caso**. Ogni contenuto
    /// viene inserito con la versione del motore che sta girando, quindi una
    /// prova che passi di lì vede sempre zero e resta verde qualunque cosa il
    /// conteggio faccia. Lo ha dimostrato un controllo negativo: tolto il ramo
    /// che conta le non registrate, **nessuna prova era diventata rossa**.
    #[test]
    fn il_conteggio_distingue_il_diverso_dal_non_registrato() {
        let registrate = [Some(1), Some(1), Some(2), None, None, None];
        let confronto = EngineDrift::between(1, 1, registrate.into_iter());

        assert_eq!(confronto.total, 6);
        assert_eq!(confronto.graded_differently, 1, "una sola e' la versione 2");
        assert_eq!(confronto.not_recorded, 3, "tre non dicono da chi");
        assert!(
            !confronto.is_comparable(),
            "con tre righe non registrate non e' confrontabile"
        );

        // TUTTE CONCORDI: e' il solo caso confrontabile.
        let concordi = EngineDrift::between(1, 1, [Some(1), Some(1)].into_iter());
        assert!(concordi.is_comparable());
        assert_eq!(concordi.not_recorded, 0);
        assert_eq!(concordi.graded_differently, 0);

        // NESSUNA RIGA: confrontabile, e il totale lo dice.
        let vuoto = EngineDrift::between(1, 1, core::iter::empty());
        assert!(vuoto.is_comparable());
        assert_eq!(vuoto.total, 0);
    }

    /// **La frase del confronto dice i numeri, non «attenzione».**
    ///
    /// # Perché conta
    ///
    /// ADR-0051 lo ha già stabilito per le versioni di un contenuto: **la
    /// relazione esatta**, mai un allarme vago. Un avviso generico non si può
    /// usare, e chi lo vede tutti i giorni smette di leggerlo.
    #[test]
    fn la_frase_del_confronto_dice_i_numeri() {
        let frase = EngineDrift {
            at_save: 1,
            now: 2,
            graded_differently: 5,
            not_recorded: 7,
            total: 42,
        }
        .as_sentence();

        for numero in ["1", "2", "5", "7", "42"] {
            assert!(frase.contains(numero), "manca «{numero}» \u{2014} {frase}");
        }
        // E NON ACCUSA I RISULTATI: dice che i metri erano diversi.
        assert!(
            frase.contains("non significa che i risultati siano sbagliati")
                || frase.contains("Non significa che i risultati siano sbagliati"),
            "{frase}"
        );
    }

    /// **Una ricerca salvata non conserva i risultati.**
    ///
    /// # Il difetto che questa prova impedisce
    ///
    /// Una fotografia che invecchia e che, riaperta, sembra attuale. È la
    /// stessa ragione per cui workspace e segnalibri riferiscono senza copiare
    /// — e qui sarebbe peggio, perché un elenco di risultati vecchi si legge
    /// come un elenco di risultati.
    #[test]
    fn una_ricerca_salvata_non_conserva_i_risultati() {
        let Some((produzione, _)) = THIS_MODULE.split_once("#[cfg(test)]\nmod tests {") else {
            panic!("il modulo deve avere un blocco di prove riconoscibile");
        };
        const INTESTAZIONE: &str = "pub struct SavedSearch {";
        let Some(inizio) = produzione.find(INTESTAZIONE) else {
            panic!("il tipo deve esistere");
        };
        let campi = &produzione[inizio + INTESTAZIONE.len()..];
        let Some(fine) = campi.find("\n}\n") else {
            panic!("il tipo deve chiudersi");
        };
        for risultato in [
            "entries",
            "results",
            "risultati",
            "contents",
            "matches",
            "rows",
        ] {
            assert!(
                !campi[..fine].contains(risultato),
                "la ricerca salvata dichiara «{risultato}»: conserverebbe una fotografia che \
                 invecchia e che, riaperta, sembra attuale"
            );
        }
    }

    /// **La ricerca salvata porta chi e quando, e la frase lo dice.**
    #[test]
    fn la_ricerca_salvata_porta_chi_e_quando() {
        let salvata = SavedSearch {
            id: SavedSearchId::new(1),
            name: nome("Droga di marzo"),
            query: query("droga", 3, false),
            engine_version: engine_in_force(),
            created_by: attore(),
            created_at: Timestamp::from_millis(ORA),
        };
        let frase = salvata.as_sentence();
        assert!(frase.contains("operatore.prova"), "{frase}");
        assert!(frase.contains("droga"), "{frase}");
    }

    /// **La versione in forza si legge da un punto solo.**
    #[test]
    fn la_versione_in_forza_si_legge_da_un_punto_solo() {
        assert_eq!(engine_in_force(), crate::analysis::ENGINE_VERSION);
    }
}
