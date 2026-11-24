//! «Che cosa direbbe, di questo contenuto, il motore di oggi?»
//!
//! # Le due frasi, e perché sono due
//!
//! Il congelamento di prodotto le detta quasi alla lettera:
//!
//! - «Al momento dell'acquisizione il motore v*Y* ha prodotto il livello *N*.»
//! - «Con il motore v*X* questo contenuto avrebbe il livello *M*.»
//!
//! La prima è un **fatto**: è successo, è registrato, e nulla lo cambia. La
//! seconda è un'**ipotesi**: nessuno l'ha mai applicata a nulla, non è entrata
//! in alcun rapporto, non ha prodotto alcun avviso.
//!
//! Tenerle su due righe, con due verbi diversi — «ha prodotto» e «avrebbe» —
//! è la sola cosa che impedisce di leggerle come due misure della stessa cosa.
//!
//! # La garanzia strutturale: un'ipotesi non può diventare un fatto
//!
//! [`HypotheticalLevel`] **non è** [`AnalysisLevel`] e **non può diventarlo**:
//! non esiste una conversione, né esplicita né implicita. Non c'è `From`, non
//! c'è `Into`, non c'è un accessore che restituisca un `AnalysisLevel`. Il solo
//! ponte fra i due è [`HypotheticalLevel::agrees_with`], che **confronta** e
//! non converte.
//!
//! Chi provasse a scrivere il livello ipotetico dove si attende quello storico
//! non otterrebbe un difetto sottile: non compilerebbe.
//!
//! È la stessa forma di garanzia di LAB-01, dove il laboratorio non può
//! scrivere perché non conosce l'archivio: qui il replay non può sostituire
//! perché il tipo non passa.
//!
//! # Questo modulo non conosce l'archivio
//!
//! Come il Rule Lab: riceve i contenuti già letti e restituisce un confronto.
//! Non può riscrivere il livello storico perché non ha nulla con cui scrivere,
//! e una prova negativa lo impone.
//!
//! # A che cosa una differenza è attribuibile, e quando non lo è
//!
//! È la parte che questo modulo esiste per non sbagliare.
//!
//! | Motore registrato | Una differenza è… |
//! |---|---|
//! | diverso da quello di adesso | attribuibile al **cambio di motore** |
//! | uguale a quello di adesso | **non** attribuibile al motore: viene da altro |
//! | **non registrato** | non attribuibile a nulla: non si sa che cosa confrontare |
//!
//! La terza riga è quella che conta di più oggi, perché i contenuti anteriori a
//! ENGINE-01 sono tutti in quel caso.

use lisi_core::ContentId;
use lisi_core::analysis::{ENGINE_VERSION, analyse};
use lisi_core::model::AnalysisLevel;
use lisi_core::model::dictionary::ResolvedDictionaryConfiguration;

/// Il livello che il motore di oggi produrrebbe: **un'ipotesi**.
///
/// # Perché non è un `AnalysisLevel`
///
/// Perché un `AnalysisLevel` è ciò che l'archivio conserva, ciò che i rapporti
/// citano e ciò su cui gli avvisi sono stati emessi. Questo numero non è
/// nessuna di quelle cose: è la risposta a una domanda che qualcuno si è posto
/// oggi, e non è mai stata applicata a niente.
///
/// Condividere il tipo renderebbe possibile passarlo dove si attende il fatto —
/// in un rapporto, in un alert, in una scrittura — e nessuno se ne
/// accorgerebbe, perché i due numeri si assomigliano.
///
/// **Non esiste alcuna conversione verso [`AnalysisLevel`]**, e non deve
/// esistere: il solo ponte è [`Self::agrees_with`], che confronta.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HypotheticalLevel(u8);

impl HypotheticalLevel {
    /// Il numero, con un nome che dice che cosa è.
    ///
    /// Si chiama così e non `get` perché chi lo legge in un punto lontano dal
    /// replay deve vedere, nel nome stesso, che non sta maneggiando un livello
    /// registrato.
    #[must_use]
    pub const fn hypothetical_value(self) -> u8 {
        self.0
    }

    /// Se l'ipotesi coincide con il fatto.
    ///
    /// **È l'unico ponte fra i due tipi, ed è un confronto**: non restituisce
    /// un livello, non ne costruisce uno, e non permette di ottenere un
    /// `AnalysisLevel` da un'ipotesi.
    #[must_use]
    pub fn agrees_with(self, stored: AnalysisLevel) -> bool {
        self.0 == stored.get()
    }
}

/// Un contenuto archiviato, come il replay lo vede.
///
/// Quattro cose: quale contenuto, che cosa dice, che livello risulta e quale
/// motore lo produsse. Nient'altro: l'autore, la fonte e gli istanti non
/// servono a rieseguire un'analisi, e ciò che non entra non si può mostrare per
/// sbaglio.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReplayInput {
    /// Quale contenuto.
    pub content_id: ContentId,
    /// Il corpo su cui il motore lavora.
    pub body: String,
    /// Il livello **registrato**: il fatto, immutabile.
    pub stored_level: AnalysisLevel,
    /// Quale motore lo produsse, quando risulta.
    ///
    /// `None` per i contenuti anteriori a ENGINE-01: non si sa.
    pub recorded_engine: Option<u32>,
}

/// A che cosa una differenza è attribuibile.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Attribution {
    /// Il motore registrato è diverso da quello di adesso.
    EngineChanged,
    /// Il motore è lo stesso: la differenza viene da altro.
    NotTheEngine,
    /// Il motore registrato non risulta: non si sa che cosa confrontare.
    Unknown,
}

/// Che cosa il replay ha trovato su un contenuto.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReplayFinding {
    /// Quale contenuto.
    pub content_id: ContentId,
    /// Il fatto: il livello registrato.
    pub stored_level: AnalysisLevel,
    /// Il fatto: quale motore lo produsse, quando risulta.
    pub recorded_engine: Option<u32>,
    /// L'ipotesi: che cosa direbbe il motore di adesso.
    pub hypothetical: HypotheticalLevel,
    /// Quale motore ha prodotto l'ipotesi.
    pub replay_engine: u32,
}

impl ReplayFinding {
    /// Se l'ipotesi coincide con il fatto.
    #[must_use]
    pub fn agrees(&self) -> bool {
        self.hypothetical.agrees_with(self.stored_level)
    }

    /// A che cosa una differenza sarebbe attribuibile.
    ///
    /// Si calcola **anche quando non c'è differenza**: dice che cosa si
    /// starebbe confrontando, ed è ciò che rende leggibile un accordo. Due
    /// livelli uguali prodotti da motori diversi sono un'informazione; due
    /// livelli uguali prodotti dallo stesso motore non lo sono.
    #[must_use]
    pub fn attribution(&self) -> Attribution {
        match self.recorded_engine {
            None => Attribution::Unknown,
            Some(registrato) if registrato == self.replay_engine => Attribution::NotTheEngine,
            Some(_) => Attribution::EngineChanged,
        }
    }

    /// **Il fatto.** «Al momento dell'acquisizione il motore v*Y* ha prodotto
    /// il livello *N*.»
    ///
    /// Il verbo è al passato e all'indicativo, e non è un dettaglio di stile:
    /// è successo.
    #[must_use]
    pub fn historical_sentence(&self) -> String {
        match self.recorded_engine {
            Some(versione) => format!(
                "Al momento dell'acquisizione il motore di analisi v{versione} ha prodotto \
                 il livello {}.",
                self.stored_level.get()
            ),
            None => format!(
                "Al momento dell'acquisizione è stato prodotto il livello {}. Quale motore \
                 lo abbia prodotto NON RISULTA: questo contenuto fu analizzato prima che il \
                 motore avesse un numero.",
                self.stored_level.get()
            ),
        }
    }

    /// **L'ipotesi.** «Con il motore v*X* questo contenuto avrebbe il livello
    /// *M*.»
    ///
    /// Il verbo è al condizionale, e non è un dettaglio di stile: non è
    /// successo, e non succederà per il fatto di averlo calcolato.
    #[must_use]
    pub fn hypothetical_sentence(&self) -> String {
        format!(
            "Con il motore di analisi v{} questo contenuto avrebbe il livello {}. \
             È un'ipotesi: non è stata applicata a nulla, non ha prodotto alcun avviso e \
             non entra in alcun rapporto.",
            self.replay_engine,
            self.hypothetical.hypothetical_value()
        )
    }

    /// Che cosa il confronto permette di dire, e che cosa no.
    #[must_use]
    pub fn attribution_sentence(&self) -> String {
        match (self.attribution(), self.agrees()) {
            (Attribution::Unknown, _) => String::from(
                "Non si sa quale motore abbia prodotto il livello registrato. Quindi una \
                 differenza non sarebbe attribuibile a nulla: potrebbe venire dal motore, dalla \
                 configurazione di allora, o da entrambi.",
            ),
            (Attribution::NotTheEngine, true) => String::from(
                "Il motore è lo stesso di allora, e il livello coincide. La rilettura ha \
                 confrontato il motore attuale con se stesso: non c'era una differenza da \
                 attribuire.",
            ),
            (Attribution::NotTheEngine, false) => String::from(
                "Il motore è lo stesso di allora, quindi questa differenza NON viene dal \
                 motore. Viene dalla configurazione di dizionario usata per la rilettura, che \
                 non è quella con cui il contenuto fu analizzato.",
            ),
            (Attribution::EngineChanged, true) => String::from(
                "Il motore è cambiato dopo l'acquisizione, e il livello coincide comunque: \
                 su questo contenuto il cambiamento non ha effetto.",
            ),
            (Attribution::EngineChanged, false) => String::from(
                "Il motore è cambiato dopo l'acquisizione, e questa differenza è \
                 attribuibile al cambiamento. Il livello registrato resta quello valido: \
                 l'analisi non viene rifatta.",
            ),
        }
    }
}

/// L'esito di un replay.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReplayComparison {
    /// Un riscontro per contenuto, nell'ordine ricevuto.
    pub findings: Vec<ReplayFinding>,
    /// Quanti contenuti sono stati riesaminati.
    pub examined: usize,
}

impl ReplayComparison {
    /// Su quanti l'ipotesi non coincide con il fatto.
    #[must_use]
    pub fn differing(&self) -> usize {
        self.findings
            .iter()
            .filter(|finding| !finding.agrees())
            .count()
    }

    /// Su quanti non si sa quale motore abbia prodotto il livello.
    #[must_use]
    pub fn without_recorded_engine(&self) -> usize {
        self.findings
            .iter()
            .filter(|finding| finding.attribution() == Attribution::Unknown)
            .count()
    }

    /// La frase dell'esito.
    ///
    /// # Perché dice quando il confronto è fra il motore e se stesso
    ///
    /// Perché finché esiste **una sola** versione del motore, il replay
    /// confronta il motore corrente con se stesso, e una differenza non
    /// verrebbe da lì. Tacerlo lascerebbe credere di aver misurato un
    /// cambiamento che nessuno ha fatto.
    #[must_use]
    pub fn as_sentence(&self) -> String {
        if self.examined == 0 {
            return String::from(
                "Nessun contenuto riesaminato: la rilettura non dice nulla del motore.",
            );
        }

        let mut frase = format!("{} contenuti riesaminati", self.examined);
        if self.differing() > 0 {
            frase.push_str(&format!(
                ", su {} l'ipotesi non coincide con il livello registrato",
                self.differing()
            ));
        } else {
            frase.push_str(", l'ipotesi coincide ovunque con il livello registrato");
        }
        frase.push('.');

        if self.without_recorded_engine() > 0 {
            frase.push_str(&format!(
                " Su {} di essi non risulta quale motore abbia prodotto il livello: una \
                 differenza non sarebbe attribuibile al motore né a nient'altro.",
                self.without_recorded_engine()
            ));
        }

        // Tutti i contenuti analizzati dal motore di adesso. Dal 2026-10-23 le
        // versioni del motore sono due (DICT-CODES-01, ADR-0170): i contenuti
        // della versione 1 ricadono in «il motore è cambiato».
        let tutti_stesso_motore = self
            .findings
            .iter()
            .all(|finding| finding.attribution() == Attribution::NotTheEngine);
        if tutti_stesso_motore && !self.findings.is_empty() {
            frase.push_str(
                " Tutti i contenuti riesaminati erano stati analizzati dal motore che gira \
                 adesso: questa rilettura ha confrontato il motore attuale con se stesso.",
            );
        }

        frase
    }
}

/// Riesegue l'analisi su contenuti archiviati con il motore di **adesso**.
///
/// # Che cosa questa funzione non ha, ed è la garanzia
///
/// Non ha un archivio, non ha un attore, non ha un istante. **Non può
/// riscrivere il livello storico perché non ha nulla con cui scrivere**, ed è
/// la stessa garanzia di LAB-01: non un divieto da ricordare, l'assenza della
/// capacità.
///
/// # Perché la configurazione arriva da fuori
///
/// Perché il replay ha senso solo con la configurazione **di quella sessione**:
/// riesaminare con i dizionari di oggi misurerebbe insieme il cambio di motore
/// e il cambio di dizionari, e non si saprebbe quale dei due abbia mosso il
/// livello. Chi chiama passa la fotografia della sessione; quando non ce l'ha,
/// il risultato lo dichiara attraverso [`Attribution::NotTheEngine`].
#[must_use]
pub fn replay(
    inputs: &[ReplayInput],
    configuration: &ResolvedDictionaryConfiguration,
) -> ReplayComparison {
    let findings = inputs
        .iter()
        .map(|input| {
            let analizzato = analyse(&input.body, configuration);
            ReplayFinding {
                content_id: input.content_id,
                stored_level: input.stored_level,
                recorded_engine: input.recorded_engine,
                hypothetical: HypotheticalLevel(analizzato.outcome.level.get()),
                replay_engine: ENGINE_VERSION,
            }
        })
        .collect();

    ReplayComparison {
        findings,
        examined: inputs.len(),
    }
}

#[cfg(test)]
mod tests {
    use lisi_core::ContentId;
    use lisi_core::analysis::ENGINE_VERSION;
    use lisi_core::model::AnalysisLevel;
    use lisi_core::model::dictionary::{MatchMode, ResolvedDictionaryConfiguration, ResolvedTerm};
    use lisi_core::text::{LanguageTag, TermCategory, TermText};

    use super::{Attribution, HypotheticalLevel, ReplayInput, replay};

    /// Questo modulo, per le guardie strutturali.
    const THIS_MODULE: &str = include_str!("replay.rs");

    /// Una configurazione con i termini indicati.
    fn configurazione(termini: &[(&str, i8)]) -> ResolvedDictionaryConfiguration {
        let risolti: Vec<ResolvedTerm> = termini
            .iter()
            .map(|(testo, livello)| {
                let (Ok(original), Ok(language), Ok(category)) = (
                    TermText::try_new(testo),
                    LanguageTag::try_new("it"),
                    TermCategory::try_new("prova"),
                ) else {
                    panic!("i valori di prova devono essere validi");
                };
                ResolvedTerm {
                    normalised: testo.to_lowercase(),
                    original,
                    category,
                    language,
                    match_mode: MatchMode::NormalizedWord,
                    suggested_level: *livello,
                    provenances: Vec::new(),
                }
            })
            .collect();

        ResolvedDictionaryConfiguration::from_terms(risolti)
    }

    fn livello(valore: u8) -> AnalysisLevel {
        let Ok(livello) = AnalysisLevel::try_new(valore) else {
            panic!("il livello di prova deve essere valido");
        };
        livello
    }

    fn contenuto(id: i64, body: &str, stored: u8, engine: Option<u32>) -> ReplayInput {
        ReplayInput {
            content_id: ContentId::new(id),
            body: body.to_owned(),
            stored_level: livello(stored),
            recorded_engine: engine,
        }
    }

    /// Il codice di produzione senza i commenti.
    fn codice_senza_commenti() -> String {
        let Some((produzione, _)) = THIS_MODULE.split_once("#[cfg(test)]\nmod tests {") else {
            panic!("il modulo deve avere un blocco di prove riconoscibile");
        };
        produzione
            .lines()
            .filter(|riga| !riga.trim_start().starts_with("//"))
            .collect::<Vec<_>>()
            .join("\n")
    }

    /// **Un'ipotesi non può diventare un fatto.**
    ///
    /// # Il difetto che questa prova impedisce
    ///
    /// I due numeri si assomigliano: sono entrambi da 0 a 4, e in una riga di
    /// codice lontana dal replay nessuno distinguerebbe il livello registrato
    /// da quello ipotetico. Se condividessero il tipo, passare l'ipotesi dove
    /// si attende il fatto — in un rapporto, in un avviso, in una scrittura —
    /// sarebbe un difetto che compila e che nessuno vede.
    ///
    /// Qui non compila, e questa prova impedisce che qualcuno apra la strada
    /// aggiungendo una conversione «per comodità».
    #[test]
    fn un_ipotesi_non_puo_diventare_un_fatto() {
        let codice = codice_senza_commenti();

        for ponte in [
            "impl From<HypotheticalLevel>",
            "impl From<AnalysisLevel> for HypotheticalLevel",
            "fn into_analysis_level",
            "fn as_analysis_level",
            "AnalysisLevel::try_new(self.0",
            "impl Deref for HypotheticalLevel",
        ] {
            assert!(
                !codice.contains(ponte),
                "il replay dichiara «{ponte}»: un livello ipotetico non deve poter \
                 diventare un livello registrato, e il solo ponte ammesso e' il \
                 confronto `agrees_with`"
            );
        }

        // Il solo ponte esiste, ed e' un confronto: restituisce un booleano.
        let ipotesi = HypotheticalLevel(3);
        let _: bool = ipotesi.agrees_with(livello(3));
        let _: u8 = ipotesi.hypothetical_value();
    }

    /// **Il replay non ha alcun modo di riscrivere il livello storico.**
    #[test]
    fn il_replay_non_ha_alcun_modo_di_scrivere() {
        let codice = codice_senza_commenti();

        for capacita in [
            "Database",
            "insert_",
            "update_",
            "append_audit",
            "&mut self",
        ] {
            assert!(
                !codice.contains(capacita),
                "il replay nomina «{capacita}»: il risultato storico e' immutabile, e la \
                 garanzia non e' un divieto da ricordare ma l'assenza della capacita'"
            );
        }
    }

    /// Le due frasi usano due verbi diversi, e non si possono confondere.
    ///
    /// «ha prodotto» è un fatto; «avrebbe» è un'ipotesi. Su due righe con lo
    /// stesso verbo si leggerebbero come due misure della stessa cosa.
    #[test]
    fn il_fatto_e_l_ipotesi_usano_due_verbi_diversi() {
        let configurazione = configurazione(&[("alfa", 2)]);
        let esito = replay(
            &[contenuto(1, "contiene alfa", 2, Some(ENGINE_VERSION))],
            &configurazione,
        );

        let finding = &esito.findings[0];
        let fatto = finding.historical_sentence();
        let ipotesi = finding.hypothetical_sentence();

        assert!(
            fatto.contains("ha prodotto"),
            "il fatto e' al passato: «{fatto}»"
        );
        assert!(
            ipotesi.contains("avrebbe"),
            "l'ipotesi e' al condizionale: «{ipotesi}»"
        );
        assert!(
            ipotesi.contains("non e' stata applicata a nulla")
                || ipotesi.contains("non è stata applicata a nulla"),
            "l'ipotesi deve dichiarare di non aver prodotto effetti: «{ipotesi}»"
        );
    }

    /// **Con il motore non registrato, nessuna differenza è attribuibile.**
    ///
    /// # Il difetto che questa prova impedisce
    ///
    /// I contenuti anteriori a ENGINE-01 non portano alcun numero di motore.
    /// Attribuire al cambio di motore una loro differenza sarebbe inventare:
    /// non si sa nemmeno se il motore sia cambiato.
    #[test]
    fn senza_motore_registrato_nulla_e_attribuibile() {
        let configurazione = configurazione(&[("alfa", 4)]);
        let esito = replay(&[contenuto(1, "contiene alfa", 1, None)], &configurazione);

        let finding = &esito.findings[0];
        assert_eq!(finding.attribution(), Attribution::Unknown);
        assert!(
            !finding.agrees(),
            "i livelli devono differire in questa prova"
        );

        let frase = finding.attribution_sentence();
        assert!(
            frase.contains("non sarebbe attribuibile a nulla"),
            "la ragione va dichiarata: «{frase}»"
        );
        assert!(
            !frase.contains("è attribuibile al cambiamento"),
            "senza il motore registrato non si puo' attribuire al motore"
        );

        assert!(
            esito.as_sentence().contains("non risulta quale motore"),
            "l'esito complessivo deve dirlo: «{}»",
            esito.as_sentence()
        );
    }

    /// **Con lo stesso motore, una differenza NON viene dal motore.**
    ///
    /// È il caso di oggi, perché esiste una sola versione del motore: una
    /// differenza verrebbe dalla configurazione di dizionario passata al
    /// replay, che non è quella con cui il contenuto fu analizzato.
    #[test]
    fn con_lo_stesso_motore_la_differenza_non_viene_dal_motore() {
        let configurazione = configurazione(&[("alfa", 4)]);
        let esito = replay(
            &[contenuto(1, "contiene alfa", 1, Some(ENGINE_VERSION))],
            &configurazione,
        );

        let finding = &esito.findings[0];
        assert_eq!(finding.attribution(), Attribution::NotTheEngine);

        let frase = finding.attribution_sentence();
        assert!(
            frase.contains("NON viene dal motore"),
            "la ragione va dichiarata: «{frase}»"
        );
        assert!(frase.contains("configurazione"), "e va detto da dove viene");
    }

    /// Con un motore diverso, la differenza è attribuibile al cambiamento —
    /// e il livello registrato resta quello valido.
    #[test]
    fn con_un_motore_diverso_la_differenza_e_del_motore_e_lo_storico_resta() {
        let configurazione = configurazione(&[("alfa", 4)]);
        // Un motore che non e' quello di adesso: il caso che si presentera' al
        // primo cambio di formula.
        let esito = replay(
            &[contenuto(1, "contiene alfa", 1, Some(ENGINE_VERSION + 1))],
            &configurazione,
        );

        let finding = &esito.findings[0];
        assert_eq!(finding.attribution(), Attribution::EngineChanged);
        assert_eq!(
            finding.stored_level,
            livello(1),
            "il livello registrato non deve essere toccato dal replay"
        );

        let frase = finding.attribution_sentence();
        assert!(frase.contains("attribuibile al cambiamento"));
        assert!(
            frase.contains("resta quello valido"),
            "il fatto storico resta valido: «{frase}»"
        );
    }

    /// L'esito dichiara quando il confronto è fra il motore e se stesso.
    ///
    /// Finché esiste una sola versione, è sempre così, e tacerlo lascerebbe
    /// credere di aver misurato un cambiamento che nessuno ha fatto.
    #[test]
    fn l_esito_dichiara_il_confronto_del_motore_con_se_stesso() {
        let configurazione = configurazione(&[("alfa", 2)]);
        let esito = replay(
            &[
                contenuto(1, "contiene alfa", 2, Some(ENGINE_VERSION)),
                contenuto(2, "niente", 0, Some(ENGINE_VERSION)),
            ],
            &configurazione,
        );

        let frase = esito.as_sentence();
        assert!(
            frase.contains("con se stesso"),
            "l'esito deve dire che il motore e' stato confrontato con se stesso: «{frase}»"
        );
    }

    /// Zero contenuti non sono un accordo.
    ///
    /// «L'ipotesi coincide ovunque» detto di un insieme vuoto farebbe credere
    /// che il motore sia stato verificato quando non ha guardato niente.
    #[test]
    fn senza_contenuti_il_replay_non_dice_nulla() {
        let configurazione = configurazione(&[("alfa", 2)]);
        let esito = replay(&[], &configurazione);

        assert_eq!(esito.examined, 0);
        let frase = esito.as_sentence();
        assert!(
            frase.contains("non dice nulla del motore"),
            "zero contenuti non sono una conferma: «{frase}»"
        );
        assert!(!frase.contains("coincide ovunque"));
    }

    /// Il replay è riproducibile: due esecuzioni danno lo stesso esito.
    #[test]
    fn due_esecuzioni_danno_lo_stesso_esito() {
        let configurazione = configurazione(&[("alfa", 3), ("beta", 1)]);
        let contenuti = [
            contenuto(1, "alfa e beta", 3, Some(ENGINE_VERSION)),
            contenuto(2, "solo beta", 1, None),
        ];

        assert_eq!(
            replay(&contenuti, &configurazione),
            replay(&contenuti, &configurazione)
        );
    }
}
