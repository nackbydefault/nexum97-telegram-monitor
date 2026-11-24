//! Le dimensioni della rilevanza, che sono quattro e restano quattro.
//!
//! # Perché non un punteggio solo
//!
//! Un contenuto può essere **tecnicamente rilevante** (parla di un incidente),
//! **rilevante per l'Italia** (riguarda qualcosa che sta qui), **rilevante per
//! un settore** (ricade in un ambito che la norma considera critico) e **grave**
//! (il motore 0-4 gli assegna un livello).
//!
//! Sono quattro domande diverse, e fondere le risposte in un numero solo
//! produrrebbe la peggiore delle confusioni: che *«riguarda l'Italia»* diventi
//! *«è grave»*.
//!
//! ADR-0035 Decisione 10 lo dice, e questo modulo lo rende impossibile per
//! costruzione: **nessuna funzione qui dentro restituisce un livello**, e
//! nessuna prende un livello in ingresso.
//!
//! # Che cosa questo modulo non fa mai
//!
//! Non decide se un contenuto sia grave. Non attribuisce nulla a nessuno. Non
//! dice che un fatto sia avvenuto. Dice **dove ricade ciò che il contenuto
//! nomina**, e chi legge decide.

/// I diciotto settori della NIS2, verificati su fonte ufficiale.
///
/// Fonte: direttiva (UE) 2022/2555, allegati I e II; recepimento italiano
/// d.lgs. 138/2024. Consultata il 2026-08-18 —
/// `docs/dictionaries/PD6_SECTOR_TAXONOMY.md`.
///
/// # Perché un'enumerazione e non un elenco di testo
///
/// Un settore inventato non deve poter esistere. E la tassonomia **scade**: va
/// riverificata quando cambia la direttiva o il decreto, e un tipo chiuso rende
/// visibile il punto in cui aggiornarla.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Sector {
    /// Allegato I.1
    Energia,
    /// Allegato I.2
    Trasporti,
    /// Allegato I.3
    Bancario,
    /// Allegato I.4
    MercatiFinanziari,
    /// Allegato I.5
    Sanita,
    /// Allegato I.6
    AcquaPotabile,
    /// Allegato I.7
    AcqueReflue,
    /// Allegato I.8
    InfrastruttureDigitali,
    /// Allegato I.9
    ServiziTic,
    /// Allegato I.10
    PubblicaAmministrazione,
    /// Allegato I.11
    Spazio,
    /// Allegato II.12
    ServiziPostali,
    /// Allegato II.13
    GestioneRifiuti,
    /// Allegato II.14
    Chimica,
    /// Allegato II.15
    Alimentare,
    /// Allegato II.16
    Fabbricazione,
    /// Allegato II.17
    ServiziDigitali,
    /// Allegato II.18
    Ricerca,
}

impl Sector {
    /// Tutti i settori, nell'ordine degli allegati.
    pub const ALL: &'static [Self] = &[
        Self::Energia,
        Self::Trasporti,
        Self::Bancario,
        Self::MercatiFinanziari,
        Self::Sanita,
        Self::AcquaPotabile,
        Self::AcqueReflue,
        Self::InfrastruttureDigitali,
        Self::ServiziTic,
        Self::PubblicaAmministrazione,
        Self::Spazio,
        Self::ServiziPostali,
        Self::GestioneRifiuti,
        Self::Chimica,
        Self::Alimentare,
        Self::Fabbricazione,
        Self::ServiziDigitali,
        Self::Ricerca,
    ];

    /// Se il settore sta nell'allegato I, quello ad **alta criticità**.
    ///
    /// # Che cosa questo NON significa
    ///
    /// Non significa «più grave». Dice soltanto che, se il fatto fosse vero,
    /// ricadrebbe in un ambito che la norma considera ad alta criticità.
    ///
    /// E vale il rovescio, che è più facile dimenticare: **un settore non
    /// elencato non è un settore che non conta.** La NIS2 elenca gli ambiti in
    /// cui impone obblighi, non tutto ciò che merita attenzione.
    #[must_use]
    pub const fn is_high_criticality(&self) -> bool {
        matches!(
            self,
            Self::Energia
                | Self::Trasporti
                | Self::Bancario
                | Self::MercatiFinanziari
                | Self::Sanita
                | Self::AcquaPotabile
                | Self::AcqueReflue
                | Self::InfrastruttureDigitali
                | Self::ServiziTic
                | Self::PubblicaAmministrazione
                | Self::Spazio
        )
    }

    /// L'etichetta che l'operatore legge.
    #[must_use]
    pub const fn label(&self) -> &'static str {
        match self {
            Self::Energia => "Energia",
            Self::Trasporti => "Trasporti",
            Self::Bancario => "Settore bancario",
            Self::MercatiFinanziari => "Infrastrutture dei mercati finanziari",
            Self::Sanita => "Sanità",
            Self::AcquaPotabile => "Acqua potabile",
            Self::AcqueReflue => "Acque reflue",
            Self::InfrastruttureDigitali => "Infrastrutture digitali",
            Self::ServiziTic => "Gestione dei servizi TIC",
            Self::PubblicaAmministrazione => "Pubblica amministrazione",
            Self::Spazio => "Spazio",
            Self::ServiziPostali => "Servizi postali e di corriere",
            Self::GestioneRifiuti => "Gestione dei rifiuti",
            Self::Chimica => "Sostanze chimiche",
            Self::Alimentare => "Alimentare",
            Self::Fabbricazione => "Fabbricazione",
            Self::ServiziDigitali => "Fornitori di servizi digitali",
            Self::Ricerca => "Ricerca",
        }
    }

    /// L'etichetta stabile, per archivio e documenti.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Energia => "energia",
            Self::Trasporti => "trasporti",
            Self::Bancario => "bancario",
            Self::MercatiFinanziari => "mercati_finanziari",
            Self::Sanita => "sanita",
            Self::AcquaPotabile => "acqua_potabile",
            Self::AcqueReflue => "acque_reflue",
            Self::InfrastruttureDigitali => "infrastrutture_digitali",
            Self::ServiziTic => "servizi_tic",
            Self::PubblicaAmministrazione => "pubblica_amministrazione",
            Self::Spazio => "spazio",
            Self::ServiziPostali => "servizi_postali",
            Self::GestioneRifiuti => "gestione_rifiuti",
            Self::Chimica => "chimica",
            Self::Alimentare => "alimentare",
            Self::Fabbricazione => "fabbricazione",
            Self::ServiziDigitali => "servizi_digitali",
            Self::Ricerca => "ricerca",
        }
    }

    /// Ricostruisce il settore dall'etichetta stabile.
    ///
    /// # Perché l'etichetta e non un numero d'ordine
    ///
    /// Un numero d'ordine cambierebbe significato il giorno in cui la direttiva
    /// aggiungesse un settore in mezzo, e ogni riga già scritta in archivio
    /// direbbe un'altra cosa senza che nulla lo segnali.
    ///
    /// # Errori
    ///
    /// Restituisce [`DomainError::UnknownVariant`] se l'etichetta non
    /// corrisponde ad alcun settore. Un valore sconosciuto letto dall'archivio
    /// indica un archivio alterato, non un errore di chi chiama.
    pub fn try_from_str(value: &str) -> crate::error::DomainResult<Self> {
        Self::ALL
            .iter()
            .find(|settore| settore.as_str() == value)
            .copied()
            .ok_or_else(|| crate::error::unknown_variant("settore NIS2", value))
    }
}

/// Un segnale che un contenuto riguardi l'Italia.
///
/// # Perché segnali e non un punteggio
///
/// Un punteggio direbbe *«rilevanza Italia: 0,7»*, che non significa nulla e che
/// nessuno può contestare. Un elenco di segnali dice *«nomina un dominio .it»*,
/// che chi legge può verificare e, se serve, smentire.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum ItalySignal {
    /// Il contenuto nomina un dominio di primo livello italiano.
    DominioItaliano {
        /// Il dominio, normalizzato.
        dominio: String,
    },
    /// Il contenuto nomina un dominio della pubblica amministrazione italiana.
    ///
    /// Distinto dal precedente perché `gov.it` è un sottoinsieme che dice di
    /// più: `.it` dice «Italia», `gov.it` dice «Italia, e pubblica
    /// amministrazione».
    DominioIstituzionale {
        /// Il dominio, normalizzato.
        dominio: String,
    },
    /// Il contenuto è in italiano.
    ///
    /// **Il segnale più debole di tutti**, e va detto: l'italiano si parla anche
    /// fuori dall'Italia, e un contenuto sull'Italia può essere in inglese.
    LinguaItaliana,
}

impl ItalySignal {
    /// Il segnale, come si scrive in una relazione.
    #[must_use]
    pub fn as_sentence(&self) -> String {
        match self {
            Self::DominioItaliano { dominio } => {
                format!("nomina il dominio italiano «{dominio}»")
            }
            Self::DominioIstituzionale { dominio } => {
                format!("nomina il dominio istituzionale italiano «{dominio}»")
            }
            Self::LinguaItaliana => String::from("è scritto in italiano"),
        }
    }
}

/// Quanto un contenuto riguardi l'Italia, e perché.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ItalyRelevance {
    /// I segnali trovati, in ordine stabile.
    pub signals: Vec<ItalySignal>,
}

impl ItalyRelevance {
    /// Se non è stato trovato alcun segnale.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.signals.is_empty()
    }

    /// Se c'è almeno un segnale più forte della sola lingua.
    ///
    /// # Perché la lingua da sola non basta
    ///
    /// L'italiano si parla anche fuori dall'Italia, e un contenuto sull'Italia
    /// può essere in inglese. Un elenco costruito sulla sola lingua sarebbe un
    /// elenco di contenuti in italiano, che è un'altra cosa.
    #[must_use]
    pub fn has_signal_beyond_language(&self) -> bool {
        self.signals
            .iter()
            .any(|segnale| !matches!(segnale, ItalySignal::LinguaItaliana))
    }

    /// Che cosa si può dire, in una frase.
    ///
    /// # Che cosa la frase non contiene, per costruzione
    ///
    /// Nessun giudizio di gravità. **Riguardare l'Italia non rende grave nulla**:
    /// è la confusione che ADR-0035 Decisione 10 esiste per impedire.
    #[must_use]
    pub fn as_sentence(&self) -> String {
        if self.signals.is_empty() {
            return String::from(
                "Nessun segnale che riguardi l'Italia. Non significa che non la \
                 riguardi: significa che il contenuto non lo dice.",
            );
        }

        let elenco: Vec<String> = self.signals.iter().map(ItalySignal::as_sentence).collect();

        let mut testo = format!("Riguarda l'Italia perché {}.", elenco.join("; "));

        if !self.has_signal_beyond_language() {
            testo.push_str(
                " Il solo segnale è la lingua, che è il più debole: l'italiano \
                 si parla anche fuori dall'Italia.",
            );
        }
        testo
    }
}

/// I domini di primo livello che indicano l'Italia.
const TLD_ITALIANI: &[&str] = &[".it"];

/// I domini che indicano la pubblica amministrazione italiana.
///
/// # Perché non un elenco di enti
///
/// Un elenco di organizzazioni inciso nel codice sarebbe una lista arbitraria
/// che nessuno ha approvato, che invecchia il giorno dopo, e che — distribuita su
/// ogni postazione — direbbe a chiunque la legga quali enti l'ufficio considera
/// bersagli. Qui ci sono **suffissi di dominio**, che sono una regola di
/// denominazione pubblica, non una lista di nomi.
const DOMINI_ISTITUZIONALI: &[&str] = &[".gov.it", ".gob.it"];

/// Riconosce i segnali che un contenuto riguardi l'Italia.
///
/// # Che cosa riceve
///
/// I domini **già estratti** dal contenuto (CY-01) e la lingua dichiarata. Non
/// rianalizza il testo: l'estrazione è già avvenuta, e rifarla qui creerebbe due
/// verità da tenere allineate.
#[must_use]
pub fn assess_italy(domains: &[String], language: Option<&str>) -> ItalyRelevance {
    let mut signals = Vec::new();

    for dominio in domains {
        let minuscolo = dominio.to_lowercase();

        // L'istituzionale si controlla PRIMA: `regione.gov.it` finisce anche in
        // `.it`, e segnalarlo due volte direbbe due cose dove ce n'e' una.
        if DOMINI_ISTITUZIONALI
            .iter()
            .any(|suffisso| minuscolo.ends_with(suffisso))
        {
            signals.push(ItalySignal::DominioIstituzionale { dominio: minuscolo });
            continue;
        }
        if TLD_ITALIANI
            .iter()
            .any(|suffisso| minuscolo.ends_with(suffisso))
        {
            signals.push(ItalySignal::DominioItaliano { dominio: minuscolo });
        }
    }

    if language.is_some_and(|tag| tag.eq_ignore_ascii_case("it")) {
        signals.push(ItalySignal::LinguaItaliana);
    }

    signals.sort();
    signals.dedup();
    ItalyRelevance { signals }
}

// ---------------------------------------------------------------- il settore
//
// La quarta dimensione, e l'ultima a essere collegata. DEC-235 l'aveva lasciata
// scollegata con una ragione precisa — «collegarla richiede una regola che
// assegni un settore a un contenuto, e nessuna regola verificata esiste» — e la
// regola ora c'e': **la dichiara un amministratore**, non il prodotto.
//
// Vedere `crate::model::organisation` per la regola e per il perche' l'elenco
// delle organizzazioni non stia nel sorgente.

/// Perché un contenuto è stato ricondotto a un'organizzazione sorvegliata.
///
/// # Perché il segnale e non solo il settore
///
/// «Questo contenuto riguarda l'energia» è un'affermazione che nessuno può
/// contestare. «Questo contenuto nomina il dominio `esempio.it`, che
/// l'amministratore ha dichiarato per un'organizzazione del settore energia» è
/// un'affermazione che chi legge può verificare e, se serve, smentire.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum SectorSignal {
    /// Il contenuto nomina un dominio dichiarato per l'organizzazione.
    ///
    /// È il segnale **più solido**: chi registra un dominio è uno solo, mentre
    /// un nome può essere ambiguo o omonimo.
    DominioDichiarato {
        /// Il dominio dichiarato che ha riscontrato.
        dominio: String,
    },
    /// Il contenuto nomina un nome dichiarato per l'organizzazione.
    ///
    /// Più debole del dominio: una ragione sociale può coincidere con una
    /// parola comune, e il prodotto non ha modo di distinguerle.
    NomeDichiarato {
        /// Il nome, nella forma scritta dall'amministratore.
        nome: String,
    },
}

impl SectorSignal {
    /// Il segnale, come si scrive in una relazione.
    #[must_use]
    pub fn as_sentence(&self) -> String {
        match self {
            Self::DominioDichiarato { dominio } => {
                format!("nomina il dominio dichiarato «{dominio}»")
            }
            Self::NomeDichiarato { nome } => format!("nomina «{nome}»"),
        }
    }
}

/// Un settore attribuito a un contenuto, con tutto ciò che serve a contestarlo.
///
/// # Perché nessun campo è facoltativo
///
/// Un'attribuzione senza provenienza è un'attribuzione inventata, ed è
/// esattamente ciò che DEC-235 esisteva per impedire. Il tipo non permette di
/// costruirne una: **non esiste un percorso che produca un `Sector` senza dire
/// da dove viene**, e una prova lo verifica.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct SectorAttribution {
    /// Il settore in cui l'amministratore ha collocato l'organizzazione.
    pub sector: Sector,
    /// Identificativo dell'organizzazione sorvegliata, per risalire alla
    /// dichiarazione.
    pub organisation_id: i64,
    /// Il nome dell'organizzazione, come l'amministratore l'ha scritto.
    pub organisation: String,
    /// Che cosa ha fatto scattare il riscontro.
    pub signal: SectorSignal,
    /// Chi ha dichiarato l'organizzazione.
    pub declared_by: String,
}

impl SectorAttribution {
    /// L'attribuzione, come si scrive in una relazione.
    ///
    /// # Che cosa la frase dice, e che cosa non dice
    ///
    /// Dice che il contenuto **nomina** un'organizzazione che qualcuno ha
    /// collocato in un settore. Non dice che l'organizzazione sia stata colpita,
    /// che il fatto sia avvenuto, né che il contenuto sia grave.
    #[must_use]
    pub fn as_sentence(&self) -> String {
        format!(
            "{} — «{}», che {}. Settore dichiarato da {}.",
            self.sector.label(),
            self.organisation,
            self.signal.as_sentence(),
            self.declared_by
        )
    }
}

/// I settori a cui un contenuto è stato ricondotto, e perché.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SectorRelevance {
    /// Le attribuzioni trovate, in ordine stabile.
    pub attributions: Vec<SectorAttribution>,
}

impl SectorRelevance {
    /// Se non è stata trovata alcuna attribuzione.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.attributions.is_empty()
    }

    /// I settori distinti toccati, in ordine.
    ///
    /// Un contenuto che nomina tre organizzazioni della sanità tocca **un**
    /// settore, non tre: contarlo tre volte farebbe sembrare più esteso ciò che
    /// il contenuto dice.
    #[must_use]
    pub fn sectors(&self) -> Vec<Sector> {
        let mut elenco: Vec<Sector> = self
            .attributions
            .iter()
            .map(|attribuzione| attribuzione.sector)
            .collect();
        elenco.sort();
        elenco.dedup();
        elenco
    }

    /// Se almeno un settore toccato sta nell'allegato I della NIS2.
    ///
    /// # Che cosa questo NON significa
    ///
    /// Non significa «più grave». Dice che, **se il fatto fosse vero**,
    /// ricadrebbe in un ambito che la norma considera ad alta criticità.
    #[must_use]
    pub fn touches_high_criticality(&self) -> bool {
        self.attributions
            .iter()
            .any(|attribuzione| attribuzione.sector.is_high_criticality())
    }

    /// Che cosa si può dire, in una frase.
    #[must_use]
    pub fn as_sentence(&self) -> String {
        if self.attributions.is_empty() {
            return String::from(
                "Nessun settore. Non significa che non ne riguardi uno: significa \
                 che il contenuto non nomina alcuna organizzazione fra quelle \
                 dichiarate.",
            );
        }

        let elenco: Vec<String> = self
            .attributions
            .iter()
            .map(SectorAttribution::as_sentence)
            .collect();

        format!(
            "{}\n\nUn settore dell'allegato I non rende grave nulla: dice in quale \
             ambito ricadrebbe il fatto, se fosse vero.",
            elenco.join("\n")
        )
    }
}

/// Riconosce i settori a cui un contenuto può essere ricondotto.
///
/// # La regola, per intero
///
/// Per ogni organizzazione **attiva** dichiarata dall'amministratore:
///
/// 1. se il contenuto nomina uno dei suoi **domini** — o un sottodominio — vale
///    quello, ed è il segnale più solido;
/// 2. altrimenti, se il testo normalizzato contiene uno dei suoi **nomi** come
///    parola intera, vale quello.
///
/// Un'organizzazione produce **al più un'attribuzione**: nominarla due volte non
/// la rende due riscontri.
///
/// # Che cosa riceve, e perché non rianalizza nulla
///
/// Il corpo del contenuto e i domini **già estratti** da CY-01. Rifare qui
/// l'estrazione creerebbe due verità da tenere allineate — lo stesso motivo per
/// cui [`assess_italy`] riceve i domini invece di ricavarli.
///
/// # Che cosa non fa, mai
///
/// Non restituisce un livello e non ne prende uno. Non deduce un settore dal
/// testo. Un'organizzazione **disattivata** non produce alcuna attribuzione: è
/// la ragione per cui si disattiva invece di cancellare.
#[must_use]
pub fn assess_sectors(
    body: &str,
    domains: &[String],
    watchlist: &[crate::model::organisation::WatchedOrganisation],
) -> SectorRelevance {
    // La normalizzazione del corpo avviene **una volta sola**, non per
    // organizzazione: con qualche centinaio di organizzazioni dichiarate il
    // costo si moltiplicherebbe per quel numero.
    let normalizzato: Vec<char> = crate::model::dictionary::normalise_for_matching(body)
        .chars()
        .collect();

    let mut attributions = Vec::new();

    for organizzazione in watchlist {
        if !organizzazione.active {
            continue;
        }

        // Il dominio prima del nome: quando entrambi riscontrano si mostra il
        // piu' solido, invece di due righe che dicono la stessa cosa.
        let per_dominio = organizzazione.domains.iter().find_map(|dichiarato| {
            domains
                .iter()
                .find(|osservato| dichiarato.matches(osservato))
                .map(|_| SectorSignal::DominioDichiarato {
                    dominio: dichiarato.as_str().to_owned(),
                })
        });

        let segnale = per_dominio.or_else(|| {
            organizzazione
                .aliases
                .iter()
                .find(|alias| contiene_parola_intera(&normalizzato, alias.normalised()))
                .map(|alias| SectorSignal::NomeDichiarato {
                    nome: alias.written().to_owned(),
                })
        });

        if let Some(signal) = segnale {
            attributions.push(SectorAttribution {
                sector: organizzazione.sector,
                organisation_id: organizzazione.id.get(),
                organisation: organizzazione.name.as_str().to_owned(),
                signal,
                declared_by: organizzazione.declared_by.as_str().to_owned(),
            });
        }
    }

    // Ordine stabile: la motivazione mostrata all'operatore non deve cambiare
    // fra due esecuzioni identiche.
    attributions.sort();
    SectorRelevance { attributions }
}

/// Se l'ago compare nel pagliaio delimitato da confini di parola.
///
/// # Perché non si riusa `find_occurrences`
///
/// Quella funzione lavora su `ResolvedTerm`, che porta con sé categoria,
/// livello suggerito e provenienza da un dizionario. Un nome di organizzazione
/// non è un termine di dizionario e non ha un livello: costruirne uno finto per
/// riusare la funzione significherebbe far entrare un livello in questo modulo,
/// che è esattamente ciò che ADR-0035 Decisione 10 vieta.
///
/// Il confine di parola è però **lo stesso**: il carattere adiacente non deve
/// essere alfanumerico. Senza, dichiarare «gam» riscontrerebbe in «gambero».
fn contiene_parola_intera(pagliaio: &[char], ago: &str) -> bool {
    let ago: Vec<char> = ago.chars().collect();
    if ago.is_empty() || ago.len() > pagliaio.len() {
        return false;
    }

    for inizio in 0..=(pagliaio.len() - ago.len()) {
        if pagliaio[inizio..inizio + ago.len()] != ago[..] {
            continue;
        }

        let fine = inizio + ago.len();
        let prima_e_parola = inizio
            .checked_sub(1)
            .and_then(|indice| pagliaio.get(indice))
            .is_some_and(|carattere| carattere.is_alphanumeric());
        let dopo_e_parola = pagliaio
            .get(fine)
            .is_some_and(|carattere| carattere.is_alphanumeric());

        if !prima_e_parola && !dopo_e_parola {
            return true;
        }
    }

    false
}

#[cfg(test)]
mod tests {
    use super::{ItalyRelevance, ItalySignal, Sector, assess_italy};

    fn domini(elenco: &[&str]) -> Vec<String> {
        elenco.iter().map(|voce| String::from(*voce)).collect()
    }

    /// **I diciotto settori sono diciotto.**
    ///
    /// La Commissione dichiara diciotto settori fra i due allegati. Se questo
    /// numero cambiasse senza che qualcuno abbia riverificato la fonte, la
    /// tassonomia direbbe qualcosa che la norma non dice.
    #[test]
    fn i_settori_sono_quelli_della_norma() {
        assert_eq!(
            Sector::ALL.len(),
            18,
            "la Commissione dichiara diciotto settori fra allegato I e II"
        );

        let alta = Sector::ALL
            .iter()
            .filter(|settore| settore.is_high_criticality())
            .count();
        assert_eq!(
            alta, 11,
            "l'allegato I — alta criticita' — ne elenca undici"
        );
    }

    /// **Le etichette stabili sono tutte diverse.**
    ///
    /// Due settori con la stessa etichetta sarebbero due settori che l'archivio
    /// non sa distinguere.
    #[test]
    fn ogni_settore_ha_un_etichetta_propria() {
        let mut stabili: Vec<&str> = Sector::ALL.iter().map(Sector::as_str).collect();
        let quanti = stabili.len();
        stabili.sort_unstable();
        stabili.dedup();
        assert_eq!(stabili.len(), quanti);

        let mut leggibili: Vec<&str> = Sector::ALL.iter().map(Sector::label).collect();
        leggibili.sort_unstable();
        leggibili.dedup();
        assert_eq!(leggibili.len(), quanti);
    }

    /// **Un dominio istituzionale non viene contato due volte.**
    #[test]
    fn un_dominio_istituzionale_e_un_segnale_solo() {
        let rilevanza = assess_italy(&domini(&["comune.gov.it"]), None);
        assert_eq!(rilevanza.signals.len(), 1);
        assert!(matches!(
            rilevanza.signals[0],
            ItalySignal::DominioIstituzionale { .. }
        ));
    }

    #[test]
    fn un_dominio_italiano_ordinario_si_riconosce() {
        let rilevanza = assess_italy(&domini(&["esempio.it"]), None);
        assert!(matches!(
            rilevanza.signals[0],
            ItalySignal::DominioItaliano { .. }
        ));
        assert!(rilevanza.has_signal_beyond_language());
    }

    /// **La lingua da sola e' il segnale piu' debole, e si dichiara.**
    ///
    /// L'italiano si parla anche fuori dall'Italia, e un contenuto sull'Italia
    /// puo' essere in inglese. Un elenco costruito sulla sola lingua sarebbe un
    /// elenco di contenuti in italiano, che e' un'altra cosa.
    #[test]
    fn la_lingua_da_sola_si_dichiara_come_segnale_debole() {
        let rilevanza = assess_italy(&[], Some("it"));
        assert!(!rilevanza.is_empty());
        assert!(!rilevanza.has_signal_beyond_language());

        let frase = rilevanza.as_sentence();
        assert!(
            frase.contains("il più debole"),
            "la frase deve dichiarare la debolezza del segnale: «{frase}»"
        );
        assert!(frase.contains("anche fuori dall'Italia"));
    }

    /// **Nessun segnale non significa «non riguarda l'Italia».**
    #[test]
    fn l_assenza_di_segnali_non_e_un_verdetto() {
        let frase = ItalyRelevance::default().as_sentence();
        assert!(
            frase.contains("Non significa che non la riguardi"),
            "l'assenza di prove non e' la prova dell'assenza: «{frase}»"
        );
    }

    /// **Riguardare l'Italia non rende grave nulla.**
    ///
    /// E' la confusione che ADR-0035 Decisione 10 esiste per impedire, e qui e'
    /// impossibile per costruzione: nessuna funzione di questo modulo
    /// restituisce un livello ne' ne prende uno.
    #[test]
    fn nessuna_frase_sulla_rilevanza_contiene_un_giudizio_di_gravita() {
        let casi = [
            assess_italy(&domini(&["ministero.gov.it", "azienda.it"]), Some("it")),
            assess_italy(&domini(&["esempio.it"]), None),
            assess_italy(&[], Some("it")),
            ItalyRelevance::default(),
        ];

        for rilevanza in casi {
            let frase = rilevanza.as_sentence().to_lowercase();
            for vietata in [
                "grave", "gravita", "critico", "urgente", "priorita", "allarme", "pericolo",
                "livello",
            ] {
                assert!(
                    !frase.contains(vietata),
                    "la frase sulla rilevanza contiene un giudizio di gravita' \
                     («{vietata}»): «{frase}»"
                );
            }
        }
    }

    /// **Alta criticita' non significa piu' grave, e si dichiara nel sorgente.**
    ///
    /// E vale il rovescio, che e' piu' facile dimenticare: un settore non
    /// elencato non e' un settore che non conta.
    #[test]
    fn l_alta_criticita_e_un_ambito_non_una_gravita() {
        // La prova e' strutturale: la funzione risponde a «sta nell'allegato I»,
        // non a «quanto e' grave», e non prende ne' restituisce livelli.
        assert!(Sector::Sanita.is_high_criticality());
        assert!(!Sector::Ricerca.is_high_criticality());

        // E il modulo non conosce affatto i livelli: se un giorno qualcuno ce li
        // portasse dentro, questa prova diventerebbe il posto in cui accorgersene.
        let sorgente = include_str!("relevance.rs");
        let produzione = sorgente.split("#[cfg(test)]").next().unwrap_or(sorgente);
        assert!(
            !produzione.contains("AnalysisLevel"),
            "il modulo della rilevanza ha acquisito il tipo del livello: da li' \
             a fondere le due dimensioni il passo e' breve"
        );
    }

    #[test]
    fn i_segnali_escono_in_ordine_stabile() {
        let primo = assess_italy(&domini(&["b.it", "a.gov.it"]), Some("it"));
        let secondo = assess_italy(&domini(&["a.gov.it", "b.it"]), Some("it"));
        assert_eq!(primo, secondo);
    }

    #[test]
    fn un_dominio_straniero_non_produce_segnali() {
        let rilevanza = assess_italy(&domini(&["esempio.com", "esempio.de"]), Some("en"));
        assert!(rilevanza.is_empty());
    }

    // ------------------------------------------------------ il settore

    use super::{SectorRelevance, SectorSignal, assess_sectors};
    use crate::id::WatchedOrganisationId;
    use crate::model::organisation::{OrganisationAlias, OrganisationDomain, WatchedOrganisation};
    use crate::text::{Actor, DisplayName};
    use crate::time::Timestamp;

    /// Un'organizzazione dichiarata, per le prove.
    ///
    /// I nomi sono inventati: il prodotto non contiene alcun elenco di enti, e
    /// nemmeno le sue prove ne costruiscono uno.
    fn dichiarata(
        id: i64,
        nome: &str,
        settore: Sector,
        alias: &[&str],
        domini_dichiarati: &[&str],
        attiva: bool,
    ) -> WatchedOrganisation {
        let (Ok(name), Ok(declared_by)) = (
            DisplayName::try_new(nome),
            Actor::try_new("amministratore.prova"),
        ) else {
            panic!("i valori di prova devono essere validi");
        };

        let aliases = alias
            .iter()
            .map(|voce| match OrganisationAlias::try_new(voce) {
                Ok(valore) => valore,
                Err(_) => panic!("l'alias di prova «{voce}» deve essere valido"),
            })
            .collect();

        let domains = domini_dichiarati
            .iter()
            .map(|voce| match OrganisationDomain::try_new(voce) {
                Ok(valore) => valore,
                Err(_) => panic!("il dominio di prova «{voce}» deve essere valido"),
            })
            .collect();

        WatchedOrganisation {
            id: WatchedOrganisationId::new(id),
            name,
            sector: settore,
            aliases,
            domains,
            note: None,
            active: attiva,
            declared_by,
            declared_at: Timestamp::from_millis(1_000),
            updated_at: Timestamp::from_millis(1_000),
        }
    }

    #[test]
    fn senza_organizzazioni_dichiarate_non_esiste_alcun_settore() {
        let rilevanza = assess_sectors("cifrati i server di mezza città", &[], &[]);

        assert!(
            rilevanza.is_empty(),
            "senza dichiarazioni il prodotto non deve inventare un settore"
        );
        assert!(
            rilevanza
                .as_sentence()
                .contains("non nomina alcuna organizzazione")
        );
    }

    #[test]
    fn un_dominio_dichiarato_produce_il_settore_con_la_sua_provenienza() {
        let elenco = vec![dichiarata(
            7,
            "Ente Alfa",
            Sector::Energia,
            &["Ente Alfa"],
            &["alfa.example"],
            true,
        )];

        let rilevanza = assess_sectors(
            "pubblicati documenti",
            &[String::from("alfa.example")],
            &elenco,
        );

        assert_eq!(rilevanza.attributions.len(), 1);
        let attribuzione = &rilevanza.attributions[0];
        assert_eq!(attribuzione.sector, Sector::Energia);
        assert_eq!(attribuzione.organisation_id, 7);
        assert_eq!(attribuzione.organisation, "Ente Alfa");
        assert_eq!(attribuzione.declared_by, "amministratore.prova");
        assert!(matches!(
            attribuzione.signal,
            SectorSignal::DominioDichiarato { .. }
        ));
    }

    #[test]
    fn il_sottodominio_di_un_dominio_dichiarato_riscontra() {
        let elenco = vec![dichiarata(
            1,
            "Ente Alfa",
            Sector::Sanita,
            &[],
            &["alfa.example"],
            true,
        )];

        let rilevanza = assess_sectors("", &[String::from("posta.alfa.example")], &elenco);

        assert_eq!(rilevanza.sectors(), vec![Sector::Sanita]);
    }

    #[test]
    fn un_nome_dichiarato_riscontra_come_parola_intera() {
        let elenco = vec![dichiarata(
            2,
            "Ente Beta",
            Sector::Trasporti,
            &["Beta Trasporti"],
            &[],
            true,
        )];

        let rilevanza = assess_sectors("rivendicato attacco a Beta Trasporti", &[], &elenco);

        assert_eq!(rilevanza.attributions.len(), 1);
        assert!(matches!(
            rilevanza.attributions[0].signal,
            SectorSignal::NomeDichiarato { .. }
        ));
    }

    #[test]
    fn un_nome_dichiarato_non_riscontra_dentro_unaltra_parola() {
        // Senza il confine di parola, dichiarare «gam» riscontrerebbe in
        // «gambero», e il settore verrebbe attribuito al rumore.
        let elenco = vec![dichiarata(
            3,
            "Ente Gamma",
            Sector::ServiziDigitali,
            &["gam"],
            &[],
            true,
        )];

        let rilevanza = assess_sectors("il gambero e la gamma cromatica", &[], &elenco);

        assert!(
            rilevanza.is_empty(),
            "«gam» non deve riscontrare dentro «gambero» né dentro «gamma»"
        );
    }

    #[test]
    fn il_dominio_prevale_sul_nome_quando_riscontrano_entrambi() {
        // Due righe che dicono la stessa cosa sarebbero rumore: si mostra
        // l'ancora piu' solida.
        let elenco = vec![dichiarata(
            4,
            "Ente Delta",
            Sector::Bancario,
            &["Ente Delta"],
            &["delta.example"],
            true,
        )];

        let rilevanza = assess_sectors(
            "violazione a Ente Delta",
            &[String::from("delta.example")],
            &elenco,
        );

        assert_eq!(rilevanza.attributions.len(), 1);
        assert!(matches!(
            rilevanza.attributions[0].signal,
            SectorSignal::DominioDichiarato { .. }
        ));
    }

    /// **Un'organizzazione disattivata non produce alcuna attribuzione.**
    ///
    /// E' la ragione per cui si disattiva invece di cancellare: i riscontri
    /// gia' registrati restano leggibili, e quelli futuri si fermano.
    #[test]
    fn unorganizzazione_disattivata_non_produce_attribuzioni() {
        let elenco = vec![dichiarata(
            5,
            "Ente Epsilon",
            Sector::Chimica,
            &["Ente Epsilon"],
            &["epsilon.example"],
            false,
        )];

        let rilevanza = assess_sectors(
            "attacco a Ente Epsilon",
            &[String::from("epsilon.example")],
            &elenco,
        );

        assert!(rilevanza.is_empty());
    }

    #[test]
    fn unorganizzazione_nominata_due_volte_produce_una_sola_attribuzione() {
        let elenco = vec![dichiarata(
            6,
            "Ente Zeta",
            Sector::Ricerca,
            &["Ente Zeta", "Zeta"],
            &["zeta.example"],
            true,
        )];

        let rilevanza = assess_sectors(
            "Ente Zeta e ancora Zeta",
            &[String::from("zeta.example"), String::from("zeta.example")],
            &elenco,
        );

        assert_eq!(
            rilevanza.attributions.len(),
            1,
            "nominarla due volte non la rende due riscontri"
        );
    }

    #[test]
    fn piu_organizzazioni_dello_stesso_settore_toccano_un_settore_solo() {
        let elenco = vec![
            dichiarata(1, "Ente Uno", Sector::Sanita, &[], &["uno.example"], true),
            dichiarata(2, "Ente Due", Sector::Sanita, &[], &["due.example"], true),
        ];

        let rilevanza = assess_sectors(
            "",
            &[String::from("uno.example"), String::from("due.example")],
            &elenco,
        );

        assert_eq!(rilevanza.attributions.len(), 2);
        assert_eq!(
            rilevanza.sectors(),
            vec![Sector::Sanita],
            "due organizzazioni della sanita' toccano UN settore, non due"
        );
    }

    #[test]
    fn le_attribuzioni_escono_in_ordine_stabile() {
        let primo = vec![
            dichiarata(
                1,
                "Ente Uno",
                Sector::Trasporti,
                &[],
                &["uno.example"],
                true,
            ),
            dichiarata(2, "Ente Due", Sector::Energia, &[], &["due.example"], true),
        ];
        let secondo = vec![
            dichiarata(2, "Ente Due", Sector::Energia, &[], &["due.example"], true),
            dichiarata(
                1,
                "Ente Uno",
                Sector::Trasporti,
                &[],
                &["uno.example"],
                true,
            ),
        ];
        let domini = vec![String::from("uno.example"), String::from("due.example")];

        assert_eq!(
            assess_sectors("", &domini, &primo),
            assess_sectors("", &domini, &secondo),
            "l'ordine della dichiarazione non deve cambiare la motivazione mostrata"
        );
    }

    #[test]
    fn lalta_criticita_si_legge_dalle_attribuzioni_senza_diventare_gravita() {
        let elenco = vec![dichiarata(
            1,
            "Ente Uno",
            Sector::Energia,
            &[],
            &["uno.example"],
            true,
        )];

        let rilevanza = assess_sectors("", &[String::from("uno.example")], &elenco);

        assert!(rilevanza.touches_high_criticality());
        assert!(
            rilevanza.as_sentence().contains("non rende grave nulla"),
            "la frase deve dire esplicitamente che l'allegato I non e' una gravita'"
        );
    }

    /// **Nessuna attribuzione esiste senza provenienza.**
    ///
    /// E' l'invariante che DEC-235 esisteva per proteggere: un settore che
    /// comparisse senza dire da dove viene sarebbe un'attribuzione inventata.
    ///
    /// La verifica e' strutturale: ogni attribuzione prodotta porta
    /// l'identificativo dell'organizzazione, il suo nome, chi l'ha dichiarata e
    /// il segnale che ha riscontrato. Il tipo non permette di costruirne una
    /// senza — i campi non sono facoltativi — e questa prova lo esercita.
    #[test]
    fn ogni_attribuzione_porta_la_propria_provenienza() {
        let elenco = vec![
            dichiarata(11, "Ente Uno", Sector::Spazio, &["Ente Uno"], &[], true),
            dichiarata(
                12,
                "Ente Due",
                Sector::Alimentare,
                &[],
                &["due.example"],
                true,
            ),
        ];

        let rilevanza = assess_sectors(
            "Ente Uno ha comunicato",
            &[String::from("due.example")],
            &elenco,
        );

        assert_eq!(rilevanza.attributions.len(), 2);
        for attribuzione in &rilevanza.attributions {
            assert!(attribuzione.organisation_id > 0, "manca l'identificativo");
            assert!(!attribuzione.organisation.is_empty(), "manca il nome");
            assert!(
                !attribuzione.declared_by.is_empty(),
                "manca chi l'ha dichiarata"
            );
            assert!(
                attribuzione.as_sentence().contains("Settore dichiarato da"),
                "la frase deve dire chi ha dichiarato il settore"
            );
        }
    }

    /// **Il settore non entra mai nel livello.**
    ///
    /// Controllo strutturale, gemello di quello gia' presente per l'alta
    /// criticita': se un giorno qualcuno portasse il tipo del livello dentro
    /// questo modulo, il passo verso la fusione delle due dimensioni sarebbe
    /// breve, e ADR-0035 Decisione 10 cadrebbe senza che nulla lo segnali.
    #[test]
    fn la_valutazione_del_settore_non_conosce_i_livelli() {
        let sorgente = include_str!("relevance.rs");
        let produzione = sorgente.split("#[cfg(test)]").next().unwrap_or(sorgente);

        assert!(
            !produzione.contains("AnalysisLevel"),
            "il modulo della rilevanza ha acquisito il tipo del livello"
        );
        assert!(
            !produzione.contains("suggested_level"),
            "il modulo della rilevanza ha acquisito un livello suggerito"
        );
    }

    /// Controllo negativo permanente: una dichiarazione senza ancore non
    /// riscontra nulla, e non deve produrre un settore «vuoto».
    #[test]
    fn controllo_negativo_unorganizzazione_muta_non_produce_settori() {
        let muta = dichiarata(9, "Ente Muto", Sector::Fabbricazione, &[], &[], true);

        let rilevanza = assess_sectors(
            "qualunque testo",
            &[String::from("qualunque.example")],
            &[muta],
        );

        assert!(
            rilevanza.is_empty(),
            "un'organizzazione senza alias e senza domini non puo' riscontrare"
        );
    }

    #[test]
    fn la_rilevanza_vuota_ha_un_valore_predefinito() {
        let vuota = SectorRelevance::default();
        assert!(vuota.is_empty());
        assert!(vuota.sectors().is_empty());
        assert!(!vuota.touches_high_criticality());
    }
}
