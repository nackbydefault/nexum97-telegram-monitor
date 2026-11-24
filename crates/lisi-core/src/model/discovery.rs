//! Il dominio della scoperta pubblica, e i confini che i tipi tengono al posto
//! del testo.
//!
//! # Che cosa decide questo modulo, e che cosa no
//!
//! Il merito è deciso da ADR-0035: cinque ambiti distinti, nessun ambito esteso
//! acceso da solo, zero Telegram Stars, il prodotto che **non entra da nessuna
//! parte**, un candidato che non è una fonte, e le interrogazioni con un tetto.
//!
//! Qui non si decide di nuovo niente di tutto ciò. Qui si decide **dove vivono
//! quelle regole**: nel testo di un documento, in un controllo scritto da
//! qualche parte, oppure nella forma dei tipi — dove sbagliare non compila
//! (ADR-0074).
//!
//! # La regola che governa questo modulo
//!
//! **Una politica validata non si costruisce: si ottiene.**
//!
//! [`ValidatedDiscoveryPolicy`] non ha un costruttore pubblico, non ha
//! `Default`, e non si scrive come letterale. L'unico modo di averne una è
//! chiederla a una [`DiscoveryPolicy`] passandole dei [`ObservedLimits`] — e
//! quelli portano con sé **quando** sono stati osservati e **con quale misura**.
//!
//! Ne segue la porta della Fase 11: il percorso di produzione non deve
//! *ricordarsi* di controllare che l'ambiente sia validato. Gli basta chiedere
//! una politica validata, e **non averla è già la risposta**.
//!
//! # Che cosa questo modulo NON nomina
//!
//! I tipi del contenuto monitorato. Un risultato di ricerca è ciò che una
//! ricerca ha restituito; un contenuto acquisito è ciò che una fonte sorvegliata
//! ha pubblicato **mentre la si sorvegliava**. Sono due cose con due storie, e
//! mescolarle significherebbe non poter più dire, di una riga, da quale delle
//! due viene.
//!
//! La decisione completa sta in
//! `docs/adr/ADR-0074-UNA-POLITICA-VALIDATA-NON-SI-COSTRUISCE-SI-OTTIENE.md`.

use crate::time::Timestamp;

/// Dove una ricerca guarda.
///
/// # Perché cinque e non uno
///
/// Rispondono a domande diverse, e trattarle come equivalenti significherebbe
/// che un risultato trovato in una chat dell'ufficio e uno pescato da un canale
/// pubblico sconosciuto **pesano uguale**. Non è così (ADR-0035, decisione 2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub enum SearchScope {
    /// Solo le fonti configurate nella sessione.
    ///
    /// **È il difetto**, e non per gentilezza: è l'unico ambito che non esce da
    /// nessuna parte. Gli ambiti estesi si accendono uno per uno, e la prima
    /// difesa è che **non accendersi sia la cosa che succede senza fare nulla**.
    #[default]
    SelectedSources,
    /// Le chat accessibili all'account d'ufficio.
    AccountChats,
    /// I post dei canali pubblici.
    PublicChannelPosts,
    /// Le chat pubbliche individuate **e realmente accessibili**.
    DiscoveredPublicChats,
    /// Combinazione controllata delle superfici attive.
    Extended,
}

impl SearchScope {
    /// Tutti gli ambiti, per chi deve mostrarli o percorrerli.
    pub const ALL: [Self; 5] = [
        Self::SelectedSources,
        Self::AccountChats,
        Self::PublicChannelPosts,
        Self::DiscoveredPublicChats,
        Self::Extended,
    ];

    /// Se questo ambito guarda **fuori** dalle fonti già configurate.
    ///
    /// Serve a chi deve chiedere una conferma in più, e a chi deve dichiarare
    /// nella fotografia della sessione **dove** è stato cercato.
    #[must_use]
    pub const fn esce_dalle_fonti_configurate(self) -> bool {
        !matches!(self, Self::SelectedSources)
    }

    /// Nome stabile, per l'archivio e per l'audit.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::SelectedSources => "fonti_selezionate",
            Self::AccountChats => "chat_dell_account",
            Self::PublicChannelPosts => "post_pubblici",
            Self::DiscoveredPublicChats => "chat_pubbliche_individuate",
            Self::Extended => "esteso",
        }
    }

    /// Riconosce un ambito dal suo nome stabile.
    ///
    /// Serve a chi rilegge l'archivio: la colonna conserva il nome, non il tipo.
    /// Restituisce `None` per un nome che questo prodotto non ha mai scritto —
    /// **inventarne uno sarebbe una provenienza che nessuno può interpretare**.
    #[must_use]
    pub fn dal_nome(nome: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|scope| scope.as_str() == nome)
    }

    /// L'etichetta che l'operatore legge.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::SelectedSources => "Solo le fonti di questo monitoraggio",
            Self::AccountChats => "Le chat a cui questo account ha già accesso",
            Self::PublicChannelPosts => "I post dei canali pubblici",
            Self::DiscoveredPublicChats => "Le chat pubbliche già raggiungibili",
            Self::Extended => "Tutte le superfici attive insieme",
        }
    }
}

/// I limiti che Telegram ha dichiarato, **misurati** e non supposti.
///
/// # Perché è un tipo e non tre numeri
///
/// «Nessun limite di Telegram va inventato» è un divieto che, scritto così, è
/// impossibile da far rispettare: una costante con un numero plausibile ha lo
/// stesso aspetto di un numero misurato.
///
/// Questo tipo porta con sé **da dove viene**. Ne segue che una politica
/// validata porta impressa la data e l'origine della misura su cui poggia, e che
/// fra sei mesi si potrà chiedere «su quali limiti è stata fatta questa
/// scoperta?» ottenendo una risposta.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObservedLimits {
    /// Interrogazioni gratuite al giorno, come dichiarate.
    free_queries_per_day: u32,
    /// Interrogazioni gratuite rimaste al momento della misura.
    remaining_free_queries: u32,
    /// Fra quanti secondi la prossima interrogazione tornerà gratuita.
    next_free_in_seconds: u32,
    /// Quando sono stati osservati.
    observed_at: Timestamp,
    /// Con quale misura, in una riga che una persona legge.
    origin: String,
}

impl ObservedLimits {
    /// Registra dei limiti **osservati**.
    ///
    /// # Perché serve un'origine, e non può essere vuota
    ///
    /// Un numero senza provenienza è un numero che, fra sei mesi, nessuno può
    /// distinguere da uno inventato. L'origine dice quale misura lo ha prodotto:
    /// non è un commento, è la sola differenza fra un limite e una congettura.
    ///
    /// Restituisce `None` se l'origine è vuota o fatta di soli spazi.
    #[must_use]
    pub fn observed(
        free_queries_per_day: u32,
        remaining_free_queries: u32,
        next_free_in_seconds: u32,
        observed_at: Timestamp,
        origin: &str,
    ) -> Option<Self> {
        let origin = origin.trim();
        if origin.is_empty() {
            return None;
        }

        Some(Self {
            free_queries_per_day,
            remaining_free_queries,
            next_free_in_seconds,
            observed_at,
            origin: origin.to_owned(),
        })
    }

    /// Interrogazioni gratuite al giorno.
    #[must_use]
    pub const fn free_queries_per_day(&self) -> u32 {
        self.free_queries_per_day
    }

    /// Interrogazioni gratuite rimaste al momento della misura.
    #[must_use]
    pub const fn remaining_free_queries(&self) -> u32 {
        self.remaining_free_queries
    }

    /// Fra quanti secondi la prossima interrogazione tornerà gratuita.
    #[must_use]
    pub const fn next_free_in_seconds(&self) -> u32 {
        self.next_free_in_seconds
    }

    /// Quando sono stati osservati.
    #[must_use]
    pub const fn observed_at(&self) -> Timestamp {
        self.observed_at
    }

    /// Con quale misura.
    #[must_use]
    pub fn origin(&self) -> &str {
        &self.origin
    }
}

/// Che cosa qualcuno vorrebbe che una scoperta facesse.
///
/// **Non basta a far partire niente.** È una richiesta: diventa qualcosa solo
/// passando per [`Self::validate`], che pretende dei limiti osservati.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiscoveryPolicy {
    /// Dove guardare.
    pub scope: SearchScope,
    /// Quante interrogazioni **distinte** al massimo.
    ///
    /// # Perché distinte e non richieste
    ///
    /// Ripetere la stessa interrogazione è gratuito: paginare non consuma quota
    /// nuova. La grandezza da governare è il numero di interrogazioni diverse
    /// (ADR-0035, decisione 4).
    pub max_distinct_queries: u32,
    /// Quanti risultati al massimo per interrogazione.
    pub max_results_per_query: u32,
}

impl DiscoveryPolicy {
    /// Chiede che questa politica diventi validata, **davanti a limiti
    /// osservati**.
    ///
    /// # Perché può dire di no
    ///
    /// Una politica che chiede più interrogazioni di quante Telegram ne dichiari
    /// gratuite non è una politica ambiziosa: è una politica che, eseguita,
    /// **supererebbe un limite vero** — e superare un limite vero su un account
    /// d'ufficio è la cosa che questo prodotto non fa da nessuna parte.
    ///
    /// Restituisce `None` anche se la politica non chiede nulla: una scoperta da
    /// zero interrogazioni non è una scoperta, ed è meglio dirlo qui che
    /// eseguirla e non trovare niente.
    #[must_use]
    pub fn validate(self, limits: &ObservedLimits) -> Option<ValidatedDiscoveryPolicy> {
        if self.max_distinct_queries == 0 || self.max_results_per_query == 0 {
            return None;
        }
        if self.max_distinct_queries > limits.free_queries_per_day() {
            return None;
        }

        Some(ValidatedDiscoveryPolicy {
            policy: self,
            limits: limits.clone(),
        })
    }
}

/// Una politica che può essere eseguita, **e che porta con sé su che cosa
/// poggia**.
///
/// # Perché non ha un costruttore
///
/// Non esiste `new`, non esiste `Default`, non esiste un letterale: i campi sono
/// privati e l'unico modo di ottenerne una è [`DiscoveryPolicy::validate`].
///
/// **Perché non basterebbe un controllo.** Un controllo si scrive in un posto e
/// si dimentica in un altro, e il posto dimenticato è sempre quello nuovo,
/// scritto fra sei mesi da chi non ha letto l'ADR. Un tipo che non si può
/// costruire non si dimentica: chi ne ha bisogno deve passare da dove si
/// ottiene.
///
/// Il cancello di PD-GATE-01 non dovrà quindi controllare nulla: gli basterà
/// chiederne una, e **non averla è già la risposta** (ADR-0074).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidatedDiscoveryPolicy {
    policy: DiscoveryPolicy,
    limits: ObservedLimits,
}

impl ValidatedDiscoveryPolicy {
    /// La politica, com'era stata chiesta.
    #[must_use]
    pub const fn policy(&self) -> &DiscoveryPolicy {
        &self.policy
    }

    /// I limiti osservati su cui poggia.
    #[must_use]
    pub const fn limits(&self) -> &ObservedLimits {
        &self.limits
    }

    /// Dove guardare.
    #[must_use]
    pub const fn scope(&self) -> SearchScope {
        self.policy.scope
    }
}

/// Un'interrogazione, così come verrà posta.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct DiscoveryQuery(String);

impl DiscoveryQuery {
    /// Compone un'interrogazione.
    ///
    /// Restituisce `None` se è vuota o fatta di soli spazi: interrogare il vuoto
    /// consuma una quota vera per una domanda che nessuno ha posto.
    #[must_use]
    pub fn try_new(raw: &str) -> Option<Self> {
        let raw = raw.trim();
        if raw.is_empty() {
            return None;
        }
        Some(Self(raw.to_owned()))
    }

    /// Il testo dell'interrogazione.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Un'esecuzione della scoperta: che cosa è stato chiesto, quando, e con quale
/// politica.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiscoveryRun {
    /// La politica validata con cui è stata eseguita.
    pub policy: ValidatedDiscoveryPolicy,
    /// Quando è cominciata.
    pub started_at: Timestamp,
    /// Le interrogazioni poste, nell'ordine in cui sono state poste.
    ///
    /// **Si registra che cosa è stato interrogato** (ADR-0035, decisione 12): una
    /// scoperta di cui non si sa che cosa ha chiesto è una scoperta di cui non si
    /// può dire che cosa non ha trovato.
    pub queries: Vec<DiscoveryQuery>,
}

/// L'indirizzo pubblico di una chat, **come Telegram lo pubblica**.
///
/// # Perché non è un identificatore di fonte
///
/// Un identificatore di fonte è una cosa che questo prodotto assegna quando
/// qualcuno decide di sorvegliare qualcosa. Questo è un nome che **esisteva
/// prima**, che chiunque può leggere, e che non impegna nessuno a niente.
///
/// Averlo è necessario per poter aprire e per poter aggiungere; **non basta** a
/// fare né l'una né l'altra cosa, che restano decisioni di una persona
/// (ADR-0080).
///
/// # Che cosa viene accettato
///
/// Un nome utente pubblico: da 5 a 32 caratteri, lettere ASCII, cifre e trattini
/// bassi, che comincia con una lettera. È un **sottoinsieme** di ciò che Telegram
/// ammette, scelto stretto di proposito: un indirizzo che arriva da dato remoto
/// e che finisce in un URL non è il posto in cui essere generosi.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PublicAddress(String);

impl PublicAddress {
    /// Compone un indirizzo pubblico.
    ///
    /// Restituisce `None` se la forma non è quella di un nome utente pubblico.
    /// **Non si corregge e non si indovina**: un indirizzo quasi giusto porta
    /// da qualche altra parte, non da nessuna parte.
    #[must_use]
    pub fn try_new(raw: &str) -> Option<Self> {
        let raw = raw.trim().trim_start_matches('@');
        if raw.len() < 5 || raw.len() > 32 {
            return None;
        }
        let primo = raw.chars().next()?;
        if !primo.is_ascii_alphabetic() {
            return None;
        }
        if !raw
            .chars()
            .all(|carattere| carattere.is_ascii_alphanumeric() || carattere == '_')
        {
            return None;
        }
        Some(Self(raw.to_owned()))
    }

    /// Il nome utente, senza chiocciola.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// L'indirizzo da aprire in un browser.
    ///
    /// Si compone **qui** e non nell'interfaccia: una composizione ripetuta in
    /// due posti diverge alla prima modifica, e questa finisce in un URL.
    #[must_use]
    pub fn public_url(&self) -> String {
        format!("https://t.me/{}", self.0)
    }
}

/// Che cosa una persona ha deciso di un candidato.
///
/// # Perché sono fatti e non uno stato
///
/// Non esiste un campo «stato del candidato» che si sovrascrive. Qualcuno può
/// cambiare idea, e allora **restano vere entrambe le cose**: che un giorno si
/// era detto di no, e che un altro giorno si è detto di sì. Uno stato
/// sovrascritto cancellerebbe la prima, che è quella che spiega perché nessuno
/// l'aveva aggiunto prima (ADR-0080).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum CandidateDecision {
    /// È stato aperto per guardarlo. **Aprire non aggiunge.**
    Opened,
    /// È stato aggiunto come fonte, da qualcuno che ne ha dichiarato
    /// l'accessibilità legittima.
    Added,
    /// Qualcuno lo ha guardato e ha detto di no. **Non si cancella**: sparisce
    /// da chi decide, non dall'archivio.
    Ignored,
}

impl CandidateDecision {
    /// Tutte le decisioni possibili.
    pub const ALL: [Self; 3] = [Self::Opened, Self::Added, Self::Ignored];

    /// Nome stabile, per l'archivio e per l'audit.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Opened => "aperto",
            Self::Added => "aggiunto",
            Self::Ignored => "ignorato",
        }
    }

    /// Riconosce una decisione dal suo nome stabile.
    #[must_use]
    pub fn dal_nome(nome: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|scelta| scelta.as_str() == nome)
    }

    /// Se questa decisione fa nascere una fonte.
    ///
    /// **Una sola** lo fa, e non è quella che si preme per prima.
    #[must_use]
    pub const fn fa_nascere_una_fonte(self) -> bool {
        matches!(self, Self::Added)
    }
}

/// Un risultato, con **da dove viene**.
///
/// # Perché l'ambito sta qui e non solo nell'esecuzione
///
/// Un'esecuzione con ambito esteso mescola risultati che vengono da superfici
/// diverse. Sapere che «questa esecuzione era estesa» non direbbe, di *questo*
/// risultato, da dove viene — e ADR-0035 vuole che la provenienza si possa dire
/// **per ogni singolo record**.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiscoveryResult {
    /// L'interrogazione che lo ha restituito.
    pub query: DiscoveryQuery,
    /// La superficie da cui viene.
    pub scope: SearchScope,
    /// Come la chat si chiama pubblicamente, così come è arrivata.
    ///
    /// **È testo che viene da fuori**, e chi lo mostra lo tratta come tale.
    pub public_name: String,
    /// L'indirizzo pubblico, quando la chat ne ha uno.
    ///
    /// # Perché può non esserci
    ///
    /// Non tutto ciò che una ricerca restituisce ha un nome utente pubblico. Un
    /// risultato senza indirizzo **non si può né aprire né aggiungere**, e la
    /// ragione si dice: senza indirizzo non c'è niente da aprire e niente da
    /// sorvegliare (ADR-0080).
    pub public_address: Option<PublicAddress>,
}

/// Perché una fonte è stata suggerita.
///
/// Un motivo vuoto non è un motivo: si costruisce solo con del testo.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct CandidateReason(String);

impl CandidateReason {
    /// Compone un motivo.
    ///
    /// Restituisce `None` se è vuoto o fatto di soli spazi.
    #[must_use]
    pub fn try_new(raw: &str) -> Option<Self> {
        let raw = raw.trim();
        if raw.is_empty() {
            return None;
        }
        Some(Self(raw.to_owned()))
    }

    /// Il testo del motivo.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Qualcosa che una ricerca ha restituito e che **potrebbe** meritare di
/// diventare una fonte.
///
/// # Un candidato non è una fonte
///
/// Non porta un identificatore di fonte, non ha un metodo che lo trasformi in
/// una, e non implementa alcuna conversione verso di essa. L'unico modo perché
/// diventi una fonte è che qualcuno **crei una fonte**, altrove, con un
/// operatore, un istante e una riga d'audit (ADR-0035 decisione 6, ADR-0074
/// decisione 3).
///
/// La ragione sta nella matrice delle capacità: `searchPublicChats` restituisce
/// «un numero significativo di risultati» con criterio ignoto e senza
/// paginazione. **Non è una risposta: è un elenco parziale.**
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SourceCandidate {
    /// Il risultato da cui nasce.
    pub result: DiscoveryResult,
    /// Perché è stato suggerito.
    ///
    /// Almeno uno: un suggerimento senza spiegazione è un suggerimento che si
    /// impara a ignorare.
    reasons: Vec<CandidateReason>,
}

impl SourceCandidate {
    /// Compone un candidato.
    ///
    /// Restituisce `None` senza almeno un motivo: ADR-0035 vuole che un
    /// suggerimento dica **perché** è stato suggerito, e una spiegazione vuota
    /// non è una spiegazione.
    #[must_use]
    pub fn try_new(result: DiscoveryResult, reasons: Vec<CandidateReason>) -> Option<Self> {
        if reasons.is_empty() {
            return None;
        }
        Some(Self { result, reasons })
    }

    /// I motivi per cui è stato suggerito.
    #[must_use]
    pub fn reasons(&self) -> &[CandidateReason] {
        &self.reasons
    }
}

#[cfg(test)]
mod tests {
    use super::{
        CandidateDecision, CandidateReason, DiscoveryPolicy, DiscoveryQuery, DiscoveryResult,
        ObservedLimits, PublicAddress, SearchScope, SourceCandidate,
    };

    /// **Un indirizzo quasi giusto non si corregge: si rifiuta.**
    ///
    /// Un indirizzo arriva da dato remoto e finisce in un URL: indovinare
    /// porterebbe da qualche altra parte, non da nessuna parte.
    #[test]
    fn un_indirizzo_pubblico_mal_formato_non_si_compone() {
        for buono in ["canale_uno", "@canale_uno", "  Canale2  ", "abcde"] {
            assert!(
                PublicAddress::try_new(buono).is_some(),
                "«{buono}» ha la forma di un nome utente pubblico"
            );
        }

        for cattivo in [
            "",
            "abcd",
            "1canale",
            "canale-uno",
            "canale uno",
            "canale.uno",
            "https://t.me/canale",
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        ] {
            assert!(
                PublicAddress::try_new(cattivo).is_none(),
                "«{cattivo}» non e' un nome utente pubblico e non si corregge"
            );
        }
    }

    /// **La chiocciola si toglie, e l'indirizzo si compone in un posto solo.**
    #[test]
    fn l_indirizzo_si_compone_in_un_posto_solo() {
        let Some(indirizzo) = PublicAddress::try_new("@canale_uno") else {
            panic!("l'indirizzo di prova e' valido");
        };
        assert_eq!(indirizzo.as_str(), "canale_uno");
        assert_eq!(indirizzo.public_url(), "https://t.me/canale_uno");
    }

    /// **Una sola decisione fa nascere una fonte, e non e' quella che si preme
    /// per prima.**
    ///
    /// Aprire e' guardare, aggiungere e' cominciare a sorvegliare: confonderle
    /// e' il modo in cui un candidato diventa una fonte per sbaglio.
    #[test]
    fn una_sola_decisione_fa_nascere_una_fonte() {
        assert!(CandidateDecision::Added.fa_nascere_una_fonte());
        assert!(!CandidateDecision::Opened.fa_nascere_una_fonte());
        assert!(!CandidateDecision::Ignored.fa_nascere_una_fonte());

        for scelta in CandidateDecision::ALL {
            assert_eq!(
                CandidateDecision::dal_nome(scelta.as_str()),
                Some(scelta),
                "«{}» non si rilegge",
                scelta.as_str()
            );
        }
        assert_eq!(CandidateDecision::dal_nome("cancellato"), None);
    }

    /// **Un ambito riletto dall'archivio e' lo stesso che vi era stato scritto.**
    ///
    /// La colonna conserva il nome stabile, non il tipo: se il nome e la lettura
    /// si separassero, una scoperta tornerebbe indietro con una provenienza
    /// diversa da quella con cui era stata scritta.
    #[test]
    fn ogni_ambito_si_rilegge_dal_proprio_nome() {
        for scope in SearchScope::ALL {
            assert_eq!(
                SearchScope::dal_nome(scope.as_str()),
                Some(scope),
                "«{}» non si rilegge",
                scope.as_str()
            );
        }

        assert_eq!(
            SearchScope::dal_nome("ambito_inventato"),
            None,
            "un nome mai scritto da questo prodotto non si interpreta"
        );
    }

    use crate::time::Timestamp;

    fn adesso() -> Timestamp {
        Timestamp::from_millis(1_700_000_000_000)
    }

    fn limiti(al_giorno: u32) -> ObservedLimits {
        let Some(limiti) = ObservedLimits::observed(
            al_giorno,
            al_giorno,
            0,
            adesso(),
            "misura dal vivo del 2026-09-13",
        ) else {
            panic!("i limiti di prova devono potersi costruire");
        };
        limiti
    }

    /// **Non fare nulla lascia l'ambito che non esce da nessuna parte.**
    #[test]
    fn l_ambito_predefinito_non_esce_dalle_fonti_configurate() {
        assert_eq!(SearchScope::default(), SearchScope::SelectedSources);
        assert!(!SearchScope::default().esce_dalle_fonti_configurate());

        for ambito in SearchScope::ALL {
            if ambito == SearchScope::SelectedSources {
                continue;
            }
            assert!(
                ambito.esce_dalle_fonti_configurate(),
                "«{}» guarda fuori dalle fonti configurate e deve dirlo",
                ambito.as_str()
            );
        }
    }

    /// **Un limite senza origine non e' un limite.**
    ///
    /// Un numero senza provenienza e' un numero che, fra sei mesi, nessuno puo'
    /// distinguere da uno inventato.
    #[test]
    fn dei_limiti_senza_origine_non_si_costruiscono() {
        assert!(ObservedLimits::observed(10, 10, 0, adesso(), "").is_none());
        assert!(ObservedLimits::observed(10, 10, 0, adesso(), "   ").is_none());

        let Some(limiti) = ObservedLimits::observed(10, 10, 0, adesso(), "  misura vera  ") else {
            panic!("dei limiti con un'origine devono potersi costruire");
        };
        assert_eq!(limiti.origin(), "misura vera");
        assert_eq!(limiti.observed_at(), adesso());
    }

    /// **Una politica che supererebbe un limite vero non si valida.**
    ///
    /// Non e' una politica ambiziosa: e' una politica che, eseguita, farebbe
    /// superare un limite vero su un account d'ufficio.
    #[test]
    fn una_politica_oltre_i_limiti_osservati_non_diventa_valida() {
        let politica = DiscoveryPolicy {
            scope: SearchScope::PublicChannelPosts,
            max_distinct_queries: 11,
            max_results_per_query: 20,
        };
        assert!(politica.validate(&limiti(10)).is_none());

        let politica = DiscoveryPolicy {
            scope: SearchScope::PublicChannelPosts,
            max_distinct_queries: 10,
            max_results_per_query: 20,
        };
        let Some(validata) = politica.validate(&limiti(10)) else {
            panic!("una politica dentro i limiti deve potersi validare");
        };
        assert_eq!(validata.scope(), SearchScope::PublicChannelPosts);
    }

    /// **Una politica che non chiede nulla non e' una politica.**
    #[test]
    fn una_politica_vuota_non_diventa_valida() {
        for (interrogazioni, risultati) in [(0, 20), (10, 0), (0, 0)] {
            let politica = DiscoveryPolicy {
                scope: SearchScope::SelectedSources,
                max_distinct_queries: interrogazioni,
                max_results_per_query: risultati,
            };
            assert!(
                politica.validate(&limiti(10)).is_none(),
                "una politica da {interrogazioni} interrogazioni e {risultati} \
                 risultati non deve diventare valida"
            );
        }
    }

    /// **Una politica validata porta impressa la misura su cui poggia.**
    ///
    /// Fra sei mesi, chi guarda una scoperta potra' chiedere «su quali limiti e'
    /// stata fatta?» e ottenere una risposta, invece di scoprire che qualcuno
    /// aveva scritto un numero in un file.
    #[test]
    fn una_politica_validata_porta_la_misura_su_cui_poggia() {
        let politica = DiscoveryPolicy {
            scope: SearchScope::AccountChats,
            max_distinct_queries: 3,
            max_results_per_query: 5,
        };
        let Some(validata) = politica.validate(&limiti(10)) else {
            panic!("la politica di prova deve potersi validare");
        };

        assert_eq!(validata.limits().origin(), "misura dal vivo del 2026-09-13");
        assert_eq!(validata.limits().observed_at(), adesso());
        assert_eq!(validata.policy().max_distinct_queries, 3);
    }

    /// **Interrogare il vuoto consuma una quota vera per una domanda che nessuno
    /// ha posto.**
    #[test]
    fn un_interrogazione_vuota_non_si_compone() {
        assert!(DiscoveryQuery::try_new("").is_none());
        assert!(DiscoveryQuery::try_new("   ").is_none());

        let Some(interrogazione) = DiscoveryQuery::try_new("  ransomware  ") else {
            panic!("un'interrogazione con del testo deve potersi comporre");
        };
        assert_eq!(interrogazione.as_str(), "ransomware");
    }

    /// **Un candidato senza spiegazione non si costruisce.**
    ///
    /// Un suggerimento senza il perche' e' un suggerimento che si impara a
    /// ignorare, e allora tanto vale non darlo.
    #[test]
    fn un_candidato_senza_motivi_non_si_costruisce() {
        let risultato = DiscoveryResult {
            query: DiscoveryQuery::try_new("ransomware").unwrap_or_else(|| {
                panic!("l'interrogazione di prova deve potersi comporre");
            }),
            scope: SearchScope::PublicChannelPosts,
            public_name: String::from("un canale qualunque"),
            public_address: None,
        };

        assert!(SourceCandidate::try_new(risultato.clone(), Vec::new()).is_none());

        let Some(motivo) = CandidateReason::try_new("18 riscontri Cyber Core") else {
            panic!("il motivo di prova deve potersi comporre");
        };
        let Some(candidato) = SourceCandidate::try_new(risultato, vec![motivo]) else {
            panic!("un candidato con un motivo deve potersi costruire");
        };
        assert_eq!(candidato.reasons().len(), 1);
    }

    /// **Un motivo vuoto non e' un motivo.**
    #[test]
    fn un_motivo_vuoto_non_si_compone() {
        assert!(CandidateReason::try_new("").is_none());
        assert!(CandidateReason::try_new("  ").is_none());
    }

    /// **Il dominio della scoperta non nomina la prova monitorata.**
    ///
    /// Un risultato di ricerca e' cio' che una ricerca ha restituito; un
    /// contenuto acquisito e' cio' che una fonte sorvegliata ha pubblicato
    /// MENTRE la si sorvegliava. Mescolarli significherebbe non poter piu' dire,
    /// di una riga, da quale delle due viene (ADR-0074, decisione 4).
    #[test]
    fn il_dominio_della_scoperta_non_nomina_il_contenuto_monitorato() {
        const QUESTO_MODULO: &str = include_str!("discovery.rs");

        let Some((produzione, _)) = QUESTO_MODULO.split_once("\n#[cfg(test)]\nmod tests {") else {
            panic!("il blocco delle prove non si delimita");
        };

        for monitorato in [
            "ContentId",
            "ContentBody",
            "SourceId",
            "SessionId",
            "AcquisitionEvent",
        ] {
            assert!(
                !produzione.contains(monitorato),
                "il dominio della scoperta nomina «{monitorato}»: i risultati \
                 della scoperta restano separati dalla prova monitorata \
                 (ADR-0074)"
            );
        }
    }

    /// **Una politica validata non si costruisce.**
    ///
    /// La prova guarda il SORGENTE: i campi devono restare privati e non deve
    /// esistere un costruttore pubblico ne' un `Default`. Se comparissero, la
    /// porta della Fase 11 si aprirebbe da sola, e PD-GATE-01 tornerebbe a
    /// doversi RICORDARE di controllare qualcosa.
    #[test]
    fn una_politica_validata_non_ha_un_costruttore() {
        const QUESTO_MODULO: &str = include_str!("discovery.rs");

        let Some(dopo) = QUESTO_MODULO
            .split("pub struct ValidatedDiscoveryPolicy {")
            .nth(1)
        else {
            panic!("la politica validata non si trova: la guardia va riscritta insieme");
        };
        let Some(campi) = dopo.split('}').next() else {
            panic!("i campi della politica validata non si delimitano");
        };
        assert!(
            !campi.contains("pub "),
            "i campi della politica validata devono restare privati: fuori da \
             questo modulo non deve esserci modo di fabbricarne una (ADR-0074)"
        );

        let Some(metodi) = QUESTO_MODULO
            .split("impl ValidatedDiscoveryPolicy {")
            .nth(1)
        else {
            panic!("i metodi della politica validata non si trovano");
        };
        let Some(metodi) = metodi.split("\n}\n").next() else {
            panic!("i metodi della politica validata non si delimitano");
        };
        assert!(
            !metodi.contains("pub fn new") && !metodi.contains("pub const fn new"),
            "la politica validata non deve avere un costruttore: si ottiene da \
             «validate», passando per dei limiti osservati"
        );

        let Some(derive) = QUESTO_MODULO
            .split("pub struct ValidatedDiscoveryPolicy")
            .next()
            .and_then(|prima| prima.rsplit("#[derive(").next())
        else {
            panic!("le derive della politica validata non si trovano");
        };
        assert!(
            !derive.contains("Default"),
            "la politica validata non deve avere un Default: sarebbe un modo di \
             ottenerne una senza limiti osservati"
        );
    }
}
