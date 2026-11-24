//! Le organizzazioni che un amministratore ha dichiarato di sorvegliare.
//!
//! # Perché questo tipo esiste, e perché l'elenco non sta nel sorgente
//!
//! `PD6_SECTOR_TAXONOMY.md` lo aveva già deciso il 2026-08-18, e questo modulo
//! lo attua:
//!
//! > Nel prodotto non si scrive alcun elenco di enti «critici». Un elenco di
//! > organizzazioni inciso nel codice sarebbe una lista arbitraria che nessuno
//! > ha approvato, che invecchia il giorno dopo, e che — distribuita su ogni
//! > postazione — dice a chiunque la legga quali enti l'ufficio considera
//! > bersagli.
//!
//! Il prodotto porta quindi **la tassonomia** dei diciotto settori NIS2, che
//! viene da una fonte ufficiale e cambia solo quando cambia la norma; e riceve
//! **l'elenco delle organizzazioni** da chi amministra la postazione, che lo
//! scrive nell'archivio locale.
//!
//! # La regola che assegna un settore, e perché è verificata
//!
//! DEC-235 aveva lasciato `Sector` deliberatamente scollegato, con una ragione
//! precisa: «collegarla richiede una regola che assegni un settore a un
//! contenuto, e nessuna regola verificata esiste».
//!
//! La regola è questa, e non la inventa il prodotto:
//!
//! > un contenuto ricade in un settore **perché un amministratore ha dichiarato
//! > che quella organizzazione appartiene a quel settore, e il contenuto la
//! > nomina.**
//!
//! È verificabile in ogni passaggio: chi l'ha dichiarata, quando, quale nome o
//! quale dominio ha fatto scattare il riscontro. Il prodotto non deduce nulla —
//! applica una regola che una persona ha scritto, e ne conserva la provenienza.
//!
//! # Che cosa questo modulo non fa, mai
//!
//! Non decide che un contenuto sia grave. Non attribuisce un fatto a nessuno.
//! Non deduce il settore dal testo con un'euristica. Non contiene un solo nome
//! di organizzazione: **cercarne uno qui dentro è la prova che qualcosa è andato
//! storto**, e una guardia lo verifica.

use crate::error::{DomainError, DomainResult};
use crate::id::WatchedOrganisationId;
use crate::model::dictionary::normalise_for_matching;
use crate::model::relevance::Sector;
use crate::text::{Actor, DisplayName, Note};
use crate::time::Timestamp;

/// Quanti nomi alternativi si accettano per una sola organizzazione.
///
/// Un'organizzazione ha un nome, una sigla, forse una denominazione storica e
/// qualche forma abbreviata. Oltre una ventina non si stanno più dichiarando
/// alias: si sta costruendo un dizionario, e per quello il prodotto ne ha già
/// uno.
pub const MAX_ALIASES: usize = 20;

/// Quanti domini si accettano per una sola organizzazione.
pub const MAX_DOMAINS: usize = 20;

/// Lunghezza massima di un alias, in caratteri.
pub const MAX_ALIAS_CHARS: usize = 120;

/// Lunghezza massima di un dominio, in caratteri.
///
/// Il limite dei nomi a dominio è 253 ottetti; qui si resta al di sotto perché
/// un dominio più lungo di così, dichiarato a mano, è quasi certamente un
/// errore di digitazione.
pub const MAX_DOMAIN_CHARS: usize = 253;

/// Quante lettere o cifre deve avere un alias perché riscontri qualcosa.
///
/// # Perché tre, e perché si contano solo lettere e cifre
///
/// Un alias di uno o due caratteri riscontrerebbe ovunque: ogni contenuto che
/// nomina `AB` diventerebbe un riscontro settoriale, e sarebbe un settore
/// attribuito al rumore. Chi ha davvero bisogno di una sigla di due lettere può
/// dichiarare un dominio, che è un'ancora molto più solida.
///
/// Si contano **lettere e cifre** perché la punteggiatura non è sostanza:
/// altrimenti `---` passerebbe come alias di tre caratteri.
pub const MIN_ALIAS_CHARS: usize = 3;

/// Un nome con cui un'organizzazione può comparire in un contenuto.
///
/// Conserva **due** forme: quella che l'amministratore ha scritto, che è ciò che
/// legge chi rilegge la dichiarazione, e quella normalizzata, che è ciò con cui
/// si confronta il testo. Tenerle separate evita il difetto in cui la forma
/// mostrata e la forma cercata divergono senza che nessuno se ne accorga.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct OrganisationAlias {
    /// La forma scritta dall'amministratore.
    written: String,
    /// La forma con cui si confronta il testo.
    normalised: String,
}

impl OrganisationAlias {
    /// Costruisce l'alias validandolo e normalizzandolo.
    ///
    /// # Errori
    ///
    /// Rifiuta un alias vuoto, più corto di [`MIN_ALIAS_CHARS`], più lungo di
    /// [`MAX_ALIAS_CHARS`], o la cui forma normalizzata risulti vuota — che
    /// accade quando l'alias è fatto di sola punteggiatura.
    pub fn try_new(raw: &str) -> DomainResult<Self> {
        let written = raw.trim();

        if written.is_empty() {
            return Err(DomainError::Empty {
                field: "alias dell'organizzazione",
            });
        }
        if written.chars().count() > MAX_ALIAS_CHARS {
            return Err(DomainError::TooLong {
                field: "alias dell'organizzazione",
                max: MAX_ALIAS_CHARS,
                actual: written.chars().count(),
            });
        }

        let normalised = normalise_for_matching(written);

        // Si contano i caratteri **alfanumerici**, non tutti.
        //
        // La ragione l'ha trovata una prova diventata rossa: si era supposto
        // che `normalise_for_matching` togliesse la punteggiatura, e non lo fa
        // — applica NFC e minuscolo, nient'altro. Contando tutti i caratteri,
        // «---» sarebbe passato come alias di tre caratteri, e avrebbe
        // riscontrato in ogni contenuto che contiene un trattino triplo.
        //
        // Contare la sostanza e' anche la regola giusta nel merito: «S.p.A.»
        // ha sei caratteri scritti e tre di sostanza, ed e' quella che decide
        // se l'alias riscontrera' qualcosa di riconoscibile.
        let sostanza = normalised
            .chars()
            .filter(|carattere| carattere.is_alphanumeric())
            .count();

        if sostanza < MIN_ALIAS_CHARS {
            return Err(DomainError::InvalidWatchedOrganisation {
                reason: "un alias con meno di tre lettere o cifre riscontrerebbe \
                         ovunque: dichiarare un dominio, che è un'ancora più solida",
            });
        }

        Ok(Self {
            written: written.to_owned(),
            normalised,
        })
    }

    /// La forma scritta dall'amministratore.
    #[must_use]
    pub fn written(&self) -> &str {
        &self.written
    }

    /// La forma con cui si confronta il testo.
    #[must_use]
    pub fn normalised(&self) -> &str {
        &self.normalised
    }
}

/// Un dominio dichiarato per un'organizzazione.
///
/// # Perché il dominio è un'ancora migliore del nome
///
/// Un nome è ambiguo — esistono organizzazioni omonime, e una parola comune può
/// essere anche una ragione sociale. Un dominio no: chi lo registra è uno solo.
/// Per questo, quando entrambi riscontrano, il prodotto mostra il dominio.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct OrganisationDomain(String);

impl OrganisationDomain {
    /// Costruisce il dominio validandolo e normalizzandolo in minuscolo.
    ///
    /// # Errori
    ///
    /// Rifiuta un dominio vuoto, troppo lungo, privo di punto, o che contenga
    /// caratteri che un nome a dominio non può contenere. **Rifiuta anche uno
    /// schema o un percorso**: `https://alfa.example/pagina` non è un dominio, e
    /// accettarlo significherebbe non riscontrare mai.
    pub fn try_new(raw: &str) -> DomainResult<Self> {
        let pulito = raw.trim().trim_end_matches('.').to_lowercase();

        if pulito.is_empty() {
            return Err(DomainError::Empty {
                field: "dominio dell'organizzazione",
            });
        }
        if pulito.chars().count() > MAX_DOMAIN_CHARS {
            return Err(DomainError::TooLong {
                field: "dominio dell'organizzazione",
                max: MAX_DOMAIN_CHARS,
                actual: pulito.chars().count(),
            });
        }
        if !pulito.contains('.') {
            return Err(DomainError::InvalidWatchedOrganisation {
                reason: "un dominio contiene almeno un punto",
            });
        }
        // Uno schema o un percorso indicano che è stato incollato un URL. Va
        // detto invece di essere tagliato in silenzio: tagliarlo indovinerebbe
        // che cosa l'amministratore intendeva.
        if pulito.contains("://") || pulito.contains('/') {
            return Err(DomainError::InvalidWatchedOrganisation {
                reason: "indicare il solo dominio, senza schema né percorso",
            });
        }
        if !pulito
            .chars()
            .all(|carattere| carattere.is_ascii_alphanumeric() || matches!(carattere, '.' | '-'))
        {
            return Err(DomainError::InvalidWatchedOrganisation {
                reason: "un dominio contiene lettere, cifre, punti e trattini",
            });
        }
        if pulito.starts_with('.') || pulito.starts_with('-') || pulito.ends_with('-') {
            return Err(DomainError::InvalidWatchedOrganisation {
                reason: "un dominio non comincia con un punto o un trattino, né finisce con un trattino",
            });
        }

        Ok(Self(pulito))
    }

    /// Il dominio, normalizzato in minuscolo.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Se il dominio osservato **è** questo, oppure ne è un sottodominio.
    ///
    /// # Perché il sottodominio conta
    ///
    /// Chi dichiara `alfa.example` intende l'organizzazione, non quel solo nome:
    /// `posta.alfa.example` è la stessa organizzazione. Il confronto è sul
    /// **confine di etichetta** — il carattere che precede dev'essere un punto —
    /// così che `nonalfa.example` non riscontri: senza quel controllo, dichiarare
    /// `alfa.example` riscontrerebbe in `nonalfa.example`.
    #[must_use]
    pub fn matches(&self, observed: &str) -> bool {
        let osservato = observed.trim().trim_end_matches('.').to_lowercase();

        if osservato == self.0 {
            return true;
        }
        osservato
            .strip_suffix(&self.0)
            .is_some_and(|prefisso| prefisso.ends_with('.'))
    }
}

/// Un'organizzazione che l'amministratore ha dichiarato di sorvegliare, con il
/// settore in cui l'ha collocata.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WatchedOrganisation {
    /// Identificatore assegnato dalla persistenza.
    pub id: WatchedOrganisationId,
    /// Il nome con cui l'operatore la riconosce.
    pub name: DisplayName,
    /// Il settore NIS2 in cui l'amministratore l'ha collocata.
    ///
    /// # Perché il settore lo sceglie una persona
    ///
    /// Dedurlo dal nome richiederebbe un elenco di enti, che il prodotto non ha
    /// e non deve avere, oppure un'euristica sul testo, che sarebbe
    /// un'attribuzione inventata. Sceglierlo è un atto, e come tale è auditato.
    pub sector: Sector,
    /// I nomi con cui l'organizzazione può comparire in un contenuto.
    pub aliases: Vec<OrganisationAlias>,
    /// I domini dichiarati per l'organizzazione.
    pub domains: Vec<OrganisationDomain>,
    /// Annotazione dell'amministratore.
    pub note: Option<Note>,
    /// Se l'organizzazione partecipa al riscontro.
    ///
    /// # Perché si disattiva invece di cancellare
    ///
    /// Un monitoraggio già svolto ha prodotto riscontri che nominano questa
    /// organizzazione. Cancellarla renderebbe inspiegabile un riscontro già
    /// registrato; disattivarla lo lascia leggibile e ferma i riscontri futuri.
    pub active: bool,
    /// Chi l'ha dichiarata.
    pub declared_by: Actor,
    /// Quando è stata dichiarata.
    pub declared_at: Timestamp,
    /// Quando è stata modificata l'ultima volta.
    pub updated_at: Timestamp,
}

impl WatchedOrganisation {
    /// Se l'organizzazione può produrre un riscontro.
    ///
    /// Un'organizzazione senza alcun alias e senza alcun dominio non potrebbe
    /// riscontrare nulla: esiste, ma è muta. La costruzione la rifiuta, e questo
    /// metodo lo verifica anche su ciò che arriva dall'archivio.
    #[must_use]
    pub fn can_match(&self) -> bool {
        !self.aliases.is_empty() || !self.domains.is_empty()
    }
}

/// Un'organizzazione che si intende dichiarare.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewWatchedOrganisation {
    /// Il nome con cui l'operatore la riconosce.
    pub name: DisplayName,
    /// Il settore NIS2 scelto dall'amministratore.
    pub sector: Sector,
    /// I nomi con cui può comparire in un contenuto.
    pub aliases: Vec<OrganisationAlias>,
    /// I domini dichiarati.
    pub domains: Vec<OrganisationDomain>,
    /// Annotazione dell'amministratore.
    pub note: Option<Note>,
    /// Chi la dichiara.
    pub declared_by: Actor,
    /// Quando.
    pub declared_at: Timestamp,
}

impl NewWatchedOrganisation {
    /// Costruisce la dichiarazione, verificandone le invarianti.
    ///
    /// Ordina e deduplica alias e domini: due dichiarazioni identiche a meno
    /// dell'ordine devono produrre lo stesso riscontro, e lo stesso alias
    /// scritto due volte non deve produrre due riscontri.
    ///
    /// # Errori
    ///
    /// - **nessun alias e nessun dominio**: l'organizzazione non potrebbe
    ///   riscontrare nulla, e dichiararla darebbe l'impressione che sia
    ///   sorvegliata;
    /// - **troppi alias o troppi domini**: vedere [`MAX_ALIASES`] e
    ///   [`MAX_DOMAINS`].
    pub fn try_new(
        name: DisplayName,
        sector: Sector,
        mut aliases: Vec<OrganisationAlias>,
        mut domains: Vec<OrganisationDomain>,
        note: Option<Note>,
        declared_by: Actor,
        declared_at: Timestamp,
    ) -> DomainResult<Self> {
        aliases.sort();
        aliases.dedup();
        domains.sort();
        domains.dedup();

        if aliases.is_empty() && domains.is_empty() {
            return Err(DomainError::InvalidWatchedOrganisation {
                reason: "servono almeno un nome alternativo o un dominio: senza, \
                 l'organizzazione non potrebbe riscontrare alcun contenuto",
            });
        }
        if aliases.len() > MAX_ALIASES {
            return Err(DomainError::InvalidWatchedOrganisation {
                reason: "troppi nomi alternativi",
            });
        }
        if domains.len() > MAX_DOMAINS {
            return Err(DomainError::InvalidWatchedOrganisation {
                reason: "troppi domini",
            });
        }

        Ok(Self {
            name,
            sector,
            aliases,
            domains,
            note,
            declared_by,
            declared_at,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::{
        MAX_ALIASES, NewWatchedOrganisation, OrganisationAlias, OrganisationDomain,
        WatchedOrganisation,
    };
    use crate::id::WatchedOrganisationId;
    use crate::model::relevance::Sector;
    use crate::text::{Actor, DisplayName};
    use crate::time::Timestamp;

    fn attore() -> Actor {
        let Ok(valore) = Actor::try_new("amministratore.prova") else {
            panic!("l'attore di prova deve essere valido");
        };
        valore
    }

    fn nome(testo: &str) -> DisplayName {
        let Ok(valore) = DisplayName::try_new(testo) else {
            panic!("il nome di prova deve essere valido");
        };
        valore
    }

    fn alias(testo: &str) -> OrganisationAlias {
        let Ok(valore) = OrganisationAlias::try_new(testo) else {
            panic!("l'alias di prova «{testo}» deve essere valido");
        };
        valore
    }

    fn dominio(testo: &str) -> OrganisationDomain {
        let Ok(valore) = OrganisationDomain::try_new(testo) else {
            panic!("il dominio di prova «{testo}» deve essere valido");
        };
        valore
    }

    #[test]
    fn lalias_conserva_la_forma_scritta_e_quella_confrontata() {
        let voce = alias("Azienda Esempio S.p.A.");

        assert_eq!(voce.written(), "Azienda Esempio S.p.A.");
        assert_ne!(
            voce.normalised(),
            voce.written(),
            "la forma normalizzata deve differire da quella scritta, altrimenti \
             la normalizzazione non sta facendo nulla"
        );
    }

    #[test]
    fn un_alias_troppo_corto_e_rifiutato() {
        // Due caratteri riscontrerebbero ovunque: sarebbe un settore attribuito
        // al rumore.
        assert!(OrganisationAlias::try_new("AB").is_err());
        assert!(OrganisationAlias::try_new("  ").is_err());
        // Sei caratteri scritti, ma la sostanza e' «spa»: si conta il
        // normalizzato, non il grezzo.
        assert!(OrganisationAlias::try_new("S.p.A.").is_ok());
    }

    #[test]
    fn un_alias_di_sola_punteggiatura_e_rifiutato() {
        assert!(OrganisationAlias::try_new("---").is_err());
        assert!(OrganisationAlias::try_new("...").is_err());
    }

    #[test]
    fn il_dominio_si_normalizza_in_minuscolo_e_senza_punto_finale() {
        assert_eq!(dominio("Alfa.EXAMPLE.").as_str(), "alfa.example");
    }

    #[test]
    fn un_url_non_e_un_dominio_e_viene_rifiutato() {
        // Tagliarlo in silenzio indovinerebbe che cosa l'amministratore
        // intendeva; rifiutarlo glielo fa correggere.
        assert!(OrganisationDomain::try_new("https://alfa.example").is_err());
        assert!(OrganisationDomain::try_new("alfa.example/pagina").is_err());
    }

    #[test]
    fn un_dominio_senza_punto_e_rifiutato() {
        assert!(OrganisationDomain::try_new("esempio").is_err());
    }

    #[test]
    fn il_dominio_riscontra_se_stesso_e_i_propri_sottodomini() {
        let voce = dominio("alfa.example");

        assert!(voce.matches("alfa.example"));
        assert!(voce.matches("posta.alfa.example"));
        assert!(voce.matches("ALFA.EXAMPLE"));
    }

    #[test]
    fn il_dominio_non_riscontra_dentro_unaltra_etichetta() {
        // Senza il confine di etichetta, dichiarare «alfa.example»
        // riscontrerebbe in «nonalfa.example», che e' un'altra organizzazione.
        let voce = dominio("alfa.example");

        assert!(!voce.matches("nonalfa.example"));
        assert!(!voce.matches("alfa.example.altro.test"));
    }

    #[test]
    fn unorganizzazione_senza_alias_e_senza_domini_e_rifiutata() {
        let esito = NewWatchedOrganisation::try_new(
            nome("Ente"),
            Sector::PubblicaAmministrazione,
            Vec::new(),
            Vec::new(),
            None,
            attore(),
            Timestamp::from_millis(1_000),
        );

        assert!(
            esito.is_err(),
            "un'organizzazione che non puo' riscontrare nulla darebbe \
             l'impressione di essere sorvegliata senza esserlo"
        );
    }

    #[test]
    fn alias_e_domini_sono_ordinati_e_deduplicati() {
        let Ok(voce) = NewWatchedOrganisation::try_new(
            nome("Ente"),
            Sector::Energia,
            vec![
                alias("Beta Energia"),
                alias("Alfa Energia"),
                alias("Beta Energia"),
            ],
            vec![
                dominio("beta.example"),
                dominio("alfa.example"),
                dominio("BETA.EXAMPLE"),
            ],
            None,
            attore(),
            Timestamp::from_millis(1_000),
        ) else {
            panic!("la dichiarazione deve essere valida");
        };

        assert_eq!(
            voce.aliases.len(),
            2,
            "l'alias ripetuto va contato una volta"
        );
        assert_eq!(
            voce.domains.len(),
            2,
            "il dominio ripetuto va contato una volta"
        );
        assert!(voce.aliases[0].written() < voce.aliases[1].written());
    }

    #[test]
    fn troppi_alias_sono_rifiutati() {
        let troppi: Vec<OrganisationAlias> = (0..=MAX_ALIASES)
            .map(|indice| alias(&format!("nome alternativo numero {indice}")))
            .collect();

        let esito = NewWatchedOrganisation::try_new(
            nome("Ente"),
            Sector::Sanita,
            troppi,
            Vec::new(),
            None,
            attore(),
            Timestamp::from_millis(1_000),
        );

        assert!(esito.is_err());
    }

    #[test]
    fn unorganizzazione_muta_si_riconosce_anche_se_arriva_dallarchivio() {
        // La costruzione la rifiuta, ma cio' che viene riletto dall'archivio non
        // passa dalla costruzione: il controllo serve anche li'.
        let muta = WatchedOrganisation {
            id: WatchedOrganisationId::new(1),
            name: nome("Ente"),
            sector: Sector::Trasporti,
            aliases: Vec::new(),
            domains: Vec::new(),
            note: None,
            active: true,
            declared_by: attore(),
            declared_at: Timestamp::from_millis(1_000),
            updated_at: Timestamp::from_millis(1_000),
        };

        assert!(!muta.can_match());
    }

    /// **Nessun nome di organizzazione vive nel sorgente.**
    ///
    /// E' la regola di `PD6_SECTOR_TAXONOMY.md`: un elenco di enti inciso nel
    /// codice sarebbe una lista arbitraria che nessuno ha approvato e che, su
    /// ogni postazione, direbbe a chiunque la legga quali enti l'ufficio
    /// considera bersagli.
    ///
    /// La verifica e' testuale e lo dichiara: cerca nel codice **di
    /// produzione** di questo modulo un elenco di nomi. Le prove qui sopra
    /// usano nomi inventati — «Ente», «Alfa», «Beta», «alfa.example» — e stanno
    /// sotto `cfg(test)`, che questa verifica esclude.
    #[test]
    fn il_sorgente_non_contiene_alcun_elenco_di_organizzazioni() {
        const SORGENTE: &str = include_str!("organisation.rs");

        let Some((produzione, _)) = SORGENTE.split_once("#[cfg(test)]\nmod tests {") else {
            panic!("il modulo deve avere un blocco di prove riconoscibile");
        };

        // Un elenco di enti si riconosce dalla forma: un array di stringhe
        // costante. Nel codice di produzione di questo modulo non ce n'e'
        // alcuno, e non deve comparirne.
        assert!(
            !produzione.contains("&[&str]"),
            "il codice di produzione di questo modulo dichiara un elenco di \
             stringhe costanti: se e' un elenco di organizzazioni, va tolto — \
             l'elenco lo dichiara un amministratore, non il sorgente"
        );
    }

    /// **Nemmeno un esempio nomina un'organizzazione reale.**
    ///
    /// # Perche' questa prova esiste
    ///
    /// L'ha chiesta un errore vero. Scrivendo CYBER-SECTOR, il commento che
    /// spiega il confine di etichetta usava come esempio **il dominio di una
    /// emittente italiana reale**: un esempio efficace, e il nome di un ente
    /// vero spedito su ogni postazione.
    ///
    /// Il dominio non si riscrive qui nemmeno per raccontarlo — sarebbe di nuovo
    /// nel sorgente, e questa prova lo troverebbe. È il difetto delle prove che
    /// trovano sé stesse, già incontrato in DEC-230 e DEC-233.
    ///
    /// Non era un elenco, quindi la prova qui sopra restava verde. Ma la regola
    /// di `PD6_SECTOR_TAXONOMY.md` non parla solo di elenchi: dice che il
    /// sorgente non deve dire a chi lo legge quali enti l'ufficio guarda. Un
    /// esempio scelto fra i nomi che verrebbero in mente lo dice comunque.
    ///
    /// # Come funziona
    ///
    /// Cerca nel modulo intero — prove comprese, perche' anche una prova viene
    /// distribuita nel sorgente — un dominio **etichettato** sotto un TLD
    /// nazionale. Gli esempi devono usare `.example`, che l'RFC 2606 riserva
    /// esattamente a questo.
    ///
    /// Non copre i nomi senza dominio: un ente nominato in prosa passerebbe. E'
    /// una guardia sulla forma piu' probabile, non una garanzia — e va detto.
    #[test]
    fn nessun_esempio_nomina_unorganizzazione_reale() {
        const SORGENTE: &str = include_str!("organisation.rs");

        // Suffissi nazionali che, preceduti da un'etichetta, indicano
        // un'organizzazione vera invece di un esempio.
        //
        // Si compongono a **tempo di esecuzione**, dal punto e dal codice del
        // paese: scritti come stringhe letterali, questa prova troverebbe sé
        // stessa — il difetto di DEC-230 e DEC-233, che qui si presenterebbe
        // come una guardia permanentemente rossa e verrebbe cancellata.
        let suffissi: Vec<String> = ["it", "fr", "de", "es", "eu"]
            .iter()
            .map(|paese| format!(".{paese}"))
            .collect();

        for suffisso in suffissi.iter().map(String::as_str) {
            let mut cercato = SORGENTE;
            while let Some(posizione) = cercato.find(suffisso) {
                let prima = &cercato[..posizione];

                // Un'etichetta prima del punto indica un dominio; il solo
                // suffisso citato non lo e'.
                let etichettato = prima
                    .chars()
                    .last()
                    .is_some_and(|carattere| carattere.is_ascii_alphanumeric() || carattere == '-');

                // E dopo il suffisso non puo' esserci una lettera: un TLD
                // finisce li'. Senza questo controllo la prova trovava se'
                // stessa — `suffissi.iter()` contiene «.it» preceduto da una
                // lettera — ed e' la terza volta che questo progetto incontra
                // una guardia che si riconosce nel proprio codice (DEC-230,
                // DEC-233). Qui il rimedio rende la regola anche piu' esatta:
                // «.it» dentro «.iter()» non e' un dominio.
                let dopo = &cercato[posizione + suffisso.len()..];
                let seguito_da_lettera = dopo
                    .chars()
                    .next()
                    .is_some_and(|carattere| carattere.is_ascii_alphanumeric());

                assert!(
                    !etichettato || seguito_da_lettera,
                    "il modulo nomina un dominio sotto «{suffisso}»: se e' un \
                     esempio, va scritto sotto «.example», che l'RFC 2606 riserva \
                     a questo. Il sorgente non deve dire a chi lo legge quali enti \
                     l'ufficio guarda."
                );

                cercato = &cercato[posizione + suffisso.len()..];
            }
        }
    }
}
