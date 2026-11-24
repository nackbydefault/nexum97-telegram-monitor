//! Formato di scambio dei dizionari: seed, import ed export.
//!
//! Le scelte sono motivate in `docs/adr/ADR-0014-DICTIONARY-EXCHANGE-FORMAT.md`.
//! Tre punti toccano direttamente questo codice.
//!
//! **I seed usano lo stesso formato dell'import.** Non esiste una forma interna
//! privilegiata. Se ci fosse, il percorso di import verrebbe esercitato soltanto
//! dai file che qualcuno si ricorda di provare; così invece è esercitato dai
//! dati che il prodotto stesso spedisce, e un test li importa tutti.
//!
//! **Un file importato è ostile finché non è stato letto.** La dimensione è
//! verificata, i campi sconosciuti sono rifiutati invece che ignorati, e ogni
//! valore passa dai tipi validati del dominio. La scrittura è **una sola
//! transazione**: un file rifiutato a metà non deve lasciare un contenitore
//! vuoto che ha già consumato il nome.
//!
//! **Limite dichiarato:** [`DictionaryService::import`] riceve i byte, non un
//! percorso, quindi il limite di dimensione agisce su un contenuto già in
//! memoria. Chi collegherà un selettore di file dovrà limitare la lettura prima
//! di chiamare. Oggi nessun percorso dell'interfaccia importa da disco.
//!
//! **Un import non pubblica nulla.** Il dizionario entra personale e in bozza:
//! l'operatore lo guarda, lo corregge se serve, e pubblica lui. Un file che
//! entrasse già pubblicato scavalcherebbe la sola verifica umana prevista.

use lisi_core::model::dictionary::{
    DictionaryOrigin, DictionaryScope, DictionaryStatus, DictionaryVisibility, MAX_IMPORT_BYTES,
    MAX_TERMS_PER_DICTIONARY, NewDictionary, SuggestedLevel, UnboundTerm, check_new_term,
};
use lisi_core::text::{
    Actor, DictionaryDescription, DictionaryName, LanguageTag, TermCategory, TermNote, TermText,
};
use lisi_core::{DictionaryId, DictionaryVersionId, RestrictedAction, Timestamp};
use lisi_storage::StorageError;
use serde::{Deserialize, Serialize};

use crate::dictionaries::DictionaryService;
use crate::error::{ServiceError, ServiceResult, from_storage};
use crate::protected_output::{Delivery, Existing, REFUSED_AUDIT_ACTION, record_refusal};

/// Ciò che si dice quando il dizionario non si scrive per i permessi.
const DICTIONARY_NOT_WRITTEN: &str = "Il dizionario esportato NON è stato scritto";

/// Marcatore che identifica il formato.
const FORMAT_MARKER: &str = "nexum-dictionary";

/// Versione del formato prodotta e accettata da questa versione del prodotto.
const FORMAT_VERSION: u32 = 1;

/// Autore attribuito ai dizionari forniti con il prodotto.
const SEED_AUTHOR: &str = "sistema";

/// Dizionari inclusi nel binario.
///
/// Sono `include_str!`: entrano nell'eseguibile e non dipendono da file
/// presenti sul disco della postazione, che potrebbero mancare o essere stati
/// sostituiti.
///
/// I dizionari operativi stanno soltanto nell'archivio; la copia pubblica del
/// codice porta al loro posto due dizionari d'esempio neutri, nello stesso
/// formato (ADR-0210, DEC-522).
const SEEDS: &[&str] = &[
    include_str!("../../../assets/dizionari-esempio/esempio-termini.json"),
    include_str!("../../../assets/dizionari-esempio/esempio-contesto-riduttivo.json"),
];

/// Esito dell'installazione dei dizionari forniti con il prodotto.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct SeedOutcome {
    /// Dizionari installati per la prima volta.
    pub installed: usize,
    /// Dizionari aggiornati a una versione più recente.
    pub updated: usize,
    /// Dizionari già presenti e già aggiornati.
    pub unchanged: usize,
}

// --------------------------------------------------------------- il formato

/// File di scambio di un dizionario.
#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct DictionaryFile {
    /// Marcatore del formato.
    format: String,
    /// Versione del formato.
    format_version: u32,
    /// Nome del dizionario.
    name: String,
    /// Descrizione.
    description: String,
    /// Ambito.
    scope: String,
    /// Versione trasportata.
    version: VersionFile,
    /// Termini.
    terms: Vec<TermFile>,
}

/// Versione trasportata dal file.
#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct VersionFile {
    /// Numero progressivo.
    number: u32,
    /// Nota di rilascio.
    note: String,
}

/// Termine trasportato dal file.
#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct TermFile {
    /// Testo.
    text: String,
    /// Categoria.
    category: String,
    /// Lingua.
    language: String,
    /// Modalità di riscontro.
    match_mode: String,
    /// Livello suggerito.
    suggested_level: i8,
    /// Nota che spiega perché il termine è presente.
    note: String,
}

/// Contenuto di un file già verificato.
///
/// Lo legge anche lo scaricamento dalla rete (DICT-NET-01, ADR-0178,
/// decisione 8): la **stessa** lettura, con tutti i suoi rifiuti.
pub(crate) struct ParsedDictionary {
    pub(crate) name: DictionaryName,
    pub(crate) description: DictionaryDescription,
    pub(crate) scope: DictionaryScope,
    pub(crate) number: u32,
    pub(crate) note: DictionaryDescription,
    pub(crate) terms: Vec<UnboundTerm>,
}

/// Legge e verifica un file di scambio.
///
/// L'ordine dei controlli non è casuale: la dimensione prima della struttura,
/// il marcatore prima dei valori. Ogni passo restringe ciò che il passo
/// successivo deve affrontare.
pub(crate) fn parse(bytes: &[u8]) -> ServiceResult<ParsedDictionary> {
    if bytes.len() > MAX_IMPORT_BYTES {
        return Err(ServiceError::ImportTooLarge {
            max: MAX_IMPORT_BYTES,
        });
    }

    let file: DictionaryFile =
        serde_json::from_slice(bytes).map_err(|_| ServiceError::ImportRefused {
            reason: "la struttura del file non corrisponde a quella attesa",
        })?;

    if file.format != FORMAT_MARKER {
        return Err(ServiceError::ImportRefused {
            reason: "non è un dizionario di questo prodotto",
        });
    }
    if file.format_version != FORMAT_VERSION {
        return Err(ServiceError::ImportRefused {
            reason: "usa una versione del formato che questa versione non conosce",
        });
    }
    if file.terms.len() > MAX_TERMS_PER_DICTIONARY {
        return Err(ServiceError::ImportRefused {
            reason: "contiene più termini di quanti un dizionario ne ammetta",
        });
    }
    if file.version.number == 0 {
        return Err(ServiceError::ImportRefused {
            reason: "dichiara un numero di versione non valido",
        });
    }

    let mut terms = Vec::with_capacity(file.terms.len());
    for (indice, term) in file.terms.into_iter().enumerate() {
        let match_mode = term.match_mode.parse()?;
        // Un termine di sole cifre è un codice numerico, o il file si rifiuta
        // (DICT-CODES-01, ADR-0170, decisione 5).
        //
        // UN'ESPRESSIONE NON AMMESSA SI DICE CON LA SUA POSIZIONE E IL PERCHE'
        // (COLLAUDO-FIX-01, CU01-003, DEC-510): nel collaudo era «problema
        // tecnico». Il testo del termine non si ripete, come per `ImportRefused`.
        check_new_term(&term.text, match_mode, term.suggested_level).map_err(
            |errore| match errore {
                lisi_core::DomainError::InvalidExpression { reason } => {
                    ServiceError::ImportExpressionRefused {
                        position: indice + 1,
                        reason,
                    }
                }
                altro => ServiceError::from(altro),
            },
        )?;
        terms.push(UnboundTerm {
            text: TermText::try_new(&term.text)?,
            category: TermCategory::try_new(&term.category)?,
            language: LanguageTag::try_new(&term.language)?,
            match_mode,
            suggested_level: SuggestedLevel::try_new(term.suggested_level)?,
            note: TermNote::try_new(&term.note)?,
        });
    }

    Ok(ParsedDictionary {
        name: DictionaryName::try_new(&file.name)?,
        description: DictionaryDescription::try_new(&file.description)?,
        scope: file.scope.parse()?,
        number: file.version.number,
        note: DictionaryDescription::try_new(&file.version.note)?,
        terms,
    })
}

impl DictionaryService {
    // ---------------------------------------------------------------- import

    /// Importa un dizionario da un file di scambio.
    ///
    /// Entra **personale, in bozza**, con origine `imported`. Non viene
    /// pubblicato: la verifica di ciò che è entrato spetta a chi importa.
    ///
    /// # Errori
    ///
    /// Restituisce [`ServiceError::ImportTooLarge`] se il file supera
    /// [`MAX_IMPORT_BYTES`], [`ServiceError::ImportRefused`] se non è un file
    /// di questo formato, [`ServiceError::Domain`] se un valore non è ammesso e
    /// [`ServiceError::DictionaryNameAlreadyUsed`] se il nome è già usato.
    pub fn import(
        &mut self,
        bytes: &[u8],
        actor: &Actor,
        now: Timestamp,
    ) -> ServiceResult<(DictionaryId, DictionaryVersionId)> {
        // Il controllo precede la lettura: un file riservato non va nemmeno
        // interpretato, perche' interpretarlo e' gia' esporsi al suo contenuto.
        self.require(RestrictedAction::ImportDictionary)?;

        let parsed = parse(bytes)?;

        let new = NewDictionary {
            name: parsed.name.clone(),
            description: parsed.description,
            scope: parsed.scope,
            origin: DictionaryOrigin::Imported,
            visibility: DictionaryVisibility::Personal,
            created_by: actor.clone(),
            derived_from: None,
        };

        let (dictionary_id, version_id) = self.write(&new, &parsed.note, 1, parsed.terms, now)?;

        self.audit(
            actor,
            "dizionario_importato",
            dictionary_id,
            parsed.name.as_str(),
            now,
        )?;
        Ok((dictionary_id, version_id))
    }

    // ---------------------------------------------------------------- export

    /// Esporta una versione nel formato di scambio.
    ///
    /// Il file trasporta il **contenuto**, non lo stato: identificatori,
    /// visibilità, autore e istanti restano sulla postazione di origine. Non è
    /// un backup, ed è un file **non firmato**: vale quanto vale la fiducia in
    /// chi lo consegna.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se la versione non esiste o se la lettura non
    /// riesce.
    pub fn export(&self, version_id: DictionaryVersionId) -> ServiceResult<String> {
        let version = self
            .database()
            .dictionary_version(version_id)
            .map_err(from_storage)?;
        let dictionary = self.database().dictionary(version.dictionary_id)?;
        let terms = self.database().dictionary_terms(version_id)?;

        let file = DictionaryFile {
            format: String::from(FORMAT_MARKER),
            format_version: FORMAT_VERSION,
            name: dictionary.name.as_str().to_owned(),
            description: dictionary.description.as_str().to_owned(),
            scope: dictionary.scope.as_str().to_owned(),
            version: VersionFile {
                number: version.number,
                note: version.note.as_str().to_owned(),
            },
            terms: terms
                .into_iter()
                .map(|term| TermFile {
                    text: term.text.as_str().to_owned(),
                    category: term.category.as_str().to_owned(),
                    language: term.language.as_str().to_owned(),
                    match_mode: term.match_mode.as_str().to_owned(),
                    suggested_level: term.suggested_level.get(),
                    note: term.note.as_str().to_owned(),
                })
                .collect(),
        };

        serde_json::to_string_pretty(&file).map_err(|_| ServiceError::ImportRefused {
            reason: "il contenuto non è rappresentabile nel formato di scambio",
        })
    }

    /// L'impronta dei termini di una versione (NEXUM97-MINOR-FIX-01, GAP-19).
    ///
    /// # Perché dei termini, e non del file
    ///
    /// Un dizionario esportato e reimportato altrove riparte dalla versione 1,
    /// e può cambiare nome: il file riesportato non è lo stesso file. I termini
    /// sì. L'impronta è lo SHA-256 dei termini **in ordine canonico** — testo,
    /// modo, categoria, lingua, livello, nota — così l'ordine in cui il file li
    /// elenca non la cambia, e un termine cambiato sì. Due postazioni la
    /// confrontano a vista. **Non è una firma**: dice che i termini sono gli
    /// stessi, non chi li ha scritti.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se la versione non esiste o la lettura non riesce.
    pub fn terms_fingerprint(&self, version_id: DictionaryVersionId) -> ServiceResult<String> {
        let mut righe: Vec<String> = self
            .database()
            .dictionary_terms(version_id)?
            .into_iter()
            .map(|term| {
                [
                    term.text.as_str().to_owned(),
                    term.match_mode.as_str().to_owned(),
                    term.category.as_str().to_owned(),
                    term.language.as_str().to_owned(),
                    term.suggested_level.get().to_string(),
                    term.note.as_str().to_owned(),
                ]
                .join("\u{1f}")
            })
            .collect();
        righe.sort();
        Ok(lisi_core::digest::Sha256Digest::of_text(&righe.join("\n"))
            .as_str()
            .to_owned())
    }

    /// Esporta una versione **pubblicata** nel file indicato, e registra
    /// l'esportazione (GAP-19).
    ///
    /// Restituisce l'impronta dei termini. Una bozza non si esporta: chi riceve
    /// il file deve avere ciò che questa postazione usa, non un lavoro in corso.
    /// **L'audit segue il file**: se il file non si scrive, nessuna riga dice
    /// che un'esportazione è avvenuta.
    ///
    /// # Errori
    ///
    /// [`ServiceError::ImportRefused`] se la versione non è pubblicata;
    /// [`ServiceError::ExportNotWritten`] se il file non si scrive; un errore di
    /// lettura o di scrittura dell'audit altrimenti.
    pub fn export_published(
        &self,
        version_id: DictionaryVersionId,
        destination: &std::path::Path,
        actor: &Actor,
        now: Timestamp,
    ) -> ServiceResult<String> {
        let version = self
            .database()
            .dictionary_version(version_id)
            .map_err(from_storage)?;
        if !version.is_published() {
            return Err(ServiceError::ImportRefused {
                reason: "si esporta soltanto una versione pubblicata",
            });
        }
        let testo = self.export(version_id)?;
        let impronta = self.terms_fingerprint(version_id)?;
        // DEL SOLO UTENTE, O NIENTE (SEC-02, ADR-0157): un dizionario dice che
        // cosa l'ufficio cerca. Il nome l'ha scelto l'operatore in una finestra
        // che gli ha chiesto se sostituire un file esistente.
        let (Some(cartella), Some(nome)) = (
            destination.parent(),
            destination
                .file_name()
                .map(|nome| nome.to_string_lossy().into_owned()),
        ) else {
            return Err(ServiceError::ExportNotWritten {
                reason: String::from("il percorso del dizionario non indica un file"),
            });
        };
        Delivery::begin(cartella, &nome, DICTIONARY_NOT_WRITTEN)
            .and_then(|mut consegna| {
                consegna.write(&nome, testo.as_bytes())?;
                consegna.deliver(Existing::Replace)
            })
            .inspect_err(|errore| {
                record_refusal(
                    self.database(),
                    actor,
                    now,
                    REFUSED_AUDIT_ACTION,
                    "dizionario",
                    errore,
                );
            })?;
        let dizionario = self.database().dictionary(version.dictionary_id)?;
        self.audit(
            actor,
            "dizionario_esportato",
            version.dictionary_id,
            &format!(
                "{} versione {}; impronta dei termini {impronta}",
                dizionario.name.as_str(),
                version.number
            ),
            now,
        )?;
        Ok(impronta)
    }

    // ------------------------------------------------------------------ seed

    /// Installa o aggiorna i dizionari forniti con il prodotto.
    ///
    /// È idempotente: eseguirla a ogni avvio non duplica nulla. Un seed che
    /// dichiari un numero di versione più alto di quello già presente viene
    /// aggiunto come **nuova versione** del dizionario esistente, non come
    /// dizionario nuovo: il nome e l'identità restano, il contenuto avanza.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se un seed non è leggibile — che sarebbe un
    /// difetto del prodotto, non del disco della postazione, perché i seed sono
    /// inclusi nel binario — o se la scrittura non riesce.
    pub fn install_seed_dictionaries(&mut self, now: Timestamp) -> ServiceResult<SeedOutcome> {
        let author = Actor::try_new(SEED_AUTHOR)?;
        let mut outcome = SeedOutcome::default();

        for raw in SEEDS {
            let parsed = parse(raw.as_bytes())?;

            let existing = self.database().dictionaries()?.into_iter().find(|entry| {
                entry.name == parsed.name && entry.visibility == DictionaryVisibility::BuiltIn
            });

            match existing {
                None => {
                    let new = NewDictionary {
                        name: parsed.name.clone(),
                        description: parsed.description,
                        scope: parsed.scope,
                        origin: DictionaryOrigin::System,
                        visibility: DictionaryVisibility::BuiltIn,
                        created_by: author.clone(),
                        derived_from: None,
                    };
                    let (dictionary_id, version_id) =
                        self.write(&new, &parsed.note, parsed.number, parsed.terms, now)?;

                    self.publish_unchecked(version_id, &author, now)?;
                    self.set_status(dictionary_id, DictionaryStatus::Active, &author, now)?;
                    outcome.installed += 1;
                }
                Some(dictionary) => {
                    let current = self
                        .database()
                        .latest_published_version(dictionary.id)?
                        .map_or(0, |version| version.number);

                    if parsed.number <= current {
                        outcome.unchanged += 1;
                        continue;
                    }

                    // Versione e termini in una sola transazione: una bozza
                    // vuota rimasta indietro occuperebbe quel numero, e ogni
                    // avvio successivo fallirebbe sul vincolo di unicita'.
                    let version_id = self.database_mut().insert_version_with_terms(
                        dictionary.id,
                        parsed.number,
                        &parsed.note,
                        &author,
                        &parsed.terms,
                        now,
                    )?;
                    self.publish_unchecked(version_id, &author, now)?;
                    outcome.updated += 1;
                }
            }
        }

        Ok(outcome)
    }

    /// Scrive dizionario, versione e termini in un solo percorso.
    ///
    /// Condiviso da import e seed perché la differenza fra i due è **che cosa**
    /// si scrive, non come: duplicarne la scrittura vorrebbe dire due punti in
    /// cui dimenticarsi qualcosa.
    ///
    /// La scrittura è **una sola transazione**. In tre transazioni distinte, il
    /// primo termine rifiutato — due parole che coincidono dopo la
    /// normalizzazione bastano — lascerebbe un contenitore vuoto che ha già
    /// consumato il nome: il secondo tentativo con il file corretto fallirebbe
    /// per nome già usato, e l'operatore non avrebbe modo di capire perché.
    pub(crate) fn write(
        &mut self,
        new: &NewDictionary,
        note: &DictionaryDescription,
        number: u32,
        terms: Vec<UnboundTerm>,
        now: Timestamp,
    ) -> ServiceResult<(DictionaryId, DictionaryVersionId)> {
        match self
            .database_mut()
            .insert_dictionary_with_terms(new, number, note, &terms, now)
        {
            Ok(pair) => Ok(pair),
            Err(StorageError::DuplicateDictionary) => Err(ServiceError::DictionaryNameAlreadyUsed),
            Err(other) => Err(from_storage(other)),
        }
    }
}

#[cfg(test)]
mod tests {
    use lisi_core::model::dictionary::{
        DictionaryOrigin, DictionaryStatus, DictionaryVisibility, MAX_IMPORT_BYTES,
        MAX_TERMS_PER_DICTIONARY,
    };
    use lisi_core::text::Actor;
    use lisi_core::{DictionaryVersionId, Timestamp};

    use lisi_storage::StorageError;

    use super::{FORMAT_MARKER, SEEDS, parse};
    use crate::dictionaries::DictionaryService;
    use crate::error::ServiceError;
    use crate::sources::open_in_memory_database;

    fn now() -> Timestamp {
        Timestamp::from_millis(1_700_000_000_000)
    }

    fn operator() -> Actor {
        let Ok(value) = Actor::try_new("operatore.prova") else {
            panic!("l'attore di prova deve essere valido");
        };
        value
    }

    fn service() -> DictionaryService {
        let Ok(database) = open_in_memory_database() else {
            panic!("il database in memoria deve potersi aprire");
        };
        DictionaryService::new(database)
    }

    /// File di scambio minimo e valido.
    fn valid_file() -> String {
        String::from(
            r#"{
              "format": "nexum-dictionary",
              "format_version": 1,
              "name": "Ricevuto",
              "description": "dizionario ricevuto da un collega",
              "scope": "thematic",
              "version": { "number": 1, "note": "prima stesura" },
              "terms": [
                {
                  "text": "incendio",
                  "category": "azione",
                  "language": "it",
                  "match_mode": "normalized_word",
                  "suggested_level": 2,
                  "note": "perche' e' presente"
                }
              ]
            }"#,
        )
    }

    // ------------------------------------------------------------------ seed

    #[test]
    fn every_dictionary_shipped_with_the_product_can_be_read() {
        // I seed usano lo stesso formato dell'import: questo test e' anche la
        // prova che l'importatore regge i dati che il prodotto spedisce.
        assert!(!SEEDS.is_empty());
        for (index, raw) in SEEDS.iter().enumerate() {
            let Ok(parsed) = parse(raw.as_bytes()) else {
                panic!("il seed numero {index} deve essere leggibile");
            };
            assert!(!parsed.terms.is_empty(), "un seed vuoto non si pubblica");
            assert!(raw.contains(FORMAT_MARKER));
        }
    }

    #[test]
    fn every_shipped_term_says_why_it_is_there() {
        // Un dizionario destinato a essere condiviso senza note e' un
        // dizionario che nessun altro potra' rivedere.
        for raw in SEEDS {
            let Ok(parsed) = parse(raw.as_bytes()) else {
                panic!("il seed deve essere leggibile");
            };
            for term in &parsed.terms {
                assert!(
                    !term.note.as_str().trim().is_empty(),
                    "il termine '{}' non spiega perche' e' presente",
                    term.text.as_str()
                );
            }
        }
    }

    #[test]
    fn no_shipped_text_points_the_operator_at_a_repository_path() {
        // Nome, descrizione e note finiscono sotto gli occhi dell'operatore,
        // che non ha il repository: un rimando a `docs/...` non gli dice dove
        // guardare, gli dice che qualcuno si e' dimenticato di chi legge.
        for raw in SEEDS {
            let Ok(parsed) = parse(raw.as_bytes()) else {
                panic!("il seed deve essere leggibile");
            };

            let mut visible = format!("{} {}", parsed.name.as_str(), parsed.description.as_str());
            for term in &parsed.terms {
                visible.push(' ');
                visible.push_str(term.note.as_str());
            }

            for marker in ["docs/", ".md", "crates/", "README"] {
                assert!(
                    !visible.contains(marker),
                    "il testo mostrato contiene '{marker}': {visible}"
                );
            }
        }
    }

    #[test]
    fn the_mitigating_context_really_lowers_the_weight() {
        // I livelli negativi sono cio' che permette a un dizionario di
        // riconoscere il proprio errore: se nessun seed li usasse, la
        // possibilita' resterebbe teorica.
        let mitigating = SEEDS.iter().any(|raw| {
            let Ok(parsed) = parse(raw.as_bytes()) else {
                panic!("il seed deve essere leggibile");
            };
            parsed
                .terms
                .iter()
                .any(|term| term.suggested_level.is_mitigating())
        });
        assert!(
            mitigating,
            "nessun seed contiene termini di contesto riduttivo"
        );
    }

    #[test]
    fn installing_the_seeds_makes_them_usable_and_read_only() {
        let mut service = service();
        let Ok(outcome) = service.install_seed_dictionaries(now()) else {
            panic!("l'installazione dei seed deve riuscire");
        };

        assert_eq!(outcome.installed, SEEDS.len());
        assert_eq!(outcome.updated, 0);
        assert_eq!(outcome.unchanged, 0);

        let Ok(usable) = service.usable() else {
            panic!("l'elenco deve potersi leggere");
        };
        assert_eq!(usable.len(), SEEDS.len());
        for dictionary in &usable {
            assert_eq!(dictionary.visibility, DictionaryVisibility::BuiltIn);
            assert_eq!(dictionary.origin, DictionaryOrigin::System);
            assert_eq!(dictionary.status, DictionaryStatus::Active);
            assert!(!dictionary.is_editable(), "si duplicano, non si modificano");
        }
    }

    #[test]
    fn installing_the_seeds_twice_changes_nothing() {
        // L'installazione avviene a ogni avvio: se duplicasse, la libreria
        // crescerebbe di quattro dizionari al giorno.
        let mut service = service();
        let (Ok(first), Ok(second)) = (
            service.install_seed_dictionaries(now()),
            service.install_seed_dictionaries(now()),
        ) else {
            panic!("l'installazione deve riuscire due volte");
        };

        assert_eq!(first.installed, SEEDS.len());
        assert_eq!(second.installed, 0);
        assert_eq!(second.unchanged, SEEDS.len());
        assert_eq!(
            service.library().map(|all| all.len()).ok(),
            Some(SEEDS.len())
        );
    }

    #[test]
    fn a_more_recent_seed_becomes_a_new_version_of_the_same_dictionary() {
        // Il nome e l'identita' restano, il contenuto avanza: un dizionario
        // nuovo lascerebbe l'operatore con due voci quasi identiche.
        let mut service = service();
        let Ok(_) = service.install_seed_dictionaries(now()) else {
            panic!("l'installazione deve riuscire");
        };

        let Ok(entries) = service.library() else {
            panic!("la libreria deve potersi leggere");
        };
        let Some(first) = entries.first() else {
            panic!("la libreria non deve essere vuota");
        };
        let name = first.dictionary.name.as_str().to_owned();
        let before = first.dictionary.id;

        // Il numero della versione simulata si ricava da quella installata,
        // invece di essere fissato: scriverlo a mano legava questo test al
        // contenuto dei seed, e infatti si e' rotto quando i dizionari sono
        // passati alla versione 2 (ampliamento del 2026-07-31). Cio' che il
        // test vuole provare e' che un seed **piu' recente** diventi una nuova
        // versione dello stesso dizionario, non che quel numero sia due.
        let next_number = first.published.as_ref().map_or(1, |version| version.number) + 1;

        // Si simula un seed piu' recente con lo stesso nome.
        let updated = format!(
            r#"{{
              "format": "nexum-dictionary",
              "format_version": 1,
              "name": "{name}",
              "description": "versione successiva",
              "scope": "thematic",
              "version": {{ "number": {next_number}, "note": "stesura successiva" }},
              "terms": [
                {{
                  "text": "termine nuovo",
                  "category": "azione",
                  "language": "it",
                  "match_mode": "normalized_word",
                  "suggested_level": 1,
                  "note": "aggiunto dalla nuova stesura"
                }}
              ]
            }}"#
        );
        let Ok(parsed) = parse(updated.as_bytes()) else {
            panic!("il seed simulato deve essere leggibile");
        };
        assert_eq!(parsed.number, next_number);

        // L'aggiornamento passa dallo stesso percorso dell'installazione.
        let Ok(version) = service.database().insert_dictionary_version(
            &lisi_core::model::dictionary::NewDictionaryVersion {
                dictionary_id: before,
                number: next_number,
                note: parsed.note,
                created_by: {
                    let Ok(author) = Actor::try_new("sistema") else {
                        panic!("l'attore deve essere valido");
                    };
                    author
                },
            },
            now(),
        ) else {
            panic!("la versione deve potersi registrare");
        };
        let terms: Vec<_> = parsed
            .terms
            .into_iter()
            .map(|term| term.bind(version))
            .collect();
        let Ok(_) = service.add_terms(version, &terms, &operator(), now()) else {
            panic!("i termini devono potersi aggiungere");
        };
        let Ok(()) = service.publish(version, &operator(), now()) else {
            panic!("la pubblicazione deve riuscire");
        };

        let Ok(entries) = service.library() else {
            panic!("la libreria deve potersi leggere");
        };
        assert_eq!(entries.len(), SEEDS.len(), "nessun dizionario in piu'");
        let Some(entry) = entries.iter().find(|entry| entry.dictionary.id == before) else {
            panic!("il dizionario deve essere ancora presente");
        };
        assert_eq!(
            entry.published.as_ref().map(|version| version.number),
            Some(next_number),
            "il seed piu' recente deve diventare la versione pubblicata"
        );
        assert_eq!(entry.published_terms, 1);
    }

    /// **Un seed più recente NON aggiorna la descrizione del dizionario**, e va
    /// saputo.
    ///
    /// # Perché questa prova fissa un limite invece di una funzione
    ///
    /// UX-02 ha corretto l'ortografia delle descrizioni dei dizionari forniti —
    /// la schermata Dizionari le disegna, e scrivevano «Piu' termini positivi
    /// si aggiungono». La correzione arriva a **una postazione nuova**, che
    /// installa i seed da zero.
    ///
    /// A una postazione che quei dizionari li ha già, **non arriva**. Il seed
    /// aggiornato aggiunge una versione con i propri termini e le proprie note,
    /// e la descrizione resta quella di prima: sta sulla riga del dizionario,
    /// non su quella della versione, e la migrazione `0003` ha un trigger che
    /// vieta di cambiarla su un dizionario di sistema — «un dizionario di
    /// sistema non si duplica: va duplicato».
    ///
    /// Il trigger non è un difetto: impedisce che due installazioni con lo
    /// stesso numero di versione contengano cose diverse. Ma la conseguenza va
    /// **scritta**, non scoperta: la descrizione di un dizionario di sistema è
    /// fissata alla prima installazione e non cambia più.
    ///
    /// Questa prova diventa rossa il giorno in cui qualcuno decide di
    /// cambiarlo. È il momento giusto per riscriverla, non per aggirarla.
    #[test]
    fn la_descrizione_di_un_seed_non_raggiunge_una_postazione_gia_installata() {
        let mut service = service();
        let Ok(_) = service.install_seed_dictionaries(now()) else {
            panic!("i seed devono potersi installare");
        };

        let Ok(entries) = service.library() else {
            panic!("la libreria deve potersi leggere");
        };
        let Some(primo) = entries.first() else {
            panic!("la libreria non deve essere vuota");
        };
        let id = primo.dictionary.id;
        let descrizione_iniziale = primo.dictionary.description.as_str().to_owned();

        // Il tentativo diretto: cambiare la descrizione di un dizionario di
        // sistema. Lo schema lo rifiuta, e questa e' la ragione per cui il
        // percorso dei seed non ci prova nemmeno.
        let (Ok(nome), Ok(nuova)) = (
            lisi_core::text::DictionaryName::try_new(primo.dictionary.name.as_str()),
            lisi_core::text::DictionaryDescription::try_new("descrizione corretta"),
        ) else {
            panic!("i valori di prova devono essere validi");
        };
        let esito = service
            .database()
            .rename_dictionary(id, &nome, &nuova, now());
        assert!(
            matches!(esito, Err(StorageError::BuiltInDictionaryIsReadOnly)),
            "lo schema deve rifiutare la modifica di un dizionario di sistema: {esito:?}"
        );

        // E la descrizione e' rimasta quella di prima.
        let Ok(entries) = service.library() else {
            panic!("la libreria deve potersi rileggere");
        };
        let Some(dopo) = entries.iter().find(|entry| entry.dictionary.id == id) else {
            panic!("il dizionario deve essere ancora presente");
        };
        assert_eq!(
            dopo.dictionary.description.as_str(),
            descrizione_iniziale,
            "la descrizione di un dizionario di sistema non cambia: e' il limite dichiarato"
        );
    }

    // ---------------------------------------------------------------- import

    #[test]
    fn an_imported_dictionary_arrives_as_a_personal_draft() {
        // Un file che entrasse gia' pubblicato scavalcherebbe la sola verifica
        // umana prevista.
        let mut service = service();
        let Ok((dictionary, version)) = service.import(valid_file().as_bytes(), &operator(), now())
        else {
            panic!("l'import deve riuscire");
        };

        let Ok(imported) = service.database().dictionary(dictionary) else {
            panic!("il dizionario deve potersi rileggere");
        };
        assert_eq!(imported.visibility, DictionaryVisibility::Personal);
        assert_eq!(imported.origin, DictionaryOrigin::Imported);
        assert_eq!(imported.status, DictionaryStatus::Draft);
        assert_eq!(imported.created_by, operator());
        assert_eq!(service.terms(version).map(|all| all.len()).ok(), Some(1));
        assert_eq!(service.usable().map(|all| all.len()).ok(), Some(0));
    }

    #[test]
    fn a_file_larger_than_the_limit_is_refused_before_being_read() {
        let mut service = service();
        let oversized = vec![b'{'; MAX_IMPORT_BYTES + 1];

        assert!(matches!(
            service.import(&oversized, &operator(), now()),
            Err(ServiceError::ImportTooLarge {
                max: MAX_IMPORT_BYTES
            })
        ));
    }

    #[test]
    fn a_file_with_more_terms_than_a_dictionary_admits_is_refused() {
        // Il controllo precede la validazione dei singoli termini, e non era
        // provato: un ramo non provato e' un ramo che si scopre rotto quando
        // serve.
        let mut service = service();
        let term = "{\"text\":\"t\",\"category\":\"c\",\"language\":\"it\",\
                    \"match_mode\":\"normalized_word\",\"suggested_level\":0,\"note\":\"\"}";
        let terms: Vec<&str> = std::iter::repeat_n(term, MAX_TERMS_PER_DICTIONARY + 1).collect();
        let oversized = format!(
            "{{\"format\":\"nexum-dictionary\",\"format_version\":1,\"name\":\"Enorme\",\
              \"description\":\"\",\"scope\":\"thematic\",\
              \"version\":{{\"number\":1,\"note\":\"\"}},\"terms\":[{}]}}",
            terms.join(",")
        );
        assert!(
            oversized.len() < MAX_IMPORT_BYTES,
            "deve passare il limite di dimensione"
        );

        assert!(matches!(
            service.import(oversized.as_bytes(), &operator(), now()),
            Err(ServiceError::ImportRefused {
                reason: "contiene più termini di quanti un dizionario ne ammetta"
            })
        ));
        assert_eq!(service.library().map(|all| all.len()).ok(), Some(0));
    }

    #[test]
    fn a_file_of_another_kind_is_refused() {
        let mut service = service();
        let alien = br#"{"format":"qualcos-altro","format_version":1,"name":"X",
                        "description":"","scope":"thematic",
                        "version":{"number":1,"note":""},"terms":[]}"#;

        assert!(matches!(
            service.import(alien, &operator(), now()),
            Err(ServiceError::ImportRefused {
                reason: "non è un dizionario di questo prodotto"
            })
        ));
    }

    #[test]
    fn a_file_from_a_newer_format_is_refused_instead_of_guessed() {
        let mut service = service();
        let newer = br#"{"format":"nexum-dictionary","format_version":99,"name":"X",
                        "description":"","scope":"thematic",
                        "version":{"number":1,"note":""},"terms":[]}"#;

        assert!(matches!(
            service.import(newer, &operator(), now()),
            Err(ServiceError::ImportRefused { .. })
        ));
    }

    #[test]
    fn a_file_carrying_an_unknown_field_is_refused_and_not_read_in_half() {
        // Ignorare in silenzio significherebbe importare un dizionario diverso
        // da quello che il mittente credeva di consegnare.
        let mut service = service();
        let extra = valid_file().replace(
            "\"scope\": \"thematic\"",
            "\"scope\": \"thematic\", \"permessi\": \"amministratore\"",
        );

        assert!(matches!(
            service.import(extra.as_bytes(), &operator(), now()),
            Err(ServiceError::ImportRefused { .. })
        ));
        assert_eq!(service.library().map(|all| all.len()).ok(), Some(0));
    }

    #[test]
    fn a_file_cannot_introduce_a_match_mode_the_product_does_not_know() {
        // Le espressioni regolari sono assenti di proposito: un file non deve
        // poterle reintrodurre.
        let mut service = service();
        let hostile = valid_file().replace("normalized_word", "regex");

        assert!(matches!(
            service.import(hostile.as_bytes(), &operator(), now()),
            Err(ServiceError::Domain(_))
        ));
        assert_eq!(service.library().map(|all| all.len()).ok(), Some(0));
    }

    /// **Un'espressione non ammessa nomina il termine e il perché**
    /// (COLLAUDO-FIX-01, CU01-003, DEC-510).
    ///
    /// Nel collaudo un dizionario con `(x)\1` non entrava, e lo schermo diceva
    /// soltanto «Si è verificato un problema tecnico»: chi l'aveva ricevuto non
    /// sapeva che cosa correggere, e pensava a un guasto del programma.
    ///
    /// Il termine si nomina **per posizione**, e il suo testo non si ripete:
    /// un messaggio che citasse il file lascerebbe a chi l'ha scritto la scelta
    /// di che cosa l'operatore legge (la regola di `ImportRefused`).
    #[test]
    fn un_espressione_non_ammessa_nomina_il_termine() {
        let mut service = service();
        let secondo = r#"{
                  "text": "(x)\\1",
                  "category": "azione",
                  "language": "it",
                  "match_mode": "expression",
                  "suggested_level": 2,
                  "note": "scritta da chi ha prodotto il file"
                }"#;
        let file = valid_file().replace(
            "\n              ]",
            &format!(",\n{secondo}\n              ]"),
        );
        let Err(errore) = service.import(file.as_bytes(), &operator(), now()) else {
            panic!("un'espressione con un riferimento all'indietro non entra");
        };
        let frase = errore.operator_message();
        assert!(!frase.contains("problema tecnico"), "{frase}");
        assert!(
            frase.contains("termine numero 2"),
            "il termine va nominato: {frase}"
        );
        assert!(
            frase.contains("cresce soltanto con il testo"),
            "il perché va detto: {frase}"
        );
        assert!(
            !frase.contains("(x)"),
            "il testo del file non si ripete: {frase}"
        );
        assert_eq!(service.library().map(|all| all.len()).ok(), Some(0));
    }

    /// **Un file porta un codice numerico soltanto come codice, con il livello
    /// 1; il modello del programma si importa** (DICT-CODES-01, ADR-0170,
    /// criterio 5; prova negativa: il controllo tolto dall'importazione →
    /// rossa).
    #[test]
    fn un_file_porta_un_codice_soltanto_come_codice() {
        let mut service = service();
        for (testo, modo, livello) in [
            ("88", "normalized_word", 2),
            ("88", "exact_word", 1),
            ("88", "numeric_code", 2),
            ("8", "numeric_code", 1),
            ("88x", "numeric_code", 1),
        ] {
            let file = valid_file()
                .replace("\"incendio\"", &format!("\"{testo}\""))
                .replace("normalized_word", modo)
                .replace(
                    "\"suggested_level\": 2",
                    &format!("\"suggested_level\": {livello}"),
                );
            assert!(
                matches!(
                    service.import(file.as_bytes(), &operator(), now()),
                    Err(ServiceError::Domain(
                        lisi_core::DomainError::InvalidNumericCode { .. }
                    ))
                ),
                "«{testo}» come {modo} con livello {livello}"
            );
        }
        assert_eq!(service.library().map(|all| all.len()).ok(), Some(0));
    }

    #[test]
    fn a_file_cannot_introduce_a_level_outside_the_admitted_range() {
        let mut service = service();
        let hostile = valid_file().replace("\"suggested_level\": 2", "\"suggested_level\": 120");

        assert!(matches!(
            service.import(hostile.as_bytes(), &operator(), now()),
            Err(ServiceError::Domain(_))
        ));
    }

    #[test]
    fn a_file_with_control_characters_in_a_term_is_refused() {
        // Il testo confluisce in log, report ed export: un carattere di
        // controllo inserito da chi produce il file ne altererebbe la struttura.
        let mut service = service();
        let hostile = valid_file().replace("\"incendio\"", "\"incen\\u0000dio\"");

        assert!(matches!(
            service.import(hostile.as_bytes(), &operator(), now()),
            Err(ServiceError::Domain(_))
        ));
    }

    #[test]
    fn a_truncated_file_is_refused_without_a_message_of_its_own_choosing() {
        // Il motivo del rifiuto e' una costante del prodotto: se riportasse il
        // testo del file, chi lo produce sceglierebbe che cosa l'operatore legge.
        let mut service = service();
        let whole = valid_file();
        let truncated = &whole.as_bytes()[..40];

        let Err(error) = service.import(truncated, &operator(), now()) else {
            panic!("il file troncato doveva essere rifiutato");
        };
        assert!(matches!(error, ServiceError::ImportRefused { .. }));
        assert!(!error.operator_message().contains("Ricevuto"));
    }

    #[test]
    fn a_file_with_two_terms_equal_after_normalisation_leaves_nothing_behind() {
        // Il vincolo di unicita' dello schema lavora sul testo normalizzato:
        // "incendio" e "Incendio" superano tutta la validazione e si scontrano
        // solo alla scrittura. Se la scrittura non fosse una sola transazione,
        // resterebbe un contenitore vuoto che ha gia' consumato il nome.
        let mut service = service();
        let colliding = valid_file().replace(
            "\"note\": \"perche' e' presente\"\n                }",
            "\"note\": \"perche' e' presente\"\n                },
                {
                  \"text\": \"INCENDIO\",
                  \"category\": \"azione\",
                  \"language\": \"it\",
                  \"match_mode\": \"normalized_word\",
                  \"suggested_level\": 2,
                  \"note\": \"stesso termine con altro caso\"
                }",
        );
        assert!(
            colliding.contains("INCENDIO"),
            "il file di prova deve contenere il termine in collisione"
        );

        assert!(
            service
                .import(colliding.as_bytes(), &operator(), now())
                .is_err(),
            "i due termini coincidono dopo la normalizzazione"
        );
        assert_eq!(
            service.library().map(|all| all.len()).ok(),
            Some(0),
            "nessun contenitore deve essere rimasto"
        );

        // E il nome deve essere ancora libero: e' la conseguenza che rendeva
        // il difetto invisibile e insieme irreparabile per l'operatore.
        assert!(
            service
                .import(valid_file().as_bytes(), &operator(), now())
                .is_ok(),
            "il secondo tentativo con il file corretto deve riuscire"
        );
    }

    #[test]
    fn a_file_cannot_choose_how_the_operator_reads_a_message() {
        // Il nome importato viene interpolato nei messaggi all'operatore. Un
        // carattere che inverte il verso di lettura gli lascerebbe scegliere
        // che cosa quella frase sembra dire.
        let mut service = service();

        for hostile in [
            valid_file().replace("\"Ricevuto\"", "\"Ricev\\u202Euto\""),
            valid_file().replace("\"incendio\"", "\"incen\\u200Bdio\""),
        ] {
            assert!(
                matches!(
                    service.import(hostile.as_bytes(), &operator(), now()),
                    Err(ServiceError::Domain(_))
                ),
                "il file doveva essere rifiutato"
            );
        }
        assert_eq!(service.library().map(|all| all.len()).ok(), Some(0));
    }

    #[test]
    fn importing_the_same_name_twice_is_reported_as_such() {
        let mut service = service();
        let Ok(_) = service.import(valid_file().as_bytes(), &operator(), now()) else {
            panic!("il primo import deve riuscire");
        };

        assert!(matches!(
            service.import(valid_file().as_bytes(), &operator(), now()),
            Err(ServiceError::DictionaryNameAlreadyUsed)
        ));
    }

    // ---------------------------------------------------------------- export

    #[test]
    fn what_is_exported_can_be_imported_again() {
        let mut service = service();
        let Ok(_) = service.install_seed_dictionaries(now()) else {
            panic!("l'installazione dei seed deve riuscire");
        };

        let Ok(entries) = service.library() else {
            panic!("la libreria deve potersi leggere");
        };
        let Some(version) = entries[0].published.as_ref() else {
            panic!("il seed deve avere una versione pubblicata");
        };
        let Ok(exported) = service.export(version.id) else {
            panic!("l'export deve riuscire");
        };

        // Il nome cambia perche' l'originale e' gia' presente: e' il contenuto
        // che deve sopravvivere al giro, non l'identita'.
        let renamed = exported.replace(
            entries[0].dictionary.name.as_str(),
            "Reimportato dopo un giro",
        );
        let Ok((_, reimported)) = service.import(renamed.as_bytes(), &operator(), now()) else {
            panic!("il file esportato deve potersi reimportare");
        };

        let (Ok(original), Ok(copy)) = (service.terms(version.id), service.terms(reimported))
        else {
            panic!("i termini devono potersi leggere");
        };
        assert_eq!(original.len(), copy.len());
        for (left, right) in original.iter().zip(&copy) {
            assert_eq!(left.text, right.text);
            assert_eq!(left.category, right.category);
            assert_eq!(left.language, right.language);
            assert_eq!(left.match_mode, right.match_mode);
            assert_eq!(left.suggested_level, right.suggested_level);
            assert_eq!(left.note, right.note);
        }
    }

    /// **Un dizionario esportato e reimportato altrove ha la stessa impronta
    /// dei termini** (GAP-19, criterio 11), anche con un altro nome e un altro
    /// numero di versione; un termine cambiato la cambia; l'esportazione resta
    /// nell'audit; una bozza non si esporta.
    /// **SEC-02: il dizionario esportato del solo utente, o niente**
    /// (ADR-0157): dice che cosa l'ufficio cerca. Vista rossa il 2026-10-22
    /// con la protezione tolta (mutazione di SEC-02).
    #[cfg(windows)]
    #[test]
    fn il_dizionario_esportato_e_del_solo_utente_o_non_si_scrive() {
        let mut qui = service();
        let Ok(_) = qui.install_seed_dictionaries(now()) else {
            panic!("l'installazione dei seed deve riuscire");
        };
        let Ok(voci) = qui.library() else {
            panic!("la libreria deve potersi leggere");
        };
        let Some(versione) = voci[0].published.as_ref() else {
            panic!("il seed deve avere una versione pubblicata");
        };
        crate::permessi_di_prova::prova_un_uscita("dizionario esportato", |cartella| {
            let file = cartella.join("dizionario.json");
            qui.export_published(versione.id, &file, &operator(), now())
                .map(|_| vec![file])
        });
    }

    #[test]
    fn un_dizionario_va_e_torna_con_la_stessa_impronta() {
        let mut qui = service();
        let Ok(_) = qui.install_seed_dictionaries(now()) else {
            panic!("l'installazione dei seed deve riuscire");
        };
        let Ok(voci) = qui.library() else {
            panic!("la libreria deve potersi leggere");
        };
        let Some(versione) = voci[0].published.as_ref() else {
            panic!("il seed deve avere una versione pubblicata");
        };
        let Ok(cartella) = tempfile::tempdir() else {
            panic!("la cartella temporanea deve potersi creare");
        };
        let file = cartella.path().join("dizionario.json");
        let Ok(impronta) = qui.export_published(versione.id, &file, &operator(), now()) else {
            panic!("l'esportazione deve riuscire");
        };
        let Ok(testo) = std::fs::read_to_string(&file) else {
            panic!("il file deve esserci");
        };
        assert_eq!(impronta.len(), 64, "SHA-256 in esadecimale: {impronta}");

        // ALTROVE: un altro archivio, un altro nome.
        let mut altrove = service();
        let rinominato = testo.replace(voci[0].dictionary.name.as_str(), "Arrivato da un collega");
        let Ok((_, arrivato)) = altrove.import(rinominato.as_bytes(), &operator(), now()) else {
            panic!("il file deve potersi importare");
        };
        let Ok(impronta_altrove) = altrove.terms_fingerprint(arrivato) else {
            panic!("l'impronta deve potersi calcolare");
        };
        assert_eq!(impronta, impronta_altrove);

        // PROVA NEGATIVA: un livello cambiato cambia l'impronta.
        let Some(posizione) = rinominato.find("\"suggested_level\": ") else {
            panic!("il file porta i livelli");
        };
        let mut alterato = rinominato.clone();
        let inizio = posizione + "\"suggested_level\": ".len();
        let fine = inizio + alterato[inizio..].find([',', '\n']).unwrap_or(1);
        let livello = if &alterato[inizio..fine] == "1" {
            "2"
        } else {
            "1"
        };
        alterato.replace_range(inizio..fine, livello);
        let alterato = alterato.replace("Arrivato da un collega", "Arrivato e cambiato");
        let Ok((_, cambiato)) = altrove.import(alterato.as_bytes(), &operator(), now()) else {
            panic!("il file alterato è ancora valido");
        };
        let Ok(impronta_cambiata) = altrove.terms_fingerprint(cambiato) else {
            panic!("l'impronta deve potersi calcolare");
        };
        assert_ne!(impronta, impronta_cambiata);

        // L'AUDIT.
        let Ok(righe) = qui.database().audit_entries() else {
            panic!("l'audit deve potersi leggere");
        };
        assert_eq!(
            righe
                .iter()
                .filter(|riga| riga.action.as_str() == "dizionario_esportato")
                .count(),
            1
        );

        // UNA BOZZA NON SI ESPORTA: un import arriva in bozza.
        let bozza = cartella.path().join("bozza.json");
        assert!(
            altrove
                .export_published(arrivato, &bozza, &operator(), now())
                .is_err()
        );
        assert!(!bozza.exists());

        // UN FILE CHE NON SI SCRIVE NON LASCIA AUDIT.
        let dentro_nulla = cartella.path().join("manca").join("x.json");
        assert!(
            qui.export_published(versione.id, &dentro_nulla, &operator(), now())
                .is_err()
        );
        let Ok(righe) = qui.database().audit_entries() else {
            panic!("l'audit deve potersi leggere");
        };
        assert_eq!(
            righe
                .iter()
                .filter(|riga| riga.action.as_str() == "dizionario_esportato")
                .count(),
            1
        );
    }

    #[test]
    fn the_export_does_not_carry_the_state_of_the_station() {
        // E' un formato di contenuto, non un backup: identificatori, stato e
        // autore restano sulla postazione di origine.
        let mut service = service();
        let Ok(_) = service.install_seed_dictionaries(now()) else {
            panic!("l'installazione dei seed deve riuscire");
        };
        let Ok(entries) = service.library() else {
            panic!("la libreria deve potersi leggere");
        };
        let Some(version) = entries[0].published.as_ref() else {
            panic!("il seed deve avere una versione pubblicata");
        };

        let Ok(exported) = service.export(version.id) else {
            panic!("l'export deve riuscire");
        };
        for absent in ["built_in", "visibility", "created_by", "status", "sistema"] {
            assert!(
                !exported.contains(absent),
                "l'export non deve trasportare '{absent}'"
            );
        }
        assert!(exported.contains(FORMAT_MARKER));
    }

    #[test]
    fn exporting_a_missing_version_is_reported_as_not_found() {
        let service = service();
        assert!(matches!(
            service.export(DictionaryVersionId::new(404)),
            Err(ServiceError::Storage(_))
        ));
    }

    // LE PROVE SUI DIZIONARI OPERATIVI STANNO SOLTANTO NELL'ARCHIVIO
    // (ADR-0210, DEC-522): leggono i dizionari che la copia pubblica non porta.

    /// **I dizionari d'esempio della copia pubblica si leggono** (ADR-0210,
    /// DEC-522): sono quelli che la copia pubblica installa al posto dei
    /// dizionari operativi, e devono reggere le stesse regole.
    #[test]
    fn i_dizionari_d_esempio_si_leggono() {
        for (nome, raw) in [
            (
                "esempio-termini",
                include_str!("../../../assets/dizionari-esempio/esempio-termini.json"),
            ),
            (
                "esempio-contesto-riduttivo",
                include_str!("../../../assets/dizionari-esempio/esempio-contesto-riduttivo.json"),
            ),
        ] {
            let Ok(parsed) = parse(raw.as_bytes()) else {
                panic!("il dizionario d'esempio «{nome}» deve leggersi");
            };
            assert!(!parsed.terms.is_empty(), "{nome}");
            assert!(
                parsed
                    .terms
                    .iter()
                    .all(|t| !t.note.as_str().trim().is_empty()),
                "{nome}: ogni termine dice perché c'è"
            );
            assert!(
                parsed.description.as_str().contains("esempio"),
                "{nome}: la descrizione dice che è un esempio"
            );
        }
    }
}
