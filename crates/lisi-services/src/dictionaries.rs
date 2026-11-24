//! Libreria dei dizionari e configurazione di una sessione.
//!
//! # Che cosa decide questo livello
//!
//! Lo schema difende l'**integrità**: una versione pubblicata non si modifica,
//! una fotografia non si altera, un dizionario di sistema non si tocca. Quelle
//! regole non sono ripetute qui, perché ripeterle non le rafforzerebbe: sono
//! già inaggirabili.
//!
//! Qui stanno le decisioni di **prodotto**, che lo schema non impone perché non
//! sono questioni di integrità:
//!
//! - una versione **senza termini non si pubblica**. Un dizionario pubblicato
//!   vuoto comparirebbe fra quelli selezionabili senza contribuire nulla;
//! - una nuova versione **parte dai termini di quella pubblicata**, altrimenti
//!   correggere una parola su tremila significherebbe riscriverne tremila;
//! - una copia nasce **personale e in bozza**, con l'origine che dice come è
//!   entrata nel sistema;
//! - una sessione **senza alcun termine non si avvia**: acquisirebbe contenuti
//!   senza poterne segnalare alcuno, e sembrerebbe funzionare.
//!
//! # Che cosa questo modulo non fa
//!
//! Non analizza nulla e non attribuisce livelli. Il **livello suggerito** di un
//! termine resta il suggerimento di chi ha compilato il dizionario; l'esito lo
//! determinerà il motore, e la valutazione finale resta all'operatore.

use lisi_core::model::NewAuditEntry;
use lisi_core::model::dictionary::{
    ConfigurationResolver, Dictionary, DictionaryScope, DictionarySelection, DictionaryStatus,
    DictionaryTerm, DictionaryVersion, DictionaryVisibility, MAX_DICTIONARIES_PER_SESSION,
    NewDictionary, NewDictionaryTerm, NewDictionaryVersion, ResolvedDictionaryConfiguration,
    TermProvenance, check_new_term, normalise_for_matching,
};
use lisi_core::text::{
    Actor, AuditAction, AuditDetail, AuditEntity, DictionaryDescription, DictionaryName,
};
use lisi_core::{
    DictionaryId, DictionaryVersionId, OperatingMode, RestrictedAction, SessionId, Timestamp,
};
use lisi_security::ProtectedStore;
use lisi_storage::{Database, StorageError};

use crate::error::{ServiceError, ServiceResult, from_storage};

/// Quel che l'operatore indica per creare un dizionario.
///
/// Non comprende l'**origine**: quella la stabilisce il servizio, perché
/// registra come il dizionario è entrato nel sistema e non è una scelta di chi
/// lo crea.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DictionaryProposal {
    /// Nome mostrato all'operatore.
    pub name: DictionaryName,
    /// Descrizione di che cosa copre.
    pub description: DictionaryDescription,
    /// Ambito.
    pub scope: DictionaryScope,
    /// Se resta personale o è condiviso con la postazione.
    pub visibility: DictionaryVisibility,
}

/// Voce della libreria, come l'interfaccia deve mostrarla.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LibraryEntry {
    /// Dizionario.
    pub dictionary: Dictionary,
    /// Versione pubblicata più recente, se esiste.
    pub published: Option<DictionaryVersion>,
    /// Numero di termini della versione pubblicata.
    pub published_terms: usize,
    /// Se ha una bozza aperta su cui si sta lavorando.
    pub has_open_draft: bool,
}

impl LibraryEntry {
    /// Se può essere scelto per una nuova sessione.
    #[must_use]
    pub const fn is_usable(&self) -> bool {
        self.dictionary.is_selectable() && self.published.is_some()
    }

    /// Perché non è utilizzabile, quando non lo è.
    ///
    /// Il testo dice all'operatore che cosa manca, non soltanto che qualcosa
    /// manca.
    #[must_use]
    pub const fn unusable_reason(&self) -> Option<&'static str> {
        if self.published.is_none() {
            return Some(
                "Non ha ancora una versione pubblicata: i suoi termini non verrebbero usati.",
            );
        }
        if !self.dictionary.is_selectable() {
            return Some("È archiviato o disattivato: non viene proposto per nuove sessioni.");
        }
        None
    }
}

/// Un dizionario scelto per una sessione, con **la versione** che verrà usata.
///
/// # Perché la versione, e non soltanto il nome
///
/// Un dizionario cambia. Fra il monitoraggio di marzo e quello di ottobre la
/// stessa voce «Incendi» può avere trenta termini in più e due tolti, e i due
/// monitoraggi non sono stati condotti con lo stesso strumento. Chi rilegge un
/// atto mesi dopo, o chi deve rispondere di come è stata composta una
/// segnalazione, ha bisogno del **numero di versione**: senza, il nome dice
/// soltanto quale dizionario, non quale contenuto.
///
/// La fotografia della sessione conservava già la coppia dizionario-versione
/// (`session_dictionary_selections` dalla migrazione 0003), ma **nessuno la
/// leggeva fuori dalle prove**: il dato esisteva e non arrivava a chi doveva
/// vederlo. È la stessa forma di difetto chiusa in CY-01 e in DEC-226 — una
/// capacità costruita e mai raggiungibile.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SelectedDictionary {
    /// Il dizionario.
    pub id: DictionaryId,
    /// La versione pubblicata che verrà usata.
    pub version_id: DictionaryVersionId,
    /// Nome mostrato all'operatore.
    pub name: DictionaryName,
    /// Numero progressivo della versione.
    pub version_number: u32,
    /// Ambito dichiarato.
    pub scope: DictionaryScope,
    /// Termini della versione, in tutto.
    pub terms: usize,
    /// Termini che **abbassano** il peso di un riscontro (livello negativo).
    ///
    /// È il contesto riduttivo: «non è vero che», «nel film», «condanniamo».
    pub reducing_terms: usize,
    /// Termini che lo **alzano** (livello da 1 in su).
    pub raising_terms: usize,
}

impl SelectedDictionary {
    /// Come si scrive in un riepilogo o in un atto: `Incendi v3`.
    #[must_use]
    pub fn label(&self) -> String {
        format!("{} v{}", self.name.as_str(), self.version_number)
    }

    /// Se il dizionario porta contesto riduttivo.
    #[must_use]
    pub const fn provides_reductive_context(&self) -> bool {
        self.reducing_terms > 0
    }

    /// Se il dizionario può far salire il livello di un contenuto.
    #[must_use]
    pub const fn can_raise(&self) -> bool {
        self.raising_terms > 0
    }
}

/// La versione con cui una bozza si confronta nel Laboratorio (F-07).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LabBaseline {
    /// L'ultima versione pubblicata dello stesso dizionario.
    OwnPublished(DictionaryVersion),
    /// La versione pubblicata del dizionario da cui la bozza è stata duplicata:
    /// il duplicato non ne ha ancora una propria.
    Origin {
        /// Il dizionario d'origine.
        dictionary: Dictionary,
        /// La sua ultima versione pubblicata.
        version: DictionaryVersion,
    },
}

impl LabBaseline {
    /// La versione di riferimento.
    #[must_use]
    pub const fn version(&self) -> &DictionaryVersion {
        match self {
            Self::OwnPublished(version) | Self::Origin { version, .. } => version,
        }
    }
}

/// Un dizionario con una bozza aperta, come il Laboratorio lo vede (F-07).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LabCandidate {
    /// Il dizionario.
    pub dictionary: Dictionary,
    /// La bozza aperta.
    pub draft: DictionaryVersion,
    /// Con che cosa si confronta, se c'è qualcosa con cui confrontarla.
    pub baseline: Option<LabBaseline>,
}

impl LabCandidate {
    /// Il dizionario che porta la versione di riferimento.
    #[must_use]
    pub fn baseline_dictionary_id(&self) -> Option<DictionaryId> {
        match self.baseline.as_ref()? {
            LabBaseline::OwnPublished(_) => Some(self.dictionary.id),
            LabBaseline::Origin { dictionary, .. } => Some(dictionary.id),
        }
    }

    /// La riga dell'elenco del Laboratorio: quale bozza, contro che cosa.
    #[must_use]
    pub fn label(&self) -> String {
        let nome = self.dictionary.name.as_str();
        let bozza = self.draft.number;
        match self.baseline.as_ref() {
            Some(LabBaseline::OwnPublished(pubblicata)) => {
                format!(
                    "{nome} — bozza v{bozza} contro la pubblicata v{}",
                    pubblicata.number
                )
            }
            Some(LabBaseline::Origin {
                dictionary,
                version,
            }) => format!(
                "{nome} — bozza v{bozza} contro l'originale «{}» v{}",
                dictionary.name.as_str(),
                version.number
            ),
            None => format!("{nome} — bozza v{bozza}, senza una versione con cui confrontarla"),
        }
    }
}

/// Criteri con cui l'operatore restringe la libreria.
///
/// La ricerca è **locale**: filtra ciò che è già stato letto, non interroga
/// nulla. Su una libreria di poche decine di voci è la scelta giusta, e su una
/// più grande resterebbe comunque preferibile riscrivere la query invece di
/// filtrare in memoria — ma quella è una decisione che si prende quando il
/// problema esiste, non prima.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct LibraryFilter {
    /// Testo cercato in nome e descrizione. Vuoto significa «tutto».
    pub query: String,
    /// Mostra soltanto i dizionari utilizzabili per una sessione.
    pub only_usable: bool,
    /// Mostra soltanto quelli che l'operatore può modificare.
    pub only_editable: bool,
}

impl LibraryFilter {
    /// Se il filtro non restringe nulla.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.query.trim().is_empty() && !self.only_usable && !self.only_editable
    }

    /// Se la voce supera il filtro.
    #[must_use]
    pub fn matches(&self, entry: &LibraryEntry) -> bool {
        if self.only_usable && !entry.is_usable() {
            return false;
        }
        if self.only_editable && !entry.dictionary.is_editable() {
            return false;
        }

        let needle = normalise_for_matching(self.query.trim());
        if needle.is_empty() {
            return true;
        }

        // La **stessa** normalizzazione dei termini: maiuscole e forma Unicode
        // non contano, gli accenti sì. Una ricerca più permissiva del motore
        // troverebbe dizionari i cui termini poi non riscontrerebbero.
        normalise_for_matching(entry.dictionary.name.as_str()).contains(&needle)
            || normalise_for_matching(entry.dictionary.description.as_str()).contains(&needle)
    }
}

/// Esito della rimozione di un dizionario.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DictionaryRemoval {
    /// Era una bozza mai usata: è stata rimossa davvero.
    Deleted,
    /// Aveva versioni pubblicate o è stato usato: è stato **archiviato**.
    Archived,
}

impl DictionaryRemoval {
    /// Messaggio destinato all'operatore.
    #[must_use]
    pub const fn operator_message(self) -> &'static str {
        match self {
            Self::Deleted => "Il dizionario è stato rimosso.",
            Self::Archived => {
                "Il dizionario è stato archiviato e non sarà più proposto per nuove \
                 sessioni. Non è stato cancellato perché ha versioni pubblicate o è \
                 già stato usato: le sessioni già svolte devono restare leggibili."
            }
        }
    }
}

/// Servizio della libreria dei dizionari.
#[derive(Debug)]
pub struct DictionaryService {
    database: Database,
    mode: OperatingMode,
}

impl DictionaryService {
    /// Crea il servizio attorno al database indicato.
    ///
    /// La modalità iniziale è quella di una postazione appena predisposta:
    /// **amministratore**. Chiamare [`DictionaryService::with_mode`] quando la
    /// modalità è stata letta dalla configurazione.
    #[must_use]
    pub const fn new(database: Database) -> Self {
        Self {
            database,
            mode: OperatingMode::Administrator,
        }
    }

    /// Crea il servizio nella modalità indicata.
    #[must_use]
    pub const fn with_mode(database: Database, mode: OperatingMode) -> Self {
        Self { database, mode }
    }

    /// Modalità corrente.
    ///
    /// L'interfaccia la mostra sempre: un operatore deve sapere in quale
    /// modalità sta lavorando **prima** di scoprirlo da un rifiuto.
    #[must_use]
    pub const fn mode(&self) -> OperatingMode {
        self.mode
    }

    /// Cambia la modalità corrente **senza** conservarla né registrarla.
    ///
    /// Serve alla costruzione e ai test. Il passaggio vero, quello che un
    /// operatore compie, è [`DictionaryService::switch_to_operator_mode`] e
    /// [`DictionaryService::switch_to_administrator_mode`]: quelli conservano
    /// la scelta e la scrivono nell'audit.
    pub const fn set_mode(&mut self, mode: OperatingMode) {
        self.mode = mode;
    }

    /// Passa la postazione in modalità operatore, fissando la parola di sblocco.
    ///
    /// Conserva la scelta e la registra nell'audit **prima** di applicarla in
    /// memoria: se la scrittura protetta fallisse, la modalità in memoria non
    /// deve essere già cambiata, altrimenti l'applicazione si comporterebbe da
    /// operatore mentre il disco dice amministratore.
    ///
    /// # Errori
    ///
    /// Restituisce [`ServiceError::WeakUnlockWord`] se la parola non è
    /// utilizzabile, e un errore se la scrittura protetta non riesce.
    /// Come [`DictionaryService::switch_to_operator_mode_in`], sulla
    /// configurazione predefinita di questa postazione.
    ///
    /// Esiste perché l'interfaccia possa compiere il passaggio **senza
    /// dipendere da `lisi-security`**: il confine è posto da ADR-0010 ed è
    /// verificato da un test.
    ///
    /// # Errori
    ///
    /// Come la variante con lo store esplicito, più un errore se la cartella
    /// dati non è determinabile.
    pub fn switch_to_operator_mode(
        &mut self,
        unlock_word: &str,
        actor: &Actor,
        now: Timestamp,
    ) -> ServiceResult<()> {
        let store = ProtectedStore::at(crate::station::default_station_path()?);
        self.switch_to_operator_mode_in(&store, unlock_word, actor, now)
    }

    /// Come [`DictionaryService::switch_to_administrator_mode_in`], sulla
    /// configurazione predefinita di questa postazione.
    ///
    /// # Errori
    ///
    /// Come la variante con lo store esplicito.
    pub fn switch_to_administrator_mode(
        &mut self,
        attempt: &str,
        actor: &Actor,
        now: Timestamp,
    ) -> ServiceResult<()> {
        let store = ProtectedStore::at(crate::station::default_station_path()?);
        self.switch_to_administrator_mode_in(&store, attempt, actor, now)
    }

    pub(crate) fn switch_to_operator_mode_in(
        &mut self,
        store: &ProtectedStore,
        unlock_word: &str,
        actor: &Actor,
        now: Timestamp,
    ) -> ServiceResult<()> {
        crate::station::enter_operator_mode(store, unlock_word)?;

        // La voce di audit porta la modalita' **di partenza**, che e' quella
        // con cui il passaggio e' stato deciso: registrare quella di arrivo
        // direbbe che l'operatore si e' messo da se' in modalita' operatore.
        self.append(
            actor,
            "modalita_operatore_attivata",
            "station",
            None,
            "",
            now,
        )?;
        self.mode = OperatingMode::Operator;
        Ok(())
    }

    /// Riporta la postazione in modalità amministratore, verificando la parola.
    ///
    /// # Errori
    ///
    /// Restituisce [`ServiceError::WrongUnlockWord`] se la parola non
    /// corrisponde. Un tentativo fallito **non** cambia nulla e viene comunque
    /// registrato: chi tenta di riprendersi i privilegi lascia la traccia di
    /// averci provato, ed è la sola cosa che il prodotto può onestamente
    /// offrire contro la determinazione.
    pub(crate) fn switch_to_administrator_mode_in(
        &mut self,
        store: &ProtectedStore,
        attempt: &str,
        actor: &Actor,
        now: Timestamp,
    ) -> ServiceResult<()> {
        match crate::station::return_to_administrator(store, attempt) {
            Ok(()) => {
                self.append(
                    actor,
                    "modalita_amministratore_ripresa",
                    "station",
                    None,
                    "",
                    now,
                )?;
                self.mode = OperatingMode::Administrator;
                Ok(())
            }
            Err(error) => {
                // La registrazione del tentativo fallito non deve nascondere
                // l'errore originale: se anche l'audit non riesce, e' il
                // rifiuto che l'operatore deve leggere.
                let _ = self.append(
                    actor,
                    "modalita_amministratore_rifiutata",
                    "station",
                    None,
                    "",
                    now,
                );
                Err(error)
            }
        }
    }

    /// Verifica che la modalità corrente consenta l'azione.
    ///
    /// # Errori
    ///
    /// Restituisce [`ServiceError::ActionReservedToAdministrator`], che porta
    /// con sé la ragione per cui l'azione è riservata: un rifiuto senza ragione
    /// sembra arbitrario, e la prima reazione a un divieto arbitrario è cercare
    /// il modo di aggirarlo.
    pub(crate) fn require(&self, action: RestrictedAction) -> ServiceResult<()> {
        if self.mode.allows(action) {
            return Ok(());
        }
        Err(ServiceError::ActionReservedToAdministrator { action })
    }

    /// Verifica il diritto di intervenire su un dizionario altrui.
    ///
    /// Il proprio si tocca sempre; quello di un altro no, perché è stato
    /// composto da qualcuno che non è presente a discuterne.
    fn require_ownership_or_administrator(
        &self,
        dictionary: &Dictionary,
        actor: &Actor,
    ) -> ServiceResult<()> {
        if &dictionary.created_by == actor {
            return Ok(());
        }
        self.require(RestrictedAction::RemoveOthersDictionary)
    }

    /// Database sottostante, per i test e la diagnostica.
    #[must_use]
    pub const fn database(&self) -> &Database {
        &self.database
    }

    /// Database sottostante in scrittura, per le operazioni transazionali.
    pub(crate) const fn database_mut(&mut self) -> &mut Database {
        &mut self.database
    }

    /// Restituisce il database, consumando il servizio.
    ///
    /// I servizi **possiedono** il database invece di condividerlo. Passarlo
    /// dall'uno all'altro è il modo in cui una sequenza si compone — configurare
    /// le fonti, comporre il monitoraggio, analizzare, revisionare — senza
    /// introdurre una condivisione che nessuno ha ancora bisogno di gestire.
    ///
    /// Non è un dettaglio dei test: senza, ciascun servizio scriverebbe in un
    /// archivio proprio, e una sessione creata da uno sarebbe invisibile
    /// all'altro.
    #[must_use]
    pub fn into_database(self) -> Database {
        self.database
    }

    // -------------------------------------------------------------- libreria

    /// Libreria completa, con lo stato di ciascun dizionario.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se la lettura non riesce.
    pub fn library(&self) -> ServiceResult<Vec<LibraryEntry>> {
        let dictionaries = self.database.dictionaries()?;

        let mut entries = Vec::with_capacity(dictionaries.len());
        for dictionary in dictionaries {
            entries.push(self.describe(dictionary)?);
        }
        Ok(entries)
    }

    /// Libreria ristretta dai criteri indicati.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se la lettura non riesce.
    pub fn library_matching(&self, filter: &LibraryFilter) -> ServiceResult<Vec<LibraryEntry>> {
        let mut entries = self.library()?;
        entries.retain(|entry| filter.matches(entry));
        Ok(entries)
    }

    /// Termini della versione pubblicata di un dizionario.
    ///
    /// È l'anteprima: prima di scegliere un dizionario l'operatore deve poter
    /// vedere **che cosa contiene**, non solo quanti termini ha. Un dizionario
    /// senza versioni pubblicate non ha nulla da mostrare, e l'elenco vuoto è
    /// la risposta giusta.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se il dizionario non esiste o se la lettura non
    /// riesce.
    pub fn published_terms(
        &self,
        dictionary_id: DictionaryId,
    ) -> ServiceResult<Vec<DictionaryTerm>> {
        let Some(version) = self.database.latest_published_version(dictionary_id)? else {
            return Ok(Vec::new());
        };
        self.terms(version.id)
    }

    /// Dizionari realmente utilizzabili per una nuova sessione.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se la lettura non riesce.
    pub fn usable(&self) -> ServiceResult<Vec<Dictionary>> {
        Ok(self.database.selectable_dictionaries()?)
    }

    /// I dizionari scelti, con **la versione** che verrebbe usata adesso.
    ///
    /// È la fotografia che il riepilogo mostra e che l'audit registra. Si
    /// calcola dalle **stesse** letture della risoluzione — `usable_version`
    /// per la versione, i termini di quella versione per i conteggi — perché
    /// due percorsi diversi verso lo stesso numero divergono al primo cambio,
    /// e allora il riepilogo direbbe una cosa e la sessione ne userebbe
    /// un'altra.
    ///
    /// L'ordine è quello in cui l'operatore ha scelto: è l'ordine che si
    /// ritrova nella schermata, e riordinarlo per conto proprio renderebbe più
    /// difficile ricontrollare la propria scelta.
    ///
    /// # Errori
    ///
    /// Restituisce [`ServiceError::DictionaryNotSelectable`] se un dizionario
    /// non è più utilizzabile, e un errore se la lettura non riesce.
    pub fn selected_versions(
        &self,
        dictionary_ids: &[DictionaryId],
    ) -> ServiceResult<Vec<SelectedDictionary>> {
        let mut chosen = Vec::with_capacity(dictionary_ids.len());

        for dictionary_id in dictionary_ids {
            let (dictionary, version) = self.usable_version(*dictionary_id)?;
            let terms = self.database.dictionary_terms(version.id)?;

            // Il segno del livello suggerito è la sola cosa che distingue un
            // termine che alza da uno che riduce, e sta nel dato: nessun nome
            // di dizionario viene guardato. Riconoscere il contesto riduttivo
            // dal nome funzionerebbe finche' qualcuno non rinomina il proprio,
            // e fallirebbe in silenzio.
            let reducing_terms = terms
                .iter()
                .filter(|term| term.suggested_level.get() < 0)
                .count();
            let raising_terms = terms
                .iter()
                .filter(|term| term.suggested_level.get() > 0)
                .count();

            chosen.push(SelectedDictionary {
                id: dictionary.id,
                version_id: version.id,
                name: dictionary.name,
                version_number: version.number,
                scope: dictionary.scope,
                terms: terms.len(),
                reducing_terms,
                raising_terms,
            });
        }

        Ok(chosen)
    }

    /// Descrive un dizionario con la versione pubblicata e le bozze aperte.
    fn describe(&self, dictionary: Dictionary) -> ServiceResult<LibraryEntry> {
        let published = self.database.latest_published_version(dictionary.id)?;
        let published_terms = match &published {
            Some(version) => self.database.dictionary_term_count(version.id)?,
            None => 0,
        };
        let has_open_draft = self
            .database
            .dictionary_versions(dictionary.id)?
            .iter()
            .any(DictionaryVersion::is_mutable);

        Ok(LibraryEntry {
            dictionary,
            published,
            published_terms,
            has_open_draft,
        })
    }

    // ------------------------------------------------------- ciclo di vita

    /// Crea un dizionario con la sua prima versione in bozza.
    ///
    /// L'origine è [`DictionaryOrigin::Operator`]: registra che il dizionario è
    /// nato da questa postazione, non che chi lo ha creato sia un operatore
    /// piuttosto che un amministratore. Un dizionario **di sistema** non si
    /// crea da qui: quelli sono forniti con il prodotto.
    ///
    /// [`DictionaryOrigin::Operator`]: lisi_core::model::dictionary::DictionaryOrigin::Operator
    ///
    /// # Errori
    ///
    /// Restituisce [`ServiceError::BuiltInDictionaryIsReadOnly`] se la
    /// visibilità richiesta è quella di sistema e
    /// [`ServiceError::DictionaryNameAlreadyUsed`] se il nome è già usato.
    pub fn create(
        &self,
        proposal: &DictionaryProposal,
        actor: &Actor,
        now: Timestamp,
    ) -> ServiceResult<(DictionaryId, DictionaryVersionId)> {
        if !proposal.visibility.is_editable() {
            return Err(ServiceError::BuiltInDictionaryIsReadOnly);
        }
        if proposal.visibility == DictionaryVisibility::Shared {
            self.require(RestrictedAction::ManageSharedDictionary)?;
        }

        let new = NewDictionary {
            name: proposal.name.clone(),
            description: proposal.description.clone(),
            scope: proposal.scope,
            origin: lisi_core::model::dictionary::DictionaryOrigin::Operator,
            visibility: proposal.visibility,
            created_by: actor.clone(),
            derived_from: None,
        };

        let dictionary_id = self
            .database
            .insert_dictionary(&new, now)
            .map_err(from_storage)?;

        // Il dizionario nasce con la propria bozza: senza, l'operatore avrebbe
        // un contenitore su cui non puo' scrivere e dovrebbe scoprire da se'
        // che gli manca un passo.
        let version_id = self
            .database
            .insert_dictionary_version(
                &NewDictionaryVersion {
                    dictionary_id,
                    number: 1,
                    note: proposal.description.clone(),
                    created_by: actor.clone(),
                },
                now,
            )
            .map_err(from_storage)?;

        self.audit(
            actor,
            "dizionario_creato",
            dictionary_id,
            proposal.name.as_str(),
            now,
        )?;
        Ok((dictionary_id, version_id))
    }

    /// Duplica un dizionario a partire dalla sua versione pubblicata.
    ///
    /// È il modo previsto per partire da un dizionario di sistema. La copia
    /// nasce **personale e in bozza**, e conserva il legame con l'originale.
    ///
    /// # Errori
    ///
    /// Restituisce [`ServiceError::DictionaryHasNoPublishedVersion`] se non c'è
    /// nulla da copiare e [`ServiceError::DictionaryNameAlreadyUsed`] se il
    /// nome è già usato.
    pub fn duplicate(
        &mut self,
        source: DictionaryId,
        name: &DictionaryName,
        actor: &Actor,
        now: Timestamp,
    ) -> ServiceResult<(DictionaryId, DictionaryVersionId)> {
        let original = self.database.dictionary(source).map_err(from_storage)?;
        let Some(published) = self.database.latest_published_version(source)? else {
            return Err(ServiceError::DictionaryHasNoPublishedVersion);
        };

        let copy = NewDictionary {
            name: name.clone(),
            description: original.description.clone(),
            scope: original.scope,
            origin: lisi_core::model::dictionary::DictionaryOrigin::Operator,
            visibility: DictionaryVisibility::Personal,
            created_by: actor.clone(),
            derived_from: Some(source),
        };

        let note = DictionaryDescription::try_new(&format!(
            "Copia di {} v{}",
            original.name.as_str(),
            published.number
        ))?;

        let (dictionary_id, version_id) = self
            .database
            .duplicate_dictionary(&copy, published.id, &note, now)
            .map_err(from_storage)?;

        self.audit(
            actor,
            "dizionario_duplicato",
            dictionary_id,
            name.as_str(),
            now,
        )?;
        Ok((dictionary_id, version_id))
    }

    /// Aggiunge termini alla bozza indicata.
    ///
    /// # Errori
    ///
    /// Restituisce [`ServiceError::PublishedVersionIsImmutable`] se la versione
    /// è già pubblicata, e un errore se un limite è superato o un termine è
    /// ripetuto.
    pub fn add_terms(
        &mut self,
        version: DictionaryVersionId,
        terms: &[NewDictionaryTerm],
        actor: &Actor,
        now: Timestamp,
    ) -> ServiceResult<usize> {
        // Una bozza esiste solo se qualcuno ha potuto crearla, ma puo' essere
        // di un altro: un operatore non scrive nella bozza aperta da chi
        // amministra la postazione.
        let owner = self
            .database
            .dictionary(self.database.dictionary_version(version)?.dictionary_id)?;
        self.require_ownership_or_administrator(&owner, actor)?;

        // La regola del codice numerico vale per ciò che si scrive adesso: un
        // termine di sole cifre è un codice, o non entra (DICT-CODES-01,
        // ADR-0170). La copia di una versione pubblicata non passa di qui.
        for term in terms {
            check_new_term(
                term.text.as_str(),
                term.match_mode,
                term.suggested_level.get(),
            )?;
        }

        let written = self
            .database
            .insert_dictionary_terms(version, terms)
            .map_err(from_storage)?;

        if written > 0 {
            let dictionary = self.database.dictionary_version(version)?.dictionary_id;
            self.audit(
                actor,
                "termini_aggiunti",
                dictionary,
                &format!("{written} termini"),
                now,
            )?;
        }
        Ok(written)
    }

    /// Termini di una versione.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se la lettura non riesce.
    /// Versione in bozza di un dizionario, se ce n'è una aperta.
    ///
    /// È il punto d'ingresso della modifica: una bozza è l'unica versione
    /// scrivibile, perché una pubblicata è immutabile per costruzione. Senza
    /// questa funzione l'interfaccia non poteva raggiungere la bozza creata da
    /// `duplicate` o da `import`, e il percorso che la metodologia prescrive
    /// all'ufficio — duplicare, **adattare**, pubblicare — si fermava al primo
    /// passo (rilevato dall'operatore il 2026-08-01).
    ///
    /// # Errori
    ///
    /// Restituisce un errore se il dizionario non esiste o se la lettura non
    /// riesce.
    pub fn open_draft(
        &self,
        dictionary_id: DictionaryId,
    ) -> ServiceResult<Option<DictionaryVersion>> {
        Ok(self
            .database
            .dictionary_versions(dictionary_id)?
            .into_iter()
            .find(DictionaryVersion::is_mutable))
    }

    /// I dizionari con una bozza aperta, ciascuno con la versione con cui la
    /// bozza si confronta nel Laboratorio (OPERATOR-E2E-REMEDIATION-01, F-07).
    ///
    /// # Il riferimento
    ///
    /// È l'ultima versione pubblicata **dello stesso dizionario**. Un duplicato
    /// appena nato non ne ha — la sua prima versione è la bozza — e fino a
    /// questa correzione il Laboratorio non lo mostrava, che era il caso più
    /// comune: si parte da un dizionario di sistema, che non si modifica, e lo
    /// si duplica. Ora un duplicato senza versione pubblicata si confronta con
    /// la versione pubblicata del dizionario **da cui è nato**, e lo dice.
    ///
    /// Una bozza senza né l'una né l'altra resta nell'elenco con il
    /// riferimento assente: il Laboratorio spiega che cosa manca invece di
    /// tacere che esiste.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se la lettura non riesce.
    pub fn lab_candidates(&self) -> ServiceResult<Vec<LabCandidate>> {
        let mut candidati = Vec::new();
        for dictionary in self.database.dictionaries()? {
            let Some(draft) = self.open_draft(dictionary.id)? else {
                continue;
            };
            let baseline = match self.database.latest_published_version(dictionary.id)? {
                Some(version) => Some(LabBaseline::OwnPublished(version)),
                None => match dictionary.derived_from {
                    Some(origine) => {
                        let origine = self.database.dictionary(origine)?;
                        self.database
                            .latest_published_version(origine.id)?
                            .map(|version| LabBaseline::Origin {
                                dictionary: origine,
                                version,
                            })
                    }
                    None => None,
                },
            };
            candidati.push(LabCandidate {
                dictionary,
                draft,
                baseline,
            });
        }
        Ok(candidati)
    }

    /// Che cosa la bozza cambia rispetto al proprio riferimento.
    ///
    /// Restituisce `None` se la bozza non ha un riferimento.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se la lettura dei termini non riesce.
    pub fn lab_term_differences(
        &self,
        candidate: &LabCandidate,
    ) -> ServiceResult<Option<crate::rule_lab::TermDifferences>> {
        let Some(baseline) = candidate.baseline.as_ref() else {
            return Ok(None);
        };
        let riferimento = self.terms(baseline.version().id)?;
        let bozza = self.terms(candidate.draft.id)?;
        Ok(Some(crate::rule_lab::term_differences(
            &riferimento,
            &bozza,
        )))
    }

    /// Toglie un termine da una versione in bozza.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se il termine appartiene a una versione già
    /// pubblicata, se chi opera non è il proprietario del dizionario né
    /// amministratore, o se la scrittura non riesce.
    pub fn remove_term(
        &self,
        dictionary_id: DictionaryId,
        term_id: lisi_core::DictionaryTermId,
        actor: &Actor,
        now: Timestamp,
    ) -> ServiceResult<()> {
        let owner = self.database.dictionary(dictionary_id)?;
        self.require_ownership_or_administrator(&owner, actor)?;

        self.database
            .delete_dictionary_term(term_id)
            .map_err(from_storage)?;
        self.audit(actor, "termine_rimosso", dictionary_id, "", now)
    }

    pub fn terms(&self, version: DictionaryVersionId) -> ServiceResult<Vec<DictionaryTerm>> {
        Ok(self.database.dictionary_terms(version)?)
    }

    /// Pubblica una bozza e rende il dizionario utilizzabile.
    ///
    /// Una versione **senza termini non si pubblica**: comparirebbe fra i
    /// dizionari selezionabili senza contribuire nulla. Lo schema non lo
    /// impedisce perché non è una questione di integrità; è una decisione di
    /// prodotto, e sta qui.
    ///
    /// # Errori
    ///
    /// Restituisce [`ServiceError::EmptyDictionaryVersion`] se la versione non
    /// ha termini e [`ServiceError::PublishedVersionIsImmutable`] se era già
    /// pubblicata.
    pub fn publish(
        &self,
        version: DictionaryVersionId,
        actor: &Actor,
        now: Timestamp,
    ) -> ServiceResult<()> {
        self.require(RestrictedAction::PublishVersion)?;
        self.publish_unchecked(version, actor, now)
    }

    /// Pubblica senza verificare la modalità.
    ///
    /// Serve all'installazione dei dizionari **forniti con il prodotto**, che
    /// non è un'azione dell'operatore: avviene a ogni avvio, prima che
    /// chiunque abbia toccato qualcosa, e sarebbe assurdo che una postazione in
    /// modalità operatore restasse senza i propri dizionari di sistema.
    ///
    /// Non è pubblica: nessun percorso raggiungibile dall'operatore vi arriva.
    pub(crate) fn publish_unchecked(
        &self,
        version: DictionaryVersionId,
        actor: &Actor,
        now: Timestamp,
    ) -> ServiceResult<()> {
        if self.database.dictionary_term_count(version)? == 0 {
            return Err(ServiceError::EmptyDictionaryVersion);
        }

        let dictionary_id = self
            .database
            .dictionary_version(version)
            .map_err(from_storage)?
            .dictionary_id;

        self.database
            .publish_dictionary_version(version, now)
            .map_err(from_storage)?;

        // Un dizionario diventa utilizzabile con la prima pubblicazione. Se e'
        // stato archiviato dall'operatore, pubblicare una versione non lo
        // riporta in uso da solo: sarebbe una decisione presa al posto suo.
        let dictionary = self.database.dictionary(dictionary_id)?;
        if dictionary.status == DictionaryStatus::Draft {
            self.database
                .set_dictionary_status(dictionary_id, DictionaryStatus::Active, now)
                .map_err(from_storage)?;
        }

        self.audit(actor, "versione_pubblicata", dictionary_id, "", now)
    }

    /// Apre una nuova bozza a partire dalla versione pubblicata.
    ///
    /// I termini della versione pubblicata vengono **copiati** nella bozza:
    /// senza, correggere una parola su tremila significherebbe riscriverne
    /// tremila, e nessuno lo farebbe.
    ///
    /// # Errori
    ///
    /// Restituisce [`ServiceError::BuiltInDictionaryIsReadOnly`] su un
    /// dizionario di sistema e
    /// [`ServiceError::DictionaryHasNoPublishedVersion`] se non c'è una
    /// versione da cui partire.
    pub fn start_new_version(
        &mut self,
        dictionary_id: DictionaryId,
        note: &DictionaryDescription,
        actor: &Actor,
        now: Timestamp,
    ) -> ServiceResult<DictionaryVersionId> {
        let dictionary = self.database.dictionary(dictionary_id)?;
        if !dictionary.is_editable() {
            return Err(ServiceError::BuiltInDictionaryIsReadOnly);
        }
        if dictionary.visibility == DictionaryVisibility::Shared {
            self.require(RestrictedAction::ManageSharedDictionary)?;
        }
        self.require_ownership_or_administrator(&dictionary, actor)?;

        let versions = self.database.dictionary_versions(dictionary_id)?;
        if let Some(open) = versions.iter().find(|version| version.is_mutable()) {
            // Una seconda bozza aperta sullo stesso dizionario obbligherebbe
            // l'operatore a chiedersi su quale delle due sta lavorando.
            return Ok(open.id);
        }

        let Some(published) = versions.iter().find(|version| version.is_published()) else {
            return Err(ServiceError::DictionaryHasNoPublishedVersion);
        };

        let next = versions
            .iter()
            .map(|version| version.number)
            .max()
            .unwrap_or(0)
            .saturating_add(1);

        let draft = self
            .database
            .insert_dictionary_version(
                &NewDictionaryVersion {
                    dictionary_id,
                    number: next,
                    note: note.clone(),
                    created_by: actor.clone(),
                },
                now,
            )
            .map_err(from_storage)?;

        let copied: Vec<NewDictionaryTerm> = self
            .database
            .dictionary_terms(published.id)?
            .into_iter()
            .map(|term| NewDictionaryTerm {
                version_id: draft,
                text: term.text,
                category: term.category,
                language: term.language,
                match_mode: term.match_mode,
                suggested_level: term.suggested_level,
                note: term.note,
            })
            .collect();

        self.database
            .insert_dictionary_terms(draft, &copied)
            .map_err(from_storage)?;

        self.audit(actor, "nuova_versione_aperta", dictionary_id, "", now)?;
        Ok(draft)
    }

    /// Cambia lo stato di un dizionario.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se il dizionario non esiste o se la scrittura non
    /// riesce.
    pub fn set_status(
        &self,
        dictionary_id: DictionaryId,
        status: DictionaryStatus,
        actor: &Actor,
        now: Timestamp,
    ) -> ServiceResult<()> {
        self.database
            .set_dictionary_status(dictionary_id, status, now)
            .map_err(from_storage)?;

        self.audit(
            actor,
            "stato_dizionario_cambiato",
            dictionary_id,
            status.as_str(),
            now,
        )
    }

    /// Rimuove un dizionario, o lo archivia se non può essere cancellato.
    ///
    /// Rispecchia il trattamento delle fonti: ciò che è già entrato nello
    /// storico non sparisce, ma esce dalla scelta. L'operatore ottiene sempre
    /// il risultato che voleva — non vederlo più fra i dizionari proposti — e
    /// il messaggio spiega che cosa è successo davvero.
    ///
    /// # Errori
    ///
    /// Restituisce [`ServiceError::BuiltInDictionaryIsReadOnly`] su un
    /// dizionario di sistema.
    pub fn remove(
        &self,
        dictionary_id: DictionaryId,
        actor: &Actor,
        now: Timestamp,
    ) -> ServiceResult<DictionaryRemoval> {
        let dictionary = self.database.dictionary(dictionary_id)?;
        self.require_ownership_or_administrator(&dictionary, actor)?;

        match self.database.delete_dictionary(dictionary_id) {
            Ok(()) => {
                self.audit(actor, "dizionario_rimosso", dictionary_id, "", now)?;
                Ok(DictionaryRemoval::Deleted)
            }
            Err(StorageError::BuiltInDictionaryIsReadOnly) => {
                Err(ServiceError::BuiltInDictionaryIsReadOnly)
            }
            Err(
                StorageError::DictionaryStillInUse
                | StorageError::PublishedDictionaryIsNotDeletable,
            ) => {
                self.database
                    .set_dictionary_status(dictionary_id, DictionaryStatus::Archived, now)
                    .map_err(from_storage)?;
                self.audit(actor, "dizionario_archiviato", dictionary_id, "", now)?;
                Ok(DictionaryRemoval::Archived)
            }
            Err(other) => Err(from_storage(other)),
        }
    }

    // -------------------------------------------- risoluzione e fotografia

    /// Risolve una selezione nei termini concreti, senza scrivere nulla.
    ///
    /// Serve all'anteprima: l'operatore deve poter vedere **quanti termini
    /// distinti** produrrà la sua scelta e quanti provengono da più dizionari,
    /// prima di avviare il monitoraggio.
    ///
    /// # Errori
    ///
    /// Restituisce [`ServiceError::EmptyDictionarySelection`] se la scelta è
    /// vuota e [`ServiceError::DictionaryNotSelectable`] se un dizionario non è
    /// utilizzabile.
    pub fn resolve(
        &self,
        selection: &DictionarySelection,
    ) -> ServiceResult<ResolvedDictionaryConfiguration> {
        if selection.is_empty() {
            return Err(ServiceError::EmptyDictionarySelection);
        }

        // Il limite sta dove il lavoro comincia. Applicarlo solo alla scrittura
        // significherebbe risolvere per intero una selezione che verrà
        // comunque respinta, e mostrarne l'anteprima all'operatore.
        if selection.dictionary_ids.len() > MAX_DICTIONARIES_PER_SESSION {
            return Err(ServiceError::Storage(
                lisi_storage::StorageError::LimitExceeded {
                    limit: "dizionari_per_sessione",
                    max: MAX_DICTIONARIES_PER_SESSION,
                    requested: selection.dictionary_ids.len(),
                },
            ));
        }

        let mut resolver = ConfigurationResolver::new();

        for dictionary_id in &selection.dictionary_ids {
            let (dictionary, version) = self.usable_version(*dictionary_id)?;

            for term in self.database.dictionary_terms(version.id)? {
                resolver.add(
                    term.text,
                    term.category,
                    term.language,
                    term.match_mode,
                    term.suggested_level.get(),
                    TermProvenance::from_dictionary(
                        dictionary.id,
                        version.id,
                        &dictionary.name,
                        version.number,
                    ),
                )?;
            }
        }

        for added in &selection.ad_hoc_terms {
            // Il livello lo dichiara chi aggiunge la parola. Fino al
            // 2026-07-31 entrava qui uno zero fisso, sul principio che «chi
            // scrive una parola dice che cosa cercare, non quanto sia grave»:
            // ragionevole in astratto, ma zero è «non rilevante», il solo
            // livello che non produce un avviso e quindi non produce mai una
            // notifica. Il wizard offriva intanto «un dizionario **oppure**
            // una parola», e chi seguiva la seconda strada otteneva un
            // monitoraggio incapace di segnalare, senza che nulla lo dicesse
            // (rilevato nel pilot del 2026-07-31: un messaggio contenente la
            // parola sorvegliata compariva nello storico come «non
            // rilevante»).
            resolver.add(
                added.text.clone(),
                ad_hoc_category()?,
                ad_hoc_language()?,
                added.match_mode,
                added.suggested_level.get(),
                TermProvenance::ad_hoc(),
            )?;
        }

        Ok(resolver.finish())
    }

    /// Fissa la configurazione di una sessione e ne scrive la fotografia.
    ///
    /// Da qui in avanti la sessione lavora sulla fotografia e non sui
    /// dizionari: se un dizionario cambia mentre la sessione è in corso, la
    /// sessione continua con i termini di prima.
    ///
    /// # Errori
    ///
    /// Come [`DictionaryService::resolve`], più un errore se la sessione ha già
    /// una configurazione o se la scrittura non riesce.
    pub fn apply_to_session(
        &mut self,
        session_id: SessionId,
        selection: &DictionarySelection,
        actor: &Actor,
        now: Timestamp,
    ) -> ServiceResult<ResolvedDictionaryConfiguration> {
        let configuration = self.resolve(selection)?;

        let selected = self.selected_versions(&selection.dictionary_ids)?;
        let chosen: Vec<(DictionaryId, DictionaryVersionId)> = selected
            .iter()
            .map(|entry| (entry.id, entry.version_id))
            .collect();

        self.database
            .set_session_dictionary_selection(session_id, &chosen, now)
            .map_err(from_storage)?;
        self.database
            .insert_session_custom_terms(session_id, &selection.ad_hoc_terms, now)
            .map_err(from_storage)?;
        self.database
            .save_resolved_configuration(session_id, &configuration)
            .map_err(from_storage)?;

        // L'impronta entra nell'audit: e' cio' che permette di dire, mesi dopo,
        // che la configurazione di questa sessione era quella e non un'altra.
        // Non e' una firma e non va presentata come tale.
        //
        // Accanto all'impronta entrano i dizionari **con la loro versione**.
        // L'impronta dice che due configurazioni sono la stessa; non dice a
        // chi la legge CHE COSA fosse. «Incendi v3, Contesto riduttivo v2» si
        // legge e si verifica; dodici caratteri esadecimali no.
        self.audit_session(
            actor,
            "configurazione_fissata",
            session_id,
            &format!(
                "{} termini, impronta {}, {}",
                configuration.unique_count,
                configuration.digest.short(),
                audit_list_of(&selected)
            ),
            now,
        )?;

        Ok(configuration)
    }

    /// La configurazione risolta di **una sola** versione di dizionario.
    ///
    /// # A che cosa serve
    ///
    /// Al Rule Lab, che confronta una versione pubblicata con una candidata
    /// sullo stesso testo. Le due si risolvono con lo **stesso** procedimento
    /// con cui si risolve la configurazione di una sessione — stesso
    /// `ConfigurationResolver`, stessa normalizzazione, stesso ordine canonico
    /// — perché un confronto fra due cose risolte in modi diversi non
    /// misurerebbe la differenza fra i dizionari.
    ///
    /// # Perché accetta anche una bozza
    ///
    /// Perché la versione candidata **è** una bozza: è il caso normale del
    /// laboratorio, non un'eccezione. Risolverla non la pubblica e non la
    /// tocca.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se la lettura non riesce o se un termine non
    /// rispetta le invarianti del dominio.
    pub fn configuration_of_version(
        &self,
        dictionary_id: DictionaryId,
        version: &DictionaryVersion,
    ) -> ServiceResult<ResolvedDictionaryConfiguration> {
        let dictionary = self.database.dictionary(dictionary_id)?;
        let mut resolver = ConfigurationResolver::new();

        for term in self.database.dictionary_terms(version.id)? {
            resolver.add(
                term.text,
                term.category,
                term.language,
                term.match_mode,
                term.suggested_level.get(),
                TermProvenance::from_dictionary(
                    dictionary.id,
                    version.id,
                    &dictionary.name,
                    version.number,
                ),
            )?;
        }

        Ok(resolver.finish())
    }

    /// Configurazione con cui una sessione è stata condotta.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se la sessione non esiste o se la copia conservata
    /// non corrisponde più alla propria impronta.
    pub fn configuration_of(
        &self,
        session_id: SessionId,
    ) -> ServiceResult<Option<ResolvedDictionaryConfiguration>> {
        Ok(self.database.session_resolved_configuration(session_id)?)
    }

    /// Dizionario e versione utilizzabili, o il motivo per cui non lo sono.
    fn usable_version(
        &self,
        dictionary_id: DictionaryId,
    ) -> ServiceResult<(Dictionary, DictionaryVersion)> {
        let dictionary = self.database.dictionary(dictionary_id)?;

        if !dictionary.is_selectable() {
            return Err(ServiceError::DictionaryNotSelectable {
                name: dictionary.name.as_str().to_owned(),
            });
        }

        let Some(version) = self.database.latest_published_version(dictionary_id)? else {
            return Err(ServiceError::DictionaryNotSelectable {
                name: dictionary.name.as_str().to_owned(),
            });
        };

        Ok((dictionary, version))
    }

    // ----------------------------------------------------------------- audit

    /// Registra la modifica nell'audit append-only.
    ///
    /// Il dettaglio riporta il nome del dizionario, che non è un segreto, e mai
    /// il contenuto dei termini.
    pub(crate) fn audit(
        &self,
        actor: &Actor,
        action: &str,
        id: DictionaryId,
        detail: &str,
        now: Timestamp,
    ) -> ServiceResult<()> {
        self.append(actor, action, "dictionary", Some(id.get()), detail, now)
    }

    /// Registra nell'audit una modifica riferita a una sessione.
    fn audit_session(
        &self,
        actor: &Actor,
        action: &str,
        id: SessionId,
        detail: &str,
        now: Timestamp,
    ) -> ServiceResult<()> {
        self.append(actor, action, "session", Some(id.get()), detail, now)
    }

    fn append(
        &self,
        actor: &Actor,
        action: &str,
        entity: &str,
        entity_id: Option<i64>,
        detail: &str,
        now: Timestamp,
    ) -> ServiceResult<()> {
        let detail = if detail.trim().is_empty() {
            None
        } else {
            Some(AuditDetail::try_new(detail)?)
        };

        let entry = NewAuditEntry {
            actor: actor.clone(),
            action: AuditAction::try_new(action)?,
            entity: AuditEntity::try_new(entity)?,
            entity_id,
            // Ogni voce scritta da questo servizio porta la modalita' con cui
            // e' stata compiuta: il registro dice non solo chi ha fatto che
            // cosa, ma con quali privilegi.
            actor_mode: Some(self.mode),
            detail,
            recorded_at: now,
        };

        self.database.append_audit(&entry)?;
        Ok(())
    }
}

/// Categoria attribuita alle parole aggiunte alla singola sessione.
fn ad_hoc_category() -> ServiceResult<lisi_core::text::TermCategory> {
    Ok(lisi_core::text::TermCategory::try_new("aggiunta")?)
}

/// Lingua attribuita alle parole aggiunte alla singola sessione.
///
/// Non è una dichiarazione sulla lingua del testo: è un valore obbligatorio
/// dello schema, e attribuirlo per indovinare sarebbe peggio che dichiararlo
/// indeterminato.
fn ad_hoc_language() -> ServiceResult<lisi_core::text::LanguageTag> {
    Ok(lisi_core::text::LanguageTag::try_new("und")?)
}

/// Quanti caratteri l'elenco dei dizionari può occupare nel dettaglio d'audit.
///
/// Il dettaglio ammette 4096 caratteri. Trentadue dizionari (il massimo per
/// sessione) con nomi di cento caratteri ci starebbero appena, e «appena» è la
/// distanza che separa una voce d'audit da un errore di validazione **al
/// momento di fissare una configurazione** — cioè nel punto peggiore possibile.
/// Il budget lascia margine al resto della frase e all'evoluzione futura.
const AUDIT_DICTIONARY_BUDGET: usize = 2_048;

/// L'elenco dei dizionari scelti, come entra nel dettaglio d'audit.
///
/// Tronca quando supera il budget, e **dichiara di averlo fatto**: un elenco
/// tagliato in silenzio farebbe credere, a chi lo rilegge, che i dizionari
/// fossero quelli e basta.
fn audit_list_of(selected: &[SelectedDictionary]) -> String {
    if selected.is_empty() {
        return String::from("nessun dizionario, soltanto parole aggiunte alla sessione");
    }

    let mut testo = String::from("dizionari: ");
    let mut scritti = 0usize;

    for entry in selected {
        let voce = entry.label();
        if !testo.is_empty() && testo.len() + voce.len() + 2 > AUDIT_DICTIONARY_BUDGET {
            break;
        }
        if scritti > 0 {
            testo.push_str(", ");
        }
        testo.push_str(&voce);
        scritti += 1;
    }

    if scritti < selected.len() {
        testo.push_str(&format!(
            " (e altri {}, non elencati per lunghezza)",
            selected.len() - scritti
        ));
    }
    testo
}

#[cfg(test)]
mod tests {
    use lisi_core::model::dictionary::{
        DictionaryOrigin, DictionaryScope, DictionarySelection, DictionaryStatus,
        DictionaryVisibility, MAX_DICTIONARIES_PER_SESSION, MatchMode, NewDictionary,
        NewDictionaryTerm, SessionCustomTerm, SuggestedLevel,
    };
    use lisi_core::model::{NewSession, NewSource, SessionDuration, SourceKind};
    use lisi_core::text::{
        Actor, DictionaryDescription, DictionaryName, DisplayName, LanguageTag, SourceIdentifier,
        TermCategory, TermNote, TermText,
    };
    use lisi_core::{
        DictionaryId, DictionaryVersionId, DomainError, OperatingMode, RestrictedAction, SessionId,
        Timestamp,
    };
    use lisi_storage::Database;

    use super::{DictionaryProposal, DictionaryRemoval, DictionaryService, LibraryFilter};
    use crate::error::ServiceError;
    use crate::sources::open_in_memory_database;

    /// Istante di riferimento: 2023-11-14T22:13:20Z.
    fn now() -> Timestamp {
        Timestamp::from_millis(1_700_000_000_000)
    }

    fn actor(raw: &str) -> Actor {
        let Ok(value) = Actor::try_new(raw) else {
            panic!("l'attore di prova '{raw}' deve essere valido");
        };
        value
    }

    fn operator() -> Actor {
        actor("operatore.prova")
    }

    fn name(raw: &str) -> DictionaryName {
        let Ok(value) = DictionaryName::try_new(raw) else {
            panic!("il nome di prova '{raw}' deve essere valido");
        };
        value
    }

    fn description(raw: &str) -> DictionaryDescription {
        let Ok(value) = DictionaryDescription::try_new(raw) else {
            panic!("la descrizione di prova deve essere valida");
        };
        value
    }

    fn proposal(label: &str) -> DictionaryProposal {
        DictionaryProposal {
            name: name(label),
            description: description("dizionario di prova"),
            scope: DictionaryScope::Thematic,
            visibility: DictionaryVisibility::Personal,
        }
    }

    fn term(version: DictionaryVersionId, text: &str, level: i8) -> NewDictionaryTerm {
        let (Ok(category), Ok(language), Ok(note), Ok(suggested_level), Ok(text)) = (
            TermCategory::try_new("prova"),
            LanguageTag::try_new("it"),
            TermNote::try_new(""),
            SuggestedLevel::try_new(level),
            TermText::try_new(text),
        ) else {
            panic!("i valori del termine di prova devono essere validi");
        };

        NewDictionaryTerm {
            version_id: version,
            text,
            category,
            language,
            match_mode: MatchMode::NormalizedWord,
            suggested_level,
            note,
        }
    }

    fn service() -> DictionaryService {
        let Ok(database) = open_in_memory_database() else {
            panic!("il database in memoria deve potersi aprire");
        };
        DictionaryService::new(database)
    }

    /// Dizionario creato, riempito e pubblicato attraverso il servizio.
    fn published(
        service: &mut DictionaryService,
        label: &str,
        terms: &[(&str, i8)],
    ) -> (DictionaryId, DictionaryVersionId) {
        let Ok((dictionary, version)) = service.create(&proposal(label), &operator(), now()) else {
            panic!("il dizionario '{label}' deve potersi creare");
        };

        let collected: Vec<_> = terms
            .iter()
            .map(|(text, level)| term(version, text, *level))
            .collect();
        let Ok(_) = service.add_terms(version, &collected, &operator(), now()) else {
            panic!("i termini devono potersi aggiungere");
        };
        let Ok(()) = service.publish(version, &operator(), now()) else {
            panic!("la pubblicazione deve riuscire");
        };

        (dictionary, version)
    }

    /// Sessione di prova, necessaria per fissare una configurazione.
    fn session_in(database: &mut Database) -> SessionId {
        let (Ok(identifier), Ok(label), Ok(title)) = (
            SourceIdentifier::try_new("canale_uno"),
            DisplayName::try_new("Sessione di prova"),
            DisplayName::try_new("Canale di prova"),
        ) else {
            panic!("i valori di prova devono essere validi");
        };

        let Ok(source) = database.insert_source(
            &NewSource {
                kind: SourceKind::Channel,
                identifier,
                display_name: title,
                authorized_by: operator(),
                active: true,
            },
            now(),
        ) else {
            panic!("la fonte di prova deve potersi registrare");
        };

        let Ok(session) = database.insert_session(
            &NewSession {
                label,
                started_by: operator(),
                duration: SessionDuration::Preset { seconds: 3_600 },
                source_ids: vec![source],
            },
            now(),
        ) else {
            panic!("la sessione di prova deve potersi creare");
        };
        session
    }

    /// Azioni registrate nell'audit, in ordine.
    fn audit_actions(service: &DictionaryService) -> Vec<String> {
        let Ok(entries) = service.database().audit_entries() else {
            panic!("l'audit deve potersi leggere");
        };
        entries
            .iter()
            .map(|entry| entry.action.as_str().to_owned())
            .collect()
    }

    // ------------------------------------------------- ricerca e anteprima

    #[test]
    fn an_empty_filter_restricts_nothing() {
        let mut service = service();
        published(&mut service, "Incendi", &[("incendio", 2)]);
        published(&mut service, "Danneggiamento", &[("sabotare", 3)]);

        let filter = LibraryFilter::default();
        assert!(filter.is_empty());
        assert_eq!(
            service.library_matching(&filter).map(|all| all.len()).ok(),
            Some(2)
        );
    }

    #[test]
    fn the_search_normalises_exactly_as_the_engine_does() {
        // La ricerca usa la stessa normalizzazione dei termini: maiuscole e
        // forma Unicode non contano, **gli accenti si'**. Non e' una
        // dimenticanza: il motore si comporta cosi', e una ricerca piu'
        // permissiva del motore troverebbe dizionari i cui termini poi non
        // riscontrerebbero, che e' il modo peggiore di imparare la differenza.
        let mut service = service();
        let mut proposal = proposal("Citt\u{e0} di prova");
        proposal.description = description("copre il territorio comunale");
        let Ok(_) = service.create(&proposal, &operator(), now()) else {
            panic!("il dizionario deve potersi creare");
        };
        published(&mut service, "Altro", &[("parola", 1)]);

        let count = |needle: &str| {
            let filter = LibraryFilter {
                query: String::from(needle),
                ..LibraryFilter::default()
            };
            let Ok(found) = service.library_matching(&filter) else {
                panic!("la ricerca deve riuscire");
            };
            found.len()
        };

        // Caso e forma Unicode non contano: "citta\u{300}" e' la forma
        // decomposta della stessa parola.
        for needle in ["citt\u{e0}", "CITT\u{c0}", "citta\u{300}"] {
            assert_eq!(count(needle), 1, "cercando '{needle}'");
        }

        // L'accento invece conta, come nel motore.
        assert_eq!(count("citta"), 0, "l'accento non viene ignorato");
    }

    #[test]
    fn the_search_looks_at_the_description_too() {
        let service = service();
        let mut proposal = proposal("Nome che non dice nulla");
        proposal.description = description("ordigni incendiari e materiali");
        let Ok(_) = service.create(&proposal, &operator(), now()) else {
            panic!("il dizionario deve potersi creare");
        };

        let filter = LibraryFilter {
            query: String::from("incendiari"),
            ..LibraryFilter::default()
        };
        assert_eq!(
            service.library_matching(&filter).map(|all| all.len()).ok(),
            Some(1)
        );
    }

    #[test]
    fn the_usable_filter_hides_what_would_contribute_nothing() {
        let mut service = service();
        published(&mut service, "Pronto", &[("incendio", 2)]);
        let Ok(_) = service.create(&proposal("Ancora in bozza"), &operator(), now()) else {
            panic!("il dizionario deve potersi creare");
        };

        let filter = LibraryFilter {
            only_usable: true,
            ..LibraryFilter::default()
        };
        let Ok(found) = service.library_matching(&filter) else {
            panic!("la ricerca deve riuscire");
        };
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].dictionary.name.as_str(), "Pronto");
    }

    #[test]
    fn the_editable_filter_hides_the_system_dictionaries() {
        let mut service = service();
        let Ok(_) = service.install_seed_dictionaries(now()) else {
            panic!("i seed devono installarsi");
        };
        let Ok(_) = service.create(&proposal("Mio"), &operator(), now()) else {
            panic!("il dizionario deve potersi creare");
        };

        let filter = LibraryFilter {
            only_editable: true,
            ..LibraryFilter::default()
        };
        let Ok(found) = service.library_matching(&filter) else {
            panic!("la ricerca deve riuscire");
        };
        assert_eq!(found.len(), 1);
        assert!(found[0].dictionary.is_editable());
    }

    #[test]
    fn the_filters_combine_instead_of_replacing_each_other() {
        let mut service = service();
        let Ok(_) = service.install_seed_dictionaries(now()) else {
            panic!("i seed devono installarsi");
        };
        published(&mut service, "Incendi personali", &[("incendio", 2)]);

        let filter = LibraryFilter {
            query: String::from("incendi"),
            only_usable: true,
            only_editable: true,
        };
        let Ok(found) = service.library_matching(&filter) else {
            panic!("la ricerca deve riuscire");
        };
        // Il seed "Incendi e ordigni incendiari" e' utilizzabile ma di sistema;
        // il personale e' entrambi.
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].dictionary.name.as_str(), "Incendi personali");
    }

    #[test]
    fn a_search_that_matches_nothing_returns_an_empty_list_and_not_everything() {
        let mut service = service();
        published(&mut service, "Incendi", &[("incendio", 2)]);

        let filter = LibraryFilter {
            query: String::from("parola-che-non-esiste"),
            ..LibraryFilter::default()
        };
        assert_eq!(
            service.library_matching(&filter).map(|all| all.len()).ok(),
            Some(0)
        );
    }

    #[test]
    fn the_preview_shows_the_terms_of_the_published_version() {
        let mut service = service();
        let (dictionary, _) =
            published(&mut service, "Incendi", &[("incendio", 2), ("molotov", 4)]);

        let Ok(terms) = service.published_terms(dictionary) else {
            panic!("l'anteprima deve potersi leggere");
        };
        let texts: Vec<&str> = terms.iter().map(|term| term.text.as_str()).collect();
        assert_eq!(texts, ["incendio", "molotov"]);
    }

    #[test]
    fn a_dictionary_without_a_published_version_has_nothing_to_preview() {
        // L'elenco vuoto e' la risposta giusta: non c'e' nulla da mostrare, e
        // mostrare la bozza spaccerebbe per contenuto cio' che nessuno ha
        // ancora approvato.
        let service = service();
        let Ok((dictionary, _)) = service.create(&proposal("Bozza"), &operator(), now()) else {
            panic!("il dizionario deve potersi creare");
        };

        assert_eq!(
            service
                .published_terms(dictionary)
                .map(|all| all.len())
                .ok(),
            Some(0)
        );
    }

    // ------------------------------------------------------ modalita' operativa

    /// Servizio in modalità operatore, con i seed già installati.
    fn operator_station() -> DictionaryService {
        let Ok(database) = open_in_memory_database() else {
            panic!("il database in memoria deve potersi aprire");
        };
        let mut service = DictionaryService::new(database);
        let Ok(_) = service.install_seed_dictionaries(now()) else {
            panic!("i dizionari forniti con il prodotto devono installarsi");
        };
        service.set_mode(OperatingMode::Operator);
        service
    }

    #[test]
    fn the_shipped_dictionaries_are_installed_even_in_operator_mode() {
        // L'installazione avviene a ogni avvio, prima che chiunque abbia
        // toccato qualcosa: sarebbe assurdo che una postazione in modalita'
        // operatore restasse senza i propri dizionari di sistema.
        let service = operator_station();

        let Ok(usable) = service.usable() else {
            panic!("l'elenco deve potersi leggere");
        };
        assert!(!usable.is_empty());
        assert_eq!(service.mode(), OperatingMode::Operator);
    }

    /// **Un operatore pubblica una versione, e l'audit dice in quale modalità**
    /// (ADR-0140).
    ///
    /// Fino al 2026-10-15 questa prova si chiamava
    /// `an_operator_cannot_publish_a_version`: la pubblicazione era riservata.
    /// Il proprietario ha deciso che il personale autorizzato pubblica, con una
    /// conferma che dice la conseguenza; la prova dice la regola nuova.
    #[test]
    fn an_operator_publishes_a_version_and_the_audit_says_in_which_mode() {
        let mut service = operator_station();
        let Ok((mio, version)) = service.create(&proposal("Mio"), &operator(), now()) else {
            panic!("un dizionario personale deve potersi creare");
        };
        let Ok(_) = service.add_terms(version, &[term(version, "incendio", 2)], &operator(), now())
        else {
            panic!("i termini nel proprio dizionario devono potersi aggiungere");
        };

        assert!(
            service.publish(version, &operator(), now()).is_ok(),
            "il personale autorizzato pubblica"
        );

        let Ok(voci) = service.database().audit_entries() else {
            panic!("l'audit deve potersi leggere");
        };
        // La voce di QUESTO dizionario: i dizionari di sistema si pubblicano
        // all'installazione, in modalita' amministratore.
        let Some(voce) = voci.iter().find(|voce| {
            voce.action.as_str() == "versione_pubblicata" && voce.entity_id == Some(mio.get())
        }) else {
            panic!("la pubblicazione deve lasciare traccia");
        };
        assert_eq!(voce.actor_mode, Some(OperatingMode::Operator));
        // Pubblicata non si modifica più: nemmeno da chi l'ha pubblicata.
        assert!(
            service
                .add_terms(version, &[term(version, "rogo", 2)], &operator(), now())
                .is_err(),
            "una versione pubblicata resta immutabile"
        );
    }

    /// **Un operatore crea dizionari condivisi e personali** (ADR-0140).
    #[test]
    fn an_operator_creates_shared_and_personal_dictionaries() {
        let service = operator_station();

        let mut shared = proposal("Condiviso");
        shared.visibility = DictionaryVisibility::Shared;
        assert!(
            service.create(&shared, &operator(), now()).is_ok(),
            "il dizionario condiviso è lavoro di tutti i giorni"
        );

        assert!(
            service
                .create(&proposal("Personale"), &operator(), now())
                .is_ok(),
            "il proprio dizionario resta disponibile"
        );
    }

    #[test]
    fn an_operator_can_duplicate_a_system_dictionary() {
        // E' il percorso previsto per partire dai dizionari forniti: negarlo
        // renderebbe la modalita' operatore inutilizzabile.
        let mut service = operator_station();
        let built_in = {
            let Ok(entries) = service.library() else {
                panic!("la libreria deve potersi leggere");
            };
            entries[0].dictionary.id
        };

        assert!(
            service
                .duplicate(built_in, &name("Copia di lavoro"), &operator(), now())
                .is_ok()
        );
    }

    #[test]
    fn an_operator_cannot_touch_a_dictionary_composed_by_someone_else() {
        let mut service = operator_station();
        service.set_mode(OperatingMode::Administrator);
        let Ok((altrui, version)) =
            service.create(&proposal("Di un collega"), &actor("altro.operatore"), now())
        else {
            panic!("il dizionario altrui deve potersi creare");
        };
        service.set_mode(OperatingMode::Operator);

        for outcome in [
            service.remove(altrui, &operator(), now()).err(),
            service
                .start_new_version(altrui, &description("x"), &operator(), now())
                .err(),
            service
                .add_terms(version, &[term(version, "parola", 1)], &operator(), now())
                .err(),
        ] {
            assert!(
                matches!(
                    outcome,
                    Some(ServiceError::ActionReservedToAdministrator {
                        action: RestrictedAction::RemoveOthersDictionary
                    })
                ),
                "l'operazione su un dizionario altrui doveva essere rifiutata"
            );
        }
    }

    #[test]
    fn an_operator_governs_their_own_dictionary_entirely() {
        let mut service = operator_station();
        let Ok((mine, version)) = service.create(&proposal("Mio"), &operator(), now()) else {
            panic!("il dizionario deve potersi creare");
        };

        assert!(
            service
                .add_terms(version, &[term(version, "incendio", 2)], &operator(), now())
                .is_ok()
        );
        assert!(service.publish(version, &operator(), now()).is_ok());
        assert!(
            service
                .start_new_version(mine, &description("correzione"), &operator(), now())
                .is_ok(),
            "una nuova bozza si apre dalla versione pubblicata"
        );
        assert!(service.remove(mine, &operator(), now()).is_ok());
    }

    /// **Un operatore importa un file, che entra personale e in bozza**
    /// (ADR-0140).
    ///
    /// Si chiamava `an_operator_cannot_import_a_file`. La protezione che resta
    /// non è il rifiuto ma l'ingresso: il dizionario importato non è
    /// utilizzabile finché qualcuno non lo pubblica, con la conferma.
    #[test]
    fn an_operator_imports_a_file_as_a_personal_draft() {
        let mut service = operator_station();
        let file = br#"{"format":"nexum-dictionary","format_version":1,"name":"X",
                       "description":"","scope":"thematic",
                       "version":{"number":1,"note":""},"terms":[]}"#;

        let Ok((importato, _)) = service.import(file, &operator(), now()) else {
            panic!("l'importazione è lavoro di tutti i giorni");
        };
        let Ok(dizionario) = service.database().dictionary(importato) else {
            panic!("il dizionario importato deve rileggersi");
        };
        assert_eq!(dizionario.visibility, DictionaryVisibility::Personal);
        let Ok(utilizzabili) = service.usable() else {
            panic!("l'elenco deve potersi leggere");
        };
        assert!(
            !utilizzabili.iter().any(|d| d.id == importato),
            "un file importato non entra in un monitoraggio prima di essere pubblicato"
        );
    }

    /// **Il servizio rifiuta ciò che resta riservato, e consente il resto**:
    /// non un pulsante disabilitato.
    ///
    /// Ogni azione è invocata direttamente, come farebbe un percorso che
    /// dimentica di consultare la modalità. Dal 2026-10-15 le azioni rifiutate
    /// all'operatore sono due (ADR-0140), dal 2026-10-30 tre (ADR-0178), dal
    /// 2026-11-04 quattro (ADR-0179), dal 2026-11-05 cinque (ADR-0181); la
    /// prova le elenca per nome invece di dedurle, così che un cambio della
    /// regola non la renda vera da sola.
    #[test]
    fn the_refusal_comes_from_the_service_and_not_from_a_disabled_button() {
        let service = operator_station();
        for action in RestrictedAction::ALL {
            let outcome = service.require(action);
            let riservata = matches!(
                action,
                RestrictedAction::RemoveOthersDictionary
                    | RestrictedAction::ChooseUpdateChannel
                    | RestrictedAction::ChooseDictionarySource
                    | RestrictedAction::ChooseTaxiiDestination
                    | RestrictedAction::ChooseSigningCertificate
                    | RestrictedAction::ChooseBackupSchedule
                    | RestrictedAction::ChooseConsultationLog
                    | RestrictedAction::ChooseOfficeNetworks
                    | RestrictedAction::ChooseRemoteCommands
                    | RestrictedAction::ChooseMembersListing
                    | RestrictedAction::ChooseIndicatorResolution
                    | RestrictedAction::ChooseRegistrationLookup
            );
            if riservata {
                assert!(
                    matches!(
                        outcome,
                        Err(ServiceError::ActionReservedToAdministrator { .. })
                    ),
                    "'{}' doveva essere rifiutata",
                    action.as_str()
                );
            } else {
                assert!(
                    outcome.is_ok(),
                    "'{}' è consentita all'operatore (ADR-0140)",
                    action.as_str()
                );
            }
        }
    }

    // ------------------------------------------------ Laboratorio (F-07)

    /// **Una bozza di un dizionario pubblicato si confronta con la sua
    /// versione pubblicata, e le differenze dei termini si contano.**
    #[test]
    fn a_new_version_is_compared_with_its_published_one() {
        let mut service = operator_station();
        let Ok((mio, v1)) = service.create(&proposal("Incendi"), &operator(), now()) else {
            panic!("il dizionario deve potersi creare");
        };
        let Ok(_) = service.add_terms(
            v1,
            &[term(v1, "incendio", 3), term(v1, "corteo", 1)],
            &operator(),
            now(),
        ) else {
            panic!("i termini devono potersi aggiungere");
        };
        let Ok(()) = service.publish(v1, &operator(), now()) else {
            panic!("la versione deve potersi pubblicare");
        };

        // Nessuna bozza: il Laboratorio non ha nulla da proporre per questo
        // dizionario.
        let Ok(prima) = service.lab_candidates() else {
            panic!("i candidati devono potersi leggere");
        };
        assert!(!prima.iter().any(|c| c.dictionary.id == mio));

        let Ok(v2) = service.start_new_version(mio, &description("correzione"), &operator(), now())
        else {
            panic!("la nuova versione deve aprirsi");
        };
        let Ok(candidati) = service.lab_candidates() else {
            panic!("i candidati devono potersi leggere");
        };
        let Some(candidato) = candidati.iter().find(|c| c.dictionary.id == mio) else {
            panic!("la bozza deve comparire fra i candidati");
        };
        assert_eq!(candidato.draft.id, v2);
        assert!(matches!(
            candidato.baseline,
            Some(super::LabBaseline::OwnPublished(ref v)) if v.id == v1
        ));
        assert!(
            candidato
                .label()
                .contains("bozza v2 contro la pubblicata v1")
        );

        // Appena aperta, la bozza è uguale alla pubblicata.
        let Ok(Some(uguale)) = service.lab_term_differences(candidato) else {
            panic!("il confronto dei termini deve riuscire");
        };
        assert!(uguale.is_empty());

        // Una parola aggiunta e una tolta.
        let Ok(_) = service.add_terms(v2, &[term(v2, "rogo", 2)], &operator(), now()) else {
            panic!("il termine deve potersi aggiungere alla bozza");
        };
        let Ok(termini) = service.terms(v2) else {
            panic!("i termini della bozza devono leggersi");
        };
        let Some(corteo) = termini.iter().find(|t| t.text.as_str() == "corteo") else {
            panic!("il termine copiato deve esserci");
        };
        let Ok(()) = service.remove_term(mio, corteo.id, &operator(), now()) else {
            panic!("il termine deve potersi togliere dalla bozza");
        };
        let Ok(Some(diverso)) = service.lab_term_differences(candidato) else {
            panic!("il confronto dei termini deve riuscire");
        };
        assert_eq!(
            (diverso.added(), diverso.removed(), diverso.changed()),
            (1, 1, 0)
        );

        // La versione pubblicata non si è mossa.
        let Ok(pubblicati) = service.terms(v1) else {
            panic!("la versione pubblicata deve leggersi");
        };
        assert_eq!(pubblicati.len(), 2, "pubblicata, non si tocca");
    }

    /// **Un duplicato senza versione propria si confronta con l'originale**, e
    /// lo dice.
    #[test]
    fn a_duplicate_is_compared_with_the_dictionary_it_was_born_from() {
        let mut service = operator_station();
        let Ok(libreria) = service.library() else {
            panic!("la libreria deve leggersi");
        };
        let Some(di_sistema) = libreria.iter().find(|e| e.published.is_some()) else {
            panic!("ci deve essere un dizionario pubblicato fornito con il prodotto");
        };
        let originale = di_sistema.dictionary.id;
        let Ok((copia, _)) = service.duplicate(originale, &name("Mia copia"), &operator(), now())
        else {
            panic!("il duplicato deve potersi creare");
        };

        let Ok(candidati) = service.lab_candidates() else {
            panic!("i candidati devono potersi leggere");
        };
        let Some(candidato) = candidati.iter().find(|c| c.dictionary.id == copia) else {
            panic!("il duplicato in bozza deve comparire");
        };
        assert_eq!(candidato.baseline_dictionary_id(), Some(originale));
        assert!(
            candidato.label().contains("contro l'originale"),
            "{}",
            candidato.label()
        );
        let Ok(Some(differenze)) = service.lab_term_differences(candidato) else {
            panic!("il confronto dei termini deve riuscire");
        };
        assert!(
            differenze.is_empty(),
            "una copia appena fatta è uguale all'originale"
        );
    }

    /// **Un termine ripetuto nella bozza è un doppione, non un guasto** (F-10).
    ///
    /// Prima della correzione l'errore arrivava come
    /// `ServiceError::Storage`, e la schermata diceva «problema tecnico».
    #[test]
    fn a_repeated_term_is_a_duplicate_and_not_a_technical_fault() {
        let mut service = operator_station();
        let Ok((_, v1)) = service.create(&proposal("Doppioni"), &operator(), now()) else {
            panic!("il dizionario deve potersi creare");
        };
        let Ok(_) = service.add_terms(v1, &[term(v1, "incendio", 2)], &operator(), now()) else {
            panic!("il primo termine deve entrare");
        };
        let esito = service.add_terms(v1, &[term(v1, "Incendio", 3)], &operator(), now());
        assert!(
            matches!(esito, Err(ServiceError::TermAlreadyInVersion)),
            "{esito:?}"
        );
        let Err(errore) = esito else {
            panic!("il doppione deve essere rifiutato");
        };
        assert!(!errore.operator_message().contains("problema tecnico"));
    }

    #[test]
    fn a_fresh_service_is_in_administrator_mode() {
        assert_eq!(service().mode(), OperatingMode::Administrator);
    }

    // ------------------------------------------------- passaggi di modalita'

    /// Store di postazione su un percorso temporaneo.
    fn station_store() -> (lisi_security::ProtectedStore, tempfile::TempDir) {
        let Ok(directory) = tempfile::tempdir() else {
            panic!("la cartella temporanea deve potersi creare");
        };
        let store = lisi_security::ProtectedStore::at(directory.path().join("station.protetto"));
        (store, directory)
    }

    #[test]
    fn switching_to_operator_mode_persists_it_and_records_it() {
        let mut service = service();
        let (store, _guard) = station_store();

        let Ok(()) =
            service.switch_to_operator_mode_in(&store, "parola-di-consegna", &operator(), now())
        else {
            panic!("il passaggio deve riuscire");
        };

        assert_eq!(service.mode(), OperatingMode::Operator);
        assert_eq!(
            crate::station::load_mode(&store).ok(),
            Some(OperatingMode::Operator),
            "la scelta deve essere conservata, non solo applicata"
        );
        assert!(audit_actions(&service).contains(&String::from("modalita_operatore_attivata")));
    }

    #[test]
    fn the_transition_is_recorded_with_the_mode_it_was_decided_in() {
        // Registrare la modalita' di arrivo direbbe che l'operatore si e' messo
        // da se' in modalita' operatore.
        let mut service = service();
        let (store, _guard) = station_store();
        let Ok(()) = service.switch_to_operator_mode_in(&store, "parola-lunga", &operator(), now())
        else {
            panic!("il passaggio deve riuscire");
        };

        let Ok(entries) = service.database().audit_entries() else {
            panic!("l'audit deve potersi leggere");
        };
        let Some(entry) = entries
            .iter()
            .find(|entry| entry.action.as_str() == "modalita_operatore_attivata")
        else {
            panic!("la voce deve essere presente");
        };
        assert_eq!(entry.actor_mode, Some(OperatingMode::Administrator));
    }

    #[test]
    fn a_failed_attempt_changes_nothing_and_still_leaves_a_trace() {
        // E' la sola cosa che il prodotto puo' onestamente offrire contro la
        // determinazione: non impedire, ma non lasciare che accada in silenzio.
        let mut service = service();
        let (store, _guard) = station_store();
        let Ok(()) =
            service.switch_to_operator_mode_in(&store, "parola-giusta", &operator(), now())
        else {
            panic!("il passaggio deve riuscire");
        };

        assert!(matches!(
            service.switch_to_administrator_mode_in(&store, "tentativo", &operator(), now()),
            Err(ServiceError::WrongUnlockWord)
        ));
        assert_eq!(service.mode(), OperatingMode::Operator, "nulla e' cambiato");
        assert_eq!(
            crate::station::load_mode(&store).ok(),
            Some(OperatingMode::Operator)
        );
        assert!(
            audit_actions(&service).contains(&String::from("modalita_amministratore_rifiutata")),
            "il tentativo fallito deve restare nel registro"
        );
    }

    #[test]
    fn the_right_word_restores_the_administrator_mode_and_records_it() {
        let mut service = service();
        let (store, _guard) = station_store();
        let Ok(()) = service.switch_to_operator_mode_in(&store, "parola-nota", &operator(), now())
        else {
            panic!("il passaggio deve riuscire");
        };

        let Ok(()) =
            service.switch_to_administrator_mode_in(&store, "parola-nota", &operator(), now())
        else {
            panic!("la parola giusta deve riportare amministratore");
        };

        assert_eq!(service.mode(), OperatingMode::Administrator);
        assert_eq!(
            crate::station::load_mode(&store).ok(),
            Some(OperatingMode::Administrator)
        );
        assert!(audit_actions(&service).contains(&String::from("modalita_amministratore_ripresa")));
    }

    #[test]
    fn a_weak_word_does_not_switch_the_mode() {
        let mut service = service();
        let (store, _guard) = station_store();

        assert!(matches!(
            service.switch_to_operator_mode_in(&store, "ab", &operator(), now()),
            Err(ServiceError::WeakUnlockWord)
        ));
        assert_eq!(
            service.mode(),
            OperatingMode::Administrator,
            "la modalita' in memoria non deve cambiare se la scrittura non e' avvenuta"
        );
        assert!(!store.exists(), "nulla deve essere stato scritto");
    }

    // -------------------------------------------------------------- creazione

    #[test]
    fn a_new_dictionary_comes_with_its_own_draft_to_write_in() {
        // Senza, l'operatore avrebbe un contenitore su cui non puo' scrivere e
        // dovrebbe scoprire da se' che gli manca un passo.
        let service = service();
        let Ok((dictionary, version)) = service.create(&proposal("Incendi"), &operator(), now())
        else {
            panic!("il dizionario deve potersi creare");
        };

        let Ok(entries) = service.library() else {
            panic!("la libreria deve potersi leggere");
        };
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].dictionary.id, dictionary);
        assert_eq!(entries[0].dictionary.status, DictionaryStatus::Draft);
        assert_eq!(entries[0].dictionary.origin, DictionaryOrigin::Operator);
        assert!(entries[0].has_open_draft);
        assert!(!entries[0].is_usable());

        assert_eq!(service.terms(version).map(|all| all.len()).ok(), Some(0));
        assert_eq!(audit_actions(&service), ["dizionario_creato"]);
    }

    #[test]
    fn a_dictionary_of_the_system_cannot_be_created_from_here() {
        let service = service();
        let mut request = proposal("Finto di sistema");
        request.visibility = DictionaryVisibility::BuiltIn;

        assert!(matches!(
            service.create(&request, &operator(), now()),
            Err(ServiceError::BuiltInDictionaryIsReadOnly)
        ));
    }

    #[test]
    fn a_repeated_name_is_reported_in_terms_the_operator_understands() {
        let service = service();
        let Ok(_) = service.create(&proposal("Incendi"), &operator(), now()) else {
            panic!("la prima creazione deve riuscire");
        };

        let Err(error) = service.create(&proposal("Incendi"), &operator(), now()) else {
            panic!("la seconda creazione doveva essere rifiutata");
        };
        assert!(matches!(error, ServiceError::DictionaryNameAlreadyUsed));
        assert!(error.operator_message().contains("nome"));
    }

    // ---------------------------------------------------------- pubblicazione

    #[test]
    fn an_empty_version_is_not_published() {
        // Comparirebbe fra i dizionari selezionabili senza contribuire nulla.
        let service = service();
        let Ok((_, version)) = service.create(&proposal("Vuoto"), &operator(), now()) else {
            panic!("il dizionario deve potersi creare");
        };

        assert!(matches!(
            service.publish(version, &operator(), now()),
            Err(ServiceError::EmptyDictionaryVersion)
        ));
    }

    #[test]
    fn publishing_makes_the_dictionary_usable() {
        let mut service = service();
        let (dictionary, _) = published(&mut service, "Incendi", &[("incendio", 2)]);

        let Ok(usable) = service.usable() else {
            panic!("l'elenco deve potersi leggere");
        };
        assert_eq!(usable.len(), 1);
        assert_eq!(usable[0].id, dictionary);
        assert_eq!(usable[0].status, DictionaryStatus::Active);

        let Ok(entries) = service.library() else {
            panic!("la libreria deve potersi leggere");
        };
        assert_eq!(entries[0].published_terms, 1);
        assert!(entries[0].is_usable());
        assert_eq!(entries[0].unusable_reason(), None);
    }

    #[test]
    fn publishing_a_version_does_not_bring_an_archived_dictionary_back_into_use() {
        // Sarebbe una decisione presa al posto dell'operatore, che lo aveva
        // tolto dall'uso di proposito.
        let mut service = service();
        let (dictionary, _) = published(&mut service, "Incendi", &[("incendio", 2)]);
        let Ok(()) = service.set_status(dictionary, DictionaryStatus::Archived, &operator(), now())
        else {
            panic!("l'archiviazione deve riuscire");
        };

        let Ok(draft) =
            service.start_new_version(dictionary, &description("v2"), &operator(), now())
        else {
            panic!("la nuova versione deve potersi aprire");
        };
        let Ok(()) = service.publish(draft, &operator(), now()) else {
            panic!("la pubblicazione deve riuscire");
        };

        assert_eq!(
            service
                .database()
                .dictionary(dictionary)
                .map(|entry| entry.status)
                .ok(),
            Some(DictionaryStatus::Archived)
        );
        assert_eq!(service.usable().map(|all| all.len()).ok(), Some(0));
    }

    #[test]
    fn a_published_version_can_no_longer_receive_terms() {
        let mut service = service();
        let (_, version) = published(&mut service, "Incendi", &[("incendio", 2)]);

        let Err(error) =
            service.add_terms(version, &[term(version, "molotov", 3)], &operator(), now())
        else {
            panic!("l'aggiunta doveva essere rifiutata");
        };
        assert!(matches!(error, ServiceError::PublishedVersionIsImmutable));
        assert!(error.operator_message().contains("Nuova versione"));
    }

    // ------------------------------------------------------- nuova versione

    #[test]
    fn a_new_version_starts_from_the_terms_of_the_published_one() {
        // Altrimenti correggere una parola su tremila significherebbe
        // riscriverne tremila, e nessuno lo farebbe.
        let mut service = service();
        let (dictionary, published_version) =
            published(&mut service, "Incendi", &[("incendio", 2), ("molotov", 4)]);

        let Ok(draft) =
            service.start_new_version(dictionary, &description("correzioni"), &operator(), now())
        else {
            panic!("la nuova versione deve potersi aprire");
        };

        let (Ok(original), Ok(copied)) = (service.terms(published_version), service.terms(draft))
        else {
            panic!("i termini devono potersi leggere");
        };
        let original: Vec<&str> = original.iter().map(|entry| entry.text.as_str()).collect();
        let copied: Vec<&str> = copied.iter().map(|entry| entry.text.as_str()).collect();
        assert_eq!(original, copied);
        assert_ne!(draft, published_version);
    }

    #[test]
    fn asking_twice_for_a_new_version_returns_the_draft_already_open() {
        // Due bozze aperte sullo stesso dizionario obbligherebbero l'operatore
        // a chiedersi su quale delle due sta lavorando.
        let mut service = service();
        let (dictionary, _) = published(&mut service, "Incendi", &[("incendio", 2)]);

        let (Ok(first), Ok(second)) = (
            service.start_new_version(dictionary, &description("una"), &operator(), now()),
            service.start_new_version(dictionary, &description("due"), &operator(), now()),
        ) else {
            panic!("l'apertura deve riuscire");
        };
        assert_eq!(first, second);
    }

    #[test]
    fn a_dictionary_without_a_published_version_has_nothing_to_start_from() {
        let mut service = service();
        let Ok((dictionary, _)) = service.create(&proposal("Bozza"), &operator(), now()) else {
            panic!("il dizionario deve potersi creare");
        };
        // La bozza iniziale viene restituita cosi' com'e'.
        let Ok(_) = service.start_new_version(dictionary, &description("x"), &operator(), now())
        else {
            panic!("la bozza aperta deve essere restituita");
        };

        // Con la bozza chiusa e nessuna pubblicazione non c'e' da dove partire.
        let Ok(versions) = service.database().dictionary_versions(dictionary) else {
            panic!("le versioni devono potersi leggere");
        };
        let Ok(()) = service.database().delete_draft_version(versions[0].id) else {
            panic!("la bozza deve potersi cancellare");
        };

        assert!(matches!(
            service.start_new_version(dictionary, &description("x"), &operator(), now()),
            Err(ServiceError::DictionaryHasNoPublishedVersion)
        ));
    }

    // ------------------------------------------------------------ duplicazione

    #[test]
    fn a_system_dictionary_is_used_by_duplicating_it() {
        let mut service = service();

        // Il dizionario di sistema entra dal seed, non dal servizio.
        let Ok(built_in) = service.database().insert_dictionary(
            &NewDictionary {
                name: name("Globale"),
                description: description("fornito con il prodotto"),
                scope: DictionaryScope::Global,
                origin: DictionaryOrigin::System,
                visibility: DictionaryVisibility::BuiltIn,
                created_by: actor("sistema"),
                derived_from: None,
            },
            now(),
        ) else {
            panic!("il dizionario di sistema deve potersi registrare");
        };
        let Ok(version) = service.database().insert_dictionary_version(
            &lisi_core::model::dictionary::NewDictionaryVersion {
                dictionary_id: built_in,
                number: 1,
                note: description("seed"),
                created_by: actor("sistema"),
            },
            now(),
        ) else {
            panic!("la versione deve potersi registrare");
        };
        let Ok(_) = service.add_terms(
            version,
            &[term(version, "incendio", 2)],
            &actor("sistema"),
            now(),
        ) else {
            panic!("i termini devono potersi aggiungere");
        };
        let Ok(()) = service.publish(version, &actor("sistema"), now()) else {
            panic!("la pubblicazione deve riuscire");
        };

        // Modificarlo non si puo'; duplicarlo si'.
        assert!(matches!(
            service.start_new_version(built_in, &description("x"), &operator(), now()),
            Err(ServiceError::BuiltInDictionaryIsReadOnly)
        ));

        let Ok((copy, copy_version)) =
            service.duplicate(built_in, &name("Globale mio"), &operator(), now())
        else {
            panic!("la duplicazione deve riuscire");
        };

        let Ok(duplicated) = service.database().dictionary(copy) else {
            panic!("la copia deve potersi rileggere");
        };
        assert_eq!(duplicated.visibility, DictionaryVisibility::Personal);
        assert_eq!(duplicated.status, DictionaryStatus::Draft);
        assert_eq!(duplicated.derived_from, Some(built_in));
        assert_eq!(
            service.terms(copy_version).map(|all| all.len()).ok(),
            Some(1)
        );
    }

    #[test]
    fn a_dictionary_with_nothing_published_cannot_be_duplicated() {
        let mut service = service();
        let Ok((dictionary, _)) = service.create(&proposal("Bozza"), &operator(), now()) else {
            panic!("il dizionario deve potersi creare");
        };

        assert!(matches!(
            service.duplicate(dictionary, &name("Copia"), &operator(), now()),
            Err(ServiceError::DictionaryHasNoPublishedVersion)
        ));
    }

    // ---------------------------------------------------------------- rimozione

    #[test]
    fn an_untouched_draft_is_really_removed() {
        let service = service();
        let Ok((dictionary, _)) = service.create(&proposal("Sbagliato"), &operator(), now()) else {
            panic!("il dizionario deve potersi creare");
        };

        assert_eq!(
            service.remove(dictionary, &operator(), now()).ok(),
            Some(DictionaryRemoval::Deleted)
        );
        assert_eq!(service.library().map(|all| all.len()).ok(), Some(0));
    }

    #[test]
    fn a_published_dictionary_is_archived_instead_of_removed() {
        // L'operatore ottiene cio' che voleva - non vederlo piu' fra i
        // dizionari proposti - e il messaggio spiega che cosa e' successo.
        let mut service = service();
        let (dictionary, _) = published(&mut service, "Incendi", &[("incendio", 2)]);

        let Ok(outcome) = service.remove(dictionary, &operator(), now()) else {
            panic!("la rimozione deve riuscire");
        };
        assert_eq!(outcome, DictionaryRemoval::Archived);
        assert!(outcome.operator_message().contains("archiviato"));

        assert_eq!(service.usable().map(|all| all.len()).ok(), Some(0));
        assert!(
            service.database().dictionary(dictionary).is_ok(),
            "resta leggibile"
        );
        assert!(audit_actions(&service).contains(&String::from("dizionario_archiviato")));
    }

    // ---------------------------------------------------------- risoluzione

    #[test]
    fn an_empty_selection_does_not_produce_a_configuration() {
        let service = service();
        let Err(error) = service.resolve(&DictionarySelection::new()) else {
            panic!("la selezione vuota doveva essere rifiutata");
        };
        assert!(matches!(error, ServiceError::EmptyDictionarySelection));
        assert!(error.operator_message().contains("senza poterne segnalare"));
    }

    #[test]
    fn the_same_term_from_two_dictionaries_keeps_both_provenances() {
        let mut service = service();
        let (first, _) = published(&mut service, "Uno", &[("incendio", 2)]);
        let (second, _) = published(&mut service, "Due", &[("incendio", 4), ("molotov", 3)]);

        let selection = DictionarySelection {
            dictionary_ids: vec![first, second],
            ad_hoc_terms: Vec::new(),
        };
        let Ok(configuration) = service.resolve(&selection) else {
            panic!("la risoluzione deve riuscire");
        };

        assert_eq!(configuration.unique_count, 2);
        assert_eq!(configuration.shared_count, 1);

        let Some(shared) = configuration
            .terms
            .iter()
            .find(|entry| entry.normalised == "incendio")
        else {
            panic!("il termine condiviso deve essere presente");
        };
        assert_eq!(shared.provenances.len(), 2);
        assert_eq!(shared.suggested_level, 4, "prevale il livello piu' alto");
        assert!(
            shared
                .provenances
                .iter()
                .any(|entry| entry.label.contains("Uno"))
        );
        assert!(
            shared
                .provenances
                .iter()
                .any(|entry| entry.label.contains("Due"))
        );
    }

    /// Una parola aggiunta dichiara la propria provenienza **e** porta il
    /// livello che chi l'ha aggiunta le ha dato.
    ///
    /// Fino al 2026-07-31 questo test si chiamava `…_carries_no_level` e
    /// fissava un livello 0: la regola era «chi scrive una parola dice che
    /// cosa cercare, non quanto sia grave». Ragionevole in astratto, ma zero è
    /// «non rilevante», il solo livello che non produce un avviso e quindi
    /// nemmeno una notifica — mentre il wizard invitava a scegliere «un
    /// dizionario **oppure** una parola». Chi seguiva la seconda strada
    /// otteneva un monitoraggio incapace di segnalare, e il test lo
    /// **certificava** invece di rivelarlo (rilevato in campo nel pilot del
    /// 2026-07-31, non da questa suite).
    #[test]
    fn an_added_word_declares_its_own_provenance_and_carries_its_declared_level() {
        let service = service();
        let (Ok(text), Ok(other)) = (
            TermText::try_new("parola"),
            TermText::try_new("frase intera"),
        ) else {
            panic!("i termini di prova devono essere validi");
        };

        let Ok(grave) = SuggestedLevel::try_new(3) else {
            panic!("il livello di prova deve essere valido");
        };
        let selection = DictionarySelection {
            dictionary_ids: Vec::new(),
            ad_hoc_terms: vec![
                // Senza dichiarare nulla: il minimo che produce comunque un
                // avviso, mai zero.
                SessionCustomTerm::normalised(text),
                // Con una gravità dichiarata: va rispettata, non appiattita.
                SessionCustomTerm {
                    text: other,
                    match_mode: MatchMode::Phrase,
                    suggested_level: grave,
                },
            ],
        };
        let Ok(configuration) = service.resolve(&selection) else {
            panic!("la risoluzione deve riuscire");
        };

        assert_eq!(configuration.unique_count, 2);
        for entry in &configuration.terms {
            // La provenienza resta quella di una parola aggiunta, non di un
            // dizionario: è ciò che permette di spiegare all'operatore perché
            // un contenuto è stato segnalato.
            assert_eq!(entry.provenances.len(), 1);
            assert_eq!(entry.provenances[0].dictionary_id, None);
            // E nessuna parola aggiunta finisce a un livello che non può
            // produrre un avviso: è il difetto che questa modifica toglie.
            assert!(
                entry.suggested_level >= SuggestedLevel::weakest_that_alerts().get(),
                "una parola sorvegliata non deve restare sotto la soglia d'avviso: {}",
                entry.suggested_level
            );
        }

        let Some(declared) = configuration
            .terms
            .iter()
            .find(|entry| entry.match_mode == MatchMode::Phrase)
        else {
            panic!("la frase aggiunta deve comparire fra i termini risolti");
        };
        assert_eq!(
            declared.suggested_level,
            grave.get(),
            "la gravità dichiarata da chi aggiunge la parola deve arrivare intatta"
        );
    }

    #[test]
    fn an_archived_dictionary_is_refused_by_name() {
        let mut service = service();
        let (dictionary, _) = published(&mut service, "Archiviato", &[("incendio", 2)]);
        let Ok(()) = service.set_status(dictionary, DictionaryStatus::Archived, &operator(), now())
        else {
            panic!("l'archiviazione deve riuscire");
        };

        let selection = DictionarySelection {
            dictionary_ids: vec![dictionary],
            ad_hoc_terms: Vec::new(),
        };
        let Err(error) = service.resolve(&selection) else {
            panic!("il dizionario archiviato doveva essere rifiutato");
        };
        assert!(matches!(
            error,
            ServiceError::DictionaryNotSelectable { ref name } if name == "Archiviato"
        ));
        assert!(error.operator_message().contains("Archiviato"));
    }

    #[test]
    fn a_dictionary_without_a_published_version_is_refused() {
        let service = service();
        let Ok((dictionary, _)) = service.create(&proposal("Bozza"), &operator(), now()) else {
            panic!("il dizionario deve potersi creare");
        };
        let Ok(()) = service.set_status(dictionary, DictionaryStatus::Active, &operator(), now())
        else {
            panic!("lo stato deve potersi cambiare");
        };

        let selection = DictionarySelection {
            dictionary_ids: vec![dictionary],
            ad_hoc_terms: Vec::new(),
        };
        assert!(matches!(
            service.resolve(&selection),
            Err(ServiceError::DictionaryNotSelectable { .. })
        ));
    }

    // ------------------------------------------------------- codici numerici

    /// **Un codice numerico entra in una bozza soltanto come codice e con il
    /// livello 1, arriva nella fotografia della sessione, e da solo non alza il
    /// livello** (DICT-CODES-01, ADR-0170, criteri 3 e 5; prova negativa: il
    /// controllo tolto dalla bozza → rossa).
    #[test]
    fn un_codice_numerico_dalla_bozza_alla_sessione() {
        let mut service = service();
        let Ok((dictionary, version)) = service.create(&proposal("Codici"), &operator(), now())
        else {
            panic!("il dizionario deve potersi creare");
        };
        let codice = |testo: &str, livello: i8| {
            let Ok(livello) = SuggestedLevel::try_new(livello) else {
                panic!("il livello di prova deve essere valido");
            };
            NewDictionaryTerm {
                match_mode: MatchMode::NumericCode,
                suggested_level: livello,
                ..term(version, testo, 1)
            }
        };

        for rifiutato in [term(version, "88", 2), codice("88", 2), codice("8", 1)] {
            assert!(
                matches!(
                    service.add_terms(version, &[rifiutato], &operator(), now()),
                    Err(ServiceError::Domain(DomainError::InvalidNumericCode { .. }))
                ),
                "un termine di sole cifre è un codice con il livello 1, o non entra"
            );
        }
        let Ok(2) = service.add_terms(
            version,
            &[codice("88", 1), term(version, "appiccare", 2)],
            &operator(),
            now(),
        ) else {
            panic!("il codice e la parola devono entrare");
        };
        let Ok(()) = service.publish(version, &operator(), now()) else {
            panic!("la pubblicazione deve riuscire");
        };

        let mut database = service.database;
        let session = session_in(&mut database);
        let mut service = DictionaryService::new(database);
        let selection = DictionarySelection {
            dictionary_ids: vec![dictionary],
            ad_hoc_terms: vec![],
        };
        let Ok(applied) = service.apply_to_session(session, &selection, &operator(), now()) else {
            panic!("la configurazione deve potersi fissare");
        };
        let Ok(Some(fotografia)) = service.database().session_resolved_configuration(session)
        else {
            panic!("la fotografia deve rileggersi");
        };
        assert_eq!(fotografia.digest, applied.digest);
        assert!(
            fotografia
                .terms
                .iter()
                .any(|termine| termine.match_mode == MatchMode::NumericCode),
            "il modo del codice arriva nella fotografia"
        );

        let da_solo = lisi_core::analysis::analyse("scritto 88 sul muro", &fotografia);
        assert_eq!(da_solo.outcome.level.get(), 0);
        assert_eq!(da_solo.occurrences.len(), 1, "il riscontro si vede");
        let insieme = lisi_core::analysis::analyse("88: appiccare stanotte", &fotografia);
        assert_eq!(insieme.outcome.level.get(), 2);
        assert!(insieme.outcome.rationale.held_codes.is_empty());
        let prezzo = lisi_core::analysis::analyse("appiccare costa 1,88", &fotografia);
        assert_eq!(prezzo.occurrences.len(), 1, "il prezzo non è il codice");
    }

    // ----------------------------------------------------------- fotografia

    #[test]
    fn fixing_the_configuration_writes_the_choice_the_words_and_the_snapshot() {
        let mut service = service();
        let (dictionary, version) = published(&mut service, "Incendi", &[("incendio", 2)]);
        let Ok(text) = TermText::try_new("parola aggiunta") else {
            panic!("il termine di prova deve essere valido");
        };

        let mut database = service.database;
        let session = session_in(&mut database);
        let mut service = DictionaryService::new(database);

        let selection = DictionarySelection {
            dictionary_ids: vec![dictionary],
            ad_hoc_terms: vec![SessionCustomTerm::normalised(text)],
        };
        let Ok(expected) = service.resolve(&selection) else {
            panic!("la risoluzione deve riuscire");
        };
        let Ok(applied) = service.apply_to_session(session, &selection, &operator(), now()) else {
            panic!("la configurazione deve potersi fissare");
        };

        assert_eq!(applied.digest, expected.digest);
        assert_eq!(
            service
                .database()
                .session_dictionary_selection(session)
                .ok(),
            Some(vec![(dictionary, version)])
        );
        assert_eq!(
            service
                .database()
                .session_custom_terms(session)
                .map(|all| all.len())
                .ok(),
            Some(1)
        );
        assert_eq!(
            service
                .configuration_of(session)
                .ok()
                .flatten()
                .map(|read| read.digest),
            Some(applied.digest.clone())
        );

        // L'impronta abbreviata entra nell'audit: e' cio' che permette di dire,
        // mesi dopo, che la configurazione era quella e non un'altra.
        let Ok(entries) = service.database().audit_entries() else {
            panic!("l'audit deve potersi leggere");
        };
        let Some(fixed) = entries
            .iter()
            .find(|entry| entry.action.as_str() == "configurazione_fissata")
        else {
            panic!("la voce di audit deve essere presente");
        };
        let Some(detail) = fixed.detail.as_ref() else {
            panic!("la voce deve avere un dettaglio");
        };
        assert!(detail.as_str().contains(&applied.digest.short()));
    }

    #[test]
    fn a_session_keeps_its_terms_even_when_the_dictionary_moves_on() {
        // E' la proprieta' per cui esiste la fotografia: se la sessione
        // guardasse i dizionari, una correzione fatta mentre e' in corso ne
        // cambierebbe i termini a sua insaputa.
        let mut service = service();
        let (dictionary, _) = published(&mut service, "Incendi", &[("incendio", 2)]);

        let mut database = service.database;
        let session = session_in(&mut database);
        let mut service = DictionaryService::new(database);

        let selection = DictionarySelection {
            dictionary_ids: vec![dictionary],
            ad_hoc_terms: Vec::new(),
        };
        let Ok(fixed) = service.apply_to_session(session, &selection, &operator(), now()) else {
            panic!("la configurazione deve potersi fissare");
        };
        assert_eq!(fixed.unique_count, 1);

        // Il dizionario prosegue: nuova versione con un termine in piu'.
        let Ok(draft) =
            service.start_new_version(dictionary, &description("v2"), &operator(), now())
        else {
            panic!("la nuova versione deve potersi aprire");
        };
        let Ok(_) = service.add_terms(draft, &[term(draft, "molotov", 4)], &operator(), now())
        else {
            panic!("il termine deve potersi aggiungere");
        };
        let Ok(()) = service.publish(draft, &operator(), now()) else {
            panic!("la pubblicazione deve riuscire");
        };

        // Una nuova risoluzione vede due termini; la sessione ne conserva uno.
        let Ok(now_resolved) = service.resolve(&selection) else {
            panic!("la risoluzione deve riuscire");
        };
        assert_eq!(now_resolved.unique_count, 2);

        let Ok(Some(stored)) = service.configuration_of(session) else {
            panic!("la fotografia deve potersi rileggere");
        };
        assert_eq!(stored.unique_count, 1);
        assert_eq!(stored.digest, fixed.digest);
        assert_ne!(stored.digest, now_resolved.digest);
    }

    #[test]
    fn the_configuration_of_a_session_is_fixed_only_once() {
        let mut service = service();
        let (dictionary, _) = published(&mut service, "Incendi", &[("incendio", 2)]);

        let mut database = service.database;
        let session = session_in(&mut database);
        let mut service = DictionaryService::new(database);

        let selection = DictionarySelection {
            dictionary_ids: vec![dictionary],
            ad_hoc_terms: Vec::new(),
        };
        let Ok(_) = service.apply_to_session(session, &selection, &operator(), now()) else {
            panic!("la prima applicazione deve riuscire");
        };

        // L'errore va nominato: `is_err()` passerebbe anche se il secondo
        // tentativo fallisse per una ragione del tutto diversa e sbagliata.
        assert!(matches!(
            service.apply_to_session(session, &selection, &operator(), now()),
            Err(ServiceError::Storage(
                lisi_storage::StorageError::SessionConfigurationAlreadyResolved
            ))
        ));
    }

    #[test]
    fn a_session_that_has_not_been_configured_yet_reports_none() {
        // Sessione che esiste ma non e' ancora stata configurata: e' il caso
        // ordinario, distinto da quello della sessione inesistente.
        let service = service();
        let mut database = service.database;
        let session = session_in(&mut database);
        let service = DictionaryService::new(database);

        assert!(matches!(service.configuration_of(session), Ok(None)));
    }

    #[test]
    fn the_configuration_of_a_missing_session_is_an_error() {
        let service = service();
        assert!(matches!(
            service.configuration_of(SessionId::new(404)),
            Err(ServiceError::Storage(_))
        ));
    }

    #[test]
    fn a_selection_at_the_limit_is_accepted_and_one_beyond_it_is_not() {
        // Un limite provato solo oltre non dimostra che al limite si passi.
        let service = service();
        let at_limit: Vec<DictionaryId> = (1..=MAX_DICTIONARIES_PER_SESSION)
            .map(|index| DictionaryId::new(index as i64))
            .collect();
        let mut beyond = at_limit.clone();
        beyond.push(DictionaryId::new(0));

        // Al limite il conteggio passa: ci si ferma sul primo dizionario
        // inesistente, non sul limite.
        assert!(matches!(
            service.resolve(&DictionarySelection {
                dictionary_ids: at_limit,
                ad_hoc_terms: Vec::new(),
            }),
            Err(ServiceError::Storage(
                lisi_storage::StorageError::NotFound { .. }
            ))
        ));

        assert!(matches!(
            service.resolve(&DictionarySelection {
                dictionary_ids: beyond,
                ad_hoc_terms: Vec::new(),
            }),
            Err(ServiceError::Storage(
                lisi_storage::StorageError::LimitExceeded {
                    limit: "dizionari_per_sessione",
                    ..
                }
            ))
        ));
    }
}
