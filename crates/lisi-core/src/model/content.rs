//! Contenuti acquisiti.
//!
//! Ogni contenuto effettivamente acquisito e analizzato viene registrato, anche
//! quando l'analisi lo giudica non rilevante. Lo storico documenta ciò che è
//! stato osservato, non soltanto ciò che ha prodotto un allarme.

use crate::digest::Sha256Digest;
use crate::id::{ContentId, SessionId, SourceId};
use crate::model::analysis::AnalysisLevel;
use crate::text::{Actor, ContentBody, ContentUrl, RemoteMessageId};
use crate::time::Timestamp;

string_enum!(
    /// Come il contenuto è entrato nell'archivio.
    ///
    /// # Perché non bastano i due istanti
    ///
    /// `published_at` e `acquired_at` sono già due colonne diverse, e la
    /// distanza fra loro **suggerisce** che un contenuto sia stato recuperato
    /// invece che osservato. Suggerire non basta: chi rilegge dovrebbe dedurlo
    /// da una differenza di orari, e una deduzione è ciò che un archivio con
    /// valore probatorio non deve chiedere a chi lo consulta. Un monitoraggio
    /// ripreso dopo pochi secondi produrrebbe una distanza minima e sembrerebbe
    /// osservazione dal vivo.
    ///
    /// La distinzione è dichiarata, non inferita.
    AcquisitionOrigin {
        /// Il contenuto è stato **visto arrivare** mentre il monitoraggio era
        /// in corso.
        Observed => "osservato",
        /// Il contenuto è stato **ritrovato dopo**, leggendo la cronologia già
        /// pubblicata.
        ///
        /// L'applicazione non c'era quando è comparso: lo attesta come
        /// pubblicato, non come sorvegliato.
        Recovered => "recuperato",
    }
);

impl AcquisitionOrigin {
    // NESSUNA FRASE PER L'OPERATORE (PR-07, ADR-0123).
    //
    // Fino a PR-07 il percorso aveva una sua frase, e per «osservato» era «dal
    // vivo»: la si scriveva nei rapporti anche dove nessuno ascoltava. Ciò che
    // l'operatore legge è il **modo** ([`AcquisitionMode`]), ricavato dai fatti;
    // il percorso resta un dato tecnico, e senza frase non si può più mostrare
    // al suo posto.

    /// Se il contenuto è stato visto arrivare mentre accadeva.
    #[must_use]
    pub const fn was_witnessed(self) -> bool {
        matches!(self, Self::Observed)
    }
}

// NESSUN VALORE PREDEFINITO (PR-07, ADR-0123).
//
// Fino a PR-07 il valore predefinito era «osservato», dichiarato prudente. Non
// lo era: è la cosa più forte che si possa affermare di un contenuto, e un
// valore che si ottiene senza sceglierlo è un'affermazione che nessuno ha
// fatto. Ciò che la colonna registra è il PERCORSO da cui la riga è entrata; il
// modo che si dichiara è `AcquisitionMode`, e si ricava dai fatti.

/// Il **modo di acquisizione** che lo schermo e i documenti dichiarano (PR-07,
/// ADR-0123).
///
/// # Il percorso e il modo sono due cose
///
/// [`AcquisitionOrigin`] è il **percorso** registrato: la riga è entrata
/// dall'acquisizione dal vivo o dal recupero. Il **modo** si ricava dai fatti,
/// con il criterio «Modo di acquisizione» di `lisi_services::acquisition_mode`:
/// «dal vivo» soltanto dove un fatto registrato dimostra che si ascoltava
/// quando il messaggio è comparso. Non si scrive: si deriva, e la colonna della
/// 0012 resta com'era.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AcquisitionMode {
    /// Un fatto registrato dimostra che l'applicazione ascoltava quando il
    /// messaggio è comparso.
    Live,
    /// Ritrovato dopo, leggendo la cronologia.
    Recovered {
        /// Quando è stato archiviato.
        at: Timestamp,
        /// L'intervallo del recupero, quando è registrato; `None` con
        /// `operator` presente vuol dire «dall'inizio del monitoraggio».
        interval: Option<(Timestamp, Timestamp)>,
        /// Chi lo ha chiesto, quando è registrato.
        operator: Option<String>,
    },
    /// Il modo non è dimostrabile: l'archivio non lo ha registrato.
    Undetermined,
}

/// Che cosa il recupero non vede. Accompagna ogni contenuto recuperato, sullo
/// schermo e nei documenti.
pub const RECOVERY_LIMITS: &str = "Un messaggio recuperato è stato letto nella cronologia dopo la \
                                   pubblicazione. Non si vedono le modifiche intermedie, le \
                                   cancellazioni avvenute prima del recupero, le reazioni e gli \
                                   altri dati che cambiano.";

/// Gli istanti di un contenuto, **ciascuno con il suo nome** (E2E01-03).
///
/// Sono quattro fatti diversi e un atto non deve confonderli: la relazione del
/// collaudo scriveva «In data \<pubblicazione\> veniva acquisito», e per un
/// messaggio recuperato una settimana dopo era un'affermazione falsa sul
/// momento dell'acquisizione.
///
/// - **pubblicazione**: l'istante dichiarato dalla fonte, non verificato;
/// - **recupero**: per un contenuto ritrovato nella cronologia, quando è stato
///   letto — coincide con l'acquisizione, ed è detto;
/// - **acquisizione**: quando NEXUM lo ha registrato nell'archivio;
/// - **analisi**: si esegue all'acquisizione, con la configurazione fotografata
///   del monitoraggio.
///
/// L'istante della **redazione** riguarda il documento, non il contenuto: lo
/// porta l'intestazione del documento.
#[must_use]
pub fn dates_sentence(published_at: Timestamp, acquired_at: Timestamp, recovered: bool) -> String {
    let pubblicato = published_at.to_readable_utc();
    let acquisito = acquired_at.to_readable_utc();
    let ingresso = if recovered {
        format!(
            "recuperato dalla cronologia e acquisito nell'archivio il {acquisito}, dopo la \
             pubblicazione"
        )
    } else {
        format!("acquisito nell'archivio il {acquisito}")
    };
    format!(
        "pubblicato dalla fonte il {pubblicato} (istante dichiarato dalla fonte, non \
         verificato); {ingresso}; analizzato all'acquisizione, il {acquisito}."
    )
}

impl AcquisitionMode {
    /// La frase che lo dichiara.
    #[must_use]
    pub fn as_sentence(&self) -> String {
        match self {
            Self::Live => String::from("Acquisito dal vivo."),
            Self::Recovered {
                at,
                interval,
                operator,
            } => match (interval, operator) {
                (Some((da, a)), Some(chi)) => format!(
                    "Recuperato il {}, per l'intervallo dal {} al {}, da {chi}.",
                    at.to_readable_utc(),
                    da.to_readable_utc(),
                    a.to_readable_utc()
                ),
                (None, Some(chi)) => format!(
                    "Recuperato il {}, dall'inizio del monitoraggio, da {chi}.",
                    at.to_readable_utc()
                ),
                _ => format!(
                    "Recuperato il {}: operatore e intervallo non registrati.",
                    at.to_readable_utc()
                ),
            },
            Self::Undetermined => String::from(
                "Modo di acquisizione non determinabile: l'archivio non lo ha registrato.",
            ),
        }
    }

    /// Se il contenuto è stato visto arrivare mentre accadeva, **dimostrato**.
    #[must_use]
    pub const fn is_live(&self) -> bool {
        matches!(self, Self::Live)
    }

    /// Se è stato ritrovato dopo.
    #[must_use]
    pub const fn is_recovered(&self) -> bool {
        matches!(self, Self::Recovered { .. })
    }
}

/// Contenuto che si intende registrare.
///
/// L'impronta del corpo e l'eventuale collegamento al contenuto duplicato non
/// sono campi di questo tipo: sono derivati, e li calcola la persistenza al
/// momento dell'inserimento. Se fossero campi, un chiamante potrebbe fornirne
/// uno incoerente con il corpo.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewContent {
    /// Sessione durante la quale il contenuto è stato acquisito.
    pub session_id: SessionId,
    /// Fonte da cui il contenuto proviene.
    pub source_id: SourceId,
    /// Identificativo del messaggio presso la fonte remota.
    pub remote_message_id: RemoteMessageId,
    /// Autore dichiarato, quando la fonte lo espone.
    ///
    /// È un **nome leggibile**, e i nomi cambiano: chi rilegge l'archivio fra
    /// un anno potrebbe trovarne uno che nel frattempo appartiene a qualcun
    /// altro. Per l'identità che regge nel tempo c'è
    /// [`Self::author_identifier`].
    pub author: Option<Actor>,
    /// Identificativo dell'autore presso la piattaforma, quando esiste.
    ///
    /// Non cambia finché l'account esiste, e per questo è ciò a cui si guarda
    /// per rispondere a «chi ha scritto questo». Non dice nulla a chi legge un
    /// rapporto: le due informazioni servono a due domande diverse e stanno in
    /// due campi diversi.
    ///
    /// È assente per i messaggi di **canale**, che portano come mittente il
    /// canale stesso: attribuirli a una persona sarebbe una falsa attribuzione
    /// in un archivio che ha valore probatorio.
    pub author_identifier: Option<String>,
    /// Username dell'autore, senza chiocciola, quando ne ha uno.
    ///
    /// **Non è un'identità, ed è il punto.** Uno username può essere rilasciato
    /// e preso da qualcun altro: fra un anno può indicare una persona diversa,
    /// il che lo rende meno affidabile perfino di un nome. Serve a **ritrovare**
    /// qualcuno su Telegram oggi, non ad attribuirgli un messaggio domani. Per
    /// quello c'è [`NewContent::author_identifier`], che è l'unico dei tre a
    /// reggere nel tempo.
    pub author_username: Option<String>,
    /// Corpo testuale, eventualmente vuoto per i messaggi di soli media.
    pub body: ContentBody,
    /// URL del messaggio presso la piattaforma, quando disponibile.
    pub url: Option<ContentUrl>,
    /// Istante di pubblicazione dichiarato dalla fonte.
    pub published_at: Timestamp,
    /// Istante di acquisizione da parte dell'applicazione.
    pub acquired_at: Timestamp,
    /// Se il contenuto è stato osservato dal vivo o recuperato dopo.
    ///
    /// Non si deduce dalla distanza fra i due istanti: si dichiara. Vedere
    /// [`AcquisitionOrigin`].
    pub origin: AcquisitionOrigin,
    /// Esito dell'analisi, da 0 a 4.
    pub analysis_level: AnalysisLevel,
}

impl NewContent {
    /// Impronta del corpo, usata per riconoscere contenuti identici.
    #[must_use]
    pub fn body_digest(&self) -> Sha256Digest {
        Sha256Digest::of_text(self.body.as_str())
    }
}

/// Contenuto registrato.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Content {
    /// Identificatore assegnato dalla persistenza.
    pub id: ContentId,
    /// Sessione durante la quale il contenuto è stato acquisito.
    pub session_id: SessionId,
    /// Fonte da cui il contenuto proviene.
    pub source_id: SourceId,
    /// Identificativo del messaggio presso la fonte remota.
    pub remote_message_id: RemoteMessageId,
    /// Autore dichiarato, quando la fonte lo espone.
    pub author: Option<Actor>,
    /// Identificativo dell'autore presso la piattaforma, quando esiste.
    ///
    /// Vale qui ciò che vale in [`NewContent::author_identifier`]: è l'identità
    /// che regge nel tempo, ed è assente per i messaggi di canale.
    pub author_identifier: Option<String>,
    /// Username dell'autore, quando ne ha uno.
    ///
    /// Vale qui ciò che vale in [`NewContent::author_username`]: serve a
    /// ritrovare, non ad attribuire.
    pub author_username: Option<String>,
    /// Corpo testuale, conservato immutato.
    pub body: ContentBody,
    /// URL del messaggio presso la piattaforma, quando disponibile.
    pub url: Option<ContentUrl>,
    /// Istante di pubblicazione dichiarato dalla fonte.
    pub published_at: Timestamp,
    /// Istante di acquisizione da parte dell'applicazione.
    pub acquired_at: Timestamp,
    /// Se il contenuto è stato osservato dal vivo o recuperato dopo.
    pub origin: AcquisitionOrigin,
    /// Esito dell'analisi, da 0 a 4.
    pub analysis_level: AnalysisLevel,
    /// Impronta del corpo.
    pub body_sha256: Sha256Digest,
    /// Prima occorrenza dello stesso corpo, quando ne esiste una in un'altra
    /// sessione.
    ///
    /// La duplicazione fra sessioni è annotata e non impedita: ogni sessione
    /// deve poter documentare per intero ciò che ha acquisito.
    pub duplicate_of_id: Option<ContentId>,
    /// Versione del motore che ha prodotto [`Self::analysis_level`].
    ///
    /// # Perché è facoltativa, e resterà facoltativa
    ///
    /// `None` significa **non registrato**: il contenuto fu analizzato prima
    /// che il motore avesse un numero, e quale formula lo abbia prodotto non
    /// risulta. Non è una lacuna da colmare — è un fatto della sua storia, e
    /// scrivergli accanto la versione corrente direbbe che qualcuno lo sa
    /// (ENGINE-01, migrazione 0024).
    pub engine_version: Option<u32>,
}

impl Content {
    /// Se il contenuto ripete un corpo già osservato in precedenza.
    #[must_use]
    pub const fn is_duplicate(&self) -> bool {
        self.duplicate_of_id.is_some()
    }
}

/// Esito dell'inserimento di un contenuto.
///
/// Il ritentativo di acquisizione dello stesso messaggio nella stessa sessione
/// è un evento normale, non un errore: il chiamante deve poterlo distinguere da
/// un'acquisizione nuova senza ispezionare messaggi di errore.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContentInsertion {
    /// Il contenuto è stato registrato ora.
    Recorded(ContentId),
    /// Il contenuto era già presente per quella sessione e quella fonte.
    AlreadyPresent(ContentId),
}

impl ContentInsertion {
    /// Identificatore del contenuto, in entrambi i casi.
    #[must_use]
    pub const fn content_id(self) -> ContentId {
        match self {
            Self::Recorded(id) | Self::AlreadyPresent(id) => id,
        }
    }

    /// Se l'inserimento ha prodotto una nuova riga.
    #[must_use]
    pub const fn is_new(self) -> bool {
        matches!(self, Self::Recorded(_))
    }
}

#[cfg(test)]
mod tests {
    use super::{AcquisitionOrigin, ContentInsertion, NewContent};
    use crate::digest::Sha256Digest;
    use crate::id::{ContentId, SessionId, SourceId};
    use crate::model::analysis::AnalysisLevel;
    use crate::text::{ContentBody, RemoteMessageId};
    use crate::time::Timestamp;

    fn sample(body: &str) -> NewContent {
        let (Ok(remote_message_id), Ok(body)) =
            (RemoteMessageId::try_new("1001"), ContentBody::try_new(body))
        else {
            panic!("i valori di prova devono essere validi");
        };

        NewContent {
            session_id: SessionId::new(1),
            source_id: SourceId::new(1),
            remote_message_id,
            author: None,
            author_identifier: None,
            author_username: None,
            body,
            url: None,
            published_at: Timestamp::from_millis(1_700_000_000_000),
            acquired_at: Timestamp::from_millis(1_700_000_001_000),
            origin: AcquisitionOrigin::Observed,
            analysis_level: AnalysisLevel::NOT_RELEVANT,
        }
    }

    #[test]
    fn the_digest_is_derived_from_the_body() {
        assert_eq!(
            sample("messaggio").body_digest(),
            Sha256Digest::of_text("messaggio")
        );
    }

    #[test]
    fn identical_bodies_produce_identical_digests() {
        assert_eq!(
            sample("uguale").body_digest(),
            sample("uguale").body_digest()
        );
    }

    #[test]
    fn different_bodies_produce_different_digests() {
        assert_ne!(sample("uno").body_digest(), sample("due").body_digest());
    }

    #[test]
    fn the_two_origins_say_different_things_and_only_one_claims_a_witness() {
        // È la distinzione per cui questo tipo esiste: «recuperato» non deve
        // poter essere letto come «osservato» da nessuna parte del prodotto.
        assert!(AcquisitionOrigin::Observed.was_witnessed());
        assert!(!AcquisitionOrigin::Recovered.was_witnessed());
        assert_ne!(
            AcquisitionOrigin::Observed.as_str(),
            AcquisitionOrigin::Recovered.as_str()
        );

        // La forma conservata è stabile: cambiarla renderebbe illeggibili le
        // righe già in archivio, che è il modo in cui un archivio perde ciò che
        // affermava.
        assert_eq!(AcquisitionOrigin::Observed.as_str(), "osservato");
        assert_eq!(AcquisitionOrigin::Recovered.as_str(), "recuperato");
    }

    #[test]
    fn a_recorded_insertion_is_new_and_carries_its_identifier() {
        let insertion = ContentInsertion::Recorded(ContentId::new(5));
        assert!(insertion.is_new());
        assert_eq!(insertion.content_id(), ContentId::new(5));
    }

    #[test]
    fn an_already_present_insertion_is_not_new_but_carries_the_existing_identifier() {
        let insertion = ContentInsertion::AlreadyPresent(ContentId::new(5));
        assert!(!insertion.is_new());
        assert_eq!(insertion.content_id(), ContentId::new(5));
    }
}
