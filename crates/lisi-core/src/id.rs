//! Identificatori tipizzati.
//!
//! Ogni entità ha il proprio tipo di identificatore. Il compilatore impedisce
//! così di passare l'identificatore di una fonte dove è atteso quello di una
//! sessione: un errore che con `i64` nudi sarebbe invisibile fino al momento in
//! cui produce un dato sbagliato in un report.

use core::fmt;

macro_rules! typed_id {
    ($(#[$meta:meta])* $name:ident, $label:literal) => {
        $(#[$meta])*
        #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
        pub struct $name(i64);

        impl $name {
            /// Costruisce l'identificatore a partire dal valore assegnato dal database.
            #[must_use]
            pub const fn new(value: i64) -> Self {
                Self(value)
            }

            /// Valore grezzo, per la persistenza.
            #[must_use]
            pub const fn get(self) -> i64 {
                self.0
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(formatter, "{}#{}", $label, self.0)
            }
        }
    };
}

typed_id!(
    /// Identificatore di una fonte monitorata.
    SourceId,
    "fonte"
);
typed_id!(
    /// Identificatore di una sessione di monitoraggio.
    SessionId,
    "sessione"
);
typed_id!(
    /// Identificatore di un contenuto acquisito.
    ContentId,
    "contenuto"
);
typed_id!(
    /// Identificatore di un match del dizionario.
    MatchId,
    "match"
);
typed_id!(
    /// Identificatore di un alert.
    AlertId,
    "alert"
);
typed_id!(
    /// Identificatore di una revisione umana.
    ReviewId,
    "revisione"
);
typed_id!(
    /// Identificatore di una fotografia del contesto (CTX-06).
    ContextSnapshotId,
    "fotografia del contesto"
);
typed_id!(
    /// Identificatore di un workspace operativo (WS-01).
    WorkspaceId,
    "workspace"
);
typed_id!(
    /// Identificatore di un segnalibro (BOOK-01).
    BookmarkId,
    "segnalibro"
);
typed_id!(
    /// Identificatore di una raccolta di segnalibri (BOOK-01).
    BookmarkCollectionId,
    "raccolta di segnalibri"
);
typed_id!(
    /// Identificatore di una nota dell'operatore (NOTE-01).
    NoteId,
    "nota"
);
typed_id!(
    /// Identificatore di una ricerca salvata (SEARCH-01).
    SavedSearchId,
    "ricerca salvata"
);
typed_id!(
    /// Identificatore di un modello di monitoraggio (TEMPLATE-01).
    MonitoringTemplateId,
    "modello di monitoraggio"
);
typed_id!(
    /// Identificatore di un soggetto investigativo (PERS-01).
    ///
    /// E' dell'archivio, non della piattaforma: una persona NON e' un account
    /// Telegram, e le identita' osservate arriveranno con PERS-02.
    PersonId,
    "soggetto"
);
typed_id!(
    /// Identificatore di un atto di valutazione di un soggetto (PERS-05).
    ///
    /// Ogni atto e' una riga propria: la valutazione corrente si ricava dalla
    /// storia, e la storia non si accorcia.
    AssessmentId,
    "valutazione"
);
typed_id!(
    /// Identificatore di un atto di associazione manuale fra un'identita'
    /// osservata e un soggetto (PERS-06).
    ///
    /// Ogni atto e' una riga propria: i legami correnti si ricavano dalla
    /// storia, e la storia non si accorcia. Sciogliere un legame non cancella
    /// che sia esistito.
    IdentityLinkId,
    "associazione di identita"
);
typed_id!(
    /// Identificatore di una ricerca puntuale registrata (PR-09).
    ///
    /// È un riferimento, non una misura: la base di un legame dice **da quale
    /// ricerca** nasce (PR-10), e un numero nudo accanto a un legame si
    /// leggerebbe come un punteggio.
    IdentityResolutionId,
    "ricerca puntuale"
);
typed_id!(
    /// Identificatore di un errore registrato.
    FaultId,
    "errore"
);
typed_id!(
    /// Identificatore di una voce di audit.
    AuditId,
    "audit"
);
typed_id!(
    /// Identificatore di un export prodotto.
    ExportId,
    "export"
);
typed_id!(
    /// Identificatore di un dizionario.
    DictionaryId,
    "dizionario"
);
typed_id!(
    /// Identificatore di una versione di dizionario.
    ///
    /// Una sessione riferisce **questa**, non il dizionario: il dizionario
    /// evolve, la versione no.
    DictionaryVersionId,
    "versione"
);
typed_id!(
    /// Identificatore di un termine.
    DictionaryTermId,
    "termine"
);
typed_id!(
    /// Identificatore di un profilo di selezione.
    DictionaryProfileId,
    "profilo"
);
typed_id!(
    /// Identificatore di una voce dell'inbox di acquisizione.
    InboxId,
    "inbox"
);
typed_id!(
    /// Identificatore di una versione di un contenuto.
    ContentVersionId,
    "versione"
);
typed_id!(
    /// Identificatore di una cancellazione osservata.
    ContentDeletionId,
    "cancellazione"
);
typed_id!(
    /// Identificatore di una notifica emessa.
    NotificationId,
    "notifica"
);
typed_id!(
    /// Identificatore di un profilo di credenziali API Telegram.
    ///
    /// Un profilo API (API id + hash dell'applicazione) puo' servire piu'
    /// account: vedere ADR-0019.
    ApiCredentialProfileId,
    "profilo_api"
);
typed_id!(
    /// Identificatore locale di un account Telegram d'ufficio.
    ///
    /// E' l'identificatore di riga; l'identita' stabile usata per le directory
    /// e le chiavi e' l'UUID dell'account, mai il numero (ADR-0019).
    TelegramAccountId,
    "account"
);
typed_id!(
    /// Identificatore di un pacchetto di report.
    ///
    /// E' l'identificatore **della riga**, assegnato dalla persistenza. Quello
    /// che compare **dentro i documenti** e' invece
    /// [`crate::model::report::ReportId`], che e' testuale e citabile: i due
    /// esistono per due mestieri diversi e non vanno confusi.
    ReportPackageId,
    "pacchetto"
);
typed_id!(
    /// Identificatore di un artefatto prodotto dentro un pacchetto.
    ReportArtifactId,
    "artefatto"
);
typed_id!(
    /// Identificatore di un'organizzazione sorvegliata.
    ///
    /// L'elenco delle organizzazioni non sta nel sorgente: lo dichiara un
    /// amministratore e vive nell'archivio della postazione
    /// (`docs/dictionaries/PD6_SECTOR_TAXONOMY.md`).
    WatchedOrganisationId,
    "organizzazione"
);
typed_id!(
    /// Identificatore di una fotografia CVE.
    ///
    /// E' l'identificatore della riga. L'identita' che una persona legge e' la
    /// COPERTURA - quali anni contiene - insieme all'istante in cui e' stata
    /// acquisita: due fotografie degli stessi anni acquisite in giorni diversi
    /// non contengono le stesse voci, perche' il catalogo cresce ogni giorno.
    CveSnapshotId,
    "fotografia_cve"
);
typed_id!(
    /// Identificatore di una fotografia del catalogo CISA KEV.
    ///
    /// E' l'identificatore della riga. L'identita' che una persona legge e' la
    /// VERSIONE del catalogo insieme all'istante in cui CISA lo ha rilasciato:
    /// il catalogo cambia piu' volte alla settimana, e due fotografie prese in
    /// giorni diversi non elencano le stesse vulnerabilita'.
    KevSnapshotId,
    "fotografia_kev"
);
typed_id!(
    /// Identificatore di un'associazione fra un termine e una tecnica ATT&CK.
    ///
    /// E' l'identificatore dell'ATTO, non del legame: un'associazione ritirata e
    /// una ridichiarata sono due atti distinti, con due motivi, e conservano
    /// identificatori diversi.
    AttackAssociationId,
    "associazione_attack"
);
typed_id!(
    /// Identificatore di una fotografia MITRE ATT&CK.
    ///
    /// E' l'identificatore **della riga**. L'identita' che una persona legge e'
    /// invece la coppia dominio e versione — `enterprise-attack 19.2` — che
    /// l'archivio tiene unica: due fotografie della stessa versione
    /// renderebbero ambiguo a quale delle due si riferisca un documento.
    AttackSnapshotId,
    "fotografia_attack"
);

#[cfg(test)]
mod tests {
    use super::{ContentId, SessionId, SourceId};

    #[test]
    fn identifiers_preserve_their_value() {
        assert_eq!(SourceId::new(42).get(), 42);
        assert_eq!(SessionId::new(-1).get(), -1);
    }

    #[test]
    fn identifiers_are_displayed_with_their_entity() {
        assert_eq!(SourceId::new(7).to_string(), "fonte#7");
        assert_eq!(ContentId::new(9).to_string(), "contenuto#9");
    }

    #[test]
    fn identifiers_of_different_entities_are_distinct_types() {
        // La verifica sostanziale è a tempo di compilazione: assegnare un
        // SourceId a un SessionId non compila. Qui si documenta l'intento.
        let source = SourceId::new(1);
        let session = SessionId::new(1);
        assert_eq!(source.get(), session.get());
        assert_ne!(source.to_string(), session.to_string());
    }
}
