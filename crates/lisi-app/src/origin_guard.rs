//! Chi dice ogni dato che l'interfaccia mostra (PR-03, ADR-0118).
//!
//! # Che cosa questa guardia verifica
//!
//! 1. **Ogni campo** di ogni struttura con cui il Rust passa dati allo schermo
//!    ha un'origine dichiarata in [`CAMPI`] — Osservato, Calcolato, Operatore —
//!    oppure è dichiarato come ciò che non è un dato: **Struttura** (ciò che
//!    serve a disegnare: identificativi, selezioni, coordinate) o
//!    **Interfaccia** (il testo del programma stesso: la guida, il glossario,
//!    i nomi dei controlli).
//! 2. **Nessun campo classificato è sparito**: un'origine dichiarata per un
//!    campo che non c'è più è una dichiarazione che nessuno rilegge.
//! 3. **I generi noti hanno l'origine del loro genere**: un livello è sempre
//!    calcolato, una revisione è sempre di una persona, un estratto è sempre
//!    osservato. Le eccezioni sono dichiarate, con la ragione.
//! 4. **Ogni elenco di dati ha la sua legenda** d'origine, e la legenda nomina
//!    **ogni** origine che la sua struttura contiene, e nessun'altra.
//! 5. **Il segno d'origine si legge senza colore**: porta la parola.
//!
//! # Che cosa questa guardia NON verifica
//!
//! Che la classificazione sia giusta campo per campo: la scrive chi ha scritto
//! il prodotto. La guardia ne garantisce la completezza e la coerenza con i
//! generi noti; la giustezza la verifica una persona (HVQ-86).

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, BTreeSet};

    use lisi_core::model::origin::Origin;

    /// L'interfaccia principale.
    const UI: &str = include_str!("../ui/app-window.slint");
    /// La libreria dei componenti.
    const COMPONENTI: &str = include_str!("../ui/components.slint");

    /// Che cosa è un campo.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum Classe {
        /// Un dato, con la sua origine.
        Dato(Origin),
        /// Un dato la cui origine cambia **da riga a riga**, e la dichiara il
        /// campo indicato: una cronologia mescola ciò che è stato pubblicato e
        /// ciò che una persona ha fatto, e ogni riga lo dice.
        PerRiga(&'static str),
        /// Serve a disegnare, non è un dato.
        Struttura,
        /// Il testo del programma stesso, non un dato sul mondo.
        Interfaccia,
    }

    use Classe::{Interfaccia, PerRiga, Struttura};
    const OSS: Classe = Classe::Dato(Origin::Observed);
    const CAL: Classe = Classe::Dato(Origin::Computed);
    const OPE: Classe = Classe::Dato(Origin::Operator);

    /// L'origine di ogni campo di ogni struttura mostrata (ADR-0118, §3).
    ///
    /// # Come si legge
    ///
    /// **Osservato**: viene da Telegram o da una fonte esterna, così com'era.
    /// **Calcolato**: lo ha prodotto il programma — un calcolo, un conteggio,
    /// una misura, un istante che il programma ha registrato, una frase che il
    /// programma compone con una regola fissa. **Operatore**: lo ha scritto o
    /// deciso una persona — anche l'istante e l'autore di quell'atto.
    const CAMPI: &[(&str, &str, Classe)] = &[
        ("AvailableSourceEntry", "chat-id", OSS),
        ("AvailableSourceEntry", "title", OSS),
        ("AvailableSourceEntry", "kind", OSS),
        ("AvailableSourceEntry", "username", OSS),
        ("AvailableSourceEntry", "already-configured", Struttura),
        ("AvailableSourceEntry", "selectable", Struttura),
        ("AvailableSourceEntry", "reason", CAL),
        ("BookmarkCollectionRow", "id", Struttura),
        ("BookmarkCollectionRow", "name", OPE),
        ("BookmarkCollectionRow", "created", OPE),
        ("BookmarkCollectionRow", "count", CAL),
        ("BookmarkRow", "id", Struttura),
        ("BookmarkRow", "kind", Struttura),
        ("BookmarkRow", "target-id", Struttura),
        ("BookmarkRow", "sentence", OSS),
        ("BookmarkRow", "present", Struttura),
        ("BookmarkRow", "marked", Struttura),
        ("BookmarkRow", "collection-name", OPE),
        ("BookmarkRow", "collection-id", Struttura),
        ("CapabilityRow", "name", Interfaccia),
        ("CapabilityRow", "requirement", Interfaccia),
        ("CapabilityRow", "status", CAL),
        ("CapabilityRow", "detail", CAL),
        ("CapabilityRow", "usable", Struttura),
        ("CapabilityRow", "blocking", Struttura),
        ("ConfiguredSourceEntry", "source-id", Struttura),
        ("ConfiguredSourceEntry", "title", OSS),
        ("ConfiguredSourceEntry", "kind", OSS),
        ("ConfiguredSourceEntry", "identifier", OSS),
        ("ConfiguredSourceEntry", "authorized-by", OPE),
        ("ConfiguredSourceEntry", "accounts", CAL),
        ("ConfiguredSourceEntry", "active", OPE),
        ("ConfiguredSourceEntry", "health", CAL),
        ("ConfiguredSourceEntry", "health-attention", Struttura),
        ("ConfiguredSourceEntry", "health-unknown", Struttura),
        ("ConfiguredSourceEntry", "health-stopped", Struttura),
        ("ConfiguredSourceEntry", "last-check", CAL),
        ("ConfiguredSourceEntry", "last-content", CAL),
        ("ConfiguredSourceEntry", "coverage", CAL),
        ("ConfiguredSourceEntry", "coverage-summary", CAL),
        ("ConfiguredSourceEntry", "recovered", CAL),
        ("ContentEntry", "content-id", Struttura),
        ("ContentEntry", "source", OSS),
        ("ContentEntry", "acquired", CAL),
        // La pubblicazione la dichiara la fonte (E2E01-06).
        ("ContentEntry", "published", OSS),
        ("ContentEntry", "level", CAL),
        ("ContentEntry", "level-label", CAL),
        ("ContentEntry", "reason", CAL),
        ("ContentEntry", "terms", CAL),
        ("ContentEntry", "excerpt", OSS),
        ("ContentEntry", "author-identifier", OSS),
        ("ContentEntry", "author-username", OSS),
        ("ContentEntry", "mode-label", CAL),
        ("ContentEntry", "url", OSS),
        ("ContentEntry", "review-state", OPE),
        ("ContentEntry", "awaiting", CAL),
        ("ContentEntry", "duplicate", CAL),
        ("ContentEntry", "history-label", OSS),
        ("ContentEntry", "has-history", Struttura),
        ("ContentEntry", "revised", OPE),
        // La citazione la riconosce il programma nel testo, con il nome
        // dalla fotografia ATT&CK (ATTACK-03, ADR-0185).
        ("ContentEntry", "cited", CAL),
        ("ContentVersionEntry", "heading", CAL),
        ("ContentVersionEntry", "observed", CAL),
        ("ContentVersionEntry", "remote-edit", OSS),
        ("ContentVersionEntry", "body", OSS),
        ("ContentVersionEntry", "change", CAL),
        ("ContentVersionEntry", "delta", CAL),
        ("ContentVersionEntry", "original", Struttura),
        ("CoperturaFonte", "name", OSS),
        ("CoperturaFonte", "tratti", CAL),
        ("CoperturaFonte", "summary", CAL),
        ("CoperturaFonte", "recuperati", CAL),
        ("ContextRow", "when", OSS),
        ("ContextRow", "text", OSS),
        ("ContextRow", "is-anchor", Struttura),
        ("ContextRow", "who", OSS),
        ("ContextRow", "relations", CAL),
        ("ContextRow", "number", OSS),
        ("CyberCandidateEntry", "sentence", CAL),
        ("CyberCandidateEntry", "first-seen", CAL),
        ("CyberCandidateEntry", "last-seen", CAL),
        ("CyberCandidateEntry", "sessions", CAL),
        ("CyberCandidateEntry", "review", OPE),
        ("CyberCandidateEntry", "first-content-id", Struttura),
        ("CyberEventEntry", "reason", CAL),
        ("CyberEventEntry", "assessment", CAL),
        ("CyberEventEntry", "contents", CAL),
        ("CyberEventEntry", "distinct-sources", CAL),
        ("CyberEventEntry", "apparent-reposts", CAL),
        ("CyberEventEntry", "first-seen", CAL),
        ("CyberEventEntry", "last-seen", CAL),
        ("CyberEventEntry", "italy", CAL),
        ("CyberEventEntry", "has-italy-signal", Struttura),
        ("CyberEventEntry", "sectors", CAL),
        ("CyberEventEntry", "has-sector", Struttura),
        ("CyberEventEntry", "sector-labels", CAL),
        ("CyberEventEntry", "indicators", CAL),
        ("CyberEventEntry", "review", OPE),
        ("CyberEventEntry", "search-key", Struttura),
        ("CyberEventEntry", "reason-kind", Struttura),
        ("CyberEventEntry", "first-content-id", Struttura),
        ("CyberIndicatorEntry", "kind", CAL),
        ("CyberIndicatorEntry", "value", OSS),
        ("CyberTimelineEntry", "when", PerRiga("is-human-act")),
        ("CyberTimelineEntry", "clock", CAL),
        ("CyberTimelineEntry", "what", PerRiga("is-human-act")),
        ("CyberTimelineEntry", "reference", Struttura),
        ("CyberTimelineEntry", "is-human-act", Struttura),
        ("DashboardRow", "question", Interfaccia),
        ("DashboardRow", "value", CAL),
        ("DashboardRow", "note", CAL),
        ("DashboardRow", "attention", Struttura),
        ("DashboardRow", "unavailable", Struttura),
        ("DiagnosticRow", "area", Interfaccia),
        ("DiagnosticRow", "outcome", CAL),
        ("DiagnosticRow", "detail", CAL),
        ("DiagnosticRow", "action", CAL),
        ("DiagnosticRow", "attention", Struttura),
        ("DiagnosticRow", "problem", Struttura),
        ("DiagnosticRow", "unmeasured", Struttura),
        ("DictionaryEntry", "dictionary-id", Struttura),
        ("DictionaryEntry", "name", OPE),
        ("DictionaryEntry", "description", OPE),
        ("DictionaryEntry", "scope", OPE),
        ("DictionaryEntry", "origin", CAL),
        ("DictionaryEntry", "visibility", OPE),
        ("DictionaryEntry", "status", CAL),
        ("DictionaryEntry", "published-version", OPE),
        ("DictionaryEntry", "published-terms", CAL),
        ("DictionaryEntry", "has-open-draft", Struttura),
        ("DictionaryEntry", "built-in", Struttura),
        ("DictionaryEntry", "usable", Struttura),
        ("DictionaryEntry", "unusable-reason", CAL),
        ("DiscoveryCandidateEntry", "name", OSS),
        ("DiscoveryCandidateEntry", "scope", CAL),
        ("DiscoveryCandidateEntry", "why", CAL),
        ("DiscoveryCandidateEntry", "reasons", CAL),
        ("DiscoveryCandidateEntry", "address", OSS),
        ("DiscoveryRunEntry", "when", CAL),
        ("DiscoveryRunEntry", "scope", OPE),
        ("DiscoveryRunEntry", "summary", CAL),
        ("DiscoveryTermEntry", "term", OPE),
        ("DiscoveryTermEntry", "reason", CAL),
        ("DiscoveryTermEntry", "consequence", CAL),
        ("FeedbackRow", "rule", OPE),
        ("FeedbackRow", "counts", CAL),
        ("FeedbackRow", "suggestion", CAL),
        ("FeedbackRow", "suggested", Struttura),
        ("GapRow", "source", OSS),
        ("GapRow", "when", CAL),
        ("GapRow", "priority", CAL),
        ("GapRow", "sentence", CAL),
        ("GapRow", "key", Struttura),
        // Le persone dell'ufficio (FR-047): le dichiara chi amministra.
        ("HubPersonRow", "id", OPE),
        ("HubPersonRow", "name", OPE),
        ("HubPersonRow", "role", OPE),
        ("HubPersonRow", "state", OPE),
        ("HubPersonRow", "active", Struttura),
        ("IntervalRow", "source", OSS),
        ("IntervalRow", "sentence", CAL),
        ("IntervalRow", "recoverable", Struttura),
        ("IntervalRow", "key", Struttura),
        ("EvidenceChoice", "content-id", Struttura),
        ("EvidenceChoice", "sentence", OSS),
        ("EvidenceChoice", "chosen", OPE),
        ("ReferenceSnapshotRow", "key", Struttura),
        ("ReferenceSnapshotRow", "source", OSS),
        ("ReferenceSnapshotRow", "when", CAL),
        ("ReferenceSnapshotRow", "who", OPE),
        ("ReferenceSnapshotRow", "content", CAL),
        ("ReferenceAssociationRow", "key", Struttura),
        ("ReferenceAssociationRow", "sentence", CAL),
        ("ReferenceAssociationRow", "motive", OPE),
        ("ReferenceAssociationRow", "who", OPE),
        ("ReferenceAssociationRow", "when", CAL),
        ("StixPlanRow", "value", OSS),
        ("StixPlanRow", "kind", CAL),
        ("StixPlanRow", "contents", CAL),
        ("StixPlanRow", "outcome", CAL),
        ("EvidencePackageRow", "reference", CAL),
        ("EvidencePackageRow", "when", CAL),
        ("EvidencePackageRow", "who", OPE),
        ("EvidencePackageRow", "count", CAL),
        ("EvidencePackageRow", "motive", OPE),
        ("ResolutionRow", "when", CAL),
        ("ResolutionRow", "operator", OPE),
        ("ResolutionRow", "input", OPE),
        ("ResolutionRow", "outcome", CAL),
        ("ResolutionRow", "found", OSS),
        ("ResolutionRow", "id", Struttura),
        ("ResolutionRow", "linkable", Struttura),
        ("ResolutionRow", "sentence", CAL),
        ("OverviewRow", "session-id", Struttura),
        ("OverviewRow", "label", OPE),
        ("OverviewRow", "chosen", Struttura),
        ("PriorHistoryRow", "source", OSS),
        ("PriorHistoryRow", "session", OPE),
        ("PriorHistoryRow", "sentence", CAL),
        ("PriorHistoryRow", "readable", Struttura),
        ("PriorHistoryRow", "key", Struttura),
        ("GlossaryRow", "term", Interfaccia),
        ("GlossaryRow", "plain", Interfaccia),
        ("GlossaryRow", "detail", Interfaccia),
        ("GraphNodeEntry", "label", OSS),
        ("GraphNodeEntry", "kind", CAL),
        ("GraphNodeEntry", "why", PerRiga("is-human-act")),
        ("GraphNodeEntry", "is-human-act", Struttura),
        ("GraphNodeEntry", "x", Struttura),
        ("GraphNodeEntry", "y", Struttura),
        ("GuideEntry", "title", Interfaccia),
        ("GuideEntry", "body", Interfaccia),
        ("HealthCheckEntry", "headline", CAL),
        ("HealthCheckEntry", "meaning", CAL),
        ("HealthCheckEntry", "conclusive", Struttura),
        ("HealthCheckEntry", "detail", CAL),
        ("HealthCheckEntry", "observer", CAL),
        ("LabRow", "content", OSS),
        ("LabRow", "reason", CAL),
        ("LabRow", "raised", CAL),
        ("LabRow", "lowered", CAL),
        ("LabRow", "not-reproducing", CAL),
        // Le differenze dei termini le calcola il confronto; i termini li ha
        // scritti chi ha compilato il dizionario (F-07).
        ("LabTermRow", "sign", CAL),
        ("LabTermRow", "sentence", CAL),
        ("LabTermRow", "removed", CAL),
        ("MonitoringRow", "label", OPE),
        ("MonitoringRow", "state", CAL),
        ("MonitoringRow", "selected", Struttura),
        ("NoteRow", "id", Struttura),
        ("NoteRow", "body", OPE),
        ("NoteRow", "sentence", OPE),
        ("NoteRow", "stands", Struttura),
        ("NoteRow", "target", OSS),
        ("NoteRow", "present", Struttura),
        ("NotificationCard", "emitted", CAL),
        ("NotificationCard", "source", OSS),
        ("NotificationCard", "level-label", CAL),
        ("NotificationCard", "privacy", OPE),
        ("NotificationCard", "reason", CAL),
        ("NotificationCard", "excerpt", OSS),
        ("NotificationCard", "url", OSS),
        ("ProfileMediaEntry", "id", Struttura),
        ("ProfileMediaEntry", "chosen", OPE),
        ("ProfileMediaEntry", "markable", Struttura),
        ("ProfileMediaEntry", "when", CAL),
        ("ProfileMediaEntry", "motive", OPE),
        ("ProfileMediaEntry", "outcome", OSS),
        ("ProfileMediaEntry", "status", OSS),
        ("ProfileMediaEntry", "bio", OSS),
        ("ProfileMediaEntry", "has-photo", Struttura),
        ("ProfileMediaEntry", "photo", OSS),
        ("ProfileMediaEntry", "photo-note", CAL),
        ("AttachmentKeepingEntry", "when", CAL),
        ("AttachmentKeepingEntry", "motive", OPE),
        ("AttachmentKeepingEntry", "outcome", OSS),
        ("AttachmentKeepingEntry", "fingerprint", CAL),
        ("ParticipantEntry", "identifier", OSS),
        ("ParticipantEntry", "display-name", OSS),
        ("ParticipantEntry", "username", OSS),
        ("ParticipantEntry", "messages", CAL),
        ("ParticipantEntry", "sources", CAL),
        ("ParticipantEntry", "first-seen", CAL),
        ("ParticipantEntry", "last-seen", CAL),
        ("ParticipantEntry", "alias-history", OSS),
        ("ParticipantEntry", "alias-caveat", CAL),
        ("ParticipantEntry", "associations", CAL),
        ("ParticipantEntry", "associations-caveat", CAL),
        ("ParticipantEntry", "timeline", OSS),
        ("ParticipantEntry", "timeline-windows", CAL),
        ("ParticipantEntry", "timeline-caveat", CAL),
        ("PersonRow", "id", Struttura),
        ("PersonRow", "label", OPE),
        ("PersonRow", "sentence", OPE),
        ("PersonRow", "reason", OPE),
        ("PersonRow", "open", Struttura),
        ("PersonRow", "assessment-label", OPE),
        ("PersonRow", "assessment-sentence", OPE),
        ("PersonRow", "assessment-history", OPE),
        ("PersonRow", "linked-identities", OPE),
        ("PersonRow", "link-history", OPE),
        ("PersonRow", "dossier", OSS),
        ("PersonRow", "entries", OPE),
        ("PersonRow", "observed-names", OSS),
        ("SubjectEntryRow", "id", Struttura),
        ("SubjectEntryRow", "sentence", OPE),
        ("SubjectEntryRow", "withdrawn", OPE),
        ("SubjectEntryRow", "content-id", Struttura),
        ("AuthorSubjectRow", "id", Struttura),
        ("AuthorSubjectRow", "label", OPE),
        ("CyberHitRow", "chat", OSS),
        ("CyberHitRow", "when", OSS),
        ("CyberHitRow", "who", OSS),
        ("CyberHitRow", "excerpt", OSS),
        // La ricerca ricorrente E (CYBER-WATCH-02): la domanda e lo stato li
        // sceglie l'operatore, la copertura la calcola il programma, le novità
        // sono ciò che Telegram ha restituito.
        // La ricerca su più rami (CYBER-SEARCH-03): i messaggi come la fonte li
        // dichiara, i rami che li hanno trovati calcolati dal programma.
        ("CyberCrossRow", "chat", OSS),
        ("CyberCrossRow", "when", OSS),
        ("CyberCrossRow", "who", OSS),
        ("CyberCrossRow", "excerpt", OSS),
        ("CyberCrossRow", "found-by", CAL),
        ("CyberRecurringRow", "id", Struttura),
        ("CyberRecurringRow", "title", OPE),
        ("CyberRecurringRow", "coverage", CAL),
        ("CyberRecurringRow", "novelties", OSS),
        ("CyberRecurringRow", "suspended", OPE),
        ("ProvenanceDecisionEntry", "heading", OPE),
        ("ProvenanceDecisionEntry", "note", OPE),
        ("ProvenanceTermEntry", "text", CAL),
        ("ProvenanceTermEntry", "origin", CAL),
        ("ProvenanceTermEntry", "position", CAL),
        ("ProvenanceTermEntry", "mitigating", CAL),
        ("ProvenanceTermEntry", "known", Struttura),
        ("QueueRow", "source", OSS),
        ("QueueRow", "session", OPE),
        ("QueueRow", "level-label", CAL),
        ("QueueRow", "level", CAL),
        ("QueueRow", "state", OPE),
        ("QueueRow", "untouched", Struttura),
        ("QueueRow", "why-here", CAL),
        ("QueueRow", "reason", CAL),
        ("QueueRow", "excerpt", OSS),
        ("QueueRow", "content-id", Struttura),
        ("ReportArtifactRow", "name", CAL),
        ("ReportArtifactRow", "kind", CAL),
        ("ReportArtifactRow", "size", CAL),
        ("ReportArtifactRow", "sha256", CAL),
        ("ReportContentRow", "content-id", Struttura),
        ("ReportContentRow", "chosen", Struttura),
        ("ReportContentRow", "level", CAL),
        ("ReportContentRow", "level-label", CAL),
        ("ReportContentRow", "source", OSS),
        ("ReportContentRow", "published", OSS),
        ("ReportContentRow", "excerpt", OSS),
        ("ReportContentRow", "review-state", OPE),
        ("ReportContentRow", "alert", CAL),
        ("ReportContentRow", "link", OSS),
        ("ReportFormatRow", "label", Interfaccia),
        ("ReportFormatRow", "available", Struttura),
        ("ReportFormatRow", "note", Interfaccia),
        ("ReportSessionEntry", "session-id", Struttura),
        ("ReportSessionEntry", "label", OPE),
        ("ReportSessionEntry", "started", CAL),
        ("ReportSessionEntry", "ended", CAL),
        ("ReportSessionEntry", "state", CAL),
        ("ReportSessionEntry", "operator", OPE),
        ("ReportSessionEntry", "sources", CAL),
        ("ReportSessionEntry", "contents", CAL),
        ("ReportSessionEntry", "alerts", CAL),
        ("ReportSessionEntry", "chosen", Struttura),
        ("ReportSummaryRow", "label", Interfaccia),
        ("ReportSummaryRow", "value", CAL),
        ("ResemblanceRow", "other", OSS),
        ("ResemblanceRow", "why", CAL),
        ("ResemblanceRow", "evidence", CAL),
        ("ResemblanceRow", "pair-key", Struttura),
        ("RetroMatchEntry", "source", OSS),
        ("RetroMatchEntry", "published", OSS),
        ("RetroMatchEntry", "level-label", CAL),
        ("RetroMatchEntry", "terms", CAL),
        ("RetroMatchEntry", "excerpt", OSS),
        ("RetroMatchEntry", "url", OSS),
        ("ReviewQueueRow", "content-id", Struttura),
        ("ReviewQueueRow", "source", OSS),
        ("ReviewQueueRow", "level", CAL),
        ("ReviewQueueRow", "raised", CAL),
        ("ReviewQueueRow", "state", OPE),
        ("ReviewQueueRow", "version", CAL),
        ("ReviewQueueRow", "why", CAL),
        ("ReviewQueueRow", "assigned", OPE),
        ("SavedSearchRow", "id", Struttura),
        ("SavedSearchRow", "name", OPE),
        ("SavedSearchRow", "sentence", OPE),
        ("SharedItemRow", "what", OSS),
        ("SharedItemRow", "added", OPE),
        ("SharedItemRow", "kind", Struttura),
        ("SharedItemRow", "target", Struttura),
        ("SharedNoteRow", "id", Struttura),
        ("SharedNoteRow", "body", OPE),
        ("SharedNoteRow", "author", OPE),
        ("SharedNoteRow", "written", OPE),
        ("SharedNoteRow", "withdrawn", OPE),
        ("SharedNoteRow", "mine", Struttura),
        ("SharedReportRow", "report-id", Struttura),
        ("SharedReportRow", "who", OPE),
        ("SharedReportRow", "state", CAL),
        ("SharedReportRow", "counts", CAL),
        ("SharedReportRow", "documents", CAL),
        ("SharedWorkspaceRow", "id", Struttura),
        ("SharedWorkspaceRow", "name", OPE),
        ("SharedWorkspaceRow", "description", OPE),
        ("SharedWorkspaceRow", "state", OPE),
        ("SharedWorkspaceRow", "open", Struttura),
        ("SharedWorkspaceRow", "summary", CAL),
        ("SnapshotRow", "sentence", OPE),
        ("SnapshotRow", "intact", CAL),
        // L'affidabilità delle fonti (SOURCE-RELIABILITY-01): la valutazione la
        // dà una persona.
        ("SourceReliabilityRow", "source-id", Struttura),
        ("SourceReliabilityRow", "name", OPE),
        ("SourceReliabilityRow", "sentence", OPE),
        // I suggerimenti di fonti (SOURCE-SUGGEST-01): la chat citata viene dai
        // contenuti, il motivo lo calcola il programma.
        ("SourceSuggestionRow", "address", OSS),
        ("SourceSuggestionRow", "title", OSS),
        ("SourceSuggestionRow", "reason", CAL),
        ("TeamLiveRow", "when", CAL),
        ("TeamLiveRow", "kind", CAL),
        ("TeamLiveRow", "subject", OSS),
        ("TeamLiveRow", "detail", CAL),
        ("TeamLiveRow", "sequence", Struttura),
        ("TeamPersonRow", "person", OPE),
        ("TeamPersonRow", "label", OPE),
        ("TeamPersonRow", "role", OPE),
        ("TeamPersonRow", "active", OPE),
        ("TeamPresenceRow", "station", OPE),
        ("TeamPresenceRow", "since", CAL),
        ("TeamPresenceRow", "last-seen", CAL),
        ("TelegramAccountEntry", "id", Struttura),
        ("TelegramAccountEntry", "label", OPE),
        ("TelegramAccountEntry", "status", CAL),
        ("TelegramAccountEntry", "masked-phone", OPE),
        ("TelegramAccountEntry", "selected", Struttura),
        ("TelegramAccountEntry", "linked", Struttura),
        ("TelegramAccountEntry", "link-label", CAL),
        ("TelegramAccountEntry", "link-trouble", Struttura),
        ("TelegramAccountEntry", "kept", OPE),
        ("TemplateRow", "id", Struttura),
        ("TemplateRow", "name", OPE),
        ("TemplateRow", "sentence", OPE),
        ("TemplateRow", "description", OPE),
        ("TemplateSourceRow", "sentence", OSS),
        ("TemplateSourceRow", "present", Struttura),
        // Le scelte del modulo di un modello: fonti e dizionari come li ha
        // configurati l'operatore, e la spunta di chi compila (F-07).
        ("TemplateChoice", "id", Struttura),
        ("TemplateChoice", "label", OPE),
        ("TemplateChoice", "detail", OPE),
        ("TemplateChoice", "chosen", OPE),
        ("TermEntry", "term-id", Struttura),
        ("TermEntry", "text", OPE),
        ("TermEntry", "category", OPE),
        ("TermEntry", "match-mode", OPE),
        ("TermEntry", "suggested-level", OPE),
        ("TermEntry", "mitigating", OPE),
        ("TermEntry", "note", OPE),
        ("ThirdPartyEntry", "component", Interfaccia),
        ("ThirdPartyEntry", "version", Interfaccia),
        ("ThirdPartyEntry", "license", Interfaccia),
        ("ThirdPartyEntry", "note", Interfaccia),
        // Il tour guidato (TOUR-01): il testo del programma e le misure del
        // disegno, nessun dato sul mondo.
        ("TourPoint", "x", Struttura),
        ("TourPoint", "y", Struttura),
        ("TourRect", "x", Struttura),
        ("TourRect", "y", Struttura),
        ("TourRect", "width", Struttura),
        ("TourRect", "height", Struttura),
        ("TourStepRow", "key", Struttura),
        ("TourStepRow", "page", Struttura),
        ("TourStepRow", "zone", Struttura),
        ("TourStepRow", "title", Interfaccia),
        ("TourStepRow", "body", Interfaccia),
        ("TourStepRow", "note", Interfaccia),
        // Il giro delle novità (NEWS-01): testi scritti dal programma.
        ("NewsRow", "title", Interfaccia),
        ("NewsRow", "sentence", Interfaccia),
        ("NewsRow", "place", Interfaccia),
        ("NewsRow", "page", Struttura),
        ("TrendRow", "what", OSS),
        ("TrendRow", "counts", CAL),
        ("VerificationRow", "report", CAL),
        ("VerificationRow", "status", CAL),
        ("VerificationRow", "ok", Struttura),
        ("WatchedOrganisationEntry", "id", Struttura),
        ("WatchedOrganisationEntry", "name", OPE),
        ("WatchedOrganisationEntry", "sector", OPE),
        ("WatchedOrganisationEntry", "anchors", OPE),
        ("WatchedOrganisationEntry", "active", OPE),
        ("WatchedOrganisationEntry", "declared", OPE),
        ("WizardChosenDictionary", "label", OPE),
        ("WizardChosenDictionary", "scope", OPE),
        ("WizardChosenDictionary", "terms", CAL),
        ("WizardChosenDictionary", "reducing-terms", CAL),
        ("WizardDictionaryEntry", "dictionary-id", Struttura),
        ("WizardDictionaryEntry", "name", OPE),
        ("WizardDictionaryEntry", "scope", OPE),
        ("WizardDictionaryEntry", "terms", CAL),
        ("WizardDictionaryEntry", "selected", Struttura),
        ("WizardDictionaryEntry", "description", OPE),
        ("WizardDictionaryEntry", "sample", OPE),
        ("WizardDictionaryEntry", "sample-truncated", Struttura),
        ("WizardNoticeEntry", "text", CAL),
        ("WizardNoticeEntry", "remedy", CAL),
        ("WizardSourceEntry", "source-id", Struttura),
        ("WizardSourceEntry", "title", OSS),
        ("WizardSourceEntry", "kind", OSS),
        ("WizardSourceEntry", "selected", Struttura),
        ("WizardStepEntry", "number", Struttura),
        ("WizardStepEntry", "title", Interfaccia),
        ("WizardStepEntry", "reached", Struttura),
        ("WizardStepEntry", "current", Struttura),
        ("WizardTermEntry", "index", Struttura),
        ("WizardTermEntry", "text", OPE),
        ("WizardTermEntry", "match-mode", OPE),
        ("WizardTermEntry", "level", OPE),
        ("WorkspaceEntryRow", "kind", Struttura),
        ("WorkspaceEntryRow", "target-id", Struttura),
        ("WorkspaceEntryRow", "sentence", OSS),
        ("WorkspaceEntryRow", "present", Struttura),
        ("WorkspaceEntryRow", "added", OPE),
        ("WorkspaceRow", "id", Struttura),
        ("WorkspaceRow", "name", OPE),
        ("WorkspaceRow", "sentence", OPE),
        ("WorkspaceRow", "open", Struttura),
    ];

    /// I generi noti e l'origine che impongono (ADR-0118, §3).
    ///
    /// Un livello è sempre calcolato, un estratto sempre osservato, una
    /// revisione sempre di una persona. È la prova contro il difetto più grave
    /// che il prodotto possa commettere: dare a un calcolo l'autorità di un
    /// fatto.
    const GENERI_NOTI: &[(&str, Origin)] = &[
        ("level", Origin::Computed),
        ("level-label", Origin::Computed),
        ("counts", Origin::Computed),
        ("reason", Origin::Computed),
        ("why", Origin::Computed),
        ("excerpt", Origin::Observed),
        ("published", Origin::Observed),
        ("url", Origin::Observed),
        ("author-identifier", Origin::Observed),
        ("author-username", Origin::Observed),
        ("review-state", Origin::Operator),
        ("assessment-label", Origin::Operator),
        ("authorized-by", Origin::Operator),
        ("written", Origin::Operator),
        ("withdrawn", Origin::Operator),
    ];

    /// Le eccezioni ai generi noti, con la ragione: struttura, campo, perché.
    const ECCEZIONI: &[(&str, &str, &str)] = &[
        (
            "WizardTermEntry",
            "level",
            "il livello di una parola in più lo sceglie l'operatore mentre prepara il \
             monitoraggio: non è il risultato dell'analisi",
        ),
        (
            "PersonRow",
            "reason",
            "il motivo per cui si è aperto un fascicolo lo scrive la persona che lo apre",
        ),
    ];

    /// Le strutture Slint e i loro campi, letti dal file dell'interfaccia.
    fn strutture() -> BTreeMap<String, Vec<String>> {
        let mut trovate: BTreeMap<String, Vec<String>> = BTreeMap::new();
        let mut corrente: Option<String> = None;
        for riga in UI.lines() {
            if let Some(resto) = riga.strip_prefix("export struct ") {
                let nome = resto.trim_end_matches('{').trim().to_owned();
                trovate.entry(nome.clone()).or_default();
                corrente = Some(nome);
                continue;
            }
            if riga.starts_with('}') {
                corrente = None;
                continue;
            }
            if let Some(nome) = &corrente {
                let pulita = riga.trim();
                if pulita.starts_with("//") || pulita.is_empty() {
                    continue;
                }
                if let Some((campo, _)) = pulita.split_once(':') {
                    trovate
                        .entry(nome.clone())
                        .or_default()
                        .push(campo.trim().to_owned());
                }
            }
        }
        trovate
    }

    /// Le origini di dato di una struttura, dalla sua classificazione.
    fn origini_di(struttura: &str) -> BTreeSet<Origin> {
        CAMPI
            .iter()
            .filter(|(s, _, _)| *s == struttura)
            .filter_map(|(_, _, classe)| match classe {
                Classe::Dato(origine) => Some(*origine),
                _ => None,
            })
            .collect()
    }

    /// Se la struttura ha campi la cui origine cambia da riga a riga.
    fn per_riga(struttura: &str) -> Option<&'static str> {
        CAMPI.iter().find_map(|(s, _, classe)| match classe {
            Classe::PerRiga(campo) if *s == struttura => Some(*campo),
            _ => None,
        })
    }

    /// I modelli di `root` con il tipo della loro struttura:
    /// `in property <[ContentEntry]> entries`.
    fn modelli() -> BTreeMap<String, String> {
        let mut modelli = BTreeMap::new();
        for riga in UI.lines() {
            let pulita = riga.trim();
            let Some(resto) = pulita
                .strip_prefix("in property <[")
                .or_else(|| pulita.strip_prefix("in-out property <["))
            else {
                continue;
            };
            let Some((tipo, dopo)) = resto.split_once("]>") else {
                continue;
            };
            let nome: String = dopo
                .trim()
                .chars()
                .take_while(|c| c.is_alphanumeric() || *c == '-')
                .collect();
            modelli.insert(nome, tipo.to_owned());
        }
        modelli
    }

    // ---------------------------------------------------------------- 1, 2

    /// **Ogni campo mostrato ha un'origine dichiarata.**
    #[test]
    fn ogni_campo_mostrato_ha_un_origine_dichiarata() {
        let strutture = strutture();
        assert!(
            strutture.len() > 50,
            "trovate solo {} strutture",
            strutture.len()
        );

        let dichiarati: BTreeSet<(&str, &str)> = CAMPI.iter().map(|(s, c, _)| (*s, *c)).collect();
        assert_eq!(
            dichiarati.len(),
            CAMPI.len(),
            "un campo è classificato due volte"
        );

        let mut mancanti = Vec::new();
        let mut esistenti = BTreeSet::new();
        for (struttura, campi) in &strutture {
            for campo in campi {
                esistenti.insert((struttura.clone(), campo.clone()));
                if !dichiarati.contains(&(struttura.as_str(), campo.as_str())) {
                    mancanti.push(format!("{struttura}.{campo}"));
                }
            }
        }
        assert!(
            mancanti.is_empty(),
            "campi mostrati senza origine dichiarata — va detto chi dice il dato \
             (Osservato, Calcolato, Operatore) o che non è un dato (Struttura, \
             Interfaccia), in `CAMPI`:\n{}",
            mancanti.join("\n")
        );

        let spariti: Vec<String> = CAMPI
            .iter()
            .filter(|(s, c, _)| !esistenti.contains(&((*s).to_owned(), (*c).to_owned())))
            .map(|(s, c, _)| format!("{s}.{c}"))
            .collect();
        assert!(
            spariti.is_empty(),
            "origini dichiarate per campi che non esistono più:\n{}",
            spariti.join("\n")
        );
    }

    // ---------------------------------------------------------------- 3

    /// **Un genere noto ha l'origine del suo genere.**
    #[test]
    fn un_genere_noto_ha_l_origine_del_suo_genere() {
        let mut sbagliati = Vec::new();
        for (struttura, campo, classe) in CAMPI {
            let Some((_, atteso)) = GENERI_NOTI.iter().find(|(nome, _)| nome == campo) else {
                continue;
            };
            if ECCEZIONI
                .iter()
                .any(|(s, c, _)| s == struttura && c == campo)
                || matches!(classe, Classe::PerRiga(_))
            {
                continue;
            }
            if *classe != Classe::Dato(*atteso) {
                sbagliati.push(format!(
                    "{struttura}.{campo} è {classe:?}, ma un «{campo}» è sempre {}",
                    atteso.label()
                ));
            }
        }
        assert!(
            sbagliati.is_empty(),
            "origini contrarie al genere del campo:\n{}",
            sbagliati.join("\n")
        );
        for (struttura, campo, ragione) in ECCEZIONI {
            assert!(
                CAMPI.iter().any(|(s, c, _)| s == struttura && c == campo),
                "l'eccezione {struttura}.{campo} ({ragione}) non riguarda più un campo esistente"
            );
        }
    }

    // ---------------------------------------------------------------- 4

    /// **Ogni elenco di dati ha la sua legenda, e la legenda nomina ogni
    /// origine che la sua struttura contiene.**
    #[test]
    fn ogni_elenco_di_dati_ha_la_sua_legenda() {
        let modelli = modelli();
        let mut difetti = Vec::new();
        let mut elenchi_controllati = 0usize;

        for (posizione, _) in UI.match_indices(" in root.") {
            let inizio_riga = UI[..posizione].rfind('\n').map_or(0, |i| i + 1);
            let riga = &UI[inizio_riga..];
            let riga = riga.lines().next().unwrap_or_default().trim_start();
            if !riga.starts_with("for ") {
                continue;
            }
            let nome: String = UI[posizione + " in root.".len()..]
                .chars()
                .take_while(|c| c.is_alphanumeric() || *c == '-')
                .collect();
            let Some(tipo) = modelli.get(&nome) else {
                continue;
            };
            let origini = origini_di(tipo);
            let numero = UI[..posizione].lines().count();

            // Il nome con cui l'elenco chiama la riga: `for voce in …`.
            let variabile = riga
                .trim_start_matches("for ")
                .split_whitespace()
                .next()
                .unwrap_or_default()
                .to_owned();
            let corpo = UI.get(posizione..posizione + 4_000).unwrap_or_default();

            if let Some(campo) = per_riga(tipo) {
                // L'origine cambia da riga a riga: la riga che SCRIVE i campi
                // a origine variabile porta il proprio segno, guidato dal campo
                // che la dichiara. Un elenco che disegna soltanto — gli archi
                // del grafo — non scrive quei campi, e non ha niente da
                // segnare.
                let scrive = CAMPI.iter().any(|(s, c, classe)| {
                    *s == tipo.as_str()
                        && matches!(classe, Classe::PerRiga(_))
                        && corpo.contains(&format!("{variabile}.{c}"))
                });
                if scrive {
                    elenchi_controllati += 1;
                    if !corpo.contains("OrigineSegno")
                        || !corpo.contains(&format!("{variabile}.{campo}"))
                    {
                        difetti.push(format!(
                            "riga {numero}: «for … in root.{nome}» ({tipo}) mescola origini riga \
                             per riga: ogni riga deve portare un OrigineSegno guidato da \
                             «{campo}»"
                        ));
                    }
                }
                continue;
            }
            if origini.is_empty() {
                continue;
            }
            elenchi_controllati += 1;

            // La legenda sta prima dell'elenco, nello stesso contenitore: si
            // cerca l'ultima legenda nelle righe che lo precedono.
            let prima = &UI[..inizio_riga];
            let finestra_inizio = prima
                .char_indices()
                .rev()
                .filter(|(_, c)| *c == '\n')
                .nth(40)
                .map_or(0, |(i, _)| i);
            let finestra = &prima[finestra_inizio..];

            // Una struttura con UNA sola origine può essere annunciata dal
            // segno d'origine che la precede, come nel pannello del percorso:
            // «CALCOLATO», e sotto i termini trovati.
            if origini.len() == 1
                && let Some(unica) = origini.iter().next()
            {
                let segno = format!(
                    "OrigineSegno {{ origine: Origine.{}; }}",
                    unica.label().to_lowercase()
                );
                if finestra.contains(&segno) {
                    continue;
                }
            }

            let Some(legenda_pos) = finestra.rfind("LegendaOrigini {") else {
                difetti.push(format!(
                    "riga {numero}: «for … in root.{nome}» ({tipo}) non ha una LegendaOrigini \
                     nelle quaranta righe che lo precedono"
                ));
                continue;
            };
            let legenda = &finestra[legenda_pos..];
            let legenda = &legenda[..legenda.find('}').unwrap_or(legenda.len())];
            for (origine, proprieta) in [
                (Origin::Observed, "osservato:"),
                (Origin::Computed, "calcolato:"),
                (Origin::Operator, "operatore:"),
            ] {
                let presente = legenda.contains(proprieta);
                let serve = origini.contains(&origine);
                if serve && !presente {
                    difetti.push(format!(
                        "riga {numero}: la legenda di «root.{nome}» ({tipo}) non dice che cosa è \
                         {}",
                        origine.label().to_lowercase()
                    ));
                }
                if presente && !serve {
                    difetti.push(format!(
                        "riga {numero}: la legenda di «root.{nome}» ({tipo}) nomina \
                         {} ma la struttura non ha dati di quell'origine",
                        origine.label().to_lowercase()
                    ));
                }
            }
        }

        assert!(
            elenchi_controllati >= 40,
            "controllati solo {elenchi_controllati} elenchi di dati: la guardia non sta \
             leggendo l'interfaccia"
        );
        assert!(difetti.is_empty(), "{}", difetti.join("\n"));
    }

    // ---------------------------------------------------------------- 5

    /// **Il segno d'origine si legge senza colore: porta la parola.**
    ///
    /// Tre segni distinti solo dal colore non direbbero niente a chi non
    /// distingue i colori, e niente a chi ascolta la schermata (PR-03,
    /// controllo negativo 4).
    #[test]
    fn il_segno_d_origine_porta_la_parola() {
        let Some(inizio) = COMPONENTI.find("export component OrigineSegno") else {
            panic!("il componente OrigineSegno deve esistere");
        };
        let fine = COMPONENTI[inizio..]
            .find("\nexport ")
            .map_or(COMPONENTI.len(), |f| inizio + f);
        let segno = &COMPONENTI[inizio..fine];

        for parola in [
            "\"OSSERVATO\"",
            "\"CALCOLATO\"",
            "\"OPERATORE\"",
            "\"ORIGINE NON REGISTRATA\"",
        ] {
            assert!(segno.contains(parola), "il segno deve scrivere {parola}");
        }
        assert!(
            segno.contains("text: root.parola;"),
            "il segno deve mostrare la parola, non solo un colore"
        );
        assert!(
            segno.contains("accessible-label: @tr(\"Origine: {}\", root.parola);"),
            "una tecnologia assistiva deve leggere la parola"
        );
        for origine in Origin::ALL {
            assert!(
                segno.contains(&format!("\"{}\"", origine.label().to_uppercase())),
                "il segno e il dominio devono usare la stessa parola: {}",
                origine.label()
            );
        }
    }

    /// **La guardia non passa a vuoto.**
    #[test]
    fn la_classificazione_non_e_vuota() {
        let dati = CAMPI
            .iter()
            .filter(|(_, _, classe)| matches!(classe, Classe::Dato(_)))
            .count();
        assert!(dati >= 200, "solo {dati} campi di dato classificati");
        for origine in Origin::ALL {
            assert!(
                CAMPI
                    .iter()
                    .any(|(_, _, classe)| *classe == Classe::Dato(origine)),
                "nessun campo è {}: la classificazione è sospetta",
                origine.label()
            );
        }
    }
}
