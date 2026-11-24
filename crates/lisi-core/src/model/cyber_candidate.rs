//! Eventi candidati in tutto l'archivio, oltre i grappoli di un monitoraggio
//! (CYBER-EVENTS-02, ADR-0189).
//!
//! # Che cosa aggiunge ai grappoli
//!
//! Un [`CyberEvent`](crate::model::cyber_event::CyberEvent) vive dentro un
//! monitoraggio (DEC-221). Lo stesso indicatore può però ricorrere in due
//! monitoraggi diversi, e nessuno dei due grappoli lo mostra. Qui lo si
//! guarda in tutto l'archivio, **dichiarando** in quanti monitoraggi
//! ricorre: il gruppo non finge di appartenere a uno solo.
//!
//! # Un episodio, non una storia intera
//!
//! Un indicatore nominato oggi e di nuovo fra tre mesi non è un evento: sono
//! due. I contenuti si dividono in **episodi** dove fra due pubblicazioni
//! consecutive passano più di [`EPISODE_GAP_HOURS`] ore. La regola è una
//! sola, con un numero scelto e dichiarato.
//!
//! # Che cosa resta un candidato
//!
//! Un episodio con almeno due contenuti da almeno **due fonti distinte**: una
//! fonte che si ripete non è un segnale che si ripete. Resta un candidato:
//! non c'è uno stato «confermato», e fonti distinte non sono conferme
//! indipendenti.
//!
//! # Deterministico
//!
//! Lo stesso archivio produce gli stessi candidati, nello stesso ordine:
//! nessun punteggio, nessun modello, nessuna dipendenza dall'ordine di
//! lettura.

use crate::Timestamp;
use crate::model::cyber_event::{
    CorrelationReason, CyberEvent, EventAssessment, EventMember, ReviewSummary,
};

/// Le ore senza pubblicazioni che separano due episodi.
pub const EPISODE_GAP_HOURS: i64 = 72;

/// I giorni dell'archivio che si guardano.
pub const ARCHIVE_WINDOW_DAYS: i64 = 30;

/// Quanti candidati al più.
pub const MAX_CANDIDATES: usize = 25;

const ORA: i64 = 3_600_000;

/// Un contenuto, con il monitoraggio che lo ha raccolto.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArchiveMember {
    /// Il contenuto.
    pub member: EventMember,
    /// Il monitoraggio.
    pub session_id: i64,
}

/// I contenuti dell'archivio che nominano lo stesso indicatore.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArchiveCluster {
    /// Perché stanno insieme.
    pub reason: CorrelationReason,
    /// I contenuti.
    pub members: Vec<ArchiveMember>,
}

/// Un evento candidato: un episodio di un indicatore in tutto l'archivio.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CandidateEvent {
    /// Perché stanno insieme.
    pub reason: CorrelationReason,
    /// I contenuti, in ordine di pubblicazione.
    pub members: Vec<ArchiveMember>,
}

impl CandidateEvent {
    fn as_event(&self) -> CyberEvent {
        CyberEvent {
            reason: self.reason.clone(),
            members: self
                .members
                .iter()
                .map(|membro| membro.member.clone())
                .collect(),
        }
    }

    /// Che cosa l'episodio permette di dire: contenuti, fonti distinte,
    /// ripubblicazioni apparenti.
    #[must_use]
    pub fn assess(&self) -> EventAssessment {
        self.as_event().assess()
    }

    /// Che cosa una persona ha deciso sui suoi contenuti.
    #[must_use]
    pub fn review_summary(&self) -> ReviewSummary {
        self.as_event().review_summary()
    }

    /// Il primo e l'ultimo istante di pubblicazione.
    #[must_use]
    pub fn seen_between(&self) -> Option<(Timestamp, Timestamp)> {
        self.as_event().seen_between()
    }

    /// I monitoraggi distinti, in ordine.
    #[must_use]
    pub fn sessions(&self) -> Vec<i64> {
        let mut sessioni: Vec<i64> = self
            .members
            .iter()
            .map(|membro| membro.session_id)
            .collect();
        sessioni.sort_unstable();
        sessioni.dedup();
        sessioni
    }

    /// Il primo contenuto pubblicato, per aprirlo.
    #[must_use]
    pub fn first_content_id(&self) -> Option<i64> {
        self.members
            .iter()
            .min_by_key(|membro| (membro.member.published_at, membro.member.content_id))
            .map(|membro| membro.member.content_id)
    }

    /// L'episodio, in una frase che non giudica.
    #[must_use]
    pub fn as_sentence(&self) -> String {
        let valutazione = self.assess();
        let monitoraggi = self.sessions().len();
        format!(
            "Evento candidato, da verificare: {} contenuti che {}, in {}. {}",
            valutazione.contents,
            self.reason.as_sentence(),
            crate::text::counted(monitoraggi, "monitoraggio", "monitoraggi"),
            valutazione.as_sentence()
        )
    }
}

/// Gli eventi candidati dei grappoli dell'archivio.
///
/// Divide ogni grappolo in episodi, tiene quelli con almeno due contenuti da
/// almeno due fonti distinte, li ordina dal più recente e ne tiene al più
/// [`MAX_CANDIDATES`].
#[must_use]
pub fn candidate_events(clusters: Vec<ArchiveCluster>) -> Vec<CandidateEvent> {
    let mut candidati = Vec::new();
    for grappolo in clusters {
        let mut membri = grappolo.members;
        membri.sort_by_key(|membro| (membro.member.published_at, membro.member.content_id));
        membri.dedup_by_key(|membro| membro.member.content_id);

        let mut episodio: Vec<ArchiveMember> = Vec::new();
        for membro in membri {
            let separato = episodio.last().is_some_and(|ultimo| {
                membro.member.published_at.as_millis() - ultimo.member.published_at.as_millis()
                    > EPISODE_GAP_HOURS * ORA
            });
            if separato {
                candidati.push(CandidateEvent {
                    reason: grappolo.reason.clone(),
                    members: std::mem::take(&mut episodio),
                });
            }
            episodio.push(membro);
        }
        if !episodio.is_empty() {
            candidati.push(CandidateEvent {
                reason: grappolo.reason.clone(),
                members: episodio,
            });
        }
    }

    candidati.retain(|candidato| {
        let valutazione = candidato.assess();
        valutazione.contents > 1 && valutazione.distinct_sources > 1
    });
    // Il più recente prima; a parità, la ragione e il primo contenuto: un
    // ordine che non dipende da come l'archivio è stato letto.
    candidati.sort_by(|a, b| {
        let fine = |c: &CandidateEvent| c.seen_between().map(|(_, ultimo)| ultimo);
        fine(b)
            .cmp(&fine(a))
            .then_with(|| a.reason.as_sentence().cmp(&b.reason.as_sentence()))
            .then_with(|| a.first_content_id().cmp(&b.first_content_id()))
    });
    candidati.truncate(MAX_CANDIDATES);
    candidati
}

#[cfg(test)]
mod tests {
    use super::{
        ArchiveCluster, ArchiveMember, CandidateEvent, EPISODE_GAP_HOURS, MAX_CANDIDATES,
        candidate_events,
    };
    use crate::Timestamp;
    use crate::model::cyber_event::{CorrelationReason, EventMember, body_fingerprint};
    use crate::model::indicator::IndicatorKind;

    const INIZIO: i64 = 1_700_000_000_000;
    const ORA: i64 = 3_600_000;

    fn membro(content_id: i64, source_id: i64, session_id: i64, ore: i64) -> ArchiveMember {
        ArchiveMember {
            member: EventMember {
                content_id,
                source_id,
                body_fingerprint: body_fingerprint(&format!("testo {content_id}")),
                published_at: Timestamp::from_millis(INIZIO + ore * ORA),
                review_state: None,
            },
            session_id,
        }
    }

    fn grappolo(valore: &str, membri: Vec<ArchiveMember>) -> ArchiveCluster {
        ArchiveCluster {
            reason: CorrelationReason::SameIndicator {
                kind: IndicatorKind::Cve,
                value: String::from(valore),
            },
            members: membri,
        }
    }

    #[test]
    fn un_indicatore_in_due_monitoraggi_diventa_un_candidato() {
        let candidati = candidate_events(vec![grappolo(
            "CVE-2026-1111",
            vec![membro(1, 10, 100, 0), membro(2, 20, 200, 5)],
        )]);
        assert_eq!(candidati.len(), 1);
        assert_eq!(candidati[0].sessions(), vec![100, 200]);
        let frase = candidati[0].as_sentence();
        assert!(frase.starts_with("Evento candidato, da verificare: 2 contenuti"));
        assert!(frase.contains("in 2 monitoraggi"));
        assert!(frase.contains("non sono conferme indipendenti"));
        assert!(!frase.to_lowercase().contains("confermat"));
    }

    #[test]
    fn una_pausa_lunga_separa_due_episodi() {
        let pausa = EPISODE_GAP_HOURS + 1;
        let candidati = candidate_events(vec![grappolo(
            "CVE-2026-2222",
            vec![
                membro(1, 10, 100, 0),
                membro(2, 20, 100, 1),
                membro(3, 10, 200, 1 + pausa),
                membro(4, 30, 200, 2 + pausa),
            ],
        )]);
        assert_eq!(candidati.len(), 2);
        // Il più recente prima.
        assert_eq!(candidati[0].first_content_id(), Some(3));
        assert_eq!(candidati[1].first_content_id(), Some(1));
    }

    #[test]
    fn una_fonte_sola_non_fa_un_candidato() {
        let candidati = candidate_events(vec![grappolo(
            "CVE-2026-3333",
            vec![membro(1, 10, 100, 0), membro(2, 10, 200, 1)],
        )]);
        assert!(candidati.is_empty());
    }

    #[test]
    fn un_contenuto_isolato_resta_fuori_dall_episodio() {
        let candidati = candidate_events(vec![grappolo(
            "CVE-2026-4444",
            vec![
                membro(1, 10, 100, 0),
                membro(2, 20, 100, 2),
                membro(3, 30, 100, 10 * EPISODE_GAP_HOURS),
            ],
        )]);
        assert_eq!(candidati.len(), 1);
        assert_eq!(candidati[0].members.len(), 2);
    }

    #[test]
    fn stesso_archivio_stessi_candidati_in_qualunque_ordine() {
        let membri = vec![
            membro(1, 10, 100, 0),
            membro(2, 20, 200, 1),
            membro(3, 30, 100, 2),
        ];
        let mut rovesciati = membri.clone();
        rovesciati.reverse();
        let a = candidate_events(vec![
            grappolo("CVE-2026-0001", membri.clone()),
            grappolo("CVE-2026-0002", membri),
        ]);
        let b = candidate_events(vec![
            grappolo("CVE-2026-0002", rovesciati.clone()),
            grappolo("CVE-2026-0001", rovesciati),
        ]);
        assert_eq!(a, b);
        assert_eq!(a.len(), 2);
    }

    #[test]
    fn i_candidati_hanno_un_tetto() {
        let grappoli = (0..40_i64)
            .map(|n| {
                grappolo(
                    &format!("CVE-2026-{:04}", n + 1000),
                    vec![membro(n * 2, 10, 100, n), membro(n * 2 + 1, 20, 100, n)],
                )
            })
            .collect();
        let candidati: Vec<CandidateEvent> = candidate_events(grappoli);
        assert_eq!(candidati.len(), MAX_CANDIDATES);
        // I più recenti restano.
        assert_eq!(candidati[0].first_content_id(), Some(78));
    }
}
