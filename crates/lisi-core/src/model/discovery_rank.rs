//! In che ordine guardare i candidati, e perché uno sta prima di un altro.
//!
//! # La regola che governa questo modulo
//!
//! **Un ordine non è un giudizio.**
//!
//! L'ordine dice in che sequenza guardare, non che cosa vale di più. Il primo
//! della lista non è più pericoloso, più sospetto né più vero degli altri: è
//! quello da cui conviene cominciare.
//!
//! Per questo un candidato ordinato **non porta un punteggio**: nessun campo lo
//! contiene, nessuna somma, nessun peso. Un numero attaccato a un candidato
//! verrebbe letto come un voto, e nessuno potrebbe più dimostrare che non lo è.
//!
//! Contare non è valutare: «tre motivi contro uno» è il numero dei motivi che si
//! possono leggere, e **i motivi restano lì, uno per uno, e si contestano uno per
//! uno**. Un punteggio no.
//!
//! # Che cosa questo modulo NON guarda
//!
//! Quanti iscritti ha una chat — *«il numero di iscritti non è una misura di
//! verità»* (ADR-0035) — quanto il nome somigli al termine cercato, e che ora
//! fosse quando la risposta è arrivata. L'ora dipende dalla rete, e due
//! esecuzioni identiche darebbero due ordini diversi.
//!
//! La decisione completa sta in
//! `docs/adr/ADR-0078-UN-ORDINE-NON-E-UN-GIUDIZIO.md`.

use core::cmp::Ordering;

use crate::model::discovery::SourceCandidate;

/// Che cosa distingue un candidato da quello che lo precede.
///
/// I criteri si applicano in quest'ordine, e in cascata: il primo che trova una
/// differenza decide.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum RankCriterion {
    /// Ha più motivi.
    MoreReasons,
    /// Viene da una superficie più vicina a ciò che l'account già raggiunge.
    ///
    /// Non è merito: è **distanza dalla verifica**. Da una chat che l'account
    /// raggiunge già un operatore controlla subito; da una superficie pubblica
    /// sconosciuta no.
    NearerSurface,
    /// Il nome pubblico, confrontato **per byte**.
    PublicNameBytes,
    /// L'interrogazione che lo ha restituito, confrontata per byte.
    QueryBytes,
    /// Il testo dei motivi.
    ///
    /// È l'ultimo, e serve perché l'ordine sia **totale**: ciò che resta
    /// indistinguibile dopo di lui è lo stesso valore.
    ReasonsText,
}

impl RankCriterion {
    /// Tutti i criteri, nell'ordine in cui si applicano.
    pub const ALL: [Self; 5] = [
        Self::MoreReasons,
        Self::NearerSurface,
        Self::PublicNameBytes,
        Self::QueryBytes,
        Self::ReasonsText,
    ];

    /// Nome stabile, per l'archivio e per l'audit.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::MoreReasons => "piu_motivi",
            Self::NearerSurface => "superficie_piu_vicina",
            Self::PublicNameBytes => "nome_pubblico",
            Self::QueryBytes => "interrogazione",
            Self::ReasonsText => "testo_dei_motivi",
        }
    }

    /// Come si dice a chi legge.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::MoreReasons => "ha più motivi di quello che lo precede",
            Self::NearerSurface => {
                "viene da una superficie più vicina a quelle che questo account già raggiunge"
            }
            Self::PublicNameBytes => "a parità di motivi e di superficie, per il nome pubblico",
            Self::QueryBytes => "a parità anche di nome, per l'interrogazione che lo ha restituito",
            Self::ReasonsText => "a parità di tutto il resto, per il testo dei motivi",
        }
    }
}

/// Perché un candidato sta in quella posizione.
///
/// Tre casi distinti, che non si confondono. Appiattirli renderebbe
/// indistinguibile «è il primo» da «niente lo distingue da chi lo precede», e la
/// seconda è la ragione per cui l'ordine fra pari non conta.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Placement {
    /// È il primo: non c'è nulla prima.
    First,
    /// Questo criterio lo distingue da chi lo precede.
    DistinguishedBy(RankCriterion),
    /// Niente lo distingue da chi lo precede.
    ///
    /// Non è un difetto dell'ordine: è un fatto sui due candidati, e dirlo è ciò
    /// che rende inutile chiedersi quale dei due venga prima.
    IdenticalToPrevious,
}

/// Un candidato, con il posto che ha e il perché.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RankedCandidate {
    /// Il candidato, invariato.
    pub candidate: SourceCandidate,
    /// Il posto, a partire da 1.
    pub position: u32,
    /// Che cosa ha deciso questo posto.
    pub placement: Placement,
}

impl RankedCandidate {
    /// Che cosa dire a chi legge.
    #[must_use]
    pub fn sentence(&self) -> String {
        let posto = self.position;
        match self.placement {
            Placement::First => {
                format!("{posto}° — ha il maggior numero di motivi fra quelli trovati.")
            }
            Placement::DistinguishedBy(criterio) => {
                let perche = criterio.label();
                format!("{posto}° — {perche}.")
            }
            Placement::IdenticalToPrevious => format!(
                "{posto}° — niente lo distingue da quello che lo precede: \
                 l'ordine fra i due non significa nulla."
            ),
        }
    }
}

/// Confronta due candidati, criterio per criterio.
///
/// # Perché i byte e non la lingua
///
/// Una collazione locale ordina diversamente su macchine configurate
/// diversamente, e produrrebbe due liste diverse dagli stessi dati: la
/// riproducibilità viene prima della gradevolezza alfabetica (ADR-0035
/// decisione 11).
fn confronta(uno: &SourceCandidate, altro: &SourceCandidate) -> Ordering {
    // PIU' MOTIVI PRIMA: e' un conteggio di cose leggibili, non un punteggio.
    altro
        .reasons()
        .len()
        .cmp(&uno.reasons().len())
        .then_with(|| uno.result.scope.cmp(&altro.result.scope))
        .then_with(|| {
            uno.result
                .public_name
                .as_bytes()
                .cmp(altro.result.public_name.as_bytes())
        })
        .then_with(|| {
            uno.result
                .query
                .as_str()
                .as_bytes()
                .cmp(altro.result.query.as_str().as_bytes())
        })
        .then_with(|| uno.reasons().cmp(altro.reasons()))
}

/// Quale criterio distingue il secondo dal primo, se ce n'è uno.
#[must_use]
fn distingue(precedente: &SourceCandidate, seguente: &SourceCandidate) -> Placement {
    if precedente.reasons().len() != seguente.reasons().len() {
        return Placement::DistinguishedBy(RankCriterion::MoreReasons);
    }
    if precedente.result.scope != seguente.result.scope {
        return Placement::DistinguishedBy(RankCriterion::NearerSurface);
    }
    if precedente.result.public_name != seguente.result.public_name {
        return Placement::DistinguishedBy(RankCriterion::PublicNameBytes);
    }
    if precedente.result.query != seguente.result.query {
        return Placement::DistinguishedBy(RankCriterion::QueryBytes);
    }
    if precedente.reasons() != seguente.reasons() {
        return Placement::DistinguishedBy(RankCriterion::ReasonsText);
    }
    Placement::IdenticalToPrevious
}

/// Mette in ordine, e dice perché.
///
/// # Che cosa non fa
///
/// **Non toglie niente**: nessun candidato viene scartato, e la posizione in
/// fondo non significa «respinto». E **non fonde due candidati con lo stesso
/// nome pubblico**: il nome viene da fuori e non è un identificatore — due chat
/// diverse possono chiamarsi uguale, e una può chiamarsi come un'altra apposta.
#[must_use]
pub fn rank(candidates: Vec<SourceCandidate>) -> Vec<RankedCandidate> {
    rank_with(candidates.into_iter().map(|uno| ((), uno)).collect())
        .into_iter()
        .map(|(_, ordinato)| ordinato)
        .collect()
}

/// Mette in ordine **portandosi dietro** qualcosa che il dominio non conosce.
///
/// # Perché esiste
///
/// Chi ordina dei candidati letti da un archivio deve poi sapere **su quale riga**
/// si sta decidendo, e la riga non è un fatto del dominio: è un numero
/// dell'archivio.
///
/// Riassociarlo dopo, confrontando i candidati, non funziona: due candidati
/// possono essere indistinguibili in tutto tranne che nella riga da cui vengono
/// — e allora una decisione finirebbe sulla riga sbagliata pur sembrando giusta.
/// **Il modo di non sbagliare è non separarli mai.**
///
/// L'ordinamento resta **uno solo**: [`rank`] è scritto su questo.
#[must_use]
pub fn rank_with<T>(mut candidates: Vec<(T, SourceCandidate)>) -> Vec<(T, RankedCandidate)> {
    candidates.sort_by(|uno, altro| confronta(&uno.1, &altro.1));

    let mut ordinati: Vec<(T, RankedCandidate)> = Vec::with_capacity(candidates.len());
    for (indice, (carico, candidato)) in candidates.into_iter().enumerate() {
        let placement = match ordinati.last() {
            None => Placement::First,
            Some((_, precedente)) => distingue(&precedente.candidate, &candidato),
        };
        let Ok(posto) = u32::try_from(indice + 1) else {
            // INVARIANTE: oltre quattro miliardi di candidati non si ordinano e
            // non si mostrano. Chi arriva qui ha gia' un problema piu' grande.
            break;
        };
        ordinati.push((
            carico,
            RankedCandidate {
                candidate: candidato,
                position: posto,
                placement,
            },
        ));
    }
    ordinati
}

#[cfg(test)]
mod tests {
    use super::{Placement, RankCriterion, rank};
    use crate::model::discovery::{
        CandidateReason, DiscoveryQuery, DiscoveryResult, SearchScope, SourceCandidate,
    };

    fn candidato(nome: &str, scope: SearchScope, motivi: &[&str]) -> SourceCandidate {
        let Some(query) = DiscoveryQuery::try_new("ransomware") else {
            panic!("l'interrogazione di prova non e' vuota");
        };
        let motivi: Vec<CandidateReason> = motivi
            .iter()
            .map(|testo| {
                let Some(motivo) = CandidateReason::try_new(testo) else {
                    panic!("un motivo di prova non e' vuoto");
                };
                motivo
            })
            .collect();
        let risultato = DiscoveryResult {
            query,
            scope,
            public_name: nome.to_owned(),
            public_address: None,
        };
        let Some(candidato) = SourceCandidate::try_new(risultato, motivi) else {
            panic!("un candidato di prova ha almeno un motivo");
        };
        candidato
    }

    fn nomi(ordinati: &[super::RankedCandidate]) -> Vec<&str> {
        ordinati
            .iter()
            .map(|c| c.candidate.result.public_name.as_str())
            .collect()
    }

    /// **Chi ha più motivi si guarda prima, e il motivo si dice.**
    #[test]
    fn piu_motivi_viene_prima_e_lo_dichiara() {
        let ordinati = rank(vec![
            candidato("uno", SearchScope::PublicChannelPosts, &["a"]),
            candidato("tre", SearchScope::PublicChannelPosts, &["a", "b", "c"]),
            candidato("due", SearchScope::PublicChannelPosts, &["a", "b"]),
        ]);

        assert_eq!(nomi(&ordinati), vec!["tre", "due", "uno"]);
        assert_eq!(ordinati[0].placement, Placement::First);
        assert_eq!(ordinati[0].position, 1);
        assert_eq!(
            ordinati[1].placement,
            Placement::DistinguishedBy(RankCriterion::MoreReasons)
        );
    }

    /// **A parità di motivi, la superficie più vicina alla verifica.**
    #[test]
    fn a_parita_di_motivi_la_superficie_piu_vicina() {
        let ordinati = rank(vec![
            candidato("lontano", SearchScope::DiscoveredPublicChats, &["a"]),
            candidato("vicino", SearchScope::AccountChats, &["a"]),
        ]);

        assert_eq!(nomi(&ordinati), vec!["vicino", "lontano"]);
        assert_eq!(
            ordinati[1].placement,
            Placement::DistinguishedBy(RankCriterion::NearerSurface)
        );
    }

    /// **Lo stesso insieme dà lo stesso ordine, comunque sia arrivato.**
    ///
    /// Due postazioni con la stessa versione devono produrre la stessa lista
    /// nello stesso ordine: un ordine che lascia dei pari merito dipende da come
    /// sono arrivati, e quello dipende dalla rete.
    #[test]
    fn lo_stesso_insieme_da_sempre_lo_stesso_ordine() {
        let insieme = || {
            vec![
                candidato("beta", SearchScope::PublicChannelPosts, &["a", "b"]),
                candidato("alfa", SearchScope::PublicChannelPosts, &["a", "b"]),
                candidato("gamma", SearchScope::AccountChats, &["a", "b"]),
                candidato("alfa", SearchScope::AccountChats, &["a", "b"]),
            ]
        };

        let diretto = rank(insieme());
        let mut rovesciato = insieme();
        rovesciato.reverse();
        let rovesciato = rank(rovesciato);

        assert_eq!(
            nomi(&diretto),
            nomi(&rovesciato),
            "l'ordine non puo' dipendere da come i risultati sono arrivati"
        );
        assert_eq!(nomi(&diretto), vec!["alfa", "gamma", "alfa", "beta"]);
    }

    /// **Due candidati con lo stesso nome non si fondono.**
    ///
    /// Il nome pubblico viene da fuori e non e' un identificatore: due chat
    /// diverse possono chiamarsi uguale, e una puo' chiamarsi come un'altra
    /// apposta.
    #[test]
    fn due_candidati_con_lo_stesso_nome_restano_due() {
        let ordinati = rank(vec![
            candidato("Canale X", SearchScope::AccountChats, &["a"]),
            candidato("Canale X", SearchScope::PublicChannelPosts, &["b"]),
        ]);

        assert_eq!(
            ordinati.len(),
            2,
            "fondere per nome fonderebbe due chat diverse"
        );
        assert_eq!(ordinati[0].candidate.reasons().len(), 1);
        assert_eq!(
            ordinati[1].candidate.reasons().len(),
            1,
            "i motivi non si sommano fra candidati diversi"
        );
    }

    /// **Ciò che nulla distingue lo dichiara, e non finge un criterio.**
    #[test]
    fn cio_che_nulla_distingue_lo_dice() {
        let ordinati = rank(vec![
            candidato("stesso", SearchScope::AccountChats, &["a"]),
            candidato("stesso", SearchScope::AccountChats, &["a"]),
        ]);

        assert_eq!(ordinati[0].placement, Placement::First);
        assert_eq!(ordinati[1].placement, Placement::IdenticalToPrevious);
        let frase = ordinati[1].sentence();
        assert!(
            frase.contains("non significa nulla"),
            "fra due candidati identici l'ordine non significa nulla: «{frase}»"
        );
    }

    /// **Nessun candidato viene tolto.**
    #[test]
    fn ordinare_non_toglie_niente() {
        let quanti = 7;
        let mut candidati = Vec::new();
        for indice in 0..quanti {
            candidati.push(candidato(
                &format!("c{indice}"),
                SearchScope::PublicChannelPosts,
                &["a"],
            ));
        }

        let ordinati = rank(candidati);
        assert_eq!(ordinati.len(), quanti);
        for (indice, ordinato) in ordinati.iter().enumerate() {
            let Ok(atteso) = u32::try_from(indice + 1) else {
                panic!("sette posizioni entrano in un u32");
            };
            assert_eq!(ordinato.position, atteso, "le posizioni sono consecutive");
        }
    }

    /// **Ogni posizione dice che cosa l'ha decisa.**
    #[test]
    fn ogni_posizione_dice_che_cosa_l_ha_decisa() {
        let ordinati = rank(vec![
            candidato("beta", SearchScope::AccountChats, &["a"]),
            candidato("alfa", SearchScope::AccountChats, &["a"]),
            candidato("primo", SearchScope::AccountChats, &["a", "b"]),
        ]);

        assert_eq!(ordinati[0].placement, Placement::First);
        assert_eq!(
            ordinati[1].placement,
            Placement::DistinguishedBy(RankCriterion::MoreReasons)
        );
        assert_eq!(
            ordinati[2].placement,
            Placement::DistinguishedBy(RankCriterion::PublicNameBytes)
        );

        for ordinato in &ordinati {
            let frase = ordinato.sentence();
            assert!(
                !frase.trim().is_empty(),
                "di ogni posizione si dice perche' e' quella"
            );
        }
    }

    /// **Cio' che si porta dietro l'ordinamento resta attaccato al suo
    /// candidato.**
    ///
    /// Due candidati possono essere indistinguibili in tutto tranne che nella
    /// riga da cui vengono: riassociarli dopo farebbe finire una decisione sulla
    /// riga sbagliata pur sembrando giusta.
    #[test]
    fn cio_che_si_porta_dietro_resta_attaccato_al_suo_candidato() {
        let ordinati = super::rank_with(vec![
            (10_i64, candidato("uno", SearchScope::AccountChats, &["a"])),
            (
                20_i64,
                candidato("tre", SearchScope::AccountChats, &["a", "b", "c"]),
            ),
            (
                30_i64,
                candidato("due", SearchScope::AccountChats, &["a", "b"]),
            ),
        ]);

        let righe: Vec<i64> = ordinati.iter().map(|(riga, _)| *riga).collect();
        let nomi: Vec<&str> = ordinati
            .iter()
            .map(|(_, ordinato)| ordinato.candidate.result.public_name.as_str())
            .collect();

        assert_eq!(nomi, vec!["tre", "due", "uno"]);
        assert_eq!(
            righe,
            vec![20, 30, 10],
            "ogni riga segue il proprio candidato"
        );
    }

    /// **L'ordinamento e' uno solo.**
    #[test]
    fn ordinare_con_o_senza_carico_da_lo_stesso_ordine() {
        let insieme = || {
            vec![
                candidato("beta", SearchScope::PublicChannelPosts, &["a"]),
                candidato("alfa", SearchScope::AccountChats, &["a", "b"]),
                candidato("gamma", SearchScope::AccountChats, &["a"]),
            ]
        };

        let senza: Vec<String> = rank(insieme())
            .into_iter()
            .map(|ordinato| ordinato.candidate.result.public_name)
            .collect();
        let con: Vec<String> = super::rank_with(insieme().into_iter().map(|c| ((), c)).collect())
            .into_iter()
            .map(|(_, ordinato)| ordinato.candidate.result.public_name)
            .collect();

        assert_eq!(senza, con);
    }

    /// **I nomi dei criteri sono stabili e distinti.**

    #[test]
    fn i_criteri_hanno_nomi_stabili_e_distinti() {
        let mut visti: Vec<&str> = RankCriterion::ALL.iter().map(|c| c.as_str()).collect();
        visti.sort_unstable();
        let quanti = visti.len();
        visti.dedup();
        assert_eq!(quanti, visti.len(), "due criteri non condividono un nome");
    }

    /// **Un ordine non e' un giudizio, e il modulo non lo diventa.**
    ///
    /// Un punteggio, una misura di pericolosita' o un ordinamento per popolarita'
    /// sarebbero la stessa cosa scritta in tre modi. E un `HashMap` renderebbe
    /// l'ordine dipendente dal caso, che e' esattamente cio' che questo modulo
    /// esiste per escludere.
    #[test]
    fn il_modulo_non_assegna_punteggi_e_non_dipende_dal_caso() {
        const QUESTO_MODULO: &str = include_str!("discovery_rank.rs");

        let Some((produzione, _)) = QUESTO_MODULO.split_once("\n#[cfg(test)]\nmod tests {") else {
            panic!("il blocco delle prove non si delimita");
        };
        let codice: String = produzione
            .lines()
            .filter(|riga| !riga.trim_start().starts_with("//"))
            .collect::<Vec<&str>>()
            .join("\n");

        for vietato in [
            "punteggio",
            "score",
            "pericolos",
            "iscritt",
            "popolar",
            "affidabil",
            "HashMap",
            "Timestamp::now",
            "SystemTime",
            "rand",
            "to_lowercase",
        ] {
            assert!(
                !codice.contains(vietato),
                "«{vietato}» nell'ordinamento: un ordine non e' un giudizio, e non \
                 dipende dal caso (ADR-0078)"
            );
        }
    }
}
