//! Prove di **proprietà**: un'affermazione verificata su molti casi generati.
//!
//! # Che cosa distingue una prova di proprietà da una prova con un esempio
//!
//! Una prova con un esempio dice «su questo testo la funzione risponde così».
//! Una prova di proprietà dice **«qualunque cosa le si dia, vale questo»** — e
//! poi lo verifica su qualche migliaio di casi che nessuno ha scelto.
//!
//! Serve dove l'ingresso è **ostile o illimitato** e l'invariante è
//! **enunciabile**. Dove l'ingresso è un elenco finito di forme note, un elenco
//! finito di esempi dice di più e si legge meglio.
//!
//! # Perché il generatore è deterministico, e il seme è scritto
//!
//! Perché una prova che fallisce una volta su mille e non si sa riprodurre è
//! **peggio** di una prova che non c'è: chi la vede rossa la riesegue, la trova
//! verde, e da quel momento ha imparato che il rosso si ignora.
//!
//! Il seme è una costante di questo modulo. Due macchine, due giorni diversi,
//! due esecuzioni: gli stessi casi, nello stesso ordine, con lo stesso esito. E
//! quando una proprietà cade, il caso che l'ha fatta cadere si stampa e si
//! riottiene.
//!
//! # Perché non c'è un fuzzer, e perché non è un merito
//!
//! Un fuzzer serve dove la superficie è un **parser di byte da una rete**, e
//! questo prodotto ne ha uno. Non gira nel cancello per tre ragioni, e nessuna
//! delle tre dice che sarebbe inutile:
//!
//! - richiede una **toolchain nightly**, e il prodotto si compila e si consegna
//!   su stabile, con `--locked`;
//! - il suo tempo **non è limitato da niente**: un cancello che deve finire non
//!   può contenerlo;
//! - i suoi risultati arrivano **fuori banda**, ore o giorni dopo, e un cancello
//!   riproducibile non può dipendere da un esito che non è ancora arrivato.
//!
//! **Non averlo mai eseguito è un limite dichiarato** (HVQ-83), non una scelta
//! di cui andare fieri. La decisione completa sta in
//! `docs/adr/ADR-0112-UNA-PROVA-CHE-NON-SI-SA-RIPRODURRE-INSEGNA-A-IGNORARE-IL-ROSSO.md`.

/// Il seme del generatore.
///
/// È scritto qui perché una proprietà che cade si possa **riprodurre**: stesso
/// seme, stessi casi, stesso fallimento.
#[cfg(test)]
pub const SEME: u64 = 0x4e45_5855_4d39_37e5;

/// Quanti casi si generano per ciascuna proprietà.
///
/// # Perché un numero e non «finché non fallisce»
///
/// Perché il cancello deve **finire**. Mille casi per proprietà costano
/// millisecondi e coprono la forma dell'ingresso; un numero che cresce finché
/// qualcosa cade è un fuzzer, e un fuzzer non sta in un cancello.
#[cfg(test)]
pub const CASI: usize = 1_000;

/// Un generatore deterministico, riproducibile e senza dipendenze.
///
/// # Perché scritto a mano e non preso da una libreria
///
/// Perché il grafo delle dipendenze di questo prodotto è **un bene sorvegliato**
/// — c'è un threat model che se ne occupa, una guardia che verifica le
/// attribuzioni, e un elenco di ciò che non deve entrare. Una libreria di
/// generazione porta con sé il proprio albero, e questo modulo ha bisogno di
/// venti righe: `xorshift64*`, che è pubblico dominio e si verifica leggendolo.
#[cfg(test)]
pub struct Casuale {
    stato: u64,
}

#[cfg(test)]
impl Casuale {
    /// Un generatore che parte dal seme dichiarato.
    #[must_use]
    pub const fn dal_seme(seme: u64) -> Self {
        // LO ZERO E' L'UNICO STATO DA CUI XORSHIFT NON ESCE: resterebbe zero per
        // sempre, e ogni caso generato sarebbe identico. Si sostituisce, e si
        // dice perche'.
        Self {
            stato: if seme == 0 {
                0x9e37_79b9_7f4a_7c15
            } else {
                seme
            },
        }
    }

    /// Il prossimo valore.
    pub const fn prossimo(&mut self) -> u64 {
        let mut x = self.stato;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.stato = x;
        x.wrapping_mul(0x2545_f491_4f6c_dd1d)
    }

    /// Un intero fra zero incluso e `limite` escluso.
    pub const fn fino_a(&mut self, limite: usize) -> usize {
        if limite == 0 {
            return 0;
        }
        (self.prossimo() % (limite as u64)) as usize
    }

    /// Un testo generato dall'alfabeto dichiarato.
    ///
    /// # Perché l'alfabeto è questo
    ///
    /// Perché è ciò che arriva davvero: lettere, cifre, la punteggiatura con cui
    /// si scrivono indirizzi e identificativi, spazi, **lettere accentate** —
    /// che occupano due byte e un carattere, ed è lì che un taglio in byte
    /// spezza — e **caratteri di controllo**, che sono la forma più semplice di
    /// testo ostile.
    pub fn testo(&mut self, lunghezza_massima: usize) -> String {
        const ALFABETO: &[char] = &[
            'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's',
            't', 'u', 'v', 'z', 'A', 'B', 'C', 'E', 'V', '0', '1', '2', '3', '4', '5', '6', '7',
            '8', '9', ' ', '.', ':', '/', '-', '_', '@', '[', ']', '=', '+', '\t', '\n', 'è', 'à',
            'ù', 'ò', '€', '\u{200b}',
        ];

        let lunghezza = self.fino_a(lunghezza_massima + 1);
        let mut testo = String::with_capacity(lunghezza);
        for _ in 0..lunghezza {
            let indice = self.fino_a(ALFABETO.len());
            testo.push(ALFABETO[indice]);
        }
        testo
    }
}

#[cfg(test)]
mod tests {
    use super::{CASI, Casuale, SEME};
    use crate::model::content_history::VersionChange;
    use crate::model::discovery::{
        CandidateReason, DiscoveryQuery, DiscoveryResult, SearchScope, SourceCandidate,
    };
    use crate::model::discovery_rank::rank;
    use crate::model::indicator::{MAX_INDICATORS, MAX_TEXT_CHARS, extract};

    /// **Il generatore è riproducibile, e due generatori dal seme diverso non
    /// producono la stessa cosa.**
    ///
    /// # Perché questa prova viene prima di tutte le altre
    ///
    /// Perché è la premessa di ogni proprietà di questo modulo. Un generatore
    /// che restituisse sempre la stessa stringa — o sempre la stringa vuota —
    /// renderebbe **verdi** tutte le proprietà senza averle verificate su
    /// niente: è la stessa forma di difetto di una guardia che non guarda
    /// niente (ADR-0111).
    #[test]
    fn il_generatore_si_riproduce_e_non_e_costante() {
        let primo: Vec<String> = {
            let mut generatore = Casuale::dal_seme(SEME);
            (0..50).map(|_| generatore.testo(40)).collect()
        };
        let secondo: Vec<String> = {
            let mut generatore = Casuale::dal_seme(SEME);
            (0..50).map(|_| generatore.testo(40)).collect()
        };
        assert_eq!(
            primo, secondo,
            "lo stesso seme ha prodotto casi diversi: una proprieta' che cade non si \
             potrebbe riprodurre"
        );

        let distinti: std::collections::BTreeSet<&String> = primo.iter().collect();
        assert!(
            distinti.len() > 40,
            "su cinquanta casi ne sono usciti solo {} distinti: il generatore non genera, \
             e ogni proprieta' di questo modulo sarebbe verde senza aver verificato niente",
            distinti.len()
        );

        let altrove: Vec<String> = {
            let mut generatore = Casuale::dal_seme(SEME ^ 0xff);
            (0..50).map(|_| generatore.testo(40)).collect()
        };
        assert_ne!(
            primo, altrove,
            "due semi diversi hanno prodotto gli stessi casi: il seme non conta, e \
             cambiarlo non esplorerebbe niente di nuovo"
        );
    }

    /// **La relazione fra due versioni, qualunque siano, è vera.**
    ///
    /// # Perché è una proprietà e non un elenco di esempi
    ///
    /// Perché `VersionChange` non descrive un caso: descrive una **relazione fra
    /// due testi qualunque**, e un documento consegnato la stampa come un fatto
    /// verificabile — «il testo precedente è l'inizio del nuovo». Se la
    /// relazione restituita non valesse, il documento affermerebbe una cosa
    /// falsa su una prova, ed è il danno di R-12.
    ///
    /// La proprietà verifica **la condizione che definisce ciascuna variante**,
    /// non l'implementazione: è la stessa frase che il documento stampa.
    #[test]
    fn ogni_relazione_fra_due_versioni_vale_davvero() {
        let mut generatore = Casuale::dal_seme(SEME);

        for caso in 0..CASI {
            let prima = generatore.testo(60);
            // META' DEI CASI PARTONO DAL PRIMO TESTO, perche' due testi
            // indipendenti sono quasi sempre `Rewritten`, e le altre quattro
            // varianti non verrebbero mai esercitate.
            let dopo = match generatore.fino_a(4) {
                0 => prima.clone(),
                1 => format!("{prima}{}", generatore.testo(20)),
                2 => prima.chars().take(prima.chars().count() / 2).collect(),
                3 => format!("{}{prima}{}", generatore.testo(10), generatore.testo(10)),
                _ => generatore.testo(60),
            };

            let relazione = VersionChange::between(&prima, &dopo);
            let vale = match relazione {
                VersionChange::Identical => prima == dopo,
                VersionChange::Appended => dopo.starts_with(&prima),
                VersionChange::Truncated => prima.starts_with(&dopo),
                VersionChange::Surrounded => dopo.contains(&prima),
                // `Rewritten` e' la risposta quando nessun'altra vale, e la sua
                // condizione e' precisamente questa.
                VersionChange::Rewritten => {
                    prima != dopo
                        && !dopo.starts_with(&prima)
                        && !prima.starts_with(&dopo)
                        && !dopo.contains(&prima)
                }
            };

            assert!(
                vale,
                "caso {caso}: la relazione {relazione:?} non vale fra «{prima}» e «{dopo}». \
                 Riproducibile dal seme {SEME:#x}"
            );
        }
    }

    /// **L'estrazione degli indicatori non si guasta, è stabile e dichiara i
    /// propri tagli.**
    ///
    /// # Perché proprio qui
    ///
    /// Perché è **la funzione più esposta del prodotto**: gira sul testo dei
    /// messaggi, che viene da fuori e non ha alcuna forma garantita. Un panico
    /// qui fermerebbe un monitoraggio; un esito instabile romperebbe la
    /// correlazione, che confronta elenchi.
    #[test]
    fn l_estrazione_regge_qualunque_testo_e_dichiara_i_tagli() {
        let mut generatore = Casuale::dal_seme(SEME);

        for caso in 0..CASI {
            let testo = generatore.testo(500);
            let primo = extract(&testo);
            let secondo = extract(&testo);

            assert_eq!(
                primo, secondo,
                "caso {caso}: due estrazioni dello stesso testo hanno dato esiti diversi, e \
                 la correlazione confronta elenchi. Riproducibile dal seme {SEME:#x}"
            );
            assert!(
                primo.indicators.len() <= MAX_INDICATORS,
                "caso {caso}: l'estrazione ha restituito {} indicatori, oltre il tetto \
                 dichiarato di {MAX_INDICATORS}",
                primo.indicators.len()
            );
            assert_eq!(
                primo.text_truncated,
                testo.chars().count() > MAX_TEXT_CHARS,
                "caso {caso}: il taglio del testo e' dichiarato diverso da come e' avvenuto"
            );
            assert!(
                primo.is_partial() || !primo.indicators_truncated,
                "caso {caso}: un elenco troncato non si dichiara parziale"
            );

            // L'ORDINE E' STABILE, e la stabilita' e' la ragione per cui questa
            // funzione puo' servire a correlare.
            let mut ordinati = primo.indicators.clone();
            ordinati.sort();
            ordinati.dedup();
            assert_eq!(
                ordinati, primo.indicators,
                "caso {caso}: gli indicatori non escono ordinati e deduplicati"
            );
        }
    }

    /// **L'ordine dei candidati è totale, deterministico e idempotente.**
    ///
    /// # Perché è la promessa di PD-RANK-01
    ///
    /// «Due postazioni con la stessa versione devono produrre la stessa lista».
    /// Un ordine che dipendesse dall'ordine d'ingresso la romperebbe senza che
    /// nessuna prova con un esempio se ne accorgesse: servirebbe l'esempio
    /// giusto, e nessuno sa quale sia.
    #[test]
    fn l_ordine_dei_candidati_e_totale_e_non_dipende_dall_ingresso() {
        let mut generatore = Casuale::dal_seme(SEME);

        for caso in 0..(CASI / 10) {
            let quanti = 2 + generatore.fino_a(6);
            let mut candidati = Vec::with_capacity(quanti);
            for _ in 0..quanti {
                let Some(query) = DiscoveryQuery::try_new(&format!("q{}", generatore.fino_a(3)))
                else {
                    panic!("l'interrogazione di prova deve essere valida");
                };
                let scope = match generatore.fino_a(3) {
                    0 => SearchScope::SelectedSources,
                    1 => SearchScope::AccountChats,
                    _ => SearchScope::PublicChannelPosts,
                };
                let quanti_motivi = 1 + generatore.fino_a(3);
                let motivi: Vec<CandidateReason> = (0..quanti_motivi)
                    .filter_map(|indice| CandidateReason::try_new(&format!("motivo {indice}")))
                    .collect();
                let Some(candidato) = SourceCandidate::try_new(
                    DiscoveryResult {
                        query,
                        scope,
                        public_name: format!("nome {}", generatore.fino_a(4)),
                        public_address: None,
                    },
                    motivi,
                ) else {
                    panic!("il candidato di prova deve essere valido");
                };
                candidati.push(candidato);
            }

            let ordinati = rank(candidati.clone());
            let nomi: Vec<&str> = ordinati
                .iter()
                .map(|uno| uno.candidate.result.public_name.as_str())
                .collect();

            // DETERMINISMO: gli stessi candidati danno la stessa lista.
            let di_nuovo = rank(candidati.clone());
            let nomi_di_nuovo: Vec<&str> = di_nuovo
                .iter()
                .map(|uno| uno.candidate.result.public_name.as_str())
                .collect();
            assert_eq!(
                nomi, nomi_di_nuovo,
                "caso {caso}: due ordinamenti degli stessi candidati hanno dato liste \
                 diverse. Riproducibile dal seme {SEME:#x}"
            );

            // INDIPENDENZA DALL'INGRESSO: rovesciare l'elenco non cambia
            // l'ordine d'uscita. E' cio' che «due postazioni producono la stessa
            // lista» significa davvero.
            let mut rovesciati = candidati;
            rovesciati.reverse();
            let dal_rovescio = rank(rovesciati);
            let nomi_dal_rovescio: Vec<&str> = dal_rovescio
                .iter()
                .map(|uno| uno.candidate.result.public_name.as_str())
                .collect();
            assert_eq!(
                nomi, nomi_dal_rovescio,
                "caso {caso}: l'ordine dipende da come i candidati arrivano, e due \
                 postazioni non produrrebbero la stessa lista. Riproducibile dal seme \
                 {SEME:#x}"
            );
        }
    }
}
