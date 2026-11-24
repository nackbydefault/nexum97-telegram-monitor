//! L'aritmetica della rilevazione, e nient'altro.
//!
//! # Perché questo file è separato
//!
//! Perché è **il metodo**, ed è di questo file che si calcola l'impronta:
//! `super::SPIKE_METHOD_FINGERPRINT` ne è l'impronta SHA-256, e una prova la
//! ricalcola. Chi cambia la formula non può cambiarla di nascosto, e non deve
//! ricordarsene: se ne accorge il cancello. È la forma di ENGINE-01, applicata
//! al metodo invece che al motore.
//!
//! Se l'impronta stesse nello stesso file che la calcola, cambiarla cambierebbe
//! il file e quindi l'impronta, all'infinito.
//!
//! # Il metodo, per esteso
//!
//! Il periodo si divide in intervalli **uguali e adiacenti**. L'ultimo è quello
//! **osservato**; i precedenti sono il confronto. Per ciascuna voce:
//!
//! 1. si prende la **mediana** dei conteggi degli intervalli di confronto;
//! 2. si prende la **mediana degli scarti assoluti** da quella mediana — lo
//!    scarto tipico;
//! 3. la soglia è `mediana + moltiplicatore x scarto`;
//! 4. c'è aumento anomalo quando l'osservato **supera** la soglia e raggiunge
//!    un minimo assoluto dichiarato.
//!
//! # Perché la mediana e non la media
//!
//! Perché una sola giornata eccezionale sposta la media e alza la soglia,
//! nascondendo l'aumento successivo. La mediana non si muove: più della metà
//! degli intervalli deve cambiare perché cambi lei.
//!
//! # Perché tutto in numeri interi
//!
//! Perché i conteggi sono interi, e un numero con la virgola qui non
//! misurerebbe niente di più: introdurrebbe soltanto un valore che qualcuno
//! finirebbe per citare come «punteggio dell'anomalia». Le due divisioni che
//! servono — la mediana di un numero pari di elementi — arrotondano **per
//! difetto**, ed è dichiarato.
//!
//! # Perché esiste uno scarto minimo
//!
//! Perché su una voce rara lo scarto misurato è **zero**: in tutti gli
//! intervalli di confronto il conteggio era lo stesso. Con scarto zero la
//! soglia coincide con la mediana, e **qualunque** occorrenza in più
//! risulterebbe anomala.
//!
//! Il metodo allora usa uno **scarto minimo dichiarato**, e la frase dice che
//! lo ha fatto. Tacere la sostituzione presenterebbe come misurata una soglia
//! che è stata scelta.

/// Quanti scarti tipici sopra la mediana perché si parli di aumento anomalo.
///
/// **Tre** è la scelta di questo metodo, non una verità. Compare in ogni frase
/// insieme ai numeri da cui la soglia nasce, così che chi la ritiene sbagliata
/// veda subito su che cosa il giudizio si è formato.
pub const DEVIATION_MULTIPLIER: u32 = 3;

/// Lo scarto che si usa quando quello misurato è zero.
///
/// Senza questo minimo, una voce che compariva sempre lo stesso numero di volte
/// produrrebbe una soglia pari alla mediana, e **una** occorrenza in più
/// sarebbe «anomala».
pub const MINIMUM_DEVIATION: u32 = 1;

/// Quante occorrenze servono comunque nell'intervallo osservato.
///
/// Una voce che passa da zero a due non è un aumento anomalo: sono due
/// occorrenze. La soglia statistica da sola, su voci rarissime, direbbe di sì.
pub const MINIMUM_OBSERVED: u32 = 5;

/// Quanti intervalli di confronto servono perché una mediana sia una mediana.
///
/// **Sette.** Su tre intervalli la mediana è il valore di mezzo di tre numeri, e
/// chiamarla «il comportamento abituale» sarebbe una parola grossa per un caso.
pub const MINIMUM_BASELINE_BUCKETS: usize = 7;

/// La misura di una voce, con tutti i numeri che l'hanno prodotta.
///
/// # Perché ci sono anche gli intermedi
///
/// Perché il piano chiede che il metodo sia **spiegabile**: chi legge deve poter
/// rifare il conto. Una struttura che portasse soltanto «anomalo: sì» sarebbe
/// un verdetto, e un verdetto non si controlla.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SpikeMeasurement {
    /// Occorrenze nell'intervallo osservato.
    pub observed: u32,
    /// Mediana dei conteggi negli intervalli di confronto.
    pub median: u32,
    /// Scarto tipico **misurato**: la mediana degli scarti assoluti.
    pub measured_deviation: u32,
    /// Scarto effettivamente usato: il misurato, o il minimo dichiarato.
    pub deviation_used: u32,
    /// La soglia: mediana + moltiplicatore × scarto usato.
    pub threshold: u32,
    /// Quanti intervalli di confronto sono entrati nella mediana.
    pub baseline_buckets: usize,
}

impl SpikeMeasurement {
    /// Se l'osservato supera la soglia e raggiunge il minimo assoluto.
    ///
    /// **Supera**, non «raggiunge»: un valore esattamente pari alla soglia è
    /// ancora dentro ciò che il metodo considera abituale.
    #[must_use]
    pub const fn is_anomalous(&self) -> bool {
        self.observed > self.threshold && self.observed >= MINIMUM_OBSERVED
    }

    /// Se lo scarto misurato era zero e si è usato il minimo dichiarato.
    #[must_use]
    pub const fn used_the_declared_floor(&self) -> bool {
        self.measured_deviation == 0
    }
}

/// Misura una voce a partire dai conteggi degli intervalli.
///
/// `baseline` sono i conteggi degli intervalli di confronto, dal più vecchio;
/// `observed` è il conteggio dell'intervallo osservato, che **non** entra nella
/// mediana.
///
/// Restituisce `None` quando gli intervalli di confronto sono meno di
/// [`MINIMUM_BASELINE_BUCKETS`]: una mediana su pochi valori non descrive un
/// comportamento abituale, e chiamarla così sarebbe la parte falsa del metodo.
#[must_use]
pub fn measure(baseline: &[u32], observed: u32) -> Option<SpikeMeasurement> {
    if baseline.len() < MINIMUM_BASELINE_BUCKETS {
        return None;
    }

    let median = mediana(baseline);

    let scarti: Vec<u32> = baseline
        .iter()
        .map(|conteggio| conteggio.abs_diff(median))
        .collect();
    let measured_deviation = mediana(&scarti);

    let deviation_used = if measured_deviation == 0 {
        MINIMUM_DEVIATION
    } else {
        measured_deviation
    };

    Some(SpikeMeasurement {
        observed,
        median,
        measured_deviation,
        deviation_used,
        threshold: median.saturating_add(DEVIATION_MULTIPLIER.saturating_mul(deviation_used)),
        baseline_buckets: baseline.len(),
    })
}

/// La mediana di un insieme di conteggi.
///
/// Su un numero pari di elementi è la **media dei due centrali arrotondata per
/// difetto**: una mediana con la virgola introdurrebbe in questo metodo l'unico
/// numero non intero, e arrotondare per difetto abbassa la soglia — che è il
/// verso prudente, perché mostra qualcosa in più invece di nasconderlo.
///
/// Su un insieme vuoto è zero. Non accade: chi chiama ha già verificato che gli
/// intervalli siano abbastanza.
fn mediana(valori: &[u32]) -> u32 {
    if valori.is_empty() {
        return 0;
    }

    let mut ordinati = valori.to_vec();
    ordinati.sort_unstable();

    let meta = ordinati.len() / 2;
    if ordinati.len() % 2 == 1 {
        ordinati[meta]
    } else {
        (ordinati[meta - 1] + ordinati[meta]) / 2
    }
}

#[cfg(test)]
mod tests {
    use super::{
        DEVIATION_MULTIPLIER, MINIMUM_BASELINE_BUCKETS, MINIMUM_DEVIATION, MINIMUM_OBSERVED,
        measure, mediana,
    };

    /// Sotto il minimo di intervalli non si misura: una mediana su pochi valori
    /// non descrive un comportamento abituale.
    #[test]
    fn con_meno_intervalli_del_minimo_non_si_misura() {
        let pochi = vec![1_u32; MINIMUM_BASELINE_BUCKETS - 1];
        assert!(measure(&pochi, 100).is_none());

        let bastano = vec![1_u32; MINIMUM_BASELINE_BUCKETS];
        assert!(measure(&bastano, 100).is_some());
    }

    /// La mediana di un numero dispari è il valore di mezzo.
    #[test]
    fn la_mediana_di_un_numero_dispari_e_il_valore_di_mezzo() {
        assert_eq!(mediana(&[5, 1, 9]), 5);
        assert_eq!(mediana(&[0, 0, 0, 7, 7]), 0);
    }

    /// **La mediana di un numero pari arrotonda per difetto.**
    ///
    /// È l'unica divisione del metodo, ed è dichiarata: arrotondare per difetto
    /// abbassa la soglia, cioè mostra qualcosa in più invece di nasconderlo.
    #[test]
    fn la_mediana_di_un_numero_pari_arrotonda_per_difetto() {
        assert_eq!(mediana(&[2, 3]), 2, "2,5 arrotondato per difetto");
        assert_eq!(mediana(&[0, 0, 5, 6]), 2, "2,5 arrotondato per difetto");
    }

    /// La soglia è mediana + moltiplicatore × scarto.
    #[test]
    fn la_soglia_e_la_mediana_piu_tre_scarti() {
        // Sette intervalli con conteggi 10, 12, 10, 14, 10, 12, 10.
        // Ordinati: 10 10 10 10 12 12 14 -> mediana 10.
        // Scarti:    0  2  0  4  0  2  0 -> ordinati 0 0 0 0 2 2 4 -> mediana 0.
        // Scarto zero: si usa il minimo dichiarato.
        let Some(misura) = measure(&[10, 12, 10, 14, 10, 12, 10], 20) else {
            panic!("la misura deve riuscire");
        };

        assert_eq!(misura.median, 10);
        assert_eq!(misura.measured_deviation, 0);
        assert_eq!(misura.deviation_used, MINIMUM_DEVIATION);
        assert_eq!(
            misura.threshold,
            10 + DEVIATION_MULTIPLIER * MINIMUM_DEVIATION
        );
        assert!(misura.used_the_declared_floor());
    }

    /// Con uno scarto misurato diverso da zero, il minimo non si usa.
    #[test]
    fn con_uno_scarto_misurato_il_minimo_non_si_usa() {
        // Conteggi 0, 4, 0, 4, 0, 4, 4 -> ordinati 0 0 0 4 4 4 4 -> mediana 4.
        // Scarti 4 0 4 0 4 0 0 -> ordinati 0 0 0 0 4 4 4 -> mediana 0.
        // Serve una serie con scarto non nullo: 1 2 3 4 5 6 7 -> mediana 4,
        // scarti 3 2 1 0 1 2 3 -> ordinati 0 1 1 2 2 3 3 -> mediana 2.
        let Some(misura) = measure(&[1, 2, 3, 4, 5, 6, 7], 20) else {
            panic!("la misura deve riuscire");
        };

        assert_eq!(misura.median, 4);
        assert_eq!(misura.measured_deviation, 2);
        assert_eq!(misura.deviation_used, 2);
        assert_eq!(misura.threshold, 4 + DEVIATION_MULTIPLIER * 2);
        assert!(!misura.used_the_declared_floor());
    }

    /// **Un valore pari alla soglia non è un aumento anomalo.**
    ///
    /// La soglia va **superata**: ciò che la tocca è ancora dentro quello che
    /// il metodo considera abituale.
    #[test]
    fn un_valore_pari_alla_soglia_non_basta() {
        let Some(misura) = measure(&[10, 12, 10, 14, 10, 12, 10], 13) else {
            panic!("la misura deve riuscire");
        };

        assert_eq!(misura.threshold, 13);
        assert!(!misura.is_anomalous(), "13 non supera 13");
    }

    /// **Sotto il minimo assoluto non si dice niente.**
    ///
    /// Una voce che passa da zero a due non è un aumento anomalo: sono due
    /// occorrenze, e la soglia statistica da sola direbbe di sì.
    #[test]
    fn sotto_il_minimo_assoluto_di_occorrenze_non_si_dice_niente() {
        // Sette intervalli a zero: mediana 0, scarto 0, soglia 0 + 3 x 1 = 3.
        let Some(misura) = measure(&[0; 7], MINIMUM_OBSERVED - 1) else {
            panic!("la misura deve riuscire");
        };

        assert_eq!(misura.threshold, DEVIATION_MULTIPLIER * MINIMUM_DEVIATION);
        assert!(
            misura.observed > misura.threshold,
            "la soglia statistica sarebbe superata"
        );
        assert!(
            !misura.is_anomalous(),
            "ma il minimo assoluto di occorrenze non e' raggiunto"
        );
    }

    /// La misura porta con sé tutti gli intermedi, perché il conto si rifaccia.
    #[test]
    fn la_misura_porta_con_se_i_numeri_che_l_hanno_prodotta() {
        let Some(misura) = measure(&[1, 2, 3, 4, 5, 6, 7], 20) else {
            panic!("la misura deve riuscire");
        };

        assert_eq!(misura.observed, 20);
        assert_eq!(misura.baseline_buckets, 7);
        assert_eq!(
            misura.threshold,
            misura.median + DEVIATION_MULTIPLIER * misura.deviation_used,
            "la soglia deve essere ricalcolabile dai numeri mostrati"
        );
    }
}
