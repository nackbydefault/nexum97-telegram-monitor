//! Valutazione umana di un soggetto (PERS-05).
//!
//! # Che cos'è questa milestone, e perché è la più delicata del prodotto
//!
//! È il punto in cui **una persona scrive un giudizio su un'altra persona**.
//!
//! Tutto ciò che le milestone precedenti hanno tenuto fuori — l'attribuzione, il
//! punteggio, l'inferenza — qui non sparisce: **diventa una decisione umana**,
//! con un nome, un motivo, un istante e una traccia. La differenza fra le due
//! cose è l'intero senso della Fase 6.
//!
//! Perciò qui non c'è nulla di automatico. Nessuna funzione di questo modulo
//! **ricava** una valutazione da un dato: la valutazione arriva da fuori, da chi
//! l'ha decisa, e il modulo si limita a non lasciarla scrivere male.
//!
//! # Quattro stati, e uno solo è neutro
//!
//! `NON VALUTATO` è lo stato iniziale, e **non è un giudizio**: è l'assenza di
//! un giudizio. Gli altri tre sono giudizi, e ognuno richiede **operatore,
//! motivo, istante e audit**.
//!
//! # Perché il tipo rende impossibile «priorità alta senza motivo»
//!
//! Perché una convalida si dimentica in un secondo punto di chiamata, e questa
//! non si può dimenticare.
//!
//! [`AssessedLevel`] contiene **soltanto i tre livelli non neutri**: non esiste
//! una variante «non valutato», quindi non si può costruire un giudizio neutro
//! con un motivo, né un giudizio non neutro senza.
//!
//! E [`SubjectAssessment`] ha due forme sole: `NotAssessed`, che non porta
//! niente perché non c'è niente da giustificare, e `Assessed`, che porta
//! **tutti e quattro** i valori. **La forma «valutato senza motivo» non esiste**,
//! e il controllo negativo che prova a costruirla non compila.
//!
//! # Mai una percentuale di pericolosità
//!
//! Il congelamento lo scrive con queste parole, e i requisiti di sicurezza
//! aggiungono: nessun punteggio di pericolosità, radicalizzazione, criminalità o
//! rischio, **in nessuna forma e nemmeno spento**.
//!
//! Qui non c'è un campo numerico, e la guardia vieta **il genere** — `f64`,
//! `i64`, `usize` — non i nomi: vietare la parola «punteggio» lascerebbe passare
//! `peso`.
//!
//! # Ritirare una valutazione costa quanto darla
//!
//! Tornare a `NON VALUTATO` è un atto, e richiede un motivo come gli altri.
//!
//! Non è pignoleria: **una valutazione ritirata in silenzio non dice se sia
//! stata ritirata perché sbagliata o perché scomoda**, e sono due cose molto
//! diverse. È la ragione per cui PERS-01 chiede un motivo anche per chiudere un
//! fascicolo, e per cui una nota si ritira lasciando traccia (NOTE-01).
//!
//! # Che cosa una valutazione non è, e non deve diventare
//!
//! Non è una conseguenza di ciò che il programma ha osservato. I **segnali
//! osservati si mostrano accanto**, mai al posto suo: chi valuta li guarda e
//! decide, e la decisione resta sua.
//!
//! E nessun livello si assegna per **affiliazione politica, critica, dissenso
//! lecito o partecipazione a una manifestazione lecita**. Il prodotto non lo fa
//! perché non valuta nulla da sé; le etichette e le descrizioni di questo modulo
//! non nominano quei terreni, e una prova lo verifica.

use crate::model::reason::OperationalReason;
use crate::text::Actor;
use crate::time::Timestamp;
use crate::{AssessmentId, PersonId};

/// Un livello **non neutro**: i tre che richiedono un motivo.
///
/// # Perché «non valutato» non è qui dentro
///
/// Perché non è un giudizio, e metterlo insieme agli altri permetterebbe due
/// cose sbagliate: valutare qualcuno come «non valutato» adducendo un motivo, e
/// — molto peggio — costruire un giudizio vero passando per una variante che
/// sembra innocua.
///
/// Tenendolo fuori, **la forma «valutato senza motivo» non esiste**.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum AssessedLevel {
    /// Da approfondire.
    ToInvestigate,
    /// Di interesse.
    OfInterest,
    /// Priorità alta.
    HighPriority,
}

impl AssessedLevel {
    /// Etichetta stabile, quella che finisce nell'archivio.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ToInvestigate => "da_approfondire",
            Self::OfInterest => "di_interesse",
            Self::HighPriority => "priorita_alta",
        }
    }

    /// Come si nomina a chi legge.
    #[must_use]
    pub const fn as_label(self) -> &'static str {
        match self {
            Self::ToInvestigate => "DA APPROFONDIRE",
            Self::OfInterest => "DI INTERESSE",
            Self::HighPriority => "PRIORIT\u{c0} ALTA",
        }
    }

    /// Che cosa questo livello significa, e che cosa **non** significa.
    ///
    /// # Perché ogni livello porta la sua negazione
    ///
    /// Perché sono parole che, lette di fretta, significano più di quello che
    /// dicono. «Priorità alta» descrive **quanto lavoro merita un fascicolo**,
    /// non quanto è pericolosa una persona, e la differenza non è ovvia a chi
    /// legge un elenco.
    #[must_use]
    pub const fn as_sentence(self) -> &'static str {
        match self {
            Self::ToInvestigate => {
                "Serve altro lavoro per capire. Non afferma nulla sulla persona."
            }
            Self::OfInterest => {
                "Riguarda il lavoro in corso. Non \u{e8} un'accusa e non attribuisce \
                 responsabilit\u{e0}."
            }
            Self::HighPriority => {
                "Va guardato prima degli altri. Dice quanto lavoro merita il fascicolo, \
                 non quanto \u{e8} pericolosa una persona."
            }
        }
    }

    /// Tutti i livelli, nell'ordine in cui si mostrano.
    #[must_use]
    pub const fn all() -> &'static [Self] {
        &[Self::ToInvestigate, Self::OfInterest, Self::HighPriority]
    }
}

impl core::str::FromStr for AssessedLevel {
    type Err = crate::error::DomainError;

    /// # Perché la conversione inversa sta qui e non nell'archivio
    ///
    /// Perché l'etichetta conservata **è** parte del dominio: il giorno in cui
    /// qualcuno la cambiasse in un posto solo, le righe già scritte
    /// comincerebbero a significare un'altra cosa.
    ///
    /// # Errori
    ///
    /// Rifiuta ogni testo che non sia uno dei tre livelli. In particolare
    /// rifiuta `non_valutato`, che **non è un livello**: è l'assenza di un
    /// giudizio, e non si registra come atto.
    fn from_str(raw: &str) -> crate::error::DomainResult<Self> {
        match raw {
            "da_approfondire" => Ok(Self::ToInvestigate),
            "di_interesse" => Ok(Self::OfInterest),
            "priorita_alta" => Ok(Self::HighPriority),
            altro => Err(crate::error::unknown_variant(
                "livello di valutazione",
                altro,
            )),
        }
    }
}

/// Che cosa un operatore ha fatto.
///
/// # Perché ritirare è un atto come valutare
///
/// Perché una valutazione ritirata in silenzio non dice se sia stata ritirata
/// **perché sbagliata** o **perché scomoda**, e sono due cose molto diverse per
/// chi rilegge un fascicolo. Entrambi gli atti chiedono un motivo.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AssessmentAct {
    /// Ha dato una valutazione.
    Assess(AssessedLevel),
    /// Ha ritirato la valutazione: si torna a **NON VALUTATO**.
    Withdraw,
}

impl AssessmentAct {
    /// Etichetta stabile.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Assess(livello) => livello.as_str(),
            Self::Withdraw => "ritirata",
        }
    }

    /// Come si nomina a chi legge.
    #[must_use]
    pub const fn as_label(self) -> &'static str {
        match self {
            Self::Assess(livello) => livello.as_label(),
            Self::Withdraw => "NON VALUTATO",
        }
    }
}

/// Ciò che serve per registrare un atto di valutazione.
///
/// # Perché tutti e tre insieme, e nessuno opzionale
///
/// Perché il congelamento chiede operatore, motivo e istante per **ogni**
/// valutazione non neutra, e uno solo di essi assente renderebbe gli altri due
/// inutili: sapere *quando* senza sapere *chi* non serve a nessuno.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewAssessment {
    /// Quale soggetto.
    pub person: PersonId,
    /// Che cosa si è fatto.
    pub act: AssessmentAct,
    /// Perché.
    ///
    /// **Anche per ritirare**: vedere [`AssessmentAct`].
    pub reason: OperationalReason,
    /// Chi.
    pub by: Actor,
    /// Quando.
    pub at: Timestamp,
}

/// Un atto di valutazione registrato, con il suo identificativo.
///
/// # Perché una riga e non un campo del soggetto
///
/// Perché un campo si sovrascrive, e la valutazione precedente sparirebbe.
///
/// Chi rilegge un fascicolo deve poter vedere **come si è arrivati** alla
/// valutazione di oggi: se qualcuno l'ha alzata, chi e perché; se qualcuno
/// l'ha ritirata, altrettanto. È la disciplina di NOTE-01 applicata alla cosa
/// che ne ha più bisogno.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AssessmentEntry {
    /// Identificativo della riga.
    pub id: AssessmentId,
    /// Quale soggetto.
    pub person: PersonId,
    /// Che cosa si è fatto.
    pub act: AssessmentAct,
    /// Perché.
    pub reason: OperationalReason,
    /// Chi.
    pub by: Actor,
    /// Quando.
    pub at: Timestamp,
}

impl AssessmentEntry {
    /// L'atto, detto a chi legge.
    #[must_use]
    pub fn as_sentence(&self) -> String {
        match self.act {
            AssessmentAct::Assess(livello) => format!(
                "{} \u{2014} da {}, il {}.",
                livello.as_label(),
                self.by.as_str(),
                self.at.to_readable_utc()
            ),
            AssessmentAct::Withdraw => format!(
                "Valutazione ritirata da {}, il {}. Il soggetto torna a NON VALUTATO.",
                self.by.as_str(),
                self.at.to_readable_utc()
            ),
        }
    }
}

/// La valutazione corrente di un soggetto.
///
/// # Perché due forme e non un livello con dei campi opzionali
///
/// Perché un livello con `reason: Option<...>` renderebbe costruibile
/// «PRIORITÀ ALTA, motivo: nessuno», che è precisamente la cosa che il
/// congelamento vieta.
///
/// Qui **quella forma non esiste**: o non c'è valutazione, e allora non c'è
/// niente da giustificare, oppure c'è, e allora ci sono tutti e quattro i
/// valori.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SubjectAssessment {
    /// **NON VALUTATO.** Lo stato iniziale, e l'assenza di un giudizio.
    ///
    /// # Perché non è un giudizio
    ///
    /// Perché nessuno l'ha espresso. Un fascicolo aperto e non valutato non dice
    /// niente sulla persona: dice che qualcuno ha deciso di guardare.
    NotAssessed,
    /// Valutato, e allora **con tutti e quattro** i valori.
    Assessed {
        /// Quale livello.
        level: AssessedLevel,
        /// Perché.
        reason: OperationalReason,
        /// Chi.
        by: Actor,
        /// Quando.
        at: Timestamp,
    },
}

impl SubjectAssessment {
    /// Come si nomina a chi legge.
    #[must_use]
    pub const fn as_label(&self) -> &'static str {
        match self {
            Self::NotAssessed => "NON VALUTATO",
            Self::Assessed { level, .. } => level.as_label(),
        }
    }

    /// Se qualcuno ha espresso un giudizio.
    #[must_use]
    pub const fn is_assessed(&self) -> bool {
        matches!(self, Self::Assessed { .. })
    }

    /// La valutazione, detta a chi legge.
    ///
    /// # Che cosa questa frase dice, e che cosa non dice
    ///
    /// Dice **chi** ha valutato e **quando**. Non dice che la persona sia
    /// qualcosa: dice che qualcuno, quel giorno, ha deciso quanto lavoro merita
    /// quel fascicolo.
    #[must_use]
    pub fn as_sentence(&self) -> String {
        match self {
            Self::NotAssessed => String::from(
                "NON VALUTATO. Nessuno ha espresso un giudizio. Non significa che la persona \
                 sia estranea, e nemmeno che sia di interesse: significa che nessuno si \u{e8} \
                 espresso.",
            ),
            Self::Assessed {
                level,
                by,
                at,
                reason: _,
            } => format!(
                "{} \u{2014} valutato da {} il {}. {} \u{c8} il giudizio di una persona, non un \
                 calcolo del programma.",
                level.as_label(),
                by.as_str(),
                at.to_readable_utc(),
                level.as_sentence()
            ),
        }
    }
}

/// Ricava la valutazione corrente dalla storia degli atti.
///
/// # Perché si ricava invece di conservarla
///
/// Perché due verità divergono: un campo «valutazione corrente» accanto a una
/// storia di atti sarebbe una copia, e il giorno in cui uno dei due si muovesse
/// senza l'altro nessuno se ne accorgerebbe.
///
/// È la scelta di PERS-02, PERS-03 e PERS-04, qui applicata a un dato **scritto**
/// invece che osservato: la storia è la verità, il resto si ricava.
///
/// # L'ordine, e perché non è quello di inserimento
///
/// Conta **l'istante dell'atto**, non l'ordine in cui le righe sono finite
/// nell'archivio: a parità di istante decide l'identificativo, perché senza un
/// criterio secondario due letture darebbero due valutazioni diverse.
#[must_use]
pub fn current_assessment(history: &[AssessmentEntry]) -> SubjectAssessment {
    let ultimo = history
        .iter()
        .max_by(|a, b| a.at.cmp(&b.at).then(a.id.get().cmp(&b.id.get())));

    match ultimo {
        None => SubjectAssessment::NotAssessed,
        Some(voce) => match voce.act {
            AssessmentAct::Withdraw => SubjectAssessment::NotAssessed,
            AssessmentAct::Assess(level) => SubjectAssessment::Assessed {
                level,
                reason: voce.reason.clone(),
                by: voce.by.clone(),
                at: voce.at,
            },
        },
    }
}

#[cfg(test)]
mod tests {
    use super::{
        AssessedLevel, AssessmentAct, AssessmentEntry, SubjectAssessment, current_assessment,
    };
    use crate::model::reason::OperationalReason;
    use crate::text::Actor;
    use crate::time::Timestamp;
    use crate::{AssessmentId, PersonId};

    const ORA: Timestamp = Timestamp::from_millis(1_760_000_000_000);

    fn ragione(testo: &str) -> OperationalReason {
        let Ok(valore) = OperationalReason::try_new(testo) else {
            panic!("la ragione di prova deve essere valida");
        };
        valore
    }

    fn attore() -> Actor {
        let Ok(valore) = Actor::try_new("operatore.prova") else {
            panic!("l'attore deve essere valido");
        };
        valore
    }

    fn voce(id: i64, act: AssessmentAct, at: Timestamp) -> AssessmentEntry {
        AssessmentEntry {
            id: AssessmentId::new(id),
            person: PersonId::new(1),
            act,
            reason: ragione("richiesta dell'autorita' procedente del 4 marzo"),
            by: attore(),
            at,
        }
    }

    /// **Senza atti, il soggetto è NON VALUTATO.**
    ///
    /// # Perché conta
    ///
    /// Perché è lo stato iniziale, e deve essere quello di chi non è stato
    /// giudicato — non un valore basso su una scala, che sarebbe già un
    /// giudizio.
    #[test]
    fn senza_atti_il_soggetto_e_non_valutato() {
        assert_eq!(current_assessment(&[]), SubjectAssessment::NotAssessed);
    }

    /// **NON VALUTATO non significa «estraneo».**
    #[test]
    fn non_valutato_non_significa_estraneo() {
        let frase = SubjectAssessment::NotAssessed.as_sentence();
        assert!(frase.contains("Nessuno ha espresso un giudizio"), "{frase}");
        assert!(
            frase.contains("significa che nessuno si \u{e8} espresso"),
            "deve negare entrambe le letture: {frase}"
        );
    }

    /// **Vale l'atto più recente, e l'ordine è ripetibile.**
    #[test]
    fn vale_l_atto_piu_recente() {
        let storia = vec![
            voce(1, AssessmentAct::Assess(AssessedLevel::ToInvestigate), ORA),
            voce(
                2,
                AssessmentAct::Assess(AssessedLevel::HighPriority),
                Timestamp::from_millis(ORA.as_millis() + 100),
            ),
        ];

        let SubjectAssessment::Assessed { level, .. } = current_assessment(&storia) else {
            panic!("deve risultare valutato");
        };
        assert_eq!(level, AssessedLevel::HighPriority);

        // E l'ordine non dipende da come le righe arrivano.
        let al_contrario: Vec<AssessmentEntry> = storia.iter().rev().cloned().collect();
        assert_eq!(
            current_assessment(&storia),
            current_assessment(&al_contrario),
            "due letture danno la stessa valutazione"
        );
    }

    /// **Ritirare riporta a NON VALUTATO, e la storia resta.**
    #[test]
    fn ritirare_riporta_a_non_valutato() {
        let storia = vec![
            voce(1, AssessmentAct::Assess(AssessedLevel::HighPriority), ORA),
            voce(
                2,
                AssessmentAct::Withdraw,
                Timestamp::from_millis(ORA.as_millis() + 100),
            ),
        ];

        assert_eq!(current_assessment(&storia), SubjectAssessment::NotAssessed);
        assert_eq!(storia.len(), 2, "la storia non si accorcia");

        let frase = storia[1].as_sentence();
        assert!(frase.contains("ritirata"), "{frase}");
        assert!(frase.contains("operatore.prova"), "chi: {frase}");
    }

    /// **Una valutazione dice chi l'ha fatta, e che non è un calcolo.**
    ///
    /// # Perché è la guardia di questa milestone
    ///
    /// Perché un livello mostrato accanto a un nome, senza dire di chi è, viene
    /// letto come una misura prodotta dal programma — ed è precisamente ciò che
    /// il prodotto non fa e non deve sembrare fare.
    #[test]
    fn una_valutazione_dice_di_chi_e() {
        let storia = vec![voce(
            1,
            AssessmentAct::Assess(AssessedLevel::HighPriority),
            ORA,
        )];
        let frase = current_assessment(&storia).as_sentence();

        assert!(frase.contains("operatore.prova"), "chi: {frase}");
        assert!(
            frase.contains("giudizio di una persona, non un calcolo del programma"),
            "deve dirlo per esteso: {frase}"
        );
    }

    /// **«Priorità alta» parla del fascicolo, non della persona.**
    #[test]
    fn priorita_alta_parla_del_fascicolo_non_della_persona() {
        let frase = AssessedLevel::HighPriority.as_sentence();
        assert!(
            frase.contains("non quanto \u{e8} pericolosa una persona"),
            "deve negare la lettura sbagliata: {frase}"
        );
    }

    /// **Nessun livello nomina un terreno vietato.**
    ///
    /// # Perché conta, e che cosa questa prova NON fa
    ///
    /// Il vincolo interpretativo del prodotto vieta di equiparare dissenso
    /// politico, manifestazione lecita, appartenenza o espressione ideologica a
    /// illecito o pericolosità.
    ///
    /// Questa prova **non censura ciò che un operatore scrive**: il motivo è suo,
    /// e filtrarlo sarebbe sbagliato. Verifica che **il prodotto** non offra quei
    /// terreni come categorie: le etichette e le descrizioni sono le parole del
    /// programma, e sono l'unico posto in cui il programma può suggerire.
    #[test]
    fn nessun_livello_nomina_un_terreno_vietato() {
        for livello in AssessedLevel::all() {
            let testo = format!(
                "{} {} {}",
                livello.as_label(),
                livello.as_str(),
                livello.as_sentence()
            )
            .to_lowercase();

            for vietato in [
                "politic",
                "ideolog",
                "estremis",
                "radicaliz",
                "religios",
                "sindacal",
                "etnic",
                "manifestazion",
                "affiliazion",
                "dissens",
                "criminal",
                "sospett",
            ] {
                assert!(
                    !testo.contains(vietato),
                    "il livello «{}» nomina «{vietato}»: il prodotto non offre quel terreno come \
                     categoria",
                    livello.as_str()
                );
            }
        }
    }

    /// **Nessuna probabilità, e nessun campo numerico in cui possa stare.**
    ///
    /// # Perché la guardia vieta la forma e non le parole
    ///
    /// Perché vietare «pericolosità» o «punteggio» lascerebbe passare
    /// `peso: f64`. Qui si vieta **il genere**, comunque si chiami il campo.
    #[test]
    fn nessuna_probabilita_e_nessun_campo_numerico() {
        let produzione = codice_senza_commenti();

        for struttura in ["pub struct NewAssessment {", "pub struct AssessmentEntry {"] {
            let Some(inizio) = produzione.find(struttura) else {
                panic!("«{struttura}» deve esistere");
            };
            let campi = &produzione[inizio + struttura.len()..];
            let Some(fine) = campi.find("\n}\n") else {
                panic!("la struttura deve chiudersi");
            };
            for numerico in ["f32", "f64", "i32", "i64", "u32", "u64", "usize", "isize"] {
                assert!(
                    !campi[..fine].contains(numerico),
                    "«{struttura}» ha un campo «{numerico}»: accanto a una persona si legge come \
                     una misura"
                );
            }
        }

        for parola in ["probabilit", "percentuale", "score", "punteggio", "risk_"] {
            assert!(
                !produzione.to_lowercase().contains(parola),
                "il modulo nomina «{parola}»"
            );
        }
    }

    /// **Il modulo non ricava una valutazione da un dato.**
    ///
    /// # Perché è la guardia più importante
    ///
    /// Perché una funzione che proponesse un livello guardando i contenuti
    /// sarebbe **una valutazione automatica di una persona**, comunque la si
    /// chiamasse — «suggerimento», «bozza», «default». Il congelamento la vieta,
    /// e qui non esiste la forma: l'unico modo di ottenere un livello è che
    /// qualcuno lo passi.
    #[test]
    fn il_modulo_non_ricava_una_valutazione_da_un_dato() {
        let produzione = codice_senza_commenti();
        for automatismo in [
            "fn suggest",
            "fn propose",
            "fn suggerisci",
            "fn calcola",
            "fn compute_level",
            "fn infer",
            "AnalysisLevel",
            "AlertLevel",
        ] {
            assert!(
                !produzione.contains(automatismo),
                "il modulo nomina «{automatismo}»: una valutazione proposta dal programma e' una \
                 valutazione automatica, comunque la si chiami"
            );
        }
    }

    /// **`AssessedLevel` non ha una variante neutra.**
    ///
    /// # Perché conta
    ///
    /// Perché è ciò che rende **inesprimibile** «valutato senza motivo»: se
    /// esistesse una variante «non valutato» fra i livelli, la si potrebbe usare
    /// per costruire un giudizio passando da una porta che sembra innocua.
    #[test]
    fn i_livelli_non_hanno_una_variante_neutra() {
        assert_eq!(AssessedLevel::all().len(), 3, "tre livelli, non quattro");

        let produzione = codice_senza_commenti();
        let Some(inizio) = produzione.find("pub enum AssessedLevel {") else {
            panic!("l'enumerazione deve esistere");
        };
        let Some(fine) = produzione[inizio..].find("\n}\n") else {
            panic!("l'enumerazione deve chiudersi");
        };
        let corpo = &produzione[inizio..inizio + fine];

        for neutra in ["NotAssessed", "None", "Neutral", "Unassessed"] {
            assert!(
                !corpo.contains(neutra),
                "«{neutra}» fra i livelli renderebbe esprimibile un giudizio senza motivo"
            );
        }
    }

    /// **La forma «valutato senza motivo» non esiste.**
    #[test]
    fn valutato_senza_motivo_non_e_esprimibile() {
        let produzione = codice_senza_commenti();

        assert!(
            !produzione.contains("Option<OperationalReason>"),
            "un motivo opzionale si passa None"
        );

        // NELLA VARIANTE `Assessed` CI SONO TUTTI E QUATTRO I VALORI.
        let Some(inizio) = produzione.find("    Assessed {") else {
            panic!("la variante deve esistere");
        };
        let variante = &produzione[inizio..];
        let Some(fine) = variante.find("    },") else {
            panic!("la variante deve chiudersi");
        };
        for obbligatorio in ["level:", "reason:", "by:", "at:"] {
            assert!(
                variante[..fine].contains(obbligatorio),
                "la variante «Assessed» deve portare «{obbligatorio}»"
            );
        }
    }

    /// Il codice di produzione di questo modulo, senza commenti.
    fn codice_senza_commenti() -> String {
        let sorgente = include_str!("assessment.rs");
        let Some(taglio) = sorgente.find("#[cfg(test)]") else {
            panic!("il modulo deve avere una sezione di prove");
        };
        sorgente[..taglio]
            .lines()
            .filter(|riga| !riga.trim_start().starts_with("//"))
            .collect::<Vec<_>>()
            .join("\n")
    }
}
