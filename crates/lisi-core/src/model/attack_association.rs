//! «Termine associato alla tecnica X», e chi lo ha deciso.
//!
//! # La regola che governa questo modulo
//!
//! **Un'associazione dice che qualcuno l'ha dichiarata. Non dice che qualcuno
//! abbia fatto qualcosa.**
//!
//! La frase che questo modulo compone è:
//!
//! > Il contenuto contiene il termine «molotov», che questo ufficio ha associato
//! > alla tecnica T1234 di ATT&CK 19.2.
//!
//! Non dice che chi ha scritto quel contenuto **abbia usato** quella tecnica.
//! Dice due fatti verificabili — un termine è comparso, e una persona ha
//! dichiarato un'associazione — e li tiene separati. Due guardie sorvegliano la
//! differenza: una legge il **codice** di questo modulo, l'altra la **frase**
//! che ne esce.
//!
//! # Nessuna proposta, e nessun posto in cui farne una
//!
//! Non esiste una funzione che cerchi tecniche per testo, che le proponga, che
//! le ordini per verosimiglianza o che le chiami «candidate». È la regola di
//! PERS-06 applicata alla tassonomia: **l'identificativo si scrive**. Una
//! somiglianza applicata a un vocabolario di attacco è il modo esatto in cui un
//! riferimento diventa un'imputazione.
//!
//! # Un'associazione non alza il livello e non produce un alert
//!
//! Un riferimento tassonomico non è un segnale. Se potesse alzare il livello di
//! analisi, il prodotto direbbe «questo contenuto è più grave perché qualcuno ha
//! collegato una sua parola a una tecnica di attacco» — l'inferenza che ADR-0048
//! vieta, travestita da tassonomia. Il modulo non nomina né il livello né gli
//! alert, e una guardia lo verifica.
//!
//! La decisione completa sta in
//! `docs/adr/ADR-0059-TERMINE-ASSOCIATO-ALLA-TECNICA.md`.

use crate::error::{DomainError, DomainResult};
use crate::id::AttackAssociationId;
use crate::model::attack::AttackTechniqueId;
use crate::text::Actor;
use crate::time::Timestamp;

/// Quanti caratteri può avere il motivo di un atto.
pub const MAX_REASON_CHARS: usize = 2_000;

/// Il termine a cui un'associazione si riferisce.
///
/// # Perché la coppia, e non l'identificatore di una riga di dizionario
///
/// Perché un riscontro registra **il termine normalizzato e la sua categoria**,
/// e nient'altro. Usare la stessa coppia è l'unico modo di far combaciare le due
/// cose senza indovinare; un identificatore di riga obbligherebbe a ricostruire
/// da quale versione venga un riscontro, e la ricostruzione sarebbe ambigua.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct AssociatedTerm {
    normalised: String,
    category: String,
}

impl AssociatedTerm {
    /// Costruisce il riferimento a un termine.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se il termine o la categoria sono vuoti.
    pub fn new(normalised: &str, category: &str) -> DomainResult<Self> {
        let normalised = normalised.trim();
        let category = category.trim();
        if normalised.is_empty() {
            return Err(DomainError::Empty {
                field: "termine_associato",
            });
        }
        if category.is_empty() {
            return Err(DomainError::Empty {
                field: "categoria_termine_associato",
            });
        }
        Ok(Self {
            normalised: String::from(normalised),
            category: String::from(category),
        })
    }

    /// Il termine normalizzato, nella forma in cui un riscontro lo scrive.
    #[must_use]
    pub fn normalised(&self) -> &str {
        &self.normalised
    }

    /// La categoria.
    #[must_use]
    pub fn category(&self) -> &str {
        &self.category
    }
}

/// Un'associazione che si intende dichiarare.
///
/// # Perché il motivo è un campo e non un `Option`
///
/// Perché un riferimento tassonomico dentro un atto è forte quanto la base su
/// cui poggia, e la base qui è una persona. Senza motivo l'associazione non è
/// documentata: è soltanto avvenuta. Il controllo negativo che lo rende
/// facoltativo **non compila**.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewAttackAssociation {
    /// Il termine.
    pub term: AssociatedTerm,
    /// La tecnica, **scritta**: non proposta, non cercata, non suggerita.
    pub technique: AttackTechniqueId,
    /// Perché questo ufficio dichiara l'associazione.
    pub reason: String,
    /// Chi la dichiara.
    pub declared_by: Actor,
    /// Quando.
    pub declared_at: Timestamp,
}

impl NewAttackAssociation {
    /// Convalida l'atto prima che raggiunga l'archivio.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se il motivo è vuoto o oltre misura.
    pub fn validated(self) -> DomainResult<Self> {
        let reason = self.reason.trim();
        if reason.is_empty() {
            return Err(DomainError::Empty {
                field: "motivo_associazione_attack",
            });
        }
        if reason.chars().count() > MAX_REASON_CHARS {
            return Err(DomainError::TooLong {
                field: "motivo_associazione_attack",
                max: MAX_REASON_CHARS,
                actual: reason.chars().count(),
            });
        }
        Ok(Self {
            reason: String::from(reason),
            ..self
        })
    }
}

/// Il ritiro di un'associazione.
///
/// # Perché ritirare costa quanto dichiarare
///
/// Perché un legame sciolto in silenzio non dice se fosse sbagliato o scomodo, e
/// cancellarlo renderebbe illeggibile il lavoro fatto mentre esisteva — compresi
/// i rapporti che lo citavano. È la lezione di PERS-06.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AttackAssociationWithdrawal {
    /// Perché si ritira.
    pub reason: String,
    /// Chi ritira.
    pub withdrawn_by: Actor,
    /// Quando.
    pub withdrawn_at: Timestamp,
}

impl AttackAssociationWithdrawal {
    /// Convalida l'atto.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se il motivo è vuoto o oltre misura.
    pub fn validated(self) -> DomainResult<Self> {
        let reason = self.reason.trim();
        if reason.is_empty() {
            return Err(DomainError::Empty {
                field: "motivo_ritiro_attack",
            });
        }
        if reason.chars().count() > MAX_REASON_CHARS {
            return Err(DomainError::TooLong {
                field: "motivo_ritiro_attack",
                max: MAX_REASON_CHARS,
                actual: reason.chars().count(),
            });
        }
        Ok(Self {
            reason: String::from(reason),
            ..self
        })
    }
}

/// Un'associazione in piedi, come si legge.
///
/// Porta con sé **tutto ciò che serve a spiegarla**: il termine, la tecnica, la
/// versione di ATT&CK in cui quella tecnica significa ciò che significa, il
/// motivo di chi l'ha dichiarata, il suo nome e la data. Chi legge un
/// riferimento dentro un rapporto deve poter sapere su quale base esiste, e la
/// base è una persona.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StandingAssociation {
    id: AttackAssociationId,
    term: AssociatedTerm,
    technique: AttackTechniqueId,
    technique_name: String,
    attack_version: String,
    deprecated: bool,
    revoked: bool,
    reason: String,
    declared_by: Actor,
    declared_at: Timestamp,
}

impl StandingAssociation {
    /// Compone un'associazione leggibile.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se il nome della tecnica, la versione o il motivo
    /// sono vuoti: un'associazione che non sappia dire di quale versione sia, o
    /// perché esista, non è leggibile e non va mostrata a metà.
    pub fn new(parts: StandingAssociationParts) -> DomainResult<Self> {
        let StandingAssociationParts {
            id,
            term,
            technique,
            technique_name,
            attack_version,
            deprecated,
            revoked,
            reason,
            declared_by,
            declared_at,
        } = parts;

        for (valore, campo) in [
            (technique_name.as_str(), "nome_tecnica_associata"),
            (attack_version.as_str(), "versione_attack_associazione"),
            (reason.as_str(), "motivo_associazione_attack"),
        ] {
            if valore.trim().is_empty() {
                return Err(DomainError::Empty { field: campo });
            }
        }

        Ok(Self {
            id,
            term,
            technique,
            technique_name: String::from(technique_name.trim()),
            attack_version: String::from(attack_version.trim()),
            deprecated,
            revoked,
            reason: String::from(reason.trim()),
            declared_by,
            declared_at,
        })
    }

    /// L'identificativo dell'atto di associazione.
    #[must_use]
    pub const fn id(&self) -> AttackAssociationId {
        self.id
    }

    /// Il termine.
    #[must_use]
    pub const fn term(&self) -> &AssociatedTerm {
        &self.term
    }

    /// La tecnica.
    #[must_use]
    pub const fn technique(&self) -> &AttackTechniqueId {
        &self.technique
    }

    /// Il nome della tecnica, come lo scrive ATT&CK.
    #[must_use]
    pub fn technique_name(&self) -> &str {
        &self.technique_name
    }

    /// La versione di ATT&CK in cui quella tecnica significa ciò che significa.
    #[must_use]
    pub fn attack_version(&self) -> &str {
        &self.attack_version
    }

    /// Se ATT&CK ha deprecato la tecnica.
    #[must_use]
    pub const fn is_deprecated(&self) -> bool {
        self.deprecated
    }

    /// Se ATT&CK ha revocato la tecnica.
    #[must_use]
    pub const fn is_revoked(&self) -> bool {
        self.revoked
    }

    /// Il motivo scritto da chi l'ha dichiarata.
    #[must_use]
    pub fn reason(&self) -> &str {
        &self.reason
    }

    /// Chi l'ha dichiarata.
    #[must_use]
    pub const fn declared_by(&self) -> &Actor {
        &self.declared_by
    }

    /// Quando.
    #[must_use]
    pub const fn declared_at(&self) -> Timestamp {
        self.declared_at
    }

    /// La frase, come va scritta e come non va scritta.
    ///
    /// # Perché la compone il dominio, e in un posto solo
    ///
    /// Perché è **la milestone**. Il congelamento detta il linguaggio — «termine
    /// associato alla tecnica X», non «l'attaccante ha usato X» — e una frase
    /// composta in tre posti diversi diverge al primo che la riscrive di fretta.
    ///
    /// Se la tecnica è deprecata o revocata, **lo dice**: mostrarla senza
    /// dirlo lascerebbe credere che ATT&CK la riconosca ancora com'era.
    #[must_use]
    pub fn as_sentence(&self) -> String {
        let stato = match (self.deprecated, self.revoked) {
            (true, true) => " (deprecata e revocata in quella versione)",
            (true, false) => " (deprecata in quella versione)",
            (false, true) => " (revocata in quella versione)",
            (false, false) => "",
        };

        format!(
            "Il termine «{termine}» è associato alla tecnica {tecnica} «{nome}» di \
             ATT&CK {versione}{stato}. L'associazione è stata dichiarata da {chi}. \
             Dice che questo ufficio ha collegato quel termine a quella tecnica. Non dice \
             che qualcuno l'abbia impiegata, né che sia accaduto qualcosa.",
            termine = self.term.normalised(),
            tecnica = self.technique.as_str(),
            nome = self.technique_name,
            versione = self.attack_version,
            chi = self.declared_by.as_str(),
        )
    }
}

/// I pezzi con cui si compone un'associazione leggibile.
///
/// Una struttura e non nove argomenti: sono i campi di una cosa sola, e due
/// stringhe adiacenti dello stesso tipo si scambiano senza che il compilatore
/// dica niente.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StandingAssociationParts {
    /// L'identificativo dell'atto di associazione: serve a dire quale si ritira
    /// (PR-14, ADR-0130).
    pub id: AttackAssociationId,
    /// Il termine.
    pub term: AssociatedTerm,
    /// La tecnica.
    pub technique: AttackTechniqueId,
    /// Il nome della tecnica.
    pub technique_name: String,
    /// La versione di ATT&CK.
    pub attack_version: String,
    /// Se la tecnica è deprecata in quella versione.
    pub deprecated: bool,
    /// Se la tecnica è revocata in quella versione.
    pub revoked: bool,
    /// Il motivo.
    pub reason: String,
    /// Chi ha dichiarato.
    pub declared_by: Actor,
    /// Quando.
    pub declared_at: Timestamp,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn attore() -> Actor {
        let Ok(attore) = Actor::try_new("operatore.prova") else {
            panic!("l'attore di prova deve essere valido");
        };
        attore
    }

    fn termine() -> AssociatedTerm {
        let Ok(termine) = AssociatedTerm::new("molotov", "oggetto") else {
            panic!("il termine di prova deve essere valido");
        };
        termine
    }

    fn tecnica() -> AttackTechniqueId {
        let Ok(tecnica) = AttackTechniqueId::try_new("T1234") else {
            panic!("l'identificativo di prova deve essere valido");
        };
        tecnica
    }

    fn associazione(deprecated: bool, revoked: bool) -> StandingAssociation {
        let Ok(associazione) = StandingAssociation::new(StandingAssociationParts {
            id: AttackAssociationId::new(1),
            term: termine(),
            technique: tecnica(),
            technique_name: String::from("Nome della tecnica"),
            attack_version: String::from("19.2"),
            deprecated,
            revoked,
            reason: String::from("il termine ricorre nei materiali che descrivono quella tecnica"),
            declared_by: attore(),
            declared_at: Timestamp::from_millis(1_757_000_000_000),
        }) else {
            panic!("l'associazione di prova deve essere valida");
        };
        associazione
    }

    /// **Un'associazione senza motivo non si dichiara.**
    #[test]
    fn un_associazione_senza_motivo_non_si_dichiara() {
        for motivo in ["", "   ", "\t\n"] {
            let atto = NewAttackAssociation {
                term: termine(),
                technique: tecnica(),
                reason: String::from(motivo),
                declared_by: attore(),
                declared_at: Timestamp::from_millis(0),
            };
            assert!(matches!(
                atto.validated(),
                Err(DomainError::Empty {
                    field: "motivo_associazione_attack"
                })
            ));
        }
    }

    /// **E nemmeno un ritiro senza motivo.**
    #[test]
    fn un_ritiro_senza_motivo_non_si_registra() {
        let atto = AttackAssociationWithdrawal {
            reason: String::from("  "),
            withdrawn_by: attore(),
            withdrawn_at: Timestamp::from_millis(0),
        };
        assert!(matches!(
            atto.validated(),
            Err(DomainError::Empty {
                field: "motivo_ritiro_attack"
            })
        ));
    }

    #[test]
    fn un_motivo_oltre_misura_si_rifiuta() {
        let atto = NewAttackAssociation {
            term: termine(),
            technique: tecnica(),
            reason: "a".repeat(MAX_REASON_CHARS + 1),
            declared_by: attore(),
            declared_at: Timestamp::from_millis(0),
        };
        assert!(matches!(atto.validated(), Err(DomainError::TooLong { .. })));
    }

    /// **La frase dice che qualcuno ha dichiarato, non che qualcuno ha fatto.**
    ///
    /// È il cuore della milestone: il congelamento detta «termine associato alla
    /// tecnica X», non «l'attaccante ha usato X».
    #[test]
    fn la_frase_non_attribuisce_a_nessuno() {
        let frase = associazione(false, false).as_sentence();

        assert!(frase.contains("è associato alla tecnica T1234"));
        assert!(frase.contains("dichiarata da operatore.prova"));
        assert!(
            frase
                .to_lowercase()
                .contains("non dice che qualcuno l'abbia impiegata")
        );

        for vietato in [
            "ha usato",
            "ha impiegato",
            "ha eseguito",
            "l'attaccante",
            "l'autore ha",
            "responsabile",
            "colpevole",
            "attribuit",
            "used the technique",
            "adversary",
        ] {
            assert!(
                !frase.to_lowercase().contains(vietato),
                "la frase non deve contenere «{vietato}»: {frase}"
            );
        }
    }

    /// Una tecnica deprecata o revocata lo dichiara nella frase.
    #[test]
    fn una_tecnica_deprecata_lo_dichiara() {
        assert!(
            associazione(true, false)
                .as_sentence()
                .contains("(deprecata in quella versione)")
        );
        assert!(
            associazione(false, true)
                .as_sentence()
                .contains("(revocata in quella versione)")
        );
        assert!(
            associazione(true, true)
                .as_sentence()
                .contains("(deprecata e revocata in quella versione)")
        );
        assert!(!associazione(false, false).as_sentence().contains("("));
    }

    /// La frase dice **di quale versione** è la tecnica.
    #[test]
    fn la_frase_dice_di_quale_versione_e_la_tecnica() {
        assert!(
            associazione(false, false)
                .as_sentence()
                .contains("ATT&CK 19.2")
        );
    }

    /// Un'associazione senza versione o senza nome non è leggibile.
    #[test]
    fn un_associazione_senza_versione_non_si_compone() {
        let Err(errore) = StandingAssociation::new(StandingAssociationParts {
            id: AttackAssociationId::new(1),
            term: termine(),
            technique: tecnica(),
            technique_name: String::from("Nome"),
            attack_version: String::new(),
            deprecated: false,
            revoked: false,
            reason: String::from("motivo"),
            declared_by: attore(),
            declared_at: Timestamp::from_millis(0),
        }) else {
            panic!("un'associazione senza versione non doveva comporsi");
        };
        assert!(matches!(
            errore,
            DomainError::Empty {
                field: "versione_attack_associazione"
            }
        ));
    }

    /// Il termine porta la propria categoria, perché la stessa parola in due
    /// categorie diverse è due termini diversi.
    #[test]
    fn un_termine_senza_categoria_non_si_costruisce() {
        assert!(matches!(
            AssociatedTerm::new("molotov", ""),
            Err(DomainError::Empty {
                field: "categoria_termine_associato"
            })
        ));
    }

    /// **Il modulo non propone, non cerca e non somiglia.**
    ///
    /// La guardia legge il **codice** e non i commenti: è la regola di PERS-06
    /// applicata alla tassonomia. Se un giorno qualcuno aggiungesse una funzione
    /// che cerca tecniche per testo, questa prova lo direbbe prima che quella
    /// funzione arrivi davanti a una persona.
    #[test]
    fn il_modulo_non_propone_e_non_somiglia() {
        for vietato in [
            "suggest",
            "suggerisc",
            "propos",
            "proponi",
            "candidat",
            "similar",
            "somiglia",
            "score",
            "punteggio",
            "ranking",
            "confidence",
            "confidenza",
            "AnalysisLevel",
            "Alert",
        ] {
            assert!(
                !codice_di_produzione().contains(vietato),
                "il modulo delle associazioni non deve nominare «{vietato}»: \
                 una proposta è il modo in cui un riferimento diventa un'imputazione, \
                 e un livello è il modo in cui diventa un giudizio"
            );
        }
    }

    /// **E non attribuisce, nemmeno nel codice.**
    #[test]
    fn il_modulo_non_nomina_l_attribuzione() {
        let codice = codice_di_produzione().to_lowercase();
        for vietato in ["ha usato", "ha impiegato", "attaccante", "adversary_used"] {
            assert!(
                !codice.contains(vietato),
                "il modulo non deve nominare «{vietato}»"
            );
        }
    }

    /// Il codice di produzione del modulo, senza commenti e senza le prove.
    ///
    /// Il modulo di prova si taglia via: qui sotto l'elenco delle parole vietate
    /// è scritto per esteso, ed è l'unico posto in cui devono comparire.
    fn codice_di_produzione() -> String {
        let sorgente = include_str!("attack_association.rs");
        let produzione = sorgente
            .split_once("\n#[cfg(test)]")
            .map_or(sorgente, |(prima, _)| prima);
        produzione
            .lines()
            .filter(|riga| {
                let trimmed = riga.trim_start();
                !trimmed.starts_with("//") && !trimmed.starts_with("///")
            })
            .collect::<Vec<&str>>()
            .join("\n")
    }
}
