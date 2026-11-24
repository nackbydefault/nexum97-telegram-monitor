//! La fotografia locale di MITRE ATT&CK: le tecniche e le tattiche.
//!
//! # La regola che governa questo modulo
//!
//! **Di ATT&CK questo prodotto prende un vocabolario di comportamenti, non un
//! elenco di attori.**
//!
//! Il pacchetto ufficiale contiene anche gruppi di attaccanti, campagne,
//! malware e strumenti, legati fra loro da migliaia di relazioni. Qui non
//! esiste un tipo per rappresentarli, e nell'archivio non esiste una tabella in
//! cui metterli: **ciò che non entra non può essere mostrato per errore**.
//!
//! Una tecnica è una descrizione — «esecuzione di comandi tramite interprete» —
//! e nominarla non dice nulla su nessuno. Un gruppo è un'attribuzione fatta da
//! qualcun altro, e importarla metterebbe dentro NEXUM il vocabolario che tutto
//! il prodotto rifiuta.
//!
//! # Perché una fotografia senza attribuzione non è costruibile
//!
//! Perché la licenza di MITRE concede l'uso «provided that you reproduce
//! MITRE's copyright designation and this license in any such copy». È un
//! obbligo di conformità, non una cortesia, e un obbligo di conformità deve
//! poter essere verificato da un test — la stessa disciplina di ADR-0005 per
//! Slint. Percio' il costruttore **non la riceve**: ogni fotografia porta
//! [`MITRE_ATTRIBUTION`], e non esiste un modo di costruirne una che ne porti
//! un'altra o nessuna. Il testo integrale della licenza e' invece un argomento,
//! perche' e' quello che si e' davvero scaricato, e il servizio rifiuta
//! l'importazione se quel testo non contiene piu' la frase che il prodotto
//! conosce.
//!
//! La decisione completa sta in
//! `docs/adr/ADR-0058-LA-FOTOGRAFIA-DI-ATT-E-CK.md`.

use crate::error::{DomainError, DomainResult};

/// La designazione di copyright che ogni copia deve riprodurre.
///
/// # Perche' e' una costante e non un dato letto
///
/// Perche' e' una CONDIZIONE della licenza, non un contorno: MITRE concede
/// l'uso «provided that you reproduce MITRE's copyright designation and this
/// license in any such copy». Una costante si puo' verificare - il servizio
/// controlla che il testo scaricato la contenga ancora, e rifiuta
/// l'importazione se non c'e' piu' - mentre un dato estratto a runtime dal
/// testo di terze parti cambierebbe forma insieme a quel testo, in silenzio.
///
/// La frase e' riprodotta parola per parola da `LICENSE.txt` di
/// `mitre-attack/attack-stix-data`. Non si abbrevia, non si traduce.
pub const MITRE_ATTRIBUTION: &str = "© 2026 The MITRE Corporation. This work is reproduced and distributed with the permission of The MITRE Corporation.";

/// Quanti caratteri di una descrizione si conservano.
///
/// Le descrizioni di ATT&CK sono lunghe e contengono citazioni: se ne conserva
/// abbastanza perché una persona capisca di che cosa si tratti, e il
/// troncamento **si dichiara** invece di essere silenzioso.
pub const MAX_DESCRIPTION_CHARS: usize = 4_000;

/// Quanti caratteri di un nome si conservano.
pub const MAX_NAME_CHARS: usize = 256;

/// Quante tecniche una fotografia può contenere.
///
/// ATT&CK Enterprise 19.2 ne ha 858. Il tetto non serve a limitare MITRE:
/// serve a rifiutare un file che dice di essere ATT&CK e non lo è.
pub const MAX_TECHNIQUES: usize = 20_000;

/// Quante tattiche una fotografia può contenere.
pub const MAX_TACTICS: usize = 1_000;

/// Identificativo di una tecnica: `T1059` oppure `T1059.001`.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct AttackTechniqueId(String);

impl AttackTechniqueId {
    /// Convalida la forma di un identificativo di tecnica.
    ///
    /// # Perché la forma si convalida invece di fidarsi
    ///
    /// Perché il pacchetto arriva da fuori, e un identificativo che non ha la
    /// forma di un identificativo finirebbe dentro un documento con l'aria di
    /// esserlo. Chi rileggesse quel documento cercherebbe su
    /// `attack.mitre.org` una tecnica che non esiste.
    ///
    /// # Errori
    ///
    /// Restituisce [`DomainError::InvalidAttackElement`] se la forma non è quella.
    pub fn try_new(raw: &str) -> DomainResult<Self> {
        let raw = raw.trim();
        let Some(resto) = raw.strip_prefix('T') else {
            return Err(DomainError::InvalidAttackElement {
                reason: "un identificativo di tecnica ha la forma T0000 o T0000.000",
            });
        };

        let (base, sotto) = match resto.split_once('.') {
            Some((base, sotto)) => (base, Some(sotto)),
            None => (resto, None),
        };

        // Quattro cifre per la tecnica, tre per la sottotecnica: e' la forma
        // che ATT&CK usa, e accettarne un'altra significherebbe accettare
        // qualcosa che ATT&CK non ha prodotto.
        if base.len() != 4 || !base.chars().all(|c| c.is_ascii_digit()) {
            return Err(DomainError::InvalidAttackElement {
                reason: "un identificativo di tecnica ha la forma T0000 o T0000.000",
            });
        }
        if let Some(sotto) = sotto
            && (sotto.len() != 3 || !sotto.chars().all(|c| c.is_ascii_digit()))
        {
            return Err(DomainError::InvalidAttackElement {
                reason: "un identificativo di tecnica ha la forma T0000 o T0000.000",
            });
        }

        Ok(Self(String::from(raw)))
    }

    /// La forma testuale, quella che finisce in un documento.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Se è una sottotecnica.
    #[must_use]
    pub fn is_subtechnique(&self) -> bool {
        self.0.contains('.')
    }

    /// L'identificativo della tecnica madre, se questa è una sottotecnica.
    #[must_use]
    pub fn parent(&self) -> Option<Self> {
        let (base, _) = self.0.split_once('.')?;
        Some(Self(String::from(base)))
    }
}

/// Identificativo di una tattica: `TA0004`.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct AttackTacticId(String);

impl AttackTacticId {
    /// Convalida la forma di un identificativo di tattica.
    ///
    /// # Errori
    ///
    /// Restituisce [`DomainError::InvalidAttackElement`] se la forma non è quella.
    pub fn try_new(raw: &str) -> DomainResult<Self> {
        let raw = raw.trim();
        let Some(cifre) = raw.strip_prefix("TA") else {
            return Err(DomainError::InvalidAttackElement {
                reason: "un identificativo di tattica ha la forma TA0000",
            });
        };
        if cifre.len() != 4 || !cifre.chars().all(|c| c.is_ascii_digit()) {
            return Err(DomainError::InvalidAttackElement {
                reason: "un identificativo di tattica ha la forma TA0000",
            });
        }
        Ok(Self(String::from(raw)))
    }

    /// La forma testuale.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Una tattica: il capitolo sotto cui le tecniche stanno.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AttackTactic {
    id: AttackTacticId,
    shortname: String,
    name: String,
    description: String,
}

impl AttackTactic {
    /// Costruisce una tattica.
    ///
    /// # Perché tre nomi e non uno
    ///
    /// Perché servono a tre cose diverse: `shortname` è la chiave con cui le
    /// tecniche la nominano dentro il pacchetto (`privilege-escalation`),
    /// `name` è ciò che una persona legge («Privilege Escalation»), e l'id è
    /// ciò con cui la si cita (`TA0004`). Sceglierne uno solo obbligherebbe a
    /// ricostruire gli altri due, e ricostruire un nome significa inventarlo.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se il nome breve o il nome sono vuoti.
    pub fn new(
        id: AttackTacticId,
        shortname: &str,
        name: &str,
        description: &str,
    ) -> DomainResult<Self> {
        let shortname = shortname.trim();
        let name = name.trim();
        if shortname.is_empty() {
            return Err(DomainError::Empty {
                field: "nome_breve_tattica",
            });
        }
        if name.is_empty() {
            return Err(DomainError::Empty {
                field: "nome_tattica",
            });
        }

        Ok(Self {
            id,
            shortname: String::from(shortname),
            name: String::from(name),
            description: truncate(description, MAX_DESCRIPTION_CHARS),
        })
    }

    /// L'identificativo.
    #[must_use]
    pub const fn id(&self) -> &AttackTacticId {
        &self.id
    }

    /// Il nome breve, quello con cui le tecniche la nominano.
    #[must_use]
    pub fn shortname(&self) -> &str {
        &self.shortname
    }

    /// Il nome leggibile.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// La descrizione, troncata.
    #[must_use]
    pub fn description(&self) -> &str {
        &self.description
    }
}

/// Una tecnica.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AttackTechnique {
    id: AttackTechniqueId,
    name: String,
    description: String,
    tactics: Vec<String>,
    deprecated: bool,
    revoked: bool,
    object_version: String,
    url: String,
}

/// Una tecnica come si legge dal pacchetto, prima di essere convalidata.
///
/// # Perché una struttura e non otto argomenti
///
/// Perché non sono otto scelte: sono i campi **di una cosa sola**, letti tutti
/// dallo stesso oggetto del pacchetto. È l'idioma che il prodotto usa già per
/// ciò che sta per essere creato — `NewContent`, `NewSession`, `NewExport` — e
/// toglie di mezzo il rischio di scambiare fra loro due argomenti dello stesso
/// tipo, che qui sarebbero il nome e la descrizione.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewAttackTechnique<'a> {
    /// L'identificativo, già convalidato.
    pub id: AttackTechniqueId,
    /// Il nome.
    pub name: &'a str,
    /// La descrizione, che verrà troncata.
    pub description: &'a str,
    /// I nomi brevi delle tattiche a cui appartiene.
    pub tactics: Vec<String>,
    /// Se ATT&CK l'ha deprecata.
    pub deprecated: bool,
    /// Se ATT&CK l'ha revocata.
    ///
    /// **Non è la stessa cosa di `deprecated`**, e ATT&CK le tiene distinte:
    /// una tecnica revocata è stata sostituita da un'altra, una deprecata è
    /// stata ritirata. Possono valere entrambe.
    pub revoked: bool,
    /// La versione **dell'oggetto**, che non è quella della fotografia.
    pub object_version: &'a str,
    /// L'indirizzo della pagina ufficiale.
    pub url: &'a str,
}

impl AttackTechnique {
    /// Costruisce una tecnica.
    ///
    /// # Perché `deprecated` e `revoked` si conservano
    ///
    /// Perché ATT&CK **marca** ciò che ha deprecato o revocato invece di
    /// toglierlo, e un documento vecchio che cita una tecnica poi deprecata
    /// deve restare leggibile. Saltarla qui la farebbe sparire; mostrarla senza
    /// dirlo sarebbe un difetto di chi la mostra.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se il nome è vuoto.
    pub fn new(new: NewAttackTechnique<'_>) -> DomainResult<Self> {
        let NewAttackTechnique {
            id,
            name,
            description,
            tactics,
            deprecated,
            revoked,
            object_version,
            url,
        } = new;
        let name = name.trim();
        if name.is_empty() {
            return Err(DomainError::Empty {
                field: "nome_tecnica",
            });
        }

        let mut tactics: Vec<String> = tactics
            .into_iter()
            .map(|tactic| String::from(tactic.trim()))
            .filter(|tactic| !tactic.is_empty())
            .collect();
        // Ordine stabile e nessun doppione: due letture della stessa fotografia
        // devono dare la stessa riga.
        tactics.sort();
        tactics.dedup();

        Ok(Self {
            id,
            name: truncate(name, MAX_NAME_CHARS),
            description: truncate(description, MAX_DESCRIPTION_CHARS),
            tactics,
            deprecated,
            revoked,
            object_version: String::from(object_version.trim()),
            url: String::from(url.trim()),
        })
    }

    /// L'identificativo.
    #[must_use]
    pub const fn id(&self) -> &AttackTechniqueId {
        &self.id
    }

    /// Il nome.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// La descrizione, troncata.
    #[must_use]
    pub fn description(&self) -> &str {
        &self.description
    }

    /// I nomi brevi delle tattiche a cui appartiene, in ordine stabile.
    #[must_use]
    pub fn tactics(&self) -> &[String] {
        &self.tactics
    }

    /// Se ATT&CK l'ha deprecata.
    #[must_use]
    pub const fn is_deprecated(&self) -> bool {
        self.deprecated
    }

    /// Se ATT&CK l'ha revocata.
    #[must_use]
    pub const fn is_revoked(&self) -> bool {
        self.revoked
    }

    /// La versione **dell'oggetto**, che non è quella della fotografia.
    #[must_use]
    pub fn object_version(&self) -> &str {
        &self.object_version
    }

    /// L'indirizzo della pagina ufficiale.
    ///
    /// **Si conserva, non si apre.** Aprirlo è un gesto di una persona
    /// (ADR-0018).
    #[must_use]
    pub fn url(&self) -> &str {
        &self.url
    }
}

/// La fotografia: che cosa si è preso, da dove, e con quale obbligo.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AttackSnapshot {
    domain: String,
    attack_version: String,
    spec_version: String,
    license_text: String,
    tactics: Vec<AttackTactic>,
    techniques: Vec<AttackTechnique>,
}

impl AttackSnapshot {
    /// Costruisce una fotografia.
    ///
    /// # Perché l'attribuzione non è un argomento
    ///
    /// Perché la licenza di MITRE concede l'uso **a condizione** che ogni copia
    /// riproduca la designazione di copyright. Se fosse un argomento, esisterebbe
    /// un modo di scriverne una sbagliata, o di passarne una vuota e vederla
    /// rifiutata a tempo d'esecuzione.
    ///
    /// Non è un argomento: ogni fotografia porta [`MITRE_ATTRIBUTION`], e **una
    /// fotografia senza attribuzione non è esprimibile**. Che il testo di
    /// licenza scaricato contenga ancora quella frase lo verifica il servizio,
    /// che rifiuta l'importazione se MITRE l'ha cambiata.
    ///
    /// Il testo integrale della licenza resta un argomento, perché è quello
    /// che si è davvero scaricato, e va conservato com'è.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se un campo obbligatorio è vuoto, se non c'è
    /// alcuna tecnica, se i tetti sono superati, o se una tecnica nomina una
    /// tattica che la fotografia non contiene.
    pub fn new(
        domain: &str,
        attack_version: &str,
        spec_version: &str,
        license_text: &str,
        tactics: Vec<AttackTactic>,
        techniques: Vec<AttackTechnique>,
    ) -> DomainResult<Self> {
        for (valore, campo) in [
            (domain, "dominio_attack"),
            (attack_version, "versione_attack"),
            (spec_version, "versione_specifica_attack"),
            (license_text, "licenza_attack"),
        ] {
            if valore.trim().is_empty() {
                return Err(DomainError::Empty { field: campo });
            }
        }

        // UNA FOTOGRAFIA SENZA TECNICHE NON E' UNA FOTOGRAFIA.
        //
        // Sarebbe il risultato di un file che si e' letto ma non si e' capito,
        // e una fotografia vuota importata in silenzio farebbe sembrare che
        // ATT&CK non conosca nulla.
        if techniques.is_empty() {
            return Err(DomainError::Empty {
                field: "tecniche_attack",
            });
        }
        if techniques.len() > MAX_TECHNIQUES || tactics.len() > MAX_TACTICS {
            return Err(DomainError::InvalidAttackElement {
                reason: "la fotografia dichiara più tecniche o tattiche di quante \
                         ATT&CK ne abbia mai avute",
            });
        }

        // OGNI TATTICA NOMINATA DEVE ESISTERE.
        //
        // Una tecnica che rimanda a una tattica assente e' una riga che, letta,
        // dice «appartiene a qualcosa» senza poter dire a che cosa. Meglio
        // rifiutare l'intera fotografia che importarne una che risponde a meta'.
        for technique in &techniques {
            for tactic in technique.tactics() {
                if !tactics.iter().any(|nota| nota.shortname() == tactic) {
                    return Err(DomainError::InvalidAttackElement {
                        reason: "una tecnica nomina una tattica che la fotografia non contiene",
                    });
                }
            }
        }

        Ok(Self {
            domain: String::from(domain.trim()),
            attack_version: String::from(attack_version.trim()),
            spec_version: String::from(spec_version.trim()),
            license_text: String::from(license_text.trim()),
            tactics,
            techniques,
        })
    }

    /// Il dominio ATT&CK.
    #[must_use]
    pub fn domain(&self) -> &str {
        &self.domain
    }

    /// La versione di ATT&CK.
    #[must_use]
    pub fn attack_version(&self) -> &str {
        &self.attack_version
    }

    /// La versione della specifica ATT&CK.
    #[must_use]
    pub fn spec_version(&self) -> &str {
        &self.spec_version
    }

    /// La designazione di copyright che ogni copia deve riprodurre.
    ///
    /// È [`MITRE_ATTRIBUTION`], sempre: non c'è un modo di costruire una
    /// fotografia che ne porti un'altra, o nessuna.
    #[must_use]
    pub const fn attribution(&self) -> &'static str {
        MITRE_ATTRIBUTION
    }

    /// Il testo integrale della licenza.
    #[must_use]
    pub fn license_text(&self) -> &str {
        &self.license_text
    }

    /// Le tattiche.
    #[must_use]
    pub fn tactics(&self) -> &[AttackTactic] {
        &self.tactics
    }

    /// Le tecniche.
    #[must_use]
    pub fn techniques(&self) -> &[AttackTechnique] {
        &self.techniques
    }
}

/// Tronca un testo a un numero di **caratteri**, non di byte.
///
/// Tagliare in byte spezzerebbe una lettera accentata a metà: è la stessa
/// ragione per cui lo Storico taglia le anteprime in caratteri.
fn truncate(raw: &str, max: usize) -> String {
    let raw = raw.trim();
    if raw.chars().count() <= max {
        return String::from(raw);
    }
    raw.chars().take(max).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tattica(id: &str, shortname: &str) -> AttackTactic {
        let Ok(id) = AttackTacticId::try_new(id) else {
            panic!("l'identificativo di prova deve essere valido");
        };
        let Ok(tattica) = AttackTactic::new(id, shortname, "Nome Leggibile", "descrizione") else {
            panic!("la tattica di prova deve essere valida");
        };
        tattica
    }

    fn tecnica(id: &str, tactics: &[&str]) -> AttackTechnique {
        let Ok(id) = AttackTechniqueId::try_new(id) else {
            panic!("l'identificativo di prova deve essere valido");
        };
        let Ok(tecnica) = AttackTechnique::new(NewAttackTechnique {
            id,
            name: "Nome tecnica",
            description: "descrizione",
            tactics: tactics.iter().map(|t| String::from(*t)).collect(),
            deprecated: false,
            revoked: false,
            object_version: "1.0",
            url: "https://attack.mitre.org/techniques/T1059",
        }) else {
            panic!("la tecnica di prova deve essere valida");
        };
        tecnica
    }

    fn fotografia(license: &str, techniques: Vec<AttackTechnique>) -> DomainResult<AttackSnapshot> {
        AttackSnapshot::new(
            "enterprise-attack",
            "19.2",
            "3.3.0",
            license,
            vec![tattica("TA0002", "execution")],
            techniques,
        )
    }

    #[test]
    fn un_identificativo_di_tecnica_ben_formato_e_accettato() {
        for valore in ["T1059", "T1059.001", "T0001", "T9999.999"] {
            assert!(
                AttackTechniqueId::try_new(valore).is_ok(),
                "«{valore}» doveva essere accettato"
            );
        }
    }

    /// **Un identificativo che non ha la forma di un identificativo si rifiuta.**
    ///
    /// Finirebbe dentro un documento con l'aria di esserlo, e chi lo rileggesse
    /// cercherebbe una tecnica che non esiste.
    #[test]
    fn un_identificativo_di_tecnica_deformato_si_rifiuta() {
        for valore in [
            "1059",
            "T105",
            "T10590",
            "TA0002",
            "T1059.1",
            "T1059.0011",
            "T1059.",
            "Tabcd",
            "T1059.abc",
            "",
        ] {
            assert!(
                AttackTechniqueId::try_new(valore).is_err(),
                "«{valore}» non doveva essere accettato"
            );
        }
    }

    #[test]
    fn una_sottotecnica_conosce_la_propria_madre() {
        let Ok(id) = AttackTechniqueId::try_new("T1059.001") else {
            panic!("l'identificativo deve essere valido");
        };
        assert!(id.is_subtechnique());
        assert_eq!(
            id.parent().map(|p| String::from(p.as_str())),
            Some(String::from("T1059"))
        );

        let Ok(madre) = AttackTechniqueId::try_new("T1059") else {
            panic!("l'identificativo deve essere valido");
        };
        assert!(!madre.is_subtechnique());
        assert_eq!(madre.parent(), None);
    }

    #[test]
    fn un_identificativo_di_tattica_deformato_si_rifiuta() {
        for valore in ["TA002", "TA00002", "T0002", "TAxxxx", ""] {
            assert!(
                AttackTacticId::try_new(valore).is_err(),
                "«{valore}» non doveva essere accettato"
            );
        }
    }

    /// **Una fotografia senza attribuzione non è esprimibile.**
    ///
    /// La licenza di MITRE concede l'uso a condizione che ogni copia riproduca
    /// la designazione di copyright. Il costruttore **non la riceve**: non c'è
    /// un modo di passarne una vuota, una sbagliata o un'altra. Il controllo
    /// negativo che la rende un argomento non compila, e questa prova verifica
    /// che ciò che ogni fotografia porta sia esattamente la frase di MITRE.
    #[test]
    fn ogni_fotografia_porta_la_designazione_di_copyright_di_mitre() {
        let Ok(snapshot) = fotografia("licenza", vec![tecnica("T1059", &["execution"])]) else {
            panic!("la fotografia di prova deve essere valida");
        };
        assert_eq!(snapshot.attribution(), MITRE_ATTRIBUTION);
        assert!(snapshot.attribution().contains("The MITRE Corporation"));
        assert!(
            snapshot
                .attribution()
                .contains("reproduced and distributed with the permission")
        );
    }

    /// **E nemmeno una senza il testo della licenza.**
    #[test]
    fn una_fotografia_senza_licenza_non_si_costruisce() {
        assert!(matches!(
            fotografia("", vec![tecnica("T1059", &["execution"])]),
            Err(DomainError::Empty {
                field: "licenza_attack"
            })
        ));
    }

    /// Una fotografia vuota non è una fotografia.
    #[test]
    fn una_fotografia_senza_tecniche_non_si_costruisce() {
        assert!(matches!(
            fotografia("licenza", Vec::new()),
            Err(DomainError::Empty {
                field: "tecniche_attack"
            })
        ));
    }

    /// **Una tecnica non può rimandare a una tattica che non c'è.**
    #[test]
    fn una_tattica_sconosciuta_rifiuta_l_intera_fotografia() {
        assert!(matches!(
            fotografia("licenza", vec![tecnica("T1059", &["persistence"])]),
            Err(DomainError::InvalidAttackElement { .. })
        ));
    }

    #[test]
    fn una_fotografia_completa_si_costruisce() {
        let Ok(snapshot) = fotografia(
            "License\n-------\n…",
            vec![tecnica("T1059", &["execution"])],
        ) else {
            panic!("la fotografia di prova deve essere valida");
        };
        assert_eq!(snapshot.attack_version(), "19.2");
        assert_eq!(snapshot.techniques().len(), 1);
    }

    /// Le tattiche di una tecnica escono ordinate e senza doppioni.
    #[test]
    fn le_tattiche_di_una_tecnica_sono_stabili() {
        let tecnica = tecnica("T1059", &["execution", "execution"]);
        assert_eq!(tecnica.tactics(), &[String::from("execution")]);
    }

    /// Il troncamento taglia in caratteri, non in byte.
    #[test]
    fn il_troncamento_non_spezza_una_lettera_accentata() {
        let lungo = "è".repeat(MAX_DESCRIPTION_CHARS + 10);
        let tagliato = truncate(&lungo, MAX_DESCRIPTION_CHARS);
        assert_eq!(tagliato.chars().count(), MAX_DESCRIPTION_CHARS);
        assert!(tagliato.chars().all(|c| c == 'è'));
    }

    /// **Il modulo non nomina gli attori, e non ha un posto in cui metterli.**
    ///
    /// La guardia legge il **codice**, non i commenti, perché una guardia deve
    /// poter spiegare la propria ragione: se un giorno qualcuno aggiungesse un
    /// tipo per i gruppi di attaccanti, questa prova lo direbbe prima che quel
    /// tipo raggiunga l'archivio.
    #[test]
    fn il_dominio_non_conosce_attori() {
        let sorgente = include_str!("attack.rs");
        // Il modulo di prova si taglia via: qui sotto l'elenco delle parole
        // vietate e' scritto per esteso, ed e' l'unico posto in cui devono
        // comparire. Una guardia che si accende dove non deve e' una guardia
        // che qualcuno allenta.
        let produzione = sorgente
            .split_once("\n#[cfg(test)]")
            .map_or(sorgente, |(prima, _)| prima);
        let codice: String = produzione
            .lines()
            .filter(|riga| {
                let trimmed = riga.trim_start();
                !trimmed.starts_with("//") && !trimmed.starts_with("///")
            })
            .collect::<Vec<&str>>()
            .join("\n");

        for vietato in [
            "IntrusionSet",
            "intrusion_set",
            "ThreatActor",
            "threat_actor",
            "Malware",
            "Campaign",
            "campaign",
            "Adversary",
            "adversary",
            "attribution_to",
        ] {
            assert!(
                !codice.contains(vietato),
                "il dominio della fotografia non deve nominare «{vietato}»: \
                 un attore è un'attribuzione, e questo prodotto non attribuisce"
            );
        }
    }
}
