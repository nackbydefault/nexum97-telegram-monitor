//! La fotografia CVE, e ciò che non copre.
//!
//! # La regola che governa questo modulo
//!
//! **«Non trovata» non è «non esiste».**
//!
//! Ogni fotografia locale ha un confine. Il pericolo non è il confine: è non
//! dirlo. Un operatore che legge `CVE-2026-1234` in un messaggio, chiede al
//! prodotto che cosa sia e riceve «sconosciuta», conclude una cosa sola — che
//! l'identificativo sia inventato.
//!
//! Perciò la risoluzione ha **tre esiti, non due**, e sono varianti distinte di
//! un'enumerazione chiusa: *trovata*, *fuori dalla copertura di questa
//! fotografia*, *dentro la copertura e assente dal catalogo*. **Non esiste un
//! valore «non trovata» che unisca gli ultimi due**, perché la differenza fra
//! loro è tutto ciò che conta: il primo dice *non lo so*, il secondo dice *NVD
//! non ha una CVE con questo numero* — ed è così che un identificativo inventato
//! si riconosce.
//!
//! È ADR-0053 applicato a un catalogo: assenza di prova non è prova di assenza.
//!
//! # Perché una descrizione non si tronca
//!
//! Perché i termini di NVD dicono che «if you modify the content accessed
//! through the API, you may not attribute the source as the NVD». Troncare una
//! descrizione e continuare a dire «fonte: NVD» sarebbe attribuire a NVD un
//! testo che NVD non ha scritto. Il tetto c'è — un testo di terze parti senza
//! limiti è un carico — ma **non tronca**: un record che lo supera viene
//! **omesso con il proprio motivo**.
//!
//! La decisione completa sta in
//! `docs/adr/ADR-0060-LA-FOTOGRAFIA-CVE-E-CIO-CHE-NON-COPRE.md`.

use crate::error::{DomainError, DomainResult};
use crate::model::indicator::as_cve;

/// Quanti caratteri può avere una descrizione perché il record entri.
///
/// **Non è una misura a cui troncare**: è la soglia oltre la quale il record
/// viene omesso. Le descrizioni CVE stanno quasi sempre sotto il migliaio di
/// caratteri; questo tetto rifiuta ciò che non è una descrizione.
pub const MAX_DESCRIPTION_CHARS: usize = 20_000;

/// Quanti record può contenere una fotografia.
///
/// Il catalogo intero ne ha qualche centinaio di migliaia. Il tetto non serve a
/// limitare NVD: serve a rifiutare un file che dice di essere una fotografia
/// CVE e non lo è.
pub const MAX_RECORDS: usize = 2_000_000;

/// Lo stato che NVD dichiara per una voce, riprodotto com'è.
///
/// # Perché non è un'enumerazione chiusa
///
/// Perché NVD può aggiungere uno stato — ne ha già sette — e rifiutare
/// un'intera fotografia perché una voce porta un'etichetta nuova sarebbe una
/// guardia che punisce la cosa sbagliata. Lo stato si conserva **come lo scrive
/// NVD**, e il prodotto ne riconosce esattamente uno: `Rejected`, perché è il
/// solo che cambia il significato del record.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct CveStatus(String);

impl CveStatus {
    /// L'etichetta esatta con cui NVD marca una voce ritirata.
    pub const REJECTED: &'static str = "Rejected";

    /// Conserva lo stato dichiarato.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se lo stato è vuoto: una voce senza stato è una
    /// voce di cui non si sa se sia ancora valida.
    pub fn try_new(raw: &str) -> DomainResult<Self> {
        let raw = raw.trim();
        if raw.is_empty() {
            return Err(DomainError::Empty { field: "stato_cve" });
        }
        Ok(Self(String::from(raw)))
    }

    /// Lo stato, come lo scrive NVD.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Se NVD ha **ritirato** questa voce.
    ///
    /// Una CVE ritirata **resta nella fotografia**: toglierla la farebbe
    /// riportare come «assente dal catalogo», cioè come inventata, e la
    /// distinzione che questo modulo costruisce andrebbe persa proprio nel caso
    /// in cui serve. Mostrarla **senza dirlo** sarebbe però un difetto.
    #[must_use]
    pub fn is_rejected(&self) -> bool {
        self.0 == Self::REJECTED
    }
}

/// Identificativo di una vulnerabilità: `CVE-anno-numero`.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct CveId(String);

impl CveId {
    /// Convalida e normalizza un identificativo CVE.
    ///
    /// # Perché riusa la regola dell'estrattore
    ///
    /// Perché il prodotto riconosce già gli identificativi CVE nei testi
    /// monitorati, e due regole diverse per la stessa cosa sono due verità: una
    /// stringa accettata dall'estrattore e rifiutata qui non si potrebbe
    /// risolvere, e nessuno saprebbe dire perché.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se la forma non è quella.
    pub fn try_new(raw: &str) -> DomainResult<Self> {
        let Some(normalizzato) = as_cve(raw.trim()) else {
            return Err(DomainError::InvalidAttackElement {
                reason: "un identificativo CVE ha la forma CVE-anno-numero",
            });
        };
        Ok(Self(normalizzato))
    }

    /// La forma normalizzata.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// L'anno dichiarato dall'identificativo.
    ///
    /// **Non è l'anno di pubblicazione.** Un identificativo `CVE-2003-…` può
    /// essere stato pubblicato nel 2002 o assegnato nel 2005: l'anno fa parte
    /// del numero, non della storia. Serve a sapere in quale fotografia annuale
    /// cercare, e a nient'altro.
    #[must_use]
    pub fn year(&self) -> Option<i32> {
        let resto = self.0.strip_prefix("CVE-")?;
        let (anno, _) = resto.split_once('-')?;
        anno.parse().ok()
    }
}

/// Una voce del catalogo, come NVD la pubblica.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CveRecord {
    id: CveId,
    description: String,
    published: String,
    last_modified: String,
    status: CveStatus,
}

impl CveRecord {
    /// Conserva una voce.
    ///
    /// # Perché gli istanti sono testo e non [`crate::Timestamp`]
    ///
    /// Perché NVD li scrive **senza fuso orario** — `2026-06-16T22:01:26.443` —
    /// e trasformarli in un istante richiederebbe sceglierne uno. Sceglierlo
    /// significherebbe **inventarlo**, e in un prodotto che mette date accanto a
    /// fatti è precisamente ciò che non si fa. Si conserva la forma che la fonte
    /// dichiara; se un giorno servirà un istante vero, sarà una decisione con la
    /// propria ragione.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se la descrizione è vuota, se supera il tetto —
    /// nel qual caso il record va **omesso**, non troncato — o se gli istanti
    /// dichiarati sono vuoti.
    pub fn new(
        id: CveId,
        description: &str,
        published: &str,
        last_modified: &str,
        status: CveStatus,
    ) -> DomainResult<Self> {
        let description = description.trim();
        if description.is_empty() {
            return Err(DomainError::Empty {
                field: "descrizione_cve",
            });
        }
        if description.chars().count() > MAX_DESCRIPTION_CHARS {
            return Err(DomainError::TooLong {
                field: "descrizione_cve",
                max: MAX_DESCRIPTION_CHARS,
                actual: description.chars().count(),
            });
        }
        for (valore, campo) in [
            (published, "pubblicazione_cve"),
            (last_modified, "ultima_modifica_cve"),
        ] {
            if valore.trim().is_empty() {
                return Err(DomainError::Empty { field: campo });
            }
        }

        Ok(Self {
            id,
            description: String::from(description),
            published: String::from(published.trim()),
            last_modified: String::from(last_modified.trim()),
            status,
        })
    }

    /// L'identificativo.
    #[must_use]
    pub const fn id(&self) -> &CveId {
        &self.id
    }

    /// La descrizione, **intera**, come NVD la pubblica.
    #[must_use]
    pub fn description(&self) -> &str {
        &self.description
    }

    /// L'istante di pubblicazione, nella forma dichiarata dalla fonte.
    #[must_use]
    pub fn published(&self) -> &str {
        &self.published
    }

    /// L'istante dell'ultima modifica, nella forma dichiarata dalla fonte.
    #[must_use]
    pub fn last_modified(&self) -> &str {
        &self.last_modified
    }

    /// Lo stato dichiarato da NVD.
    #[must_use]
    pub const fn status(&self) -> &CveStatus {
        &self.status
    }
}

/// La copertura di una fotografia: quali anni contiene.
///
/// # Perché è un dato e non un commento
///
/// Perché è ciò che permette di distinguere «non lo so» da «non esiste», e una
/// distinzione che vive in un commento non arriva a chi legge il risultato.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CveCoverage {
    years: Vec<i32>,
}

impl CveCoverage {
    /// Costruisce una copertura.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se non c'è alcun anno: una fotografia che non
    /// copre niente non è una fotografia, e permetterla renderebbe ogni
    /// risoluzione «fuori copertura» — cioè inutile ma dall'aria prudente.
    pub fn new(years: Vec<i32>) -> DomainResult<Self> {
        let mut years = years;
        years.sort_unstable();
        years.dedup();
        if years.is_empty() {
            return Err(DomainError::Empty {
                field: "copertura_cve",
            });
        }
        Ok(Self { years })
    }

    /// Gli anni coperti, in ordine.
    #[must_use]
    pub fn years(&self) -> &[i32] {
        &self.years
    }

    /// Se l'anno di un identificativo cade dentro la copertura.
    #[must_use]
    pub fn covers(&self, id: &CveId) -> bool {
        id.year().is_some_and(|anno| self.years.contains(&anno))
    }

    /// La copertura, come si scrive a una persona.
    #[must_use]
    pub fn as_sentence(&self) -> String {
        let elenco: Vec<String> = self.years.iter().map(ToString::to_string).collect();
        format!("questa fotografia copre gli anni {}", elenco.join(", "))
    }
}

/// Perché una voce del catalogo non è entrata nella fotografia.
///
/// # Perché l'omissione è un esito e non un silenzio
///
/// Perché una fotografia a cui manca una voce, senza dirlo, risponde «assente
/// dal catalogo» a una domanda a cui NVD risponde di sì — e quella risposta,
/// in questo prodotto, significa «identificativo inventato». Un'omissione
/// silenziosa produrrebbe esattamente l'accusa che la milestone esiste per non
/// fare.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum CveOmissionReason {
    /// La descrizione supera il tetto, e **non si tronca**.
    ///
    /// Troncarla e continuare a dire «fonte: NVD» attribuirebbe a NVD un testo
    /// che NVD non ha scritto.
    DescriptionTooLong,
    /// La voce non porta alcuna descrizione in inglese.
    ///
    /// Le traduzioni sono feed separati, di altri enti: prenderne una e
    /// chiamarla NVD sarebbe attribuire a NVD un testo che non è suo.
    NoEnglishDescription,
    /// L'identificativo non ha la forma di un identificativo CVE.
    MalformedIdentifier,
    /// La voce non dichiara uno stato, o dichiara istanti vuoti.
    IncompleteRecord,
}

impl CveOmissionReason {
    /// Etichetta stabile, per l'audit.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::DescriptionTooLong => "descrizione_oltre_il_tetto",
            Self::NoEnglishDescription => "nessuna_descrizione_inglese",
            Self::MalformedIdentifier => "identificativo_deformato",
            Self::IncompleteRecord => "voce_incompleta",
        }
    }

    /// Il motivo, come si scrive a una persona.
    #[must_use]
    pub const fn as_sentence(self) -> &'static str {
        match self {
            Self::DescriptionTooLong => {
                "la descrizione supera la misura ammessa, e troncarla significherebbe \
                 attribuire a NVD un testo che NVD non ha scritto"
            }
            Self::NoEnglishDescription => {
                "la voce non porta una descrizione in inglese, e le traduzioni sono \
                 di altri enti"
            }
            Self::MalformedIdentifier => {
                "l'identificativo non ha la forma di un identificativo CVE"
            }
            Self::IncompleteRecord => "la voce non dichiara stato o istanti",
        }
    }
}

/// Una voce lasciata fuori, con il proprio motivo.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CveOmission {
    /// L'identificativo, come la fonte lo scrive.
    pub declared_id: String,
    /// Perché non è entrata.
    pub reason: CveOmissionReason,
}

/// L'esito della ricerca di un identificativo.
///
/// # Perché tre varianti e non due
///
/// Perché «non trovata» unirebbe due cose opposte. *Fuori copertura* dice **non
/// lo so**: l'identificativo potrebbe essere validissimo, e questa fotografia
/// semplicemente non lo contiene. *Assente dal catalogo* dice **NVD non ha una
/// CVE con questo numero**, ed è un'informazione vera e utile — è così che un
/// identificativo inventato si riconosce.
///
/// Non esiste una variante che le unisca, e non deve esistere.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CveResolution {
    /// Trovata nel catalogo di questa fotografia.
    Found(Box<CveRecord>),
    /// L'anno dell'identificativo è **fuori** dalla copertura: non si sa.
    OutsideCoverage {
        /// Che cosa questa fotografia copre davvero.
        coverage: CveCoverage,
    },
    /// L'anno è coperto, e nel catalogo quell'identificativo **non c'è**.
    AbsentFromCatalogue {
        /// Che cosa questa fotografia copre davvero.
        coverage: CveCoverage,
    },
}

impl CveResolution {
    /// L'esito, come si scrive a una persona.
    ///
    /// # Perché la frase la compone il dominio
    ///
    /// Perché è la milestone. Tre esiti che si raccontano con due frasi
    /// tornerebbero a essere due esiti, e la distinzione andrebbe persa nel
    /// punto in cui una persona la legge.
    #[must_use]
    pub fn as_sentence(&self, id: &CveId) -> String {
        match self {
            Self::Found(record) => {
                let ritirata = if record.status().is_rejected() {
                    " NVD ha RITIRATO questa voce: l'identificativo esiste, ma non \
                     designa più una vulnerabilità."
                } else {
                    ""
                };
                format!(
                    "{identificativo} risulta nel catalogo, con stato «{stato}».{ritirata}",
                    identificativo = id.as_str(),
                    stato = record.status().as_str(),
                )
            }
            Self::OutsideCoverage { coverage } => format!(
                "{identificativo} è fuori dalla copertura di questa fotografia: \
                 {copertura}. Non significa che non esista: significa che qui non \
                 se ne sa nulla.",
                identificativo = id.as_str(),
                copertura = coverage.as_sentence(),
            ),
            Self::AbsentFromCatalogue { coverage } => format!(
                "{identificativo} ha un anno coperto da questa fotografia ({copertura}), \
                 e nel catalogo non c'è. Alla data di acquisizione, NVD non aveva \
                 pubblicato una CVE con questo numero.",
                identificativo = id.as_str(),
                copertura = coverage.as_sentence(),
            ),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn identificativo(raw: &str) -> CveId {
        let Ok(id) = CveId::try_new(raw) else {
            panic!("l'identificativo di prova deve essere valido");
        };
        id
    }

    fn copertura() -> CveCoverage {
        let Ok(copertura) = CveCoverage::new(vec![2024, 2025, 2026]) else {
            panic!("la copertura di prova deve essere valida");
        };
        copertura
    }

    fn record(stato: &str) -> CveRecord {
        let Ok(status) = CveStatus::try_new(stato) else {
            panic!("lo stato di prova deve essere valido");
        };
        let Ok(record) = CveRecord::new(
            identificativo("CVE-2026-1234"),
            "Buffer overflow in qualcosa che permette a un utente locale di eseguire comandi.",
            "2026-01-11T05:00:00.000",
            "2026-06-16T22:01:26.443",
            status,
        ) else {
            panic!("il record di prova deve essere valido");
        };
        record
    }

    #[test]
    fn un_identificativo_ben_formato_e_accettato_e_normalizzato() {
        assert_eq!(identificativo("cve-2026-1234").as_str(), "CVE-2026-1234");
        assert_eq!(identificativo("CVE-2026-98765").as_str(), "CVE-2026-98765");
    }

    #[test]
    fn un_identificativo_deformato_si_rifiuta() {
        for valore in [
            "CVE-26-1234",
            "CVE-2026-1",
            "2026-1234",
            "",
            "CVE-2026-abcd",
        ] {
            assert!(
                CveId::try_new(valore).is_err(),
                "«{valore}» non doveva essere accettato"
            );
        }
    }

    #[test]
    fn l_anno_si_legge_dall_identificativo() {
        assert_eq!(identificativo("CVE-2026-1234").year(), Some(2026));
        assert_eq!(identificativo("CVE-1999-0001").year(), Some(1999));
    }

    /// **Una descrizione oltre il tetto non si tronca: il record si rifiuta.**
    ///
    /// Troncarla e continuare a dire «fonte: NVD» sarebbe attribuire a NVD un
    /// testo che NVD non ha scritto.
    #[test]
    fn una_descrizione_oltre_il_tetto_rifiuta_il_record() {
        let Ok(status) = CveStatus::try_new("Analyzed") else {
            panic!("lo stato di prova deve essere valido");
        };
        let lunga = "a".repeat(MAX_DESCRIPTION_CHARS + 1);
        assert!(matches!(
            CveRecord::new(
                identificativo("CVE-2026-1234"),
                &lunga,
                "2026-01-01T00:00:00.000",
                "2026-01-01T00:00:00.000",
                status,
            ),
            Err(DomainError::TooLong {
                field: "descrizione_cve",
                ..
            })
        ));
    }

    /// La descrizione entra **intera**, senza essere toccata.
    #[test]
    fn la_descrizione_si_conserva_intera() {
        let testo = "Una descrizione con più frasi. E con un URL: https://esempio.test/a. \
                     E con «virgolette» e caratteri accentati.";
        let Ok(status) = CveStatus::try_new("Analyzed") else {
            panic!("lo stato di prova deve essere valido");
        };
        let Ok(record) = CveRecord::new(
            identificativo("CVE-2026-1234"),
            testo,
            "2026-01-01T00:00:00.000",
            "2026-01-01T00:00:00.000",
            status,
        ) else {
            panic!("il record di prova deve essere valido");
        };
        assert_eq!(record.description(), testo);
    }

    /// **«Fuori copertura» e «assente dal catalogo» non si confondono.**
    ///
    /// È la milestone: la prima dice «non lo so», la seconda dice «NVD non ha
    /// una CVE con questo numero».
    #[test]
    fn fuori_copertura_e_assente_dal_catalogo_sono_due_cose_diverse() {
        let fuori = CveResolution::OutsideCoverage {
            coverage: copertura(),
        };
        let assente = CveResolution::AbsentFromCatalogue {
            coverage: copertura(),
        };
        assert_ne!(fuori, assente);

        let vecchia = identificativo("CVE-2019-1234");
        let recente = identificativo("CVE-2026-9999");

        let frase_fuori = fuori.as_sentence(&vecchia);
        assert!(frase_fuori.contains("fuori dalla copertura"));
        assert!(frase_fuori.contains("Non significa che non esista"));

        let frase_assente = assente.as_sentence(&recente);
        assert!(frase_assente.contains("nel catalogo non c'è"));
        assert!(!frase_assente.contains("Non significa che non esista"));
    }

    /// La copertura decide quale dei due esiti sia possibile.
    #[test]
    fn la_copertura_dice_quale_anno_contiene() {
        let copertura = copertura();
        assert!(copertura.covers(&identificativo("CVE-2025-1234")));
        assert!(!copertura.covers(&identificativo("CVE-2019-1234")));
        assert!(copertura.as_sentence().contains("2024, 2025, 2026"));
    }

    /// Una fotografia che non copre niente non è una fotografia.
    #[test]
    fn una_copertura_vuota_non_si_costruisce() {
        assert!(matches!(
            CveCoverage::new(Vec::new()),
            Err(DomainError::Empty {
                field: "copertura_cve"
            })
        ));
    }

    /// **Una CVE ritirata resta, e la frase lo dice.**
    #[test]
    fn una_cve_ritirata_resta_e_lo_dichiara() {
        let ritirata = record(CveStatus::REJECTED);
        assert!(ritirata.status().is_rejected());

        let esito = CveResolution::Found(Box::new(ritirata));
        let frase = esito.as_sentence(&identificativo("CVE-2026-1234"));
        assert!(frase.contains("RITIRATO"));
        assert!(frase.contains("non designa più una vulnerabilità"));
    }

    /// Una CVE viva non porta l'avvertenza del ritiro.
    #[test]
    fn una_cve_viva_non_porta_l_avvertenza_del_ritiro() {
        let esito = CveResolution::Found(Box::new(record("Analyzed")));
        let frase = esito.as_sentence(&identificativo("CVE-2026-1234"));
        assert!(frase.contains("risulta nel catalogo"));
        assert!(!frase.contains("RITIRATO"));
    }

    /// Uno stato sconosciuto **non** rifiuta il record.
    ///
    /// NVD ne ha già sette e può aggiungerne: rifiutare un'intera fotografia
    /// perché una voce porta un'etichetta nuova sarebbe una guardia che punisce
    /// la cosa sbagliata.
    #[test]
    fn uno_stato_sconosciuto_si_conserva_invece_di_rifiutare() {
        let Ok(status) = CveStatus::try_new("Uno Stato Che Oggi Non Esiste") else {
            panic!("uno stato non vuoto deve essere accettato");
        };
        assert!(!status.is_rejected());
        assert_eq!(status.as_str(), "Uno Stato Che Oggi Non Esiste");
    }

    /// **Il modulo non importa il punteggio CVSS**, e non ha un posto in cui
    /// metterlo.
    ///
    /// Un numero sembra oggettivo, e questo prodotto mette i propri risultati
    /// accanto a contenuti scritti da persone: un «9.8 CRITICAL» stampato di
    /// fianco a un messaggio viene letto come «questo messaggio è critico».
    /// Non è un no definitivo — è un no **per ora**, e la guardia lo sorveglia.
    #[test]
    fn il_dominio_non_conosce_punteggi() {
        let sorgente = include_str!("cve.rs");
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
            "cvss",
            "Cvss",
            "CVSS",
            "base_score",
            "baseScore",
            "baseSeverity",
            "severity",
            "Severity",
            "score",
        ] {
            assert!(
                !codice.contains(vietato),
                "il dominio della fotografia CVE non deve nominare «{vietato}»: \
                 un numero sembra oggettivo, e finirebbe accanto a un messaggio \
                 scritto da una persona"
            );
        }
    }
}
