//! Il catalogo CISA KEV, e ciò che la sua assenza non dice.
//!
//! # La regola che governa questo modulo
//!
//! **L'assenza da KEV non è un'informazione.**
//!
//! In [`crate::model::cve`] una delle due assenze era un'informazione vera e
//! utile: un identificativo dentro la copertura e assente dal catalogo dice che
//! NVD non ha pubblicato una CVE con quel numero, ed è così che un
//! identificativo inventato si riconosce.
//!
//! Qui **non vale**, e per due ragioni che si sommano.
//!
//! **Le assenze non sono distinguibili.** KEV non ha una copertura per anno:
//! contiene tutto lo spazio degli identificativi fino al proprio rilascio. Da
//! dentro la fotografia, «CISA non l'ha mai elencata» e «CISA l'ha elencata dopo
//! questo rilascio» hanno esattamente lo stesso aspetto. Un terzo esito che le
//! distinguesse sarebbe **fabbricato**.
//!
//! **E l'assenza non è comunque un'informazione.** KEV non è l'inventario delle
//! vulnerabilità sfruttate: è l'elenco di quelle di cui **CISA ha constatato**
//! uno sfruttamento e che ha deciso di pubblicare. Una vulnerabilità sfruttata
//! di cui CISA non sa nulla è assente esattamente come una mai sfruttata.
//!
//! Perciò gli esiti sono **due, e sono asimmetrici**: *elencata* afferma,
//! *non elencata* non sa. E non esiste, né deve esistere, un valore booleano
//! «sfruttata sì/no»: sarebbe la forma in cui l'asimmetria si perde.
//!
//! # Ciò che KEV afferma resta di CISA
//!
//! «Known Exploited» dice che qualcuno ha usato quella vulnerabilità contro
//! qualcuno, nel mondo reale. Questo prodotto non ha modo di verificarlo, e non
//! deve averlo: **non lo fa proprio, lo cita**. Nessuna frase di questo modulo
//! dice «questa vulnerabilità è stata sfruttata»; ogni frase nomina CISA come
//! soggetto dell'affermazione.
//!
//! # Ciò che KEV ordina non entra
//!
//! `requiredAction`, `dueDate` e `forensicTriage` discendono da una direttiva
//! che obbliga le agenzie federali civili statunitensi. Non riguardano questo
//! ufficio, e **non esiste un campo in cui metterli**.
//!
//! La decisione completa sta in
//! `docs/adr/ADR-0061-L-ASSENZA-DA-KEV-NON-E-UN-INFORMAZIONE.md`.

use crate::error::{DomainError, DomainResult};
use crate::model::cve::CveId;

/// Quanti caratteri può avere la descrizione breve perché la voce entri.
///
/// **Non è una misura a cui troncare**: è la soglia oltre la quale la voce viene
/// omessa con il proprio motivo. Le descrizioni KEV stanno sotto il migliaio di
/// caratteri; questo tetto rifiuta ciò che non è una descrizione.
pub const MAX_SHORT_DESCRIPTION_CHARS: usize = 20_000;

/// Quanti caratteri può avere un nome — fornitore, prodotto, vulnerabilità.
pub const MAX_NAME_CHARS: usize = 1_000;

/// Quante voci può contenere un catalogo.
///
/// Il catalogo reale ne aveva **1705** il 2026-09-10. Il tetto non serve a
/// limitare CISA: serve a rifiutare un file che dice di essere un catalogo KEV e
/// non lo è.
pub const MAX_ENTRIES: usize = 200_000;

/// Che cosa CISA dichiara sull'uso in campagne ransomware.
///
/// # Perché non è un booleano
///
/// Perché il valore è `Known` oppure `Unknown`, e **`Unknown` significa «CISA
/// non lo sa», non «non è avvenuto»**. Un booleano trasformerebbe un'ignoranza
/// dichiarata in una constatazione negativa — la stessa trappola dell'assenza
/// dal catalogo, dentro un solo campo.
///
/// # Perché il valore si conserva come CISA lo scrive
///
/// Stessa ragione di [`crate::model::cve::CveStatus`]: CISA può aggiungere un
/// valore, e rifiutare un intero catalogo perché una voce porta un'etichetta
/// nuova sarebbe una guardia che punisce la cosa sbagliata. Il prodotto ne
/// riconosce esattamente uno — `Known` — perché è il solo che **afferma**
/// qualcosa. Qualunque altro produce la frase prudente.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct RansomwareUse(String);

impl RansomwareUse {
    /// L'etichetta esatta con cui CISA dichiara noto un impiego in campagne
    /// ransomware.
    pub const KNOWN: &'static str = "Known";

    /// L'etichetta con cui CISA dichiara di non saperlo.
    pub const UNKNOWN: &'static str = "Unknown";

    /// Conserva la dichiarazione.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se la dichiarazione è vuota: una voce che non dice
    /// nulla non è distinguibile da una che dice «non lo so», e le due vanno
    /// tenute separate.
    pub fn try_new(raw: &str) -> DomainResult<Self> {
        let raw = raw.trim();
        if raw.is_empty() {
            return Err(DomainError::Empty {
                field: "uso_ransomware_kev",
            });
        }
        Ok(Self(String::from(raw)))
    }

    /// La dichiarazione, come CISA la scrive.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Se CISA dichiara **noto** un impiego in campagne ransomware.
    ///
    /// Il contrario di questo valore **non** è «non è avvenuto»: è «CISA non lo
    /// dichiara noto». Vedere [`Self::as_sentence`].
    #[must_use]
    pub fn is_known(&self) -> bool {
        self.0 == Self::KNOWN
    }

    /// La dichiarazione, come si scrive a una persona.
    ///
    /// # Perché la frase la compone il dominio
    ///
    /// Perché il caso negativo è quello che si racconta male. «Nessun impiego
    /// noto» si legge come «non è avvenuto», e il dominio è il solo posto in cui
    /// la differenza può essere scritta una volta per tutte.
    #[must_use]
    pub fn as_sentence(&self) -> String {
        if self.is_known() {
            String::from(
                "CISA dichiara noto un impiego di questa vulnerabilità in campagne \
                 ransomware.",
            )
        } else {
            format!(
                "CISA non dichiara noto un impiego in campagne ransomware \
                 (dichiarazione: «{dichiarazione}»). Non significa che non sia \
                 avvenuto: significa che CISA non lo ha constatato.",
                dichiarazione = self.0,
            )
        }
    }
}

/// L'identità di un catalogo: la sua versione e l'istante che dichiara.
///
/// # Perché è un dato e non un commento
///
/// Perché è **l'unico confine che esiste**. KEV non ha una copertura per anno:
/// ciò che delimita una fotografia è il momento in cui il catalogo è stato
/// rilasciato, e l'esito negativo della risoluzione non è raccontabile senza.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KevCatalogIdentity {
    version: String,
    released_at: String,
}

impl KevCatalogIdentity {
    /// Conserva l'identità dichiarata dal catalogo.
    ///
    /// # Perché l'istante è testo e non [`crate::Timestamp`]
    ///
    /// Stessa ragione di [`crate::model::cve::CveRecord`]: si conserva la forma
    /// che la fonte dichiara. `dateReleased` porta una `Z`, ma la versione è una
    /// data senza ora — `2026.09.10` — e interpretarle entrambe come istanti del
    /// dominio richiederebbe di inventare ciò che manca.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se la versione o l'istante di rilascio sono vuoti:
    /// una fotografia che non sa dire di quando è non ha il confine che le serve,
    /// e il suo esito negativo diventerebbe inesprimibile.
    pub fn new(version: &str, released_at: &str) -> DomainResult<Self> {
        let version = version.trim();
        let released_at = released_at.trim();
        if version.is_empty() {
            return Err(DomainError::Empty {
                field: "versione_catalogo_kev",
            });
        }
        if released_at.is_empty() {
            return Err(DomainError::Empty {
                field: "rilascio_catalogo_kev",
            });
        }
        if version.chars().count() > MAX_NAME_CHARS || released_at.chars().count() > MAX_NAME_CHARS
        {
            return Err(DomainError::TooLong {
                field: "identita_catalogo_kev",
                max: MAX_NAME_CHARS,
                actual: version.chars().count().max(released_at.chars().count()),
            });
        }
        Ok(Self {
            version: String::from(version),
            released_at: String::from(released_at),
        })
    }

    /// La versione dichiarata dal catalogo, per esempio `2026.09.10`.
    #[must_use]
    pub fn version(&self) -> &str {
        &self.version
    }

    /// L'istante di rilascio, nella forma dichiarata dalla fonte.
    #[must_use]
    pub fn released_at(&self) -> &str {
        &self.released_at
    }

    /// L'identità, come si scrive a una persona.
    #[must_use]
    pub fn as_sentence(&self) -> String {
        format!(
            "catalogo CISA KEV versione {versione}, rilasciato il {rilascio}",
            versione = self.version,
            rilascio = self.released_at,
        )
    }
}

/// Una voce del catalogo, come CISA la pubblica.
///
/// # Che cosa non c'è qui dentro
///
/// `requiredAction`, `dueDate` e `forensicTriage`: sono un **ordine rivolto a
/// qualcun altro**, e non esiste un campo in cui metterli. `cwes` e `notes`
/// restano fuori per proporzione — vedere ADR-0061.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KevEntry {
    cve_id: CveId,
    vendor_project: String,
    product: String,
    vulnerability_name: String,
    date_added: String,
    short_description: String,
    ransomware_use: RansomwareUse,
}

impl KevEntry {
    /// Conserva una voce.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se un campo obbligatorio è vuoto o se supera il
    /// proprio tetto — nel qual caso la voce va **omessa**, non troncata.
    pub fn new(
        cve_id: CveId,
        vendor_project: &str,
        product: &str,
        vulnerability_name: &str,
        date_added: &str,
        short_description: &str,
        ransomware_use: RansomwareUse,
    ) -> DomainResult<Self> {
        // ANCHE L'IDENTIFICATIVO HA UN TETTO.
        //
        // L'estrattore accetta un numero di cifre arbitrariamente lungo, e
        // giustamente: i numeri CVE hanno superato le 9999 nel 2014 e fermarsi
        // a quattro perderebbe tutto cio' che conta oggi. Ma «arbitrariamente
        // lungo» dentro un file di terze parti significa che
        // `CVE-2026-<centomila cifre>` finirebbe in archivio e in una frase
        // destinata a una persona.
        let _ = campo(cve_id.as_str(), "identificativo_kev", MAX_NAME_CHARS)?;
        let vendor_project = campo(vendor_project, "fornitore_kev", MAX_NAME_CHARS)?;
        let product = campo(product, "prodotto_kev", MAX_NAME_CHARS)?;
        let vulnerability_name =
            campo(vulnerability_name, "nome_vulnerabilita_kev", MAX_NAME_CHARS)?;
        let date_added = campo(date_added, "inserimento_kev", MAX_NAME_CHARS)?;
        let short_description = campo(
            short_description,
            "descrizione_kev",
            MAX_SHORT_DESCRIPTION_CHARS,
        )?;

        Ok(Self {
            cve_id,
            vendor_project,
            product,
            vulnerability_name,
            date_added,
            short_description,
            ransomware_use,
        })
    }

    /// L'identificativo della vulnerabilità.
    #[must_use]
    pub const fn cve_id(&self) -> &CveId {
        &self.cve_id
    }

    /// Il fornitore o il progetto, come CISA lo scrive.
    #[must_use]
    pub fn vendor_project(&self) -> &str {
        &self.vendor_project
    }

    /// Il prodotto, come CISA lo scrive.
    #[must_use]
    pub fn product(&self) -> &str {
        &self.product
    }

    /// Il nome della vulnerabilità, come CISA lo scrive.
    #[must_use]
    pub fn vulnerability_name(&self) -> &str {
        &self.vulnerability_name
    }

    /// Il giorno in cui CISA ha inserito la voce nel catalogo.
    #[must_use]
    pub fn date_added(&self) -> &str {
        &self.date_added
    }

    /// La descrizione breve, **intera**, come CISA la pubblica.
    #[must_use]
    pub fn short_description(&self) -> &str {
        &self.short_description
    }

    /// Che cosa CISA dichiara sull'uso in campagne ransomware.
    #[must_use]
    pub const fn ransomware_use(&self) -> &RansomwareUse {
        &self.ransomware_use
    }
}

/// Convalida un campo di testo che deve esserci e non deve essere troncato.
fn campo(valore: &str, nome: &'static str, tetto: usize) -> DomainResult<String> {
    let valore = valore.trim();
    if valore.is_empty() {
        return Err(DomainError::Empty { field: nome });
    }
    if valore.chars().count() > tetto {
        return Err(DomainError::TooLong {
            field: nome,
            max: tetto,
            actual: valore.chars().count(),
        });
    }
    Ok(String::from(valore))
}

/// Perché una voce non è entrata nella fotografia.
///
/// # Perché l'omissione è un esito e non un silenzio
///
/// Perché una fotografia a cui manca una voce, **senza dirlo**, risponde «non
/// elencata» a una domanda a cui CISA risponde di sì — ed è l'unica risposta che
/// questa fotografia non deve mai sbagliare.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum KevOmissionReason {
    /// L'identificativo non ha la forma di un identificativo CVE.
    MalformedIdentifier,
    /// Un campo obbligatorio è vuoto.
    IncompleteEntry,
    /// Un campo supera il proprio tetto, e **non si tronca**.
    FieldTooLong,
    /// Il catalogo elenca lo stesso identificativo più di una volta.
    ///
    /// **È l'unica strada per cui una voce potrebbe sparire in silenzio**: due
    /// righe con lo stesso identificativo non possono stare entrambe in una
    /// fotografia, e quella che non entra deve dire di non essere entrata.
    DuplicateIdentifier,
}

impl KevOmissionReason {
    /// Etichetta stabile, per l'audit.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::MalformedIdentifier => "identificativo_deformato",
            Self::IncompleteEntry => "voce_incompleta",
            Self::FieldTooLong => "campo_oltre_il_tetto",
            Self::DuplicateIdentifier => "identificativo_ripetuto",
        }
    }

    /// Il motivo, come si scrive a una persona.
    #[must_use]
    pub const fn as_sentence(self) -> &'static str {
        match self {
            Self::MalformedIdentifier => {
                "l'identificativo non ha la forma di un identificativo CVE"
            }
            Self::IncompleteEntry => "la voce non dichiara tutti i campi che il catalogo prevede",
            Self::FieldTooLong => {
                "un campo supera la misura ammessa, e troncarlo cambierebbe ciò che CISA \
                 ha scritto"
            }
            Self::DuplicateIdentifier => {
                "il catalogo elenca questo identificativo più di una volta, e una \
                 fotografia non può contenerlo due volte"
            }
        }
    }
}

/// Una voce lasciata fuori, con il proprio motivo.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KevOmission {
    /// L'identificativo, come la fonte lo scrive.
    pub declared_id: String,
    /// Perché non è entrata.
    pub reason: KevOmissionReason,
}

/// L'esito della ricerca di un identificativo nel catalogo.
///
/// # Perché due varianti, e non tre come per le CVE
///
/// Perché le due assenze **non sono distinguibili dal dato**, e perché nessuna
/// delle due sarebbe comunque un'informazione. Vedere la documentazione del
/// modulo: un terzo esito qui sarebbe fabbricato.
///
/// Le due varianti sono **asimmetriche**: la prima afferma — per bocca di CISA —
/// la seconda non sa.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KevResolution {
    /// CISA la elenca fra le vulnerabilità sfruttate note.
    Listed(Box<KevEntry>),
    /// Questa fotografia non la elenca, e **non si sa altro**.
    NotListed {
        /// L'identità del catalogo: l'unico confine che esiste.
        catalog: KevCatalogIdentity,
    },
}

impl KevResolution {
    /// L'esito, come si scrive a una persona.
    ///
    /// # Perché la frase la compone il dominio
    ///
    /// Perché è la milestone. Due esiti asimmetrici raccontati con due frasi
    /// simmetriche tornerebbero a essere un sì e un no, e l'asimmetria andrebbe
    /// persa proprio nel punto in cui una persona la legge.
    ///
    /// **Nessuna delle due frasi afferma per conto proprio.** La prima riporta
    /// ciò che CISA dichiara; la seconda dice che cosa non si sa, e dice per
    /// esteso che non significa «non sfruttata».
    #[must_use]
    pub fn as_sentence(&self, id: &CveId) -> String {
        match self {
            Self::Listed(entry) => format!(
                "CISA dichiara di aver constatato uno sfruttamento reale di \
                 {identificativo} ({fornitore} {prodotto}, «{nome}»). L'ha elencata fra le \
                 vulnerabilità sfruttate note il {inserimento}. {ransomware}",
                identificativo = id.as_str(),
                fornitore = entry.vendor_project(),
                prodotto = entry.product(),
                nome = entry.vulnerability_name(),
                inserimento = entry.date_added(),
                ransomware = entry.ransomware_use().as_sentence(),
            ),
            Self::NotListed { catalog } => format!(
                "{identificativo} non è elencata da questa fotografia ({catalogo}). \
                 Non significa che non sia stata sfruttata. Il catalogo KEV \
                 raccoglie le vulnerabilità di cui CISA ha constatato uno sfruttamento \
                 e che ha deciso di pubblicare. Non raccoglie tutte quelle sfruttate. Non si sa \
                 nemmeno se CISA l'abbia elencata dopo questo rilascio.",
                identificativo = id.as_str(),
                catalogo = catalog.as_sentence(),
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

    fn catalogo() -> KevCatalogIdentity {
        let Ok(identita) = KevCatalogIdentity::new("2026.09.10", "2026-09-10T19:00:05.1949Z")
        else {
            panic!("l'identità di prova deve essere valida");
        };
        identita
    }

    fn uso(dichiarazione: &str) -> RansomwareUse {
        let Ok(valore) = RansomwareUse::try_new(dichiarazione) else {
            panic!("la dichiarazione di prova deve essere valida");
        };
        valore
    }

    fn voce(dichiarazione: &str) -> KevEntry {
        let Ok(voce) = KevEntry::new(
            identificativo("CVE-2026-86060"),
            "MikroTik",
            "RouterOS",
            "MikroTik RouterOS Improper Neutralization of Argument Delimiters Vulnerability",
            "2026-09-10",
            "RouterOS contiene un difetto che permette l'elevazione di privilegi.",
            uso(dichiarazione),
        ) else {
            panic!("la voce di prova deve essere valida");
        };
        voce
    }

    /// **Elencata: CISA afferma, e la frase lo dice.**
    #[test]
    fn una_voce_elencata_attribuisce_l_affermazione_a_cisa() {
        let esito = KevResolution::Listed(Box::new(voce(RansomwareUse::UNKNOWN)));
        let frase = esito.as_sentence(&identificativo("CVE-2026-86060"));
        assert!(frase.contains("CISA dichiara"));
        assert!(frase.contains("2026-09-10"));
        assert!(frase.contains("MikroTik"));
    }

    /// **Non elencata: non si sa, e la frase lo dice per esteso.**
    ///
    /// È la milestone. Una frase che dicesse soltanto «non elencata» verrebbe
    /// letta come «non sfruttata».
    #[test]
    fn non_elencata_dice_per_esteso_che_non_significa_non_sfruttata() {
        let esito = KevResolution::NotListed {
            catalog: catalogo(),
        };
        let frase = esito.as_sentence(&identificativo("CVE-2026-1234"));
        assert!(frase.contains("Non significa che non sia stata sfruttata"));
        assert!(frase.contains("2026.09.10"));
        assert!(frase.contains("dopo questo rilascio"));
    }

    /// I due esiti non si confondono.
    #[test]
    fn elencata_e_non_elencata_sono_due_cose_diverse() {
        let elencata = KevResolution::Listed(Box::new(voce(RansomwareUse::KNOWN)));
        let assente = KevResolution::NotListed {
            catalog: catalogo(),
        };
        assert_ne!(elencata, assente);
    }

    /// **«Unknown» non è «no».**
    #[test]
    fn unknown_non_e_una_constatazione_negativa() {
        let dichiarazione = uso(RansomwareUse::UNKNOWN);
        assert!(!dichiarazione.is_known());

        let frase = dichiarazione.as_sentence();
        assert!(frase.contains("Non significa che non sia avvenuto"));
        assert!(frase.contains("CISA non lo ha constatato"));
    }

    /// «Known» afferma, e la frase lo riporta a CISA.
    #[test]
    fn known_afferma_per_bocca_di_cisa() {
        let dichiarazione = uso(RansomwareUse::KNOWN);
        assert!(dichiarazione.is_known());

        let frase = dichiarazione.as_sentence();
        assert!(frase.starts_with("CISA dichiara noto"));
        assert!(!frase.contains("Non significa"));
    }

    /// Una dichiarazione sconosciuta **non** rifiuta la voce, e non afferma.
    #[test]
    fn una_dichiarazione_sconosciuta_si_conserva_e_non_afferma() {
        let dichiarazione = uso("Una Dichiarazione Che Oggi Non Esiste");
        assert!(!dichiarazione.is_known());
        assert_eq!(
            dichiarazione.as_str(),
            "Una Dichiarazione Che Oggi Non Esiste"
        );
        assert!(dichiarazione.as_sentence().contains("non dichiara noto"));
    }

    /// Una dichiarazione vuota si rifiuta: non è distinguibile da «non lo so».
    #[test]
    fn una_dichiarazione_vuota_si_rifiuta() {
        assert!(matches!(
            RansomwareUse::try_new("   "),
            Err(DomainError::Empty {
                field: "uso_ransomware_kev"
            })
        ));
    }

    /// Una fotografia senza identità non si costruisce.
    #[test]
    fn un_catalogo_senza_identita_non_si_costruisce() {
        assert!(matches!(
            KevCatalogIdentity::new("  ", "2026-09-10T19:00:05.1949Z"),
            Err(DomainError::Empty {
                field: "versione_catalogo_kev"
            })
        ));
        assert!(matches!(
            KevCatalogIdentity::new("2026.09.10", ""),
            Err(DomainError::Empty {
                field: "rilascio_catalogo_kev"
            })
        ));
    }

    /// Un campo oltre il tetto rifiuta la voce invece di troncarla.
    #[test]
    fn un_campo_oltre_il_tetto_rifiuta_la_voce() {
        let lunga = "a".repeat(MAX_SHORT_DESCRIPTION_CHARS + 1);
        assert!(matches!(
            KevEntry::new(
                identificativo("CVE-2026-86060"),
                "MikroTik",
                "RouterOS",
                "un nome",
                "2026-09-10",
                &lunga,
                uso(RansomwareUse::UNKNOWN),
            ),
            Err(DomainError::TooLong {
                field: "descrizione_kev",
                ..
            })
        ));
    }

    /// **Anche l'identificativo ha un tetto.**
    ///
    /// L'estrattore accetta un numero di cifre arbitrariamente lungo, e
    /// giustamente; ma «arbitrariamente lungo» dentro un file di terze parti
    /// significa che l'identificativo finirebbe in archivio e in una frase
    /// destinata a una persona.
    #[test]
    fn un_identificativo_lunghissimo_rifiuta_la_voce() {
        let cifre = "1".repeat(MAX_NAME_CHARS + 1);
        let Ok(id) = CveId::try_new(&format!("CVE-2026-{cifre}")) else {
            panic!("l'estrattore accetta un numero di cifre qualunque: è il presupposto");
        };
        assert!(matches!(
            KevEntry::new(
                id,
                "MikroTik",
                "RouterOS",
                "un nome",
                "2026-09-10",
                "una descrizione",
                uso(RansomwareUse::UNKNOWN),
            ),
            Err(DomainError::TooLong {
                field: "identificativo_kev",
                ..
            })
        ));
    }

    /// Un identificativo ripetuto ha un motivo proprio, e non si confonde.
    #[test]
    fn il_motivo_del_duplicato_esiste_e_si_spiega() {
        let motivo = KevOmissionReason::DuplicateIdentifier;
        assert_eq!(motivo.as_str(), "identificativo_ripetuto");
        assert!(motivo.as_sentence().contains("più di una volta"));
        assert_ne!(motivo, KevOmissionReason::IncompleteEntry);
    }

    /// Una voce incompleta si rifiuta.
    #[test]
    fn una_voce_incompleta_si_rifiuta() {
        assert!(matches!(
            KevEntry::new(
                identificativo("CVE-2026-86060"),
                "   ",
                "RouterOS",
                "un nome",
                "2026-09-10",
                "una descrizione",
                uso(RansomwareUse::UNKNOWN),
            ),
            Err(DomainError::Empty {
                field: "fornitore_kev"
            })
        ));
    }

    /// La descrizione entra **intera**, senza essere toccata.
    #[test]
    fn la_descrizione_si_conserva_intera() {
        let testo = "RouterOS contiene un difetto. Con «virgolette», accenti e un \
                     riferimento a CVE-2026-0001.";
        let Ok(voce) = KevEntry::new(
            identificativo("CVE-2026-86060"),
            "MikroTik",
            "RouterOS",
            "un nome",
            "2026-09-10",
            testo,
            uso(RansomwareUse::UNKNOWN),
        ) else {
            panic!("la voce di prova deve essere valida");
        };
        assert_eq!(voce.short_description(), testo);
    }

    /// **Il dominio non conosce l'ordine che KEV rivolge a qualcun altro.**
    ///
    /// `requiredAction`, `dueDate` e `forensicTriage` obbligano le agenzie
    /// federali civili statunitensi. Un campo che non esiste qui non può essere
    /// mostrato per errore.
    #[test]
    fn il_dominio_non_conosce_scadenze_ne_azioni_imposte() {
        let sorgente = include_str!("kev.rs");
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
            "requiredAction",
            "required_action",
            "dueDate",
            "due_date",
            "forensicTriage",
            "forensic_triage",
            "scadenza",
            "deadline",
        ] {
            assert!(
                !codice.contains(vietato),
                "il dominio di KEV non deve nominare «{vietato}»: è un ordine \
                 rivolto alle agenzie federali statunitensi, e questo ufficio non \
                 vi è soggetto"
            );
        }
    }

    /// **Non esiste un valore booleano «sfruttata».**
    ///
    /// Sarebbe la forma in cui l'asimmetria fra i due esiti si perde: `false`
    /// verrebbe letto come «non sfruttata», che è ciò che l'assenza da KEV non
    /// dice.
    #[test]
    fn il_dominio_non_ha_un_booleano_sfruttata() {
        let sorgente = include_str!("kev.rs");
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
            "is_exploited",
            "exploited: bool",
            "sfruttata: bool",
            "fn is_sfruttata",
            "NotExploited",
            "Exploited,",
        ] {
            assert!(
                !codice.contains(vietato),
                "il dominio di KEV non deve esprimere «{vietato}»: un booleano \
                 trasformerebbe un'ignoranza dichiarata in una constatazione"
            );
        }
    }
}
