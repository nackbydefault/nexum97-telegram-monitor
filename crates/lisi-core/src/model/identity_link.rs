//! Associazione manuale fra un'identità osservata e un soggetto (PERS-06).
//!
//! # La porta che quattro milestone hanno tenuto chiusa
//!
//! PERS-02, PERS-03, PERS-04 e PERS-05 hanno tutte rifiutato di collegare
//! un'identità osservata a un fascicolo, e ognuna ha una guardia che lo
//! verifica: i loro moduli **non nominano** `PersonId`.
//!
//! Questa milestone apre quella porta, e la apre **con una chiave umana**: chi
//! collega, perché, quando, e con la possibilità di sciogliere il legame.
//!
//! **Il divieto non è stato tolto.** Le quattro guardie restano dove sono e
//! restano rosse se qualcuno collegasse da lì: il collegamento manuale è
//! un'altra strada, non un permesso. Un legame nasce **solo** qui, e solo perché
//! qualcuno lo ha deciso.
//!
//! # Mai automatica per somiglianza di nome
//!
//! Il congelamento lo scrive con queste parole, e il freeze §9 elenca «una
//! fusione automatica di identità per somiglianza di nome» fra i controlli
//! negativi attesi.
//!
//! Qui non esiste alcuna funzione che **cerchi** identità da collegare, che ne
//! **proponga**, che le ordini per verosimiglianza o che le chiami «candidate».
//! Il prodotto ha un algoritmo di somiglianza — serve a riconoscere due
//! ripubblicazioni dello stesso testo (ADR-0055) — e **questo modulo non lo
//! nomina**: applicarlo a due nomi di persona unirebbe due omonimi, che è
//! esattamente l'errore che PERS-02 aveva già evitato raggruppando per
//! identificativo.
//!
//! L'identificativo da collegare **si scrive**, come si scrive il nome di un
//! soggetto quando lo si apre.
//!
//! # Sciogliere è un atto, e non cancella che il legame sia esistito
//!
//! «Reversibilità dove praticabile», dice il piano. Qui è praticabile: un legame
//! si scioglie.
//!
//! Ma **sciogliere non riscrive il passato**. Se qualcuno ha lavorato su un
//! fascicolo mentre un'identità vi era collegata, cancellare il legame
//! renderebbe illeggibile quel lavoro: sembrerebbe che nessuno avesse mai
//! collegato niente. La storia resta, e dice chi ha collegato, chi ha sciolto, e
//! perché ciascuno dei due.
//!
//! # Nessun numero, e nessuna confidenza
//!
//! Un legame **non ha un punteggio di confidenza**. Un numero accanto a un
//! legame fra una persona e un fascicolo è la stessa cosa di un numero accanto a
//! una persona: si legge come una misura, e questa non esiste.
//!
//! Un legame o c'è perché qualcuno lo ha deciso, o non c'è.

use std::collections::BTreeMap;

use crate::model::reason::OperationalReason;
use crate::text::Actor;
use crate::time::Timestamp;
use crate::{IdentityLinkId, IdentityResolutionId, PersonId};

/// Che cosa un operatore ha fatto a un legame.
///
/// # Perché sciogliere è un atto come collegare
///
/// Perché un legame sciolto in silenzio non dice se sia stato sciolto **perché
/// era sbagliato** o **perché è diventato scomodo**, e sono due cose molto
/// diverse per chi rilegge un fascicolo. È la stessa ragione per cui una
/// valutazione si ritira con un motivo (PERS-05).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum LinkAct {
    /// Ha collegato un'identità osservata a un soggetto.
    Link,
    /// Ha sciolto il legame.
    Unlink,
}

impl LinkAct {
    /// Etichetta stabile, quella che finisce nell'archivio.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Link => "collegata",
            Self::Unlink => "sciolta",
        }
    }

    /// Come si nomina a chi legge.
    #[must_use]
    pub const fn as_label(self) -> &'static str {
        match self {
            Self::Link => "COLLEGATA",
            Self::Unlink => "SCIOLTA",
        }
    }
}

impl core::str::FromStr for LinkAct {
    type Err = crate::error::DomainError;

    /// # Errori
    ///
    /// Rifiuta ogni testo che non sia uno dei due atti.
    fn from_str(raw: &str) -> crate::error::DomainResult<Self> {
        match raw {
            "collegata" => Ok(Self::Link),
            "sciolta" => Ok(Self::Unlink),
            altro => Err(crate::error::unknown_variant(
                "atto di associazione di identita",
                altro,
            )),
        }
    }
}

/// Ciò che serve per registrare un atto su un legame.
///
/// # Perché il motivo non è opzionale, per nessuno dei due atti
///
/// Perché collegare un'identità osservata a un fascicolo è **la decisione che
/// questo prodotto ha rimandato per cinque milestone**, e scriverla senza dire
/// perché la renderebbe indistinguibile da un automatismo.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewIdentityLink {
    /// Quale soggetto.
    pub person: PersonId,
    /// Quale identità osservata, per **identificativo**.
    ///
    /// # Perché l'identificativo e non il nome
    ///
    /// Perché il nome non regge nel tempo e non è unico: due persone possono
    /// chiamarsi allo stesso modo, e una può cambiare nome. È la decisione di
    /// PERS-02, e qui sbagliare costerebbe di più — collegherebbe a un fascicolo
    /// la persona sbagliata.
    pub identifier: String,
    /// Che cosa si è fatto.
    pub act: LinkAct,
    /// Perché.
    pub reason: OperationalReason,
    /// Chi.
    pub by: Actor,
    /// Quando.
    pub at: Timestamp,
    /// La base: la ricerca puntuale (PR-09) da cui il legame nasce, oppure
    /// nessuna — la base di sempre, un'identità osservata nei monitoraggi
    /// (PR-10, ADR-0126).
    pub resolution: Option<IdentityResolutionId>,
}

/// Se un testo ha la forma di un'identità Telegram (OPERATOR-E2E-REMEDIATION-01,
/// F-18).
///
/// # La regola, e da dove viene
///
/// Un **nome utente**: da 5 a 32 caratteri fra lettere (senza distinzione fra
/// maiuscole e minuscole), cifre e trattino basso — la regola di
/// `account.checkUsername` nella documentazione ufficiale di Telegram
/// (core.telegram.org). La `@` iniziale con cui lo si scrive di solito si può
/// lasciare. Oppure un **identificativo numerico**, come quelli che i
/// monitoraggi registrano per gli autori.
///
/// # Che cosa questa funzione non dice
///
/// Che l'identità **esista**: lo può dire soltanto una ricerca puntuale, e il
/// legame lo dichiara nella sua base. Qui si rifiuta soltanto ciò che non può
/// essere un'identità Telegram — «abc» era stato accettato e scritto in un
/// fascicolo come se lo fosse.
#[must_use]
pub fn is_telegram_identity(testo: &str) -> bool {
    let testo = testo.trim();
    if !testo.is_empty() && testo.len() <= 20 && testo.bytes().all(|b| b.is_ascii_digit()) {
        return testo.bytes().any(|b| b != b'0');
    }
    let nome = testo.strip_prefix('@').unwrap_or(testo);
    (5..=32).contains(&nome.len()) && nome.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
}

/// Un atto registrato su un legame.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IdentityLinkEntry {
    /// Identificativo della riga.
    pub id: IdentityLinkId,
    /// Quale soggetto.
    pub person: PersonId,
    /// Quale identità osservata.
    pub identifier: String,
    /// Che cosa si è fatto.
    pub act: LinkAct,
    /// Perché.
    pub reason: OperationalReason,
    /// Chi.
    pub by: Actor,
    /// Quando.
    pub at: Timestamp,
    /// La base, come in [`NewIdentityLink::resolution`].
    pub resolution: Option<IdentityResolutionId>,
}

impl IdentityLinkEntry {
    /// L'atto, detto a chi legge.
    #[must_use]
    pub fn as_sentence(&self) -> String {
        match self.act {
            LinkAct::Link => format!(
                "Identit\u{e0} {} collegata da {}, il {}.",
                self.identifier,
                self.by.as_str(),
                self.at.to_readable_utc()
            ),
            LinkAct::Unlink => format!(
                "Legame con l'identit\u{e0} {} sciolto da {}, il {}. Resta scritto che era \
                 esistito.",
                self.identifier,
                self.by.as_str(),
                self.at.to_readable_utc()
            ),
        }
    }
}

/// Un legame **attualmente in essere**.
///
/// # Perché porta chi lo ha deciso, e non solo l'identificativo
///
/// Perché è il punto di tutta la milestone: un legame non è un fatto osservato,
/// è **la decisione di una persona**, e la riga che lo mostra deve dire di chi
/// è. Un elenco di identificativi accanto a un fascicolo, senza nomi e senza
/// istanti, si leggerebbe come un risultato del programma.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinkedIdentity {
    /// L'identificativo osservato.
    pub identifier: String,
    /// Chi lo ha collegato.
    pub by: Actor,
    /// Quando.
    pub at: Timestamp,
    /// Perché.
    pub reason: OperationalReason,
    /// La base, come in [`NewIdentityLink::resolution`].
    pub resolution: Option<IdentityResolutionId>,
}

impl LinkedIdentity {
    /// Chi lo afferma (PR-03): **sempre una persona**. Un legame è una
    /// decisione, e non diventa mai un dato osservato — nemmeno quando nasce da
    /// ciò che Telegram ha restituito a una ricerca.
    #[must_use]
    pub const fn origin(&self) -> crate::model::origin::Origin {
        crate::model::origin::Origin::Operator
    }

    /// Su che cosa il legame è stato deciso (PR-10, ADR-0126).
    #[must_use]
    pub fn basis_sentence(&self) -> String {
        // SENZA RICERCA, LA BASE E' CIO' CHE UNA PERSONA HA SCRITTO (F-18). La
        // frase diceva «un'identità osservata nei monitoraggi» anche per un
        // identificativo che nessun monitoraggio aveva mai incontrato: era
        // un'affermazione di fatto su una cosa soltanto dichiarata. Se un
        // monitoraggio l'ha incontrata, il fascicolo lo dice a parte.
        self.resolution.map_or_else(
            || {
                String::from(
                    "Base: l'identificativo scritto da chi ha collegato, non verificato da una \
                     ricerca puntuale.",
                )
            },
            |ricerca| {
                format!(
                    "Base: la ricerca puntuale n. {}, in cui Telegram ha restituito questo \
                     identificativo.",
                    ricerca.get()
                )
            },
        )
    }

    /// Il legame, detto a chi legge.
    #[must_use]
    pub fn as_sentence(&self) -> String {
        format!(
            "{} \u{2014} collegata da {} il {}. \u{c8} la decisione di una persona, non un \
             risultato del programma. {}",
            self.identifier,
            self.by.as_str(),
            self.at.to_readable_utc(),
            self.basis_sentence()
        )
    }
}

/// Ricava i legami in essere dalla storia degli atti.
///
/// # Perché si ricavano invece di conservarli
///
/// Perché due verità divergono. La storia è la verità; l'elenco di oggi si
/// ricava. È la scelta di PERS-05 per la valutazione, e vale qui per la stessa
/// ragione.
///
/// # Come si decide, per ogni identificativo
///
/// Vale **l'atto più recente** su quel legame: a parità di istante decide
/// l'identificativo della riga, perché senza un criterio secondario due letture
/// darebbero due elenchi diversi.
#[must_use]
pub fn current_links(history: &[IdentityLinkEntry]) -> Vec<LinkedIdentity> {
    // UN ATTO PIU' RECENTE PER OGNI IDENTIFICATIVO.
    //
    // Chi ha collegato, sciolto e ricollegato la stessa identita' ha tre righe
    // nella storia e un legame solo — quello che dice l'ultimo atto.
    let mut ultimo: BTreeMap<&str, &IdentityLinkEntry> = BTreeMap::new();
    for voce in history {
        let chiave = voce.identifier.as_str();
        match ultimo.get(chiave) {
            Some(precedente)
                if (precedente.at, precedente.id.get()) >= (voce.at, voce.id.get()) => {}
            _ => {
                ultimo.insert(chiave, voce);
            }
        }
    }

    ultimo
        .into_values()
        .filter(|voce| voce.act == LinkAct::Link)
        .map(|voce| LinkedIdentity {
            identifier: voce.identifier.clone(),
            by: voce.by.clone(),
            at: voce.at,
            reason: voce.reason.clone(),
            resolution: voce.resolution,
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::{IdentityLinkEntry, LinkAct, current_links};
    use crate::model::reason::OperationalReason;
    use crate::text::Actor;
    use crate::time::Timestamp;
    use crate::{IdentityLinkId, PersonId};

    const ORA: Timestamp = Timestamp::from_millis(1_760_000_000_000);

    fn attore(nome: &str) -> Actor {
        let Ok(valore) = Actor::try_new(nome) else {
            panic!("l'attore deve essere valido");
        };
        valore
    }

    fn ragione() -> OperationalReason {
        let Ok(valore) =
            OperationalReason::try_new("riscontro documentale con l'autorita' procedente")
        else {
            panic!("la ragione di prova deve essere valida");
        };
        valore
    }

    fn voce(id: i64, identifier: &str, act: LinkAct, at: Timestamp) -> IdentityLinkEntry {
        IdentityLinkEntry {
            id: IdentityLinkId::new(id),
            person: PersonId::new(1),
            identifier: identifier.to_owned(),
            act,
            reason: ragione(),
            by: attore("operatore.prova"),
            at,
            resolution: None,
        }
    }

    /// **Un legame nato da una ricerca puntuale è di una persona, e lo dice**
    /// (PR-10, controllo negativo 3): l'origine è Operatore, e la base si
    /// distingue da quella di un'identità osservata.
    #[test]
    fn un_legame_da_ricerca_e_di_una_persona_e_dice_la_base() {
        use crate::model::origin::Origin;

        let mut da_ricerca = voce(1, "42", LinkAct::Link, ORA);
        da_ricerca.resolution = Some(crate::IdentityResolutionId::new(7));
        let osservata = voce(2, "43", LinkAct::Link, ORA);
        let legami = current_links(&[da_ricerca, osservata]);
        assert_eq!(legami.len(), 2);
        for legame in &legami {
            assert_eq!(legame.origin(), Origin::Operator, "mai Osservato");
        }
        let (da_ricerca, osservata) = (&legami[0], &legami[1]);
        assert!(da_ricerca.as_sentence().contains("ricerca puntuale n. 7"));
        // Senza ricerca la base è ciò che una persona ha scritto (F-18): la
        // frase diceva «osservata nei monitoraggi» anche quando nessun
        // monitoraggio l'aveva incontrata.
        assert!(
            osservata
                .as_sentence()
                .contains("scritto da chi ha collegato, non verificato")
        );
        assert!(
            !osservata
                .as_sentence()
                .contains("osservata nei monitoraggi")
        );
        assert_ne!(da_ricerca.basis_sentence(), osservata.basis_sentence());
    }

    /// **Un'identità Telegram ha una forma, e «abc» non ce l'ha** (F-18).
    ///
    /// La regola è quella di `account.checkUsername` nella documentazione
    /// ufficiale: da 5 a 32 caratteri fra lettere, cifre e trattino basso.
    #[test]
    fn un_identita_telegram_ha_una_forma() {
        for buona in [
            "@mario_rossi",
            "mario_rossi",
            "Abcde",
            "user_32",
            "123456789",
            "a1234",
        ] {
            assert!(super::is_telegram_identity(buona), "«{buona}»");
        }
        for cattiva in [
            "abc",
            "@abc",
            "",
            "  ",
            "mario rossi",
            "mario-rossi",
            "0",
            "a234567890123456789012345678901234",
            "ciao!",
            "@",
        ] {
            assert!(!super::is_telegram_identity(cattiva), "«{cattiva}»");
        }
    }

    /// **Senza atti, non c'è alcun legame.**
    #[test]
    fn senza_atti_non_c_e_alcun_legame() {
        assert!(current_links(&[]).is_empty());
    }

    /// **Un legame porta chi lo ha deciso.**
    ///
    /// # Perché è la guardia di questa milestone
    ///
    /// Perché un elenco di identificativi accanto a un fascicolo, senza nomi e
    /// senza istanti, si leggerebbe come un risultato del programma — ed è
    /// esattamente ciò che questo legame non è.
    #[test]
    fn un_legame_porta_chi_lo_ha_deciso() {
        let legami = current_links(&[voce(1, "111", LinkAct::Link, ORA)]);
        assert_eq!(legami.len(), 1);
        assert_eq!(legami[0].by.as_str(), "operatore.prova");

        let frase = legami[0].as_sentence();
        assert!(frase.contains("operatore.prova"), "chi: {frase}");
        assert!(
            frase.contains("decisione di una persona"),
            "e che non e' un calcolo: {frase}"
        );
    }

    /// **Sciogliere toglie il legame, e la storia resta.**
    #[test]
    fn sciogliere_toglie_il_legame_e_la_storia_resta() {
        let storia = vec![
            voce(1, "111", LinkAct::Link, ORA),
            voce(
                2,
                "111",
                LinkAct::Unlink,
                Timestamp::from_millis(ORA.as_millis() + 100),
            ),
        ];

        assert!(
            current_links(&storia).is_empty(),
            "sciolto: non e' piu' in essere"
        );
        assert_eq!(storia.len(), 2, "la storia non si accorcia");

        let frase = storia[1].as_sentence();
        assert!(
            frase.contains("Resta scritto che era esistito"),
            "sciogliere non riscrive il passato: {frase}"
        );
    }

    /// **Ricollegare dopo aver sciolto rimette il legame.**
    ///
    /// # Perché conta
    ///
    /// Perché è il caso in cui un errore si corregge: qualcuno ha sciolto per
    /// sbaglio, e deve poter tornare indietro senza che il fascicolo perda la
    /// traccia di che cosa è successo.
    #[test]
    fn ricollegare_dopo_aver_sciolto_rimette_il_legame() {
        let storia = vec![
            voce(1, "111", LinkAct::Link, ORA),
            voce(
                2,
                "111",
                LinkAct::Unlink,
                Timestamp::from_millis(ORA.as_millis() + 100),
            ),
            voce(
                3,
                "111",
                LinkAct::Link,
                Timestamp::from_millis(ORA.as_millis() + 200),
            ),
        ];

        let legami = current_links(&storia);
        assert_eq!(legami.len(), 1, "vale l'atto piu' recente");
        assert_eq!(storia.len(), 3, "e tutti e tre restano scritti");
    }

    /// **Due identità collegate restano due, e l'ordine è ripetibile.**
    #[test]
    fn due_identita_restano_due_e_l_ordine_e_ripetibile() {
        let storia = vec![
            voce(1, "222", LinkAct::Link, ORA),
            voce(
                2,
                "111",
                LinkAct::Link,
                Timestamp::from_millis(ORA.as_millis() + 100),
            ),
        ];

        let legami = current_links(&storia);
        assert_eq!(legami.len(), 2);

        let identificativi: Vec<&str> = legami.iter().map(|l| l.identifier.as_str()).collect();
        assert_eq!(
            identificativi,
            vec!["111", "222"],
            "ordine stabile per identificativo"
        );

        let al_contrario: Vec<IdentityLinkEntry> = storia.iter().rev().cloned().collect();
        assert_eq!(
            current_links(&storia),
            current_links(&al_contrario),
            "due letture danno lo stesso elenco"
        );
    }

    /// **Nessuna somiglianza, e nessun posto in cui possa stare.**
    ///
    /// # Perché è la guardia che il congelamento chiede per nome
    ///
    /// Perché il freeze §9 elenca «una fusione automatica di identità per
    /// somiglianza di nome» fra i controlli negativi attesi.
    ///
    /// Il prodotto **ha** un algoritmo di somiglianza (ADR-0055), e serve a
    /// riconoscere due ripubblicazioni dello stesso testo. Applicarlo a due nomi
    /// di persona unirebbe due omonimi — l'errore che PERS-02 aveva già evitato
    /// raggruppando per identificativo.
    #[test]
    fn nessuna_somiglianza_e_nessun_posto_in_cui_possa_stare() {
        let produzione = codice_senza_commenti().to_lowercase();
        for vietata in [
            "similar",
            "somigli",
            "distance",
            "levenshtein",
            "fuzzy",
            "candidate",
            "candidat",
            "suggest",
            "suggeri",
            "propose",
            "propon",
            "match_name",
            "score",
        ] {
            assert!(
                !produzione.contains(vietata),
                "il modulo nomina «{vietata}»: una fusione per somiglianza e' vietata dal \
                 congelamento, e qui non deve esistere nemmeno la forma"
            );
        }
    }

    /// **Un legame non ha un punteggio di confidenza.**
    ///
    /// # Perché la guardia vieta la forma
    ///
    /// Perché vietare la parola «confidenza» lascerebbe passare `peso: f64`. Un
    /// numero accanto a un legame fra una persona e un fascicolo è la stessa cosa
    /// di un numero accanto a una persona.
    #[test]
    fn un_legame_non_ha_un_punteggio_di_confidenza() {
        let produzione = codice_senza_commenti();
        for struttura in [
            "pub struct NewIdentityLink {",
            "pub struct IdentityLinkEntry {",
            "pub struct LinkedIdentity {",
        ] {
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
                    "«{struttura}» ha un campo «{numerico}»: un numero su un legame si legge come \
                     una misura"
                );
            }
        }
    }

    /// **Il motivo non è opzionale, per nessuno dei due atti.**
    #[test]
    fn il_motivo_non_e_opzionale() {
        let produzione = codice_senza_commenti();
        assert!(
            !produzione.contains("Option<OperationalReason>"),
            "un motivo opzionale si passa None, e un legame senza motivo e' \
             indistinguibile da un automatismo"
        );
    }

    /// Il codice di produzione di questo modulo, senza commenti.
    fn codice_senza_commenti() -> String {
        let sorgente = include_str!("identity_link.rs");
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
