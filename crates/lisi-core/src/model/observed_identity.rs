//! Identità Telegram **osservate** e storia degli alias (PERS-02).
//!
//! # Perché il nome dice «osservata»
//!
//! Perché in questo prodotto «identità» significa già un'altra cosa:
//! [`crate::model::identity`] è l'identità **di dispositivo e di operatore** —
//! quale macchina sta parlando, chi sta agendo.
//!
//! Qui si parla di ciò che una fonte Telegram ha mostrato: un identificativo,
//! un nome, uno username. Due nozioni con lo stesso nome si confondono alla
//! prima lettura distratta, e la confusione fra «chi agisce sulla postazione» e
//! «chi è stato osservato in un gruppo» sarebbe la peggiore possibile.
//!
//! # Che cosa questo modulo costruisce, e perché non una tabella
//!
//! Niente di nuovo. I nomi che qualcuno ha portato nel tempo **sono già
//! nell'archivio**: ogni contenuto acquisito conserva chi lo ha scritto, con il
//! nome leggibile e lo username di allora, e i contenuti non cambiano.
//!
//! Il modulo dei partecipanti lo dice già, scegliendo il nome più recente: «i
//! precedenti restano nei contenuti, che non cambiano». Questa milestone li
//! rende **leggibili**.
//!
//! Conservarli in una tabella propria creerebbe una seconda copia che può
//! divergere da ciò che i contenuti dicono, e non aggiungerebbe niente: la
//! storia si ricava, e ogni riga rimanda al contenuto che l'ha mostrata.
//!
//! # Nessuna fusione automatica per somiglianza di nome
//!
//! Il congelamento lo scrive con queste parole, ed è la guardia di questa
//! milestone.
//!
//! Le osservazioni si raggruppano **per identificativo**, mai per nome.
//! Raggrupparle per nome unirebbe due persone omonime e separerebbe una che ha
//! cambiato nome — che è l'errore opposto, e insieme fanno un elenco che non
//! significa niente.
//!
//! Lo username **non è un'identità**: può essere rilasciato e preso da qualcun
//! altro.
//!
//! # «Prima osservato» non è «cambiato»
//!
//! È la cosa che questo modulo deve dire e che nessuno vedrebbe da sé.
//!
//! L'archivio sa **quando ha visto per la prima volta** un nome nuovo. Non sa
//! quando quella persona lo ha cambiato: può averlo fatto un minuto prima, o sei
//! mesi prima, in un periodo in cui non ha scritto niente.
//!
//! Perciò i campi si chiamano `first_observed_at`, e le frasi dicono
//! «osservato», mai «cambiato». È ADR-0053 applicato a una persona, dove
//! affermare un istante che nessuno ha misurato si porta dietro conseguenze.

use std::collections::BTreeMap;

use crate::ContentId;
use crate::time::Timestamp;

/// Che cosa un alias osserva.
///
/// # Perché due generi e non un campo di testo
///
/// Perché il nome leggibile e lo username sono due cose diverse con due
/// significati diversi: il primo è come una persona si presenta, il secondo è
/// come la si ritrova su Telegram **oggi**. Mescolarli in un elenco unico
/// renderebbe una storia illeggibile.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum AliasKind {
    /// Il nome leggibile che la piattaforma annunciava.
    DisplayName,
    /// Lo username, senza chiocciola.
    Username,
}

impl AliasKind {
    /// Come si nomina a chi legge.
    #[must_use]
    pub const fn as_label(self) -> &'static str {
        match self {
            Self::DisplayName => "Nome visualizzato",
            Self::Username => "Username",
        }
    }
}

/// Un valore osservato per un'identità, e da quando lo si è visto.
///
/// # Perché «osservato» e non «cambiato»
///
/// Perché l'archivio sa quando ha **visto** questo valore per la prima volta.
/// Non sa quando quella persona lo ha adottato: può averlo fatto molto prima, in
/// un periodo in cui non ha scritto niente.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AliasObservation {
    /// Che cosa si osserva.
    pub kind: AliasKind,
    /// Il valore, oppure niente se in quell'osservazione non ce n'era uno.
    ///
    /// `None` **non significa «lo ha tolto»**: significa che i contenuti di
    /// quel periodo non ne portavano uno. Per i messaggi di canale e per chi
    /// semplicemente non ha uno username è la situazione ordinaria, e la
    /// migrazione che conserva quel campo lo dice.
    pub value: Option<String>,
    /// Quando lo si è **osservato per la prima volta**.
    pub first_observed_at: Timestamp,
    /// In quale contenuto lo si è osservato: è la provenienza di questa riga.
    ///
    /// # Perché un identificativo e non una chiave esterna
    ///
    /// Perché la conservazione cancella i contenuti vecchi, e una chiave esterna
    /// porterebbe via con essi la storia — o impedirebbe di applicarla. Il
    /// riferimento resta, e chi legge riceve la dichiarazione che quel contenuto
    /// non è più nell'archivio invece del silenzio.
    pub observed_in: ContentId,
}

impl AliasObservation {
    /// Che cosa si è osservato, detto a chi legge.
    ///
    /// # Che cosa questa frase non dice
    ///
    /// Quando la persona ha cambiato nome. L'archivio non lo sa, e una frase
    /// che lo affermasse inventerebbe un istante.
    #[must_use]
    pub fn as_sentence(&self) -> String {
        match self.value.as_ref() {
            Some(valore) => format!(
                "{}: «{valore}», osservato per la prima volta il {}.",
                self.kind.as_label(),
                self.first_observed_at.to_readable_utc()
            ),
            None => format!(
                "{}: nessuno, in ci\u{f2} che si \u{e8} osservato dal {}. Non significa che \
                 sia stato tolto: i contenuti di quel periodo non ne portavano uno.",
                self.kind.as_label(),
                self.first_observed_at.to_readable_utc()
            ),
        }
    }
}

/// Un'identità Telegram osservata, con la sua storia.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObservedIdentity {
    /// L'identificativo presso la piattaforma.
    ///
    /// È l'**unico** dei campi che regge nel tempo, ed è la chiave con cui le
    /// osservazioni si raggruppano.
    pub identifier: String,
    /// Prima osservazione fra i contenuti esaminati.
    pub first_seen: Timestamp,
    /// Ultima osservazione.
    pub last_seen: Timestamp,
    /// I valori osservati, dal più antico al più recente.
    ///
    /// Contiene **un elemento per ogni cambiamento osservato**, non uno per
    /// contenuto: se qualcuno ha portato lo stesso nome per mille messaggi,
    /// qui c'è una riga sola.
    pub aliases: Vec<AliasObservation>,
}

impl ObservedIdentity {
    /// Se questa identità ha portato più di un valore di quel genere.
    #[must_use]
    pub fn has_history(&self, kind: AliasKind) -> bool {
        self.aliases.iter().filter(|a| a.kind == kind).count() > 1
    }

    /// Se c'è qualcosa da raccontare: almeno un valore è cambiato.
    ///
    /// # Perché serve
    ///
    /// Perché mostrare «si è sempre chiamato così» sotto ogni riga sarebbe
    /// rumore, e il rumore fa smettere di leggere anche ciò che conta.
    #[must_use]
    pub fn has_any_history(&self) -> bool {
        self.has_history(AliasKind::DisplayName) || self.has_history(AliasKind::Username)
    }

    /// Che cosa si sa di questa identità, detto a chi legge.
    ///
    /// # Che cosa questa frase dice, e che cosa non dice
    ///
    /// Dice che i nomi sono **osservati**. Non dice che la persona abbia
    /// cambiato nome in un certo momento: quello l'archivio non lo sa.
    #[must_use]
    pub fn as_sentence(&self) -> String {
        if !self.has_any_history() {
            return format!(
                "Un solo nome osservato, dal {} al {}.",
                self.first_seen.to_readable_utc(),
                self.last_seen.to_readable_utc()
            );
        }
        format!(
            "Pi\u{f9} di un nome osservato, dal {} al {}. Gli istanti dicono quando il nome \
             \u{e8} stato visto la prima volta, non quando \u{e8} stato cambiato. Fra \
             un'osservazione e l'altra pu\u{f2} essere passato molto tempo.",
            self.first_seen.to_readable_utc(),
            self.last_seen.to_readable_utc()
        )
    }
}

/// Ciò che serve per ricavare la storia: un'osservazione di un contenuto.
///
/// # Perché un tipo proprio e non il contenuto
///
/// Perché la derivazione ha bisogno di **cinque valori**, e prendere il
/// contenuto intero le darebbe accesso al corpo del messaggio — che qui non
/// serve e non deve arrivare. Una funzione che non riceve una cosa non può
/// usarla.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IdentitySighting {
    /// Quale contenuto lo ha mostrato.
    pub content: ContentId,
    /// L'identificativo dell'autore.
    pub identifier: String,
    /// Il nome leggibile, se annunciato.
    pub display_name: Option<String>,
    /// Lo username, se ne aveva uno.
    pub username: Option<String>,
    /// Quando il contenuto è stato pubblicato.
    pub at: Timestamp,
}

/// Ricava le identità osservate e la loro storia.
///
/// # Perché una funzione pura
///
/// Perché il raggruppamento è la parte che merita una prova, e una prova non
/// deve costruire un archivio per esercitarla.
///
/// # Come si raggruppa, e come **non** si raggruppa
///
/// **Per identificativo, mai per nome.** Raggruppare per nome unirebbe due
/// persone omonime e separerebbe una che ha cambiato nome: il congelamento lo
/// vieta con queste parole, «nessuna fusione automatica di identità per
/// somiglianza di nome».
#[must_use]
pub fn observed_identities(sightings: &[IdentitySighting]) -> Vec<ObservedIdentity> {
    // ORDINATE NEL TEMPO, perche' una storia si legge dall'inizio.
    //
    // A parita' di istante si ordina per contenuto: senza, due osservazioni
    // simultanee darebbero una storia diversa a ogni lettura.
    let mut ordinate: Vec<&IdentitySighting> = sightings.iter().collect();
    ordinate.sort_by(|a, b| a.at.cmp(&b.at).then(a.content.get().cmp(&b.content.get())));

    let mut per_identificativo: BTreeMap<&str, ObservedIdentity> = BTreeMap::new();

    for avvistamento in ordinate {
        let identita = per_identificativo
            .entry(avvistamento.identifier.as_str())
            .or_insert_with(|| ObservedIdentity {
                identifier: avvistamento.identifier.clone(),
                first_seen: avvistamento.at,
                last_seen: avvistamento.at,
                aliases: Vec::new(),
            });

        if avvistamento.at > identita.last_seen {
            identita.last_seen = avvistamento.at;
        }

        for (kind, valore) in [
            (AliasKind::DisplayName, &avvistamento.display_name),
            (AliasKind::Username, &avvistamento.username),
        ] {
            // UNA RIGA PER OGNI CAMBIAMENTO, NON PER OGNI CONTENUTO.
            //
            // Chi ha portato lo stesso nome per mille messaggi ha una riga
            // sola: mille righe uguali non sono una storia, sono un elenco che
            // nessuno scorre, e in mezzo al quale il cambiamento vero sparisce.
            let ultimo = identita
                .aliases
                .iter()
                .rev()
                .find(|a| a.kind == kind)
                .map(|a| &a.value);

            if ultimo != Some(valore) {
                identita.aliases.push(AliasObservation {
                    kind,
                    value: valore.clone(),
                    first_observed_at: avvistamento.at,
                    observed_in: avvistamento.content,
                });
            }
        }
    }

    per_identificativo.into_values().collect()
}

#[cfg(test)]
mod tests {
    use super::{AliasKind, IdentitySighting, observed_identities};
    use crate::ContentId;
    use crate::time::Timestamp;

    /// Questo modulo, per le guardie strutturali.
    const THIS_MODULE: &str = include_str!("observed_identity.rs");

    const ORA: i64 = 1_700_000_000_000;

    fn avvistamento(
        content: i64,
        identifier: &str,
        display_name: Option<&str>,
        username: Option<&str>,
        at: i64,
    ) -> IdentitySighting {
        IdentitySighting {
            content: ContentId::new(content),
            identifier: String::from(identifier),
            display_name: display_name.map(str::to_owned),
            username: username.map(str::to_owned),
            at: Timestamp::from_millis(at),
        }
    }

    /// **Le identità si raggruppano per identificativo, mai per nome.**
    ///
    /// # Il difetto che questa prova impedisce
    ///
    /// Il solo che il congelamento nomina per questa milestone: «nessuna
    /// fusione automatica di identità per somiglianza di nome».
    ///
    /// Raggruppare per nome fa **due errori insieme**: unisce due persone
    /// omonime, e separa una che ha cambiato nome. Un elenco che li commette
    /// entrambi non significa niente, e nessuno se ne accorge guardandolo.
    #[test]
    fn le_identita_si_raggruppano_per_identificativo_mai_per_nome() {
        let avvistamenti = vec![
            // DUE PERSONE CON LO STESSO NOME: restano due.
            avvistamento(1, "111", Some("Mario Rossi"), None, ORA),
            avvistamento(2, "222", Some("Mario Rossi"), None, ORA + 10),
            // UNA PERSONA CHE CAMBIA NOME: resta una.
            avvistamento(3, "111", Some("Mario R."), None, ORA + 20),
        ];

        let identita = observed_identities(&avvistamenti);
        assert_eq!(
            identita.len(),
            2,
            "due omonimi restano due, e chi cambia nome resta uno"
        );

        let Some(primo) = identita.iter().find(|i| i.identifier == "111") else {
            panic!("l'identificativo 111 deve esserci");
        };
        assert!(
            primo.has_history(AliasKind::DisplayName),
            "chi ha cambiato nome ha una storia"
        );
    }

    /// **Una riga per ogni cambiamento, non per ogni contenuto.**
    #[test]
    fn una_riga_per_ogni_cambiamento_non_per_ogni_contenuto() {
        let avvistamenti: Vec<IdentitySighting> = (0..10)
            .map(|i| avvistamento(i + 1, "111", Some("Mario"), Some("mario"), ORA + i))
            .collect();

        let identita = observed_identities(&avvistamenti);
        assert_eq!(identita.len(), 1);
        assert_eq!(
            identita[0].aliases.len(),
            2,
            "un nome e uno username, osservati una volta sola \u{2014} {:?}",
            identita[0].aliases
        );
        assert!(!identita[0].has_any_history(), "nulla e' cambiato");
    }

    /// **La storia è in ordine di tempo, e ripetibile.**
    ///
    /// # Il difetto che questa prova impedisce
    ///
    /// Una storia che cambia a ogni lettura. Due osservazioni con lo stesso
    /// istante, senza un secondo criterio, si ordinerebbero come capita — e chi
    /// rilegge vedrebbe due racconti diversi degli stessi fatti.
    #[test]
    fn la_storia_e_in_ordine_e_ripetibile() {
        let avvistamenti = vec![
            avvistamento(3, "111", Some("Terzo"), None, ORA + 20),
            avvistamento(1, "111", Some("Primo"), None, ORA),
            // STESSO ISTANTE del terzo: l'ordine lo decide il contenuto.
            avvistamento(2, "111", Some("Secondo"), None, ORA + 20),
        ];

        let prima = observed_identities(&avvistamenti);
        let mut mescolati = avvistamenti;
        mescolati.reverse();
        let dopo = observed_identities(&mescolati);

        assert_eq!(
            prima, dopo,
            "la storia non deve dipendere dall'ordine di lettura"
        );

        let nomi: Vec<Option<&str>> = prima[0]
            .aliases
            .iter()
            .filter(|a| a.kind == AliasKind::DisplayName)
            .map(|a| a.value.as_deref())
            .collect();
        assert_eq!(nomi, vec![Some("Primo"), Some("Secondo"), Some("Terzo")]);
    }

    /// **«Nessuno username» non è «lo ha tolto».**
    ///
    /// # Il difetto che questa prova impedisce
    ///
    /// Una frase che afferma una rimozione. L'assenza di username, dice la
    /// migrazione che conserva quel campo, è la situazione **ordinaria** per la
    /// maggioranza delle persone e per i messaggi di canale. Leggerla come un
    /// atto attribuirebbe a qualcuno una cosa che non ha fatto.
    #[test]
    fn nessuno_username_non_e_lo_ha_tolto() {
        let avvistamenti = vec![
            avvistamento(1, "111", Some("Mario"), Some("mario"), ORA),
            avvistamento(2, "111", Some("Mario"), None, ORA + 10),
        ];

        let identita = observed_identities(&avvistamenti);
        let senza = identita[0]
            .aliases
            .iter()
            .find(|a| a.kind == AliasKind::Username && a.value.is_none());
        let Some(senza) = senza else {
            panic!("l'assenza di username deve comparire nella storia");
        };

        let frase = senza.as_sentence();
        // MINUSCOLE, perche' la frase comincia una proposizione e la maiuscola
        // e' una scelta di punteggiatura, non di significato.
        assert!(
            frase
                .to_lowercase()
                .contains("non significa che sia stato tolto"),
            "{frase}"
        );
        for atto in ["rimoss", "cancellat", "eliminat"] {
            assert!(
                !frase.to_lowercase().contains(atto),
                "la frase dice «{atto}»: attribuirebbe un atto che nessuno ha osservato"
            );
        }
    }

    /// **Le frasi dicono «osservato», mai «cambiato».**
    ///
    /// # Il difetto che questa prova impedisce
    ///
    /// Un istante inventato. L'archivio sa quando ha **visto** un nome nuovo,
    /// non quando quella persona lo ha adottato: può averlo fatto sei mesi
    /// prima, in un periodo in cui non ha scritto niente.
    ///
    /// Dire «ha cambiato nome il 3 marzo» sarebbe un fatto che nessuno ha
    /// misurato, e in un fascicolo un fatto del genere si porta dietro
    /// conseguenze.
    #[test]
    fn le_frasi_dicono_osservato_mai_cambiato() {
        let avvistamenti = vec![
            avvistamento(1, "111", Some("Primo"), None, ORA),
            avvistamento(2, "111", Some("Secondo"), None, ORA + 10),
        ];
        let identita = observed_identities(&avvistamenti);

        let frase = identita[0].as_sentence();
        assert!(
            frase.contains("non quando \u{e8} stato cambiato"),
            "la frase deve dire che cosa gli istanti NON dicono \u{2014} {frase}"
        );

        for alias in &identita[0].aliases {
            let frase = alias.as_sentence();
            assert!(
                frase.contains("osservat"),
                "la frase di un alias deve dire «osservato» \u{2014} {frase}"
            );
            assert!(
                !frase.to_lowercase().contains("cambiat"),
                "e non «cambiato» \u{2014} {frase}"
            );
        }
    }

    /// **La derivazione non riceve il corpo del messaggio.**
    ///
    /// # Perché conta
    ///
    /// Perché una funzione che non riceve una cosa non può usarla. La storia
    /// degli alias si ricava da cinque valori, e dare in pasto il contenuto
    /// intero le darebbe accesso al testo — che qui non serve, e che in un
    /// modulo sulle persone non deve arrivare.
    #[test]
    fn la_derivazione_non_riceve_il_corpo() {
        let Some((produzione, _)) = THIS_MODULE.split_once("#[cfg(test)]\nmod tests {") else {
            panic!("il modulo deve avere un blocco di prove riconoscibile");
        };
        for corpo in ["body", "ContentBody", "text"] {
            assert!(
                !produzione.contains(corpo),
                "il modulo nomina «{corpo}»: la storia degli alias non ha bisogno del testo"
            );
        }
    }

    /// **C'è qualcosa da raccontare solo se qualcosa è cambiato.**
    #[test]
    fn c_e_qualcosa_da_raccontare_solo_se_qualcosa_e_cambiato() {
        let fermo = observed_identities(&[avvistamento(1, "111", Some("Mario"), None, ORA)]);
        assert!(!fermo[0].has_any_history());
        assert!(fermo[0].as_sentence().contains("Un solo nome osservato"));

        let cambiato = observed_identities(&[
            avvistamento(1, "111", Some("Mario"), None, ORA),
            avvistamento(2, "111", Some("Mario R."), None, ORA + 10),
        ]);
        assert!(cambiato[0].has_any_history());
    }

    /// **Due persone che si scambiano lo username restano due, ciascuna con la
    /// sua storia nell'ordine giusto** (IDENTITY-03, criterio 1; prova
    /// negativa: raggruppamento per username → rossa).
    ///
    /// È il caso che un raggruppamento per nome utente sbaglia due volte: il
    /// nome resta, le persone cambiano.
    #[test]
    fn due_persone_che_si_scambiano_lo_username_restano_due() {
        let avvistamenti = vec![
            avvistamento(1, "111", Some("Anna"), Some("alfa_uno"), ORA),
            avvistamento(2, "222", Some("Bruno"), Some("beta_due"), ORA + 10),
            avvistamento(3, "111", Some("Anna"), Some("beta_due"), ORA + 20),
            avvistamento(4, "222", Some("Bruno"), Some("alfa_uno"), ORA + 30),
        ];
        let identita = observed_identities(&avvistamenti);
        assert_eq!(identita.len(), 2, "due identificativi, due persone");
        let storia = |id: &str| -> Vec<String> {
            identita
                .iter()
                .find(|i| i.identifier == id)
                .map(|i| {
                    i.aliases
                        .iter()
                        .filter(|a| a.kind == AliasKind::Username)
                        .filter_map(|a| a.value.clone())
                        .collect()
                })
                .unwrap_or_default()
        };
        assert_eq!(storia("111"), ["alfa_uno", "beta_due"]);
        assert_eq!(storia("222"), ["beta_due", "alfa_uno"]);
    }

    /// **Le grafie simili non uniscono e non si correggono: ciascuna resta
    /// com'è stata osservata** (IDENTITY-03, criterio 2).
    ///
    /// Maiuscole, un accento, una lettera cirillica che sembra latina, uno
    /// spazio in più: per una persona che legge sono lo stesso nome, per il
    /// programma sono grafie diverse, e non tocca al programma decidere che
    /// due persone sono una.
    #[test]
    fn le_grafie_simili_non_uniscono_e_non_si_correggono() {
        let grafie = [
            "Mario Rossi",
            "mario rossi",
            "Mario Rossì",
            "\u{41c}ario Rossi",
            "Mario  Rossi",
        ];
        let numero = |indice: usize| i64::try_from(indice).unwrap_or(0);
        let distinti: Vec<IdentitySighting> = grafie
            .iter()
            .enumerate()
            .map(|(indice, nome)| {
                avvistamento(
                    numero(indice) + 1,
                    &format!("{}", 100 + indice),
                    Some(nome),
                    None,
                    ORA,
                )
            })
            .collect();
        assert_eq!(
            observed_identities(&distinti).len(),
            grafie.len(),
            "cinque identificativi con grafie simili restano cinque identità"
        );

        let stesso: Vec<IdentitySighting> = grafie
            .iter()
            .enumerate()
            .map(|(indice, nome)| {
                avvistamento(
                    numero(indice) + 1,
                    "777",
                    Some(nome),
                    None,
                    ORA + numero(indice),
                )
            })
            .collect();
        let una = observed_identities(&stesso);
        assert_eq!(una.len(), 1);
        let nomi: Vec<&str> = una[0]
            .aliases
            .iter()
            .filter(|a| a.kind == AliasKind::DisplayName)
            .filter_map(|a| a.value.as_deref())
            .collect();
        assert_eq!(
            nomi, grafie,
            "ogni grafia è un nome osservato, nessuna si corregge in un'altra"
        );
    }
}
