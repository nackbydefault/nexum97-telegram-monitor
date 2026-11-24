//! Il dominio Persona: **un soggetto investigativo, aperto da qualcuno, per una
//! ragione scritta** (PERS-01).
//!
//! # Che cosa un soggetto NON è: l'elenco dei partecipanti
//!
//! È la distinzione più importante di questa milestone, e va detta prima di
//! tutto il resto.
//!
//! «Persone» esiste già, ed è **derivata**: chi ha scritto durante un
//! monitoraggio, ricavato dai messaggi acquisiti. È un'**osservazione**, e non
//! afferma niente su nessuno.
//!
//! Un soggetto è un'altra cosa: è qualcuno su cui l'ufficio ha deciso di aprire
//! un fascicolo. Confonderli significherebbe che **chiunque abbia scritto una
//! volta in un gruppo monitorato diventa un soggetto** — che è esattamente ciò
//! che il congelamento vieta: «nessun profilo creato automaticamente per ogni
//! utente che compare in una fonte monitorata».
//!
//! Le due cose restano due, e nessuna riga passa dall'una all'altra da sola.
//!
//! # Nessun punteggio, e nessun posto in cui possa stare
//!
//! Il congelamento è esplicito: «mai una percentuale di pericolosità», «nessuna
//! attribuzione automatica di responsabilità», «nessuna classificazione
//! automatica di una persona come criminale o estremista per affiliazione
//! politica, critica politica, dissenso lecito, protesta lecita o
//! partecipazione a una manifestazione lecita».
//!
//! Il modo di rispettarlo non è ricordarsene: **[`Person`] non ha alcun campo
//! numerico**. Non un livello, non un rischio, non una probabilità, non un
//! conteggio che qualcuno possa leggere come una misura. Una prova lo verifica,
//! e un'altra vieta il vocabolario che quel campo avrebbe.
//!
//! La valutazione umana arriva con PERS-05: quattro stati **con un nome**, e un
//! atto di un operatore con motivo, istante e audit. Mai un numero.
//!
//! # Serve una ragione, ed è per **questo** soggetto
//!
//! La ragione degli elenchi di persone (ADR-0024) vale **una volta** e riguarda
//! l'ufficio: «perché componiamo elenchi di persone». Non autorizza ad aprire un
//! fascicolo su un nome.
//!
//! Trattarle come la stessa cosa lascerebbe che una frase scritta un anno fa
//! giustifichi ogni soggetto aperto da allora — ed è la differenza fra un atto
//! documentato e un atto e basta, che è l'argomento con cui quella regola esiste.
//!
//! La **regola** su che cosa sia una ragione è però una sola, e vive in
//! [`crate::model::reason`].

use crate::PersonId;
use crate::model::reason::OperationalReason;
use crate::text::{Actor, DisplayName};
use crate::time::Timestamp;

/// Un soggetto da aprire.
///
/// # Perché i campi sono privati
///
/// Perché il tipo garantisce ciò che una struttura aperta non garantirebbe: che
/// un soggetto **non si apra senza una ragione**. Il tipo della ragione la
/// convalida da sé, e un campo pubblico permetterebbe di costruirne uno
/// aggirandola.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewPerson {
    label: DisplayName,
    reason: OperationalReason,
}

impl NewPerson {
    /// Apre un soggetto.
    ///
    /// # Perché la ragione è un tipo e non una stringa
    ///
    /// Perché così **non si può chiamare senza**. Una convalida dentro la
    /// funzione si può dimenticare in un secondo servizio; un parametro che
    /// esiste solo se qualcuno ha scritto venti caratteri no.
    ///
    /// # Perché non restituisce un errore
    ///
    /// Perché non ne ha uno da restituire. I due valori che servono sono
    /// **entrambi tipi che si convalidano da sé**: `DisplayName` rifiuta già
    /// un'etichetta vuota, e `OperationalReason` rifiuta già una ragione che
    /// non è una ragione.
    ///
    /// Un controllo qui sarebbe codice morto, e — peggio — una prova scritta
    /// per esercitarlo **non potrebbe costruire il caso**: `DisplayName::try_new`
    /// non restituisce mai un'etichetta vuota. Sarebbe una guardia che sorveglia
    /// una cosa che da qui non può accadere, e il progetto ne ha già trovata
    /// una in SEARCH-01.
    #[must_use]
    pub const fn open(label: DisplayName, reason: OperationalReason) -> Self {
        Self { label, reason }
    }

    /// Come l'ufficio chiama questo soggetto.
    #[must_use]
    pub const fn label(&self) -> &DisplayName {
        &self.label
    }

    /// Perché è stato aperto.
    #[must_use]
    pub const fn reason(&self) -> &OperationalReason {
        &self.reason
    }
}

/// La chiusura di un soggetto: chi, quando, e perché.
///
/// # Perché i tre valori stanno insieme
///
/// Perché un fascicolo chiuso senza motivo non dice se sia stato chiuso perché
/// non c'era niente o perché nessuno se ne occupava più. Sono due esiti
/// diversi, e chi rilegge deve poterli distinguere.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PersonClosure {
    /// Chi lo ha chiuso.
    pub by: Actor,
    /// Quando.
    pub at: Timestamp,
    /// Perché.
    pub reason: OperationalReason,
}

/// Un soggetto investigativo.
///
/// # Che cosa questo tipo non ha, e non avrà
///
/// Un punteggio. Non un livello, non un rischio, non una probabilità: **nessun
/// campo numerico**, perché un campo numerico su una persona diventa una misura
/// il giorno in cui qualcuno lo mostra accanto a un nome.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Person {
    /// Identificativo interno stabile.
    ///
    /// È dell'archivio, non della piattaforma: una persona **non è un account
    /// Telegram**, e le identità osservate arriveranno con PERS-02.
    pub id: PersonId,
    /// Come l'ufficio lo chiama.
    pub label: DisplayName,
    /// Perché è stato aperto.
    pub reason: OperationalReason,
    /// Chi lo ha aperto.
    pub opened_by: Actor,
    /// Quando.
    pub opened_at: Timestamp,
    /// Se e da chi è stato chiuso.
    pub closure: Option<PersonClosure>,
}

impl Person {
    /// Se il fascicolo è ancora aperto.
    ///
    /// # Perché una domanda e non un confronto
    ///
    /// Perché chi mostra la riga deve poter chiedere «è ancora aperto?» senza
    /// ispezionare la forma della chiusura.
    #[must_use]
    pub const fn is_open(&self) -> bool {
        self.closure.is_none()
    }

    /// Che cosa questo soggetto è, detto a chi legge.
    ///
    /// # Che cosa questa frase dice, e che cosa NON dice
    ///
    /// Dice chi lo ha aperto, quando, e — se è chiuso — chi lo ha chiuso e
    /// quando. **Non dice nulla sulla persona**: non un giudizio, non una
    /// misura, non un aggettivo. Un fascicolo aperto non è un'accusa, e la
    /// frase che lo presenta non deve suonare come tale.
    #[must_use]
    pub fn as_sentence(&self) -> String {
        match self.closure.as_ref() {
            None => format!(
                "Soggetto aperto da {} il {}. Un fascicolo aperto non \u{e8} una valutazione: \
                 dice che qualcuno ha deciso di raccogliere, e perch\u{e9}.",
                self.opened_by.as_str(),
                self.opened_at.to_readable_utc()
            ),
            Some(chiusura) => format!(
                "Soggetto aperto da {} il {}, chiuso da {} il {}. Non si riapre: se il lavoro \
                 riprende, se ne apre uno nuovo.",
                self.opened_by.as_str(),
                self.opened_at.to_readable_utc(),
                chiusura.by.as_str(),
                chiusura.at.to_readable_utc()
            ),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{NewPerson, Person, PersonClosure};
    use crate::PersonId;
    use crate::model::reason::OperationalReason;
    use crate::text::{Actor, DisplayName};
    use crate::time::Timestamp;

    /// Questo modulo, per le guardie strutturali.
    const THIS_MODULE: &str = include_str!("person.rs");

    const ORA: i64 = 1_700_000_000_000;

    fn attore(nome: &str) -> Actor {
        let Ok(attore) = Actor::try_new(nome) else {
            panic!("l'attore di prova deve essere valido");
        };
        attore
    }

    fn etichetta(testo: &str) -> DisplayName {
        let Ok(nome) = DisplayName::try_new(testo) else {
            panic!("l'etichetta di prova deve essere valida");
        };
        nome
    }

    fn ragione() -> OperationalReason {
        let Ok(ragione) =
            OperationalReason::try_new("richiesta della procura del 3 marzo, fascicolo 123/2026")
        else {
            panic!("la ragione di prova deve essere valida");
        };
        ragione
    }

    fn soggetto(chiusura: Option<PersonClosure>) -> Person {
        Person {
            id: PersonId::new(1),
            label: etichetta("Soggetto A"),
            reason: ragione(),
            opened_by: attore("operatore.prova"),
            opened_at: Timestamp::from_millis(ORA),
            closure: chiusura,
        }
    }

    /// Il codice di produzione, senza le prove.
    fn produzione() -> &'static str {
        let Some((produzione, _)) = THIS_MODULE.split_once("#[cfg(test)]\nmod tests {") else {
            panic!("il modulo deve avere un blocco di prove riconoscibile");
        };
        produzione
    }

    /// Il codice di produzione **senza i commenti**.
    ///
    /// # Perché serve, e che cosa è successo senza
    ///
    /// Perché la guardia che vieta il vocabolario del punteggio si è trovata
    /// rossa sulla propria **spiegazione**: il commento che dice «qui non c'è un
    /// punteggio» contiene la parola «punteggio».
    ///
    /// Una guardia rossa sulla prosa che la giustifica verrebbe tolta al primo
    /// fastidio. Si guarda il **codice**.
    fn codice_senza_commenti() -> String {
        produzione()
            .lines()
            .filter(|riga| {
                let riga = riga.trim_start();
                !riga.starts_with("//") && !riga.starts_with("///") && !riga.starts_with("//!")
            })
            .collect::<Vec<_>>()
            .join("\n")
    }

    /// I campi dichiarati da una struttura.
    fn campi_di(intestazione: &str) -> Vec<String> {
        let testo = produzione();
        let Some(inizio) = testo.find(intestazione) else {
            panic!("«{intestazione}» deve esistere");
        };
        let corpo = &testo[inizio + intestazione.len()..];
        let Some(fine) = corpo.find("\n}\n") else {
            panic!("«{intestazione}» deve chiudersi");
        };
        corpo[..fine]
            .lines()
            .map(str::trim)
            .filter(|riga| riga.contains(':') && !riga.starts_with("//"))
            .map(str::to_owned)
            .collect()
    }

    /// **Un soggetto non ha un punteggio, e non ha dove metterlo.**
    ///
    /// # Il difetto che questa prova impedisce
    ///
    /// Il solo che il congelamento nomina tre volte: «mai una percentuale di
    /// pericolosità», «nessuna attribuzione automatica di responsabilità»,
    /// «nessuna classificazione automatica di una persona come criminale o
    /// estremista».
    ///
    /// Un campo numerico su una persona **diventa una misura** il giorno in cui
    /// qualcuno lo mostra accanto a un nome, e non serve che qualcuno lo voglia:
    /// basta che il campo ci sia.
    ///
    /// # Perché la guardia guarda i tipi e non i nomi
    ///
    /// Perché un punteggio chiamato `peso` o `indice` passerebbe un controllo
    /// sui nomi. Qui si vieta **la forma**: nessun campo numerico, comunque si
    /// chiami.
    #[test]
    fn un_soggetto_non_ha_un_punteggio() {
        for intestazione in ["pub struct Person {", "pub struct NewPerson {"] {
            for campo in campi_di(intestazione) {
                for numerico in [
                    "u8", "u16", "u32", "u64", "usize", "i8", "i16", "i32", "i64", "isize", "f32",
                    "f64",
                ] {
                    assert!(
                        !campo.contains(&format!(": {numerico}")),
                        "«{intestazione}» ha un campo numerico: «{campo}». Un numero su una \
                         persona diventa una misura il giorno in cui qualcuno lo mostra accanto \
                         a un nome"
                    );
                }
            }
        }

        // E NEMMENO IL VOCABOLARIO, che e' il modo in cui un punteggio entra
        // portandosi dietro il proprio significato.
        let codice = codice_senza_commenti().to_lowercase();
        for parola in [
            "score",
            "punteggio",
            "risk",
            "rischio",
            "pericolosit",
            "threat",
            "probabilit",
            "livello",
        ] {
            assert!(
                !codice.contains(parola),
                "il codice nomina «{parola}»: il congelamento lo vieta, e un tipo che lo nomina \
                 e' un tipo che prima o poi lo porta"
            );
        }
    }

    /// **Un soggetto non si apre senza una ragione, e non per convalida.**
    ///
    /// # Perché il compilatore e non un controllo
    ///
    /// Perché [`NewPerson::open`] prende una `OperationalReason`, che esiste
    /// solo se qualcuno ha scritto abbastanza. Un controllo dentro la funzione
    /// si può dimenticare in un secondo servizio; un parametro no.
    #[test]
    fn un_soggetto_non_si_apre_senza_una_ragione() {
        // LA FIRMA LO DICE: la ragione non e' una stringa da convalidare, e'
        // un valore che esiste solo se qualcuno ne ha scritta una.
        let codice = codice_senza_commenti();
        assert!(
            codice.contains("fn open(label: DisplayName, reason: OperationalReason)"),
            "la ragione deve essere un tipo, non una stringa da convalidare"
        );
        assert!(
            !codice.contains("fn open(label: DisplayName, reason: &str)"),
            "una stringa si puo' passare vuota, e la convalida si puo' dimenticare"
        );

        // E una ragione che non e' una ragione non si costruisce.
        assert!(OperationalReason::try_new("ok").is_err());
    }

    /// **Un'etichetta vuota non arriva nemmeno fino a qui.**
    ///
    /// # Perché la prova è questa e non «aprire con l'etichetta vuota fallisce»
    ///
    /// Perché quella prova **non si può scrivere**: `DisplayName::try_new` non
    /// restituisce mai un'etichetta vuota, quindi il caso non si costruisce.
    ///
    /// Il primo tentativo aveva un controllo dentro `open` e una prova che
    /// cercava di esercitarlo: la prova è fallita costruendo il proprio dato,
    /// non eseguendo la funzione. Era una guardia che sorvegliava una cosa che
    /// da lì non poteva accadere — la stessa forma trovata in SEARCH-01 — e la
    /// correzione è stata togliere il controllo morto e verificare **dove la
    /// garanzia sta davvero**.
    #[test]
    fn una_etichetta_vuota_non_arriva_fino_a_qui() {
        for vuota in ["", "   ", "\t"] {
            assert!(
                DisplayName::try_new(vuota).is_err(),
                "«{vuota:?}» non e' un'etichetta, e il tipo lo dice prima di arrivare al soggetto"
            );
        }
        let _ = NewPerson::open(etichetta("Soggetto A"), ragione());
    }

    /// **La frase non dice niente sulla persona.**
    ///
    /// # Il difetto che questa prova impedisce
    ///
    /// Una frase che suoni come un'accusa. Un fascicolo aperto dice che qualcuno
    /// ha deciso di raccogliere, e perché: non dice che quella persona abbia
    /// fatto qualcosa.
    #[test]
    fn la_frase_non_dice_niente_sulla_persona() {
        let frase = soggetto(None).as_sentence();
        assert!(frase.contains("operatore.prova"), "{frase}");
        assert!(
            frase.contains("non \u{e8} una valutazione"),
            "la frase deve dire che cosa NON e' \u{2014} {frase}"
        );
        for giudizio in [
            "sospett", "pericolo", "criminal", "estremis", "indagat", "colpevol",
        ] {
            assert!(
                !frase.to_lowercase().contains(giudizio),
                "la frase contiene «{giudizio}»: un fascicolo aperto non e' un'accusa"
            );
        }
    }

    /// **Un soggetto chiuso lo dice, e dice che non si riapre.**
    #[test]
    fn un_soggetto_chiuso_dice_che_non_si_riapre() {
        let aperto = soggetto(None);
        assert!(aperto.is_open());

        let chiuso = soggetto(Some(PersonClosure {
            by: attore("altro.operatore"),
            at: Timestamp::from_millis(ORA + 3_600_000),
            reason: ragione(),
        }));
        assert!(!chiuso.is_open());
        let frase = chiuso.as_sentence();
        assert!(frase.contains("altro.operatore"), "{frase}");
        assert!(frase.contains("Non si riapre"), "{frase}");
        assert!(
            frase.contains("se ne apre uno nuovo"),
            "la frase deve dire che cosa fare \u{2014} {frase}"
        );
    }

    /// **La chiusura tiene insieme chi, quando e perché.**
    ///
    /// # Perché la ragione anche qui
    ///
    /// Perché un fascicolo chiuso senza motivo non dice se sia stato chiuso
    /// perché non c'era niente o perché nessuno se ne occupava più. Sono due
    /// esiti diversi.
    #[test]
    fn la_chiusura_tiene_insieme_chi_quando_e_perche() {
        let campi = campi_di("pub struct PersonClosure {");
        assert_eq!(campi.len(), 3, "chi, quando e perche' \u{2014} {campi:?}");
        assert!(
            campi
                .iter()
                .any(|c| c.contains("reason: OperationalReason"))
        );
    }

    /// **Il dominio non conosce Telegram.**
    ///
    /// # Il difetto che questa prova impedisce
    ///
    /// Una persona identificata dal proprio account. Una persona **non è** un
    /// account: può averne più d'uno, può cambiarlo, e l'account può cambiare
    /// padrone. Le identità osservate arriveranno con PERS-02, e staranno in
    /// un'altra tabella proprio perché nessuna di esse definisce la persona.
    #[test]
    fn il_dominio_non_conosce_telegram() {
        for telegram in [
            "telegram_id",
            "TelegramId",
            "username",
            "user_id",
            "remote_id",
        ] {
            assert!(
                !produzione().contains(telegram),
                "il dominio nomina «{telegram}»: una persona non e' un account, e identificarla \
                 con uno la definirebbe con qualcosa che puo' cambiare padrone"
            );
        }
    }

    /// **Il dominio non sa costruire un soggetto da un'osservazione.**
    ///
    /// # Il difetto che questa prova impedisce
    ///
    /// Il solo che la Fase 6 nomina nella propria intestazione: «non si crea un
    /// profilo per ogni utente Telegram solo perché compare in una fonte
    /// monitorata».
    ///
    /// Una conversione da partecipante osservato a soggetto sarebbe il primo
    /// passo, e sembrerebbe una comodità.
    #[test]
    fn il_dominio_non_sa_costruire_un_soggetto_da_una_osservazione() {
        for derivazione in [
            "Participant",
            "from_participant",
            "from_content",
            "Content",
            "impl From<",
        ] {
            assert!(
                !produzione().contains(derivazione),
                "il dominio nomina «{derivazione}»: un soggetto si apre perche' qualcuno lo \
                 decide, non perche' qualcuno ha scritto in un gruppo"
            );
        }
    }
}
