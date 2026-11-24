//! La fotografia di un contesto: ciò che una persona ha visto, e perché lo ha
//! conservato.
//!
//! # La regola che questa milestone poteva tradire
//!
//! Il congelamento lo scrive da CTX-02: «scorrere la vista **non** trasforma
//! ciò che si vede in prova operativa». Fino a ieri il modo di rispettarla era
//! semplice — **nessuno scriveva niente**, e una prova cercava nel sorgente
//! ogni scrittura.
//!
//! CTX-06 scrive per forza. La regola resta vera, e va garantita altrove.
//!
//! # La garanzia: conservare non può osservare
//!
//! Sono due capacità, e **non stanno mai nella stessa funzione**.
//!
//! Chi legge un contesto riceve l'archivio in sola lettura e un connettore
//! verso Telegram: può osservare, e non può scrivere. Chi prende una fotografia
//! riceve l'archivio scrivibile e **nessun connettore**: può conservare, e non
//! può osservare.
//!
//! Ne segue ciò che serve: una fotografia contiene **soltanto** ciò che era già
//! stato mostrato a una persona. Non esiste un percorso che, in silenzio,
//! chieda qualcosa a Telegram e lo archivi. Scorrere non conserva, e conservare
//! non guarda.
//!
//! # La seconda garanzia: non esiste una fotografia senza un perché
//!
//! [`NewContextSnapshot`] ha campi privati e un solo costruttore, che **rifiuta**
//! una ragione vuota. Non è una convalida che qualcuno potrebbe dimenticare di
//! chiamare: è l'unica strada per costruire il tipo.
//!
//! Conservare ciò che si vede su Telegram è un atto di cui qualcuno risponde, e
//! un atto senza ragione non è documentato: è soltanto avvenuto. È la stessa
//! disciplina delle revisioni che contraddicono il motore.
//!
//! # La terza garanzia: l'impronta si calcola, non si riceve
//!
//! [`NewContextSnapshot::integrity`] è calcolata da questo modulo sui dati che
//! la fotografia porta. Non è un parametro: nessuno può consegnare un'impronta
//! che non corrisponde a ciò che sta conservando.
//!
//! E [`ContextSnapshot::verify`] la ricalcola. Un'impronta che non si può
//! ricontrollare non è un'impronta: è un numero.
//!
//! # Che cosa una fotografia NON è
//!
//! **Non è una prova acquisita.** La prova sta in `contents`, è stata acquisita
//! dal monitoraggio, e non cambia. Una fotografia è un'**osservazione
//! documentata**: dice che una certa persona, in un certo istante e per una
//! certa ragione, ha visto questo.
//!
//! È esattamente ciò che la rende utile senza fingere: non pretende di essere
//! ciò che non è, e chi la legge sa che cosa ha in mano.

use crate::digest::Sha256Digest;
use crate::error::{DomainError, DomainResult};
use crate::model::content_history::VersionChange;
use crate::model::context_state::Divergence;
use crate::text::{Actor, Note};
use crate::time::Timestamp;
use crate::{ContentId, ContextSnapshotId, SourceId};

/// Una riga del contorno, come fu vista.
///
/// # Perché conserva il testo
///
/// Perché una fotografia che conservasse i soli identificativi non sarebbe
/// rileggibile: domani quei messaggi possono non esserci più, ed è proprio il
/// caso in cui una fotografia serve.
///
/// # Perché questo testo non è una prova
///
/// Perché fu **letto**, non acquisito. Vive in una tabella diversa da quella
/// dei contenuti, e non esiste alcuna conversione verso un contenuto.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SnapshotMessage {
    /// Identificativo del messaggio presso Telegram.
    pub remote_message_id: String,
    /// Istante di pubblicazione dichiarato allora.
    pub published_at: Timestamp,
    /// Il testo, **come si leggeva allora**.
    pub body: String,
    /// La frase su chi lo aveva scritto, **come fu composta allora**.
    ///
    /// Si conserva la frase e non i suoi pezzi: ricomporla domani, con il
    /// codice di domani, direbbe che quel giorno si era letta una frase che non
    /// si era letta.
    pub author_sentence: String,
    /// La frase sulle relazioni, quando ce n'erano.
    pub relations_sentence: Option<String>,
    /// Se era il messaggio attorno a cui il contesto era stato chiesto.
    pub is_anchor: bool,
}

/// Il confronto fra la prova e lo stato corrente, **come fu osservato allora**.
///
/// # Perché si conserva invece di ricalcolarlo
///
/// Perché era un'osservazione **datata**. Ricalcolarlo domani, sui testi di
/// domani, direbbe che quel giorno si era osservato qualcosa che non si era
/// osservato.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SnapshotComparison {
    /// La relazione esatta fra i due testi (ADR-0051).
    pub change: VersionChange,
    /// Se differivano, e se Telegram lo dichiarava.
    pub divergence: Divergence,
}

/// Una fotografia da conservare.
///
/// # Perché i campi sono privati
///
/// Perché il tipo garantisce due cose che una struttura aperta non
/// garantirebbe: che ci sia una ragione, e che l'impronta corrisponda a ciò che
/// si sta conservando.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewContextSnapshot {
    content_id: ContentId,
    source_id: SourceId,
    taken_by: Actor,
    reason: Note,
    taken_at: Timestamp,
    observed_at: Timestamp,
    anchor_remote_message_id: String,
    anchor_digest: Sha256Digest,
    comparison: Option<SnapshotComparison>,
    declared_edit_at: Option<Timestamp>,
    messages: Vec<SnapshotMessage>,
    integrity: Sha256Digest,
}

impl NewContextSnapshot {
    /// Prepara una fotografia.
    ///
    /// # Errori
    ///
    /// Restituisce [`DomainError`] quando la ragione è vuota o composta di soli
    /// spazi: conservare ciò che si vede è un atto di cui qualcuno risponde, e
    /// un atto senza ragione non è documentato.
    ///
    /// # Perché l'impronta non è un parametro
    ///
    /// Perché sarebbe possibile consegnarne una che non corrisponde. Qui si
    /// calcola sui dati che la fotografia porta, e non c'è altra strada.
    #[expect(
        clippy::too_many_arguments,
        reason = "il congelamento elenca che cosa una fotografia deve portare: provenienza, \
                  fonte, identificativi, ragione, operatore, istante, integrita'. Raggrupparli \
                  in una struttura intermedia sposterebbe il problema senza toglierne uno"
    )]
    pub fn prepare(
        content_id: ContentId,
        source_id: SourceId,
        taken_by: &Actor,
        reason: &Note,
        taken_at: Timestamp,
        observed_at: Timestamp,
        anchor_remote_message_id: &str,
        anchor_body: &str,
        comparison: Option<SnapshotComparison>,
        declared_edit_at: Option<Timestamp>,
        messages: Vec<SnapshotMessage>,
    ) -> DomainResult<Self> {
        // UNA RAGIONE FATTA DI SOLI SPAZI NON E' UNA RAGIONE.
        //
        // Si riusa `Empty`, che il progetto ha gia' per questo: un errore nuovo
        // direbbe la stessa cosa con parole diverse, e due modi di dire la
        // stessa cosa divergono. La frase per l'operatore la compone il
        // servizio, che sa di quale atto si tratta.
        if reason.as_str().trim().is_empty() {
            return Err(DomainError::Empty { field: "reason" });
        }

        let anchor_digest = Sha256Digest::of_text(anchor_body);
        let integrity = compute_integrity(
            content_id,
            source_id,
            taken_by,
            reason,
            taken_at,
            observed_at,
            anchor_remote_message_id,
            &anchor_digest,
            comparison,
            declared_edit_at,
            &messages,
        );

        Ok(Self {
            content_id,
            source_id,
            taken_by: taken_by.clone(),
            reason: reason.clone(),
            taken_at,
            observed_at,
            anchor_remote_message_id: anchor_remote_message_id.to_owned(),
            anchor_digest,
            comparison,
            declared_edit_at,
            messages,
            integrity,
        })
    }

    /// Il contenuto dell'archivio attorno a cui si guardava.
    #[must_use]
    pub const fn content_id(&self) -> ContentId {
        self.content_id
    }

    /// La fonte da cui quel contenuto proviene.
    #[must_use]
    pub const fn source_id(&self) -> SourceId {
        self.source_id
    }

    /// Chi l'ha presa.
    #[must_use]
    pub const fn taken_by(&self) -> &Actor {
        &self.taken_by
    }

    /// Perché.
    #[must_use]
    pub const fn reason(&self) -> &Note {
        &self.reason
    }

    /// Quando è stata presa.
    #[must_use]
    pub const fn taken_at(&self) -> Timestamp {
        self.taken_at
    }

    /// Quando il contorno era stato letto da Telegram.
    #[must_use]
    pub const fn observed_at(&self) -> Timestamp {
        self.observed_at
    }

    /// L'identificativo remoto del messaggio scelto.
    #[must_use]
    pub fn anchor_remote_message_id(&self) -> &str {
        &self.anchor_remote_message_id
    }

    /// L'impronta del testo acquisito, al momento della fotografia.
    #[must_use]
    pub const fn anchor_digest(&self) -> &Sha256Digest {
        &self.anchor_digest
    }

    /// Il confronto come fu osservato allora.
    #[must_use]
    pub const fn comparison(&self) -> Option<SnapshotComparison> {
        self.comparison
    }

    /// L'istante che Telegram dichiarava come modifica.
    #[must_use]
    pub const fn declared_edit_at(&self) -> Option<Timestamp> {
        self.declared_edit_at
    }

    /// Le righe del contorno, nell'ordine in cui furono viste.
    #[must_use]
    pub fn messages(&self) -> &[SnapshotMessage] {
        &self.messages
    }

    /// L'impronta dell'atto e di tutte le sue righe.
    #[must_use]
    pub const fn integrity(&self) -> &Sha256Digest {
        &self.integrity
    }
}

/// Una fotografia conservata.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContextSnapshot {
    /// Identificativo assegnato dall'archivio.
    pub id: ContextSnapshotId,
    /// Il contenuto attorno a cui si guardava.
    pub content_id: ContentId,
    /// La fonte da cui quel contenuto proviene.
    pub source_id: SourceId,
    /// Chi l'ha presa.
    pub taken_by: Actor,
    /// Perché.
    pub reason: Note,
    /// Quando è stata presa.
    pub taken_at: Timestamp,
    /// Quando il contorno era stato letto.
    pub observed_at: Timestamp,
    /// L'identificativo remoto del messaggio scelto.
    pub anchor_remote_message_id: String,
    /// L'impronta del testo acquisito, al momento della fotografia.
    pub anchor_digest: Sha256Digest,
    /// Il confronto come fu osservato allora.
    pub comparison: Option<SnapshotComparison>,
    /// L'istante dichiarato come modifica, allora.
    pub declared_edit_at: Option<Timestamp>,
    /// Le righe del contorno, nell'ordine in cui furono viste.
    pub messages: Vec<SnapshotMessage>,
    /// L'impronta registrata quando fu presa.
    pub integrity: Sha256Digest,
}

impl ContextSnapshot {
    /// Se la fotografia è quella che fu presa.
    ///
    /// Ricalcola l'impronta sui dati riletti e la confronta con quella
    /// registrata. Un'impronta che non si può ricontrollare non è un'impronta:
    /// è un numero.
    #[must_use]
    pub fn verify(&self) -> bool {
        compute_integrity(
            self.content_id,
            self.source_id,
            &self.taken_by,
            &self.reason,
            self.taken_at,
            self.observed_at,
            &self.anchor_remote_message_id,
            &self.anchor_digest,
            self.comparison,
            self.declared_edit_at,
            &self.messages,
        ) == self.integrity
    }

    /// Che cosa questa fotografia è, detto a chi legge.
    ///
    /// # Perché la frase dice sempre che non è una prova acquisita
    ///
    /// Perché è l'unica cosa che la distingue dal contenuto accanto a cui
    /// compare, e chi la guarda a lungo smette di ricordarsene.
    #[must_use]
    pub fn as_sentence(&self) -> String {
        format!(
            "Fotografia presa da {} il {}, per questa ragione: «{}». Conserva ci\u{f2} che \
             Telegram mostrava il {}: {} messagg{} attorno al contenuto {}. Non \u{e8} una \
             prova acquisita: \u{e8} un'osservazione documentata, e la prova resta il testo \
             dell'archivio.",
            self.taken_by.as_str(),
            self.taken_at.to_readable_utc(),
            self.reason.as_str(),
            self.observed_at.to_readable_utc(),
            self.messages.len(),
            if self.messages.len() == 1 { "io" } else { "i" },
            self.content_id.get()
        )
    }
}

/// L'impronta dell'atto e di tutte le sue righe.
///
/// # Perché ogni campo entra, e con un separatore
///
/// Perché un'impronta che coprisse solo i testi non si accorgerebbe di una
/// ragione cambiata, e una che concatenasse senza separatore confonderebbe
/// «ab» + «c» con «a» + «bc».
///
/// Il separatore è `\u{1f}` — il separatore di unità di ASCII — che non compare
/// nei testi di Telegram e non richiede di sfuggire nulla.
#[expect(
    clippy::too_many_arguments,
    reason = "copre tutto cio' che la fotografia porta: un sottoinsieme sarebbe un'impronta che \
              non si accorge di una parte"
)]
fn compute_integrity(
    content_id: ContentId,
    source_id: SourceId,
    taken_by: &Actor,
    reason: &Note,
    taken_at: Timestamp,
    observed_at: Timestamp,
    anchor_remote_message_id: &str,
    anchor_digest: &Sha256Digest,
    comparison: Option<SnapshotComparison>,
    declared_edit_at: Option<Timestamp>,
    messages: &[SnapshotMessage],
) -> Sha256Digest {
    const SEPARATORE: char = '\u{1f}';

    let mut materiale = String::new();
    materiale.push_str(&content_id.get().to_string());
    materiale.push(SEPARATORE);
    materiale.push_str(&source_id.get().to_string());
    materiale.push(SEPARATORE);
    materiale.push_str(taken_by.as_str());
    materiale.push(SEPARATORE);
    materiale.push_str(reason.as_str());
    materiale.push(SEPARATORE);
    materiale.push_str(&taken_at.as_millis().to_string());
    materiale.push(SEPARATORE);
    materiale.push_str(&observed_at.as_millis().to_string());
    materiale.push(SEPARATORE);
    materiale.push_str(anchor_remote_message_id);
    materiale.push(SEPARATORE);
    materiale.push_str(anchor_digest.as_str());
    materiale.push(SEPARATORE);
    materiale.push_str(match comparison {
        None => "non-confrontato",
        Some(confronto) => match confronto.divergence {
            Divergence::None => "coincidono",
            Divergence::Declared { .. } => "differiscono-dichiarata",
            Divergence::Undeclared => "differiscono-non-dichiarata",
        },
    });
    materiale.push(SEPARATORE);
    materiale.push_str(match comparison.map(|confronto| confronto.change) {
        None => "-",
        Some(VersionChange::Identical) => "identico",
        Some(VersionChange::Appended) => "aggiunto",
        Some(VersionChange::Truncated) => "accorciato",
        Some(VersionChange::Surrounded) => "attorno",
        Some(VersionChange::Rewritten) => "riscritto",
    });
    materiale.push(SEPARATORE);
    materiale.push_str(&declared_edit_at.map_or_else(
        || String::from("-"),
        |istante| istante.as_millis().to_string(),
    ));

    for messaggio in messages {
        materiale.push(SEPARATORE);
        materiale.push_str(&messaggio.remote_message_id);
        materiale.push(SEPARATORE);
        materiale.push_str(&messaggio.published_at.as_millis().to_string());
        materiale.push(SEPARATORE);
        materiale.push_str(&messaggio.body);
        materiale.push(SEPARATORE);
        materiale.push_str(&messaggio.author_sentence);
        materiale.push(SEPARATORE);
        materiale.push_str(messaggio.relations_sentence.as_deref().unwrap_or("-"));
        materiale.push(SEPARATORE);
        materiale.push_str(if messaggio.is_anchor { "1" } else { "0" });
    }

    Sha256Digest::of_text(&materiale)
}

#[cfg(test)]
mod tests {
    use super::{
        ContextSnapshot, NewContextSnapshot, SnapshotComparison, SnapshotMessage, compute_integrity,
    };
    use crate::model::content_history::VersionChange;
    use crate::model::context_state::Divergence;
    use crate::text::{Actor, Note};
    use crate::time::Timestamp;
    use crate::{ContentId, ContextSnapshotId, SourceId};

    /// Questo modulo, per le guardie strutturali.
    const THIS_MODULE: &str = include_str!("context_snapshot.rs");

    const ORA: i64 = 1_700_000_000_000;

    fn operatore() -> Actor {
        let Ok(attore) = Actor::try_new("operatore.prova") else {
            panic!("l'attore di prova deve essere valido");
        };
        attore
    }

    fn ragione(testo: &str) -> Note {
        let Ok(nota) = Note::try_new(testo) else {
            panic!("la ragione di prova deve essere valida");
        };
        nota
    }

    fn riga(id: &str, testo: &str, ancora: bool) -> SnapshotMessage {
        SnapshotMessage {
            remote_message_id: String::from(id),
            published_at: Timestamp::from_millis(ORA),
            body: String::from(testo),
            author_sentence: String::from("Scritto da qualcuno."),
            relations_sentence: None,
            is_anchor: ancora,
        }
    }

    fn prepara(motivo: &str, righe: Vec<SnapshotMessage>) -> NewContextSnapshot {
        let Ok(fotografia) = NewContextSnapshot::prepare(
            ContentId::new(7),
            SourceId::new(3),
            &operatore(),
            &ragione(motivo),
            Timestamp::from_millis(ORA + 60_000),
            Timestamp::from_millis(ORA),
            "500",
            "il testo acquisito",
            Some(SnapshotComparison {
                change: VersionChange::Identical,
                divergence: Divergence::None,
            }),
            None,
            righe,
        ) else {
            panic!("la fotografia di prova deve potersi preparare");
        };
        fotografia
    }

    /// **Non esiste una fotografia senza una ragione.**
    ///
    /// # Il difetto che questa prova impedisce
    ///
    /// Che conservare ciò che si vede su Telegram diventi un gesto senza
    /// responsabile. Un atto senza ragione non è documentato: è soltanto
    /// avvenuto.
    #[test]
    fn una_fotografia_senza_ragione_non_si_prepara() {
        for vuota in ["", "   ", "\t\n "] {
            let Ok(nota) = Note::try_new(vuota) else {
                // Una nota vuota puo' gia' essere rifiutata dal suo tipo: va
                // benissimo, ed e' la stessa protezione un passo prima.
                continue;
            };
            let esito = NewContextSnapshot::prepare(
                ContentId::new(7),
                SourceId::new(3),
                &operatore(),
                &nota,
                Timestamp::from_millis(ORA),
                Timestamp::from_millis(ORA),
                "500",
                "corpo",
                None,
                None,
                Vec::new(),
            );
            assert!(
                esito.is_err(),
                "una ragione fatta di soli spazi non e' una ragione: «{vuota:?}»"
            );
        }
    }

    /// **Una ragione vera si conserva com'è.**
    #[test]
    fn una_ragione_vera_si_conserva() {
        let fotografia = prepara("serve al fascicolo 12/2026", vec![riga("500", "x", true)]);
        assert_eq!(fotografia.reason().as_str(), "serve al fascicolo 12/2026");
        assert_eq!(fotografia.taken_by().as_str(), "operatore.prova");
    }

    /// **L'impronta cambia se cambia una qualunque parte.**
    ///
    /// # Il difetto che questa prova impedisce
    ///
    /// Un'impronta che copra i soli testi e non si accorga di una ragione
    /// cambiata, o di un operatore diverso: coprirebbe la parte meno
    /// contestabile e lascerebbe fuori quella che dice **chi** e **perché**.
    #[test]
    fn l_impronta_copre_ogni_parte_della_fotografia() {
        let base = prepara("una ragione", vec![riga("500", "testo", true)]);

        // Ragione diversa.
        let altra_ragione = prepara("un'altra ragione", vec![riga("500", "testo", true)]);
        assert_ne!(base.integrity(), altra_ragione.integrity());

        // Testo diverso.
        let altro_testo = prepara("una ragione", vec![riga("500", "testo diverso", true)]);
        assert_ne!(base.integrity(), altro_testo.integrity());

        // Una riga in più.
        let piu_righe = prepara(
            "una ragione",
            vec![riga("500", "testo", true), riga("501", "dopo", false)],
        );
        assert_ne!(base.integrity(), piu_righe.integrity());

        // Ordine diverso: una fotografia riordinata non e' la stessa
        // fotografia, perche' l'ordine e' il discorso.
        let ordine_a = prepara(
            "una ragione",
            vec![riga("500", "primo", true), riga("501", "secondo", false)],
        );
        let ordine_b = prepara(
            "una ragione",
            vec![riga("501", "secondo", false), riga("500", "primo", true)],
        );
        assert_ne!(ordine_a.integrity(), ordine_b.integrity());
    }

    /// **Due parti non si confondono fra loro.**
    ///
    /// Senza separatore, «ab» + «c» e «a» + «bc» darebbero la stessa impronta:
    /// due fotografie diverse con lo stesso numero.
    #[test]
    fn due_parti_diverse_non_danno_la_stessa_impronta() {
        let uno = prepara("una ragione", vec![riga("500", "ab", true)]);
        let due = prepara("una ragione", vec![riga("5", "00ab", true)]);
        assert_ne!(uno.integrity(), due.integrity());
    }

    /// **La stessa fotografia dà sempre la stessa impronta.**
    #[test]
    fn la_stessa_fotografia_da_sempre_la_stessa_impronta() {
        let uno = prepara("una ragione", vec![riga("500", "testo", true)]);
        let due = prepara("una ragione", vec![riga("500", "testo", true)]);
        assert_eq!(uno.integrity(), due.integrity());
    }

    /// **Una fotografia riletta si verifica, e una manomessa no.**
    #[test]
    fn una_fotografia_manomessa_non_si_verifica() {
        let preparata = prepara("una ragione", vec![riga("500", "testo", true)]);
        let riletta = ContextSnapshot {
            id: ContextSnapshotId::new(1),
            content_id: preparata.content_id(),
            source_id: preparata.source_id(),
            taken_by: preparata.taken_by().clone(),
            reason: preparata.reason().clone(),
            taken_at: preparata.taken_at(),
            observed_at: preparata.observed_at(),
            anchor_remote_message_id: preparata.anchor_remote_message_id().to_owned(),
            anchor_digest: preparata.anchor_digest().clone(),
            comparison: preparata.comparison(),
            declared_edit_at: preparata.declared_edit_at(),
            messages: preparata.messages().to_vec(),
            integrity: preparata.integrity().clone(),
        };
        assert!(riletta.verify(), "una fotografia intatta si verifica");

        let mut manomessa = riletta.clone();
        manomessa.messages[0].body = String::from("un testo che nessuno ha visto");
        assert!(
            !manomessa.verify(),
            "un testo cambiato dopo deve far fallire la verifica"
        );

        let mut ragione_cambiata = riletta;
        ragione_cambiata.reason = ragione("un'altra ragione");
        assert!(
            !ragione_cambiata.verify(),
            "una ragione cambiata dopo deve far fallire la verifica"
        );
    }

    /// **L'impronta non è un parametro.**
    ///
    /// # Il difetto che questa prova impedisce
    ///
    /// Che qualcuno consegni un'impronta che non corrisponde a ciò che sta
    /// conservando. Un'impronta ricevuta dall'esterno non prova nulla: prova
    /// solo che chi l'ha scritta sapeva scrivere un'impronta.
    #[test]
    fn l_impronta_si_calcola_e_non_si_riceve() {
        let Some((produzione, _)) = THIS_MODULE.split_once("#[cfg(test)]\nmod tests {") else {
            panic!("il modulo deve avere un blocco di prove riconoscibile");
        };
        let Some(inizio) = produzione.find("    pub fn prepare(") else {
            panic!("il costruttore deve esistere");
        };
        let Some(fine) = produzione[inizio..].find(") -> DomainResult<Self> {") else {
            panic!("il costruttore deve chiudersi");
        };
        let parametri = &produzione[inizio..inizio + fine];

        assert!(
            !parametri.contains("integrity:") && !parametri.contains("digest:"),
            "l'impronta non deve essere un parametro del costruttore \u{2014} {parametri}"
        );
        assert!(
            produzione.contains("let integrity = compute_integrity("),
            "l'impronta deve essere calcolata dentro il costruttore"
        );
    }

    /// **La frase dice sempre che non è una prova acquisita.**
    #[test]
    fn la_frase_dice_sempre_che_non_e_una_prova_acquisita() {
        let preparata = prepara("serve al fascicolo", vec![riga("500", "x", true)]);
        let riletta = ContextSnapshot {
            id: ContextSnapshotId::new(1),
            content_id: preparata.content_id(),
            source_id: preparata.source_id(),
            taken_by: preparata.taken_by().clone(),
            reason: preparata.reason().clone(),
            taken_at: preparata.taken_at(),
            observed_at: preparata.observed_at(),
            anchor_remote_message_id: preparata.anchor_remote_message_id().to_owned(),
            anchor_digest: preparata.anchor_digest().clone(),
            comparison: preparata.comparison(),
            declared_edit_at: preparata.declared_edit_at(),
            messages: preparata.messages().to_vec(),
            integrity: preparata.integrity().clone(),
        };

        let frase = riletta.as_sentence();
        assert!(frase.contains("Non \u{e8} una prova acquisita"), "{frase}");
        assert!(frase.contains("osservazione documentata"), "{frase}");
        assert!(frase.contains("operatore.prova"), "{frase}");
        assert!(frase.contains("serve al fascicolo"), "{frase}");
        // I due istanti sono diversi, e si leggono entrambi: chi guarda una
        // vista aperta da un quarto d'ora conserva cio' che si vedeva allora.
        assert!(frase.contains("Fotografia presa da"), "{frase}");
        assert!(frase.contains("Telegram mostrava il"), "{frase}");
    }

    /// **Il conteggio dei messaggi si accorda al numero.**
    #[test]
    fn la_frase_accorda_il_conteggio() {
        for (quante, atteso) in [(1_usize, "1 messaggio"), (2, "2 messaggi")] {
            let righe: Vec<SnapshotMessage> = (0..quante)
                .map(|indice| riga(&format!("{}", 500 + indice), "x", indice == 0))
                .collect();
            let preparata = prepara("una ragione", righe);
            let riletta = ContextSnapshot {
                id: ContextSnapshotId::new(1),
                content_id: preparata.content_id(),
                source_id: preparata.source_id(),
                taken_by: preparata.taken_by().clone(),
                reason: preparata.reason().clone(),
                taken_at: preparata.taken_at(),
                observed_at: preparata.observed_at(),
                anchor_remote_message_id: preparata.anchor_remote_message_id().to_owned(),
                anchor_digest: preparata.anchor_digest().clone(),
                comparison: preparata.comparison(),
                declared_edit_at: preparata.declared_edit_at(),
                messages: preparata.messages().to_vec(),
                integrity: preparata.integrity().clone(),
            };
            assert!(riletta.as_sentence().contains(atteso), "{quante}");
        }
    }

    /// **Un confronto assente non diventa «coincidevano».**
    ///
    /// Nell'impronta le due cose devono restare distinte, o due fotografie
    /// diverse avrebbero lo stesso numero (ADR-0053).
    #[test]
    fn un_confronto_assente_non_e_un_confronto_riuscito() {
        let senza = compute_integrity(
            ContentId::new(7),
            SourceId::new(3),
            &operatore(),
            &ragione("una ragione"),
            Timestamp::from_millis(ORA),
            Timestamp::from_millis(ORA),
            "500",
            &crate::digest::Sha256Digest::of_text("corpo"),
            None,
            None,
            &[],
        );
        let coincidevano = compute_integrity(
            ContentId::new(7),
            SourceId::new(3),
            &operatore(),
            &ragione("una ragione"),
            Timestamp::from_millis(ORA),
            Timestamp::from_millis(ORA),
            "500",
            &crate::digest::Sha256Digest::of_text("corpo"),
            Some(SnapshotComparison {
                change: VersionChange::Identical,
                divergence: Divergence::None,
            }),
            None,
            &[],
        );
        assert_ne!(
            senza, coincidevano,
            "«non confrontato» e «confrontato e coincidevano» sono due fotografie diverse"
        );
    }
}
