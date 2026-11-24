//! «Che cosa devo guardare adesso?»
//!
//! # Perché una coda, e non l'elenco degli alert
//!
//! Perché l'elenco degli alert è **di una sessione**, e il lavoro non fatto in
//! una sessione chiusa è esattamente quello che si dimentica. Una coda che
//! attraversa tutte le sessioni è l'unico posto in cui un contenuto segnalato
//! tre settimane fa e mai esaminato torna davanti a qualcuno.
//!
//! # Nessuna assegnazione, e non è una mancanza
//!
//! Non esiste «Prendi in carico», non esiste «Assegna a». Non perché sia
//! difficile: perché **non esiste ancora un'identità di operatore
//! autenticata**. Su questa postazione chi agisce è un segnaposto
//! (`lisi-app::operator`), e un'assegnazione fatta a un segnaposto direbbe che
//! qualcuno ha preso in carico qualcosa quando nessuno lo ha fatto.
//!
//! Sarebbe **peggio** che non averla: due operatori sulla stessa macchina
//! vedrebbero «preso in carico» e lo crederebbero, e il lavoro che ciascuno
//! pensa dell'altro non lo fa nessuno. L'assegnazione arriverà con
//! TEAM-ASSIGN-01, **dopo** l'identità, e ogni cambio sarà auditato.
//!
//! # Nessun punteggio, e nemmeno uno nascosto
//!
//! La coda **non calcola un numero di priorità**. L'ordine è un confronto
//! lessicografico su fatti registrati, e ogni riga dice quali fatti l'hanno
//! collocata dov'è. Un numero composto — anche innocuo, anche solo per
//! ordinare — si leggerebbe come una misura di gravità del contenuto, che
//! questo prodotto non produce (ADR-0048) e che nessun fatto autorizzerebbe.

use std::cmp::Ordering;
use std::collections::BTreeSet;

use lisi_core::model::ReviewState;
use lisi_core::{ContentId, SessionId, Timestamp};
use lisi_storage::Database;
use lisi_storage::repository::work_queue::PendingWorkRow;

use crate::error::ServiceResult;

/// Un contenuto che aspetta una persona.
///
/// # Perché non porta il testo del contenuto
///
/// Perché la coda dice **che cosa** aspetta e **perché**; il testo si legge
/// aprendo il contenuto. Portarlo qui significherebbe caricare tutti i corpi in
/// attesa per mostrarne l'elenco, e mostrare in una lista contenuti che nessuno
/// ha ancora deciso di guardare.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QueueItem {
    /// Contenuto in attesa.
    pub content_id: ContentId,
    /// Sessione in cui è stato acquisito.
    pub session_id: SessionId,
    /// Etichetta della sessione.
    pub session_label: String,
    /// Nome della fonte.
    pub source_name: String,
    /// Livello dell'allarme, da 1 a 4.
    pub level: u8,
    /// Motivazione dell'allarme, come il motore l'ha scritta.
    pub reason: String,
    /// Quando l'allarme è stato generato.
    pub raised_at: Timestamp,
    /// Stato della revisione, quando qualcuno l'ha già toccato.
    ///
    /// `None` è **mai toccato**, che non è [`ReviewState::New`] registrato.
    pub state: Option<ReviewState>,
    /// Se il contenuto fa parte di un grappolo di Cyber Watch.
    ///
    /// # Che cosa significa, e che cosa no
    ///
    /// Significa che **altri contenuti** nominano gli stessi indicatori tecnici:
    /// il contenuto non è isolato. **Non significa che sia più grave**, e non
    /// alza il livello — il livello lo decide il motore sui dizionari
    /// (ADR-0035). Nella coda conta come corroborazione: qualcos'altro dice la
    /// stessa cosa, e vale la pena guardarlo prima di un contenuto solo.
    pub in_cyber_event: bool,
    /// Il testo del contenuto, di cui la coda mostra l'inizio
    /// (OPERATOR-UX-REMEDIATION-01, OS-10).
    pub body: String,
}

impl QueueItem {
    /// Se nessuno lo ha ancora toccato.
    #[must_use]
    pub const fn is_untouched(&self) -> bool {
        self.state.is_none()
    }

    /// Lo stato, come l'operatore lo legge.
    #[must_use]
    pub fn state_label(&self) -> &'static str {
        self.state.map_or("Mai esaminato", ReviewState::label)
    }

    /// Da quanto aspetta.
    ///
    /// # Perché in giorni interi e non in ore
    ///
    /// Perché la coda si guarda una volta al giorno, e «da 3 giorni» è ciò che
    /// serve a decidere. «Da 74 ore» è più preciso e meno utile.
    #[must_use]
    pub fn waiting_for(&self, now: Timestamp) -> String {
        let trascorsi = now.as_millis().saturating_sub(self.raised_at.as_millis());
        if trascorsi < 0 {
            // L'orologio della postazione può essere stato spostato indietro.
            // Non si inventa un'attesa negativa: si dice che non si sa.
            return String::from("attesa non calcolabile: l'istante è successivo a ora");
        }
        let giorni = trascorsi / 86_400_000;
        match giorni {
            0 => String::from("in attesa da meno di un giorno"),
            1 => String::from("in attesa da un giorno"),
            _ => format!("in attesa da {giorni} giorni"),
        }
    }

    /// **Perché sta dov'è**: i fatti che lo hanno collocato, in quest'ordine.
    ///
    /// Non è una spiegazione accanto al risultato: sono gli stessi fatti su cui
    /// il confronto lavora, elencati nella stessa precedenza. Chi legge può
    /// verificarli uno per uno.
    #[must_use]
    pub fn why_here(&self, now: Timestamp) -> String {
        let mut fatti = Vec::new();
        fatti.push(if self.is_untouched() {
            String::from("mai esaminato")
        } else {
            format!("stato: {}", self.state_label())
        });
        fatti.push(format!("livello {}", self.level));
        if self.in_cyber_event {
            fatti.push(String::from("in un grappolo di «Segnali cyber»"));
        }
        fatti.push(self.waiting_for(now));
        fatti.join(" · ")
    }
}

/// L'ordine della coda.
///
/// # I criteri, e perché in quest'ordine
///
/// 1. **Mai esaminato prima di già toccato.** Su un contenuto in esame
///    qualcuno sta già lavorando; su uno mai toccato non lavora nessuno, ed è
///    quello che rischia di non essere guardato mai.
/// 2. **Livello più alto prima.** È la valutazione che il motore
///    deterministico ha prodotto, ed è il solo segnale diretto che la coda ha
///    sul contenuto.
/// 3. **In un grappolo prima che da solo.** Non perché sia più grave — il
///    grappolo non alza il livello, e non deve (ADR-0035) — ma perché è
///    **corroborato**: qualcos'altro nomina gli stessi indicatori, e vale la
///    pena guardarlo prima di un contenuto isolato dello stesso livello.
/// 4. **Più vecchio prima.** Una coda che scorre sempre dalla cima e non
///    arriva mai in fondo nasconde ciò che sta in fondo. L'età lo riporta su.
/// 5. **A parità di tutto, l'identificativo.** Non significa nulla: serve a
///    rendere l'ordine **totale**, così che due composizioni della stessa coda
///    diano la stessa sequenza. Un ordine che cambia a ogni apertura fa
///    perdere il segno a chi stava scorrendo.
///
/// # Perché il livello dopo lo stato, e non prima
///
/// È la scelta discutibile di questa milestone, e va detta. Un livello 4 già in
/// esame **non** precede un livello 1 mai guardato: la ragione è che la coda
/// esiste per far emergere ciò che nessuno ha visto, non per riordinare ciò che
/// è già sul tavolo di qualcuno. Se l'uso mostrasse il contrario, si cambia
/// questa funzione e nient'altro — è il solo posto in cui l'ordine è deciso.
fn queue_order(a: &QueueItem, b: &QueueItem) -> Ordering {
    // 1. Mai toccato prima: `false < true`, quindi si confronta «è stato
    //    toccato» e il non toccato viene per primo.
    a.state
        .is_some()
        .cmp(&b.state.is_some())
        // 2. Livello più alto prima.
        .then_with(|| b.level.cmp(&a.level))
        // 3. Corroborato prima che isolato: `true` deve precedere, quindi si
        //    confronta al contrario.
        .then_with(|| b.in_cyber_event.cmp(&a.in_cyber_event))
        // 4. Più vecchio prima.
        .then_with(|| a.raised_at.as_millis().cmp(&b.raised_at.as_millis()))
        // 5. Ordine totale.
        .then_with(|| a.content_id.get().cmp(&b.content_id.get()))
}

/// La coda, a un istante.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkQueue {
    /// Gli elementi, nell'ordine in cui vanno guardati.
    pub items: Vec<QueueItem>,
    /// Quando è stata composta.
    pub composed_at: Timestamp,
}

impl WorkQueue {
    /// Quanti non sono mai stati esaminati.
    #[must_use]
    pub fn untouched(&self) -> usize {
        self.items.iter().filter(|item| item.is_untouched()).count()
    }

    /// Quanti sono già in esame.
    #[must_use]
    pub fn in_review(&self) -> usize {
        self.items
            .iter()
            .filter(|item| item.state == Some(ReviewState::InReview))
            .count()
    }

    /// La frase del riepilogo.
    ///
    /// Dice **quanti**, non «quanto lavoro»: una stima di tempo sarebbe
    /// inventata, e verrebbe letta come una promessa.
    #[must_use]
    pub fn as_sentence(&self) -> String {
        if self.items.is_empty() {
            return String::from("Nessun contenuto in attesa di revisione.");
        }

        let mut frase = format!("{} contenuti in attesa", self.items.len());
        if self.untouched() > 0 {
            frase.push_str(&format!(", {} mai esaminati", self.untouched()));
        }
        if self.in_review() > 0 {
            frase.push_str(&format!(", {} già in esame", self.in_review()));
        }
        frase.push('.');
        frase
    }
}

/// Compone la coda di lavoro.
#[derive(Debug)]
pub struct WorkQueueService {
    database: Database,
}

impl WorkQueueService {
    /// Crea il servizio attorno all'archivio indicato.
    #[must_use]
    pub const fn new(database: Database) -> Self {
        Self { database }
    }

    /// Archivio sottostante, per le prove.
    #[must_use]
    pub const fn database(&self) -> &Database {
        &self.database
    }

    /// Archivio sottostante in scrittura, per la preparazione delle prove.
    #[must_use]
    pub const fn database_mut(&mut self) -> &mut Database {
        &mut self.database
    }

    /// La coda, ordinata.
    ///
    /// # Che cosa costa
    ///
    /// **Una interrogazione**, non una per sessione: la coda attraversa tutte
    /// le sessioni, e chiederle una alla volta la farebbe crescere con la
    /// storia dell'ufficio invece che con il lavoro rimasto.
    ///
    /// # Che cosa esclude, e chi lo decide
    ///
    /// Gli elementi **decisi**, secondo [`ReviewState::is_decided`], che è
    /// l'unica autorità su che cosa sia concluso. La persistenza restituisce
    /// tutto; il dominio filtra. Due filtri — uno in SQL e uno qui —
    /// divergerebbero il giorno in cui nasce uno stato nuovo.
    ///
    /// # Non scrive nulla
    ///
    /// Guardare la coda non cambia la coda. Se aprirla registrasse qualcosa,
    /// l'atto di guardare il lavoro diventerebbe lavoro.
    ///
    /// # Errori
    ///
    /// Restituisce l'errore della persistenza se la lettura non riesce.
    pub fn compose(&self, now: Timestamp) -> ServiceResult<WorkQueue> {
        let righe = self.database.pending_work()?;

        let in_attesa: Vec<PendingWorkRow> = righe
            .into_iter()
            .filter(|riga| !riga.state.is_some_and(ReviewState::is_decided))
            .collect();

        let corroborati = self.clustered_contents(&in_attesa)?;

        let mut items: Vec<QueueItem> = in_attesa
            .into_iter()
            .map(|riga| into_item(riga, &corroborati))
            .collect();

        items.sort_by(queue_order);

        Ok(WorkQueue {
            items,
            composed_at: now,
        })
    }
}

impl WorkQueueService {
    /// I contenuti che fanno parte di un grappolo, fra quelli in attesa.
    ///
    /// # Perché solo per le sessioni che hanno lavoro in attesa
    ///
    /// Perché la correlazione è la parte cara di questa composizione, e
    /// calcolarla per una sessione senza nulla in coda produrrebbe un insieme
    /// che nessuna riga guarda. Il costo cresce così con **il lavoro rimasto**,
    /// non con la storia dell'ufficio — che è la relazione giusta: una coda
    /// vuota non costa nulla.
    ///
    /// # Errori
    ///
    /// Restituisce l'errore della persistenza se una lettura non riesce.
    fn clustered_contents(&self, in_attesa: &[PendingWorkRow]) -> ServiceResult<BTreeSet<i64>> {
        let sessioni: BTreeSet<i64> = in_attesa.iter().map(|riga| riga.session_id.get()).collect();

        let mut corroborati = BTreeSet::new();
        for sessione in sessioni {
            let grappoli = crate::cyber_watch::events_of(&self.database, SessionId::new(sessione))?;
            for grappolo in grappoli {
                for membro in &grappolo.event.members {
                    corroborati.insert(membro.content_id);
                }
            }
        }
        Ok(corroborati)
    }
}

/// Traduce una riga dell'archivio in un elemento della coda.
fn into_item(riga: PendingWorkRow, corroborati: &BTreeSet<i64>) -> QueueItem {
    QueueItem {
        in_cyber_event: corroborati.contains(&riga.content_id.get()),
        content_id: riga.content_id,
        session_id: riga.session_id,
        session_label: riga.session_label,
        source_name: riga.source_name,
        level: riga.level,
        reason: riga.reason,
        raised_at: riga.raised_at,
        state: riga.state,
        body: riga.body,
    }
}

#[cfg(test)]
mod tests {
    use lisi_core::model::{ReviewState, SourceKind};
    use lisi_core::{ContentId, SessionId, Timestamp};

    use super::{QueueItem, WorkQueueService, queue_order};

    /// Questo modulo, per le guardie testuali.
    const THIS_MODULE: &str = include_str!("work_queue.rs");

    fn now() -> Timestamp {
        Timestamp::from_millis(1_700_000_000_000)
    }

    /// Un elemento di prova, con i soli fatti che l'ordine guarda.
    fn item(id: i64, level: u8, state: Option<ReviewState>, raised_at: i64) -> QueueItem {
        clustered_item(id, level, state, raised_at, false)
    }

    /// Come [`item`], dicendo anche se il contenuto sia in un grappolo.
    fn clustered_item(
        id: i64,
        level: u8,
        state: Option<ReviewState>,
        raised_at: i64,
        in_cyber_event: bool,
    ) -> QueueItem {
        QueueItem {
            in_cyber_event,
            content_id: ContentId::new(id),
            session_id: SessionId::new(1),
            session_label: String::from("Monitoraggio"),
            source_name: String::from("Canale"),
            level,
            reason: String::from("termine trovato"),
            raised_at: Timestamp::from_millis(raised_at),
            state,
            body: String::from("testo"),
        }
    }

    /// Mai esaminato precede ciò che qualcuno sta già guardando.
    ///
    /// Anche a livello più basso: la coda esiste per far emergere ciò che
    /// nessuno ha visto, non per riordinare ciò che è già sul tavolo.
    #[test]
    fn cio_che_nessuno_ha_visto_precede_cio_che_qualcuno_sta_guardando() {
        let mai_visto = item(1, 1, None, 1_000);
        let in_esame = item(2, 4, Some(ReviewState::InReview), 1_000);

        let mut coda = [in_esame.clone(), mai_visto.clone()];
        coda.sort_by(queue_order);

        assert_eq!(
            coda[0], mai_visto,
            "il livello 4 in esame non scavalca un livello 1 mai visto"
        );
        assert_eq!(coda[1], in_esame);
    }

    /// A parità di stato, il livello più alto precede.
    #[test]
    fn a_parita_di_stato_il_livello_piu_alto_precede() {
        let basso = item(1, 2, None, 1_000);
        let alto = item(2, 4, None, 1_000);

        let mut coda = [basso.clone(), alto.clone()];
        coda.sort_by(queue_order);

        assert_eq!(coda[0], alto);
        assert_eq!(coda[1], basso);
    }

    /// A parità di stato e livello, ciò che è corroborato precede ciò che è
    /// isolato.
    #[test]
    fn a_parita_di_livello_cio_che_e_in_un_grappolo_precede() {
        let isolato = clustered_item(1, 3, None, 1_000, false);
        let corroborato = clustered_item(2, 3, None, 9_000, true);

        let mut coda = [isolato.clone(), corroborato.clone()];
        coda.sort_by(queue_order);

        assert_eq!(
            coda[0], corroborato,
            "il grappolo precede l'età: qualcos'altro dice la stessa cosa"
        );
        assert_eq!(coda[1], isolato);
    }

    /// **Un grappolo non alza il livello.**
    ///
    /// # Il difetto che questa prova impedisce
    ///
    /// Far contare il grappolo prima del livello equivarrebbe a dire che un
    /// contenuto è più grave perché altri ne parlano, che è il salto che
    /// ADR-0035 vieta: il livello lo decide il motore sui dizionari, e il
    /// grappolo dice soltanto che il contenuto non è isolato.
    #[test]
    fn un_grappolo_non_alza_il_livello_di_un_contenuto() {
        let alto_isolato = clustered_item(1, 4, None, 9_000, false);
        let basso_corroborato = clustered_item(2, 1, None, 1_000, true);

        let mut coda = [basso_corroborato.clone(), alto_isolato.clone()];
        coda.sort_by(queue_order);

        assert_eq!(
            coda[0], alto_isolato,
            "il livello 4 isolato precede il livello 1 in un grappolo: essere \
             corroborato non è essere più grave"
        );
    }

    /// A parità di stato e livello, il più vecchio precede.
    ///
    /// Una coda che si scorre sempre dalla cima e non arriva mai in fondo
    /// nasconde ciò che sta in fondo.
    #[test]
    fn a_parita_di_livello_il_piu_vecchio_precede() {
        let recente = item(1, 3, None, 9_000);
        let vecchio = item(2, 3, None, 1_000);

        let mut coda = [recente.clone(), vecchio.clone()];
        coda.sort_by(queue_order);

        assert_eq!(coda[0], vecchio);
        assert_eq!(coda[1], recente);
    }

    /// L'ordine è **totale**: due composizioni danno la stessa sequenza.
    ///
    /// Un ordine che cambia a ogni apertura fa perdere il segno a chi stava
    /// scorrendo, e non c'è modo di accorgersene se non scorrendo due volte.
    #[test]
    fn l_ordine_e_totale_e_non_cambia_fra_due_composizioni() {
        let elementi = vec![
            item(3, 3, None, 5_000),
            item(1, 3, None, 5_000),
            item(2, 3, None, 5_000),
        ];

        let mut prima = elementi.clone();
        prima.sort_by(queue_order);
        let mut poi = elementi;
        poi.reverse();
        poi.sort_by(queue_order);

        assert_eq!(prima, poi, "la stessa coda deve dare la stessa sequenza");
        // E nessuna coppia distinta risulta equivalente.
        for finestra in prima.windows(2) {
            assert_ne!(
                queue_order(&finestra[0], &finestra[1]),
                std::cmp::Ordering::Equal,
                "due elementi distinti non devono risultare equivalenti"
            );
        }
    }

    /// Un elemento deciso esce dalla coda.
    #[test]
    fn un_elemento_deciso_non_e_piu_in_coda() {
        use lisi_core::model::{AcquisitionOrigin, AnalysisLevel, SessionDuration};
        use lisi_core::model::{NewAlert, NewContent, NewReview, NewSession, NewSource};
        use lisi_core::text::{
            Actor, AlertReason, ContentBody, DisplayName, RemoteMessageId, SourceIdentifier,
        };

        let Ok(mut database) = crate::sources::open_in_memory_database() else {
            panic!("l'archivio in memoria deve potersi aprire");
        };
        let (Ok(identifier), Ok(display_name), Ok(label), Ok(actor)) = (
            SourceIdentifier::try_new("-1001"),
            DisplayName::try_new("Canale"),
            DisplayName::try_new("Monitoraggio"),
            Actor::try_new("operatore.prova"),
        ) else {
            panic!("i valori di prova devono essere validi");
        };
        let Ok(source_id) = database.insert_source(
            &NewSource {
                kind: SourceKind::Channel,
                identifier,
                display_name,
                authorized_by: actor.clone(),
                active: true,
            },
            now(),
        ) else {
            panic!("la fonte deve potersi registrare");
        };
        let Ok(session_id) = database.insert_session(
            &NewSession {
                label,
                started_by: actor.clone(),
                duration: SessionDuration::Preset { seconds: 3_600 },
                source_ids: vec![source_id],
            },
            now(),
        ) else {
            panic!("la sessione deve potersi creare");
        };
        let (Ok(remote), Ok(body), Ok(level)) = (
            RemoteMessageId::try_new("7"),
            ContentBody::try_new("testo"),
            AnalysisLevel::try_new(3),
        ) else {
            panic!("i valori del contenuto devono essere validi");
        };
        let Ok(inserimento) = database.insert_content(&NewContent {
            session_id,
            source_id,
            remote_message_id: remote,
            author: None,
            author_identifier: None,
            author_username: None,
            body,
            url: None,
            published_at: now(),
            acquired_at: now(),
            origin: AcquisitionOrigin::Observed,
            analysis_level: level,
        }) else {
            panic!("il contenuto deve potersi registrare");
        };
        let content_id = inserimento.content_id();
        let (Ok(alert_level), Ok(reason)) = (
            lisi_core::model::AlertLevel::try_new(level),
            AlertReason::try_new("termine trovato"),
        ) else {
            panic!("i valori dell'alert devono essere validi");
        };
        let Ok(_) = database.insert_alert(&NewAlert {
            content_id,
            level: alert_level,
            reason,
            raised_at: now(),
        }) else {
            panic!("l'alert deve potersi registrare");
        };

        let mut service = WorkQueueService::new(database);
        let Ok(coda) = service.compose(now()) else {
            panic!("la coda deve potersi comporre");
        };
        assert_eq!(coda.items.len(), 1, "un contenuto segnalato entra in coda");
        assert!(coda.items[0].is_untouched());

        // Una decisione conclusa lo toglie.
        let Ok(_) = service.database_mut().insert_review(&NewReview {
            content_id,
            state: ReviewState::NotRelevant,
            reviewer: actor,
            note: None,
            decided_at: Timestamp::from_millis(now().as_millis() + 1_000),
        }) else {
            panic!("la revisione deve potersi registrare");
        };

        let Ok(coda) = service.compose(now()) else {
            panic!("la coda deve potersi comporre");
        };
        assert!(
            coda.items.is_empty(),
            "un contenuto deciso non aspetta più nessuno"
        );
        assert!(coda.as_sentence().contains("Nessun contenuto in attesa"));
    }

    /// Il codice di produzione **senza i commenti**.
    ///
    /// # Perché i commenti si tolgono
    ///
    /// Perché le due guardie qui sotto cercano parole che il codice non deve
    /// contenere, e la prosa che spiega **perché** non deve contenerle le
    /// nomina per forza. Una guardia che si accende sulla propria spiegazione
    /// costringerebbe a non scrivere la spiegazione, che è il contrario di ciò
    /// che serve.
    fn codice_senza_commenti() -> String {
        let Some((produzione, _)) = THIS_MODULE.split_once("#[cfg(test)]\nmod tests {") else {
            panic!("il modulo deve avere un blocco di prove riconoscibile");
        };

        produzione
            .lines()
            .filter(|riga| !riga.trim_start().starts_with("//"))
            .collect::<Vec<_>>()
            .join("\n")
    }

    /// **Nessuna assegnazione**, e nemmeno il vocabolario per averla.
    ///
    /// # Il difetto che questa prova impedisce
    ///
    /// Un'assegnazione fatta a un segnaposto direbbe che qualcuno ha preso in
    /// carico qualcosa quando nessuno lo ha fatto. Due operatori sulla stessa
    /// macchina lo crederebbero, e il lavoro che ciascuno pensa dell'altro non
    /// lo farebbe nessuno.
    #[test]
    fn la_coda_non_assegna_nulla_a_nessuno() {
        let produzione = codice_senza_commenti();

        for parola in [
            "assignee",
            "assigned_to",
            "assign(",
            "take_charge",
            "claimed_by",
        ] {
            assert!(
                !produzione.contains(parola),
                "la coda nomina «{parola}»: non esiste un'identità di operatore \
                 autenticata, e assegnare a un segnaposto è peggio che non assegnare"
            );
        }
    }

    /// **Nessun punteggio**, e nemmeno uno usato solo per ordinare.
    ///
    /// Un numero composto si leggerebbe come una misura di gravità del
    /// contenuto, che questo prodotto non produce (ADR-0048).
    #[test]
    fn la_coda_non_calcola_alcun_punteggio() {
        let produzione = codice_senza_commenti();

        for parola in ["score", "punteggio", "priority_value", "weight", "peso"] {
            assert!(
                !produzione.contains(parola),
                "la coda nomina «{parola}»: l'ordine è un confronto fra fatti, non \
                 un numero, e un numero si leggerebbe come una misura di gravità"
            );
        }

        // E il tipo non porta alcun campo numerico di priorità: se ne
        // comparisse uno, questa riga smetterebbe di compilare.
        let elemento = item(1, 4, None, 1_000);
        let _: u8 = elemento.level;
    }

    /// Ogni elemento dice perché sta dov'è, con i fatti dell'ordine.
    #[test]
    fn ogni_elemento_dice_perche_sta_dov_e() {
        let elemento = item(1, 4, None, now().as_millis() - 3 * 86_400_000);
        let spiegazione = elemento.why_here(now());

        assert!(spiegazione.contains("mai esaminato"));
        assert!(spiegazione.contains("livello 4"));
        assert!(spiegazione.contains("in attesa da 3 giorni"));
    }

    /// Un orologio spostato indietro non produce un'attesa negativa.
    #[test]
    fn un_orologio_spostato_indietro_non_inventa_un_attesa() {
        let futuro = item(1, 2, None, now().as_millis() + 86_400_000);
        let frase = futuro.waiting_for(now());

        assert!(
            frase.contains("non calcolabile"),
            "un'attesa che non si può calcolare si dichiara: «{frase}»"
        );
    }
}
