//! Segnali che si somigliano, messi insieme.
//!
//! # Che cos'è un evento, e soprattutto che cosa non è
//!
//! Un [`CyberEvent`] è **un grappolo di segnali**: più contenuti che nominano lo
//! stesso indicatore tecnico, raccolti perché qualcuno li guardi insieme.
//!
//! **Non è la prova che un attacco sia avvenuto.** Non lo è mai, per costruzione:
//! non esiste uno stato «confermato» che il programma possa assegnare da solo.
//! Quella è una conclusione, e una conclusione la trae una persona.
//!
//! Il prodotto non deve poter scrivere «attacco confermato». Un elenco di
//! messaggi che nominano la stessa CVE è esattamente ciò che è: un elenco di
//! messaggi che nominano la stessa CVE.
//!
//! # Perché la correlazione è deterministica e spiegabile
//!
//! Ogni grappolo nasce da una **ragione dicibile**: «questi contenuti nominano
//! CVE-2026-1234». Chi lo legge può verificarla aprendo i contenuti, e chi
//! risponde di un documento può scriverla in una relazione.
//!
//! Un punteggio di somiglianza calcolato da un modello darebbe grappoli migliori
//! e ragioni che nessuno sa spiegare a chi chiede conto (ADR-0035 Decisione 7).
//!
//! # La distinzione che il mandato chiede, e che conta più di tutte
//!
//! **Fonti distinte non sono conferme indipendenti.**
//!
//! Cinque canali Telegram che ripubblicano lo stesso messaggio sono cinque
//! copie, non cinque testimoni. Contarli come corroborazione trasformerebbe un
//! rilancio in una conferma, ed è esattamente l'errore che un prodotto di
//! monitoraggio non deve indurre.
//!
//! Qui si contano le **fonti distinte** e, separatamente, si dichiara quante di
//! quelle voci sembrano ripubblicazioni. Nessuna delle due si chiama
//! «indipendenza», perché stabilirla richiede sapere chi ha scritto per primo, e
//! il prodotto non lo sa.

use crate::Timestamp;
use crate::model::indicator::IndicatorKind;
use crate::model::review::ReviewState;

/// Perché due contenuti stanno nello stesso grappolo.
///
/// Ogni variante è una ragione che si può leggere ad alta voce.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CorrelationReason {
    /// Nominano lo stesso indicatore tecnico.
    SameIndicator {
        /// Il genere.
        kind: IndicatorKind,
        /// Il valore normalizzato.
        value: String,
    },
}

impl CorrelationReason {
    /// La ragione, come si scrive in una relazione.
    #[must_use]
    pub fn as_sentence(&self) -> String {
        match self {
            Self::SameIndicator { kind, value } => {
                format!("nominano {} «{value}»", kind.label())
            }
        }
    }
}

/// Un contenuto dentro un grappolo.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EventMember {
    /// Il contenuto.
    pub content_id: i64,
    /// La fonte da cui proviene.
    pub source_id: i64,
    /// L'impronta del corpo normalizzato, per riconoscere le ripubblicazioni.
    pub body_fingerprint: String,
    /// Quando il contenuto è stato pubblicato dalla fonte.
    ///
    /// # Perché la pubblicazione e non l'acquisizione
    ///
    /// Un grappolo racconta **quando la cosa è stata detta**, non quando questo
    /// programma se n'è accorto. Le due date possono distare giorni — il
    /// recupero della cronologia acquisisce contenuti vecchi — e usare
    /// l'acquisizione mostrerebbe la storia del monitoraggio invece di quella
    /// dei fatti.
    pub published_at: Timestamp,
    /// Che cosa una persona ha deciso su questo contenuto, se ha deciso.
    ///
    /// `None` quando nessuna revisione è stata registrata. Non è la stessa cosa
    /// di [`ReviewState::New`], che è una decisione presa e registrata come «da
    /// esaminare».
    pub review_state: Option<ReviewState>,
}

/// Un grappolo di segnali che si somigliano.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CyberEvent {
    /// Perché stanno insieme.
    pub reason: CorrelationReason,
    /// I contenuti del grappolo, in ordine stabile.
    pub members: Vec<EventMember>,
}

/// Che cosa il grappolo permette di dire, e che cosa no.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EventAssessment {
    /// Quanti contenuti.
    pub contents: usize,
    /// Quante fonti **distinte**.
    ///
    /// Non è un conteggio di testimoni: vedere [`Self::apparent_reposts`].
    pub distinct_sources: usize,
    /// Quanti contenuti sembrano ripubblicazioni di un altro del grappolo.
    ///
    /// Si riconoscono dall'impronta del corpo normalizzato: due testi che dopo
    /// la normalizzazione coincidono sono lo stesso testo.
    ///
    /// **Non è una misura di indipendenza.** Un testo diverso può essere
    /// comunque una ripresa, e due testi uguali possono essere due persone che
    /// citano lo stesso comunicato.
    pub apparent_reposts: usize,
}

impl EventAssessment {
    /// Che cosa si può dire del grappolo, in una frase.
    ///
    /// # Perché nessuna frase contiene un giudizio
    ///
    /// Il prodotto non ha titolo per dire che un attacco è avvenuto, che una
    /// notizia è vera, o che una fonte è attendibile. Dice **che cosa ha
    /// trovato**, e chi legge decide.
    #[must_use]
    pub fn as_sentence(&self) -> String {
        let mut testo = format!(
            "{} contenuti da {} fonti distinte",
            self.contents, self.distinct_sources
        );

        if self.apparent_reposts > 0 {
            testo.push_str(&format!(
                ", di cui {} con testo identico a un altro del gruppo",
                self.apparent_reposts
            ));
        }

        testo.push('.');

        // La frase che impedisce l'errore piu' probabile.
        if self.distinct_sources > 1 {
            testo.push_str(
                " Fonti distinte non sono conferme indipendenti: possono \
                 riprendere la stessa origine.",
            );
        }
        testo
    }

    /// Se il grappolo merita che qualcuno lo guardi.
    ///
    /// # Perché un solo contenuto non è un grappolo
    ///
    /// Un contenuto che nomina una CVE è un contenuto che nomina una CVE. Il
    /// valore della correlazione sta nel **ripetersi**, e un elenco pieno di
    /// grappoli da uno solo sarebbe rumore che insegna a ignorare l'elenco.
    #[must_use]
    pub const fn is_worth_looking_at(&self) -> bool {
        self.contents > 1
    }
}

/// Che cosa una persona ha deciso sui contenuti di un grappolo.
///
/// # Perché il prodotto non riassume la decisione in una parola
///
/// La tentazione sarebbe un unico stato del grappolo — «esaminato», «rilevante»
/// — e sarebbe un'invenzione: la revisione umana è **per contenuto**, e un
/// grappolo può contenere due messaggi giudicati rilevanti e otto mai guardati.
/// Riassumerli in una parola cancellerebbe proprio la differenza che chi legge
/// deve vedere.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ReviewSummary {
    /// Quanti contenuti hanno una decisione conclusa.
    pub decided: usize,
    /// Quanti sono stati presi in carico e non conclusi.
    pub in_progress: usize,
    /// Quanti non sono mai stati guardati.
    pub untouched: usize,
}

impl ReviewSummary {
    /// Che cosa si può dire della revisione, in una frase.
    ///
    /// Non dice mai che il grappolo *è* qualcosa: dice quante persone hanno
    /// guardato che cosa.
    #[must_use]
    pub fn as_sentence(&self) -> String {
        let totale = self.decided + self.in_progress + self.untouched;
        if self.decided == 0 && self.in_progress == 0 {
            return format!("Nessuno dei {totale} contenuti è stato ancora esaminato.");
        }

        let mut testo = format!("{} contenuti su {totale} con una decisione", self.decided);
        if self.in_progress > 0 {
            testo.push_str(&format!(", {} in esame", self.in_progress));
        }
        if self.untouched > 0 {
            testo.push_str(&format!(", {} mai guardati", self.untouched));
        }
        testo.push('.');
        testo
    }
}

impl CyberEvent {
    /// Quando il primo e l'ultimo contenuto del grappolo sono stati pubblicati.
    ///
    /// # Perché due date e non una durata
    ///
    /// «Nell'arco di tre giorni» nasconde **quando**, e quando è la metà della
    /// domanda: un grappolo di tre giorni del mese scorso e uno di tre giorni
    /// iniziato stamattina meritano due reazioni diverse.
    ///
    /// Restituisce `None` su un grappolo vuoto, che non dovrebbe esistere ma che
    /// il tipo consente.
    #[must_use]
    pub fn seen_between(&self) -> Option<(Timestamp, Timestamp)> {
        let mut istanti = self.members.iter().map(|member| member.published_at);
        let primo = istanti.next()?;

        Some(istanti.fold((primo, primo), |(minimo, massimo), istante| {
            (
                if istante < minimo { istante } else { minimo },
                if istante > massimo { istante } else { massimo },
            )
        }))
    }

    /// Che cosa una persona ha deciso sui contenuti del grappolo.
    #[must_use]
    pub fn review_summary(&self) -> ReviewSummary {
        let mut riassunto = ReviewSummary::default();

        for member in &self.members {
            match member.review_state {
                Some(stato) if stato.is_decided() => riassunto.decided += 1,
                Some(ReviewState::InReview) => riassunto.in_progress += 1,
                // `New` significa «non ancora esaminato», ed e' quello che dice
                // anche l'assenza di una revisione. Contarlo come «in esame»
                // perche' una riga esiste direbbe che qualcuno lo sta
                // guardando, e nessuno lo sta guardando.
                Some(ReviewState::New) | None => riassunto.untouched += 1,
                // Gli stati conclusi sono gia' presi dal primo braccio; questo
                // resta perche' `is_decided` e' una funzione e non un tipo, e
                // il compilatore non puo' saperlo.
                Some(_) => riassunto.decided += 1,
            }
        }
        riassunto
    }

    /// Che cosa il grappolo permette di dire.
    #[must_use]
    pub fn assess(&self) -> EventAssessment {
        let mut fonti: Vec<i64> = self.members.iter().map(|member| member.source_id).collect();
        fonti.sort_unstable();
        fonti.dedup();

        // Una ripubblicazione e' un contenuto la cui impronta compare gia' in un
        // altro membro del grappolo. Si conta una volta per ogni copia oltre la
        // prima: cinque copie dello stesso testo sono quattro ripubblicazioni.
        let mut impronte: Vec<&str> = self
            .members
            .iter()
            .map(|member| member.body_fingerprint.as_str())
            .collect();
        impronte.sort_unstable();
        let totali = impronte.len();
        impronte.dedup();
        let ripubblicazioni = totali - impronte.len();

        EventAssessment {
            contents: self.members.len(),
            distinct_sources: fonti.len(),
            apparent_reposts: ripubblicazioni,
        }
    }
}

/// L'impronta di un corpo, per riconoscere le ripubblicazioni.
///
/// # Che cosa normalizza, e perché proprio quello
///
/// Minuscole, spazi collassati, punteggiatura tolta. È il minimo che riconosce
/// due copie dello stesso messaggio quando una ha una maiuscola diversa o uno
/// spazio in più.
///
/// **Non** normalizza di più. Togliere le parole comuni o riordinare i termini
/// produrrebbe collisioni fra testi diversi, e un falso «ripubblicazione»
/// direbbe a chi legge che due voci sono una sola quando non lo sono.
///
/// # Perché non un'espressione regolare
///
/// Il testo arriva da Telegram, cioè è ostile per definizione. Una passata sola,
/// carattere per carattere, non ha un caso peggiore che qualcuno possa costruire.
#[must_use]
pub fn body_fingerprint(body: &str) -> String {
    let mut normalizzato = String::with_capacity(body.len());
    let mut spazio_pendente = false;

    for carattere in body.chars() {
        if carattere.is_alphanumeric() {
            if spazio_pendente && !normalizzato.is_empty() {
                normalizzato.push(' ');
            }
            spazio_pendente = false;
            for minuscolo in carattere.to_lowercase() {
                normalizzato.push(minuscolo);
            }
        } else {
            spazio_pendente = true;
        }
    }

    crate::Sha256Digest::of_text(&normalizzato)
        .as_str()
        .to_owned()
}

/// Raggruppa i contenuti che nominano lo stesso indicatore.
///
/// I grappoli escono in ordine stabile, e quelli da un solo contenuto restano
/// fuori: il valore della correlazione sta nel ripetersi.
#[must_use]
pub fn correlate(mut events: Vec<CyberEvent>) -> Vec<CyberEvent> {
    for event in &mut events {
        event
            .members
            .sort_by_key(|member| (member.source_id, member.content_id));
        event.members.dedup_by_key(|member| member.content_id);
    }

    events.retain(|event| event.assess().is_worth_looking_at());
    events.sort_by_key(|event| event.reason.as_sentence());
    events
}

#[cfg(test)]
mod tests {
    use super::{
        CorrelationReason, CyberEvent, EventAssessment, EventMember, body_fingerprint, correlate,
    };
    use crate::Timestamp;
    use crate::model::indicator::IndicatorKind;
    use crate::model::review::ReviewState;

    fn membro(content_id: i64, source_id: i64, corpo: &str) -> EventMember {
        membro_completo(content_id, source_id, corpo, 1_700_000_000_000, None)
    }

    /// Membro con l'istante di pubblicazione e lo stato di revisione indicati.
    fn membro_completo(
        content_id: i64,
        source_id: i64,
        corpo: &str,
        pubblicato: i64,
        revisione: Option<ReviewState>,
    ) -> EventMember {
        EventMember {
            content_id,
            source_id,
            body_fingerprint: body_fingerprint(corpo),
            published_at: Timestamp::from_millis(pubblicato),
            review_state: revisione,
        }
    }

    fn evento(membri: Vec<EventMember>) -> CyberEvent {
        CyberEvent {
            reason: CorrelationReason::SameIndicator {
                kind: IndicatorKind::Cve,
                value: String::from("CVE-2026-1234"),
            },
            members: membri,
        }
    }

    /// **Il prodotto non puo' dire che un attacco sia avvenuto.**
    ///
    /// Non c'e' uno stato «confermato» da assegnare: un elenco di messaggi che
    /// nominano la stessa CVE e' esattamente cio' che e'.
    #[test]
    fn nessuna_frase_contiene_un_giudizio() {
        let valutazione = EventAssessment {
            contents: 12,
            distinct_sources: 5,
            apparent_reposts: 3,
        };
        let frase = valutazione.as_sentence();

        for vietata in [
            "attacco",
            "confermat",
            "certo",
            "provato",
            "colpevole",
            "responsabile",
            "pericolos",
        ] {
            assert!(
                !frase.to_lowercase().contains(vietata),
                "la frase contiene un giudizio («{vietata}»): «{frase}»"
            );
        }
    }

    /// **Fonti distinte non sono conferme indipendenti.**
    ///
    /// Cinque canali che ripubblicano lo stesso messaggio sono cinque copie, non
    /// cinque testimoni. Contarli come corroborazione trasformerebbe un rilancio
    /// in una conferma.
    #[test]
    fn la_frase_avverte_che_fonti_distinte_non_sono_conferme() {
        let valutazione = EventAssessment {
            contents: 5,
            distinct_sources: 5,
            apparent_reposts: 4,
        };
        let frase = valutazione.as_sentence();
        assert!(
            frase.contains("non sono conferme indipendenti"),
            "senza questa frase, cinque copie sembrerebbero cinque testimoni: \
             «{frase}»"
        );
    }

    /// **Con una fonte sola l'avvertenza non serve.**
    ///
    /// Un'avvertenza che compare sempre e' un'avvertenza che nessuno legge.
    #[test]
    fn con_una_fonte_sola_non_si_avverte_di_nulla() {
        let valutazione = EventAssessment {
            contents: 3,
            distinct_sources: 1,
            apparent_reposts: 0,
        };
        assert!(!valutazione.as_sentence().contains("conferme indipendenti"));
    }

    /// **Cinque copie dello stesso testo sono quattro ripubblicazioni.**
    #[test]
    fn le_copie_dello_stesso_testo_si_contano() {
        let corpo = "Allarme: la CVE-2026-1234 e' sfruttata attivamente.";
        let evento = evento(vec![
            membro(1, 10, corpo),
            membro(2, 11, corpo),
            membro(3, 12, corpo),
            membro(4, 13, corpo),
            membro(5, 14, corpo),
        ]);

        let valutazione = evento.assess();
        assert_eq!(valutazione.contents, 5);
        assert_eq!(valutazione.distinct_sources, 5);
        assert_eq!(
            valutazione.apparent_reposts, 4,
            "cinque copie sono quattro ripubblicazioni"
        );
    }

    /// **Testi diversi non diventano ripubblicazioni.**
    ///
    /// Un falso «ripubblicazione» direbbe a chi legge che due voci sono una
    /// sola quando non lo sono.
    #[test]
    fn testi_diversi_non_diventano_ripubblicazioni() {
        let evento = evento(vec![
            membro(1, 10, "La CVE-2026-1234 riguarda i sistemi di posta."),
            membro(
                2,
                11,
                "Segnalata un'attivita' anomala su un servizio esposto.",
            ),
        ]);
        assert_eq!(evento.assess().apparent_reposts, 0);
    }

    /// **La normalizzazione riconosce le differenze che non contano.**
    #[test]
    fn maiuscole_spazi_e_punteggiatura_non_fanno_due_testi_diversi() {
        let uno = body_fingerprint("Allarme: CVE-2026-1234 sfruttata!");
        let due = body_fingerprint("allarme   cve 2026 1234   sfruttata");
        assert_eq!(uno, due);
    }

    /// **Ma non normalizza tanto da confondere testi diversi.**
    #[test]
    fn due_testi_diversi_restano_due_impronte_diverse() {
        let uno = body_fingerprint("la vulnerabilita' e' stata corretta");
        let due = body_fingerprint("la vulnerabilita' non e' stata corretta");
        assert_ne!(
            uno, due,
            "togliere le parole comuni produrrebbe collisioni fra testi che \
             dicono il contrario"
        );
    }

    /// **Un grappolo da uno solo non e' un grappolo.**
    ///
    /// Un elenco pieno di grappoli da uno solo sarebbe rumore che insegna a
    /// ignorare l'elenco.
    #[test]
    fn un_contenuto_solo_non_produce_un_grappolo() {
        let soli = correlate(vec![evento(vec![membro(1, 10, "testo")])]);
        assert!(soli.is_empty());

        let insieme = correlate(vec![evento(vec![
            membro(1, 10, "uno"),
            membro(2, 11, "due"),
        ])]);
        assert_eq!(insieme.len(), 1);
    }

    /// **Lo stesso contenuto non entra due volte nello stesso grappolo.**
    #[test]
    fn un_contenuto_ripetuto_non_gonfia_il_grappolo() {
        let evento = evento(vec![
            membro(1, 10, "uno"),
            membro(1, 10, "uno"),
            membro(2, 11, "due"),
        ]);
        let grappoli = correlate(vec![evento]);
        assert_eq!(grappoli.len(), 1);
        assert_eq!(grappoli[0].members.len(), 2);
    }

    /// **La ragione si legge ad alta voce.**
    ///
    /// Chi risponde di un documento deve poterla scrivere in una relazione.
    #[test]
    fn ogni_ragione_si_puo_scrivere_in_una_relazione() {
        let ragione = CorrelationReason::SameIndicator {
            kind: IndicatorKind::Cve,
            value: String::from("CVE-2026-1234"),
        };
        let frase = ragione.as_sentence();
        assert!(frase.contains("CVE-2026-1234"));
        assert!(
            frase.len() > 15,
            "la ragione deve essere una frase, non un'etichetta: «{frase}»"
        );
    }

    /// **L'ordine dei grappoli e' stabile.**
    ///
    /// Due esecuzioni sugli stessi dati devono produrre lo stesso elenco: un
    /// ordine che cambia rende impossibile confrontare due letture.
    #[test]
    fn l_ordine_dei_grappoli_e_stabile() {
        let costruisci = |valore: &str| CyberEvent {
            reason: CorrelationReason::SameIndicator {
                kind: IndicatorKind::Cve,
                value: String::from(valore),
            },
            members: vec![membro(1, 10, "uno"), membro(2, 11, "due")],
        };

        let primo = correlate(vec![
            costruisci("CVE-2026-3333"),
            costruisci("CVE-2026-1111"),
        ]);
        let secondo = correlate(vec![
            costruisci("CVE-2026-1111"),
            costruisci("CVE-2026-3333"),
        ]);

        let nomi = |grappoli: &[CyberEvent]| -> Vec<String> {
            grappoli
                .iter()
                .map(|grappolo| grappolo.reason.as_sentence())
                .collect()
        };
        assert_eq!(nomi(&primo), nomi(&secondo));
    }

    #[test]
    fn un_corpo_vuoto_ha_comunque_un_impronta() {
        // Un messaggio con la sola immagine ha corpo vuoto, ed e' un caso reale.
        // Deve produrre un'impronta stabile invece di far esplodere qualcosa.
        assert_eq!(body_fingerprint(""), body_fingerprint("   ...   "));
    }
}
