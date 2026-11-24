//! Che cosa è successo a un contenuto dopo che è stato acquisito.
//!
//! # Perché questo modulo esiste
//!
//! L'archivio conserva da `0005_acquisition_runtime` due cose che nessuno
//! vedeva: le **versioni** di un contenuto modificato dopo l'acquisizione, e le
//! **cancellazioni** osservate presso la fonte. Sono immutabili per costruzione
//! — due trigger abortiscono modifica e cancellazione — e fino a CTX-01
//! l'operatore non aveva modo di sapere che esistessero.
//!
//! Era la forma di difetto che questo progetto ha già incontrato: una capacità
//! costruita, protetta e mai raggiungibile.
//!
//! # I tre fatti che governano tutto il resto
//!
//! Vanno letti insieme, perché separati inducono in errore.
//!
//! **1. Il corpo del contenuto non cambia mai.** `contents.body` è il testo con
//! cui il messaggio è stato acquisito, e nessuna riga di codice lo riscrive. Una
//! modifica osservata **aggiunge una versione**, non ne sostituisce una.
//!
//! **2. L'analisi non viene rifatta su una modifica.** Il livello 0-4, i
//! riscontri e l'eventuale alert sono stati calcolati sul corpo con cui il
//! contenuto è stato acquisito — la versione 1 — e restano quelli.
//!
//! **3. Ne segue la cosa che l'operatore deve sapere, e che nessuna schermata
//! diceva:** se un messaggio è stato modificato dopo l'acquisizione, il testo
//! mostrato e il livello mostrato **si riferiscono entrambi alla versione 1**,
//! non a ciò che si legge oggi su Telegram.
//!
//! Non è un difetto da correggere rianalizzando: rianalizzare sovrascriverebbe
//! il livello con cui un alert è stato emesso e una persona ha deciso, e
//! renderebbe inspiegabile una revisione già registrata. È un fatto da
//! **dichiarare**, ed è ciò che questo modulo esiste per rendere dicibile.
//!
//! # Che cosa questo modulo non dice, mai
//!
//! Che l'autore abbia cancellato il messaggio. Che qualcuno abbia voluto
//! nascondere qualcosa. Che NEXUM/97 abbia cancellato alcunché — non lo fa, e la
//! formulazione non deve lasciarlo credere. Dice **che cosa è stato osservato**,
//! e chi legge decide.

use crate::model::acquisition::{ContentDeletion, ContentVersion};
use crate::text::ContentBody;
use crate::time::Timestamp;

/// Quanto è successo a un contenuto, in forma breve.
///
/// # Perché una forma breve accanto a quella completa
///
/// Lo Storico mostra centinaia di righe, e ciascuna deve poter dire «modificato»
/// o «eliminato» senza caricare i corpi di ogni versione. La forma completa —
/// [`ContentHistory`] — si costruisce quando l'operatore apre un contenuto, ed è
/// l'unico momento in cui i corpi servono davvero.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ContentHistorySummary {
    /// Quante **modifiche** sono state osservate dopo l'acquisizione.
    ///
    /// Non è il numero delle versioni: le versioni sono le modifiche più una,
    /// perché la prima è il corpo originale. Un contenuto mai modificato ha zero
    /// revisioni e — nell'archivio — zero versioni, perché la versione 1 viene
    /// scritta solo quando serve, cioè alla prima modifica.
    pub revisions: u32,
    /// Quando l'ultima modifica è stata osservata.
    pub last_revision_at: Option<Timestamp>,
    /// Quando la cancellazione è stata osservata presso la fonte.
    pub deleted_at: Option<Timestamp>,
}

impl ContentHistorySummary {
    /// Se il contenuto è stato modificato dopo l'acquisizione.
    #[must_use]
    pub const fn was_revised(&self) -> bool {
        self.revisions > 0
    }

    /// Se la fonte non espone più il messaggio.
    #[must_use]
    pub const fn was_deleted(&self) -> bool {
        self.deleted_at.is_some()
    }

    /// Se c'è qualcosa da dire oltre all'acquisizione.
    #[must_use]
    pub const fn has_anything_to_show(&self) -> bool {
        self.was_revised() || self.was_deleted()
    }

    /// L'etichetta breve per una riga di elenco, o `None` se non c'è nulla da
    /// dire.
    ///
    /// # Perché «eliminato su Telegram» e non «eliminato»
    ///
    /// «Eliminato» da solo, accanto a una riga di NEXUM/97, si legge come «il
    /// programma lo ha eliminato». Il programma non elimina nulla: ha osservato
    /// che la fonte non lo espone più.
    #[must_use]
    pub fn short_label(&self) -> Option<String> {
        match (self.was_revised(), self.was_deleted()) {
            (false, false) => None,
            (false, true) => Some(String::from("eliminato su Telegram")),
            (true, false) => Some(if self.revisions == 1 {
                String::from("modificato")
            } else {
                format!("modificato {} volte", self.revisions)
            }),
            (true, true) => Some(if self.revisions == 1 {
                String::from("modificato, poi eliminato su Telegram")
            } else {
                format!(
                    "modificato {} volte, poi eliminato su Telegram",
                    self.revisions
                )
            }),
        }
    }
}

/// Che cosa si può dire confrontando due versioni consecutive.
///
/// # Perché non un confronto parola per parola
///
/// Un algoritmo di differenza produce, su un testo riscritto, un elenco di
/// frammenti che **sembra** dire che cosa è cambiato e non lo dice: allinea
/// pezzi che l'autore non ha messo in relazione, e chi legge crede di vedere
/// una modifica mirata dove c'è stata una riscrittura.
///
/// Le relazioni qui sotto sono invece **esatte**: o valgono o non valgono, si
/// verificano rileggendo i due testi, e non richiedono di fidarsi di un
/// allineamento. Quando nessuna vale, il prodotto lo dice e mostra i due testi
/// interi — che è la risposta onesta a «non lo so dire in breve».
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VersionChange {
    /// I due corpi sono identici.
    ///
    /// Telegram segnala una modifica anche quando cambia qualcosa che non è il
    /// testo: un allegato, un'anteprima, la formattazione. Il prodotto vede solo
    /// il testo, e dirlo è più utile che tacere.
    Identical,
    /// Il testo precedente è l'inizio del nuovo: è stato aggiunto in coda.
    Appended,
    /// Il nuovo testo è l'inizio del precedente: è stato accorciato in coda.
    Truncated,
    /// Il testo precedente compare per intero dentro il nuovo, non all'inizio.
    Surrounded,
    /// Nessuna delle relazioni precedenti vale.
    Rewritten,
}

impl VersionChange {
    /// Riconosce la relazione fra due corpi consecutivi.
    ///
    /// L'ordine dei controlli conta: `Identical` prima di tutto, e `Appended`
    /// prima di `Surrounded`, perché un testo aggiunto in coda è anche contenuto
    /// nel nuovo, e dire la relazione più forte è dire di più.
    #[must_use]
    pub fn between(previous: &str, current: &str) -> Self {
        if previous == current {
            return Self::Identical;
        }
        if current.starts_with(previous) {
            return Self::Appended;
        }
        if previous.starts_with(current) {
            return Self::Truncated;
        }
        // Qui `previous` non può essere vuoto, e vale la pena scriverlo perché
        // sembra il contrario: `contains` su una stringa vuota è sempre vero, e
        // un corpo precedente vuoto sarebbe classificato come «contenuto
        // attorno», che non significa nulla.
        //
        // A impedirlo è il controllo **più in alto**: `current.starts_with("")`
        // è anch'esso sempre vero, quindi un corpo precedente vuoto esce come
        // `Appended` — che è la risposta giusta — e non arriva mai fin qui.
        //
        // Un controllo esplicito su `previous.is_empty()` c'era, e una prova
        // negativa ha mostrato che **non veniva mai eseguito**: toglierlo non
        // cambiava alcun esito. È stato tolto, perché una riga che sembra
        // proteggere e non protegge è peggio della sua assenza — chi la legge
        // smette di cercare la protezione vera.
        if current.contains(previous) {
            return Self::Surrounded;
        }
        Self::Rewritten
    }

    /// Come si scrive per l'operatore.
    #[must_use]
    pub const fn as_sentence(&self) -> &'static str {
        match self {
            Self::Identical => {
                "Il testo non è cambiato. Telegram segnala una modifica anche \
                 quando cambia qualcosa che non è il testo, e il prodotto vede \
                 solo il testo."
            }
            Self::Appended => "Il testo precedente è rimasto, e ne è stato aggiunto altro in coda.",
            Self::Truncated => "Il testo è stato accorciato: la parte finale non c'è più.",
            Self::Surrounded => {
                "Il testo precedente compare per intero nel nuovo, con altro testo \
                 attorno."
            }
            Self::Rewritten => {
                "Il testo è stato riscritto. Le due versioni si leggono per \
                 intero qui sotto: un confronto parola per parola allineerebbe \
                 pezzi che nessuno ha messo in relazione."
            }
        }
    }
}

/// Il passaggio da una versione alla successiva.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VersionStep {
    /// La versione a cui si è arrivati.
    pub version: ContentVersion,
    /// Che cosa è cambiato rispetto alla precedente.
    pub change: VersionChange,
    /// Di quanti caratteri il testo si è allungato o accorciato.
    pub length_delta: i64,
}

/// Tutto ciò che si sa di un contenuto dopo l'acquisizione.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ContentHistory {
    /// Le versioni conservate, dalla prima all'ultima.
    ///
    /// **Vuoto** quando il contenuto non è mai stato modificato: la versione 1
    /// si scrive solo alla prima modifica, e un archivio che la scrivesse per
    /// ogni contenuto raddoppierebbe lo spazio dei corpi senza aggiungere un
    /// fatto.
    pub versions: Vec<ContentVersion>,
    /// La cancellazione osservata, se c'è stata.
    pub deletion: Option<ContentDeletion>,
}

impl ContentHistory {
    /// La forma breve, per una riga di elenco.
    #[must_use]
    pub fn summary(&self) -> ContentHistorySummary {
        ContentHistorySummary {
            revisions: self.revisions(),
            last_revision_at: self.versions.last().and_then(|ultima| {
                if ultima.is_original() {
                    None
                } else {
                    Some(ultima.observed_at)
                }
            }),
            deleted_at: self.deletion.as_ref().map(|voce| voce.observed_at),
        }
    }

    /// Quante modifiche sono state osservate.
    ///
    /// Le versioni meno la prima, che è il corpo originale. Zero versioni
    /// significa zero modifiche, non «storia perduta».
    #[must_use]
    pub fn revisions(&self) -> u32 {
        u32::try_from(self.versions.len().saturating_sub(1)).unwrap_or(u32::MAX)
    }

    /// Se il contenuto è stato modificato dopo l'acquisizione.
    #[must_use]
    pub fn was_revised(&self) -> bool {
        self.revisions() > 0
    }

    /// Se la fonte non espone più il messaggio.
    #[must_use]
    pub const fn was_deleted(&self) -> bool {
        self.deletion.is_some()
    }

    /// Il corpo dell'ultima versione osservata, se il contenuto è stato
    /// modificato.
    ///
    /// `None` per un contenuto mai modificato: in quel caso l'ultimo corpo
    /// osservato **è** quello del contenuto, e restituirne una copia
    /// suggerirebbe che esista una versione separata.
    #[must_use]
    pub fn latest_body(&self) -> Option<&ContentBody> {
        if !self.was_revised() {
            return None;
        }
        self.versions.last().map(|versione| &versione.body)
    }

    /// I passaggi da una versione alla successiva, in ordine.
    ///
    /// Vuoto per un contenuto mai modificato. La prima versione non è un
    /// passaggio: non c'è nulla da cui provenga.
    #[must_use]
    pub fn steps(&self) -> Vec<VersionStep> {
        let mut passaggi = Vec::new();

        for coppia in self.versions.windows(2) {
            let (precedente, corrente) = (&coppia[0], &coppia[1]);
            let prima = precedente.body.as_str();
            let dopo = corrente.body.as_str();

            // Si contano i **caratteri**, non i byte: un accento pesa due byte
            // e un carattere, e dire «piu' due caratteri» per una lettera
            // accentata aggiunta sarebbe sbagliato.
            let delta = i64::try_from(dopo.chars().count()).unwrap_or(i64::MAX)
                - i64::try_from(prima.chars().count()).unwrap_or(i64::MAX);

            passaggi.push(VersionStep {
                version: corrente.clone(),
                change: VersionChange::between(prima, dopo),
                length_delta: delta,
            });
        }

        passaggi
    }

    /// Che cosa si può dire in una frase, per l'operatore.
    ///
    /// # Che cosa la frase contiene sempre, quando serve
    ///
    /// L'avvertenza sulla **versione analizzata**. È la cosa che nessuna
    /// schermata diceva e che cambia il modo di leggere una riga: livello,
    /// riscontri e alert riguardano il corpo con cui il contenuto è stato
    /// acquisito, non l'ultima versione osservata.
    #[must_use]
    pub fn as_sentence(&self) -> String {
        if !self.was_revised() && !self.was_deleted() {
            return String::from(
                "Nessuna modifica e nessuna cancellazione osservate dopo \
                 l'acquisizione. Non significa che non ce ne siano state: \
                 significa che il monitoraggio non le ha viste.",
            );
        }

        let mut frasi = Vec::new();

        if self.was_revised() {
            let quante = self.revisions();
            frasi.push(if quante == 1 {
                String::from("Il messaggio è stato modificato una volta dopo l'acquisizione.")
            } else {
                format!("Il messaggio è stato modificato {quante} volte dopo l'acquisizione.")
            });
            frasi.push(String::from(
                "Il testo e il livello mostrati nello Storico sono quelli della \
                 versione acquisita: l'analisi non è stata rifatta sulle versioni \
                 successive.",
            ));
        }

        if let Some(cancellazione) = &self.deletion {
            frasi.push(format!(
                "Il {} il messaggio non risultava più esposto dalla fonte. \
                 NEXUM/97 non ha cancellato nulla, e che la fonte non lo esponga \
                 più non dice chi lo abbia rimosso.",
                cancellazione.observed_at.to_readable_utc()
            ));
        }

        frasi.join(" ")
    }
}

#[cfg(test)]
mod tests {
    use super::{ContentHistory, ContentHistorySummary, VersionChange};
    use crate::digest::Sha256Digest;
    use crate::id::{ContentDeletionId, ContentId, ContentVersionId, SessionId};
    use crate::model::acquisition::{ContentDeletion, ContentVersion};
    use crate::text::ContentBody;
    use crate::time::Timestamp;

    fn versione(numero: u32, corpo: &str, quando: i64) -> ContentVersion {
        let Ok(body) = ContentBody::try_new(corpo) else {
            panic!("il corpo di prova deve essere valido");
        };
        ContentVersion {
            id: ContentVersionId::new(i64::from(numero)),
            content_id: ContentId::new(1),
            version_number: numero,
            body_sha256: Sha256Digest::of_text(corpo),
            body,
            remote_edit_timestamp: None,
            observed_at: Timestamp::from_millis(quando),
            previous_version_id: None,
        }
    }

    fn cancellazione(quando: i64) -> ContentDeletion {
        ContentDeletion {
            id: ContentDeletionId::new(1),
            content_id: Some(ContentId::new(1)),
            session_id: SessionId::new(1),
            source_id: None,
            remote_event_id: None,
            observed_at: Timestamp::from_millis(quando),
        }
    }

    #[test]
    fn un_contenuto_mai_toccato_non_ha_nulla_da_mostrare() {
        let storia = ContentHistory::default();

        assert!(!storia.was_revised());
        assert!(!storia.was_deleted());
        assert_eq!(storia.revisions(), 0);
        assert!(storia.summary().short_label().is_none());
        assert!(storia.latest_body().is_none());
        assert!(storia.steps().is_empty());
    }

    /// **Zero versioni non significa storia perduta.**
    ///
    /// La versione 1 si scrive solo alla prima modifica. Un archivio vuoto di
    /// versioni per un contenuto e' il caso NORMALE, e la frase non deve
    /// suggerire che manchi qualcosa.
    #[test]
    fn la_frase_di_un_contenuto_mai_toccato_non_promette_assenza_di_fatti() {
        let frase = ContentHistory::default().as_sentence();

        assert!(frase.contains("non le ha viste"));
        assert!(
            !frase.contains("non ce ne sono state"),
            "la frase non deve affermare che non ci siano state modifiche: \
             afferma che non sono state osservate"
        );
    }

    #[test]
    fn le_versioni_meno_una_sono_le_modifiche() {
        let storia = ContentHistory {
            versions: vec![
                versione(1, "originale", 1_000),
                versione(2, "originale piu' testo", 2_000),
            ],
            deletion: None,
        };

        assert_eq!(storia.revisions(), 1);
        assert!(storia.was_revised());
        assert_eq!(
            storia.summary().short_label().as_deref(),
            Some("modificato")
        );
    }

    #[test]
    fn piu_modifiche_si_contano_e_si_dicono() {
        let storia = ContentHistory {
            versions: vec![
                versione(1, "a", 1_000),
                versione(2, "ab", 2_000),
                versione(3, "abc", 3_000),
            ],
            deletion: None,
        };

        assert_eq!(storia.revisions(), 2);
        assert_eq!(
            storia.summary().short_label().as_deref(),
            Some("modificato 2 volte")
        );
    }

    /// **L'etichetta non lascia credere che sia stato il prodotto a eliminare.**
    #[test]
    fn letichetta_della_cancellazione_nomina_telegram() {
        let storia = ContentHistory {
            versions: Vec::new(),
            deletion: Some(cancellazione(5_000)),
        };

        let etichetta = storia.summary().short_label();
        assert_eq!(etichetta.as_deref(), Some("eliminato su Telegram"));
        assert!(
            storia.as_sentence().contains("non ha cancellato nulla"),
            "la frase deve dire esplicitamente che il prodotto non cancella"
        );
    }

    /// **La frase non attribuisce la cancellazione a nessuno.**
    ///
    /// Che la fonte non esponga piu' un messaggio non dice chi lo abbia
    /// rimosso: puo' essere l'autore, un amministratore del canale, o Telegram.
    #[test]
    fn la_frase_della_cancellazione_non_attribuisce_a_nessuno() {
        let storia = ContentHistory {
            versions: Vec::new(),
            deletion: Some(cancellazione(5_000)),
        };
        let frase = storia.as_sentence().to_lowercase();

        for vietata in ["l'autore", "ha cancellato il proprio", "per nascondere"] {
            assert!(
                !frase.contains(vietata),
                "la frase attribuisce la cancellazione («{vietata}»): «{frase}»"
            );
        }
        assert!(frase.contains("non dice chi lo abbia rimosso"));
    }

    #[test]
    fn modifica_e_cancellazione_convivono() {
        let storia = ContentHistory {
            versions: vec![versione(1, "a", 1_000), versione(2, "ab", 2_000)],
            deletion: Some(cancellazione(5_000)),
        };

        assert_eq!(
            storia.summary().short_label().as_deref(),
            Some("modificato, poi eliminato su Telegram")
        );
    }

    /// **L'avvertenza sulla versione analizzata c'e' ogni volta che serve.**
    ///
    /// E' la cosa che nessuna schermata diceva: livello e testo mostrati
    /// riguardano la versione acquisita, non l'ultima osservata.
    #[test]
    fn la_frase_dichiara_che_lanalisi_non_e_stata_rifatta() {
        let storia = ContentHistory {
            versions: vec![versione(1, "a", 1_000), versione(2, "ab", 2_000)],
            deletion: None,
        };

        assert!(
            storia
                .as_sentence()
                .contains("l'analisi non è stata rifatta"),
            "chi legge deve sapere che il livello riguarda la versione acquisita"
        );
    }

    #[test]
    fn lultimo_corpo_esiste_solo_se_ce_stata_una_modifica() {
        let mai_toccato = ContentHistory::default();
        assert!(mai_toccato.latest_body().is_none());

        let modificato = ContentHistory {
            versions: vec![versione(1, "a", 1_000), versione(2, "ab", 2_000)],
            deletion: None,
        };
        assert_eq!(
            modificato.latest_body().map(ContentBody::as_str),
            Some("ab")
        );
    }

    #[test]
    fn i_passaggi_riconoscono_le_relazioni_esatte() {
        assert_eq!(
            VersionChange::between("abc", "abc"),
            VersionChange::Identical
        );
        assert_eq!(
            VersionChange::between("abc", "abcdef"),
            VersionChange::Appended
        );
        assert_eq!(
            VersionChange::between("abcdef", "abc"),
            VersionChange::Truncated
        );
        assert_eq!(
            VersionChange::between("bcd", "abcde"),
            VersionChange::Surrounded
        );
        assert_eq!(
            VersionChange::between("uno", "altro"),
            VersionChange::Rewritten
        );
    }

    /// **Un corpo precedente vuoto esce come `Appended`, non come
    /// «contenuto attorno».**
    ///
    /// `contains` su una stringa vuota e' sempre vero, quindi il caso sembra
    /// pericoloso. Non lo e', e la ragione va scritta perche' non e' quella che
    /// verrebbe in mente: a proteggerlo e' il controllo piu' in alto —
    /// `starts_with("")` e' anch'esso sempre vero — e il caso non arriva mai
    /// al confronto per contenimento.
    ///
    /// Un controllo esplicito `!previous.is_empty()` c'era, e questa prova ha
    /// mostrato che **non veniva mai eseguito**: rimuovendolo l'esito non
    /// cambiava. E' stato tolto.
    #[test]
    fn un_corpo_precedente_vuoto_esce_come_testo_aggiunto() {
        assert_eq!(
            VersionChange::between("", "qualcosa"),
            VersionChange::Appended
        );

        // E due corpi vuoti restano identici, che e' l'altro estremo.
        assert_eq!(VersionChange::between("", ""), VersionChange::Identical);
    }

    #[test]
    fn il_passaggio_porta_la_variazione_di_lunghezza_in_caratteri() {
        let storia = ContentHistory {
            versions: vec![versione(1, "abc", 1_000), versione(2, "abcde", 2_000)],
            deletion: None,
        };

        let passaggi = storia.steps();
        assert_eq!(passaggi.len(), 1);
        assert_eq!(passaggi[0].length_delta, 2);
        assert_eq!(passaggi[0].change, VersionChange::Appended);
    }

    /// **La lunghezza si conta in caratteri, non in byte.**
    ///
    /// Un accento pesa due byte e un carattere: contare i byte direbbe «piu'
    /// due» dove e' stata aggiunta una lettera sola.
    #[test]
    fn la_variazione_di_lunghezza_conta_i_caratteri_non_i_byte() {
        let storia = ContentHistory {
            versions: vec![versione(1, "citta", 1_000), versione(2, "città", 2_000)],
            deletion: None,
        };

        let passaggi = storia.steps();
        assert_eq!(
            passaggi[0].length_delta, 0,
            "«citta» e «città» hanno la stessa lunghezza in caratteri"
        );
    }

    #[test]
    fn una_riscrittura_dichiara_di_non_saper_dire_di_piu() {
        let frase = VersionChange::Rewritten.as_sentence();
        assert!(frase.contains("si leggono per intero"));
        assert!(
            frase.contains("nessuno ha messo in relazione"),
            "la frase deve dire PERCHE' non si mostra un confronto parola per parola"
        );
    }

    #[test]
    fn una_modifica_senza_cambiamento_di_testo_si_dichiara() {
        let frase = VersionChange::Identical.as_sentence();
        assert!(frase.contains("non è cambiato"));
        assert!(
            frase.contains("vede solo il testo"),
            "chi legge deve sapere perche' una modifica non mostra differenze"
        );
    }

    #[test]
    fn il_riepilogo_breve_e_coerente_con_la_storia_completa() {
        let storia = ContentHistory {
            versions: vec![versione(1, "a", 1_000), versione(2, "ab", 2_500)],
            deletion: Some(cancellazione(9_000)),
        };
        let breve = storia.summary();

        assert_eq!(breve.revisions, storia.revisions());
        assert_eq!(breve.was_revised(), storia.was_revised());
        assert_eq!(breve.was_deleted(), storia.was_deleted());
        assert_eq!(breve.last_revision_at, Some(Timestamp::from_millis(2_500)));
        assert_eq!(breve.deleted_at, Some(Timestamp::from_millis(9_000)));
        assert!(breve.has_anything_to_show());
    }

    /// **Una sola versione conservata non e' una modifica.**
    ///
    /// Puo' capitare che l'originale sia stato seminato e la modifica sia poi
    /// fallita: la storia ha una versione, e zero revisioni.
    #[test]
    fn una_sola_versione_conservata_non_conta_come_modifica() {
        let storia = ContentHistory {
            versions: vec![versione(1, "solo l'originale", 1_000)],
            deletion: None,
        };

        assert_eq!(storia.revisions(), 0);
        assert!(!storia.was_revised());
        assert!(storia.summary().short_label().is_none());
        assert!(storia.summary().last_revision_at.is_none());
        assert!(storia.latest_body().is_none());
    }

    #[test]
    fn il_riepilogo_vuoto_non_ha_nulla_da_mostrare() {
        let vuoto = ContentHistorySummary::default();
        assert!(!vuoto.has_anything_to_show());
        assert!(vuoto.short_label().is_none());
    }
}
