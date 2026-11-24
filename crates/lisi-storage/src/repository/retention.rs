//! La conservazione: quanto si tiene, che cosa si toglie, che cosa resta.
//!
//! # Il principio
//!
//! **Si conta prima e si cancella dopo, e chi cancella deve poter vedere il
//! conteggio.** Una cancellazione che non si può prevedere è una cancellazione
//! che si scopre quando è troppo tardi.
//!
//! # Le tre cose che non si toccano mai
//!
//! Non sono un dettaglio implementativo: sono la ragione per cui questa
//! politica può esistere senza rendere l'archivio inaffidabile.
//!
//! 1. **L'audit.** È la traccia di ciò che è successo, compresa la
//!    conservazione stessa. Un archivio che potesse cancellare la propria
//!    traccia non sarebbe più una traccia.
//!
//! 2. **Le fotografie dei rapporti.** Un documento già consegnato deve restare
//!    spiegabile. Lo schema lo aveva già previsto: `report_content_snapshots`
//!    tiene `content_id` come intero grezzo e non come chiave esterna, apposta
//!    perché sopravviva a ciò che descrive.
//!
//! 3. **I contenuti citati da un pacchetto prodotto**, a prescindere
//!    dall'età. Sono le prove di un documento firmato: cancellarle
//!    renderebbe l'atto inverificabile proprio nel momento in cui qualcuno
//!    chiedesse conto.
//!
//! E naturalmente nulla di ciò che è **configurazione** — dizionari, fonti,
//! account, credenziali: non è materiale acquisito, è come il prodotto è stato
//! impostato.
//!
//! # Un contenuto con una storia resta, intero (ADR-0133)
//!
//! Le **versioni** di un contenuto (migrazione 0005), le **fotografie del
//! contesto** (migrazione 0025) e le **richieste di allegati** (migrazione 0076,
//! DEC-452) sono in sola aggiunta: un trigger ne vieta la
//! cancellazione. Fino al 2026-10-02 la conservazione provava a cancellare le
//! versioni dei contenuti scaduti, il trigger annullava la transazione, e la
//! conservazione non toglieva **nulla** (D-17).
//!
//! Ora un contenuto più vecchio del limite si toglie solo **per intero**: se ha
//! una versione o una fotografia del contesto, resta con tutto ciò che lo
//! riguarda, e il conteggio [`RetentionPreview::preserved_because_history`]
//! lo dice. **Nessuna istruzione di questo modulo cancella da
//! `content_versions` o da `context_snapshots`**, e una prova lo verifica.
//!
//! # L'ordine di cancellazione non è arbitrario
//!
//! Due tabelle **non** in sola aggiunta hanno `ON DELETE RESTRICT` su
//! `contents`: `notifications` e `content_deletions`. Si sgombrano prima,
//! altrimenti la cancellazione del contenuto fallisce; il resto —
//! corrispondenze, avvisi, revisioni, indicatori, assegnazioni, recuperi — se
//! ne va da sé con `ON DELETE CASCADE`.

use lisi_core::model::NewAuditEntry;
use lisi_core::model::retention::RetentionPolicy;
use lisi_core::role::OperatingMode;
use lisi_core::text::{Actor, AuditDetail};
use rusqlite::{Connection, TransactionBehavior};

use crate::error::StorageResult;
use crate::repository::millis;

use crate::Database;

/// I contenuti più vecchi del limite che **si possono togliere**: né citati,
/// né con una storia.
///
/// Una sola definizione, usata per contare e per cancellare: due copie della
/// stessa selezione divergerebbero in silenzio, e l'esito direbbe un numero
/// diverso da ciò che è stato tolto.
const DA_TOGLIERE: &str = "SELECT id FROM contents
     WHERE published_at < ?1
       AND id NOT IN (SELECT content_id FROM report_content_snapshots)
       AND id NOT IN (SELECT content_id FROM content_versions)
       AND id NOT IN (SELECT content_id FROM context_snapshots)
       AND id NOT IN (SELECT content_id FROM attachment_keepings)";

/// Quanto verrebbe tolto, se la politica si applicasse adesso.
///
/// # Perché i conteggi sono separati
///
/// «Duecento righe» non dice nulla. «Centoventi contenuti, trecento
/// corrispondenze, dodici avvisi» dice a chi legge che cosa sta per perdere, e
/// gli permette di accorgersi se il numero è quello che si aspettava.
///
/// # Le tre colonne dei contenuti scaduti
///
/// Ogni contenuto più vecchio del limite sta in **una sola** colonna, in
/// quest'ordine: citato, con una storia, da togliere. Le tre sommano al numero
/// dei contenuti scaduti, e nessuno è contato due volte (ADR-0133).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct RetentionPreview {
    /// Contenuti che verrebbero cancellati.
    pub contents: u64,
    /// Corrispondenze che se ne andrebbero con loro.
    pub matches: u64,
    /// Avvisi che se ne andrebbero con loro.
    pub alerts: u64,
    /// Notifiche che verrebbero tolte prima dei contenuti.
    pub notifications: u64,
    /// Contenuti **risparmiati** perché citati da un pacchetto prodotto.
    ///
    /// Si mostra insieme agli altri: è la differenza fra «il prodotto non ha
    /// cancellato tutto ciò che doveva» e «il prodotto ha protetto le prove di
    /// un documento firmato».
    pub preserved_because_cited: u64,
    /// Contenuti **trattenuti per preservare la storia**: hanno una versione
    /// successiva o una fotografia del contesto, che non si cancellano
    /// (ADR-0133). Non contiene i citati.
    pub preserved_because_history: u64,
}

impl RetentionPreview {
    /// Se non c'è nulla da cancellare.
    ///
    /// Un contenuto trattenuto non è «qualcosa da cancellare»: con soli
    /// trattenuti l'anteprima è vuota, ma [`Self::retained`] non lo è.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.contents == 0
    }

    /// Quanti contenuti scaduti restano, per l'una o l'altra ragione.
    #[must_use]
    pub const fn retained(&self) -> u64 {
        self.preserved_because_cited + self.preserved_because_history
    }
}

impl Database {
    /// La politica di conservazione conservata.
    ///
    /// # Errori
    ///
    /// Se la lettura non riesce.
    pub fn retention_policy(&self) -> StorageResult<RetentionPolicy> {
        let stored: Option<i64> = self.connection.query_row(
            "SELECT keep_days FROM retention_policy WHERE id = 1",
            [],
            |row| row.get(0),
        )?;

        Ok(RetentionPolicy::from_stored(
            stored.and_then(|days| u32::try_from(days).ok()),
        ))
    }

    /// Salva la politica scelta.
    ///
    /// # Errori
    ///
    /// Se la scrittura non riesce.
    pub fn save_retention_policy(
        &self,
        policy: RetentionPolicy,
        actor: &Actor,
        now_ms: i64,
    ) -> StorageResult<()> {
        self.connection.execute(
            "UPDATE retention_policy
             SET keep_days = ?1, updated_at = ?2, updated_by = ?3
             WHERE id = 1",
            rusqlite::params![policy.days(), now_ms, actor.as_str()],
        )?;
        Ok(())
    }

    /// Quanto verrebbe tolto applicando la politica adesso.
    ///
    /// Non cancella nulla.
    ///
    /// # Errori
    ///
    /// Se una delle interrogazioni non riesce.
    pub fn retention_preview(
        &self,
        policy: RetentionPolicy,
        now_ms: i64,
    ) -> StorageResult<RetentionPreview> {
        let Some(cutoff) = cutoff_ms(policy, now_ms) else {
            // «Si conserva tutto» non ha nulla da mostrare, e non e' un caso
            // vuoto per caso: e' il predefinito.
            return Ok(RetentionPreview::default());
        };
        conteggi(&self.connection, cutoff)
    }

    /// Applica la politica dove è possibile, e restituisce ciò che è stato
    /// **effettivamente** tolto e trattenuto.
    ///
    /// # La conservazione si applica dove è possibile, e lo dice
    ///
    /// Un contenuto con una storia resta, intero (ADR-0133): l'esito ne porta
    /// il numero, e così la voce d'audit.
    ///
    /// # Perche' i conteggi si fanno dentro la transazione
    ///
    /// La transazione prende la scrittura **dall'inizio** (`IMMEDIATE`): ciò
    /// che conta e ciò che cancella vedono lo stesso archivio, e l'esito dice
    /// ciò che è successo, non ciò che si prevedeva un istante prima.
    ///
    /// # Perche' la traccia entra nella stessa transazione
    ///
    /// Se la cancellazione riuscisse e la traccia venisse scritta dopo, un
    /// arresto fra le due lascerebbe **materiale sparito senza che nulla dica
    /// che qualcuno lo ha fatto sparire**. Registrare insieme rende quel caso
    /// impossibile: o restano entrambe, o non accade nessuna delle due.
    ///
    /// La traccia si scrive solo se qualcosa e' stato davvero tolto: «non
    /// c'era nulla da togliere» non e' un fatto, ed e' il caso piu' frequente.
    ///
    /// # Errori
    ///
    /// Se una cancellazione non riesce. In quel caso la transazione viene
    /// annullata e **nulla** è stato cancellato: una conservazione applicata a
    /// metà lascerebbe l'archivio in uno stato che nessuna anteprima aveva
    /// descritto.
    pub fn apply_retention(
        &mut self,
        policy: RetentionPolicy,
        now_ms: i64,
        audit: &NewAuditEntry,
    ) -> StorageResult<RetentionPreview> {
        let Some(cutoff) = cutoff_ms(policy, now_ms) else {
            return Ok(RetentionPreview::default());
        };

        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;

        let esito = conteggi(&transaction, cutoff)?;
        if esito.is_empty() {
            // Nulla da togliere, forse qualcosa da trattenere: l'esito lo
            // dice, e l'archivio resta com'era.
            transaction.commit()?;
            return Ok(esito);
        }

        // **L'ordine conta.** Le due tabelle con ON DELETE RESTRICT che non
        // sono in sola aggiunta vanno sgombrate prima. Le versioni e le
        // fotografie del contesto NON compaiono qui: i loro contenuti sono
        // esclusi da DA_TOGLIERE (ADR-0133).
        for tabella in ["notifications", "content_deletions"] {
            transaction.execute(
                &format!("DELETE FROM {tabella} WHERE content_id IN ({DA_TOGLIERE})"),
                rusqlite::params![cutoff],
            )?;
        }

        // E qui se ne vanno anche alerts, matches e reviews, per CASCADE.
        transaction.execute(
            &format!("DELETE FROM contents WHERE id IN ({DA_TOGLIERE})"),
            rusqlite::params![cutoff],
        )?;

        let dettaglio = dettaglio_con_i_numeri(audit.detail.as_ref(), &esito)?;
        transaction.execute(
            "INSERT INTO audit (actor, action, entity, entity_id, actor_mode, detail, recorded_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            rusqlite::params![
                audit.actor.as_str(),
                audit.action.as_str(),
                audit.entity.as_str(),
                audit.entity_id,
                audit.actor_mode.map(OperatingMode::as_str),
                dettaglio.as_str(),
                millis(audit.recorded_at),
            ],
        )?;

        transaction.commit()?;

        Ok(esito)
    }

    /// Ricostruisce il file dell'archivio, restituendo lo spazio liberato.
    ///
    /// # Perche' cancellare non basta
    ///
    /// Cancellare delle righe non rimpicciolisce il file: SQLite segna le
    /// pagine come libere e le riusa. Sono due problemi, non uno.
    ///
    /// Il primo e' una promessa non mantenuta. Chi sceglie «90 giorni» lo fa
    /// anche per liberare spazio; se dopo la cancellazione il file pesa uguale,
    /// il prodotto dice di aver tolto qualcosa e il disco dice di no. Fra le
    /// due, chi guarda crede al disco.
    ///
    /// Il secondo e' piu' serio. Una pagina libera **conserva i byte** di cio'
    /// che conteneva finche' qualcosa non la riscrive: del materiale
    /// «cancellato» resta leggibile con strumenti forensi sul file. Per un
    /// archivio di monitoraggio d'ufficio non e' una sottigliezza.
    ///
    /// `VACUUM` ricostruisce il file da capo e risolve entrambi.
    ///
    /// # Che cosa NON risolve
    ///
    /// La copia temporanea che `VACUUM` scrive durante la ricostruzione, e i
    /// file del giornale WAL, sono stati su disco che possono a loro volta
    /// restare leggibili. La cifratura del volume resta la sola difesa che
    /// copre l'intero ciclo (ADR-0036).
    ///
    /// # Errori
    ///
    /// Restituisce un errore se lo spazio per la copia temporanea non basta, se
    /// il file e' bloccato da un altro processo, o se una transazione e' aperta:
    /// `VACUUM` non puo' stare dentro una transazione.
    pub fn compact(&self) -> StorageResult<()> {
        self.connection.execute_batch("VACUUM")?;
        Ok(())
    }
}

/// I conteggi dell'anteprima e dell'esito, su una connessione o dentro una
/// transazione.
fn conteggi(connection: &Connection, cutoff: i64) -> StorageResult<RetentionPreview> {
    let conta = |sql: &str| -> StorageResult<u64> {
        let value: i64 = connection.query_row(sql, rusqlite::params![cutoff], |row| row.get(0))?;
        Ok(u64::try_from(value).unwrap_or(0))
    };

    Ok(RetentionPreview {
        contents: conta(&format!("SELECT count(*) FROM ({DA_TOGLIERE})"))?,
        matches: conta(&format!(
            "SELECT count(*) FROM matches WHERE content_id IN ({DA_TOGLIERE})"
        ))?,
        alerts: conta(&format!(
            "SELECT count(*) FROM alerts WHERE content_id IN ({DA_TOGLIERE})"
        ))?,
        notifications: conta(&format!(
            "SELECT count(*) FROM notifications WHERE content_id IN ({DA_TOGLIERE})"
        ))?,
        preserved_because_cited: conta(
            "SELECT count(*) FROM contents
             WHERE published_at < ?1
               AND id IN (SELECT content_id FROM report_content_snapshots)",
        )?,
        preserved_because_history: conta(
            "SELECT count(*) FROM contents
             WHERE published_at < ?1
               AND id NOT IN (SELECT content_id FROM report_content_snapshots)
               AND (id IN (SELECT content_id FROM content_versions)
                    OR id IN (SELECT content_id FROM context_snapshots)
                    OR id IN (SELECT content_id FROM attachment_keepings))",
        )?,
    })
}

/// Il dettaglio della voce d'audit, con i numeri dell'esito.
///
/// L'audit dice che cosa è stato tolto **e** che cosa è stato trattenuto: una
/// traccia che contasse solo i tolti lascerebbe credere che la politica sia
/// stata applicata per intero.
fn dettaglio_con_i_numeri(
    base: Option<&AuditDetail>,
    esito: &RetentionPreview,
) -> StorageResult<AuditDetail> {
    let numeri = format!(
        "tolti {} contenuti; trattenuti {} per preservare la storia e {} perché citati",
        esito.contents, esito.preserved_because_history, esito.preserved_because_cited
    );
    let testo = match base {
        Some(base) => format!("{}; {numeri}", base.as_str()),
        None => numeri,
    };
    Ok(AuditDetail::try_new(&testo)?)
}

/// L'istante prima del quale un contenuto è «vecchio».
///
/// `None` quando la politica conserva tutto: non c'è alcuna soglia, ed è
/// diverso da una soglia infinitamente lontana.
fn cutoff_ms(policy: RetentionPolicy, now_ms: i64) -> Option<i64> {
    let days = i64::from(policy.days()?);
    // Millisecondi in un giorno. Il calcolo non passa per fusi orari o
    // calendari: una politica di conservazione che cambiasse lunghezza con
    // l'ora legale sarebbe impossibile da spiegare a chi chiede conto.
    days.checked_mul(86_400_000)
        .and_then(|durata| now_ms.checked_sub(durata))
}

#[cfg(test)]
mod tests {
    use lisi_core::model::retention::{RetentionDays, RetentionPolicy};

    use crate::test_support::{actor, database_with_session, new_content};

    /// Un giorno in millisecondi.
    const GIORNO: i64 = 86_400_000;

    /// Una voce d'audit di prova.
    fn voce(now_ms: i64) -> lisi_core::model::NewAuditEntry {
        let (Ok(action), Ok(entity)) = (
            lisi_core::text::AuditAction::try_new("conservazione_applicata"),
            lisi_core::text::AuditEntity::try_new("retention"),
        ) else {
            panic!("il vocabolario d'audit di prova deve essere valido");
        };
        lisi_core::model::NewAuditEntry {
            actor: actor("operatore.prova"),
            action,
            entity,
            entity_id: None,
            actor_mode: None,
            detail: None,
            recorded_at: lisi_core::Timestamp::from_millis(now_ms),
        }
    }

    /// Applica la conservazione con una voce d'audit di prova.
    ///
    /// Le prove che seguono verificano *che cosa* viene tolto; che la traccia
    /// venga scritta, e nella stessa transazione, ha una prova sua.
    trait ApplicaPerProva {
        fn apply_retention_prova(
            &mut self,
            policy: RetentionPolicy,
            now_ms: i64,
        ) -> crate::error::StorageResult<super::RetentionPreview>;
    }

    impl ApplicaPerProva for crate::Database {
        fn apply_retention_prova(
            &mut self,
            policy: RetentionPolicy,
            now_ms: i64,
        ) -> crate::error::StorageResult<super::RetentionPreview> {
            self.apply_retention(policy, now_ms, &voce(now_ms))
        }
    }

    fn politica(giorni: u32) -> RetentionPolicy {
        let Ok(giorni) = RetentionDays::try_new(giorni) else {
            panic!("i giorni di prova devono essere ammessi");
        };
        RetentionPolicy::Days(giorni)
    }

    #[test]
    fn un_archivio_nuovo_conserva_tutto() {
        // E' il predefinito, ed e' la scelta prudente: qualunque altro
        // cancellerebbe dati il giorno dell'aggiornamento.
        let (database, _, _) = database_with_session();
        let Ok(policy) = database.retention_policy() else {
            panic!("la riga predefinita deve potersi leggere");
        };
        assert_eq!(policy, RetentionPolicy::Unlimited);
    }

    #[test]
    fn la_politica_scelta_si_rilegge_uguale() {
        let (database, _, _) = database_with_session();
        let scelta = politica(90);

        database
            .save_retention_policy(scelta, &actor("operatore.prova"), 1_000)
            .expect("la politica deve potersi salvare");

        let Ok(riletta) = database.retention_policy() else {
            panic!("la politica deve potersi rileggere");
        };
        assert_eq!(riletta, scelta);
    }

    #[test]
    fn conservare_tutto_non_cancella_e_non_promette_di_cancellare() {
        let (mut database, source_id, session_id) = database_with_session();
        let mut contenuto = new_content(session_id, source_id, "m-1", "vecchio");
        contenuto.published_at = lisi_core::Timestamp::from_millis(0);
        database
            .insert_content(&contenuto)
            .expect("il contenuto di prova deve potersi registrare");

        let adesso = 1_000 * GIORNO;

        let Ok(anteprima) = database.retention_preview(RetentionPolicy::Unlimited, adesso) else {
            panic!("l'anteprima deve riuscire");
        };
        assert!(
            anteprima.is_empty(),
            "con «tutto» non c'e' nulla da togliere"
        );

        let Ok(esito) = database.apply_retention_prova(RetentionPolicy::Unlimited, adesso) else {
            panic!("l'applicazione deve riuscire");
        };
        assert_eq!(esito.contents, 0);

        let rimasti: i64 = database
            .connection
            .query_row("SELECT count(*) FROM contents", [], |row| row.get(0))
            .expect("il conteggio deve riuscire");
        assert_eq!(rimasti, 1, "il contenuto non doveva essere toccato");
    }

    #[test]
    fn l_anteprima_dice_quanto_prima_di_cancellare_e_poi_lo_toglie() {
        // Si conta prima e si cancella dopo. Una cancellazione che non si puo'
        // prevedere e' una cancellazione che si scopre quando e' troppo tardi.
        let (mut database, source_id, session_id) = database_with_session();

        let adesso = 1_000 * GIORNO;

        // Tre vecchi e uno recente.
        for (numero, quando) in [(1, 900), (2, 800), (3, 700), (4, 999)] {
            let mut contenuto = new_content(session_id, source_id, &format!("m-{numero}"), "testo");
            contenuto.published_at = lisi_core::Timestamp::from_millis(quando * GIORNO);
            database
                .insert_content(&contenuto)
                .expect("il contenuto di prova deve potersi registrare");
        }

        // Trenta giorni: sopravvive solo quello di ieri.
        let policy = politica(30);

        let Ok(anteprima) = database.retention_preview(policy, adesso) else {
            panic!("l'anteprima deve riuscire");
        };
        assert_eq!(
            anteprima.contents, 3,
            "l'anteprima deve contare i tre vecchi"
        );

        let Ok(esito) = database.apply_retention_prova(policy, adesso) else {
            panic!("l'applicazione deve riuscire");
        };
        assert_eq!(
            esito.contents, anteprima.contents,
            "cio' che e' stato tolto deve coincidere con cio' che era stato annunciato"
        );

        let rimasti: i64 = database
            .connection
            .query_row("SELECT count(*) FROM contents", [], |row| row.get(0))
            .expect("il conteggio deve riuscire");
        assert_eq!(rimasti, 1, "doveva restare il solo contenuto recente");
    }

    /// **La prova che conta: le prove di un documento firmato non spariscono.**
    ///
    /// Un contenuto citato da un pacchetto gia' prodotto resta nell'archivio
    /// a prescindere dall'eta'. Cancellarlo renderebbe l'atto inverificabile
    /// proprio nel momento in cui qualcuno chiedesse conto — e sarebbe il
    /// prodotto stesso a distruggere le proprie prove, per una politica che
    /// nessuno aveva pensato riguardasse anche quelle.
    ///
    /// Il pacchetto si apre con l'API vera e non inserendo righe a mano: una
    /// prova che scrivesse da se' la fotografia verificherebbe la propria
    /// idea di come e' fatta, non quella del prodotto.
    #[test]
    fn un_contenuto_citato_da_un_documento_prodotto_non_si_cancella_mai() {
        let (mut database, source_id, session_id) = database_with_session();
        let adesso = 1_000 * GIORNO;

        // Due contenuti, entrambi vecchissimi.
        let mut citato = new_content(session_id, source_id, "m-citato", "prova");
        citato.published_at = lisi_core::Timestamp::from_millis(0);
        let Ok(citato) = database.insert_content(&citato) else {
            panic!("il contenuto citato deve potersi registrare");
        };

        let mut qualunque = new_content(session_id, source_id, "m-altro", "prova");
        qualunque.published_at = lisi_core::Timestamp::from_millis(0);
        database
            .insert_content(&qualunque)
            .expect("il secondo contenuto deve potersi registrare");

        // Un pacchetto che cita il primo.
        let Ok(report_id) = lisi_core::model::report::ReportId::try_new("R-2026-000001") else {
            panic!("l'identificativo di prova deve essere valido");
        };
        let snapshot = lisi_core::model::report::ReportSnapshot {
            taken_at: lisi_core::Timestamp::from_millis(adesso),
            session_id,
            source_ids: vec![source_id],
            dictionary_version_ids: Vec::new(),
            template_version: 1,
            contents: vec![lisi_core::model::report::ReportContentSnapshot {
                content_id: citato.content_id(),
                level: lisi_core::model::analysis::AnalysisLevel::NOT_RELEVANT,
                review_state: None,
                body_sha256: lisi_core::Sha256Digest::of_text("prova"),
                selected: true,
            }],
        };
        let request = lisi_core::model::report::ReportRequest {
            report_id,
            session_id,
            requested_by: actor("operatore.prova"),
            requested_at: lisi_core::Timestamp::from_millis(adesso),
            selection: lisi_core::model::report::ReportSelection::empty(),
            requested_kinds: Vec::new(),
            template_version: 1,
        };
        database
            .open_report_package(&request, &snapshot)
            .expect("il pacchetto di prova deve potersi aprire");

        // Una politica severissima: un giorno.
        let policy = politica(1);

        let Ok(anteprima) = database.retention_preview(policy, adesso) else {
            panic!("l'anteprima deve riuscire");
        };
        assert_eq!(
            anteprima.contents, 1,
            "solo il contenuto NON citato deve risultare cancellabile"
        );
        assert_eq!(
            anteprima.preserved_because_cited, 1,
            "l'anteprima deve DIRE che uno e' stato risparmiato, non tacerlo"
        );

        database
            .apply_retention_prova(policy, adesso)
            .expect("l'applicazione deve riuscire");

        let sopravvissuto: i64 = database
            .connection
            .query_row(
                "SELECT count(*) FROM contents WHERE id = ?1",
                rusqlite::params![citato.content_id().get()],
                |row| row.get(0),
            )
            .expect("il conteggio deve riuscire");
        assert_eq!(
            sopravvissuto, 1,
            "il prodotto ha cancellato le prove di un documento che ha firmato"
        );

        let totale: i64 = database
            .connection
            .query_row("SELECT count(*) FROM contents", [], |row| row.get(0))
            .expect("il conteggio deve riuscire");
        assert_eq!(totale, 1, "l'altro contenuto doveva essere tolto");
    }

    #[test]
    fn l_audit_non_viene_mai_toccato() {
        // E' la traccia di cio' che e' successo, compresa la conservazione
        // stessa. Un archivio che potesse cancellare la propria traccia non
        // sarebbe piu' una traccia.
        let (mut database, source_id, session_id) = database_with_session();

        let adesso = 1_000 * GIORNO;
        let mut contenuto = new_content(session_id, source_id, "m-1", "vecchio");
        contenuto.published_at = lisi_core::Timestamp::from_millis(0);
        database
            .insert_content(&contenuto)
            .expect("il contenuto di prova deve potersi registrare");

        let prima: i64 = database
            .connection
            .query_row("SELECT count(*) FROM audit", [], |row| row.get(0))
            .expect("il conteggio deve riuscire");

        database
            .apply_retention_prova(politica(30), adesso)
            .expect("l'applicazione deve riuscire");

        let dopo: i64 = database
            .connection
            .query_row("SELECT count(*) FROM audit", [], |row| row.get(0))
            .expect("il conteggio deve riuscire");

        assert_eq!(
            dopo,
            prima + 1,
            "la conservazione deve solo AGGIUNGERE la propria traccia, mai togliere"
        );
    }

    /// **Una cancellazione senza traccia non deve poter esistere.**
    ///
    /// La traccia entra nella stessa transazione della cancellazione: o
    /// restano entrambe, o non accade nessuna delle due. Se fosse scritta
    /// dopo, un arresto fra le due lascerebbe materiale sparito senza che
    /// nulla dica che qualcuno lo ha fatto sparire.
    #[test]
    fn cio_che_viene_tolto_lascia_traccia_e_cio_che_non_viene_tolto_no() {
        let (mut database, source_id, session_id) = database_with_session();
        let adesso = 1_000 * GIORNO;

        // Prima: nulla da togliere. Non deve nascere alcuna traccia, perche'
        // «non c'era nulla da togliere» non e' un fatto da registrare.
        let prima = quante_tracce(&database);
        database
            .apply_retention_prova(politica(30), adesso)
            .expect("l'applicazione deve riuscire");
        assert_eq!(
            quante_tracce(&database),
            prima,
            "una conservazione che non ha tolto nulla non deve lasciare traccia"
        );

        // Poi: qualcosa da togliere. La traccia deve esserci.
        let mut contenuto = new_content(session_id, source_id, "m-1", "vecchio");
        contenuto.published_at = lisi_core::Timestamp::from_millis(0);
        database
            .insert_content(&contenuto)
            .expect("il contenuto di prova deve potersi registrare");

        database
            .apply_retention_prova(politica(30), adesso)
            .expect("l'applicazione deve riuscire");

        assert_eq!(
            quante_tracce(&database),
            prima + 1,
            "il prodotto ha cancellato del materiale senza lasciarne traccia"
        );
    }

    /// **Lo spazio va restituito davvero.**
    ///
    /// Cancellare delle righe non rimpicciolisce il file: SQLite segna le
    /// pagine come libere e le riusa. Chi sceglie una conservazione breve lo fa
    /// anche per liberare spazio, e se dopo la cancellazione il file pesa
    /// uguale, il prodotto dice di aver tolto qualcosa e il disco dice di no.
    ///
    /// La prova sta su un archivio **su disco** e non in memoria: un archivio
    /// in memoria non ha un file da misurare, e una prova che misurasse una
    /// dimensione inventata verificherebbe la propria idea di come funziona
    /// SQLite invece del comportamento reale.
    #[test]
    fn dopo_la_conservazione_il_file_dell_archivio_si_rimpicciolisce() {
        let Ok(cartella) = tempfile::tempdir() else {
            panic!("la cartella temporanea deve potersi creare");
        };
        let percorso = cartella.path().join("archivio.sqlite3");

        let (source_id, session_id) = {
            let Ok(mut database) = crate::Database::open(&percorso) else {
                panic!("l'archivio di prova deve potersi aprire");
            };
            let Ok(source_id) = database.insert_source(
                &crate::test_support::new_source("canale_uno"),
                crate::test_support::now(),
            ) else {
                panic!("la fonte di prova deve potersi registrare");
            };
            let Ok(session_id) = database.insert_session(
                &crate::test_support::new_session(vec![source_id]),
                crate::test_support::now(),
            ) else {
                panic!("la sessione di prova deve potersi creare");
            };

            // Materiale abbondante: con poche righe la differenza sparirebbe
            // nell'arrotondamento delle pagine, e la prova non distinguerebbe
            // una compattazione riuscita da una non avvenuta.
            let corpo = "x".repeat(4_000);
            for numero in 0..400_u32 {
                let mut contenuto =
                    new_content(session_id, source_id, &format!("m-{numero}"), &corpo);
                contenuto.published_at = lisi_core::Timestamp::from_millis(0);
                let Ok(_) = database.insert_content(&contenuto) else {
                    panic!("il contenuto di prova deve potersi registrare");
                };
            }
            (source_id, session_id)
        };
        let _ = (source_id, session_id);

        let prima = dimensione(&percorso);
        assert!(
            prima > 500_000,
            "l'archivio di prova deve essere abbastanza grande da misurarlo: {prima} byte"
        );

        {
            let Ok(mut database) = crate::Database::open(&percorso) else {
                panic!("l'archivio deve potersi riaprire");
            };
            let Ok(esito) = database.apply_retention_prova(politica(1), 1_000 * GIORNO) else {
                panic!("l'applicazione deve riuscire");
            };
            assert_eq!(esito.contents, 400, "dovevano sparire tutti i contenuti");
            let Ok(()) = database.compact() else {
                panic!("la compattazione deve riuscire");
            };
        }

        let dopo = dimensione(&percorso);
        assert!(
            dopo < prima / 2,
            "il file e' passato da {prima} a {dopo} byte: lo spazio non e' stato restituito"
        );
    }

    /// La dimensione di un file, in byte.
    fn dimensione(percorso: &std::path::Path) -> u64 {
        let Ok(dati) = std::fs::metadata(percorso) else {
            panic!("il file dell'archivio deve esistere");
        };
        dati.len()
    }

    /// Quante tracce di conservazione applicata contiene l'audit.
    fn quante_tracce(database: &crate::Database) -> i64 {
        database
            .connection
            .query_row(
                "SELECT count(*) FROM audit WHERE action = 'conservazione_applicata'",
                [],
                |row| row.get(0),
            )
            .expect("il conteggio deve riuscire")
    }

    #[test]
    fn la_configurazione_non_viene_mai_toccata() {
        // Dizionari, fonti e sessioni non sono materiale acquisito: sono come
        // il prodotto e' stato impostato.
        let (mut database, _, _) = database_with_session();

        database
            .apply_retention_prova(politica(1), 10_000 * GIORNO)
            .expect("l'applicazione deve riuscire");

        for tabella in ["sources", "sessions", "retention_policy"] {
            let quante: i64 = database
                .connection
                .query_row(&format!("SELECT count(*) FROM {tabella}"), [], |row| {
                    row.get(0)
                })
                .expect("il conteggio deve riuscire");
            assert!(quante > 0, "la conservazione ha svuotato «{tabella}»");
        }
    }

    // ---------------------------------------------------------------------
    // D-17 (ADR-0133): un contenuto con una storia resta, intero.
    // ---------------------------------------------------------------------

    /// Un contenuto vecchio, registrato; restituisce il suo identificativo.
    fn vecchio(
        database: &mut crate::Database,
        sessione: lisi_core::SessionId,
        fonte: lisi_core::SourceId,
        id: &str,
    ) -> lisi_core::ContentId {
        let mut contenuto = new_content(sessione, fonte, id, "testo");
        contenuto.published_at = lisi_core::Timestamp::from_millis(0);
        let Ok(inserito) = database.insert_content(&contenuto) else {
            panic!("il contenuto di prova deve potersi registrare");
        };
        inserito.content_id()
    }

    /// Aggiunge una versione al contenuto, come farebbe l'acquisizione.
    fn versione(database: &crate::Database, contenuto: lisi_core::ContentId, numero: i64) {
        let Ok(_) = database.connection.execute(
            "INSERT INTO content_versions
                 (content_id, version_number, body, body_sha256, observed_at)
             VALUES (?1, ?2, 'corpo', ?3, 1)",
            rusqlite::params![contenuto.get(), numero, "a".repeat(64)],
        ) else {
            panic!("la versione di prova deve potersi registrare");
        };
    }

    /// Aggiunge una fotografia del contesto al contenuto.
    fn fotografia(
        database: &crate::Database,
        contenuto: lisi_core::ContentId,
        fonte: lisi_core::SourceId,
    ) {
        let Ok(_) = database.connection.execute(
            "INSERT INTO context_snapshots
                 (content_id, source_id, taken_by, reason, taken_at, observed_at,
                  anchor_remote_message_id, anchor_digest, integrity)
             VALUES (?1, ?2, 'operatore.prova', 'prova', 1, 1, 'm', 'x', 'integra')",
            rusqlite::params![contenuto.get(), fonte.get()],
        ) else {
            panic!("la fotografia di prova deve potersi registrare");
        };
    }

    /// Un pacchetto prodotto che cita il contenuto, con l'API vera.
    fn cita(
        database: &mut crate::Database,
        contenuto: lisi_core::ContentId,
        sessione: lisi_core::SessionId,
        fonte: lisi_core::SourceId,
    ) {
        let Ok(report_id) = lisi_core::model::report::ReportId::try_new("R-2026-000002") else {
            panic!("l'identificativo di prova deve essere valido");
        };
        let snapshot = lisi_core::model::report::ReportSnapshot {
            taken_at: lisi_core::Timestamp::from_millis(1),
            session_id: sessione,
            source_ids: vec![fonte],
            dictionary_version_ids: Vec::new(),
            template_version: 1,
            contents: vec![lisi_core::model::report::ReportContentSnapshot {
                content_id: contenuto,
                level: lisi_core::model::analysis::AnalysisLevel::NOT_RELEVANT,
                review_state: None,
                body_sha256: lisi_core::Sha256Digest::of_text("testo"),
                selected: true,
            }],
        };
        let request = lisi_core::model::report::ReportRequest {
            report_id,
            session_id: sessione,
            requested_by: actor("operatore.prova"),
            requested_at: lisi_core::Timestamp::from_millis(1),
            selection: lisi_core::model::report::ReportSelection::empty(),
            requested_kinds: Vec::new(),
            template_version: 1,
        };
        let Ok(_) = database.open_report_package(&request, &snapshot) else {
            panic!("il pacchetto di prova deve potersi aprire");
        };
    }

    fn conta(database: &crate::Database, sql: &str) -> i64 {
        let Ok(valore) = database.connection.query_row(sql, [], |row| row.get(0)) else {
            panic!("il conteggio «{sql}» deve riuscire");
        };
        valore
    }

    /// **Il difetto D-17, com'era**: un solo contenuto scaduto con una
    /// versione faceva annullare l'intera conservazione. Ora resta lui, con
    /// la sua versione, e gli altri se ne vanno.
    #[test]
    fn un_contenuto_con_una_versione_resta_e_gli_altri_se_ne_vanno() {
        let (mut database, fonte, sessione) = database_with_session();
        let adesso = 1_000 * GIORNO;
        let modificato = vecchio(&mut database, sessione, fonte, "m-modificato");
        versione(&database, modificato, 1);
        vecchio(&mut database, sessione, fonte, "m-semplice");

        let Ok(anteprima) = database.retention_preview(politica(30), adesso) else {
            panic!("l'anteprima deve riuscire");
        };
        assert_eq!(anteprima.contents, 1);
        assert_eq!(anteprima.preserved_because_history, 1);

        let esito = database.apply_retention_prova(politica(30), adesso);
        let Ok(esito) = esito else {
            panic!("la conservazione non deve fermarsi per una versione: {esito:?}");
        };
        assert_eq!(
            esito, anteprima,
            "l'esito deve dire ciò che l'anteprima aveva detto"
        );
        assert_eq!(conta(&database, "SELECT count(*) FROM contents"), 1);
        assert_eq!(
            conta(
                &database,
                &format!(
                    "SELECT count(*) FROM contents WHERE id = {}",
                    modificato.get()
                )
            ),
            1,
            "il contenuto con una storia doveva restare"
        );
        assert_eq!(conta(&database, "SELECT count(*) FROM content_versions"), 1);
    }

    /// **Più versioni: nessuna mutilazione.** La storia resta intera.
    #[test]
    fn un_contenuto_con_piu_versioni_resta_con_tutte() {
        let (mut database, fonte, sessione) = database_with_session();
        let modificato = vecchio(&mut database, sessione, fonte, "m-modificato");
        for numero in 1..=3 {
            versione(&database, modificato, numero);
        }
        let Ok(esito) = database.apply_retention_prova(politica(30), 1_000 * GIORNO) else {
            panic!("la conservazione deve riuscire");
        };
        assert_eq!(esito.contents, 0);
        assert!(esito.is_empty());
        assert_eq!(esito.preserved_because_history, 1);
        assert_eq!(conta(&database, "SELECT count(*) FROM content_versions"), 3);
        assert_eq!(conta(&database, "SELECT count(*) FROM contents"), 1);
    }

    /// **Una fotografia del contesto è storia anch'essa**: il secondo caso
    /// della stessa forma, trovato correggendo D-17.
    #[test]
    fn un_contenuto_con_una_fotografia_del_contesto_resta() {
        let (mut database, fonte, sessione) = database_with_session();
        let fotografato = vecchio(&mut database, sessione, fonte, "m-fotografato");
        fotografia(&database, fotografato, fonte);
        let esito = database.apply_retention_prova(politica(30), 1_000 * GIORNO);
        let Ok(esito) = esito else {
            panic!("la conservazione deve riuscire con una fotografia del contesto: {esito:?}");
        };
        assert_eq!(esito.preserved_because_history, 1);
        assert_eq!(conta(&database, "SELECT count(*) FROM contents"), 1);
        assert_eq!(
            conta(&database, "SELECT count(*) FROM context_snapshots"),
            1
        );
    }

    /// **Un contenuto con un allegato chiesto resta, intero** (ATTACH-01
    /// parte 2, DEC-452): la richiesta, riuscita o no, è un fatto
    /// sull'archivio e non si toglie. Prova negativa: il contenuto accanto,
    /// senza richieste, se ne va.
    #[test]
    fn un_contenuto_con_un_allegato_chiesto_resta() {
        let (mut database, fonte, sessione) = database_with_session();
        let chiesto = vecchio(&mut database, sessione, fonte, "m-allegato");
        let _ = vecchio(&mut database, sessione, fonte, "m-senza");
        let Ok(_) = database.connection.execute(
            "INSERT INTO attachment_keepings
                 (content_id, requested_by, reason, requested_at, outcome)
             VALUES (?1, 'operatore.prova', 'prova', 1, 'rifiutato')",
            [chiesto.get()],
        ) else {
            panic!("la richiesta di prova deve potersi registrare");
        };
        let esito = database.apply_retention_prova(politica(30), 1_000 * GIORNO);
        let Ok(esito) = esito else {
            panic!("la conservazione deve riuscire con un allegato chiesto: {esito:?}");
        };
        assert_eq!(esito.preserved_because_history, 1);
        assert_eq!(conta(&database, "SELECT count(*) FROM contents"), 1);
        assert_eq!(
            conta(&database, "SELECT count(*) FROM attachment_keepings"),
            1
        );
    }

    /// **Le tre colonne sommano ai contenuti scaduti**, e nessuno è contato
    /// due volte: un contenuto citato **e** con una versione è un citato.
    #[test]
    fn le_tre_colonne_sommano_e_la_citazione_viene_prima() {
        let (mut database, fonte, sessione) = database_with_session();
        let citato = vecchio(&mut database, sessione, fonte, "m-citato");
        versione(&database, citato, 1);
        cita(&mut database, citato, sessione, fonte);
        let modificato = vecchio(&mut database, sessione, fonte, "m-modificato");
        versione(&database, modificato, 1);
        vecchio(&mut database, sessione, fonte, "m-semplice");

        let Ok(anteprima) = database.retention_preview(politica(30), 1_000 * GIORNO) else {
            panic!("l'anteprima deve riuscire");
        };
        assert_eq!(anteprima.contents, 1);
        assert_eq!(anteprima.preserved_because_cited, 1);
        assert_eq!(anteprima.preserved_because_history, 1);
        let scaduti = conta(
            &database,
            "SELECT count(*) FROM contents WHERE published_at < 1",
        );
        assert_eq!(
            i64::try_from(anteprima.contents + anteprima.retained()).unwrap_or(-1),
            scaduti,
            "tolti più trattenuti devono fare i contenuti scaduti: {anteprima:?}"
        );
    }

    /// **L'audit dice i tolti e i trattenuti.** Una traccia che contasse solo
    /// i tolti lascerebbe credere che la politica sia stata applicata per
    /// intero.
    #[test]
    fn l_audit_dice_quanti_sono_stati_tolti_e_quanti_trattenuti() {
        let (mut database, fonte, sessione) = database_with_session();
        let modificato = vecchio(&mut database, sessione, fonte, "m-modificato");
        versione(&database, modificato, 1);
        vecchio(&mut database, sessione, fonte, "m-semplice");
        let Ok(_) = database.apply_retention_prova(politica(30), 1_000 * GIORNO) else {
            panic!("la conservazione deve riuscire");
        };
        let Ok(dettaglio) = database.connection.query_row(
            "SELECT detail FROM audit WHERE action = 'conservazione_applicata'",
            [],
            |row| row.get::<_, String>(0),
        ) else {
            panic!("la traccia della conservazione deve esserci");
        };
        assert!(dettaglio.contains("tolti 1 contenuti"), "{dettaglio}");
        assert!(
            dettaglio.contains("trattenuti 1 per preservare la storia"),
            "{dettaglio}"
        );
    }

    /// **Un errore a metà non toglie niente.** Un trigger di prova fa fallire
    /// la cancellazione dei contenuti: il contenuto, le sue righe e l'audit
    /// restano com'erano.
    #[test]
    fn un_errore_a_meta_annulla_tutto_e_non_perde_nulla() {
        let (mut database, fonte, sessione) = database_with_session();
        vecchio(&mut database, sessione, fonte, "m-semplice");
        let Ok(()) = database.connection.execute_batch(
            "CREATE TEMP TRIGGER guasto_di_prova BEFORE DELETE ON contents
             BEGIN SELECT RAISE(ABORT, 'guasto di prova'); END;",
        ) else {
            panic!("il guasto di prova deve potersi installare");
        };
        let audit_prima = conta(&database, "SELECT count(*) FROM audit");

        assert!(
            database
                .apply_retention_prova(politica(30), 1_000 * GIORNO)
                .is_err()
        );
        assert_eq!(conta(&database, "SELECT count(*) FROM contents"), 1);
        assert_eq!(conta(&database, "SELECT count(*) FROM audit"), audit_prima);
    }

    /// **Nessuna istruzione cancella una storia** (ADR-0133). La guardia legge
    /// il codice di produzione di questo modulo: il giorno in cui qualcuno
    /// rimettesse `content_versions` fra le tabelle da sgombrare, diventa
    /// rossa prima che il trigger lo fermi in un ufficio.
    #[test]
    fn nessuna_istruzione_cancella_versioni_o_fotografie() {
        const QUESTO_MODULO: &str = include_str!("retention.rs");
        let Some((produzione, _)) = QUESTO_MODULO.split_once("#[cfg(test)]") else {
            panic!("il modulo deve avere una parte di produzione");
        };
        assert!(
            produzione.contains("DELETE FROM"),
            "la guardia non ha letto nulla"
        );
        let Some((_, sgombero)) = produzione.split_once("for tabella in [") else {
            panic!("l'elenco delle tabelle da sgombrare deve esistere");
        };
        let elenco = sgombero.split(']').next().unwrap_or_default();
        let Some((_, selezione)) = produzione.split_once("const DA_TOGLIERE: &str =") else {
            panic!("la selezione dei contenuti da togliere deve esistere");
        };
        let selezione = selezione.split(';').next().unwrap_or_default();
        for storia in [
            "content_versions",
            "context_snapshots",
            "attachment_keepings",
        ] {
            assert!(
                !elenco.contains(storia),
                "la conservazione sgombra «{storia}», che è in sola aggiunta"
            );
            assert!(
                !produzione.contains(&format!("DELETE FROM {storia}")),
                "la conservazione cancella da «{storia}»"
            );
            assert!(
                selezione.contains(&format!("NOT IN (SELECT content_id FROM {storia})")),
                "la selezione da togliere non esclude chi ha una riga in «{storia}»"
            );
        }
    }
}
