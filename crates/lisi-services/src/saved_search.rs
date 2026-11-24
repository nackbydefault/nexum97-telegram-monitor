//! Salvare una ricerca, e rifarla sapendo che cosa si è mosso (SEARCH-01).
//!
//! # Una sola nozione di ricerca
//!
//! Cercare nello storico esiste da prima di questa milestone: è
//! [`HistoryFilter`], applicato a un [`HistoryScope`]. Qui non se ne costruisce
//! un secondo — si **converte** ciò che è stato salvato in quel filtro, e si
//! chiama la ricerca che c'era già.
//!
//! Una guardia conta i campi delle due parti: **un campo di filtro che non si
//! potesse salvare sarebbe una ricerca che non si può rifare**, e nessuno se ne
//! accorgerebbe finché qualcuno non la rifà.
//!
//! # Rifare una ricerca non riproduce il risultato
//!
//! È il fatto centrale, e questo servizio lo **dice** invece di lasciarlo
//! scoprire.
//!
//! I livelli non si ricalcolano a ogni lettura: sono stati prodotti
//! dall'analisi al momento dell'acquisizione, da una versione del motore. Se
//! quella versione cambia, una ricerca «livello almeno 3» rifatta oggi mette
//! insieme righe valutate da metri diversi.
//!
//! Perciò rieseguire restituisce le righe **e** un [`EngineDrift`]: quante sono
//! state valutate da una versione diversa da quella in forza al salvataggio, e
//! quante **non registrano affatto** quale motore le abbia valutate — che non è
//! «uguale», è **non misurato** (ADR-0053).
//!
//! # Che cosa non si conserva
//!
//! I risultati. Solo la domanda. Conservarli darebbe una fotografia che
//! invecchia e che, riaperta, sembrerebbe attuale.

use lisi_core::model::audit::NewAuditEntry;
use lisi_core::model::saved_search::{
    EngineDrift, NewSavedSearch, SavedQuery, SavedSearch, engine_in_force,
};
use lisi_core::text::{Actor, AuditAction, AuditDetail, AuditEntity};
use lisi_core::{SavedSearchId, Timestamp};
use lisi_storage::Database;

use crate::error::{ServiceError, ServiceResult};
use crate::history::{HistoryEntry, HistoryFilter, HistoryScope, HistoryService};

/// Ciò che una riesecuzione produce: le righe, **e come vanno lette**.
///
/// # Perché i due valori stanno insieme
///
/// Perché un elenco senza il confronto si legge come «ecco che cosa quella
/// ricerca trova», e non è vero: è che cosa trova **adesso**, con metri che
/// possono non essere quelli di allora. Separarli permetterebbe di mostrare
/// l'uno senza l'altro, ed è esattamente ciò che succederebbe.
#[derive(Debug, Clone)]
pub struct SearchRun {
    /// La ricerca rieseguita.
    pub search: SavedSearch,
    /// Le righe trovate **adesso**.
    pub entries: Vec<HistoryEntry>,
    /// Che cosa è cambiato fra il motore di allora e quello di adesso.
    pub drift: EngineDrift,
}

/// Servizio delle ricerche salvate.
#[derive(Debug)]
pub struct SavedSearchService {
    database: Database,
}

impl SavedSearchService {
    /// Costruisce il servizio sull'archivio indicato.
    #[must_use]
    pub const fn new(database: Database) -> Self {
        Self { database }
    }

    /// L'archivio, in sola lettura.
    #[must_use]
    pub const fn database(&self) -> &Database {
        &self.database
    }

    /// Restituisce l'archivio al chiamante.
    #[must_use]
    pub fn into_database(self) -> Database {
        self.database
    }

    /// Il filtro dello Storico che corrisponde a una ricerca salvata.
    ///
    /// # Perché una conversione e non un secondo filtro
    ///
    /// Perché la ricerca è **una**. Questa funzione è il solo punto in cui ciò
    /// che è stato salvato ridiventa la domanda che lo Storico sa porre, e una
    /// guardia verifica che i campi delle due parti siano tanti quanti.
    #[must_use]
    pub fn filter_of(query: &SavedQuery) -> HistoryFilter {
        HistoryFilter {
            query: query.query.clone(),
            minimum_level: query.minimum_level,
            only_pending: query.only_pending,
        }
    }

    /// L'ambito di una ricerca salvata.
    #[must_use]
    pub fn scope_of(query: &SavedQuery) -> HistoryScope {
        match query.session {
            Some(session) => HistoryScope::Session(session),
            None => HistoryScope::Everything,
        }
    }

    /// Salva una ricerca, **con la configurazione in forza adesso**.
    ///
    /// # Errori
    ///
    /// Restituisce [`ServiceError::SavedSearchNameTaken`] se una ricerca con
    /// quel nome esiste già.
    pub fn save(&self, search: &NewSavedSearch, now: Timestamp) -> ServiceResult<SavedSearchId> {
        // LA CONFIGURAZIONE LA LEGGE IL SERVIZIO, non il chiamante.
        //
        // Farla passare da fuori permetterebbe di registrarne una diversa da
        // quella che sta davvero girando, e nessuno se ne accorgerebbe.
        let id = self
            .database
            .insert_saved_search(search, engine_in_force(), now)
            .map_err(|errore| Self::nome_gia_preso(errore, search))?;

        self.database.append_audit(&NewAuditEntry {
            actor: search.created_by().clone(),
            action: AuditAction::try_new("ricerca_salvata")?,
            entity: AuditEntity::try_new("saved_search")?,
            entity_id: Some(id.get()),
            actor_mode: None,
            detail: Some(AuditDetail::try_new(search.name().as_str())?),
            recorded_at: now,
        })?;

        Ok(id)
    }

    /// Traduce il rifiuto del nome duplicato in una frase che dice perché.
    fn nome_gia_preso(errore: lisi_storage::StorageError, search: &NewSavedSearch) -> ServiceError {
        if matches!(errore, lisi_storage::StorageError::Sqlite(_)) {
            return ServiceError::SavedSearchNameTaken {
                name: search.name().as_str().to_owned(),
            };
        }
        ServiceError::Storage(errore)
    }

    /// Le ricerche salvate, in ordine di nome.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se la lettura non riesce.
    pub fn all(&self) -> ServiceResult<Vec<SavedSearch>> {
        Ok(self.database.saved_searches()?)
    }

    /// Cancella una ricerca salvata.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se non c'era.
    pub fn delete(
        &self,
        id: SavedSearchId,
        removed_by: &Actor,
        now: Timestamp,
    ) -> ServiceResult<()> {
        self.database.delete_saved_search(id)?;

        self.database.append_audit(&NewAuditEntry {
            actor: removed_by.clone(),
            action: AuditAction::try_new("ricerca_cancellata")?,
            entity: AuditEntity::try_new("saved_search")?,
            entity_id: Some(id.get()),
            actor_mode: None,
            detail: None,
            recorded_at: now,
        })?;

        Ok(())
    }

    /// Riesegue una ricerca salvata, **e dice come vanno lette le righe**.
    ///
    /// # Che cosa questa funzione non promette
    ///
    /// Di riprodurre il risultato di allora. Non lo riprodurrebbe comunque —
    /// è arrivato materiale nuovo, altro è stato modificato o cancellato, e le
    /// decisioni delle persone sono cambiate. Ciò che questa funzione aggiunge
    /// è la parte che **nessuno vedrebbe da sé**: che i livelli confrontati
    /// possono essere stati prodotti da motori diversi.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se la ricerca non esiste o se la lettura non
    /// riesce.
    pub fn run(&self, id: SavedSearchId, history: &HistoryService) -> ServiceResult<SearchRun> {
        let search = self.database.saved_search(id)?;

        // LA RICERCA E' QUELLA CHE C'ERA GIA'.
        let filter = Self::filter_of(&search.query);
        let scope = Self::scope_of(&search.query);
        let entries = history.matching(scope, &filter)?;

        // IL CONTEGGIO LO FA IL DOMINIO, e non questo modulo.
        //
        // Non e' un riordino: qui il caso **non si puo' costruire in una
        // prova**. Ogni contenuto viene inserito con la versione del motore che
        // sta girando, quindi una prova che passi di qui vede sempre zero e
        // resta verde qualunque cosa il conteggio faccia — l'ha dimostrato un
        // controllo negativo. Nel dominio il conteggio prende dei numeri, e i
        // numeri si possono scrivere.
        let drift = EngineDrift::between(
            search.engine_version,
            engine_in_force(),
            entries.iter().map(|entry| entry.content.engine_version),
        );

        Ok(SearchRun {
            drift,
            search,
            entries,
        })
    }
}

#[cfg(test)]
mod tests {
    use lisi_core::Timestamp;
    use lisi_core::model::saved_search::{NewSavedSearch, SavedQuery};
    use lisi_core::text::{Actor, DisplayName};

    use super::SavedSearchService;
    use crate::error::ServiceError;
    use crate::history::HistoryService;

    /// Questo modulo, per le guardie strutturali.
    const THIS_MODULE: &str = include_str!("saved_search.rs");

    /// Il modulo dello Storico, dove vive l'unica nozione di ricerca.
    const HISTORY_MODULE: &str = include_str!("history.rs");

    const ORA: i64 = 1_700_000_000_000;

    fn istante(millis: i64) -> Timestamp {
        Timestamp::from_millis(millis)
    }

    fn attore() -> Actor {
        let Ok(attore) = Actor::try_new("operatore.prova") else {
            panic!("l'attore di prova deve essere valido");
        };
        attore
    }

    fn servizio() -> SavedSearchService {
        let Ok(database) = crate::sources::open_in_memory_database() else {
            panic!("il database in memoria deve potersi aprire");
        };
        SavedSearchService::new(database)
    }

    fn ricerca(etichetta: &str, testo: &str, livello: u8) -> NewSavedSearch {
        let Ok(nome) = DisplayName::try_new(etichetta) else {
            panic!("il nome di prova deve essere valido");
        };
        let Ok(ricerca) = NewSavedSearch::of(
            nome,
            SavedQuery {
                query: String::from(testo),
                minimum_level: livello,
                only_pending: false,
                session: None,
            },
            attore(),
        ) else {
            panic!("la ricerca di prova deve essere valida");
        };
        ricerca
    }

    /// I campi dichiarati da una struttura, dato il modulo e l'intestazione.
    fn campi_di(modulo: &str, intestazione: &str) -> Vec<String> {
        let Some((produzione, _)) = modulo.split_once("#[cfg(test)]\nmod tests {") else {
            panic!("il modulo deve avere un blocco di prove riconoscibile");
        };
        let Some(inizio) = produzione.find(intestazione) else {
            panic!("«{intestazione}» deve esistere");
        };
        let corpo = &produzione[inizio + intestazione.len()..];
        let Some(fine) = corpo.find("\n}\n") else {
            panic!("«{intestazione}» deve chiudersi");
        };
        corpo[..fine]
            .lines()
            .map(str::trim)
            .filter(|riga| {
                riga.contains(':') && !riga.starts_with("///") && !riga.starts_with("//")
            })
            .map(|riga| {
                riga.split(':')
                    .next()
                    .unwrap_or_default()
                    .replace("pub ", "")
                    .trim()
                    .to_owned()
            })
            .collect()
    }

    /// **Ogni campo del filtro si può salvare.**
    ///
    /// # Il difetto che questa prova impedisce
    ///
    /// Un campo aggiunto al filtro dello Storico e non alla ricerca salvata.
    /// Da quel momento salvare una ricerca ne conserverebbe **una parte**, e
    /// rifarla darebbe risultati diversi da quelli che si vedevano quando la si
    /// è salvata — senza che nulla lo dica, perché la ricerca sembrerebbe la
    /// stessa.
    ///
    /// È il rischio che NOTE-01 aveva dichiarato aprendo questa milestone:
    /// «costruire qui una ricerca sarebbe la seconda nozione di ricerca del
    /// prodotto». Una nozione sola, e questa guardia la tiene tale.
    #[test]
    fn ogni_campo_del_filtro_si_puo_salvare() {
        let del_filtro = campi_di(HISTORY_MODULE, "pub struct HistoryFilter {");
        let salvati = campi_di(
            include_str!("../../lisi-core/src/model/saved_search.rs"),
            "pub struct SavedQuery {",
        );

        for campo in &del_filtro {
            assert!(
                salvati.contains(campo),
                "il filtro ha «{campo}» e la ricerca salvata no: salvarla ne conserverebbe una \
                 parte, e rifarla darebbe altro \u{2014} filtro {del_filtro:?}, salvati {salvati:?}"
            );
        }

        // E LA RICERCA SALVATA NE HA UNO IN PIU', L'AMBITO: e' l'unica
        // differenza ammessa, perche' l'ambito nello Storico non sta nel filtro
        // ma accanto. Se un giorno ne comparisse un altro, questa riga lo dice.
        assert_eq!(
            salvati.len(),
            del_filtro.len() + 1,
            "la ricerca salvata conserva i campi del filtro piu' l'ambito, e nient'altro \
             \u{2014} filtro {del_filtro:?}, salvati {salvati:?}"
        );
    }

    /// **Si salva, si rilegge, si cancella.**
    #[test]
    fn si_salva_si_rilegge_e_si_cancella() {
        let servizio = servizio();
        let Ok(id) = servizio.save(&ricerca("Droga di marzo", "droga", 3), istante(ORA)) else {
            panic!("la ricerca deve potersi salvare");
        };

        let Ok(elenco) = servizio.all() else {
            panic!("la lettura deve riuscire");
        };
        assert_eq!(elenco.len(), 1);
        assert_eq!(
            elenco[0].engine_version,
            lisi_core::analysis::ENGINE_VERSION
        );

        let Ok(()) = servizio.delete(id, &attore(), istante(ORA + 100)) else {
            panic!("la cancellazione deve riuscire");
        };
        let Ok(dopo) = servizio.all() else {
            panic!("la lettura deve riuscire");
        };
        assert!(dopo.is_empty());
    }

    /// **Due ricerche omonime producono una frase che nomina.**
    #[test]
    fn due_ricerche_omonime_producono_una_frase_che_nomina() {
        let servizio = servizio();
        let Ok(_) = servizio.save(&ricerca("Droga", "droga", 0), istante(ORA)) else {
            panic!("la prima deve potersi salvare");
        };

        let esito = servizio.save(&ricerca("Droga", "altro", 0), istante(ORA + 1));
        let Err(ServiceError::SavedSearchNameTaken { name }) = esito else {
            panic!("la seconda deve essere rifiutata");
        };
        assert_eq!(name, "Droga");

        let frase = ServiceError::SavedSearchNameTaken {
            name: String::from("Droga"),
        }
        .operator_message();
        assert!(frase.contains("Droga"), "{frase}");
    }

    /// **Rieseguire dichiara che cosa si è mosso.**
    ///
    /// # Che cosa questa prova sorveglia
    ///
    /// Che la riesecuzione non restituisca soltanto le righe. Un elenco senza
    /// il confronto si legge come «ecco che cosa quella ricerca trova», e non è
    /// vero: è che cosa trova **adesso**, con metri che possono non essere
    /// quelli di allora.
    #[test]
    fn rieseguire_dichiara_che_cosa_si_e_mosso() {
        let servizio = servizio();
        let Ok(id) = servizio.save(&ricerca("Droga", "droga", 0), istante(ORA)) else {
            panic!("la ricerca deve potersi salvare");
        };

        let Ok(database) = crate::sources::open_in_memory_database() else {
            panic!("il database in memoria deve potersi aprire");
        };
        let storico = HistoryService::new(database);

        let Ok(esecuzione) = servizio.run(id, &storico) else {
            panic!("la riesecuzione deve riuscire");
        };
        assert_eq!(
            esecuzione.drift.at_save,
            lisi_core::analysis::ENGINE_VERSION
        );
        assert_eq!(esecuzione.drift.now, lisi_core::analysis::ENGINE_VERSION);
        assert_eq!(esecuzione.drift.total, esecuzione.entries.len());
        assert_eq!(esecuzione.search.name.as_str(), "Droga");
    }

    /// **Ogni atto lascia traccia nell'audit.**
    #[test]
    fn ogni_atto_lascia_traccia() {
        let servizio = servizio();
        let Ok(id) = servizio.save(&ricerca("Droga", "droga", 0), istante(ORA)) else {
            panic!("la ricerca deve potersi salvare");
        };
        let Ok(()) = servizio.delete(id, &attore(), istante(ORA + 100)) else {
            panic!("la cancellazione deve riuscire");
        };

        let Ok(voci) = servizio.database().audit_entries() else {
            panic!("l'audit deve potersi leggere");
        };
        for azione in ["ricerca_salvata", "ricerca_cancellata"] {
            assert!(
                voci.iter().any(|voce| voce.action.as_str() == azione),
                "l'azione «{azione}» deve comparire nell'audit"
            );
        }
    }

    /// **La configurazione la legge il servizio, non il chiamante.**
    ///
    /// # Il difetto che questa prova impedisce
    ///
    /// Una versione del motore passata da fuori, e quindi diversa da quella che
    /// sta davvero girando. Nessuno se ne accorgerebbe: il confronto direbbe
    /// «stesso motore» confrontando un numero inventato con sé stesso.
    #[test]
    fn la_configurazione_la_legge_il_servizio() {
        let Some((produzione, _)) = THIS_MODULE.split_once("#[cfg(test)]\nmod tests {") else {
            panic!("il modulo deve avere un blocco di prove riconoscibile");
        };
        let Some(inizio) = produzione.find("pub fn save(") else {
            panic!("la funzione deve esistere");
        };
        let Some(fine) = produzione[inizio..].find("\n    }\n") else {
            panic!("la funzione deve chiudersi");
        };
        let firma_e_corpo = &produzione[inizio..inizio + fine];

        assert!(
            firma_e_corpo.contains("engine_in_force()"),
            "la versione si legge da chi sta girando"
        );
        assert!(
            !firma_e_corpo.contains("engine_version:"),
            "la versione non entra come parametro: sarebbe registrabile diversa da quella vera"
        );
    }

    /// **Il servizio non conserva i risultati.**
    #[test]
    fn il_servizio_non_conserva_i_risultati() {
        let campi = campi_di(THIS_MODULE, "pub struct SavedSearchService {");
        assert_eq!(
            campi.len(),
            1,
            "il servizio ha un campo solo, l'archivio \u{2014} {campi:?}"
        );
    }
}
