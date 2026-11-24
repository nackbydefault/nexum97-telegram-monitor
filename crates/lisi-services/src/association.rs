//! Le associazioni di chi è stato osservato, con la loro provenienza (PERS-03).
//!
//! # Serve la stessa ragione degli elenchi di persone
//!
//! Un elenco di ciò a cui una persona risulta collegata **è** un elenco di
//! persone guardato più da vicino: dice che una certa persona ha scritto in certe
//! fonti, che i suoi contenuti hanno alzato certi alert, che portano certi
//! indicatori. Chi lo tira fuori risponde di averlo fatto.
//!
//! Vale quindi la ragione di ADR-0024, e **la stessa**, per il motivo già scritto
//! in PERS-02: registrarne una specifica per le associazioni farebbe credere che
//! due autorizzazioni diverse esistano dove ce n'è una, e chi ne avesse motivata
//! una sola si troverebbe una funzione bloccata senza capire quale frase manchi.
//!
//! # Che cosa non costruisce
//!
//! Una tabella. Le associazioni **si ricavano** da fatti che l'archivio ha già —
//! chi ha scritto che cosa, da quale fonte, con quale alert, con quali indicatori,
//! dentro quali workspace — e quei fatti non cambiano. Una copia sarebbe una
//! seconda verità che può divergere, e PERS-02 ha già preso questa decisione per
//! la storia degli alias. **PERS-03 non ha una migrazione.**
//!
//! # E non collega niente a un fascicolo
//!
//! Il collegamento fra un'identità osservata e un soggetto è **PERS-06**, ed è
//! manuale, con operatore, motivo, istante e audit. Questo servizio non nomina
//! `PersonId`, e una guardia lo verifica: senza di essa, chi apre un fascicolo si
//! troverebbe collegate cose che nessuno ha deciso di collegare.

use lisi_core::SessionId;
use lisi_core::model::association::{
    AssociationFacts, AssociationTarget, PersonAssociation, associations_for,
};
use lisi_storage::Database;

use crate::error::{ServiceError, ServiceResult};

/// Servizio delle associazioni osservate.
#[derive(Debug)]
pub struct AssociationService {
    database: Database,
}

impl AssociationService {
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

    /// Le associazioni osservate durante una sessione, con la loro provenienza.
    ///
    /// # Errori
    ///
    /// Restituisce [`ServiceError::MissingParticipantBasis`] se nessuna ragione è
    /// stata registrata: un elenco di associazioni **non si produce** prima, per
    /// la stessa ragione per cui non si produce un elenco di persone.
    ///
    /// Restituisce un errore se l'archivio non è leggibile.
    pub fn for_session(&self, session_id: SessionId) -> ServiceResult<Vec<PersonAssociation>> {
        // LA RAGIONE E' QUELLA DEGLI ELENCHI DI PERSONE, non una seconda.
        if !self.basis_recorded()? {
            return Err(ServiceError::MissingParticipantBasis);
        }

        let contents = self.database.session_contents(session_id)?;

        let mut fatti: Vec<AssociationFacts> = Vec::new();
        for content in &contents {
            // I MESSAGGI DI CANALE NON HANNO UN AUTORE INDIVIDUALE.
            //
            // Attribuirli a qualcuno significherebbe attribuire a una persona
            // cio' che una persona non ha scritto: e' la scelta di PERS-02, e
            // vale qui a maggior ragione, perche' qui si costruiscono legami.
            let Some(identifier) = content.author_identifier.clone() else {
                continue;
            };

            // SI RACCOLGONO I FATTI, NON IL CONTENUTO.
            //
            // Alla derivazione non serve il testo del messaggio, e una funzione
            // che non lo riceve non puo' usarlo.
            let alert = self.database.content_alert(content.id)?.map(|a| a.id);
            let indicators = self
                .database
                .content_indicators(content.id)?
                .into_iter()
                .map(|indicatore| (indicatore.kind, indicatore.value))
                .collect();
            let workspaces = self.database.workspaces_holding_content(content.id)?;

            fatti.push(AssociationFacts {
                content: content.id,
                identifier,
                source: content.source_id,
                at: content.published_at,
                alert,
                indicators,
                workspaces,
            });
        }

        Ok(associations_for(&fatti))
    }

    /// Le associazioni di **una sola** identità osservata, durante una sessione.
    ///
    /// # Perché filtra qui invece di interrogare l'archivio
    ///
    /// Perché il filtro per autore è una selezione su un elenco già costruito, e
    /// costruirne una seconda strada verso l'archivio significherebbe due letture
    /// che il giorno in cui una cambia divergono. La sessione è l'unità in cui il
    /// prodotto ragiona, ed è già il confine della lettura.
    ///
    /// # Errori
    ///
    /// Gli stessi di [`Self::for_session`].
    pub fn for_identity(
        &self,
        session_id: SessionId,
        identifier: &str,
    ) -> ServiceResult<Vec<PersonAssociation>> {
        let tutte = self.for_session(session_id)?;
        Ok(tutte
            .into_iter()
            .filter(|associazione| associazione.identifier() == identifier)
            .collect())
    }

    /// Quante cose distinte, per genere, risultano associate a un'identità.
    ///
    /// # Perché un conteggio per genere non è un punteggio
    ///
    /// Perché non è **un** numero accanto a una persona: sono i conti di quanti
    /// contenuti, quante fonti, quanti alert — cioè quante righe ci sono da
    /// leggere in ciascuna sezione, che è la stessa cosa che si vedrebbe
    /// scorrendole.
    ///
    /// Un punteggio è un numero che **sostituisce** la lettura e ordina le
    /// persone; questo la annuncia soltanto. Per questo non esiste un totale
    /// unico, che sarebbe indistinguibile da un punteggio: chi lo volesse deve
    /// sommarlo da sé, e sapendo che cosa sta sommando.
    ///
    /// # Errori
    ///
    /// Gli stessi di [`Self::for_session`].
    pub fn counts_by_kind(
        &self,
        session_id: SessionId,
        identifier: &str,
    ) -> ServiceResult<Vec<(&'static str, usize)>> {
        let associazioni = self.for_identity(session_id, identifier)?;

        let mut conti: Vec<(&'static str, usize)> = Vec::new();
        for etichetta in ["Contenuto", "Fonte", "Alert", "Indicatore", "Raccoglitore"] {
            let quante = associazioni
                .iter()
                .filter(|a| a.target().kind_label() == etichetta)
                .count();
            // LE SEZIONI VUOTE NON SI ANNUNCIANO.
            //
            // «Alert: 0» sotto ogni persona sarebbe rumore, e il rumore fa
            // smettere di leggere anche cio' che conta. E' la lezione di PERS-02.
            if quante > 0 {
                conti.push((etichetta, quante));
            }
        }
        Ok(conti)
    }

    /// Se una ragione è già stata registrata.
    ///
    /// # Perché legge l'audit e non un'impostazione
    ///
    /// Perché la ragione **è** una voce di audit: sta dove nessuno la può
    /// cambiare senza lasciare traccia. È la stessa lettura che fanno il servizio
    /// dei partecipanti e quello delle identità osservate, e la stessa voce.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se l'audit non è leggibile.
    pub fn basis_recorded(&self) -> ServiceResult<bool> {
        Ok(self.database.operational_basis_recorded()?)
    }
}

/// Le associazioni di un genere, raggruppate per la lettura.
///
/// # Perché esiste
///
/// Perché un elenco piatto di contenuti, fonti, alert, indicatori e workspace
/// mescolati non si legge: chi guarda vuole sapere «in quali fonti ha scritto»,
/// non scorrere trenta righe di generi diversi cercando le fonti.
#[must_use]
pub fn group_by_kind(
    associations: &[PersonAssociation],
) -> Vec<(&'static str, Vec<&PersonAssociation>)> {
    let mut gruppi: Vec<(&'static str, Vec<&PersonAssociation>)> = Vec::new();
    // ORDINE DICHIARATO, non quello in cui capitano.
    //
    // Il contenuto viene per primo perche' e' il fatto da cui tutti gli altri
    // discendono; il workspace per ultimo perche' e' l'unico che dipende da un
    // gesto dell'operatore invece che dall'osservazione.
    for etichetta in ["Contenuto", "Fonte", "Alert", "Indicatore", "Raccoglitore"] {
        let righe: Vec<&PersonAssociation> = associations
            .iter()
            .filter(|a| a.target().kind_label() == etichetta)
            .collect();
        if !righe.is_empty() {
            gruppi.push((etichetta, righe));
        }
    }
    gruppi
}

/// Come si nomina, a chi legge, la cosa associata.
#[must_use]
pub fn target_label(target: &AssociationTarget) -> String {
    match target {
        AssociationTarget::Content(id) => format!("Contenuto #{}", id.get()),
        AssociationTarget::Source(id) => format!("Fonte #{}", id.get()),
        AssociationTarget::Alert(id) => format!("Avviso #{}", id.get()),
        AssociationTarget::Workspace(id) => format!("Raccoglitore #{}", id.get()),
        AssociationTarget::Indicator { kind, value } => {
            format!("{}: {value}", kind.label())
        }
    }
}

#[cfg(test)]
mod tests {
    use lisi_core::model::association::{AssociationRule, AssociationTarget};
    use lisi_core::model::indicator::IndicatorKind;
    use lisi_core::model::{
        AcquisitionOrigin, AnalysisLevel, NewAuditEntry, NewContent, NewSession, NewSource,
        SessionDuration, SourceKind,
    };
    use lisi_core::text::{
        Actor, AuditAction, AuditDetail, AuditEntity, ContentBody, DisplayName, RemoteMessageId,
        SourceIdentifier,
    };
    use lisi_core::{SessionId, Timestamp};
    use lisi_storage::Database;

    use super::{AssociationService, group_by_kind, target_label};
    use crate::error::ServiceError;
    use crate::sources::open_in_memory_database;

    const ORA: i64 = 1_760_000_000_000;

    /// L'operatore delle prove.
    fn operatore() -> Actor {
        let Ok(attore) = Actor::try_new("operatore.prova") else {
            panic!("l'attore deve essere valido");
        };
        attore
    }

    /// Un servizio su un archivio con una sessione e un contenuto scritto.
    fn servizio_con_un_contenuto() -> (AssociationService, SessionId) {
        let Ok(database) = open_in_memory_database() else {
            panic!("il database in memoria deve potersi aprire");
        };
        let mut database: Database = database;
        let ora = Timestamp::from_millis(ORA);

        let (Ok(identificativo), Ok(titolo), Ok(etichetta)) = (
            SourceIdentifier::try_new("canale_uno"),
            DisplayName::try_new("Canale di prova"),
            DisplayName::try_new("Sessione di prova"),
        ) else {
            panic!("i valori di prova devono essere validi");
        };

        let Ok(source_id) = database.insert_source(
            &NewSource {
                kind: SourceKind::Channel,
                identifier: identificativo,
                display_name: titolo,
                authorized_by: operatore(),
                active: true,
            },
            ora,
        ) else {
            panic!("la fonte deve potersi registrare");
        };

        let Ok(session_id) = database.insert_session(
            &NewSession {
                label: etichetta,
                started_by: operatore(),
                duration: SessionDuration::Preset { seconds: 3_600 },
                source_ids: vec![source_id],
            },
            ora,
        ) else {
            panic!("la sessione deve potersi creare");
        };

        let (Ok(remoto), Ok(corpo), Ok(livello)) = (
            RemoteMessageId::try_new("900"),
            ContentBody::try_new("un testo qualunque"),
            AnalysisLevel::try_new(1),
        ) else {
            panic!("i valori del contenuto devono essere validi");
        };

        let Ok(_) = database.insert_content(&NewContent {
            session_id,
            source_id,
            remote_message_id: remoto,
            author: None,
            // CHI LO HA SCRITTO: e' il fatto da cui tutto discende.
            author_identifier: Some("111".to_owned()),
            author_username: None,
            body: corpo,
            url: None,
            published_at: ora,
            acquired_at: ora,
            origin: AcquisitionOrigin::Observed,
            analysis_level: livello,
        }) else {
            panic!("il contenuto deve potersi registrare");
        };

        (AssociationService::new(database), session_id)
    }

    /// Registra la ragione degli elenchi di persone (ADR-0024).
    ///
    /// # Perché la scrivono le prove e non il servizio
    ///
    /// Perché il servizio delle associazioni **legge** soltanto: la ragione la
    /// scrive il comando dedicato dei partecipanti, e ne basta una per tutte le
    /// funzioni che producono elenchi di persone.
    fn registra_la_ragione(servizio: &AssociationService) {
        let (Ok(azione), Ok(entita), Ok(dettaglio)) = (
            AuditAction::try_new("elenco_persone_motivato"),
            AuditEntity::try_new("session"),
            AuditDetail::try_new("verifica autorizzata di una fonte d'ufficio"),
        ) else {
            panic!("i valori dell'audit devono essere validi");
        };
        let Ok(_) = servizio.database().append_audit(&NewAuditEntry {
            actor: operatore(),
            action: azione,
            entity: entita,
            entity_id: None,
            actor_mode: None,
            detail: Some(dettaglio),
            recorded_at: Timestamp::from_millis(ORA),
        }) else {
            panic!("la ragione deve potersi registrare");
        };
    }

    /// **Un elenco di associazioni non si produce senza una ragione.**
    #[test]
    fn le_associazioni_non_si_producono_senza_una_ragione() {
        let (servizio, session_id) = servizio_con_un_contenuto();

        let esito = servizio.for_session(session_id);
        assert!(
            matches!(esito, Err(ServiceError::MissingParticipantBasis)),
            "senza ragione registrata non si produce nulla"
        );

        registra_la_ragione(&servizio);
        let Ok(associazioni) = servizio.for_session(session_id) else {
            panic!("con la ragione registrata deve riuscire");
        };
        assert!(!associazioni.is_empty(), "ora c'e' qualcosa");
    }

    /// **È la stessa ragione degli elenchi di persone, non una seconda.**
    ///
    /// # Perché conta
    ///
    /// Perché due autorizzazioni dove ce n'è una bloccherebbero una funzione
    /// senza che chi la usa capisca quale frase manchi.
    #[test]
    fn e_la_stessa_ragione_degli_elenchi_di_persone() {
        let codice = codice_senza_commenti();
        // LA DOMANDA SI PONE ATTRAVERSO L'UNICA DEFINIZIONE.
        //
        // Prima di HARDEN-04 questa guardia verificava che il modulo NOMINASSE
        // la voce d'audit condivisa. Era la cosa giusta finche' ciascuno se la
        // scriveva: sei moduli, sei copie della stessa stringa.
        //
        // Ora la voce ha un nome solo, in `repository::audit`, e chiederla
        // significa chiamare `operational_basis_recorded`. La guardia e' stata
        // VISTA ROSSA e ristretta: verificare la chiamata e' piu' forte che
        // verificare la stringa, perche' un modulo che chiama non puo' nominare
        // una voce diversa nemmeno per distrazione (ADR-0113).
        assert!(
            codice.contains("operational_basis_recorded"),
            "il servizio deve porre la domanda attraverso l'unica definizione"
        );
        for seconda in [
            "elenco_associazioni_motivato",
            "associazioni_motivate",
            "elenco_legami_motivato",
        ] {
            assert!(
                !codice.contains(seconda),
                "«{seconda}» sarebbe una seconda autorizzazione dove ce n'e' una"
            );
        }
    }

    /// **Il servizio non collega un'identità a un soggetto.**
    ///
    /// # Perché identificatori veri e non frammenti
    ///
    /// Perché un divieto sulla stringa «person» sarebbe rosso su
    /// `elenco_persone_motivato`, che è la voce di audit condivisa e non c'entra
    /// nulla con i fascicoli. Una guardia rossa sulla cosa sbagliata viene tolta
    /// al primo fastidio.
    #[test]
    fn il_servizio_non_collega_una_identita_a_un_soggetto() {
        let codice = codice_senza_commenti();
        for collegamento in [
            "PersonId",
            "PersonService",
            "model::person",
            "NewPerson",
            "persons",
        ] {
            assert!(
                !codice.contains(collegamento),
                "il servizio nomina «{collegamento}»: l'associazione a un fascicolo e' PERS-06"
            );
        }
    }

    /// **Il servizio non scrive niente.**
    ///
    /// # Perché conta
    ///
    /// Perché ricavare associazioni è una **lettura**. Un servizio che scrivesse
    /// costruirebbe la copia che questa milestone esiste per non costruire.
    #[test]
    fn il_servizio_non_scrive_niente() {
        let codice = codice_senza_commenti();
        for scrittura in ["insert_", "update_", "delete_", "record_audit", "&mut self"] {
            assert!(
                !codice.contains(scrittura),
                "il servizio nomina «{scrittura}»: ricavare e' una lettura"
            );
        }
    }

    /// **Ogni associazione prodotta porta la sua provenienza.**
    #[test]
    fn ogni_associazione_prodotta_porta_la_provenienza() {
        let (servizio, session_id) = servizio_con_un_contenuto();
        registra_la_ragione(&servizio);

        let Ok(associazioni) = servizio.for_session(session_id) else {
            panic!("deve riuscire");
        };
        assert!(!associazioni.is_empty());

        for associazione in &associazioni {
            let provenienza = associazione.provenance();
            assert!(
                provenienza.content().get() > 0,
                "la provenienza nomina un contenuto vero"
            );
            assert!(
                provenienza.source().get() > 0,
                "la provenienza nomina una fonte vera"
            );
            let frase = provenienza.as_sentence();
            assert!(
                frase.contains("Osservato nel contenuto"),
                "la frase dice da dove viene: {frase}"
            );
        }
    }

    /// **Le frasi non attribuiscono, e non dicono che qualcuno «è» qualcosa.**
    ///
    /// # Perché è la guardia di questa milestone
    ///
    /// Perché un elenco di legami sotto il nome di una persona è esattamente il
    /// materiale con cui si scrive una frase che nessun fatto sostiene. Le regole
    /// dicono che **ha scritto** un contenuto, e che quel contenuto ha una
    /// proprietà: mai che la persona sia, appartenga o risulti pericolosa.
    #[test]
    fn le_frasi_non_attribuiscono() {
        for regola in [
            AssociationRule::AuthoredContent,
            AssociationRule::ContentFromSource,
            AssociationRule::ContentRaisedAlert,
            AssociationRule::ContentCarriesIndicator,
            AssociationRule::WorkspaceHoldsContent,
        ] {
            let frase = regola.as_sentence().to_lowercase();
            for vietata in [
                "pericolos",
                "sospett",
                "estremis",
                "radicaliz",
                "responsabil",
                "colpevol",
                "appartiene",
                "affiliat",
                "rischio",
            ] {
                assert!(
                    !frase.contains(vietata),
                    "la frase di «{}» dice «{vietata}»: attribuirebbe cio' che nessun fatto \
                     sostiene",
                    regola.as_str()
                );
            }
        }
    }

    /// **Non esiste un totale unico, che sarebbe un punteggio.**
    #[test]
    fn i_conteggi_sono_per_genere_e_non_c_e_un_totale() {
        let (servizio, session_id) = servizio_con_un_contenuto();
        registra_la_ragione(&servizio);

        let Ok(conti) = servizio.counts_by_kind(session_id, "111") else {
            panic!("deve riuscire");
        };
        assert!(!conti.is_empty(), "qualcosa c'e'");
        for (etichetta, quante) in &conti {
            assert!(*quante > 0, "«{etichetta}» vuoto non si annuncia");
        }

        let codice = codice_senza_commenti();
        for totale in ["fn total", "fn score", "fn punteggio", "fn overall"] {
            assert!(
                !codice.contains(totale),
                "«{totale}» sarebbe un numero unico accanto a una persona"
            );
        }
    }

    /// **Un'identità che non ha scritto non ha associazioni.**
    ///
    /// # Perché conta
    ///
    /// Perché il caso vuoto è quello ordinario, e una funzione che restituisse
    /// qualcosa per un identificativo mai visto costruirebbe un legame che nessun
    /// fatto sostiene.
    #[test]
    fn chi_non_ha_scritto_non_ha_associazioni() {
        let (servizio, session_id) = servizio_con_un_contenuto();
        registra_la_ragione(&servizio);

        let Ok(nessuna) = servizio.for_identity(session_id, "999") else {
            panic!("deve riuscire");
        };
        assert!(
            nessuna.is_empty(),
            "chi non ha scritto non risulta collegato a niente"
        );
    }

    /// **I gruppi si leggono in ordine dichiarato, e i vuoti non compaiono.**
    #[test]
    fn i_gruppi_seguono_un_ordine_dichiarato() {
        let (servizio, session_id) = servizio_con_un_contenuto();
        registra_la_ragione(&servizio);

        let Ok(associazioni) = servizio.for_identity(session_id, "111") else {
            panic!("deve riuscire");
        };
        let gruppi = group_by_kind(&associazioni);

        let etichette: Vec<&str> = gruppi.iter().map(|(e, _)| *e).collect();
        assert_eq!(
            etichette,
            vec!["Contenuto", "Fonte"],
            "senza alert, indicatori e workspace quei gruppi non compaiono"
        );
        for (_, righe) in &gruppi {
            assert!(!righe.is_empty(), "un gruppo vuoto non si mostra");
        }
    }

    /// **Un indicatore si nomina con genere e valore, non con un numero.**
    #[test]
    fn un_indicatore_si_nomina_con_genere_e_valore() {
        let etichetta = target_label(&AssociationTarget::Indicator {
            kind: IndicatorKind::Domain,
            value: "esempio.test".to_owned(),
        });
        assert!(
            etichetta.contains("esempio.test"),
            "il valore si legge: {etichetta}"
        );
        assert!(
            !etichetta.contains('#'),
            "un indicatore non ha un identificativo d'archivio: {etichetta}"
        );
    }

    /// Il codice di produzione di questo modulo, senza commenti.
    fn codice_senza_commenti() -> String {
        let sorgente = include_str!("association.rs");
        let Some(taglio) = sorgente.find("#[cfg(test)]") else {
            panic!("il modulo deve avere una sezione di prove");
        };
        sorgente[..taglio]
            .lines()
            .filter(|riga| {
                let pulita = riga.trim_start();
                !pulita.starts_with("//")
            })
            .collect::<Vec<_>>()
            .join("\n")
    }
}
