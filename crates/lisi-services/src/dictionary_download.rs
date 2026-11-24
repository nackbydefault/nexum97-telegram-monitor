//! Un dizionario dalla rete, soltanto firmato da chi l'ufficio ha scelto
//! (DICT-NET-01 parte 2, ADR-0178).
//!
//! # L'ordine non è casuale
//!
//! 1. **Prima di andare in rete:** una fonte configurata e almeno un
//!    firmatario ammesso. Con l'elenco vuoto ogni dizionario si rifiuterebbe:
//!    non si contatta nessuno per rifiutare ciò che arriva.
//! 2. **La rete:** il dizionario e la sua firma, allo stesso indirizzo con
//!    `.p7s` in fondo, dalla sola porta (`lisi_platform::https`), con i limiti
//!    chiusi di quella porta. Mai altro indirizzo: né da un contenuto
//!    monitorato, né dal dizionario stesso (ADR-0067).
//! 3. **La firma**, verificata da Windows (`detached_signature`), **prima** di
//!    interpretare un solo byte (decisione 8).
//! 4. **Chi ha firmato:** l'impronta SHA-256 del certificato deve essere fra
//!    quelle scritte dall'amministratore (decisione 4).
//! 5. **La stessa lettura dell'import da file**, con tutti i suoi rifiuti.
//! 6. **In bozza**, personale: un dizionario nuovo, o una versione nuova di
//!    quello già scaricato con lo stesso nome, soltanto se il numero è più
//!    alto (decisione 9).
//!
//! Ogni tentativo che arriva in rete lascia una riga nel registro e una
//! nell'audit, anche un rifiuto (decisione 10). I byte rifiutati non si
//! tengono: resta la loro impronta (decisione 11).
//!
//! # Che cosa non è ancora vero
//!
//! Il dizionario e la riga del registro si scrivono in due transazioni. Se la
//! seconda non riuscisse, il dizionario resterebbe in bozza senza la sua riga:
//! lo dice l'audit della creazione, e in bozza non vale per nessuno.

use lisi_core::model::NewAuditEntry;
use lisi_core::model::dictionary::{
    DictionaryOrigin, DictionaryVisibility, MAX_IMPORT_BYTES, NewDictionary,
};
use lisi_core::text::{Actor, AuditAction, AuditDetail, AuditEntity};
use lisi_core::{DictionaryId, DictionaryVersionId, RestrictedAction, Sha256Digest, Timestamp};
use lisi_platform::DetachedVerdict;
use lisi_platform::detached_signature;
use lisi_platform::https::{self, BodyLimit, Fetched};
use lisi_storage::repository::dictionary_download::NewDictionaryDownload;
pub use lisi_storage::repository::dictionary_download::StoredDictionaryDownload;

use crate::dictionaries::DictionaryService;
use crate::dictionary_io::parse;
use crate::error::{ServiceError, ServiceResult};

/// Quanti firmatari si possono ammettere (ADR-0178, decisione 4).
pub const MAX_DICTIONARY_SIGNERS: usize = 8;

/// Dove sta la firma: allo stesso indirizzo, con questo in fondo.
const SIGNATURE_SUFFIX: &str = ".p7s";

/// La verifica della firma separata.
///
/// In produzione è sempre [`detached_signature::verify_detached`]: le prove ne
/// passano una che dice l'esito che serve, perché un certificato attendibile
/// per la postazione non si fabbrica in una prova senza toccare l'archivio di
/// Windows.
pub(crate) type Verifier = fn(&[u8], &[u8]) -> DetachedVerdict;

/// Com'è andato uno scaricamento.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DictionaryDownloadOutcome {
    /// Il dizionario è entrato, in bozza.
    Entered {
        /// Il dizionario.
        dictionary_id: DictionaryId,
        /// La versione scritta.
        version_id: DictionaryVersionId,
        /// Il nome dichiarato.
        name: String,
        /// Il numero dichiarato.
        number: u32,
    },
    /// Il dizionario è arrivato e non è entrato. I byte non si tengono.
    Refused {
        /// Perché, in parole per l'operatore.
        reason: String,
    },
    /// La fonte non ha dato il dizionario o la firma.
    NotReached {
        /// Perché, in parole per l'operatore.
        reason: String,
    },
}

impl DictionaryDownloadOutcome {
    /// La frase per l'operatore.
    #[must_use]
    pub fn operator_message(&self) -> String {
        match self {
            Self::Entered { name, number, .. } => format!(
                "Il dizionario «{name}», versione {number}, è entrato in bozza. Va guardato \
                 e pubblicato da una persona."
            ),
            Self::Refused { reason } => {
                format!("Il dizionario scaricato non è entrato: {reason}. Non è stato tenuto.")
            }
            Self::NotReached { reason } => {
                format!("Il dizionario non è stato scaricato: {reason}.")
            }
        }
    }
}

impl DictionaryService {
    /// L'indirizzo da cui si scaricano i dizionari, se configurato.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se la lettura non riesce.
    pub fn dictionary_source(&self) -> ServiceResult<Option<String>> {
        Ok(self.database().dictionary_network_source()?)
    }

    /// Indica l'indirizzo, o lo svuota passando `None`.
    ///
    /// Nel registro finisce che la fonte è cambiata, non quale: come per
    /// l'origine degli aggiornamenti, la destinazione di oggi si legge dove è
    /// scritta.
    ///
    /// # Errori
    ///
    /// [`ServiceError::ActionReservedToAdministrator`] in modalità operatore,
    /// [`ServiceError::DictionarySourceRefused`] per un indirizzo non
    /// utilizzabile, o un errore se la scrittura non riesce.
    pub fn set_dictionary_source(
        &mut self,
        url: Option<&str>,
        actor: &Actor,
        now: Timestamp,
    ) -> ServiceResult<()> {
        self.require(RestrictedAction::ChooseDictionarySource)?;

        let url = url.map(str::trim).filter(|url| !url.is_empty());
        if let Some(url) = url {
            crate::update::check_url(url)
                .map_err(|reason| ServiceError::DictionarySourceRefused { reason })?;
            // La firma sta allo stesso indirizzo con `.p7s` in fondo: anche
            // quell'indirizzo deve stare nel limite della porta.
            if url.chars().count() + SIGNATURE_SUFFIX.len() > https::MAX_URL_CHARS {
                return Err(ServiceError::DictionarySourceRefused {
                    reason: String::from("è troppo lungo"),
                });
            }
        }

        let audit = self.audit_entry(
            actor,
            "fonte_dizionari_impostata",
            if url.is_some() {
                "indicata"
            } else {
                "svuotata"
            },
            now,
        )?;
        self.database_mut()
            .save_dictionary_network_source(url, actor, &audit)?;
        Ok(())
    }

    /// Le impronte SHA-256 dei certificati ammessi a firmare dizionari.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se la lettura non riesce.
    pub fn dictionary_signers(&self) -> ServiceResult<Vec<String>> {
        Ok(self.database().dictionary_signers()?)
    }

    /// Sostituisce l'elenco dei firmatari ammessi; vuoto, non ne ammette
    /// nessuno.
    ///
    /// Un'impronta si può scrivere con maiuscole, spazi o due punti, come la
    /// mostrano gli strumenti di Windows: si conserva in esadecimale minuscolo.
    ///
    /// # Errori
    ///
    /// [`ServiceError::ActionReservedToAdministrator`] in modalità operatore,
    /// [`ServiceError::DictionarySignersRefused`] per un'impronta non valida o
    /// per più di [`MAX_DICTIONARY_SIGNERS`], o un errore se la scrittura non
    /// riesce. Un rifiuto lascia l'elenco di prima.
    pub fn set_dictionary_signers(
        &mut self,
        fingerprints: &[&str],
        actor: &Actor,
        now: Timestamp,
    ) -> ServiceResult<()> {
        self.require(RestrictedAction::ChooseDictionarySource)?;

        let mut impronte: Vec<String> = Vec::with_capacity(fingerprints.len());
        for scritta in fingerprints {
            let pulita: String = scritta
                .chars()
                .filter(|carattere| !carattere.is_whitespace() && *carattere != ':')
                .collect();
            let Ok(impronta) = Sha256Digest::from_hex(&pulita) else {
                return Err(ServiceError::DictionarySignersRefused {
                    reason: String::from(
                        "un'impronta è fatta di 64 cifre da 0 a 9 e lettere da a a f, quelle del certificato",
                    ),
                });
            };
            let impronta = impronta.as_str().to_owned();
            if !impronte.contains(&impronta) {
                impronte.push(impronta);
            }
        }
        if impronte.len() > MAX_DICTIONARY_SIGNERS {
            return Err(ServiceError::DictionarySignersRefused {
                reason: format!("se ne ammettono al più {MAX_DICTIONARY_SIGNERS}"),
            });
        }

        let audit = self.audit_entry(
            actor,
            "firmatari_dizionari_impostati",
            &format!("{} ammessi", impronte.len()),
            now,
        )?;
        self.database_mut()
            .replace_dictionary_signers(&impronte, actor, &audit)?;
        Ok(())
    }

    /// I tentativi di scaricamento, dal più recente.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se la lettura non riesce.
    pub fn dictionary_downloads(&self) -> ServiceResult<Vec<StoredDictionaryDownload>> {
        Ok(self.database().dictionary_downloads()?)
    }

    /// Scarica il dizionario dalla fonte configurata, quando una persona
    /// preme (ADR-0178, decisione 6).
    ///
    /// # Errori
    ///
    /// [`ServiceError::DictionarySourceMissing`] senza fonte,
    /// [`ServiceError::NoDictionarySignerAllowed`] senza firmatari: in
    /// entrambi i casi non si va in rete. Un errore se l'archivio non si legge
    /// o non si scrive. Ogni altro esito è un [`DictionaryDownloadOutcome`],
    /// già scritto nel registro.
    pub fn download_dictionary(
        &mut self,
        actor: &Actor,
        now: Timestamp,
    ) -> ServiceResult<DictionaryDownloadOutcome> {
        self.require(RestrictedAction::ImportDictionary)?;

        let Some(fonte) = self.dictionary_source()? else {
            return Err(ServiceError::DictionarySourceMissing);
        };
        if self.dictionary_signers()?.is_empty() {
            return Err(ServiceError::NoDictionarySignerAllowed);
        }
        let firma = format!("{fonte}{SIGNATURE_SUFFIX}");

        let contenuto = match https::fetch_within(&fonte, BodyLimit::Dictionary) {
            Fetched::Body(byte) => byte,
            Fetched::Refused(motivo) => {
                return self.record_not_reached(&fonte, None, &motivo.to_string(), actor, now);
            }
        };
        let firma = match https::fetch_within(&firma, BodyLimit::Small) {
            Fetched::Body(byte) => byte,
            Fetched::Refused(motivo) => {
                return self.record_not_reached(
                    &fonte,
                    Some(&contenuto),
                    &format!("la firma: {motivo}"),
                    actor,
                    now,
                );
            }
        };

        self.receive_dictionary(
            &fonte,
            &contenuto,
            &firma,
            detached_signature::verify_detached,
            actor,
            now,
        )
    }

    /// Ciò che si fa dei byte arrivati: firma, firmatario, lettura, ingresso.
    pub(crate) fn receive_dictionary(
        &mut self,
        url: &str,
        content: &[u8],
        signature: &[u8],
        verify: Verifier,
        actor: &Actor,
        now: Timestamp,
    ) -> ServiceResult<DictionaryDownloadOutcome> {
        let mut registro = NewDictionaryDownload {
            requested_by: actor.as_str().to_owned(),
            requested_at: now,
            url: url.to_owned(),
            content_sha256: Some(Sha256Digest::of_bytes(content).as_str().to_owned()),
            signer_sha256: None,
            declared_name: None,
            declared_version: None,
            outcome: String::from("rifiutato"),
            outcome_detail: None,
            dictionary_id: None,
            version_id: None,
        };

        // I limiti della porta, ricontrollati qui: un controllo che sta in un
        // posto solo è un controllo che un giorno qualcuno aggira.
        if content.len() > MAX_IMPORT_BYTES || signature.len() > https::MAX_BODY_BYTES {
            return self.record_refusal(registro, "supera il limite ammesso", actor, now);
        }

        // 1. LA FIRMA, PRIMA DI INTERPRETARE UN SOLO BYTE.
        let certificato = match verify(content, signature) {
            DetachedVerdict::Verified { signer_certificate } => signer_certificate,
            verdetto => {
                if let DetachedVerdict::ChainNotTrusted {
                    signer_certificate, ..
                } = &verdetto
                {
                    registro.signer_sha256 = Some(
                        Sha256Digest::of_bytes(signer_certificate)
                            .as_str()
                            .to_owned(),
                    );
                }
                let motivo = verdetto.operator_message();
                return self.record_refusal(registro, &motivo, actor, now);
            }
        };

        // 2. CHI HA FIRMATO lo sceglie l'ufficio.
        let firmatario = Sha256Digest::of_bytes(&certificato).as_str().to_owned();
        registro.signer_sha256 = Some(firmatario.clone());
        if !self.dictionary_signers()?.contains(&firmatario) {
            return self.record_refusal(
                registro,
                "la firma è valida, ma chi ha firmato non è fra i firmatari ammessi",
                actor,
                now,
            );
        }

        // 3. LA STESSA LETTURA DELL'IMPORT DA FILE.
        let letto = match parse(content) {
            Ok(letto) => letto,
            Err(errore) => {
                let motivo = errore.operator_message();
                return self.record_refusal(registro, &motivo, actor, now);
            }
        };
        let nome = letto.name.as_str().to_owned();
        registro.declared_name = Some(nome.clone());
        registro.declared_version = Some(letto.number);

        // 4. IN BOZZA: un dizionario nuovo, o una versione più alta di quello
        // già scaricato con lo stesso nome, se esiste ancora.
        let precedente = self
            .database()
            .latest_dictionary_download_named(&nome)?
            .and_then(|riga| riga.dictionary_id.zip(riga.declared_version))
            .map(|(id, numero)| (DictionaryId::new(id), numero))
            .filter(|(id, _)| self.database().dictionary(*id).is_ok());

        let scritto = match precedente {
            Some((_, ultimo)) if letto.number <= ultimo => {
                let motivo = format!(
                    "dichiara la versione {}, che non è più alta dell'ultima scaricata, la {ultimo}",
                    letto.number
                );
                return self.record_refusal(registro, &motivo, actor, now);
            }
            Some((dizionario, _)) => self
                .database_mut()
                .insert_version_with_terms(
                    dizionario,
                    letto.number,
                    &letto.note,
                    actor,
                    &letto.terms,
                    now,
                )
                .map(|versione| (dizionario, versione))
                .map_err(crate::error::from_storage),
            None => {
                let nuovo = NewDictionary {
                    name: letto.name.clone(),
                    description: letto.description,
                    scope: letto.scope,
                    origin: DictionaryOrigin::Imported,
                    visibility: DictionaryVisibility::Personal,
                    created_by: actor.clone(),
                    derived_from: None,
                };
                self.write(&nuovo, &letto.note, letto.number, letto.terms, now)
            }
        };
        let (dizionario, versione) = match scritto {
            Ok(coppia) => coppia,
            Err(ServiceError::DictionaryNameAlreadyUsed) => {
                return self.record_refusal(
                    registro,
                    "c'è già un dizionario con questo nome, che non è arrivato dalla rete",
                    actor,
                    now,
                );
            }
            Err(errore) => {
                let motivo = errore.operator_message();
                return self.record_refusal(registro, &motivo, actor, now);
            }
        };

        registro.outcome = String::from("importato");
        registro.dictionary_id = Some(dizionario.get());
        registro.version_id = Some(versione.get());
        let audit = self.audit_entry(
            actor,
            "dizionario_scaricato",
            &format!("{nome}, versione {}", letto.number),
            now,
        )?;
        self.database_mut()
            .insert_dictionary_download(&registro, &audit)?;

        Ok(DictionaryDownloadOutcome::Entered {
            dictionary_id: dizionario,
            version_id: versione,
            name: nome,
            number: letto.number,
        })
    }

    /// Scrive un rifiuto e lo restituisce.
    fn record_refusal(
        &mut self,
        mut registro: NewDictionaryDownload,
        motivo: &str,
        actor: &Actor,
        now: Timestamp,
    ) -> ServiceResult<DictionaryDownloadOutcome> {
        registro.outcome = String::from("rifiutato");
        registro.outcome_detail = Some(motivo.to_owned());
        let audit = self.audit_entry(actor, "dizionario_scaricato_rifiutato", motivo, now)?;
        self.database_mut()
            .insert_dictionary_download(&registro, &audit)?;
        Ok(DictionaryDownloadOutcome::Refused {
            reason: motivo.to_owned(),
        })
    }

    /// Scrive un tentativo che non è arrivato fino in fondo.
    fn record_not_reached(
        &mut self,
        url: &str,
        content: Option<&[u8]>,
        motivo: &str,
        actor: &Actor,
        now: Timestamp,
    ) -> ServiceResult<DictionaryDownloadOutcome> {
        let registro = NewDictionaryDownload {
            requested_by: actor.as_str().to_owned(),
            requested_at: now,
            url: url.to_owned(),
            content_sha256: content.map(|byte| Sha256Digest::of_bytes(byte).as_str().to_owned()),
            signer_sha256: None,
            declared_name: None,
            declared_version: None,
            outcome: String::from("non_riuscito"),
            outcome_detail: Some(motivo.to_owned()),
            dictionary_id: None,
            version_id: None,
        };
        let audit = self.audit_entry(actor, "dizionario_non_scaricato", motivo, now)?;
        self.database_mut()
            .insert_dictionary_download(&registro, &audit)?;
        Ok(DictionaryDownloadOutcome::NotReached {
            reason: motivo.to_owned(),
        })
    }

    /// Una riga d'audit di questo modulo, con la modalità di chi agisce.
    fn audit_entry(
        &self,
        actor: &Actor,
        action: &str,
        detail: &str,
        now: Timestamp,
    ) -> ServiceResult<NewAuditEntry> {
        // Un dettaglio lungo si accorcia: il registro ha la frase intera.
        let dettaglio: String = detail.chars().take(240).collect();
        Ok(NewAuditEntry {
            actor: actor.clone(),
            action: AuditAction::try_new(action)?,
            entity: AuditEntity::try_new("dizionario")?,
            entity_id: None,
            actor_mode: Some(self.mode()),
            detail: Some(AuditDetail::try_new(&dettaglio)?),
            recorded_at: now,
        })
    }
}

#[cfg(test)]
mod tests {
    use lisi_core::model::dictionary::{DictionaryOrigin, DictionaryVisibility, MAX_IMPORT_BYTES};
    use lisi_core::text::Actor;
    use lisi_core::{OperatingMode, RestrictedAction, Sha256Digest, Timestamp};
    use lisi_platform::DetachedVerdict;
    use lisi_platform::detached_signature::verify_detached;

    use super::{DictionaryDownloadOutcome, MAX_DICTIONARY_SIGNERS};
    use crate::dictionaries::DictionaryService;
    use crate::error::ServiceError;
    use crate::sources::open_in_memory_database;

    const DIZIONARIO: &[u8] =
        include_bytes!("../../lisi-platform/tests/fixtures/firma_separata/dizionario.json");
    const FIRMA: &[u8] =
        include_bytes!("../../lisi-platform/tests/fixtures/firma_separata/dizionario.json.p7s");
    const CERTIFICATO_A: &[u8] =
        include_bytes!("../../lisi-platform/tests/fixtures/firma_separata/firmatario_a.cer");
    const CERTIFICATO_B: &[u8] =
        include_bytes!("../../lisi-platform/tests/fixtures/firma_separata/firmatario_b.cer");
    const FONTE: &str = "https://esempio.test/dizionario.json";

    fn now() -> Timestamp {
        Timestamp::from_millis(1_700_000_000_000)
    }

    fn persona(nome: &str) -> Actor {
        let Ok(attore) = Actor::try_new(nome) else {
            panic!("l'attore di prova deve essere valido");
        };
        attore
    }

    fn impronta(certificato: &[u8]) -> String {
        Sha256Digest::of_bytes(certificato).as_str().to_owned()
    }

    /// Windows direbbe «firmato da A, e A è attendibile».
    fn firmato_da_a(_contenuto: &[u8], _firma: &[u8]) -> DetachedVerdict {
        DetachedVerdict::Verified {
            signer_certificate: CERTIFICATO_A.to_vec(),
        }
    }

    /// Windows direbbe «firmato da B, e B è attendibile».
    fn firmato_da_b(_contenuto: &[u8], _firma: &[u8]) -> DetachedVerdict {
        DetachedVerdict::Verified {
            signer_certificate: CERTIFICATO_B.to_vec(),
        }
    }

    /// Una postazione amministrata, con la fonte e il firmatario A ammesso.
    fn postazione_con_a() -> DictionaryService {
        let Ok(database) = open_in_memory_database() else {
            panic!("il database in memoria deve potersi aprire");
        };
        let mut servizio = DictionaryService::new(database);
        let amministratore = persona("amministratore.prova");
        let Ok(()) = servizio.set_dictionary_source(Some(FONTE), &amministratore, now()) else {
            panic!("la fonte si scrive");
        };
        let a = impronta(CERTIFICATO_A);
        let Ok(()) = servizio.set_dictionary_signers(&[a.as_str()], &amministratore, now()) else {
            panic!("il firmatario A si ammette");
        };
        servizio
    }

    fn ricevi(
        servizio: &mut DictionaryService,
        contenuto: &[u8],
        verifica: super::Verifier,
    ) -> DictionaryDownloadOutcome {
        let Ok(esito) = servizio.receive_dictionary(
            FONTE,
            contenuto,
            FIRMA,
            verifica,
            &persona("operatore.prova"),
            now(),
        ) else {
            panic!("l'esito deve potersi scrivere");
        };
        esito
    }

    /// Lo stesso dizionario di prova, con un altro numero di versione.
    fn versione(numero: u32) -> Vec<u8> {
        let Ok(testo) = std::str::from_utf8(DIZIONARIO) else {
            panic!("il dizionario di prova è testo");
        };
        testo
            .replace("\"number\": 2", &format!("\"number\": {numero}"))
            .into_bytes()
    }

    /// **Di fabbrica non si va in rete** (ADR-0178, decisioni 4 e 5): senza
    /// fonte, e con la fonte ma senza firmatari, lo scaricamento si ferma
    /// prima della porta e non lascia righe.
    #[test]
    fn di_fabbrica_non_si_va_in_rete() {
        let Ok(database) = open_in_memory_database() else {
            panic!("il database in memoria deve potersi aprire");
        };
        let mut servizio = DictionaryService::new(database);
        let chi = persona("operatore.prova");
        assert_eq!(servizio.dictionary_source().ok(), Some(None));
        assert!(matches!(
            servizio.download_dictionary(&chi, now()),
            Err(ServiceError::DictionarySourceMissing)
        ));

        let Ok(()) = servizio.set_dictionary_source(Some(FONTE), &chi, now()) else {
            panic!("la fonte si scrive");
        };
        assert!(matches!(
            servizio.download_dictionary(&chi, now()),
            Err(ServiceError::NoDictionarySignerAllowed)
        ));
        assert_eq!(
            servizio.dictionary_downloads().map(|r| r.len()).ok(),
            Some(0)
        );
    }

    /// **La fonte e i firmatari sono dell'amministratore** (ADR-0178, DEC-455;
    /// prova negativa: l'operatore, un indirizzo in chiaro, un'impronta
    /// malformata, nove firmatari → rifiutati, e l'elenco di prima resta).
    #[test]
    fn la_fonte_e_i_firmatari_sono_dell_amministratore() {
        let mut servizio = postazione_con_a();
        let chi = persona("amministratore.prova");

        servizio.set_mode(OperatingMode::Operator);
        assert!(matches!(
            servizio.set_dictionary_source(None, &chi, now()),
            Err(ServiceError::ActionReservedToAdministrator {
                action: RestrictedAction::ChooseDictionarySource
            })
        ));
        assert!(matches!(
            servizio.set_dictionary_signers(&[], &chi, now()),
            Err(ServiceError::ActionReservedToAdministrator { .. })
        ));
        servizio.set_mode(OperatingMode::Administrator);

        assert!(matches!(
            servizio.set_dictionary_source(Some("http://esempio.test/d.json"), &chi, now()),
            Err(ServiceError::DictionarySourceRefused { .. })
        ));
        let lunga = format!("https://esempio.test/{}", "a".repeat(2030));
        assert!(matches!(
            servizio.set_dictionary_source(Some(&lunga), &chi, now()),
            Err(ServiceError::DictionarySourceRefused { .. })
        ));
        assert_eq!(
            servizio.dictionary_source().ok().flatten().as_deref(),
            Some(FONTE),
            "un rifiuto lascia la fonte di prima"
        );

        assert!(matches!(
            servizio.set_dictionary_signers(&["non è un'impronta"], &chi, now()),
            Err(ServiceError::DictionarySignersRefused { .. })
        ));
        let nove: Vec<String> = (0..=MAX_DICTIONARY_SIGNERS)
            .map(|cifra| cifra.to_string().repeat(64))
            .collect();
        let nove: Vec<&str> = nove.iter().map(String::as_str).collect();
        assert!(matches!(
            servizio.set_dictionary_signers(&nove, &chi, now()),
            Err(ServiceError::DictionarySignersRefused { .. })
        ));
        assert_eq!(
            servizio.dictionary_signers().ok(),
            Some(vec![impronta(CERTIFICATO_A)])
        );

        // Come la mostrano gli strumenti di Windows: maiuscole e spazi.
        let b = impronta(CERTIFICATO_B);
        let scritta: String = b
            .to_ascii_uppercase()
            .as_bytes()
            .chunks(2)
            .map(|coppia| String::from_utf8_lossy(coppia).into_owned())
            .collect::<Vec<String>>()
            .join(" ");
        let Ok(()) = servizio.set_dictionary_signers(&[scritta.as_str()], &chi, now()) else {
            panic!("un'impronta con spazi e maiuscole si ammette");
        };
        assert_eq!(servizio.dictionary_signers().ok(), Some(vec![b]));

        let Ok(audit) = servizio.database().audit_entries() else {
            panic!("l'audit si legge");
        };
        for azione in ["fonte_dizionari_impostata", "firmatari_dizionari_impostati"] {
            assert!(
                audit.iter().any(|riga| riga.action.as_str() == azione),
                "manca «{azione}» nell'audit"
            );
        }
    }

    /// **Firmato da chi l'ufficio ha scelto, entra in bozza** (ADR-0178,
    /// decisione 9): personale, importato, non pubblicato, con il suo numero, e
    /// il registro dice chi, che cosa e chi ha firmato.
    #[test]
    fn un_dizionario_firmato_da_un_ammesso_entra_in_bozza() {
        let mut servizio = postazione_con_a();
        let DictionaryDownloadOutcome::Entered {
            dictionary_id,
            version_id,
            number,
            ..
        } = ricevi(&mut servizio, DIZIONARIO, firmato_da_a)
        else {
            panic!("un dizionario firmato da un ammesso deve entrare");
        };
        assert_eq!(number, 2);

        let (Ok(dizionario), Ok(versione)) = (
            servizio.database().dictionary(dictionary_id),
            servizio.database().dictionary_version(version_id),
        ) else {
            panic!("il dizionario e la versione si leggono");
        };
        assert_eq!(dizionario.origin, DictionaryOrigin::Imported);
        assert_eq!(dizionario.visibility, DictionaryVisibility::Personal);
        assert!(!versione.is_published(), "entra in bozza, mai pubblicato");

        let Ok(registro) = servizio.dictionary_downloads() else {
            panic!("il registro si legge");
        };
        let [riga] = registro.as_slice() else {
            panic!("una riga per tentativo");
        };
        assert_eq!(riga.outcome, "importato");
        assert_eq!(riga.signer_sha256, Some(impronta(CERTIFICATO_A)));
        assert_eq!(
            riga.content_sha256,
            Some(Sha256Digest::of_bytes(DIZIONARIO).as_str().to_owned())
        );
        assert_eq!(riga.url, FONTE);
    }

    /// **Una firma che Windows non accetta, o di chi non è ammesso, si rifiuta
    /// e resta scritta** (ADR-0178, decisioni 3, 4, 10 e 11; la prima con la
    /// verifica vera: il certificato di prova non risale a una radice della
    /// postazione).
    #[test]
    fn una_firma_non_attendibile_o_di_un_altro_si_rifiuta_e_resta_scritta() {
        let mut servizio = postazione_con_a();

        let esito = ricevi(&mut servizio, DIZIONARIO, verify_detached);
        assert!(
            matches!(esito, DictionaryDownloadOutcome::Refused { .. }),
            "una catena che la postazione non riconosce si rifiuta: {esito:?}"
        );
        let esito = ricevi(&mut servizio, DIZIONARIO, firmato_da_b);
        let DictionaryDownloadOutcome::Refused { reason } = esito else {
            panic!("un firmatario non ammesso si rifiuta");
        };
        assert!(reason.contains("non è fra i firmatari ammessi"), "{reason}");

        let Ok(registro) = servizio.dictionary_downloads() else {
            panic!("il registro si legge");
        };
        assert_eq!(registro.len(), 2, "anche i rifiuti si scrivono");
        assert!(registro.iter().all(|riga| riga.outcome == "rifiutato"));
        assert!(
            registro
                .iter()
                .any(|riga| riga.signer_sha256 == Some(impronta(CERTIFICATO_B))),
            "il registro dice chi ha firmato ciò che si è rifiutato"
        );
        assert!(
            registro.iter().all(|riga| riga.declared_name.is_none()),
            "ciò che non ha passato la firma non si è letto"
        );
        let Ok(dizionari) = servizio.database().dictionaries() else {
            panic!("i dizionari si leggono");
        };
        assert!(dizionari.is_empty(), "niente è entrato");
    }

    /// **Soltanto una versione più alta, e accanto alle vecchie** (ADR-0178,
    /// decisione 9; prova negativa: la stessa versione → rifiutata).
    #[test]
    fn una_versione_non_piu_alta_si_rifiuta_e_una_piu_alta_si_aggiunge() {
        let mut servizio = postazione_con_a();
        let DictionaryDownloadOutcome::Entered { dictionary_id, .. } =
            ricevi(&mut servizio, DIZIONARIO, firmato_da_a)
        else {
            panic!("la prima volta entra");
        };

        for numero in [2, 1] {
            let esito = ricevi(&mut servizio, &versione(numero), firmato_da_a);
            assert!(
                matches!(esito, DictionaryDownloadOutcome::Refused { .. }),
                "la versione {numero} non è più alta della 2"
            );
        }

        let DictionaryDownloadOutcome::Entered {
            dictionary_id: stesso,
            number,
            ..
        } = ricevi(&mut servizio, &versione(3), firmato_da_a)
        else {
            panic!("la versione 3 entra");
        };
        assert_eq!(
            stesso, dictionary_id,
            "accanto alle vecchie, non un dizionario nuovo"
        );
        assert_eq!(number, 3);
        let Ok(versioni) = servizio.database().dictionary_versions(dictionary_id) else {
            panic!("le versioni si leggono");
        };
        assert_eq!(versioni.len(), 2, "la versione di prima non si cancella");
    }

    /// **Dopo la firma, la stessa lettura dell'import** (ADR-0178, decisione
    /// 8): un contenuto firmato che non è un dizionario si rifiuta.
    #[test]
    fn un_contenuto_firmato_che_non_e_un_dizionario_si_rifiuta() {
        let mut servizio = postazione_con_a();
        let esito = ricevi(&mut servizio, b"{\"format\": \"altro\"}", firmato_da_a);
        assert!(matches!(esito, DictionaryDownloadOutcome::Refused { .. }));
        let Ok(registro) = servizio.dictionary_downloads() else {
            panic!("il registro si legge");
        };
        assert!(registro.iter().all(|riga| riga.declared_name.is_none()));
    }

    /// **Il limite della porta è quello dell'import, e l'ordine è quello
    /// deciso** (ADR-0178, decisioni 7 e 8): la firma prima della lettura,
    /// la verifica vera in produzione.
    #[test]
    fn il_limite_e_quello_dell_import_e_la_firma_viene_prima() {
        assert_eq!(lisi_platform::https::MAX_DICTIONARY_BYTES, MAX_IMPORT_BYTES);

        const QUESTO_MODULO: &str = include_str!("dictionary_download.rs");
        let Some((produzione, _)) = QUESTO_MODULO.split_once("\n#[cfg(test)]\nmod tests {") else {
            panic!("il modulo deve avere una parte di produzione");
        };
        let Some(ricezione) = produzione.split("fn receive_dictionary(").nth(1) else {
            panic!("la ricezione deve esistere");
        };
        let (Some(firma), Some(firmatario), Some(lettura)) = (
            ricezione.find("verify(content, signature)"),
            ricezione.find("self.dictionary_signers()?.contains("),
            ricezione.find("parse(content)"),
        ) else {
            panic!("firma, firmatario e lettura devono stare nella ricezione");
        };
        assert!(
            firma < firmatario && firmatario < lettura,
            "prima la firma, poi chi ha firmato, poi la lettura"
        );
        assert!(
            produzione.contains("detached_signature::verify_detached,"),
            "in produzione la verifica è quella di Windows"
        );
    }
}
