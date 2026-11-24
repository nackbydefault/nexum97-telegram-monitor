//! L'esame di un manifesto di aggiornamento ricevuto dall'ufficio.
//!
//! # Perché da un file e non dalla rete
//!
//! ADR-0037 stabilisce che lo **scaricamento** non si costruisce finché non
//! esiste un certificato Authenticode (HVQ-07): costruire il pezzo pericoloso
//! prima del pezzo che lo rende sicuro è l'ordine sbagliato.
//!
//! Ma la decisione — *questo aggiornamento è accettabile per questa postazione?*
//! — è già costruita, collaudata, e **non era raggiungibile da nessuno**. Un
//! motore costruito e mai invocato è il difetto che questo progetto ha già
//! commesso tre volte (DEC-226).
//!
//! Un ufficio che oggi riceve un pacchetto lo riceve **a mano**: su una
//! condivisione, su una chiavetta, allegato a una comunicazione interna. Il
//! manifesto arriva per la stessa strada, e leggerlo da un file è esattamente la
//! stessa operazione che sarà leggerlo dalla rete — **con lo stesso grado di
//! fiducia, che è nessuno**.
//!
//! # Che cosa questo modulo NON fa
//!
//! Non scarica. Non installa. Non tocca la rete, e non esiste alcun controllo
//! automatico: ADR-0037 lo vuole spento finché qualcuno non lo accende, e qui
//! non c'è nemmeno l'interruttore.
//!
//! Dice soltanto **se quell'aggiornamento sarebbe accettabile**, e lo registra.

use std::io::Read;
use std::path::Path;

use lisi_core::Sha256Digest;
use lisi_core::Timestamp;
use lisi_core::model::NewAuditEntry;
use lisi_core::role::{OperatingMode, RestrictedAction};
use lisi_core::text::{Actor, AuditAction, AuditDetail, AuditEntity};
use lisi_platform::DetachedVerdict;
use lisi_platform::detached_signature;
use lisi_platform::os_version::windows_version;
use lisi_storage::Database;
pub use lisi_storage::repository::update_signers::StoredUpdateSigner;

use crate::error::{ServiceError, ServiceResult};
use crate::update::{
    Channel, MAX_MANIFEST_BYTES, ManifestFreshness, StationState, UpdateDecision, UpdateManifest,
    UpdateRefusal, Version, decide, freshness,
};

/// Lo stato di questa postazione, per decidere su un aggiornamento.
///
/// # Perché il canale arriva da fuori
///
/// Fino a UPDATE-01 era fisso su «stabile», scritto qui. Il canale è invece una
/// **decisione della postazione**, conservata in archivio e verbalizzata
/// (ADR-0066): questa funzione non può sceglierlo, e non deve indovinarlo.
///
/// Il canale decide **quale** manifesto riguarda questa postazione. Non tocca
/// alcuna verifica: il pilota è lo stesso artefatto, firmato allo stesso modo,
/// pubblicato prima (ADR-0040).
#[must_use]
pub fn station_state(channel: Channel) -> StationState {
    StationState {
        current_version: Version::current(),
        channel,
        // «Non lo so» viaggia come `None` fino alla decisione, che lo dichiara
        // all'operatore invece di fingere una verifica non fatta.
        windows_version: windows_version().as_str().map(String::from),
    }
}

/// La firma del manifesto: accanto al file, o allo stesso indirizzo, con
/// questo in fondo (ADR-0183, decisione 1).
pub const SIGNATURE_SUFFIX: &str = ".p7s";

/// Quanto può essere grande una firma da leggere.
const MAX_SIGNATURE_BYTES: u64 = 64 * 1024;

/// Quanto può essere lungo il nome di un firmatario.
const MAX_SIGNER_NAME_CHARS: usize = 120;

/// Le impronte dei certificati delle prove
/// (`lisi-platform/tests/fixtures/firma_separata`, «Prova sintetica
/// NEXUM97»): non sono un'identità di rilascio, e ammetterle si rifiuta
/// sempre, in ogni build (ADR-0045, requisito 5; ADR-0183, decisione 6).
pub const TEST_SIGNERS: [&str; 2] = [
    "4bba12f291c70ec5f886d9316fc33566d6ac9d06b1a81a23a3ba01ca37f803d7",
    "d053250c873875bf0f954b5d6c8c5efb110e07880f9cdbb25c195a5f48261152",
];

/// La verifica della firma separata: in produzione
/// [`detached_signature::verify_detached`], nelle prove una funzione che dice
/// l'esito che serve.
pub(crate) type Verifier = fn(&[u8], &[u8]) -> DetachedVerdict;

/// Servizio che esamina un manifesto ricevuto.
#[derive(Debug)]
pub struct UpdateReviewService {
    database: Database,
    verify: Verifier,
}

impl UpdateReviewService {
    /// Crea il servizio attorno all'archivio indicato.
    #[must_use]
    pub fn new(database: Database) -> Self {
        Self {
            database,
            verify: detached_signature::verify_detached,
        }
    }

    /// Crea il servizio con una verifica che dice l'esito che serve.
    #[cfg(test)]
    pub(crate) fn with_verifier(database: Database, verify: Verifier) -> Self {
        Self { database, verify }
    }

    /// Archivio sottostante, per i test e la diagnostica.
    #[must_use]
    pub const fn database(&self) -> &Database {
        &self.database
    }

    /// Il canale scelto per questa postazione.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se la lettura non riesce, o se l'etichetta
    /// conservata non si riconosce — che significa un archivio scritto a mano,
    /// perché la migrazione non ammette altri valori.
    pub fn channel(&self) -> ServiceResult<Channel> {
        let conservato = self.database.update_channel()?;
        Channel::from_stored(&conservato)
            .ok_or(ServiceError::UnreadableUpdateChannel { found: conservato })
    }

    /// Che cosa questa postazione è, canale compreso.
    ///
    /// # Errori
    ///
    /// Come [`Self::channel`].
    pub fn station_state(&self) -> ServiceResult<StationState> {
        Ok(station_state(self.channel()?))
    }

    /// Sceglie il canale di questa postazione, e lo verbalizza.
    ///
    /// # Perché la modalità è un parametro e non un campo
    ///
    /// La modalità operativa vive già nel servizio dei dizionari, che è dove
    /// l'interfaccia la cambia. Tenerne una seconda copia qui vorrebbe dire due
    /// verità sulla stessa cosa, e un giorno divergerebbero: chi chiama porta
    /// quella vera.
    ///
    /// # Perché è riservata all'amministratore
    ///
    /// Il criterio di ADR-0015 è uno solo: ciò che ha effetto **oltre la propria
    /// sessione** richiede l'amministratore. Il canale vale per la postazione e
    /// decide quando **ogni** operatore riceverà il programma nuovo.
    ///
    /// # Errori
    ///
    /// Restituisce [`ServiceError::ActionReservedToAdministrator`] in modalità
    /// operatore, o un errore se la scrittura non riesce.
    pub fn choose_channel(
        &self,
        channel: Channel,
        mode: OperatingMode,
        actor: &Actor,
        now: Timestamp,
    ) -> ServiceResult<()> {
        if !mode.allows(RestrictedAction::ChooseUpdateChannel) {
            return Err(ServiceError::ActionReservedToAdministrator {
                action: RestrictedAction::ChooseUpdateChannel,
            });
        }

        self.database
            .save_update_channel(channel.as_str(), actor, now.as_millis())?;

        // NEL REGISTRO FINISCE LA SCELTA, E BASTA.
        //
        // Non è un dettaglio: la domanda a cui questa riga dovrà rispondere fra
        // un anno è «da quando questa postazione riceve prima, e chi l'ha
        // deciso», e la risposta è il canale più l'attore più l'istante.
        self.database.append_audit(&NewAuditEntry {
            actor: actor.clone(),
            action: AuditAction::try_new("canale_aggiornamenti_scelto")?,
            entity: AuditEntity::try_new("aggiornamento")?,
            entity_id: None,
            actor_mode: None,
            detail: Some(AuditDetail::try_new(channel.as_str())?),
            recorded_at: now,
        })?;

        Ok(())
    }

    /// L'origine da cui scaricare l'informazione sugli aggiornamenti.
    ///
    /// `None` significa **non configurata**, ed è il valore di fabbrica: con
    /// l'origine vuota il prodotto non ha dove andare, e lo dice.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se la lettura non riesce.
    pub fn origin(&self) -> ServiceResult<Option<String>> {
        Ok(self.database.update_origin()?)
    }

    /// Indica l'origine, o la svuota passando `None`.
    ///
    /// # Perché è riservata all'amministratore
    ///
    /// È **l'unica destinazione** che questo prodotto può raggiungere in rete
    /// (ADR-0067). Chi la scrive decide con chi la postazione parla.
    ///
    /// # Errori
    ///
    /// Restituisce [`ServiceError::ActionReservedToAdministrator`] in modalità
    /// operatore, o un errore se la scrittura non riesce — compreso il caso di
    /// un indirizzo che non comincia con `https://`.
    pub fn set_origin(
        &self,
        origin: Option<&str>,
        mode: OperatingMode,
        actor: &Actor,
        now: Timestamp,
    ) -> ServiceResult<()> {
        if !mode.allows(RestrictedAction::ChooseUpdateChannel) {
            return Err(ServiceError::ActionReservedToAdministrator {
                action: RestrictedAction::ChooseUpdateChannel,
            });
        }

        // La stessa regola dell'indirizzo del file (F-11): un'origine in chiaro
        // non si salva, e il rifiuto si dice invece di scoprirlo allo scarico.
        if let Some(origin) = origin {
            crate::update::check_url(origin)
                .map_err(|reason| ServiceError::UpdateOriginRefused { reason })?;
        }

        self.database
            .save_update_origin(origin, actor, now.as_millis())?;

        // NEL REGISTRO FINISCE CHE L'ORIGINE È CAMBIATA, NON QUALE.
        //
        // Un indirizzo in un registro che qualcuno rilegge fra due anni è un
        // indirizzo che qualcuno prima o poi apre. Ciò che serve sapere è
        // **quando** la destinazione è cambiata e **chi** l'ha cambiata: la
        // destinazione di oggi si legge dove è scritta.
        self.database.append_audit(&NewAuditEntry {
            actor: actor.clone(),
            action: AuditAction::try_new("origine_aggiornamenti_impostata")?,
            entity: AuditEntity::try_new("aggiornamento")?,
            entity_id: None,
            actor_mode: None,
            detail: Some(AuditDetail::try_new(if origin.is_some() {
                "indicata"
            } else {
                "svuotata"
            })?),
            recorded_at: now,
        })?;

        Ok(())
    }

    /// I firmatari degli aggiornamenti, ammessi e ritirati, dal più recente.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se la lettura non riesce.
    pub fn update_signers(&self) -> ServiceResult<Vec<StoredUpdateSigner>> {
        Ok(self.database.update_signers()?)
    }

    /// Ammette un firmatario degli aggiornamenti, per impronta SHA-256 del
    /// certificato, con un nome (ADR-0183, decisioni 3 e 4).
    ///
    /// # Errori
    ///
    /// [`ServiceError::ActionReservedToAdministrator`] in modalità operatore;
    /// [`ServiceError::UpdateSignerRefused`] per un'impronta non valida, un
    /// nome vuoto o troppo lungo, un certificato delle prove, un'impronta già
    /// vista o il nono ammesso; un errore se la scrittura non riesce.
    pub fn admit_update_signer(
        &mut self,
        sha256: &str,
        name: &str,
        mode: OperatingMode,
        actor: &Actor,
        now: Timestamp,
    ) -> ServiceResult<()> {
        if !mode.allows(RestrictedAction::ChooseUpdateChannel) {
            return Err(ServiceError::ActionReservedToAdministrator {
                action: RestrictedAction::ChooseUpdateChannel,
            });
        }
        let rifiuto = |reason: &str| ServiceError::UpdateSignerRefused {
            reason: reason.to_owned(),
        };
        let Some(impronta) = impronta_pulita(sha256) else {
            return Err(rifiuto(
                "un'impronta è fatta di 64 cifre da 0 a 9 e lettere da a a f, quelle del certificato",
            ));
        };
        if TEST_SIGNERS.contains(&impronta.as_str()) {
            return Err(rifiuto(
                "è il certificato delle prove, e non firma un aggiornamento vero",
            ));
        }
        let nome = name.trim();
        if nome.is_empty()
            || nome.chars().count() > MAX_SIGNER_NAME_CHARS
            || nome.chars().any(char::is_control)
        {
            return Err(rifiuto(&format!(
                "il nome va scritto, su una riga, in al più {MAX_SIGNER_NAME_CHARS} caratteri"
            )));
        }
        let firmatari = self.database.update_signers()?;
        if firmatari
            .iter()
            .any(|firmatario| firmatario.sha256 == impronta)
        {
            return Err(rifiuto(
                "questa impronta c'è già; una ritirata non torna, si ammette un certificato nuovo",
            ));
        }
        if firmatari.iter().filter(|f| f.is_admitted()).count() >= 8 {
            return Err(rifiuto("se ne ammettono al più otto insieme"));
        }
        let audit = NewAuditEntry {
            actor: actor.clone(),
            action: AuditAction::try_new("firmatario_aggiornamenti_ammesso")?,
            entity: AuditEntity::try_new("aggiornamento")?,
            entity_id: None,
            actor_mode: Some(mode),
            detail: Some(AuditDetail::try_new(&impronta)?),
            recorded_at: now,
        };
        self.database
            .admit_update_signer(&impronta, nome, actor, &audit)?;
        Ok(())
    }

    /// Ritira un firmatario degli aggiornamenti: resta, e una firma sua si
    /// rifiuta dicendo che è ritirato (ADR-0045, requisito 4).
    ///
    /// # Errori
    ///
    /// [`ServiceError::ActionReservedToAdministrator`] in modalità operatore;
    /// [`ServiceError::UpdateSignerRefused`] se non c'è un firmatario ammesso
    /// con quell'impronta; un errore se la scrittura non riesce.
    pub fn retire_update_signer(
        &mut self,
        sha256: &str,
        mode: OperatingMode,
        actor: &Actor,
        now: Timestamp,
    ) -> ServiceResult<()> {
        if !mode.allows(RestrictedAction::ChooseUpdateChannel) {
            return Err(ServiceError::ActionReservedToAdministrator {
                action: RestrictedAction::ChooseUpdateChannel,
            });
        }
        let non_c_e = || ServiceError::UpdateSignerRefused {
            reason: String::from("non c'è un firmatario ammesso con questa impronta"),
        };
        let impronta = impronta_pulita(sha256).ok_or_else(non_c_e)?;
        let audit = NewAuditEntry {
            actor: actor.clone(),
            action: AuditAction::try_new("firmatario_aggiornamenti_ritirato")?,
            entity: AuditEntity::try_new("aggiornamento")?,
            entity_id: None,
            actor_mode: Some(mode),
            detail: Some(AuditDetail::try_new(&impronta)?),
            recorded_at: now,
        };
        if self
            .database
            .retire_update_signer(&impronta, actor, &audit)?
        {
            Ok(())
        } else {
            Err(non_c_e())
        }
    }

    /// La firma di un manifesto: `None` se è valida e di un firmatario
    /// ammesso, il rifiuto altrimenti (ADR-0183, decisioni 2, 3 e 5).
    fn check_signature(
        &self,
        documento: &[u8],
        firma: Option<&[u8]>,
    ) -> ServiceResult<Option<UpdateRefusal>> {
        let firmatari = self.database.update_signers()?;
        if !firmatari.iter().any(StoredUpdateSigner::is_admitted) {
            return Ok(Some(UpdateRefusal::NoSignerAdmitted));
        }
        let Some(firma) = firma else {
            return Ok(Some(UpdateRefusal::Unsigned));
        };
        let certificato = match (self.verify)(documento, firma) {
            DetachedVerdict::Verified { signer_certificate } => signer_certificate,
            altro => {
                return Ok(Some(UpdateRefusal::SignatureNotValid {
                    reason: altro.operator_message(),
                }));
            }
        };
        let impronta = Sha256Digest::of_bytes(&certificato).as_str().to_owned();
        Ok(
            match firmatari
                .iter()
                .find(|firmatario| firmatario.sha256 == impronta)
            {
                Some(firmatario) if firmatario.is_admitted() => None,
                Some(firmatario) => Some(UpdateRefusal::SignerRetired {
                    name: firmatario.name.clone(),
                }),
                None => Some(UpdateRefusal::SignerNotAdmitted { sha256: impronta }),
            },
        )
    }

    /// Scarica l'informazione sull'aggiornamento dall'origine, e la esamina.
    ///
    /// # Che cosa questo metodo NON fa
    ///
    /// Non scarica l'aggiornamento: scarica **il documento che lo descrive**, e
    /// lo sottopone alla stessa decisione che si applica a un file scelto a mano.
    /// Scaricare l'artefatto è UPDATE-03.
    ///
    /// E non decide **se** farlo: si muove quando qualcuno lo chiede. Non esiste
    /// un controllo automatico, e non è una funzione mancante (ADR-0037).
    ///
    /// # Errori
    ///
    /// [`ServiceError::UpdateOriginMissing`] se non c'è un'origine;
    /// [`ServiceError::UpdateNotFetched`] se il documento non è arrivato — che
    /// **non** è un aggiornamento rifiutato, ed è un fatto diverso.
    pub fn fetch_and_review(
        &self,
        actor: &Actor,
        now: Timestamp,
    ) -> ServiceResult<(UpdateDecision, ManifestFreshness)> {
        let Some(origine) = self.origin()? else {
            return Err(ServiceError::UpdateOriginMissing);
        };

        let esito = self.fetch_document(&origine);
        // LA FIRMA STA ALLO STESSO INDIRIZZO, con `.p7s` in fondo (ADR-0183,
        // decisione 1): nessuna destinazione nuova. Si chiede soltanto se il
        // manifesto è arrivato.
        let firma = format!("{origine}{SIGNATURE_SUFFIX}");
        let firmata = esito
            .is_ok()
            .then(|| self.fetch_bytes(&firma).ok())
            .flatten();

        // IL PASSAGGIO IN RETE SI REGISTRA, RIUSCITO O NO.
        //
        // È l'unica uscita verso la rete che questo prodotto ha, e un'uscita che
        // non lascia traccia è un'uscita che nessuno può verificare. Nel registro
        // finisce che è stata tentata e come è andata, mai il documento.
        let dettaglio = match &esito {
            Ok(documento) => match &firmata {
                Some(firma) => format!(
                    "scaricato, {} byte, firma {} byte",
                    documento.len(),
                    firma.len()
                ),
                None => format!("scaricato, {} byte, firma non arrivata", documento.len()),
            },
            Err(errore) => format!("non scaricato: {errore}"),
        };
        self.database.append_audit(&NewAuditEntry {
            actor: actor.clone(),
            action: AuditAction::try_new("aggiornamento_scaricato")?,
            entity: AuditEntity::try_new("aggiornamento")?,
            entity_id: None,
            actor_mode: None,
            detail: Some(AuditDetail::try_new(&dettaglio)?),
            recorded_at: now,
        })?;

        let documento = esito?;
        self.review_document(&documento, firmata.as_deref(), actor, now)
    }

    /// Scarica l'artefatto descritto dal manifesto, e si ferma lì.
    ///
    /// # Che cosa questo metodo NON fa
    ///
    /// **Non verifica nulla**: non l'impronta, non la firma. Ciò che scrive sono
    /// byte arrivati dalla rete, e il file che li contiene **non è eseguibile**
    /// e non viene aperto da nessuno (ADR-0068). La verifica è UPDATE-04, la
    /// consegna all'installatore è UPDATE-07, e nessuna delle due esiste oggi.
    ///
    /// # Perché il manifesto si riprende
    ///
    /// Si scarica l'artefatto **di un manifesto accettato**, e accettarlo è una
    /// decisione che si rifà: fra l'esame e lo scaricamento l'origine può aver
    /// pubblicato altro. Riprenderlo costa una richiesta piccola e toglie di
    /// mezzo la domanda «quale manifesto stava guardando l'operatore».
    ///
    /// # Errori
    ///
    /// [`ServiceError::UpdateOriginMissing`] senza origine;
    /// [`ServiceError::UpdateNotFetched`] se qualcosa non è arrivato;
    /// [`ServiceError::UpdateNotOffered`] se il manifesto non offre nulla per
    /// questa postazione; [`ServiceError::UpdateArtifactElsewhere`] se indica
    /// l'artefatto su un host diverso da quello configurato.
    pub fn download_artifact(
        &self,
        actor: &Actor,
        now: Timestamp,
    ) -> ServiceResult<StagedArtifact> {
        let Some(origine) = self.origin()? else {
            return Err(ServiceError::UpdateOriginMissing);
        };

        let documento = self.fetch_signed_document(&origine)?;
        let Ok(manifesto) = serde_json::from_str::<UpdateManifest>(&documento) else {
            return Err(ServiceError::UpdateNotFetched {
                reason: String::from("l'informazione ricevuta non si interpreta"),
            });
        };

        // Si scarica l'artefatto di un manifesto ACCETTATO, e basta.
        if !matches!(
            crate::update::evaluate(&manifesto, &self.station_state()?),
            UpdateDecision::Offer { .. }
        ) {
            return Err(ServiceError::UpdateNotOffered);
        }

        // LO STESSO HOST DELL'ORIGINE (ADR-0068).
        //
        // L'indirizzo dell'artefatto viene dal manifesto, che è dato non fidato:
        // senza questo vincolo, chi controlla il manifesto sceglierebbe dove la
        // postazione va a bussare — e cadrebbe la proprietà con cui UPDATE-02 ha
        // sostituito la guardia forte di ADR-0048.
        let atteso = lisi_platform::https::host_of(&origine);
        let Some(atteso) = atteso else {
            return Err(ServiceError::UpdateNotFetched {
                reason: String::from("l'origine configurata non ha un nome di computer leggibile"),
            });
        };
        if lisi_platform::https::host_of(&manifesto.artifact_url).as_deref()
            != Some(atteso.as_str())
        {
            return Err(ServiceError::UpdateArtifactElsewhere { expected: atteso });
        }

        let cartella = staging_directory()?;
        svuota_staging(&cartella)?;
        controlla_spazio(&cartella, manifesto.artifact_bytes)?;

        let destinazione = cartella.join(NOME_ARTEFATTO);
        let esito = lisi_platform::https::fetch_to_file(
            &manifesto.artifact_url,
            &destinazione,
            manifesto.artifact_bytes,
        );

        // IL PASSAGGIO IN RETE SI REGISTRA, RIUSCITO O NO, e senza l'indirizzo.
        let dettaglio = match &esito {
            lisi_platform::https::Downloaded::Saved { bytes } => {
                format!("artefatto scaricato, {bytes} byte, non verificato")
            }
            lisi_platform::https::Downloaded::Refused(motivo) => {
                format!("artefatto non scaricato: {motivo}")
            }
        };
        self.database.append_audit(&NewAuditEntry {
            actor: actor.clone(),
            action: AuditAction::try_new("artefatto_scaricato")?,
            entity: AuditEntity::try_new("aggiornamento")?,
            entity_id: None,
            actor_mode: None,
            detail: Some(AuditDetail::try_new(&dettaglio)?),
            recorded_at: now,
        })?;

        match esito {
            lisi_platform::https::Downloaded::Saved { bytes } => Ok(StagedArtifact {
                path: destinazione,
                bytes,
            }),
            lisi_platform::https::Downloaded::Refused(motivo) => {
                Err(ServiceError::UpdateNotFetched {
                    reason: motivo.to_string(),
                })
            }
        }
    }

    /// A che punto è l'aggiornamento, e qual è il passo successivo.
    ///
    /// # Perché non tocca la rete
    ///
    /// Rispondere richiede **due domande al mondo** — c'è un'origine? c'è un file
    /// sceso? — e nessuna delle due esce dalla postazione. La schermata si
    /// aggiorna quando vuole, e il prodotto continua a non contattare nessuno
    /// finché qualcuno non lo chiede (ADR-0037).
    ///
    /// # Errori
    ///
    /// Restituisce un errore se l'archivio non si legge. **Non** è un errore non
    /// avere un'origine o non avere un file: sono due dei tre passi.
    pub fn step(&self) -> ServiceResult<UpdateStep> {
        let origine = self.origin()?.is_some();
        let in_attesa = staging_directory()
            .map(|cartella| cartella.join(NOME_ARTEFATTO).is_file())
            .unwrap_or(false);

        Ok(UpdateStep::of(origine, in_attesa))
    }

    /// Che cosa è successo all'ultima consegna.
    ///
    /// # Perché non tocca nulla
    ///
    /// Legge il registro degli atti e la versione di questo binario, e basta.
    /// Non guarda il disco, non esce in rete, non ripara e non ritenta: dire lo
    /// stato è tutto ciò che si può fare onestamente **nel momento in cui la
    /// postazione è nello stato meno noto** (ADR-0073).
    ///
    /// # Errori
    ///
    /// Restituisce un errore se il registro non si legge.
    pub fn delivery_outcome(&self) -> ServiceResult<DeliveryOutcome> {
        let righe = self.database.audit_entries()?;

        // L'ULTIMA consegna, non la prima: le precedenti sono già state
        // raccontate quando erano l'ultima.
        let consegnata = righe
            .iter()
            .rev()
            .find(|riga| riga.action.as_str() == "aggiornamento_consegnato")
            .and_then(|riga| riga.detail.as_ref())
            .and_then(|dettaglio| versione_della_consegna(dettaglio.as_str()));

        let Some(consegnata) = consegnata else {
            return Ok(DeliveryOutcome::NothingToSay);
        };

        let corrente = Version::current();
        if consegnata > corrente {
            return Ok(DeliveryOutcome::NotInstalled {
                delivered: consegnata,
                running: corrente,
            });
        }

        Ok(DeliveryOutcome::NothingToSay)
    }

    /// Consegna l'aggiornamento all'installatore di Windows, e si ferma lì.
    ///
    /// # Le tre condizioni, e nessuna si salta
    ///
    /// 1. **Un verdetto positivo appena calcolato**, con il file ancora aperto:
    ///    fra un verdetto vecchio e la consegna c'è la finestra che ADR-0070 ha
    ///    chiuso. Per questo la verifica avviene **qui dentro** e non altrove.
    /// 2. **Nessun monitoraggio in corso** (ADR-0037): sostituire il programma
    ///    mentre osserva significa interrompere un'osservazione.
    /// 3. **Un operatore che lo chiede**: non un timer, non un avvio, non una
    ///    conseguenza automatica del verdetto.
    ///
    /// # L'ordine, che non è un dettaglio
    ///
    /// Si registra l'atto **prima** di consegnare: dopo, il processo sta per
    /// morire, e un audit scritto dopo è un audit che può non esistere. Meglio
    /// una riga su una consegna che poi fallisce che nessuna riga su una
    /// consegna riuscita.
    ///
    /// # Che cosa NON fa
    ///
    /// Non chiude il programma — lo fa chi chiama, che è l'unico a sapere che
    /// cosa tiene aperto — e **non lo riapre**: un programma che si riaprisse
    /// dopo essere stato sostituito aprirebbe un programma diverso da quello che
    /// l'operatore ha chiuso, senza che nessuno lo guardi partire (ADR-0072).
    ///
    /// # Errori
    ///
    /// [`ServiceError::UpdateNotVerified`] se la catena non dice di sì;
    /// [`ServiceError::UpdateMonitoringRunning`] se qualcosa sta osservando; e
    /// gli errori della verifica, che sono quelli di [`Self::verify_artifact`].
    pub fn hand_off_to_installer(&self, actor: &Actor, now: Timestamp) -> ServiceResult<()> {
        // CONDIZIONE 2 PRIMA DELLA 1, di proposito: se c'è un monitoraggio in
        // corso non si esce nemmeno in rete a riprendere il manifesto. Il
        // rifiuto non dipende da che cosa c'è là fuori.
        let in_corso = self.database.acquiring_session_count()?;
        if in_corso > 0 {
            return Err(ServiceError::UpdateMonitoringRunning { running: in_corso });
        }

        let verdetto = self.verify_artifact(actor, now)?;
        let ArtifactVerdict::Verified { file, version, .. } = &verdetto else {
            return Err(ServiceError::UpdateNotVerified);
        };

        // L'ATTO SI REGISTRA PRIMA. Vedere la nota qui sopra.
        self.database.append_audit(&NewAuditEntry {
            actor: actor.clone(),
            action: AuditAction::try_new("aggiornamento_consegnato")?,
            entity: AuditEntity::try_new("aggiornamento")?,
            entity_id: None,
            actor_mode: None,
            // IL DETTAGLIO DICE ANCHE QUALE VERSIONE, e per questo il prodotto
            // potrà dire, riaprendo, che la consegna non ha prodotto
            // un'installazione (ADR-0073). Non è un frammento del documento: è
            // un numero già interpretato, tre interi.
            detail: Some(AuditDetail::try_new(&dettaglio_della_consegna(version))?),
            recorded_at: now,
        })?;

        avvia_l_installatore(file)
    }

    /// Toglie il file scaricato, se c'è.
    ///
    /// # Perché esiste un comando apposta
    ///
    /// Lo staging **non si svuota da solo** (ADR-0068): cancellare prima che
    /// qualcuno abbia verificato significherebbe cancellare un file che stava per
    /// essere verificato. Serve quindi un modo esplicito, e si chiama con il suo
    /// nome — togliere il file scaricato — non «annulla», che non direbbe che
    /// cosa sparisce.
    ///
    /// # Errori
    ///
    /// Se la cartella non si determina o il file non si toglie.
    pub fn discard_staged(&self, actor: &Actor, now: Timestamp) -> ServiceResult<()> {
        let cartella = staging_directory()?;
        svuota_staging(&cartella)?;

        self.database.append_audit(&NewAuditEntry {
            actor: actor.clone(),
            action: AuditAction::try_new("artefatto_scartato")?,
            entity: AuditEntity::try_new("aggiornamento")?,
            entity_id: None,
            actor_mode: None,
            detail: Some(AuditDetail::try_new(
                "file scaricato tolto dalla postazione",
            )?),
            recorded_at: now,
        })?;

        Ok(())
    }

    /// Percorre la catena di verifica sull'artefatto sceso.
    ///
    /// # L'impronta non è una firma
    ///
    /// L'impronta viene dal **manifesto**, che è dato non fidato: se coincide,
    /// ciò che è dimostrato è che *«questi byte sono quelli che quel documento
    /// descriveva»*. Se il documento è ostile, ha descritto ciò che voleva far
    /// scaricare, e l'impronta torna perfettamente. L'ancoraggio della fiducia è
    /// la firma di Windows, che non viene dal documento (ADR-0069).
    ///
    /// # L'ordine, e perché si ferma al primo anello rotto
    ///
    /// C'è un file → è grande come dichiarato → l'impronta di ciò che è **sul
    /// disco** coincide → che cosa dice Windows della firma. Ogni anello rotto
    /// ha un verdetto proprio, perché un file troncato, uno sostituito e uno
    /// firmato da uno sconosciuto portano a tre azioni diverse.
    ///
    /// # Errori
    ///
    /// Gli stessi di [`Self::download_artifact`] per la parte che riprende il
    /// manifesto. **Un artefatto che non regge la verifica non è un errore**: è
    /// un verdetto, ed è il valore restituito.
    pub fn verify_artifact(&self, actor: &Actor, now: Timestamp) -> ServiceResult<ArtifactVerdict> {
        let Some(origine) = self.origin()? else {
            return Err(ServiceError::UpdateOriginMissing);
        };

        let documento = self.fetch_signed_document(&origine)?;
        let Ok(manifesto) = serde_json::from_str::<UpdateManifest>(&documento) else {
            return Err(ServiceError::UpdateNotFetched {
                reason: String::from("l'informazione ricevuta non si interpreta"),
            });
        };

        // LA DECISIONE SI RIPETE QUI (FINAL-REVIEW-01, FR-025).
        //
        // Il documento si riprende alla verifica, e la consegna passa da qui:
        // un documento che nel frattempo dice una versione non più recente di
        // quella in esecuzione, o un altro prodotto, o un altro canale, non è
        // più un aggiornamento offerto — anche se il file sceso è intatto.
        if !matches!(
            crate::update::evaluate(&manifesto, &self.station_state()?),
            UpdateDecision::Offer { .. }
        ) {
            return Err(ServiceError::UpdateNotOffered);
        }

        let percorso = staging_directory()?.join(NOME_ARTEFATTO);
        let verdetto = percorri_la_catena(&percorso, &manifesto);

        // ADR-0037 §3: UN FILE CHE NON SUPERA LA VERIFICA NON SI TIENE.
        //
        // Era deciso dal 2026-08, e fino a UPDATE-07 non era stato fatto:
        // UPDATE-04 ha costruito la catena e ha lasciato il file dov'era.
        //
        // «Un file scaricato che non supera la verifica della firma e' la prova
        // di un TENTATIVO, non un file con un problema: si cancella, si registra
        // il fatto.» Si toglie solo quando il motivo riguarda IL FILE: se non
        // c'e', se non si e' potuto leggere o se non lo si e' nemmeno guardato,
        // non e' un tentativo — e' una cosa che non si e' potuta dire.
        if verdetto.e_un_tentativo() {
            let _ = std::fs::remove_file(&percorso);
        }

        // NEL REGISTRO FINISCE CHE LA VERIFICA E' STATA FATTA E COM'E' ANDATA.
        //
        // È un fatto avvenuto, e i fatti avvenuti non cambiano. Il VERDETTO
        // invece non si conserva: affermare «verificato» di un file che da quel
        // momento può cambiare sarebbe una bugia con una data (ADR-0069).
        self.database.append_audit(&NewAuditEntry {
            actor: actor.clone(),
            action: AuditAction::try_new("artefatto_verificato")?,
            entity: AuditEntity::try_new("aggiornamento")?,
            entity_id: None,
            actor_mode: None,
            detail: Some(AuditDetail::try_new(verdetto.audit_detail())?),
            recorded_at: now,
        })?;

        Ok(verdetto)
    }

    /// Scarica un documento piccolo dall'indirizzo indicato.
    ///
    /// Esiste perché il manifesto si prende in due momenti — l'esame e lo
    /// scaricamento — e prenderlo in due modi sarebbe prenderlo in due modi
    /// **diversi**.
    fn fetch_document(&self, origine: &str) -> ServiceResult<String> {
        let byte = self.fetch_bytes(origine)?;

        // Il documento è dato NON FIDATO, esattamente come uno letto da file: la
        // rete non lo rende né più né meno attendibile (ADR-0040). Byte che non
        // sono testo non si «riparano»: si dichiarano illeggibili.
        String::from_utf8(byte).map_err(|_| ServiceError::UpdateNotFetched {
            reason: String::from("la risposta non è testo leggibile"),
        })
    }

    /// Il manifesto ripreso dall'origine, soltanto se la sua firma è valida e
    /// di un firmatario ammesso (ADR-0183): un manifesto sostituito fra
    /// l'esame e lo scaricamento non passa.
    fn fetch_signed_document(&self, origine: &str) -> ServiceResult<String> {
        let documento = self.fetch_document(origine)?;
        let firma = format!("{origine}{SIGNATURE_SUFFIX}");
        let firmata = self.fetch_bytes(&firma).ok();
        if self
            .check_signature(documento.as_bytes(), firmata.as_deref())?
            .is_some()
        {
            return Err(ServiceError::UpdateNotOffered);
        }
        Ok(documento)
    }

    /// L'unica lettura della rete di questo servizio: l'origine conservata,
    /// o la sua firma allo stesso indirizzo.
    fn fetch_bytes(&self, origine: &str) -> ServiceResult<Vec<u8>> {
        let esito = lisi_platform::https::fetch(origine);

        match esito {
            lisi_platform::https::Fetched::Body(byte) => Ok(byte),
            lisi_platform::https::Fetched::Refused(motivo) => Err(ServiceError::UpdateNotFetched {
                reason: motivo.to_string(),
            }),
        }
    }

    /// Esamina il manifesto nel percorso indicato e registra l'esito.
    ///
    /// # Errori
    ///
    /// Restituisce un errore solo se l'archivio non accetta la registrazione.
    /// Un manifesto illeggibile o inaccettabile **non è un errore del servizio**:
    /// è una decisione, ed è il valore restituito.
    pub fn review(
        &self,
        path: &Path,
        actor: &Actor,
        now: Timestamp,
    ) -> ServiceResult<UpdateDecision> {
        Ok(self.review_with_freshness(path, actor, now)?.0)
    }

    /// Come [`Self::review`], e dice anche **quanto è fresco il manifesto**.
    ///
    /// # Perché due valori e non uno
    ///
    /// La freschezza non è una decisione: un manifesto fermo non si rifiuta, e
    /// un manifesto fresco non si accetta per questo. È un'osservazione sul
    /// **canale**, non sull'aggiornamento, e mescolarla all'esito avrebbe fatto
    /// una delle due cose sbagliate — rifiutare un aggiornamento buono servito
    /// da uno specchio vecchio, o tacere che il canale è fermo (ADR-0045).
    ///
    /// # Errori
    ///
    /// Come [`Self::review`].
    pub fn review_with_freshness(
        &self,
        path: &Path,
        actor: &Actor,
        now: Timestamp,
    ) -> ServiceResult<(UpdateDecision, ManifestFreshness)> {
        let documento = match read_bounded(path) {
            Ok(documento) => documento,
            Err(motivo) => {
                let decisione = UpdateDecision::Refused(motivo);
                self.record_review(&decisione, actor, now)?;
                return Ok((decisione, ManifestFreshness::Undeclared));
            }
        };

        let firma = read_signature_beside(path);
        self.review_document(&documento, firma.as_deref(), actor, now)
    }

    /// Esamina un documento già in mano, da qualunque parte arrivi.
    ///
    /// # Perché una sola strada per due provenienze
    ///
    /// Un manifesto letto da file e uno scaricato dall'origine sono **la stessa
    /// cosa**: dato non fidato che va sottoposto alla stessa decisione. Due
    /// strade separate sarebbero due decisioni che un giorno divergono, e la
    /// prima a divergere sarebbe quella meno percorsa.
    ///
    /// # Errori
    ///
    /// Restituisce un errore solo se l'archivio non accetta la registrazione o
    /// se il canale della postazione non si legge.
    fn review_document(
        &self,
        documento: &str,
        firma: Option<&[u8]>,
        actor: &Actor,
        now: Timestamp,
    ) -> ServiceResult<(UpdateDecision, ManifestFreshness)> {
        // PRIMA LA FIRMA, POI IL CONTENUTO (ADR-0183, decisione 2): un manifesto
        // che nessun firmatario ammesso ha firmato non si legge nemmeno, e la
        // sua data non dice niente.
        if let Some(rifiuto) = self.check_signature(documento.as_bytes(), firma)? {
            let decisione = UpdateDecision::Refused(rifiuto);
            self.record_review(&decisione, actor, now)?;
            return Ok((decisione, ManifestFreshness::Undeclared));
        }
        let decisione = match decide(documento, &self.station_state()?) {
            UpdateDecision::Offer {
                version,
                notes,
                bytes,
                windows_checked,
                ..
            } => UpdateDecision::Offer {
                version,
                notes,
                bytes,
                manifest_signed: true,
                windows_checked,
            },
            altra => altra,
        };
        // La freschezza si legge dal manifesto interpretato, e un documento che
        // non si interpreta non ne ha una: si dice «non dichiarata» invece di
        // indovinare.
        let freschezza = serde_json::from_str::<UpdateManifest>(documento)
            .map_or(ManifestFreshness::Undeclared, |manifesto| {
                freshness(&manifesto, now.as_millis())
            });

        self.record_review(&decisione, actor, now)?;
        Ok((decisione, freschezza))
    }

    /// Registra l'esito di un esame.
    ///
    /// Nell'audit finisce l'**esito**, mai il contenuto del manifesto: è dato
    /// non fidato, e un audit che lo trascrivesse porterebbe testo altrui dentro
    /// il registro che deve restare affidabile.
    fn record_review(
        &self,
        decisione: &UpdateDecision,
        actor: &Actor,
        now: Timestamp,
    ) -> ServiceResult<()> {
        self.database.append_audit(&NewAuditEntry {
            actor: actor.clone(),
            action: AuditAction::try_new("aggiornamento_esaminato")?,
            entity: AuditEntity::try_new("aggiornamento")?,
            entity_id: None,
            actor_mode: None,
            detail: Some(AuditDetail::try_new(decisione.audit_detail())?),
            recorded_at: now,
        })?;
        Ok(())
    }
}

/// Legge il file fermandosi al limite, invece di leggerlo e poi misurarlo.
///
/// # Perché il limite agisce sulla lettura e non dopo
///
/// `decide` rifiuta un documento troppo grande, ma per misurarlo bisogna già
/// averlo in memoria. Un file da quattro gigabyte scelto per sbaglio — o non per
/// sbaglio — verrebbe caricato per intero **prima** che qualcuno lo rifiuti.
///
/// Si legge un byte in più del limite: se arriva, il file è troppo grande, e
/// nessuno ha allocato più di così.
/// La firma accanto a un manifesto letto da file, se c'è e non è troppo
/// grande.
fn read_signature_beside(path: &Path) -> Option<Vec<u8>> {
    let mut nome = path.as_os_str().to_owned();
    nome.push(SIGNATURE_SUFFIX);
    let file = std::fs::File::open(Path::new(&nome)).ok()?;
    let mut byte = Vec::new();
    file.take(MAX_SIGNATURE_BYTES + 1)
        .read_to_end(&mut byte)
        .ok()?;
    (u64::try_from(byte.len()).ok()? <= MAX_SIGNATURE_BYTES).then_some(byte)
}

/// Un'impronta scritta come la mostra Windows (maiuscole, spazi, due punti)
/// in esadecimale minuscolo, o `None` se non è un'impronta SHA-256.
fn impronta_pulita(scritta: &str) -> Option<String> {
    let pulita: String = scritta
        .chars()
        .filter(|carattere| !carattere.is_whitespace() && *carattere != ':')
        .collect();
    Sha256Digest::from_hex(&pulita.to_ascii_lowercase())
        .ok()
        .map(|impronta| impronta.as_str().to_owned())
}

fn read_bounded(path: &Path) -> Result<String, UpdateRefusal> {
    let file = std::fs::File::open(path).map_err(|errore| UpdateRefusal::Malformed {
        reason: format!("il file non si apre: {errore}"),
    })?;

    let mut byte = Vec::new();
    file.take(MAX_MANIFEST_BYTES as u64 + 1)
        .read_to_end(&mut byte)
        .map_err(|errore| UpdateRefusal::Malformed {
            reason: format!("il file non si legge: {errore}"),
        })?;

    if byte.len() > MAX_MANIFEST_BYTES {
        return Err(UpdateRefusal::TooLarge { bytes: byte.len() });
    }

    String::from_utf8(byte).map_err(|_| UpdateRefusal::Malformed {
        reason: String::from(
            "il file non è testo: la descrizione di un aggiornamento è qualche riga di testo",
        ),
    })
}

impl UpdateDecision {
    /// L'esito in forma breve, per l'audit.
    ///
    /// # Perché non il messaggio dell'operatore
    ///
    /// Il messaggio dell'operatore contiene pezzi del manifesto — versioni,
    /// prodotti, indirizzi — che sono **testo altrui**. Nell'audit va il fatto, e
    /// il fatto è quale controllo ha risposto.
    #[must_use]
    pub const fn audit_detail(&self) -> &'static str {
        match self {
            Self::UpToDate => "già aggiornato",
            Self::Offer { .. } => "aggiornamento disponibile, nulla scaricato",
            Self::Refused(motivo) => motivo.audit_detail(),
        }
    }
}

impl UpdateRefusal {
    /// Quale controllo ha respinto il manifesto.
    #[must_use]
    pub const fn audit_detail(&self) -> &'static str {
        match self {
            Self::TooLarge { .. } => "rifiutato: troppo grande",
            Self::Malformed { .. } => "rifiutato: non leggibile",
            Self::UnknownSchema { .. } => "rifiutato: schema sconosciuto",
            Self::WrongProduct { .. } => "rifiutato: altro prodotto",
            Self::WrongArchitecture { .. } => "rifiutato: altra architettura",
            Self::WrongChannel { .. } => "rifiutato: altro canale",
            Self::UnreadableVersion { .. } => "rifiutato: versione illeggibile",
            Self::NotNewer { .. } => "rifiutato: non più recente",
            Self::NeedsIntermediate { .. } => "rifiutato: serve una versione intermedia",
            Self::UnusableDigest => "rifiutato: impronta inutilizzabile",
            Self::UnusableUrl { .. } => "rifiutato: indirizzo inaccettabile",
            Self::NeedsNewerWindows { .. } => "rifiutato: serve una Windows più recente",
            Self::NoSignerAdmitted => "rifiutato: nessun firmatario ammesso",
            Self::Unsigned => "rifiutato: senza firma",
            Self::SignatureNotValid { .. } => "rifiutato: firma non valida",
            Self::SignerNotAdmitted { .. } => "rifiutato: firmatario non ammesso",
            Self::SignerRetired { .. } => "rifiutato: firmatario ritirato",
        }
    }
}

/// Che cosa è successo all'ultima consegna, riaprendo il programma.
///
/// # Perché è un fatto e non uno stato
///
/// Il prodotto si è chiuso per consegnare, e riapre. Se l'installazione è
/// riuscita, riapre **con la versione nuova** e non c'è niente da dire. Se non è
/// riuscita, riapre identico — e per lui non è successo niente.
///
/// Ma nel registro degli atti c'è scritto che una consegna è avvenuta, e la
/// versione che gira è ancora quella di prima: le due cose insieme dicono che
/// **l'aggiornamento è stato consegnato e non è stato installato** (ADR-0073).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DeliveryOutcome {
    /// Nessuna consegna è mai stata registrata, o l'ultima ha prodotto ciò che
    /// doveva.
    NothingToSay,
    /// Una consegna è avvenuta e la versione non è cambiata.
    NotInstalled {
        /// La versione che era stata consegnata.
        delivered: Version,
        /// La versione che sta girando adesso.
        running: Version,
    },
}

impl DeliveryOutcome {
    /// Che cosa dire a chi riapre il programma.
    ///
    /// # Perché non si sceglie una causa
    ///
    /// Il prodotto **non sa perché** l'installazione non è avvenuta: sa che è
    /// stata consegnata e che la versione non è cambiata. Elencare le cause
    /// possibili come se le conoscesse sarebbe inventare; nominarne due come
    /// esempi dichiarati tali è dire la verità e aiutare chi indaga.
    #[must_use]
    pub fn sentence(&self) -> Option<String> {
        match self {
            Self::NothingToSay => None,
            Self::NotInstalled { delivered, running } => Some(format!(
                "L'aggiornamento alla versione {delivered} è stato consegnato \
                 all'installatore, e questo programma sta ancora girando nella \
                 versione {running}: l'installazione non è avvenuta.\n\nIl \
                 programma non sa perché — può essere stata annullata, oppure \
                 fermata da un antivirus, oppure interrotta da uno spegnimento — e \
                 non prova a indovinare. Il file scaricato è ancora qui e ha già \
                 superato la verifica: si può riprovare, oppure toglierlo e \
                 restare su questa versione, che funziona."
            )),
        }
    }
}

/// Come si scrive nel registro la versione consegnata.
///
/// # Perché esiste una funzione invece di un `format!` sparso
///
/// Chi scrive e chi rilegge devono essere d'accordo. Due formati che divergono
/// sono **un fatto che smette di essere leggibile senza che nessuno se ne
/// accorga**, ed è esattamente la specie di difetto che non produce errori.
#[must_use]
pub fn dettaglio_della_consegna(versione: &Version) -> String {
    format!("consegnato all'installatore di Windows, versione {versione}")
}

/// Rilegge la versione da un dettaglio scritto da [`dettaglio_della_consegna`].
#[must_use]
pub fn versione_della_consegna(dettaglio: &str) -> Option<Version> {
    Version::parse(dettaglio.rsplit(' ').next()?)
}

/// A che punto è l'aggiornamento su questa postazione, e qual è il passo dopo.
///
/// # Perché si calcola e non si conserva
///
/// Non esiste una riga «l'aggiornamento è a metà»: lo stato **è il mondo** — c'è
/// un'origine? c'è un file sceso? Conservarlo significherebbe poter affermare
/// «c'è un file scaricato» quando l'antivirus lo ha appena tolto, ed è la stessa
/// bugia con una data che ADR-0069 ha rifiutato per il verdetto.
///
/// Ne segue che il prodotto **non può trovarsi in uno stato inconsistente
/// rispetto al disco**: non ha uno stato proprio da tenere allineato.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UpdateStep {
    /// Non c'è un'origine: non c'è dove chiedere.
    OriginMissing,
    /// C'è un'origine e non c'è nulla in attesa: si può chiedere.
    AskTheOrigin,
    /// C'è un file sceso e **non verificato**: il passo è verificarlo.
    VerifyWhatArrived,
}

impl UpdateStep {
    /// Qual è il passo, viste le due sole cose che contano.
    ///
    /// # Perché l'ordine è questo
    ///
    /// Un file in attesa viene prima di tutto: è già sul disco, non è stato
    /// verificato, e lasciarlo indietro per proporre di chiedere di nuovo
    /// all'origine significherebbe **scaricare sopra qualcosa che nessuno ha
    /// guardato**.
    #[must_use]
    pub const fn of(origine_indicata: bool, file_in_attesa: bool) -> Self {
        if file_in_attesa {
            return Self::VerifyWhatArrived;
        }
        if origine_indicata {
            return Self::AskTheOrigin;
        }
        Self::OriginMissing
    }

    /// L'etichetta del comando che porta avanti, se un comando c'è.
    ///
    /// `None` quando il passo **non è dell'operatore**: indicare l'origine
    /// richiede la modalità amministratore, e proporre un comando che rifiuterà
    /// sarebbe la stessa promessa di un pulsante che non fa nulla.
    #[must_use]
    pub const fn command(self) -> Option<&'static str> {
        match self {
            Self::OriginMissing => None,
            Self::AskTheOrigin => Some("Chiedi se c'è un aggiornamento"),
            Self::VerifyWhatArrived => Some("Verifica il file scaricato"),
        }
    }

    /// Dove si è, detto a chi guarda.
    #[must_use]
    pub fn sentence(self) -> String {
        match self {
            Self::OriginMissing => String::from(
                "Non è indicato da dove prendere gli aggiornamenti, quindi non c'è \
                 niente da chiedere e il programma non contatta nessuno. \
                 L'indirizzo lo scrive chi amministra la postazione.",
            ),
            Self::AskTheOrigin => String::from(
                "Non c'è nessun file in attesa. Il passo successivo è chiedere \
                 all'origine se esista un aggiornamento per questa postazione: \
                 finché non lo si chiede, il programma non esce in rete.",
            ),
            Self::VerifyWhatArrived => String::from(
                "C'è un file scaricato che non è stato verificato. Finché non lo \
                 è, sono soltanto byte arrivati dalla rete: il programma non li \
                 apre e non li esegue.",
            ),
        }
    }

    /// Che cosa succede se non si fa nulla.
    ///
    /// # Perché non è un pulsante
    ///
    /// «Più tardi» non avrebbe niente da fare: il prodotto non controlla da sé,
    /// non ha un timer e non guarda all'avvio (ADR-0037). Un comando lo
    /// suggerirebbe, e **nessuno se ne ricorderebbe**. Ciò che si costruisce è
    /// la verità corrispondente (ADR-0071).
    #[must_use]
    pub const fn doing_nothing(self) -> &'static str {
        "Si può lasciar perdere: niente parte da solo, niente scade, e tornando \
         qui si ritroverà esattamente questo."
    }
}

/// Perché il comando che installa non c'è.
///
/// # Perché una frase e non un pulsante
///
/// Installare è UPDATE-07, e oggi non esiste. Un comando «Installa ora» che non
/// installa è **una promessa**: chi lo preme non impara che la funzione manca,
/// impara che il programma non funziona. Un pulsante disabilitato sembrerebbe
/// invece un permesso mancante, e l'operatore andrebbe a cercare chi glielo può
/// dare — e non c'è (ADR-0071).
pub const PERCHE_NON_SI_INSTALLA: &str = "Il programma non si sostituisce da sé e non si riapre da solo. Quando \
     qualcuno decide di farlo, consegna l'aggiornamento all'installatore di \
     Windows e si chiude. Non succede durante un monitoraggio. È una scelta scritta \
     nel registro degli atti: un documento prodotto ieri e uno prodotto oggi devono \
     poter dire con quale versione sono nati.";

/// Che cosa succede premendo il comando che consegna, detto **prima**.
///
/// # Perché sta scritto prima e non dopo
///
/// Il programma si chiude. Un operatore che lo scopre **dopo** averlo premuto ha
/// perso di vista che cosa stava facendo, e il prodotto glielo ha fatto perdere
/// senza dirglielo (ADR-0072).
pub const COSA_SUCCEDE_CONSEGNANDO: &str = "Premendo, il programma verifica di nuovo il file, lo consegna \
     all'installatore di Windows e si chiude. Non si riapre da solo: riaprirlo è \
     un gesto, e dopo un aggiornamento è un gesto che vale la pena fare \
     guardando. Se c'è un monitoraggio in corso, la consegna non avviene.";

/// Che cosa la catena di verifica dice dell'artefatto sceso.
///
/// # Perché è un verdetto e non un'autorizzazione
///
/// È la risposta a una domanda, non il permesso di fare qualcosa. Nessun file
/// viene eseguito, aperto o consegnato: la verifica di UPDATE-04 non ne ha
/// bisogno, e la guardia che lo impedisce resta intera (ADR-0069).
///
/// **Non è confrontabile né copiabile per valore**: porta un file aperto, e due
/// verdetti «uguali» sarebbero due aperture diverse dello stesso nome — cioè
/// esattamente la confusione che ADR-0070 toglie di mezzo.
#[derive(Debug, Clone)]
pub enum ArtifactVerdict {
    /// L'impronta coincide **e** la firma è attendibile.
    ///
    /// **Verificato non è autorizzato**: nulla in questo prodotto lo installa,
    /// e installarlo è UPDATE-07.
    ///
    /// # Perché porta con sé un file aperto
    ///
    /// Un percorso si può ri-risolvere, e ri-risolverlo può dare un file
    /// diverso: fra la verifica e l'uso ci sarebbe una finestra in cui
    /// sostituire i byte. L'apertura è **quella** su cui la catena ha detto di
    /// sì, ed è viva finché vive il verdetto — con la condivisione in scrittura
    /// negata, quindi nessuno può cambiarla (ADR-0070).
    ///
    /// Chi userà il file dovrà ricevere **questo**, non un nome.
    Verified {
        /// Quanti byte sono stati improntati.
        bytes: u64,
        /// **Di quale versione** è verdetto.
        ///
        /// Un verdetto su un file è un verdetto su «l'aggiornamento alla
        /// versione X»: senza il numero, l'atto della consegna non potrebbe
        /// dire che cosa è stato consegnato, e riaprendo non si potrebbe dire
        /// che l'installazione non è avvenuta (ADR-0073).
        version: Version,
        /// Il file aperto e verificato.
        file: std::sync::Arc<std::fs::File>,
    },
    /// La catena si è fermata, e questo è l'anello che si è rotto.
    Broken(ArtifactFlaw),
}

/// Quale anello della catena si è rotto.
///
/// Sono distinti apposta: un file troncato, un file sostituito e un file
/// legittimo firmato da uno sconosciuto sono tre situazioni che portano a tre
/// azioni diverse, e appiattirle in «non verificato» toglierebbe a chi indaga
/// l'unica cosa utile.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ArtifactFlaw {
    /// Non c'è nessun file da verificare.
    ///
    /// **Non è un guasto.** Può essere che non si sia mai scaricato nulla, o che
    /// qualcosa — un antivirus, una pulizia — abbia tolto il file.
    Missing,
    /// Il documento non dichiara una versione leggibile.
    ///
    /// È il primo anello, e viene prima di guardare il file: un verdetto su un
    /// file è un verdetto su «l'aggiornamento alla versione X», e senza X non c'è
    /// niente da dire — nemmeno se i byte fossero giusti.
    UnreadableVersion,
    /// Il file non è grande come il manifesto dichiara.
    ///
    /// È la prima cosa che cambia se il file è stato toccato dopo lo
    /// scaricamento, e costa una lettura di metadati.
    SizeChanged {
        /// I byte che il file ha.
        found: u64,
        /// I byte che il manifesto dichiara.
        declared: u64,
    },
    /// Il file supera il tetto del prodotto e non si legge senza freno.
    ///
    /// Un file che cresce da solo è già una risposta.
    TooLarge {
        /// Il tetto, in byte.
        max: u64,
    },
    /// Il file non si è potuto leggere.
    Unreadable,
    /// L'impronta di ciò che è sul disco non è quella dichiarata.
    ///
    /// Nel messaggio **non compare nessuna delle due**: sono sessantaquattro
    /// caratteri che nessuno confronta a occhio, e una di esse arriva da un
    /// documento che viene da fuori.
    DigestMismatch,
    /// Windows dice che il file non è firmato, o che la firma non regge.
    ///
    /// Porta con sé la frase di `SignatureState`, che distingue già «non
    /// firmato», «firma non attendibile», «modificato dopo la firma» e «non si è
    /// potuto stabilire» — e quest'ultima **non è** «non firmato».
    NotSigned {
        /// Che cosa Windows ha detto, in italiano piano.
        reason: String,
    },
    /// Firmato e attendibile per Windows, ma non da un editore che questo
    /// prodotto riconosce come proprio (FINAL-REVIEW-01, FR-004).
    ///
    /// Authenticode dice CHI ha firmato; «attendibile» dice soltanto che una
    /// qualunque autorità riconosciuta ha firmato. Un file legittimo firmato da
    /// uno sconosciuto è un esito distinto (ADR-0069), ed è un rifiuto.
    PublisherNotRecognised,
}

impl ArtifactVerdict {
    /// L'esito in una frase che una persona legge.
    #[must_use]
    pub fn operator_message(&self) -> String {
        match self {
            Self::Verified { bytes, version, .. } => format!(
                "Il file scaricato ({bytes} byte) porta alla versione {version}, \
                 corrisponde a quanto dichiarato ed è firmato da un'autorità che \
                 questa postazione riconosce.\n\nVerificato non vuol dire \
                 installato: finché nessuno lo chiede, il programma non lo esegue \
                 e non si sostituisce a sé stesso."
            ),
            Self::Broken(ArtifactFlaw::Missing) => String::from(
                "Non c'è nessun file da verificare. O non è ancora stato scaricato, \
                 oppure qualcosa lo ha tolto: un antivirus che lo mette in quarantena \
                 fa esattamente questo.",
            ),
            Self::Broken(ArtifactFlaw::UnreadableVersion) => String::from(
                "L'informazione ricevuta non dice in modo leggibile a quale \
                 versione porterebbe questo file. Non è stato verificato altro: \
                 senza sapere a che cosa porta, non c'è niente da dire su di esso.",
            ),
            Self::Broken(ArtifactFlaw::SizeChanged { found, declared }) => format!(
                "Il file sul disco è di {found} byte e l'informazione ricevuta ne \
                 dichiara {declared}. È cambiato dopo essere stato scaricato, oppure \
                 l'informazione nel frattempo è un'altra: in entrambi i casi non è il \
                 file descritto."
            ),
            Self::Broken(ArtifactFlaw::TooLarge { max }) => format!(
                "Il file sul disco supera {max} byte, che è il limite oltre il quale \
                 questo programma non legge. Un file che cresce da solo è già una \
                 risposta."
            ),
            Self::Broken(ArtifactFlaw::Unreadable) => String::from(
                "Il file sul disco non si è potuto leggere. Non significa che sia \
                 sbagliato: significa che non si è potuto dire nulla su di esso.",
            ),
            Self::Broken(ArtifactFlaw::DigestMismatch) => String::from(
                "Il file sul disco non è quello che l'informazione ricevuta descrive. \
                 Non è stato installato nulla, e non va installato: o è stato \
                 sostituito, o è arrivato rovinato.",
            ),
            Self::Broken(ArtifactFlaw::NotSigned { reason }) => format!(
                "Il file corrisponde a quanto dichiarato, ma la firma non regge: \
                 {reason}\n\nUn file che corrisponde a un documento non è per questo un \
                 file di cui fidarsi. Il documento dice che cosa aspettarsi; la firma dice \
                 chi lo ha prodotto. Senza la firma, non si installa."
            ),
            Self::Broken(ArtifactFlaw::PublisherNotRecognised) => String::from(
                "Il file corrisponde a quanto dichiarato ed è firmato, ma non da un \
                 editore che questo programma riconosce come proprio. Una firma valida \
                 dice chi ha prodotto il file, non che sia un aggiornamento di NEXUM/97. \
                 L'identità del certificato di NEXUM/97 non è ancora stata fissata: \
                 finché non lo è, nessun file viene consegnato all'installatore.",
            ),
        }
    }

    /// Se questo verdetto è **la prova di un tentativo**, e non una cosa che non
    /// si è potuta dire.
    ///
    /// # Perché la distinzione conta
    ///
    /// ADR-0037 vuole che un file che non supera la verifica **venga tolto**. Ma
    /// «non c'è», «non si è potuto leggere» e «non l'ho nemmeno guardato» non
    /// sono fallimenti del file: sono fallimenti dell'osservazione, e togliere un
    /// file per un'osservazione non riuscita cancellerebbe qualcosa di cui non si
    /// sa nulla.
    #[must_use]
    pub const fn e_un_tentativo(&self) -> bool {
        matches!(
            self,
            Self::Broken(
                ArtifactFlaw::SizeChanged { .. }
                    | ArtifactFlaw::DigestMismatch
                    | ArtifactFlaw::NotSigned { .. }
                    | ArtifactFlaw::PublisherNotRecognised
            )
        )
    }

    /// Che cosa finisce nel registro degli atti.
    ///
    /// **Mai l'impronta, mai il percorso, mai il nome di chi ha firmato**:
    /// l'ultimo arriva dal file, e il file arriva da fuori.
    #[must_use]
    pub const fn audit_detail(&self) -> &'static str {
        match self {
            Self::Verified { .. } => "verificato: impronta e firma",
            Self::Broken(ArtifactFlaw::Missing) => "nessun file da verificare",
            Self::Broken(ArtifactFlaw::UnreadableVersion) => "versione non leggibile nel documento",
            Self::Broken(ArtifactFlaw::SizeChanged { .. }) => {
                "dimensione diversa da quella dichiarata"
            }
            Self::Broken(ArtifactFlaw::TooLarge { .. }) => "file oltre il limite di lettura",
            Self::Broken(ArtifactFlaw::Unreadable) => "file non leggibile",
            Self::Broken(ArtifactFlaw::DigestMismatch) => "impronta diversa da quella dichiarata",
            Self::Broken(ArtifactFlaw::NotSigned { .. }) => "firma assente o non attendibile",
            Self::Broken(ArtifactFlaw::PublisherNotRecognised) => {
                "firma attendibile, editore non riconosciuto"
            }
        }
    }
}

/// Le voci della cartella di staging che non sono il file verificato
/// (FINAL-REVIEW-01, FR-026).
fn staging_extraneous_entries(cartella: &std::path::Path) -> ServiceResult<Vec<String>> {
    let voci = std::fs::read_dir(cartella).map_err(|errore| ServiceError::UpdateNotFetched {
        reason: format!("la cartella dell'aggiornamento non si legge: {errore}"),
    })?;
    let mut estranei = Vec::new();
    for voce in voci {
        let voce = voce.map_err(|errore| ServiceError::UpdateNotFetched {
            reason: format!("la cartella dell'aggiornamento non si legge: {errore}"),
        })?;
        let nome = voce.file_name().to_string_lossy().into_owned();
        if nome != NOME_ARTEFATTO {
            estranei.push(nome);
        }
    }
    Ok(estranei)
}

/// Gli editori di cui questo prodotto accetta un aggiornamento: il soggetto
/// del certificato di firma, esatto.
///
/// **Vuoto, e deliberatamente** (FINAL-REVIEW-01, FR-004, DEC-379): il
/// certificato di NEXUM/97 non esiste ancora (HVQ-07). Quando esisterà, qui
/// andrà il suo soggetto, e accanto la lettura del firmatario dal file
/// verificato (`WTHelperProvDataFromStateData`), che oggi non c'è perché non
/// c'è nulla da riconoscere.
const EDITORI_RICONOSCIUTI: &[&str] = &[];

/// Vero se il firmatario del file è uno degli editori riconosciuti.
///
/// Con l'elenco vuoto è sempre falso; con un elenco non vuoto è falso anche
/// lui, finché la lettura del firmatario non è costruita: un editore che non
/// si sa leggere non si può riconoscere, e la risposta prudente è no.
const fn editore_riconosciuto(riconosciuti: &[&str]) -> bool {
    let _ = riconosciuti;
    false
}

/// Il nome del file che scende, e non è eseguibile.
///
/// Niente `.exe`, niente `.msi`. Non è sicurezza — chi ha la macchina rinomina
/// un file — è un **impedimento all'errore**: un doppio clic in una cartella, un
/// antivirus che decide di «provarlo», uno script dell'ufficio che cerca gli
/// installatori. Finché la verifica di UPDATE-04 non esiste, quel file è
/// soltanto byte arrivati dalla rete, e la sua estensione dice la verità.
const NOME_ARTEFATTO: &str = "aggiornamento.scaricato";

/// Quanto spazio si vuole oltre alla dimensione dichiarata, in byte.
///
/// Un disco riempito **esattamente** è un disco pieno, e ciò che smette di
/// funzionare non è lo scaricamento: è l'archivio, che sta sullo stesso volume.
const MARGINE_DISCO: u64 = 256 * 1024 * 1024;

/// Un artefatto sceso su disco, **non verificato**.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StagedArtifact {
    /// Dove si trova.
    pub path: std::path::PathBuf,
    /// Quanti byte sono arrivati.
    pub bytes: u64,
}

/// La cartella in cui scende l'artefatto.
///
/// # Errori
///
/// Se la cartella dati non è determinabile o non si crea.
fn staging_directory() -> ServiceResult<std::path::PathBuf> {
    let cartella = crate::data_directory::application_directory()?.join("aggiornamenti");
    if !cartella.exists() {
        std::fs::create_dir_all(&cartella).map_err(|_| ServiceError::UpdateNotFetched {
            reason: String::from("la cartella degli aggiornamenti non si crea"),
        })?;
    }
    Ok(cartella)
}

/// Percorre la catena su un file e un manifesto già in mano.
///
/// # Perché è una funzione libera
///
/// Non tocca l'archivio e non tocca la rete: prende un percorso e un manifesto,
/// e restituisce un verdetto. Così si può provare **tutta la catena** senza
/// aprire un archivio e senza uscire, che è l'unico modo in cui una catena di
/// verifica si prova davvero.
fn percorri_la_catena(percorso: &std::path::Path, manifesto: &UpdateManifest) -> ArtifactVerdict {
    // 0. A CHE COSA PORTA? Un verdetto su un file è un verdetto su
    //    «l'aggiornamento alla versione X»: senza X non c'è niente da dire,
    //    nemmeno se i byte fossero giusti.
    let Some(versione) = Version::parse(&manifesto.version) else {
        return ArtifactVerdict::Broken(ArtifactFlaw::UnreadableVersion);
    };

    // 1. C'è un file? Non averlo NON è un guasto: può non essere mai stato
    //    scaricato, o un antivirus può averlo tolto.
    let Ok(dati) = std::fs::metadata(percorso) else {
        return ArtifactVerdict::Broken(ArtifactFlaw::Missing);
    };
    if !dati.is_file() {
        return ArtifactVerdict::Broken(ArtifactFlaw::Missing);
    }
    let dimensione = dati.len();

    // 2. Il tetto vale anche in lettura: un file cresciuto dopo lo scaricamento
    //    non si legge senza freno.
    if dimensione > lisi_platform::https::MAX_ARTIFACT_BYTES {
        return ArtifactVerdict::Broken(ArtifactFlaw::TooLarge {
            max: lisi_platform::https::MAX_ARTIFACT_BYTES,
        });
    }

    // 3. È grande come dichiarato? È la prima cosa che cambia se il file è stato
    //    toccato, e costa una lettura di metadati.
    if dimensione != manifesto.artifact_bytes {
        return ArtifactVerdict::Broken(ArtifactFlaw::SizeChanged {
            found: dimensione,
            declared: manifesto.artifact_bytes,
        });
    }

    // 4. UNA SOLA APERTURA, E TUTTI GLI ANELLI LA USANO (ADR-0070).
    //
    //    Aprire una volta per l'impronta e una seconda per la firma lascerebbe
    //    una finestra FRA LE DUE, ed è esattamente il difetto che questa
    //    milestone chiude, spostato di qualche riga.
    //
    //    L'apertura nega la condivisione in SCRITTURA e lascia quella in
    //    lettura: finché è viva nessuno può cambiare quei byte — nemmeno il
    //    proprietario — e l'installatore, che è un altro processo, potrà
    //    comunque leggerli quando sarà il momento (UPDATE-07).
    let Ok(file) = apri_senza_scrittori(percorso) else {
        return ArtifactVerdict::Broken(ArtifactFlaw::Unreadable);
    };

    // L'IMPRONTA SI CALCOLA SU CIO' CHE E' SUL DISCO, non sul flusso che lo ha
    // prodotto: fra il transito e il disco c'è il sistema, e ciò che verrà
    // eseguito è il file.
    let Ok(impronta) = lisi_core::digest::Sha256Digest::of_reader(std::io::BufReader::new(&file))
    else {
        return ArtifactVerdict::Broken(ArtifactFlaw::Unreadable);
    };
    let Ok(dichiarata) = lisi_core::digest::Sha256Digest::from_hex(&manifesto.artifact_sha256)
    else {
        return ArtifactVerdict::Broken(ArtifactFlaw::DigestMismatch);
    };
    if impronta != dichiarata {
        return ArtifactVerdict::Broken(ArtifactFlaw::DigestMismatch);
    }

    // 5. E SOLO ADESSO la firma, che è l'unica cosa che non viene dal documento.
    //
    //    Una firma che non si è potuta stabilire NON è una firma valida:
    //    `is_trusted` è falso per ogni caso che non sia «firmato e attendibile».
    let firma = lisi_platform::signature::verify_open_file(percorso, &file);
    if !firma.is_trusted() {
        return ArtifactVerdict::Broken(ArtifactFlaw::NotSigned {
            reason: firma.operator_message(),
        });
    }

    // 6. E CHI HA FIRMATO (FINAL-REVIEW-01, FR-004).
    //
    //    «Attendibile» vuol dire firmato da chiunque abbia un certificato che
    //    Windows riconosce. Fino al 2026-10-03 bastava: chi controllava il
    //    documento all'origine poteva far eseguire, con un clic, un qualunque
    //    eseguibile firmato da altri. L'editore si confronta con l'elenco
    //    compilato qui sotto, che è VUOTO finché l'identità del certificato di
    //    NEXUM/97 non è fissata (HVQ-07): fino ad allora ogni file è rifiutato,
    //    e la consegna all'installatore resta chiusa per una ragione dichiarata.
    if !editore_riconosciuto(EDITORI_RICONOSCIUTI) {
        return ArtifactVerdict::Broken(ArtifactFlaw::PublisherNotRecognised);
    }

    // L'APERTURA ESCE INSIEME AL VERDETTO. Chi userà il file riceverà questa, e
    // non un nome: un nome si ri-risolve, un'apertura no.
    ArtifactVerdict::Verified {
        bytes: dimensione,
        version: versione,
        file: std::sync::Arc::new(file),
    }
}

/// Avvia l'installatore sul file **che è stato verificato**.
///
/// # L'unico punto di questo prodotto che esegue qualcosa arrivato dalla rete
///
/// Prende il **file aperto e verificato**, non un percorso: non c'è modo di
/// invocarla su un file diverso, perché non ha modo di nominarne un altro
/// (ADR-0070, ADR-0072). L'apertura resta viva per tutta la durata di questa
/// funzione, quindi nessuno può sostituire quei byte **mentre Windows li sta
/// caricando**.
///
/// # Perché il file non viene rinominato
///
/// `CreateProcess` — che è ciò che `Command` usa — carica un'immagine eseguibile
/// **indipendentemente dall'estensione**. Rinominarlo in `.exe` non servirebbe a
/// avviarlo e servirebbe soltanto a renderlo cliccabile in una cartella, che è
/// esattamente ciò che ADR-0068 ha deciso di non fare.
///
/// # Errori
///
/// Se il processo non parte. **Non** attende che finisca: l'installatore vive più
/// a lungo di chi lo ha avviato, ed è il motivo per cui chi chiama si chiude
/// subito dopo.
fn avvia_l_installatore(file: &std::sync::Arc<std::fs::File>) -> ServiceResult<()> {
    let percorso = staging_directory()?.join(NOME_ARTEFATTO);

    // L'APERTURA VERIFICATA E' VIVA IN QUESTO ISTANTE, e non per caso: la
    // possiede il verdetto, che vive nel chiamante fino a DOPO questa chiamata.
    // Fra il verdetto e `CreateProcess` nessuno ha potuto toccare quei byte,
    // ed e' esattamente cio' per cui ADR-0070 esisteva.
    //
    // Il parametro non si usa: serve a rendere IMPOSSIBILE chiamare questa
    // funzione senza avere in mano il file verificato.
    let _ = file;

    // NESSUN ALTRO FILE ACCANTO (FINAL-REVIEW-01, FR-026).
    //
    // `Command::new` riceve un nome, e la libreria standard di Rust su
    // Windows, per un percorso senza `.exe`, prova PRIMA `<nome>.exe`: un
    // `aggiornamento.scaricato.exe` messo accanto dopo lo scaricamento sarebbe
    // stato avviato al posto del file verificato. La cartella di staging
    // contiene un file solo, quello: se contiene altro, non si avvia niente.
    let cartella = staging_directory()?;
    let estranei = staging_extraneous_entries(&cartella)?;
    if !estranei.is_empty() {
        return Err(ServiceError::UpdateNotFetched {
            reason: format!(
                "nella cartella dell'aggiornamento ci sono {} file oltre a quello \
                 verificato: non si avvia nulla. Togliere il file scaricato e \
                 riscaricarlo.",
                estranei.len()
            ),
        });
    }

    let esito = std::process::Command::new(&percorso).spawn();

    match esito {
        Ok(_) => Ok(()),
        Err(errore) => Err(ServiceError::UpdateNotFetched {
            reason: format!("l'installatore non è partito: {errore}"),
        }),
    }
}

/// Apre un file negando la condivisione in **scrittura**, non in lettura.
///
/// # Perché non si nega tutto
///
/// Negare anche la lettura sarebbe più semplice da spiegare e renderebbe
/// impossibile ciò che viene dopo: l'installatore di Windows è un **processo
/// diverso**, e per installare deve poter aprire il file. Chi arrivasse a
/// UPDATE-07 si troverebbe davanti alla scelta fra «non funziona» e
/// «indeboliamo questa decisione», che è il modo in cui le decisioni di
/// sicurezza muoiono.
///
/// Ciò che va impedito è la **modifica**, non la lettura: un lettore in più non
/// cambia i byte, e la cancellazione è negata insieme alla scrittura (ADR-0070).
///
/// # Errori
///
/// Restituisce l'errore di apertura. **Un file che qualcun altro tiene aperto in
/// scrittura non si apre**, ed è la risposta giusta: significa che in questo
/// momento qualcuno lo sta cambiando.
fn apri_senza_scrittori(percorso: &std::path::Path) -> std::io::Result<std::fs::File> {
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;

        // Solo `FILE_SHARE_READ`: niente scrittura, niente cancellazione.
        const SOLO_LETTURA_CONDIVISA: u32 = 1;

        std::fs::OpenOptions::new()
            .read(true)
            .share_mode(SOLO_LETTURA_CONDIVISA)
            .open(percorso)
    }
    #[cfg(not(windows))]
    {
        // Fuori da Windows la condivisione non si nega all'apertura, e questo
        // prodotto è per Windows: si apre e basta, senza fingere una protezione
        // che il sistema non darebbe.
        std::fs::File::open(percorso)
    }
}

/// Toglie ciò che c'era prima di scaricare.
///
/// # Perché prima e non dopo
///
/// Un file rimasto da un tentativo precedente è un file che qualcuno potrebbe
/// scambiare per quello nuovo. Due artefatti nella stessa cartella sono due
/// risposte alla domanda «quale aggiornamento è stato scaricato» (ADR-0068).
///
/// # Errori
///
/// Se ciò che c'era non si toglie: scaricare accanto sarebbe peggio.
fn svuota_staging(cartella: &std::path::Path) -> ServiceResult<()> {
    let Ok(voci) = std::fs::read_dir(cartella) else {
        return Ok(());
    };
    for voce in voci.flatten() {
        let percorso = voce.path();
        if percorso.is_file() && std::fs::remove_file(&percorso).is_err() {
            return Err(ServiceError::UpdateNotFetched {
                reason: String::from(
                    "quello che era stato scaricato prima non si toglie, e scaricare \
                     accanto lascerebbe due file",
                ),
            });
        }
    }
    Ok(())
}

/// Verifica che ci sia spazio prima di cominciare.
///
/// # Perché «non lo so» non è «non ce n'è»
///
/// Se la misura non riesce **si prova lo stesso**: confondere l'assenza di
/// misura con l'assenza di spazio farebbe comparire un disco pieno su ogni
/// postazione in cui la misura non riesce (ADR-0054).
///
/// # Errori
///
/// Se lo spazio è misurato e non basta.
fn controlla_spazio(cartella: &std::path::Path, dichiarati: u64) -> ServiceResult<()> {
    let servono = dichiarati.saturating_add(MARGINE_DISCO);
    if let lisi_platform::disk_space::DiskSpace::Measured {
        available_to_user, ..
    } = lisi_platform::disk_space::for_directory(cartella)
        && available_to_user < servono
    {
        return Err(ServiceError::UpdateNotFetched {
            reason: String::from(
                "sul disco non c'è spazio per il file dell'aggiornamento, e \
                 riempire il volume fermerebbe l'archivio",
            ),
        });
    }

    Ok(())
}

#[cfg(test)]
mod tests {

    use lisi_core::Timestamp;
    use lisi_core::text::Actor;

    use lisi_core::role::{OperatingMode, RestrictedAction};

    use lisi_core::Sha256Digest;
    use lisi_platform::DetachedVerdict;

    use super::{
        Channel, SIGNATURE_SUFFIX, ServiceError, TEST_SIGNERS, UpdateReviewService, station_state,
    };
    use crate::sources::open_in_memory_database;
    use crate::update::{MAX_MANIFEST_BYTES, UpdateDecision, UpdateRefusal};

    /// Il certificato del produttore nelle prove: bastano dei byte, perché la
    /// verifica è finta.
    const PRODUTTORE: &[u8] = b"certificato del produttore di prova";

    /// La firma finta: dice di quale contenuto è.
    fn firma_di(contenuto: &[u8]) -> Vec<u8> {
        let mut firma = b"firma:".to_vec();
        firma.extend_from_slice(Sha256Digest::of_bytes(contenuto).as_str().as_bytes());
        firma
    }

    fn verifica_finta(contenuto: &[u8], firma: &[u8]) -> DetachedVerdict {
        if firma == firma_di(contenuto).as_slice() {
            DetachedVerdict::Verified {
                signer_certificate: PRODUTTORE.to_vec(),
            }
        } else {
            DetachedVerdict::ContentMismatch
        }
    }

    fn impronta_del_produttore() -> String {
        Sha256Digest::of_bytes(PRODUTTORE).as_str().to_owned()
    }

    /// Il servizio senza firmatari: com'è di fabbrica.
    fn servizio_di_fabbrica() -> UpdateReviewService {
        let Ok(database) = open_in_memory_database() else {
            panic!("l'archivio di prova deve potersi aprire");
        };
        UpdateReviewService::with_verifier(database, verifica_finta)
    }

    /// Il servizio con il produttore delle prove fra i firmatari ammessi.
    fn servizio() -> UpdateReviewService {
        let mut servizio = servizio_di_fabbrica();
        let Ok(()) = servizio.admit_update_signer(
            &impronta_del_produttore(),
            "Produttore di prova",
            OperatingMode::Administrator,
            &attore(),
            adesso(),
        ) else {
            panic!("il firmatario delle prove deve potersi ammettere");
        };
        servizio
    }

    fn attore() -> Actor {
        let Ok(actor) = Actor::try_new("operatore.prova") else {
            panic!("l'attore di prova deve essere valido");
        };
        actor
    }

    fn adesso() -> Timestamp {
        Timestamp::from_millis(1_700_000_000_000)
    }

    /// Scrive il file e, accanto, la sua firma finta: un manifesto delle prove
    /// è firmato dal produttore, salvo nelle prove della firma (ADR-0183).
    fn scrivi(cartella: &std::path::Path, nome: &str, contenuto: &[u8]) -> std::path::PathBuf {
        let percorso = cartella.join(nome);
        let firma = cartella.join(format!("{nome}{SIGNATURE_SUFFIX}"));
        let (Ok(()), Ok(())) = (
            std::fs::write(&percorso, contenuto),
            std::fs::write(firma, firma_di(contenuto)),
        ) else {
            panic!("il file di prova deve potersi scrivere");
        };
        percorso
    }

    fn rifiuto(servizio: &UpdateReviewService, percorso: &std::path::Path) -> UpdateRefusal {
        let Ok(UpdateDecision::Refused(rifiuto)) = servizio.review(percorso, &attore(), adesso())
        else {
            panic!("il manifesto va rifiutato");
        };
        rifiuto
    }

    /// **Senza firma valida di un firmatario ammesso, nessun aggiornamento**
    /// (ADR-0183, decisioni 2, 3 e 5): di fabbrica nessuno è ammesso; un
    /// manifesto senza firma, con una firma d'altro contenuto o di un
    /// certificato non ammesso si rifiuta, e il rifiuto dice quale controllo
    /// è fallito. Con la firma giusta l'offerta dice che il manifesto è
    /// firmato.
    #[test]
    fn senza_firma_valida_di_un_ammesso_nessun_aggiornamento() {
        let Ok(cartella) = tempfile::tempdir() else {
            panic!("la cartella di prova deve crearsi");
        };
        let percorso = scrivi(
            cartella.path(),
            "manifesto.json",
            manifesto_valido("99.0.0").as_bytes(),
        );

        assert_eq!(
            rifiuto(&servizio_di_fabbrica(), &percorso),
            UpdateRefusal::NoSignerAdmitted
        );

        let servizio = servizio();
        let Ok(UpdateDecision::Offer {
            manifest_signed, ..
        }) = servizio.review(&percorso, &attore(), adesso())
        else {
            panic!("il manifesto firmato dal produttore si accetta");
        };
        assert!(manifest_signed);

        let firma = cartella
            .path()
            .join(format!("manifesto.json{SIGNATURE_SUFFIX}"));
        let Ok(()) = std::fs::write(&firma, firma_di(b"un altro manifesto")) else {
            panic!("la firma si riscrive");
        };
        assert!(matches!(
            rifiuto(&servizio, &percorso),
            UpdateRefusal::SignatureNotValid { .. }
        ));

        let Ok(()) = std::fs::remove_file(&firma) else {
            panic!("la firma si toglie");
        };
        assert_eq!(rifiuto(&servizio, &percorso), UpdateRefusal::Unsigned);
        assert!(
            UpdateDecision::Refused(UpdateRefusal::Unsigned)
                .operator_message()
                .contains("firma")
        );
    }

    /// **Un firmatario ritirato non firma più, e lo si dice** (ADR-0045,
    /// requisito 4): resta nell'elenco, e la sua firma si rifiuta con il suo
    /// nome. Un certificato mai ammesso si rifiuta con la sua impronta.
    #[test]
    fn un_firmatario_ritirato_non_firma_piu_e_lo_si_dice() {
        let Ok(cartella) = tempfile::tempdir() else {
            panic!("la cartella di prova deve crearsi");
        };
        let percorso = scrivi(
            cartella.path(),
            "manifesto.json",
            manifesto_valido("99.0.0").as_bytes(),
        );
        let mut servizio = servizio();
        let Ok(()) = servizio.admit_update_signer(
            &"c".repeat(64),
            "Chiave nuova",
            OperatingMode::Administrator,
            &attore(),
            adesso(),
        ) else {
            panic!("la chiave nuova si ammette insieme alla vecchia");
        };
        let Ok(()) = servizio.retire_update_signer(
            &impronta_del_produttore().to_ascii_uppercase(),
            OperatingMode::Administrator,
            &attore(),
            adesso(),
        ) else {
            panic!("la chiave vecchia si ritira, scritta anche in maiuscolo");
        };
        assert_eq!(
            rifiuto(&servizio, &percorso),
            UpdateRefusal::SignerRetired {
                name: String::from("Produttore di prova")
            }
        );
        let Ok(firmatari) = servizio.update_signers() else {
            panic!("i firmatari si leggono");
        };
        assert_eq!(firmatari.len(), 2, "il ritirato resta");

        let mut altro = servizio_di_fabbrica();
        let Ok(()) = altro.admit_update_signer(
            &"d".repeat(64),
            "Un altro produttore",
            OperatingMode::Administrator,
            &attore(),
            adesso(),
        ) else {
            panic!("un firmatario si ammette");
        };
        assert_eq!(
            rifiuto(&altro, &percorso),
            UpdateRefusal::SignerNotAdmitted {
                sha256: impronta_del_produttore()
            }
        );
    }

    /// **I firmatari li sceglie l'amministratore, e non quelli delle prove**
    /// (ADR-0183, decisioni 4 e 6): l'operatore riceve il rifiuto; il
    /// certificato delle prove, un'impronta storta, un nome vuoto, un doppione
    /// e un ritiro di chi non c'è si rifiutano, e niente si scrive.
    #[test]
    fn i_firmatari_li_sceglie_l_amministratore_e_non_quelli_delle_prove() {
        let mut servizio = servizio_di_fabbrica();
        assert!(matches!(
            servizio.admit_update_signer(
                &impronta_del_produttore(),
                "Produttore",
                OperatingMode::Operator,
                &attore(),
                adesso()
            ),
            Err(ServiceError::ActionReservedToAdministrator {
                action: RestrictedAction::ChooseUpdateChannel
            })
        ));
        for (impronta, nome) in [
            (TEST_SIGNERS[0].to_owned(), "Prova"),
            (TEST_SIGNERS[1].to_ascii_uppercase(), "Prova"),
            (String::from("non è un'impronta"), "Produttore"),
            (impronta_del_produttore(), "  "),
            (impronta_del_produttore(), "Produt\ntore"),
        ] {
            assert!(
                matches!(
                    servizio.admit_update_signer(
                        &impronta,
                        nome,
                        OperatingMode::Administrator,
                        &attore(),
                        adesso()
                    ),
                    Err(ServiceError::UpdateSignerRefused { .. })
                ),
                "{impronta} «{nome}» va rifiutato"
            );
        }
        assert_eq!(servizio.update_signers().ok(), Some(Vec::new()));

        let Ok(()) = servizio.admit_update_signer(
            &impronta_del_produttore(),
            "Produttore",
            OperatingMode::Administrator,
            &attore(),
            adesso(),
        ) else {
            panic!("l'amministratore ammette");
        };
        assert!(matches!(
            servizio.admit_update_signer(
                &impronta_del_produttore(),
                "Di nuovo",
                OperatingMode::Administrator,
                &attore(),
                adesso()
            ),
            Err(ServiceError::UpdateSignerRefused { .. })
        ));
        assert!(matches!(
            servizio.retire_update_signer(
                &"e".repeat(64),
                OperatingMode::Administrator,
                &attore(),
                adesso()
            ),
            Err(ServiceError::UpdateSignerRefused { .. })
        ));
        assert!(matches!(
            servizio.retire_update_signer(
                &impronta_del_produttore(),
                OperatingMode::Operator,
                &attore(),
                adesso()
            ),
            Err(ServiceError::ActionReservedToAdministrator { .. })
        ));
    }

    fn manifesto_valido(versione: &str) -> String {
        let impronta = "a".repeat(64);
        format!(
            "{{\
             \"schema\": 1,\
             \"product\": \"nexum97-telegram-monitor\",\
             \"version\": \"{versione}\",\
             \"channel\": \"stable\",\
             \"published\": \"2026-09-01\",\
             \"architecture\": \"x86_64\",\
             \"minimum_windows\": \"10.0.19045\",\
             \"minimum_product\": \"0.0.1\",\
             \"artifact_url\": \"https://esempio.test/nexum97.exe\",\
             \"artifact_bytes\": 26000000,\
             \"artifact_sha256\": \"{impronta}\",\
             \"notes\": \"Correzioni.\"\
             }}"
        )
    }

    /// **Un manifesto valido produce una decisione, e resta traccia.**
    #[test]
    fn un_manifesto_leggibile_viene_esaminato_e_registrato() {
        let Ok(cartella) = tempfile::tempdir() else {
            panic!("la cartella temporanea deve potersi creare");
        };
        let percorso = scrivi(
            cartella.path(),
            "manifesto.json",
            manifesto_valido("99.0.0").as_bytes(),
        );

        let servizio = servizio();
        let Ok(decisione) = servizio.review(&percorso, &attore(), adesso()) else {
            panic!("l'esame deve riuscire");
        };
        assert!(
            matches!(decisione, UpdateDecision::Offer { .. }),
            "una versione molto piu' recente deve essere offerta: {decisione:?}"
        );

        let Ok(voci) = servizio.database().audit_entries() else {
            panic!("l'audit deve potersi leggere");
        };
        assert!(
            voci.iter()
                .any(|voce| voce.action.as_str() == "aggiornamento_esaminato"),
            "l'esame di un aggiornamento deve lasciare traccia"
        );
    }

    /// **Nell'audit non finisce il contenuto del manifesto.**
    ///
    /// E' dato non fidato: un audit che lo trascrivesse porterebbe testo altrui
    /// dentro il registro che deve restare affidabile.
    #[test]
    fn l_audit_registra_l_esito_e_non_il_manifesto() {
        let Ok(cartella) = tempfile::tempdir() else {
            panic!("la cartella temporanea deve potersi creare");
        };
        let percorso = scrivi(
            cartella.path(),
            "manifesto.json",
            manifesto_valido("99.0.0").as_bytes(),
        );

        let servizio = servizio();
        let Ok(_) = servizio.review(&percorso, &attore(), adesso()) else {
            panic!("l'esame deve riuscire");
        };
        let Ok(voci) = servizio.database().audit_entries() else {
            panic!("l'audit deve potersi leggere");
        };
        let Some(voce) = voci
            .iter()
            .find(|voce| voce.action.as_str() == "aggiornamento_esaminato")
        else {
            panic!("la voce deve esserci");
        };
        let Some(dettaglio) = voce.detail.as_ref() else {
            panic!("la voce deve portare un dettaglio");
        };
        for proibito in ["https://", "esempio.test", "nexum97.exe", "aaaa"] {
            assert!(
                !dettaglio.as_str().contains(proibito),
                "l'audit trascrive il manifesto: «{}»",
                dettaglio.as_str()
            );
        }
    }

    /// **Un file enorme non viene caricato per intero prima di essere rifiutato.**
    ///
    /// Il limite di `decide` agisce su un documento gia' in memoria. Qui la
    /// lettura si ferma da sola: se il rifiuto arrivasse dopo, un file scelto per
    /// sbaglio — o non per sbaglio — verrebbe caricato tutto.
    #[test]
    fn un_file_enorme_si_ferma_alla_lettura() {
        let Ok(cartella) = tempfile::tempdir() else {
            panic!("la cartella temporanea deve potersi creare");
        };
        let gonfio = vec![b'a'; MAX_MANIFEST_BYTES * 4];
        let percorso = scrivi(cartella.path(), "gonfio.json", &gonfio);

        let Ok(decisione) = servizio().review(&percorso, &attore(), adesso()) else {
            panic!("l'esame deve concludersi");
        };
        let UpdateDecision::Refused(UpdateRefusal::TooLarge { bytes }) = decisione else {
            panic!("un file enorme deve essere rifiutato per la dimensione: {decisione:?}");
        };
        assert_eq!(
            bytes,
            MAX_MANIFEST_BYTES + 1,
            "la lettura non si e' fermata al limite: ha caricato {bytes} byte"
        );
    }

    /// **Un file che non e' testo si rifiuta senza tentare di interpretarlo.**
    #[test]
    fn un_file_che_non_e_testo_si_rifiuta() {
        let Ok(cartella) = tempfile::tempdir() else {
            panic!("la cartella temporanea deve potersi creare");
        };
        let percorso = scrivi(cartella.path(), "immagine.png", &[0xFF, 0xD8, 0xFF, 0x00]);

        let Ok(decisione) = servizio().review(&percorso, &attore(), adesso()) else {
            panic!("l'esame deve concludersi");
        };
        assert!(
            matches!(
                decisione,
                UpdateDecision::Refused(UpdateRefusal::Malformed { .. })
            ),
            "un file binario deve essere rifiutato: {decisione:?}"
        );
    }

    /// **Un file che non esiste lo dice invece di tacere.**
    #[test]
    fn un_file_assente_lo_dice_invece_di_tacere() {
        let inesistente = std::path::Path::new("C:/questo/manifesto/non/esiste.json");
        let Ok(decisione) = servizio().review(inesistente, &attore(), adesso()) else {
            panic!("l'esame deve concludersi");
        };
        let UpdateDecision::Refused(UpdateRefusal::Malformed { reason }) = decisione else {
            panic!("un file assente deve produrre un rifiuto spiegato: {decisione:?}");
        };
        assert!(
            reason.contains("non si apre"),
            "il rifiuto non dice che il file non si apre: «{reason}»"
        );
    }

    /// **Il canale si cambia solo da chi amministra.**
    ///
    /// Non e' un fastidio burocratico: il criterio di ADR-0015 e' uno solo — cio'
    /// che ha effetto oltre la propria sessione richiede l'amministratore — e il
    /// canale decide quando OGNI operatore ricevera' il programma nuovo.
    #[test]
    fn in_modalita_operatore_il_canale_non_si_cambia() {
        let servizio = servizio();
        let esito =
            servizio.choose_channel(Channel::Pilot, OperatingMode::Operator, &attore(), adesso());

        let Err(ServiceError::ActionReservedToAdministrator { action }) = esito else {
            panic!("in modalita' operatore il canale non deve potersi cambiare: {esito:?}");
        };
        assert_eq!(action, RestrictedAction::ChooseUpdateChannel);
        assert_eq!(
            servizio.channel().ok(),
            Some(Channel::Stable),
            "un rifiuto non deve lasciare il canale cambiato a meta'"
        );
    }

    /// **Il canale scelto resta scritto, e nel registro c'e' chi l'ha scelto.**
    ///
    /// La domanda a cui questa riga dovra' rispondere fra un anno e' «da quando
    /// questa postazione riceve prima, e chi l'ha deciso».
    #[test]
    fn il_canale_scelto_resta_scritto_e_verbalizzato() {
        let servizio = servizio();
        let Ok(()) = servizio.choose_channel(
            Channel::Pilot,
            OperatingMode::Administrator,
            &attore(),
            adesso(),
        ) else {
            panic!("in modalita' amministratore il canale deve potersi cambiare");
        };

        assert_eq!(servizio.channel().ok(), Some(Channel::Pilot));

        let Ok(righe) = servizio.database().audit_entries() else {
            panic!("il registro deve potersi leggere");
        };
        let scelta = righe
            .iter()
            .find(|riga| riga.action.as_str() == "canale_aggiornamenti_scelto");
        let Some(scelta) = scelta else {
            panic!("la scelta del canale deve lasciare una riga nel registro");
        };
        assert_eq!(scelta.actor.as_str(), "operatore.prova");
        assert_eq!(
            scelta.detail.as_ref().map(|dettaglio| dettaglio.as_str()),
            Some("pilot"),
            "il registro deve dire QUALE canale e' stato scelto"
        );
    }

    /// **Il canale scelto arriva davvero fino alla decisione.**
    ///
    /// E' la prova che il canale non e' decorativo: su una postazione pilota un
    /// manifesto pilota viene esaminato invece di essere respinto, e un manifesto
    /// stabile viene respinto invece di essere esaminato. Senza questa prova, il
    /// canale potrebbe restare scritto in archivio e non arrivare mai a contare.
    #[test]
    fn il_canale_scelto_decide_quale_manifesto_riguarda_la_postazione() {
        let Ok(cartella) = tempfile::tempdir() else {
            panic!("la cartella temporanea deve potersi creare");
        };
        let servizio = servizio();
        let Ok(()) = servizio.choose_channel(
            Channel::Pilot,
            OperatingMode::Administrator,
            &attore(),
            adesso(),
        ) else {
            panic!("il canale deve potersi cambiare");
        };

        let pilota = manifesto_valido("99.0.0").replace("\"stable\"", "\"pilot\"");
        let percorso = scrivi(cartella.path(), "pilota.json", pilota.as_bytes());
        let Ok(decisione) = servizio.review(&percorso, &attore(), adesso()) else {
            panic!("l'esame deve concludersi");
        };
        assert!(
            matches!(decisione, UpdateDecision::Offer { .. }),
            "su una postazione pilota un manifesto pilota va esaminato: {decisione:?}"
        );

        let stabile = scrivi(
            cartella.path(),
            "stabile.json",
            manifesto_valido("99.0.0").as_bytes(),
        );
        let Ok(decisione) = servizio.review(&stabile, &attore(), adesso()) else {
            panic!("l'esame deve concludersi");
        };
        assert!(
            matches!(
                decisione,
                UpdateDecision::Refused(UpdateRefusal::WrongChannel { .. })
            ),
            "su una postazione pilota un manifesto stabile va respinto: {decisione:?}"
        );
    }

    /// **Senza un'origine non si contatta nessuno, e non e' un guasto.**
    ///
    /// Di fabbrica l'origine non c'e', ed e' la verita': nulla e' pubblicato su
    /// alcun canale finche' manca il certificato di firma. Un indirizzo
    /// predefinito scritto nel prodotto sarebbe un indirizzo che un giorno
    /// qualcuno contatta.
    #[test]
    fn senza_un_origine_non_si_contatta_nessuno() {
        let servizio = servizio();
        assert_eq!(servizio.origin().ok(), Some(None));

        let esito = servizio.fetch_and_review(&attore(), adesso());
        assert!(
            matches!(esito, Err(ServiceError::UpdateOriginMissing)),
            "senza origine non si deve uscire in rete: {esito:?}"
        );

        let Ok(righe) = servizio.database().audit_entries() else {
            panic!("il registro deve potersi leggere");
        };
        assert!(
            !righe
                .iter()
                .any(|riga| riga.action.as_str() == "aggiornamento_scaricato"),
            "senza origine non deve risultare alcun passaggio in rete"
        );
    }

    /// Un manifesto vero, con impronta e dimensione di un contenuto scelto.
    fn manifesto_per(contenuto: &[u8]) -> super::UpdateManifest {
        let Ok(mut manifesto) =
            serde_json::from_str::<super::UpdateManifest>(&manifesto_valido("99.0.0"))
        else {
            panic!("il manifesto di prova deve interpretarsi");
        };
        manifesto.artifact_bytes = contenuto.len() as u64;
        manifesto.artifact_sha256 = lisi_core::digest::Sha256Digest::of_bytes(contenuto)
            .as_str()
            .to_string();
        manifesto
    }

    /// Scrive un artefatto di prova e restituisce il percorso.
    fn artefatto(cartella: &std::path::Path, contenuto: &[u8]) -> std::path::PathBuf {
        let percorso = cartella.join(super::NOME_ARTEFATTO);
        let Ok(()) = std::fs::write(&percorso, contenuto) else {
            panic!("l'artefatto di prova deve potersi scrivere");
        };
        percorso
    }

    /// **Chi scrive l'atto e chi lo rilegge sono d'accordo.**
    ///
    /// Due formati che divergono sono **un fatto che smette di essere leggibile
    /// senza che nessuno se ne accorga**: e' la specie di difetto che non
    /// produce errori, e per questo serve una prova che li tenga insieme.
    #[test]
    fn l_atto_della_consegna_si_rilegge_come_e_stato_scritto() {
        for (major, minor, patch) in [(1, 0, 0), (0, 9, 12), (10, 0, 3), (99, 99, 99)] {
            let versione = super::Version {
                major,
                minor,
                patch,
            };
            let dettaglio = super::dettaglio_della_consegna(&versione);
            assert_eq!(
                super::versione_della_consegna(&dettaglio),
                Some(versione),
                "l'atto «{dettaglio}» non si rilegge come e' stato scritto"
            );
        }

        // E un dettaglio che non viene da li' non si interpreta a forza.
        assert_eq!(super::versione_della_consegna("qualcos'altro"), None);
        assert_eq!(super::versione_della_consegna(""), None);
    }

    /// **Senza consegne non c'e' niente da dire.**
    #[test]
    fn senza_consegne_non_c_e_niente_da_dire() {
        let servizio = servizio();
        assert_eq!(
            servizio.delivery_outcome().ok(),
            Some(super::DeliveryOutcome::NothingToSay)
        );
    }

    /// **Una consegna che non ha prodotto un'installazione si dice.**
    ///
    /// E' la stessa forma di ADR-0064: il prodotto riapre com'era, e per lui non
    /// e' successo niente — ma nel registro c'e' scritto che una consegna e'
    /// avvenuta, e la versione e' ancora quella di prima.
    #[test]
    fn una_consegna_senza_installazione_si_dice() {
        let servizio = servizio();
        let corrente = super::Version::current();
        let piu_nuova = super::Version {
            major: corrente.major + 1,
            minor: 0,
            patch: 0,
        };

        let Ok(azione) = lisi_core::text::AuditAction::try_new("aggiornamento_consegnato") else {
            panic!("l'azione di prova deve essere valida");
        };
        let Ok(entita) = lisi_core::text::AuditEntity::try_new("aggiornamento") else {
            panic!("l'entita' di prova deve essere valida");
        };
        let Ok(dettaglio) =
            lisi_core::text::AuditDetail::try_new(&super::dettaglio_della_consegna(&piu_nuova))
        else {
            panic!("il dettaglio di prova deve essere valido");
        };
        let Ok(_) = servizio
            .database()
            .append_audit(&lisi_core::model::NewAuditEntry {
                actor: attore(),
                action: azione,
                entity: entita,
                entity_id: None,
                actor_mode: None,
                detail: Some(dettaglio),
                recorded_at: adesso(),
            })
        else {
            panic!("l'atto di prova deve potersi registrare");
        };

        let Ok(super::DeliveryOutcome::NotInstalled { delivered, running }) =
            servizio.delivery_outcome()
        else {
            panic!("una consegna senza installazione deve essere riconosciuta");
        };
        assert_eq!(delivered, piu_nuova);
        assert_eq!(running, corrente);

        let Some(frase) = super::DeliveryOutcome::NotInstalled { delivered, running }.sentence()
        else {
            panic!("il fatto deve avere una frase");
        };
        assert!(
            frase.contains("non è avvenuta"),
            "la frase deve dire che l'installazione non c'e' stata: «{frase}»"
        );
        assert!(
            frase.contains("non sa perché"),
            "il prodotto non sa perche', e lo dice invece di indovinare: «{frase}»"
        );
        assert!(
            frase.contains("si può riprovare"),
            "la frase deve dire che il file e' ancora li': «{frase}»"
        );
        assert!(
            !frase.to_lowercase().contains("ripristin")
                && !frase.to_lowercase().contains("torna indietro"),
            "il prodotto non torna indietro da solo: sostituirebbe il programma \
             senza che nessuno lo abbia deciso (ADR-0073): «{frase}»"
        );
    }

    /// **Una consegna gia' installata non ha niente da dire.**
    #[test]
    fn una_consegna_gia_installata_non_ha_niente_da_dire() {
        let servizio = servizio();
        let corrente = super::Version::current();

        let Ok(azione) = lisi_core::text::AuditAction::try_new("aggiornamento_consegnato") else {
            panic!("l'azione di prova deve essere valida");
        };
        let Ok(entita) = lisi_core::text::AuditEntity::try_new("aggiornamento") else {
            panic!("l'entita' di prova deve essere valida");
        };
        let Ok(dettaglio) =
            lisi_core::text::AuditDetail::try_new(&super::dettaglio_della_consegna(&corrente))
        else {
            panic!("il dettaglio di prova deve essere valido");
        };
        let Ok(_) = servizio
            .database()
            .append_audit(&lisi_core::model::NewAuditEntry {
                actor: attore(),
                action: azione,
                entity: entita,
                entity_id: None,
                actor_mode: None,
                detail: Some(dettaglio),
                recorded_at: adesso(),
            })
        else {
            panic!("l'atto di prova deve potersi registrare");
        };

        assert_eq!(
            servizio.delivery_outcome().ok(),
            Some(super::DeliveryOutcome::NothingToSay),
            "una consegna che ha prodotto cio' che doveva non lascia niente da dire"
        );
    }

    /// **Senza sapere a che cosa porta, non c'e' niente da dire sul file.**
    #[test]
    fn un_documento_senza_versione_leggibile_ferma_la_catena_per_primo() {
        let Ok(cartella) = tempfile::tempdir() else {
            panic!("la cartella temporanea deve potersi creare");
        };
        let contenuto = b"byte qualunque";
        let mut manifesto = manifesto_per(contenuto);
        manifesto.version = String::from("ultima");
        // Il file NON esiste: se la versione non fosse il primo anello, il
        // verdetto sarebbe «non c'e' niente da verificare».
        let percorso = cartella.path().join(super::NOME_ARTEFATTO);

        assert!(
            matches!(
                super::percorri_la_catena(&percorso, &manifesto),
                super::ArtifactVerdict::Broken(super::ArtifactFlaw::UnreadableVersion)
            ),
            "una versione che non si legge ferma la catena prima di tutto"
        );
    }

    /// **Senza monitoraggi il primo cancello lascia passare.**
    ///
    /// Il rifiuto con un monitoraggio in corso (ADR-0037) e' verificato nella sua
    /// POSIZIONE dalla prova strutturale. Qui si verifica che, senza nulla che
    /// osservi, quel cancello lasci passare: altrimenti la consegna sarebbe
    /// bloccata sempre, e nessuno se ne accorgerebbe.
    #[test]
    fn senza_monitoraggi_la_consegna_prosegue_oltre_il_primo_cancello() {
        let servizio = servizio();
        let esito = servizio.hand_off_to_installer(&attore(), adesso());
        // Senza sessioni non c'e' il rifiuto del monitoraggio: si arriva
        // all'origine mancante, che e' il passo prima.
        assert!(
            matches!(esito, Err(ServiceError::UpdateOriginMissing)),
            "senza monitoraggi la consegna prosegue fino all'origine: {esito:?}"
        );
    }

    /// **Cio' che non supera la verifica non si tiene** (ADR-0037 §3).
    ///
    /// Era deciso dal 2026-08 e non era mai stato fatto: UPDATE-04 ha costruito
    /// la catena e ha lasciato il file dov'era.
    #[test]
    fn un_verdetto_che_e_un_tentativo_toglie_il_file() {
        use super::{ArtifactFlaw, ArtifactVerdict};

        // Questi riguardano IL FILE: sono la prova di un tentativo.
        assert!(
            ArtifactVerdict::Broken(ArtifactFlaw::DigestMismatch).e_un_tentativo(),
            "un'impronta diversa e' un tentativo"
        );
        assert!(
            ArtifactVerdict::Broken(ArtifactFlaw::SizeChanged {
                found: 1,
                declared: 2
            })
            .e_un_tentativo(),
            "una dimensione diversa e' un tentativo"
        );
        assert!(
            ArtifactVerdict::Broken(ArtifactFlaw::NotSigned {
                reason: String::from("qualunque cosa dica Windows")
            })
            .e_un_tentativo(),
            "una firma che non regge e' un tentativo"
        );

        // Questi NON riguardano il file: sono cose che non si sono potute dire,
        // e togliere un file per un'osservazione non riuscita cancellerebbe
        // qualcosa di cui non si sa nulla.
        assert!(
            !ArtifactVerdict::Broken(ArtifactFlaw::Missing).e_un_tentativo(),
            "un file che non c'e' non e' un tentativo"
        );
        assert!(
            !ArtifactVerdict::Broken(ArtifactFlaw::Unreadable).e_un_tentativo(),
            "un file che non si e' potuto leggere non e' un tentativo"
        );
        assert!(
            !ArtifactVerdict::Broken(ArtifactFlaw::TooLarge { max: 1 }).e_un_tentativo(),
            "un file che non si e' nemmeno guardato non e' un tentativo"
        );
    }

    /// **Il comando che consegna dice PRIMA che il programma si chiude.**
    ///
    /// Scoprirlo dopo averlo premuto significa aver perso di vista che cosa si
    /// stava facendo, e il prodotto glielo avrebbe fatto perdere senza dirlo.
    #[test]
    fn la_nota_della_consegna_dice_prima_che_il_programma_si_chiude() {
        let nota = super::COSA_SUCCEDE_CONSEGNANDO;
        assert!(
            nota.contains("si chiude"),
            "la nota deve dire che il programma si chiude: «{nota}»"
        );
        assert!(
            nota.to_lowercase().contains("non si riapre da solo"),
            "la nota deve dire che non torna su da se': «{nota}»"
        );
        assert!(
            nota.contains("monitoraggio in corso"),
            "la nota deve dire quando la consegna non avviene: «{nota}»"
        );
        assert!(
            nota.contains("verifica di nuovo"),
            "la nota deve dire che il file viene verificato di nuovo, perche' fra \
             un verdetto vecchio e la consegna ci sarebbe una finestra: «{nota}»"
        );
    }

    /// **La consegna non e' raggiungibile senza un verdetto positivo.**
    ///
    /// E' la prova che tiene insieme tutta la fase: se questo confronto sparisse,
    /// l'esecuzione smetterebbe di essere legata alla verifica.
    #[test]
    fn la_consegna_passa_solo_da_un_verdetto_positivo() {
        const QUESTO_MODULO: &str = include_str!("update_review.rs");

        let Some(corpo) = QUESTO_MODULO
            .split("pub fn hand_off_to_installer(&self, actor: &Actor, now: Timestamp)")
            .nth(1)
        else {
            panic!("la consegna non si trova: la guardia va riscritta insieme");
        };
        let Some(corpo) = corpo.split("\n    }\n").next() else {
            panic!("il corpo della consegna non si delimita");
        };
        let codice: String = corpo
            .lines()
            .filter(|riga| !riga.trim_start().starts_with("//"))
            .collect::<Vec<&str>>()
            .join("\n");

        let Some(monitoraggio) = codice.find("UpdateMonitoringRunning") else {
            panic!("manca il rifiuto con un monitoraggio in corso (ADR-0037)");
        };
        let Some(verifica) = codice.find("self.verify_artifact(") else {
            panic!("la consegna deve verificare ADESSO, non fidarsi di un verdetto vecchio");
        };
        assert!(
            monitoraggio < verifica,
            "il rifiuto con un monitoraggio in corso deve venire PRIMA della \
             verifica: con qualcosa che osserva non si esce nemmeno in rete"
        );

        let Some(verdetto) = codice.find("ArtifactVerdict::Verified") else {
            panic!("la consegna deve passare da un verdetto positivo");
        };
        let Some(avvio) = codice.find("avvia_l_installatore(") else {
            panic!("la consegna non avvia piu' l'installatore");
        };
        assert!(
            verdetto < avvio,
            "il verdetto positivo deve venire PRIMA dell'avvio"
        );

        let Some(registro) = codice.find("aggiornamento_consegnato") else {
            panic!("la consegna non lascia piu' una riga nel registro");
        };
        assert!(
            registro < avvio,
            "l'atto si registra PRIMA di consegnare: dopo, il processo sta per \
             morire, e un audit scritto dopo e' un audit che puo' non esistere"
        );
    }

    /// **Un file in attesa viene prima di tutto.**
    ///
    /// Lasciarlo indietro per proporre di chiedere di nuovo all'origine
    /// significherebbe scaricare sopra qualcosa che nessuno ha guardato.
    #[test]
    fn il_passo_e_quello_che_il_mondo_dice() {
        use super::UpdateStep;

        assert_eq!(UpdateStep::of(false, false), UpdateStep::OriginMissing);
        assert_eq!(UpdateStep::of(true, false), UpdateStep::AskTheOrigin);
        assert_eq!(UpdateStep::of(true, true), UpdateStep::VerifyWhatArrived);

        // Un file sceso senza origine non e' un caso teorico: l'origine si puo'
        // svuotare dopo aver scaricato. Il file resta, e va verificato prima di
        // ogni altra cosa.
        assert_eq!(UpdateStep::of(false, true), UpdateStep::VerifyWhatArrived);
    }

    /// **Senza un'origine non si propone un comando che verrebbe rifiutato.**
    ///
    /// Indicare l'origine richiede la modalita' amministratore: offrirlo a
    /// chiunque sarebbe la stessa promessa di un pulsante che non fa nulla.
    #[test]
    fn il_passo_che_non_e_dell_operatore_non_porta_un_comando() {
        use super::UpdateStep;

        assert_eq!(UpdateStep::OriginMissing.command(), None);
        assert!(UpdateStep::AskTheOrigin.command().is_some());
        assert!(UpdateStep::VerifyWhatArrived.command().is_some());
    }

    /// **Ogni passo dice dove si e', e nessuno promette un promemoria.**
    #[test]
    fn ogni_passo_dice_dove_si_e_e_che_niente_parte_da_solo() {
        use super::UpdateStep;

        for passo in [
            UpdateStep::OriginMissing,
            UpdateStep::AskTheOrigin,
            UpdateStep::VerifyWhatArrived,
        ] {
            let frase = passo.sentence();
            assert!(
                frase.chars().count() > 40,
                "ogni passo deve dire dove si e': «{frase}»"
            );

            let inazione = passo.doing_nothing();
            assert!(
                inazione.contains("niente parte da solo"),
                "chi non fa nulla deve sapere che nulla parte da solo: «{inazione}»"
            );
            assert!(
                !inazione.to_lowercase().contains("ricorder")
                    && !inazione.to_lowercase().contains("avvis")
                    && !inazione.to_lowercase().contains("promemoria"),
                "«piu' tardi» non deve promettere un promemoria che non esiste: \
                 «{inazione}»"
            );
        }
    }

    /// **La frase che spiega perche' non si installa non e' un guasto.**
    ///
    /// La differenza non e' una sfumatura: «manca una funzione» manda a
    /// segnalare un difetto, «e' una scelta» no.
    #[test]
    fn la_frase_sull_installazione_dichiara_una_scelta_e_non_un_guasto() {
        let frase = super::PERCHE_NON_SI_INSTALLA;
        assert!(
            frase.to_lowercase().contains("è una scelta"),
            "la frase deve dire che e' una scelta: «{frase}»"
        );
        assert!(
            frase.contains("non si sostituisce da sé"),
            "la frase deve dire che cosa il programma non fa: «{frase}»"
        );
        // UPDATE-07 HA CAMBIATO L'AFFERMAZIONE, non solo le parole: prima
        // diceva «si installa a mano», ora dice «consegna e si chiude». La prova
        // segue l'affermazione nuova, e aggiunge la parte che prima non c'era —
        // il programma non si riapre da solo.
        assert!(
            frase.contains("non si riapre da solo"),
            "la frase deve dire che il programma non torna su da se': riaprirlo \
             aprirebbe un programma diverso da quello che l'operatore ha chiuso \
             (ADR-0072): «{frase}»"
        );
        assert!(
            frase.contains("durante un monitoraggio"),
            "la frase deve dire che non succede mentre qualcosa osserva: «{frase}»"
        );
        assert!(
            !frase.to_lowercase().contains("non ancora")
                && !frase.to_lowercase().contains("prossimamente")
                && !frase.to_lowercase().contains("in arrivo"),
            "la frase non deve promettere una data: «{frase}»"
        );
    }

    /// **Il file scaricato si puo' togliere, e resta scritto che e' stato tolto.**
    #[test]
    fn il_file_scaricato_si_puo_togliere() {
        let servizio = servizio();
        let Ok(()) = servizio.discard_staged(&attore(), adesso()) else {
            panic!("togliere il file deve riuscire anche quando non ce n'e' uno");
        };

        let Ok(righe) = servizio.database().audit_entries() else {
            panic!("il registro deve potersi leggere");
        };
        assert!(
            righe
                .iter()
                .any(|riga| riga.action.as_str() == "artefatto_scartato"),
            "togliere il file deve lasciare una riga nel registro"
        );
    }

    /// **Se la schermata offre di installare, la consegna esiste ed e' custodita.**
    ///
    /// # Che cosa diceva prima, e perche' e' cambiata ADESSO
    ///
    /// In UPDATE-06 questa prova diceva che nessun comando poteva dire
    /// «installa», perche' installare non esisteva e un comando che non fa cio'
    /// che dice e' una promessa. ADR-0071 aveva scritto che il giorno di
    /// UPDATE-07 sarebbe andata cambiata **insieme al comando che arriva, non
    /// prima**: e' quel giorno.
    ///
    /// Non e' stata tolta. La proprieta' e' diventata piu' forte: il comando puo'
    /// esistere **solo se** esiste la consegna, e la consegna e' custodita — un
    /// verdetto positivo, nessun monitoraggio in corso, e l'atto nel registro.
    /// Toglierla avrebbe lasciato la schermata libera di promettere di nuovo.
    #[test]
    fn se_la_schermata_offre_di_installare_la_consegna_esiste_ed_e_custodita() {
        const SCHERMATA: &str = include_str!("../../lisi-app/ui/app-window.slint");
        const QUESTO_MODULO: &str = include_str!("update_review.rs");

        let Some(sezione) = SCHERMATA.split("\"AGGIORNAMENTI\"").nth(1) else {
            panic!("la sezione degli aggiornamenti non si trova");
        };
        let Some(sezione) = sezione.split("// ----").next() else {
            panic!("la sezione degli aggiornamenti non si delimita");
        };

        let promette = sezione
            .lines()
            .map(str::trim_start)
            .filter(|riga| riga.starts_with("label:"))
            .any(|riga| riga.to_lowercase().contains("installa"));

        if !promette {
            return;
        }

        for custodia in [
            "pub fn hand_off_to_installer(",
            "ServiceError::UpdateMonitoringRunning",
            "ArtifactVerdict::Verified",
            "aggiornamento_consegnato",
        ] {
            assert!(
                QUESTO_MODULO.contains(custodia),
                "la schermata offre di installare, ma «{custodia}» non c'e': un \
                 comando che non fa cio' che dice e' una promessa, e una consegna \
                 senza custodia e' peggio (ADR-0071, ADR-0072)"
            );
        }

        // E la frase che accompagna il comando deve dire che il programma si
        // chiude: scoprirlo dopo averlo premuto significa aver perso di vista
        // che cosa si stava facendo.
        assert!(
            sezione.contains("root.update-hand-off-note"),
            "la schermata offre di installare e non dice che cosa succede premendo"
        );
    }

    /// **Mentre il verdetto e' vivo, quei byte non si possono cambiare.**
    /// **Mentre il verdetto e' vivo, quei byte non si possono cambiare.**
    ///
    /// E' la prova che dice se ADR-0070 e' stato costruito o solo scritto: non
    /// verifica che il codice *dica* di negare la scrittura, verifica che il
    /// sistema operativo la neghi davvero.
    ///
    /// La catena si ferma su «non firmato», ma l'apertura viene fatta PRIMA di
    /// quell'anello: per provare la chiusura della finestra si apre nello stesso
    /// modo e si prova a scrivere.
    #[cfg(windows)]
    #[test]
    fn mentre_il_file_e_aperto_nessuno_puo_cambiarlo() {
        let Ok(cartella) = tempfile::tempdir() else {
            panic!("la cartella temporanea deve potersi creare");
        };
        let percorso = artefatto(cartella.path(), b"i byte verificati");

        // Prima: chiunque puo' scrivere.
        assert!(
            std::fs::OpenOptions::new()
                .write(true)
                .open(&percorso)
                .is_ok(),
            "senza un'apertura viva il file e' scrivibile, ed e' il caso normale"
        );

        let Ok(aperto) = super::apri_senza_scrittori(&percorso) else {
            panic!("l'apertura senza scrittori deve riuscire");
        };

        // Mentre l'apertura e' viva: NESSUNO scrive, e nessuno cancella.
        assert!(
            std::fs::OpenOptions::new()
                .write(true)
                .open(&percorso)
                .is_err(),
            "con l'apertura viva la scrittura deve essere NEGATA DAL SISTEMA, \
             non sconsigliata dal codice (ADR-0070)"
        );
        assert!(
            std::fs::remove_file(&percorso).is_err(),
            "con l'apertura viva la cancellazione deve essere negata"
        );

        // E la lettura resta possibile: l'installatore e' un altro processo, e
        // deve poter leggere quando sara' il momento (UPDATE-07).
        assert!(
            std::fs::File::open(&percorso).is_ok(),
            "la lettura non va negata: cio' che va impedito e' la MODIFICA"
        );

        drop(aperto);

        // Dopo: il file torna scrivibile, ed e' giusto — il verdetto non c'e'
        // piu', e con esso l'affermazione su quei byte.
        assert!(
            std::fs::OpenOptions::new()
                .write(true)
                .open(&percorso)
                .is_ok(),
            "chiusa l'apertura, il file torna come prima"
        );
    }

    /// **Un file che qualcun altro sta scrivendo non si verifica.**
    ///
    /// E' la risposta giusta: significa che in questo momento qualcuno lo sta
    /// cambiando, e un verdetto su byte in movimento non varrebbe nulla.
    #[cfg(windows)]
    #[test]
    fn un_file_tenuto_aperto_in_scrittura_non_si_verifica() {
        let Ok(cartella) = tempfile::tempdir() else {
            panic!("la cartella temporanea deve potersi creare");
        };
        let contenuto = b"byte che qualcuno sta ancora cambiando";
        let manifesto = manifesto_per(contenuto);
        let percorso = artefatto(cartella.path(), contenuto);

        use std::os::windows::fs::OpenOptionsExt;
        let Ok(scrittore) = std::fs::OpenOptions::new()
            .write(true)
            .share_mode(0)
            .open(&percorso)
        else {
            panic!("lo scrittore di prova deve potersi aprire");
        };

        let verdetto = super::percorri_la_catena(&percorso, &manifesto);
        assert!(
            matches!(
                verdetto,
                super::ArtifactVerdict::Broken(super::ArtifactFlaw::Unreadable)
            ),
            "un file che qualcun altro tiene aperto in scrittura non si verifica: {verdetto:?}"
        );

        drop(scrittore);
    }

    /// **Fuori dal modulo non esiste un modo di nominare il file.**
    ///
    /// E' la parte strutturale di ADR-0070: chi usera' l'artefatto non dovra'
    /// RICORDARSI di passare dalla verifica — non avra' un'altra strada.
    #[test]
    fn il_percorso_dell_artefatto_non_esce_dal_modulo() {
        const QUESTO_MODULO: &str = include_str!("update_review.rs");

        let Some((produzione, _)) = QUESTO_MODULO.split_once("\n#[cfg(test)]\nmod tests {") else {
            panic!("il blocco delle prove non si delimita");
        };

        for privato in ["const NOME_ARTEFATTO", "fn staging_directory"] {
            let Some(riga) = produzione
                .lines()
                .find(|riga| riga.trim_start().starts_with(privato))
            else {
                panic!("«{privato}» non si trova piu': la guardia va riscritta insieme");
            };
            assert!(
                !riga.trim_start().starts_with("pub "),
                "«{privato}» non deve essere pubblico: fuori di qui non deve \
                 esistere un modo di nominare il file non verificato (ADR-0070)"
            );
        }
    }

    /// **Non avere niente da verificare non e' un guasto.**
    ///
    /// Puo' essere che non si sia mai scaricato nulla, o che un antivirus abbia
    /// messo il file in quarantena: sono due cose diverse da «non verificato».
    #[test]
    fn senza_file_non_c_e_niente_da_verificare() {
        let Ok(cartella) = tempfile::tempdir() else {
            panic!("la cartella temporanea deve potersi creare");
        };
        let manifesto = manifesto_per(b"qualcosa");

        let verdetto =
            super::percorri_la_catena(&cartella.path().join(super::NOME_ARTEFATTO), &manifesto);
        assert!(matches!(
            verdetto,
            super::ArtifactVerdict::Broken(super::ArtifactFlaw::Missing)
        ));
        assert!(
            verdetto.operator_message().contains("quarantena"),
            "la frase deve nominare la causa piu' probabile: «{}»",
            verdetto.operator_message()
        );
    }

    /// **La catena si ferma al PRIMO anello rotto.**
    ///
    /// Qui la dimensione e l'impronta sono entrambe sbagliate, e il verdetto e'
    /// quello della dimensione: verificare oltre un anello rotto significherebbe
    /// dire due cose di un file di cui la prima e' gia' decisiva.
    #[test]
    fn la_catena_si_ferma_al_primo_anello_rotto() {
        let Ok(cartella) = tempfile::tempdir() else {
            panic!("la cartella temporanea deve potersi creare");
        };
        let manifesto = manifesto_per(b"quello che ci si aspetta");
        let percorso = artefatto(cartella.path(), b"altro, e di lunghezza diversa");

        let verdetto = super::percorri_la_catena(&percorso, &manifesto);
        let super::ArtifactVerdict::Broken(super::ArtifactFlaw::SizeChanged { found, declared }) =
            verdetto
        else {
            panic!("la dimensione diversa deve fermare la catena: {verdetto:?}");
        };
        assert_eq!(found, 29);
        assert_eq!(declared, 24);
    }

    /// **Un'impronta diversa si dichiara, e non si mostra.**
    ///
    /// Sessantaquattro caratteri che nessuno confronta a occhio, e una delle due
    /// arriva da un documento che viene da fuori.
    #[test]
    fn un_impronta_diversa_si_dichiara_e_non_si_mostra() {
        let Ok(cartella) = tempfile::tempdir() else {
            panic!("la cartella temporanea deve potersi creare");
        };
        // Stessa lunghezza, contenuto diverso: la dimensione passa, l'impronta no.
        let mut manifesto = manifesto_per(b"aaaaaaaaaaaaaaaa");
        let percorso = artefatto(cartella.path(), b"bbbbbbbbbbbbbbbb");

        let verdetto = super::percorri_la_catena(&percorso, &manifesto);
        assert!(matches!(
            verdetto,
            super::ArtifactVerdict::Broken(super::ArtifactFlaw::DigestMismatch)
        ));

        let frase = verdetto.operator_message();
        assert!(
            !frase.contains(&manifesto.artifact_sha256),
            "l'impronta dichiarata non deve comparire nella frase"
        );
        assert!(
            frase.contains("non va installato"),
            "la frase deve dire che cosa NON si fa: «{frase}»"
        );

        // E un'impronta dichiarata che non e' nemmeno un'impronta si comporta
        // allo stesso modo: non si «accomoda».
        manifesto.artifact_sha256 = String::from("non-e-un-impronta");
        assert!(matches!(
            super::percorri_la_catena(&percorso, &manifesto),
            super::ArtifactVerdict::Broken(super::ArtifactFlaw::DigestMismatch)
        ));
    }

    /// **UN FILE CHE CORRISPONDE MA NON E' FIRMATO SI RIFIUTA.**
    ///
    /// E' la prova che conta piu' di ogni altra in questa milestone: l'impronta
    /// viene dal manifesto, che e' dato NON FIDATO. Se coincide, cio' che e'
    /// dimostrato e' che «questi byte sono quelli che quel documento
    /// descriveva» — e se il documento e' ostile, ha descritto cio' che voleva
    /// far scaricare, e l'impronta torna perfettamente.
    ///
    /// L'ancoraggio della fiducia e' la firma, che non viene dal documento.
    #[test]
    fn un_file_che_corrisponde_ma_non_e_firmato_si_rifiuta() {
        let Ok(cartella) = tempfile::tempdir() else {
            panic!("la cartella temporanea deve potersi creare");
        };
        let contenuto = b"byte che corrispondono esattamente a quanto dichiarato";
        let manifesto = manifesto_per(contenuto);
        let percorso = artefatto(cartella.path(), contenuto);

        let verdetto = super::percorri_la_catena(&percorso, &manifesto);
        assert!(
            matches!(
                verdetto,
                super::ArtifactVerdict::Broken(super::ArtifactFlaw::NotSigned { .. })
            ),
            "un file non firmato non si accetta, per quanto l'impronta torni: {verdetto:?}"
        );

        let frase = verdetto.operator_message();
        assert!(
            frase.contains("la firma dice chi lo ha prodotto"),
            "la frase deve spiegare perche' l'impronta non basta: «{frase}»"
        );
        assert!(
            frase.contains("non si installa"),
            "la frase deve dire che cosa NON si fa: «{frase}»"
        );
    }

    /// **Nessun modo di accettare un artefatto non firmato.**
    ///
    /// Non un interruttore, non una variabile d'ambiente, non un ramo di prova.
    /// Sarebbe la porta di servizio che ADR-0067 ha gia' rifiutato per il canale
    /// pilota, con la differenza che qui aprirebbe direttamente all'esecuzione
    /// di codice (ADR-0069).
    #[test]
    fn la_verifica_non_ha_un_ramo_di_prova() {
        const QUESTO_MODULO: &str = include_str!("update_review.rs");

        let Some(catena) = QUESTO_MODULO
            .split("fn percorri_la_catena(percorso: &std::path::Path")
            .nth(1)
        else {
            panic!("la catena non si trova: la guardia va riscritta insieme");
        };
        let Some(catena) = catena.split("\n}\n").next() else {
            panic!("il corpo della catena non si delimita");
        };
        let codice: String = catena
            .lines()
            .filter(|riga| !riga.trim_start().starts_with("//"))
            .collect::<Vec<&str>>()
            .join("\n");

        for scorciatoia in [
            "cfg!(test)",
            "cfg(test)",
            "debug_assertions",
            "env::var",
            "cfg!(debug",
        ] {
            assert!(
                !codice.contains(scorciatoia),
                "«{scorciatoia}» nella catena di verifica: la verifica non si \
                 indebolisce per rendere le prove piu' comode (Fase 10, ADR-0069)"
            );
        }
        assert!(
            codice.contains("if !firma.is_trusted()"),
            "la catena deve rifiutare ogni firma che non sia attendibile, \
             compresa quella che non si e' potuta stabilire"
        );

        // E CHI HA FIRMATO (FINAL-REVIEW-01, FR-004): attendibile non basta.
        let Some(dopo_la_firma) = codice.split("if !firma.is_trusted()").nth(1) else {
            panic!("il controllo della firma deve esserci");
        };
        let Some(prima_del_verdetto) = dopo_la_firma.split("ArtifactVerdict::Verified {").next()
        else {
            panic!("il verdetto deve seguire la firma");
        };
        assert!(
            prima_del_verdetto.contains("if !editore_riconosciuto(EDITORI_RICONOSCIUTI)")
                && prima_del_verdetto.contains("ArtifactFlaw::PublisherNotRecognised"),
            "fra la firma attendibile e il verdetto deve esserci il controllo \
             dell'editore: un file firmato da chiunque non è un aggiornamento"
        );
        assert!(
            super::EDITORI_RICONOSCIUTI.is_empty()
                && !super::editore_riconosciuto(&["Qualunque editore"]),
            "finché la lettura del firmatario non esiste, nessun editore si riconosce"
        );

        // UNA SOLA APERTURA, E TUTTI GLI ANELLI LA USANO (ADR-0070).
        //
        // Due aperture lascerebbero una finestra FRA LE DUE, ed e' il difetto
        // che UPDATE-05 chiude — spostato di qualche riga invece che tolto.
        assert_eq!(
            codice.matches("apri_senza_scrittori(").count(),
            1,
            "il file si apre UNA volta sola dentro la catena"
        );
        assert!(
            !codice.contains("File::open("),
            "nella catena non deve esserci una seconda apertura del file"
        );
        assert!(
            codice.contains("verify_open_file(percorso, &file)"),
            "la firma va verificata SULL'APERTURA, non su una seconda \
             risoluzione del percorso (ADR-0070)"
        );
        assert!(
            !codice.contains("signature::verify_file("),
            "la verifica per percorso lascerebbe una finestra fra l'impronta e \
             la firma"
        );
    }

    /// **Nel registro non finiscono ne' l'impronta ne' il percorso.**
    #[test]
    fn il_registro_della_verifica_non_porta_impronte_ne_percorsi() {
        let Ok(cartella) = tempfile::tempdir() else {
            panic!("la cartella temporanea deve potersi creare");
        };
        let percorso = artefatto(cartella.path(), b"qualcosa");
        let Ok(aperto) = std::fs::File::open(&percorso) else {
            panic!("il file di prova deve potersi aprire");
        };

        let verdetti = [
            super::ArtifactVerdict::Verified {
                bytes: 1,
                version: super::Version {
                    major: 1,
                    minor: 0,
                    patch: 0,
                },
                file: std::sync::Arc::new(aperto),
            },
            super::ArtifactVerdict::Broken(super::ArtifactFlaw::Missing),
            super::ArtifactVerdict::Broken(super::ArtifactFlaw::SizeChanged {
                found: 1,
                declared: 2,
            }),
            super::ArtifactVerdict::Broken(super::ArtifactFlaw::TooLarge { max: 3 }),
            super::ArtifactVerdict::Broken(super::ArtifactFlaw::Unreadable),
            super::ArtifactVerdict::Broken(super::ArtifactFlaw::DigestMismatch),
            super::ArtifactVerdict::Broken(super::ArtifactFlaw::NotSigned {
                reason: String::from("qualunque cosa dica Windows"),
            }),
        ];

        for verdetto in &verdetti {
            let dettaglio = verdetto.audit_detail();
            assert!(
                !dettaglio.contains(super::NOME_ARTEFATTO)
                    && !dettaglio.to_lowercase().contains("sha")
                    && !dettaglio.contains('\\')
                    && !dettaglio.contains('/'),
                "nel registro non deve finire ne' l'impronta ne' il percorso: «{dettaglio}»"
            );
        }
    }

    /// **Senza un'origine non si scarica nemmeno l'artefatto.**
    ///
    /// E' la stessa regola del manifesto, e vale la pena provarla anche qui:
    /// sono due strade, e una delle due potrebbe un giorno dimenticarsene.
    #[test]
    fn senza_un_origine_non_si_scarica_l_artefatto() {
        let servizio = servizio();
        let esito = servizio.download_artifact(&attore(), adesso());
        assert!(
            matches!(esito, Err(ServiceError::UpdateOriginMissing)),
            "senza origine non si deve uscire in rete: {esito:?}"
        );

        let Ok(righe) = servizio.database().audit_entries() else {
            panic!("il registro deve potersi leggere");
        };
        assert!(
            !righe
                .iter()
                .any(|riga| riga.action.as_str() == "artefatto_scaricato"),
            "senza origine non deve risultare alcun tentativo di scaricamento"
        );
    }

    /// **Il file che scende non ha un'estensione eseguibile.**
    ///
    /// Non e' sicurezza — chi ha la macchina rinomina un file — e' un
    /// impedimento all'errore: un doppio clic, un antivirus che decide di
    /// «provarlo», uno script dell'ufficio che cerca gli installatori.
    #[test]
    fn il_file_che_scende_non_sembra_un_programma() {
        let nome = super::NOME_ARTEFATTO.to_lowercase();
        for eseguibile in [".exe", ".msi", ".bat", ".cmd", ".ps1", ".com", ".scr"] {
            assert!(
                !nome.ends_with(eseguibile),
                "«{nome}» finisce come un programma, e finche' non e' verificato non lo e'"
            );
        }
    }

    /// **Lo staging si svuota prima, e se non si svuota non si scarica.**
    ///
    /// Un file rimasto da un tentativo precedente e' un file che qualcuno
    /// potrebbe scambiare per quello nuovo.
    #[test]
    fn lo_staging_si_svuota_prima_di_scaricare() {
        let Ok(cartella) = tempfile::tempdir() else {
            panic!("la cartella temporanea deve potersi creare");
        };
        let vecchio = cartella.path().join("aggiornamento.scaricato");
        let Ok(()) = std::fs::write(&vecchio, b"resto di un tentativo precedente") else {
            panic!("il file di prova deve potersi scrivere");
        };
        assert!(vecchio.exists());

        let Ok(()) = super::svuota_staging(cartella.path()) else {
            panic!("lo staging deve potersi svuotare");
        };
        assert!(
            !vecchio.exists(),
            "cio' che c'era prima deve sparire prima che scenda altro"
        );
    }

    /// **Se sul disco non c'e' spazio non si comincia.**
    ///
    /// Riempire il volume di una postazione d'ufficio e' un guasto che il
    /// prodotto causerebbe, non uno che subisce — e a fermarsi non sarebbe lo
    /// scaricamento, ma l'archivio, che sta sullo stesso volume.
    #[test]
    fn senza_spazio_non_si_comincia() {
        let Ok(cartella) = tempfile::tempdir() else {
            panic!("la cartella temporanea deve potersi creare");
        };

        // Una dimensione che nessun volume regge. Se la misura non riesce —
        // fuori da Windows — la prova non afferma nulla: «non lo so» non e'
        // «non ce n'e'», ed e' esattamente la regola che si sta verificando.
        let esito = super::controlla_spazio(cartella.path(), u64::MAX / 2);
        if cfg!(windows) {
            assert!(
                matches!(esito, Err(ServiceError::UpdateNotFetched { .. })),
                "con un disco insufficiente non si deve cominciare: {esito:?}"
            );
        }

        // Una dimensione piccola deve passare comunque.
        assert!(
            super::controlla_spazio(cartella.path(), 1).is_ok(),
            "un artefatto piccolo non deve essere fermato dal disco"
        );
    }

    /// **L'origine si cambia solo da chi amministra.**
    ///
    /// E' l'UNICA destinazione che questo prodotto puo' raggiungere in rete
    /// (ADR-0067): chi la scrive decide con chi la postazione parla.
    #[test]
    fn in_modalita_operatore_l_origine_non_si_cambia() {
        let servizio = servizio();
        let esito = servizio.set_origin(
            Some("https://esempio.test/m.json"),
            OperatingMode::Operator,
            &attore(),
            adesso(),
        );

        assert!(
            matches!(
                esito,
                Err(ServiceError::ActionReservedToAdministrator { .. })
            ),
            "in modalita' operatore l'origine non deve potersi cambiare: {esito:?}"
        );
        assert_eq!(servizio.origin().ok(), Some(None));
    }

    /// **Nel registro finisce CHE l'origine e' cambiata, non QUALE.**
    ///
    /// Un indirizzo in un registro che qualcuno rilegge fra due anni e' un
    /// indirizzo che qualcuno prima o poi apre. Cio' che serve sapere e' quando
    /// la destinazione e' cambiata e chi l'ha cambiata.
    #[test]
    fn il_registro_dice_che_l_origine_e_cambiata_e_non_quale() {
        let servizio = servizio();
        let Ok(()) = servizio.set_origin(
            Some("https://esempio.test/m.json"),
            OperatingMode::Administrator,
            &attore(),
            adesso(),
        ) else {
            panic!("in modalita' amministratore l'origine deve potersi indicare");
        };

        assert_eq!(
            servizio.origin().ok().flatten().as_deref(),
            Some("https://esempio.test/m.json")
        );

        let Ok(righe) = servizio.database().audit_entries() else {
            panic!("il registro deve potersi leggere");
        };
        let Some(riga) = righe
            .iter()
            .find(|riga| riga.action.as_str() == "origine_aggiornamenti_impostata")
        else {
            panic!("il cambio di origine deve lasciare una riga nel registro");
        };
        assert_eq!(
            riga.detail.as_ref().map(|dettaglio| dettaglio.as_str()),
            Some("indicata")
        );
        for testo in righe.iter().filter_map(|riga| {
            riga.detail
                .as_ref()
                .map(lisi_core::text::AuditDetail::as_str)
        }) {
            assert!(
                !testo.contains("esempio.test"),
                "l'indirizzo non deve finire nel registro: «{testo}»"
            );
        }
    }

    /// **Un'origine in chiaro non si accetta, e il rifiuto si spiega** (F-11).
    ///
    /// L'archivio la rifiutava già, ma con un errore generico che la schermata
    /// poi copriva: ora il servizio la ferma prima, con la ragione.
    #[test]
    fn un_origine_in_chiaro_non_si_accetta() {
        let servizio = servizio();
        let esito = servizio.set_origin(
            Some("http://esempio.test/m.json"),
            OperatingMode::Administrator,
            &attore(),
            adesso(),
        );
        assert!(
            matches!(esito, Err(ServiceError::UpdateOriginRefused { .. })),
            "un'origine in chiaro non deve potersi indicare: {esito:?}"
        );
        assert_eq!(servizio.origin().ok(), Some(None));
    }

    /// **La postazione si descrive davvero, non con valori inventati.**

    #[test]
    fn la_postazione_dichiara_la_propria_versione_di_windows() {
        let stato = station_state(Channel::Stable);
        if cfg!(windows) {
            let Some(windows) = stato.windows_version.as_deref() else {
                panic!(
                    "su Windows la versione deve essere leggibile: senza, il minimo \
                     richiesto da un aggiornamento non verrebbe confrontato con nulla"
                );
            };
            assert!(windows.starts_with("10."), "versione inattesa: «{windows}»");
        }
    }

    /// **Il canale della postazione e' stabile, e un manifesto pilota si rifiuta.**
    ///
    /// Non e' una preferenza estetica: e' l'unico modo in cui, oggi, il canale
    /// produce una conseguenza osservabile.
    #[test]
    fn un_manifesto_di_un_altro_canale_si_rifiuta() {
        let Ok(cartella) = tempfile::tempdir() else {
            panic!("la cartella temporanea deve potersi creare");
        };
        let pilota = manifesto_valido("99.0.0").replace("\"stable\"", "\"pilot\"");
        let percorso = scrivi(cartella.path(), "pilota.json", pilota.as_bytes());

        let Ok(decisione) = servizio().review(&percorso, &attore(), adesso()) else {
            panic!("l'esame deve concludersi");
        };
        assert!(
            matches!(
                decisione,
                UpdateDecision::Refused(UpdateRefusal::WrongChannel { .. })
            ),
            "un manifesto di un altro canale deve essere rifiutato: {decisione:?}"
        );
    }

    /// **Una versione piu' vecchia non passa nemmeno da un file.**
    ///
    /// E' l'unico attacco che un manifesto sostituito potrebbe portare a segno:
    /// una versione piu' vecchia, legittimamente firmata, con una falla nota.
    #[test]
    fn una_versione_piu_vecchia_non_passa_nemmeno_da_un_file() {
        let Ok(cartella) = tempfile::tempdir() else {
            panic!("la cartella temporanea deve potersi creare");
        };
        let percorso = scrivi(
            cartella.path(),
            "vecchio.json",
            manifesto_valido("0.0.1").as_bytes(),
        );

        let Ok(decisione) = servizio().review(&percorso, &attore(), adesso()) else {
            panic!("l'esame deve concludersi");
        };
        assert!(
            matches!(
                decisione,
                UpdateDecision::Refused(UpdateRefusal::NotNewer { .. }) | UpdateDecision::UpToDate
            ),
            "una versione piu' vecchia non deve essere offerta: {decisione:?}"
        );
    }
}

#[cfg(test)]
mod staging_tests {
    /// **Un file messo accanto a quello verificato ferma la consegna**
    /// (FINAL-REVIEW-01, FR-026).
    #[test]
    fn a_file_planted_next_to_the_verified_one_is_seen() {
        let Ok(cartella) = tempfile::tempdir() else {
            panic!("cartella temporanea");
        };
        let verificato = cartella.path().join(super::NOME_ARTEFATTO);
        if std::fs::write(&verificato, b"verificato").is_err() {
            panic!("il file verificato deve potersi scrivere");
        }
        let Ok(nessuno) = super::staging_extraneous_entries(cartella.path()) else {
            panic!("la cartella deve potersi leggere");
        };
        assert!(
            nessuno.is_empty(),
            "il solo file verificato non è un estraneo"
        );

        let piantato = cartella
            .path()
            .join(format!("{}.exe", super::NOME_ARTEFATTO));
        if std::fs::write(&piantato, b"altro").is_err() {
            panic!("il file piantato deve potersi scrivere");
        }
        let Ok(estranei) = super::staging_extraneous_entries(cartella.path()) else {
            panic!("la cartella deve potersi leggere");
        };
        assert_eq!(estranei, vec![format!("{}.exe", super::NOME_ARTEFATTO)]);
    }

    /// La guardia sta nella consegna, prima dell'avvio.
    #[test]
    fn the_installer_launch_checks_the_staging_folder_first() {
        const QUESTO_MODULO: &str = include_str!("update_review.rs");
        let Some((_, corpo)) = QUESTO_MODULO
            .split_once("fn avvia_l_installatore(file: &std::sync::Arc<std::fs::File>)")
        else {
            panic!("la consegna deve esistere");
        };
        let Some((prima_dell_avvio, _)) = corpo.split_once("std::process::Command::new(") else {
            panic!("la consegna deve avviare qualcosa");
        };
        assert!(
            prima_dell_avvio.contains("staging_extraneous_entries(&cartella)?")
                && prima_dell_avvio.contains("if !estranei.is_empty()"),
            "prima di avviare, la cartella deve contenere il solo file verificato"
        );
    }
}
