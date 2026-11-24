//! Il programma avviato da Windows come servizio, mentre la persona è uscita
//! (SERVICE-01, ADR-0203).
//!
//! # Che cosa fa
//!
//! Aspetta che la persona esca da Windows e che il file dell'istanza sia
//! libero. Allora prende l'acquisizione: se la finestra l'aveva lasciata da
//! poco, riprende gli account che la persona aveva collegati e continua; se no
//! registra l'interruzione, come la finestra all'avvio, e non riprende nulla.
//! Quando la persona rientra, chiude i client e lascia il file dell'istanza
//! alla finestra.
//!
//! # Che cosa NON fa
//!
//! Non mostra nulla e non chiede nulla: nessuna finestra, nessun accesso
//! nuovo, nessuna decisione al posto della persona. Le ricerche ricorrenti, le
//! copie pianificate e il recupero della cronologia aspettano la finestra.

use std::time::{Duration, Instant};

use lisi_core::model::background::{HEARTBEAT_INTERVAL_MS, Keeper, SERVICE_NAME};
use lisi_platform::background_service::{StopSignal, run_as_service, user_has_a_session};
use lisi_services::background::{Takeover, release_without_handover, sign, take_over};
use lisi_services::hub_live::HubLivePublisher;

/// Ogni quanto si guarda se la persona è rientrata.
const CONTROLLO: Duration = Duration::from_secs(2);

/// Il giro dell'acquisizione, come nella finestra.
const GIRO: Duration = Duration::from_millis(200);

/// Consegna il processo a Windows.
///
/// # Errori
///
/// Restituisce un errore se il programma non è stato avviato da Windows come
/// servizio.
pub fn run() -> Result<(), Box<dyn std::error::Error>> {
    run_as_service(SERVICE_NAME, corpo)?;
    Ok(())
}

/// La persona è collegata a Windows. Nel dubbio sì: allora l'acquisizione
/// resta alla finestra, che la persona vede.
fn persona_collegata() -> bool {
    user_has_a_session().unwrap_or(true)
}

fn adesso() -> lisi_core::Timestamp {
    lisi_core::time::anchored_now()
}

/// Aspetta `quanto`, a meno che Windows chieda di fermarsi.
fn attendi(fermata: &StopSignal, quanto: Duration) {
    let fine = Instant::now() + quanto;
    while !fermata.requested() && Instant::now() < fine {
        std::thread::sleep(GIRO);
    }
}

fn corpo(fermata: &StopSignal) {
    if lisi_services::run_mode::establish(lisi_core::model::run_mode::RunMode::Operational).is_err()
        || lisi_core::time::anchor_clock().is_err()
    {
        return;
    }
    lisi_core::time::install_local_offset(lisi_platform::local_time::utc_offset_minutes);
    let _registro = crate::logging::initialize();
    tracing::info!("servizio in background avviato");
    while !fermata.requested() {
        if persona_collegata() {
            attendi(fermata, CONTROLLO);
            continue;
        }
        match lisi_services::instance::acquire() {
            Ok(Some(istanza)) => {
                custodisci(fermata);
                drop(istanza);
            }
            _ => attendi(fermata, CONTROLLO),
        }
    }
    tracing::info!("servizio in background fermato");
}

/// Perché il servizio lascia l'acquisizione.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Motivo {
    /// La persona è rientrata: la finestra continua.
    Rientro,
    /// Windows ha chiesto di fermarsi: nessuno continua da sé.
    Fermata,
}

/// Tiene l'acquisizione finché la persona non rientra o Windows non ferma il
/// servizio.
fn custodisci(fermata: &StopSignal) {
    let Ok(mut archivio) = lisi_services::sources::open_application_database() else {
        tracing::warn!("archivio non apribile dal servizio in background");
        attendi(fermata, CONTROLLO);
        return;
    };
    let account = match take_over(&mut archivio, Keeper::Service, adesso()) {
        Ok(Takeover::Continued { accounts, .. }) => accounts,
        Ok(Takeover::Interrupted(_)) => Vec::new(),
        Err(errore) => {
            tracing::warn!(
                kind = errore.kind(),
                "presa dell'acquisizione non registrata"
            );
            Vec::new()
        }
    };

    let apri = lisi_services::sources::open_application_database;
    // Il servizio puo' partire prima della finestra: consuma lui la
    // configurazione arrivata con la distribuzione (ADR-0204).
    crate::configurazione::importa(apri().ok());
    let sessione = apri().ok().map(crate::account::create_service);
    let ripresi = sessione
        .as_ref()
        .map_or(0, |sessione| sessione.borrow_mut().resume_linked(&account));
    tracing::info!(ripresi, "il servizio in background tiene l'acquisizione");
    let mut acquisizione =
        crate::acquisition::create_service(apri().ok(), apri().ok(), apri().ok(), apri().ok()).map(
            |pump| {
                let live = if crate::team_live::questa_postazione_e_un_hub() {
                    apri().ok().map(HubLivePublisher::new)
                } else {
                    None
                };
                pump.with_hub_live(live)
            },
        );

    let mut ultimo_controllo = Instant::now();
    let mut ultimo_segno = Instant::now();
    let segno_ogni = Duration::from_millis(u64::try_from(HEARTBEAT_INTERVAL_MS).unwrap_or(10_000));
    let motivo = loop {
        if fermata.requested() {
            break Motivo::Fermata;
        }
        if ultimo_controllo.elapsed() >= CONTROLLO {
            ultimo_controllo = Instant::now();
            if persona_collegata() {
                break Motivo::Rientro;
            }
        }
        if let Some(sessione) = sessione.as_ref() {
            let mut sessione = sessione.borrow_mut();
            sessione.pump();
            if let Some(acquisizione) = acquisizione.as_mut() {
                let mut runtimes = sessione.runtimes_for_acquisition();
                acquisizione.ingest_all(&mut runtimes, adesso());
                let _ = acquisizione.take_concluded();
            }
            if ultimo_segno.elapsed() >= segno_ogni {
                ultimo_segno = Instant::now();
                if let Err(errore) = sign(
                    &archivio,
                    Keeper::Service,
                    adesso(),
                    &sessione.linked_live_accounts(),
                ) {
                    tracing::warn!(kind = errore.kind(), "segno di vita non scritto");
                }
            }
        }
        std::thread::sleep(GIRO);
    };

    // Il segno di chi lascia si scrive PRIMA di chiudere: gli account collegati
    // si leggono finché i client sono aperti.
    let collegati = sessione
        .as_ref()
        .map(|sessione| sessione.borrow().linked_live_accounts())
        .unwrap_or_default();
    let esito = if motivo == Motivo::Rientro && !collegati.is_empty() {
        sign(&archivio, Keeper::Service, adesso(), &collegati)
    } else {
        release_without_handover(&archivio, Keeper::Service, adesso())
    };
    if let Err(errore) = esito {
        tracing::warn!(kind = errore.kind(), "uscita del servizio non registrata");
    }
    if let Some(sessione) = sessione.as_ref() {
        sessione.borrow_mut().close_all();
    }
    tracing::info!(?motivo, "il servizio in background lascia l'acquisizione");
}
