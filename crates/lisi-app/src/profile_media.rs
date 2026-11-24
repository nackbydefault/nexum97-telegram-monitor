//! La scheda «Foto, biografia e stato» di un autore, nella schermata Persone
//! (PERSON-MEDIA-01 parte 2, ADR-0174).
//!
//! # Che cosa fa
//!
//! Apre, per un autore del monitoraggio scelto, la scheda con le osservazioni
//! già registrate e il comando per chiederne una nuova, con la ragione. La
//! richiesta passa dal servizio, che decide i rifiuti; qui si mostra ciò che
//! dice.
//!
//! # La foto
//!
//! I byte conservati si trasformano in pixel **soltanto per mostrarli**, in
//! [`photo_image`], con un tetto di dimensione e di memoria. Nessuna funzione
//! di questo modulo confronta la foto con altre, ne misura qualcosa o la
//! riscrive: una guardia lo sorveglia (ADR-0174, decisione 5).

use std::cell::RefCell;
use std::rc::Rc;

use lisi_core::SessionId;
use lisi_core::model::reason::OperationalReason;
use lisi_services::Database;
use lisi_services::profile_media::{
    ProfileMediaAttempt, ProfileMediaRequest, StoredProfileMediaObservation, is_chosen,
    mark_for_documents, observations, request_profile_media, status_in_words,
};
use slint::{ComponentHandle, ModelRc, SharedString, VecModel};

use crate::account::SharedSession;
use crate::{AppWindow, ProfileMediaEntry};

/// L'archivio della scheda.
pub struct ProfileMediaScreen {
    archive: Database,
}

/// Condiviso fra i gestori dei comandi.
pub type SharedProfileMedia = Rc<RefCell<ProfileMediaScreen>>;

/// Crea la scheda sull'archivio indicato.
#[must_use]
pub fn create_service(archive: Option<Database>) -> Option<SharedProfileMedia> {
    Some(Rc::new(RefCell::new(ProfileMediaScreen {
        archive: archive?,
    })))
}

/// La frase che compare una volta, in ambra, sopra le osservazioni.
pub const CAVEAT: &str = "Ciò che Telegram mostra di questo account in un istante. Non è \
                          un'identità: la foto può ritrarre un'altra persona o essere stata \
                          cambiata, e lo stato dipende dalle impostazioni di riservatezza.";

/// Il tetto dei lati della foto da mostrare, in pixel: l'immagine piccola del
/// profilo ne ha 160.
const MAX_SIDE: u32 = 1_024;

/// Il tetto della memoria per decodificarla.
const MAX_DECODE_BYTES: u64 = 16 * 1024 * 1024;

/// I pixel della foto, **soltanto per mostrarla**. `None` se i byte non sono
/// un JPEG leggibile entro i tetti: la scheda lo dice, e i byte restano
/// conservati come sono.
fn photo_image(byte: &[u8]) -> Option<slint::Image> {
    let mut lettore =
        image::ImageReader::with_format(std::io::Cursor::new(byte), image::ImageFormat::Jpeg);
    let mut tetti = image::Limits::default();
    tetti.max_image_width = Some(MAX_SIDE);
    tetti.max_image_height = Some(MAX_SIDE);
    tetti.max_alloc = Some(MAX_DECODE_BYTES);
    lettore.limits(tetti);
    let pixel = lettore.decode().ok()?.to_rgba8();
    let buffer = slint::SharedPixelBuffer::<slint::Rgba8Pixel>::clone_from_slice(
        pixel.as_raw(),
        pixel.width(),
        pixel.height(),
    );
    Some(slint::Image::from_rgba8(buffer))
}

/// Una riga della scheda. `scelta` dice se l'osservazione entra nei
/// documenti (PERSON-MEDIA-01 parte 3).
fn entry(osservazione: &StoredProfileMediaObservation, scelta: bool) -> ProfileMediaEntry {
    let foto = osservazione.photo.as_deref().and_then(photo_image);
    let nota_foto = match (&osservazione.photo, &foto, &osservazione.photo_not_read) {
        (Some(_), Some(_), _) => String::new(),
        (Some(_), None, _) => String::from("Foto conservata, ma qui non si può mostrare."),
        (None, _, Some(perche)) => perche.clone(),
        (None, _, None) if osservazione.outcome == "osservato" => {
            String::from("Nessuna foto visibile a questo account.")
        }
        (None, _, None) => String::new(),
    };
    ProfileMediaEntry {
        id: i32::try_from(osservazione.id).unwrap_or(-1),
        chosen: scelta,
        // Un numero che non entra nella schermata non si sceglie: il comando
        // porterebbe a un'altra osservazione.
        markable: osservazione.outcome == "osservato" && i32::try_from(osservazione.id).is_ok(),
        when: crate::lingua::schermo(format!(
            "Chiesto il {} da {}",
            osservazione.requested_at.to_readable_local(),
            osservazione.requested_by
        )),
        motive: crate::lingua::schermo(format!("Ragione: «{}»", osservazione.reason)),
        outcome: SharedString::from(match osservazione.outcome.as_str() {
            "osservato" => String::from("Osservato"),
            "rifiutato" => format!(
                "Rifiutato da Telegram. {}",
                osservazione.outcome_detail.as_deref().unwrap_or_default()
            ),
            _ => format!(
                "Non riuscito. {}",
                osservazione.outcome_detail.as_deref().unwrap_or_default()
            ),
        }),
        status: SharedString::from(osservazione.status.as_deref().map_or_else(
            String::new,
            |chiave| {
                format!(
                    "Stato: {}",
                    status_in_words(chiave, osservazione.status_was_online)
                )
            },
        )),
        bio: SharedString::from(
            osservazione
                .bio
                .as_deref()
                .map_or_else(String::new, |bio| format!("Biografia: «{bio}»")),
        ),
        has_photo: foto.is_some(),
        photo: foto.unwrap_or_default(),
        photo_note: SharedString::from(nota_foto),
    }
}

/// Riporta nella scheda le osservazioni dell'autore aperto.
pub fn refresh(window: &AppWindow, screen: &SharedProfileMedia, message: Option<&str>) {
    if let Some(testo) = message {
        window.set_profile_media_message(SharedString::from(testo));
    }
    if !window.get_profile_media_open() {
        return;
    }
    let sessione = SessionId::new(i64::from(window.get_participants_session_id()));
    let autore = window.get_profile_media_author().to_string();
    let schermata = screen.borrow();
    let righe: Vec<ProfileMediaEntry> = match observations(&schermata.archive, sessione, &autore) {
        Ok(lette) => lette
            .iter()
            .map(|osservazione| {
                // Una scelta che non si legge non è «scelta»: la riga
                // propone di sceglierla, e il servizio decide.
                let scelta = is_chosen(&schermata.archive, osservazione.id).unwrap_or(false);
                entry(osservazione, scelta)
            })
            .collect(),
        Err(errore) => {
            tracing::warn!(
                kind = errore.kind(),
                "osservazioni del profilo non leggibili"
            );
            Vec::new()
        }
    };
    window.set_profile_media_entries(ModelRc::from(Rc::new(VecModel::from(righe))));
}

/// Chiede foto, biografia e stato dell'autore aperto. Restituisce la frase
/// per l'operatore.
fn ask(window: &AppWindow, screen: &SharedProfileMedia, session: Option<&SharedSession>) -> String {
    // Prima ciò che l'operatore può correggere nel campo, poi ciò che dipende
    // dalla postazione.
    let motivo = window.get_profile_media_reason().to_string();
    let Ok(ragione) = OperationalReason::try_new(&motivo) else {
        return format!(
            "Scrivere una ragione operativa fra {} e {} caratteri; quella scritta ne ha {}. La \
             richiesta riguarda una persona, e chi la rilegge deve sapere perché.",
            lisi_core::model::reason::MIN_REASON_CHARS,
            lisi_core::model::reason::MAX_REASON_CHARS,
            motivo.trim().chars().count(),
        );
    };
    let Ok(operatore) = crate::operator::audit_actor() else {
        return String::from(
            "Non si riesce a stabilire chi stia agendo su questa postazione: la richiesta non \
             parte.",
        );
    };
    let Some(session) = session else {
        return String::from(
            "Questa esecuzione non ha la sessione degli account: la richiesta non parte, e non è \
             registrata.",
        );
    };
    let sessione = SessionId::new(i64::from(window.get_participants_session_id()));
    let autore = window.get_profile_media_author().to_string();
    // L'autorità si prende e si lascia, come per la ricerca puntuale: il
    // connettore si chiede subito dopo, con un prestito diverso.
    let richiesta = {
        let account = session.borrow();
        let Some(autorita) = account.authority() else {
            return account.refused("La richiesta di foto, biografia e stato");
        };
        ProfileMediaRequest::new(autorita, sessione, &autore, operatore, ragione)
    };
    let mut account = session.borrow_mut();
    let Some(runtime) = account.runtime_mut() else {
        return String::from(
            "Nessun account d'ufficio collegato: la richiesta non parte, e non è registrata.",
        );
    };
    let uuid = runtime.account_uuid().clone();
    let mut screen = screen.borrow_mut();
    match request_profile_media(
        runtime.connector_mut(),
        &uuid,
        &mut screen.archive,
        &richiesta,
        crate::account::now(),
    ) {
        Ok(ProfileMediaAttempt::Recorded { outcome, .. }) => match outcome {
            "osservato" => {
                String::from("Richiesta registrata: qui sotto, ciò che Telegram mostra.")
            }
            "rifiutato" => String::from("Telegram ha rifiutato; la richiesta resta registrata."),
            _ => String::from(
                "La richiesta non è arrivata a una risposta; resta registrata. Non vuol dire che \
                 il dato manchi.",
            ),
        },
        Ok(ProfileMediaAttempt::Refused(frase)) => frase,
        Err(errore) => {
            tracing::warn!(kind = errore.kind(), "richiesta del profilo non registrata");
            errore.operator_message()
        }
    }
}

/// Sceglie un'osservazione per i documenti, o la toglie. Restituisce la
/// frase per l'operatore.
fn mark(window: &AppWindow, screen: &SharedProfileMedia, id: i32, scelta: bool) -> String {
    let Ok(operatore) = crate::operator::audit_actor() else {
        return String::from(
            "Non si riesce a stabilire chi stia agendo su questa postazione: la scelta non si \
             registra.",
        );
    };
    let sessione = SessionId::new(i64::from(window.get_participants_session_id()));
    let mut schermata = screen.borrow_mut();
    match mark_for_documents(
        &mut schermata.archive,
        sessione,
        i64::from(id),
        scelta,
        &operatore,
        crate::account::now(),
    ) {
        Ok(Ok(frase)) => String::from(frase),
        Ok(Err(frase)) => frase,
        Err(errore) => {
            tracing::warn!(
                kind = errore.kind(),
                "scelta per i documenti non registrata"
            );
            errore.operator_message()
        }
    }
}

/// Collega i comandi della scheda.
pub fn wire(window: &AppWindow, screen: &SharedProfileMedia, session: Option<&SharedSession>) {
    window.set_profile_media_caveat(crate::lingua::schermo(CAVEAT));
    {
        let weak = window.as_weak();
        let screen = Rc::clone(screen);
        window.on_profile_media_open_for(move |autore, nome| {
            if crate::lock::refuse_while_locked("profile_media_open_for") {
                return;
            }
            let Some(window) = weak.upgrade() else { return };
            let chi = if nome.is_empty() {
                autore.clone()
            } else {
                nome
            };
            window.set_profile_media_title(crate::lingua::schermo(format!(
                "Foto, biografia e stato di {chi} (identificativo {autore})"
            )));
            window.set_profile_media_author(autore);
            window.set_profile_media_reason(SharedString::default());
            window.set_profile_media_open(true);
            refresh(&window, &screen, Some(""));
        });
    }
    {
        let weak = window.as_weak();
        window.on_profile_media_close(move || {
            if crate::lock::refuse_while_locked("profile_media_close") {
                return;
            }
            let Some(window) = weak.upgrade() else { return };
            window.set_profile_media_open(false);
            window.set_profile_media_entries(ModelRc::from(Rc::new(VecModel::from(Vec::<
                ProfileMediaEntry,
            >::new(
            )))));
        });
    }
    {
        let weak = window.as_weak();
        let screen = Rc::clone(screen);
        window.on_profile_media_mark(move |id, scelta| {
            if crate::lock::refuse_while_locked("profile_media_mark") {
                return;
            }
            let Some(window) = weak.upgrade() else { return };
            let frase = mark(&window, &screen, id, scelta);
            refresh(&window, &screen, Some(&frase));
        });
    }
    {
        let weak = window.as_weak();
        let screen = Rc::clone(screen);
        let session = session.map(Rc::clone);
        window.on_profile_media_ask(move || {
            if crate::lock::refuse_while_locked("profile_media_ask") {
                return;
            }
            let Some(window) = weak.upgrade() else { return };
            let frase = ask(&window, &screen, session.as_ref());
            refresh(&window, &screen, Some(&frase));
        });
    }
}

#[cfg(test)]
mod tests {
    use lisi_core::{SessionId, Timestamp};
    use lisi_services::profile_media::StoredProfileMediaObservation;

    /// Un JPEG sintetico di `larghezza` × `altezza`, grigio.
    fn jpeg(larghezza: u32, altezza: u32) -> Vec<u8> {
        let pixel = image::RgbImage::from_pixel(larghezza, altezza, image::Rgb([128, 128, 128]));
        let mut byte = Vec::new();
        let Ok(()) = pixel.write_to(
            &mut std::io::Cursor::new(&mut byte),
            image::ImageFormat::Jpeg,
        ) else {
            panic!("il JPEG di prova si scrive");
        };
        byte
    }

    fn osservazione(outcome: &str, foto: Option<Vec<u8>>) -> StoredProfileMediaObservation {
        StoredProfileMediaObservation {
            id: 1,
            session_id: SessionId::new(1),
            author_identifier: String::from("42"),
            account_uuid: None,
            requested_by: String::from("operatore.prova"),
            reason: String::from("Verifica dell'autore di un messaggio di minaccia"),
            requested_at: Timestamp::from_millis(1_800_000_000_000),
            outcome: String::from(outcome),
            outcome_detail: (outcome != "osservato").then(|| String::from("USER_ID_INVALID")),
            bio: (outcome == "osservato").then(|| String::from("Cronista")),
            status: (outcome == "osservato").then(|| String::from("di_recente")),
            status_was_online: None,
            photo_sha256: foto.as_ref().map(|_| "a".repeat(64)),
            photo: foto,
            photo_not_read: None,
        }
    }

    /// **La scheda dice chi ha chiesto, perché, e ciò che Telegram mostrava;
    /// la foto si mostra se è un JPEG leggibile, e un'assenza si spiega**
    /// (PERSON-MEDIA-01 parte 2). Prova negativa: byte che non sono una foto
    /// non diventano un'immagine.
    #[test]
    fn la_riga_dice_l_osservazione_e_mostra_la_foto_soltanto_se_leggibile() {
        let con_foto = super::entry(&osservazione("osservato", Some(jpeg(160, 160))), false);
        assert!(con_foto.has_photo);
        assert!(con_foto.when.contains("operatore.prova"));
        assert!(con_foto.motive.contains("minaccia"));
        assert_eq!(con_foto.status.as_str(), "Stato: visto di recente");
        assert_eq!(con_foto.bio.as_str(), "Biografia: «Cronista»");
        assert!(con_foto.photo_note.is_empty());

        let rotta = super::entry(&osservazione("osservato", Some(vec![1, 2, 3])), false);
        assert!(!rotta.has_photo, "tre byte non sono una foto");
        assert_eq!(
            rotta.photo_note.as_str(),
            "Foto conservata, ma qui non si può mostrare."
        );

        let senza = super::entry(&osservazione("osservato", None), false);
        assert_eq!(
            senza.photo_note.as_str(),
            "Nessuna foto visibile a questo account."
        );

        let rifiutata = super::entry(&osservazione("rifiutato", None), false);
        assert!(rifiutata.outcome.starts_with("Rifiutato da Telegram."));
        assert!(rifiutata.status.is_empty() && rifiutata.bio.is_empty());
        assert!(
            rifiutata.photo_note.is_empty(),
            "un rifiuto non dice «nessuna foto»"
        );
    }

    /// **Si sceglie per i documenti soltanto un'osservazione riuscita, e la
    /// riga dice se è scelta; il comando dalla finestra passa dal servizio**
    /// (PERSON-MEDIA-01 parte 3). Prova negativa: un rifiuto non si può
    /// scegliere, e un'osservazione che non c'è si dice.
    #[test]
    fn si_sceglie_dalla_scheda_soltanto_un_osservazione_riuscita() {
        let riuscita = super::entry(&osservazione("osservato", None), true);
        assert!(riuscita.markable && riuscita.chosen);
        assert_eq!(riuscita.id, 1);
        let rifiutata = super::entry(&osservazione("rifiutato", None), false);
        assert!(!rifiutata.markable, "un rifiuto non ha niente da riportare");

        i_slint_backend_testing::init_no_event_loop();
        let Ok(window) = crate::AppWindow::new() else {
            panic!("la finestra di prova si costruisce");
        };
        let Ok(archivio) = lisi_services::Database::open_in_memory() else {
            panic!("l'archivio di prova si apre");
        };
        let Some(screen) = super::create_service(Some(archivio)) else {
            panic!("la scheda nasce");
        };
        super::wire(&window, &screen, None);
        window.invoke_profile_media_mark(77, true);
        assert_eq!(
            window.get_profile_media_message().as_str(),
            "Questa osservazione non c'è più nell'archivio."
        );
    }

    /// **Una foto oltre il tetto dei lati non si decodifica** (ADR-0174): la
    /// decodifica è per mostrare l'immagine piccola del profilo, non altro.
    #[test]
    fn una_foto_oltre_il_tetto_non_si_decodifica() {
        assert!(super::photo_image(&jpeg(160, 160)).is_some());
        assert!(super::photo_image(&jpeg(super::MAX_SIDE + 1, 8)).is_none());
    }

    /// **La scheda si apre per l'autore, e la richiesta senza ragione o senza
    /// sessione si rifiuta dicendolo** (PERSON-MEDIA-01 parte 2).
    #[test]
    fn la_scheda_si_apre_e_i_rifiuti_si_dicono() {
        use slint::Model;

        i_slint_backend_testing::init_no_event_loop();
        let Ok(window) = crate::AppWindow::new() else {
            panic!("la finestra di prova si costruisce");
        };
        let Ok(archivio) = lisi_services::Database::open_in_memory() else {
            panic!("l'archivio di prova si apre");
        };
        let Some(screen) = super::create_service(Some(archivio)) else {
            panic!("la scheda nasce");
        };
        super::wire(&window, &screen, None);
        window.invoke_profile_media_open_for("42".into(), "Mario".into());
        assert!(window.get_profile_media_open());
        assert_eq!(
            window.get_profile_media_title().as_str(),
            "Foto, biografia e stato di Mario (identificativo 42)"
        );
        assert_eq!(window.get_profile_media_caveat().as_str(), super::CAVEAT);
        assert_eq!(window.get_profile_media_entries().row_count(), 0);

        window.invoke_profile_media_ask();
        assert!(
            window
                .get_profile_media_message()
                .contains("ragione operativa"),
            "{}",
            window.get_profile_media_message()
        );
        window.set_profile_media_reason("Verifica dell'autore di un messaggio di minaccia".into());
        window.invoke_profile_media_ask();
        assert!(
            window.get_profile_media_message().contains("non parte"),
            "{}",
            window.get_profile_media_message()
        );
        window.invoke_profile_media_close();
        assert!(!window.get_profile_media_open());
    }

    /// **La foto si decodifica in un punto solo, e niente la confronta**
    /// (ADR-0174, decisione 5). Prova negativa: `image::` fuori da questo
    /// modulo, o un `compare` qui → rossa.
    #[test]
    fn la_foto_si_decodifica_in_un_punto_solo_e_niente_la_confronta() {
        let cartella = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
        let Ok(voci) = std::fs::read_dir(&cartella) else {
            panic!("i sorgenti si leggono");
        };
        let produzione = |testo: &str| -> String {
            testo
                .split_once("#[cfg(test)]\nmod tests {")
                .map_or(testo, |(prima, _)| prima)
                .lines()
                .filter(|riga| !riga.trim_start().starts_with("//"))
                .collect::<Vec<_>>()
                .join("\n")
        };
        for voce in voci.flatten() {
            let percorso = voce.path();
            if percorso
                .file_name()
                .is_some_and(|nome| nome == "profile_media.rs")
            {
                continue;
            }
            let Ok(testo) = std::fs::read_to_string(&percorso) else {
                continue;
            };
            assert!(
                !produzione(&testo).contains("image::"),
                "{} decodifica immagini: soltanto profile_media.rs lo fa",
                percorso.display()
            );
        }
        let questo = produzione(include_str!("profile_media.rs")).to_lowercase();
        for vietato in [
            "compare",
            "similar",
            "distance",
            "embedding",
            "landmark",
            "resize",
            "histogram",
        ] {
            assert!(
                !questo.contains(vietato),
                "la foto non si analizza («{vietato}»)"
            );
        }
        assert_eq!(
            questo.matches(".decode()").count(),
            1,
            "una decodifica sola, in `photo_image`"
        );
    }
}
