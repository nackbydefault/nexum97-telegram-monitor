//! Consegna delle notifiche al riquadro di avviso di Windows.
//!
//! Le scelte sono in `docs/adr/ADR-0025-WINDOWS-TOAST.md`.
//!
//! # Perché questo modulo sta qui e non in `lisi-platform`
//!
//! `lisi-platform` sa mostrare un avviso; `lisi-services` sa decidere se e che
//! cosa notificare. Nessuno dei due conosce l'altro, ed è giusto così: il
//! motore delle notifiche si prova senza Windows, e il crate di piattaforma non
//! sa nulla di Telegram né di riservatezza.
//!
//! Questo modulo è il punto in cui i due si incontrano, e `lisi-app` è dove i
//! pezzi si mettono insieme.
//!
//! # Il ripiego non è un dettaglio
//!
//! Windows mostra un avviso solo a un'applicazione che ha un collegamento nel
//! menu Start con il proprio `AppUserModelID`. L'eseguibile avviato da una
//! cartella di sviluppo non ce l'ha, e il sistema rifiuta: **è il caso normale
//! finché il prodotto non è installato.**
//!
//! Un rifiuto non deve far perdere la notifica. La decisione di notificare è
//! già stata presa, registrata nell'audit e scritta nel centro notifiche
//! dell'applicazione: il riquadro è la sua **resa**, non il fatto. Quando la
//! resa non riesce, resta la riga redatta di prima.
//!
//! # «Consegnato» non vuol dire «visto»
//!
//! Windows **accetta** la chiamata anche quando poi non mostra nulla: a
//! un'applicazione senza collegamento nel menu Start, o con gli avvisi
//! disattivati dall'utente, la richiesta va a buon fine e il riquadro non
//! compare. Il programma non ha modo di saperlo.
//!
//! Per questo il registro scrive «consegnato a Windows» e non «mostrato». Un
//! registro che affermasse il secondo direbbe un fatto non verificato, e chi lo
//! rileggesse cercando perché l'operatore non ha visto l'avviso vi troverebbe
//! scritto che l'ha visto.

use lisi_services::notification::{Notification, Notifier};

/// Consegna le notifiche al riquadro di avviso di Windows.
///
/// Se il sistema rifiuta, ripiega sulla riga redatta nel registro.
#[derive(Debug, Default)]
pub struct WindowsToastNotifier {
    /// Se il sistema ha già rifiutato in questa esecuzione.
    ///
    /// Serve a registrare il **motivo** una volta sola. Su una postazione senza
    /// collegamento nel menu Start il rifiuto si ripete a ogni avviso, e una
    /// riga per ciascuno riempirebbe il registro di rumore che dice sempre la
    /// stessa cosa — rendendo più difficile trovare quello che non la dice.
    already_refused: bool,
}

impl Notifier for WindowsToastNotifier {
    fn deliver(&mut self, notification: &Notification) {
        // Si consegnano SOLO titolo e corpo. Livello, riservatezza e
        // identificativo del contenuto sono metadati per chi registra, non per
        // chi guarda: in modalità riservata il corpo è generico apposta, perché
        // l'avviso può comparire su una schermata bloccata, e aggiungervi il
        // livello riporterebbe in vista ciò che quella modalità nasconde.
        let shown = lisi_platform::show_toast(&notification.title, &notification.body);

        match shown {
            Ok(()) => {
                // «Consegnato», non «mostrato», ed è una distinzione che è
                // costata un test rosso: Windows **accetta** la chiamata anche
                // quando poi non mostra nulla — per esempio a un'applicazione
                // priva di collegamento nel menu Start, o con gli avvisi
                // disattivati dall'utente. Un registro che scrivesse «mostrato»
                // affermerebbe un fatto che il programma non ha modo di
                // verificare, e chi lo rileggesse cercando perché l'operatore
                // non ha visto l'avviso troverebbe scritto che l'ha visto.
                //
                // La riga resta **redatta**: è la traccia che quell'avviso è
                // uscito, e deve poter essere riletta senza rivelare più di
                // quanto l'avviso stesso rivelasse.
                tracing::info!(
                    contenuto = notification.content_id.map(lisi_core::ContentId::get),
                    livello = notification.level,
                    riservatezza = notification.privacy.as_str(),
                    "avviso consegnato a Windows"
                );
            }
            Err(error) => {
                if !self.already_refused {
                    self.already_refused = true;
                    tracing::info!(
                        errore = %error,
                        "il sistema non mostra avvisi a questa applicazione: gli avvisi \
                         restano nel centro notifiche dell'applicazione. È il caso \
                         normale finché il prodotto non è installato, perché Windows \
                         li attribuisce solo a chi ha un collegamento nel menu Start"
                    );
                }

                tracing::info!(
                    contenuto = notification.content_id.map(lisi_core::ContentId::get),
                    livello = notification.level,
                    riservatezza = notification.privacy.as_str(),
                    "notifica registrata senza riquadro di avviso"
                );
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use lisi_core::model::NotificationPrivacy;
    use lisi_core::{ContentId, Timestamp};
    use lisi_services::notification::{Notification, Notifier};

    use super::WindowsToastNotifier;

    fn a_notification() -> Notification {
        Notification {
            content_id: Some(ContentId::new(1)),
            title: String::from("Fonte di prova"),
            body: String::from("Termine trovato"),
            url: None,
            level: 3,
            privacy: NotificationPrivacy::Full,
            emitted_at: Timestamp::from_millis(1_700_000_000_000),
        }
    }

    /// Consegnare una notifica non deve mai far cadere il chiamante.
    ///
    /// È la proprietà che conta di questo modulo. Il riquadro è la **resa** di
    /// una decisione già presa e registrata: che la resa non riesca è
    /// ammissibile, che porti via la decisione no.
    ///
    /// # Che cosa questo test ha insegnato
    ///
    /// Nella prima stesura pretendeva che il sistema **rifiutasse**, perché mi
    /// aspettavo un errore senza collegamento nel menu Start. È fallito:
    /// Windows **accetta** la chiamata e restituisce successo. Non significa
    /// che il riquadro sia comparso — significa che il programma non ha modo di
    /// saperlo, ed è per questo che il registro scrive «consegnato» e non
    /// «mostrato».
    ///
    /// Che il riquadro **compaia davvero** non lo può dire alcun test: è la
    /// sezione N del pilot.
    #[test]
    fn delivering_a_notification_never_takes_the_decision_down_with_it() {
        let mut notifier = WindowsToastNotifier::default();

        // Due consegne: qualunque cosa faccia il sistema — mostrare, accettare
        // e ignorare, rifiutare — la seconda deve comportarsi come la prima.
        notifier.deliver(&a_notification());
        notifier.deliver(&a_notification());
    }
}
