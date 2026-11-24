//! Apertura di un messaggio nell'applicazione Telegram, con ripiego sul browser.
//!
//! # Perche' esiste, e perche' non viola ADR-0018
//!
//! ADR-0018 ammette **solo** schemi web e vieta gli handler di protocollo
//! arbitrari. La ragione e' la provenienza: quell'URL **arriva dal contenuto
//! acquisito**, cioe' da una fonte ostile per ipotesi, e lasciare che una
//! sorgente ostile scelga lo schema significherebbe lasciarle scegliere quale
//! programma della postazione avviare.
//!
//! Il collegamento a un messaggio monitorato ha una provenienza diversa: **lo
//! costruiamo noi** da due identificativi numerici, in
//! `lisi-telegram::permalink`. Nessuna stringa del contenuto vi entra.
//!
//! La distinzione non e' una scappatoia, ed e' verificabile: questo modulo
//! **non accetta un URL qualunque**. Accetta soltanto la forma
//! `https://t.me/c/<numero>/<numero>` che quel calcolo produce, e da essa
//! ricava l'indirizzo per l'applicazione. Qualunque altra cosa - compreso un
//! `tg://` gia' pronto passato da un chiamante - viene rifiutata.
//!
//! # Perche' non basta aprire il browser
//!
//! Il collegamento `https://t.me/...` apre una pagina che a sua volta propone
//! di aprire Telegram: due clic e una finestra che nessuno voleva. Per chi
//! consulta decine di avvisi in un turno e' attrito che si somma.
//!
//! # Il ripiego non si indovina
//!
//! Se Telegram Desktop non e' installato, `ShellExecuteW` **lo dice**: restituisce
//! `SE_ERR_NOASSOC`. Si distingue quel caso da ogni altro errore e si apre il
//! browser, invece di lasciare che il clic non produca nulla.
//!
//! # Invarianti di sicurezza
//!
//! 1. L'unica forma accettata e' `https://t.me/c/<cifre>/<cifre>`; le due parti
//!    numeriche sono verificate cifra per cifra prima di comporre l'indirizzo.
//! 2. Nessun carattere proveniente dal contenuto acquisito raggiunge la
//!    chiamata: l'indirizzo per l'applicazione e' composto da due numeri.
//! 3. Il resto delle invarianti e' quello di `browser`, che esegue la chiamata.

use crate::error::{PlatformError, PlatformResult};

/// Prefisso dell'unica forma di collegamento accettata.
const PRIVATE_POST_PREFIX: &str = "https://t.me/c/";

/// Apre il messaggio in Telegram, ripiegando sul browser quando non si puo'.
///
/// Restituisce `Ok` anche quando ha aperto il browser invece dell'applicazione:
/// per chi chiama il risultato e' lo stesso — il messaggio e' stato mostrato.
///
/// # Errori
///
/// Rifiuta ogni indirizzo che non sia un collegamento a messaggio costruito dal
/// prodotto, e riporta l'errore del sistema quando nessuna delle due strade
/// riesce.
pub fn open_message(url: &str) -> PlatformResult<()> {
    let Some((channel, post)) = private_post_parts(url) else {
        // Non e' un collegamento a messaggio: si apre nel browser, dove la
        // validazione ordinaria di ADR-0018 fa il proprio lavoro.
        return crate::browser::open_in_browser(url);
    };

    let application_link = format!("tg://privatepost?channel={channel}&post={post}");

    match crate::browser::launch_raw(&application_link) {
        Ok(()) => Ok(()),
        // Telegram Desktop non e' installato: e' il solo errore che giustifica
        // il ripiego, ed e' distinto dagli altri dal sistema.
        Err(PlatformError::NoAssociatedApplication) => crate::browser::open_in_browser(url),
        Err(other) => Err(other),
    }
}

/// Le due parti numeriche di un collegamento a messaggio, se lo e'.
///
/// La verifica e' cifra per cifra e non con una divisione approssimativa: e'
/// cio' che garantisce che nulla di arbitrario finisca nell'indirizzo composto.
fn private_post_parts(url: &str) -> Option<(&str, &str)> {
    let rest = url.trim().strip_prefix(PRIVATE_POST_PREFIX)?;
    let (channel, post) = rest.split_once('/')?;

    if channel.is_empty() || post.is_empty() {
        return None;
    }
    if !channel.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    if !post.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }

    Some((channel, post))
}

#[cfg(test)]
mod tests {
    use super::{PRIVATE_POST_PREFIX, private_post_parts};

    #[test]
    fn a_link_built_by_the_product_is_recognised() {
        assert_eq!(
            private_post_parts("https://t.me/c/1234567890/42"),
            Some(("1234567890", "42"))
        );
    }

    #[test]
    fn nothing_that_is_not_two_numbers_is_recognised() {
        // E' la prova che conta: se una di queste passasse, un frammento
        // arbitrario finirebbe dentro l'indirizzo `tg://` composto.
        for hostile in [
            "https://t.me/c/1234/42?extra=1",
            "https://t.me/c/../../42",
            "https://t.me/c/1234/4 2",
            "https://t.me/c/abc/42",
            "https://t.me/c/1234/abc",
            "https://t.me/c/1234",
            "https://t.me/c//42",
            "https://t.me/c/1234/",
            "https://t.me/canale/42",
            "https://esempio.invalid/c/1234/42",
            "tg://privatepost?channel=1&post=1",
            "javascript:alert(1)",
        ] {
            assert_eq!(
                private_post_parts(hostile),
                None,
                "non deve essere riconosciuto come collegamento a messaggio: {hostile}"
            );
        }
    }

    #[test]
    fn a_ready_made_application_link_is_not_accepted_from_a_caller() {
        // L'indirizzo per l'applicazione lo compone questo modulo, mai il
        // chiamante: e' cio' che rende verificabile l'affermazione che nessuna
        // stringa esterna sceglie il programma da avviare.
        assert_eq!(private_post_parts("tg://resolve?domain=x"), None);
    }

    #[test]
    fn the_accepted_prefix_is_a_web_scheme() {
        // Se il prefisso smettesse di essere https, il ripiego aprirebbe
        // qualcosa che la validazione di ADR-0018 rifiuterebbe.
        assert!(PRIVATE_POST_PREFIX.starts_with("https://"));
    }
}
