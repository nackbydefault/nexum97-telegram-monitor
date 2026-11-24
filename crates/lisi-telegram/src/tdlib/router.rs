//! L'instradatore di `td_receive`: ogni aggiornamento al suo account
//! (MULTI-ACCOUNT-02, ADR-0173, decisione 1).
//!
//! # Il problema
//!
//! TDLib consegna gli oggetti di **tutti** i client del processo da un'unica
//! funzione, `td_receive`. Se ogni connettore la chiama per conto suo, con due
//! account il connettore del primo può ricevere — e attribuire al proprio
//! account — un messaggio arrivato al secondo. Con un account solo il difetto
//! non si vede, ed è per questo che va chiuso prima di averne due.
//!
//! # La soluzione
//!
//! Un instradatore, uno per processo attorno all'unica libreria, è il solo a
//! chiamare `td_receive`. Ogni connettore riceve attraverso la propria
//! maniglia ([`RoutedBackend`]), che ricorda il proprio client: un oggetto con
//! un altro `@client_id` va nella coda di quel client, e lo riceverà il suo
//! connettore.
//!
//! # Che cosa non fa
//!
//! Non interpreta gli oggetti oltre il `@client_id` al primo livello, e non
//! tocca l'`unsafe`, che resta in `ffi.rs` (ADR-0003).

use std::collections::{BTreeMap, VecDeque};
use std::sync::{Arc, Mutex, PoisonError};

use std::path::Path;

use crate::error::TelegramResult;
use crate::tdlib::ffi::TdJsonLibrary;
use crate::tdlib::live::{TdJsonBackend, top_level_number};

/// Quanti oggetti si tengono, al più, nella coda di un client che nessuno sta
/// leggendo. Oltre, si perdono i più vecchi, e si contano.
pub const MAX_QUEUED_PER_CLIENT: usize = 10_000;

/// Lo stato dell'instradatore: le code per client e quanto si è perso.
#[derive(Debug, Default)]
struct RouterState {
    queues: BTreeMap<i32, VecDeque<String>>,
    dropped: u64,
}

/// L'instradatore condiviso, attorno all'unica libreria del processo.
#[derive(Debug)]
pub struct TdJsonRouter<L> {
    library: L,
    state: Mutex<RouterState>,
}

/// Il `@client_id` al primo livello di un oggetto, se c'è.
fn client_of(json: &str) -> Option<i32> {
    top_level_number(json, "@client_id").and_then(|id| i32::try_from(id).ok())
}

impl<L: TdJsonBackend> TdJsonRouter<L> {
    /// Un instradatore attorno alla libreria.
    #[must_use]
    pub fn new(library: L) -> Arc<Self> {
        Arc::new(Self {
            library,
            state: Mutex::new(RouterState::default()),
        })
    }

    /// Una maniglia per un connettore, che non ha ancora un client.
    #[must_use]
    pub fn handle(self: &Arc<Self>) -> RoutedBackend<L> {
        RoutedBackend {
            router: Arc::clone(self),
            client: Mutex::new(None),
        }
    }

    /// Quanti oggetti si sono persi per code piene.
    #[must_use]
    pub fn dropped(&self) -> u64 {
        self.lock().dropped
    }

    /// Il lock dello stato, recuperato se avvelenato: le code restano
    /// coerenti a ogni operazione, e i requisiti vietano il panico.
    fn lock(&self) -> std::sync::MutexGuard<'_, RouterState> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Riceve per `own`: prima dalla sua coda, poi da `td_receive`. Un oggetto
    /// di un altro client va nella coda di quello, e questa chiamata restituisce
    /// niente; un oggetto senza `@client_id` va a chi sta leggendo.
    fn receive_for(
        &self,
        own: Option<i32>,
        timeout_seconds: f64,
    ) -> TelegramResult<Option<String>> {
        let mut guardia = self.lock();
        let stato: &mut RouterState = &mut guardia;
        if let Some(id) = own
            && let Some(json) = stato.queues.get_mut(&id).and_then(VecDeque::pop_front)
        {
            return Ok(Some(json));
        }
        let Some(json) = self.library.receive(timeout_seconds)? else {
            return Ok(None);
        };
        match (client_of(&json), own) {
            (Some(destinatario), Some(id)) if destinatario != id => {
                let coda = stato.queues.entry(destinatario).or_default();
                if coda.len() >= MAX_QUEUED_PER_CLIENT {
                    coda.pop_front();
                    stato.dropped = stato.dropped.saturating_add(1);
                    tracing::warn!(
                        client = destinatario,
                        "coda di un client piena: perso l'oggetto piu' vecchio"
                    );
                }
                coda.push_back(json);
                Ok(None)
            }
            _ => Ok(Some(json)),
        }
    }
}

/// La maniglia di un connettore: riceve soltanto ciò che è del suo client.
#[derive(Debug)]
pub struct RoutedBackend<L> {
    router: Arc<TdJsonRouter<L>>,
    client: Mutex<Option<i32>>,
}

impl<L> RoutedBackend<L> {
    /// Il client di questa maniglia, se è stato creato.
    fn own(&self) -> Option<i32> {
        *self.client.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

impl<L: TdJsonBackend> TdJsonBackend for RoutedBackend<L> {
    fn create_client_id(&self) -> TelegramResult<i32> {
        let id = self.router.library.create_client_id()?;
        *self.client.lock().unwrap_or_else(PoisonError::into_inner) = Some(id);
        Ok(id)
    }

    fn send(&self, client_id: i32, request: &str) -> TelegramResult<()> {
        self.router.library.send(client_id, request)
    }

    fn receive(&self, timeout_seconds: f64) -> TelegramResult<Option<String>> {
        self.router.receive_for(self.own(), timeout_seconds)
    }

    fn execute(&self, request: &str) -> TelegramResult<Option<String>> {
        self.router.library.execute(request)
    }
}

/// L'instradatore del processo, attorno all'unica libreria caricata: il primo
/// connettore reale lo crea, gli altri lo condividono (ADR-0173).
static SHARED: Mutex<Option<Arc<TdJsonRouter<TdJsonLibrary>>>> = Mutex::new(None);

/// L'instradatore condiviso del processo, caricando la libreria la prima
/// volta.
///
/// La libreria è una per processo: chiamate successive con un altro percorso
/// ricevono l'instradatore già creato, perché due librerie sarebbero due
/// `td_receive` che si rubano gli oggetti.
///
/// # Errori
///
/// Restituisce l'errore del caricamento se la libreria non si carica.
pub fn shared_router(path: &Path) -> TelegramResult<Arc<TdJsonRouter<TdJsonLibrary>>> {
    let mut condiviso = SHARED.lock().unwrap_or_else(PoisonError::into_inner);
    if let Some(router) = condiviso.as_ref() {
        return Ok(Arc::clone(router));
    }
    let router = TdJsonRouter::new(TdJsonLibrary::load(path)?);
    *condiviso = Some(Arc::clone(&router));
    Ok(router)
}
#[cfg(test)]
mod tests {
    use std::collections::VecDeque;
    use std::sync::Mutex;

    use super::{MAX_QUEUED_PER_CLIENT, TdJsonRouter};
    use crate::error::TelegramResult;
    use crate::tdlib::live::TdJsonBackend;

    /// Una libreria finta: crea client numerati da 1, e consegna gli oggetti
    /// nell'ordine in cui li si mette, a chiunque chiami `receive`, come
    /// `td_receive`.
    #[derive(Debug, Default)]
    struct FakeTd {
        prossimo: Mutex<i32>,
        coda: Mutex<VecDeque<String>>,
    }

    impl FakeTd {
        fn con(oggetti: &[&str]) -> Self {
            Self {
                prossimo: Mutex::new(0),
                coda: Mutex::new(oggetti.iter().map(|o| (*o).to_owned()).collect()),
            }
        }
    }

    impl TdJsonBackend for FakeTd {
        fn create_client_id(&self) -> TelegramResult<i32> {
            let Ok(mut prossimo) = self.prossimo.lock() else {
                panic!("il lock di prova non e' avvelenato");
            };
            *prossimo += 1;
            Ok(*prossimo)
        }

        fn send(&self, _client_id: i32, _request: &str) -> TelegramResult<()> {
            Ok(())
        }

        fn receive(&self, _timeout_seconds: f64) -> TelegramResult<Option<String>> {
            let Ok(mut coda) = self.coda.lock() else {
                panic!("il lock di prova non e' avvelenato");
            };
            Ok(coda.pop_front())
        }

        fn execute(&self, _request: &str) -> TelegramResult<Option<String>> {
            Ok(None)
        }
    }

    /// **Ogni oggetto va al connettore del suo client: un messaggio del
    /// secondo account non arriva al primo** (MULTI-ACCOUNT-02, ADR-0173,
    /// criterio 1; prova negativa: l'instradamento tolto → rossa).
    #[test]
    fn ogni_oggetto_va_al_suo_account() {
        let router = TdJsonRouter::new(FakeTd::con(&[
            r#"{"@type":"updateNewMessage","message":{"chat_id":-1002},"@client_id":2}"#,
            r#"{"@type":"updateNewMessage","message":{"chat_id":-1001},"@client_id":1}"#,
            r#"{"@type":"updateOption","name":"version"}"#,
        ]));
        let primo = router.handle();
        let secondo = router.handle();
        let (Ok(1), Ok(2)) = (primo.create_client_id(), secondo.create_client_id()) else {
            panic!("i client di prova devono nascere in ordine");
        };

        // Il primo legge: l'oggetto del secondo non gli arriva.
        assert_eq!(primo.receive(0.0).ok(), Some(None), "l'oggetto del secondo");
        let Ok(Some(suo)) = primo.receive(0.0) else {
            panic!("il primo deve ricevere il suo oggetto");
        };
        assert!(suo.contains("-1001"), "{suo}");
        // Un oggetto senza client va a chi legge.
        let Ok(Some(del_processo)) = primo.receive(0.0) else {
            panic!("un oggetto senza client va a chi legge");
        };
        assert!(del_processo.contains("updateOption"));

        // Il secondo trova il suo nella sua coda.
        let Ok(Some(suo)) = secondo.receive(0.0) else {
            panic!("il secondo deve ricevere il suo oggetto dalla coda");
        };
        assert!(suo.contains("-1002"), "{suo}");
        assert_eq!(secondo.receive(0.0).ok(), Some(None));
    }

    /// **Conta soltanto il `@client_id` del primo livello**: uno annidato non
    /// decide il destinatario (criterio 1).
    #[test]
    fn conta_soltanto_il_client_del_primo_livello() {
        let router = TdJsonRouter::new(FakeTd::con(&[
            r#"{"@type":"x","inner":{"@client_id":2},"@client_id":1}"#,
        ]));
        let primo = router.handle();
        let secondo = router.handle();
        let (Ok(1), Ok(2)) = (primo.create_client_id(), secondo.create_client_id()) else {
            panic!("i client di prova devono nascere in ordine");
        };
        assert!(matches!(primo.receive(0.0), Ok(Some(_))));
        assert_eq!(secondo.receive(0.0).ok(), Some(None));
    }

    /// **La coda di un client che nessuno legge ha un tetto, e ciò che si
    /// perde si conta** (criterio 2).
    #[test]
    fn la_coda_di_un_client_ha_un_tetto() {
        let oggetti: Vec<String> = (0..=MAX_QUEUED_PER_CLIENT)
            .map(|indice| format!(r#"{{"@type":"x","n":{indice},"@client_id":2}}"#))
            .collect();
        let riferimenti: Vec<&str> = oggetti.iter().map(String::as_str).collect();
        let router = TdJsonRouter::new(FakeTd::con(&riferimenti));
        let primo = router.handle();
        let secondo = router.handle();
        let (Ok(1), Ok(2)) = (primo.create_client_id(), secondo.create_client_id()) else {
            panic!("i client di prova devono nascere in ordine");
        };
        for _ in 0..=MAX_QUEUED_PER_CLIENT {
            assert_eq!(primo.receive(0.0).ok(), Some(None));
        }
        assert_eq!(router.dropped(), 1);
        let Ok(Some(primo_rimasto)) = secondo.receive(0.0) else {
            panic!("il secondo deve trovare la sua coda");
        };
        assert!(
            primo_rimasto.contains(r#""n":1,"#),
            "il piu' vecchio si e' perso"
        );
    }
}
