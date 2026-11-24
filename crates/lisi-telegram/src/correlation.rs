//! A quale richiesta appartiene una risposta.
//!
//! # Il problema, e perché non è teorico
//!
//! TDLib ha **una coda sola**. Le risposte a tutte le richieste e tutti gli
//! aggiornamenti spontanei escono dallo stesso `receive`, mescolati e senza
//! alcun ordine garantito. Chi manda due richieste e legge la coda deve
//! decidere, per ogni messaggio che arriva, a chi appartenga.
//!
//! Il modo naturale di farlo — e quello che questo prodotto usava prima di
//! questa milestone — è **guardare il tipo**: «è arrivato un `chats`, quindi è
//! la risposta al mio `getChats`». Funziona finché c'è una richiesta sola per
//! tipo. Con due, il conteggio dei tipi è l'unica cosa che resta, e un errore
//! che arriva in mezzo non si sa di chi sia: il codice lo assorbiva
//! commentando «è quasi sempre la risposta a `loadChats`».
//!
//! **«Quasi sempre» è il punto.** Un errore su `getChats` — un limite di
//! frequenza, una sessione scaduta — veniva contato come benigno, e l'elenco
//! delle fonti risultava semplicemente più corto, senza che nulla lo
//! dichiarasse.
//!
//! # La soluzione: ogni richiesta porta un identificativo, e nessuno lo riusa
//!
//! TDLib rimanda indietro il campo `@extra` così come lo riceve. Questo modulo
//! ne assegna uno per richiesta, tiene il conto di ciò che è in attesa, e sa
//! dire di chi sia ogni risposta.
//!
//! # La garanzia strutturale: un identificativo non si può fabbricare
//!
//! [`RequestId`] ha il campo **privato** e **nessun costruttore pubblico**: lo
//! conia soltanto il correlatore, da un contatore che cresce e non torna mai
//! indietro. Non si può inventarne uno, e non si può riusare quello di una
//! richiesta conclusa.
//!
//! Perché conta: se gli identificativi si riusassero, una risposta arrivata in
//! ritardo per la richiesta *n* verrebbe consegnata alla richiesta *n* nuova, e
//! **nessuno se ne accorgerebbe** — la risposta ha la forma giusta, arriva nel
//! momento giusto, e riguarda un'altra domanda. È il difetto peggiore di questa
//! famiglia: silenzioso, plausibile, e riproducibile solo sotto carico.
//!
//! # Le tre cose che si dichiarano invece di tacerle
//!
//! 1. **Una scadenza non è una risposta.** [`Resolution::TimedOut`] dice che
//!    entro il termine dichiarato non è arrivato nulla; non dice che la
//!    risposta fosse negativa, né che l'elenco fosse vuoto.
//! 2. **Una risposta a nessuno si dichiara.** Se arriva l'esito di una
//!    richiesta già scaduta, non si butta in silenzio: buttarlo nasconderebbe
//!    che i termini sono troppo stretti, e i termini si correggono soltanto se
//!    qualcuno sa che sono stati superati.
//! 3. **Un aggiornamento spontaneo non è la risposta a niente.** Arriva dalla
//!    stessa coda e non appartiene ad alcuna richiesta: [`Delivery`] lo tiene
//!    separato per costruzione.
//!
//! # Questo modulo non conosce TDLib
//!
//! Non carica alcuna libreria, non contiene `unsafe`, non conosce il formato
//! JSON e non ha bisogno della feature `tdlib-runtime`: riceve messaggi già
//! classificati e restituisce a chi appartengono. **È provabile per intero su
//! una macchina che TDLib non ce l'ha**, ed è la ragione per cui è un modulo a
//! parte — un'infrastruttura che si può provare solo dal vivo è
//! un'infrastruttura che nessuno prova.

use std::collections::BTreeMap;
use std::fmt;

use lisi_core::Timestamp;

/// Quante richieste possono restare in attesa nello stesso momento.
///
/// # Perché un limite
///
/// Perché ogni richiesta in attesa occupa memoria finché non arriva la risposta
/// o scade il termine. Senza limite, una libreria che smettesse di rispondere
/// farebbe crescere l'attesa senza fine, e il primo segnale sarebbe la memoria
/// della postazione.
///
/// **Duecentocinquantasei** è largo per l'uso previsto — le richieste di questo
/// prodotto sono poche e in sequenza — e stretto abbastanza da accorgersi di
/// una perdita. Oltre, la registrazione **si rifiuta**: meglio una richiesta
/// che non parte di una attesa che non finisce.
pub const DEFAULT_PENDING_LIMIT: usize = 256;

/// L'identificativo di una richiesta in attesa.
///
/// # Perché il campo è privato e non c'è un costruttore pubblico
///
/// Perché soltanto il correlatore deve poterne coniare, e da un contatore che
/// **non torna mai indietro**. Un identificativo fabbricato altrove, o riusato
/// dopo che la sua richiesta è finita, farebbe consegnare la risposta di una
/// domanda alla domanda sbagliata: la risposta avrebbe la forma giusta,
/// arriverebbe nel momento giusto, e nessuno se ne accorgerebbe.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RequestId(u64);

impl RequestId {
    /// Il valore da mettere nel campo `@extra` della richiesta.
    ///
    /// Si chiama così e non `get` perché chi lo legge lontano da qui deve
    /// vedere, nel nome, che è un valore da rimandare indietro identico e non
    /// un numero su cui fare aritmetica.
    #[must_use]
    pub const fn as_extra(self) -> u64 {
        self.0
    }
}

impl fmt::Display for RequestId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}", self.0)
    }
}

/// Una richiesta partita e non ancora conclusa.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingRequest {
    /// L'identificativo, coniato dal correlatore.
    pub id: RequestId,
    /// Che cosa è stato chiesto, per la frase che l'operatore legge.
    ///
    /// È il nome della funzione TDLib — `getChats`, `getMessageLink` — e non il
    /// corpo della richiesta: il corpo può contenere identificativi di chat, e
    /// una frase di diagnostica non è il posto in cui farli comparire.
    pub kind: String,
    /// Quando è partita.
    pub sent_at: Timestamp,
    /// Entro quando ci si aspetta una risposta.
    pub deadline: Timestamp,
}

impl PendingRequest {
    /// Da quanto si aspetta, a un dato istante.
    #[must_use]
    pub const fn waited_ms(&self, now: Timestamp) -> i64 {
        now.as_millis() - self.sent_at.as_millis()
    }

    /// Se il termine è passato.
    #[must_use]
    pub const fn is_expired(&self, now: Timestamp) -> bool {
        now.as_millis() >= self.deadline.as_millis()
    }
}

/// Un messaggio uscito dalla coda, già classificato.
///
/// # Perché tre varianti e non due
///
/// Perché un **errore** di TDLib è la conclusione di una richiesta, non la sua
/// assenza: chi la aspettava ha una risposta, ed è negativa. Confonderlo con
/// una scadenza direbbe «non è arrivato niente» quando invece è arrivato un
/// rifiuto motivato.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Incoming {
    /// L'esito positivo di una richiesta.
    Answer {
        /// A chi appartiene.
        id: RequestId,
        /// Il corpo, così com'è arrivato.
        payload: String,
    },
    /// L'esito negativo di una richiesta.
    Failure {
        /// A chi appartiene.
        id: RequestId,
        /// Codice dichiarato da TDLib.
        code: i32,
        /// Messaggio dichiarato da TDLib.
        message: String,
    },
    /// Un aggiornamento spontaneo: **non è la risposta a niente**.
    Unsolicited {
        /// Il corpo, così com'è arrivato.
        payload: String,
    },
}

/// Come una richiesta si è conclusa.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Resolution {
    /// È arrivata una risposta.
    Answered {
        /// La richiesta che aspettava.
        request: PendingRequest,
        /// Il corpo della risposta.
        payload: String,
        /// Quanto si è aspettato.
        waited_ms: i64,
    },
    /// È arrivato un errore: la richiesta è conclusa, e l'esito è negativo.
    Failed {
        /// La richiesta che aspettava.
        request: PendingRequest,
        /// Codice dichiarato da TDLib.
        code: i32,
        /// Messaggio dichiarato da TDLib.
        message: String,
        /// Quanto si è aspettato.
        waited_ms: i64,
    },
    /// Il termine è passato senza che arrivasse nulla.
    ///
    /// **Non è una risposta negativa.** Non dice che la richiesta sia stata
    /// rifiutata, né che il risultato fosse vuoto: dice che entro il termine
    /// dichiarato non è arrivato niente.
    TimedOut {
        /// La richiesta che aspettava.
        request: PendingRequest,
        /// Quanto si è aspettato prima di rinunciare.
        waited_ms: i64,
    },
}

impl Resolution {
    /// La richiesta a cui l'esito appartiene.
    #[must_use]
    pub const fn request(&self) -> &PendingRequest {
        match self {
            Self::Answered { request, .. }
            | Self::Failed { request, .. }
            | Self::TimedOut { request, .. } => request,
        }
    }

    /// Se la richiesta ha avuto una risposta, qualunque essa sia.
    ///
    /// Un errore **è** una risposta: chi la aspettava sa com'è andata. Una
    /// scadenza no.
    #[must_use]
    pub const fn was_answered(&self) -> bool {
        matches!(self, Self::Answered { .. } | Self::Failed { .. })
    }

    /// Che cosa è successo, detto a chi legge una diagnostica.
    #[must_use]
    pub fn as_sentence(&self) -> String {
        match self {
            Self::Answered {
                request, waited_ms, ..
            } => format!(
                "\u{ab}{}\u{bb} ha risposto dopo {waited_ms} ms.",
                request.kind
            ),
            Self::Failed {
                request,
                code,
                message,
                waited_ms,
            } => format!(
                "\u{ab}{}\u{bb} ha risposto con un errore dopo {waited_ms} ms: {code} {message}. \
                 \u{c8} una risposta, e dice di no.",
                request.kind
            ),
            Self::TimedOut { request, waited_ms } => format!(
                "\u{ab}{}\u{bb} non ha risposto entro {} ms (attesa: {waited_ms} ms). Non \
                 significa che la risposta fosse negativa n\u{e9} che il risultato fosse vuoto: \
                 significa che non \u{e8} arrivato niente.",
                request.kind,
                request.deadline.as_millis() - request.sent_at.as_millis()
            ),
        }
    }
}

/// A chi un messaggio della coda è stato consegnato.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Delivery {
    /// A una richiesta che lo aspettava.
    Resolved(Resolution),
    /// A nessuno, perché è un aggiornamento spontaneo.
    Unsolicited(String),
    /// A nessuno, perché la richiesta era già scaduta.
    ///
    /// **Si dichiara, non si butta.** Buttarlo nasconderebbe che i termini sono
    /// troppo stretti, e un termine si corregge soltanto se qualcuno sa di
    /// averlo superato.
    AnswerToNobody {
        /// L'identificativo che la risposta portava.
        id: RequestId,
    },
}

impl Delivery {
    /// Che cosa è successo, detto a chi legge una diagnostica.
    #[must_use]
    pub fn as_sentence(&self) -> String {
        match self {
            Self::Resolved(resolution) => resolution.as_sentence(),
            Self::Unsolicited(_) => {
                String::from("Aggiornamento spontaneo: non \u{e8} la risposta ad alcuna richiesta.")
            }
            Self::AnswerToNobody { id } => format!(
                "\u{c8} arrivata la risposta alla richiesta {id}, che era gi\u{e0} scaduta. La \
                 risposta non serve pi\u{f9} a nessuno, ma il fatto che sia arrivata dice che il \
                 termine era troppo stretto."
            ),
        }
    }
}

/// Perché una richiesta non è stata registrata.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum CorrelationError {
    /// Le richieste in attesa hanno raggiunto il limite.
    #[error(
        "richieste in attesa al limite di {limit}: la nuova non parte, perche' un'attesa che non finisce e' peggio di una richiesta che non comincia"
    )]
    TooManyPending {
        /// Il limite raggiunto.
        limit: usize,
    },
}

/// Tiene il conto di che cosa è stato chiesto e non ha ancora risposta.
#[derive(Debug)]
pub struct Correlator {
    /// Il prossimo identificativo. **Cresce e non torna indietro.**
    next: u64,
    /// Le richieste in attesa, per identificativo.
    pending: BTreeMap<u64, PendingRequest>,
    /// Quante possono essercene insieme.
    limit: usize,
}

impl Correlator {
    /// Crea un correlatore vuoto.
    #[must_use]
    pub const fn new(limit: usize) -> Self {
        Self {
            // Si comincia da 1 e non da 0: uno zero in un campo `@extra` si
            // confonde con un campo assente in troppi strumenti di lettura.
            next: 1,
            pending: BTreeMap::new(),
            limit,
        }
    }

    /// Registra una richiesta e ne conia l'identificativo.
    ///
    /// # Errori
    ///
    /// Restituisce [`CorrelationError::TooManyPending`] quando le richieste in
    /// attesa hanno raggiunto il limite.
    pub fn register(
        &mut self,
        kind: &str,
        now: Timestamp,
        timeout_ms: i64,
    ) -> Result<RequestId, CorrelationError> {
        if self.pending.len() >= self.limit {
            return Err(CorrelationError::TooManyPending { limit: self.limit });
        }

        let id = RequestId(self.next);
        // Il contatore avanza **prima** di ogni altra cosa e non viene mai
        // riportato indietro, nemmeno quando la richiesta si conclude: un
        // identificativo speso resta speso.
        self.next = self.next.saturating_add(1);

        self.pending.insert(
            id.0,
            PendingRequest {
                id,
                kind: kind.to_owned(),
                sent_at: now,
                deadline: Timestamp::from_millis(now.as_millis().saturating_add(timeout_ms)),
            },
        );
        Ok(id)
    }

    /// Riconosce un valore `@extra` rimandato indietro dalla libreria.
    ///
    /// # Perché serve, e perché non è una porta di servizio
    ///
    /// Chi legge la coda trova un **numero** dentro un messaggio, e deve sapere
    /// se sia uno degli identificativi coniati qui. Non può costruirsi un
    /// [`RequestId`] — è precisamente ciò che la garanzia impedisce — quindi lo
    /// chiede al correlatore, che è l'unico a saperlo.
    ///
    /// La risposta è esatta senza bisogno di ricordare nulla: gli
    /// identificativi **crescono e non tornano indietro**, quindi «mai coniato»
    /// coincide con «maggiore o uguale al prossimo». Un numero inventato da
    /// altri, o l'eco di un campo che non abbiamo scritto noi, non passa.
    ///
    /// Riconosce anche gli identificativi di richieste **già concluse**: è
    /// voluto. Una risposta arrivata tardi appartiene comunque a una domanda
    /// che questo correlatore aveva fatto, e [`Delivery::AnswerToNobody`] lo
    /// dichiara invece di confonderla con un aggiornamento spontaneo.
    #[must_use]
    pub const fn recognise(&self, raw: u64) -> Option<RequestId> {
        if raw == 0 || raw >= self.next {
            return None;
        }
        Some(RequestId(raw))
    }

    /// Consegna un messaggio della coda a chi lo aspettava.
    pub fn deliver(&mut self, incoming: Incoming, now: Timestamp) -> Delivery {
        match incoming {
            Incoming::Unsolicited { payload } => Delivery::Unsolicited(payload),
            Incoming::Answer { id, payload } => match self.pending.remove(&id.0) {
                Some(request) => {
                    let waited_ms = request.waited_ms(now);
                    Delivery::Resolved(Resolution::Answered {
                        request,
                        payload,
                        waited_ms,
                    })
                }
                None => Delivery::AnswerToNobody { id },
            },
            Incoming::Failure { id, code, message } => match self.pending.remove(&id.0) {
                Some(request) => {
                    let waited_ms = request.waited_ms(now);
                    Delivery::Resolved(Resolution::Failed {
                        request,
                        code,
                        message,
                        waited_ms,
                    })
                }
                None => Delivery::AnswerToNobody { id },
            },
        }
    }

    /// Conclude le richieste il cui termine è passato.
    ///
    /// Le restituisce **tutte**, perché ciascuna aveva qualcuno che la
    /// aspettava e ciascuno deve sapere com'è andata.
    pub fn sweep(&mut self, now: Timestamp) -> Vec<Resolution> {
        let scadute: Vec<u64> = self
            .pending
            .iter()
            .filter(|(_, request)| request.is_expired(now))
            .map(|(chiave, _)| *chiave)
            .collect();

        scadute
            .into_iter()
            .filter_map(|chiave| {
                let request = self.pending.remove(&chiave)?;
                let waited_ms = request.waited_ms(now);
                Some(Resolution::TimedOut { request, waited_ms })
            })
            .collect()
    }

    /// Quante richieste sono in attesa.
    #[must_use]
    pub fn pending_count(&self) -> usize {
        self.pending.len()
    }

    /// Se una richiesta è ancora in attesa.
    #[must_use]
    pub fn is_waiting_for(&self, id: RequestId) -> bool {
        self.pending.contains_key(&id.0)
    }

    /// Le richieste in attesa, dalla più vecchia.
    #[must_use]
    pub fn pending(&self) -> Vec<&PendingRequest> {
        self.pending.values().collect()
    }
}

impl Default for Correlator {
    fn default() -> Self {
        Self::new(DEFAULT_PENDING_LIMIT)
    }
}

#[cfg(test)]
mod tests {
    use lisi_core::Timestamp;

    use super::{
        CorrelationError, Correlator, DEFAULT_PENDING_LIMIT, Delivery, Incoming, Resolution,
    };

    /// Questo modulo, per le guardie strutturali.
    const THIS_MODULE: &str = include_str!("correlation.rs");

    const ORA_ZERO: i64 = 1_700_000_000_000;
    const TERMINE: i64 = 5_000;

    fn istante(millis: i64) -> Timestamp {
        Timestamp::from_millis(millis)
    }

    /// Il codice di produzione senza i commenti.
    fn codice_senza_commenti() -> String {
        let Some((produzione, _)) = THIS_MODULE.split_once("#[cfg(test)]\nmod tests {") else {
            panic!("il modulo deve avere un blocco di prove riconoscibile");
        };
        produzione
            .lines()
            .filter(|riga| !riga.trim_start().starts_with("//"))
            .collect::<Vec<_>>()
            .join("\n")
    }

    /// Il blocco `impl` di un tipo, dalla riga di apertura alla graffa che lo
    /// chiude a colonna zero.
    ///
    /// # Perché non c'è un ripiego
    ///
    /// Perché un estrattore che, non trovando la fine, restituisse il resto del
    /// file renderebbe la guardia cieca proprio mentre sembra funzionare. È
    /// l'errore corretto in SIM-01, e non si ripete.
    fn blocco_impl(nome: &str) -> String {
        let produzione = codice_senza_commenti();
        let Some(inizio) = produzione.find(nome) else {
            panic!("il modulo deve dichiarare {nome}");
        };
        let resto = &produzione[inizio..];
        let Some(fine) = resto.find("\n}\n") else {
            panic!("la dichiarazione {nome} deve chiudersi");
        };
        resto[..fine].to_owned()
    }

    /// **Un identificativo non si può fabbricare fuori dal correlatore.**
    ///
    /// # Il difetto che questa prova impedisce
    ///
    /// Che qualcuno costruisca un `RequestId` da un numero letto altrove — per
    /// esempio dal campo `@extra` di un messaggio — e lo usi per cercare una
    /// richiesta. Da lì, un identificativo inventato o riusato consegnerebbe la
    /// risposta di una domanda alla domanda sbagliata.
    #[test]
    fn un_identificativo_non_si_puo_fabbricare_fuori_dal_correlatore() {
        let produzione = codice_senza_commenti();
        assert!(
            produzione.contains("pub struct RequestId(u64);"),
            "il campo dell'identificativo deve restare privato"
        );

        let blocco = blocco_impl("impl RequestId {");
        for costruttore in [
            "pub fn new(",
            "pub const fn new(",
            "pub fn from(",
            "From<u64>",
        ] {
            assert!(
                !blocco.contains(costruttore),
                "«{costruttore}» permetterebbe di coniare un identificativo fuori dal correlatore"
            );
        }
    }

    /// **Un identificativo speso resta speso.**
    ///
    /// Nemmeno dopo una scadenza torna disponibile: se tornasse, una risposta
    /// arrivata in ritardo verrebbe consegnata alla richiesta nuova, e nessuno
    /// se ne accorgerebbe.
    #[test]
    fn un_identificativo_speso_non_torna_mai_disponibile() {
        let mut correlatore = Correlator::default();

        let Ok(primo) = correlatore.register("getChats", istante(ORA_ZERO), TERMINE) else {
            panic!("la registrazione deve riuscire");
        };
        // La prima scade e viene tolta dall'attesa.
        let scadute = correlatore.sweep(istante(ORA_ZERO + TERMINE));
        assert_eq!(scadute.len(), 1);
        assert_eq!(correlatore.pending_count(), 0);

        let Ok(secondo) = correlatore.register("getChats", istante(ORA_ZERO + TERMINE), TERMINE)
        else {
            panic!("la registrazione deve riuscire");
        };

        assert_ne!(primo, secondo);
        assert!(
            secondo.as_extra() > primo.as_extra(),
            "il contatore non torna indietro"
        );
    }

    /// **Una risposta arrivata dopo la scadenza non risveglia nessuno.**
    ///
    /// E non si butta in silenzio: si dichiara, perché è il solo segnale che il
    /// termine era troppo stretto.
    #[test]
    fn una_risposta_tardiva_non_risveglia_nessuno_e_si_dichiara() {
        let mut correlatore = Correlator::default();
        let Ok(id) = correlatore.register("getChats", istante(ORA_ZERO), TERMINE) else {
            panic!("la registrazione deve riuscire");
        };
        let _ = correlatore.sweep(istante(ORA_ZERO + TERMINE));

        let esito = correlatore.deliver(
            Incoming::Answer {
                id,
                payload: String::from("{\"@type\":\"chats\"}"),
            },
            istante(ORA_ZERO + TERMINE + 100),
        );

        assert!(matches!(esito, Delivery::AnswerToNobody { .. }));
        assert!(
            esito.as_sentence().contains("termine era troppo stretto"),
            "{}",
            esito.as_sentence()
        );
    }

    /// **Una scadenza non è una risposta negativa.**
    #[test]
    fn una_scadenza_non_e_una_risposta_negativa() {
        let mut correlatore = Correlator::default();
        let Ok(_) = correlatore.register("getChats", istante(ORA_ZERO), TERMINE) else {
            panic!("la registrazione deve riuscire");
        };

        let scadute = correlatore.sweep(istante(ORA_ZERO + TERMINE + 1));
        assert_eq!(scadute.len(), 1);
        assert!(
            !scadute[0].was_answered(),
            "una scadenza non e' una risposta"
        );

        let frase = scadute[0].as_sentence();
        assert!(frase.contains("non \u{e8} arrivato niente"), "{frase}");
        assert!(
            !frase.contains("vuoto:") || frase.contains("n\u{e9} che il risultato fosse vuoto"),
            "{frase}"
        );
    }

    /// **Un errore è una risposta**, e si distingue da una scadenza.
    #[test]
    fn un_errore_e_una_risposta_e_si_distingue_da_una_scadenza() {
        let mut correlatore = Correlator::default();
        let Ok(id) = correlatore.register("getChats", istante(ORA_ZERO), TERMINE) else {
            panic!("la registrazione deve riuscire");
        };

        let esito = correlatore.deliver(
            Incoming::Failure {
                id,
                code: 420,
                message: String::from("Too Many Requests"),
            },
            istante(ORA_ZERO + 200),
        );

        let Delivery::Resolved(risoluzione) = esito else {
            panic!("l'errore doveva concludere la richiesta");
        };
        assert!(matches!(risoluzione, Resolution::Failed { .. }));
        assert!(
            risoluzione.was_answered(),
            "un errore e' una risposta: dice di no"
        );
        assert!(risoluzione.as_sentence().contains("dice di no"));
    }

    /// **Un aggiornamento spontaneo non risolve alcuna richiesta.**
    #[test]
    fn un_aggiornamento_spontaneo_non_risolve_alcuna_richiesta() {
        let mut correlatore = Correlator::default();
        let Ok(id) = correlatore.register("getChats", istante(ORA_ZERO), TERMINE) else {
            panic!("la registrazione deve riuscire");
        };

        let esito = correlatore.deliver(
            Incoming::Unsolicited {
                payload: String::from("{\"@type\":\"updateNewMessage\"}"),
            },
            istante(ORA_ZERO + 10),
        );

        assert!(matches!(esito, Delivery::Unsolicited(_)));
        assert!(
            correlatore.is_waiting_for(id),
            "la richiesta deve restare in attesa"
        );
        assert_eq!(correlatore.pending_count(), 1);
    }

    /// Una risposta conclude la richiesta e la toglie dall'attesa.
    #[test]
    fn una_risposta_conclude_la_richiesta_e_la_toglie_dall_attesa() {
        let mut correlatore = Correlator::default();
        let Ok(id) = correlatore.register("getChats", istante(ORA_ZERO), TERMINE) else {
            panic!("la registrazione deve riuscire");
        };

        let esito = correlatore.deliver(
            Incoming::Answer {
                id,
                payload: String::from("{\"@type\":\"chats\"}"),
            },
            istante(ORA_ZERO + 120),
        );

        let Delivery::Resolved(Resolution::Answered {
            request, waited_ms, ..
        }) = esito
        else {
            panic!("la risposta doveva concludere la richiesta");
        };
        assert_eq!(request.kind, "getChats");
        assert_eq!(waited_ms, 120);
        assert!(!correlatore.is_waiting_for(id));
        assert_eq!(correlatore.pending_count(), 0);
    }

    /// **Due richieste dello stesso tipo non si confondono.**
    ///
    /// È il caso che il conteggio per tipo non sapeva distinguere, e la ragione
    /// per cui questo modulo esiste.
    #[test]
    fn due_richieste_dello_stesso_tipo_non_si_confondono() {
        let mut correlatore = Correlator::default();
        let (Ok(principale), Ok(archivio)) = (
            correlatore.register("getChats", istante(ORA_ZERO), TERMINE),
            correlatore.register("getChats", istante(ORA_ZERO), TERMINE),
        ) else {
            panic!("le registrazioni devono riuscire");
        };
        assert_ne!(principale, archivio);

        // Arriva un errore: appartiene alla SECONDA, e non alla prima.
        let esito = correlatore.deliver(
            Incoming::Failure {
                id: archivio,
                code: 400,
                message: String::from("CHAT_LIST_INVALID"),
            },
            istante(ORA_ZERO + 50),
        );

        let Delivery::Resolved(risoluzione) = esito else {
            panic!("l'errore doveva concludere una richiesta");
        };
        assert_eq!(risoluzione.request().id, archivio);
        assert!(
            correlatore.is_waiting_for(principale),
            "la prima richiesta non e' stata toccata dall'errore della seconda"
        );
    }

    /// **Oltre il limite la richiesta non parte.**
    ///
    /// Un'attesa che non finisce è peggio di una richiesta che non comincia.
    #[test]
    fn oltre_il_limite_la_richiesta_non_parte() {
        let mut correlatore = Correlator::new(2);
        let (Ok(_), Ok(_)) = (
            correlatore.register("uno", istante(ORA_ZERO), TERMINE),
            correlatore.register("due", istante(ORA_ZERO), TERMINE),
        ) else {
            panic!("le prime due devono riuscire");
        };

        assert_eq!(
            correlatore.register("tre", istante(ORA_ZERO), TERMINE),
            Err(CorrelationError::TooManyPending { limit: 2 })
        );
        assert_eq!(correlatore.pending_count(), 2);
    }

    /// Il termine si conta dal momento dell'invio, e la frase lo dichiara.
    #[test]
    fn la_frase_della_scadenza_dichiara_il_termine() {
        let mut correlatore = Correlator::default();
        let Ok(_) = correlatore.register("getMessageLink", istante(ORA_ZERO), 3_000) else {
            panic!("la registrazione deve riuscire");
        };

        let scadute = correlatore.sweep(istante(ORA_ZERO + 3_500));
        let frase = scadute[0].as_sentence();

        assert!(frase.contains("3000 ms"), "{frase}");
        assert!(frase.contains("3500 ms"), "{frase}");
        assert!(frase.contains("getMessageLink"), "{frase}");
    }

    /// Una richiesta non ancora scaduta non viene toccata dalla spazzata.
    #[test]
    fn una_richiesta_non_scaduta_resta_in_attesa() {
        let mut correlatore = Correlator::default();
        let Ok(id) = correlatore.register("getChats", istante(ORA_ZERO), TERMINE) else {
            panic!("la registrazione deve riuscire");
        };

        assert!(
            correlatore
                .sweep(istante(ORA_ZERO + TERMINE - 1))
                .is_empty()
        );
        assert!(correlatore.is_waiting_for(id));
    }

    /// **Questo modulo non carica TDLib e non conosce il JSON.**
    ///
    /// È la ragione per cui è provabile su una macchina che TDLib non ce l'ha:
    /// un'infrastruttura che si può provare solo dal vivo è un'infrastruttura
    /// che nessuno prova.
    #[test]
    fn il_correlatore_non_conosce_tdlib_ne_il_json() {
        let produzione = codice_senza_commenti();
        for vietato in [
            "unsafe",
            "libloading",
            "tdlib-runtime",
            "@type",
            "serde",
            "TdJson",
        ] {
            assert!(
                !produzione.contains(vietato),
                "«{vietato}» legherebbe il correlatore alla libreria o al formato"
            );
        }
    }

    /// **Un `@extra` mai coniato non è la risposta a niente.**
    ///
    /// # Il difetto che questa prova impedisce
    ///
    /// Che un numero letto dalla coda — l'eco di un campo scritto da qualcun
    /// altro, o un valore inventato — venga trattato come l'identificativo di
    /// una richiesta. Gli identificativi crescono e non tornano indietro: «mai
    /// coniato» è esattamente «maggiore o uguale al prossimo».
    #[test]
    fn un_extra_mai_coniato_non_e_la_risposta_a_niente() {
        let mut correlatore = Correlator::default();
        let Ok(id) = correlatore.register("getChats", istante(ORA_ZERO), TERMINE) else {
            panic!("la registrazione deve riuscire");
        };

        assert_eq!(correlatore.recognise(id.as_extra()), Some(id));
        assert_eq!(correlatore.recognise(0), None, "lo zero non si conia mai");
        assert_eq!(
            correlatore.recognise(id.as_extra() + 1),
            None,
            "un valore non ancora coniato non appartiene a nessuno"
        );
        assert_eq!(correlatore.recognise(999_999), None);
    }

    /// Un identificativo di una richiesta **già conclusa** resta riconoscibile.
    ///
    /// Serve a distinguere una risposta tardiva da un aggiornamento spontaneo:
    /// la prima dice che il termine era troppo stretto, il secondo non dice
    /// niente di nessuno.
    #[test]
    fn un_identificativo_gia_concluso_resta_riconoscibile() {
        let mut correlatore = Correlator::default();
        let Ok(id) = correlatore.register("getChats", istante(ORA_ZERO), TERMINE) else {
            panic!("la registrazione deve riuscire");
        };
        let _ = correlatore.sweep(istante(ORA_ZERO + TERMINE));

        assert!(!correlatore.is_waiting_for(id));
        assert_eq!(
            correlatore.recognise(id.as_extra()),
            Some(id),
            "una risposta tardiva appartiene comunque a una domanda che avevamo fatto"
        );
    }

    /// Il limite predefinito è quello dichiarato.
    #[test]
    fn il_limite_predefinito_e_quello_dichiarato() {
        let mut correlatore = Correlator::default();
        for indice in 0..DEFAULT_PENDING_LIMIT {
            let Ok(_) = correlatore.register("prova", istante(ORA_ZERO), TERMINE) else {
                panic!("la registrazione {indice} doveva riuscire");
            };
        }
        assert!(
            correlatore
                .register("prova", istante(ORA_ZERO), TERMINE)
                .is_err()
        );
    }
}
