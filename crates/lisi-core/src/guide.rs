//! Guida all'uso, per operatori non tecnici.
//!
//! Il contenuto vive qui, e non nel file dell'interfaccia, per una ragione
//! precisa: **un test verifica che la guida dichiari i limiti invece di
//! sovrapprometterli**. Una guida che dicesse che il prodotto è inviolabile, o
//! che il motore «capisce», o che il manifest è una firma, sarebbe una bugia
//! più pericolosa dell'assenza di guida. Il test qui sotto la tiene onesta.
//!
//! Le stesse parole che l'operatore legge nelle schermate compaiono qui: la
//! guida non descrive un altro prodotto, descrive questo.

/// Una sezione della guida: un titolo e il testo che lo spiega.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GuideSection {
    /// Titolo della sezione.
    pub title: &'static str,
    /// Corpo, in italiano piano.
    pub body: &'static str,
}

/// Le affermazioni che la guida deve contenere **testuali**.
///
/// Sono i limiti che il prodotto dichiara invece di sovrapprometterli: che non
/// promette di essere inviolabile, che il motore non decide, che il manifest
/// non e' una firma. Una guida che le perdesse sarebbe piu' pericolosa
/// dell'assenza di guida.
///
/// # Perche' sono pubbliche e non chiuse nella prova
///
/// Perche' le controlla piu' di una prova, in crate diversi. L'interfaccia
/// spezza i corpi in capoversi per renderli leggibili, e quella
/// trasformazione deve dimostrare di non tagliare in mezzo a una di queste
/// frasi: una seconda copia dell'elenco, altrove, prima o poi divergerebbe da
/// questa, e a divergere sarebbe proprio la copia che sorveglia meno.
pub const DECLARED_LIMITS: &[&str] = &[
    "non promette di essere inviolabile",
    "il motore attribuisce un livello e lo spiega; non decide",
    "non comprende",
    "mai su identità",
    "non una firma",
    "non stabilisce se un monitoraggio sia lecito",
    "non ferma l'acquisizione",
    "non riceve contenuti",
];

/// La guida, in sezioni, nell'ordine in cui si leggono.
///
/// # Il linguaggio (PR-01, ADR-0117)
///
/// Frasi brevi, una idea per frase, parole comuni. I termini tecnici non
/// stanno qui: stanno nel glossario, che la schermata Guida mostra accanto a
/// queste sezioni. Le affermazioni di [`DECLARED_LIMITS`] restano **alla
/// lettera**: sono ciò che impedisce alla guida di promettere troppo.
///
/// # Che cosa PR-01 ha corretto, oltre alla forma
///
/// Tre sezioni dicevano cose **superate**: che il programma «non scarica
/// nulla» (da UPDATE-02 scarica, su richiesta, l'informazione e il file di un
/// aggiornamento); che un monitoraggio si esporta «in un rapporto di testo» (da
/// MP-18 ci sono relazione, allegato e registro); che nessun dato esce «verso
/// Internet» senza dire che cosa si intende per dato. Sono corrette nei fatti,
/// e la correzione è registrata in DEC-358.
pub const GUIDE: &[GuideSection] = &[
    GuideSection {
        title: "Che cos'è NEXUM/97",
        body: "È uno strumento per il monitoraggio autorizzato di fonti Telegram. Le fonti sono \
               quelle che l'account d'ufficio può già leggere. Il programma non cerca fonti, non \
               entra in gruppi e non aggira nulla. Serve a seguire, registrare e valutare i \
               messaggi di fonti che l'ufficio è autorizzato a seguire. Di tutto lascia una \
               traccia ordinata, che si può ricostruire.",
    },
    GuideSection {
        title: "Preparare e avviare un monitoraggio",
        body: "Si comincia dalla schermata «Nuovo monitoraggio». Lì si scelgono le fonti da \
               seguire, fra quelle configurate. Poi i dizionari con cui valutarle, ed eventuali \
               parole in più valide solo per questa volta. Infine la durata. La preparazione si \
               può lasciare a metà e riprendere. Alla conferma il monitoraggio parte, e compare \
               nella schermata «Monitoraggio» con il suo stato e i suoi comandi. La procedura \
               ricomincia vuota: per ripartire dalle stesse scelte si usa un modello.",
    },
    // UX-EXCELLENCE-02, SIM3-05 e ADR-0136: l'operatore leggeva «07:07 UTC» con
    // l'orologio di Windows sulle 09:07.
    GuideSection {
        title: "Gli orari: ora locale e UTC",
        body: "Sullo schermo ogni orario si legge prima nell'ora dell'orologio del computer. \
               Fra parentesi c'è la stessa ora in UTC, il tempo universale. Il programma \
               conserva tutto in UTC, e i documenti prodotti restano in UTC. La parentesi è il \
               numero che si ritrova nella relazione. Quando l'ora legale finisce, la stessa ora \
               locale torna due volte: l'UTC le distingue.",
    },
    GuideSection {
        title: "Sospendere gli avvisi non è mettere in pausa",
        body: "Sospendere gli avvisi fa tacere le notifiche, ma non ferma l'acquisizione. Il \
               monitoraggio continua a ricevere e a conservare. Serve a chi sta rivedendo e non \
               vuole essere interrotto. Arrestare, invece, chiude il monitoraggio in modo \
               ordinato. La differenza è voluta. Una «pausa» che non dice se ferma \
               l'acquisizione lascerebbe un vuoto che nessuno ha dichiarato.",
    },
    GuideSection {
        title: "I livelli, da 0 a 4",
        body: "Ogni messaggio acquisito riceve un livello. Il livello 0 non vuol dire «nessuna \
               analisi». Vuol dire che il messaggio è stato analizzato e non ha dato un \
               avviso. Resta comunque registrato. Il livello lo dà il motore, e non usa le \
               parole della revisione: «Rilevante» e «Non rilevante» le dice una persona. \
               Dal livello 1 al 4 la rilevanza cresce, \
               secondo i dizionari scelti. Il livello 4 non dice «è molto probabile che \
               accada». Dice che sono comparse parole che l'ufficio ha deciso di seguire. E che \
               la combinazione è una di quelle che l'ufficio ha deciso di considerare grave.",
    },
    GuideSection {
        title: "Il motore propone, la persona decide",
        body: "Il motore attribuisce un livello e lo spiega; non decide. La valutazione resta \
               all'operatore. Il motore non comprende: cerca parole. Non coglie l'ironia, una \
               negazione lontana, il rimando a un messaggio precedente, il sottinteso. E lavora \
               su condotte, oggetti e circostanze, mai su identità: non segnala una persona per \
               chi è, ma per ciò che un testo dice.",
    },
    GuideSection {
        title: "La revisione umana",
        body: "Un messaggio segnalato si può confermare rilevante o giudicare non rilevante. Si \
               può anche segnare come doppione, archiviare o segnalare ad altri. Dire «non \
               rilevante» a ciò che il motore aveva segnalato richiede una motivazione. È così \
               che i dizionari si correggono, e senza spiegazione quel segnale andrebbe perso. \
               Le decisioni non si sovrascrivono: si aggiungono. Cambiare parere lascia traccia \
               di chi ha guardato che cosa, e quando.",
    },
    GuideSection {
        title: "Lo storico e gli avvisi",
        body: "Lo storico contiene ogni messaggio acquisito e analizzato, anche quelli di \
               livello 0. Gli avvisi sono lo stesso archivio, mostrato dal livello 1 in su. \
               Mostrare solo ciò che ha fatto scattare un allarme sarebbe falso. Direbbe che il \
               monitoraggio ha visto solo quello. Ogni riga porta la motivazione scritta al \
               momento dell'analisi, senza ricalcolarla.",
    },
    GuideSection {
        title: "Le notifiche e la loro riservatezza",
        body: "Quando un messaggio supera la soglia scelta, il programma può mandare una \
               notifica. Quanto dice la notifica si sceglie. Completa: fonte, livello, estratto \
               e motivazione. Ridotta: fonte e livello, senza il testo. Riservata: solo «Nuovo \
               contenuto da esaminare». A schermo bloccato la scelta prudente nasconde. Un \
               contenuto delicato visibile a chiunque passi è una fuga che nessun controllo \
               successivo recupera.",
    },
    GuideSection {
        title: "I documenti e l'elenco delle impronte",
        body: "Da un monitoraggio si producono documenti: la relazione, l'allegato tecnico e il \
               registro. Alla fine, «Apri la cartella» mostra i file in Esplora file. Accanto a \
               ogni pacchetto c'è l'elenco delle impronte. Un'impronta è un \
               codice calcolato dal file: se il file cambia, cambia. L'elenco è un'impronta, \
               non una firma. Dice che il file consegnato è identico a quello prodotto, a chi ha \
               entrambi. Non dice chi l'ha prodotto. E non impedisce di rifare insieme documento \
               ed elenco.",
    },
    GuideSection {
        title: "Gli identificativi degli autori nel rapporto",
        body: "Accanto al comando che produce il rapporto c'è una spunta. Aggiunge \
               l'identificativo Telegram di chi ha scritto ogni messaggio. È spenta all'inizio. \
               Un rapporto che elenca persone è un documento diverso da uno che elenca messaggi, \
               e chi lo firma deve sceglierlo. Il rapporto dichiara la scelta in ogni caso. \
               Così chi lo riceve non confonde «non c'erano autori» con «gli autori non sono \
               stati riportati». I messaggi pubblicati dalla fonte non hanno un autore singolo, \
               e il rapporto lo scrive. La scelta vale per quel rapporto e resta nel registro \
               delle operazioni.",
    },
    GuideSection {
        title: "Dal vivo o recuperato",
        body: "Ogni messaggio dice come è entrato in archivio. «Dal vivo» vuol dire che il \
               programma era in ascolto quando il messaggio è comparso. «Recuperato dalla \
               cronologia» vuol dire che il programma non c'era. Il messaggio è stato preso \
               dopo, leggendo ciò che la fonte aveva già pubblicato. È attestato come pubblicato, \
               non come seguito mentre accadeva. La differenza conta quando il rapporto esce \
               dall'ufficio: per questo il documento la scrive per ogni messaggio. Nello \
               Storico compare solo dove c'è, perché ripeterla ovunque nasconderebbe \
               l'eccezione. Un messaggio già acquisito dal vivo non diventa recuperato se lo si \
               ritrova: l'archivio conserva l'affermazione più forte.",
    },
    GuideSection {
        title: "Bloccare la postazione",
        body: "Su un computer condiviso, il comando «Blocca la postazione», in fondo al menu, \
               nasconde i dati dell'account. Avvisi, storico e comandi spariscono finché non si scrive la \
               propria parola di sblocco. Ogni account Telegram ha la sua, e si imposta in \
               Impostazioni. Il monitoraggio non si ferma. A schermo resta il fatto, cioè \
               quanti avvisi attendono, senza il contenuto. Dopo dieci minuti senza comandi la \
               postazione si blocca da sola, perché uscendo nessuno si ricorda di bloccare. I \
               minuti si cambiano in Impostazioni. A postazione bloccata nessun comando \
               risponde. Con la tastiera si passa solo dalla parola a «Sblocca», e la finestra non \
               si chiude. Una seconda copia del programma non si apre. Dopo tre parole errate di \
               fila, il tentativo dopo si accetta più tardi. Non è una protezione contro chi controlla il \
               computer. Chi usa quel profilo di Windows può cancellare il file delle parole. \
               Allora gli account risultano non protetti: in modo visibile, non di nascosto.",
    },
    GuideSection {
        title: "La copia di sicurezza, e che cosa non salva",
        body: "In Impostazioni, «Scrivi una copia…» salva una copia dell'archivio nella \
               cartella scelta. Accanto scrive un foglio che la spiega. La copia contiene tutto \
               ciò che il programma conserva: monitoraggi, messaggi, riscontri, avvisi e \
               registro delle operazioni. Non contiene le credenziali dell'account Telegram né \
               le parole di sblocco. Quelle sono protette da Windows e legate a questo profilo, \
               su questo computer, e non si possono spostare. Quindi la copia rimette \
               l'archivio, non l'accesso. Su un computer nuovo l'accesso a Telegram si rifà da \
               capo, con il codice che arriva sul telefono autorizzato. Il programma non \
               ripristina da solo, ed è voluto. Sovrascrivere l'archivio in uso con uno più \
               vecchio cancellerebbe mesi di lavoro in un secondo. Le istruzioni sono nel \
               foglio accanto alla copia. La copia non è cifrata: va custodita come l'archivio.",
    },
    GuideSection {
        title: "Gli aggiornamenti",
        body: "Il programma non cerca aggiornamenti da solo e non si sostituisce da sé. Chi \
               amministra può indicare, in Impostazioni, un indirizzo web da cui prendere \
               l'informazione sugli aggiornamenti. Il programma lo contatta solo quando qualcuno \
               lo chiede. Nessun contenuto dell'archivio esce verso Internet. Un file \
               scaricato o ricevuto a mano si esamina e si verifica: non si crede. Esaminare dice \
               se l'aggiornamento è adatto a questa postazione. Deve essere il prodotto giusto, \
               per il Windows giusto, e più recente di quello in uso. Mai uno più vecchio: \
               tornare indietro rimetterebbe in circolo difetti già corretti. Nemmeno un file \
               verificato si installa da solo. Si installa con il pacchetto ufficiale, quando \
               qualcuno decide di farlo.",
    },
    GuideSection {
        title: "Operatore e amministratore",
        body: "La postazione ha due modalità. L'operatore lavora: configura fonti e account, \
               crea e pubblica dizionari, usa Laboratorio e Modelli. Le operazioni che cancellano \
               o valgono per tutti si spiegano, e chiedono una conferma su un comando diverso. \
               Restano all'amministratore due azioni: togliere un dizionario creato da un'altra \
               persona, e scegliere da dove arrivano gli aggiornamenti. Per passare a quella \
               modalità serve una parola di sblocco. Non è un confine di \
               sicurezza contro chi controlla il proprio computer. Chi vuole può ripristinare la \
               modalità amministratore, e il programma lo dichiara. È una protezione contro \
               l'errore: rende quel gesto necessario e visibile. Ogni operazione registra la \
               modalità con cui è stata compiuta.",
    },
    // OPERATOR-E2E-REMEDIATION-01, F-06 e F-07: l'Esercitazione non si trovava dal
    // programma, e Laboratorio e Modelli non si potevano usare.
    GuideSection {
        title: "Esercitarsi",
        body: "Per imparare senza rischi c'è l'Esercitazione. Ha messaggi di prova, avvisi e \
               documenti, in un archivio separato, e non contatta Telegram. Si apre da questa \
               Guida con «Apri l'Esercitazione», in una seconda finestra. La modalità \
               dimostrativa di Account è un'altra cosa: prova i passi dell'accesso, ma non ha \
               messaggi.",
    },
    GuideSection {
        title: "Provare un dizionario e ripartire da un modello",
        body: "In Dizionari, «Nuova versione» apre una bozza con gli stessi termini. «Prova nel \
               Laboratorio» mostra che cosa la bozza cambia. Se c'è un monitoraggio già fatto, \
               mostra anche che cosa cambierebbe sui suoi messaggi. Il Laboratorio non pubblica: \
               si pubblica in Dizionari, con una conferma. In Modelli, «Nuovo modello» conserva \
               fonti e dizionari scelti. «Prepara un nuovo monitoraggio con queste scelte» \
               compila la procedura guidata, ma non avvia nulla.",
    },
    GuideSection {
        title: "Che cosa il prodotto non fa",
        body: "Non promette di essere inviolabile: nessun programma può. Non stabilisce se un \
               monitoraggio sia lecito. Registra ciò che l'operatore dichiara e lo rende \
               ricostruibile. Non cerca fonti, non entra in gruppi, non usa account falsi, non \
               nasconde la propria provenienza in rete. Non aggira i limiti della piattaforma. \
               Finché l'accesso a Telegram non è predisposto su questa postazione, un \
               monitoraggio si può comandare ma non riceve contenuti.",
    },
];

#[cfg(test)]
mod tests {
    use super::{DECLARED_LIMITS, GUIDE};

    #[test]
    fn the_guide_has_sections_with_a_title_and_a_body() {
        assert!(
            GUIDE.len() >= 8,
            "la guida deve coprire i concetti principali"
        );
        for section in GUIDE {
            assert!(
                !section.title.trim().is_empty(),
                "ogni sezione ha un titolo"
            );
            assert!(
                section.body.chars().count() > 60,
                "ogni sezione spiega davvero: '{}'",
                section.title
            );
        }
    }

    #[test]
    fn the_guide_declares_the_limits_instead_of_overpromising() {
        // È la ragione per cui il contenuto sta qui e non nell'interfaccia: una
        // guida che sovrapromette è peggio di nessuna guida. Se una di queste
        // affermazioni sparisce, la modifica va rivista, non il test.
        let text: String = GUIDE
            .iter()
            .map(|section| format!("{} {}", section.title, section.body))
            .collect::<Vec<_>>()
            .join(" ")
            .to_lowercase();

        for claim in DECLARED_LIMITS {
            assert!(
                text.contains(&claim.to_lowercase()),
                "la guida deve dichiarare: «{claim}»"
            );
        }
    }

    #[test]
    fn the_guide_never_claims_an_institutional_authority() {
        // Lo stesso limite del branding: il prodotto non è emanazione di alcuna
        // istituzione, e la guida non deve lasciarlo intendere.
        let text: String = GUIDE
            .iter()
            .map(|section| section.body)
            .collect::<Vec<_>>()
            .join(" ")
            .to_lowercase();

        for forbidden in ["polizia", "ministero", "forze dell'ordine", "procura"] {
            assert!(
                !text.contains(forbidden),
                "la guida non deve nominare un'autorità: '{forbidden}'"
            );
        }
    }
}
