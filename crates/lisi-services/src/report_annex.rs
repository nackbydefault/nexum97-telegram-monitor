//! Che cosa dice l'allegato tecnico, prima e indipendentemente da come e'
//! scritto.
//!
//! # In che cosa differisce dal registro, visto che coprono gli stessi fatti
//!
//! È la domanda che l'ufficio ha posto quando ha deciso di volerli entrambi, e
//! la risposta sta nella **forma**, non nel contenuto.
//!
//! Il registro `.xlsx` mette gli stessi fatti in tabella: si filtra, si ordina,
//! si conta. Serve a chi analizza. L'allegato li mette **uno dopo l'altro, in
//! forma leggibile**: serve a chi legge, e a chi riceve un fascicolo su carta
//! senza aprire un foglio di calcolo. Una tabella di quaranta colonne stampata
//! su A4 non si legge; un elenco di contenuti si'.
//!
//! # Le tre cose che tiene separate
//!
//! ADR-0031 Decisione 5 lo chiede esplicitamente, ed e' la ragione per cui ogni
//! contenuto ha tre gruppi di righe invece di uno:
//!
//! - **dati originali** — cio' che la fonte ha pubblicato;
//! - **metadati del sistema** — quando l'abbiamo visto, con che impronta, con
//!   che origine;
//! - **valutazioni** — livello proposto dal motore, decisione della persona.
//!
//! Mescolarle produrrebbe un documento in cui non si distingue piu' cio' che e'
//! stato osservato da cio' che e' stato giudicato — e in un atto destinato a un
//! ufficio quella distinzione e' la cosa piu' importante che ci sia.
//!
//! # Rappresenta tutto il monitorato
//!
//! Come il registro e a differenza della relazione: livello 0 compreso, non
//! selezionati compresi, senza alert compresi.

use lisi_core::model::report::ReportId;
use lisi_core::text::Actor;
use lisi_core::{Timestamp, model::report_template::ReportTemplateProfile};

use crate::report_ledger::{
    CHE_COSA_E_UN_RACCOGLITORE, CHE_COSA_E_UN_RIFERIMENTO_TASSONOMICO, CHE_COSA_E_UN_SOGGETTO,
    CHE_COSA_E_UNA_NOTA, LedgerAlert, LedgerContent, LedgerCyberEvent, LedgerFault,
    LedgerNeighbourhood, LedgerNote, LedgerOfficialSource, LedgerSession, LedgerSource,
    LedgerSubject, LedgerTaxonomyReference, LedgerTimeline, LedgerWorkspace,
    NESSUN_RIFERIMENTO_TASSONOMICO_DICHIARATO, NESSUNA_NOTA_E_NESSUN_RACCOGLITORE,
    PERCHE_LA_FIGURA_NON_E_RIPRODOTTA, SENZA_RAGIONE_OPERATIVA_NON_SI_COMPONE_IL_VICINATO,
    SENZA_RAGIONE_OPERATIVA_NON_SI_ELENCA, UNA_FOTOGRAFIA_NON_E_OGGI,
};
use crate::report_narrative::{
    Block, Letterhead, LetterheadLine, NOT_AVAILABLE, NOT_REVIEWED, NarrativeReport, push_contexts,
    push_revisions,
};

/// Tutto cio' che serve a comporre l'allegato.
#[derive(Debug, Clone)]
pub struct AnnexInput<'a> {
    /// Identificativo del report, che lega l'allegato agli altri artefatti.
    pub report_id: &'a ReportId,
    /// Profilo documentale dell'ufficio.
    pub profile: &'a ReportTemplateProfile,
    /// Chi ha chiesto la generazione.
    pub operator: &'a Actor,
    /// Istante della generazione.
    pub generated_at: Timestamp,
    /// I fatti della sessione.
    pub session: &'a LedgerSession,
    /// Le fonti monitorate.
    pub sources: &'a [LedgerSource],
    /// **Tutti** i contenuti monitorati.
    pub contents: &'a [LedgerContent],
    /// Gli avvisi emessi.
    pub alerts: &'a [LedgerAlert],
    /// Le anomalie tecniche.
    pub faults: &'a [LedgerFault],
    /// I gruppi di segnali tecnici, se ce ne sono.
    ///
    /// **Non sono incidenti confermati**, e la sezione lo dichiara prima di
    /// elencarli.
    pub cyber_events: &'a [LedgerCyberEvent],
    /// I soggetti aperti a cui questo monitoraggio ha osservato qualcosa.
    pub subjects: &'a [LedgerSubject],
    /// I riferimenti tassonomici dichiarati per i contenuti del monitoraggio.
    pub taxonomy: &'a [LedgerTaxonomyReference],
    /// Quanti riferimenti restano fuori dal documento per via del tetto.
    pub taxonomy_beyond: usize,
    /// Le fotografie dei cataloghi ufficiali che l'archivio conserva.
    pub official_sources: &'a [LedgerOfficialSource],
    /// Le annotazioni scritte sulle cose che il documento rappresenta.
    pub notes: &'a [LedgerNote],
    /// Quante annotazioni restano fuori dal documento per via del tetto.
    pub notes_beyond: usize,
    /// I raccoglitori che contengono contenuti di questo monitoraggio.
    pub workspaces: &'a [LedgerWorkspace],
    /// Quanti raccoglitori restano fuori dal documento per via del tetto.
    pub workspaces_beyond: usize,
    /// Se la ragione operativa che autorizza il lavoro investigativo è
    /// registrata: **un cancello solo** per gli elenchi di persone e per il
    /// vicinato del grafo.
    pub investigative_basis: bool,
    /// Che cosa la postazione ha guardato, fonte per fonte (PR-05).
    pub coverage: &'a [crate::coverage::CoverageLine],
    /// Con quali termini l'analisi è stata condotta (ADR-0156): la stessa
    /// composizione della relazione, del registro e del rapporto.
    pub configuration: &'a crate::analysis_configuration::AnalysisConfiguration,
}

/// Compone l'allegato tecnico.
#[must_use]
pub fn compose(input: &AnnexInput<'_>) -> NarrativeReport {
    let mut blocks = Vec::new();

    blocks.push(Block::Heading(String::from("ALLEGATO TECNICO")));
    blocks.push(Block::Lead {
        lead: String::from("OGGETTO:"),
        body: format!(
            "elenco integrale dei contenuti acquisiti e analizzati nel corso del \
             monitoraggio «{}», riferimento {}.",
            input.session.label,
            input.report_id.as_str()
        ),
    });

    blocks.push(Block::Paragraph(format!(
        "Il presente allegato rappresenta {} contenuti, cioè l'intera acquisizione \
         della sessione: vi compaiono anche i contenuti di livello 0, quelli che non \
         hanno generato alcun avviso e quelli che l'operatore non ha selezionato per \
         la relazione. Nessun contenuto è stato escluso.",
        input.contents.len()
    )));

    blocks.push(Block::Paragraph(crate::report_narrative::origin_legend()));

    blocks.push(Block::Heading(String::from("1. LA SESSIONE")));
    blocks.push(Block::Paragraph(format!(
        "Monitoraggio «{}», stato {}, avviato il {} e {}. Documento generato il {} su \
         richiesta di {}.",
        input.session.label,
        input.session.state,
        input.session.started_at.to_readable_utc(),
        input.session.ended_at.map_or_else(
            || String::from("non ancora concluso"),
            |instant| format!("concluso il {}", instant.to_readable_utc())
        ),
        input.generated_at.to_readable_utc(),
        input.operator.as_str()
    )));
    // CON QUALI TERMINI (ADR-0156): accanto alla sessione, perché ogni livello
    // dei contenuti che seguono è stato calcolato con questa configurazione.
    // L'allegato non la riportava affatto (BUG-REP-2).
    input.configuration.push_blocks(&mut blocks);

    blocks.push(Block::Heading(String::from("2. LE FONTI")));
    if input.sources.is_empty() {
        blocks.push(Block::Paragraph(String::from(
            "Nessuna fonte risulta associata alla sessione.",
        )));
    } else {
        blocks.push(Block::Table {
            headers: vec![
                String::from("Fonte"),
                String::from("Genere"),
                String::from("Acquisiti"),
            ],
            rows: input
                .sources
                .iter()
                .map(|source| {
                    vec![
                        source.label.clone(),
                        source.kind.clone(),
                        source.acquired.to_string(),
                    ]
                })
                .collect(),
        });
    }
    // CHE COSA SI GUARDAVA (PR-05): accanto alle fonti, perché dice su che cosa
    // l'elenco dei contenuti si basa.
    crate::report_narrative::push_coverage(&mut blocks, input.coverage);

    blocks.push(Block::Heading(String::from("3. I CONTENUTI")));
    if input.contents.is_empty() {
        blocks.push(Block::Paragraph(String::from(
            "La sessione non ha acquisito alcun contenuto.",
        )));
    }
    for (index, content) in input.contents.iter().enumerate() {
        push_content(&mut blocks, index + 1, content, input.alerts);
    }

    blocks.push(Block::Heading(String::from("4. LE ANOMALIE TECNICHE")));
    if input.faults.is_empty() {
        // Dire che non ne sono state registrate NON e' dire che non ce ne siano
        // state: il documento afferma cio' che sa, non cio' che spera.
        blocks.push(Block::Paragraph(String::from(
            "Nel corso della sessione non sono state registrate anomalie tecniche. \
             La presente dichiarazione riguarda ciò che il programma ha registrato, \
             e non costituisce attestazione che nessuna anomalia si sia verificata.",
        )));
    } else {
        for fault in input.faults {
            blocks.push(Block::Lead {
                lead: format!("{} —", fault.happened_at.to_readable_utc()),
                body: format!("{}: {}", fault.kind, fault.detail),
            });
        }
    }

    // 5. I GRUPPI DI SEGNALI
    //
    // # Perche' stanno nell'ALLEGATO e non nella relazione
    //
    // La relazione narrativa racconta **la selezione dell'operatore**: contiene
    // cio' che una persona ha scelto di rappresentare, e ADR-0031 Decisione 2
    // fissa che quella scelta e' sua e il motore non la fa. Un gruppo di segnali
    // non e' stato scelto da nessuno: e' il risultato di una correlazione
    // automatica.
    //
    // Metterlo nella relazione significherebbe far entrare in un atto un fatto
    // che l'operatore non ha selezionato, presentato accanto a quelli che ha
    // selezionato. L'allegato tecnico e' il posto giusto: rappresenta **tutto
    // il monitorato**, ed e' li' che chi legge si aspetta di trovare cio' che il
    // programma ha prodotto senza che nessuno lo scegliesse.
    blocks.push(Block::Heading(String::from(
        "5. I GRUPPI DI SEGNALI TECNICI",
    )));

    // La dichiarazione viene PRIMA dell'elenco, e sta in ogni copia del
    // documento: un fascicolo si legge anche a distanza di mesi, da chi non ha
    // mai visto il programma e non sa che cosa questo elenco sia.
    blocks.push(Block::Paragraph(String::from(
        "Le voci che seguono sono risultati di correlazione prodotti da NEXUM/97: \
         contenuti che nominano lo stesso indicatore tecnico, raccolti perché siano \
         letti insieme. Un gruppo è un candidato all'esame, e non costituisce \
         accertamento che un fatto sia avvenuto. Il programma non attribuisce la \
         paternità di alcuna condotta e non nomina alcun autore: la valutazione \
         resta di chi legge, ed è registrata separatamente.",
    )));

    // «Fonti distinte» non e' «fonti indipendenti», e in un atto la differenza
    // e' la piu' importante che ci sia: contarle come corroborazione
    // trasformerebbe un rilancio in una conferma.
    blocks.push(Block::Paragraph(String::from(
        "Il numero di fonti distinte non misura l'indipendenza delle voci: più canali \
         possono riprendere la stessa origine, e stabilire chi abbia scritto per primo \
         non è nelle possibilità del programma. La rilevanza per l'Italia, dove \
         indicata, non è un giudizio di gravità.",
    )));

    if input.cyber_events.is_empty() {
        blocks.push(Block::Paragraph(String::from(
            "Nessun indicatore tecnico ricorre in più di un contenuto della sessione: \
             non si è formato alcun gruppo. La presente dichiarazione riguarda ciò che \
             la correlazione ha trovato nei contenuti acquisiti, e non costituisce \
             attestazione che nulla di rilevante sia accaduto.",
        )));
    } else {
        for event in input.cyber_events {
            blocks.push(Block::Lead {
                lead: format!("{} \u{2014}", event.reason),
                body: format!(
                    "{} contenuti da {} fonti distinte{}. Osservati fra il {} e il {}. {} {}",
                    event.contents,
                    event.distinct_sources,
                    if event.apparent_reposts > 0 {
                        format!(
                            ", di cui {} con testo identico a un altro del gruppo",
                            event.apparent_reposts
                        )
                    } else {
                        String::new()
                    },
                    event
                        .first_seen
                        .map_or_else(|| String::from(NOT_AVAILABLE), Timestamp::to_readable_utc),
                    event
                        .last_seen
                        .map_or_else(|| String::from(NOT_AVAILABLE), Timestamp::to_readable_utc),
                    event.italy,
                    event.review
                ),
            });

            // Il settore in un paragrafo proprio, e non nella riga del gruppo.
            //
            // Nella riga si perderebbe fra i numeri, e un'attribuzione
            // settoriale in un fascicolo che esce dall'ufficio va letta con la
            // propria provenienza accanto: quale organizzazione, che cosa ha
            // riscontrato, e chi l'ha dichiarata.
            //
            // Compare **solo quando c'e'**: una riga «Nessun settore» ripetuta
            // per ogni gruppo insegnerebbe a saltarla.
            if let Some(settori) = &event.sectors {
                blocks.push(Block::Paragraph(settori.clone()));
            }

            if !event.indicators.is_empty() {
                blocks.push(Block::Paragraph(format!(
                    "Indicatori nominati dai contenuti del gruppo: {}.",
                    event.indicators.join("; ")
                )));
            }

            push_timeline(&mut blocks, event.timeline.as_ref());
            push_neighbourhood(
                &mut blocks,
                event.neighbourhood.as_ref(),
                input.investigative_basis,
            );
        }
    }

    // 6. I SOGGETTI
    //
    // # Perche' stanno nell'ALLEGATO e non nella relazione
    //
    // Per la stessa ragione dei gruppi di segnali, e con un motivo in piu'. La
    // relazione rappresenta la selezione dei CONTENUTI che una persona ha
    // scelto di rappresentare (ADR-0031 Decisione 2); un soggetto non e' un
    // contenuto, e metterlo li' trasformerebbe un atto sui fatti osservati in
    // un atto sulle persone.
    //
    // L'allegato rappresenta tutto cio' che il monitoraggio ha prodotto, ed e'
    // li' che chi legge si aspetta di trovare il lavoro dell'ufficio accanto ai
    // fatti (ADR-0105, decisione 6).
    blocks.push(Block::Heading(String::from("6. I SOGGETTI")));

    // IL CANCELLO DELLA RAGIONE OPERATIVA VALE ANCHE SULLA CARTA, e quando e'
    // chiuso il documento lo DICE: una sezione vuota si leggerebbe come
    // «nessuna persona di interesse», che e' un'affermazione e non un'assenza.
    if !input.investigative_basis {
        blocks.push(Block::Paragraph(String::from(
            SENZA_RAGIONE_OPERATIVA_NON_SI_ELENCA,
        )));
    } else {
        // LA DICHIARAZIONE VIENE PRIMA DEI NOMI, e sta in ogni copia del
        // documento: su carta non si vede nulla di cio' che dentro il programma
        // rende evidente che un fascicolo e' nato da una decisione.
        blocks.push(Block::Paragraph(String::from(CHE_COSA_E_UN_SOGGETTO)));

        if input.subjects.is_empty() {
            blocks.push(Block::Paragraph(String::from(
                "Nessun fascicolo aperto dall'ufficio ha un'identità collegata a cui il \
                 presente monitoraggio abbia osservato contenuti. La presente \
                 dichiarazione riguarda i fascicoli e i collegamenti registrati, e non \
                 costituisce attestazione che nessuna persona sia di interesse.",
            )));
        } else {
            for (position, subject) in input.subjects.iter().enumerate() {
                push_subject(&mut blocks, position + 1, subject);
            }
        }
    }

    // 7. I RIFERIMENTI TASSONOMICI E I DATI UFFICIALI
    //
    // # Perche' la sezione c'e' anche quando e' vuota
    //
    // Perche' un fascicolo senza la sezione si leggerebbe come un fascicolo in
    // cui la domanda non e' stata posta. Vuota, la sezione dice che NESSUNO ne
    // ha dichiarati — che e' un fatto diverso da «non ce ne sono» (ADR-0107,
    // decisione 5).
    blocks.push(Block::Heading(String::from(
        "7. I RIFERIMENTI TASSONOMICI E I DATI UFFICIALI",
    )));

    // LA DICHIARAZIONE VIENE PRIMA DEI RIFERIMENTI. Un identificativo con un
    // nome accanto ha l'aspetto di una classificazione compiuta, e nessuno
    // immagina che dietro ci sia una persona che ha scritto un motivo.
    blocks.push(Block::Paragraph(String::from(
        CHE_COSA_E_UN_RIFERIMENTO_TASSONOMICO,
    )));

    if input.taxonomy.is_empty() {
        blocks.push(Block::Paragraph(String::from(
            NESSUN_RIFERIMENTO_TASSONOMICO_DICHIARATO,
        )));
    } else {
        for reference in input.taxonomy {
            push_taxonomy_reference(&mut blocks, reference);
        }

        if input.taxonomy_beyond > 0 {
            blocks.push(Block::Paragraph(format!(
                "Per i contenuti del presente monitoraggio risultano dichiarati altri {} \
                 riferimenti, non riprodotti nel presente documento per ragioni di \
                 estensione.",
                input.taxonomy_beyond
            )));
        }
    }

    // I CATALOGHI UFFICIALI, con la loro data e la loro designazione.
    blocks.push(Block::Paragraph(String::from(UNA_FOTOGRAFIA_NON_E_OGGI)));

    if input.official_sources.is_empty() {
        blocks.push(Block::Paragraph(String::from(
            "L'archivio non conserva alcuna fotografia di catalogo ufficiale. Nessuna \
             affermazione del presente documento poggia quindi su una fonte ufficiale \
             importata.",
        )));
    } else {
        for source in input.official_sources {
            blocks.push(Block::Lead {
                lead: format!("{} —", source.catalogue),
                body: format!(
                    "{}. Importata da {} il {}. {}{}",
                    source.identity,
                    source.imported_by,
                    source.imported_at.to_readable_utc(),
                    source.counts,
                    source
                        .digest
                        .as_ref()
                        .map_or_else(String::new, |impronta| format!(
                            " Impronta di ciò che è stato acquisito: {impronta}."
                        ))
                ),
            });
            // LA DESIGNAZIONE SI RIPRODUCE, ed e' un obbligo di licenza e non
            // una cortesia: un documento consegnato e' una copia (ADR-0107,
            // decisione 4).
            blocks.push(Block::Paragraph(source.attribution.clone()));
        }
    }

    // 8. LE NOTE E I RACCOGLITORI DELL'OPERATORE
    //
    // # Perche' in fondo, e non accanto a ogni contenuto
    //
    // Perche' una nota accanto al testo acquisito si legge come parte del
    // contenuto: stessa pagina, stesso carattere, nessuna distanza. In una
    // sezione propria, aperta dalla frase che dice che cosa sono, chi legge
    // sa di aver cambiato genere di materiale (ADR-0108, decisione 1).
    blocks.push(Block::Heading(String::from(
        "8. LE NOTE E I RACCOGLITORI DELL'OPERATORE",
    )));

    if input.notes.is_empty() && input.workspaces.is_empty() {
        blocks.push(Block::Paragraph(String::from(
            NESSUNA_NOTA_E_NESSUN_RACCOGLITORE,
        )));
    } else {
        if !input.notes.is_empty() {
            blocks.push(Block::Paragraph(String::from(CHE_COSA_E_UNA_NOTA)));
            for note in input.notes {
                push_note(&mut blocks, note);
            }
            if input.notes_beyond > 0 {
                blocks.push(Block::Paragraph(format!(
                    "Sulle cose rappresentate nel presente documento risultano scritte altre \
                     {} annotazioni, non riprodotte per ragioni di estensione.",
                    input.notes_beyond
                )));
            }
        }

        if !input.workspaces.is_empty() {
            blocks.push(Block::Paragraph(String::from(CHE_COSA_E_UN_RACCOGLITORE)));
            for workspace in input.workspaces {
                blocks.push(Block::Lead {
                    lead: format!(
                        "{} ({}) —",
                        workspace.name,
                        if workspace.open { "aperto" } else { "chiuso" }
                    ),
                    body: format!(
                        "aperto da {} il {}. Contiene {} contenuti di questo monitoraggio.{}",
                        workspace.created_by,
                        workspace.created_at.to_readable_utc(),
                        workspace.contents_here,
                        workspace
                            .description
                            .as_ref()
                            .map_or_else(String::new, |scopo| format!(
                                " A che cosa serve, \
                                 secondo chi lo ha aperto: «{scopo}»."
                            ))
                    ),
                });
            }
            if input.workspaces_beyond > 0 {
                blocks.push(Block::Paragraph(format!(
                    "Contengono contenuti di questo monitoraggio altri {} raccoglitori, non \
                     riprodotti per ragioni di estensione.",
                    input.workspaces_beyond
                )));
            }
        }
    }

    blocks.push(Block::Signature {
        place_and_date: format!(
            "{}, {}",
            input
                .profile
                .place
                .as_ref()
                .map_or(NOT_AVAILABLE, |field| field.as_str()),
            input.generated_at.to_readable_utc()
        ),
        role: input
            .profile
            .signer_role
            .as_ref()
            .map(|field| field.as_str().to_owned()),
        name: input
            .profile
            .signer_name
            .as_ref()
            .map(|field| field.as_str().to_owned()),
    });

    NarrativeReport {
        generated_at: input.generated_at,
        letterhead: letterhead(input.profile),
        footer: Vec::new(),
        blocks,
    }
}

/// Un contenuto, con le tre categorie tenute separate.
fn push_content(
    blocks: &mut Vec<Block>,
    position: usize,
    content: &LedgerContent,
    alerts: &[LedgerAlert],
) {
    blocks.push(Block::Emphasis(format!(
        "3.{position} — contenuto {} (fonte: {})",
        content.content_id.get(),
        content.source_label
    )));

    // Dati originali: cio' che la fonte ha pubblicato.
    blocks.push(Block::Lead {
        lead: String::from("Dati originali."),
        body: format!(
            "Pubblicato il {}. Autore: {}. Collegamento: {}.",
            content.published_at.to_readable_utc(),
            content.author.as_deref().unwrap_or(NOT_AVAILABLE),
            crate::message_link::in_documents_with(
                content.asked_link.as_deref(),
                content.url.as_deref()
            )
        ),
    });
    blocks.push(Block::Paragraph(format!("Testo: {}", content.body)));
    // L'ALLEGATO (ATTACH-01, ADR-0177, decisione 9): descrizione e impronta.
    if let Some(allegato) = &content.attachment {
        blocks.push(Block::Paragraph(allegato.clone()));
    }

    // Metadati del sistema: quando l'abbiamo visto e con che impronta.
    blocks.push(Block::Lead {
        lead: String::from("Metadati del sistema."),
        body: format!(
            "Acquisito il {}. Modo di acquisizione: {} Impronta SHA-256 del corpo: {}.",
            content.acquired_at.to_readable_utc(),
            content.origin,
            content.body_digest
        ),
    });

    // Che cosa e' successo DOPO l'acquisizione.
    //
    // # Perche' e' un blocco proprio, e perche' viene qui
    //
    // Viene dopo il testo e prima delle valutazioni, perche' e' la cosa che
    // cambia il modo di leggere entrambi: il testo qui sopra e' quello
    // acquisito, e il livello qui sotto e' stato calcolato su quello.
    //
    // Compare **solo quando c'e' qualcosa da dire**. Una riga «nessuna
    // modifica osservata» ripetuta per ogni contenuto di un allegato che ne
    // contiene centinaia insegnerebbe a saltarla, e la renderebbe inutile
    // proprio dove conta.
    if let Some(dopo) = &content.after_acquisition {
        blocks.push(Block::Lead {
            lead: String::from("Dopo l'acquisizione."),
            body: format!(
                "{dopo}. Il testo e il livello riportati qui sono quelli della \
                 versione acquisita: l'analisi non viene rifatta sulle versioni \
                 successive. NEXUM/97 non cancella contenuti, e che la fonte non \
                 esponga più un messaggio non dice chi lo abbia rimosso."
            ),
        });
    }

    // Valutazioni: cio' che il motore ha proposto e cio' che una persona ha
    // deciso, dichiarati come due cose distinte.
    let motivo = alerts
        .iter()
        .find(|alert| alert.content_id == content.content_id)
        .map_or_else(
            || String::from("nessun avviso emesso"),
            |alert| format!("avviso di livello {}: {}", alert.level, alert.reason),
        );
    blocks.push(Block::Lead {
        lead: String::from("Valutazioni."),
        body: format!(
            "Livello proposto dal motore: {}. Stato della revisione umana: {}. \
             Rappresentato nella relazione: {}. Motivazione del motore: {motivo}.",
            content.level,
            content.review_state.as_deref().unwrap_or(NOT_REVIEWED),
            if content.selected { "si" } else { "no" }
        ),
    });

    // Da dove venivano i termini che hanno prodotto quel livello.
    //
    // # Perche' subito dopo le valutazioni, e perche' solo quando c'e'
    //
    // Perche' e' cio' che rende la valutazione qui sopra **contestabile**: chi
    // legge puo' andare a vedere il dizionario, la versione, i termini. Senza,
    // «il motore ha proposto 3» resta un'affermazione che nessuno puo'
    // discutere.
    //
    // Compare solo per i contenuti che hanno prodotto riscontri. Su un
    // contenuto senza riscontri non c'e' provenienza da dichiarare, e una riga
    // ripetuta a vuoto insegnerebbe a saltare anche quelle che contano —
    // e' la stessa ragione del blocco «Dopo l'acquisizione» (ADR-0051
    // Decisione 6).
    if let Some(origine) = &content.analysis_origin {
        blocks.push(Block::Lead {
            lead: String::from("Origine dell'analisi."),
            body: origine.clone(),
        });
    }

    // Le versioni e il contorno chiudono il contenuto, dopo i tre gruppi.
    //
    // Composti dove li compone la relazione, e non qui: l'avvertenza che
    // distingue il testo giudicato dai testi osservati dopo deve essere la
    // stessa nei due documenti, e due composizioni divergono alla prima
    // modifica (ADR-0104).
    push_revisions(blocks, &content.revisions, content.revisions_beyond);
    push_contexts(blocks, &content.contexts, content.contexts_beyond);
}

/// Una nota, con la propria condizione prima del testo.
///
/// # Perche' il ritiro si legge PRIMA delle parole
///
/// Perche' letto dopo, il testo si e' gia' letto come se valesse. Una nota
/// ritirata resta nel documento — omettendola si riscriverebbe che cosa avevano
/// davanti quelli che ci hanno lavorato sopra — ma deve arrivare gia' marcata
/// (ADR-0108, decisione 2).
fn push_note(blocks: &mut Vec<Block>, note: &LedgerNote) {
    let intestazione = match note.withdrawal.as_ref() {
        None => format!(
            "Annotazione di {} del {} —",
            note.author,
            note.written_at.to_readable_utc()
        ),
        Some((chi, quando)) => format!(
            "Annotazione RITIRATA da {} il {}, scritta da {} il {} —",
            chi,
            quando.to_readable_utc(),
            note.author,
            note.written_at.to_readable_utc()
        ),
    };

    blocks.push(Block::Lead {
        lead: intestazione,
        body: format!("su {}: «{}»", note.about, note.body),
    });
}

/// Un riferimento tassonomico, con chi lo ha dichiarato e perche'.
///
/// # Perche' «deprecata» e «revocata» si scrivono con quelle parole
///
/// Perche' citare una tecnica che la tassonomia non riconosce piu', senza
/// dirlo, mette in un atto un riferimento che chi verifica non ritrovera' —
/// e la spiegazione piu' probabile, agli occhi di chi legge, sara' che il
/// riferimento era sbagliato (ADR-0107, decisione 2).
fn push_taxonomy_reference(blocks: &mut Vec<Block>, reference: &LedgerTaxonomyReference) {
    let stato = match (reference.deprecated, reference.revoked) {
        (false, false) => String::new(),
        (true, false) => {
            String::from(" ATTENZIONE: questa tecnica risulta DEPRECATA nella versione indicata.")
        }
        (false, true) => {
            String::from(" ATTENZIONE: questa tecnica risulta REVOCATA nella versione indicata.")
        }
        (true, true) => String::from(
            " ATTENZIONE: questa tecnica risulta DEPRECATA e REVOCATA nella versione indicata.",
        ),
    };

    blocks.push(Block::Lead {
        lead: format!("{} {} —", reference.technique, reference.technique_name),
        body: format!(
            "il termine «{}» ({}), trovato nel contenuto {}, è stato associato a questa \
             tecnica da {} il {}, con motivo: «{}». Versione di ATT&CK: {}.{}",
            reference.term,
            reference.term_category,
            reference.content_id.get(),
            reference.declared_by,
            reference.declared_at.to_readable_utc(),
            reference.reason,
            reference.attack_version,
            stato
        ),
    });
}

/// La cronologia di un grappolo, con la finestra e l'avvertenza.
///
/// # Perche' la finestra viene prima delle righe
///
/// Perche' e' cio' che rende leggibile un vuoto. Letta dopo, la linea si e' gia'
/// letta come una successione di fatti, e la finestra arriva a spiegare un
/// silenzio che nessuno aveva notato (ADR-0106, decisione 2).
fn push_timeline(blocks: &mut Vec<Block>, timeline: Option<&LedgerTimeline>) {
    let Some(timeline) = timeline else {
        return;
    };

    blocks.push(Block::Lead {
        lead: String::from("La cronologia del gruppo."),
        body: format!("{} {}", timeline.window, timeline.caveat),
    });

    for row in &timeline.rows {
        // OGNI RIGA NOMINA IL PROPRIO OROLOGIO, e non una volta in fondo alla
        // sezione: una riga citata in un documento viaggia da sola (ADR-0106,
        // decisione 1). La dicitura sta gia' nella frase che il dominio compone.
        blocks.push(Block::Paragraph(row.clone()));
    }

    if timeline.rows_beyond > 0 {
        blocks.push(Block::Paragraph(format!(
            "La cronologia di questo gruppo comprende altre {} righe, non riprodotte nel \
             presente documento per ragioni di estensione.",
            timeline.rows_beyond
        )));
    }
}

/// Il vicinato di un grappolo nel grafo delle prove, come legenda.
///
/// # Perche' nessuna voce e' collegata a un'altra voce
///
/// Perche' **un arco e' un fatto e un percorso e' un'affermazione**: ogni voce
/// dice per quale fatto e' collegata al CENTRO, e la composizione di fatti veri
/// che dicesse «A e B sono collegate» non avrebbe un arco da correggere
/// (GRAPH-01, R-15).
fn push_neighbourhood(
    blocks: &mut Vec<Block>,
    neighbourhood: Option<&LedgerNeighbourhood>,
    basis: bool,
) {
    // IL CANCELLO DELLA RAGIONE OPERATIVA vale anche qui, e quando e' chiuso il
    // documento lo dice invece di tacere: un silenzio si leggerebbe come «non
    // c'e' niente attorno a questo gruppo».
    if !basis {
        blocks.push(Block::Paragraph(String::from(
            SENZA_RAGIONE_OPERATIVA_NON_SI_COMPONE_IL_VICINATO,
        )));
        return;
    }

    let Some(neighbourhood) = neighbourhood else {
        return;
    };

    blocks.push(Block::Lead {
        lead: String::from("Che cosa tocca questo gruppo."),
        body: format!(
            "{} {} {}",
            neighbourhood.centre, neighbourhood.caveat, PERCHE_LA_FIGURA_NON_E_RIPRODOTTA
        ),
    });

    for node in &neighbourhood.legend {
        blocks.push(Block::Lead {
            lead: format!("{}. {} —", node.number, node.kind),
            body: format!(
                "{}. {} {}",
                node.label,
                node.why,
                if node.decided_by_a_person {
                    "Origine: operatore. Questo collegamento è l'atto di una persona."
                } else {
                    "Origine: osservato. Questo collegamento viene dall'archivio, non dalla decisione di qualcuno."
                }
            ),
        });
    }

    if neighbourhood.legend_beyond > 0 {
        blocks.push(Block::Paragraph(format!(
            "Al gruppo risultano collegate altre {} voci, non riprodotte nel presente \
             documento per ragioni di estensione.",
            neighbourhood.legend_beyond
        )));
    }

    if neighbourhood.edges_omitted > 0 {
        blocks.push(Block::Paragraph(format!(
            "Il vicinato conserva altri {} collegamenti oltre il tetto con cui è stato \
             composto.",
            neighbourhood.edges_omitted
        )));
    }
}

/// Un soggetto, con la valutazione tenuta separata dai fatti osservati.
///
/// # Perche' la valutazione ha un blocco tutto suo
///
/// Perche' il congelamento chiede che i segnali osservati stiano **accanto** a
/// essa, mai al posto suo. Scritti nella stessa riga, i numeri diventerebbero la
/// giustificazione del giudizio — e il giudizio, letto accanto ai numeri,
/// diventerebbe la loro conclusione (ADR-0105, decisione 4).
fn push_subject(blocks: &mut Vec<Block>, position: usize, subject: &LedgerSubject) {
    blocks.push(Block::Emphasis(format!(
        "6.{position} — {} ({})",
        subject.label,
        if subject.open {
            "fascicolo aperto"
        } else {
            "fascicolo chiuso"
        }
    )));

    blocks.push(Block::Lead {
        lead: String::from("Il fascicolo."),
        body: format!(
            "{} Motivo: «{}».",
            subject.dossier_sentence, subject.dossier_reason
        ),
    });

    // LA VALUTAZIONE, e «NON VALUTATO» si scrive invece di essere omesso:
    // un'omissione si leggerebbe come assenza di interesse.
    blocks.push(Block::Lead {
        lead: String::from("La valutazione dell'ufficio."),
        body: match subject.assessment_reason.as_deref() {
            None => subject.assessment_sentence.clone(),
            Some(motivo) => format!("{} Motivo: «{motivo}».", subject.assessment_sentence),
        },
    });

    for identity in &subject.identities {
        blocks.push(Block::Lead {
            lead: format!("Identità {} —", identity.identifier),
            body: format!(
                "collegata da {} il {}, con motivo: «{}». {}",
                identity.linked_by,
                identity.linked_at.to_readable_utc(),
                identity.link_reason,
                identity.link_basis
            ),
        });
        blocks.push(Block::Lead {
            lead: String::from("Osservato in questo monitoraggio:"),
            body: format!(
                "{} contenuti, di cui {} con avviso, da {} fonti distinte{}.",
                identity.contents_here,
                identity.alerts_here,
                identity.distinct_sources_here,
                match (identity.first_seen_here, identity.last_seen_here) {
                    (Some(primo), Some(ultimo)) => format!(
                        ", pubblicati fra il {} e il {}",
                        primo.to_readable_utc(),
                        ultimo.to_readable_utc()
                    ),
                    _ => String::new(),
                }
            ),
        });
    }

    if subject.identities_beyond > 0 {
        blocks.push(Block::Paragraph(format!(
            "A questo fascicolo risultano collegate altre {} identità, non riprodotte \
             nel presente documento per ragioni di estensione.",
            subject.identities_beyond
        )));
    }
}

/// La carta intestata dell'allegato, con gli stessi segnaposto della relazione.
fn letterhead(profile: &ReportTemplateProfile) -> Letterhead {
    let mut lines = Vec::new();
    push_line(
        &mut lines,
        profile.organisation.as_ref().map(|f| f.as_str()),
        "Denominazione dell'amministrazione",
    );
    push_line(
        &mut lines,
        profile.office.as_ref().map(|f| f.as_str()),
        "Ufficio o articolazione",
    );
    Letterhead {
        emblem: profile.emblem.clone(),
        lines,
    }
}

/// Una riga della carta intestata: configurata, oppure spazio da compilare.
fn push_line(lines: &mut Vec<LetterheadLine>, value: Option<&str>, placeholder: &str) {
    lines.push(value.map_or_else(
        || LetterheadLine::Placeholder(String::from(placeholder)),
        |text| LetterheadLine::Configured(String::from(text)),
    ));
}

#[cfg(test)]
mod tests {
    use lisi_core::ContentId;
    use lisi_core::digest::Sha256Digest;

    use super::*;
    use crate::report_ledger::{
        LedgerGraphNode, LedgerNote, LedgerOfficialSource, LedgerSubjectIdentity,
        LedgerTaxonomyReference, LedgerWorkspace,
    };

    fn contenuto(id: i64, level: u8, selected: bool, body: &str) -> LedgerContent {
        LedgerContent {
            content_id: ContentId::new(id),
            source_label: String::from("Canale di prova"),
            author: None,
            published_at: Timestamp::from_millis(1_752_001_000_000),
            acquired_at: Timestamp::from_millis(1_752_001_500_000),
            origin: String::from("osservato"),
            body: String::from(body),
            url: None,
            asked_link: None,
            attachment: None,
            level,
            review_state: None,
            selected,
            body_digest: Sha256Digest::of_text(body).as_str().to_owned(),
            after_acquisition: None,
            revisions: Vec::new(),
            revisions_beyond: 0,
            contexts: Vec::new(),
            contexts_beyond: 0,
            analysis_origin: None,
        }
    }

    fn sessione() -> LedgerSession {
        LedgerSession {
            label: String::from("Monitoraggio di prova"),
            started_at: Timestamp::from_millis(1_752_000_000_000),
            ended_at: None,
            state: String::from("conclusa"),
        }
    }

    fn testo(report: &NarrativeReport) -> String {
        report
            .blocks
            .iter()
            .map(|block| match block {
                Block::Heading(text)
                | Block::Paragraph(text)
                | Block::Emphasis(text)
                | Block::RightLine(text) => text.clone(),
                Block::Lead { lead, body } => format!("{lead} {body}"),
                Block::Table { headers, rows } => {
                    format!("{} {}", headers.join(" "), rows.concat().join(" "))
                }
                Block::Signature {
                    place_and_date,
                    role,
                    name,
                } => format!(
                    "{place_and_date} {} {}",
                    role.clone().unwrap_or_default(),
                    name.clone().unwrap_or_default()
                ),
            })
            .collect::<Vec<_>>()
            .join("\n")
    }

    fn allegato(contents: &[LedgerContent], alerts: &[LedgerAlert]) -> NarrativeReport {
        let report_id = ReportId::from_sequence(2026, 1);
        let profile = ReportTemplateProfile::default();
        let operator = Actor::try_new("operatore").expect("attore valido");
        let session = sessione();
        compose(&AnnexInput {
            report_id: &report_id,
            profile: &profile,
            operator: &operator,
            generated_at: Timestamp::from_millis(1_752_086_400_000),
            session: &session,
            sources: &[],
            contents,
            alerts,
            faults: &[],
            cyber_events: &[],
            subjects: &[],
            taxonomy: &[],
            taxonomy_beyond: 0,
            official_sources: &[],
            notes: &[],
            notes_beyond: 0,
            workspaces: &[],
            workspaces_beyond: 0,
            investigative_basis: true,
            coverage: &[],
            configuration: &crate::analysis_configuration::AnalysisConfiguration::unknown(),
        })
    }

    /// **Un contenuto recuperato si dichiara tale nell'allegato**, con chi,
    /// quando, per quale intervallo e ciò che il recupero non vede (PR-07,
    /// controllo negativo 4).
    #[test]
    fn a_recovered_content_is_declared_as_such() {
        let modo = lisi_core::model::AcquisitionMode::Recovered {
            at: Timestamp::from_millis(1_752_002_000_000),
            interval: Some((
                Timestamp::from_millis(1_752_000_000_000),
                Timestamp::from_millis(1_752_001_800_000),
            )),
            operator: Some(String::from("operatore.prova")),
        };
        let mut recuperato = contenuto(1, 2, true, "ritrovato dopo");
        recuperato.origin = crate::acquisition_mode::declared(&modo);
        let testo = testo(&allegato(&[recuperato], &[]));
        assert!(
            testo.contains("Modo di acquisizione: Recuperato il"),
            "l'allegato deve dichiarare il modo"
        );
        assert!(testo.contains("da operatore.prova"));
        assert!(testo.contains(lisi_core::model::RECOVERY_LIMITS));
    }

    #[test]
    fn every_monitored_content_appears_including_level_zero() {
        // Come il registro e a differenza della relazione: rappresenta tutto.
        let contents = [
            contenuto(1, 0, false, "livello zero"),
            contenuto(2, 4, true, "selezionato"),
            contenuto(3, 0, false, "un altro livello zero"),
        ];
        let report = allegato(&contents, &[]);
        let testo = testo(&report);

        for corpo in ["livello zero", "selezionato", "un altro livello zero"] {
            assert!(testo.contains(corpo), "manca «{corpo}»");
        }
        assert!(testo.contains("3 contenuti"));
    }

    #[test]
    fn the_three_categories_are_kept_apart() {
        // È la ragione per cui questo documento esiste in questa forma: dati
        // originali, metadati del sistema e valutazioni non si mescolano.
        let contents = [contenuto(1, 2, false, "testo")];
        let report = allegato(&contents, &[]);
        let testo = testo(&report);

        assert!(testo.contains("Dati originali."));
        assert!(testo.contains("Metadati del sistema."));
        assert!(testo.contains("Valutazioni."));
    }

    #[test]
    fn the_engine_level_and_the_human_decision_are_two_distinct_statements() {
        let contents = [contenuto(1, 3, false, "testo")];
        let report = allegato(&contents, &[]);
        let testo = testo(&report);

        assert!(testo.contains("Livello proposto dal motore: 3"));
        assert!(testo.contains("Stato della revisione umana:"));
    }

    #[test]
    fn a_content_without_an_alert_says_so_instead_of_staying_silent() {
        let contents = [contenuto(1, 0, false, "testo")];
        let report = allegato(&contents, &[]);
        assert!(testo(&report).contains("nessun avviso emesso"));
    }

    #[test]
    fn no_faults_recorded_is_not_the_same_as_no_faults_happened() {
        // Il documento afferma cio' che sa, non cio' che spera: e' la stessa
        // regola per cui una relazione senza selezione non dichiara che non
        // esistano elementi illeciti.
        let report = allegato(&[contenuto(1, 0, false, "testo")], &[]);
        let testo = testo(&report);

        assert!(testo.contains("non sono state registrate anomalie tecniche"));
        assert!(
            testo.contains("non costituisce attestazione"),
            "l'allegato afferma piu' di quanto sappia"
        );
    }

    #[test]
    fn the_body_digest_reaches_the_document() {
        let contents = [contenuto(1, 0, false, "corpo noto")];
        let atteso = Sha256Digest::of_text("corpo noto").as_str().to_owned();
        let report = allegato(&contents, &[]);
        assert!(testo(&report).contains(&atteso));
    }

    #[test]
    fn an_unconfigured_profile_leaves_blanks_to_fill() {
        let report = allegato(&[contenuto(1, 0, false, "testo")], &[]);
        let intestazione: Vec<String> = report
            .letterhead
            .lines
            .iter()
            .map(LetterheadLine::text)
            .collect();
        assert!(
            intestazione
                .iter()
                .any(|line| line.contains("[Denominazione dell'amministrazione]")),
            "gli spazi da compilare non compaiono: {intestazione:?}"
        );
    }

    #[test]
    fn the_annex_carries_the_report_identifier() {
        // È il legame fra gli artefatti dello stesso pacchetto.
        let report = allegato(&[contenuto(1, 0, false, "testo")], &[]);
        assert!(testo(&report).contains("R-2026-"));
    }

    /// Un gruppo di segnali di prova, con l'indicatore indicato.
    fn gruppo(valore: &str, contenuti: usize, fonti: usize) -> LedgerCyberEvent {
        LedgerCyberEvent {
            reason: format!("nominano la vulnerabilità dichiarata «{valore}»"),
            indicator_kind: String::from("vulnerabilità dichiarata"),
            indicator_value: String::from(valore),
            contents: contenuti,
            distinct_sources: fonti,
            apparent_reposts: 0,
            first_seen: Some(Timestamp::from_millis(1_752_000_000_000)),
            last_seen: Some(Timestamp::from_millis(1_752_086_400_000)),
            italy: String::from("Nessun segnale che riguardi l'Italia."),
            sectors: None,
            indicators: vec![String::from("vulnerabilità dichiarata: CVE-2026-1")],
            review: String::from("Nessuno dei 2 contenuti è stato ancora esaminato."),
            timeline: None,
            neighbourhood: None,
        }
    }

    /// Una nota di prova, ritirata o in piedi.
    fn nota(ritirata: bool) -> LedgerNote {
        LedgerNote {
            about: String::from("il contenuto 1"),
            body: String::from("questo messaggio sembra ripreso da un canale che seguiamo"),
            author: String::from("operatore.anna"),
            written_at: Timestamp::from_millis(1_752_001_000_000),
            withdrawal: ritirata.then(|| {
                (
                    String::from("operatore.bruno"),
                    Timestamp::from_millis(1_752_002_000_000),
                )
            }),
        }
    }

    /// Un raccoglitore di prova.
    fn raccoglitore() -> LedgerWorkspace {
        LedgerWorkspace {
            name: String::from("FILONE DI LUGLIO"),
            description: Some(String::from("tutto ciò che nomina lo stesso dominio")),
            created_by: String::from("operatore.anna"),
            created_at: Timestamp::from_millis(1_752_000_500_000),
            open: true,
            contents_here: 3,
        }
    }

    /// Allegato con le note e i raccoglitori indicati.
    fn allegato_con_note(
        note: &[LedgerNote],
        note_oltre: usize,
        raccoglitori: &[LedgerWorkspace],
        raccoglitori_oltre: usize,
    ) -> NarrativeReport {
        let report_id = ReportId::from_sequence(2026, 1);
        let profile = ReportTemplateProfile::default();
        let operator = Actor::try_new("operatore").expect("attore valido");
        let session = sessione();
        compose(&AnnexInput {
            report_id: &report_id,
            profile: &profile,
            operator: &operator,
            generated_at: Timestamp::from_millis(1_752_086_400_000),
            session: &session,
            sources: &[],
            contents: &[],
            alerts: &[],
            faults: &[],
            cyber_events: &[],
            subjects: &[],
            taxonomy: &[],
            taxonomy_beyond: 0,
            official_sources: &[],
            notes: note,
            notes_beyond: note_oltre,
            workspaces: raccoglitori,
            workspaces_beyond: raccoglitori_oltre,
            investigative_basis: true,
            coverage: &[],
            configuration: &crate::analysis_configuration::AnalysisConfiguration::unknown(),
        })
    }

    /// **La sezione dichiara che cos'è una nota, prima di riportarne una.**
    ///
    /// # Il difetto che questa prova impedisce
    ///
    /// Una nota non e' un'osservazione e non e' una decisione: si scrive quando
    /// si vuole, e nessun fatto la occasiona. Accanto al testo acquisito e alla
    /// motivazione del motore arriva nella stessa pagina con lo stesso
    /// carattere, e chi riceve il fascicolo non distingue «il motore ha trovato
    /// questi termini» da «un operatore ha scritto che secondo lui questo e' un
    /// segnale» (ADR-0108, decisione 1; R-18).
    #[test]
    fn la_sezione_delle_note_dichiara_prima_di_riportare() {
        let report = allegato_con_note(&[nota(false)], 0, &[], 0);
        let text = report.text();

        let Some(posizione_dichiarazione) = text.find("LE PAROLE DI UNA PERSONA") else {
            panic!("la dichiarazione deve esserci");
        };
        let Some(posizione_nota) = text.find("sembra ripreso da un canale") else {
            panic!("la nota deve esserci");
        };
        assert!(
            posizione_dichiarazione < posizione_nota,
            "una nota compare prima della dichiarazione che spiega che cos'e'"
        );
        assert!(
            text.contains("NON MODIFICANO LA PROVA ORIGINALE"),
            "la dichiarazione non dice che la nota non tocca la prova"
        );
        assert!(
            text.contains("Non sono osservazioni del programma"),
            "la dichiarazione non distingue la nota da un'osservazione"
        );
    }

    /// **Una nota ritirata compare marcata, e la marca si legge prima del
    /// testo.**
    ///
    /// # Il difetto che questa prova impedisce
    ///
    /// Stampata come se valesse, attribuirebbe a una persona un'affermazione
    /// che quella persona ha ritirato. Omessa, riscriverebbe che cosa avevano
    /// davanti quelli che ci hanno lavorato sopra. Letta la marca DOPO, il testo
    /// si e' gia' letto come se valesse (ADR-0108, decisione 2).
    #[test]
    fn una_nota_ritirata_compare_marcata_prima_del_testo() {
        let report = allegato_con_note(&[nota(true)], 0, &[], 0);
        let text = report.text();

        // Resta: non sparisce.
        assert!(
            text.contains("sembra ripreso da un canale"),
            "una nota ritirata e' sparita dal documento"
        );

        let Some(posizione_marca) = text.find("RITIRATA") else {
            panic!("la marca del ritiro deve esserci");
        };
        let Some(posizione_testo) = text.find("sembra ripreso da un canale") else {
            panic!("il testo della nota deve esserci");
        };
        assert!(
            posizione_marca < posizione_testo,
            "il testo di una nota ritirata si legge prima della marca che la ritira"
        );
        assert!(
            text.contains("operatore.bruno"),
            "il ritiro non dice chi lo ha fatto"
        );

        // E una nota in piedi NON porta la marca.
        let in_piedi = allegato_con_note(&[nota(false)], 0, &[], 0);
        assert!(
            !in_piedi.text().contains("RITIRATA"),
            "una nota in piedi porta una marca che non le spetta"
        );
    }

    /// **Del raccoglitore si dichiara che raccogliere non è concludere.**
    ///
    /// E che **contiene altro**: un raccoglitore attraversa i monitoraggi per
    /// costruzione, un documento no (ADR-0108, decisione 3).
    #[test]
    fn del_raccoglitore_si_dichiara_che_raccogliere_non_e_concludere() {
        let report = allegato_con_note(&[], 0, &[raccoglitore()], 0);
        let text = report.text();

        let Some(posizione_dichiarazione) = text.find("RACCOGLIERE NON È CONCLUDERE") else {
            panic!("la dichiarazione deve esserci");
        };
        let Some(posizione_nome) = text.find("FILONE DI LUGLIO") else {
            panic!("il raccoglitore deve esserci");
        };
        assert!(
            posizione_dichiarazione < posizione_nome,
            "un raccoglitore compare prima della dichiarazione che spiega che cos'e'"
        );
        assert!(
            text.contains("SOLTANTO gli elementi di questo monitoraggio"),
            "il documento non dice che il raccoglitore contiene altro"
        );
        assert!(
            text.contains("Contiene 3 contenuti di questo monitoraggio"),
            "manca il conteggio degli elementi di questo monitoraggio"
        );
    }

    /// **Senza note e senza raccoglitori la sezione resta, e dice il proprio
    /// vuoto.**
    #[test]
    fn senza_note_e_raccoglitori_la_sezione_resta_e_dichiara_il_vuoto() {
        let report = allegato_con_note(&[], 0, &[], 0);
        let text = report.text();

        assert!(text.contains("8. LE NOTE E I RACCOGLITORI DELL'OPERATORE"));
        assert!(
            text.contains("non risultano annotazioni scritte"),
            "la sezione vuota non dice che nessuno ha annotato"
        );
        assert!(
            text.contains("NON significa che non vi fosse nulla da \\\n     annotare")
                || text.contains("NON significa che non vi fosse nulla da"),
            "l'assenza si traveste da assenza di cose da annotare"
        );
    }

    /// **I tagli delle note e dei raccoglitori si dichiarano.**
    #[test]
    fn i_tagli_delle_note_e_dei_raccoglitori_si_dichiarano() {
        let report = allegato_con_note(&[nota(false)], 6, &[raccoglitore()], 2);
        let text = report.text();

        assert!(
            text.contains("altre 6 annotazioni"),
            "il taglio delle note non dice quante restano fuori"
        );
        assert!(
            text.contains("altri 2 raccoglitori"),
            "il taglio dei raccoglitori non dice quanti restano fuori"
        );
    }

    /// Un riferimento tassonomico di prova.
    fn riferimento(deprecated: bool, revoked: bool) -> LedgerTaxonomyReference {
        LedgerTaxonomyReference {
            content_id: ContentId::new(1),
            term: String::from("esca"),
            term_category: String::from("lessico"),
            technique: String::from("T1566"),
            technique_name: String::from("Phishing"),
            attack_version: String::from("19.2"),
            deprecated,
            revoked,
            reason: String::from("il termine ricorre nei messaggi di adescamento"),
            declared_by: String::from("operatore.anna"),
            declared_at: Timestamp::from_millis(1_752_001_000_000),
        }
    }

    /// Una fotografia di catalogo ufficiale di prova.
    fn fonte_ufficiale() -> LedgerOfficialSource {
        LedgerOfficialSource {
            catalogue: String::from("MITRE ATT&CK"),
            identity: String::from("dominio enterprise-attack, versione 19.2, specifica 3.3.0"),
            imported_by: String::from("operatore.anna"),
            imported_at: Timestamp::from_millis(1_752_000_000_000),
            digest: Some(String::from("abcdef0123456789")),
            counts: String::from("799 tecniche e 14 tattiche."),
            attribution: String::from(
                "© 2026 The MITRE Corporation. Questo lavoro riproduce dati di MITRE ATT&CK.",
            ),
        }
    }

    /// Allegato con i riferimenti e le fotografie indicati.
    fn allegato_con_tassonomia(
        riferimenti: &[LedgerTaxonomyReference],
        oltre: usize,
        fonti: &[LedgerOfficialSource],
    ) -> NarrativeReport {
        let report_id = ReportId::from_sequence(2026, 1);
        let profile = ReportTemplateProfile::default();
        let operator = Actor::try_new("operatore").expect("attore valido");
        let session = sessione();
        compose(&AnnexInput {
            report_id: &report_id,
            profile: &profile,
            operator: &operator,
            generated_at: Timestamp::from_millis(1_752_086_400_000),
            session: &session,
            sources: &[],
            contents: &[],
            alerts: &[],
            faults: &[],
            cyber_events: &[],
            subjects: &[],
            taxonomy: riferimenti,
            taxonomy_beyond: oltre,
            official_sources: fonti,
            notes: &[],
            notes_beyond: 0,
            workspaces: &[],
            workspaces_beyond: 0,
            investigative_basis: true,
            coverage: &[],
            configuration: &crate::analysis_configuration::AnalysisConfiguration::unknown(),
        })
    }

    /// **La sezione dichiara che ATT&CK è un vocabolario, prima di elencare.**
    ///
    /// # Il difetto che questa prova impedisce
    ///
    /// Un identificativo con un nome accanto **ha l'aspetto di una
    /// classificazione compiuta**, e nessuno immagina che dietro ci sia una
    /// persona che ha scritto un motivo. Letto in un atto, `T1566 — Phishing`
    /// diventa «questo e' phishing», e a un passo «questa persona ha fatto
    /// phishing» (ADR-0107, decisione 1; R-16).
    #[test]
    fn la_sezione_tassonomica_dichiara_prima_di_elencare() {
        let report = allegato_con_tassonomia(&[riferimento(false, false)], 0, &[]);
        let text = report.text();

        let Some(posizione_dichiarazione) = text.find("è un vocabolario condiviso") else {
            panic!("la dichiarazione deve esserci");
        };
        let Some(posizione_tecnica) = text.find("T1566") else {
            panic!("il riferimento deve esserci");
        };
        assert!(
            posizione_dichiarazione < posizione_tecnica,
            "una tecnica compare prima della dichiarazione che spiega che cos'e'"
        );

        for atteso in [
            "NON attribuiscono alcuna condotta",
            "NON alza il livello di analisi",
            "non è un segnale",
        ] {
            assert!(
                text.contains(atteso),
                "la dichiarazione non dice «{atteso}»"
            );
        }
    }

    /// **Ogni riferimento porta chi, quando, perché e la versione.**
    ///
    /// La versione non e' un dettaglio: un identificativo significa cose diverse
    /// in versioni diverse, e citarlo senza versione cita una cosa che non si sa
    /// quale sia.
    #[test]
    fn ogni_riferimento_porta_chi_quando_perche_e_la_versione() {
        let report = allegato_con_tassonomia(&[riferimento(false, false)], 0, &[]);
        let text = report.text();

        assert!(text.contains("operatore.anna"), "manca chi ha dichiarato");
        assert!(
            text.contains("il termine ricorre nei messaggi di adescamento"),
            "manca il motivo con le parole di chi lo ha scritto"
        );
        assert!(
            text.contains("Versione di ATT&CK: 19.2"),
            "manca la versione della tassonomia"
        );
        assert!(
            text.contains("il termine «esca»"),
            "il riferimento non dice che riguarda un TERMINE"
        );
    }

    /// **Una tecnica deprecata o revocata si dice con quelle parole.**
    ///
    /// # Il difetto che questa prova impedisce
    ///
    /// Citare una tecnica che la tassonomia non riconosce piu', senza dirlo,
    /// mette in un atto un riferimento che chi verifica non ritrovera' — e la
    /// spiegazione piu' probabile, agli occhi di chi legge, sara' che il
    /// riferimento era sbagliato (ADR-0107, decisione 2).
    #[test]
    fn una_tecnica_deprecata_o_revocata_si_dice_con_quelle_parole() {
        for (deprecata, revocata, attesa) in [
            (true, false, "DEPRECATA"),
            (false, true, "REVOCATA"),
            (true, true, "DEPRECATA e REVOCATA"),
        ] {
            let report = allegato_con_tassonomia(&[riferimento(deprecata, revocata)], 0, &[]);
            assert!(
                report.text().contains(attesa),
                "una tecnica {attesa} non lo dichiara"
            );
        }

        // E una tecnica in vigore NON porta l'avvertenza: una guardia che
        // compare anche dove non serve si impara a saltarla.
        let report = allegato_con_tassonomia(&[riferimento(false, false)], 0, &[]);
        assert!(
            !report.text().contains("DEPRECATA") && !report.text().contains("REVOCATA"),
            "una tecnica in vigore porta un'avvertenza che non le spetta"
        );
    }

    /// **Senza riferimenti la sezione resta, e dice che nessuno ne ha
    /// dichiarati.**
    ///
    /// Un fascicolo senza la sezione si leggerebbe come un fascicolo in cui la
    /// domanda non e' stata posta, e una sezione vuota come «nessuna tecnica e'
    /// pertinente» — che e' un'affermazione che nessuno ha fatto.
    #[test]
    fn senza_riferimenti_la_sezione_resta_e_dice_che_nessuno_ne_ha_dichiarati() {
        let report = allegato_con_tassonomia(&[], 0, &[]);
        let text = report.text();

        assert!(text.contains("7. I RIFERIMENTI TASSONOMICI E I DATI UFFICIALI"));
        assert!(
            text.contains("Nessun operatore ha dichiarato riferimenti tassonomici"),
            "la sezione vuota non dice che nessuno si e' espresso"
        );
        assert!(
            text.contains("NON significa che nessuna tecnica sia pertinente"),
            "l'assenza si traveste da assenza di pertinenza"
        );
    }

    /// **La designazione di copyright si riproduce, e la fotografia non si
    /// presenta come lo stato di oggi.**
    ///
    /// # Perche' la designazione non e' una cortesia
    ///
    /// Perche' le fotografie portano una designazione che **ogni copia deve
    /// riprodurre**, e un documento consegnato e' una copia. Un atto che usa
    /// quei dati senza riprodurla viola la licenza con cui sono stati ottenuti
    /// (ADR-0107, decisione 4).
    #[test]
    fn la_designazione_si_riproduce_e_la_fotografia_non_e_oggi() {
        let fonti = [fonte_ufficiale()];
        let report = allegato_con_tassonomia(&[], 0, &fonti);
        let fonte = &fonti[0];
        let text = report.text();

        assert!(
            text.contains(fonte.attribution.as_str()),
            "la designazione di copyright non e' riprodotta nel documento"
        );
        assert!(
            text.contains("Non sono lo stato odierno"),
            "il documento presenta una fotografia come lo stato di oggi"
        );
        assert!(
            text.contains("può esservi entrato dopo"),
            "il documento non dice che cio' che manca puo' essere arrivato dopo"
        );
        assert!(
            text.contains("799 tecniche e 14 tattiche"),
            "i conteggi della fotografia non arrivano al documento"
        );
        assert!(
            text.contains("abcdef0123456789"),
            "l'impronta della fotografia non arriva al documento"
        );
    }

    /// Una cronologia di prova, con righe di due orologi.
    fn cronologia(rows_beyond: usize) -> LedgerTimeline {
        LedgerTimeline {
            window: String::from(
                "Si è osservato dal 2026-07-09 al 2026-07-10, e soltanto nelle fonti del \
                 monitoraggio.",
            ),
            caveat: String::from(
                "Queste righe dicono che cosa si è osservato. Un periodo senza righe non \
                 significa che non sia successo niente. Gli istanti vengono da due orologi \
                 diversi.",
            ),
            rows: vec![
                String::from(
                    "2026-07-09 10:00:00 UTC (dichiarato dalla fonte) — primo contenuto del \
                     gruppo. Contenuto 1.",
                ),
                String::from(
                    "2026-07-09 12:00:00 UTC (misurato da questa postazione) — revisione \
                     avviata. Contenuto 1.",
                ),
            ],
            rows_beyond,
        }
    }

    /// Un vicinato di prova, con due voci.
    fn vicinato(legend_beyond: usize) -> LedgerNeighbourhood {
        LedgerNeighbourhood {
            centre: String::from("gruppo di segnali: CVE-2026-0001"),
            caveat: String::from(
                "Ogni arco dice per quale fatto esiste. Due nodi che risultano collegati \
                 attraverso un terzo non hanno per questo a che fare l'uno con l'altro.",
            ),
            legend: vec![
                LedgerGraphNode {
                    number: 1,
                    kind: String::from("contenuto"),
                    label: String::from("CONTENUTO UNO"),
                    why: String::from("nomina l'indicatore del gruppo; fatto letto dall'archivio."),
                    decided_by_a_person: false,
                },
                LedgerGraphNode {
                    number: 2,
                    kind: String::from("soggetto"),
                    label: String::from("SOGGETTO DUE"),
                    why: String::from("collegato da operatore.anna; atto registrato."),
                    decided_by_a_person: true,
                },
            ],
            legend_beyond,
            edges_omitted: 0,
        }
    }

    /// Allegato con un gruppo che porta cronologia e vicinato.
    fn allegato_con_cronologia(
        timeline: Option<LedgerTimeline>,
        neighbourhood: Option<LedgerNeighbourhood>,
        ragione: bool,
    ) -> NarrativeReport {
        let report_id = ReportId::from_sequence(2026, 1);
        let profile = ReportTemplateProfile::default();
        let operator = Actor::try_new("operatore").expect("attore valido");
        let session = sessione();
        let mut evento = gruppo("CVE-2026-0001", 2, 2);
        evento.timeline = timeline;
        evento.neighbourhood = neighbourhood;
        let eventi = [evento];
        compose(&AnnexInput {
            report_id: &report_id,
            profile: &profile,
            operator: &operator,
            generated_at: Timestamp::from_millis(1_752_086_400_000),
            session: &session,
            sources: &[],
            contents: &[],
            alerts: &[],
            faults: &[],
            cyber_events: &eventi,
            subjects: &[],
            taxonomy: &[],
            taxonomy_beyond: 0,
            official_sources: &[],
            notes: &[],
            notes_beyond: 0,
            workspaces: &[],
            workspaces_beyond: 0,
            investigative_basis: ragione,
            coverage: &[],
            configuration: &crate::analysis_configuration::AnalysisConfiguration::unknown(),
        })
    }

    /// **La finestra di osservazione viene prima delle righe.**
    ///
    /// # Il difetto che questa prova impedisce
    ///
    /// Letta dopo, la linea si e' gia' letta come una successione di fatti, e la
    /// finestra arriva a spiegare un silenzio che nessuno aveva notato. Un
    /// periodo senza righe **non** significa che non sia successo niente: puo'
    /// significare che nessuno stava guardando (ADR-0106, decisione 2).
    #[test]
    fn la_finestra_di_osservazione_viene_prima_delle_righe() {
        let report = allegato_con_cronologia(Some(cronologia(0)), None, true);
        let text = report.text();

        let Some(posizione_finestra) = text.find("Si è osservato dal") else {
            panic!("la finestra deve esserci");
        };
        let Some(posizione_prima_riga) = text.find("primo contenuto del gruppo") else {
            panic!("le righe devono esserci");
        };
        assert!(
            posizione_finestra < posizione_prima_riga,
            "le righe compaiono prima della finestra che le rende leggibili"
        );
        assert!(
            text.contains("non significa che non sia successo niente"),
            "manca l'avvertenza che rende leggibile un vuoto"
        );
    }

    /// **Ogni riga della cronologia nomina il proprio orologio.**
    ///
    /// # Perche' in ogni riga e non una volta in fondo
    ///
    /// Perche' una riga citata in un documento **viaggia da sola**: chi la
    /// copia in una comunicazione di servizio non porta con se' la nota a pie'
    /// di sezione, e l'istante resta senza il proprio orologio (ADR-0106,
    /// decisione 1).
    #[test]
    fn ogni_riga_della_cronologia_nomina_il_proprio_orologio() {
        let cronologia = cronologia(0);
        let report = allegato_con_cronologia(Some(cronologia.clone()), None, true);
        let text = report.text();

        for riga in &cronologia.rows {
            assert!(
                text.contains(riga.as_str()),
                "una riga della cronologia non arriva al documento intera: «{riga}»"
            );
        }
        assert!(text.contains("dichiarato dalla fonte"));
        assert!(text.contains("misurato da questa postazione"));
        assert!(
            text.contains("due orologi"),
            "la linea mescola due orologi e non lo dice"
        );
    }

    /// **Nessuna voce del vicinato e' collegata a un'altra voce.**
    ///
    /// # Il difetto che questa prova impedisce
    ///
    /// **Un arco e' un fatto, un percorso e' un'affermazione.** La composizione
    /// di fatti veri produce un'impressione falsa: A e B nominano lo stesso
    /// dominio, ogni arco e' vero, e la figura dice che A e B sono collegate.
    /// Non c'e' un arco da correggere (GRAPH-01, R-15).
    #[test]
    fn nessuna_voce_del_vicinato_e_collegata_a_un_altra_voce() {
        let vicinato = vicinato(0);
        let report = allegato_con_cronologia(None, Some(vicinato.clone()), true);

        for voce in &vicinato.legend {
            let Some(blocco) = report
                .blocks
                .iter()
                .find(|block| block.text().contains(voce.label.as_str()))
            else {
                panic!("la voce «{}» deve esserci", voce.label);
            };
            for altra in &vicinato.legend {
                if altra.number == voce.number {
                    continue;
                }
                assert!(
                    !blocco.text().contains(altra.label.as_str()),
                    "la voce «{}» nomina «{}»: una legenda che collega due voci fra loro \
                     afferma un percorso",
                    voce.label,
                    altra.label
                );
            }
        }

        assert!(
            report
                .text()
                .contains("non hanno per questo a che fare l'uno con l'altro"),
            "l'avvertenza del vicinato non viaggia con la sezione"
        );
    }

    /// **Il documento dichiara perche' la figura non e' riprodotta.**
    ///
    /// Un silenzio si leggerebbe come «non c'e' niente da disegnare», che e'
    /// un'affermazione e non un'assenza (ADR-0106, decisione 4).
    #[test]
    fn il_documento_dichiara_perche_la_figura_non_e_riprodotta() {
        let report = allegato_con_cronologia(None, Some(vicinato(0)), true);
        let text = report.text();

        assert!(
            text.contains("non è riprodotta nel \\\n     presente documento")
                || text.contains("non è riprodotta")
        );
        assert!(
            text.contains("due documenti dello stesso fascicolo mostrerebbero cose diverse"),
            "il documento non dice perche' la figura manca"
        );
    }

    /// **Senza la ragione operativa il vicinato non si compone, e si dice.**
    #[test]
    fn senza_ragione_operativa_il_vicinato_non_si_compone_e_il_documento_lo_dice() {
        let report = allegato_con_cronologia(None, Some(vicinato(0)), false);
        let text = report.text();

        assert!(
            !text.contains("CONTENUTO UNO"),
            "una voce del vicinato e' entrata senza la ragione operativa"
        );
        assert!(
            text.contains("non è stato composto"),
            "il documento non dice perche' il vicinato manca"
        );
        assert!(
            text.contains("NON significa che il gruppo non sia collegato a nulla"),
            "l'assenza si traveste da assenza di collegamenti"
        );
    }

    /// **I tagli della cronologia e della legenda si dichiarano.**
    #[test]
    fn i_tagli_della_cronologia_e_della_legenda_si_dichiarano() {
        let report = allegato_con_cronologia(Some(cronologia(7)), Some(vicinato(4)), true);
        let text = report.text();

        assert!(
            text.contains("altre 7 righe"),
            "il taglio della cronologia non dice quante righe restano fuori"
        );
        assert!(
            text.contains("altre 4 voci"),
            "il taglio della legenda non dice quante voci restano fuori"
        );
    }

    /// Un soggetto di prova, con un'identità osservata in questo monitoraggio.
    fn soggetto(label: &str, valutato: bool) -> LedgerSubject {
        LedgerSubject {
            label: String::from(label),
            dossier_sentence: String::from(
                "Soggetto aperto da operatore.anna il 2026-09-01. Un fascicolo aperto non è \
                 una valutazione: dice che qualcuno ha deciso di raccogliere, e perché.",
            ),
            dossier_reason: String::from("segnalazione del 1 settembre"),
            open: true,
            assessment_label: String::from(if valutato {
                "DA APPROFONDIRE"
            } else {
                "NON VALUTATO"
            }),
            assessment_sentence: String::from(if valutato {
                "DA APPROFONDIRE — valutato da operatore.anna il 2026-09-02. È il giudizio di \
                 una persona, non un calcolo del programma."
            } else {
                "NON VALUTATO. Nessuno ha espresso un giudizio, e questo non significa né che \
                 la persona sia estranea né che sia di interesse: significa che nessuno si è \
                 espresso."
            }),
            assessment_reason: valutato.then(|| String::from("ricorre in tre monitoraggi")),
            identities: vec![LedgerSubjectIdentity {
                identifier: String::from("@tale"),
                linked_by: String::from("operatore.anna"),
                linked_at: Timestamp::from_millis(1_752_000_500_000),
                link_reason: String::from("stesso numero dichiarato in atti"),
                link_basis: String::from("Base: un'identità osservata nei monitoraggi."),
                contents_here: 4,
                alerts_here: 1,
                distinct_sources_here: 2,
                first_seen_here: Some(Timestamp::from_millis(1_752_000_100_000)),
                last_seen_here: Some(Timestamp::from_millis(1_752_000_900_000)),
            }],
            identities_beyond: 0,
        }
    }

    /// Allegato con i soggetti indicati, e il cancello nello stato indicato.
    fn allegato_con_soggetti(soggetti: &[LedgerSubject], ragione: bool) -> NarrativeReport {
        let report_id = ReportId::from_sequence(2026, 1);
        let profile = ReportTemplateProfile::default();
        let operator = Actor::try_new("operatore").expect("attore valido");
        let session = sessione();
        compose(&AnnexInput {
            report_id: &report_id,
            profile: &profile,
            operator: &operator,
            generated_at: Timestamp::from_millis(1_752_086_400_000),
            session: &session,
            sources: &[],
            contents: &[],
            alerts: &[],
            faults: &[],
            cyber_events: &[],
            subjects: soggetti,
            taxonomy: &[],
            taxonomy_beyond: 0,
            official_sources: &[],
            notes: &[],
            notes_beyond: 0,
            workspaces: &[],
            workspaces_beyond: 0,
            investigative_basis: ragione,
            coverage: &[],
            configuration: &crate::analysis_configuration::AnalysisConfiguration::unknown(),
        })
    }

    /// **La sezione dichiara che nessuno è stato trovato dal programma, PRIMA di
    /// nominare qualcuno.**
    ///
    /// # Il difetto che questa prova impedisce
    ///
    /// Dentro il programma si vede che un fascicolo è nato da una decisione: c'è
    /// la schermata, la storia degli atti, il motivo accanto a ogni gesto. **Su
    /// carta non si vede niente di tutto questo**, e un elenco di nomi con sotto
    /// dei numeri si legge come un profilo — cioè come la cosa che il
    /// congelamento vieta (ADR-0105, R-13).
    #[test]
    fn la_sezione_dei_soggetti_dichiara_prima_di_nominare() {
        let report = allegato_con_soggetti(&[soggetto("PERSONA UNO", false)], true);
        let text = report.text();

        let Some(posizione_dichiarazione) = text.find("NEXUM/97 non crea profili") else {
            panic!("la dichiarazione deve esserci");
        };
        let Some(posizione_nome) = text.find("PERSONA UNO") else {
            panic!("il soggetto deve esserci");
        };
        assert!(
            posizione_dichiarazione < posizione_nome,
            "un nome compare prima della dichiarazione che spiega perche' e' li'"
        );
        assert!(
            text.contains("non attribuisce alcun punteggio a una persona"),
            "la dichiarazione non esclude il punteggio"
        );
        assert!(
            text.contains("soltanto ciò che QUESTO monitoraggio ha osservato"),
            "la dichiarazione non dice che il fascicolo contiene altro"
        );
    }

    /// **Senza la ragione operativa nessun nome entra nel documento.**
    ///
    /// # Perche' la prova passa dei soggetti al composer
    ///
    /// Perche' il cancello non deve stare solo dove i soggetti si leggono: se un
    /// giorno un percorso nuovo componesse un allegato con un elenco gia' in
    /// mano, il documento non deve stamparlo. La difesa vale dove il documento
    /// si scrive, non solo dove i dati si raccolgono (ADR-0105, decisione 5).
    #[test]
    fn senza_ragione_operativa_nessun_nome_entra_nel_documento() {
        let report = allegato_con_soggetti(&[soggetto("PERSONA UNO", true)], false);
        let text = report.text();

        assert!(
            !text.contains("PERSONA UNO"),
            "un nome e' entrato in un documento senza la ragione operativa"
        );
        assert!(
            text.contains("la ragione operativa che ne autorizza la compilazione non risulta"),
            "il documento non dice perche' l'elenco manca"
        );
        // L'assenza non si traveste da assenza di interesse: sarebbe
        // un'affermazione che nessuno ha fatto.
        assert!(
            text.contains("NON significa che nessuna persona sia di interesse"),
            "una sezione vuota si leggerebbe come «nessuna persona di interesse»"
        );
    }

    /// **NON VALUTATO si scrive, invece di essere omesso.**
    ///
    /// Un fascicolo senza la riga della valutazione si leggerebbe come un
    /// fascicolo senza interesse, e nessuno lo ha detto.
    #[test]
    fn non_valutato_si_scrive_invece_di_essere_omesso() {
        let report = allegato_con_soggetti(&[soggetto("PERSONA UNO", false)], true);
        let text = report.text();

        assert!(text.contains("La valutazione dell'ufficio."));
        assert!(text.contains("NON VALUTATO"));
        assert!(
            text.contains("Nessuno ha espresso un giudizio"),
            "la frase non dice che l'assenza di giudizio non e' un giudizio"
        );
    }

    /// **La valutazione e i fatti osservati non stanno nella stessa riga.**
    ///
    /// # Il difetto che questa prova impedisce
    ///
    /// Il congelamento chiede che i segnali osservati stiano **accanto** alla
    /// valutazione, mai al posto suo. Scritti nella stessa riga, i numeri
    /// diventerebbero la giustificazione del giudizio — e il giudizio, letto
    /// accanto ai numeri, diventerebbe la loro conclusione (ADR-0105,
    /// decisione 4).
    #[test]
    fn la_valutazione_non_sta_nella_riga_dei_fatti_osservati() {
        let report = allegato_con_soggetti(&[soggetto("PERSONA UNO", true)], true);

        let Some(blocco_valutazione) = report
            .blocks
            .iter()
            .find(|block| block.text().contains("DA APPROFONDIRE"))
        else {
            panic!("il blocco della valutazione deve esserci");
        };
        assert!(
            !blocco_valutazione.text().contains("contenuti, di cui"),
            "i fatti osservati stanno nella riga della valutazione"
        );
        assert!(
            blocco_valutazione
                .text()
                .contains("non un calcolo del programma"),
            "la valutazione non si dichiara giudizio di una persona"
        );

        let Some(blocco_osservato) = report
            .blocks
            .iter()
            .find(|block| block.text().contains("contenuti, di cui"))
        else {
            panic!("il blocco dei fatti osservati deve esserci");
        };
        assert!(
            !blocco_osservato.text().contains("DA APPROFONDIRE"),
            "la valutazione compare nella riga dei fatti osservati"
        );
    }

    /// **Nessuna parola di misura compare nella sezione dei soggetti.**
    ///
    /// # Perche' una guardia sul testo composto
    ///
    /// Perche' il divieto del congelamento — «mai una percentuale di
    /// pericolosita'» — non riguarda un campo: riguarda cio' che una persona
    /// legge. Un tipo senza campi numerici non impedisce a una frase di
    /// contenere «indice di rischio», e sulla carta la frase e' tutto cio' che
    /// resta.
    #[test]
    fn nessuna_parola_di_misura_compare_nella_sezione_dei_soggetti() {
        let report = allegato_con_soggetti(&[soggetto("PERSONA UNO", true)], true);
        let text = report.text();

        // SI LEGGE DOPO LA DICHIARAZIONE, non prima.
        //
        // La dichiarazione dice «non attribuisce alcun punteggio a una
        // persona»: una frase che spiega un divieto deve poterlo nominare, ed e'
        // la stessa ragione per cui la guardia del Cyber Watch condiviso non
        // sorveglia i commenti che spiegano le parole vietate.
        let Some((_, dopo_il_titolo)) = text.split_once("6. I SOGGETTI") else {
            panic!("la sezione dei soggetti deve esserci");
        };
        let Some((_, sezione)) = dopo_il_titolo.split_once(CHE_COSA_E_UN_SOGGETTO) else {
            panic!("la dichiarazione deve precedere i soggetti");
        };

        for vietata in [
            "punteggio",
            "rischio",
            "pericolosità",
            "probabilità",
            "percentuale",
            "indice",
            "score",
        ] {
            assert!(
                !sezione.to_lowercase().contains(vietata),
                "la sezione dei soggetti contiene «{vietata}»: una misura accanto a un nome \
                 diventa un profilo"
            );
        }
    }

    /// Allegato con i gruppi di segnali indicati.
    fn allegato_con_gruppi(eventi: &[LedgerCyberEvent]) -> NarrativeReport {
        let report_id = ReportId::from_sequence(2026, 1);
        let profile = ReportTemplateProfile::default();
        let operator = Actor::try_new("operatore").expect("attore valido");
        let session = sessione();
        compose(&AnnexInput {
            report_id: &report_id,
            profile: &profile,
            operator: &operator,
            generated_at: Timestamp::from_millis(1_752_086_400_000),
            session: &session,
            sources: &[],
            contents: &[],
            alerts: &[],
            faults: &[],
            cyber_events: eventi,
            subjects: &[],
            taxonomy: &[],
            taxonomy_beyond: 0,
            official_sources: &[],
            notes: &[],
            notes_beyond: 0,
            workspaces: &[],
            workspaces_beyond: 0,
            investigative_basis: true,
            coverage: &[],
            configuration: &crate::analysis_configuration::AnalysisConfiguration::unknown(),
        })
    }

    /// **La sezione dichiara che cosa un gruppo è, PRIMA di elencarne uno.**
    ///
    /// Un fascicolo si legge anche a distanza di mesi, da chi non ha mai visto
    /// il programma. Una dichiarazione dopo l'elenco arriva quando
    /// l'impressione si è già formata, ed è lo stesso motivo per cui la
    /// schermata Cyber Watch la porta in cima.
    #[test]
    fn la_sezione_dichiara_che_cosa_e_un_gruppo_prima_di_elencarne_uno() {
        let report = allegato_con_gruppi(&[gruppo("CVE-2026-1", 4, 3)]);
        let scritto = testo(&report);

        let Some(dichiarazione) = scritto.find("non costituisce accertamento") else {
            panic!("l'allegato deve dichiarare che un gruppo non e' un accertamento");
        };
        let Some(primo_gruppo) = scritto.find("CVE-2026-1") else {
            panic!("il gruppo deve comparire");
        };

        assert!(
            dichiarazione < primo_gruppo,
            "la dichiarazione arriva DOPO il primo gruppo: chi legge si e' gia' \
             fatto un'idea di cio' che sta leggendo"
        );
    }

    /// **L'allegato non attribuisce, e non chiama indipendenti le fonti.**
    ///
    /// In un atto la differenza fra «distinte» e «indipendenti» è la più
    /// importante che ci sia: contarle come corroborazione trasformerebbe un
    /// rilancio in una conferma.
    #[test]
    fn l_allegato_non_attribuisce_e_non_dichiara_fonti_indipendenti() {
        let report = allegato_con_gruppi(&[gruppo("CVE-2026-2", 6, 4)]);
        let scritto = testo(&report).to_lowercase();

        for vietata in [
            "fonti indipendenti",
            "attacco confermato",
            "incidente confermato",
            "attribuito a",
            "responsabile dell'attacco",
            "gruppo di attaccanti",
        ] {
            assert!(
                !scritto.contains(vietata),
                "l'allegato contiene «{vietata}»: un gruppo e' una correlazione, \
                 non un accertamento, e il prodotto non attribuisce"
            );
        }

        assert!(
            scritto.contains("fonti distinte"),
            "le fonti si contano come DISTINTE, e l'allegato lo scrive"
        );
        assert!(
            scritto.contains("non misura l'indipendenza"),
            "e dichiara che cosa quel numero NON misura"
        );
    }

    /// **Senza gruppi la sezione c'è lo stesso, e dice perché è vuota.**
    ///
    /// Una sezione assente in un fascicolo si legge come «non è stato cercato».
    /// E la frase non dice che non sia successo nulla: dice che cosa la
    /// correlazione ha trovato nei contenuti acquisiti.
    #[test]
    fn senza_gruppi_la_sezione_resta_e_dichiara_il_proprio_limite() {
        let report = allegato_con_gruppi(&[]);
        let scritto = testo(&report);

        assert!(
            scritto.contains("5. I GRUPPI DI SEGNALI TECNICI"),
            "la sezione deve esserci anche vuota"
        );
        assert!(
            scritto.contains("non si è formato alcun gruppo"),
            "e deve dire che cosa non e' stato trovato"
        );
        assert!(
            scritto.contains("non costituisce attestazione che nulla di rilevante sia accaduto"),
            "senza questa frase, «nessun gruppo» si legge come «nessun problema»"
        );
    }

    /// **La rilevanza per l'Italia non diventa un giudizio di gravità.**
    #[test]
    fn la_rilevanza_italiana_non_si_presenta_come_gravita() {
        let report = allegato_con_gruppi(&[gruppo("CVE-2026-3", 3, 2)]);
        let scritto = testo(&report);

        assert!(
            scritto.contains("non è un giudizio di gravità"),
            "l'allegato deve tenere separate le due cose (ADR-0035 Decisione 10)"
        );
    }

    /// **Lo stesso allegato, generato due volte, è identico.**
    ///
    /// La sezione dei gruppi non introduce nulla di variabile: nessun orario
    /// letto dall'orologio, nessun ordine dipendente da una tabella hash.
    #[test]
    fn la_sezione_dei_gruppi_e_deterministica() {
        let eventi = [gruppo("CVE-2026-4", 5, 3), gruppo("CVE-2026-5", 2, 2)];
        let primo = testo(&allegato_con_gruppi(&eventi));
        let secondo = testo(&allegato_con_gruppi(&eventi));

        assert_eq!(
            primo, secondo,
            "due generazioni dagli stessi fatti devono dire la stessa cosa"
        );
    }

    /// **Il testo di un indicatore finisce nel documento COM'È.**
    ///
    /// Un indicatore viene da un contenuto remoto, e va trattato come ostile.
    /// Nell'allegato — che è prosa — non c'è una formula da neutralizzare:
    /// quella è una questione del registro `.xlsx`, dove una cella che comincia
    /// con `=` diventa un calcolo. Qui il criterio è l'opposto: il testo non
    /// deve essere **alterato**, perché un allegato che ripulisce ciò che
    /// riporta smette di riportarlo.
    #[test]
    fn un_indicatore_ostile_finisce_nel_documento_senza_essere_alterato() {
        let mut ostile = gruppo("=1+1", 2, 2);
        ostile.indicator_value = String::from("=SOMMA(A1:A9)");
        ostile.indicators = vec![String::from("dominio: =cmd|'/c calc'!A1")];

        let scritto = testo(&allegato_con_gruppi(&[ostile]));
        assert!(
            scritto.contains("=cmd|'/c calc'!A1"),
            "l'allegato riporta cio' che ha trovato, senza ripulirlo: «{scritto}»"
        );
    }
}
