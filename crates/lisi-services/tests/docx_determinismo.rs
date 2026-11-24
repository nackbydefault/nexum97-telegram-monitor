//! Prove sul documento `.docx` realmente prodotto.
//!
//! Coprono il criterio 2 (nessun contenuto attivo) e il criterio 30
//! (generazione deterministica) della Milestone 18, e sono la prova 4 e la
//! prova 6 di ADR-0032.
//!
//! # Perche' l'archivio si apre davvero invece di cercare stringhe nei byte
//!
//! Un `.docx` e' uno ZIP, e uno ZIP **comprime**: cercare `vbaProject` nei byte
//! grezzi del file darebbe verde anche a un documento che lo contiene, perche'
//! la stringa non c'e' in chiaro. Sarebbe un test che non puo' fallire, cioe'
//! il genere peggiore. Qui l'archivio si apre voce per voce.

use std::io::Cursor;

use lisi_core::digest::Sha256Digest;
use lisi_core::model::ReviewState;
use lisi_core::model::analysis::AnalysisLevel;
use lisi_core::model::report::{ReportContentSnapshot, ReportId, ReportSnapshot};
use lisi_core::model::report_template::{ReportTemplateProfile, TemplateEmblem, TemplateField};
use lisi_core::text::Actor;
use lisi_core::{ContentId, SessionId, Timestamp};
use lisi_services::analysis_configuration::AnalysisConfiguration;
use lisi_services::report_docx::render;
use lisi_services::report_narrative::{
    NarrativeFinding, NarrativeInput, NarrativeSession, NarrativeSource, compose,
};

/// Compone e scrive una relazione con selezione, fonti e anomalie.
fn relazione() -> Vec<u8> {
    let identifier = ReportId::from_sequence(2026, 42);
    let operator = Actor::try_new("operatore").expect("attore valido");
    let profile = ReportTemplateProfile {
        version: 2,
        organisation: Some(TemplateField::try_new("Ente di prova").expect("valido")),
        office: Some(TemplateField::try_new("Ufficio di prova").expect("valido")),
        recipient: Some(TemplateField::try_new("Al Destinatario di prova").expect("valido")),
        place: Some(TemplateField::try_new("Roma").expect("valido")),
        signer_role: Some(TemplateField::try_new("Qualifica di prova").expect("valido")),
        signer_name: Some(TemplateField::try_new("Nome DI PROVA").expect("valido")),
        footer_line: Some(TemplateField::try_new("documento interno").expect("valido")),
        ..ReportTemplateProfile::default()
    };
    let snapshot = ReportSnapshot {
        taken_at: Timestamp::from_millis(1_700_000_000_000),
        session_id: SessionId::new(1),
        source_ids: Vec::new(),
        dictionary_version_ids: Vec::new(),
        template_version: 2,
        contents: vec![
            ReportContentSnapshot {
                content_id: ContentId::new(1),
                level: AnalysisLevel::try_new(3).expect("livello valido"),
                review_state: Some(ReviewState::Relevant),
                body_sha256: Sha256Digest::of_text("primo"),
                selected: true,
            },
            ReportContentSnapshot {
                content_id: ContentId::new(2),
                level: AnalysisLevel::try_new(0).expect("livello valido"),
                review_state: None,
                body_sha256: Sha256Digest::of_text("secondo"),
                selected: false,
            },
        ],
    };
    let session = NarrativeSession {
        label: String::from("Sessione di prova"),
        started_at: Timestamp::from_millis(1_700_000_000_000),
        ended_at: Some(Timestamp::from_millis(1_700_007_200_000)),
        account: None,
        profile_observations: Vec::new(),
    };
    let sources = [NarrativeSource {
        label: String::from("Canale di prova"),
        acquired: 2,
        reliability: None,
    }];
    let findings = [NarrativeFinding {
        content_id: ContentId::new(1),
        source_label: String::from("Canale di prova"),
        published_at: Timestamp::from_millis(1_700_000_500_000),
        acquired_at: Timestamp::from_millis(1_700_000_560_000),
        recovered: false,
        url: None,
        asked_link: None,
        attachment: None,
        body: String::from("testo conservato del primo contenuto"),
        level: AnalysisLevel::try_new(3).expect("livello valido"),
        engine_reason: Some(String::from("termine di dizionario")),
        review_state: Some(ReviewState::Relevant),
        review_note: None,
        after_acquisition: None,
        revisions: Vec::new(),
        revisions_beyond: 0,
        contexts: Vec::new(),
        contexts_beyond: 0,
        acquisition_mode: String::from("Acquisito dal vivo."),
    }];
    let faults = [String::from("Una fonte non ha risposto per due minuti.")];

    let report = compose(&NarrativeInput {
        report_id: &identifier,
        profile: &profile,
        snapshot: &snapshot,
        operator: &operator,
        generated_at: Timestamp::from_millis(1_700_010_000_000),
        session: &session,
        sources: &sources,
        findings: &findings,
        coverage: &[],
        faults: &faults,
        configuration: &AnalysisConfiguration::unknown(),
    });

    render(&report).expect("la relazione deve potersi scrivere")
}

/// Restituisce nome e contenuto di ogni voce dell'archivio.
///
/// Le parti di un OOXML sono XML, con **una** eccezione legittima: le immagini
/// sotto `word/media/`, che sono binarie per costruzione. Quelle si leggono in
/// modo tollerante; ogni altra parte deve essere testo, e se non lo fosse il
/// fatto sarebbe di per se' interessante e va visto.
fn voci(bytes: &[u8]) -> Vec<(String, String)> {
    let mut archive =
        zip::ZipArchive::new(Cursor::new(bytes.to_vec())).expect("il file e' uno ZIP");
    let mut collected = Vec::new();
    for index in 0..archive.len() {
        let mut entry = archive.by_index(index).expect("voce leggibile");
        let name = entry
            .name()
            .expect("nome della voce leggibile")
            .into_owned();
        let mut raw = Vec::new();
        std::io::Read::read_to_end(&mut entry, &mut raw).expect("voce leggibile");

        let content = if name.starts_with("word/media/") {
            String::from_utf8_lossy(&raw).into_owned()
        } else {
            String::from_utf8(raw)
                .unwrap_or_else(|error| panic!("la voce «{name}» non e' testo: {error}"))
        };
        collected.push((name, content));
    }
    collected
}

#[test]
fn the_archive_can_actually_be_opened_and_read() {
    // Prova che le prove che seguono non siano vuote: se questo non trovasse
    // il testo della relazione dentro l'archivio, tutte le ricerche di stringhe
    // vietate sarebbero verdi per la ragione sbagliata.
    let bytes = relazione();
    let voci = voci(&bytes);

    assert!(!voci.is_empty(), "l'archivio non contiene alcuna voce");
    let tutto: String = voci.iter().map(|(_, content)| content.as_str()).collect();
    assert!(
        tutto.contains("testo conservato del primo contenuto"),
        "il testo della relazione non si ritrova nell'archivio: la prova sarebbe cieca"
    );
}

#[test]
fn the_document_carries_no_active_content() {
    // Criterio 2: niente macro, niente OLE, niente template remoti, nessuna
    // relazione esterna.
    let bytes = relazione();
    let voci = voci(&bytes);

    for (name, _) in &voci {
        for vietato in ["vbaProject", "oleObject", "embeddings/", "activeX"] {
            assert!(
                !name.contains(vietato),
                "l'archivio contiene la voce vietata «{name}»"
            );
        }
    }

    let tutto: String = voci.iter().map(|(_, content)| content.as_str()).collect();
    for vietato in [
        "TargetMode=\"External\"",
        "attachedTemplate",
        "vbaProject",
        "oleObject",
        "http://schemas.openxmlformats.org/officeDocument/2006/relationships/attachedTemplate",
    ] {
        assert!(
            !tutto.contains(vietato),
            "il documento contiene «{vietato}», che ADR-0031 Decisione 7 vieta"
        );
    }
}

// ------------------------------------------- impostazione documentale MP-18C-R
//
// Le prove che seguono nascono dal confronto con un modello di riferimento,
// documentato nell'archivio del progetto. Guardano il documento
// **prodotto**, non le costanti del sorgente: una costante giusta e un
// documento sbagliato sono lo scenario che questi test esistono per escludere.

/// Il testo di una voce dell'archivio.
fn voce(bytes: &[u8], nome: &str) -> String {
    voci(bytes)
        .into_iter()
        .find(|(name, _)| name == nome)
        .map(|(_, content)| content)
        .unwrap_or_else(|| panic!("il documento deve contenere «{nome}»"))
}

/// L'intestazione di **prima pagina**, risolta come la risolve Word.
///
/// # Perche' non «la prima parte che si chiama `word/header…`»
///
/// Le intestazioni nel pacchetto sono piu' d'una, e il numero nel nome non dice
/// a che cosa servono: quale sia quella di prima pagina lo stabilisce
/// `document.xml`, che la richiama per identificativo, e `document.xml.rels`,
/// che traduce l'identificativo in un percorso. Seguire quella catena invece di
/// indovinare dal nome significa che questa funzione verifica **anche** il
/// collegamento: se un giorno il documento puntasse alla parte sbagliata, le
/// prove che la usano diventerebbero rosse invece di continuare a leggere per
/// caso il file giusto.
fn intestazione_di_prima_pagina(bytes: &[u8]) -> String {
    let document = voce(bytes, "word/document.xml");
    let marker = "w:type=\"first\" r:id=\"";
    let at = document
        .find(marker)
        .or_else(|| document.find("<w:headerReference"))
        .unwrap_or_else(|| panic!("il documento non richiama alcuna intestazione di prima pagina"));
    let rest = &document[at + marker.len()..];
    let id = &rest[..rest
        .find('"')
        .expect("l'identificativo dell'intestazione deve chiudersi")];

    let rels = voce(bytes, "word/_rels/document.xml.rels");
    let marker = format!("Id=\"{id}\"");
    let at = rels
        .find(&marker)
        .unwrap_or_else(|| panic!("«{id}» non e' dichiarato fra le relazioni del documento"));
    let rest = &rels[at..];
    let marker = "Target=\"";
    let at = rest
        .find(marker)
        .expect("la relazione dell'intestazione deve avere un percorso");
    let rest = &rest[at + marker.len()..];
    let target = &rest[..rest.find('"').expect("il percorso deve chiudersi")];

    voce(bytes, &format!("word/{target}"))
}

#[test]
fn the_page_is_a4_with_the_declared_margins() {
    // A4 e i margini erano identici ai predefiniti della libreria, quindi il
    // documento era A4 **per caso**. Ora sono dichiarati, e questo test lo
    // verifica sul file prodotto.
    let document = voce(&relazione(), "word/document.xml");

    assert!(
        document.contains(r#"<w:pgSz w:w="11906" w:h="16838" />"#),
        "la pagina non e' A4"
    );
    assert!(
        document.contains(
            r#"<w:pgMar w:top="1985" w:right="1701" w:bottom="1701" w:left="1701" w:header="851" w:footer="992" w:gutter="0" />"#
        ),
        "i margini non sono quelli dichiarati"
    );
}

#[test]
fn the_body_is_times_new_roman_twelve_points() {
    // Criterio del facsimile numero 5 e 6: il carattere e' Times New Roman e il
    // corpo e' 12 pt (24 mezzi punti). Si verifica **sia** nello stile
    // predefinito **sia** sui frammenti, perche' basta che uno dei due manchi
    // perche' un paragrafo esca in un carattere diverso dagli altri.
    let bytes = relazione();
    let styles = voce(&bytes, "word/styles.xml");
    let document = voce(&bytes, "word/document.xml");

    assert!(
        styles.contains(r#"w:ascii="Times New Roman""#),
        "lo stile predefinito non dichiara il carattere del corpo"
    );
    assert!(
        styles.contains(r#"<w:sz w:val="24" />"#),
        "lo stile predefinito non dichiara il corpo a 12 pt"
    );
    assert!(
        document.contains(r#"w:ascii="Times New Roman""#),
        "i frammenti non dichiarano il carattere"
    );
    assert!(
        !document.contains("Calibri") && !document.contains("Cambria"),
        "nel documento compare un carattere che non e' quello stabilito"
    );
}

#[test]
fn the_body_is_justified_and_breathes() {
    // Il difetto principale trovato dal confronto: meta' del documento non era
    // giustificata, e nessun paragrafo aveva spazio dopo di se'.
    let document = voce(&relazione(), "word/document.xml");

    assert!(
        document.contains(r#"<w:jc w:val="both" />"#),
        "il corpo non e' giustificato"
    );
    assert!(
        document.contains(r#"w:after="200""#) && document.contains(r#"w:line="276""#),
        "il corpo non ha ne' spaziatura ne' interlinea"
    );
}

#[test]
fn the_justification_uses_the_only_value_that_ooxml_defines() {
    // `justified` non appartiene all'enumerazione `ST_Jc`; `both` si', ed e'
    // quello che Word scrive. Il generatore usava il primo da MP-18C: nessun
    // test poteva accorgersene, perche' il file si scrive e l'archivio si apre
    // lo stesso. Se ne accorge Word, e proprio nella voce del pilot che nessuno
    // aveva ancora eseguito.
    let document = voce(&relazione(), "word/document.xml");

    assert!(
        !document.contains(r#"w:val="justified""#),
        "il documento usa un valore di allineamento che OOXML non definisce"
    );
}

#[test]
fn the_subject_and_the_dates_carry_a_bold_lead() {
    // L'attacco in grassetto seguito dal testo in tondo, **nello stesso
    // paragrafo**: e' la forma che il facsimile usa per l'oggetto e per ogni
    // voce cronologica, ed e' il motivo per cui esiste `Block::Lead`.
    let document = voce(&relazione(), "word/document.xml");

    for atteso in ["OGGETTO: ", "In data "] {
        let posizione = document
            .find(atteso)
            .unwrap_or_else(|| panic!("«{atteso}» non compare nel documento"));
        // Il frammento che porta l'attacco deve essere in grassetto: si guarda
        // indietro dalla posizione del testo fino all'inizio del frammento.
        let inizio = document[..posizione]
            .rfind("<w:r>")
            .expect("ogni testo sta dentro un frammento");
        assert!(
            document[inizio..posizione].contains("<w:b />"),
            "l'attacco «{atteso}» non e' in grassetto"
        );
    }
}

#[test]
fn a_section_title_stays_with_its_text() {
    // Senza `keepNext` un salto di pagina puo' lasciare «Risultanze» solo in
    // fondo a un foglio e il suo contenuto sul successivo. Si vede solo
    // stampando, quindi la guardia sta qui.
    let document = voce(&relazione(), "word/document.xml");

    assert!(
        document.contains("<w:keepNext />"),
        "i titoli di sezione non restano attaccati al proprio testo"
    );
}

#[test]
fn the_document_has_a_footer_with_page_numbers() {
    // ADR-0031 Decisione 4 la prescrive, e MP-18G l'aveva trovata assente.
    let bytes = relazione();
    let footer = voce(&bytes, "word/footer1.xml");

    assert!(
        footer.contains("PAGE") && footer.contains("NUMPAGES"),
        "il piede non porta la numerazione delle pagine"
    );
    assert!(
        footer.contains("documento interno"),
        "la riga di pie' configurata non compare nel piede"
    );

    let document = voce(&bytes, "word/document.xml");
    assert!(
        document.contains("footerReference"),
        "la sezione non fa riferimento ad alcun piede"
    );
}

#[test]
fn the_letterhead_and_the_signature_are_where_a_relazione_puts_them() {
    let bytes = relazione();
    let document = voce(&bytes, "word/document.xml");

    // La carta intestata sta nell'INTESTAZIONE DI PAGINA vera, centrata: e' li'
    // che un ufficio va a cercarla quando apre il file per adattarlo. Con
    // `titlePg` compare sulla sola prima pagina, come nel facsimile.
    let header = intestazione_di_prima_pagina(&bytes);
    assert!(header.contains("Ente di prova"));
    assert!(header.contains(r#"<w:jc w:val="center" />"#));
    assert!(
        !document.contains("Ente di prova"),
        "la carta intestata non deve essere anche nel corpo"
    );

    // Qualifica e nome in calce, allineati a destra.
    assert!(document.contains("Qualifica di prova"));
    assert!(document.contains("Nome DI PROVA"));
    assert!(document.contains(r#"<w:jc w:val="right" />"#));
}

#[test]
fn the_document_declares_no_external_relationship() {
    // Gli URL restano **testo**: un hyperlink e' una relazione esterna, ed e'
    // esattamente cio' che la guardia del criterio 2 tiene a zero. Il facsimile
    // non ne ha alcuno, quindi la riconciliazione non ne chiede.
    let bytes = relazione();
    for (name, content) in voci(&bytes) {
        if name.ends_with(".rels") {
            assert!(
                !content.contains("TargetMode=\"External\""),
                "«{name}» dichiara una relazione esterna"
            );
        }
    }
}

// La prova che segue cerca stringhe di un modello che appartengono a
// un'attività specifica: sta soltanto nell'archivio (ADR-0210).

#[test]
fn the_emblem_has_a_fixed_name_and_a_fixed_relationship() {
    // Con `docx-rs` l'identificativo dell'immagine veniva da un contatore
    // globale del processo e andava sovrascritto (ADR-0032). Il generatore di
    // ADR-0180 li scrive costanti: questa prova tiene fermi il nome del media
    // e la relazione, da cui dipende il determinismo con lo stemma.
    let bytes = relazione_con_stemma();
    assert!(
        voci(&bytes)
            .iter()
            .any(|(name, _)| name == "word/media/emblem.png"),
        "lo stemma non ha il nome fisso"
    );
    let rels = voce(&bytes, "word/_rels/header2.xml.rels");
    assert!(
        rels.contains(r#"Id="Emblem""#) && rels.contains(r#"Target="media/emblem.png""#),
        "la relazione dello stemma non e' quella fissa: {rels}"
    );

    // Senza stemma non restano ne' l'immagine ne' la sua relazione.
    let senza = voci(&relazione());
    assert!(
        !senza
            .iter()
            .any(|(name, _)| name.starts_with("word/media/")
                || name == "word/_rels/header2.xml.rels"),
        "senza stemma il pacchetto porta ancora un'immagine"
    );
}

/// Controlla che ogni marcatore aperto si chiuda, nell'ordine, e che ogni `&`
/// apra una delle cinque entita' di XML.
///
/// Non e' un validatore: e' la prova minima che il generatore, scrivendo
/// testo, non abbia lasciato una parte che nessun lettore XML aprirebbe.
fn bilanciato(xml: &str) -> Result<(), String> {
    let mut aperti: Vec<&str> = Vec::new();
    let mut resto = xml;
    while let Some(inizio) = resto.find('<') {
        let testo = &resto[..inizio];
        for (at, _) in testo.match_indices('&') {
            let entita = &testo[at..];
            if !["&amp;", "&lt;", "&gt;", "&quot;", "&apos;"]
                .iter()
                .any(|nota| entita.starts_with(nota))
            {
                return Err(format!("una «&» non apre un'entita': {entita}"));
            }
        }
        let dopo = &resto[inizio + 1..];
        let fine = dopo
            .find('>')
            .ok_or_else(|| String::from("un marcatore non si chiude"))?;
        let marcatore = &dopo[..fine];
        resto = &dopo[fine + 1..];
        if marcatore.starts_with('?') {
            continue;
        }
        if let Some(nome) = marcatore.strip_prefix('/') {
            match aperti.pop() {
                Some(atteso) if atteso == nome.trim() => {}
                altro => return Err(format!("</{nome}> chiude {altro:?}")),
            }
        } else if !marcatore.ends_with('/') {
            aperti.push(marcatore.split_whitespace().next().unwrap_or_default());
        }
    }
    if aperti.is_empty() {
        Ok(())
    } else {
        Err(format!("restano aperti {aperti:?}"))
    }
}

#[test]
fn every_xml_part_is_well_nested() {
    // Controllo negativo prima: una prova di buona forma che non sa
    // riconoscere un documento rotto non dimostra niente.
    assert!(bilanciato("<a><b></a></b>").is_err());
    assert!(bilanciato("<a><b /></a>").is_ok());
    assert!(bilanciato("<a>x & y</a>").is_err());
    assert!(bilanciato("<a>").is_err());

    for bytes in [relazione(), relazione_con_stemma()] {
        for (name, content) in voci(&bytes) {
            if name.starts_with("word/media/") {
                continue;
            }
            if let Err(difetto) = bilanciato(&content) {
                panic!("«{name}» non e' XML ben annidato: {difetto}");
            }
        }
    }
}

/// I valori di un attributo, in ordine, ovunque compaia in una parte.
fn valori(part: &str, attributo: &str) -> Vec<String> {
    let marker = format!("{attributo}=\"");
    part.match_indices(&marker)
        .filter_map(|(at, _)| {
            let rest = &part[at + marker.len()..];
            rest.find('"').map(|end| String::from(&rest[..end]))
        })
        .collect()
}

#[test]
fn every_part_has_a_content_type_and_every_reference_a_part() {
    // Word rifiuta un pacchetto in cui una parte non ha tipo, o in cui il
    // documento richiama un'intestazione che non c'e'. Nessuno dei due
    // difetti impedisce allo ZIP di aprirsi: per questo la prova li cerca.
    let bytes = relazione_con_stemma();
    let voci = voci(&bytes);
    let nomi: Vec<&str> = voci.iter().map(|(name, _)| name.as_str()).collect();
    let tipi = voce(&bytes, "[Content_Types].xml");

    for name in &nomi {
        if name.starts_with("word/") && name.ends_with(".xml") {
            assert!(
                tipi.contains(&format!("PartName=\"/{name}\"")),
                "«{name}» non ha un tipo di contenuto proprio"
            );
        }
        let estensione = name.rsplit_once('.').map_or("", |(_, ext)| ext);
        assert!(
            tipi.contains(&format!("PartName=\"/{name}\""))
                || tipi.contains(&format!("Extension=\"{estensione}\"")),
            "«{name}» non ha alcun tipo di contenuto"
        );
    }
    for parte in valori(&tipi, "PartName") {
        let parte = parte.trim_start_matches('/');
        assert!(
            nomi.contains(&parte),
            "il tipo di «{parte}» non ha la parte"
        );
    }
    for (rels, base) in [
        ("_rels/.rels", ""),
        ("word/_rels/document.xml.rels", "word/"),
        ("word/_rels/header2.xml.rels", "word/"),
    ] {
        for target in valori(&voce(&bytes, rels), "Target") {
            let parte = format!("{base}{target}");
            assert!(
                nomi.contains(&parte.as_str()),
                "«{rels}» richiama «{parte}», che non c'e'"
            );
        }
    }
}

/// Un PNG **vero e visualizzabile** delle dimensioni indicate.
///
/// # Perche' non basta un'intestazione
///
/// Il dominio valida i primi ventiquattro byte, quindi per le prove di
/// struttura basterebbero quelli. I due esemplari del pilot invece finiscono
/// **sotto gli occhi di una persona**, che deve poter dire se lo stemma
/// compaia, dove e di che dimensione: un PNG monco farebbe comparire in Word il
/// riquadro dell'immagine rotta, e la voce del pilot diventerebbe illeggibile.
///
/// L'immagine e' in scala di grigi, con una cornice e una diagonale: si vede
/// che e' un'immagine, e si vede se e' stata schiacciata. Il flusso zlib usa
/// **blocchi non compressi**, che sono legittimi e si scrivono senza
/// dipendenze.
fn png(width: u32, height: u32) -> Vec<u8> {
    let (w, h) = (width as usize, height as usize);

    // Righe grezze: un byte di filtro (0 = nessuno) e poi i pixel.
    let mut raw = Vec::with_capacity(h * (1 + w));
    for y in 0..h {
        raw.push(0);
        for x in 0..w {
            let bordo = x < 2 || y < 2 || x + 2 >= w || y + 2 >= h;
            let diagonale = w > 1 && h > 1 && (x * (h - 1)) / (w - 1).max(1) == y;
            raw.push(if bordo || diagonale { 0x20 } else { 0xE0 });
        }
    }

    let mut bytes = vec![0x89, b'P', b'N', b'G', 0x0d, 0x0a, 0x1a, 0x0a];

    let mut ihdr = Vec::new();
    ihdr.extend_from_slice(&width.to_be_bytes());
    ihdr.extend_from_slice(&height.to_be_bytes());
    // 8 bit per campione, scala di grigi, senza interlacciamento.
    ihdr.extend_from_slice(&[8, 0, 0, 0, 0]);
    push_chunk(&mut bytes, b"IHDR", &ihdr);
    push_chunk(&mut bytes, b"IDAT", &zlib_stored(&raw));
    push_chunk(&mut bytes, b"IEND", &[]);
    bytes
}

/// Un'immagine di prova **impossibile da confondere con un riquadro vuoto**.
///
/// # Perche' ce ne vuole una seconda
///
/// Quella di sopra ha il riempimento grigio chiaro e le linee spesse due pixel:
/// a un centimetro e mezzo di stampa diventa un quadrato pallido con un filo
/// attorno. Chi la guarda in Word vede la stessa cosa che vedrebbe se
/// l'immagine non si caricasse affatto, e i due casi non si distinguono.
///
/// Questa e' nera piena con una croce bianca larga: se compare, l'immagine e'
/// arrivata; se al suo posto resta un riquadro vuoto, non e' arrivata. Serve a
/// rendere la verifica su Word una risposta invece che un'impressione.
fn png_contrastato(width: u32, height: u32) -> Vec<u8> {
    let (w, h) = (width as usize, height as usize);
    let spessore = (w.min(h) / 6).max(1);

    let mut raw = Vec::with_capacity(h * (1 + w));
    for y in 0..h {
        raw.push(0);
        for x in 0..w {
            let croce = x.abs_diff(w / 2) < spessore || y.abs_diff(h / 2) < spessore;
            raw.push(if croce { 0xFF } else { 0x00 });
        }
    }

    let mut bytes = vec![0x89, b'P', b'N', b'G', 0x0d, 0x0a, 0x1a, 0x0a];
    let mut ihdr = Vec::new();
    ihdr.extend_from_slice(&width.to_be_bytes());
    ihdr.extend_from_slice(&height.to_be_bytes());
    ihdr.extend_from_slice(&[8, 0, 0, 0, 0]);
    push_chunk(&mut bytes, b"IHDR", &ihdr);
    push_chunk(&mut bytes, b"IDAT", &zlib_stored(&raw));
    push_chunk(&mut bytes, b"IEND", &[]);
    bytes
}

/// Aggiunge un blocco PNG con la propria lunghezza e il proprio CRC.
fn push_chunk(out: &mut Vec<u8>, kind: &[u8; 4], data: &[u8]) {
    out.extend_from_slice(&(data.len() as u32).to_be_bytes());
    out.extend_from_slice(kind);
    out.extend_from_slice(data);

    let mut crc_input = Vec::with_capacity(4 + data.len());
    crc_input.extend_from_slice(kind);
    crc_input.extend_from_slice(data);
    out.extend_from_slice(&crc32(&crc_input).to_be_bytes());
}

/// Un flusso zlib con blocchi **non compressi**, che il formato ammette.
fn zlib_stored(data: &[u8]) -> Vec<u8> {
    // 0x78 0x01: metodo deflate, finestra 32 KiB, e i bit di controllo che
    // rendono l'intestazione divisibile per 31, come zlib pretende.
    let mut out = vec![0x78, 0x01];
    let mut chunks = data.chunks(0xFFFF).peekable();
    while let Some(chunk) = chunks.next() {
        out.push(u8::from(chunks.peek().is_none()));
        let len = chunk.len() as u16;
        out.extend_from_slice(&len.to_le_bytes());
        out.extend_from_slice(&(!len).to_le_bytes());
        out.extend_from_slice(chunk);
    }
    out.extend_from_slice(&adler32(data).to_be_bytes());
    out
}

/// CRC-32 come lo definisce il PNG.
fn crc32(data: &[u8]) -> u32 {
    let mut crc = u32::MAX;
    for byte in data {
        crc ^= u32::from(*byte);
        for _ in 0..8 {
            crc = if crc & 1 == 1 {
                (crc >> 1) ^ 0xEDB8_8320
            } else {
                crc >> 1
            };
        }
    }
    !crc
}

/// Adler-32, la somma di controllo del flusso zlib.
fn adler32(data: &[u8]) -> u32 {
    let (mut a, mut b) = (1_u32, 0_u32);
    for byte in data {
        a = (a + u32::from(*byte)) % 65_521;
        b = (b + a) % 65_521;
    }
    (b << 16) | a
}

/// La stessa relazione, con uno stemma configurato.
fn relazione_con_stemma() -> Vec<u8> {
    let identifier = ReportId::from_sequence(2026, 42);
    let operator = Actor::try_new("operatore").expect("attore valido");
    let profile = ReportTemplateProfile {
        organisation: Some(TemplateField::try_new("Ente di prova").expect("valido")),
        emblem: TemplateEmblem::from_png(png(64, 72)).ok(),
        ..ReportTemplateProfile::default()
    };
    let snapshot = ReportSnapshot {
        taken_at: Timestamp::from_millis(1_700_000_000_000),
        session_id: SessionId::new(1),
        source_ids: Vec::new(),
        dictionary_version_ids: Vec::new(),
        template_version: 1,
        contents: Vec::new(),
    };
    let session = NarrativeSession {
        label: String::from("Sessione di prova"),
        started_at: Timestamp::from_millis(1_700_000_000_000),
        ended_at: Some(Timestamp::from_millis(1_700_007_200_000)),
        account: None,
        profile_observations: Vec::new(),
    };

    render(&compose(&NarrativeInput {
        report_id: &identifier,
        profile: &profile,
        snapshot: &snapshot,
        operator: &operator,
        generated_at: Timestamp::from_millis(1_700_010_000_000),
        session: &session,
        sources: &[],
        findings: &[],
        coverage: &[],
        faults: &[],
        configuration: &AnalysisConfiguration::unknown(),
    }))
    .expect("la relazione con stemma deve potersi scrivere")
}

#[test]
fn the_emblem_reaches_the_package_as_a_local_image() {
    let bytes = relazione_con_stemma();
    let voci = voci(&bytes);

    assert!(
        voci.iter().any(|(name, _)| name.starts_with("word/media/")),
        "lo stemma non e' finito nel pacchetto: {:?}",
        voci.iter().map(|(name, _)| name).collect::<Vec<_>>()
    );

    // Sta nell'intestazione di **prima pagina**, non nel corpo: si stampa una
    // volta e non si ripete su ogni foglio.
    let header = intestazione_di_prima_pagina(&bytes);
    assert!(
        header.contains("<w:drawing>"),
        "lo stemma non e' nell'intestazione"
    );
    assert!(header.contains("Ente di prova"));

    let document = voce(&bytes, "word/document.xml");
    assert!(
        document.contains("<w:titlePg />"),
        "senza titlePg la carta intestata si ripeterebbe su ogni pagina"
    );
    assert!(
        !document.contains("<w:drawing>"),
        "lo stemma non va nel corpo"
    );
}

/// Gli identificativi delle immagini richiamate da una parte dell'archivio.
///
/// In OOXML un'immagine non e' incorporata dove si vede: la parte che la mostra
/// dichiara `r:embed="qualcosa"`, e quel `qualcosa` e' un identificativo che il
/// file di relazioni della **stessa parte** deve tradurre in un percorso.
fn riferimenti_immagine(part: &str) -> Vec<String> {
    part.match_indices("r:embed=\"")
        .filter_map(|(at, marker)| {
            let rest = &part[at + marker.len()..];
            rest.find('"').map(|end| String::from(&rest[..end]))
        })
        .collect()
}

/// Il file di relazioni che accompagna una parte: `word/header1.xml` diventa
/// `word/_rels/header1.xml.rels`.
fn relazioni_di(part: &str) -> String {
    match part.rsplit_once('/') {
        Some((directory, file)) => format!("{directory}/_rels/{file}.rels"),
        None => format!("_rels/{part}.rels"),
    }
}

#[test]
fn every_picture_reference_resolves_to_a_declared_relationship() {
    // **La prova che lo stemma si veda davvero.**
    //
    // Le altre due si accontentano di trovare l'immagine nel pacchetto e il
    // disegno nell'intestazione: erano verdi mentre in Word non compariva
    // nulla. Un `.docx` puo' contenere l'immagine, contenere il disegno che la
    // richiama, ed essere ugualmente cieco — se l'identificativo che il disegno
    // usa non e' dichiarato nelle relazioni di quella parte, Word non ha modo
    // di sapere quale file aprire, e non mostra niente. Nessun avviso, nessun
    // errore: uno spazio vuoto.
    //
    // Qui l'invariante e' quella vera: **ogni riferimento si risolve**.
    let bytes = relazione_con_stemma();
    let voci = voci(&bytes);

    let mut verificati = 0_usize;
    for (name, content) in &voci {
        // Le relazioni non richiamano immagini: le dichiarano.
        if !name.ends_with(".xml") || name.contains("/_rels/") {
            continue;
        }

        for id in riferimenti_immagine(content) {
            let atteso = relazioni_di(name);
            let rels = voci
                .iter()
                .find(|(altro, _)| *altro == atteso)
                .map(|(_, content)| content.as_str())
                .unwrap_or_else(|| {
                    panic!("«{name}» richiama l'immagine «{id}» ma «{atteso}» non esiste")
                });

            assert!(
                rels.contains(&format!("Id=\"{id}\"")),
                "«{name}» richiama l'immagine «{id}», che «{atteso}» non dichiara: \
                 in Word l'immagine non compare. Le relazioni sono: {rels}"
            );
            verificati += 1;
        }
    }

    assert!(
        verificati > 0,
        "nessun riferimento a immagine trovato: la prova sarebbe cieca"
    );
}

#[test]
fn the_emblem_does_not_cost_the_determinism() {
    // **Il test che rende implementabile lo stemma.** Con `docx-rs`
    // l'identificativo dell'immagine veniva da un contatore globale del
    // processo; il generatore di ADR-0180 scrive costanti l'identificativo e
    // il nome del media. Due generazioni devono essere identiche **al byte**,
    // esattamente come senza stemma.
    let primo = relazione_con_stemma();
    std::thread::sleep(std::time::Duration::from_millis(2_100));
    let secondo = relazione_con_stemma();

    assert_eq!(
        Sha256Digest::of_bytes(&primo),
        Sha256Digest::of_bytes(&secondo),
        "due generazioni della stessa relazione con stemma hanno impronte diverse"
    );
}

#[test]
fn an_unconfigured_letterhead_leaves_blanks_to_fill_in_word() {
    // Il documento nasce per essere completato: dove l'ufficio non ha
    // configurato nulla, l'intestazione porta uno spazio che dice che cosa
    // scriverci, invece di non esserci affatto.
    let bytes = relazione();
    let header = intestazione_di_prima_pagina(&bytes);

    assert!(
        header.contains("Ente di prova"),
        "la riga configurata compare"
    );
    assert!(
        header.contains("[Sede, indirizzo e recapiti]"),
        "la riga non configurata deve restare uno spazio da compilare"
    );
}

#[test]
fn the_properties_declare_the_real_generation_instant() {
    // Il valore predefinito della libreria e' il primo gennaio 1970: chi apre
    // le proprieta' in Word leggerebbe quella data. Deterministico e falso.
    let bytes = relazione();
    let voci = voci(&bytes);
    let core = voci
        .iter()
        .find(|(name, _)| name == "docProps/core.xml")
        .map(|(_, content)| content.as_str())
        .expect("il documento deve portare le proprie proprieta'");

    let atteso = Timestamp::from_millis(1_700_010_000_000).to_w3cdtf_utc();
    assert!(
        core.contains(&atteso),
        "le proprieta' non dichiarano l'istante di generazione: {core}"
    );
    assert!(
        !core.contains("1970-01-01"),
        "le proprieta' dichiarano ancora la data predefinita della libreria"
    );
}

#[test]
fn the_properties_do_not_leak_who_or_what_produced_the_file() {
    // I metadati viaggiano con ogni copia del documento e nessuno li guarda:
    // e' il posto in cui un dato di troppo sopravvive piu' a lungo.
    let bytes = relazione();
    let voci = voci(&bytes);
    let proprieta: String = voci
        .iter()
        .filter(|(name, _)| name.starts_with("docProps/"))
        .map(|(_, content)| content.as_str())
        .collect();

    let utente = std::env::var("USERNAME").unwrap_or_default();
    if !utente.is_empty() {
        assert!(
            !proprieta.contains(&utente),
            "le proprieta' del documento contengono il nome utente della macchina"
        );
    }
    for vietato in ["C:\\", "operatore", "Ente di prova"] {
        assert!(
            !proprieta.contains(vietato),
            "le proprieta' del documento contengono «{vietato}»"
        );
    }
}

#[test]
fn two_generations_of_the_same_report_produce_the_same_bytes() {
    // Criterio 30. L'attesa in mezzo non e' un vezzo: le date nelle voci di uno
    // ZIP hanno risoluzione di due secondi, e un confronto immediato passerebbe
    // anche con una libreria che vi scrive l'ora corrente.
    let primo = relazione();
    std::thread::sleep(std::time::Duration::from_millis(2_100));
    let secondo = relazione();

    assert_eq!(
        Sha256Digest::of_bytes(&primo),
        Sha256Digest::of_bytes(&secondo),
        "due generazioni dello stesso documento hanno impronte diverse"
    );
}

/// Scrive un esemplare da aprire a mano in Microsoft Word.
///
/// Il criterio 1 chiede che il documento si apra **e si modifichi** in Word, e
/// nessun test automatico lo dimostra. Questo produce il file su cui eseguire
/// quella verifica, e resta `ignored` perche' scrive sul disco:
///
/// ```text
/// $env:LISI_DOCX_SAMPLE = "C:\percorso\relazione.docx"
/// cargo test -p lisi-services --test docx_determinismo -- --ignored --nocapture
/// ```
#[test]
#[ignore = "scrive un file: si esegue a mano per la verifica su Word"]
fn writes_a_sample_for_the_manual_check() {
    let Ok(path) = std::env::var("LISI_DOCX_SAMPLE") else {
        panic!("impostare LISI_DOCX_SAMPLE con il percorso del file da scrivere");
    };
    std::fs::write(&path, relazione()).expect("il file deve potersi scrivere");
    println!("esemplare scritto in {path}");
}

/// Profilo documentale **dichiaratamente inventato** per i due esemplari.
///
/// Nessun dato di questo profilo appartiene a un ufficio reale, e i valori
/// portano lettere accentate e un apostrofo perche' la voce T20 del pilot
/// verifica proprio quelli.
fn profilo_di_prova() -> ReportTemplateProfile {
    let campo = |value: &str| TemplateField::try_new(value).expect("valore di prova valido");
    ReportTemplateProfile {
        version: 1,
        organisation: Some(campo("ENTE DI PROVA")),
        office: Some(campo("Unità di Prova per la Verifica Documentale")),
        header_line: Some(campo("Sede operativa di Città d'Esempio")),
        recipient: Some(campo("AL RESPONSABILE DELL'UNITÀ DI PROVA")),
        recipient_cc: Some(campo("SEDE")),
        place: Some(campo("Città d'Esempio")),
        signer_role: Some(campo("Qualifica di Prova")),
        signer_name: Some(campo("Nome COGNOME")),
        footer_line: Some(campo("Documento di prova — non ha valore d'atto")),
        subject_base: Some(campo("Relazione di servizio")),
        // Uno stemma **sintetico**: un segno PNG di prova, non lo stemma di
        // un'amministrazione. Serve a far vedere che l'immagine c'e', dov'e' e
        // quanto e' grande — e per questo e' ad alto contrasto: un'immagine
        // pallida in Word non si distingue da un'immagine che non si carica.
        emblem: TemplateEmblem::from_png(png_contrastato(96, 106)).ok(),
    }
}

/// Fotografia sintetica con il numero di contenuti indicato.
fn fotografia(selezionati: &[i64], monitorati: &[i64]) -> ReportSnapshot {
    ReportSnapshot {
        taken_at: Timestamp::from_millis(1_752_000_000_000),
        session_id: SessionId::new(1),
        source_ids: Vec::new(),
        dictionary_version_ids: Vec::new(),
        template_version: 1,
        contents: monitorati
            .iter()
            .map(|raw| ReportContentSnapshot {
                content_id: ContentId::new(*raw),
                level: AnalysisLevel::try_new(u8::try_from(raw % 5).unwrap_or(0))
                    .expect("livello valido"),
                review_state: None,
                body_sha256: Sha256Digest::of_text(&format!("corpo {raw}")),
                selected: selezionati.contains(raw),
            })
            .collect(),
    }
}

/// Scrive i **due** esemplari del pilot su Microsoft Word.
///
/// Sono i due documenti che una persona deve aprire: quello senza elementi
/// selezionati e quello con risultanze. I dati sono **sintetici e
/// dichiaratamente tali**: nessun contenuto proviene da Telegram, nessun nome
/// appartiene a una persona, nessun ufficio esiste.
///
/// ```text
/// $env:LISI_DOCX_PILOT_DIR = "C:\percorso\cartella"
/// cargo test -p lisi-services --test docx_determinismo -- --ignored --nocapture
/// ```
#[test]
#[ignore = "scrive due file: si esegue a mano per la verifica su Word"]
fn writes_the_two_pilot_documents() {
    let Ok(directory) = std::env::var("LISI_DOCX_PILOT_DIR") else {
        panic!("impostare LISI_DOCX_PILOT_DIR con la cartella in cui scrivere");
    };
    let directory = std::path::PathBuf::from(directory);
    std::fs::create_dir_all(&directory).expect("la cartella deve potersi creare");

    let profile = profilo_di_prova();
    let operator = Actor::try_new("operatore.prova").expect("attore valido");
    let generated_at = Timestamp::from_millis(1_752_086_400_000);
    let session = NarrativeSession {
        label: String::from("Monitoraggio di prova"),
        started_at: Timestamp::from_millis(1_752_000_000_000),
        ended_at: Some(Timestamp::from_millis(1_752_010_800_000)),
        account: None,
        profile_observations: Vec::new(),
    };
    let sources = [
        NarrativeSource {
            label: String::from("Canale di prova alfa"),
            acquired: 4,
            reliability: None,
        },
        NarrativeSource {
            label: String::from("Gruppo di prova beta"),
            acquired: 2,
            reliability: None,
        },
    ];

    // -------------------------------------------------- A. senza risultanze
    let identifier = ReportId::from_sequence(2026, 900_001);
    let snapshot = fotografia(&[], &[1, 2, 3, 4, 5, 6]);
    let negativo = render(&compose(&NarrativeInput {
        report_id: &identifier,
        profile: &profile,
        snapshot: &snapshot,
        operator: &operator,
        generated_at,
        session: &session,
        sources: &sources,
        findings: &[],
        coverage: &[],
        faults: &[],
        configuration: &AnalysisConfiguration::unknown(),
    }))
    .expect("la relazione senza risultanze deve potersi scrivere");

    let percorso_a = directory.join("NEXUM97_REPORT_WORD_PILOT_NEGATIVO.docx");
    std::fs::write(&percorso_a, &negativo).expect("il file deve potersi scrivere");

    // ------------------------------------------------- B. con le risultanze
    let identifier = ReportId::from_sequence(2026, 900_002);
    let snapshot = fotografia(&[2, 3, 5], &[1, 2, 3, 4, 5, 6]);
    let findings = [
        NarrativeFinding {
            content_id: ContentId::new(2),
            source_label: String::from("Canale di prova alfa"),
            published_at: Timestamp::from_millis(1_752_001_800_000),
            acquired_at: Timestamp::from_millis(1_752_001_860_000),
            recovered: false,
            // Un elemento con collegamento.
            url: Some(String::from("https://esempio.invalid/prova/2")),
            asked_link: None,
            attachment: None,
            body: String::from(
                "Messaggio sintetico di prova, con lettere accentate — città, perché, \
                 così — e un apostrofo nell'estratto, per verificare la resa.",
            ),
            level: AnalysisLevel::try_new(4).expect("livello valido"),
            engine_reason: Some(String::from(
                "Riscontro di due termini del dizionario di prova.",
            )),
            review_state: Some(ReviewState::Relevant),
            review_note: None,
            after_acquisition: None,
            revisions: Vec::new(),
            revisions_beyond: 0,
            contexts: Vec::new(),
            contexts_beyond: 0,
            acquisition_mode: String::from("Acquisito dal vivo."),
        },
        NarrativeFinding {
            content_id: ContentId::new(3),
            source_label: String::from("Gruppo di prova beta"),
            published_at: Timestamp::from_millis(1_752_003_600_000),
            acquired_at: Timestamp::from_millis(1_752_003_660_000),
            recovered: false,
            // Un elemento senza collegamento: il documento deve dichiararlo.
            url: None,
            asked_link: None,
            attachment: None,
            body: String::from("Secondo messaggio sintetico di prova, piu' breve del precedente."),
            level: AnalysisLevel::try_new(2).expect("livello valido"),
            engine_reason: None,
            review_state: Some(ReviewState::InReview),
            review_note: None,
            after_acquisition: None,
            revisions: Vec::new(),
            revisions_beyond: 0,
            contexts: Vec::new(),
            contexts_beyond: 0,
            acquisition_mode: String::from("Acquisito dal vivo."),
        },
        NarrativeFinding {
            content_id: ContentId::new(5),
            source_label: String::from("Canale di prova alfa"),
            published_at: Timestamp::from_millis(1_752_007_200_000),
            acquired_at: Timestamp::from_millis(1_752_007_260_000),
            recovered: false,
            url: Some(String::from("https://esempio.invalid/prova/5")),
            asked_link: None,
            attachment: None,
            body: String::from(
                "Terzo messaggio sintetico di prova, di livello diverso dagli altri due.",
            ),
            level: AnalysisLevel::try_new(1).expect("livello valido"),
            engine_reason: Some(String::from("Riscontro di un termine attenuato.")),
            review_state: None,
            review_note: None,
            after_acquisition: None,
            revisions: Vec::new(),
            revisions_beyond: 0,
            contexts: Vec::new(),
            contexts_beyond: 0,
            acquisition_mode: String::from("Acquisito dal vivo."),
        },
    ];
    let faults = [String::from(
        "Una fonte non ha risposto per due minuti; l'acquisizione e' ripresa da sola.",
    )];

    let con_risultanze = render(&compose(&NarrativeInput {
        report_id: &identifier,
        profile: &profile,
        snapshot: &snapshot,
        operator: &operator,
        generated_at,
        session: &session,
        sources: &sources,
        findings: &findings,
        coverage: &[],
        faults: &faults,
        configuration: &AnalysisConfiguration::unknown(),
    }))
    .expect("la relazione con risultanze deve potersi scrivere");

    let percorso_b = directory.join("NEXUM97_REPORT_WORD_PILOT_CON_RISULTANZE.docx");
    std::fs::write(&percorso_b, &con_risultanze).expect("il file deve potersi scrivere");

    // ------------------------------------------------- C. senza alcun profilo
    // Le voci T31-T33 del pilot chiedono di **giudicare** come stanno in
    // stampa gli spazi fra parentesi quadre, e chi conduce la verifica non lo
    // puo' fare sui due esemplari qui sopra: hanno il profilo compilato, e i
    // segnaposto non si vedono. Questo terzo esemplare e' il documento di chi
    // ha risposto «Non inserirli».
    let identifier = ReportId::from_sequence(2026, 900_003);
    let snapshot = fotografia(&[2], &[1, 2, 3, 4, 5, 6]);
    let senza_profilo = render(&compose(&NarrativeInput {
        report_id: &identifier,
        profile: &ReportTemplateProfile::default(),
        snapshot: &snapshot,
        operator: &operator,
        generated_at,
        session: &session,
        sources: &sources,
        findings: &findings[..1],
        coverage: &[],
        faults: &[],
        configuration: &AnalysisConfiguration::unknown(),
    }))
    .expect("la relazione senza profilo deve potersi scrivere");

    let percorso_c = directory.join("NEXUM97_REPORT_WORD_PILOT_SENZA_PROFILO.docx");
    std::fs::write(&percorso_c, &senza_profilo).expect("il file deve potersi scrivere");

    println!("A. senza risultanze : {}", percorso_a.display());
    println!("B. con risultanze   : {}", percorso_b.display());
    println!("C. senza profilo    : {}", percorso_c.display());
}

#[test]
fn every_entry_of_the_package_carries_the_same_fixed_date() {
    // La prova 4 di ADR-0032, sul generatore di ADR-0180: le date nelle voci
    // dello ZIP sono fisse, cosi' che il giorno in cui il determinismo si
    // rompesse si sappia subito da che parte guardare.
    let bytes = relazione_con_stemma();
    let mut archive = zip::ZipArchive::new(Cursor::new(bytes)).expect("il file e' uno ZIP");
    assert!(archive.len() > 10, "il pacchetto e' troppo piccolo");
    for index in 0..archive.len() {
        let entry = archive.by_index(index).expect("voce leggibile");
        let name = entry
            .name()
            .expect("nome della voce leggibile")
            .into_owned();
        let Some(data) = entry.last_modified() else {
            panic!("«{name}» non ha una data");
        };
        assert_eq!(
            (
                data.year(),
                data.month(),
                data.day(),
                data.hour(),
                data.minute()
            ),
            (1980, 1, 1, 0, 0),
            "«{name}» porta una data che non e' quella fissa"
        );
    }
}
