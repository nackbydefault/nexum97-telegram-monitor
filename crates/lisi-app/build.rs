//! Compilazione dell'interfaccia Slint e, se la modalita' reale e' attiva,
//! preparazione della libreria TDLib.
//!
//! Lo stile dei widget di libreria è **fissato**, non lasciato al tema di
//! sistema. Senza questo, gli stessi pulsanti compaiono chiari su una
//! postazione in tema chiaro e scuri su una in tema scuro, dentro una finestra
//! che resta comunque scura: il risultato è testo scuro su pannello scuro, o un
//! pulsante chiaro che stona con tutto il resto.
//!
//! Il prodotto ha una tavolozza propria e dichiarata in `docs/ux/`: i widget
//! devono seguirla, non l'impostazione di chi usa la macchina.

use std::path::{Path, PathBuf};

fn main() -> Result<(), slint_build::CompileError> {
    // I caratteri vanno preparati **prima** della compilazione dell'interfaccia:
    // il file generato viene importato da `app-window.slint`, e deve esistere
    // quando il compilatore di Slint lo cerca.
    let generated = configure_embedded_fonts();

    // LE INFORMAZIONI SUGLI ELEMENTI, SOLO IN DEBUG (OPERATOR-E2E-REMEDIATION-01,
    // F-01).
    //
    // Servono alle prove che cercano un comando per il nome che annuncia alle
    // tecnologie assistive, come farebbe un lettore di schermo: senza, la
    // ricerca del backend di prova non vede alcun elemento. Le prove girano in
    // debug; il binario di rilascio resta com'era, senza tabelle in piu'.
    let debug = std::env::var("PROFILE").is_ok_and(|profile| profile == "debug");

    // LE ALTRE LINGUE (I18N-01, ADR-0197). Un catalogo gettext per lingua,
    // uno solo per l'interfaccia e per il Rust: Slint lo incorpora con la sua
    // funzione, senza contesto predefinito (lo stesso testo italiano si
    // traduce una volta sola); il Rust lo legge dalla tabella generata qui.
    generate_rust_catalogue();

    slint_build::compile_with_config(
        "ui/app-window.slint",
        slint_build::CompilerConfiguration::new()
            .with_style(String::from("fluent-dark"))
            .with_include_paths(vec![generated])
            .with_bundled_translations(TRANSLATIONS)
            .with_default_translation_context(slint_build::DefaultTranslationContext::None)
            .with_debug_info(debug),
    )?;

    embed_application_icon();
    copy_tdlib_library_if_enabled();

    Ok(())
}

/// Una voce del catalogo: testo italiano, traduzione, se è tradotta.
type Voice = (String, String, bool);

/// La cartella dei cataloghi: `translations/<lingua>/LC_MESSAGES/<pacchetto>.po`.
const TRANSLATIONS: &str = "translations";

/// Scrive in `OUT_DIR` la tabella dei cataloghi per i testi del Rust.
///
/// # Perché una tabella generata e non una lettura all'avvio
///
/// Slint incorpora i cataloghi nell'interfaccia, ma non offre fra le funzioni
/// pubbliche un modo di tradurre un testo che nasce nel Rust. Il catalogo si
/// legge quindi qui, con lo stesso lettore che usa Slint (`rspolib`), e
/// diventa una tabella ordinata per testo italiano: il binario non porta un
/// lettore, e un catalogo illeggibile ferma la compilazione invece di
/// lasciare il programma in italiano senza dirlo.
///
/// Per ogni voce si scrive se è tradotta con la regola di Slint: non
/// obsoleta, non incerta (`fuzzy`), con una traduzione non vuota.
fn generate_rust_catalogue() {
    use rspolib::prelude::*;

    println!("cargo:rerun-if-changed={TRANSLATIONS}");
    let package = std::env::var("CARGO_PKG_NAME").unwrap_or_default();
    let mut languages: Vec<(String, Vec<Voice>)> = Vec::new();

    let entries = std::fs::read_dir(TRANSLATIONS)
        .unwrap_or_else(|error| panic!("cartella {TRANSLATIONS} non leggibile: {error}"));
    for entry in entries.flatten() {
        let path = entry
            .path()
            .join("LC_MESSAGES")
            .join(format!("{package}.po"));
        if !path.exists() {
            continue;
        }
        println!("cargo:rerun-if-changed={}", path.display());
        let catalogue = rspolib::pofile(path.as_path())
            .unwrap_or_else(|error| panic!("catalogo {} non leggibile: {error}", path.display()));
        let mut voices: Vec<Voice> = catalogue
            .entries
            .iter()
            .filter(|voice| !voice.obsolete && voice.msgctxt.is_none())
            .map(|voice| {
                (
                    voice.msgid.clone(),
                    voice.msgstr.clone().unwrap_or_default(),
                    voice.translated(),
                )
            })
            .collect();
        voices.sort_by(|a, b| a.0.cmp(&b.0));
        languages.push((entry.file_name().to_string_lossy().into_owned(), voices));
    }
    languages.sort_by(|a, b| a.0.cmp(&b.0));

    let mut code = String::from(
        "// Generato da build.rs dai cataloghi in `translations/`: non si modifica.\n\
         pub(crate) static CATALOGUES: &[(&str, &[Voce])] = &[\n",
    );
    for (language, voices) in &languages {
        code.push_str(&format!("    ({language:?}, &[\n"));
        for (original, translation, translated) in voices {
            code.push_str(&format!(
                "        ({original:?}, {translation:?}, {translated}),\n"
            ));
        }
        code.push_str("    ]),\n");
    }
    code.push_str("];\n");

    let out_dir = std::env::var_os("OUT_DIR")
        .map(PathBuf::from)
        .unwrap_or_default();
    let target = out_dir.join("catalogues.rs");
    // Si riscrive solo se cambia, come i caratteri: un file riscritto uguale
    // fa ricompilare l'intero crate a ogni comando.
    if std::fs::read_to_string(&target).ok().as_deref() != Some(code.as_str()) {
        std::fs::write(&target, code)
            .unwrap_or_else(|error| panic!("tabella dei cataloghi non scritta: {error}"));
    }
}

/// Decide se i caratteri del sistema grafico entrano nel binario.
///
/// # Il contratto, e perche' e' asimmetrico
///
/// I file dei caratteri **non sono versionati**: `fonts.lock.json` ne conserva
/// l'impronta e `scripts/fetch-fonts.ps1` li scarica e la riverifica, come gia'
/// si fa per TDLib e per il redistribuibile. Una clonazione pulita quindi non
/// li ha.
///
/// Da qui due comportamenti diversi, ed e' voluto:
///
/// - in **debug** manca un carattere e la build prosegue con un avviso. Chi
///   lavora al codice non deve scaricare 280 KB per compilare;
/// - in **release** la build **fallisce**. Una release costruita senza i
///   caratteri parte, funziona e sembra giusta: usa la catena di ripiego, e la
///   differenza la vede solo chi la mette accanto al riferimento approvato. E'
///   il difetto piu' pericoloso di tutti - quello che non si annuncia - e
///   l'unico momento in cui si puo' fermare e' qui.
///
/// Questo e' anche il motivo per cui il controllo non sta in un test: un test
/// gira in debug, dove il caso da bloccare non si presenta.
///
/// # Come si incorpora un carattere in Slint
///
/// **Non** con `include_bytes!` e una registrazione a runtime: in Slint 1.17
/// quella via esiste solo dietro la feature `unstable-fontique-010`, e non si
/// mette una feature instabile in un prodotto che fissa le dipendenze.
///
/// La via sostenuta e' l'`import` di un `.ttf` **dentro un file `.slint`**: il
/// compilatore raccoglie i caratteri di *tutti* i documenti dell'unita' e ne
/// genera la registrazione. Da qui il file generato qui sotto — che esiste
/// sempre, cosi' che l'`import` in `app-window.slint` non cada mai, e che
/// contiene le due righe di `import` **solo quando i caratteri ci sono**.
///
/// Restituisce la cartella da aggiungere ai percorsi di inclusione.
fn configure_embedded_fonts() -> PathBuf {
    let out_dir = std::env::var_os("OUT_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            panic!("OUT_DIR non disponibile: la compilazione non puo' proseguire");
        });

    let generated = out_dir.join("product-fonts.slint");

    // Senza questa dichiarazione `cfg!(fonts_embedded)` produce
    // `unexpected_cfgs`, che con `-D warnings` fa fallire clippy.
    println!("cargo::rustc-check-cfg=cfg(fonts_embedded)");

    let Some(directory) = fonts_directory() else {
        println!("cargo:warning=cartella dei caratteri non determinabile");
        write_font_module(&generated, None);
        return out_dir;
    };

    let core = directory.join("Sora-Variable.ttf");
    let mono = directory.join("IBMPlexMono-Regular.ttf");
    println!("cargo:rerun-if-changed={}", core.display());
    println!("cargo:rerun-if-changed={}", mono.display());

    if core.is_file() && mono.is_file() {
        write_font_module(&generated, Some((&core, &mono)));
        println!("cargo:rustc-cfg=fonts_embedded");
        return out_dir;
    }

    let missing = if core.is_file() {
        "IBMPlexMono-Regular.ttf"
    } else if mono.is_file() {
        "Sora-Variable.ttf"
    } else {
        "Sora-Variable.ttf e IBMPlexMono-Regular.ttf"
    };

    if std::env::var("PROFILE").as_deref() == Ok("release") {
        panic!(
            "caratteri assenti in build release: manca {missing} sotto assets/fonts/.\n\
             Una release con i caratteri di ripiego sembra giusta e non lo e'.\n\
             Eseguire: scripts\\fetch-fonts.ps1"
        );
    }

    println!(
        "cargo:warning=caratteri assenti ({missing}): il testo usera' la catena di ripiego. \
         Eseguire scripts\\fetch-fonts.ps1 per incorporarli."
    );
    write_font_module(&generated, None);
    out_dir
}

/// Scrive il modulo Slint che porta — o non porta — i caratteri.
///
/// Esporta sempre `ProductFonts`, cosi' che l'`import` in `app-window.slint` sia
/// valido in entrambi i casi. E' un elemento vuoto: non disegna nulla, serve
/// solo a dare un nome da importare, perche' in Slint un file si importa per i
/// simboli che esporta.
fn write_font_module(path: &Path, fonts: Option<(&Path, &Path)>) {
    let mut source = String::from(
        "// GENERATO DA build.rs — non modificare a mano.\n\
         //\n\
         // Le righe di `import` di un `.ttf` sono il modo con cui Slint\n\
         // incorpora e registra un carattere. Compaiono solo se i file ci sono.\n\n",
    );

    if let Some((core, mono)) = fonts {
        // Le barre rovesciate di Windows non vanno in un percorso Slint.
        source.push_str(&format!(
            "import \"{}\";\nimport \"{}\";\n\n",
            core.display().to_string().replace('\\', "/"),
            mono.display().to_string().replace('\\', "/")
        ));
    }

    source.push_str("export component ProductFonts inherits Rectangle {\n    width: 0px;\n    height: 0px;\n}\n");

    // SI RISCRIVE SOLTANTO SE CAMBIA (ADR-0182, misurato il 2026-11-06).
    //
    // Il compilatore Slint dichiara a cargo i file che importa, e questo è
    // fra quelli. Riscritto a ogni esecuzione, risultava sempre più recente
    // del registro dello script: cargo rifaceva lo script e ricompilava
    // l'interfaccia intera a ogni comando, dieci minuti anche quando nulla
    // era cambiato. Uguale, il file si lascia com'è, con la sua data.
    if std::fs::read_to_string(path).is_ok_and(|presente| presente == source) {
        return;
    }
    if let Err(error) = std::fs::write(path, source) {
        panic!("modulo dei caratteri non scrivibile: {error}");
    }
}

/// Cartella dei caratteri, alla radice del workspace.
fn fonts_directory() -> Option<PathBuf> {
    let manifest_dir = std::env::var_os("CARGO_MANIFEST_DIR")?;
    let workspace_root = Path::new(&manifest_dir).parent()?.parent()?;
    Some(workspace_root.join("assets").join("fonts"))
}

/// Incorpora l'icona del prodotto nell'eseguibile Windows.
///
/// # Perché a mano e non con una libreria
///
/// Esistono crate che fanno esattamente questo, e sono buoni. Farebbero però
/// entrare una dipendenza per **un file di venti righe**, e questo progetto
/// tratta ogni dipendenza come una decisione di catena di fornitura. Il Windows
/// SDK è già nella baseline vincolante, quindi `rc.exe` c'è: quello che manca è
/// solo trovarlo, ed è ciò che fa [`resource_compiler`].
///
/// # Il difetto da cui guardarsi
///
/// Non è «la build fallisce»: è **la build riesce e l'icona non c'è**. Un
/// eseguibile senza icona non si distingue da uno con l'icona finché qualcuno
/// non guarda Esplora file, e a quel punto nessuno collega la cosa a questo
/// file. Per questo l'assenza del compilatore di risorse produce un avviso
/// esplicito, e `scripts/verify-executable-icon.ps1` controlla l'eseguibile
/// prodotto invece di fidarsi che il passaggio sia avvenuto.
fn embed_application_icon() {
    if !cfg!(target_os = "windows") {
        return;
    }

    let Some(icon) = icon_path() else {
        println!("cargo:warning=icona del prodotto non trovata: l'eseguibile non la portera'");
        return;
    };
    println!("cargo:rerun-if-changed={}", icon.display());

    let Some(out_dir) = std::env::var_os("OUT_DIR").map(PathBuf::from) else {
        println!("cargo:warning=OUT_DIR non disponibile: l'icona non e' stata incorporata");
        return;
    };

    // `1` è l'identificatore che la shell di Windows usa per l'icona
    // principale: è quella che compare in Esplora file e sulla barra delle
    // applicazioni. Il percorso va con le barre rovesciate raddoppiate perché
    // per il compilatore di risorse la barra rovesciata è un escape.
    let script = out_dir.join("nexum97.rc");
    let escaped = icon.display().to_string().replace('\\', "\\\\");
    let mut resources = format!("1 ICON \"{escaped}\"\n");
    resources.push_str(&version_information());
    if let Err(error) = std::fs::write(&script, resources) {
        println!("cargo:warning=script di risorse non scrivibile: {error}");
        return;
    }

    let Some(compiler) = resource_compiler() else {
        println!(
            "cargo:warning=rc.exe non trovato nel Windows SDK: l'eseguibile non portera' l'icona"
        );
        return;
    };

    let compiled = out_dir.join("nexum97.res");
    let outcome = std::process::Command::new(&compiler)
        .arg("/nologo")
        .arg("/fo")
        .arg(&compiled)
        .arg(&script)
        .status();

    match outcome {
        Ok(status) if status.success() => {
            // Il file di risorse si passa al linker come un oggetto qualunque.
            println!("cargo:rustc-link-arg={}", compiled.display());
        }
        Ok(status) => {
            println!("cargo:warning=compilazione dell'icona fallita (codice {status})");
        }
        Err(error) => {
            println!("cargo:warning=compilazione dell'icona non avviabile: {error}");
        }
    }
}

/// Blocco `VERSIONINFO`, che riempie le proprietà del file in Windows.
///
/// # Da dove vengono i nomi
///
/// Da `lisi-core::branding`, letto **dal sorgente**. Riscriverli qui sarebbe
/// creare una seconda copia del nome del prodotto, ed è esattamente il modo in
/// cui erano nate le quattro varianti dell'attribuzione (DEC-120): nessuno le
/// scrive diverse apposta, si scrivono diverse **dopo**, quando una delle due
/// cambia e l'altra no.
///
/// Se il sorgente non è leggibile o una costante non ha la forma attesa, il
/// blocco viene **omesso** con un avviso: proprietà di file con un nome
/// sbagliato sono peggio di proprietà assenti, perché sembrano vere.
fn version_information() -> String {
    let Some(name) = branding_constant("PRODUCT_NAME") else {
        println!("cargo:warning=nome del prodotto non leggibile: proprieta' del file omesse");
        return String::new();
    };
    let Some(description) = branding_constant("PRODUCT_DESCRIPTION") else {
        println!("cargo:warning=descrizione non leggibile: proprieta' del file omesse");
        return String::new();
    };
    let Some(publisher) = branding_constant("PUBLISHER") else {
        println!("cargo:warning=editore non leggibile: proprieta' del file omesse");
        return String::new();
    };
    // LegalCopyright era vuota (INSTALLED-APP-E2E-01, E2E01-24).
    let Some(copyright) = branding_constant("COPYRIGHT") else {
        println!("cargo:warning=copyright non leggibile: proprieta' del file omesse");
        return String::new();
    };

    let version = std::env::var("CARGO_PKG_VERSION").unwrap_or_else(|_| String::from("0.0.0"));
    // La quaterna numerica vuole quattro campi; la versione del prodotto ne ha
    // tre, e il quarto resta zero. Non si inventa un numero di build: un valore
    // che cambia senza che nulla sia cambiato rende inutile confrontarlo.
    let numeric = format!("{},0", version.replace('.', ","));

    // `040904E4` è inglese-USA con la tabella caratteri Windows a 1252: è la
    // combinazione che Windows legge senza che il sistema sia in quella lingua,
    // ed è quella usata di fatto da ogni prodotto che non traduce le proprietà.
    format!(
        "\n1 VERSIONINFO\n\
         FILEVERSION {numeric}\n\
         PRODUCTVERSION {numeric}\n\
         FILEOS 0x40004L\n\
         FILETYPE 0x1L\n\
         BEGIN\n\
         \x20 BLOCK \"StringFileInfo\"\n\
         \x20 BEGIN\n\
         \x20   BLOCK \"040904E4\"\n\
         \x20   BEGIN\n\
         \x20     VALUE \"CompanyName\", \"{publisher}\"\n\
         \x20     VALUE \"FileDescription\", \"{description}\"\n\
         \x20     VALUE \"FileVersion\", \"{version}\"\n\
         \x20     VALUE \"LegalCopyright\", \"{copyright}\"\n\
         \x20     VALUE \"ProductName\", \"{name}\"\n\
         \x20     VALUE \"ProductVersion\", \"{version}\"\n\
         \x20   END\n\
         \x20 END\n\
         \x20 BLOCK \"VarFileInfo\"\n\
         \x20 BEGIN\n\
         \x20   VALUE \"Translation\", 0x409, 1252\n\
         \x20 END\n\
         END\n"
    )
}

/// Legge una costante testuale da `lisi-core::branding`.
///
/// Cerca la forma esatta `pub const NOME: &str = "valore";`, che un test di
/// `lisi-core` protegge. Una forma diversa produce `None`, e chi chiama omette
/// il blocco invece di indovinare.
fn branding_constant(name: &str) -> Option<String> {
    let manifest_dir = std::env::var_os("CARGO_MANIFEST_DIR")?;
    let source = Path::new(&manifest_dir)
        .parent()?
        .join("lisi-core")
        .join("src")
        .join("branding.rs");
    println!("cargo:rerun-if-changed={}", source.display());

    let text = std::fs::read_to_string(source).ok()?;
    let needle = format!("pub const {name}: &str = \"");
    let start = text.find(&needle)? + needle.len();
    let rest = text.get(start..)?;
    let end = rest.find('"')?;
    let value = rest.get(..end)?;

    // Le proprietà di file non ammettono virgolette né a capo: un valore che ne
    // contenesse produrrebbe uno script di risorse malformato, e il difetto
    // comparirebbe come «icona assente» senza alcun rapporto con la causa.
    if value.is_empty() || value.contains('"') || value.contains('\n') {
        return None;
    }
    Some(value.to_owned())
}

/// Percorso dell'icona multi-risoluzione del prodotto.
fn icon_path() -> Option<PathBuf> {
    let manifest_dir = std::env::var_os("CARGO_MANIFEST_DIR")?;
    let workspace_root = Path::new(&manifest_dir).parent()?.parent()?;
    let icon = workspace_root
        .join("assets")
        .join("brand")
        .join("icon")
        .join("nexum97.ico");
    icon.is_file().then_some(icon)
}

/// Trova `rc.exe` nel Windows SDK installato, scegliendo la versione più alta.
///
/// Si guarda in entrambe le cartelle dei programmi perché il kit si installa
/// sotto quella a 32 bit sulle macchine a 64 bit, ma non è una regola su cui
/// valga la pena scommettere. Fra più versioni si prende **l'ultima**: per
/// compilare un'icona vanno bene tutte, e scegliere in modo deterministico
/// evita che due macchine con gli stessi kit producano build diverse.
fn resource_compiler() -> Option<PathBuf> {
    let roots = [
        std::env::var_os("ProgramFiles(x86)"),
        std::env::var_os("ProgramFiles"),
    ];

    let mut candidates: Vec<PathBuf> = Vec::new();
    for root in roots.into_iter().flatten() {
        let bin = Path::new(&root).join("Windows Kits").join("10").join("bin");
        let Ok(entries) = std::fs::read_dir(&bin) else {
            continue;
        };
        for entry in entries.flatten() {
            let candidate = entry.path().join("x64").join("rc.exe");
            if candidate.is_file() {
                candidates.push(candidate);
            }
        }
    }

    candidates.sort();
    candidates.pop()
}

/// Copia la libreria TDLib e le sue dipendenze accanto al binario compilato,
/// solo quando la feature `tdlib-runtime` è attiva.
///
/// Windows risolve le dipendenze di una DLL caricata da un percorso esplicito
/// cercando nella cartella dell'**eseguibile**, non in quella della DLL
/// stessa: le quattro DLL devono percio' stare insieme li', non solo essere
/// raggiungibili da un percorso indicato a runtime. Un guasto qui (per
/// esempio artefatti non ancora compilati con `scripts/build-tdlib.ps1`) non
/// deve impedire la build: il prodotto resta utilizzabile in modalita' Mock
/// anche senza TDLib, ed e' un avviso, non un errore fatale.
fn copy_tdlib_library_if_enabled() {
    if std::env::var_os("CARGO_FEATURE_TDLIB_RUNTIME").is_none() {
        return;
    }

    let Some(target_dir) = executable_output_directory() else {
        println!(
            "cargo:warning=impossibile determinare la cartella dell'eseguibile: le DLL TDLib non sono state copiate"
        );
        return;
    };

    let Some(artifacts_dir) = tdlib_artifacts_directory() else {
        println!(
            "cargo:warning=cartella degli artefatti TDLib non determinabile: le DLL non sono state copiate"
        );
        return;
    };

    for file_name in [
        "tdjson.dll",
        "libcrypto-3-x64.dll",
        "libssl-3-x64.dll",
        "z.dll",
    ] {
        let source = artifacts_dir.join(file_name);
        let destination = target_dir.join(file_name);
        if let Err(error) = std::fs::copy(&source, &destination) {
            println!(
                "cargo:warning=impossibile copiare {file_name} accanto all'eseguibile: {error}"
            );
        }
    }
}

/// Cartella del binario compilato, risalendo da `OUT_DIR`.
///
/// `OUT_DIR` e' `target/{profilo}/build/{crate}-{hash}/out`: la cartella del
/// binario e' tre livelli sopra.
fn executable_output_directory() -> Option<PathBuf> {
    let out_dir = std::env::var_os("OUT_DIR")?;
    Path::new(&out_dir)
        .ancestors()
        .nth(3)
        .map(Path::to_path_buf)
}

/// Cartella degli artefatti TDLib verificati, alla radice del workspace.
fn tdlib_artifacts_directory() -> Option<PathBuf> {
    let manifest_dir = std::env::var_os("CARGO_MANIFEST_DIR")?;
    let workspace_root = Path::new(&manifest_dir).parent()?.parent()?;
    Some(workspace_root.join("artifacts").join("tdlib"))
}
