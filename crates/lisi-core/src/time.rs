//! Istanti temporali del dominio.
//!
//! Gli istanti sono millisecondi trascorsi dall'epoca Unix in UTC. La scelta è
//! motivata in ADR-0006: ordinamento e confronto esatti, nessuna ambiguità di
//! fuso o di formato, nessuna dipendenza di calendario.
//!
//! La resa leggibile ([`Timestamp::to_readable_utc`]) sta comunque qui, e non
//! nell'interfaccia o nei report: lo stesso istante deve comparire identico
//! nella schermata, nella notifica e nel documento esportato. Tre formattazioni
//! separate diventerebbero tre orari che un giorno non coincidono più.

use core::fmt;
use std::sync::OnceLock;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use crate::error::{DomainError, DomainResult};

/// Istante espresso in millisecondi dall'epoca Unix, in UTC.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Timestamp(i64);

impl Timestamp {
    /// Costruisce un istante da millisecondi dall'epoca Unix.
    #[must_use]
    pub const fn from_millis(millis: i64) -> Self {
        Self(millis)
    }

    /// Millisecondi dall'epoca Unix.
    #[must_use]
    pub const fn as_millis(self) -> i64 {
        self.0
    }

    /// Istante corrente letto dall'orologio di sistema.
    ///
    /// # Errori
    ///
    /// Restituisce [`DomainError::ClockBeforeEpoch`] se l'orologio precede
    /// l'epoca Unix e [`DomainError::TimestampOutOfRange`] se il valore non è
    /// rappresentabile. Il caso è remoto ma reale su macchine con orologio non
    /// impostato, e i requisiti vietano di ricorrere a `unwrap`.
    pub fn now() -> DomainResult<Self> {
        let since_epoch = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| DomainError::ClockBeforeEpoch)?;
        let millis =
            i64::try_from(since_epoch.as_millis()).map_err(|_| DomainError::TimestampOutOfRange)?;
        Ok(Self(millis))
    }

    /// Differenza in millisecondi rispetto a un istante precedente.
    ///
    /// Satura invece di traboccare: un istante incoerente non deve far cadere
    /// l'applicazione.
    #[must_use]
    pub const fn millis_since(self, earlier: Self) -> i64 {
        self.0.saturating_sub(earlier.0)
    }

    /// Istante spostato in avanti di un numero di secondi.
    #[must_use]
    pub const fn plus_seconds(self, seconds: i64) -> Self {
        Self(self.0.saturating_add(seconds.saturating_mul(1_000)))
    }

    /// Verifica che questo istante non preceda `start`.
    ///
    /// # Errori
    ///
    /// Restituisce [`DomainError::EndBeforeStart`] se l'ordine è invertito.
    pub const fn ensure_not_before(self, start: Self) -> DomainResult<Self> {
        if self.0 < start.0 {
            return Err(DomainError::EndBeforeStart);
        }
        Ok(self)
    }

    /// Istante per un **nome di file**: `2026-10-19_14-30-12-345Z` (E2E01-13).
    ///
    /// In UTC, con la Z che lo dice, e con i millisecondi: due copie fatte nello
    /// stesso secondo restano distinte. Le cifre hanno sempre la stessa
    /// larghezza, così l'ordine alfabetico dei nomi è l'ordine degli istanti.
    /// Nessun carattere che Windows rifiuta in un nome (niente due punti).
    #[must_use]
    pub fn to_file_stamp_utc(self) -> String {
        let millis = self.0.max(0);
        let (data, ora) = civil_parts(millis);
        format!("{data}_{}-{:03}Z", ora.replace(':', "-"), millis % 1_000)
    }

    /// Istante reso leggibile: `AAAA-MM-GG HH:MM:SS UTC`.
    ///
    /// # Perché UTC, e perché scritto
    ///
    /// L'istante è conservato in UTC e qui viene mostrato in UTC. Convertirlo
    /// nell'ora locale richiede il fuso della postazione e le sue regole di ora
    /// legale, e produrrebbe un orario che **cambia con la macchina** su cui il
    /// documento viene riletto: in un rapporto è precisamente ciò che non deve
    /// accadere. La sigla è sempre scritta: un orario senza fuso è un orario di
    /// cui non si sa nulla, e il dubbio ricadrebbe su chi lo legge un anno dopo.
    ///
    /// Mostrare **anche** l'ora locale accanto a questa è una decisione di
    /// prodotto che tocca schermate, notifiche e report insieme, e va presa una
    /// volta sola: finché non lo è, il prodotto ne mostra una sola, dichiarata.
    ///
    /// Un istante che precede l'epoca Unix non è rappresentabile qui e viene
    /// reso come tale invece di produrre una data verosimile e sbagliata.
    #[must_use]
    pub fn to_readable_utc(self) -> String {
        if self.0 < 0 {
            return String::from("istante non rappresentabile");
        }

        let total_seconds = self.0 / 1_000;
        let days = total_seconds / 86_400;
        let second_of_day = total_seconds % 86_400;

        let (year, month, day) = civil_from_days(days);
        let hour = second_of_day / 3_600;
        let minute = (second_of_day % 3_600) / 60;
        let second = second_of_day % 60;

        format!("{year:04}-{month:02}-{day:02} {hour:02}:{minute:02}:{second:02} UTC")
    }

    /// Istante reso leggibile **per lo schermo**: l'ora dell'orologio della
    /// postazione, e accanto quella UTC (ADR-0136, che chiude la decisione
    /// lasciata aperta da DEC-385).
    ///
    /// `2026-10-13 09:07:29 ora locale (07:07:29 UTC)`; se le due date
    /// differiscono, la data UTC è scritta per intero:
    /// `2026-10-14 00:30:00 ora locale (2026-10-13 22:30:00 UTC)`.
    ///
    /// # Perché, e perché non al posto di UTC
    ///
    /// Un operatore italiano in ottobre leggeva «07:07 UTC» mentre la barra
    /// delle applicazioni segnava le 09:07, e capiva un'ora sbagliata di due ore
    /// (OPERATOR-SIM-01, 02 e 03). Lo schermo mette quindi **prima** l'ora che
    /// l'operatore ha sotto gli occhi. L'UTC resta scritto accanto, con la
    /// sigla: è l'ora che compare nei documenti probatori, nell'audit e
    /// nell'archivio, e chi confronta lo schermo con una relazione deve poter
    /// ritrovare lo stesso numero.
    ///
    /// L'istante conservato **non cambia**: cambia soltanto come lo si scrive a
    /// schermo. I documenti probatori continuano a usare
    /// [`Self::to_readable_utc`].
    ///
    /// # Da dove viene il fuso
    ///
    /// Dal risolutore installato all'avvio con [`install_local_offset`], che
    /// sulla postazione chiede a Windows lo scarto **di quell'istante**, ora
    /// legale compresa. Se non c'è risolutore, o se Windows non risponde, la
    /// resa è quella di [`Self::to_readable_utc`]: un orario dichiarato UTC,
    /// mai un'ora locale indovinata.
    #[must_use]
    pub fn to_readable_local(self) -> String {
        let scarto = LOCAL_OFFSET.get().and_then(|risolutore| risolutore(self.0));
        self.to_readable_with_offset(scarto)
    }

    /// Data e minuto dell'ora locale, per un **nome**: `2026-10-13 09:07 ora
    /// locale`, oppure `2026-10-13 07:07 UTC` se il fuso non si conosce.
    ///
    /// Serve al nome predefinito di un monitoraggio, che l'operatore legge nei
    /// selettori e confronta con il proprio orologio. L'istante esatto, con
    /// l'UTC accanto, resta nel campo «avviato il» della sessione: un nome è
    /// un'etichetta, non una registrazione.
    #[must_use]
    pub fn to_label_local(self) -> String {
        let scarto = LOCAL_OFFSET.get().and_then(|risolutore| risolutore(self.0));
        self.to_label_with_offset(scarto)
    }

    /// La resa di [`Self::to_label_local`] con uno scarto dato: la parte pura.
    #[must_use]
    pub fn to_label_with_offset(self, offset_minutes: Option<i32>) -> String {
        if self.0 < 0 {
            return String::from("istante non rappresentabile");
        }
        let scarto = offset_minutes.filter(|minuti| *minuti != 0 && minuti.abs() <= 18 * 60);
        let locale = scarto.map(|minuti| self.0.saturating_add(i64::from(minuti) * 60_000));
        match locale {
            Some(locale) if locale >= 0 => {
                let (data, ora) = civil_parts(locale);
                format!("{data} {} ora locale", &ora[..5])
            }
            _ => {
                let (data, ora) = civil_parts(self.0);
                format!("{data} {} UTC", &ora[..5])
            }
        }
    }

    /// La resa di [`Self::to_readable_local`] con uno scarto dato, in minuti:
    /// la parte pura, che le prove possono guidare.
    ///
    /// Uno scarto assente, nullo o fuori da ogni fuso esistente (oltre le
    /// diciotto ore) produce la sola resa UTC.
    #[must_use]
    pub fn to_readable_with_offset(self, offset_minutes: Option<i32>) -> String {
        let Some(scarto) = offset_minutes else {
            return self.to_readable_utc();
        };
        if scarto == 0 || scarto.abs() > 18 * 60 || self.0 < 0 {
            return self.to_readable_utc();
        }
        let locale = self.0.saturating_add(i64::from(scarto) * 60_000);
        if locale < 0 {
            return self.to_readable_utc();
        }

        let (data_locale, ora_locale) = civil_parts(locale);
        let (data_utc, ora_utc) = civil_parts(self.0);
        if data_locale == data_utc {
            format!("{data_locale} {ora_locale} ora locale ({ora_utc} UTC)")
        } else {
            format!("{data_locale} {ora_locale} ora locale ({data_utc} {ora_utc} UTC)")
        }
    }

    /// Anno civile dell'istante, in UTC.
    ///
    /// # A che cosa serve
    ///
    /// L'identificativo citabile di un report ha la forma `R-<anno>-<numero>`
    /// (ADR-0031): comporlo richiede l'anno, e ricavarlo tagliando i primi
    /// quattro caratteri di [`Self::to_readable_utc`] significherebbe leggere
    /// un numero da una frase pensata per una persona. Il giorno in cui quella
    /// frase cambiasse forma, l'identificativo diventerebbe sbagliato senza che
    /// nulla lo segnali.
    ///
    /// Vale il limite già dichiarato per le altre rese: un istante precedente
    /// all'epoca Unix non è rappresentabile e restituisce `1970`.
    #[must_use]
    pub fn year_utc(self) -> i32 {
        if self.0 < 0 {
            return 1970;
        }

        let (year, _, _) = civil_from_days(self.0 / 1_000 / 86_400);
        i32::try_from(year).unwrap_or(1970)
    }

    /// Istante in forma W3CDTF: `AAAA-MM-GGTHH:MM:SSZ`.
    ///
    /// # A che cosa serve, dato che ce n'è già una leggibile
    ///
    /// I metadati di un documento OOXML pretendono questa forma esatta, e non
    /// quella leggibile: `dcterms:created` con un formato diverso è un campo che
    /// Word ignora o mostra sbagliato. È una forma per le macchine, mentre
    /// [`Self::to_readable_utc`] è per le persone, e tenerle separate evita di
    /// piegarne una alle esigenze dell'altra.
    ///
    /// Vale anche qui il limite dichiarato sopra: un istante precedente
    /// all'epoca Unix non è rappresentabile e restituisce l'inizio dell'epoca
    /// invece di una data verosimile e sbagliata.
    #[must_use]
    pub fn to_w3cdtf_utc(self) -> String {
        if self.0 < 0 {
            return String::from("1970-01-01T00:00:00Z");
        }

        let total_seconds = self.0 / 1_000;
        let days = total_seconds / 86_400;
        let second_of_day = total_seconds % 86_400;

        let (year, month, day) = civil_from_days(days);
        let hour = second_of_day / 3_600;
        let minute = (second_of_day % 3_600) / 60;
        let second = second_of_day % 60;

        format!("{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}Z")
    }

    /// Istante nella forma che STIX 2.1 pretende: `AAAA-MM-GGTHH:MM:SS.mmmZ`.
    ///
    /// # Perché una terza resa, e non la seconda
    ///
    /// Perché STIX 2.1 chiede per `created` e `modified` una precisione **al
    /// millesimo di secondo, con esattamente tre cifre decimali**, e
    /// [`Self::to_w3cdtf_utc`] si ferma al secondo. Allargare quella
    /// significherebbe cambiare i metadati dei documenti OOXML per una ragione
    /// che non li riguarda: Word li vuole com'erano, e un campo che due formati
    /// tirano in due direzioni finisce sbagliato per entrambi.
    ///
    /// Vale il limite già dichiarato per le altre rese: un istante precedente
    /// all'epoca Unix non è rappresentabile e restituisce l'inizio dell'epoca
    /// invece di una data verosimile e sbagliata.
    #[must_use]
    pub fn to_stix_utc(self) -> String {
        if self.0 < 0 {
            return String::from("1970-01-01T00:00:00.000Z");
        }

        let total_seconds = self.0 / 1_000;
        let millis = self.0 % 1_000;
        let days = total_seconds / 86_400;
        let second_of_day = total_seconds % 86_400;

        let (year, month, day) = civil_from_days(days);
        let hour = second_of_day / 3_600;
        let minute = (second_of_day % 3_600) / 60;
        let second = second_of_day % 60;

        format!("{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}.{millis:03}Z")
    }
}

/// Il fuso della postazione, come funzione: dato un istante in millisecondi
/// UTC, i minuti da aggiungere per avere l'ora che segnava l'orologio della
/// postazione **in quell'istante**, ora legale compresa (ADR-0136).
///
/// `lisi-core` non parla col sistema operativo: il risolutore lo fornisce chi
/// avvia il programma, che lo chiede a Windows.
pub type LocalOffsetResolver = fn(i64) -> Option<i32>;

static LOCAL_OFFSET: OnceLock<LocalOffsetResolver> = OnceLock::new();

/// Installa il risolutore del fuso, una volta sola per processo.
///
/// Restituisce `false` se ce n'era già uno: il primo resta, perché due
/// risolutori sarebbero due orologi.
pub fn install_local_offset(resolver: LocalOffsetResolver) -> bool {
    LOCAL_OFFSET.set(resolver).is_ok()
}

/// Una data e un'ora locali scritte da una persona, già verificate
/// (SCHEDULE-01, ADR-0171).
///
/// Non è un istante: lo diventa con il fuso **di quel giorno**
/// ([`local_to_instant`]), perché fra oggi e quel giorno può cambiare l'ora
/// legale.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LocalDateTime {
    /// Anno, dal 2000 al 2100.
    pub year: i64,
    /// Mese, da 1 a 12.
    pub month: u32,
    /// Giorno del mese.
    pub day: u32,
    /// Ora, da 0 a 23.
    pub hour: u32,
    /// Minuto, da 0 a 59.
    pub minute: u32,
}

impl LocalDateTime {
    /// Legge una data scritta `GG/MM/AAAA` o `AAAA-MM-GG` e un'ora scritta
    /// `HH:MM` o `HH.MM`.
    ///
    /// Restituisce `None` per tutto il resto, e per una data che non esiste
    /// (il 31 aprile, il 29 febbraio di un anno non bisestile).
    #[must_use]
    pub fn parse(date: &str, time: &str) -> Option<Self> {
        let date = date.trim();
        let (year, month, day) = if let Some((giorno, resto)) = date.split_once('/') {
            let (mese, anno) = resto.split_once('/')?;
            (number(anno, 4)?, number(mese, 2)?, number(giorno, 2)?)
        } else {
            let mut parti = date.split('-');
            let anno = number(parti.next()?, 4)?;
            let mese = number(parti.next()?, 2)?;
            let giorno = number(parti.next()?, 2)?;
            if parti.next().is_some() {
                return None;
            }
            (anno, mese, giorno)
        };
        let time = time.trim();
        let (ora, minuto) = time.split_once(':').or_else(|| time.split_once('.'))?;
        let (hour, minute) = (number(ora, 2)?, number(minuto, 2)?);

        let year = i64::from(year);
        if !(2000..=2100).contains(&year) || !(1..=12).contains(&month) {
            return None;
        }
        if day == 0 || day > days_in_month(year, month) || hour > 23 || minute > 59 {
            return None;
        }
        Some(Self {
            year,
            month,
            day,
            hour,
            minute,
        })
    }

    /// I millisecondi che questa data e ora avrebbero se fossero UTC: la base
    /// da cui si toglie lo scarto del fuso.
    fn as_if_utc(self) -> i64 {
        let giorni = days_from_civil(self.year, self.month, self.day);
        giorni * 86_400_000 + i64::from(self.hour * 60 + self.minute) * 60_000
    }
}

/// Un numero di una a `massimo` cifre ASCII.
fn number(text: &str, massimo: usize) -> Option<u32> {
    let text = text.trim();
    if text.is_empty() || text.len() > massimo || !text.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    text.parse().ok()
}

/// I giorni di un mese, con gli anni bisestili del calendario gregoriano.
const fn days_in_month(year: i64, month: u32) -> u32 {
    match month {
        4 | 6 | 9 | 11 => 30,
        2 if (year % 4 == 0 && year % 100 != 0) || year % 400 == 0 => 29,
        2 => 28,
        _ => 31,
    }
}

/// I giorni dall'epoca Unix di una data civile: l'inverso di
/// `civil_from_days`, dello stesso algoritmo di Howard Hinnant.
fn days_from_civil(year: i64, month: u32, day: u32) -> i64 {
    let year = if month <= 2 { year - 1 } else { year };
    let era = year.div_euclid(400);
    let year_of_era = year.rem_euclid(400);
    let shifted_month = i64::from(if month > 2 { month - 3 } else { month + 9 });
    let day_of_year = (153 * shifted_month + 2) / 5 + i64::from(day) - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    era * 146_097 + day_of_era - 719_468
}

/// Che cosa diventa un'ora locale, il giorno in cui cade.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LocalConversion {
    /// Un istante solo.
    Exact(Timestamp),
    /// Quel giorno quell'ora non esiste: l'orologio va avanti e la salta.
    Nonexistent,
    /// Quel giorno quell'ora esiste due volte: l'orologio torna indietro.
    Ambiguous,
    /// Il fuso di Windows non si legge.
    UnknownZone,
}

/// Converte un'ora locale nell'istante, con lo scarto del fuso **di quel
/// giorno** (SCHEDULE-01, ADR-0171, decisione 1).
///
/// `offset_at` dà lo scarto in minuti in vigore in un istante UTC. Si provano
/// gli scarti in vigore un giorno prima, quel giorno e un giorno dopo: un
/// candidato vale se nel suo istante vige proprio lo scarto con cui è stato
/// calcolato. Nessun candidato: l'ora non esiste; due: esiste due volte. Non se
/// ne sceglie una per conto di chi l'ha scritta.
#[must_use]
pub fn local_to_instant(
    local: LocalDateTime,
    offset_at: impl Fn(i64) -> Option<i32>,
) -> LocalConversion {
    let base = local.as_if_utc();
    let mut validi: Vec<i64> = Vec::new();
    for sonda in [base - 86_400_000, base, base + 86_400_000] {
        let Some(scarto) = offset_at(sonda) else {
            return LocalConversion::UnknownZone;
        };
        let candidato = base - i64::from(scarto) * 60_000;
        if offset_at(candidato) == Some(scarto) && !validi.contains(&candidato) {
            validi.push(candidato);
        }
    }
    match validi.as_slice() {
        [] => LocalConversion::Nonexistent,
        [unico] => LocalConversion::Exact(Timestamp::from_millis(*unico)),
        _ => LocalConversion::Ambiguous,
    }
}

/// [`local_to_instant`] con il fuso installato all'avvio
/// ([`install_local_offset`]). Senza fuso, [`LocalConversion::UnknownZone`].
#[must_use]
pub fn local_to_instant_here(local: LocalDateTime) -> LocalConversion {
    match LOCAL_OFFSET.get() {
        Some(risolutore) => local_to_instant(local, *risolutore),
        None => LocalConversion::UnknownZone,
    }
}

/// Data e ora civili di un istante in millisecondi, già scritte:
/// `("AAAA-MM-GG", "HH:MM:SS")`. Solo per istanti non negativi.
fn civil_parts(millis: i64) -> (String, String) {
    let total_seconds = millis / 1_000;
    let days = total_seconds / 86_400;
    let second_of_day = total_seconds % 86_400;

    let (year, month, day) = civil_from_days(days);
    let hour = second_of_day / 3_600;
    let minute = (second_of_day % 3_600) / 60;
    let second = second_of_day % 60;

    (
        format!("{year:04}-{month:02}-{day:02}"),
        format!("{hour:02}:{minute:02}:{second:02}"),
    )
}

/// L'ancora dell'orologio: l'istante di sistema letto **una volta sola**
/// all'avvio, con il punto monotono in cui lo si è letto.
///
/// Si fissa con [`anchor_clock`] e si legge con [`anchored_now`].
static CLOCK_ANCHOR: OnceLock<(Timestamp, Instant)> = OnceLock::new();

/// Legge l'orologio di sistema e lo fissa come ancora del processo.
///
/// Va chiamata **prima di tutto il resto**, e una volta sola: chiamate
/// successive restituiscono l'ancora già fissata senza rileggere l'orologio.
///
/// # Perché esiste
///
/// Perché la domanda «che cosa fa il programma se l'orologio non si legge?»
/// aveva trentadue risposte identiche sparse in due crate, e tutte la stessa:
/// scrivere **1970-01-01** e tacere. In un prodotto costruito intorno alla
/// provenienza e all'ora era l'unico punto in cui una cosa non vera veniva
/// scritta senza dirlo (FINAL-PRODUCT-REVIEW-01, FPR-10).
///
/// Adesso la risposta è una: se l'orologio non si legge **all'avvio**, il
/// programma non si avvia e dice perché; se smette di leggersi **dopo**,
/// l'istante si ricava dall'ancora e dal tempo monotono trascorso, che non è
/// un valore inventato — è lo stesso istante contato in un altro modo.
///
/// # Errori
///
/// Gli stessi di [`Timestamp::now`]: un orologio che precede l'epoca Unix o un
/// valore non rappresentabile.
pub fn anchor_clock() -> DomainResult<Timestamp> {
    if let Some((istante, _)) = CLOCK_ANCHOR.get() {
        return Ok(*istante);
    }
    let adesso = Timestamp::now()?;
    // `get_or_init` e non `set`: fra il controllo qui sopra e questa riga un
    // altro filo potrebbe aver fissato la propria ancora, e due ancore
    // sarebbero due orologi.
    let (istante, _) = CLOCK_ANCHOR.get_or_init(|| (adesso, Instant::now()));
    Ok(*istante)
}

/// L'istante corrente, **senza inventare nulla**.
///
/// Legge l'orologio di sistema. Se non è leggibile — una condizione remota ma
/// reale, che esiste solo con un orologio precedente al 1970 — l'istante si
/// ricava dall'ancora dell'avvio più il tempo monotono trascorso da allora.
///
/// # Che cosa restituisce quando non c'è nemmeno l'ancora
///
/// L'epoca, cioè `1970-01-01`. **Non è un ripiego silenzioso**: è il valore che
/// il controllo di prontezza riconosce come «l'orologio è tornato indietro»
/// (`preflight`, controllo 9, che risponde «Ogni istante registrato adesso
/// sarebbe falso»). Nel prodotto quel ramo non si raggiunge, perché
/// [`anchor_clock`] viene chiamata all'avvio e un suo errore impedisce
/// l'avvio; resta scritto e provato perché una libreria non può presumere di
/// essere chiamata nell'ordine giusto.
#[must_use]
pub fn anchored_now() -> Timestamp {
    match Timestamp::now() {
        Ok(adesso) => adesso,
        Err(_) => {
            let Some((istante, letto)) = CLOCK_ANCHOR.get() else {
                return from_anchor(None, 0);
            };
            let trascorsi = i64::try_from(letto.elapsed().as_millis()).unwrap_or(i64::MAX);
            from_anchor(Some(*istante), trascorsi)
        }
    }
}

/// L'istante ricavato dall'ancora, come funzione pura: è la parte che le prove
/// possono guidare, perché un orologio di sistema rotto non si può chiedere a
/// una macchina che funziona.
const fn from_anchor(ancora: Option<Timestamp>, trascorsi_ms: i64) -> Timestamp {
    match ancora {
        Some(istante) => Timestamp::from_millis(istante.as_millis().saturating_add(trascorsi_ms)),
        None => Timestamp::from_millis(0),
    }
}

/// Converte i giorni dall'epoca Unix in anno, mese e giorno del calendario.
///
/// È l'algoritmo civile di Howard Hinnant, valido per il calendario gregoriano
/// prolettico. Sta qui, scritto per esteso e coperto da test, invece che in una
/// dipendenza di calendario: il prodotto ha bisogno di una sola conversione, e
/// una dipendenza porta con sé una superficie che nessuno riesamina.
fn civil_from_days(days: i64) -> (i64, u32, u32) {
    // Si sposta l'origine al 1° marzo dell'anno 0: così il giorno bisestile
    // cade in fondo al ciclo e non richiede casi particolari.
    let shifted = days + 719_468;
    let era = shifted.div_euclid(146_097);
    let day_of_era = shifted.rem_euclid(146_097);

    let year_of_era =
        (day_of_era - day_of_era / 1_460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let year = year_of_era + era * 400;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);

    let shifted_month = (5 * day_of_year + 2) / 153;
    let day = u32::try_from(day_of_year - (153 * shifted_month + 2) / 5 + 1).unwrap_or(1);
    let month = u32::try_from(if shifted_month < 10 {
        shifted_month + 3
    } else {
        shifted_month - 9
    })
    .unwrap_or(1);

    (if month <= 2 { year + 1 } else { year }, month, day)
}

impl fmt::Display for Timestamp {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}ms", self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::Timestamp;
    use crate::error::DomainError;

    /// **Il nome della copia si legge e ordina come l'istante** (E2E01-13).
    #[test]
    fn l_istante_per_un_nome_di_file_si_legge_e_ordina() {
        assert_eq!(
            Timestamp::from_millis(1_700_000_000_123).to_file_stamp_utc(),
            "2023-11-14_22-13-20-123Z"
        );
        assert_eq!(
            Timestamp::from_millis(0).to_file_stamp_utc(),
            "1970-01-01_00-00-00-000Z"
        );
        let prima = Timestamp::from_millis(1_792_150_899_223).to_file_stamp_utc();
        let dopo = Timestamp::from_millis(1_792_150_899_224).to_file_stamp_utc();
        assert!(prima < dopo, "{prima} {dopo}");
        assert!(
            !prima.contains(':'),
            "Windows non accetta i due punti: {prima}"
        );
    }

    #[test]
    fn senza_ancora_l_istante_e_quello_che_il_controllo_di_prontezza_riconosce() {
        // Non è un ripiego silenzioso: 1970 è il valore che il controllo 9 di
        // `preflight` legge come «l'orologio è tornato indietro», e la riga
        // che l'operatore vede dice «Ogni istante registrato adesso sarebbe
        // falso» (FINAL-PRODUCT-REVIEW-01, FPR-10).
        assert_eq!(super::from_anchor(None, 0), Timestamp::from_millis(0));
        assert_eq!(super::from_anchor(None, 90_000), Timestamp::from_millis(0));
    }

    #[test]
    fn con_l_ancora_l_istante_cresce_del_tempo_trascorso() {
        // L'orologio di sistema non si legge più; l'istante si ricava
        // dall'avvio e dal tempo monotono. Non è inventato: è lo stesso
        // istante contato in un altro modo.
        let avvio = Timestamp::from_millis(1_790_000_000_000);
        assert_eq!(super::from_anchor(Some(avvio), 0), avvio);
        assert_eq!(
            super::from_anchor(Some(avvio), 3_600_000),
            Timestamp::from_millis(1_790_003_600_000)
        );
    }

    #[test]
    fn un_tempo_trascorso_assurdo_non_fa_traboccare_l_istante() {
        // La prova negativa del limite: un contatore monotono che restituisse
        // un valore enorme non deve produrre un istante che va a ritroso per
        // trabocco.
        let avvio = Timestamp::from_millis(1_790_000_000_000);
        let oltre = super::from_anchor(Some(avvio), i64::MAX);
        assert!(oltre >= avvio, "l'istante non può tornare indietro");
        assert_eq!(oltre, Timestamp::from_millis(i64::MAX));
    }

    #[test]
    fn l_ancora_si_fissa_una_volta_sola() {
        // Due chiamate, la stessa ancora: un secondo orologio sarebbe un
        // secondo istante di partenza, e due istanti di partenza sono due
        // cronologie.
        let (Ok(prima), Ok(seconda)) = (super::anchor_clock(), super::anchor_clock()) else {
            panic!("su una macchina con l'orologio impostato l'ancora si fissa");
        };
        assert_eq!(prima, seconda);
        // E l'istante corrente non precede l'ancora.
        assert!(super::anchored_now() >= prima);
    }

    #[test]
    fn now_is_after_the_year_2020() {
        let Ok(now) = Timestamp::now() else {
            panic!("l'orologio di sistema deve essere leggibile nei test");
        };
        // 2020-01-01T00:00:00Z in millisecondi.
        assert!(now.as_millis() > 1_577_836_800_000);
    }

    #[test]
    fn the_epoch_is_rendered_as_the_first_of_january_1970() {
        assert_eq!(
            Timestamp::from_millis(0).to_readable_utc(),
            "1970-01-01 00:00:00 UTC"
        );
    }

    #[test]
    fn a_known_instant_is_rendered_exactly() {
        // 1_700_000_000 secondi dall'epoca: e' il valore usato come istante di
        // prova in tutto il progetto, e vale la pena saperlo leggere.
        assert_eq!(
            Timestamp::from_millis(1_700_000_000_000).to_readable_utc(),
            "2023-11-14 22:13:20 UTC"
        );
    }

    #[test]
    fn the_machine_readable_form_follows_w3cdtf() {
        // I metadati di un documento OOXML pretendono questa forma esatta.
        assert_eq!(
            Timestamp::from_millis(1_700_000_000_000).to_w3cdtf_utc(),
            "2023-11-14T22:13:20Z"
        );
        assert_eq!(
            Timestamp::from_millis(0).to_w3cdtf_utc(),
            "1970-01-01T00:00:00Z"
        );
    }

    #[test]
    fn the_two_forms_describe_the_same_instant() {
        // Due rappresentazioni che divergessero sarebbero peggio di una sola:
        // il documento direbbe una cosa nel corpo e un'altra nelle proprieta'.
        let instant = Timestamp::from_millis(1_709_208_000_000);
        let readable = instant.to_readable_utc();
        let machine = instant.to_w3cdtf_utc();

        assert_eq!(readable.replace(' ', "T").replace("TUTC", "Z"), machine);
    }

    #[test]
    fn a_leap_day_is_rendered_as_the_twenty_ninth_of_february() {
        // 2024-02-29T12:00:00Z. Il 29 febbraio e' il caso in cui una
        // conversione di calendario scritta a mano sbaglia per prima.
        assert_eq!(
            Timestamp::from_millis(1_709_208_000_000).to_readable_utc(),
            "2024-02-29 12:00:00 UTC"
        );
    }

    #[test]
    fn the_year_agrees_with_the_readable_form() {
        // Due letture dello stesso istante che divergessero produrrebbero un
        // identificativo di report intestato a un anno diverso da quello che il
        // documento dichiara al proprio interno.
        for millis in [0, 1_700_000_000_000, 1_709_208_000_000, 4_102_444_800_000] {
            let instant = Timestamp::from_millis(millis);
            let readable = instant.to_readable_utc();
            let Ok(from_text) = readable[..4].parse::<i32>() else {
                panic!("la resa leggibile deve cominciare con l'anno: {readable}");
            };
            assert_eq!(instant.year_utc(), from_text);
        }
    }

    #[test]
    fn the_last_instant_of_a_year_still_belongs_to_that_year() {
        // 2026-12-31T23:59:59Z: il confine e' il punto in cui una conversione
        // scritta a mano sbaglia per prima.
        assert_eq!(Timestamp::from_millis(1_798_761_599_000).year_utc(), 2026);
        assert_eq!(Timestamp::from_millis(1_798_761_600_000).year_utc(), 2027);
    }

    #[test]
    fn an_instant_before_the_epoch_has_no_year_to_invent() {
        assert_eq!(Timestamp::from_millis(-1).year_utc(), 1970);
    }

    #[test]
    fn an_instant_before_the_epoch_says_so_instead_of_inventing_a_date() {
        assert_eq!(
            Timestamp::from_millis(-2_203_891_200_000).to_readable_utc(),
            "istante non rappresentabile",
            "un istante prima dell'epoca non produce una data verosimile e sbagliata"
        );
    }

    #[test]
    fn the_timezone_is_always_written() {
        // Un orario senza fuso e' un orario di cui non si sa nulla, e il dubbio
        // ricadrebbe su chi lo rilegge un anno dopo.
        for millis in [0, 1_000, 1_700_000_000_000, 4_102_444_800_000] {
            assert!(
                Timestamp::from_millis(millis)
                    .to_readable_utc()
                    .ends_with("UTC"),
                "manca la sigla del fuso"
            );
        }
    }

    #[test]
    fn every_day_of_a_leap_year_round_trips_through_the_calendar() {
        // La conversione e' scritta a mano: vale la pena percorrere un anno
        // intero invece di fidarsi di tre istanti scelti bene.
        let start = 1_704_067_200_000_i64; // 2024-01-01T00:00:00Z
        let mut seen = std::collections::BTreeSet::new();
        for day in 0..366_i64 {
            let rendered = Timestamp::from_millis(start + day * 86_400_000).to_readable_utc();
            assert!(
                rendered.starts_with("2024-"),
                "giorno fuori anno: {rendered}"
            );
            seen.insert(rendered);
        }
        assert_eq!(
            seen.len(),
            366,
            "ogni giorno deve produrre una data diversa"
        );
    }

    #[test]
    fn difference_is_computed_in_milliseconds() {
        let start = Timestamp::from_millis(1_000);
        let end = Timestamp::from_millis(4_500);
        assert_eq!(end.millis_since(start), 3_500);
    }

    #[test]
    fn difference_saturates_instead_of_overflowing() {
        let huge = Timestamp::from_millis(i64::MAX);
        let tiny = Timestamp::from_millis(i64::MIN);
        assert_eq!(huge.millis_since(tiny), i64::MAX);
    }

    #[test]
    fn ordering_follows_the_instant() {
        assert!(Timestamp::from_millis(10) < Timestamp::from_millis(20));
    }

    #[test]
    fn plus_seconds_saturates_at_the_upper_bound() {
        let near_max = Timestamp::from_millis(i64::MAX - 10);
        assert_eq!(near_max.plus_seconds(1_000).as_millis(), i64::MAX);
    }

    #[test]
    fn an_end_before_the_start_is_rejected() {
        let start = Timestamp::from_millis(5_000);
        let end = Timestamp::from_millis(4_999);
        assert_eq!(
            end.ensure_not_before(start),
            Err(DomainError::EndBeforeStart)
        );
    }

    #[test]
    fn an_end_equal_to_the_start_is_accepted() {
        let start = Timestamp::from_millis(5_000);
        assert_eq!(start.ensure_not_before(start), Ok(start));
    }

    /// 2026-10-13 07:07:29 UTC: l'istante di OPERATOR-SIM-03, quando la barra
    /// delle applicazioni segnava le 09:07.
    const SIM_03: i64 = 1_791_875_249_000;

    /// **Lo schermo mostra prima l'ora dell'orologio, poi quella UTC**
    /// (ADR-0136, SIM3-05).
    #[test]
    fn l_ora_locale_viene_prima_e_l_utc_resta_accanto() {
        let istante = Timestamp::from_millis(SIM_03);
        assert_eq!(istante.to_readable_utc(), "2026-10-13 07:07:29 UTC");
        // Ora legale italiana: UTC+2.
        assert_eq!(
            istante.to_readable_with_offset(Some(120)),
            "2026-10-13 09:07:29 ora locale (07:07:29 UTC)"
        );
        // Ora solare: UTC+1. Il fuso è quello dell'istante, non un +1 o un +2
        // fisso: lo sceglie il risolutore, qui lo si passa.
        assert_eq!(
            istante.to_readable_with_offset(Some(60)),
            "2026-10-13 08:07:29 ora locale (07:07:29 UTC)"
        );
        // Un fuso a ovest, e uno con la mezz'ora.
        assert_eq!(
            istante.to_readable_with_offset(Some(-300)),
            "2026-10-13 02:07:29 ora locale (07:07:29 UTC)"
        );
        assert_eq!(
            istante.to_readable_with_offset(Some(330)),
            "2026-10-13 12:37:29 ora locale (07:07:29 UTC)"
        );
    }

    /// **Il cambio di data si scrive per intero**: «00:30 ora locale (22:30
    /// UTC)» senza la data UTC farebbe credere che le due ore siano dello
    /// stesso giorno.
    #[test]
    fn il_cambio_di_data_si_scrive_per_intero() {
        // 2026-10-13 22:30:00 UTC.
        let istante = Timestamp::from_millis(1_791_930_600_000);
        assert_eq!(
            istante.to_readable_with_offset(Some(120)),
            "2026-10-14 00:30:00 ora locale (2026-10-13 22:30:00 UTC)"
        );
        // E all'indietro, a ovest.
        let mattino = Timestamp::from_millis(1_791_853_200_000); // 2026-10-13 01:00 UTC
        assert_eq!(
            mattino.to_readable_with_offset(Some(-300)),
            "2026-10-12 20:00:00 ora locale (2026-10-13 01:00:00 UTC)"
        );
    }

    /// **Il nome di un monitoraggio porta l'ora dell'orologio**, al minuto.
    #[test]
    fn il_nome_porta_l_ora_dell_orologio() {
        let istante = Timestamp::from_millis(SIM_03);
        assert_eq!(
            istante.to_label_with_offset(Some(120)),
            "2026-10-13 09:07 ora locale"
        );
        assert_eq!(istante.to_label_with_offset(None), "2026-10-13 07:07 UTC");
        assert_eq!(
            istante.to_label_with_offset(Some(0)),
            "2026-10-13 07:07 UTC"
        );
        assert_eq!(
            Timestamp::from_millis(-5).to_label_with_offset(Some(60)),
            "istante non rappresentabile"
        );
    }

    /// **Senza un fuso affidabile, solo UTC, dichiarato**: mai un'ora locale
    /// indovinata.
    #[test]
    fn senza_fuso_resta_l_utc_dichiarato() {
        let istante = Timestamp::from_millis(SIM_03);
        let utc = "2026-10-13 07:07:29 UTC";
        assert_eq!(istante.to_readable_with_offset(None), utc);
        assert_eq!(istante.to_readable_with_offset(Some(0)), utc);
        assert_eq!(istante.to_readable_with_offset(Some(19 * 60)), utc);
        assert_eq!(istante.to_readable_with_offset(Some(-19 * 60)), utc);
        assert_eq!(
            Timestamp::from_millis(-1).to_readable_with_offset(Some(120)),
            "istante non rappresentabile"
        );
        // Un istante vicino all'epoca che il fuso porterebbe prima del 1970.
        assert_eq!(
            Timestamp::from_millis(1_000).to_readable_with_offset(Some(-60)),
            "1970-01-01 00:00:01 UTC"
        );
    }

    /// **L'ordine non cambia**: la resa locale è una scrittura, l'istante è
    /// lo stesso, e due istanti in ordine restano in ordine anche dopo il
    /// passaggio all'ora solare, quando l'ora locale «torna indietro».
    #[test]
    fn l_istante_non_cambia_e_l_ordine_nemmeno() {
        // 2026-10-25 00:30 UTC (02:30 legale) e 01:30 UTC (02:30 solare).
        let prima = Timestamp::from_millis(1_792_888_200_000);
        let dopo = Timestamp::from_millis(1_792_891_800_000);
        assert!(prima < dopo);
        let a = prima.to_readable_with_offset(Some(120));
        let b = dopo.to_readable_with_offset(Some(60));
        assert_eq!(a, "2026-10-25 02:30:00 ora locale (00:30:00 UTC)");
        assert_eq!(b, "2026-10-25 02:30:00 ora locale (01:30:00 UTC)");
        // Le due ore locali coincidono: è l'UTC accanto a distinguerle, ed è
        // per questo che resta scritto.
        assert_ne!(a, b);
    }

    // ------------------------------------------- ora locale e istante (SCHEDULE-01)

    use super::{LocalConversion, LocalDateTime, local_to_instant};

    /// Una data e un'ora, già verificate.
    fn locale(year: i64, month: u32, day: u32, hour: u32, minute: u32) -> LocalDateTime {
        LocalDateTime {
            year,
            month,
            day,
            hour,
            minute,
        }
    }

    /// Il fuso di Roma nel 2026: ora legale dal 29 marzo alle 01:00 UTC al 25
    /// ottobre alle 01:00 UTC.
    fn roma(utc: i64) -> Option<i32> {
        let inizio = locale(2026, 3, 29, 1, 0).as_if_utc();
        let fine = locale(2026, 10, 25, 1, 0).as_if_utc();
        Some(if (inizio..fine).contains(&utc) {
            120
        } else {
            60
        })
    }

    /// **Il cambio dell'ora legale non sposta l'inizio** (SCHEDULE-01,
    /// ADR-0171, criterio 1; prova negativa: lo scarto di oggi al posto di
    /// quello del giorno → rossa). Programmato il 23 ottobre, in ora legale,
    /// per il 26 alle 09:00, in ora solare: l'istante è le 08:00 UTC, non le
    /// 07:00.
    #[test]
    fn il_cambio_dell_ora_legale_non_sposta_l_inizio() {
        assert_eq!(
            local_to_instant(locale(2026, 10, 26, 9, 0), roma),
            LocalConversion::Exact(Timestamp::from_millis(
                locale(2026, 10, 26, 8, 0).as_if_utc()
            ))
        );
        assert_eq!(
            local_to_instant(locale(2026, 10, 23, 9, 0), roma),
            LocalConversion::Exact(Timestamp::from_millis(
                locale(2026, 10, 23, 7, 0).as_if_utc()
            ))
        );
    }

    /// **Un'ora che non esiste o che esiste due volte si rifiuta, e un fuso
    /// che non si legge lo dice** (ADR-0171, decisione 1).
    #[test]
    fn un_ora_saltata_o_doppia_non_si_sceglie_a_caso() {
        assert_eq!(
            local_to_instant(locale(2026, 3, 29, 2, 30), roma),
            LocalConversion::Nonexistent
        );
        assert_eq!(
            local_to_instant(locale(2026, 10, 25, 2, 30), roma),
            LocalConversion::Ambiguous
        );
        assert_eq!(
            local_to_instant(locale(2026, 10, 26, 9, 0), |_| None),
            LocalConversion::UnknownZone
        );
        // In UTC ogni ora esiste una volta.
        assert_eq!(
            local_to_instant(locale(2026, 10, 25, 2, 30), |_| Some(0)),
            LocalConversion::Exact(Timestamp::from_millis(
                locale(2026, 10, 25, 2, 30).as_if_utc()
            ))
        );
    }

    /// **Una data si legge nei due modi, e una data che non esiste no.**
    #[test]
    fn una_data_e_un_ora_si_leggono_o_si_rifiutano() {
        assert_eq!(
            LocalDateTime::parse("26/10/2026", "09:00"),
            Some(locale(2026, 10, 26, 9, 0))
        );
        assert_eq!(
            LocalDateTime::parse(" 2026-10-26 ", "9.05"),
            Some(locale(2026, 10, 26, 9, 5))
        );
        assert_eq!(
            LocalDateTime::parse("29/02/2028", "00:00"),
            Some(locale(2028, 2, 29, 0, 0))
        );
        for (data, ora) in [
            ("31/04/2026", "09:00"),
            ("29/02/2027", "09:00"),
            ("2026-13-01", "09:00"),
            ("26/10/2026", "24:00"),
            ("26/10/2026", "12:60"),
            ("26/10/1999", "09:00"),
            ("domani", "09:00"),
            ("26/10/2026", "nove"),
            ("2026-10-26-01", "09:00"),
            ("26/10/2026", ""),
        ] {
            assert_eq!(LocalDateTime::parse(data, ora), None, "«{data} {ora}»");
        }
        // L'algoritmo inverso di quello che scrive le date.
        assert_eq!(
            Timestamp::from_millis(locale(2026, 10, 13, 7, 7).as_if_utc()).to_readable_utc(),
            "2026-10-13 07:07:00 UTC"
        );
    }
}
