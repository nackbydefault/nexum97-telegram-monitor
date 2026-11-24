//! Che cosa un riferimento raggiunge, **e come lo si dice** (NOTE-01).
//!
//! # Perché questo modulo esiste
//!
//! Perché la risoluzione di un riferimento serve a tre cose — i workspace, i
//! segnalibri, le note — e finora viveva dentro il modulo dei workspace. Il
//! codice era già uno solo, quindi non poteva divergere; a divergere erano **le
//! parole**, e l'hanno fatto.
//!
//! La frase che dichiara un riferimento appeso diceva «questo **workspace** lo
//! aveva raccolto». Su un segnalibro era falsa, e nessuno se n'era accorto:
//! BOOK-01 l'ha spedita così. Una frase che nomina il contenitore vive nel posto
//! sbagliato — il fatto riguarda **il riferimento**, non chi lo teneva.
//!
//! Adesso la frase dice soltanto ciò che la risoluzione sa, ed è vera per
//! chiunque la usi. Una prova lo sorveglia.
//!
//! # Perché non è una `Option`
//!
//! Perché `None` si legge come «non c'è», e qui il fatto è un altro: **c'era, e
//! non c'è più**. Un elenco che lasciasse sparire la riga direbbe che quel
//! riferimento non è mai stato messo.

use core::str::FromStr;

use lisi_core::model::reference::ArchiveRefKind;
use rusqlite::OptionalExtension;

use crate::database::Database;
use crate::error::StorageResult;

/// Che cosa un riferimento raggiunge, quando lo raggiunge.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResolvedTarget {
    /// La cosa esiste, e questa è l'etichetta con cui si riconosce **adesso**.
    Present {
        /// Come si chiama adesso nell'archivio.
        label: String,
    },
    /// La cosa non è più nell'archivio.
    ///
    /// **Non dice chi l'abbia rimossa né quando.** Dice che il riferimento non
    /// arriva più a nulla, che è ciò che si è osservato.
    NoLongerInArchive,
}

impl ResolvedTarget {
    /// Se il riferimento arriva ancora a qualcosa.
    ///
    /// # Perché una domanda e non un confronto
    ///
    /// Perché chi mostra la riga deve poter chiedere «arriva ancora?» senza
    /// ispezionare le varianti: il giorno in cui se ne aggiungesse una terza,
    /// un confronto scritto altrove direbbe la cosa sbagliata in silenzio.
    #[must_use]
    pub const fn is_present(&self) -> bool {
        matches!(self, Self::Present { .. })
    }

    /// Che cosa si è trovato, detto a chi legge.
    ///
    /// # Perché la frase non nomina chi teneva il riferimento
    ///
    /// Perché lo stesso riferimento è tenuto da un workspace, da un segnalibro
    /// o da una nota, e una frase che ne nomina uno è **falsa** per gli altri
    /// due. Lo è già stata: fino a NOTE-01 diceva «questo workspace lo aveva
    /// raccolto» anche sotto un segnalibro.
    ///
    /// Il fatto che questa frase conosce riguarda il riferimento: c'era, e non
    /// c'è più. Chi tiene il riferimento lo sa il chiamante, e se serve dirlo lo
    /// dice lui.
    #[must_use]
    pub fn as_sentence(&self, kind: ArchiveRefKind) -> String {
        match self {
            Self::Present { label } => format!("{}: {label}", kind.as_label()),
            Self::NoLongerInArchive => format!(
                "{}: non \u{e8} pi\u{f9} nell'archivio. Il riferimento resta, e dice che \
                 quella cosa c'era.",
                kind.as_label()
            ),
        }
    }
}

impl Database {
    /// Che cosa un riferimento raggiunge.
    ///
    /// # Perché una interrogazione per genere e non una sola
    ///
    /// Perché i generi vivono in tabelle diverse, con colonne diverse. Una
    /// interrogazione sola richiederebbe una tabella di indirezione che nessuno
    /// mantiene, e il giorno in cui divergesse nessuno se ne accorgerebbe.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se la lettura non riesce, o se l'archivio contiene
    /// un genere che il dominio non conosce.
    pub(crate) fn resolve_reference(
        &self,
        kind: ArchiveRefKind,
        target_id: i64,
    ) -> StorageResult<ResolvedTarget> {
        let etichetta: Option<String> = match kind {
            ArchiveRefKind::Source => self
                .connection
                .query_row(
                    "SELECT display_name FROM sources WHERE id = ?1",
                    [target_id],
                    |row| row.get(0),
                )
                .optional()?,
            ArchiveRefKind::Content => self
                .connection
                .query_row(
                    "SELECT c.remote_message_id, c.body, s.display_name
                       FROM contents c
                       JOIN sources s ON s.id = c.source_id
                      WHERE c.id = ?1",
                    [target_id],
                    |row| {
                        Ok((
                            row.get::<_, String>(0)?,
                            row.get::<_, String>(1)?,
                            row.get::<_, String>(2)?,
                        ))
                    },
                )
                .optional()?
                .map(|(remoto, testo, fonte)| content_label(&remoto, &testo, &fonte)),
            ArchiveRefKind::Report => self
                .connection
                .query_row(
                    "SELECT report_id FROM report_packages WHERE id = ?1",
                    [target_id],
                    |row| row.get(0),
                )
                .optional()?,
            // IL WORKSPACE SI RISOLVE COL SUO NOME (NOTE-01).
            //
            // E' cio' con cui chi lavora lo chiama. Lo stato — in lavorazione o
            // chiuso — NON entra nell'etichetta: una nota su un workspace resta
            // vera quando quel workspace viene chiuso, e una frase che dicesse
            // «chiuso» invecchierebbe da sola.
            ArchiveRefKind::Workspace => self
                .connection
                .query_row(
                    "SELECT name FROM workspaces WHERE id = ?1",
                    [target_id],
                    |row| row.get(0),
                )
                .optional()?,
            // UN SEGNALIBRO SI RISOLVE DI UN LIVELLO, E DI UNO SOLO.
            //
            // Un segnalibro non porta un testo proprio: il suo nome e' cio' a
            // cui punta. Si risolve quello, e ci si ferma — un segnalibro non
            // puo' puntare a un segnalibro, e la migrazione lo vieta, quindi
            // non esiste catena in cui perdersi.
            ArchiveRefKind::Bookmark => {
                let puntato: Option<(String, i64)> = self
                    .connection
                    .query_row(
                        "SELECT kind, target_id FROM bookmarks WHERE id = ?1",
                        [target_id],
                        |row| Ok((row.get(0)?, row.get(1)?)),
                    )
                    .optional()?;
                match puntato {
                    None => None,
                    Some((genere, identificativo)) => {
                        let genere = ArchiveRefKind::from_str(&genere)?;
                        let dentro = self.resolve_reference(genere, identificativo)?;
                        Some(match dentro {
                            ResolvedTarget::Present { label } => {
                                format!("su {} {label}", genere.as_label().to_lowercase())
                            }
                            // Il segnalibro c'e', e cio' che segnava non c'e'
                            // piu': sono due fatti diversi, e si dicono
                            // entrambi.
                            ResolvedTarget::NoLongerInArchive => format!(
                                "su {} che non \u{e8} pi\u{f9} nell'archivio",
                                genere.as_label().to_lowercase()
                            ),
                        })
                    }
                }
            }
        };

        Ok(match etichetta {
            Some(label) => ResolvedTarget::Present { label },
            None => ResolvedTarget::NoLongerInArchive,
        })
    }
}

/// Quanti caratteri del testo entrano nell'etichetta di un contenuto.
const CONTENT_LABEL_CHARS: usize = 60;

/// L'etichetta di un contenuto: l'inizio del testo, la fonte e il numero del
/// messaggio (OPERATOR-UX-REMEDIATION-01, OS-02).
///
/// Era soltanto «messaggio 102»: in un workspace, fra i segnalibri e sotto una
/// nota, chi leggeva non sapeva di quale messaggio si trattasse senza aprirlo.
/// Il taglio si fa in caratteri e si dichiara con l'ellissi, come
/// l'anteprima dello Storico.
fn content_label(remoto: &str, testo: &str, fonte: &str) -> String {
    let riga: String = testo
        .chars()
        .map(|carattere| {
            if carattere.is_control() {
                ' '
            } else {
                carattere
            }
        })
        .collect();
    let riga = riga.trim();
    if riga.is_empty() {
        return format!("{fonte}, messaggio {remoto}");
    }
    let inizio = if riga.chars().count() <= CONTENT_LABEL_CHARS {
        String::from(riga)
    } else {
        let testa: String = riga.chars().take(CONTENT_LABEL_CHARS).collect();
        format!("{}\u{2026}", testa.trim_end())
    };
    format!("\u{ab}{inizio}\u{bb} \u{2014} {fonte}, messaggio {remoto}")
}

#[cfg(test)]
mod tests {
    use lisi_core::model::reference::ArchiveRefKind;

    use super::ResolvedTarget;

    /// Questo modulo, per le guardie strutturali.
    const THIS_MODULE: &str = include_str!("reference.rs");

    /// **La frase di un riferimento appeso non nomina chi lo teneva.**
    ///
    /// # Il difetto che questa prova impedisce
    ///
    /// Quello che BOOK-01 ha spedito. La frase diceva «il riferimento resta, e
    /// dice che questo **workspace** lo aveva raccolto», ed era falsa sotto un
    /// segnalibro — dove pure compariva, perché la risoluzione è una sola.
    ///
    /// Il fatto che questa frase conosce riguarda il **riferimento**: c'era, e
    /// non c'è più. Chi lo teneva è un'altra cosa, e la sa il chiamante.
    #[test]
    fn la_frase_non_nomina_chi_teneva_il_riferimento() {
        let appeso = ResolvedTarget::NoLongerInArchive;
        for genere in [
            ArchiveRefKind::Source,
            ArchiveRefKind::Content,
            ArchiveRefKind::Report,
            ArchiveRefKind::Bookmark,
            ArchiveRefKind::Workspace,
        ] {
            let frase = appeso.as_sentence(genere);

            // L'ETICHETTA INIZIALE E' IL GENERE PUNTATO, e ci deve stare: dice
            // che cosa non si trova. Cio' che si sorveglia e' la SPIEGAZIONE,
            // dove il nome di un contenitore sarebbe una parola su chi teneva
            // il riferimento — e quella parola e' vera per uno solo.
            let atteso = format!("{}: ", genere.as_label());
            let Some(spiegazione) = frase.strip_prefix(&atteso) else {
                panic!("la frase deve dire di che cosa parla \u{2014} «{frase}»");
            };
            for contenitore in ["workspace", "segnalibro", "nota", "raccolt"] {
                assert!(
                    !spiegazione.to_lowercase().contains(contenitore),
                    "la spiegazione nomina «{contenitore}», e vale per un contenitore solo: \
                     «{spiegazione}»"
                );
            }
            assert!(
                spiegazione.contains("non \u{e8} pi\u{f9} nell'archivio"),
                "la spiegazione deve dire il fatto \u{2014} «{spiegazione}»"
            );
        }
    }

    /// **Ogni genere ha un modo di risolversi.**
    ///
    /// # Il difetto che questa prova impedisce
    ///
    /// Una variante aggiunta al dominio e mai risolta qui. Il compilatore
    /// obbliga il `match` a essere esaustivo, ma non obbliga il ramo nuovo a
    /// interrogare qualcosa: potrebbe restituire `None` e passare per «non è
    /// più nell'archivio», che è una bugia silenziosa — la cosa c'è, e nessuno
    /// l'ha cercata.
    #[test]
    fn ogni_genere_interroga_una_tabella() {
        let Some((produzione, _)) = THIS_MODULE.split_once("#[cfg(test)]\nmod tests {") else {
            panic!("il modulo deve avere un blocco di prove riconoscibile");
        };
        let Some(inizio) = produzione.find("let etichetta: Option<String> = match kind {") else {
            panic!("la risoluzione deve esistere");
        };
        let corpo = &produzione[inizio..];
        for (genere, tabella) in [
            (ArchiveRefKind::Source, "FROM sources"),
            (ArchiveRefKind::Content, "FROM contents"),
            (ArchiveRefKind::Report, "FROM report_packages"),
            (ArchiveRefKind::Workspace, "FROM workspaces"),
            (ArchiveRefKind::Bookmark, "FROM bookmarks"),
        ] {
            assert!(
                corpo.contains(tabella),
                "il genere «{}» non interroga nulla: restituirebbe «non e' piu' nell'archivio» \
                 senza aver cercato",
                genere.as_str()
            );
        }
    }

    /// **Un contenuto si nomina con l'inizio del testo e la fonte** (OS-02):
    /// «messaggio 102» non diceva di quale messaggio si trattasse.
    #[test]
    fn un_contenuto_si_nomina_con_testo_e_fonte() {
        let breve = super::content_label("102", "Corteo\nin piazza", "Canale di prova");
        assert_eq!(
            breve,
            "\u{ab}Corteo in piazza\u{bb} \u{2014} Canale di prova, messaggio 102"
        );

        let lungo = "à".repeat(200);
        let tagliato = super::content_label("7", &lungo, "Fonte");
        assert!(
            tagliato.contains('\u{2026}'),
            "il taglio si dichiara: {tagliato}"
        );
        assert!(tagliato.chars().count() < 100, "{tagliato}");

        assert_eq!(
            super::content_label("8", "  ", "Fonte"),
            "Fonte, messaggio 8"
        );
    }
}
