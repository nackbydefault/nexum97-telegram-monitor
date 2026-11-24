//! La cartella in cui l'ufficio conserva i documenti prodotti.
//!
//! Vive qui, nel dominio, e non nei servizi, per la stessa ragione di
//! [`crate::model::settings`]: la persistenza la legge e la scrive, e lo storage
//! dipende da `lisi-core` ma non dai servizi.
//!
//! # Perche' un tipo e non un `PathBuf`
//!
//! Perche' un `PathBuf` accetta qualunque cosa, e il percorso di destinazione
//! arriva da due sorgenti che meritano fiducia diversa: la finestra di scelta di
//! Windows, che restituisce cartelle vere, e **l'archivio**, che le restituisce
//! come le ha trovate. Un archivio alterato a mano puo' contenere un percorso
//! relativo, o uno con un `..` in mezzo, e il programma che lo rilegge senza
//! guardarlo scriverebbe dove non deve.
//!
//! Convalidare al confine significa che chi ha in mano un [`ExportDestination`]
//! sa gia' che il percorso e' assoluto e non risale. Non e' una garanzia sul
//! disco - la cartella puo' essere sparita, o essere di sola lettura, e lo si
//! scopre scrivendo - ma toglie di mezzo la classe di errori che si puo'
//! togliere prima.

use std::path::{Component, Path, PathBuf};

use crate::error::{DomainError, DomainResult};

/// Lunghezza massima del percorso conservato.
///
/// Windows accetta percorsi lunghi solo con il prefisso esteso e la chiave di
/// registro attiva; oltre questa misura il percorso e' quasi certamente il
/// frutto di un errore o di una manomissione, non una scelta.
pub const MAX_PATH_CHARS: usize = 4_096;

/// Una cartella di destinazione **assoluta e senza risalite**.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExportDestination(PathBuf);

impl ExportDestination {
    /// Convalida un percorso proposto come destinazione.
    ///
    /// # Errori
    ///
    /// Restituisce [`DomainError::InvalidDestination`] se il percorso e' vuoto,
    /// troppo lungo, relativo, oppure contiene un componente `..`.
    pub fn try_new(path: impl Into<PathBuf>) -> DomainResult<Self> {
        let path = path.into();

        let Some(text) = path.to_str() else {
            // Un percorso che non e' testo valido non si puo' conservare
            // nell'archivio ne' mostrare all'operatore: rifiutarlo qui e' meglio
            // che scoprirlo a meta' di una scrittura.
            return Err(DomainError::InvalidDestination {
                reason: "il percorso contiene caratteri non rappresentabili",
            });
        };

        if text.trim().is_empty() {
            return Err(DomainError::InvalidDestination {
                reason: "nessuna cartella indicata",
            });
        }

        if text.chars().count() > MAX_PATH_CHARS {
            return Err(DomainError::InvalidDestination {
                reason: "il percorso è troppo lungo",
            });
        }

        if !path.is_absolute() {
            // Un percorso relativo si risolverebbe rispetto alla cartella di
            // lavoro del processo, che nessuno ha scelto e che puo' cambiare.
            return Err(DomainError::InvalidDestination {
                reason: "la cartella deve essere indicata per intero",
            });
        }

        if path
            .components()
            .any(|part| matches!(part, Component::ParentDir))
        {
            // Un `..` in mezzo rende il percorso conservato diverso da dove
            // scrive davvero, e la differenza si vede solo eseguendola.
            return Err(DomainError::InvalidDestination {
                reason: "il percorso non può risalire di cartella",
            });
        }

        Ok(Self(path))
    }

    /// Il percorso convalidato.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.0
    }

    /// Il percorso come testo, per l'archivio e per l'interfaccia.
    #[must_use]
    pub fn as_str(&self) -> &str {
        // Invariante: `try_new` rifiuta cio' che non e' testo valido, quindi
        // qui la conversione non puo' fallire.
        self.0.to_str().unwrap_or_default()
    }
}

impl From<ExportDestination> for PathBuf {
    fn from(value: ExportDestination) -> Self {
        value.0
    }
}

impl ExportDestination {
    /// Se la destinazione e' su una condivisione di rete.
    ///
    /// # Perche' questa domanda esiste
    ///
    /// I documenti prodotti finiscono dove l'operatore sceglie, e spesso e'
    /// proprio una cartella condivisa: e' il motivo per cui quella scelta
    /// esiste.
    ///
    /// Su una condivisione il prodotto **non sa e non puo' sapere** chi ha
    /// accesso. Non lo sa Windows dal lato client, non lo dice il percorso, e
    /// imporre permessi su un server altrui e' fuori discussione (ADR-0041).
    ///
    /// L'unica cosa vera che si possa dire e' dirlo.
    ///
    /// # Che cosa questa funzione riconosce, e che cosa no
    ///
    /// Riconosce i percorsi UNC — `\\server\condivisa` — che sono la forma
    /// esplicita. **Non** riconosce un'unita' di rete mappata a lettera: `Z:`
    /// e `C:` si scrivono allo stesso modo, e distinguerle richiederebbe
    /// interrogare il tipo di unita'.
    ///
    /// Il limite e' dichiarato invece che nascosto: un'avvertenza che non
    /// compare non e' un'assenza di rischio.
    #[must_use]
    pub fn is_network_share(&self) -> bool {
        let testo = self.as_str();
        testo.starts_with("\\\\") || testo.starts_with("//")
    }

    /// L'avvertenza da mostrare, quando serve.
    ///
    /// `None` quando non c'e' nulla da avvertire: un'avvertenza che compare
    /// sempre e' un'avvertenza che nessuno legge.
    #[must_use]
    pub fn caution(&self) -> Option<String> {
        if !self.is_network_share() {
            return None;
        }
        Some(String::from(
            "Questa è una cartella di rete: il prodotto non può sapere chi \
             potrà leggere i documenti che ci finiscono. L'archivio resta \
             protetto sulla postazione; i documenti prodotti no.",
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_absolute_folder_is_accepted_and_kept_as_it_is() {
        let destination =
            ExportDestination::try_new(r"C:\Documenti\Relazioni").expect("percorso valido");
        assert_eq!(destination.path(), Path::new(r"C:\Documenti\Relazioni"));
        assert_eq!(destination.as_str(), r"C:\Documenti\Relazioni");
    }

    #[test]
    fn a_relative_folder_is_refused() {
        // Si risolverebbe rispetto alla cartella di lavoro del processo, che
        // nessuno ha scelto.
        let error = ExportDestination::try_new("Relazioni").expect_err("deve rifiutare");
        assert_eq!(error.kind(), "cartella_non_valida");
    }

    #[test]
    fn a_path_that_climbs_is_refused() {
        // Il percorso conservato direbbe una cosa e la scrittura ne farebbe
        // un'altra.
        let error =
            ExportDestination::try_new(r"C:\Documenti\..\Windows").expect_err("deve rifiutare");
        assert_eq!(error.kind(), "cartella_non_valida");
    }

    #[test]
    fn an_empty_path_is_refused() {
        assert!(ExportDestination::try_new("").is_err());
        assert!(ExportDestination::try_new("   ").is_err());
    }

    #[test]
    fn an_overlong_path_is_refused() {
        let lungo = format!(r"C:\{}", "a".repeat(MAX_PATH_CHARS));
        let error = ExportDestination::try_new(lungo).expect_err("deve rifiutare");
        assert_eq!(error.kind(), "cartella_non_valida");
    }

    #[test]
    fn a_unc_path_is_accepted() {
        // Una cartella di rete e' una destinazione legittima: molti uffici
        // conservano i documenti su un condiviso, e rifiutarla obbligherebbe a
        // salvare in locale e copiare a mano.
        let destination =
            ExportDestination::try_new(r"\\server\condiviso\Relazioni").expect("percorso valido");
        assert!(destination.path().is_absolute());
    }

    /// **Una cartella di rete si dichiara come tale.**
    ///
    /// Un prodotto che tacesse lascerebbe credere che i documenti siano
    /// protetti come l'archivio, e non lo sono.
    #[test]
    fn una_cartella_di_rete_porta_la_propria_avvertenza() {
        for percorso in [r"\\server\condivisa\documenti", r"//server/condivisa"] {
            let Ok(destinazione) = ExportDestination::try_new(std::path::Path::new(percorso))
            else {
                panic!("«{percorso}» deve essere una destinazione valida");
            };
            assert!(destinazione.is_network_share(), "«{percorso}» e' di rete");

            let Some(avvertenza) = destinazione.caution() else {
                panic!("«{percorso}» deve portare un'avvertenza");
            };
            assert!(
                avvertenza.contains("non può sapere chi"),
                "l'avvertenza deve dire CHE COSA il prodotto non sa: «{avvertenza}»"
            );
            assert!(
                avvertenza.contains("L'archivio resta protetto"),
                "e deve distinguere l'archivio dai documenti, altrimenti sembra \
                 che sia tutto esposto: «{avvertenza}»"
            );
        }
    }

    /// **Una cartella locale non porta avvertenze.**
    ///
    /// Un'avvertenza che compare sempre e' un'avvertenza che nessuno legge.
    #[test]
    fn una_cartella_locale_non_avverte_di_nulla() {
        let Ok(destinazione) =
            ExportDestination::try_new(std::path::Path::new(r"C:\Users\Prova\Documenti"))
        else {
            panic!("una cartella locale deve essere valida");
        };
        assert!(!destinazione.is_network_share());
        assert!(destinazione.caution().is_none());
    }
}
