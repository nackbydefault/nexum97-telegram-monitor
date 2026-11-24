//! **Un riferimento a materiale dell'archivio**, e uno solo per tutto il
//! prodotto.
//!
//! # Perché questo tipo vive qui e non dentro chi lo usa
//!
//! Perché più di una cosa, nel prodotto, **riferisce senza copiare**: un
//! workspace operativo (WS-01), un segnalibro (BOOK-01), e domani le note e le
//! ricerche salvate. Ognuna di esse ha bisogno di dire *che cosa* e *quale*.
//!
//! Fino a BOOK-01 il tipo viveva dentro il workspace. Darne uno anche ai
//! segnalibri avrebbe prodotto **due nozioni di riferimento**: due elenchi di
//! generi ammessi, due convalide, due punti in cui aggiungere «persona» il
//! giorno in cui le persone esisteranno. Il giorno in cui uno dei due si
//! muovesse senza l'altro, nessuno se ne accorgerebbe — è la cosa che questo
//! progetto ha rifiutato in ogni milestone della Fase 4, e la rifiuta anche qui.
//!
//! **Uno solo, condiviso.** Chi aggiunge un genere lo aggiunge per tutti, e
//! deve poterlo risolvere per tutti.
//!
//! # La garanzia: un riferimento non può contenere una copia
//!
//! [`ArchiveRef`] è **`Copy`**, e un tipo `Copy` non può contenere una
//! `String`. Il giorno in cui qualcuno vi aggiungesse il testo del contenuto
//! riferito — per mostrarlo senza rileggerlo, che è la cosa più naturale del
//! mondo — **il progetto non compilerebbe**.
//!
//! Ne segue la proprietà che serve davvero: **ciò che riferisce mostra sempre
//! ciò che l'archivio dice adesso**, perché non ha una seconda copia da cui
//! divergere.
//!
//! # I generi sono quelli che l'archivio sa risolvere
//!
//! Il congelamento ne elenca otto per il workspace: fonti, contenuti, persone,
//! CyberEvent, segnalibri, note, ricerche salvate, rapporti.
//!
//! Qui ce ne sono **cinque**, quelle che qualcosa può davvero produrre e che
//! l'archivio sa risolvere. Un genere che nulla può costruire sarebbe una
//! capacità dichiarata, protetta e mai raggiungibile: è il debito che questo
//! progetto ha già pagato con LAB-01, e non lo ripaga.
//!
//! Delle tre che mancano, due aspettano la loro milestone — **persona**
//! (PERS-01) e **ricerca salvata** (SEARCH-01). La terza è diversa, e va detta:
//!
//! **CyberEvent non ha un identificativo.** Non è una dimenticanza né una
//! milestone che manca: un grappolo è `{ragione, membri}`, ricalcolato a ogni
//! lettura dai contenuti che lo compongono. Non c'è nulla di stabile a cui un
//! riferimento possa puntare, e un riferimento a qualcosa che cambia identità
//! fra un calcolo e l'altro punterebbe ogni volta a una cosa diversa mentendo
//! di puntare alla stessa. Finché un grappolo non viene conservato con un
//! identificativo suo, **non si può riferire** — e dichiararlo è meglio che
//! aggiungere una variante che l'archivio non saprebbe risolvere.

use core::fmt;
use core::str::FromStr;

use crate::error::{DomainError, DomainResult};

/// Che genere di cosa dell'archivio si sta riferendo.
///
/// # Perché cinque varianti e non otto
///
/// Perché cinque sono quelle che l'archivio sa risolvere oggi. Vedere il
/// commento del modulo.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ArchiveRefKind {
    /// Una fonte monitorata.
    Source,
    /// Un contenuto acquisito.
    Content,
    /// Un rapporto prodotto.
    Report,
    /// Un segnalibro (BOOK-01).
    Bookmark,
    /// Un workspace operativo (NOTE-01).
    ///
    /// # Perche' arriva soltanto adesso
    ///
    /// Perche' fino a NOTE-01 nulla aveva ragione di riferire un workspace:
    /// un workspace raccoglie, non viene raccolto. Una nota su un workspace
    /// invece ha senso — «questo filone non ha portato a nulla» — e il
    /// congelamento la elenca.
    Workspace,
}

impl ArchiveRefKind {
    /// Etichetta stabile, quella che finisce nell'archivio.
    ///
    /// # Perché una parola e non l'indice della variante
    ///
    /// Perché un indice cambia significato il giorno in cui qualcuno riordina
    /// l'enumerazione, e le righe già scritte comincerebbero a riferire un'altra
    /// cosa senza che nulla cambi nell'archivio.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Source => "fonte",
            Self::Content => "contenuto",
            Self::Report => "rapporto",
            Self::Bookmark => "segnalibro",
            Self::Workspace => "workspace",
        }
    }

    /// Come si nomina a chi legge.
    #[must_use]
    pub const fn as_label(self) -> &'static str {
        match self {
            Self::Source => "Fonte",
            Self::Content => "Contenuto",
            Self::Report => "Rapporto",
            Self::Bookmark => "Segnalibro",
            Self::Workspace => "Raccoglitore",
        }
    }
}

impl fmt::Display for ArchiveRefKind {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl FromStr for ArchiveRefKind {
    type Err = DomainError;

    fn from_str(raw: &str) -> DomainResult<Self> {
        match raw {
            "fonte" => Ok(Self::Source),
            "contenuto" => Ok(Self::Content),
            "rapporto" => Ok(Self::Report),
            "segnalibro" => Ok(Self::Bookmark),
            "workspace" => Ok(Self::Workspace),
            altro => Err(crate::error::unknown_variant(
                "genere di riferimento all'archivio",
                altro,
            )),
        }
    }
}

/// Il riferimento: **che cosa** e **quale**, e nient'altro.
///
/// # Perché è `Copy`, e perché conta
///
/// Perché un tipo `Copy` non può contenere una `String`. Il giorno in cui
/// qualcuno vi aggiungesse il testo del contenuto riferito — per mostrarlo
/// senza rileggerlo — **il progetto non compilerebbe**.
///
/// È la stessa forma di garanzia di CTX-04, dove il testo di un messaggio non
/// entra in una relazione, e di CTX-05, dove due testi non si possono
/// scambiare: il compilatore, non una convenzione.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ArchiveRef {
    kind: ArchiveRefKind,
    target_id: i64,
}

impl ArchiveRef {
    /// Un riferimento a una cosa dell'archivio.
    ///
    /// # Errori
    ///
    /// Rifiuta un identificativo minore o uguale a zero: gli identificativi
    /// dell'archivio partono da uno, e uno zero significherebbe «nessuno».
    pub const fn to(kind: ArchiveRefKind, target_id: i64) -> DomainResult<Self> {
        // UN RIFERIMENTO A NULLA NON E' UN RIFERIMENTO.
        //
        // Gli identificativi dell'archivio partono da uno; uno zero o un
        // negativo verrebbero da un errore di calcolo, e una riga che punta a
        // nulla si legge come una riga che punta a qualcosa.
        if target_id <= 0 {
            return Err(DomainError::Empty { field: "target_id" });
        }
        Ok(Self { kind, target_id })
    }

    /// Che genere di cosa.
    #[must_use]
    pub const fn kind(self) -> ArchiveRefKind {
        self.kind
    }

    /// Quale.
    #[must_use]
    pub const fn target_id(self) -> i64 {
        self.target_id
    }
}

#[cfg(test)]
mod tests {
    use super::{ArchiveRef, ArchiveRefKind};
    use core::str::FromStr;

    /// Questo modulo, per le guardie strutturali.
    const THIS_MODULE: &str = include_str!("reference.rs");

    /// **Un riferimento non può contenere una copia, e lo impone il
    /// compilatore.**
    ///
    /// # Perché questa prova non può fallire in esecuzione
    ///
    /// Perché non deve. Se qualcuno aggiungesse a [`ArchiveRef`] il testo del
    /// contenuto riferito — per mostrarlo senza rileggerlo, che è la cosa più
    /// naturale del mondo — `ArchiveRef` smetterebbe di essere `Copy` e
    /// **questa riga non compilerebbe**.
    #[test]
    fn un_riferimento_non_puo_contenere_una_copia() {
        const fn richiede_copy<T: Copy>() {}
        richiede_copy::<ArchiveRef>();
        richiede_copy::<ArchiveRefKind>();
    }

    /// **Un riferimento a nulla non è un riferimento.**
    #[test]
    fn un_riferimento_a_nulla_non_si_costruisce() {
        for identificativo in [0_i64, -1, -999] {
            assert!(
                ArchiveRef::to(ArchiveRefKind::Content, identificativo).is_err(),
                "l'identificativo {identificativo} non punta a nulla"
            );
        }
        assert!(ArchiveRef::to(ArchiveRefKind::Content, 1).is_ok());
    }

    /// **I generi sono quelli che l'archivio sa risolvere.**
    ///
    /// # Il difetto che questa prova impedisce
    ///
    /// Un genere che nulla può costruire: una capacità dichiarata, protetta e
    /// mai raggiungibile. È il debito che questo progetto ha già pagato con
    /// LAB-01, e chi aggiunge un genere qui deve poterlo anche risolvere —
    /// **per ogni cosa che riferisce**, perché il tipo è uno solo.
    #[test]
    fn i_generi_sono_quelli_che_l_archivio_sa_risolvere() {
        let Some((produzione, _)) = THIS_MODULE.split_once("#[cfg(test)]\nmod tests {") else {
            panic!("il modulo deve avere un blocco di prove riconoscibile");
        };
        let Some(inizio) = produzione.find("pub enum ArchiveRefKind {") else {
            panic!("l'enumerazione deve esistere");
        };
        let Some(fine) = produzione[inizio..].find("\n}\n") else {
            panic!("l'enumerazione deve chiudersi");
        };
        let varianti: Vec<&str> = produzione[inizio..inizio + fine]
            .lines()
            .map(str::trim)
            .filter(|riga| riga.ends_with(','))
            .filter(|riga| !riga.starts_with("///") && !riga.starts_with("//"))
            .collect();
        assert_eq!(
            varianti.len(),
            5,
            "i generi ammessi sono cinque, quelli che l'archivio sa risolvere; chi ne aggiunge \
             uno deve poterlo anche risolvere \u{2014} {varianti:?}"
        );

        for assente in ["Person", "OperatorNote", "SavedSearch", "CyberEvent"] {
            assert!(
                !produzione.contains(&format!("    {assente},")),
                "il genere «{assente}» non ha ancora nulla che lo produca"
            );
        }
    }

    /// **Le etichette vanno e tornano identiche.**
    ///
    /// Un indice cambia significato il giorno in cui qualcuno riordina
    /// l'enumerazione; una parola no.
    #[test]
    fn le_etichette_vanno_e_tornano_identiche() {
        for genere in [
            ArchiveRefKind::Source,
            ArchiveRefKind::Content,
            ArchiveRefKind::Report,
            ArchiveRefKind::Bookmark,
        ] {
            let Ok(letto) = ArchiveRefKind::from_str(genere.as_str()) else {
                panic!("l'etichetta «{}» deve tornare indietro", genere.as_str());
            };
            assert_eq!(letto, genere);
            assert!(!genere.as_label().is_empty());
        }
        assert!(ArchiveRefKind::from_str("persona").is_err());
        assert!(ArchiveRefKind::from_str("").is_err());
    }

    /// **Due riferimenti alla stessa cosa sono lo stesso riferimento.**
    ///
    /// Serve a chi li raccoglie: due righe identiche non direbbero nulla di
    /// più, e chi legge conterebbe due volte lo stesso oggetto.
    #[test]
    fn due_riferimenti_alla_stessa_cosa_coincidono() {
        let (Ok(uno), Ok(due)) = (
            ArchiveRef::to(ArchiveRefKind::Content, 7),
            ArchiveRef::to(ArchiveRefKind::Content, 7),
        ) else {
            panic!("i riferimenti di prova devono essere validi");
        };
        assert_eq!(uno, due);

        let Ok(altro) = ArchiveRef::to(ArchiveRefKind::Source, 7) else {
            panic!("il riferimento di prova deve essere valido");
        };
        assert_ne!(uno, altro, "stesso numero, genere diverso: cosa diversa");
    }
}
