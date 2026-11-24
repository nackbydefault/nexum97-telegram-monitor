//! Note dell'operatore: **le parole di una persona su qualcosa che sta
//! nell'archivio** (NOTE-01).
//!
//! # Che cos'è una nota, e perché non è una revisione
//!
//! Una revisione porta già un campo per le parole dell'operatore, ed è la
//! **motivazione di una decisione**: esiste perché una decisione è stata presa,
//! è legata al passaggio di stato, e senza quella decisione non avrebbe ragione
//! di esistere.
//!
//! Una nota **non ha occasione**. Si scrive quando si vuole, e su cose che non
//! hanno alcuna revisione: una fonte, un rapporto, un workspace. È la differenza
//! fra «perché ho deciso così» e «annoto questo».
//!
//! È la stessa forma di distinzione che tiene separati workspace e segnalibri:
//! non *che cosa contengono*, ma **che cosa le occasiona**.
//!
//! # La nota non tocca la prova
//!
//! Il congelamento lo scrive con queste parole: «non modificano mai la prova
//! originale». Il modo di rispettarlo non è ricordarsene: una nota vive in una
//! tabella sua, riferisce con [`crate::model::reference::ArchiveRef`], e nulla
//! nel percorso che la scrive sa nominare il contenuto.
//!
//! # Il testo di una nota non si riscrive
//!
//! Una nota porta **un autore e un istante**. Se il testo potesse cambiare
//! dopo, quei due valori mentirebbero: direbbero che quella persona ha scritto
//! quella frase quel giorno, e non sarebbe più vero.
//!
//! Perciò non esiste un modo di modificarla. Una nota sbagliata si **ritira** —
//! e il ritiro porta a sua volta chi e quando — e se ne scrive un'altra. La
//! nota ritirata **resta visibile**: qualcuno può averci lavorato sopra, e
//! farla sparire riscriverebbe che cosa quella persona aveva davanti.
//!
//! Non è severità: è la stessa disciplina del workspace che non si riapre e
//! dell'audit che non si cancella.
//!
//! # Una nota non si annota su un segnalibro
//!
//! Un segnalibro è esso stesso un riferimento. Una nota su di lui sarebbe una
//! nota **sul dito invece che sulla cosa indicata**, e chi la scrivesse
//! intendeva la cosa. Il costruttore lo rifiuta, e l'archivio anche.

use crate::NoteId;
use crate::error::{DomainError, DomainResult};
use crate::model::reference::{ArchiveRef, ArchiveRefKind};
use crate::text::{Actor, Note};
use crate::time::Timestamp;

/// Una nota da scrivere.
///
/// # Perché i campi sono privati
///
/// Perché il tipo garantisce due cose che una struttura aperta non
/// garantirebbe: che non si annoti un segnalibro, e che una nota abbia parole.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewOperatorNote {
    reference: ArchiveRef,
    body: Note,
}

impl NewOperatorNote {
    /// Scrive una nota su una cosa dell'archivio.
    ///
    /// # Errori
    ///
    /// Rifiuta un riferimento a un **segnalibro**: un segnalibro è esso stesso
    /// un riferimento, e annotarlo sarebbe annotare il dito invece della cosa
    /// indicata.
    ///
    /// Rifiuta un testo **vuoto**: una nota senza parole non è una nota, e una
    /// riga vuota con un autore e un istante direbbe che qualcuno ha annotato
    /// qualcosa senza dire niente.
    pub fn about(reference: ArchiveRef, body: &Note) -> DomainResult<Self> {
        if matches!(reference.kind(), ArchiveRefKind::Bookmark) {
            return Err(DomainError::Empty {
                field: "note_target",
            });
        }
        // IL TIPO DEL TESTO E' QUELLO CHE C'ERA GIA'.
        //
        // `Note` e' «annotazione libera dell'operatore», e accetta il vuoto
        // perche' altrove e' facoltativa — la descrizione di un workspace, la
        // motivazione di una revisione. Il divieto del vuoto appartiene a CHI
        // RICHIEDE PAROLE, non al tipo condiviso: darglielo avrebbe rotto gli
        // altri usi, e creare un secondo tipo di testo dell'operatore avrebbe
        // creato una seconda nozione da tenere allineata.
        if body.as_str().trim().is_empty() {
            return Err(DomainError::Empty { field: "note_body" });
        }
        Ok(Self {
            reference,
            body: body.clone(),
        })
    }

    /// Su che cosa.
    #[must_use]
    pub const fn reference(&self) -> ArchiveRef {
        self.reference
    }

    /// Le parole.
    #[must_use]
    pub const fn body(&self) -> &Note {
        &self.body
    }
}

/// Il ritiro di una nota: chi e quando.
///
/// # Perché i due valori stanno insieme
///
/// Perché una nota ritirata da nessuno, o ritirata in nessun istante, sarebbe
/// un ritiro a metà. Il tipo li tiene insieme, e l'archivio lo impone con un
/// vincolo.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NoteWithdrawal {
    /// Chi l'ha ritirata.
    pub by: Actor,
    /// Quando.
    pub at: Timestamp,
}

/// Una nota conservata.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OperatorNote {
    /// Identificativo stabile.
    pub id: NoteId,
    /// Su che cosa.
    pub reference: ArchiveRef,
    /// Le parole, come sono state scritte.
    pub body: Note,
    /// Chi l'ha scritta.
    pub author: Actor,
    /// Quando.
    pub written_at: Timestamp,
    /// Se e da chi è stata ritirata.
    pub withdrawal: Option<NoteWithdrawal>,
}

impl OperatorNote {
    /// Se vale ancora.
    ///
    /// # Perché una domanda e non un confronto
    ///
    /// Perché chi mostra la riga deve poter chiedere «vale ancora?» senza
    /// ispezionare la forma del ritiro.
    #[must_use]
    pub const fn stands(&self) -> bool {
        self.withdrawal.is_none()
    }

    /// Che cosa questa nota è, detto a chi legge.
    ///
    /// # Perché la frase la compone il modello
    ///
    /// DEC-252: una schermata **riceve** frasi già composte invece di
    /// ricomporle. Due schermate che compongono la stessa frase la compongono
    /// diversa, e la differenza si vede solo mettendole vicine — cosa che non
    /// succede mai.
    ///
    /// # Che cosa questa frase NON contiene
    ///
    /// Le parole della nota. Sono il suo corpo, si mostrano per intero, e
    /// ripeterle qui darebbe due posti da cui leggerle.
    #[must_use]
    pub fn as_sentence(&self) -> String {
        match self.withdrawal.as_ref() {
            None => format!(
                "Scritta da {} il {}.",
                self.author.on_screen(),
                self.written_at.to_readable_local()
            ),
            // LA NOTA RITIRATA RESTA, E DICE ENTRAMBE LE COSE.
            //
            // Chi l'ha scritta e quando non smettono di essere veri perche' e'
            // stata ritirata: qualcuno puo' averci lavorato sopra, e sapere
            // solo che «e' ritirata» non direbbe che cosa quella persona aveva
            // davanti.
            Some(ritiro) => format!(
                "Scritta da {} il {}, ritirata da {} il {}. Resta visibile perch\u{e9} \
                 qualcuno pu\u{f2} averci lavorato sopra.",
                self.author.on_screen(),
                self.written_at.to_readable_local(),
                ritiro.by.on_screen(),
                ritiro.at.to_readable_local()
            ),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{NewOperatorNote, NoteWithdrawal, OperatorNote};
    use crate::NoteId;
    use crate::model::reference::{ArchiveRef, ArchiveRefKind};
    use crate::text::{Actor, Note};
    use crate::time::Timestamp;

    /// Questo modulo, per le guardie strutturali.
    const THIS_MODULE: &str = include_str!("note.rs");

    const ORA: i64 = 1_700_000_000_000;

    fn attore() -> Actor {
        let Ok(attore) = Actor::try_new("operatore.prova") else {
            panic!("l'attore di prova deve essere valido");
        };
        attore
    }

    fn testo(raw: &str) -> Note {
        let Ok(nota) = Note::try_new(raw) else {
            panic!("il testo di prova deve essere valido");
        };
        nota
    }

    fn riferimento(kind: ArchiveRefKind, id: i64) -> ArchiveRef {
        let Ok(riferimento) = ArchiveRef::to(kind, id) else {
            panic!("il riferimento di prova deve essere valido");
        };
        riferimento
    }

    fn nota(ritiro: Option<NoteWithdrawal>) -> OperatorNote {
        OperatorNote {
            id: NoteId::new(1),
            reference: riferimento(ArchiveRefKind::Content, 42),
            body: testo("la fonte ha ripubblicato lo stesso testo tre volte"),
            author: attore(),
            written_at: Timestamp::from_millis(ORA),
            withdrawal: ritiro,
        }
    }

    /// **Una nota non si annota su un segnalibro.**
    ///
    /// # Il difetto che questa prova impedisce
    ///
    /// Una nota sul dito invece che sulla cosa indicata. Chi la scrivesse
    /// intendeva la cosa, e chi la rileggesse la troverebbe attaccata a un
    /// puntatore — che domani può essere tolto senza che il contenuto cambi.
    #[test]
    fn una_nota_non_si_annota_su_un_segnalibro() {
        assert!(
            NewOperatorNote::about(riferimento(ArchiveRefKind::Bookmark, 1), &testo("qualcosa"))
                .is_err(),
            "annotare un segnalibro sarebbe annotare il dito"
        );
        for genere in [
            ArchiveRefKind::Source,
            ArchiveRefKind::Content,
            ArchiveRefKind::Report,
            ArchiveRefKind::Workspace,
        ] {
            assert!(
                NewOperatorNote::about(riferimento(genere, 1), &testo("qualcosa")).is_ok(),
                "«{}» si puo' annotare",
                genere.as_str()
            );
        }
    }

    /// **Una nota senza parole non è una nota.**
    ///
    /// # Il difetto che questa prova impedisce
    ///
    /// Una riga con un autore e un istante e nient'altro, che dice che qualcuno
    /// ha annotato qualcosa senza dire niente. Chi la rilegge non sa se manchi
    /// il testo o se la persona non avesse nulla da dire.
    #[test]
    fn una_nota_senza_parole_non_e_una_nota() {
        for vuoto in ["", "   ", "\t", "\n  \n"] {
            assert!(
                NewOperatorNote::about(riferimento(ArchiveRefKind::Content, 1), &testo(vuoto))
                    .is_err(),
                "«{vuoto:?}» non e' una nota"
            );
        }
        assert!(
            NewOperatorNote::about(riferimento(ArchiveRefKind::Content, 1), &testo("x")).is_ok()
        );
    }

    /// **Non esiste un modo di riscrivere una nota.**
    ///
    /// # Il difetto che questa prova impedisce
    ///
    /// Un `set_body`, o un campo pubblico, o qualunque cosa che permetta di
    /// cambiare il testo dopo. Una nota porta un autore e un istante: se il
    /// testo cambiasse, quei due valori direbbero che quella persona ha scritto
    /// quella frase quel giorno, e sarebbe falso.
    ///
    /// # Perché la guardia guarda il sorgente
    ///
    /// Perché il compilatore non può vietare un metodo che ancora non esiste.
    /// Qui la garanzia è **l'assenza di una capacità**, e l'assenza si
    /// sorveglia cercandola.
    #[test]
    fn non_esiste_un_modo_di_riscrivere_una_nota() {
        let Some((produzione, _)) = THIS_MODULE.split_once("#[cfg(test)]\nmod tests {") else {
            panic!("il modulo deve avere un blocco di prove riconoscibile");
        };
        for scrittura in [
            "fn set_body",
            "fn edit",
            "fn modifica",
            "fn riscrivi",
            "fn update",
            "&mut self",
        ] {
            assert!(
                !produzione.contains(scrittura),
                "il modulo espone «{scrittura}»: una nota si ritira, non si riscrive"
            );
        }
        // E il testo della nota da scrivere e' PRIVATO: un campo pubblico
        // sarebbe la stessa capacita' con un altro nome.
        const INTESTAZIONE: &str = "pub struct NewOperatorNote {";
        let Some(inizio) = produzione.find(INTESTAZIONE) else {
            panic!("il tipo deve esistere");
        };
        // SI GUARDANO I CAMPI, NON L'INTESTAZIONE.
        //
        // La riga che apre la struttura comincia essa stessa con «pub»: una
        // guardia che la includesse sarebbe rossa sempre, e quindi verrebbe
        // tolta.
        let campi = &produzione[inizio + INTESTAZIONE.len()..];
        let Some(fine) = campi.find("\n}\n") else {
            panic!("il tipo deve chiudersi");
        };
        assert!(
            !campi[..fine].contains("pub "),
            "i campi sono privati: un campo pubblico sarebbe la riscrittura con un altro nome"
        );
    }

    /// **La nota a schermo nomina l'operatore della postazione e l'ora come le
    /// altre schermate** (E2E01-16, E2E01-19): mai «operatore.locale», e l'ora
    /// passa da `to_readable_local` (senza fuso noto, quella resa è l'UTC).
    #[test]
    fn la_nota_a_schermo_non_mostra_codici() {
        let Ok(locale) = Actor::try_new(crate::model::identity::LOCAL_OPERATOR) else {
            panic!("nome valido");
        };
        let mut scritta = nota(None);
        scritta.author = locale;
        let frase = scritta.as_sentence();
        assert!(!frase.contains("operatore.locale"), "{frase}");
        assert!(frase.contains("operatore di questa postazione"), "{frase}");
        assert!(
            frase.contains(&Timestamp::from_millis(ORA).to_readable_local()),
            "{frase}"
        );
    }

    /// **La frase di una nota ritirata dice entrambe le cose.**
    ///
    /// # Perché conta
    ///
    /// Perché chi l'ha scritta e quando non smettono di essere veri: qualcuno
    /// può averci lavorato sopra, e sapere solo che è ritirata non direbbe che
    /// cosa quella persona aveva davanti.
    #[test]
    fn la_frase_di_una_nota_ritirata_dice_entrambe_le_cose() {
        let viva = nota(None);
        assert!(viva.stands());
        let frase = viva.as_sentence();
        assert!(frase.contains("operatore.prova"), "{frase}");
        assert!(!frase.contains("ritirata"), "{frase}");

        let Ok(chi) = Actor::try_new("altro.operatore") else {
            panic!("l'attore di prova deve essere valido");
        };
        let ritirata = nota(Some(NoteWithdrawal {
            by: chi,
            at: Timestamp::from_millis(ORA + 3_600_000),
        }));
        assert!(!ritirata.stands());
        let frase = ritirata.as_sentence();
        assert!(
            frase.contains("operatore.prova"),
            "chi l'ha scritta \u{2014} {frase}"
        );
        assert!(
            frase.contains("altro.operatore"),
            "chi l'ha ritirata \u{2014} {frase}"
        );
        assert!(frase.contains("ritirata"), "{frase}");
    }

    /// **La frase non ripete le parole della nota.**
    ///
    /// # Il difetto che questa prova impedisce
    ///
    /// Due posti da cui leggere lo stesso testo. Il corpo si mostra per intero;
    /// la frase dice **chi e quando**, che è ciò che il corpo non dice.
    #[test]
    fn la_frase_non_ripete_le_parole() {
        let viva = nota(None);
        assert!(
            !viva.as_sentence().contains("ripubblicato"),
            "la frase ripete il corpo: darebbe due posti da cui leggerlo"
        );
    }
}
