//! L'indirizzo pubblico di una fonte, come è stato visto (CONTEXT-02,
//! ADR-0165).
//!
//! Serve a «Apri la fonte» quando il collegamento al messaggio non c'è. **Non
//! è un'identità**: un nome utente può cambiare padrone, e l'identità della
//! fonte resta il suo numero. Si conserva l'ultimo visto, con l'istante.

use lisi_core::{SourceId, Timestamp};
use rusqlite::OptionalExtension;

use crate::database::Database;
use crate::error::StorageResult;
use crate::repository::{instant, millis};

/// L'indirizzo di una fonte e quando è stato visto.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SourceAddress {
    /// Il nome utente pubblico, senza chiocciola.
    pub address: String,
    /// Quando è stato visto l'ultima volta.
    pub observed_at: Timestamp,
}

impl Database {
    /// Registra l'indirizzo visto per una fonte, sostituendo quello di prima.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se lo schema rifiuta la forma dell'indirizzo, se
    /// la fonte non esiste o se la scrittura non riesce.
    pub fn record_source_address(
        &self,
        source: SourceId,
        address: &str,
        observed_at: Timestamp,
    ) -> StorageResult<()> {
        self.connection.execute(
            "INSERT INTO source_public_addresses (source_id, address, observed_at)
             VALUES (?1, ?2, ?3)
             ON CONFLICT (source_id) DO UPDATE SET
                 address = excluded.address,
                 observed_at = excluded.observed_at",
            rusqlite::params![source.get(), address, millis(observed_at)],
        )?;
        Ok(())
    }

    /// L'indirizzo visto per una fonte, se ne è stato visto uno.
    ///
    /// # Errori
    ///
    /// Restituisce un errore se la lettura non riesce.
    pub fn source_address(&self, source: SourceId) -> StorageResult<Option<SourceAddress>> {
        Ok(self
            .connection
            .query_row(
                "SELECT address, observed_at FROM source_public_addresses WHERE source_id = ?1",
                [source.get()],
                |row| {
                    Ok(SourceAddress {
                        address: row.get(0)?,
                        observed_at: instant(row.get(1)?),
                    })
                },
            )
            .optional()?)
    }
}

#[cfg(test)]
mod tests {
    use lisi_core::model::{NewSource, SourceKind};
    use lisi_core::text::{DisplayName, SourceIdentifier};

    use crate::test_support::{actor, database, later};

    /// **L'indirizzo si registra, si aggiorna, ha la forma di un indirizzo
    /// pubblico e se ne va con la fonte** (CONTEXT-02, criterio 3).
    #[test]
    fn l_indirizzo_si_registra_si_aggiorna_e_se_ne_va_con_la_fonte() {
        let archivio = database();
        let (Ok(identificativo), Ok(nome)) = (
            SourceIdentifier::try_new("-1001"),
            DisplayName::try_new("Canale di prova"),
        ) else {
            panic!("valori validi");
        };
        let Ok(fonte) = archivio.insert_source(
            &NewSource {
                kind: SourceKind::Channel,
                identifier: identificativo,
                display_name: nome,
                authorized_by: actor("operatore.prova"),
                active: true,
            },
            later(0),
        ) else {
            panic!("la fonte deve registrarsi");
        };
        assert_eq!(archivio.source_address(fonte).ok(), Some(None));
        let Ok(()) = archivio.record_source_address(fonte, "canale_cyber", later(1)) else {
            panic!("l'indirizzo deve registrarsi");
        };
        let Ok(()) = archivio.record_source_address(fonte, "canale_nuovo", later(2)) else {
            panic!("l'indirizzo deve aggiornarsi");
        };
        let Ok(Some(visto)) = archivio.source_address(fonte) else {
            panic!("l'indirizzo deve leggersi");
        };
        assert_eq!(visto.address, "canale_nuovo");
        assert_eq!(visto.observed_at, later(2));
        for sbagliato in [
            "abc",
            "1canale",
            "canale-cyber",
            "canale cyber",
            &"a".repeat(33),
        ] {
            assert!(
                archivio
                    .record_source_address(fonte, sbagliato, later(3))
                    .is_err(),
                "lo schema deve rifiutare «{sbagliato}»"
            );
        }
        let Ok(_) = archivio
            .connection
            .execute("DELETE FROM sources WHERE id = ?1", [fonte.get()])
        else {
            panic!("una fonte si toglie ancora");
        };
        assert_eq!(archivio.source_address(fonte).ok(), Some(None));
    }
}
