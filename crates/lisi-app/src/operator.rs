//! Chi risulta aver agito, in questa versione del prodotto.
//!
//! # Perché un modulo per un valore solo
//!
//! Fino a oggi sedici schermate dichiaravano ciascuna il proprio attore
//! dell'audit, e lo scrivevano per esteso: sedici copie della stessa stringa.
//! Finché resta la stessa non fa danno.
//!
//! Il danno arriva il giorno in cui l'operatore viene autenticato davvero — che
//! è HUB-03 e la modalità squadra. Quindici copie cambierebbero e una no, e
//! l'audit conterrebbe atti attribuiti a una persona accanto ad atti attribuiti
//! a un segnaposto, **senza che nulla lo segnali**: le due righe si assomigliano
//! troppo perché qualcuno le noti rileggendo.
//!
//! Qui la copia è una, ed è il punto in cui HUB-03 dovrà intervenire.
//!
//! # Perché il segnaposto e non il nome dell'utente di Windows
//!
//! Perché il prodotto non ha verificato niente. Il nome dell'utente di Windows
//! direbbe *chi ha fatto l'accesso alla macchina*, e verrebbe letto come *chi ha
//! compiuto l'atto*. Sono due affermazioni diverse, e la seconda questo
//! programma non è in grado di farla.

use lisi_core::model::identity::{LOCAL_OPERATOR, OperatorId};
use lisi_core::text::Actor;
use lisi_services::ServiceResult;

/// Nome dell'operatore corrente, per i servizi che accettano un testo.
pub const NAME: &str = LOCAL_OPERATOR;

/// Chi sta agendo su questa postazione.
///
/// Oggi è sempre il segnaposto locale, e lo dichiara.
#[must_use]
pub fn current() -> OperatorId {
    OperatorId::local()
}

/// Soggetto da scrivere nell'audit.
///
/// # Errori
///
/// Restituisce un errore se il valore non supera la validazione di [`Actor`].
/// Per il segnaposto non può accadere; la firma resta fallibile perché con
/// HUB-03 l'identificativo arriverà da fuori.
pub fn audit_actor() -> ServiceResult<Actor> {
    Ok(current().audit_actor()?)
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::{NAME, audit_actor, current};

    /// **L'operatore corrente si dichiara segnaposto.**
    ///
    /// Sostituiva quattro prove identiche sparse in quattro schermate, che
    /// fissavano lo stesso valore ciascuna per conto proprio.
    #[test]
    fn l_operatore_corrente_si_dichiara_segnaposto() {
        assert!(
            current().is_local_placeholder(),
            "l'operatore corrente non si dichiara piu' un segnaposto: se qualcuno \
             viene autenticato davvero, questa prova va riscritta con cognizione"
        );
        assert_eq!(current().as_str(), NAME);

        let Ok(attore) = audit_actor() else {
            panic!("l'attore dell'audit deve potersi costruire");
        };
        assert_eq!(attore.as_str(), NAME);
    }

    /// I sorgenti di produzione di questo crate.
    ///
    /// Come in `lisi-telegram::prohibitions`: non trovarli e' un fallimento, non
    /// un rinvio. Una guardia che non legge cio' che sorveglia e passa lo stesso
    /// dichiara sicuro cio' che non ha guardato.
    fn sorgenti() -> Vec<(String, String)> {
        let cartella = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src");
        let Ok(voci) = std::fs::read_dir(&cartella) else {
            panic!("i sorgenti di lisi-app devono potersi leggere: {cartella:?}");
        };

        let mut letti = Vec::new();
        for voce in voci.flatten() {
            let percorso = voce.path();
            if percorso.extension().is_none_or(|ext| ext != "rs") {
                continue;
            }
            let Some(nome) = percorso.file_name().and_then(|nome| nome.to_str()) else {
                continue;
            };
            if nome == "operator.rs" {
                continue;
            }
            let Ok(contenuto) = std::fs::read_to_string(&percorso) else {
                panic!("il sorgente {nome} deve potersi leggere");
            };
            letti.push((nome.to_owned(), contenuto));
        }

        assert!(
            letti.len() > 10,
            "trovati solo {} sorgenti: la guardia non sta guardando cio' che crede",
            letti.len()
        );
        letti
    }

    /// **Nessuna schermata dichiara per conto proprio chi ha agito.**
    ///
    /// # Il difetto che questa prova impedisce
    ///
    /// Sedici copie di una stringa non si aggiornano insieme. Questa prova
    /// diventa rossa appena qualcuno ne riscrive una diciassettesima, che e' il
    /// momento in cui costa poco correggerla.
    #[test]
    fn nessuna_schermata_dichiara_per_conto_proprio_chi_ha_agito() {
        // Il valore si compone qui invece di comparire come stringa: scritto per
        // esteso, questa prova troverebbe se' stessa nel proprio sorgente.
        let segnaposto: String = ["operatore", ".locale"].concat();

        for (nome, contenuto) in sorgenti() {
            assert!(
                !contenuto.contains(&segnaposto),
                "{nome} scrive di nuovo per esteso il nome dell'operatore: \
                 usare crate::operator, dove la copia e' una sola e HUB-03 sa \
                 dove intervenire"
            );
        }
    }
}
