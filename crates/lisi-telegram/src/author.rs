//! Chi ha scritto un messaggio, quando si sa.
//!
//! # Da dove viene questo modulo
//!
//! Si chiamava `permalink` e conteneva anche il **collegamento composto** a un
//! messaggio: `t.me/c/<chat>/<messaggio>`, ricavato dai due identificativi che
//! l'aggiornamento porta con sé.
//!
//! LINK-01 lo ha tolto. Non perché non funzionasse — funzionava, per i membri
//! di quella conversazione — ma perché quell'indirizzo **finiva
//! nell'archivio**, nella colonna che dice dove sta il messaggio, accanto al
//! testo acquisito e all'istante dichiarato dalla fonte. Un indirizzo composto
//! da noi è una **deduzione**, e in un archivio che ha valore probatorio non
//! sta nella stessa colonna dei fatti osservati. Il congelamento lo scrive:
//! **non si fabbrica** un collegamento che Telegram non fornisce.
//!
//! Il collegamento ufficiale si chiede ora con
//! [`crate::connector::TelegramConnector::message_link`], e il dominio dei due
//! collegamenti — quello al messaggio e quello alla fonte, che restano distinti
//! — vive in [`crate::link`].
//!
//! # Le due convenzioni di Telegram che quel calcolo usava
//!
//! Si scrivono qui perché la conoscenza non vada persa con il codice, e perché
//! chi in futuro ne avesse bisogno non debba ritrovarle a tentativi. Erano
//! stabili e documentate, ma non ovvie, e sbagliarne una produceva un
//! collegamento che si apriva sul messaggio **sbagliato** invece di non
//! aprirsi.
//!
//! **L'identificativo di messaggio di TDLib non è quello del server.** TDLib lo
//! moltiplica per 2^20 per farci stare i messaggi pianificati e le bozze: il
//! messaggio numero uno ha identificativo 1048576.
//!
//! **L'identificativo di chat dice già di che tipo di chat si tratta.**
//! Supergruppi e canali hanno identificativi minori di -1000000000000, con il
//! prefisso `-100` davanti all'identificativo interno. I gruppi semplici no, e
//! per loro non esiste alcun collegamento permanente.

/// Identificativo numerico dell'autore, quando il mittente e' una persona.
///
/// Restituisce `None` quando il messaggio non e' firmato da un utente: nei
/// **canali** i messaggi portano come mittente il canale stesso, e attribuirli
/// a una persona sarebbe falso. `None` dice «non lo sappiamo», che e' la verita'.
///
/// L'identificativo e' quello di Telegram e **non cambia** finche' l'account
/// esiste. Non e' un nome: non dice nulla a chi legge, ma regge nel tempo, che
/// e' l'opposto di quanto fa uno username.
#[must_use]
pub fn author_identifier(sender_type: Option<&str>, user_id: Option<i64>) -> Option<String> {
    if sender_type? != "messageSenderUser" {
        return None;
    }

    let user_id = user_id?;
    if user_id <= 0 {
        return None;
    }

    Some(user_id.to_string())
}

#[cfg(test)]
mod tests {
    use super::author_identifier;

    #[test]
    fn a_message_written_by_a_person_carries_that_person_identifier() {
        assert_eq!(
            author_identifier(Some("messageSenderUser"), Some(42)).as_deref(),
            Some("42")
        );
    }

    #[test]
    fn a_channel_post_is_not_attributed_to_a_person() {
        // Nei canali il mittente e' il canale. Attribuire il messaggio a una
        // persona sarebbe una falsa attribuzione in un archivio che ha valore
        // probatorio: `None` dice «non lo sappiamo», ed e' la verita'.
        assert_eq!(author_identifier(Some("messageSenderChat"), Some(42)), None);
    }

    #[test]
    fn an_absent_or_implausible_sender_yields_nothing() {
        assert_eq!(author_identifier(None, Some(42)), None);
        assert_eq!(author_identifier(Some("messageSenderUser"), None), None);
        assert_eq!(author_identifier(Some("messageSenderUser"), Some(0)), None);
        assert_eq!(author_identifier(Some("messageSenderUser"), Some(-7)), None);
    }
}
