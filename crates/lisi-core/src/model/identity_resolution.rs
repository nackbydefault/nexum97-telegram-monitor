//! La ricerca puntuale: i cinque esiti (PR-09, ADR-0125).
//!
//! # Cinque, e perché cinque
//!
//! Un esito in più si giustifica **solo quando cambia che cosa l'operatore deve
//! fare**. [`ResolutionOutcome::Found`] si legge; [`ResolutionOutcome::NotAvailable`]
//! chiude la domanda — Telegram ha risposto, in modo definitivo, che il dato non
//! è fornito a questo account; [`ResolutionOutcome::InvalidRequest`] chiede di
//! correggere l'ingresso; [`ResolutionOutcome::Temporary`] di riprovare più
//! tardi, a mano; [`ResolutionOutcome::Operational`] che qualcuno intervenga.
//!
//! Gli ultimi tre **non sono risultati**, e non si confondono con il secondo:
//! scambiarli farebbe credere che un dato non esista quando nessuno lo ha
//! davvero chiesto.

/// Il genere di un ingresso.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ResolutionInputKind {
    /// Un nome utente.
    Username,
    /// Un numero di telefono.
    PhoneNumber,
    /// Un identificativo Telegram.
    TelegramId,
    /// Un collegamento.
    Link,
}

impl ResolutionInputKind {
    /// Tutti, nell'ordine della schermata.
    pub const ALL: [Self; 4] = [
        Self::Username,
        Self::PhoneNumber,
        Self::TelegramId,
        Self::Link,
    ];

    /// Il nome stabile, per il registro.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Username => "nome_utente",
            Self::PhoneNumber => "numero",
            Self::TelegramId => "identificativo",
            Self::Link => "collegamento",
        }
    }

    /// La parola per l'operatore.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Username => "nome utente",
            Self::PhoneNumber => "numero di telefono",
            Self::TelegramId => "identificativo Telegram",
            Self::Link => "collegamento",
        }
    }

    /// Dal nome stabile.
    #[must_use]
    pub fn from_stored(valore: &str) -> Option<Self> {
        Self::ALL
            .into_iter()
            .find(|genere| genere.as_str() == valore)
    }
}

/// Ciò che Telegram ha restituito, **e nient'altro**.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedIdentity {
    /// Il genere, nella parola dell'operatore: persona, bot, canale, gruppo…
    pub kind: String,
    /// L'identificativo Telegram.
    pub telegram_id: i64,
    /// Il nome mostrato, così come Telegram lo dà. Può essere vuoto.
    pub name: String,
    /// Il nome utente, quando Telegram ne restituisce uno: il primo degli
    /// attivi.
    pub username: Option<String>,
    /// Il nome proprio e il cognome, separati, quando Telegram li dà
    /// (ADR-0153). Vuoti per una chat.
    pub first_name: String,
    /// Il cognome.
    pub last_name: String,
    /// **Tutti** gli username attivi restituiti, nell'ordine di Telegram.
    pub usernames: Vec<String>,
    /// Il telefono **mascherato**, soltanto se Telegram lo ha restituito: il
    /// numero pieno non arriva mai qui (ADR-0153, decisione 2).
    pub masked_phone: Option<crate::model::MaskedPhoneNumber>,
    /// Che cosa, fra ciò che ci si poteva aspettare, **non** è arrivato, e
    /// perché. L'assenza si mostra: nasconderla farebbe sembrare completo un
    /// risultato parziale.
    pub not_obtained: Vec<String>,
}

/// L'esito di una ricerca puntuale.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResolutionOutcome {
    /// Telegram ha restituito il dato all'account.
    Found(ResolvedIdentity),
    /// Telegram ha risposto, **in modo definitivo**, che il dato non è fornito
    /// a questo account.
    NotAvailable {
        /// Perché, quando lo si sa.
        reason: String,
    },
    /// La richiesta non è stata eseguita perché l'ingresso non è ammissibile,
    /// o Telegram l'ha respinta come malformata.
    InvalidRequest {
        /// Perché.
        reason: String,
    },
    /// La richiesta non è arrivata a una risposta per una causa transitoria.
    Temporary {
        /// Perché.
        reason: String,
        /// L'attesa che Telegram ha indicato, in secondi, quando l'ha indicata.
        wait_seconds: Option<u32>,
    },
    /// La richiesta non può arrivare a una risposta finché qualcuno non
    /// interviene.
    Operational {
        /// Perché, e che cosa fare.
        reason: String,
        /// Codice e messaggio di Telegram, per la diagnostica.
        technical: Option<String>,
    },
}

impl ResolutionOutcome {
    /// Il nome stabile, per il registro.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Found(_) => "trovato",
            Self::NotAvailable { .. } => "dato_non_disponibile",
            Self::InvalidRequest { .. } => "richiesta_non_valida",
            Self::Temporary { .. } => "errore_temporaneo",
            Self::Operational { .. } => "errore_operativo",
        }
    }

    /// La parola per l'operatore.
    #[must_use]
    pub const fn label(&self) -> &'static str {
        match self {
            Self::Found(_) => "Trovato",
            Self::NotAvailable { .. } => "Dato non disponibile",
            Self::InvalidRequest { .. } => "Richiesta non valida",
            Self::Temporary { .. } => "Errore temporaneo",
            Self::Operational { .. } => "Errore operativo",
        }
    }

    /// Che cosa fa l'operatore.
    #[must_use]
    pub fn what_to_do(&self) -> String {
        match self {
            Self::Found(_) => String::from(
                "Leggere il risultato. Trovare un profilo non è un giudizio su una persona.",
            ),
            Self::NotAvailable { .. } => String::from(
                "Nulla: Telegram non dà questo dato a questo account, e non va cercato altrove.",
            ),
            Self::InvalidRequest { .. } => String::from("Correggere l'ingresso e riprovare."),
            Self::Temporary { wait_seconds, .. } => wait_seconds.map_or_else(
                || String::from("Riprovare più tardi, a mano. Il dato potrebbe esserci."),
                |secondi| {
                    format!(
                        "Riprovare a mano dopo {secondi} secondi, l'attesa che Telegram ha \
                         chiesto. Il dato potrebbe esserci."
                    )
                },
            ),
            Self::Operational { .. } => String::from(
                "Seguire l'indicazione: un nuovo accesso, l'amministratore o la diagnostica.",
            ),
        }
    }

    /// Il motivo, o per `Trovato` che cosa è arrivato.
    #[must_use]
    pub fn sentence(&self) -> String {
        match self {
            Self::Found(trovato) => {
                let mut frase = format!(
                    "Telegram ha restituito: {}, identificativo {}",
                    trovato.kind, trovato.telegram_id
                );
                if !trovato.name.is_empty() {
                    frase.push_str(&format!(", nome «{}»", trovato.name));
                }
                // TUTTI GLI USERNAME ATTIVI (ADR-0153, DG-07): quando ce n'è
                // più d'uno si dicono tutti, nell'ordine di Telegram.
                match trovato.usernames.as_slice() {
                    [] => {
                        if let Some(nome_utente) = &trovato.username {
                            frase.push_str(&format!(", nome utente @{nome_utente}"));
                        }
                    }
                    [solo] => frase.push_str(&format!(", nome utente @{solo}")),
                    tutti => frase.push_str(&format!(
                        ", nomi utente attivi {}",
                        tutti
                            .iter()
                            .map(|nome| format!("@{nome}"))
                            .collect::<Vec<_>>()
                            .join(", ")
                    )),
                }
                if let Some(telefono) = &trovato.masked_phone {
                    frase.push_str(&format!(
                        ", telefono mostrato da Telegram {} (si conservano soltanto le ultime \
                         cifre)",
                        telefono.as_str()
                    ));
                }
                frase.push('.');
                for mancante in &trovato.not_obtained {
                    frase.push(' ');
                    frase.push_str(mancante);
                }
                frase
            }
            Self::NotAvailable { reason }
            | Self::InvalidRequest { reason }
            | Self::Temporary { reason, .. }
            | Self::Operational { reason, .. } => reason.clone(),
        }
    }

    /// Se è un risultato — `Trovato` o `DatoNonDisponibile` — e non l'assenza
    /// di un risultato.
    #[must_use]
    pub const fn is_a_result(&self) -> bool {
        matches!(self, Self::Found(_) | Self::NotAvailable { .. })
    }
}

#[cfg(test)]
mod tests {
    use super::{ResolutionInputKind, ResolutionOutcome, ResolvedIdentity};

    /// **Cinque esiti, cinque nomi, e soltanto due sono risultati.**
    #[test]
    fn cinque_esiti_e_soltanto_due_risultati() {
        let esiti = [
            ResolutionOutcome::Found(ResolvedIdentity {
                kind: String::from("canale"),
                telegram_id: -1,
                name: String::new(),
                username: None,
                first_name: String::new(),
                last_name: String::new(),
                usernames: Vec::new(),
                masked_phone: None,
                not_obtained: Vec::new(),
            }),
            ResolutionOutcome::NotAvailable {
                reason: String::from("r"),
            },
            ResolutionOutcome::InvalidRequest {
                reason: String::from("r"),
            },
            ResolutionOutcome::Temporary {
                reason: String::from("r"),
                wait_seconds: Some(30),
            },
            ResolutionOutcome::Operational {
                reason: String::from("r"),
                technical: None,
            },
        ];
        let nomi: std::collections::BTreeSet<&str> =
            esiti.iter().map(ResolutionOutcome::as_str).collect();
        assert_eq!(nomi.len(), 5);
        assert_eq!(esiti.iter().filter(|esito| esito.is_a_result()).count(), 2);
        assert!(esiti[3].what_to_do().contains("30 secondi"));
        assert!(esiti[3].what_to_do().contains("potrebbe esserci"));
    }

    #[test]
    fn il_genere_si_rilegge_dal_registro() {
        for genere in ResolutionInputKind::ALL {
            assert_eq!(
                ResolutionInputKind::from_stored(genere.as_str()),
                Some(genere)
            );
        }
    }
}
