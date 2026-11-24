//! Le traduzioni dei messaggi di sicurezza, e la loro revisione (I18N-01,
//! ADR-0197, decisione 5).
//!
//! # Una traduzione si mostra soltanto se una persona l'ha rivista
//!
//! Un'avvertenza tradotta male è peggio di un'avvertenza in un'altra lingua:
//! chi la legge si fida di una frase che dice un'altra cosa. Per questo ogni
//! traduzione registra:
//!
//! - l'impronta della versione italiana che traduce (`of_fingerprint`):
//!   cambiare l'avvertenza italiana rende rossa la prova, e la traduzione va
//!   rifatta e riletta;
//! - la propria impronta (`fingerprint`), calcolata come quella delle versioni
//!   italiane: cambiare una parola tradotta senza aggiornarla rende rossa la
//!   prova;
//! - gli elementi di significato tradotti, che il testo deve contenere tutti;
//! - la revisione, se c'è: chi, quando, dove è registrata e **quale impronta
//!   ha letto**. Una traduzione cambiata dopo la revisione non è più rivista.
//!
//! La guardia per lingua di `lisi-app` verifica l'altra metà: che il catalogo
//! non traduca un messaggio senza una traduzione rivista e identica.
//!
//! # Le bozze
//!
//! Le traduzioni qui sotto sono bozze: `review` è `None`. Le scrive chi
//! scrive il programma; la revisione la fa una persona che non l'ha scritto
//! (HVQ-165), e la registra chi l'ha fatta.

use crate::security_messages::SECURITY_MESSAGES;

/// La lettura di una persona.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Review {
    /// Chi ha riletto: un ruolo o un nome, come lo registra l'ufficio.
    pub by: &'static str,
    /// Quando, nella forma `AAAA-MM-GG`.
    pub date: &'static str,
    /// Dove è registrata: una voce di coda (`HVQ-000`) o una decisione
    /// (`DEC-000`).
    pub record: &'static str,
    /// L'impronta della traduzione letta.
    pub fingerprint: &'static str,
}

/// La traduzione di un messaggio di sicurezza in una lingua.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Translation {
    /// Il codice del messaggio, `SIC-00`.
    pub code: &'static str,
    /// La lingua, come la cartella del catalogo: `en`.
    pub language: &'static str,
    /// L'impronta della versione italiana tradotta.
    pub of_fingerprint: &'static str,
    /// La frase semplice, tradotta.
    pub text: &'static str,
    /// Il dettaglio tecnico, tradotto.
    pub technical_detail: &'static str,
    /// Gli elementi di significato, tradotti.
    pub meaning_elements: &'static [&'static str],
    /// L'impronta di testo, dettaglio ed elementi tradotti.
    pub fingerprint: &'static str,
    /// La revisione di una persona, se c'è stata.
    pub review: Option<Review>,
}

impl Translation {
    /// Se la traduzione si può mostrare: una persona l'ha letta così com'è,
    /// e traduce la versione italiana in vigore.
    #[must_use]
    pub fn is_reviewed(&self) -> bool {
        let in_vigore = SECURITY_MESSAGES.iter().any(|messaggio| {
            messaggio.code == self.code && messaggio.current.fingerprint == self.of_fingerprint
        });
        in_vigore
            && self
                .review
                .is_some_and(|revisione| revisione.fingerprint == self.fingerprint)
    }
}

/// La traduzione rivista di un messaggio in una lingua, se c'è.
#[must_use]
pub fn reviewed(code: &str, language: &str) -> Option<&'static Translation> {
    TRANSLATIONS
        .iter()
        .find(|traduzione| traduzione.code == code && traduzione.language == language)
        .filter(|traduzione| traduzione.is_reviewed())
}

/// Le traduzioni registrate.
pub const TRANSLATIONS: &[Translation] = &[
    Translation {
        code: "SIC-15",
        language: "en",
        of_fingerprint: "b511bf38dd89328188acdc3fcf73378f72f8d94f28d4016ac343d4321e760fce",
        text: "This copy of the program cannot connect to Telegram. It was built without the \
               component that allows it. It can only be used in demonstration mode. Report this \
               to whoever supplied the package.",
        technical_detail: "The program was compiled without the `tdlib-runtime` feature: real \
                           mode does not exist in this file, and cannot be enabled from the \
                           settings.",
        meaning_elements: &[
            "cannot connect to Telegram",
            "built without the component",
            "demonstration mode",
            "Report this to whoever supplied the package",
        ],
        fingerprint: "63232d58fc9150fffffdbc9db292e7f6c7c32d12c678ef793817ca600e8297fd",
        review: None,
    },
    Translation {
        code: "SIC-01",
        language: "en",
        of_fingerprint: "d79fd3b4b45531adc39fef4be40dd8fdc43f1f3f5cb742235a2b64c764c82b39",
        text: "A snapshot keeps what Telegram shows right now. It records who takes it, when \
               and why. It does not become acquired evidence: the evidence remains the text in \
               the archive.",
        technical_detail: "The context snapshot saves the messages around a content item, with \
                           operator, time and reason. It does not replace the acquired content, \
                           which remains the source of the data.",
        meaning_elements: &[
            "who takes it, when and why",
            "does not become acquired evidence",
            "the evidence remains the text in the archive",
        ],
        fingerprint: "2e590e34dcc3f12833803ea329aa25f3111fc36cdfe02381d006f0728afbe515",
        review: None,
    },
    Translation {
        code: "SIC-02",
        language: "en",
        of_fingerprint: "f2cff6343d3036d01a34adb2f72d800937144ca4ee429dd46a3db869d59a853b",
        text: "Removing an account also deletes its Telegram session from this computer. \
               Signing back in will require the number and code again. The operation cannot be \
               undone. The operations log keeps a record of the removal.",
        technical_detail: "The TDLib session and the credentials protected with DPAPI are \
                           deleted. The audit log keeps the operation, without any secret.",
        meaning_elements: &[
            "also deletes its Telegram session",
            "require the number and code again",
            "cannot be undone",
            "keeps a record of the removal",
        ],
        fingerprint: "a2dca50e55265f87215ba29e88ca21cda3b6996abc8e4ab35406a7cbc0d585e2",
        review: None,
    },
    Translation {
        code: "SIC-03",
        language: "en",
        of_fingerprint: "d60ccfbbe27c05c26aea9b9d8cdafc190143371fee73e8559fe79866d47f10b8",
        text: "“Reset the entire archive” deletes ALL of the archive of this workstation. Not \
               only the history: also monitorings, accounts, profiles, sources, dictionaries \
               and settings. First, the operations log is saved to a separate file, with its \
               fingerprint. The deletion does not happen immediately: it happens the next time \
               the program opens. Until then a notice at the top recalls it.",
        technical_detail: "On the next start the SQLite database file is removed, when no \
                           service holds it open. The audit log is first exported with its \
                           SHA-256 fingerprint.",
        meaning_elements: &[
            "deletes ALL of the archive",
            "Not only the history",
            "does not happen immediately",
            "the next time the program opens",
        ],
        fingerprint: "2394d367eceb0948e6d3b0eb548535127ae009d8d2a6157de568e008b3d57a20",
        review: None,
    },
    Translation {
        code: "SIC-04",
        language: "en",
        of_fingerprint: "39cfd92945611cddd4c85972e504e87a11e5f8bde87f97c6f31c310a0c3e3891",
        text: "Warning: real Telegram mode opens a real session on the office account. It uses \
               the official channel that Telegram offers to programs. Use it only with \
               authorisation. Demonstration mode does not contact Telegram.",
        technical_detail: "Real mode uses TDLib and the official Telegram API with the \
                           credentials of the office. NEXUM/97 is not an official Telegram \
                           client.",
        meaning_elements: &[
            "real session on the office account",
            "only with authorisation",
            "does not contact Telegram",
            "not an official Telegram client",
        ],
        fingerprint: "fef1ebf52cb7ee46774294b79548e9f0f97c8282c4ec8471dab9bfdc385b3198",
        review: None,
    },
    Translation {
        code: "SIC-05",
        language: "en",
        of_fingerprint: "c92d525319f296ea72c93eee4bd7a1ecc4d73aab80cf24939a38efa61d7b79d0",
        text: "The fingerprint says that two configurations are the same. It is not a \
               signature: it does not prove who composed it.",
        technical_detail: "SHA-256 fingerprint of the configuration written in canonical form. \
                           A signature would require a key and an identity: the fingerprint has \
                           neither.",
        meaning_elements: &["It is not a signature", "does not prove who composed it"],
        fingerprint: "60af234fb0bcba75a9351ed8491f46f59ea561c1b060a45ffd5e1c10bdbe1d59",
        review: None,
    },
    Translation {
        code: "SIC-06",
        language: "en",
        of_fingerprint: "fb59005050b551072ed5474e541fb77bccc77d497c48eec0dedb2524ed92e201",
        text: "Downloading the file does not verify it and does not install it. “Verify the \
               file” checks two things. The first: that the file arrived whole. The second: \
               that it is signed by someone this workstation recognises. Only the second says \
               whom you are trusting. Not even a verified file installs itself: the program \
               does not replace itself.",
        technical_detail: "The first check compares the SHA-256 fingerprint with the one \
                           declared by the update information: it proves the transport, because \
                           that information is not trusted. The second is the Authenticode \
                           signature, verified by Windows.",
        meaning_elements: &[
            "does not verify it and does not install it",
            "arrived whole",
            "whom you are trusting",
            "does not replace itself",
        ],
        fingerprint: "f23dfe6bfbb83086771857cd425336b5097e2722fef3823b56ba218c363e5463",
        review: None,
    },
    Translation {
        code: "SIC-07",
        language: "en",
        of_fingerprint: "1a3bfe292c9df64686ef4d1bb3678db8f9462bfcbf68882d9174216e5dc03aa6",
        text: "Recalculates the fingerprint of every exported report and compares it with its \
               list of fingerprints. It proves that the report is still identical to the one \
               produced. It does not prove that the list of fingerprints is the original.",
        technical_detail: "Byte-by-byte comparison through SHA-256 with the integrity manifest. \
                           The manifest is not signed: whoever can change the report can also \
                           change the manifest.",
        meaning_elements: &[
            "still identical to the one produced",
            "does not prove that the list of fingerprints is the original",
        ],
        fingerprint: "2362bdd3a113b1a2039eba8cd82154fef0326a5e77541d2c67803a5cf648c210",
        review: None,
    },
    Translation {
        code: "SIC-08",
        language: "en",
        of_fingerprint: "44eaf64391fce5245f1b69f1b1f54d137a96765e4f8abf903ae3789ca8451371",
        text: "This list comes from messages already acquired: who appears as author, how many \
               times, in which sources. It is not a list requested from Telegram. It does not \
               include those who have never written.",
        technical_detail: "Aggregation of the senders of the content in the archive. Telegram \
                           is not asked for the member list of any source.",
        meaning_elements: &[
            "not a list requested from Telegram",
            "does not include those who have never written",
        ],
        fingerprint: "2cbf096062c4ae910101b734c94c49cf46642d4316b44a70df37ceff0c7e0929",
        review: None,
    },
    Translation {
        code: "SIC-09",
        language: "en",
        of_fingerprint: "a9cba4745f1500d4feb548be19786cb7f5d6cc657303de10e24756d522ba853b",
        text: "A subject is not a person from the list above. That list says who wrote during a \
               monitoring. It is an observation, and it states nothing about anyone. A subject \
               is opened by hand, writing why. Nobody becomes a subject for having written in a \
               group.",
        technical_detail: "The file of a subject requires operator, reason and time, and stays \
                           in the audit log. The list of participants is derived from the \
                           senders of the content.",
        meaning_elements: &[
            "A subject is not a person from the list above",
            "states nothing about anyone",
            "opened by hand, writing why",
            "Nobody becomes a subject for having written in a group",
        ],
        fingerprint: "f3015a1382c879880966602b3175837e5d3dd2e7bebefa6250d57b865ef19ab2",
        review: None,
    },
    Translation {
        code: "SIC-10",
        language: "en",
        of_fingerprint: "619c0637bb884f943995c22cfa9ea7ab5f1fd049fa187bce43f715b68bd4d012",
        text: "This figure shows an element and what touches it, one step at a time. Each link \
               says which fact it exists for and where it comes from. It is not a network of \
               relationships. Two elements linked through a third do not, for that reason, have \
               anything to do with each other.",
        technical_detail: "The evidence graph shows the nodes at distance one. Each edge \
                           carries the fact that justifies it and its provenance. No transitive \
                           relationship is inferred.",
        meaning_elements: &[
            "which fact it exists for",
            "not a network of relationships",
            "do not, for that reason, have anything to do with each other",
        ],
        fingerprint: "4697cab00077e9456cdbf52f9712a6f74983004d0a446ca6b69e888cd500d690",
        review: None,
    },
    Translation {
        code: "SIC-11",
        language: "en",
        of_fingerprint: "01a88586f4129139809d27967fa9a6647998aad572b6406828ab5a915653539a",
        text: "Here you see what would change by publishing the draft of a dictionary. The \
               calculation uses the content already archived. The comparison writes nothing and \
               publishes nothing. The decision remains with a person.",
        technical_detail: "The analysis is run again, with the draft, on the archived content. \
                           The result is not saved and the draft is not published.",
        meaning_elements: &[
            "writes nothing and publishes nothing",
            "The decision remains with a person",
        ],
        fingerprint: "e176c5e9c11373d4a863bd202854157299daa533e7da006b9a0f05aceb98e616",
        review: None,
    },
    Translation {
        code: "SIC-12",
        language: "en",
        of_fingerprint: "24065f6a9597b7d2f1f8e7c53138717f088d16f5067dc9062c58d416646a3a66",
        text: "These entries say what was checked. They do not say that everything will work. \
               An area “not measured” is not an area that is fine. It is an area the program \
               could not check, and the line says why.",
        technical_detail: "Each diagnostic check has three outcomes: passed, not passed, not \
                           measured. “Not measured” means that the measurement was not \
                           possible.",
        meaning_elements: &[
            "do not say that everything will work",
            "not an area that is fine",
            "the line says why",
        ],
        fingerprint: "bfd1bd9958a28563279bd7023a512b128059a58196548c2e4576e2a9004bd98f",
        review: None,
    },
    Translation {
        code: "SIC-13",
        language: "en",
        of_fingerprint: "0cf1d1a33d186fe32a8a1fff5edeb7682ef89b8382be430c7dc9c6e962e122c4",
        text: "A group is not an attack, nor a verified news item. It is an invitation to look. \
               The conclusion is drawn by a person. The program has no way to record it in \
               their place.",
        technical_detail: "A cluster gathers content that shares indicators, such as domains, \
                           addresses or CVE codes. The correlation is deterministic and assigns \
                           no threat status.",
        meaning_elements: &[
            "A group is not an attack",
            "nor a verified news item",
            "The conclusion is drawn by a person",
        ],
        fingerprint: "c2b00c48a8a256cc4eea6e88a9f670886221e2c63c5794052052ed65654cdc24",
        review: None,
    },
    Translation {
        code: "SIC-14",
        language: "en",
        of_fingerprint: "1a5b13c49d932d2242de95b2fa0a4f329f3b90ca1aa7d27d9d7415ee8a6b2b20",
        text: "The sector appears only for the organisations declared in Settings. The program \
               does not infer it from the text: assigning one by eye would be inventing it. \
               Content without a sector names no declared organisation. It does not mean that \
               it does not concern a sector. A sector that the regulation does not list also \
               counts.",
        technical_detail: "The sector comes from the list of declared organisations, compared \
                           by name. The text is not classified.",
        meaning_elements: &[
            "declared in Settings",
            "does not infer it from the text",
            "would be inventing it",
            "does not mean that it does not concern a sector",
        ],
        fingerprint: "91aa1e4f412b18f3fb5238ca741232cd9dbdfb6b8de2fc9e58e08d295206885c",
        review: None,
    },
    Translation {
        code: "SIC-16",
        language: "en",
        of_fingerprint: "a12fb2e1cc44678a310b9c30921d960545fdc80f42ceb8363ac14610c356861c",
        text: "This package is not forensic evidence and is not an expert report. The program \
               does not perform forensic acquisition, and does not have its chain of custody.",
        technical_detail: "The package gathers the chosen content, its provenance and a \
                           manifest of fingerprints. The manifest says that the files are the \
                           ones produced, not who produced them.",
        meaning_elements: &[
            "not forensic evidence",
            "not an expert report",
            "chain of custody",
        ],
        fingerprint: "274b34dd63413312225c6e31565fe83bb501b2c29e66ca01b751e812d8441a63",
        review: None,
    },
    Translation {
        code: "SIC-17",
        language: "en",
        of_fingerprint: "4d4041b7cdc5b929be31ff34be1d42cb15fb772d0818671227a2cfb0b622d004",
        text: "EXERCISE. Synthetic data, no contact with Telegram. What is produced here has no \
               value as an official record.",
        technical_detail: "The exercise archive is separate from the one of the office. Every \
                           document carries the Italian word ESERCITAZIONE in the file name and \
                           at the top: documents stay in Italian.",
        meaning_elements: &[
            "EXERCISE",
            "Synthetic data",
            "no contact with Telegram",
            "no value as an official record",
        ],
        fingerprint: "d32807d324db3f1cef58da49995f430bfc8fbd5e551fd87d1d70f12c1e612fe0",
        review: None,
    },
    Translation {
        code: "SIC-18",
        language: "en",
        of_fingerprint: "f224a7a8550d50c66ab96c245834622f1938137a3e3dbc0c986c22d7b67df72f",
        text: "A CVE identifier named in a message is not a conclusion of compromise, nor of \
               danger. Being in the KEV catalogue says that someone has exploited the \
               vulnerability, not that it happened here.",
        technical_detail: "The answers come from the imported snapshots, with their date. What \
                           a snapshot does not contain is called absent, not non-existent.",
        meaning_elements: &[
            "not a conclusion of compromise",
            "nor of danger",
            "not that it happened here",
            "imported snapshots",
        ],
        fingerprint: "651083b801280ed672abee9a3aeaca4de4846c2316c03f9cdc72d13d1039443b",
        review: None,
    },
];

#[cfg(test)]
mod tests {
    use super::{Review, TRANSLATIONS, reviewed};
    use crate::security_messages::{SECURITY_MESSAGES, fingerprint};

    fn normalizzato(testo: &str) -> String {
        testo
            .to_lowercase()
            .split_whitespace()
            .collect::<Vec<_>>()
            .join(" ")
    }

    #[test]
    fn ogni_messaggio_ha_la_sua_bozza_inglese() {
        assert!(
            SECURITY_MESSAGES.len() >= 18,
            "messaggi letti: {}",
            SECURITY_MESSAGES.len()
        );
        for messaggio in SECURITY_MESSAGES {
            let bozze = TRANSLATIONS
                .iter()
                .filter(|t| t.code == messaggio.code && t.language == "en")
                .count();
            assert_eq!(bozze, 1, "{}: traduzioni inglesi {bozze}", messaggio.code);
        }
        assert_eq!(TRANSLATIONS.len(), SECURITY_MESSAGES.len());
    }

    #[test]
    fn una_traduzione_traduce_la_versione_italiana_in_vigore() {
        for traduzione in TRANSLATIONS {
            let Some(messaggio) = SECURITY_MESSAGES.iter().find(|m| m.code == traduzione.code)
            else {
                panic!("{}: messaggio inesistente", traduzione.code);
            };
            assert_eq!(
                traduzione.of_fingerprint, messaggio.current.fingerprint,
                "{}: l'avvertenza italiana è cambiata, la traduzione va rifatta e riletta",
                traduzione.code
            );
        }
    }

    #[test]
    fn l_impronta_della_traduzione_torna() {
        for traduzione in TRANSLATIONS {
            let calcolata = fingerprint(
                traduzione.text,
                traduzione.technical_detail,
                traduzione.meaning_elements,
            );
            assert_eq!(
                calcolata.as_str(),
                traduzione.fingerprint,
                "{}: una parola tradotta è cambiata senza aggiornare l'impronta ({calcolata})",
                traduzione.code
            );
        }
    }

    #[test]
    fn la_traduzione_contiene_i_suoi_elementi_di_significato() {
        for traduzione in TRANSLATIONS {
            let insieme = normalizzato(&format!(
                "{} {}",
                traduzione.text, traduzione.technical_detail
            ));
            assert!(
                !traduzione.meaning_elements.is_empty(),
                "{}",
                traduzione.code
            );
            for elemento in traduzione.meaning_elements {
                assert!(
                    insieme.contains(&normalizzato(elemento)),
                    "{}: manca «{elemento}»",
                    traduzione.code
                );
            }
        }
    }

    #[test]
    fn una_revisione_vale_per_il_testo_che_ha_letto() {
        for traduzione in TRANSLATIONS {
            if let Some(revisione) = traduzione.review {
                assert_eq!(
                    revisione.fingerprint, traduzione.fingerprint,
                    "{}",
                    traduzione.code
                );
                assert!(!revisione.by.trim().is_empty(), "{}", traduzione.code);
                assert_eq!(revisione.date.len(), 10, "{}", traduzione.code);
                assert!(
                    revisione.record.starts_with("HVQ-") || revisione.record.starts_with("DEC-"),
                    "{}",
                    traduzione.code
                );
            }
        }
    }

    #[test]
    fn una_bozza_non_e_una_traduzione_rivista() {
        // Oggi nessuna traduzione è stata letta da una persona: nessuna si
        // mostra. La revisione è HVQ-165.
        for traduzione in TRANSLATIONS.iter().filter(|t| t.review.is_none()) {
            assert!(!traduzione.is_reviewed());
            assert!(reviewed(traduzione.code, traduzione.language).is_none());
        }
        let Some(prima) = TRANSLATIONS.first() else {
            panic!("nessuna traduzione registrata");
        };
        let mut rivista = *prima;
        rivista.review = Some(Review {
            by: "prova",
            date: "2026-11-09",
            record: "HVQ-165",
            fingerprint: rivista.fingerprint,
        });
        assert!(rivista.is_reviewed());
        // Una parola cambiata dopo la lettura annulla la revisione.
        rivista.fingerprint = "0000";
        assert!(!rivista.is_reviewed());
    }
}
