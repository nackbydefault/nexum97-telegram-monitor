# Uso legittimo / Lawful use

Ideazione e progettazione: Giuseppe LISI

**Questa è un'informativa, non una condizione della licenza.** Il codice è distribuito con la
[Apache License 2.0](LICENSE), che non pone limiti su chi lo usa o per quale scopo. Qui si dice
per che cosa il programma è stato pensato, e che cosa resta responsabilità di chi lo usa.

## Per che cosa è pensato

NEXUM/97 serve al **monitoraggio autorizzato** di fonti Telegram accessibili a un account
d'ufficio: canali e gruppi pubblici, o fonti in cui l'account è entrato in modo legittimo. Usa
soltanto le API ufficiali di Telegram, attraverso TDLib.

## Che cosa il programma non fa, per costruzione

- Non usa intelligenza artificiale: regole deterministiche e una persona che decide
  ([ADR-0048](docs/adr/ADR-0048-NESSUNA-INTELLIGENZA-ARTIFICIALE.md)).
- Non entra da sé in gruppi, non scrive, non reagisce, non spende Telegram Stars.
- Non usa account falsi, proxy a rotazione, aggiramento dei CAPTCHA o dei limiti di Telegram.
- Non attribuisce responsabilità e non classifica le persone per opinioni politiche, dissenso
  lecito o partecipazione a una manifestazione lecita. Ogni valutazione è di una persona, con il
  motivo e l'istante.

Queste regole stanno nel codice e nelle sue prove. Chi lo modifica può toglierle: la licenza lo
permette, ma il programma che ne nasce non è più quello descritto qui.

## Che cosa resta a chi lo usa

- Avere titolo per guardare le fonti che guarda, secondo la legge che si applica: per esempio il
  Regolamento (UE) 2016/679, la normativa nazionale sulla protezione dei dati e le regole del
  proprio ufficio.
- Rispettare i termini di servizio di Telegram e le condizioni delle API.
- Custodire i dati raccolti, i documenti prodotti e le credenziali dell'applicazione.

Il software è fornito «così com'è», senza garanzie, come dice la licenza (sezioni 7 e 8).

---

*English.* **This is a notice, not a licence condition.** The code is licensed under the Apache
License 2.0, which places no restriction on who uses it or for what purpose. NEXUM/97 is designed
for **authorized** monitoring of Telegram sources reachable by an office account, through the
official API only. By construction it uses no artificial intelligence, never joins, posts, reacts
or spends Telegram Stars, uses no fake accounts or evasion techniques, and never classifies people
by political opinion, lawful dissent or lawful protest. Users remain responsible for having legal
grounds for what they monitor (for example the GDPR and national data protection law), for
complying with Telegram's terms, and for safeguarding collected data and credentials. The
software is provided "as is", without warranties.
