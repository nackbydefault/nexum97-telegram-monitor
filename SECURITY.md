# Sicurezza / Security

Ideazione e progettazione: Giuseppe LISI

## Come segnalare una vulnerabilità

Non segnalare le vulnerabilità in una issue pubblica. Usa la segnalazione privata di GitHub:
scheda **Security** → **Report a vulnerability**
(https://github.com/nackbydefault/nexum97-telegram-monitor/security/advisories/new).

Scrivi che cosa succede, in quale versione o commit, e i passi per riprodurlo, con dati inventati.
Non includere credenziali, sessioni, dati personali, registri non ripuliti o informazioni operative.

## Che cosa succede dopo

Il titolare legge la segnalazione, risponde nella stessa scheda, corregge nell'archivio di
sviluppo e porta la correzione qui con una richiesta di modifica. Quando la correzione è
pubblicata, l'avviso si rende pubblico con il riconoscimento a chi ha segnalato, se lo desidera.

## Versioni seguite

Il codice di `main`. Questa repository non pubblica eseguibili né installer.

## Avvisi noti

RUSTSEC-2026-0543 su `chrono`, dipendenza dell'interfaccia Slint: nessuna soluzione a monte per
ora. Il controllo «Catena di fornitura» resta rosso finché l'avviso c'è.

---

*English.* Do not report vulnerabilities in a public issue. Use GitHub private vulnerability
reporting (Security tab → Report a vulnerability). Describe what happens, the version or commit
and the steps to reproduce it with made-up data; never include credentials, sessions, personal
data, uncleaned logs or operational details. The owner answers in the advisory, fixes the issue in
the development archive and brings the fix here through a pull request; the advisory is then
published, crediting the reporter if they wish. Only `main` is supported; no binaries are
published here. Known: RUSTSEC-2026-0543 (`chrono`, via Slint), no upstream fix yet.
