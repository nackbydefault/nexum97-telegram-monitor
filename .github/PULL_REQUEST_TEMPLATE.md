## Che cosa cambia / What changes

<!-- In poche righe: che cosa e perché. Il numero della issue, se c'è. -->

## Controlli / Checks

- [ ] `cargo fmt --all -- --check`
- [ ] `cargo clippy --workspace --all-targets --all-features --locked -- -D warnings`
- [ ] `cargo test --workspace --all-features --locked`
- [ ] Per una regola o per la sicurezza: una prova che fallisce senza la modifica / a test that fails without the change
- [ ] Ogni commit ha `Signed-off-by` (`git commit -s`, Developer Certificate of Origin)
- [ ] Nessun dato vero, nessuna credenziale, nessun registro non ripulito / no real data or credentials
- [ ] Le regole di disegno di CONTRIBUTING.md restano / the design rules in CONTRIBUTING.md still hold
