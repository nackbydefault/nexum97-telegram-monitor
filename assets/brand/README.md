# Asset di marchio — NEXUM/97

**Tutti i file di questa cartella sono generati da uno script del repository.** Nessuno è disegnato a mano in un editor esterno, nessuno proviene da un'opera, un gioco, un sito o un marchio di terzi.

```powershell
.\scripts\build-brand-assets.ps1      # genera
.\scripts\verify-brand-assets.ps1     # verifica
```

Chi deve cambiare un colore o una proporzione **modifica lo script e rigenera**. Ritoccare un PNG a mano lo fa divergere dagli altri quindici alla prima modifica, ed è il difetto che questa impostazione esiste per impedire.

## Che cos'è il segno

Un **occhio geometrico costruito**: una lente esagonale a spigoli vivi, un'iride ad archi incompleti e una pupilla-nodo di rete, con un glitch controllato e un rombo appena accennato agli angoli.

È la realizzazione della specifica scritta in `docs/ux/ICONOGRAPHY.md`, rimasta sulla carta dalla Milestone 3C.

**Non è un occhio disegnato.** Nessuna palpebra, nessun riflesso, nessuna sfumatura organica: sono rette, blocchi e simmetrie. Il divieto di `ICONOGRAPHY.md` riguarda l'occhio *realistico*, che dichiarerebbe una sorveglianza sulle persone; qui si monitorano fonti autorizzate, ed è una cosa diversa che il marchio non deve confondere.

**Non contiene** stemmi istituzionali, scudi, riferimenti a corpi dello Stato, imitazioni di marchi esistenti, né il logo di Telegram.

## Come è costruito

Non è un'immagine ridotta a più dimensioni. Sono **quattro griglie disegnate a mano** — 16, 20, 24, 32 — ingrandite per fattori interi:

| Dimensione | Origine | | Dimensione | Origine |
|---|---|---|---|---|
| 16 | griglia 16 ×1 | | 48 | griglia 24 ×2 |
| 20 | griglia 20 ×1 | | 64 | griglia 32 ×2 |
| 24 | griglia 24 ×1 | | 128 | griglia 32 ×4 |
| 32 | griglia 32 ×1 | | 256 | griglia 32 ×8 |
| 40 | griglia 20 ×2 | | 512 | griglia 32 ×16 |

Una riduzione produrrebbe pixel sfocati, che è esattamente ciò che un marchio in pixel art non deve avere. Il dettaglio cala al calare della dimensione, come prescrive `ICONOGRAPHY.md`: sotto i 32 px cadono le connessioni esterne, le tacche d'angolo e il glitch, e resta la lente con il nucleo.

## File

| File | Che cos'è |
|---|---|
| `nexum97-eye.svg` | master vettoriale, griglia 512, generato dalla **stessa** griglia dei PNG |
| `nexum97-logo.png` / `-2x` | logotipo completo, **per fondo scuro** |
| `nexum97-logo-su-chiaro.png` / `-2x` | logotipo completo, **per fondo chiaro** |
| `anteprima-dimensioni.png` | provino delle dimensioni piccole, ingrandite a pixel netti |
| `icon/nexum97.ico` | icona Windows multi-risoluzione, nove dimensioni |
| `icon/nexum97-eye-{16…512}.png` | PNG trasparenti |
| `icon/nexum97-eye-mono-{32,256}.png` | variante monocromatica |

### Perché due logotipi e non uno

La lente scura dell'occhio regge su fondo chiaro e su fondo scuro da sola. **Le lettere no.** Il controllo su fondo chiaro ha mostrato «NEXUM/97» in bianco freddo su bianco sporco, cioè praticamente invisibile. Un solo file non può servire entrambi i fondi, e fingere di sì avrebbe prodotto un logotipo che sparisce in metà degli impieghi.

## Verifica

`verify-brand-assets.ps1` controlla ciò che si può controllare a macchina: presenza dei file, struttura dell'ICO (nove dimensioni, 32 bit, offset dentro il file, DIB fino a 48 e PNG da 64), dimensioni dei PNG, angolo trasparente e nucleo opaco.

**Non sostituisce lo sguardo.** Che l'occhio si legga a 16 px lo dice solo chi lo guarda, ed è il motivo per cui esiste `anteprima-dimensioni.png`. La prima stesura di queste griglie è stata scartata proprio guardandolo: a 20, 24, 40 e 48 px l'arco dell'iride toccava la pupilla e le due forme insieme leggevano come una «T».

## Limite dichiarato

Gli asset **non sono ancora collegati a nulla**. L'eseguibile non ha icona, la finestra non ha icona, l'installer non esiste. È lavoro di MP-15C e MP-15D, e finché non è fatto un'icona corretta in questa cartella non è un'icona corretta sullo schermo.

`System.Drawing.Icon`, richiesto a 256 px, restituisce la voce da 128: è un limite noto di quella classe con le voci PNG, non un difetto dell'ICO — il payload da 256 incorporato è stato decodificato e misura 256×256. Va comunque **riconfermato sulla shell reale** in MP-15C.

---

**Ideazione e progettazione: Giuseppe LISI**
