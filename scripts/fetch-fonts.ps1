# Scarica i caratteri del sistema grafico approvato e ne verifica l'impronta.
#
# I file NON sono versionati. Il repository conserva `fonts.lock.json`, cioe'
# cio' che permette di verificare, non i binari di terze parti: e' lo stesso
# modo di `tdlib.lock.json` e `vcredist.lock.json`.
#
# ---------------------------------------------------------------------------
# PERCHE' l'impronta e non la fiducia.
#
# Scaricare da una URL significa eseguire codice altrui su questa macchina: un
# carattere e' un formato interpretato, e un file sostituito a monte
# arriverebbe senza che nessuno se ne accorga. L'impronta e' cio' che rende la
# sostituzione visibile - non impedisce nulla, ma non lascia passare in
# silenzio.
#
# Aggiornare una versione e' una DECISIONE, non un aggiornamento automatico:
# `-Update` riscrive il lock, e chi lo esegue deve poi scrivere in
# DECISION_LOG perche' la versione e' cambiata.
#
# ---------------------------------------------------------------------------
# Uso:
#   scripts\fetch-fonts.ps1              scarica cio' che manca e verifica tutto
#   scripts\fetch-fonts.ps1 -Force       riscarica anche cio' che c'e' gia'
#   scripts\fetch-fonts.ps1 -Update      riscarica e RISCRIVE le impronte
#   scripts\fetch-fonts.ps1 -VerifyOnly  non scarica nulla, verifica e basta
param(
    [switch] $Force,
    [switch] $Update,
    [switch] $VerifyOnly
)

$ErrorActionPreference = "Stop"

# Scarica un file ritentando, con attese crescenti.
#
# ---------------------------------------------------------------------------
# PERCHE' il ritentativo.
#
# Il 2026-08-17 il gate su Windows e' caduto qui: la cache di passaggio davanti
# all'origine ha risposto «503 first byte timeout». Nulla era rotto nel
# prodotto - format, clippy e l'intera suite erano verdi - ed e' bastato il
# malumore di un intermediario per far fallire la corsa. Senza ritentativo la
# riuscita del gate dipende da chi sta in mezzo alla rete.
#
# Il ritentativo riguarda il SOLO trasferimento. L'impronta si verifica dopo,
# identica a prima: ritentare non rende un file piu' fidato, rende solo meno
# probabile non averlo affatto.
#
# ---------------------------------------------------------------------------
# PERCHE' si scarica DI FIANCO e si sposta solo alla fine.
#
# Scrivendo direttamente sul bersaglio, un trasferimento interrotto lascia al
# suo posto un file troncato, che al giro dopo risulta presente e viene
# misurato invece che riscaricato. Cancellarlo pero' non basta: con -Force su
# un file gia' buono, un download che non riesce distruggerebbe cio' che c'era
# - e' successo, provando questa funzione con l'origine irraggiungibile.
#
# Il file provvisorio risolve entrambe le cose: il bersaglio non viene toccato
# finche' il trasferimento non e' completo, quindi cio' che c'e' resta, e cio'
# che arriva a meta' non prende mai il posto di nulla.
function Invoke-Download {
    param(
        [Parameter(Mandatory)] [string] $Uri,
        [Parameter(Mandatory)] [string] $Target
    )

    $parziale = "$Target.parziale"
    $attese = @(3, 10, 30)

    for ($tentativo = 0; $tentativo -le $attese.Count; $tentativo++) {
        try {
            Invoke-WebRequest -Uri $Uri -OutFile $parziale -UseBasicParsing -TimeoutSec 120
            Move-Item -LiteralPath $parziale -Destination $Target -Force
            return
        }
        catch {
            if (Test-Path -LiteralPath $parziale) { Remove-Item -LiteralPath $parziale -Force }
            if ($tentativo -eq $attese.Count) { throw }

            $attesa = $attese[$tentativo]
            Write-Host ("  non riuscito ({0}); riprovo fra {1} s" -f $_.Exception.Message, $attesa)
            Start-Sleep -Seconds $attesa
        }
    }
}

$root = Split-Path -Parent $PSScriptRoot
$lockPath = Join-Path $root "fonts.lock.json"
if (-not (Test-Path -LiteralPath $lockPath)) { throw "fonts.lock.json non trovato in $root" }

$lock = Get-Content -LiteralPath $lockPath -Raw -Encoding UTF8 | ConvertFrom-Json

# I caratteri e le licenze si trattano allo stesso modo: sono file scaricati di
# cui si conosce l'impronta. Tenerli in due elenchi separati nel lock serve a
# chi legge, non allo script.
$entries = @()
foreach ($f in $lock.caratteri) { $entries += $f }
foreach ($l in $lock.licenze)   { $entries += $l }

$failures = New-Object System.Collections.Generic.List[string]
$changed  = $false

foreach ($entry in $entries) {
    $target = Join-Path $root $entry.file
    $dir = Split-Path -Parent $target
    if (-not (Test-Path -LiteralPath $dir)) { New-Item -ItemType Directory -Force -Path $dir | Out-Null }

    $present = Test-Path -LiteralPath $target
    $mustFetch = (-not $present) -or $Force -or $Update

    if ($mustFetch -and -not $VerifyOnly) {
        Write-Host "scarico $($entry.file)"
        # TLS esplicito: su Windows PowerShell 5.1 il valore predefinito puo'
        # essere ancora TLS 1.0, che GitHub rifiuta.
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        Invoke-Download -Uri $entry.origine -Target $target
    }

    if (-not (Test-Path -LiteralPath $target)) {
        $failures.Add("$($entry.file): assente, e non e' stato scaricato")
        continue
    }

    # -LiteralPath ovunque: il nome a monte di Sora contiene parentesi quadre,
    # che PowerShell tratta come caratteri jolly. Con -Path l'impronta esce
    # VUOTA e il confronto passerebbe per un file mai letto.
    $hash = (Get-FileHash -LiteralPath $target -Algorithm SHA256).Hash.ToLowerInvariant()
    $size = (Get-Item -LiteralPath $target).Length

    if ($Update) {
        if ($entry.sha256 -ne $hash) { $changed = $true }
        $entry.sha256 = $hash
        $entry.byte = $size
        Write-Host ("  impronta aggiornata: {0}" -f $hash)
        continue
    }

    if ($hash -ne $entry.sha256) {
        $failures.Add("$($entry.file): impronta $hash, attesa $($entry.sha256)")
    }
    elseif ($size -ne $entry.byte) {
        $failures.Add("$($entry.file): $size byte, attesi $($entry.byte)")
    }
    else {
        Write-Host ("  ok  {0}  ({1} byte)" -f $entry.file, $size)
    }
}

if ($Update) {
    $lock.generato = (Get-Date -Format "yyyy-MM-dd")
    $json = $lock | ConvertTo-Json -Depth 6
    Set-Content -LiteralPath $lockPath -Value $json -Encoding utf8
    Write-Host ""
    if ($changed) {
        Write-Host "fonts.lock.json riscritto, e UN'IMPRONTA E' CAMBIATA." -ForegroundColor Yellow
        Write-Host "Va scritto in DECISION_LOG perche' la versione e' cambiata." -ForegroundColor Yellow
    }
    else {
        Write-Host "fonts.lock.json riscritto; nessuna impronta e' cambiata."
    }
    exit 0
}

Write-Host ""
if ($failures.Count -gt 0) {
    Write-Host "$($failures.Count) file non corrispondono al lock:" -ForegroundColor Red
    $failures | ForEach-Object { Write-Host ("  " + $_) -ForegroundColor Red }
    Write-Host ""
    Write-Host "Un'impronta diversa non e' un fastidio da aggirare con -Update:" -ForegroundColor Red
    Write-Host "significa che il file NON e' quello su cui il prodotto e' stato costruito." -ForegroundColor Red
    exit 1
}

Write-Host "Tutti i caratteri e i testi di licenza corrispondono a fonts.lock.json." -ForegroundColor Green
exit 0
