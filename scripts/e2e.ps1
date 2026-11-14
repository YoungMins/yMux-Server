# End-to-end interoperability test: the real server binary, the real desktop socket loop + engine
# (#[ignore]d tests in the ymux repo) and the real PWA protocol code (web/scripts/e2e-*.ts), all on
# loopback with a temp data dir. Exits non-zero on any failure. Nothing is committed.
#
# Two scenarios, each against a fresh server:
#   1. one desktop, one device: pairing (link key, equal check numbers), sessions, every command, every
#      rejection path of PROTOCOL.md, reconnect, capability change, removal; exact counts of what
#      reached the desktop's page.
#   2. two desktops (same setup token), ONE device process with the PWA's Fleet and two pairings:
#      isolation of lists and commands, wrong-key / wrong-desktop frames, one desktop stopped while
#      the other keeps answering, removal of one pairing.
#
#   pwsh scripts\e2e.ps1 [-Ymux ..\ymux] [-Keep] [-Only single|fleet]
param(
    [string]$Ymux = '..\ymux',
    [switch]$Keep,
    [ValidateSet('both', 'single', 'fleet')][string]$Only = 'both'
)
$ErrorActionPreference = 'Stop'
$root = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$ymuxDir = (Resolve-Path (Join-Path $root $Ymux)).Path
$env:CARGO_INCREMENTAL = '0'

function Free-GB($path) {
    $drive = (Get-Item $path).PSDrive
    [math]::Round($drive.Free / 1GB, 1)
}
foreach ($p in @($root, $ymuxDir)) {
    $free = Free-GB $p
    Write-Host "free space for ${p}: $free GB"
    if ($free -lt 6) { throw "less than 6 GB free for $p; stopping before a build" }
}

$tmp = Join-Path ([IO.Path]::GetTempPath()) ("ymux-e2e-" + [guid]::NewGuid().ToString('n').Substring(0, 8))
New-Item -ItemType Directory -Path $tmp | Out-Null
$script:procs = @()
$failed = $false

function Stop-Tree($p) {
    if ($p -and -not $p.HasExited) { & taskkill /F /T /PID $p.Id 2>&1 | Out-Null }
}

function Start-Server($dir, $label) {
    New-Item -ItemType Directory -Path "$dir\data" | Out-Null
    $l = [Net.Sockets.TcpListener]::new([Net.IPAddress]::Loopback, 0)
    $l.Start(); $port = $l.LocalEndpoint.Port; $l.Stop()
    $url = "http://127.0.0.1:$port"
    Write-Host "== [$label] start server on $url"
    $env:YMUX_SERVER_BIND = "127.0.0.1:$port"
    $env:YMUX_SERVER_PUBLIC_URL = $url
    $env:YMUX_SERVER_DATA_DIR = "$dir\data"
    $srv = Start-Process -FilePath $script:serverExe -PassThru -NoNewWindow `
        -RedirectStandardOutput "$dir\server.out.log" -RedirectStandardError "$dir\server.err.log"
    $script:procs += $srv
    $up = $false
    for ($i = 0; $i -lt 100 -and -not $up; $i++) {
        try { $up = (Invoke-WebRequest "$url/healthz" -UseBasicParsing -TimeoutSec 2).StatusCode -eq 200 }
        catch { Start-Sleep -Milliseconds 100 }
    }
    if (-not $up) { throw 'server did not come up' }
    $token = (& $script:serverExe token | Select-Object -Last 1).Trim()
    if (-not $token) { throw 'no setup token' }
    return @{ Url = $url; Token = $token; Proc = $srv }
}

# Run one desktop-side live test (the compiled test binary, so two can run at once).
function Start-Desktop($srv, $rv, $logBase, $test, $variant) {
    New-Item -ItemType Directory -Path $rv -Force | Out-Null
    $env:YMUX_E2E_URL = $srv.Url
    $env:YMUX_E2E_TOKEN = $srv.Token
    $env:YMUX_E2E_DIR = $rv
    if ($variant) { $env:YMUX_E2E_VARIANT = $variant } else { Remove-Item Env:\YMUX_E2E_VARIANT -ErrorAction SilentlyContinue }
    $p = Start-Process -FilePath $script:testExe -PassThru -NoNewWindow -WorkingDirectory "$ymuxDir\src-tauri" `
        -ArgumentList @('--ignored', '--exact', '--nocapture', $test) `
        -RedirectStandardOutput "$logBase.out.log" -RedirectStandardError "$logBase.err.log"
    $null = $p.Handle   # keeps the exit code readable once the process is gone
    $script:procs += $p
    return $p
}

function Start-Device($srv, $file, $dirs, $logBase) {
    $env:E2E_URL = $srv.Url
    foreach ($k in $dirs.Keys) { Set-Item -Path "Env:\$k" -Value $dirs[$k] }
    $p = Start-Process -FilePath 'pnpm.cmd' -PassThru -NoNewWindow -WorkingDirectory (Join-Path $root 'web') `
        -ArgumentList @('exec', 'vitest', 'run', '--config', 'vitest.e2e.config.ts', $file) `
        -RedirectStandardOutput "$logBase.log" -RedirectStandardError "$logBase.err.log"
    $null = $p.Handle
    $script:procs += $p
    return $p
}

# The sides wait for each other through files: when one dies the others would sit out their
# timeouts, so stop everything as soon as any process fails.
function Wait-All($procs, $minutes) {
    $deadline = (Get-Date).AddMinutes($minutes)
    while ($true) {
        if ((Get-Date) -gt $deadline) { throw 'timed out' }
        $running = $false
        foreach ($p in $procs) {
            if (-not $p.HasExited) { $running = $true }
            elseif ($p.ExitCode -ne 0) { throw "a side failed (pid $($p.Id), exit $($p.ExitCode))" }
        }
        if (-not $running) { break }
        Start-Sleep -Milliseconds 300
    }
    foreach ($p in $procs) { $p.WaitForExit() }
    foreach ($p in $procs) { if ($p.ExitCode -ne 0) { throw "a side failed (pid $($p.Id), exit $($p.ExitCode))" } }
}

try {
    Write-Host '== build server'
    Push-Location $root
    cargo build --quiet
    if ($LASTEXITCODE -ne 0) { throw 'server build failed' }
    Pop-Location
    $script:serverExe = Join-Path $root 'target\debug\ymux-server.exe'

    if (-not (Test-Path (Join-Path $root 'web\node_modules'))) {
        Push-Location (Join-Path $root 'web')
        pnpm install --frozen-lockfile
        if ($LASTEXITCODE -ne 0) { throw 'pnpm install failed' }
        Pop-Location
    }

    Write-Host '== build desktop test binary'
    Push-Location $ymuxDir
    $ErrorActionPreference = 'Continue'
    $lines = cargo test -p ymux --lib --no-run --message-format=json --quiet 2>$null
    $buildExit = $LASTEXITCODE
    $ErrorActionPreference = 'Stop'
    if ($buildExit -ne 0) { throw 'desktop test build failed' }
    Pop-Location
    $art = $lines | ForEach-Object { try { $_ | ConvertFrom-Json } catch { $null } } |
        Where-Object { $_ -and $_.reason -eq 'compiler-artifact' -and $_.executable -and $_.profile.test -and ($_.target.kind -contains 'lib') } |
        Select-Object -Last 1
    if (-not $art) { throw 'could not find the desktop test binary' }
    $script:testExe = $art.executable

    if ($Only -in 'both', 'single') {
        $d = "$tmp\single"; New-Item -ItemType Directory -Path $d | Out-Null
        $srv = Start-Server $d 'single'
        Write-Host '== [single] desktop (real socket loop + engine, fake page) + device (PWA protocol code)'
        $desk = Start-Desktop $srv "$d\rv" "$d\desktop" 'remote::runtime::e2e::live_pair_session_commands_reconnect_removal' $null
        $dev = Start-Device $srv 'scripts/e2e-device.ts' @{ E2E_DIR = "$d\rv" } "$d\device"
        Wait-All @($desk, $dev) 4
        Get-Content "$d\device.log" | Select-Object -Last 8
        Write-Host '== [single] passed'
        Stop-Tree $srv.Proc
    }

    if ($Only -in 'both', 'fleet') {
        $d = "$tmp\fleet"; New-Item -ItemType Directory -Path $d | Out-Null
        $srv = Start-Server $d 'fleet'
        Write-Host '== [fleet] two desktops + one device process with two pairings'
        $da = Start-Desktop $srv "$d\rv-a" "$d\desktop-a" 'remote::runtime::e2e::live_fleet_member' 'A'
        $db = Start-Desktop $srv "$d\rv-b" "$d\desktop-b" 'remote::runtime::e2e::live_fleet_member' 'B'
        $dev = Start-Device $srv 'scripts/e2e-fleet.ts' @{ E2E_DIR_A = "$d\rv-a"; E2E_DIR_B = "$d\rv-b" } "$d\device"
        Wait-All @($da, $db, $dev) 4
        Get-Content "$d\device.log" | Select-Object -Last 8
        Write-Host '== [fleet] passed'
        Stop-Tree $srv.Proc
    }
}
catch {
    Write-Host "ERROR: $_"
    $failed = $true
}
finally {
    foreach ($p in $script:procs) { Stop-Tree $p }
    if ($failed) {
        foreach ($f in Get-ChildItem $tmp -Recurse -Filter '*.log') {
            Write-Host "---- $($f.FullName.Substring($tmp.Length))"
            Get-Content $f.FullName -Tail 40
        }
    }
    if ($Keep -or $failed) { Write-Host "logs kept in $tmp" }
    else { Remove-Item -Recurse -Force $tmp -ErrorAction SilentlyContinue }
}
if ($failed) { Write-Host 'E2E FAILED'; exit 1 }
Write-Host 'E2E PASSED'
exit 0
