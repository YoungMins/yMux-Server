# Demo mode: the real server on http://127.0.0.1:8787 (temp data dir) and TWO fake desktops,
# "Office PC" and "Home PC", with sample panes (waiting with a 3-option menu, working, done, idle).
# Open a pairing URL in a browser (or the phone emulator) to pair; answer, interrupt and prompt work.
# Each fake desktop approves pairing with capability `prompt` and keeps a pairing window open
# (renewed every 100 s and after each request). The current links (they carry the desktop's key
# agreement key `dk`) are in <temp>\demo-urls.txt, which is rewritten whenever they change. Stops on
# Ctrl+C and leaves nothing running.
#
# Pairing needs a number: the phone shows 6 digits, and a real desktop asks its user to TYPE them.
#   -AutoApprove (default ON): the fake desktop skips the typing and approves with the number the
#       engine minted itself. A DEMO-ONLY SHORTCUT inside this #[ignore]d test harness: the
#       accessor behind it exists only in test builds; the app has no way to read the number.
#   -AutoApprove:$false: the fake desktop lists the waiting request (name and device) and waits for
#       the number in <temp>\type-check-office.txt / type-check-home.txt, e.g.
#         Set-Content <temp>\type-check-office.txt 123456
#       A wrong number counts as a try (three refuse the request), as in the real app. The script
#       prints waiting requests and the exact file names.
#
# The fake desktops are an #[ignore]d test of the ymux repo (remote::runtime::e2e::demo_fake_desktop):
# test code, not part of any build of the app.
#
#   pwsh scripts\demo.ps1 [-Ymux ..\ymux] [-Port 8787] [-SkipWebBuild] [-AutoApprove:$false]
param(
    [string]$Ymux = '..\ymux',
    [int]$Port = 8787,
    [switch]$SkipWebBuild,
    [bool]$AutoApprove = $true
)
$ErrorActionPreference = 'Stop'
$root = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$ymuxDir = (Resolve-Path (Join-Path $root $Ymux)).Path
$env:CARGO_INCREMENTAL = '0'

foreach ($p in @($root, $ymuxDir)) {
    $free = [math]::Round(((Get-Item $p).PSDrive.Free) / 1GB, 1)
    Write-Host "free space for ${p}: $free GB"
    if ($free -lt 6) { throw "less than 6 GB free for $p; stopping before a build" }
}
if (Get-NetTCPConnection -State Listen -LocalPort $Port -ErrorAction SilentlyContinue) {
    throw "port $Port is already in use"
}

$tmp = Join-Path ([IO.Path]::GetTempPath()) ("ymux-demo-" + [guid]::NewGuid().ToString('n').Substring(0, 8))
New-Item -ItemType Directory -Path $tmp, "$tmp\data", "$tmp\office", "$tmp\home" | Out-Null
$procs = @()
$urlsFile = Join-Path $tmp 'demo-urls.txt'

try {
    if (-not $SkipWebBuild) {
        Write-Host '== build web'
        Push-Location (Join-Path $root 'web')
        if (-not (Test-Path 'node_modules')) { pnpm install --frozen-lockfile; if ($LASTEXITCODE -ne 0) { throw 'pnpm install failed' } }
        pnpm build
        if ($LASTEXITCODE -ne 0) { throw 'web build failed' }
        Pop-Location
    }
    Write-Host '== build server'
    Push-Location $root
    cargo build --quiet
    if ($LASTEXITCODE -ne 0) { throw 'server build failed' }
    Pop-Location
    $serverExe = Join-Path $root 'target\debug\ymux-server.exe'

    Write-Host '== build desktop test binary'
    Push-Location $ymuxDir
    $ErrorActionPreference = 'Continue'
    $lines = cargo test -p ymux --lib --no-run --message-format=json --quiet 2>$null
    $buildExit = $LASTEXITCODE
    $ErrorActionPreference = 'Stop'
    Pop-Location
    if ($buildExit -ne 0) { throw 'desktop test build failed' }
    $art = $lines | ForEach-Object { try { $_ | ConvertFrom-Json } catch { $null } } |
        Where-Object { $_ -and $_.reason -eq 'compiler-artifact' -and $_.executable -and $_.profile.test -and ($_.target.kind -contains 'lib') } |
        Select-Object -Last 1
    if (-not $art) { throw 'could not find the desktop test binary' }
    $testExe = $art.executable

    $url = "http://127.0.0.1:$Port"
    $env:YMUX_SERVER_BIND = "127.0.0.1:$Port"
    $env:YMUX_SERVER_PUBLIC_URL = $url
    $env:YMUX_SERVER_DATA_DIR = "$tmp\data"
    $server = Start-Process -FilePath $serverExe -PassThru -NoNewWindow `
        -RedirectStandardOutput "$tmp\server.out.log" -RedirectStandardError "$tmp\server.err.log"
    $procs += $server
    $up = $false
    for ($i = 0; $i -lt 100 -and -not $up; $i++) {
        try { $up = (Invoke-WebRequest "$url/healthz" -UseBasicParsing -TimeoutSec 2).StatusCode -eq 200 }
        catch { Start-Sleep -Milliseconds 100 }
    }
    if (-not $up) { throw 'server did not come up' }
    $token = (& $serverExe token | Select-Object -Last 1).Trim()
    if (-not $token) { throw 'no setup token' }

    $desktops = @(
        @{ Name = 'Office PC'; Dir = "$tmp\office"; Type = "$tmp\type-check-office.txt" },
        @{ Name = 'Home PC'; Dir = "$tmp\home"; Type = "$tmp\type-check-home.txt" }
    )
    foreach ($d in $desktops) {
        $env:YMUX_DEMO_URL = $url
        $env:YMUX_DEMO_TOKEN = $token
        $env:YMUX_DEMO_DIR = $d.Dir
        $env:YMUX_DEMO_NAME = $d.Name
        $env:YMUX_DEMO_TYPE_FILE = $d.Type
        if ($AutoApprove) { $env:YMUX_DEMO_AUTOAPPROVE = '1' } else { Remove-Item Env:\YMUX_DEMO_AUTOAPPROVE -ErrorAction SilentlyContinue }
        $p = Start-Process -FilePath $testExe -PassThru -NoNewWindow -WorkingDirectory "$ymuxDir\src-tauri" `
            -ArgumentList @('--ignored', '--exact', '--nocapture', 'remote::runtime::e2e::demo_fake_desktop') `
            -RedirectStandardOutput "$($d.Dir)\desktop.out.log" -RedirectStandardError "$($d.Dir)\desktop.err.log"
        $procs += $p
        $d.Proc = $p
    }

    Write-Host ''
    Write-Host "Server:  $url   (data in $tmp)"
    Write-Host "Links:   $urlsFile   (rewritten when they change)"
    Write-Host ''
    if ($AutoApprove) {
        Write-Host '*** AUTO-APPROVE IS ON: DEMO-ONLY SHORTCUT. ***' -ForegroundColor Yellow
        Write-Host '    The fake desktops approve a pairing request with the check number they minted' -ForegroundColor Yellow
        Write-Host '    themselves, so nobody has to type it. The real app never does this: its user must' -ForegroundColor Yellow
        Write-Host '    type the number the phone shows (run with -AutoApprove:$false to try that).' -ForegroundColor Yellow
    }
    else {
        Write-Host 'Auto-approve is OFF: type the number your phone shows into the file of the desktop you paired with:'
        foreach ($d in $desktops) { Write-Host ("    {0}: Set-Content '{1}' <6 digits>" -f $d.Name, $d.Type) }
    }
    Write-Host ''
    Write-Host 'Press Ctrl+C to stop.'
    $last = ''
    $lastPending = ''
    while ($true) {
        foreach ($d in $desktops) {
            if ($d.Proc.HasExited) { throw "the fake desktop '$($d.Name)' exited; see $($d.Dir)\desktop.err.log" }
        }
        if ($server.HasExited) { throw "the server exited; see $tmp\server.err.log" }
        $rows = @()
        foreach ($d in $desktops) {
            $f = Join-Path $d.Dir 'pair-url.txt'
            if (Test-Path $f) { $rows += ('{0}: {1}' -f $d.Name, (Get-Content $f -Raw).Trim()) }
        }
        $text = $rows -join "`n"
        if ($text -ne $last -and $rows.Count -gt 0) {
            Set-Content -Path $urlsFile -Value $text -Encoding ascii
            Write-Host ''
            Write-Host "Pairing links ($(Get-Date -Format 'HH:mm:ss')), each good for about 2 minutes:"
            $rows | ForEach-Object { Write-Host "  $_" }
            $last = $text
        }
        $pend = @()
        foreach ($d in $desktops) {
            $f = Join-Path $d.Dir 'pair-pending.txt'
            if (Test-Path $f) { $pend += ('{0} is asked to pair: {1}' -f $d.Name, (Get-Content $f -Raw -ErrorAction SilentlyContinue).Trim()) }
        }
        $ptext = $pend -join "`n"
        if ($ptext -ne $lastPending) {
            if ($pend.Count -gt 0) {
                Write-Host ''
                $pend | ForEach-Object { Write-Host "  $_" }
                if (-not $AutoApprove) { Write-Host '  (type the number the phone shows into the file named above)' }
            }
            $lastPending = $ptext
        }
        Start-Sleep -Seconds 1
    }
}
catch {
    Write-Host "ERROR: $_"
    $script:failed = $true
}
finally {
    foreach ($p in $procs) {
        if ($p -and -not $p.HasExited) { & taskkill /F /T /PID $p.Id 2>&1 | Out-Null }
    }
    Remove-Item -Recurse -Force $tmp -ErrorAction SilentlyContinue
}
if ($script:failed) { exit 1 }
