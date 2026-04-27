# Deploy Firebase functions in batches to avoid rate limiting.
# Usage:
#   .\scripts\deploy-batched.ps1 -Functions 'fn1','fn2' -BatchSize 5 -DelaySeconds 30
#   .\scripts\deploy-batched.ps1           # reads functions.txt if present
param(
    [string[]]$Functions = @(),
    [string[]]$SoloFunctions = @("sudoFundAndCreateCard"),
    [int]$BatchSize = 5,
    [int]$DelaySeconds = 30,
    [switch]$DryRun
)

function FailIfNoFirebase {
    if (-not (Get-Command firebase -ErrorAction SilentlyContinue)) {
        Write-Error "firebase CLI not found. Install it: npm install -g firebase-tools"
        exit 2
    }
}

if (-not $DryRun) { FailIfNoFirebase }

if ($Functions -eq $null -or $Functions.Count -eq 0) {
    if (Test-Path functions.txt) {
        $Functions = Get-Content functions.txt | Where-Object { $_ -and $_ -notmatch '^\s*#' } | ForEach-Object { $_.Trim() }
    } else {
        $scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
        $repoRoot = Resolve-Path (Join-Path $scriptDir '..')
        $indexPath = Join-Path $repoRoot 'functions\index.js'

        if (-not (Test-Path $indexPath)) {
            Write-Host "No functions specified and functions.txt not found."
            Write-Host "Usage: .\scripts\deploy-batched.ps1 -Functions 'fn1','fn2' -SoloFunctions 'sudoFun' -BatchSize 5 -DelaySeconds 30"
            exit 1
        }

        $text = Get-Content -Raw -Path $indexPath
        $text = [regex]::Replace($text, '/\*.*?\*/', '', [System.Text.RegularExpressions.RegexOptions]::Singleline)
        $text = [regex]::Replace($text, '//.*$', '', [System.Text.RegularExpressions.RegexOptions]::Multiline)

        $names = New-Object System.Collections.Generic.HashSet[string]([System.StringComparer]::OrdinalIgnoreCase)

        $m = [regex]::Matches($text, 'exports\.(\w+)')
        foreach ($mm in $m) { [void]$names.Add($mm.Groups[1].Value) }

        $m2 = [regex]::Matches($text, 'exports\[\s*([^\]]+)\s*\]')
        foreach ($mm in $m2) {
            $val = $mm.Groups[1].Value.Trim()
            $val = $val.Trim([char]34, [char]39)
            if ($val) { [void]$names.Add($val) }
        }

        $m3 = [regex]::Match($text, 'module\.exports\s*=\s*{([\s\S]*?)}', [System.Text.RegularExpressions.RegexOptions]::Singleline)
        if ($m3.Success) {
            $body = $m3.Groups[1].Value
            $m4 = [regex]::Matches($body, '([A-Za-z0-9_$]+)\s*:')
            foreach ($mm in $m4) { [void]$names.Add($mm.Groups[1].Value) }
        }

        $m5 = [regex]::Matches($text, 'Object\.defineProperty\(exports,\s*([^,\)]+)')
        foreach ($mm in $m5) {
            $val = $mm.Groups[1].Value.Trim()
            $val = $val.Trim([char]34, [char]39)
            if ($val) { [void]$names.Add($val) }
        }

        $arr = New-Object string[] $names.Count
        $names.CopyTo($arr)
        $Functions = $arr
    }
}

$Functions = $Functions | ForEach-Object { $_.Trim() } | Where-Object { $_ -ne '' }
$SoloSet = New-Object System.Collections.Generic.HashSet[string]([System.StringComparer]::OrdinalIgnoreCase)
foreach ($s in $SoloFunctions) { if ($s) { $SoloSet.Add($s) } }

# Deploy solo functions first (one by one)
foreach ($fn in $Functions) {
    if ($SoloSet.Contains($fn)) {
        Write-Host "Deploying solo function: $fn"
        $onlyArg = "functions:$fn"
        if ($DryRun) {
            Write-Host "DRYRUN: firebase deploy --only $onlyArg"
        } else {
            & firebase deploy --only $onlyArg
            if ($LASTEXITCODE -ne 0) { Write-Warning "Deploy failed for $fn (exit $LASTEXITCODE)" }
        }
        Start-Sleep -Seconds $DelaySeconds
    }
}

# Remaining functions
$remaining = $Functions | Where-Object { -not $SoloSet.Contains($_) }
if ($remaining.Count -eq 0) {
    Write-Host "No remaining functions to batch deploy."
    exit 0
}

for ($i = 0; $i -lt $remaining.Count; $i += $BatchSize) {
    $end = [math]::Min($i + $BatchSize - 1, $remaining.Count - 1)
    $batch = $remaining[$i..$end]
    $onlyArg = "functions:" + ($batch -join ",")
    Write-Host "Deploying batch: $($batch -join ', ')"
    if ($DryRun) {
        Write-Host "DRYRUN: firebase deploy --only $onlyArg"
    } else {
        & firebase deploy --only $onlyArg
        if ($LASTEXITCODE -ne 0) { Write-Warning "Batch deploy failed for $($batch -join ', ') (exit $LASTEXITCODE)" }
    }
    if ($i + $BatchSize -lt $remaining.Count) {
        Start-Sleep -Seconds $DelaySeconds
    }
}

Write-Host "All deployments completed."