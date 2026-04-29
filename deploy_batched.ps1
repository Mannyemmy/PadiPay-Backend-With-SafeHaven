# deploy_batched.ps1
# Deploys SafeHaven Cloud Functions in batches to avoid rate limits.
# 5-minute breathing space between each batch.

Set-Location $PSScriptRoot

$breathingSpaceSecs = 300   # 5 minute

$functions = @(
    "safehavenCreateUser",
    "safehavenCreateBusinessUser",
    "safehavenVerifyBusinessCustomer",
    "safehavenUpgradeCustomerKyc",
    "safehavenInitiateIdentityVerification",
    "safehavenValidateIdentityVerification",
    "safehavenCreateSubAccount",
    "safehavenFetchAccountBalance",
    "safehavenFetchAccountDetails",
    "safehavenFetchAccountNumber",
    "safehavenCreateCounterparty",
    "safehavenTransferNip",
    "safehavenTransferIntra",
    "safehavenVerifyTransferByReference",
    "safehavenBankList",
    "safehavenNameEnquiry",
    "safehavenListBillerProducts",
    "safehavenFetchDepositAccount",
    "safehavenGetTransfers",
    "safehavenGetServiceCategories",
    "safehavenGetCategoryProducts",
    "safehavenPurchaseVas"
)

$batchSize  = 6
$batches    = [System.Collections.Generic.List[string[]]]::new()
$i          = 0

while ($i -lt $functions.Count) {
    $batches.Add($functions[$i..([Math]::Min($i + $batchSize - 1, $functions.Count - 1))])
    $i += $batchSize
}

$totalBatches = $batches.Count
Write-Host ""
Write-Host "=============================================="
Write-Host "  Batched Firebase Functions Deploy"
Write-Host "  Total functions : $($functions.Count)"
Write-Host "  Batch size      : $batchSize"
Write-Host "  Number of batches: $totalBatches"
Write-Host "  Breathing space : $breathingSpaceSecs s between batches"
Write-Host "=============================================="
Write-Host ""

for ($b = 0; $b -lt $totalBatches; $b++) {
    $batch      = $batches[$b]
    $batchNum   = $b + 1
    $targets    = ($batch | ForEach-Object { "functions:$_" }) -join ","

    Write-Host "----------------------------------------------"
    Write-Host "  Batch $batchNum / $totalBatches"
    Write-Host "  Functions:"
    $batch | ForEach-Object { Write-Host "    - $_" }
    Write-Host "----------------------------------------------"

    firebase deploy --only $targets
    $exitCode = $LASTEXITCODE

    if ($exitCode -ne 0) {
        Write-Host ""
        Write-Host "[ERROR] Batch $batchNum failed with exit code $exitCode. Stopping." -ForegroundColor Red
        exit $exitCode
    }

    Write-Host ""
    Write-Host "[OK] Batch $batchNum deployed successfully." -ForegroundColor Green

    if ($batchNum -lt $totalBatches) {
        Write-Host ""
        Write-Host "Waiting $breathingSpaceSecs seconds before next batch..." -ForegroundColor Cyan
        $remaining = $breathingSpaceSecs
        while ($remaining -gt 0) {
            $mins = [Math]::Floor($remaining / 60)
            $secs = $remaining % 60
            Write-Host -NoNewline "`r  Time remaining: ${mins}m ${secs}s   "
            Start-Sleep -Seconds 1
            $remaining--
        }
        Write-Host "`r  Done waiting.                     "
        Write-Host ""
    }
}

Write-Host ""
Write-Host "=============================================="
Write-Host "  All $totalBatches batches deployed successfully!" -ForegroundColor Green
Write-Host "=============================================="
