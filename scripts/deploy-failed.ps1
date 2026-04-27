$batches = @(
  "functions:freezeAccount,functions:unFreezeAccount,functions:fetchAccountBalance,functions:fetchAccountBalanceHttp",
  "functions:upgradeCustomerKyc,functions:verifyAccountNumber,functions:verifyTransfer,functions:getAllBanks",
  "functions:createGetanchorBusinessUser,functions:listBillers,functions:fetchCustomerVirtualAccount,functions:fetchCustomerAccount",
  "functions:bridgecardCreateUsdCard,functions:bridgecardCreateNgnCard,functions:bridgecardGetIssuingWalletBalance,functions:bridgecardWebhookHandler",
  "functions:bridgecardFundNairaCard,functions:dailyUpdateBillers,functions:getanchorWebhook,functions:sendBrmLoginEmail",
  "functions:updateStandUser,functions:requestTermiiSenderId,functions:sendAdminLoginEmail,functions:createNipTransfer",
  "functions:reconcileAtmTransaction"
)

$waitSeconds = 180

Write-Host "Starting redeploy at $(Get-Date -Format u)"
Write-Host "Batches: $($batches.Count)"

for ($i = 0; $i -lt $batches.Count; $i++) {
    $batchNum = $i + 1
    $spec = $batches[$i]
    Write-Host ""
    Write-Host "Batch $batchNum of $($batches.Count)"
    Write-Host "Functions: $spec"
    Write-Host "Time: $(Get-Date -Format u)"

    firebase deploy --only $spec

    $code = $LASTEXITCODE
    if ($code -ne 0) {
        Write-Host "Batch $batchNum had errors (code $code). Continuing..."
    } else {
        Write-Host "Batch $batchNum done."
    }

    if ($i -lt $batches.Count - 1) {
        Write-Host "Waiting $waitSeconds seconds..."
        Start-Sleep -Seconds $waitSeconds
    }
}

Write-Host ""
Write-Host "All done at $(Get-Date -Format u)"
