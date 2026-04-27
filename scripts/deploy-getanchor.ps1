<#
PowerShell script to deploy GetAnchor-related Firebase functions in groups of five
with a 5-minute pause between each group.

Usage:
  - From Windows cmd: powershell -ExecutionPolicy Bypass -File .\scripts\deploy-getanchor.ps1
  - Or run `npm run deploy:getanchor` (added to root package.json)

The script exits immediately if any deploy command fails.
#>

# Define groups of functions (comma-separated list for each firebase deploy --only)
$groups = @(
  "functions:createGetanchorUser,functions:createGetanchorBusinessUser,functions:verifyBusinessCustomer,functions:upgradeCustomerKyc,functions:createElectronicAccount",
  "functions:fetchAccountBalance,functions:fetchAccountBalanceHttp,functions:fetchAccountDetails,functions:fetchAccountNumber,functions:freezeAccount",
  "functions:unFreezeAccount,functions:createCounterparty,functions:createNipTransfer,functions:createBookTransfer,functions:verifyTransfer",
  "functions:getAllBanks,functions:verifyAccountNumber,functions:listBillerProducts,functions:fetchDepositAccount,functions:listTransactions",
  "functions:getanchorWebhook,functions:listBillers,functions:getBillerProducts,functions:uploadDocument,functions:fetchCustomer",
  "functions:fetchCustomerAccount,functions:initiateBillPayment,functions:sendTransactionNotification,functions:getGetAnchorCustomerIdByEmail,functions:getGetAnchorCustomerTierByEmail"
)

$waitSeconds = 600 # 10 minutes

Write-Host "Starting batched GetAnchor deployment ($(Get-Date -Format u))"

for ($i = 0; $i -lt $groups.Count; $i++) {
    $group = $groups[$i]
    Write-Host "\n--- Deploying group $($i + 1)/$($groups.Count): $group ---"

    # Run firebase deploy --only <group>
    & firebase deploy --only $group
    if ($LASTEXITCODE -ne 0) {
        Write-Error "firebase deploy failed for group $($i + 1) with exit code $LASTEXITCODE. Aborting."
        exit $LASTEXITCODE
    }

    # If not the last group, wait
    if ($i -lt $groups.Count - 1) {
        Write-Host "Group $($i + 1) deployed successfully. Waiting $($waitSeconds/60) minutes before next group ($(Get-Date -Format u))."
        Start-Sleep -Seconds $waitSeconds
    }
}

Write-Host "\nAll groups deployed successfully ($(Get-Date -Format u))."
exit 0
