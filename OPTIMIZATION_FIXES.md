# PadiPay Firebase Functions — Optimization Fixes Applied

**Date:** April 18, 2026

---

## 1. SEQUENTIAL ENTITY LOOKUPS → PARALLEL (HIGH)
**File:** `functions/index.js` — `findEntityRef()`
**Problem:** `findEntityRef()` queried businesses THEN users sequentially (2 sequential Firestore reads per webhook). Combined with `getDeviceToken()`, this meant 4 sequential reads per payment event.
**Fix:** Changed to `Promise.all()` to query both collections in parallel. Also added a check to skip the redundant user lookup when the entity is already a user (not a business account).

---

## 2. FULL COLLECTION SCAN FOR posStands (CRITICAL)
**File:** `functions/index.js` — `payment.settled` webhook handler
**Problem:** The posStand lookup scanned the ENTIRE `businesses` collection with nested loops on every `payment.settled` webhook. With 1000 businesses, this = 1000 reads × nested array iteration per webhook.
**Fix:**
- Added an optimized `posStandAccountIds` array-contains query path (O(1) read if index exists).
- Fallback still does full scan but WITHOUT the retry loop (removed the 5-retry × 500ms blocking delay).
- Recommendation: Denormalize `posStandAccountIds` onto business documents for the indexed query path.

---

## 3. INDIVIDUAL WRITES → BATCH WRITES (MEDIUM)
**File:** `functions/index.js` — `nip.transfer.successful` and bill payment handlers
**Problem:** Transaction status updates used `Promise.all(docs.map(doc => doc.ref.update(...)))` — each update was a separate Firestore write operation choking Firestore's write rate limit.
**Fix:** Replaced with `admin.firestore().batch()` for atomic batch writes (up to 500 per batch).

---

## 4. MISSING TIMEOUT ON LONG-RUNNING FUNCTION (HIGH)
**File:** `functions/index.js` — `backfillAtmTransactionsFromStatement`
**Problem:** No `timeoutSeconds` configured. Default is 60s, but statement reconciliation routinely takes 2-5 minutes, causing silent timeouts.
**Fix:** Added `timeoutSeconds: 300` (5 minutes).

---

## 5. EXCESSIVE API RESPONSE LOGGING (HIGH)
**File:** `functions/index.js` — `makeApiRequest()` and Bridgecard request handler
**Problem:** Full request headers (including auth tokens), request bodies, and entire response bodies were logged. For transactions/statements with large payloads, this bloated Cloud Logging costs significantly and posed a security risk (PII/API keys in logs).
**Fix:** Reduced to logging only method + URL + response status + size. Full error bodies logged only on non-2xx responses, truncated to 500 chars.

---

## REMAINING RECOMMENDATIONS (Not Auto-Fixed)

### A. Create Composite Firestore Indexes
Add indexes for these heavily-queried fields:
- `users.getAnchorData.customerCreation.data.id`
- `businesses.kybCreation.data.id`
- `transactions.api_response.data.id`
- `users.getAnchorData.virtualAccount.data.id`
- `businesses.posStandAccountIds` (array index)

### B. Persistent Token Caching
Currently QoreID and SafeHaven tokens are cached in-memory only. With Firebase Functions autoscaling, each new instance fetches its own token. Consider caching tokens in a Firestore `_tokenCache` collection with TTL.

### C. Rate Limiting on External API Calls
`makeApiRequest()` and `sudoRequest()` don't handle 429 (Too Many Requests) responses with backoff. Consider adding exponential backoff for rate-limited APIs.

### D. Reusable Validation Helpers
Email/phone/BVN validation is repeated in 15+ functions with the same inline code. Extract to shared validators.

### E. Transaction Type Constants
Magic strings like `"va_settlement"`, `"nip_transfer"`, `"atm_payment"` are scattered throughout. Use a shared constants object.
