# PadiPay Cloud Functions — Security Patterns

This document records the security vulnerabilities found and fixed in April 2026,
and the patterns that must be followed for all future Cloud Function development.

---

## 1. Webhook Signature Verification

### What went wrong
`verifySignature()` was defined but never called. Any attacker could POST a crafted
payload to `getanchorWebhook` with a fake `transaction.completed` or
`virtualNuban.credit` event and the app would process it as legitimate.

### Pattern: always verify HMAC before ANY processing

```js
app.post("/", async (req, res) => {
  const secret = anchorWebhookSecret.value();

  // ALWAYS verify signature FIRST — before JSON.parse, Firestore reads, anything.
  if (!verifySignature(req.rawBody, req.headers["x-anchor-signature"], secret)) {
    return res.status(401).json({ error: "Invalid signature" });
  }

  const event = JSON.parse(req.rawBody.toString());
  // ... safe to process now
});
```

**Rules:**
- Verify before parsing the body
- Use `crypto.timingSafeEqual` to compare — prevents timing attacks
- Return `401` immediately on failure; log the raw header for debugging
- Every webhook handler (`bridgecardWebhookHandler`, `qoreidWebhook`, `getanchorWebhook`) must do this

---

## 2. Bearer Token Auth for HTTP Endpoints

### What went wrong
`findUserByBvn` and `fetchAccountBalanceHttp` were `onRequest` functions with no
authentication. Anyone on the internet could call them and receive sensitive
financial/personal data.

### Pattern: protect all `onRequest` endpoints with Bearer token

```js
exports.myInternalEndpoint = onRequest(
  { secrets: [padiLoanApiSecret] }, // always declare the secret
  async (req, res) => {
    // SECURITY: verify Bearer token before any logic
    const authHeader = req.headers.authorization;
    const secret = padiLoanApiSecret.value();
    if (!authHeader || authHeader !== `Bearer ${secret}`) {
      return res.status(401).json({ error: "Unauthorized" });
    }
    // ... safe to proceed
  }
);
```

**Rules:**
- All `onRequest` functions that are not public webhooks must have a Bearer token guard
- The token must come from Firebase Secret Manager — never hardcoded
- Client apps (Flutter / web) must NOT call HTTP endpoints directly; use `onCall` instead
- Only server-to-server callers (internal services, admin backends) may use HTTP endpoints

### Pattern: client apps use `onCall`, which sends Firebase Auth automatically

```dart
// Flutter — correct
final result = await FirebaseFunctions.instance
    .httpsCallable('fetchAccountBalance')
    .call({'accountId': id});

// WRONG — raw HTTP from client, no auth attached
final resp = await http.post(Uri.parse('...cloudfunctions.net/fetchAccountBalanceHttp'), ...);
```

---

## 3. Never Hardcode API Keys or Tokens in Source Code

### What went wrong
`bridgecardMakeApiRequest` had a full Bridgecard API token hardcoded in the `headers`
object. This token was committed to source control and visible in Cloud Functions logs.
Even though the function accepted a `secretKey` parameter, it was ignored.

### Pattern: only use secrets from Firebase Secret Manager

```js
// In function definition:
exports.myFunction = onCall(
  { secrets: [bridgecardSecretKey] },   // declare every secret used
  async (data) => {
    const secretKey = bridgecardSecretKey.value();  // resolve at runtime
    return makeRequest({ url, secretKey });           // pass it through
  }
);

// In helper:
const makeRequest = async ({ url, method, secretKey }) => {
  const headers = { token: `Bearer ${secretKey}` };  // use the parameter
  // NEVER: token: `Bearer at_test_abc123...`
};
```

**Rules:**
- Every secret is declared in the function's `secrets: [...]` array
- Secrets are resolved with `.value()` inside the handler — never at module level
- The resolved value is passed as a parameter to helpers — helpers never resolve secrets themselves
- Run `git log -S "your_key_fragment"` before deploying if you suspect a key was ever committed; rotate the key immediately

---

## 4. OTP Brute-Force Protection

### What went wrong
`verifyEmailOTP` and `verifyPasswordResetOTP` had no attempt counter. A 6-digit OTP
has only 1,000,000 combinations. With no rate limit an attacker who obtained a `pinId`
could exhaust all possibilities before the OTP expired.

### Pattern: track attempts in the Firestore OTP document

```js
const MAX_ATTEMPTS = 5;
const attempts = (data.attempts || 0) + 1;

if (attempts > MAX_ATTEMPTS) {
  await docRef.update({ used: true }); // permanently lock this OTP
  throw new HttpsError("resource-exhausted", "Too many incorrect attempts. Request a new OTP.");
}

if (data.code !== String(code)) {
  await docRef.update({ attempts }); // persist the incremented counter
  return { verified: false };        // do NOT throw — caller can retry up to MAX
}

await docRef.update({ used: true }); // mark consumed on success
```

**Rules:**
- All OTP verification functions must have an attempt counter
- On lockout: set `used: true` so re-use is impossible, return `resource-exhausted`
- On wrong code: only persist the counter, return `{ verified: false }` — do not throw
- The `used`, `expiresAt`, and `attempts` fields must be checked in this order

### Pattern: login brute-force for Firestore-backed credentials (BRM accounts)

```ts
const failedAttempts = (brm.failedLoginAttempts || 0);
const lockedUntil = brm.lockedUntil || 0;

if (lockedUntil > Date.now()) {
  const minutesLeft = Math.ceil((lockedUntil - Date.now()) / 60000);
  throw new HttpsError("resource-exhausted", `Account temporarily locked. Try again in ${minutesLeft} minute(s).`);
}

const match = await bcrypt.compare(password, storedHash);
if (!match) {
  const newAttempts = failedAttempts + 1;
  const updateData: Record<string, any> = { failedLoginAttempts: newAttempts };
  if (newAttempts >= 5) {
    updateData.lockedUntil = Date.now() + 15 * 60 * 1000; // 15-minute lockout
  }
  await doc.ref.update(updateData);
  throw new HttpsError("unauthenticated", "Invalid email or password");
}

// Reset on success
if (failedAttempts > 0) {
  await doc.ref.update({ failedLoginAttempts: 0, lockedUntil: 0 });
}
```

---

## 5. Cryptographically Secure Randomness

### What went wrong
`Math.random()` was used to generate:
- Admin account temporary passwords
- BRM password reset tokens
- BRM referral codes

`Math.random()` is not cryptographically secure and its output can be predicted from
prior outputs in some V8 engine versions.

### Pattern: use `crypto.randomBytes()` for all security-sensitive values

```js
// Token / password (Node.js)
const token = crypto.randomBytes(32).toString("hex"); // 256 bits of entropy

// Code with character set (Node.js)
const chars = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
const randomBytes = crypto.randomBytes(length);
let code = "";
for (let i = 0; i < length; i++) {
  code += chars[randomBytes[i] % chars.length]; // uniform distribution
}
```

**When to use `crypto.randomBytes` (always):**
- Password reset tokens
- Temporary passwords
- OTP codes (if generating in-house rather than via Termii)
- Referral/invite codes
- Any value that, if predicted, gives an attacker an advantage

**When `Math.random()` is acceptable:**
- Mock data seeding amounts for demo mode (non-security context only)

---

## 6. Role Checks on All Privileged `onCall` Functions

### What went wrong
`updateUserEmail` verified Firebase Auth but not admin role. Any authenticated user
could update any other user's email — a direct account takeover vector.

### Pattern: always check auth AND role for privileged operations

```js
exports.privilegedFunction = onCall(async (request) => {
  // Step 1: authenticated at all?
  if (!request.auth) {
    throw new HttpsError("unauthenticated", "User must be authenticated");
  }

  // Step 2: correct role?
  const callerDoc = await admin.firestore().collection("admins").doc(request.auth.uid).get();
  if (!callerDoc.exists || callerDoc.data()?.role !== "admin") {
    throw new HttpsError("permission-denied", "Only admins can call this function");
  }

  // Step 3: safe to operate
});
```

**For user-facing callables, use `ensureVerifiedOrStandUser`:**

```js
exports.userFacingFunction = onCall({ secrets: [...] }, async (data) => {
  await ensureVerifiedOrStandUser(data.auth); // throws HttpsError if not allowed
  // ...
});
```

**Rules:**
- `onCall` functions never trust `request.auth` alone for privileged operations
- Pattern: auth check → role check → business logic
- `ensureVerifiedOrStandUser` covers: `email_verified === true`, `standUsers` list, `admins` list

---

## 7. Preventing SMS / Email Resource Abuse

### What went wrong
`sendTermiiSMS` had no authentication — any Firebase user (even unverified) could call
it to send arbitrary SMS to any phone number at the company's expense.

### Pattern: gate all outbound messaging functions

```js
// Callable that sends SMS/email must require verified auth
exports.sendTermiiSMS = onCall({ secrets: [termiiApiKey] }, async (request) => {
  await ensureVerifiedOrStandUser(request.auth); // rejects unverified callers
  // ...
});
```

---

## 8. Idempotency for Webhook Event Processing

The Anchor webhook already implements event deduplication via `getanchorEvents/{eventId}`.
All future webhook handlers must do the same.

```js
const eventRef = db.collection("getanchorEvents").doc(eventId);
const eventDoc = await eventRef.get();

if (eventDoc.exists) {
  return res.status(200).send("OK"); // acknowledge but skip duplicate
}

await eventRef.set({ eventId, eventType, processedAt: FieldValue.serverTimestamp() });
// ... process event
```

---

## 9. Cross-Validation of Financial Webhook Events Against the Upstream API

### The threat HMAC alone does not prevent

HMAC signature verification proves **the sender knew the webhook secret**. It does NOT
prove **the event is real on the payment processor's side**. If the secret is ever:
- leaked to an Anchor employee or contractor,
- exposed via an environment variable misconfiguration,
- extracted from a compromised server,

…an attacker can construct a perfectly-signed `payment.settled` payload with any
`amount` and `paymentId`, causing the app to create a fake deposit transaction and
notify the user they received money that never actually moved.

### The fix: query Anchor's API to confirm the event before recording it

For any event that **creates or finalises a financial record**, after the HMAC check,
fetch the referenced object from the upstream API and confirm:
1. It exists (payment / transfer ID is real)
2. Its status matches the event type
3. Its amount matches the payload amount

```js
case "payment.settled": {
  const paymentId = payment.paymentId;
  const amount   = payment.amount; // in kobo

  // SECURITY: Cross-validate before creating any Firestore transaction document.
  const apiResp = await makeApiRequest({
    url: `${BASE_URL}/payments/${encodeURIComponent(paymentId)}`,
    method: "GET",
    secretKey: getanchorSecretKey.value(),   // getanchorSecretKey must be in the function's secrets array
  });

  const apiPayment = apiResp?.data;
  if (!apiPayment?.id)                          { console.error("Payment not found"); break; }
  if (apiPayment.attributes.status !== "SETTLED") { console.error("Status mismatch"); break; }
  if (apiPayment.attributes.amount !== amount)  { console.error("Amount mismatch");  break; }

  // Safe to create the transaction record now.
}
```

### What to do when Anchor's API is unreachable

Reject the event (do not record the transaction) and `break` out of the case.
Anchor will retry the webhook. This is safer than recording a potentially forged
payment because a momentary API outage is recoverable; an undetected forged deposit
is not.

### Which events require cross-validation (rule of thumb)

| Event | Creates new financial record? | Requires cross-validation |
|---|---|---|
| `payment.settled`           | ✅ Yes — new deposit doc | ✅ Yes |
| `nip.transfer.successful`   | ❌ No — updates existing | ✅ Yes (status finalisation) |
| `bills.successful`          | ❌ No — updates existing | Recommended |
| `nip.transfer.failed`       | ❌ No — updates existing | Optional |

### Prerequisite: declare the API secret in the webhook function's secrets array

```js
exports.getanchorWebhook = onRequest(
  {
    // getanchorSecretKey is needed for cross-validation API calls inside the handler.
    secrets: [anchorWebhookSecret, getanchorSecretKey, smtpHost, smtpUser, smtpPass],
  },
  app,
);
```

---

## Quick Reference Checklist

Before deploying any new Cloud Function, verify all of these:

| Check | Requirement |
|-------|-------------|
| `onRequest` webhook | HMAC signature verified before body parse |
| `onRequest` internal endpoint | Bearer token guard using a Firebase secret |
| `onCall` user function | `ensureVerifiedOrStandUser` called first |
| `onCall` admin function | `request.auth` check + Firestore role check |
| API key usage | From `Secret Manager` via `.value()`, never hardcoded |
| Random token generation | `crypto.randomBytes()`, never `Math.random()` |
| OTP verification | Attempt counter (max 5), `used` flag, expiry check |
| Outbound SMS/email | Auth guard to prevent abuse of paid APIs |
| Webhook event | Saved to Firestore for idempotency check |
| Financial webhook event | Cross-validated against upstream API before recording |
