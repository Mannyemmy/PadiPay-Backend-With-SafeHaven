/**
 * externalApi.js
 * ─────────────────────────────────────────────────────────────────────────────
 * BaaS (Banking-as-a-Service) layer that exposes your SafeHaven banking
 * infrastructure to external fintech clients via REST.
 *
 * Architecture
 * ─────────────────────────────────────────────────────────────────────────────
 *  Fintech Client  ──►  this API (API-key auth)  ──►  safehavenRequest()
 *                              │
 *                        Firestore
 *                   (apiClients, apiUsageLogs,
 *                    externalAccounts, externalTransactions,
 *                    externalWebhooks, rateLimits)
 *
 * How to wire into your existing index.js
 * ─────────────────────────────────────────────────────────────────────────────
 *  1. Copy this file next to index.js (same directory).
 *  2. In index.js, near the bottom, add:
 *
 *       const { registerExternalApi } = require("./externalApi");
 *       registerExternalApi({ exports, onRequest, db, admin,
 *                             safehavenRequest, safehavenClientId,
 *                             safehavenPrivateKey, safehavenCompanyUrl,
 *                             safehavenDebitAccountNumber,
 *                             _incrRateLimit });
 *
 *  3. Add the new Firebase secret to firebase.json / secrets:
 *       EXTERNAL_API_MASTER_KEY  (used only for the admin provisioning endpoint)
 *
 * Firestore collections created by this module
 * ─────────────────────────────────────────────────────────────────────────────
 *  apiClients/{clientId}
 *    keyHash       string   SHA-256 of the live API key
 *    testKeyHash   string   SHA-256 of the test/sandbox API key
 *    name          string   Fintech company name
 *    email         string   Contact email
 *    status        string   "active" | "suspended"
 *    webhookUrl    string   Where to POST SafeHaven events
 *    webhookSecret string   HMAC-SHA256 secret for signing webhook deliveries
 *    allowedIps    string[] Optional IP allowlist (empty = all IPs allowed)
 *    createdAt     timestamp
 *    updatedAt     timestamp
 *
 *  externalAccounts/{accountId}
 *    clientId      string
 *    externalRef   string   Client's own user/reference ID
 *    safehavenAccountId     string
 *    safehavenAccountNumber string
 *    safehavenBankCode      string
 *    safehavenBankName      string
 *    safehavenAccountName   string
 *    mode          string   "live" | "test"
 *    createdAt     timestamp
 *
 *  externalTransactions/{txId}
 *    clientId      string
 *    type          string   "nip" | "intra"
 *    status        string
 *    amountKobo    number
 *    reference     string
 *    idempotencyKey string
 *    mode          string   "live" | "test"
 *    createdAt     timestamp
 *
 *  apiUsageLogs/{autoId}
 *    clientId, endpoint, method, status, durationMs, mode, ip, createdAt
 *
 *  externalWebhooks/{autoId}  — outbound delivery log
 *    clientId, event, payload, status, attempts, lastAttemptAt
 */

"use strict";

const crypto = require("crypto");

// ─── Constants ───────────────────────────────────────────────────────────────

const RATE_LIMIT = {
  // per API key, per minute
  REQUESTS_PER_MIN: 60,
  WINDOW_MS: 60 * 1000,
  // per API key, per day — for financial ops
  TRANSFERS_PER_DAY: 500,
  DAY_MS: 24 * 60 * 60 * 1000,
};

const API_VERSION = "v1";
const BASE_PATH = `/${API_VERSION}`;

// ─── Helpers ─────────────────────────────────────────────────────────────────

const hashKey = (raw) =>
  crypto.createHash("sha256").update(String(raw)).digest("hex");

const generateApiKey = (prefix = "pk_live") =>
  `${prefix}_${crypto.randomBytes(32).toString("hex")}`;

const jsonError = (res, status, message, code) =>
  res.status(status).json({ error: { message, code: code || "error" } });

const jsonOk = (res, data, meta = {}) =>
  res.status(200).json({ success: true, data, ...meta });

const nowTs = (admin) => admin.firestore.FieldValue.serverTimestamp();

// QoreID token cache (per cold start)
let _qoreIdToken = null;
let _qoreIdTokenExpiresAt = 0;

const _getQoreIdToken = async (qoreIdClientId, qoreIdApiKey) => {
  const now = Date.now();
  if (_qoreIdToken && now < _qoreIdTokenExpiresAt) return _qoreIdToken;

  const clientId = qoreIdClientId?.value ? qoreIdClientId.value() : qoreIdClientId;
  const secret = qoreIdApiKey?.value ? qoreIdApiKey.value() : qoreIdApiKey;
  if (!clientId || !secret) {
    throw new Error("QoreID credentials are not configured");
  }

  const res = await fetch("https://api.qoreid.com/token", {
    method: "POST",
    headers: { accept: "application/json", "content-type": "application/json" },
    body: JSON.stringify({ clientId, secret }),
  });

  if (!res.ok) {
    const body = await res.text().catch(() => "(unreadable)");
    console.error(`[externalApi] QoreID token request failed ${res.status}: ${body}`);
    throw new Error(`QoreID token request failed: ${res.status}`);
  }

  const json = await res.json();
  const token = json?.accessToken ?? json?.token ?? json?.access_token;
  if (!token) {
    throw new Error("QoreID token response did not contain a token");
  }

  _qoreIdToken = token;
  _qoreIdTokenExpiresAt = now + 50 * 60 * 1000;
  return token;
};

const handleVerifyBvn = (qoreIdClientId, qoreIdApiKey) => async (req, res) => {
  const { bvn, firstName, lastName } = req.body || {};
  if (!bvn || typeof bvn !== "string" || bvn.trim().length !== 11) {
    return jsonError(res, 400, "BVN must be an 11-digit string", "validation_error");
  }
  if (!firstName || !lastName) {
    return jsonError(res, 400, "firstName and lastName are required", "validation_error");
  }

  const cleanBvn = bvn.trim();
  if (req.apiMode === "test") {
    return jsonOk(res, {
      verified: true,
      status: "EXACT_MATCH",
      fieldMatches: { firstname: true, lastname: true, bvn: true },
      bvnData: {
        bvn: cleanBvn,
        firstname: firstName.trim(),
        lastname: lastName.trim(),
        middlename: null,
        birthdate: null,
        gender: null,
        phone: null,
        photo: null,
      },
    });
  }

  try {
    const token = await _getQoreIdToken(qoreIdClientId, qoreIdApiKey);
    const response = await fetch(
      `https://api.qoreid.com/v1/ng/identities/bvn-basic/${encodeURIComponent(cleanBvn)}`,
      {
        method: "POST",
        headers: {
          accept: "application/json",
          "content-type": "application/json",
          Authorization: `Bearer ${token}`,
        },
        body: JSON.stringify({ firstname: String(firstName).trim(), lastname: String(lastName).trim() }),
      },
    );

    if (!response.ok) {
      const errBody = await response.text().catch(() => "(unreadable)");
      console.error(`[externalApi] QoreID BVN verify failed ${response.status}: ${errBody}`);
      if (response.status === 401) {
        _qoreIdToken = null;
        _qoreIdTokenExpiresAt = 0;
      }
      return jsonError(res, 500, `QoreID request failed: ${response.status}`, "internal");
    }

    const json = await response.json();
    const status = json?.summary?.bvn_check?.status ?? "NO_MATCH";
    const fieldMatches = json?.summary?.bvn_check?.fieldMatches ?? {};
    const isMatch = status === "EXACT_MATCH" || status === "PARTIAL_MATCH";
    const bvnRecord = json?.bvn ?? {};
    const bvnData = {
      bvn: bvnRecord.bvn ?? cleanBvn,
      firstname: bvnRecord.firstname ?? null,
      lastname: bvnRecord.lastname ?? null,
      middlename: bvnRecord.middlename ?? null,
      birthdate: bvnRecord.birthdate ?? null,
      gender: bvnRecord.gender ?? null,
      phone: bvnRecord.phone ?? null,
      photo: bvnRecord.photo ?? null,
    };

    return jsonOk(res, {
      verified: isMatch,
      status,
      fieldMatches,
      bvnData,
    });
  } catch (err) {
    console.error("[externalApi] verifyBvn error:", err);
    return jsonError(res, 500, err.message || "BVN verification failed", "internal");
  }
};

/** Deliver a webhook to a fintech client with HMAC signature */
const deliverWebhook = async ({ db, admin, clientId, event, payload }) => {
  const clientSnap = await db.collection("apiClients").doc(clientId).get();
  if (!clientSnap.exists) return;
  const client = clientSnap.data() || {};
  const webhookUrl = client.webhookUrl;
  if (!webhookUrl) return;

  const body = JSON.stringify({
    event,
    data: payload,
    timestamp: new Date().toISOString(),
  });

  const signature = crypto
    .createHmac("sha256", client.webhookSecret || "")
    .update(body)
    .digest("hex");

  const logRef = await db.collection("externalWebhooks").add({
    clientId,
    event,
    payload,
    status: "pending",
    attempts: 0,
    createdAt: nowTs(admin),
  });

  try {
    const resp = await fetch(webhookUrl, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-PadiPay-Signature": `sha256=${signature}`,
        "X-PadiPay-Event": event,
      },
      body,
      signal: AbortSignal.timeout(10000),
    });
    await logRef.update({
      status: resp.ok ? "delivered" : "failed",
      httpStatus: resp.status,
      attempts: 1,
      lastAttemptAt: nowTs(admin),
    });
  } catch (err) {
    console.error(`[externalApi] webhook delivery failed → ${clientId}`, err.message);
    await logRef.update({
      status: "failed",
      error: err.message,
      attempts: 1,
      lastAttemptAt: nowTs(admin),
    });
  }
};

// ─── Auth Middleware ──────────────────────────────────────────────────────────

/**
 * Validates `Authorization: Bearer <api_key>` and attaches `req.apiClient`
 * and `req.apiMode` ("live" | "test") to the request.
 */
const makeAuthMiddleware = (db) => async (req, res, next) => {
  const authHeader = req.headers["authorization"] || "";
  const raw = authHeader.startsWith("Bearer ") ? authHeader.slice(7).trim() : "";

  if (!raw) return jsonError(res, 401, "Missing API key", "unauthorized");

  // Determine mode from key prefix
  const isTest = raw.startsWith("pk_test_");
  const isLive = raw.startsWith("pk_live_");
  if (!isTest && !isLive) {
    return jsonError(res, 401, "Invalid API key format", "unauthorized");
  }

  const keyHash = hashKey(raw);
  const field = isTest ? "testKeyHash" : "keyHash";

  let clientSnap;
  try {
    const snap = await db
      .collection("apiClients")
      .where(field, "==", keyHash)
      .limit(1)
      .get();
    if (snap.empty) return jsonError(res, 401, "Invalid API key", "unauthorized");
    clientSnap = snap.docs[0];
  } catch (err) {
    console.error("[externalApi] auth lookup error:", err);
    return jsonError(res, 500, "Internal error", "internal");
  }

  const client = clientSnap.data() || {};

  if (client.status !== "active") {
    return jsonError(res, 403, "Account suspended. Contact support.", "forbidden");
  }

  // Optional IP allowlist
  if (Array.isArray(client.allowedIps) && client.allowedIps.length > 0) {
    const callerIp =
      (req.headers["x-forwarded-for"] || "").split(",")[0].trim() || req.ip;
    if (!client.allowedIps.includes(callerIp)) {
      return jsonError(res, 403, "IP not allowlisted", "forbidden");
    }
  }

  req.apiClient = { id: clientSnap.id, ...client };
  req.apiMode = isTest ? "test" : "live";
  next();
};

/** Rate-limit middleware — uses your existing _incrRateLimit helper */
const makeRateLimitMiddleware = (_incrRateLimit) => async (req, res, next) => {
  const clientId = req.apiClient?.id;
  if (!clientId) return next();
  try {
    const count = await _incrRateLimit(
      "external:rpm",
      clientId,
      RATE_LIMIT.REQUESTS_PER_MIN,
      RATE_LIMIT.WINDOW_MS,
    );
    res.setHeader("X-RateLimit-Limit", RATE_LIMIT.REQUESTS_PER_MIN);
    res.setHeader(
      "X-RateLimit-Remaining",
      Math.max(0, RATE_LIMIT.REQUESTS_PER_MIN - count),
    );
    if (count > RATE_LIMIT.REQUESTS_PER_MIN) {
      return jsonError(res, 429, "Rate limit exceeded. Retry after 60s.", "rate_limited");
    }
  } catch (_) {
    // fail open — don't block requests if rate limiter has an issue
  }
  next();
};

/** Request/response logger */
const makeLoggingMiddleware = (db, admin) => {
  return (req, res, next) => {
    const start = Date.now();
    res.on("finish", () => {
      const clientId = req.apiClient?.id;
      if (!clientId) return;
      db.collection("apiUsageLogs")
        .add({
          clientId,
          endpoint: req.path,
          method: req.method,
          status: res.statusCode,
          durationMs: Date.now() - start,
          mode: req.apiMode || "unknown",
          ip: (req.headers["x-forwarded-for"] || "").split(",")[0].trim() || req.ip,
          createdAt: nowTs(admin),
        })
        .catch(() => {});
    });
    next();
  };
};

// ─── Route Handlers ───────────────────────────────────────────────────────────

/**
 * POST /accounts
 * Create a virtual sub-account for one of the fintech's end-users.
 *
 * Body:
 *   externalRef    string  — fintech's own user ID (idempotency key)
 *   firstName      string
 *   lastName       string
 *   email          string
 *   phoneNumber    string  — e.g. "08012345678"
 *   bvn            string
 *   type           string  — "individual" (default) | "business"
 *   businessName   string  — required when type === "business"
 *   companyRegistrationNumber  string  — required for business
 *
 * Response:
 *   { accountId, accountNumber, bankCode, bankName, accountName, status }
 */
const handleCreateAccount = (db, admin, safehavenRequest) => async (req, res) => {
  const client = req.apiClient;
  const mode = req.apiMode;

  const {
    externalRef,
    firstName,
    lastName,
    email,
    phoneNumber,
    bvn,
    type = "individual",
    businessName,
    companyRegistrationNumber,
  } = req.body || {};

  // Validation
  const missing = [];
  if (!externalRef) missing.push("externalRef");
  if (!email) missing.push("email");
  if (!phoneNumber) missing.push("phoneNumber");
  if (type === "individual" && !bvn) missing.push("bvn");
  if (type === "business" && !companyRegistrationNumber) missing.push("companyRegistrationNumber");
  if (missing.length) {
    return jsonError(res, 400, `Missing required fields: ${missing.join(", ")}`, "validation_error");
  }

  // Idempotency — if account already exists for this client+ref, return it
  const existing = await db
    .collection("externalAccounts")
    .where("clientId", "==", client.id)
    .where("externalRef", "==", String(externalRef).trim())
    .limit(1)
    .get();

  if (!existing.empty) {
    const acc = existing.docs[0].data();
    return jsonOk(res, {
      accountId: acc.safehavenAccountId,
      accountNumber: acc.safehavenAccountNumber,
      bankCode: acc.safehavenBankCode,
      bankName: acc.safehavenBankName,
      accountName: acc.safehavenAccountName,
      status: "ACTIVE",
      externalRef: acc.externalRef,
    });
  }

  // In test mode, return a mock account without hitting SafeHaven
  if (mode === "test") {
    const mockAccount = {
      accountId: `test_acct_${crypto.randomBytes(8).toString("hex")}`,
      accountNumber: `${Math.floor(1000000000 + Math.random() * 9000000000)}`,
      bankCode: "090286",
      bankName: "Safe Haven MFB (Test)",
      accountName: `${firstName || ""} ${lastName || ""}`.trim() || businessName || "Test Account",
      status: "ACTIVE",
      externalRef,
    };
    await db.collection("externalAccounts").add({
      clientId: client.id,
      externalRef,
      mode: "test",
      ...mockAccount,
      createdAt: nowTs(admin),
    });
    return jsonOk(res, mockAccount);
  }

  // Live mode — call SafeHaven
  try {
    const isBusinessAccount = type === "business";
    const idempotencyKey = `ext_${client.id}_${hashKey(externalRef).slice(0, 16)}`;

    const subAccountBody = {
      phoneNumber: String(phoneNumber).trim(),
      emailAddress: String(email).trim(),
      externalReference: idempotencyKey,
      autoSweep: false,
    };

    if (isBusinessAccount) {
      subAccountBody.identityType = "CAC";
      subAccountBody.companyRegistrationNumber = String(companyRegistrationNumber).trim();
      if (businessName) subAccountBody.businessName = String(businessName).trim();
    } else {
      // Individual — use BVN mode directly (simplest path for external clients)
      const cleanBvn = String(bvn).trim();

      // Step 1: Initiate identity check with BVN
      let debitAccountNumber = "0104610514"; // default; override from Firestore if set
      try {
        const configDoc = await db.collection("appConfig").doc("safehaven").get();
        const cfg = configDoc.data() || {};
        debitAccountNumber = cfg.debitAccountNumber || cfg.sandboxDebitAccountNumber || debitAccountNumber;
      } catch (_) {}

      const identityResp = await safehavenRequest({
        path: "/identity/v2",
        method: "POST",
        body: { type: "BVN", number: cleanBvn, debitAccountNumber, async: false },
      });

      const identityId =
        identityResp?._id || identityResp?.data?._id || identityResp?.data?.id || identityResp?.id;

      if (!identityId) {
        return jsonError(res, 422, "BVN verification failed", "identity_error");
      }

      subAccountBody.identityType = "BVN";
      subAccountBody.identityId = identityId;
    }

    const resp = await safehavenRequest({
      path: "/accounts/subaccount",
      method: "POST",
      body: subAccountBody,
    });

    const acct = resp.data || {};
    const accountData = {
      clientId: client.id,
      externalRef: String(externalRef).trim(),
      safehavenAccountId: acct._id || acct.id || "",
      safehavenAccountNumber: acct.accountNumber || "",
      safehavenBankCode: acct.bankCode || "090286",
      safehavenBankName: acct.bankName || "Safe Haven MFB",
      safehavenAccountName: acct.accountName || "",
      mode: "live",
      createdAt: nowTs(admin),
    };

    await db.collection("externalAccounts").add(accountData);

    return jsonOk(res, {
      accountId: accountData.safehavenAccountId,
      accountNumber: accountData.safehavenAccountNumber,
      bankCode: accountData.safehavenBankCode,
      bankName: accountData.safehavenBankName,
      accountName: accountData.safehavenAccountName,
      status: acct.status || "ACTIVE",
      externalRef,
    });
  } catch (err) {
    console.error("[externalApi] createAccount error:", err);
    return jsonError(res, 500, err.message || "Account creation failed", "internal");
  }
};

/**
 * GET /accounts/:accountNumber
 * Fetch balance + details for an account owned by this client.
 */
const handleGetAccount = (db, admin, safehavenRequest) => async (req, res) => {
  const client = req.apiClient;
  const { accountNumber } = req.params;

  if (!accountNumber) return jsonError(res, 400, "accountNumber is required", "validation_error");

  // Verify account belongs to this client
  const snap = await db
    .collection("externalAccounts")
    .where("clientId", "==", client.id)
    .where("safehavenAccountNumber", "==", accountNumber.trim())
    .limit(1)
    .get();

  if (snap.empty) {
    return jsonError(res, 404, "Account not found", "not_found");
  }

  const acc = snap.docs[0].data();

  if (req.apiMode === "test") {
    return jsonOk(res, {
      accountId: acc.safehavenAccountId,
      accountNumber: acc.safehavenAccountNumber,
      bankCode: acc.safehavenBankCode,
      bankName: acc.safehavenBankName,
      accountName: acc.safehavenAccountName,
      availableBalance: 500000, // mock: ₦5,000 in kobo
      ledgerBalance: 500000,
      currency: "NGN",
      status: "ACTIVE",
    });
  }

  try {
    const resp = await safehavenRequest({
      path: `/accounts/${encodeURIComponent(acc.safehavenAccountId)}`,
      method: "GET",
    });
    const acct = resp.data || {};
    return jsonOk(res, {
      accountId: acc.safehavenAccountId,
      accountNumber: acct.accountNumber || acc.safehavenAccountNumber,
      bankCode: acc.safehavenBankCode,
      bankName: acc.safehavenBankName,
      accountName: acct.accountName || acc.safehavenAccountName,
      availableBalance: Math.round((acct.accountBalance ?? 0) * 100), // returns kobo
      ledgerBalance: Math.round((acct.ledgerBalance ?? acct.accountBalance ?? 0) * 100),
      currency: acct.currency || "NGN",
      status: acct.status || "ACTIVE",
    });
  } catch (err) {
    console.error("[externalApi] getAccount error:", err);
    return jsonError(res, 500, err.message || "Failed to fetch account", "internal");
  }
};

/**
 * POST /transfers/nip
 * Interbank (NIP) transfer — sends money to any Nigerian bank account.
 *
 * Body:
 *   fromAccountNumber  string   — must belong to this client
 *   beneficiaryAccountNumber  string
 *   beneficiaryBankCode       string   — CBN bank sort code e.g. "044"
 *   amount             number   — in kobo (smallest unit)
 *   narration          string
 *   reference          string   — client's own idempotency key (max 50 chars)
 */
const handleNipTransfer = (db, admin, safehavenRequest, _incrRateLimit) => async (req, res) => {
  const client = req.apiClient;
  const mode = req.apiMode;

  const {
    fromAccountNumber,
    beneficiaryAccountNumber,
    beneficiaryBankCode,
    amount,
    narration,
    reference,
  } = req.body || {};

  // Validation
  const missing = [];
  if (!fromAccountNumber) missing.push("fromAccountNumber");
  if (!beneficiaryAccountNumber) missing.push("beneficiaryAccountNumber");
  if (!beneficiaryBankCode) missing.push("beneficiaryBankCode");
  if (!amount || typeof amount !== "number" || amount <= 0) missing.push("amount (positive number in kobo)");
  if (!reference) missing.push("reference");
  if (missing.length) {
    return jsonError(res, 400, `Missing required fields: ${missing.join(", ")}`, "validation_error");
  }

  // Daily transfer rate limit
  const dayCount = await _incrRateLimit(
    "external:transfers:day",
    client.id,
    RATE_LIMIT.TRANSFERS_PER_DAY,
    RATE_LIMIT.DAY_MS,
  );
  if (dayCount > RATE_LIMIT.TRANSFERS_PER_DAY) {
    return jsonError(res, 429, "Daily transfer limit reached", "rate_limited");
  }

  // Idempotency check
  const existingTx = await db
    .collection("externalTransactions")
    .where("clientId", "==", client.id)
    .where("idempotencyKey", "==", String(reference).trim())
    .limit(1)
    .get();

  if (!existingTx.empty) {
    return jsonOk(res, existingTx.docs[0].data());
  }

  // Verify the source account belongs to this client
  const accSnap = await db
    .collection("externalAccounts")
    .where("clientId", "==", client.id)
    .where("safehavenAccountNumber", "==", String(fromAccountNumber).trim())
    .limit(1)
    .get();

  if (accSnap.empty) {
    return jsonError(res, 403, "fromAccountNumber does not belong to your client account", "forbidden");
  }

  const acc = accSnap.docs[0].data();

  // Test mode — mock response
  if (mode === "test") {
    const mockTx = {
      transactionId: `test_tx_${crypto.randomBytes(8).toString("hex")}`,
      type: "nip",
      status: "PENDING",
      amountKobo: amount,
      currency: "NGN",
      narration: narration || "Transfer",
      reference,
      beneficiaryAccountNumber,
      beneficiaryBankCode,
      createdAt: new Date().toISOString(),
    };
    await db.collection("externalTransactions").add({
      clientId: client.id,
      idempotencyKey: reference,
      mode: "test",
      ...mockTx,
      createdAt: nowTs(admin),
    });
    return jsonOk(res, mockTx);
  }

  // Live — run name enquiry then transfer
  try {
    // 1. Name enquiry
    const enquiryResp = await safehavenRequest({
      path: "/transfers/name-enquiry",
      method: "POST",
      body: {
        beneficiaryBankCode: String(beneficiaryBankCode).trim(),
        beneficiaryAccountNumber: String(beneficiaryAccountNumber).trim(),
        senderAccountNumber: acc.safehavenAccountNumber,
      },
    });

    const nameEnquiryReference =
      enquiryResp?.data?.nameEnquiryReference ||
      enquiryResp?.nameEnquiryReference;

    if (!nameEnquiryReference) {
      return jsonError(res, 422, "Name enquiry failed — verify beneficiary details", "name_enquiry_failed");
    }

    // 2. Execute NIP transfer
    const transferResp = await safehavenRequest({
      path: "/transfers",
      method: "POST",
      body: {
        nameEnquiryReference,
        debitAccountNumber: acc.safehavenAccountNumber,
        beneficiaryBankCode: String(beneficiaryBankCode).trim(),
        beneficiaryAccountNumber: String(beneficiaryAccountNumber).trim(),
        narration: String(narration || "Transfer").slice(0, 100),
        amount: amount / 100, // SafeHaven expects naira
        saveBeneficiary: false,
        paymentReference: String(reference).trim(),
      },
    });

    const tx = transferResp.data || {};
    const result = {
      transactionId: tx._id || tx.id || reference,
      type: "nip",
      status: tx.status || "PENDING",
      amountKobo: amount,
      currency: "NGN",
      narration: narration || "Transfer",
      reference: tx.paymentReference || reference,
      beneficiaryAccountNumber,
      beneficiaryBankCode,
      beneficiaryName: enquiryResp?.data?.beneficiaryName || "",
      createdAt: new Date().toISOString(),
    };

    await db.collection("externalTransactions").add({
      clientId: client.id,
      idempotencyKey: reference,
      mode: "live",
      ...result,
      createdAt: nowTs(admin),
    });

    return jsonOk(res, result);
  } catch (err) {
    console.error("[externalApi] nipTransfer error:", err);
    return jsonError(res, 500, err.message || "Transfer failed", "internal");
  }
};

/**
 * POST /transfers/intra
 * Book transfer (intra-bank) — between two Safe Haven MFB accounts.
 * This is instant and free.
 *
 * Body:
 *   fromAccountNumber  string   — must belong to this client
 *   toAccountNumber    string   — destination Safe Haven account
 *   amount             number   — kobo
 *   narration          string
 *   reference          string
 */
const handleIntraTransfer = (db, admin, safehavenRequest, _incrRateLimit) => async (req, res) => {
  const client = req.apiClient;
  const mode = req.apiMode;

  const { fromAccountNumber, toAccountNumber, amount, narration, reference } = req.body || {};

  const missing = [];
  if (!fromAccountNumber) missing.push("fromAccountNumber");
  if (!toAccountNumber) missing.push("toAccountNumber");
  if (!amount || typeof amount !== "number" || amount <= 0) missing.push("amount (positive number in kobo)");
  if (!reference) missing.push("reference");
  if (missing.length) {
    return jsonError(res, 400, `Missing required fields: ${missing.join(", ")}`, "validation_error");
  }

  if (fromAccountNumber === toAccountNumber) {
    return jsonError(res, 400, "fromAccountNumber and toAccountNumber must be different", "validation_error");
  }

  // Idempotency
  const existingTx = await db
    .collection("externalTransactions")
    .where("clientId", "==", client.id)
    .where("idempotencyKey", "==", String(reference).trim())
    .limit(1)
    .get();
  if (!existingTx.empty) return jsonOk(res, existingTx.docs[0].data());

  // Verify source account
  const accSnap = await db
    .collection("externalAccounts")
    .where("clientId", "==", client.id)
    .where("safehavenAccountNumber", "==", String(fromAccountNumber).trim())
    .limit(1)
    .get();

  if (accSnap.empty) {
    return jsonError(res, 403, "fromAccountNumber does not belong to your client account", "forbidden");
  }
  const acc = accSnap.docs[0].data();

  if (mode === "test") {
    const mockTx = {
      transactionId: `test_itx_${crypto.randomBytes(8).toString("hex")}`,
      type: "intra",
      status: "SUCCESSFUL",
      amountKobo: amount,
      currency: "NGN",
      narration: narration || "Transfer",
      reference,
      toAccountNumber,
      createdAt: new Date().toISOString(),
    };
    await db.collection("externalTransactions").add({
      clientId: client.id,
      idempotencyKey: reference,
      mode: "test",
      ...mockTx,
      createdAt: nowTs(admin),
    });
    return jsonOk(res, mockTx);
  }

  try {
    const transferResp = await safehavenRequest({
      path: "/transfers/intra-bank",
      method: "POST",
      body: {
        originatorAccountNumber: acc.safehavenAccountNumber,
        beneficiaryAccountNumber: String(toAccountNumber).trim(),
        amount: amount / 100,
        narration: String(narration || "Transfer").slice(0, 100),
        paymentReference: String(reference).trim(),
        saveBeneficiary: false,
      },
    });

    const tx = transferResp.data || {};
    const result = {
      transactionId: tx._id || tx.id || reference,
      type: "intra",
      status: tx.status || "SUCCESSFUL",
      amountKobo: amount,
      currency: "NGN",
      narration: narration || "Transfer",
      reference: tx.paymentReference || reference,
      toAccountNumber,
      createdAt: new Date().toISOString(),
    };

    await db.collection("externalTransactions").add({
      clientId: client.id,
      idempotencyKey: reference,
      mode: "live",
      ...result,
      createdAt: nowTs(admin),
    });

    return jsonOk(res, result);
  } catch (err) {
    console.error("[externalApi] intraTransfer error:", err);
    return jsonError(res, 500, err.message || "Transfer failed", "internal");
  }
};

/**
 * GET /transfers/:reference
 * Fetch a transaction by client-supplied reference.
 */
const handleGetTransaction = (db) => async (req, res) => {
  const client = req.apiClient;
  const { reference } = req.params;

  if (!reference) return jsonError(res, 400, "reference is required", "validation_error");

  const snap = await db
    .collection("externalTransactions")
    .where("clientId", "==", client.id)
    .where("idempotencyKey", "==", reference.trim())
    .limit(1)
    .get();

  if (snap.empty) return jsonError(res, 404, "Transaction not found", "not_found");

  return jsonOk(res, snap.docs[0].data());
};

/**
 * GET /banks
 * List supported banks for NIP transfers — proxied from SafeHaven.
 * Cached in Firestore for 24h to avoid hammering the upstream.
 */
const handleListBanks = (db, admin, safehavenRequest) => async (req, res) => {
  if (req.apiMode === "test") {
    return jsonOk(res, [
      { bankCode: "044", bankName: "Access Bank" },
      { bankCode: "058", bankName: "GTBank" },
      { bankCode: "057", bankName: "Zenith Bank" },
    ]);
  }

  // 24h cache
  try {
    const cacheDoc = await db.collection("appConfig").doc("bankListCache").get();
    const cache = cacheDoc.data() || {};
    const age = Date.now() - Number(cache.cachedAt || 0);
    if (cache.banks && age < 24 * 60 * 60 * 1000) {
      return jsonOk(res, cache.banks);
    }
  } catch (_) {}

  try {
    const resp = await safehavenRequest({ path: "/transfers/banks", method: "GET" });
    const banks = Array.isArray(resp.data) ? resp.data : [];
    const normalized = banks.map((b) => ({
      bankCode: b.bankCode || b.code || "",
      bankName: b.bankName || b.name || "",
    }));

    await db.collection("appConfig").doc("bankListCache").set(
      { banks: normalized, cachedAt: Date.now() },
      { merge: true },
    );

    return jsonOk(res, normalized);
  } catch (err) {
    console.error("[externalApi] listBanks error:", err);
    return jsonError(res, 500, "Failed to fetch bank list", "internal");
  }
};

/**
 * POST /verify/account
 * Name enquiry — resolve account name before initiating a transfer.
 *
 * Body:
 *   accountNumber  string
 *   bankCode       string
 */
const handleVerifyAccount = (db, safehavenRequest) => async (req, res) => {
  const { accountNumber, bankCode } = req.body || {};
  if (!accountNumber || !bankCode) {
    return jsonError(res, 400, "accountNumber and bankCode are required", "validation_error");
  }

  if (req.apiMode === "test") {
    return jsonOk(res, {
      accountNumber,
      bankCode,
      accountName: "TEST ACCOUNT NAME",
    });
  }

  try {
    // Get any account number owned by this client to use as the "sender" for enquiry
    const anyAccSnap = await db
      .collection("externalAccounts")
      .where("clientId", "==", req.apiClient.id)
      .limit(1)
      .get();

    const senderAccountNumber = anyAccSnap.empty
      ? ""
      : anyAccSnap.docs[0].data().safehavenAccountNumber;

    const resp = await safehavenRequest({
      path: "/transfers/name-enquiry",
      method: "POST",
      body: {
        beneficiaryAccountNumber: String(accountNumber).trim(),
        beneficiaryBankCode: String(bankCode).trim(),
        senderAccountNumber,
      },
    });

    const data = resp.data || {};
    return jsonOk(res, {
      accountNumber,
      bankCode,
      accountName: data.beneficiaryName || data.accountName || "",
      nameEnquiryReference: data.nameEnquiryReference || "",
    });
  } catch (err) {
    console.error("[externalApi] verifyAccount error:", err);
    return jsonError(res, 500, err.message || "Account verification failed", "internal");
  }
};

/**
 * PUT /webhooks
 * Let a fintech update their webhook URL and/or rotate their webhook signing secret.
 *
 * Body:
 *   webhookUrl     string  — HTTPS URL SafeHaven events will be forwarded to
 *   rotateSecret   bool    — if true, generates a new signing secret
 */
const handleUpdateWebhook = (db, admin) => async (req, res) => {
  const client = req.apiClient;
  const { webhookUrl, rotateSecret } = req.body || {};

  if (!webhookUrl) return jsonError(res, 400, "webhookUrl is required", "validation_error");

  try {
    new URL(webhookUrl); // throws if invalid
    if (!webhookUrl.startsWith("https://")) {
      return jsonError(res, 400, "webhookUrl must use HTTPS", "validation_error");
    }
  } catch {
    return jsonError(res, 400, "webhookUrl is not a valid URL", "validation_error");
  }

  const patch = {
    webhookUrl,
    updatedAt: nowTs(admin),
  };

  let newSecret;
  if (rotateSecret) {
    newSecret = crypto.randomBytes(32).toString("hex");
    patch.webhookSecret = newSecret;
  }

  await db.collection("apiClients").doc(client.id).update(patch);

  return jsonOk(res, {
    webhookUrl,
    ...(newSecret ? { webhookSecret: newSecret, note: "Store this secret securely. It will not be shown again." } : {}),
  });
};

// ─── Admin Provisioning Endpoint ─────────────────────────────────────────────
// Protected by a master key (EXTERNAL_API_MASTER_KEY secret). Use this to
// onboard new fintech clients. This route is NOT mounted on the external app —
// it's a separate Cloud Function.

const makeProvisionHandler = (db, admin, masterKey) => async (req, res) => {
  if (req.method !== "POST") return res.status(405).json({ error: "Method not allowed" });

  const provided = (req.headers["x-master-key"] || "").trim();
  if (!provided || !crypto.timingSafeEqual(Buffer.from(provided), Buffer.from(masterKey))) {
    return res.status(401).json({ error: "Invalid master key" });
  }

  const { name, email, webhookUrl } = req.body || {};
  if (!name || !email) return res.status(400).json({ error: "name and email are required" });

  const liveKey = generateApiKey("pk_live");
  const testKey = generateApiKey("pk_test");
  const webhookSecret = crypto.randomBytes(32).toString("hex");

  const docRef = await db.collection("apiClients").add({
    name: String(name).trim(),
    email: String(email).trim(),
    webhookUrl: webhookUrl || "",
    webhookSecret,
    keyHash: hashKey(liveKey),
    testKeyHash: hashKey(testKey),
    status: "active",
    allowedIps: [],
    createdAt: nowTs(admin),
    updatedAt: nowTs(admin),
  });

  return res.status(201).json({
    clientId: docRef.id,
    liveKey,
    testKey,
    webhookSecret,
    warning: "Store these credentials securely. The plain-text keys will not be shown again.",
  });
};

// ─── Registration ─────────────────────────────────────────────────────────────

/**
 * Call this from index.js to wire up the external API.
 *
 * @param {object} deps
 * @param {object} deps.exports           — Firebase exports object
 * @param {function} deps.onRequest       — firebase-functions onRequest
 * @param {object} deps.db                — Firestore instance
 * @param {object} deps.admin             — firebase-admin
 * @param {function} deps.safehavenRequest — your existing safehavenRequest helper
 * @param {object} deps.safehavenClientId  — secret ref
 * @param {object} deps.safehavenPrivateKey — secret ref
 * @param {object} deps.safehavenCompanyUrl — secret ref
 * @param {object} deps.safehavenDebitAccountNumber — secret ref
 * @param {object} deps.qoreIdClientId — secret ref
 * @param {object} deps.qoreIdApiKey — secret ref
 * @param {function} deps._incrRateLimit  — your existing rate limiter
 * @param {object} deps.externalApiMasterKey — secret ref (defineSecret("EXTERNAL_API_MASTER_KEY"))
 */
const registerExternalApi = (deps) => {
  const {
    exports: exp,
    onRequest,
    db,
    admin,
    safehavenRequest,
    safehavenClientId,
    safehavenPrivateKey,
    safehavenCompanyUrl,
    safehavenDebitAccountNumber,
    qoreIdClientId,
    qoreIdApiKey,
    _incrRateLimit,
    externalApiMasterKey,
  } = deps;

  const express = require("express");
  const cors = require("cors");

  // ── External BaaS app ──────────────────────────────────────────────────────
  const externalApp = express();
  externalApp.use(cors({ origin: true }));
  externalApp.use(express.json());

  const authMiddleware = makeAuthMiddleware(db);
  const rateLimitMiddleware = makeRateLimitMiddleware(_incrRateLimit);
  const loggingMiddleware = makeLoggingMiddleware(db, admin);

  // Public endpoints (no auth needed)
  externalApp.get(`${BASE_PATH}/health`, (_req, res) => {
    res.json({ status: "ok", version: API_VERSION, timestamp: new Date().toISOString() });
  });

  // Apply auth + rate limiting + logging to all protected routes
  externalApp.use(BASE_PATH, authMiddleware, rateLimitMiddleware, loggingMiddleware);

  // Account routes
  externalApp.post(`${BASE_PATH}/accounts`, handleCreateAccount(db, admin, safehavenRequest));
  externalApp.get(`${BASE_PATH}/accounts/:accountNumber`, handleGetAccount(db, admin, safehavenRequest));

  // Transfer routes
  externalApp.post(`${BASE_PATH}/transfers/nip`, handleNipTransfer(db, admin, safehavenRequest, _incrRateLimit));
  externalApp.post(`${BASE_PATH}/transfers/intra`, handleIntraTransfer(db, admin, safehavenRequest, _incrRateLimit));
  externalApp.get(`${BASE_PATH}/transfers/:reference`, handleGetTransaction(db));

  // Utility routes
  externalApp.get(`${BASE_PATH}/banks`, handleListBanks(db, admin, safehavenRequest));
  externalApp.post(`${BASE_PATH}/verify/account`, handleVerifyAccount(db, safehavenRequest));
  externalApp.post(`${BASE_PATH}/verify/bvn`, handleVerifyBvn(qoreIdClientId, qoreIdApiKey));
  externalApp.put(`${BASE_PATH}/webhooks`, handleUpdateWebhook(db, admin));

  // 404 catch-all for the external API
  externalApp.use((req, res) => {
    jsonError(res, 404, `Route ${req.method} ${req.path} not found`, "not_found");
  });

  // ── Firebase Cloud Function: externalApi ───────────────────────────────────
  exp.externalApi = onRequest(
    {
      secrets: [
        safehavenClientId,
        safehavenPrivateKey,
        safehavenCompanyUrl,
        safehavenDebitAccountNumber,
        qoreIdClientId,
        qoreIdApiKey,
      ],
    },
    externalApp,
  );

  // ── Admin provisioning function ────────────────────────────────────────────
  exp.provisionApiClient = onRequest(
    { secrets: [externalApiMasterKey] },
    async (req, res) => {
      const cors_ = require("cors");
      cors_({ origin: false })(req, res, async () => {
        const masterKey = externalApiMasterKey.value();
        return makeProvisionHandler(db, admin, masterKey)(req, res);
      });
    },
  );

  console.log("[externalApi] BaaS routes registered.");
};

/**
 * Webhook fan-out helper — call this from your existing safehavenWebhook
 * handler whenever you process an inbound SafeHaven event, so the event
 * gets forwarded to the relevant fintech client.
 *
 * Usage (inside safehavenApp route handler in index.js):
 *
 *   const { forwardWebhookToClient } = require("./externalApi");
 *   // ... after you identify which client the account belongs to:
 *   await forwardWebhookToClient({ db, admin, accountNumber, event, payload });
 */
const forwardWebhookToClient = async ({ db, admin, accountNumber, event, payload }) => {
  if (!accountNumber) return;
  try {
    const snap = await db
      .collection("externalAccounts")
      .where("safehavenAccountNumber", "==", String(accountNumber).trim())
      .limit(1)
      .get();

    if (snap.empty) return; // Account not managed by external API — ignore

    const { clientId } = snap.docs[0].data();
    await deliverWebhook({ db, admin, clientId, event, payload });
  } catch (err) {
    console.error("[externalApi] forwardWebhookToClient error:", err);
  }
};

module.exports = { registerExternalApi, forwardWebhookToClient };