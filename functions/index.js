const { onSchedule } = require("firebase-functions/v2/scheduler");
const { serverTimestamp } = require("@google-cloud/firestore");
const { getFirestore } = require("firebase-admin/firestore");
const { getMessaging } = require("firebase-admin/messaging");
const {
  onCall,
  HttpsError,
  onRequest,
} = require("firebase-functions/v2/https");
const { defineSecret } = require("firebase-functions/params");
const admin = require("firebase-admin");
const express = require("express");
const cors = require("cors");
const crypto = require("crypto");
const { type } = require("os");
const AES256 = require("aes-everywhere");
const { error } = require("console");
const nodemailer = require("nodemailer");
const textToSpeech = require("@google-cloud/text-to-speech");
admin.initializeApp();
const bridgecardSecretKey = defineSecret("BRIDGECARD_SECRET_KEY");
const strowalletPublicKey = defineSecret("STROWALLET_PUBLIC_KEY");
const bridgecardWebhookSecret = defineSecret("BRIDGECARD_WEBHOOK_SECRET");
const qoreidWebhookSecret = defineSecret("QOREID_WEBHOOK_SECRET");

const sudoApiKey = defineSecret("SUDO_API_KEY");
const sudoWebhookSecret = defineSecret("SUDO_WEBHOOK_SECRET");
const bridgecardBaseUrl =
  "https://issuecards.api.bridgecard.co/v1/issuing/sandbox/";
const getanchorSecretKey = defineSecret("GETANCHOR_SECRET_KEY");
const qoreIdApiKey = defineSecret("QOREID_API_KEY");
const qoreIdClientId = defineSecret("QOREID_CLIENT_ID");
// Safe Haven MFB ? OAuth2 client-credentials secrets
const safehavenClientId = defineSecret("SAFEHAVEN_CLIENT_ID");
const safehavenPrivateKey = defineSecret("SAFEHAVEN_PRIVATE_KEY"); // RS256 PEM private key
const safehavenCompanyUrl = defineSecret("SAFEHAVEN_COMPANY_URL"); // e.g. https://yourcompany.com
const safehavenDebitAccountNumber = defineSecret("SAFEHAVEN_DEBIT_ACCOUNT_NUMBER");
// SafeHaven webhook secret removed: SafeHaven does not require HMAC verification
// const safehavenWebhookSecret = defineSecret("SAFEHAVEN_WEBHOOK_SECRET");
// Use sandbox URL for all Getanchor API calls
// Update BASE_URL here if switching to live environment
const BASE_URL = "https://api.getanchor.co/api/v1";
const SANDBOX_BASE_URL = "https://api.sandbox.getanchor.co/api/v1";

const anchorWebhookSecret = defineSecret("ANCHOR_WEBHOOK_SECRET");
const anchorWebhookSecretSecondary = defineSecret(
  "ANCHOR_WEBHOOK_SECRET_SECONDARY",
);
const padiLoanApiSecret = defineSecret("PADILOAN_API_SECRET");

// Termii API secret for SMS and OTP
const termiiApiKey = defineSecret("TERMII_API_KEY");

// SMTP secrets (NodeMailer)
const smtpHost = defineSecret("SMTP_HOST");
const smtpUser = defineSecret("SMTP_USER");
const smtpPass = defineSecret("SMTP_PASS");
const db = admin.firestore();
const ttsClient = new textToSpeech.TextToSpeechClient();

// FCM platform config ? forces Android to use padi_transactions_channel (Importance.max, sound ON)
// and sets high priority so messages wake the device even in background/Doze.
const FCM_CHANNEL = {
  android: {
    priority: "high",
    notification: {
      channelId: "padi_transactions_channel",
      sound: "default",
      defaultSound: true,
      defaultVibrateTimings: true,
      priority: "max",
      visibility: "public",
    },
  },
  apns: {
    payload: { aps: { sound: "default" } },
    headers: { "apns-priority": "10", "apns-push-type": "alert" },
  },
};

const app = express();
app.use(cors({ origin: true }));
app.use(
  express.json({
    verify: (req, res, buf) => {
      req.rawBody = buf;
    },
  }),
);

// Separate Express app for SafeHaven webhooks (exposed as its own function)
const safehavenApp = express();
safehavenApp.use(cors({ origin: true }));
safehavenApp.use(
  express.json({
    verify: (req, res, buf) => {
      req.rawBody = buf;
    },
  }),
);

// Export SafeHaven webhook as a separate Cloud Function
exports.safehavenWebhook = onRequest(safehavenApp);

const sendViaSMTP = async ({ to, subject, html, text, replyTo }) => {
  const host = smtpHost.value();
  const user = smtpUser.value();
  const pass = smtpPass.value();

  if (!host || !user || !pass) {
    throw new Error("SMTP credentials are not configured.");
  }

  const transporter = nodemailer.createTransport({
    host,
    port: 587,
    secure: false,
    auth: { user, pass },
  });

  const mailOptions = {
    from: `"PadiPay" <${user}>`,
    to: Array.isArray(to) ? to.join(", ") : to,
    subject,
    html,
  };

  if (text) mailOptions.text = text;
  if (replyTo) mailOptions.replyTo = replyTo;

  const info = await transporter.sendMail(mailOptions);
  return info.messageId;
};

// Helper function to validate input data
const validateData = (data, requiredFields) => {
  if (!data || typeof data !== "object") {
    throw new HttpsError("invalid-argument", "Invalid data format");
  }

  requiredFields.forEach(({ key, message, validator }) => {
    const rawValue = data[key];
    const value = typeof rawValue === "string" ? rawValue.trim() : rawValue;

    if (
      value === undefined ||
      value === null ||
      value === "" ||
      (validator && !validator(value))
    ) {
      throw new HttpsError("invalid-argument", message);
    }
  });
};

// -------------------------
// Rate limiting helpers
// -------------------------
// Uses Firestore collection `rateLimits` with documents keyed by
// `${scope}:${sha256(id)}`. Documents store { count, expiresAt }.
const _rateLimitDocId = (scope, id) => `${scope}:${crypto.createHash("sha256").update(String(id || "")).digest("hex")}`;

const _incrRateLimit = async (scope, id, limit, windowMs) => {
  if (!id) return 0;
  const docId = _rateLimitDocId(scope, id);
  const ref = db.collection("rateLimits").doc(docId);
  const now = Date.now();
  try {
    return await db.runTransaction(async (tx) => {
      const snap = await tx.get(ref);
      if (!snap.exists) {
        tx.set(ref, {
          count: 1,
          expiresAt: now + windowMs,
          createdAt: admin.firestore.FieldValue.serverTimestamp(),
        });
        return 1;
      }
      const data = snap.data() || {};
      const expiresAt = Number(data.expiresAt || 0);
      const count = Number(data.count || 0);
      if (now > expiresAt) {
        tx.set(
          ref,
          {
            count: 1,
            expiresAt: now + windowMs,
            createdAt: admin.firestore.FieldValue.serverTimestamp(),
          },
          { merge: true },
        );
        return 1;
      }
      const newCount = count + 1;
      tx.update(ref, { count: newCount });
      return newCount;
    });
  } catch (err) {
    console.error(`[rateLimit] transaction error for ${scope} ${id}:`, err);
    // Fail closed: return a very large number to block action when rate limiter fails
    return Number.MAX_SAFE_INTEGER;
  }
};

const _resetRateLimit = async (scope, id) => {
  if (!id) return;
  const docId = _rateLimitDocId(scope, id);
  try {
    await db.collection("rateLimits").doc(docId).delete();
  } catch (err) {
    // ignore
  }
};

const _getCallerIp = (req) => {
  try {
    const raw = req && (req.rawRequest || req.rawRequest);
    if (!raw) return null;
    const headers = raw.headers || {};
    const forwarded = headers["x-forwarded-for"] || headers["x-client-ip"] || headers["x-appengine-user-ip"] || headers["x-real-ip"];
    if (forwarded) return String(forwarded).split(",")[0].trim();
    if (raw.ip) return raw.ip;
    if (raw.connection && raw.connection.remoteAddress) return raw.connection.remoteAddress;
    return null;
  } catch (e) {
    return null;
  }
};

const STOREFRONT_SESSION_TTL_MS = 7 * 24 * 60 * 60 * 1000;
const STOREFRONT_OTP_TTL_MS = 10 * 60 * 1000;

const normalizePhone = (value) => {
  const digits = String(value || "").replace(/\D/g, "");
  if (!digits) return "";
  if (digits.length === 11 && digits.startsWith("0")) {
    return `234${digits.slice(1)}`;
  }
  if (digits.length === 10) {
    return `234${digits}`;
  }
  if (digits.length === 13 && digits.startsWith("234")) {
    return digits;
  }
  return digits;
};

const getPhoneLookupVariants = (value) => {
  const normalized = normalizePhone(value);
  if (!normalized) return [];

  const variants = new Set([normalized]);
  if (normalized.startsWith("234") && normalized.length === 13) {
    variants.add(`+${normalized}`);
    variants.add(`0${normalized.slice(3)}`);
  }

  return Array.from(variants);
};

const hashStorefrontPassword = (password, saltHex = null) => {
  const salt = saltHex ? Buffer.from(saltHex, "hex") : crypto.randomBytes(16);
  const derived = crypto.pbkdf2Sync(String(password), salt, 120000, 64, "sha512");
  return {
    salt: salt.toString("hex"),
    hash: derived.toString("hex"),
  };
};

const verifyStorefrontPassword = (password, saltHex, hashHex) => {
  const cleanSaltHex = String(saltHex || "").trim();
  const cleanHashHex = String(hashHex || "").trim();

  if (!cleanSaltHex || !cleanHashHex) {
    return false;
  }

  try {
    const { hash } = hashStorefrontPassword(password, cleanSaltHex);
    const computedBuffer = Buffer.from(hash, "hex");
    const storedBuffer = Buffer.from(cleanHashHex, "hex");

    if (computedBuffer.length === 0 || storedBuffer.length === 0) {
      return false;
    }
    if (computedBuffer.length !== storedBuffer.length) {
      return false;
    }

    return crypto.timingSafeEqual(computedBuffer, storedBuffer);
  } catch (error) {
    console.error("[storefront] verifyStorefrontPassword failed:", error);
    return false;
  }
};

const sanitizeUsername = (value) =>
  String(value || "")
    .trim()
    .toLowerCase()
    .replace(/[^a-z0-9_]/g, "");

const pickStorefrontUid = (usernameDocData = {}) => {
  const candidates = [
    usernameDocData.uid,
    usernameDocData.userId,
    usernameDocData.ownerUid,
    usernameDocData.merchantUid,
  ];

  for (const candidate of candidates) {
    const value = String(candidate || "").trim();
    if (value) {
      return value;
    }
  }

  return "";
};

const findUserByUsernameFallback = async (username) => {
  const candidateFields = ["username", "userName", "tag", "userTag"];

  for (const field of candidateFields) {
    const snap = await db
      .collection("users")
      .where(field, "==", username)
      .limit(1)
      .get();

    if (!snap.empty) {
      return snap.docs[0];
    }
  }

  return null;
};

const getMerchantForStorefront = async (usernameInput) => {
  const username = sanitizeUsername(usernameInput);
  if (!username) {
    throw new HttpsError("invalid-argument", "A valid username is required.");
  }

  const usernameSnap = await db.collection("usernames").doc(username).get();
  const usernameData = usernameSnap.exists ? usernameSnap.data() || {} : {};

  let uid = pickStorefrontUid(usernameData);
  let userSnap = null;

  if (uid) {
    userSnap = await db.collection("users").doc(uid).get();
    if (!userSnap.exists) {
      userSnap = null;
      uid = "";
    }
  }

  if (!userSnap) {
    userSnap = await findUserByUsernameFallback(username);
    uid = userSnap?.id || "";
  }

  if (!userSnap || !uid) {
    throw new HttpsError("not-found", "Merchant storefront not found.");
  }

  const businessSnap = await db.collection("businesses").doc(uid).get();

  const userData = userSnap.data() || {};
  const businessData = businessSnap.exists ? businessSnap.data() || {} : {};

  const fullName = `${String(userData.firstName || "").trim()} ${String(userData.lastName || "").trim()}`.trim();
  const businessName =
    String(
      businessData.business_name ||
        businessData.businessName ||
        userData.businessName ||
        fullName ||
        username,
    ).trim();

  const vaFromUser = userData.getAnchorData?.virtualAccount?.data;
  const vaFromBusiness = businessData.getAnchorData?.virtualAccount?.data;
  const vaData = vaFromBusiness || vaFromUser || null;

  const accountId = vaData?.id || "";
  const accountType = vaData?.type || "DepositAccount";
  const accountNumber = vaData?.attributes?.accountNumber || "";
  const bankName = vaData?.attributes?.bank?.name || "";

  return {
    uid,
    username,
    businessName,
    ownerName: fullName,
    phone: normalizePhone(userData.phone || ""),
    accountId: String(accountId || ""),
    accountType: String(accountType || "DepositAccount"),
    accountNumber: String(accountNumber || ""),
    bankName: String(bankName || ""),
    active: userData.isBlocked !== true,
  };
};

const createStorefrontSession = async (customerId, phone, metadata = {}) => {
  const plainToken = crypto.randomBytes(32).toString("hex");
  const tokenHash = crypto.createHash("sha256").update(plainToken).digest("hex");
  const now = Date.now();
  await db.collection("storefrontSessions").add({
    customerId,
    phone: normalizePhone(phone),
    tokenHash,
    createdAt: admin.firestore.FieldValue.serverTimestamp(),
    expiresAtMs: now + STOREFRONT_SESSION_TTL_MS,
    ...metadata,
  });
  return plainToken;
};

const getStorefrontSession = async (sessionToken) => {
  const token = String(sessionToken || "").trim();
  if (!token) {
    throw new HttpsError("unauthenticated", "Session token is required.");
  }
  const tokenHash = crypto.createHash("sha256").update(token).digest("hex");
  const snap = await db
    .collection("storefrontSessions")
    .where("tokenHash", "==", tokenHash)
    .limit(1)
    .get();
  if (snap.empty) {
    throw new HttpsError("unauthenticated", "Invalid session token.");
  }
  const doc = snap.docs[0];
  const data = doc.data() || {};
  if (Date.now() > Number(data.expiresAtMs || 0)) {
    await doc.ref.delete().catch(() => null);
    throw new HttpsError("unauthenticated", "Session expired.");
  }
  return { id: doc.id, ...data };
};

const createStorefrontTransactionRecord = async ({
  userId,
  type,
  amountNaira,
  reference,
  status,
  extra = {},
}) => {
  await db.collection("transactions").add({
    userId,
    type,
    amount: amountNaira,
    reference,
    status,
    timestamp: admin.firestore.FieldValue.serverTimestamp(),
    ...extra,
  });
};

const fulfillStorefrontOrder = async (orderId) => {
  const orderRef = db.collection("storefrontOrders").doc(orderId);
  const orderSnap = await orderRef.get();
  if (!orderSnap.exists) {
    throw new HttpsError("not-found", "Order not found.");
  }

  const order = orderSnap.data() || {};
  if (order.status === "fulfilled") {
    return { ok: true, status: "fulfilled", alreadyFulfilled: true };
  }
  if (order.status !== "paid") {
    throw new HttpsError("failed-precondition", "Order is not paid yet.");
  }

  const merchant = await getMerchantForStorefront(order.merchantUsername);
  if (!merchant.accountId) {
    throw new HttpsError("failed-precondition", "Merchant account not configured.");
  }

  const secretKey = getanchorSecretKey.value();
  if (!secretKey) {
    throw new HttpsError("internal", "Getanchor Secret Key is not set");
  }

  const amountKobo = Number(order.amountKobo || 0);
  if (!Number.isFinite(amountKobo) || amountKobo <= 0) {
    throw new HttpsError("invalid-argument", "Order amount is invalid.");
  }

  await orderRef.update({
    status: "processing",
    processingStartedAt: admin.firestore.FieldValue.serverTimestamp(),
  });

  const billReference = `store_${orderId}_${Date.now()}`;
  const billBody = {
    data: {
      type: "Data",
      attributes: {
        amount: amountKobo,
        reference: billReference,
        phoneNumber: String(order.recipientPhone || ""),
        productSlug: String(order.productSlug || ""),
      },
      relationships: {
        account: {
          data: {
            type: merchant.accountType || "DepositAccount",
            id: merchant.accountId,
          },
        },
      },
    },
  };

  try {
    const billResp = await makeApiRequest({
      url: "/bills",
      method: "POST",
      secretKey,
      body: billBody,
      idempotencyKey: `bill_${orderId}`,
    });

    const billData = billResp?.data || {};
    const billStatus = String(billData?.attributes?.status || "pending").toUpperCase();

    const accepted = ["SUCCESSFUL", "COMPLETED", "PENDING", "PROCESSING", "IN_PROGRESS"].includes(
      billStatus,
    );

    if (!accepted) {
      await orderRef.update({
        status: "failed",
        failureReason: String(billData?.attributes?.failureReason || "Bill purchase failed"),
        updatedAt: admin.firestore.FieldValue.serverTimestamp(),
      });
      return { ok: false, status: "failed", reason: "Bill purchase failed" };
    }

    await orderRef.update({
      status: "fulfilled",
      billId: String(billData.id || ""),
      billStatus,
      fulfilledAt: admin.firestore.FieldValue.serverTimestamp(),
      updatedAt: admin.firestore.FieldValue.serverTimestamp(),
    });

    await createStorefrontTransactionRecord({
      userId: merchant.uid,
      type: "storefront_data_sale",
      amountNaira: amountKobo / 100,
      reference: String(billData.id || billReference),
      status: billStatus.toLowerCase(),
      extra: {
        source: "storefront",
        recipientPhone: String(order.recipientPhone || ""),
        productSlug: String(order.productSlug || ""),
        orderId,
      },
    });

    return {
      ok: true,
      status: "fulfilled",
      billId: String(billData.id || ""),
      billStatus,
    };
  } catch (err) {
    console.error(`[storefront] fulfillStorefrontOrder failed for ${orderId}:`, err);
    await orderRef.update({
      status: "failed",
      failureReason: String(err?.message || "Order fulfillment failed"),
      updatedAt: admin.firestore.FieldValue.serverTimestamp(),
    });
    return { ok: false, status: "failed", reason: String(err?.message || "Order fulfillment failed") };
  }
};

const tryMatchAndSettleStorefrontOrder = async ({ merchantUid, payment }) => {
  try {
    const narration = String(payment?.narration || "").toLowerCase();
    const paymentRef = String(payment?.paymentReference || payment?.paymentId || "").toLowerCase();
    const amountKobo = Number(payment?.amount || 0);
    if (!merchantUid || !amountKobo) return;

    const pendingSnap = await db
      .collection("storefrontOrders")
      .where("merchantUid", "==", merchantUid)
      .where("status", "==", "pending_transfer")
      .orderBy("createdAt", "desc")
      .limit(40)
      .get();

    if (pendingSnap.empty) return;

    let matchedDoc = null;
    for (const doc of pendingSnap.docs) {
      const order = doc.data() || {};
      const expectedRef = String(order.expectedReference || "").toLowerCase();
      const expectedAmount = Number(order.amountKobo || 0);
      const refMatched = expectedRef && (narration.includes(expectedRef) || paymentRef.includes(expectedRef));
      const amountMatched = expectedAmount > 0 && expectedAmount === amountKobo;
      if (refMatched || (amountMatched && expectedRef && expectedRef.length >= 6)) {
        matchedDoc = doc;
        break;
      }
    }

    if (!matchedDoc) return;

    await matchedDoc.ref.update({
      status: "paid",
      paidAt: admin.firestore.FieldValue.serverTimestamp(),
      settlement: {
        paymentId: String(payment?.paymentId || ""),
        paymentReference: String(payment?.paymentReference || ""),
        amountKobo,
        senderName: String(payment?.counterParty?.accountName || ""),
      },
      updatedAt: admin.firestore.FieldValue.serverTimestamp(),
    });

    await fulfillStorefrontOrder(matchedDoc.id);
  } catch (err) {
    console.error("[storefront] tryMatchAndSettleStorefrontOrder error:", err);
  }
};

exports.storefrontGetMerchant = onCall(async (request) => {
  const { username } = request.data || {};

  // Rate limit public merchant lookups by username and by IP to reduce scraping
  const GET_USERNAME_LIMIT = 500; // per hour per username
  const GET_USERNAME_WINDOW = 60 * 60 * 1000;
  const GET_IP_LIMIT = 2000; // per hour per IP
  const GET_IP_WINDOW = 60 * 60 * 1000;
  const normalized = sanitizeUsername(username || "");
  const ip = _getCallerIp(request);
  try {
    if (normalized) {
      const nameCount = await _incrRateLimit("storefront:getmerchant:username", normalized, GET_USERNAME_LIMIT, GET_USERNAME_WINDOW);
      if (nameCount > GET_USERNAME_LIMIT) {
        throw new HttpsError("resource-exhausted", "Too many requests for this merchant. Try again later.");
      }
    }
    if (ip) {
      const ipCount = await _incrRateLimit("storefront:getmerchant:ip", ip, GET_IP_LIMIT, GET_IP_WINDOW);
      if (ipCount > GET_IP_LIMIT) {
        throw new HttpsError("resource-exhausted", "Too many requests from this IP. Try again later.");
      }
    }
  } catch (err) {
    if (err instanceof HttpsError) throw err;
    console.error("[rateLimit] storefrontGetMerchant check failed:", err);
  }

  const merchant = await getMerchantForStorefront(username);
  return {
    merchant: {
      uid: merchant.uid,
      username: merchant.username,
      businessName: merchant.businessName,
      ownerName: merchant.ownerName,
      bankName: merchant.bankName,
      accountNumber: merchant.accountNumber,
      active: merchant.active,
    },
  };
});

exports.storefrontListDataBillers = onCall(
  { secrets: [getanchorSecretKey] },
  async () => {
    const secretKey = getanchorSecretKey.value();
    if (!secretKey) {
      throw new HttpsError("internal", "Getanchor Secret Key is not set");
    }

    try {
      const response = await makeApiRequest({
        url: "/bills/billers?category=data",
        method: "GET",
        secretKey,
      });

      const payload = response?.data;
      const billers = Array.isArray(payload)
        ? payload
        : Array.isArray(payload?.data)
          ? payload.data
          : [];

      console.log(`[storefront] storefrontListDataBillers loaded ${billers.length} data billers`);
      if (billers.length === 0) {
        console.warn("[storefront] storefrontListDataBillers returned 0 billers", payload);
      }

      return { billers };
    } catch (error) {
      console.error("[storefront] storefrontListDataBillers failed:", error);
      throw new HttpsError("internal", "Failed to load data networks.");
    }
  },
);

exports.storefrontListDataProducts = onCall(
  { secrets: [getanchorSecretKey] },
  async (request) => {
    const { billerId } = request.data || {};
    const cleanBillerId = String(billerId || "").trim();
    if (!cleanBillerId) {
      throw new HttpsError("invalid-argument", "billerId is required.");
    }

    const secretKey = getanchorSecretKey.value();
    if (!secretKey) {
      throw new HttpsError("internal", "Getanchor Secret Key is not set");
    }

    try {
      const response = await makeApiRequest({
        url: `/bills/billers/${encodeURIComponent(cleanBillerId)}/products`,
        method: "GET",
        secretKey,
      });

      const payload = response?.data;
      const products = Array.isArray(payload)
        ? payload
        : Array.isArray(payload?.data)
          ? payload.data
          : [];

      console.log(`[storefront] storefrontListDataProducts loaded ${products.length} products for biller ${cleanBillerId}`);
      if (products.length === 0) {
        console.warn("[storefront] storefrontListDataProducts returned 0 products", {
          billerId: cleanBillerId,
          payload,
        });
      }

      return { products };
    } catch (error) {
      console.error("[storefront] storefrontListDataProducts failed:", {
        billerId: cleanBillerId,
        error,
      });
      throw new HttpsError("internal", "Failed to load data bundles.");
    }
  },
);

exports.storefrontCreateAccount = onCall(async (request) => {
  const { phone, password, fullName } = request.data || {};
  const normalizedPhone = normalizePhone(phone);
  const cleanPassword = String(password || "");
  const cleanName = String(fullName || "").trim();

  if (!normalizedPhone || normalizedPhone.length < 13) {
    throw new HttpsError("invalid-argument", "A valid phone number is required.");
  }
  if (cleanPassword.length < 6) {
    throw new HttpsError("invalid-argument", "Password must be at least 6 characters.");
  }

  // Rate limit signup attempts by phone and by IP
  const SIGNUP_PHONE_LIMIT = 3;
  const SIGNUP_PHONE_WINDOW = 24 * 60 * 60 * 1000; // 24 hours
  const SIGNUP_IP_LIMIT = 20;
  const SIGNUP_IP_WINDOW = 60 * 60 * 1000; // 1 hour
  try {
    const phoneCount = await _incrRateLimit("storefront:signup:phone", normalizedPhone, SIGNUP_PHONE_LIMIT, SIGNUP_PHONE_WINDOW);
    if (phoneCount > SIGNUP_PHONE_LIMIT) {
      throw new HttpsError("resource-exhausted", "Too many signup attempts for this phone. Try again later.");
    }
    const ip = _getCallerIp(request);
    if (ip) {
      const ipCount = await _incrRateLimit("storefront:signup:ip", ip, SIGNUP_IP_LIMIT, SIGNUP_IP_WINDOW);
      if (ipCount > SIGNUP_IP_LIMIT) {
        throw new HttpsError("resource-exhausted", "Too many signup attempts from this IP. Try again later.");
      }
    }
  } catch (err) {
    if (err instanceof HttpsError) throw err;
    console.error("[rateLimit] signup check failed:", err);
    throw new HttpsError("internal", "Rate limit check failed");
  }

  const existing = await db
    .collection("storefrontCustomers")
    .where("phone", "==", normalizedPhone)
    .limit(1)
    .get();

  if (!existing.empty) {
    throw new HttpsError("already-exists", "An account already exists for this phone number.");
  }

  const { salt, hash } = hashStorefrontPassword(cleanPassword);
  const docRef = await db.collection("storefrontCustomers").add({
    phone: normalizedPhone,
    fullName: cleanName,
    passwordHash: hash,
    passwordSalt: salt,
    createdAt: admin.firestore.FieldValue.serverTimestamp(),
    updatedAt: admin.firestore.FieldValue.serverTimestamp(),
    status: "active",
  });

  const sessionToken = await createStorefrontSession(docRef.id, normalizedPhone, {
    reason: "signup",
  });

  return {
    customerId: docRef.id,
    sessionToken,
    phone: normalizedPhone,
    fullName: cleanName,
  };
});

exports.storefrontLogin = onCall(async (request) => {
  const { phone, password } = request.data || {};
  const normalizedPhone = normalizePhone(phone);
  const cleanPassword = String(password || "");

  if (!normalizedPhone || !cleanPassword) {
    throw new HttpsError("invalid-argument", "Phone and password are required.");
  }

  // Rate limit failed login attempts (pre-check)
  const LOGIN_FAIL_LIMIT = 5;
  const LOGIN_FAIL_WINDOW = 15 * 60 * 1000; // 15 minutes
  const callerIp = _getCallerIp(request);
  try {
    if (normalizedPhone) {
      const blockRef = db.collection("rateLimits").doc(_rateLimitDocId("storefront:login:fail:phone", normalizedPhone));
      const blockSnap = await blockRef.get();
      if (blockSnap.exists) {
        const data = blockSnap.data() || {};
        if (Date.now() <= Number(data.expiresAt || 0) && Number(data.count || 0) >= LOGIN_FAIL_LIMIT) {
          throw new HttpsError("resource-exhausted", "Too many failed login attempts for this account. Try again later.");
        }
      }
    }
  } catch (err) {
    if (err instanceof HttpsError) throw err;
    console.error("[rateLimit] pre-check failed:", err);
    // proceed normally if rate-limit store is unavailable
  }

  const snap = await db
    .collection("storefrontCustomers")
    .where("phone", "==", normalizedPhone)
    .limit(1)
    .get();

  if (snap.empty) {
    // Unknown phone - increment IP-based failure counter to slow down enumeration
    try {
      if (callerIp) {
        const ipCount = await _incrRateLimit("storefront:login:fail:ip", callerIp, 100, 60 * 60 * 1000);
        if (ipCount > 100) {
          throw new HttpsError("resource-exhausted", "Too many login attempts from this IP. Try again later.");
        }
      }
    } catch (err) {
      if (err instanceof HttpsError) throw err;
      console.error("[rateLimit] increment for unknown-phone failed:", err);
    }
    throw new HttpsError("not-found", "Invalid phone or password.");
  }

  const doc = snap.docs[0];
  const data = doc.data() || {};
  const ok = verifyStorefrontPassword(
    cleanPassword,
    String(data.passwordSalt || ""),
    String(data.passwordHash || ""),
  );

  if (!ok) {
    try {
      const phoneCount = await _incrRateLimit("storefront:login:fail:phone", normalizedPhone, LOGIN_FAIL_LIMIT, LOGIN_FAIL_WINDOW);
      if (callerIp) await _incrRateLimit("storefront:login:fail:ip", callerIp, 100, 60 * 60 * 1000);
      if (phoneCount > LOGIN_FAIL_LIMIT) {
        throw new HttpsError("resource-exhausted", "Too many failed login attempts for this account. Try again later.");
      }
    } catch (err) {
      if (err instanceof HttpsError) throw err;
      console.error("[rateLimit] increment on failed login failed:", err);
    }
    throw new HttpsError("permission-denied", "Invalid phone or password.");
  }

  const sessionToken = await createStorefrontSession(doc.id, normalizedPhone, {
    reason: "login",
  });

  await doc.ref.update({
    lastLoginAt: admin.firestore.FieldValue.serverTimestamp(),
    updatedAt: admin.firestore.FieldValue.serverTimestamp(),
  });

  // Successful login: reset failure counters for this phone and caller IP
  try {
    await _resetRateLimit("storefront:login:fail:phone", normalizedPhone);
    if (callerIp) await _resetRateLimit("storefront:login:fail:ip", callerIp);
  } catch (err) {
    console.error("[rateLimit] reset on successful login failed:", err);
  }

  return {
    customerId: doc.id,
    sessionToken,
    phone: normalizedPhone,
    fullName: String(data.fullName || ""),
  };
});

exports.storefrontRequestPasswordReset = onCall(async (request) => {
  const { phone } = request.data || {};
  const normalizedPhone = normalizePhone(phone);
  if (!normalizedPhone) {
    throw new HttpsError("invalid-argument", "Phone number is required.");
  }

  // Rate limit password reset requests by phone and IP
  const RESET_PHONE_LIMIT = 5;
  const RESET_PHONE_WINDOW = 60 * 60 * 1000; // 1 hour
  const RESET_IP_LIMIT = 100;
  const RESET_IP_WINDOW = 60 * 60 * 1000; // 1 hour
  const reqIp = _getCallerIp(request);
  try {
    const phoneCount = await _incrRateLimit("storefront:password_reset:phone", normalizedPhone, RESET_PHONE_LIMIT, RESET_PHONE_WINDOW);
    if (phoneCount > RESET_PHONE_LIMIT) {
      throw new HttpsError("resource-exhausted", "Too many password reset requests for this phone. Try again later.");
    }
    if (reqIp) {
      const ipCount = await _incrRateLimit("storefront:password_reset:ip", reqIp, RESET_IP_LIMIT, RESET_IP_WINDOW);
      if (ipCount > RESET_IP_LIMIT) {
        throw new HttpsError("resource-exhausted", "Too many requests from this IP. Try again later.");
      }
    }
  } catch (err) {
    if (err instanceof HttpsError) throw err;
    console.error("[rateLimit] password reset check failed:", err);
    throw new HttpsError("internal", "Rate limit check failed");
  }

  const snap = await db
    .collection("storefrontCustomers")
    .where("phone", "==", normalizedPhone)
    .limit(1)
    .get();

  if (snap.empty) {
    // Return generic success response to avoid user enumeration.
    return { sent: true };
  }

  const otp = String(Math.floor(100000 + Math.random() * 900000));
  const otpHash = crypto.createHash("sha256").update(otp).digest("hex");
  await db.collection("storefrontPasswordResets").add({
    customerId: snap.docs[0].id,
    phone: normalizedPhone,
    otpHash,
    expiresAtMs: Date.now() + STOREFRONT_OTP_TTL_MS,
    used: false,
    createdAt: admin.firestore.FieldValue.serverTimestamp(),
  });

  // NOTE: OTP delivery can be integrated to Termii SMS endpoint.
  // For now we persist hash and return debugOtp for immediate storefront flow.
  console.log(`[storefront] password reset OTP issued for ${normalizedPhone}`);

  return { sent: true, debugOtp: otp };
});

exports.storefrontResetPassword = onCall(async (request) => {
  const { phone, otp, newPassword } = request.data || {};
  const normalizedPhone = normalizePhone(phone);
  const cleanOtp = String(otp || "").trim();
  const cleanPassword = String(newPassword || "");

  if (!normalizedPhone || !cleanOtp || !cleanPassword) {
    throw new HttpsError("invalid-argument", "Phone, OTP, and new password are required.");
  }
  if (cleanPassword.length < 6) {
    throw new HttpsError("invalid-argument", "Password must be at least 6 characters.");
  }

  // Rate limit OTP verification attempts to prevent brute-force
  const RESET_VERIFY_LIMIT = 10;
  const RESET_VERIFY_WINDOW = 60 * 60 * 1000; // 1 hour
  const verifyIp = _getCallerIp(request);
  try {
    const verifyCount = await _incrRateLimit("storefront:password_reset_verify:phone", normalizedPhone, RESET_VERIFY_LIMIT, RESET_VERIFY_WINDOW);
    if (verifyCount > RESET_VERIFY_LIMIT) {
      throw new HttpsError("resource-exhausted", "Too many OTP verification attempts. Try again later.");
    }
    if (verifyIp) {
      await _incrRateLimit("storefront:password_reset_verify:ip", verifyIp, 200, RESET_VERIFY_WINDOW);
    }
  } catch (err) {
    if (err instanceof HttpsError) throw err;
    console.error("[rateLimit] reset-password verify check failed:", err);
    throw new HttpsError("internal", "Rate limit check failed");
  }

  const resetSnap = await db
    .collection("storefrontPasswordResets")
    .where("phone", "==", normalizedPhone)
    .where("used", "==", false)
    .orderBy("createdAt", "desc")
    .limit(1)
    .get();

  if (resetSnap.empty) {
    throw new HttpsError("invalid-argument", "Invalid or expired OTP.");
  }

  const resetDoc = resetSnap.docs[0];
  const resetData = resetDoc.data() || {};
  if (Date.now() > Number(resetData.expiresAtMs || 0)) {
    throw new HttpsError("invalid-argument", "Invalid or expired OTP.");
  }

  const otpHash = crypto.createHash("sha256").update(cleanOtp).digest("hex");
  if (otpHash !== String(resetData.otpHash || "")) {
    throw new HttpsError("permission-denied", "Invalid or expired OTP.");
  }

  const customerRef = db.collection("storefrontCustomers").doc(String(resetData.customerId || ""));
  const customerSnap = await customerRef.get();
  if (!customerSnap.exists) {
    throw new HttpsError("not-found", "Customer account not found.");
  }

  const { salt, hash } = hashStorefrontPassword(cleanPassword);
  await Promise.all([
    customerRef.update({
      passwordHash: hash,
      passwordSalt: salt,
      updatedAt: admin.firestore.FieldValue.serverTimestamp(),
    }),
    resetDoc.ref.update({
      used: true,
      usedAt: admin.firestore.FieldValue.serverTimestamp(),
    }),
  ]);

  // Reset OTP/rate-limit counters on successful password reset
  try {
    await _resetRateLimit("storefront:password_reset_verify:phone", normalizedPhone);
    const resetIp = _getCallerIp(request);
    if (resetIp) await _resetRateLimit("storefront:password_reset_verify:ip", resetIp);
  } catch (err) {
    console.error("[rateLimit] reset counters after password reset failed:", err);
  }

  return { reset: true };
});

exports.storefrontCreateTransferOrder = onCall(async (request) => {
  const {
    sessionToken,
    merchantUsername,
    recipientPhone,
    network,
    productSlug,
    amountKobo,
  } = request.data || {};

  const session = await getStorefrontSession(sessionToken);
  const merchant = await getMerchantForStorefront(merchantUsername);

  if (!merchant.accountNumber || !merchant.bankName) {
    throw new HttpsError("failed-precondition", "Merchant account details are unavailable.");
  }

  const amount = Number(amountKobo || 0);
  if (!Number.isFinite(amount) || amount <= 0) {
    throw new HttpsError("invalid-argument", "amountKobo must be a positive number.");
  }

  const expectedReference = `PP${Date.now().toString(36).toUpperCase()}${Math.floor(
    Math.random() * 1000,
  )}`;

  const orderRef = await db.collection("storefrontOrders").add({
    customerId: session.customerId,
    customerPhone: session.phone,
    merchantUid: merchant.uid,
    merchantUsername: merchant.username,
    recipientPhone: normalizePhone(recipientPhone),
    network: String(network || "").trim(),
    productSlug: String(productSlug || "").trim(),
    amountKobo: amount,
    paymentMethod: "bank_transfer",
    expectedReference,
    status: "pending_transfer",
    createdAt: admin.firestore.FieldValue.serverTimestamp(),
    updatedAt: admin.firestore.FieldValue.serverTimestamp(),
  });

  return {
    orderId: orderRef.id,
    status: "pending_transfer",
    expectedReference,
    amountKobo: amount,
    merchant: {
      businessName: merchant.businessName,
      bankName: merchant.bankName,
      accountNumber: merchant.accountNumber,
    },
  };
});

exports.storefrontPayWithPadipay = onCall(
  { secrets: [getanchorSecretKey] },
  async (request) => {
    const {
      sessionToken,
      merchantUsername,
      buyerPhone,
      buyerPin,
      recipientPhone,
      network,
      productSlug,
      amountKobo,
    } = request.data || {};

    const session = await getStorefrontSession(sessionToken);
    const merchant = await getMerchantForStorefront(merchantUsername);
    if (!merchant.accountId) {
      throw new HttpsError("failed-precondition", "Merchant account is unavailable.");
    }

    const phoneVariants = getPhoneLookupVariants(buyerPhone);
    if (phoneVariants.length === 0) {
      throw new HttpsError("invalid-argument", "Buyer phone is required.");
    }
    const normalizedBuyerPhone = phoneVariants[0];
    const buyerPinText = String(buyerPin || "").trim();
    if (!buyerPinText) {
      throw new HttpsError("invalid-argument", "Transaction PIN is required.");
    }

    console.log("[storefront] storefrontPayWithPadipay buyer lookup variants", {
      provided: String(buyerPhone || ""),
      variants: phoneVariants,
    });

    const buyerSnap = await db
      .collection("users")
      .where("phone", "in", phoneVariants)
      .limit(1)
      .get();

    if (buyerSnap.empty) {
      console.warn("[storefront] storefrontPayWithPadipay buyer not found", {
        variants: phoneVariants,
      });
      throw new HttpsError("not-found", "PadiPay buyer account not found.");
    }

    const buyerDoc = buyerSnap.docs[0];
    const buyerData = buyerDoc.data() || {};
    const storedPin = String(buyerData.passcode || "");
    if (!storedPin || storedPin !== buyerPinText) {
      throw new HttpsError("permission-denied", "Invalid transaction PIN.");
    }

    const fromAccountId = String(buyerData.getAnchorData?.virtualAccount?.data?.id || "").trim();
    const fromAccountType = String(
      buyerData.getAnchorData?.virtualAccount?.data?.type || "DepositAccount",
    ).trim();
    if (!fromAccountId) {
      throw new HttpsError("failed-precondition", "Buyer account is unavailable.");
    }

    const amount = Number(amountKobo || 0);
    if (!Number.isFinite(amount) || amount <= 0) {
      throw new HttpsError("invalid-argument", "amountKobo must be a positive number.");
    }

    const secretKey = getanchorSecretKey.value();
    if (!secretKey) {
      throw new HttpsError("internal", "Getanchor Secret Key is not set");
    }

    const orderRef = await db.collection("storefrontOrders").add({
      customerId: session.customerId,
      customerPhone: session.phone,
      merchantUid: merchant.uid,
      merchantUsername: merchant.username,
      buyerUid: buyerDoc.id,
      buyerPhone: normalizedBuyerPhone,
      recipientPhone: normalizePhone(recipientPhone),
      network: String(network || "").trim(),
      productSlug: String(productSlug || "").trim(),
      amountKobo: amount,
      paymentMethod: "padipay",
      status: "processing",
      createdAt: admin.firestore.FieldValue.serverTimestamp(),
      updatedAt: admin.firestore.FieldValue.serverTimestamp(),
    });

    const transferReference = crypto.randomUUID();
    const transferIdempotency = transferReference;
    const transferBody = {
      data: {
        type: "BookTransfer",
        attributes: {
          currency: "NGN",
          amount,
          reason: `Storefront order ${orderRef.id}`,
          reference: transferReference,
        },
        relationships: {
          destinationAccount: {
            data: {
              type: merchant.accountType || "DepositAccount",
              id: merchant.accountId,
            },
          },
          account: {
            data: {
              type: fromAccountType || "DepositAccount",
              id: fromAccountId,
            },
          },
        },
      },
    };

    try {
      const transferResp = await makeApiRequest({
        url: "/transfers",
        method: "POST",
        secretKey,
        body: transferBody,
        idempotencyKey: transferIdempotency,
      });

      await orderRef.update({
        transferId: String(transferResp?.data?.id || ""),
        transferStatus: String(transferResp?.data?.attributes?.status || "").toUpperCase(),
        paidAt: admin.firestore.FieldValue.serverTimestamp(),
        status: "paid",
        updatedAt: admin.firestore.FieldValue.serverTimestamp(),
      });

      await createStorefrontTransactionRecord({
        userId: buyerDoc.id,
        type: "storefront_payment",
        amountNaira: amount / 100,
        reference: String(transferResp?.data?.id || transferReference),
        status: String(transferResp?.data?.attributes?.status || "pending").toLowerCase(),
        extra: {
          receiverId: merchant.uid,
          source: "storefront",
          orderId: orderRef.id,
          recipientPhone: normalizePhone(recipientPhone),
          productSlug: String(productSlug || ""),
        },
      });

      const fulfillment = await fulfillStorefrontOrder(orderRef.id);
      return {
        orderId: orderRef.id,
        status: fulfillment.status,
        transferId: String(transferResp?.data?.id || ""),
        billId: fulfillment.billId || null,
      };
    } catch (err) {
      console.error("[storefront] storefrontPayWithPadipay failed:", err);
      await orderRef.update({
        status: "failed",
        failureReason: String(err?.message || "Payment failed"),
        updatedAt: admin.firestore.FieldValue.serverTimestamp(),
      });
      throw err;
    }
  },
);

exports.storefrontGetOrder = onCall(async (request) => {
  const { sessionToken, orderId } = request.data || {};
  const session = await getStorefrontSession(sessionToken);

  if (!orderId) {
    throw new HttpsError("invalid-argument", "orderId is required.");
  }

  const orderSnap = await db.collection("storefrontOrders").doc(String(orderId)).get();
  if (!orderSnap.exists) {
    throw new HttpsError("not-found", "Order not found.");
  }
  const order = orderSnap.data() || {};
  if (String(order.customerId || "") !== String(session.customerId || "")) {
    throw new HttpsError("permission-denied", "You do not have access to this order.");
  }

  return {
    order: {
      id: orderSnap.id,
      status: order.status,
      amountKobo: order.amountKobo,
      network: order.network,
      productSlug: order.productSlug,
      recipientPhone: order.recipientPhone,
      paymentMethod: order.paymentMethod,
      expectedReference: order.expectedReference || null,
      transferId: order.transferId || null,
      billId: order.billId || null,
      billStatus: order.billStatus || null,
      failureReason: order.failureReason || null,
    },
  };
});
// QoreID token cache (in-memory, per cold start)
let _qoreIdToken = null;
let _qoreIdTokenExpiresAt = 0;

const _getQoreIdToken = async () => {
  const now = Date.now();
  if (_qoreIdToken && now < _qoreIdTokenExpiresAt) return _qoreIdToken;

  const clientId = qoreIdClientId.value();
  const secret = qoreIdApiKey.value();
  if (!clientId || !secret) {
    throw new HttpsError("internal", "QoreID credentials are not configured");
  }

  const res = await fetch("https://api.qoreid.com/token", {
    method: "POST",
    headers: { accept: "application/json", "content-type": "application/json" },
    body: JSON.stringify({ clientId, secret }),
  });

  if (!res.ok) {
    const body = await res.text().catch(() => "(unreadable)");
    console.error(`QoreID token request failed ${res.status}: ${body}`);
    throw new HttpsError("internal", `QoreID token request failed: ${res.status}`);
  }

  const json = await res.json();
  const token = json?.accessToken ?? json?.token ?? json?.access_token;
  if (!token) {
    throw new HttpsError("internal", "QoreID token response did not contain a token");
  }

  // Cache for ~50 minutes (tokens are typically valid for 1 hour)
  _qoreIdToken = token;
  _qoreIdTokenExpiresAt = now + 50 * 60 * 1000;
  return token;
};

exports.verifyBvnNoFace = onCall(
  { secrets: [qoreIdApiKey, qoreIdClientId] },
  async (data, context) => {
    const { bvn, firstName, lastName } = data.data;

    if (!bvn || bvn.length !== 11) {
      throw new HttpsError("invalid-argument", "BVN must be 11 digits");
    }
    if (!firstName || !lastName) {
      throw new HttpsError("invalid-argument", "First and last name are required");
    }

    // Run auth check and token fetch in parallel ? they're independent
    const [token] = await Promise.all([
      _getQoreIdToken(),
      ensureVerifiedOrStandUser(data.auth),
    ]);

    const url = `https://api.qoreid.com/v1/ng/identities/bvn-basic/${bvn}`;

    const response = await fetch(url, {
      method: "POST",
      headers: {
        accept: "application/json",
        "content-type": "application/json",
        Authorization: `Bearer ${token}`,
      },
      body: JSON.stringify({ firstname: firstName, lastname: lastName }),
    });

    if (!response.ok) {
      const errBody = await response.text().catch(() => "(unreadable)");
      console.error(`QoreID ${response.status} for BVN ${bvn}: ${errBody}`);
      // If 401, invalidate cached token so next call re-fetches
      if (response.status === 401) { _qoreIdToken = null; _qoreIdTokenExpiresAt = 0; }
      throw new HttpsError("internal", `QoreID request failed: ${response.status}`);
    }

    const json = await response.json();
    const jsonForLog = { ...json, bvn: json.bvn ? { ...json.bvn, photo: "[omitted]" } : json.bvn };
    console.log(`QoreID BVN response for ${bvn}:`, JSON.stringify(jsonForLog, null, 2));

    const status = json?.summary?.bvn_check?.status ?? "NO_MATCH";
    const fieldMatches = json?.summary?.bvn_check?.fieldMatches ?? {};
    const isMatch = status === "EXACT_MATCH" || status === "PARTIAL_MATCH";

    const bvnRecord = json?.bvn ?? {};
    const bvnData = {
      bvn: bvnRecord.bvn ?? bvn,
      firstname: bvnRecord.firstname ?? null,
      lastname: bvnRecord.lastname ?? null,
      middlename: bvnRecord.middlename ?? null,
      birthdate: bvnRecord.birthdate ?? null,
      gender: bvnRecord.gender ?? null,
      phone: bvnRecord.phone ?? null,
      photo: bvnRecord.photo ?? null,
    };

    // Fire-and-forget Firestore write ? don't block the response on it
    const uid = data.auth?.uid;
    if (uid) {
      db.collection("users").doc(uid).update({
        "qoreIdData.bvnVerificationNoFace": {
          verified: isMatch,
          status,
          fieldMatches,
          ...bvnData,
          verifiedAt: admin.firestore.FieldValue.serverTimestamp(),
        },
      }).catch((err) => console.error("BVN Firestore write failed:", err));
    }

    return { verified: isMatch, status, fieldMatches, bvnData };
  }
);
// Ensure caller is either email-verified or present in standUsers
const ensureVerifiedOrStandUser = async (auth) => {
  const isVerified = auth && auth.token && auth.token.email_verified === true;
  if (isVerified) return;

  const email = auth && auth.token && auth.token.email;
  if (!email) {
    throw new HttpsError(
      "unauthenticated",
      "You must be signed in to call this function 1.",
    );
  }

  const standSnap = await admin
    .firestore()
    .collection("standUsers")
    .where("email", "==", email)
    .limit(1)
    .get();

  if (!standSnap.empty) return;
  const adminsSnap = await admin
    .firestore()
    .collection("admins")
    .where("email", "==", email)
    .limit(1)
    .get();

  if (!adminsSnap.empty) return;

  throw new HttpsError(
    "unauthenticated",
    "You must be signed in to call this function 2.",
  );
};

const DEFAULT_SUPER_AGENT_SETTINGS = {
  perNipTransferAmount: 5,
  verifiedBusinessBonusAmount: 5000,
  starThresholds: {
    1: 0,
    2: 10000,
    3: 30000,
    4: 70000,
    5: 150000,
  },
};

const getSuperAgentProgramSettings = async () => {
  const snap = await db.collection("settings").doc("superAgentProgram").get();
  if (!snap.exists) return DEFAULT_SUPER_AGENT_SETTINGS;
  const data = snap.data() || {};
  return {
    perNipTransferAmount:
      typeof data.perNipTransferAmount === "number"
        ? data.perNipTransferAmount
        : DEFAULT_SUPER_AGENT_SETTINGS.perNipTransferAmount,
    verifiedBusinessBonusAmount:
      typeof data.verifiedBusinessBonusAmount === "number"
        ? data.verifiedBusinessBonusAmount
        : DEFAULT_SUPER_AGENT_SETTINGS.verifiedBusinessBonusAmount,
    starThresholds: {
      ...DEFAULT_SUPER_AGENT_SETTINGS.starThresholds,
      ...(data.starThresholds || {}),
    },
  };
};

const computeSuperAgentStars = (totalEarnings, starThresholds) => {
  let stars = 0;
  for (let i = 1; i <= 5; i++) {
    const threshold = Number(starThresholds?.[i] ?? starThresholds?.[String(i)] ?? 0);
    if (totalEarnings >= threshold) {
      stars = i;
    }
  }
  return stars;
};

const requireAdminCaller = async (request) => {
  if (!request.auth) {
    throw new HttpsError("unauthenticated", "Authentication is required.");
  }
  const callerDoc = await db.collection("admins").doc(request.auth.uid).get();
  if (!callerDoc.exists || callerDoc.data()?.role !== "admin") {
    throw new HttpsError("permission-denied", "Only admins can perform this action.");
  }
  return request.auth.uid;
};

const generateBusinessSuperAgentCode = async () => {
  const chars = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
  for (let attempt = 0; attempt < 10; attempt++) {
    let code = "";
    const randomBytes = crypto.randomBytes(6);
    for (let i = 0; i < 6; i++) {
      code += chars[randomBytes[i] % chars.length];
    }
    const candidate = `PADI-SA-${code}`;

    const existingBusiness = await db
      .collection("businesses")
      .where("superAgentReferralCode", "==", candidate)
      .limit(1)
      .get();
    if (!existingBusiness.empty) continue;

    // Backward compatibility while old superAgents collection still exists.
    const existingLegacy = await db
      .collection("superAgents")
      .where("referral_code", "==", candidate)
      .limit(1)
      .get();
    if (!existingLegacy.empty) continue;

    return candidate;
  }
  throw new HttpsError("internal", "Could not generate a unique super-agent referral code.");
};

// Runtime key override: set appConfig/anchor { secretKeyOverride: "test_key" } in Firestore
// to switch to sandbox without redeployment. Delete the field (or set to "") to revert to live.
let _anchorKeyOverrideCache = null;
let _anchorKeyOverrideFetchedAt = 0;
const _ANCHOR_KEY_CACHE_TTL_MS = 60000; // 1 minute
let _anchorLegacyEnabledCache = null;
let _anchorLegacyEnabledFetchedAt = 0;

const _isAnchorLegacyEnabled = async () => {
  const now = Date.now();
  if (now - _anchorLegacyEnabledFetchedAt < _ANCHOR_KEY_CACHE_TTL_MS) {
    return Boolean(_anchorLegacyEnabledCache);
  }

  try {
    const doc = await db.collection("appConfig").doc("anchor").get();
    const legacyEnabled = Boolean(doc.exists && doc.data()?.legacyEnabled === true);
    _anchorLegacyEnabledCache = legacyEnabled;
    _anchorLegacyEnabledFetchedAt = now;
    return legacyEnabled;
  } catch (e) {
    console.warn("Failed to read anchor legacyEnabled flag. Defaulting to disabled:", e.message);
    _anchorLegacyEnabledCache = false;
    _anchorLegacyEnabledFetchedAt = now;
    return false;
  }
};

const _assertAnchorLegacyEnabled = async () => {
  const enabled = await _isAnchorLegacyEnabled();
  if (!enabled) {
    throw new HttpsError(
      "failed-precondition",
      "Legacy Anchor endpoints are disabled. Set appConfig/anchor.legacyEnabled=true to temporarily enable them.",
    );
  }
};

// Returns { key, baseUrl } ? sandbox when Firestore override present, live otherwise
const _resolveAnchorKey = async (fallback) => {
  const now = Date.now();
  if (now - _anchorKeyOverrideFetchedAt < _ANCHOR_KEY_CACHE_TTL_MS) {
    const key = _anchorKeyOverrideCache || fallback;
    const baseUrl = _anchorKeyOverrideCache ? SANDBOX_BASE_URL : BASE_URL;
    return { key, baseUrl };
  }
  try {
    const doc = await db.collection("appConfig").doc("anchor").get();
    const override = doc.exists ? (doc.data().secretKeyOverride || "") : "";
    _anchorKeyOverrideCache = override;
    _anchorKeyOverrideFetchedAt = now;
    const key = override || fallback;
    const baseUrl = override ? SANDBOX_BASE_URL : BASE_URL;
    return { key, baseUrl };
  } catch (e) {
    console.warn("Failed to read anchor key override from Firestore, using secret:", e.message);
    return { key: fallback, baseUrl: BASE_URL };
  }
};

// Helper function to make API requests
const makeApiRequest = async ({
  url,
  method,
  secretKey,
  body = null,
  idempotencyKey = null,
}) => {
  await _assertAnchorLegacyEnabled();

  const { key: resolvedKey, baseUrl: resolvedBaseUrl } = await _resolveAnchorKey(secretKey);
  // Support absolute URLs and relative endpoint paths (e.g. "/bills").
  const normalizedUrl = String(url || "").trim();
  if (!normalizedUrl) {
    throw new HttpsError("invalid-argument", "URL is required");
  }

  let resolvedUrl;
  if (/^https?:\/\//i.test(normalizedUrl)) {
    // Replace BASE_URL or SANDBOX_BASE_URL prefix in url with the resolved one
    resolvedUrl = normalizedUrl
      .replace(BASE_URL, resolvedBaseUrl)
      .replace(SANDBOX_BASE_URL, resolvedBaseUrl);
  } else {
    const relativePath = normalizedUrl.startsWith("/")
      ? normalizedUrl
      : `/${normalizedUrl}`;
    resolvedUrl = `${resolvedBaseUrl}${relativePath}`;
  }

  const headers = {
    accept: "application/json",
    "x-anchor-key": resolvedKey,
  };
  if (method === "POST" || method === "PUT") {
    headers["content-type"] = "application/json";
  }
  if (idempotencyKey) {
    headers["x-anchor-idempotent-key"] = idempotencyKey;
  }

  const options = { method, headers };
  if (body) {
    options.body = JSON.stringify(body);
  }

  const logHeaders = {
    ...headers,
    "x-anchor-key": headers["x-anchor-key"] ? "[redacted]" : undefined,
    "x-anchor-idempotent-key": headers["x-anchor-idempotent-key"]
      ? "[redacted]"
      : undefined,
  };

  console.log(`Request to ${resolvedUrl}:`, {
    method,
    headers: logHeaders,
    body: body ? JSON.stringify(body) : null,
  });

  try {
    const response = await fetch(resolvedUrl, options);
    const responseText = await response.text();

    console.log(`Response status for ${resolvedUrl}:`, response.status);
    console.log(`Response body for ${resolvedUrl}:`, responseText);

    if (!response.status.toString().startsWith("2")) {
      throw new HttpsError(
        "internal",
        `HTTP ${response.status}: ${responseText}`,
      );
    }

    const json = JSON.parse(responseText);
    if (!json.data) {
      throw new HttpsError(
        "internal",
        `Getanchor API error: ${json.message || "Unknown error"}`,
      );
    }

    return json;
  } catch (err) {
    console.error(`Fetch error for ${resolvedUrl}:`, err);
    throw new HttpsError("internal", err.message);
  }
};

// ============================================================
// Safe Haven MFB API helpers
// ============================================================
const SAFEHAVEN_PROD_BASE_URL = "https://api.safehavenmfb.com";
const SAFEHAVEN_SANDBOX_BASE_URL = "https://api.sandbox.safehavenmfb.com";
const _SAFEHAVEN_CONFIG_CACHE_TTL_MS = 60000;

let _safehavenConfigCache = null;
let _safehavenConfigFetchedAt = 0;
let _safehavenTokenCache = null;
let _safehavenTokenCacheKey = null;
let _safehavenTokenExpiresAt = 0;

const _resolveSafehavenConfig = async () => {
  const now = Date.now();
  if (
    _safehavenConfigCache &&
    now - _safehavenConfigFetchedAt < _SAFEHAVEN_CONFIG_CACHE_TTL_MS
  ) {
    return _safehavenConfigCache;
  }

  const prodClientId = safehavenClientId.value();
  const privateKeyPem = safehavenPrivateKey.value();
  const companyUrl = safehavenCompanyUrl.value();

  if (!prodClientId || !privateKeyPem || !companyUrl) {
    throw new HttpsError("internal", "Safe Haven credentials are not configured");
  }

  let sandboxClientId = "";
  try {
    const doc = await db.collection("appConfig").doc("safehaven").get();
    sandboxClientId = doc.exists ? String(doc.data()?.sandboxClientId || "").trim() : "";
  } catch (e) {
    console.warn(
      "Failed to read Safehaven sandbox client id from Firestore, using prod:",
      e.message,
    );
  }

  const resolvedConfig = {
    clientId: sandboxClientId || prodClientId,
    privateKeyPem,
    companyUrl,
    baseUrl: sandboxClientId ? SAFEHAVEN_SANDBOX_BASE_URL : SAFEHAVEN_PROD_BASE_URL,
    mode: sandboxClientId ? "sandbox" : "prod",
  };

  _safehavenConfigCache = resolvedConfig;
  _safehavenConfigFetchedAt = now;
  return resolvedConfig;
};

const _getSafehavenDebitAccountConfig = async () => {
  const config = await _resolveSafehavenConfig();

  if (config.mode === "prod") {
    const prodDebitAccount = String(safehavenDebitAccountNumber.value() || "").trim();
    return {
      mode: config.mode,
      source: prodDebitAccount ? "secret" : "none",
      debitAccountNumber: prodDebitAccount,
    };
  }

  try {
    const doc = await db.collection("appConfig").doc("safehaven").get();
    const sandboxDebitAccountNumber = doc.exists ? String(doc.data()?.sandboxDebitAccountNumber || "").trim() : "";
    return {
      mode: config.mode,
      source: sandboxDebitAccountNumber ? "appConfig.safehaven.sandboxDebitAccountNumber" : "sandbox-default",
      debitAccountNumber: sandboxDebitAccountNumber || "0104610514",
    };
  } catch (e) {
    console.warn(
      "Failed to read Safehaven sandbox debit account from Firestore, using default:",
      e.message,
    );
    return {
      mode: config.mode,
      source: "sandbox-default",
      debitAccountNumber: "0104610514",
    };
  }
};

/**
 * Builds a signed RS256 JWT for the Safehaven client_assertion flow.
 */
const _buildSafehavenJwt = (clientId, privateKeyPem, baseUrl) => {
  const headerJson = JSON.stringify({ alg: "RS256", typ: "JWT" });
  const now = Math.floor(Date.now() / 1000);
  const payloadJson = JSON.stringify({
    iss: clientId,
    sub: clientId,
    aud: baseUrl,
    iat: now,
    exp: now + 300,
    jti: crypto.randomUUID(),
  });
  const header = Buffer.from(headerJson).toString("base64url");
  const payload = Buffer.from(payloadJson).toString("base64url");
  const signingInput = `${header}.${payload}`;
  const signer = crypto.createSign("RSA-SHA256");
  signer.update(signingInput, "utf8");
  const signature = signer.sign(privateKeyPem, "base64url");
  return `${signingInput}.${signature}`;
};

/**
 * Fetches (and caches) a Safehaven OAuth2 access token using the
 * JWT client-credentials grant.
 */
const _getSafehavenToken = async () => {
  const now = Date.now();
  const config = await _resolveSafehavenConfig();
  const cacheKey = `${config.baseUrl}|${config.clientId}`;

  if (
    _safehavenTokenCache &&
    _safehavenTokenCacheKey === cacheKey &&
    now < _safehavenTokenExpiresAt - 60000
  ) {
    return {
      accessToken: _safehavenTokenCache,
      clientId: config.clientId,
      baseUrl: config.baseUrl,
      mode: config.mode,
    };
  }
  const clientAssertion = _buildSafehavenJwt(
    config.clientId,
    config.privateKeyPem,
    config.baseUrl,
  );
  const params = new URLSearchParams({
    grant_type: "client_credentials",
    client_assertion_type: "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
    client_assertion: clientAssertion,
    client_id: config.clientId,
  });
  const tokenUrl = `${config.baseUrl}/oauth2/token`;
  console.log("[SafeHaven] OAuth request", {
    url: tokenUrl,
    mode: config.mode,
    grant_type: "client_credentials",
    hasClientId: Boolean(config.clientId),
    hasPrivateKey: Boolean(config.privateKeyPem),
    assertionLength: clientAssertion ? String(clientAssertion).length : 0,
  });

  const response = await fetch(tokenUrl, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: params.toString(),
  });
  const text = await response.text();
  console.log("[SafeHaven] OAuth response", {
    url: tokenUrl,
    status: response.status,
    body: text.slice(0, 1000),
  });
  if (!response.ok) {
    console.error("[SafeHaven] token error:", {
      url: tokenUrl,
      status: response.status,
      body: text.slice(0, 1000),
    });
    _safehavenTokenCache = null;
    _safehavenTokenCacheKey = null;
    _safehavenTokenExpiresAt = 0;
    throw new HttpsError("internal", `SafeHaven OAuth failed (${response.status}): ${text}`);
  }
  let json;
  try {
    json = JSON.parse(text);
  } catch (e) {
    console.error('[SafeHaven] token parse error', { status: response.status, body: text });
    throw new HttpsError('internal', `SafeHaven OAuth parse error: ${e.message}`);
  }

  if (!json || !json.access_token) {
    console.error('[SafeHaven] token error (no access_token)', { status: response.status, body: text });
    _safehavenTokenCache = null;
    _safehavenTokenCacheKey = null;
    _safehavenTokenExpiresAt = 0;
    throw new HttpsError('internal', `SafeHaven OAuth failed (${response.status}): ${text}`);
  }

  _safehavenTokenCache = json.access_token;
  _safehavenTokenCacheKey = cacheKey;
  _safehavenTokenExpiresAt = now + (json.expires_in || 3600) * 1000;
  return {
    accessToken: _safehavenTokenCache,
    clientId: config.clientId,
    baseUrl: config.baseUrl,
    mode: config.mode,
  };
};

/**
 * Makes an authenticated request to the Safe Haven MFB API.
 * Always includes Authorization: Bearer <token> and ClientID header.
 */
const safehavenRequest = async ({ path, method = "GET", body = null }) => {
  const { accessToken, clientId, baseUrl, mode } = await _getSafehavenToken();
  const url = `${baseUrl}${path}`;
  const headers = {
    Accept: "application/json",
    Authorization: `Bearer ${accessToken}`,
    ClientID: clientId,
  };
  if (method === "POST" || method === "PUT" || method === "PATCH") {
    headers["Content-Type"] = "application/json";
  }
  const options = { method, headers };
  if (body) options.body = JSON.stringify(body);
  console.log(
    `[SafeHaven] ${mode} ${method} ${url}`,
    body ? JSON.stringify(body).slice(0, 400) : "",
  );
  const response = await fetch(url, options);
  const text = await response.text();
  console.log(`[SafeHaven] ${response.status} ${url}:`, text.slice(0, 600));
  if (!response.ok) {
    throw new HttpsError("internal", `SafeHaven API ${response.status}: ${text.slice(0, 300)}`);
  }
  const parsed = JSON.parse(text);
  // SafeHaven sometimes returns HTTP 2xx with an error statusCode in the body
  if (parsed && typeof parsed.statusCode === "number" && parsed.statusCode >= 400) {
    throw new HttpsError("internal", `SafeHaven API ${parsed.statusCode}: ${text.slice(0, 300)}`);
  }
  return parsed;
};

// Adds consistent logs for callable entry/success/error so app issues can be
// traced quickly in Cloud Functions logs.
const onCallLogged = (functionName, options, handler) =>
  onCall(options, async (data, context) => {
    const payload = data?.data && typeof data.data === "object" ? data.data : {};
    const traceId =
      payload?.idempotencyKey ||
      payload?.reference ||
      payload?.paymentReference ||
      `${Date.now()}_${Math.random().toString(36).slice(2, 8)}`;
    const uid = data?.auth?.uid || "anonymous";
    console.log(`[CF:${functionName}] start`, {
      uid,
      traceId,
      payloadKeys: Object.keys(payload),
    });
    try {
      const result = await handler(data, context);
      console.log(`[CF:${functionName}] success`, { uid, traceId });
      return result;
    } catch (err) {
      console.error(`[CF:${functionName}] error`, {
        uid,
        traceId,
        code: err?.code,
        message: err?.message,
      });
      throw err;
    }
  });

/**
 * Looks up a user document in Firestore and returns the Safehaven
 * account number and _id from getAnchorData.virtualAccount.
 */
const _getSafehavenAccountForUser = async (uid) => {
  const snap = await db.collection("users").doc(uid).get();
  if (!snap.exists) return null;
  const va = snap.data()?.getAnchorData?.virtualAccount?.data;
  if (!va) return null;
  return {
    accountId: va.id || "",
    accountNumber: va.attributes?.accountNumber || "",
    bankCode: va.attributes?.bank?.id || "999240",
  };
};

/**
 * Performs a Safehaven name enquiry and caches the nameEnquiryReference
 * in Firestore (5-minute TTL) keyed to the caller's UID.
 */
const _safehavenNameEnquiry = async (uid, bankCode, accountNumber) => {
  const resp = await safehavenRequest({
    path: "/transfers/name-enquiry",
    method: "POST",
    body: {
      bankCode: String(bankCode || "").trim(),
      accountNumber: String(accountNumber || "").trim(),
    },
  });
  // Cache the name enquiry reference
  if (uid && resp.data?.nameEnquiryReference) {
    const cacheKey = crypto.createHash("sha256").update(`${bankCode}:${accountNumber}`).digest("hex");
    await db.collection("safehavenNameEnquiryCache").doc(`${uid}_${cacheKey}`).set({
      nameEnquiryReference: resp.data.nameEnquiryReference,
      bankCode,
      accountNumber,
      accountName: resp.data.accountName || resp.data.beneficiaryAccountName || "",
      createdAt: admin.firestore.FieldValue.serverTimestamp(),
      expiresAtMs: Date.now() + 5 * 60 * 1000,
    });
  }
  return resp.data || {};
};
// ============================================================
// End Safe Haven MFB API helpers
// ============================================================

// Create Safehaven User (replaces createGetanchorUser)
// In the Safehaven model there is no separate "customer" entity.
// We store the user's details in Firestore for use during account creation
// and return an Anchor-compatible placeholder so the existing app flow is unaffected.
exports.safehavenCreateUser = onCallLogged(
  "safehavenCreateUser",
  { secrets: [safehavenClientId, safehavenPrivateKey, safehavenCompanyUrl] },
  async (data, context) => {
    await ensureVerifiedOrStandUser(data.auth);

    const requiredFields = [
      { key: "firstName", message: "First name is required" },
      { key: "lastName", message: "Last name is required" },
      {
        key: "email",
        message: "Valid email is required",
        validator: (v) => v.includes("@"),
      },
      { key: "phoneNumber", message: "Phone number is required" },
    ];
    validateData(data.data, requiredFields);

    const {
      firstName,
      lastName,
      email,
      country,
      state,
      addressLine1,
      city,
      postalCode,
      phoneNumber,
    } = data.data;

    const uid = data.auth?.uid;
    if (!uid) throw new HttpsError("unauthenticated", "User is not authenticated");

    // Store user setup data in Firestore for use during createElectronicAccount
    await db.collection("safehavenUserSetup").doc(uid).set({
      firstName: firstName?.trim() || "",
      lastName: lastName?.trim() || "",
      email: email?.trim() || "",
      phoneNumber: phoneNumber?.trim() || "",
      country: country?.trim() || "NG",
      state: state?.trim() || "",
      addressLine1: addressLine1?.trim() || "",
      city: city?.trim() || "",
      postalCode: postalCode?.trim() || "",
      updatedAt: admin.firestore.FieldValue.serverTimestamp(),
    }, { merge: true });

    // Return Anchor-compatible response ï¿½ uid is used as the "customer ID"
    return {
      data: {
        id: uid,
        type: "IndividualCustomer",
        attributes: {
          fullName: { firstName: firstName?.trim() || "", lastName: lastName?.trim() || "" },
          email: email?.trim() || "",
          phoneNumber: phoneNumber?.trim() || "",
          status: "ACTIVE",
        },
      },
    };
  },
);
// Create Safehaven Business User
exports.safehavenCreateBusinessUser = onCallLogged(
  "safehavenCreateBusinessUser",
  { secrets: [safehavenClientId, safehavenPrivateKey, safehavenCompanyUrl] },
  async (data, context) => {
    await ensureVerifiedOrStandUser(data.auth);
    validateData(data.data, [
      { key: "businessName", message: "Business name is required" },
      {
        key: "email",
        message: "Valid email is required",
        validator: (v) => typeof v === "string" && v.includes("@"),
      },
      { key: "phoneNumber", message: "Phone number is required" },
    ]);

    const uid = data.auth?.uid;
    if (!uid) {
      throw new HttpsError("unauthenticated", "User is not authenticated");
    }

    const officers = Array.isArray(data.data.officers) ? data.data.officers : [];
    const firstOfficer = officers[0] || {};

    const businessName = String(data.data.businessName || "").trim();
    const email = String(data.data.email || "").trim();
    const phoneNumber = String(data.data.phoneNumber || "").trim();
    const companyRegistrationNumber = String(
      data.data.companyRegistrationNumber ||
        data.data.registrationNumber ||
        data.data.businessBvn ||
        "",
    ).trim();
    const identityId = String(
      data.data.identityId ||
        firstOfficer.bvn ||
        data.data.businessBvn ||
        "",
    ).trim();

    const autoSweep = Boolean(data.data.autoSweep);
    const autoSweepAccountNumber = String(data.data.autoSweepAccountNumber || "").trim();

    const subAccountPayload = {
      phoneNumber,
      emailAddress: email,
      identityType: "BVN",
      companyRegistrationNumber,
      identityId,
      autoSweep,
      externalReference: `biz-${uid}-${Date.now()}`,
    };

    if (autoSweep && autoSweepAccountNumber) {
      subAccountPayload.autoSweepDetails = {
        schedule: "Monthly",
        accountNumber: autoSweepAccountNumber,
      };
    }

    const resp = await safehavenRequest({
      path: "/accounts/subaccount",
      method: "POST",
      body: subAccountPayload,
    });

    const acct = resp.data || {};
    const accountId = acct._id || acct.id || uid;

    await db.collection("safehavenUserSetup").doc(uid).set({
      safehavenAccountId: accountId,
      safehavenAccountNumber: acct.accountNumber || "",
      safehavenBankCode: acct.bankCode || "090286",
      safehavenBankName: acct.bankName || "Safe Haven MFB",
      businessProfile: {
        businessName,
        email,
        phoneNumber,
        companyRegistrationNumber,
        identityId,
        accountType: acct.subAccountDetails?.accountType || "Corporate",
      },
      updatedAt: admin.firestore.FieldValue.serverTimestamp(),
    }, { merge: true });

    return {
      data: {
        id: uid,
        type: "BusinessCustomer",
        attributes: {
          basicDetail: {
            businessName,
            registrationType: data.data.registrationType || "Corporate",
            country: data.data.country || "NG",
            dateOfRegistration: data.data.dateOfRegistration || null,
          },
          contact: {
            email: { general: email },
            phoneNumber,
          },
          status: acct.status || "ACTIVE",
          accountId,
          _safehaven: acct,
        },
      },
    };
  },
);

// Verify Getanchor Business Customer
exports.safehavenVerifyBusinessCustomer = onCallLogged(
  "safehavenVerifyBusinessCustomer",
  { secrets: [safehavenClientId, safehavenPrivateKey, safehavenCompanyUrl] },
  async (data, context) => {
    await ensureVerifiedOrStandUser(data.auth);
    const requiredFields = [
      { key: "customerId", message: "Customer ID is required" },
    ];
    validateData(data.data, requiredFields);
    const customerId = String(data.data.customerId || "").trim();

    const setupDoc = await db.collection("safehavenUserSetup").doc(customerId).get();
    if (!setupDoc.exists) {
      throw new HttpsError("not-found", "Business customer profile not found");
    }

    const setup = setupDoc.data() || {};
    const accountId = setup.safehavenAccountId;
    let accountStatus = "PENDING";
    let safehavenData = null;

    if (accountId) {
      try {
        const accountResp = await safehavenRequest({
          path: `/accounts/${encodeURIComponent(accountId)}`,
          method: "GET",
        });
        safehavenData = accountResp.data || null;
        accountStatus = safehavenData?.status || "ACTIVE";
      } catch (err) {
        console.warn("[verifyBusinessCustomer] Safehaven lookup failed:", err.message);
      }
    }

    return {
      data: {
        id: customerId,
        type: "BusinessVerification",
        attributes: {
          status: accountStatus,
          verified: accountStatus === "ACTIVE",
          accountId: accountId || null,
          _safehaven: safehavenData,
        },
      },
    };
  },
);

// Upgrade Customer KYC (Safe Haven ï¿½ stores BVN/identity data and calls /identity/v2/validate)
exports.safehavenUpgradeCustomerKyc = onCallLogged(
  "safehavenUpgradeCustomerKyc",
  { secrets: [safehavenClientId, safehavenPrivateKey, safehavenCompanyUrl] },
  async (data, context) => {
    await ensureVerifiedOrStandUser(data.auth);

    validateData(data.data, [
      { key: "customerId", message: "Customer ID is required" },
      {
        key: "level",
        message: "Valid level (TIER_1, TIER_2 or TIER_3) is required",
        validator: (v) => ["TIER_1", "TIER_2", "TIER_3"].includes(v),
      },
    ]);

    const uid = data.auth?.uid;
    if (!uid) throw new HttpsError("unauthenticated", "User is not authenticated");

    const {
      level,
      bvn,
      idNumber,
      idType,
      dateOfBirth,
      gender,
      expiryDate,
    } = data.data;

    if (level === "TIER_2" && (!bvn?.trim() || !dateOfBirth?.trim() || !gender?.trim())) {
      throw new HttpsError("invalid-argument", "BVN, dateOfBirth, and gender are required for TIER_2");
    }
    if (level === "TIER_3" && (!idNumber?.trim() || !idType?.trim())) {
      throw new HttpsError("invalid-argument", "ID number and ID type are required for TIER_3");
    }

    // Store KYC data in Firestore for use during createElectronicAccount
    const kycUpdate = { level, updatedAt: admin.firestore.FieldValue.serverTimestamp() };
    if (level === "TIER_2") {
      kycUpdate.bvn = bvn.trim();
      kycUpdate.dateOfBirth = dateOfBirth.trim();
      kycUpdate.gender = gender.trim();
    } else if (level === "TIER_3") {
      kycUpdate.idNumber = idNumber.trim();
      kycUpdate.idType = idType.trim();
      if (expiryDate) kycUpdate.idExpiryDate = expiryDate;
    }
    await db.collection("safehavenUserSetup").doc(uid).set(kycUpdate, { merge: true });

    // Call Safehaven identity validation for TIER_2 (BVN) and TIER_3 (ID doc)
    let safehavenResp = null;
    try {
      if (level === "TIER_2" && bvn?.trim()) {
        safehavenResp = await safehavenRequest({
          path: "/identity/v2/validate",
          method: "POST",
          body: {
            type: "BVN",
            number: bvn.trim(),
            debitAccountNumber: "", // will be populated after account creation
          },
        });
      } else if (level === "TIER_3" && idNumber?.trim()) {
        safehavenResp = await safehavenRequest({
          path: "/identity/v2/validate",
          method: "POST",
          body: {
            type: idType?.trim() || "NIN",
            number: idNumber.trim(),
          },
        });
      }
    } catch (err) {
      // Identity validation errors are non-fatal here; we store the attempt
      console.warn("[upgradeCustomerKyc] SafeHaven identity validate error:", err.message);
    }

    // Return Anchor-compatible response
    return {
      data: {
        id: uid,
        type: "Verification",
        attributes: {
          level,
          status: safehavenResp?.data?.status || "PENDING",
          _safehaven: safehavenResp?.data || null,
        },
      },
    };
  },
);

// Initiate identity verification to obtain identityId (_id)
// Docs: POST /identity/v2
exports.safehavenInitiateIdentityVerification = onCallLogged(
  "safehavenInitiateIdentityVerification",
  { secrets: [safehavenClientId, safehavenPrivateKey, safehavenCompanyUrl, safehavenDebitAccountNumber] },
  async (data, context) => {
    await ensureVerifiedOrStandUser(data.auth);

    validateData(data.data, [
      {
        key: "type",
        message: "type is required (BVN or NIN)",
        validator: (v) => ["BVN", "NIN", "BVNUSSD", "VNIN", "VID"].includes(String(v || "").toUpperCase()),
      },
      { key: "number", message: "number is required" },
    ]);

    const uid = data.auth?.uid;
    if (!uid) throw new HttpsError("unauthenticated", "User is not authenticated");

    const setupDoc = await db.collection("safehavenUserSetup").doc(uid).get();
    const setup = setupDoc.exists ? setupDoc.data() : {};

    const type = String(data.data.type || "").trim().toUpperCase();
    const number = String(data.data.number || "").trim();
    const configuredDebitAccount = await _getSafehavenDebitAccountConfig();
    let debitAccountNumber = String(
      data.data.debitAccountNumber ||
        setup.safehavenAccountNumber ||
        configuredDebitAccount.debitAccountNumber ||
        "",
    ).trim();
    // Default to async:true â€” synchronous mode requires an immediate NIP debit
    // which fails if the account has zero balance (sandbox always has 0).
    // Async mode returns PENDING immediately; the result arrives via webhook.
    const asyncMode = data.data.async !== false;

    if (debitAccountNumber) {
      console.log("[safehavenInitiateIdentityVerification] debit account source", {
        mode: configuredDebitAccount.mode,
        source: data.data.debitAccountNumber
          ? "request"
          : setup.safehavenAccountNumber
          ? "safehavenUserSetup"
          : configuredDebitAccount.source,
        suffix: debitAccountNumber.slice(-4),
      });
    }

    // Auto-resolve company main account number when not supplied or when the
    // configured value is the sandbox-default fallback. GET /accounts?isSubAccount=false
    // returns the main (non-sub) accounts for the client.
    if (!debitAccountNumber || configuredDebitAccount.source === "sandbox-default") {
      if (configuredDebitAccount.source === "sandbox-default" && debitAccountNumber) {
        console.log(
          "[safehavenInitiateIdentityVerification] configured debit account is sandbox-default; attempting /accounts auto-resolve to prefer a real company account",
        );
      }
      try {
        const accountsResp = await safehavenRequest({
          path: "/accounts?isSubAccount=false&page=0&limit=1",
          method: "GET",
        });
        const rootData = accountsResp?.data;
        const candidateList = Array.isArray(rootData)
          ? rootData
          : Array.isArray(rootData?.data)
            ? rootData.data
            : Array.isArray(rootData?.accounts)
              ? rootData.accounts
              : Array.isArray(rootData?.result)
                ? rootData.result
                : [];

        console.log("[safehavenInitiateIdentityVerification] /accounts response shape", {
          rootIsArray: Array.isArray(rootData),
          hasDataArray: Array.isArray(rootData?.data),
          hasAccountsArray: Array.isArray(rootData?.accounts),
          hasResultArray: Array.isArray(rootData?.result),
          candidateCount: candidateList.length,
        });

        const firstAccount = candidateList[0] || rootData;
        console.log("[safehavenInitiateIdentityVerification] /accounts first account keys", {
          keys: firstAccount && typeof firstAccount === "object" ? Object.keys(firstAccount) : [],
          hasAccountNumber: Boolean(firstAccount?.accountNumber),
        });

        const resolved = String(firstAccount?.accountNumber || "").trim();
        if (resolved) {
          debitAccountNumber = resolved;
          console.log(`[safehavenInitiateIdentityVerification] Resolved company debitAccountNumber: ${debitAccountNumber}`);
        }
      } catch (fetchErr) {
        console.warn("[safehavenInitiateIdentityVerification] Could not auto-resolve company account:", fetchErr.message);
      }
    }

    if (!debitAccountNumber) {
      throw new HttpsError(
        "invalid-argument",
        "debitAccountNumber is required to initiate identity verification",
      );
    }

    const resp = await safehavenRequest({
      path: "/identity/v2",
      method: "POST",
      body: {
        type,
        number,
        debitAccountNumber,
        async: asyncMode,
      },
    });

    const verification = resp.data || {};
    const identityId = String(
      verification._id || verification.id || verification.identityId || "",
    ).trim();

    await db.collection("safehavenUserSetup").doc(uid).set(
      {
        identityVerification: {
          identityId: identityId || null,
          type,
          number,
          status: verification.status || "PENDING",
          initiatedAt: admin.firestore.FieldValue.serverTimestamp(),
          rawInitiate: verification,
        },
        identityId: identityId || null,
        identityType: identityId ? "vID" : setup.identityType || null,
        updatedAt: admin.firestore.FieldValue.serverTimestamp(),
      },
      { merge: true },
    );

    return {
      data: {
        identityId: identityId || null,
        type,
        status: verification.status || "PENDING",
        _safehaven: verification,
      },
    };
  },
);

// Validate identity verification with OTP
// Docs: POST /identity/v2/validate
exports.safehavenValidateIdentityVerification = onCallLogged(
  "safehavenValidateIdentityVerification",
  { secrets: [safehavenClientId, safehavenPrivateKey, safehavenCompanyUrl] },
  async (data, context) => {
    await ensureVerifiedOrStandUser(data.auth);

    validateData(data.data, [
      { key: "identityId", message: "identityId is required" },
      {
        key: "type",
        message: "type is required (BVN or NIN)",
        validator: (v) => ["BVN", "NIN", "BVNUSSD", "VNIN", "VID"].includes(String(v || "").toUpperCase()),
      },
      { key: "otp", message: "otp is required" },
    ]);

    const uid = data.auth?.uid;
    if (!uid) throw new HttpsError("unauthenticated", "User is not authenticated");

    const identityId = String(data.data.identityId || "").trim();
    const type = String(data.data.type || "").trim().toUpperCase();
    const otp = String(data.data.otp || "").trim();

    const resp = await safehavenRequest({
      path: "/identity/v2/validate",
      method: "POST",
      body: {
        identityId,
        type,
        otp,
      },
    });

    const verification = resp.data || {};
    const resolvedIdentityId = String(
      verification._id || verification.identityId || identityId,
    ).trim();

    await db.collection("safehavenUserSetup").doc(uid).set(
      {
        identityVerification: {
          identityId: resolvedIdentityId,
          type,
          status: verification.status || "VALIDATED",
          validatedAt: admin.firestore.FieldValue.serverTimestamp(),
          rawValidate: verification,
        },
        identityId: resolvedIdentityId,
        identityType: "vID",
        updatedAt: admin.firestore.FieldValue.serverTimestamp(),
      },
      { merge: true },
    );

    return {
      data: {
        identityId: resolvedIdentityId,
        identityType: "vID",
        status: verification.status || "VALIDATED",
        _safehaven: verification,
      },
    };
  },
);

// Create Sub Account
// Creates a Safehaven sub-account under the company account.
exports.safehavenCreateSubAccount = onCallLogged(
  "safehavenCreateSubAccount",
  { secrets: [safehavenClientId, safehavenPrivateKey, safehavenCompanyUrl, safehavenDebitAccountNumber] },
  async (data, context) => {
    await ensureVerifiedOrStandUser(data.auth);

    validateData(data.data, [
      { key: "idempotencyKey", message: "Idempotency key is required" },
    ]);

    const uid = data.auth?.uid;
    if (!uid) throw new HttpsError("unauthenticated", "User is not authenticated");

    const idempotencyKey = data.data.idempotencyKey.trim();

    const setupPatch = {
      firstName: String(data.data.firstName || "").trim(),
      lastName: String(data.data.lastName || "").trim(),
      email: String(data.data.email || "").trim(),
      phoneNumber: String(data.data.phoneNumber || "").trim(),
      country: String(data.data.country || "NG").trim() || "NG",
      state: String(data.data.state || "").trim(),
      addressLine1: String(data.data.addressLine1 || "").trim(),
      city: String(data.data.city || "").trim(),
      postalCode: String(data.data.postalCode || "").trim(),
      bvn: String(data.data.bvn || "").trim(),
      updatedAt: admin.firestore.FieldValue.serverTimestamp(),
    };

    await db.collection("safehavenUserSetup").doc(uid).set(setupPatch, { merge: true });

    // Read user info stored for subaccount creation.
    const setupDoc = await db.collection("safehavenUserSetup").doc(uid).get();
    const setup = setupDoc.exists ? setupDoc.data() : {};

    const requestedIdentityId = String(data.data.identityId || "").trim();
    const setupIdentityId = String(
      setup.identityId || setup.identityVerification?.identityId || "",
    ).trim();
    // If the webhook already marked this identityId as FAILED, discard it so
    // we fall through to the BVN fallback path without a wasted 500 round-trip.
    const storedIdentityStatus = String(setup.identityCheckStatus || "").trim().toUpperCase();
    const rawResolvedId = requestedIdentityId || setupIdentityId;
    const resolvedIdentityId = (storedIdentityStatus === "FAILED" && !requestedIdentityId)
      ? ""
      : rawResolvedId;

    const requestedIdentityType = String(data.data.identityType || "").trim();
    const resolvedIdentityType = requestedIdentityType || (resolvedIdentityId ? "vID" : "BVN");

    const externalReference = String(data.data.externalReference || idempotencyKey).trim() || idempotencyKey;
    const companyRegistrationNumber = String(data.data.companyRegistrationNumber || "").trim();
    const autoSweep = Boolean(data.data.autoSweep);
    const autoSweepDetails =
      data.data.autoSweepDetails && typeof data.data.autoSweepDetails === "object"
        ? data.data.autoSweepDetails
        : null;

    const subAccountBody = {
      phoneNumber: setup.phoneNumber || "",
      emailAddress: setup.email || "",
      identityType: resolvedIdentityType,
      externalReference,
      autoSweep,
    };

    if (!subAccountBody.phoneNumber) {
      throw new HttpsError("invalid-argument", "phoneNumber is required to create subaccount");
    }

    if (!subAccountBody.emailAddress) {
      throw new HttpsError("invalid-argument", "email is required to create subaccount");
    }

    if (companyRegistrationNumber) {
      subAccountBody.companyRegistrationNumber = companyRegistrationNumber;
    }

    if (autoSweep && autoSweepDetails) {
      subAccountBody.autoSweepDetails = autoSweepDetails;
    }

    // Build identity section. We always prefer vID (identityId) first, then
    // fall back to BVN direct if identityId is absent or its credit-check failed.
    const bvnForFallback = String(setup.bvn || data.data.bvn || "").trim();

    if (resolvedIdentityId) {
      subAccountBody.identityId = resolvedIdentityId;
    } else if (bvnForFallback) {
      // No identityId yet â€” use BVN mode directly (no identityId field).
      subAccountBody.identityType = "BVN";
      subAccountBody.identityNumber = bvnForFallback;
    } else {
      throw new HttpsError(
        "failed-precondition",
        "Missing identityId or BVN. Call safehavenInitiateIdentityVerification then safehavenValidateIdentityVerification before creating subaccount.",
      );
    }

    let resp;
    try {
      resp = await safehavenRequest({
        path: "/accounts/subaccount",
        method: "POST",
        body: subAccountBody,
      });
    } catch (err) {
      // If the vID mode failed (e.g. identity credit-check FAILED in sandbox /
      // production), fall back to BVN mode which does not require the debit.
      const isVidMode = subAccountBody.identityType === "vID";
      const is500 = String(err?.message || "").includes("500");
      if (isVidMode && bvnForFallback && (is500 || err?.code === "internal")) {
        console.warn(
          `[safehavenCreateSubAccount] vID mode failed (${err.message}); retrying with BVN fallback`,
        );
        // BVN mode requires an identityId obtained from POST /identity/v2 first.
        const debitAccountConfig = await _getSafehavenDebitAccountConfig();
        const debitAccountNumber = debitAccountConfig.debitAccountNumber || "0104610514";
        console.log("[safehavenCreateSubAccount] Initiating BVN identity check", { debitSource: debitAccountConfig.source });
        const identityInitResp = await safehavenRequest({
          path: "/identity/v2",
          method: "POST",
          body: { type: "BVN", number: bvnForFallback, debitAccountNumber, async: false },
        });
        const bvnIdentityId =
          identityInitResp?._id ||
          identityInitResp?.data?._id ||
          identityInitResp?.data?.id ||
          identityInitResp?.id;
        const bvnIdentityStatus = String(
          identityInitResp?.data?.status || identityInitResp?.status || ""
        ).trim().toUpperCase();
        if (!bvnIdentityId) {
          throw new HttpsError("internal", "BVN identity check failed: no identityId returned from /identity/v2");
        }
        if (bvnIdentityStatus && bvnIdentityStatus !== "SUCCESS") {
          throw new HttpsError(
            "failed-precondition",
            `BVN identity check status: ${bvnIdentityStatus}. Debit may have failed â€” check debitAccountNumber.`,
          );
        }
        console.log("[safehavenCreateSubAccount] BVN identity check OK", { bvnIdentityId, bvnIdentityStatus });
        const bvnBody = {
          ...subAccountBody,
          identityType: "BVN",
          identityId: bvnIdentityId,
        };
        delete bvnBody.identityNumber;
        console.log("[safehavenCreateSubAccount] Retrying subaccount creation with BVN fallback", { bvnBody });
        resp = await safehavenRequest({
          path: "/accounts/subaccount",
          method: "POST",
          body: bvnBody,
        });
      } else {
        throw err;
      }
    }

    const acct = resp.data || {};
    console.log("[safehavenCreateSubAccount] subaccount creation response", { resp: acct });
    const accountId = acct._id || acct.id || uid;
    const accountNumber = acct.accountNumber || "";
    const bankCode = acct.bankCode || "090286";
    const bankName = acct.bankName || "Safe Haven MFB";
    const accountName = acct.accountName || "";

    // Persist mapping for later lookups
    await db.collection("safehavenUserSetup").doc(uid).set({
      safehavenAccountId: accountId,
      safehavenAccountNumber: accountNumber,
      safehavenBankCode: bankCode,
      safehavenBankName: bankName,
      safehavenAccountName: accountName,
      identityId: resolvedIdentityId || null,
      identityType: subAccountBody.identityType,
      updatedAt: admin.firestore.FieldValue.serverTimestamp(),
    }, { merge: true });

    // Return Anchor-compatible shape that Flutter stores under getAnchorData.virtualAccount
    return {
      data: {
        id: accountId,
        type: "DepositAccount",
        attributes: {
          accountNumber,
          accountName,
          currency: "NGN",
          bank: { id: bankCode, name: bankName },
          status: acct.status || "ACTIVE",
        },
      },
    };
  },
);

// Fetch Account Balance (Safehaven ï¿½ returns balance in kobo to match Anchor contract)
exports.safehavenFetchAccountBalance = onCall(
  { secrets: [safehavenClientId, safehavenPrivateKey, safehavenCompanyUrl] },
  async (data, context) => {
    console.log("fetchAccountBalance called with data:", data);
    await ensureVerifiedOrStandUser(data.auth);

    validateData(data.data, [
      { key: "accountId", message: "Account ID is required" },
    ]);

    let accountId = data.data.accountId.trim();
    // SafeHaven MongoDB _ids are 24 chars. If accountId > 24 chars it's a Firebase
    // UID stored as fallback when the subaccount API didn't return _id. Look up
    // the real SafeHaven accountId from safehavenUserSetup.
    if (accountId.length > 24) {
      const callerUid = data.auth?.uid;
      if (callerUid) {
        const setupSnap = await db.collection("safehavenUserSetup").doc(callerUid).get();
        const realId = setupSnap.data()?.safehavenAccountId;
        if (realId && realId.length <= 24) {
          console.log(`[safehavenFetchAccountBalance] Resolved Firebase UID to SafeHaven accountId: ${realId}`);
          accountId = realId;
        } else {
          throw new HttpsError("not-found", "SafeHaven account ID not found. Please contact support.");
        }
      }
    }

    const resp = await safehavenRequest({
      path: `/accounts/${encodeURIComponent(accountId)}`,
      method: "GET",
    });

    const acct = resp.data || {};
    // Safehaven returns balance in naira; Flutter divides by 100 expecting kobo
    const balanceKobo = Math.round((acct.accountBalance ?? 0) * 100);
    const ledgerKobo = Math.round((acct.ledgerBalance ?? acct.accountBalance ?? 0) * 100);

    return {
      data: {
        availableBalance: balanceKobo,
        ledgerBalance: ledgerKobo,
        accountNumber: acct.accountNumber || "",
        currency: acct.currency || "NGN",
      },
    };
  },
);

// SECURITY: Internal service endpoint ? requires Bearer token auth using PADILOAN_API_SECRET.
// Client apps (Flutter/web) must NOT call this directly; use the callable fetchAccountBalance instead.
// Only internal server-to-server callers (e.g. admin backend) may use this HTTP endpoint.
exports.fetchAccountBalanceHttp = onRequest(
  { secrets: [getanchorSecretKey, padiLoanApiSecret] },
  async (req, res) => {
    // Allow CORS for any origin
    cors({ origin: true })(req, res, async () => {
      try {
        // Handle preflight
        if (req.method === "OPTIONS") {
          return res.status(204).send("");
        }

        if (req.method !== "POST") {
          return res.status(405).json({ error: "Method not allowed" });
        }

        // SECURITY: Bearer token guard ? must match PADILOAN_API_SECRET Firebase secret.
        const authHeader = req.headers.authorization;
        const apiSecret = padiLoanApiSecret.value();
        if (!authHeader || authHeader !== `Bearer ${apiSecret}`) {
          return res.status(401).json({ error: "Unauthorized" });
        }

        const secretKey = getanchorSecretKey.value();
        if (!secretKey || secretKey.length === 0) {
          return res
            .status(500)
            .json({ error: "Getanchor Secret Key is not set" });
        }

        const accountId =
          req.body && req.body.accountId
            ? typeof req.body.accountId === "string"
              ? req.body.accountId.trim()
              : req.body.accountId
            : null;
        if (!accountId) {
          return res.status(400).json({ error: "Account ID is required" });
        }

        const url = `/accounts/balance/${encodeURIComponent(accountId)}`;
        const response = await makeApiRequest({
          url,
          method: "GET",
          secretKey,
        });
        return res.status(200).json(response);
      } catch (err) {
        console.error("fetchAccountBalanceHttp error", err);
        return res
          .status(500)
          .json({ error: err.message || "Internal server error" });
      }
    });
  },
);

// Fetch Account Details
exports.safehavenFetchAccountDetails = onCall(
  { secrets: [getanchorSecretKey] },
  async (data, context) => {
    await ensureVerifiedOrStandUser(data.auth);
    const secretKey = getanchorSecretKey.value();
    if (secretKey.length === 0) {
      throw new HttpsError(
        "invalid-argument",
        "Getanchor Secret Key is not set",
      );
    }

    validateData(data.data, [
      { key: "accountId", message: "Account ID is required" },
    ]);

    const accountId = data.data.accountId.trim();
    
    const url = `${BASE_URL}/accounts/${encodeURIComponent(accountId)}`;

    return makeApiRequest({ url, method: "GET", secretKey });
  },
);

// Fetch Account Number
exports.safehavenFetchAccountNumber = onCall(
  { secrets: [safehavenClientId, safehavenPrivateKey, safehavenCompanyUrl] },
  async (data, context) => {
    await ensureVerifiedOrStandUser(data.auth);

    validateData(data.data, [
      { key: "accountId", message: "Account ID is required" },
    ]);

    let accountId = data.data.accountId.trim();
    // If accountId > 24 chars it's a Firebase UID stored as fallback. Look up
    // the real SafeHaven accountId from safehavenUserSetup.
    if (accountId.length > 24) {
      const callerUid = data.auth?.uid;
      if (callerUid) {
        const setupSnap = await db.collection("safehavenUserSetup").doc(callerUid).get();
        const realId = setupSnap.data()?.safehavenAccountId;
        if (realId && realId.length <= 24) {
          console.log(`[safehavenFetchAccountNumber] Resolved Firebase UID to SafeHaven accountId: ${realId}`);
          accountId = realId;
        } else {
          throw new HttpsError("not-found", "SafeHaven account ID not found. Please contact support.");
        }
      }
    }

    // SafeHaven assigns account numbers asynchronously after subaccount creation.
    // Retry up to 4 times with 3-second gaps if accountNumber is still empty.
    let acct = {};
    const maxAttempts = 4;
    for (let attempt = 1; attempt <= maxAttempts; attempt++) {
      const resp = await safehavenRequest({
        path: `/accounts/${encodeURIComponent(accountId)}`,
        method: "GET",
      });
      acct = resp.data || {};
      if (acct.accountNumber) break;
      if (attempt < maxAttempts) {
        console.log(`[safehavenFetchAccountNumber] accountNumber empty on attempt ${attempt}; retrying in 3s...`);
        await new Promise((r) => setTimeout(r, 3000));
      }
    }

    const accountNumber = acct.accountNumber || null;

    if (!accountNumber) {
      throw new HttpsError("not-found", "Account number not yet assigned by SafeHaven");
    }

    // Bank is always Safe Haven MFB for subaccounts; include name + code if available
    const bankName = acct.bankName || "Safe Haven MFB";
    const bankCode = acct.bankCode || "090286";

    return { accountNumber, bank: { name: bankName, id: bankCode } };
  },
);

const notifyUserByAccountId = async (accountId, notification) => {
  try {
    const snap = await admin
      .firestore()
      .collection("users")
      .where("getAnchorData.virtualAccount.data.id", "==", accountId)
      .limit(1)
      .get();

    if (snap.empty) {
      console.log(`No user found for accountId ${accountId}`);
      return;
    }

    const token = snap.docs[0].data()?.deviceToken;
    if (!token) {
      console.log(`No deviceToken for accountId ${accountId}`);
      return;
    }

    await admin.messaging().send({ token, notification, ...FCM_CHANNEL });
  } catch (err) {
    console.error("notifyUserByAccountId error", err);
  }
};

/**
 * Persist a notification to users/{userId}/notifications so the Flutter app
 * can display a real notification history feed.
 */
const saveNotification = async (userId, { title, body, type, amount }) => {
  if (!userId) return;
  try {
    await admin
      .firestore()
      .collection("users")
      .doc(userId)
      .collection("notifications")
      .add({
        title,
        body,
        type: type || "general",
        amount: amount ?? null,
        read: false,
        timestamp: admin.firestore.FieldValue.serverTimestamp(),
      });
  } catch (err) {
    console.error("saveNotification error", err);
  }
};

/**
 * Send email notification by looking up user via account ID
 * Finds the user, gets their email, and sends an email
 */
const sendEmailNotificationByAccountId = async (accountId, { title, body }) => {
  try {
    const snap = await admin
      .firestore()
      .collection("users")
      .where("getAnchorData.virtualAccount.data.id", "==", accountId)
      .limit(1)
      .get();

    if (snap.empty) {
      console.log(`No user found for accountId ${accountId} to send email`);
      return;
    }

    const userData = snap.docs[0].data();
    const email = userData?.email;
    if (!email) {
      console.log(`No email found for accountId ${accountId}`);
      return;
    }

    // Send email with title as subject and body as text content
    await sendNotifyEmail({
      to: email,
      subject: title,
      text: body,
      html: `<p>${body}</p>`,
    });
  } catch (err) {
    console.error("sendEmailNotificationByAccountId error", err);
  }
};

// Freeze Account
exports.sudoFreezeAccount = onCall(
  { secrets: [getanchorSecretKey] },
  async (data, context) => {
    await ensureVerifiedOrStandUser(data.auth);

    const secretKey = getanchorSecretKey.value();
    if (secretKey.length === 0) {
      throw new HttpsError(
        "invalid-argument",
        "Getanchor Secret Key is not set",
      );
    }

    validateData(data.data, [
      { key: "accountId", message: "Account ID is required" },
      {
        key: "freezeReason",
        message: "Freeze reason is required",
        validator: (v) => typeof v === "string" && v.trim().length > 0,
      },
      {
        key: "freezeDescription",
        message: "Freeze description is required",
        validator: (v) => typeof v === "string" && v.trim().length > 0,
      },
    ]);

    const accountId = data.data.accountId.trim();
    const freezeReason = data.data.freezeReason.trim();
    const freezeDescription = data.data.freezeDescription.trim();

    
    const url = `${BASE_URL}/accounts/${encodeURIComponent(accountId)}/freeze`;

    const body = {
      data: {
        attributes: { freezeReason, freezeDescription },
        type: "DepositAccount",
      },
    };

    const response = await makeApiRequest({
      url,
      method: "POST",
      secretKey,
      body,
    });

    await notifyUserByAccountId(accountId, {
      title: "Account Frozen",
      body: "Your account has been frozen. Please contact support if this was unexpected.",
    });

    await sendEmailNotificationByAccountId(accountId, {
      title: "Account Frozen",
      body: "Your account has been frozen. Please contact support if this was unexpected.",
    });

    return response;
  },
);

// Unfreeze Account
exports.sudoUnFreezeAccount = onCall(
  { secrets: [getanchorSecretKey] },
  async (data, context) => {
    await ensureVerifiedOrStandUser(data.auth);

    const secretKey = getanchorSecretKey.value();
    if (secretKey.length === 0) {
      throw new HttpsError(
        "invalid-argument",
        "Getanchor Secret Key is not set",
      );
    }

    validateData(data.data, [
      { key: "accountId", message: "Account ID is required" },
    ]);

    const accountId = data.data.accountId.trim();

    
    const url = `${BASE_URL}/accounts/unfreeze`;

    const body = {
      data: {
        attributes: { id: accountId },
        type: "DepositAccount",
      },
    };

    const response = await makeApiRequest({
      url,
      method: "POST",
      secretKey,
      body,
    });

    await notifyUserByAccountId(accountId, {
      title: "Account Unfrozen",
      body: "Your account has been unfrozen and is now active.",
    });

    await sendEmailNotificationByAccountId(accountId, {
      title: "Account Unfrozen",
      body: "Your account has been unfrozen and is now active.",
    });

    return response;
  },
);

// Create Counterparty (Safehaven shim â€” stores beneficiary in Firestore)
exports.safehavenCreateCounterparty = onCall(
  { secrets: [safehavenClientId, safehavenPrivateKey, safehavenCompanyUrl] },
  async (data, context) => {
    await ensureVerifiedOrStandUser(data.auth);

    validateData(data.data, [
      { key: "accountName", message: "Account name is required" },
      { key: "accountNumber", message: "Account number is required" },
      { key: "bankId", message: "Bank id is required" },
    ]);

    const uid = data.auth?.uid;
    if (!uid) throw new HttpsError("unauthenticated", "User is not authenticated");

    const accountName = data.data.accountName.trim();
    const bankName = data.data.bankName?.trim() || "";
    const accountNumber = data.data.accountNumber.trim();
    const bankCode = data.data.bankId.trim();
    const generatedId = `${bankCode}_${accountNumber}`;

    await db
      .collection("safehavenCounterparties")
      .doc(uid)
      .collection("beneficiaries")
      .doc(generatedId)
      .set({
        accountName,
        accountNumber,
        bankCode,
        bankName,
        updatedAt: admin.firestore.FieldValue.serverTimestamp(),
      }, { merge: true });

    return {
      data: {
        id: generatedId,
        type: "CounterParty",
        attributes: {
          accountName,
          accountNumber,
          bank: { id: bankCode, name: bankName },
        },
      },
    };
  },
);

// Create NIP Transfer
exports.safehavenTransferNip = onCallLogged(
  "safehavenTransferNip",
  { secrets: [safehavenClientId, safehavenPrivateKey, safehavenCompanyUrl] },
  async (data, context) => {
    await ensureVerifiedOrStandUser(data.auth);

    validateData(data.data, [
      { key: "accountId", message: "Account ID is required" },
      { key: "counterpartyId", message: "Counterparty ID is required" },
      {
        key: "amount",
        message: "Valid amount is required",
        validator: (v) => typeof v === "number" && v > 0,
      },
      { key: "idempotencyKey", message: "Idempotency key is required" },
    ]);

    const uid = data.auth?.uid;
    if (!uid) throw new HttpsError("unauthenticated", "User is not authenticated");

    const counterpartyId = data.data.counterpartyId.trim();
    const amount = data.data.amount; // kobo
    const narration = data.data.narration?.trim() || "Transfer";
    const idempotencyKey = data.data.idempotencyKey.trim();

    const cpDoc = await db
      .collection("safehavenCounterparties")
      .doc(uid)
      .collection("beneficiaries")
      .doc(counterpartyId)
      .get();
    if (!cpDoc.exists) {
      throw new HttpsError("not-found", "Counterparty not found");
    }
    const cp = cpDoc.data();

    const acctInfo = await _getSafehavenAccountForUser(uid);
    const debitAccountNumber = acctInfo.accountNumber;
    if (!debitAccountNumber) {
      throw new HttpsError("failed-precondition", "Virtual account not set up");
    }

    const enquiry = await _safehavenNameEnquiry(uid, cp.bankCode, cp.accountNumber);
    const nameEnquiryReference = enquiry.nameEnquiryReference;
    if (!nameEnquiryReference) {
      throw new HttpsError("failed-precondition", "Name enquiry failed");
    }

    const resp = await safehavenRequest({
      path: "/transfers",
      method: "POST",
      body: {
        nameEnquiryReference,
        debitAccountNumber,
        beneficiaryBankCode: cp.bankCode,
        beneficiaryAccountNumber: cp.accountNumber,
        narration,
        amount: amount / 100,
        saveBeneficiary: false,
        paymentReference: idempotencyKey,
      },
    });
    const tx = resp.data || {};

    return {
      data: {
        id: tx._id || tx.id || idempotencyKey,
        type: "NIPTransfer",
        attributes: {
          amount,
          currency: "NGN",
          status: tx.status || "PENDING",
          narration,
          reference: tx.paymentReference || idempotencyKey,
        },
      },
    };
  },
);

// Create Book Transfer
exports.safehavenTransferIntra = onCallLogged(
  "safehavenTransferIntra",
  { secrets: [safehavenClientId, safehavenPrivateKey, safehavenCompanyUrl] },
  async (data, context) => {
    await ensureVerifiedOrStandUser(data.auth);

    validateData(data.data, [
      { key: "fromAccountId", message: "From Account ID is required" },
      { key: "toAccountId", message: "To Account ID is required" },
      {
        key: "amount",
        message: "Valid amount is required",
        validator: (v) => typeof v === "number" && v > 0,
      },
      { key: "narration", message: "Narration is required" },
      { key: "idempotencyKey", message: "Idempotency key is required" },
    ]);

    const uid = data.auth?.uid;
    if (!uid) throw new HttpsError("unauthenticated", "User is not authenticated");

    const fromAccountId = data.data.fromAccountId.trim();
    const toAccountId = data.data.toAccountId.trim();
    const amount = data.data.amount; // kobo
    const narration = data.data.narration.trim();
    const idempotencyKey = data.data.idempotencyKey.trim();

    const fromSnap = await db
      .collection("safehavenUserSetup")
      .where("safehavenAccountId", "==", fromAccountId)
      .limit(1)
      .get();
    const toSnap = await db
      .collection("safehavenUserSetup")
      .where("safehavenAccountId", "==", toAccountId)
      .limit(1)
      .get();

    const fromAcct = fromSnap.empty ? null : fromSnap.docs[0].data();
    const toAcct = toSnap.empty ? null : toSnap.docs[0].data();

    const fromAccountNumber = fromAcct?.safehavenAccountNumber || fromAccountId;
    const toAccountNumber = toAcct?.safehavenAccountNumber || toAccountId;
    const bankCode = fromAcct?.safehavenBankCode || "090286";
    const fromUid = fromSnap.empty ? uid : fromSnap.docs[0].id;

    const enquiry = await _safehavenNameEnquiry(fromUid, bankCode, toAccountNumber);
    const nameEnquiryReference = enquiry.nameEnquiryReference;
    if (!nameEnquiryReference) {
      throw new HttpsError("failed-precondition", "Name enquiry failed for destination account");
    }

    const resp = await safehavenRequest({
      path: "/transfers",
      method: "POST",
      body: {
        nameEnquiryReference,
        debitAccountNumber: fromAccountNumber,
        beneficiaryBankCode: bankCode,
        beneficiaryAccountNumber: toAccountNumber,
        narration,
        amount: amount / 100,
        saveBeneficiary: false,
        paymentReference: idempotencyKey,
      },
    });
    const tx = resp.data || {};

    return {
      data: {
        id: tx._id || tx.id || idempotencyKey,
        type: "BookTransfer",
        attributes: {
          amount,
          currency: "NGN",
          status: tx.status || "PENDING",
          narration,
          reference: tx.paymentReference || idempotencyKey,
        },
      },
    };
  },
);

// Verify Transfer
exports.sudoVerifyTransfer = onCall(
  { secrets: [getanchorSecretKey] },
  async (data, context) => {
    await ensureVerifiedOrStandUser(data.auth);
    const secretKey = getanchorSecretKey.value();
    if (secretKey.length === 0) {
      throw new HttpsError(
        "invalid-argument",
        "Getanchor Secret Key is not set",
      );
    }

    validateData(data.data, [
      { key: "transferId", message: "Transfer ID is required" },
    ]);

    const transferId = data.data.transferId.trim();
    
    const url = `${BASE_URL}/transfers/verify/${encodeURIComponent(
      transferId,
    )}`;

    return makeApiRequest({ url, method: "GET", secretKey });
  },
);

// Verify Transfer by Reference (idempotency key used as reference in book transfer)
exports.safehavenVerifyTransferByReference = onCallLogged(
  "safehavenVerifyTransferByReference",
  { secrets: [safehavenClientId, safehavenPrivateKey, safehavenCompanyUrl] },
  async (data, context) => {
    await ensureVerifiedOrStandUser(data.auth);
    validateData(data.data, [
      { key: "reference", message: "Transfer reference is required" },
    ]);

    const reference = data.data.reference.trim();

    const resp = await safehavenRequest({
      path: `/transfers?page=0&limit=50&paymentReference=${encodeURIComponent(reference)}`,
      method: "GET",
    });

    const transfers = Array.isArray(resp.data) ? resp.data : [];
    const matched =
      transfers.find((item) => item.paymentReference === reference) ||
      transfers.find((item) => item.reference === reference) ||
      null;

    if (!matched) {
      throw new HttpsError("not-found", "Transfer not found");
    }

    return {
      data: {
        id: matched._id || matched.id || reference,
        type: "Transfer",
        attributes: {
          amount: Math.round((matched.amount || 0) * 100),
          status: matched.status || "PENDING",
          reference: matched.paymentReference || reference,
          narration: matched.narration || "",
          createdAt: matched.createdAt || null,
        },
        _safehaven: matched,
      },
    };
  },
);

// Get All Banks
// Get All Banks (Safehaven ï¿½ transforms to Anchor-compatible bank list shape)
exports.safehavenBankList = onCallLogged(
  "safehavenBankList",
  { secrets: [safehavenClientId, safehavenPrivateKey, safehavenCompanyUrl] },
  async (data, context) => {
    await ensureVerifiedOrStandUser(data.auth);

    const resp = await safehavenRequest({
      path: "/transfers/banks?showLogos=true",
      method: "GET",
    });

    const banks = Array.isArray(resp.data) ? resp.data : [];

    // Transform to Anchor shape: [{id, attributes:{name}}]
    return {
      data: banks.map((b) => ({
        id: b.bankCode || b._id || b.id,
        type: "Bank",
        attributes: { name: b.name || b.bankName || "" },
        _safehaven: { bankCode: b.bankCode, routingKey: b.routingKey },
      })),
    };
  },
);

// Verify Account Number (Safehaven name-enquiry ï¿½ Anchor-compatible response)
exports.safehavenNameEnquiry = onCallLogged(
  "safehavenNameEnquiry",
  { secrets: [safehavenClientId, safehavenPrivateKey, safehavenCompanyUrl] },
  async (data, context) => {
    await ensureVerifiedOrStandUser(data.auth);

    validateData(data.data, [
      { key: "accountNumber", message: "Account number is required" },
    ]);

    const uid = data.auth?.uid;
    const accountNumber = data.data.accountNumber.trim();
    const bankCodeRaw = data.data.bankIdOrBankCode ?? data.data.bankCode;
    const bankCode = String(bankCodeRaw || "").trim();
    if (!bankCode) {
      throw new HttpsError("invalid-argument", "Bank ID or bank code is required");
    }

    const enquiry = await _safehavenNameEnquiry(uid, bankCode, accountNumber);

    // Return Anchor-compatible shape Flutter reads: data.attributes.accountName
    return {
      data: {
        type: "AccountVerification",
        attributes: {
          accountName: enquiry.accountName || "",
          accountNumber,
          bankCode,
        },
        _safehaven: {
          nameEnquiryReference: enquiry.nameEnquiryReference || "",
          sessionId: enquiry.sessionId || "",
        },
      },
    };
  },
);

// List Billers

// List Biller Products
exports.safehavenListBillerProducts = onCall(
  { secrets: [safehavenClientId, safehavenPrivateKey, safehavenCompanyUrl] },
  async (data, context) => {
    await ensureVerifiedOrStandUser(data.auth);
    validateData(data.data, [
      { key: "billerId", message: "Biller ID is required" },
    ]);

    const serviceCategoryId = data.data.billerId.trim();

    const resp = await safehavenRequest({
      path: `/vas/service-category/${encodeURIComponent(serviceCategoryId)}/products`,
      method: "GET",
    });

    const products = Array.isArray(resp.data) ? resp.data : [];
    return {
      data: products.map((p) => {
        const amountKobo = p.amount == null ? 0 : Math.round(Number(p.amount) * 100);
        return {
          id: p.bundleCode || p.slug || p.name,
          type: "BillerProduct",
          attributes: {
            name: p.name || "",
            slug: p.bundleCode || p.slug || p.name,
            code: p.bundleCode || p.slug || p.name,
            price: {
              minimumAmount: amountKobo,
              maximumAmount: p.isAmountFixed ? amountKobo : null,
            },
            isAmountFixed: Boolean(p.isAmountFixed),
            duration: p.duration || null,
          },
          _safehaven: p,
        };
      }),
    };
  },
);

exports.safehavenFetchDepositAccount = onCall(
  { secrets: [safehavenClientId, safehavenPrivateKey, safehavenCompanyUrl] },
  async (data, context) => {
    await ensureVerifiedOrStandUser(data.auth);

    const { accountId } = data.data;
    if (!accountId) {
      throw new HttpsError("invalid-argument", "Account ID is required");
    }

    const resp = await safehavenRequest({
      path: `/accounts/${encodeURIComponent(accountId.trim())}`,
      method: "GET",
    });
    const acct = resp.data || {};

    return {
      data: {
        id: acct._id || acct.id || accountId,
        type: "DepositAccount",
        attributes: {
          accountNumber: acct.accountNumber || "",
          currency: acct.currency || "NGN",
          availableBalance: Math.round((acct.accountBalance ?? 0) * 100),
          bank: {
            id: acct.bankCode || "090286",
            name: acct.bankName || "Safe Haven MFB",
          },
          status: acct.status || "ACTIVE",
        },
      },
    };
  },
);

// List Transactions
exports.safehavenGetTransfers = onCallLogged(
  "safehavenGetTransfers",
  { secrets: [safehavenClientId, safehavenPrivateKey, safehavenCompanyUrl] },
  async (data, context) => {
    await ensureVerifiedOrStandUser(data.auth);
    const uid = data.auth?.uid;
    if (!uid) throw new HttpsError("unauthenticated", "User is not authenticated");

    const acct = await _getSafehavenAccountForUser(uid);
    const accountId =
      data.data?.accountId?.trim() ||
      acct.accountId ||
      data.data?.customerId?.trim() ||
      "";

    const params = new URLSearchParams({
      page: "0",
      limit: "100",
    });
    if (accountId) params.append("accountId", accountId);
    if (data.data?.from) params.append("fromDate", data.data.from);
    if (data.data?.to) params.append("toDate", data.data.to);

    const resp = await safehavenRequest({
      path: `/transfers?${params.toString()}`,
      method: "GET",
    });

    const transfers = Array.isArray(resp.data) ? resp.data : [];

    return {
      data: transfers.map((tx) => ({
        id: tx._id || tx.id || tx.paymentReference || "",
        type: "Transaction",
        attributes: {
          amount: Math.round((tx.amount || 0) * 100),
          status: tx.status || "PENDING",
          direction: (tx.type || "").toLowerCase() === "inwards" ? "credit" : "debit",
          narration: tx.narration || "",
          reference: tx.paymentReference || "",
          provider: tx.provider || "BANK",
          createdAt: tx.createdAt || null,
        },
        _safehaven: tx,
      })),
      pagination: resp.pagination || null,
    };
  },
);

const _pickAnchorSignatureHeader = (headers = {}) => {
  const candidates = [
    "x-anchor-signature",
    "x-webhook-signature",
    "anchor-signature",
    "x-signature",
  ];

  for (const key of candidates) {
    const value = headers[key];
    if (value) return { key, value };
  }
  return { key: null, value: null };
};

const _safeTimingEqual = (left, right) => {
  if (!Buffer.isBuffer(left) || !Buffer.isBuffer(right)) return false;
  if (left.length !== right.length) return false;
  return crypto.timingSafeEqual(left, right);
};

const _safeTimingEqualString = (left, right) => {
  const leftBuf = Buffer.from(String(left));
  const rightBuf = Buffer.from(String(right));
  return _safeTimingEqual(leftBuf, rightBuf);
};

const _normalizeBase64 = (value) => {
  const base = value.replace(/-/g, "+").replace(/_/g, "/");
  const pad = base.length % 4;
  if (pad === 2) return `${base}==`;
  if (pad === 3) return `${base}=`;
  if (pad === 1) return null;
  return base;
};

// Webhook verification helper
const verifySignature = (rawBody, signature, secret) => {
  if (!signature || !rawBody || !secret) {
    return { valid: false, mode: "missing-input" };
  }

  const rawSignature = Array.isArray(signature)
    ? String(signature[0])
    : String(signature);

  // Handle values like "sha1=..." or composite headers like "t=...,sha1=..."
  const sha1Tagged = rawSignature.match(/sha1\s*=\s*([A-Za-z0-9+/_=-]+)/i);
  const signatureValue = (sha1Tagged ? sha1Tagged[1] : rawSignature).trim();
  const normalized = signatureValue.replace(/^sha1=/i, "");

  // Anchor docs: Base64(HMAC_SHA1(payload, secret).hexdigest())
  const expectedHex = crypto.createHmac("sha1", secret).update(rawBody).digest("hex");
  const expectedDocSignature = Buffer.from(expectedHex, "utf8").toString("base64");

  if (_safeTimingEqualString(normalized, expectedDocSignature)) {
    return { valid: true, mode: "anchor-doc-base64-hex" };
  }

  const expectedDigest = Buffer.from(expectedHex, "hex");

  // Hex form
  if (/^[a-fA-F0-9]{40}$/.test(normalized)) {
    const providedHexDigest = Buffer.from(normalized.toLowerCase(), "hex");
    if (_safeTimingEqual(providedHexDigest, expectedDigest)) {
      return { valid: true, mode: "hex" };
    }
  }

  // Base64 or base64url form
  const b64 = _normalizeBase64(normalized);
  if (b64) {
    try {
      const providedB64Digest = Buffer.from(b64, "base64");
      if (_safeTimingEqual(providedB64Digest, expectedDigest)) {
        return { valid: true, mode: "base64-raw-digest" };
      }
    } catch (err) {
      // Ignore parsing errors and fail closed.
    }
  }

  return { valid: false, mode: "no-match" };
};

// SafeHaven webhook signature verifier (supports sha256 and sha1 variants)
const verifySafehavenSignature = (rawBody, signature, secret) => {
  if (!signature || !rawBody || !secret) {
    return { valid: false, mode: "missing-input" };
  }

  const rawSignature = Array.isArray(signature) ? String(signature[0]) : String(signature);

  // Try to detect tagged format like "sha256=..." or "sha1=..."
  const tagMatch = rawSignature.match(/(sha1|sha256)\s*=\s*([A-Za-z0-9+/_=-]+)/i);
  let algo = null;
  let signatureValue = rawSignature;
  if (tagMatch) {
    algo = tagMatch[1].toLowerCase();
    signatureValue = tagMatch[2];
  } else {
    signatureValue = rawSignature.trim();
    if (/^[a-fA-F0-9]{64}$/.test(signatureValue)) algo = "sha256";
    else if (/^[a-fA-F0-9]{40}$/.test(signatureValue)) algo = "sha1";
    else algo = "sha256"; // default to sha256 when ambiguous
  }

  // Compute expected HMAC digest (hex)
  const expectedHex = crypto.createHmac(algo, secret).update(rawBody).digest("hex");
  const expectedDigest = Buffer.from(expectedHex, "hex");

  // If provided signature is hex
  if (/^[a-fA-F0-9]+$/.test(signatureValue)) {
    const providedHex = signatureValue.toLowerCase();
    if (_safeTimingEqualString(providedHex, expectedHex)) {
      return { valid: true, mode: `${algo}-hex` };
    }
  }

  // Try base64 / base64url forms
  const b64 = _normalizeBase64(signatureValue);
  if (b64) {
    try {
      const providedBuf = Buffer.from(b64, "base64");
      if (_safeTimingEqual(providedBuf, expectedDigest)) {
        return { valid: true, mode: `${algo}-base64` };
      }
    } catch (e) {
      // ignore
    }
  }

  return { valid: false, mode: "no-match" };
};

// SafeHaven webhook endpoint - logs incoming events (no signature verification)
safehavenApp.post("/", async (req, res) => {
  try {
    const rawBody = req.rawBody || Buffer.from(JSON.stringify(req.body || {}));
    const headers = req.headers || {};
    const rawBodyString = rawBody ? rawBody.toString("utf8") : "";
    let parsed = null;
    try { parsed = rawBodyString ? JSON.parse(rawBodyString) : req.body; } catch (e) { parsed = req.body || null; }

    console.log("[SafeHaven webhook] received", {
      bodyPreview: rawBodyString.length > 1000 ? `${rawBodyString.slice(0, 1000)}...[truncated]` : rawBodyString,
    });

    // Persist webhook to Firestore for later inspection
    await db.collection("safehavenWebhooks").add({
      receivedAt: admin.firestore.FieldValue.serverTimestamp(),
      headers,
      rawBody: rawBodyString,
      body: parsed,
      signatureHeader: null,
      signatureVerified: null,
      verificationMode: "disabled",
    });

    // Post-process some SafeHaven webhook events (non-blocking best-effort)
    (async () => {
      try {
        const evtType = parsed && (parsed.type || parsed.eventType)
          ? (parsed.type || parsed.eventType)
          : null;

        // identityCreditCheck is emitted when SafeHaven performs the small debit
        // used to verify identity during BVN flows. We notify the user by device
        // token and email when this occurs so the client can react.
        if (evtType && evtType.toString().toLowerCase() === "identitycreditcheck") {
          const payload = parsed.data || parsed;
          const accountNumber = String(
            payload.debitAccountNumber || payload.accountNumber || payload.debitAccount || "",
          ).trim();
          const status = String(payload.status || "").trim().toUpperCase();
          const debitMsg = String(payload.debitMessage || payload.message || payload.reason || "").trim();

          // Tie the event to the user who initiated identity verification.
          // safehavenUserSetup is keyed by Firebase UID and stores identityId
          // from safehavenInitiateIdentityVerification â€” this is the authoritative link.
          const identityCheckId = String(payload._id || payload.id || "").trim();
          let resolvedUid = null;

          if (identityCheckId) {
            try {
              const setupQuery = await db
                .collection("safehavenUserSetup")
                .where("identityId", "==", identityCheckId)
                .limit(1)
                .get();
              if (!setupQuery.empty) {
                resolvedUid = setupQuery.docs[0].id; // doc ID is the Firebase UID
                // Persist status so safehavenCreateSubAccount can skip a FAILED identityId
                await setupQuery.docs[0].ref.set({
                  identityCheckStatus: status,
                  identityCheckMessage: debitMsg || null,
                  identityCheckUpdatedAt: admin.firestore.FieldValue.serverTimestamp(),
                }, { merge: true });
                console.log(`[SafeHaven webhook] identityCreditCheck status ${status} stored for uid ${resolvedUid}, identityId ${identityCheckId}`);
              } else {
                console.log(`[SafeHaven webhook] no safehavenUserSetup found for identityId ${identityCheckId}`);
              }
            } catch (setupErr) {
              console.warn("[SafeHaven webhook] failed to update identityCheckStatus:", setupErr.message);
            }
          }

          if (resolvedUid) {
            try {
              const userSnap = await db.collection("users").doc(resolvedUid).get();
              const userData = userSnap.exists ? userSnap.data() : {};
              const deviceToken = userData.deviceToken || null;
              const userEmail = userData.email || null;

              const title = status === "FAILED" ? "Identity Verification Debit Failed" : "Identity Verification Debit";
              const bodyMsg = status === "FAILED"
                ? `Identity verification debit failed: ${debitMsg} (code: ${payload.debitResponsCode || ""})`
                : `Identity verification debit ${status.toLowerCase()}.`;

              // Send push notification (best-effort)
              if (deviceToken) {
                try {
                  // await admin.messaging().send({
                  //   token: deviceToken,
                  //   notification: { title, body: bodyMsg },
                  //   ...FCM_CHANNEL,
                  // });
                  // console.log(`SafeHaven webhook: pushed notification to ${resolvedUid}`);
                } catch (msgErr) {
                  console.error("SafeHaven webhook push error:", msgErr);
                }
              }

              // Persist notification to user's notification feed
              try {
                await saveNotification(resolvedUid, {
                  title,
                  body: bodyMsg,
                  type: "identity_credit_check",
                  amount: payload.amount || null,
                });
              } catch (saveErr) {
                console.error("SafeHaven webhook saveNotification error:", saveErr);
              }

              // Send email notification (best-effort)
              if (userEmail) {
                try {
                  await sendNotifyEmail({
                    to: userEmail,
                    subject: title,
                    text: bodyMsg,
                    html: `<p>${bodyMsg}</p>`,
                  });
                  console.log(`SafeHaven webhook: emailed ${userEmail}`);
                } catch (emailErr) {
                  console.error("SafeHaven webhook email error:", emailErr);
                }
              }
            } catch (notifyErr) {
              console.error("[SafeHaven webhook] user notification error:", notifyErr);
            }
          } else {
            console.log(`[SafeHaven webhook] identityCreditCheck: could not resolve user for identityId ${identityCheckId}`);
          }
        }
      } catch (postErr) {
        console.error("SafeHaven webhook post-processing error:", postErr);
      }
    })();

    return res.status(200).send("OK");
  } catch (err) {
    console.error("[SafeHaven webhook] processing error:", err);
    return res.status(400).json({ error: "Invalid payload" });
  }
});

// Anchor webhook (existing root handler)
app.post("/", async (req, res) => {
  try {
    const candidateSecrets = [
      String(anchorWebhookSecret.value() || "").trim(),
      String(anchorWebhookSecretSecondary.value() || "").trim(),
    ].filter(Boolean);

    if (candidateSecrets.length === 0) {
      console.error("ANCHOR_WEBHOOK_SECRET is not set");
      return res.status(500).json({ error: "Server configuration error" });
    }
    const { key: signatureHeaderKey, value: signature } = _pickAnchorSignatureHeader(
      req.headers,
    );
    const rawBody = req.rawBody || Buffer.from(JSON.stringify(req.body || {}));

    // SECURITY: Always verify HMAC-SHA1 signature before processing any payload.
    // verifySignature uses crypto.timingSafeEqual to prevent timing attacks.
    // Reject early ? no Firestore reads or side-effects before this check.
    let signatureResult = { valid: false, mode: "no-match" };
    let matchedSecretIndex = -1;
    for (let i = 0; i < candidateSecrets.length; i++) {
      const result = verifySignature(rawBody, signature, candidateSecrets[i]);
      if (result.valid) {
        signatureResult = result;
        matchedSecretIndex = i;
        break;
      }
    }

    if (!signatureResult.valid) {
      const signatureHeaderNames = Object.keys(req.headers || {}).filter((k) =>
        k.toLowerCase().includes("signature"),
      );
      const sanitizedHeaders = Object.fromEntries(
        Object.entries(req.headers || {}).map(([key, value]) => [
          key,
          /(authorization|cookie|token|secret|key)/i.test(key)
            ? "[redacted]"
            : value,
        ]),
      );

      const rawBodyString = rawBody ? rawBody.toString("utf8") : "";
      const payloadHash = rawBody
        ? crypto.createHash("sha1").update(rawBody).digest("hex")
        : null;
      const signatureShape = signature
        ? {
            header: signatureHeaderKey,
            length: String(Array.isArray(signature) ? signature[0] : signature)
              .trim()
              .length,
            hasSha1Prefix: /^sha1=/i.test(
              String(Array.isArray(signature) ? signature[0] : signature).trim(),
            ),
          }
        : null;

      console.error("Anchor webhook: invalid or missing signature", {
        contentType: req.headers["content-type"] || null,
        rawBodyLength: rawBody ? rawBody.length : 0,
        rawBodySha1: payloadHash,
        rawBodyPreview:
          rawBodyString.length > 1200
            ? `${rawBodyString.slice(0, 1200)}...[truncated]`
            : rawBodyString,
        verificationModeTried: signatureResult.mode,
        signatureHeadersPresent: signatureHeaderNames,
        signatureShape,
        allHeaders: sanitizedHeaders,
        secretConfigured: candidateSecrets.length > 0,
        configuredSecretCount: candidateSecrets.length,
      });
      return res.status(401).json({ error: "Invalid signature" });
    }

    console.log("Anchor webhook: signature verified", {
      header: signatureHeaderKey,
      mode: signatureResult.mode,
      matchedSecretIndex,
      rawBodyLength: rawBody.length,
    });

    const event = JSON.parse(rawBody.toString());
    console.log("Received webhook event:", JSON.stringify(event, null, 2));
    const eventId = event.id;
    const eventType = event.type;
    const createdAt = event.attributes?.createdAt;
    // Check for duplicate event
    const eventRef = admin
      .firestore()
      .collection("getanchorEvents")
      .doc(eventId);
    const eventDoc = await eventRef.get();

    const allowDuplicates = [
      "document.reenter_information",
      "customer.identification.reenter_information",
      "customer.identification.approved",
      "document.rejected",
      "document.approved",
      "customer.identification.rejected",
    ].includes(eventType);

    if (eventDoc.exists && !allowDuplicates) {
      console.log(`Duplicate event detected: ${eventId}, skipping processing`);
      return res.status(200).send("OK"); // Acknowledge but skip processing
    }

    // Save event to Firestore
    await eventRef.set({
      eventId,
      eventType,
      eventData: event,
      processedAt: admin.firestore.FieldValue.serverTimestamp(),
      createdAt,
    });
    // Act based on event type
    switch (eventType) {
      case "customer.created":
        console.log("Customer created event");
        // Extract customerId from relationships or data
        // await updateUserFirestore(customerId, event);
        break;
      case "account.created":
        console.log("Account created event");
        // Save account details to user
        console.log("Account Created");
        break;
      case "virtualNuban.created":
        console.log("Virtual Nuban created event");
        // Update virtualAccount in user doc
        break;

      case "customer.identification.error": {
        console.log("Customer identification error");
        const customerId = event.relationships.customer.data.id;
        const errorReason = event.attributes.reason || "Unknown error";

        // Find entity (user or business) by customerId
        let entitySnapshot;
        let isUser = true;
        let attempts = 0;
        const maxAttempts = 5;
        let querySuccess = false;

        // First, try users collection
        do {
          try {
            const userQuery = admin
              .firestore()
              .collection("users")
              .where(
                "getAnchorData.customerCreation.data.id",
                "==",
                customerId,
              );
            entitySnapshot = await userQuery.get();
            if (!entitySnapshot.empty) {
              querySuccess = true;
              break;
            }
          } catch (queryError) {
            console.error(
              `Firestore query error for customer ID ${customerId} in users (attempt ${
                attempts + 1
              }):`,
              queryError,
            );
            if (
              queryError.code === "failed-precondition" ||
              queryError.message.includes("index")
            ) {
              console.error(
                "Likely missing composite index on getAnchorData.customerCreation.data.id - check Firebase console",
              );
            }
          }
          attempts++;
          console.log(
            `Attempt ${attempts}: No user found for customer ID: ${customerId}, retrying in 500ms...`,
          );
          if (attempts < maxAttempts) {
            await new Promise((resolve) => setTimeout(resolve, 500));
          }
        } while (attempts < maxAttempts);

        if (!querySuccess || entitySnapshot.empty) {
          // If not found in users, try businesses collection
          isUser = false;
          attempts = 0;
          querySuccess = false;
          do {
            try {
              const businessQuery = admin
                .firestore()
                .collection("businesses")
                .where("kybCreation.data.id", "==", customerId);
              entitySnapshot = await businessQuery.get();
              if (!entitySnapshot.empty) {
                querySuccess = true;
                break;
              }
            } catch (queryError) {
              console.error(
                `Firestore query error for customer ID ${customerId} in businesses (attempt ${
                  attempts + 1
                }):`,
                queryError,
              );
              if (
                queryError.code === "failed-precondition" ||
                queryError.message.includes("index")
              ) {
                console.error(
                  "Likely missing composite index on kybCreation.data.id - check Firebase console",
                );
              }
            }
            attempts++;
            console.log(
              `Attempt ${attempts}: No business found for customer ID: ${customerId}, retrying in 500ms...`,
            );
            if (attempts < maxAttempts) {
              await new Promise((resolve) => setTimeout(resolve, 500));
            }
          } while (attempts < maxAttempts);
        }

        if (querySuccess && !entitySnapshot.empty) {
          const entityDoc = entitySnapshot.docs[0];
          const entityId = entityDoc.id; // This is userId for both cases

          // Get deviceToken from users collection
          const userRef = admin.firestore().collection("users").doc(entityId);
          const userDoc = await userRef.get();
          let deviceToken = null;
          if (userDoc.exists) {
            deviceToken = userDoc.data().deviceToken;
          }

          // Update verification status in appropriate collection
          const collectionName = isUser ? "users" : "businesses";
          await admin
            .firestore()
            .collection(collectionName)
            .doc(entityId)
            .update({
              kycStatus: "FAILED",
              kycErrorReason: errorReason,
            });

          // Send notification
          if (deviceToken) {
            const message = {
              token: deviceToken,
              notification: {
                title: "KYC Verification Failed",
                body: `Identity verification failed: ${errorReason}. Please try again.`,
              },
              ...FCM_CHANNEL,
            };
            await admin.messaging().send(message);
            console.log(`Sent KYC error notification to user ${entityId}`);
          }
        } else {
          console.log(
            `Failed to find entity after ${maxAttempts} attempts for customer ID: ${customerId}`,
          );
        }
        break;
      }

      case "customer.identification.awaitingDocument": {
        console.log("Customer identification awaiting document");

        const customerId = event.relationships.customer.data.id;
        const requiredDocuments = event.attributes.requiredDocuments || [];

        const documentIds = (event.relationships?.documents?.data || []).map(
          (d) => d.id,
        );

        if (requiredDocuments.length !== documentIds.length) {
          console.warn(
            `Document count mismatch - required: ${requiredDocuments.length}, IDs: ${documentIds.length}`,
          );
        }

        const requiredTypes = requiredDocuments.map((doc, index) => ({
          type: doc.type,
          description: doc.description || "",
          anchorId: documentIds[index] || null,
          status: "pending",
          // ? requestedAt completely removed ? it was causing array to turn into map
        }));

        const typeNames = requiredDocuments.map((d) =>
          d.type
            .replace(/_/g, " ")
            .toLowerCase()
            .replace(/\b\w/g, (l) => l.toUpperCase()),
        );
        const listText =
          typeNames.length === 1
            ? typeNames[0]
            : typeNames.length === 2
              ? `${typeNames[0]} and ${typeNames[1]}`
              : `${typeNames.slice(0, 2).join(", ")} + ${
                  typeNames.length - 2
                } more`;

        // Find entity ? 15 retries
        let entitySnapshot = null;
        let isUser = true;
        let entityId = null;

        for (let i = 0; i < 15; i++) {
          try {
            const snap = await admin
              .firestore()
              .collection("users")
              .where("getAnchorData.customerCreation.data.id", "==", customerId)
              .limit(1)
              .get();

            if (!snap.empty) {
              entitySnapshot = snap;
              entityId = snap.docs[0].id;
              break;
            }
          } catch (err) {
            console.error("Users query error:", err);
          }
          if (i < 14) await new Promise((r) => setTimeout(r, 1000));
        }

        if (!entitySnapshot) {
          isUser = false;
          for (let i = 0; i < 15; i++) {
            try {
              const snap = await admin
                .firestore()
                .collection("businesses")
                .where("kybCreation.data.id", "==", customerId)
                .limit(1)
                .get();

              if (!snap.empty) {
                entitySnapshot = snap;
                entityId = snap.docs[0].id;
                break;
              }
            } catch (err) {
              console.error("Businesses query error:", err);
            }
            if (i < 14) await new Promise((r) => setTimeout(r, 1000));
          }
        }

        if (!entitySnapshot || entitySnapshot.empty) {
          console.error(`Entity NOT FOUND for customerId: ${customerId}`);
          break;
        }

        const collectionName = isUser ? "users" : "businesses";
        const entityRef = admin
          .firestore()
          .collection(collectionName)
          .doc(entityId);

        let deviceToken = null;
        if (isUser) {
          const doc = await entityRef.get();
          deviceToken = doc.data()?.deviceToken;
        } else {
          const userDoc = await admin
            .firestore()
            .collection("users")
            .doc(entityId)
            .get();
          if (userDoc.exists) deviceToken = userDoc.data()?.deviceToken;
        }

        // ONLY ONE WRITE ? no requestedAt ? array stays array forever
        await entityRef.set(
          {
            kycStatus: "AWAITING_DOCUMENT",

            requiredDocuments: requiredTypes,
          },
          { merge: true },
        );

        if (deviceToken) {
          try {
            await admin.messaging().send({
              token: deviceToken,
              notification: {
                title: "Additional Documents Required",
                body: `Please upload: ${listText}`,
              },
              data: { type: "kyc_awaiting_document" },
              ...FCM_CHANNEL,
            });
          } catch (err) {
            console.error("FCM error:", err);
          }
        }

        console.log(`awaitingDocument handled ? ${collectionName}/${entityId}`);
        break;
      }
      // ================================================================
      // DOCUMENT APPROVED ? update only that specific document status
      // ================================================================
      case "document.approved": {
        const customerId = event.relationships.customer.data.id;
        const approvedDocId = event.relationships.documents.data[0].id;

        const entityRef = await findEntityRef(customerId);
        if (!entityRef) break;
        let allApproved = true;
        await admin.firestore().runTransaction(async (transaction) => {
          const snap = await transaction.get(entityRef);
          const data = snap.data();

          if (!data || !Array.isArray(data.requiredDocuments)) return;

          const newDocs = data.requiredDocuments.map((doc) => {
            if (doc.anchorId === approvedDocId) {
              return {
                ...doc,
                status: "approved",
              };
            }
            if (doc.status !== "approved") allApproved = false;
            return doc;
          });

          const updates = {
            requiredDocuments: newDocs,
          };

          // If all documents are now approved ? final status = APPROVED
          if (allApproved) {
            updates.kycStatus = "APPROVED";
          }

          transaction.update(entityRef, updates);
        });

        // Send notification (outside transaction since it may fail independently)
        const snap = await entityRef.get();
        const data = snap.data();
        const token = await getDeviceToken(entityRef, data);
        if (token) {
          await admin.messaging().send({
            token,
            notification: {
              title: "Document Approved ?",
              body: allApproved
                ? "All your documents are approved! Your business is now fully verified."
                : "One of your documents has been approved.",
            },
            data: { type: "kyc_document_update" },
            ...FCM_CHANNEL,
          });
        }

        console.log(
          `Document approved${
            allApproved ? " ? KYB FULLY APPROVED" : ""
          } for ${customerId}`,
        );
        break;
      }

      // ================================================================
      // DOCUMENT REJECTED
      // ================================================================
      case "document.rejected": {
        const customerId = event.relationships.customer.data.id;
        const rejectedDocId = event.relationships.documents.data[0].id;
        const reason =
          event.attributes.reason || "Document did not meet requirements";

        const entityRef = await findEntityRef(customerId);
        if (!entityRef) break;

        await admin.firestore().runTransaction(async (transaction) => {
          const snap = await transaction.get(entityRef);
          const data = snap.data();

          if (!data || !Array.isArray(data.requiredDocuments)) return;

          const newDocs = data.requiredDocuments.map((doc) => {
            if (doc.anchorId === rejectedDocId) {
              return {
                ...doc,
                status: "rejected",
                rejectedReason: reason,
              };
            }
            return doc;
          });

          const updates = {
            requiredDocuments: newDocs,
            kycStatus: "AWAITING_DOCUMENT", // go back to awaiting
          };

          transaction.update(entityRef, updates);
        });

        // Send notification
        const snap = await entityRef.get();
        const data = snap.data();
        const token = await getDeviceToken(entityRef, data);
        if (token) {
          await admin.messaging().send({
            token,
            notification: {
              title: "Document Rejected",
              body: `${reason}. Please upload a clearer copy.`,
            },
            data: { type: "kyc_awaiting_document" },
            ...FCM_CHANNEL,
          });
        }

        console.log(`Document rejected for ${customerId}`);
        break;
      }

      // ================================================================
      // DOCUMENT MANUAL REVIEW
      // ================================================================
      case "document.manualReview": {
        const customerId = event.relationships.customer.data.id;
        const docId = event.relationships.documents.data[0].id;

        const entityRef = await findEntityRef(customerId);
        if (!entityRef) break;

        await admin.firestore().runTransaction(async (transaction) => {
          const snap = await transaction.get(entityRef);
          const data = snap.data();

          if (!data || !Array.isArray(data.requiredDocuments)) return;

          const newDocs = data.requiredDocuments.map((doc) => {
            if (doc.anchorId === docId) {
              return {
                ...doc,
                status: "manual_review",
              };
            }
            return doc;
          });

          const updates = {
            requiredDocuments: newDocs,
            kycStatus: "MANUAL_REVIEW",
          };

          transaction.update(entityRef, updates);
        });

        // Send notification
        const snap = await entityRef.get();
        const data = snap.data();
        const token = await getDeviceToken(entityRef, data);
        if (token) {
          await admin.messaging().send({
            token,
            notification: {
              title: "Document Under Review",
              body: "We are reviewing your document. We'll notify you soon.",
            },
            ...FCM_CHANNEL,
          });
        }
        break;
      }

      // ================================================================
      // REENTER INFORMATION (for individual docs or whole KYB)
      // ================================================================
      case "document.reenter_information":
      case "customer.identification.reenter_information": {
        const customerId = event.relationships.customer.data.id;
        const reason =
          event.attributes.reason || "Please update the information";

        const entityRef = await findEntityRef(customerId);
        if (!entityRef) break;

        await entityRef.update({
          kycStatus: "REENTER_INFORMATION",
          kycReason: reason,
        });

        const token = await getDeviceToken(customerId);
        if (token) {
          await admin.messaging().send({
            token,
            notification: {
              title: "Update Required",
              body: reason,
            },
            data: { type: "kyc_awaiting_document" },
            ...FCM_CHANNEL,
          });
        }
        break;
      }

      // ================================================================
      // FINAL APPROVED (when all docs pass
      // ================================================================
      case "customer.identification.approved": {
        const customerId = event.relationships.customer.data.id;

        const entityRef = await findEntityRef(customerId);
        if (!entityRef) break;

        await entityRef.update({
          kycStatus: "APPROVED",
        });

        const token = await getDeviceToken(customerId);
        if (token) {
          await admin.messaging().send({
            token,
            notification: {
              title: "Account Verified! ??",
              body: "Your account is now fully verified. Enjoy all features!",
            },
            data: { type: "kyc_approved" },
            ...FCM_CHANNEL,
          });
        }
        console.log(`KYC FULLY APPROVED for ${customerId}`);
        break;
      }
      case "customer.identification.rejected": {
        console.log("Customer identification rejected");
        const customerId = event.relationships.customer.data.id;
        const rejectionReason = event.attributes.reason || "Unknown reason";

        // Find entity (user or business) by customerId
        let entitySnapshot;
        let isUser = true;
        let attempts = 0;
        const maxAttempts = 5;
        let querySuccess = false;

        // First, try users collection
        do {
          try {
            const userQuery = admin
              .firestore()
              .collection("users")
              .where(
                "getAnchorData.customerCreation.data.id",
                "==",
                customerId,
              );
            entitySnapshot = await userQuery.get();
            if (!entitySnapshot.empty) {
              querySuccess = true;
              break;
            }
          } catch (queryError) {
            console.error(
              `Firestore query error for customer ID ${customerId} in users (attempt ${
                attempts + 1
              }):`,
              queryError,
            );
            if (
              queryError.code === "failed-precondition" ||
              queryError.message.includes("index")
            ) {
              console.error(
                "Likely missing composite index on getAnchorData.customerCreation.data.id - check Firebase console",
              );
            }
          }
          attempts++;
          console.log(
            `Attempt ${attempts}: No user found for customer ID: ${customerId}, retrying in 500ms...`,
          );
          if (attempts < maxAttempts) {
            await new Promise((resolve) => setTimeout(resolve, 500));
          }
        } while (attempts < maxAttempts);

        if (!querySuccess || entitySnapshot.empty) {
          // If not found in users, try businesses collection
          isUser = false;
          attempts = 0;
          querySuccess = false;
          do {
            try {
              const businessQuery = admin
                .firestore()
                .collection("businesses")
                .where("kybCreation.data.id", "==", customerId);
              entitySnapshot = await businessQuery.get();
              if (!entitySnapshot.empty) {
                querySuccess = true;
                break;
              }
            } catch (queryError) {
              console.error(
                `Firestore query error for customer ID ${customerId} in businesses (attempt ${
                  attempts + 1
                }):`,
                queryError,
              );
              if (
                queryError.code === "failed-precondition" ||
                queryError.message.includes("index")
              ) {
                console.error(
                  "Likely missing composite index on kybCreation.data.id - check Firebase console",
                );
              }
            }
            attempts++;
            console.log(
              `Attempt ${attempts}: No business found for customer ID: ${customerId}, retrying in 500ms...`,
            );
            if (attempts < maxAttempts) {
              await new Promise((resolve) => setTimeout(resolve, 500));
            }
          } while (attempts < maxAttempts);
        }

        if (querySuccess && !entitySnapshot.empty) {
          const entityDoc = entitySnapshot.docs[0];
          const entityId = entityDoc.id; // This is userId for both cases

          // Get deviceToken from users collection
          const userRef = admin.firestore().collection("users").doc(entityId);
          const userDoc = await userRef.get();
          let deviceToken = null;
          if (userDoc.exists) {
            deviceToken = userDoc.data().deviceToken;
          }

          // Update verification status in appropriate collection
          const collectionName = isUser ? "users" : "businesses";
          await admin
            .firestore()
            .collection(collectionName)
            .doc(entityId)
            .update({
              kycStatus: "REJECTED",
              kycRejectionReason: rejectionReason,
            });

          // Send notification
          if (deviceToken) {
            const message = {
              token: deviceToken,
              notification: {
                title: "KYC Verification Rejected",
                body: `Identity verification rejected: ${rejectionReason}. Please contact support.`,
              },
              ...FCM_CHANNEL,
            };
            await admin.messaging().send(message);
            console.log(`Sent KYC rejected notification to user ${entityId}`);
          }
        } else {
          console.log(
            `Failed to find entity after ${maxAttempts} attempts for customer ID: ${customerId}`,
          );
        }
        break;
      }
      case "nip.transfer.failed": {
        console.log("NIP transfer failed");
        const transferIdFailed = event.relationships.transfer.data.id;
        let failedSnapshot;
        let attempts = 0;
        const maxAttempts = 5;
        let queryFailed = false;

        do {
          try {
            const failedQuery = admin
              .firestore()
              .collection("transactions")
              .where("api_response.data.id", "==", transferIdFailed);
            failedSnapshot = await failedQuery.get();
            if (!failedSnapshot.empty) {
              queryFailed = true;
              break;
            }
          } catch (queryError) {
            console.error(
              `Firestore query error for failed transfer ID ${transferIdFailed} (attempt ${
                attempts + 1
              }):`,
              queryError,
            );
            if (
              queryError.code === "failed-precondition" ||
              queryError.message.includes("index")
            ) {
              console.error(
                "Likely missing composite index on api_response.data.id - check Firebase console",
              );
            }
          }
          attempts++;
          console.log(
            `Attempt ${attempts}: No transaction found for transfer ID: ${transferIdFailed}, retrying in 500ms...`,
          );
          if (attempts < maxAttempts) {
            await new Promise((resolve) => setTimeout(resolve, 500));
          }
        } while (attempts < maxAttempts);

        if (queryFailed && !failedSnapshot.empty) {
          try {
            const updatePromises = failedSnapshot.docs.map((doc) =>
              doc.ref.update({
                "api_response.data.attributes.status": "FAILED",
              }),
            );
            await Promise.all(updatePromises);
            console.log(
              `Updated ${failedSnapshot.size} transaction(s) to FAILED for transfer ID: ${transferIdFailed}`,
            );

            // ONLY send notification for user-initiated transfers (not settlement transfers)
            if (failedSnapshot.size > 0) {
              const transactionDoc = failedSnapshot.docs[0];
              const transactionData = transactionDoc.data();
              const transactionType = transactionData.type;

              // Check if this is a settlement transfer (system-initiated)
              const isSettlementTransfer =
                transactionType === "va_settlement" ||
                transactionType === "va_settlement_failed" ||
                transactionData.from === "company_va" ||
                transactionData.to === "merchant_va";

              if (isSettlementTransfer) {
                console.log(
                  `Skipping notification for settlement transfer ${transferIdFailed} - system-initiated`,
                );
                break;
              }

              // Only proceed for user-initiated transfers
              const senderId = transactionData.userId;
              const amount = transactionData.amount;
              const recipientName = transactionData.recipientName;

              // Fetch sender user
              let senderToken = null;
              if (senderId) {
                const senderUserRef = admin
                  .firestore()
                  .collection("users")
                  .doc(senderId);
                const senderUserDoc = await senderUserRef.get();
                if (senderUserDoc.exists) {
                  senderToken = senderUserDoc.data().deviceToken;
                }
              }

              if (senderToken) {
                const senderMessage = {
                  token: senderToken,
                  notification: {
                    title: "Transfer Failed",
                    body: `Your transfer of ${amount} to ${recipientName || "recipient"} failed. Please try again or contact support.`,
                  },
                  ...FCM_CHANNEL,
                };
                try {
                  await admin.messaging().send(senderMessage);
                  console.log(
                    `Sent failure notification to sender ${senderId}`,
                  );
                } catch (msgErr) {
                  console.error(
                    `Error sending failure notification to sender ${senderId}:`,
                    msgErr,
                  );
                }
                await saveNotification(senderId, {
                  title: "Transfer Failed",
                  body: `Your transfer of ${amount} to ${recipientName || "recipient"} failed.`,
                  type: "transfer_failed",
                  amount,
                });
              }
            }
          } catch (updateError) {
            console.error(
              `Firestore update error for failed transfer ID ${transferIdFailed}:`,
              updateError,
            );
          }
        } else if (!queryFailed) {
          console.error(
            `Query failed entirely after ${maxAttempts} attempts for transfer ID: ${transferIdFailed}`,
          );
        } else {
          console.log(
            `Failed to find transaction after ${maxAttempts} attempts for transfer ID: ${transferIdFailed}`,
          );
        }
        break;
      }

      case "nip.transfer.successful": {
        console.log("NIP transfer successful");
        const transferIdSuccess = event.relationships.transfer.data.id;

        // SECURITY: Cross-validate the transfer against Anchor's API before marking
        // it SUCCESSFUL. Without this, an insider with the webhook secret could send
        // a correctly-signed "nip.transfer.successful" payload for a transfer ID that
        // is still pending or failed on Anchor's side, causing the app to incorrectly
        // mark it complete and trigger payout/notification flows.
        try {
          const anchorApiSecretForTransfer = getanchorSecretKey.value();
          const transferVerifyUrl = `${BASE_URL}/transfers/verify/${encodeURIComponent(transferIdSuccess)}`;
          const transferApiResp = await makeApiRequest({
            url: transferVerifyUrl,
            method: "GET",
            secretKey: anchorApiSecretForTransfer,
          });
          const apiTransferStatus =
            transferApiResp?.data?.attributes?.status;
          if (apiTransferStatus !== "SUCCESSFUL") {
            console.error(
              `nip.transfer.successful REJECTED ? Anchor API status is "${apiTransferStatus}" for transferId ${transferIdSuccess} (expected SUCCESSFUL)`,
            );
            break;
          }
          console.log(
            `nip.transfer.successful cross-validation PASSED for transferId ${transferIdSuccess}`,
          );
        } catch (cvErr) {
          console.error(
            `nip.transfer.successful REJECTED ? Anchor API verification failed for transferId ${transferIdSuccess}:`,
            cvErr,
          );
          break;
        }

        let successSnapshot;
        let attempts = 0;
        const maxAttempts = 5;
        let querySuccess = false;

        do {
          try {
            const successQuery = admin
              .firestore()
              .collection("transactions")
              .where("api_response.data.id", "==", transferIdSuccess);
            successSnapshot = await successQuery.get();
            if (!successSnapshot.empty) {
              querySuccess = true;
              break;
            }
          } catch (queryError) {
            console.error(
              `Firestore query error for success transfer ID ${transferIdSuccess} (attempt ${
                attempts + 1
              }):`,
              queryError,
            );
            if (
              queryError.code === "failed-precondition" ||
              queryError.message.includes("index")
            ) {
              console.error(
                "Likely missing composite index on api_response.data.id - check Firebase console",
              );
            }
          }
          attempts++;
          console.log(
            `Attempt ${attempts}: No transaction found for transfer ID: ${transferIdSuccess}, retrying in 500ms...`,
          );
          if (attempts < maxAttempts) {
            await new Promise((resolve) => setTimeout(resolve, 500));
          }
        } while (attempts < maxAttempts);

        if (querySuccess && !successSnapshot.empty) {
          // Declare up-front so it's available outside the try block
          let docsToUpdate = [];
          try {
            docsToUpdate = successSnapshot.docs.filter((doc) => {
              const status = doc.data()?.api_response?.data?.attributes?.status;
              return status !== "SUCCESSFUL";
            });

            if (docsToUpdate.length > 0) {
              // Use batch writes instead of individual updates
              const batch = admin.firestore().batch();
              for (const doc of docsToUpdate) {
                batch.update(doc.ref, {
                  "api_response.data.attributes.status": "SUCCESSFUL",
                });
              }
              await batch.commit();
              console.log(
                `Updated ${docsToUpdate.length} transaction(s) to SUCCESSFUL for transfer ID: ${transferIdSuccess}`,
              );
            } else {
              console.log(
                `No transaction status change needed for transfer ID: ${transferIdSuccess} (already SUCCESSFUL) ? skipping notification`,
              );
            }
          } catch (updateError) {
            console.error(
              `Firestore update error for success transfer ID ${transferIdSuccess}:`,
              updateError,
            );
          }

          // Send notifications (only if we actually updated any docs)
          if (docsToUpdate.length > 0) {
            const transactionDoc = docsToUpdate[0];
            const transactionData = transactionDoc.data();
            const transactionType = transactionData.type;

            // Check if this is a settlement transfer (system-initiated)
            const isSettlementTransfer =
              transactionType === "va_settlement" ||
              transactionType === "va_settlement_failed" ||
              transactionData.from === "company_va" ||
              transactionData.to === "merchant_va";

            if (isSettlementTransfer) {
              console.log(
                `Skipping notification for settlement transfer ${transferIdSuccess} - system-initiated`,
              );
              break;
            }

            // Only proceed for user-initiated transfers
            const senderId = transactionData.userId;
            const amount = transactionData.amount;
            var recipientName = transactionData.recipientName;

            // -- Super Agent Commission ----------------------------------
            // Business-based super-agent model:
            // - Super agent is a business (businesses/{id}.isSuperAgent === true)
            // - Referred business stores superAgentReferralCode
            // - Reward amounts are configurable in settings/superAgentProgram
            try {
              if (senderId) {
                const businessSnap = await admin
                  .firestore()
                  .collection("businesses")
                  .doc(senderId)
                  .get();

                if (businessSnap.exists) {
                  const businessData = businessSnap.data();
                  const saReferralCode = businessData.superAgentReferralCode;

                  if (saReferralCode) {
                    const settings = await getSuperAgentProgramSettings();

                    // New source of truth: businesses collection.
                    const agentBizSnap = await admin
                      .firestore()
                      .collection("businesses")
                      .where("superAgentReferralCode", "==", saReferralCode)
                      .where("isSuperAgent", "==", true)
                      .limit(1)
                      .get();

                    // Backward fallback for existing records still on superAgents.
                    const legacyAgentSnap = agentBizSnap.empty
                      ? await admin
                        .firestore()
                        .collection("superAgents")
                        .where("referral_code", "==", saReferralCode)
                        .limit(1)
                        .get()
                      : null;

                    if (!agentBizSnap.empty || (legacyAgentSnap && !legacyAgentSnap.empty)) {
                      const isBusinessModel = !agentBizSnap.empty;
                      const agentDoc = isBusinessModel ? agentBizSnap.docs[0] : legacyAgentSnap.docs[0];
                      const agentId = agentDoc.id;
                      const NIP_COMMISSION = Number(settings.perNipTransferAmount || 0);
                      const VERIFIED_BUSINESS_BONUS = Number(settings.verifiedBusinessBonusAmount || 0);

                      const commissionBatch = admin.firestore().batch();
                      let totalNewEarnings = NIP_COMMISSION;

                      // Record NIP transfer commission
                      const nipCommRef = admin
                        .firestore()
                        .collection("superAgentCommissions")
                        .doc();
                      commissionBatch.set(nipCommRef, {
                        superAgentId: agentId, // kept for backward compatibility
                        superAgentBusinessId: isBusinessModel ? agentId : null,
                        type: "nip_transfer",
                        amount: NIP_COMMISSION,
                        businessId: senderId,
                        transactionId: transferIdSuccess,
                        status: "credited",
                        createdAt: admin.firestore.FieldValue.serverTimestamp(),
                      });

                      // Business verification bonus (idempotent via flag)
                      if (!businessData.superAgentFirstTxBonusPaid) {
                        totalNewEarnings += VERIFIED_BUSINESS_BONUS;
                        const bonusRef = admin
                          .firestore()
                          .collection("superAgentCommissions")
                          .doc();
                        commissionBatch.set(bonusRef, {
                          superAgentId: agentId,
                          superAgentBusinessId: isBusinessModel ? agentId : null,
                          type: "business_verified_bonus",
                          amount: VERIFIED_BUSINESS_BONUS,
                          businessId: senderId,
                          transactionId: transferIdSuccess,
                          status: "credited",
                          createdAt: admin.firestore.FieldValue.serverTimestamp(),
                        });

                        // Mark bonus as paid so it's never duplicated.
                        commissionBatch.update(businessSnap.ref, {
                          superAgentFirstTxBonusPaid: true,
                        });
                      }

                      if (isBusinessModel) {
                        const currentTotal = Number(agentDoc.data()?.superAgentTotalEarnings || 0);
                        const newTotal = currentTotal + totalNewEarnings;
                        const oldStars = Number(agentDoc.data()?.superAgentStars || 0);
                        const newStars = computeSuperAgentStars(newTotal, settings.starThresholds);

                        commissionBatch.update(agentDoc.ref, {
                          superAgentTotalEarnings: admin.firestore.FieldValue.increment(totalNewEarnings),
                          superAgentAvailableEarnings: admin.firestore.FieldValue.increment(totalNewEarnings),
                          superAgentStars: newStars,
                          superAgentUpdatedAt: admin.firestore.FieldValue.serverTimestamp(),
                        });

                        if (newStars > oldStars) {
                          const to = String(agentDoc.data()?.businessEmail || "").trim().toLowerCase();
                          if (to) {
                            const businessName = String(agentDoc.data()?.businessName || "Super Agent").trim();
                            const starsLabel = "?".repeat(newStars);
                            await sendNotifyEmail({
                              to,
                              subject: `Congratulations! You reached ${newStars}-Star Super Agent`,
                              html: `<div style="font-family:Arial,sans-serif;max-width:600px;margin:0 auto;padding:24px;color:#111827;"><h2 style="margin:0 0 12px;">You are now a ${newStars}-Star Super Agent ${starsLabel}</h2><p style="margin:0 0 12px;">Hello ${businessName}, your total super-agent earnings are now ?${newTotal.toLocaleString()}.</p><p style="margin:0;color:#6b7280;">Keep referring active businesses to unlock the next star tier.</p></div>`,
                              text: `Hello ${businessName}, you are now a ${newStars}-Star Super Agent. Total earnings: ?${newTotal.toLocaleString()}.`,
                            });
                          }
                        }
                      } else {
                        // Legacy fallback update for old superAgents documents.
                        commissionBatch.update(agentDoc.ref, {
                          total_earnings: admin.firestore.FieldValue.increment(totalNewEarnings),
                          pending_earnings: admin.firestore.FieldValue.increment(totalNewEarnings),
                        });
                      }

                      await commissionBatch.commit();
                      console.log(
                        `Super Agent commission: agentId=${agentId} amount=?${totalNewEarnings} businessId=${senderId}`,
                      );
                    }
                  }
                }
              }
            } catch (saCommErr) {
              // Non-fatal: log but don't interrupt the transfer flow
              console.error("Super Agent commission error:", saCommErr);
            }
            // -- End Super Agent Commission ------------------------------

            // Fetch sender user
            let senderName = "";
            let senderToken = null;
            if (senderId) {
              const senderUserRef = admin
                .firestore()
                .collection("users")
                .doc(senderId);
              const senderUserDoc = await senderUserRef.get();
              if (senderUserDoc.exists) {
                const senderData = senderUserDoc.data();
                senderName = `${senderData.firstName || ""} ${
                  senderData.lastName || ""
                }`.trim();
                senderToken = senderData.deviceToken;
              }
            }

            // Determine receiver user ID
            let receiverUserId = transactionData.receiverId;
            if (!receiverUserId) {
              const counterPartyId =
                transactionData.api_response?.data?.relationships?.counterParty
                  ?.data?.id;
              if (counterPartyId) {
                const counterPartyRef = admin
                  .firestore()
                  .collection("counterparties")
                  .doc(counterPartyId);
                const counterPartyDoc = await counterPartyRef.get();
                if (counterPartyDoc.exists) {
                  receiverUserId = counterPartyDoc.data().userId;
                }
              }
            }

            // Send sender notification (skip if recipient is "Pay Padi" or if it's a settlement)
            if (recipientName !== "Pay Padi" && !isSettlementTransfer) {
              if (senderToken) {
                const senderMessage = {
                  token: senderToken,
                  notification: {
                    title: "Transfer Successful",
                    body: `You sent ${amount} to ${recipientName}`,
                  },
                  ...FCM_CHANNEL,
                };
                await admin.messaging().send(senderMessage);
                console.log(`Sent notification to sender ${senderId}`);
              }
              await saveNotification(senderId, {
                title: "Transfer Successful",
                body: `You sent ${amount} to ${recipientName}`,
                type: "transfer_sent",
                amount,
              });
            }

            // Send receiver notification if receiver user found and not the sender
            if (
              receiverUserId &&
              receiverUserId !== senderId &&
              !isSettlementTransfer
            ) {
              const receiverUserRef = admin
                .firestore()
                .collection("users")
                .doc(receiverUserId);
              const receiverUserDoc = await receiverUserRef.get();
              if (receiverUserDoc.exists) {
                const receiverToken = receiverUserDoc.data().deviceToken;
                if (receiverToken) {
                  const formattedAmount = Number(amount).toLocaleString("en-NG");
                  const receiverMessage = {
                    token: receiverToken,
                    notification: {
                      title: "Transfer Received",
                      body: `You received ${formattedAmount} from ${
                        senderName || "a user"
                      }`,
                    },
                    ...FCM_CHANNEL,
                  };
                  await admin.messaging().send(receiverMessage);
                  console.log(
                    `Sent notification to receiver ${receiverUserId}`,
                  );
                  await saveNotification(receiverUserId, {
                    title: "Transfer Received",
                    body: `You received ${formattedAmount} from ${senderName || "a user"}`,
                    type: "transfer_received",
                    amount,
                  });

                  // record this transfer notification so that the subsequent
                  // `payment.settled` event can detect it and avoid sending a
                  // duplicate "Payment Received" message.  Only store the
                  // timestamp when we actually sent a notification.
                  try {
                    await admin
                      .firestore()
                      .collection("users")
                      .doc(receiverUserId)
                      .update({
                        lastReceivedTransfer: {
                          amount, // amount is already in naira here
                          timestamp:
                            admin.firestore.FieldValue.serverTimestamp(),
                        },
                      });
                  } catch (err) {
                    console.error(
                      `Failed to update lastReceivedTransfer for user ${receiverUserId}:`,
                      err,
                    );
                  }
                }
              }
            } else if (receiverUserId && receiverUserId === senderId) {
              // Avoid sending a duplicate notification back to the sender
              console.log(
                `Skipping receiver notification because receiverUserId (${receiverUserId}) is the same as senderId (${senderId})`,
              );
            }
          }
        } else if (!querySuccess) {
          console.error(
            `Query failed entirely after ${maxAttempts} attempts for transfer ID: ${transferIdSuccess}`,
          );
        } else {
          console.log(
            `Failed to find transaction after ${maxAttempts} attempts for transfer ID: ${transferIdSuccess}`,
          );
        }
        break;
      }
      case "bills.successful": {
        console.log("Bills successful");
        const billIdSuccess = event.relationships.bill.data.id;
        let successSnapshot;
        let attempts = 0;
        const maxAttempts = 5;
        let querySuccess = false;
        do {
          try {
            const successQuery = admin
              .firestore()
              .collection("transactions")
              .where("reference", "==", billIdSuccess);
            successSnapshot = await successQuery.get();
            if (!successSnapshot.empty) {
              querySuccess = true;
              break;
            }
          } catch (queryError) {
            console.error(
              `Firestore query error for success bill ID ${billIdSuccess} (attempt ${
                attempts + 1
              }):`,
              queryError,
            );
            if (
              queryError.code === "failed-precondition" ||
              queryError.message.includes("index")
            ) {
              console.error(
                "Likely missing composite index on transactionId - check Firebase console",
              );
            }
          }
          attempts++;
          console.log(
            `Attempt ${attempts}: No transaction found for bill ID: ${billIdSuccess}, retrying in 500ms...`,
          );
          if (attempts < maxAttempts) {
            await new Promise((resolve) => setTimeout(resolve, 500));
          }
        } while (attempts < maxAttempts);
        if (querySuccess && !successSnapshot.empty) {
          try {
            // Only update docs that are not already SUCCESSFUL to ensure idempotency
            const docsToUpdate = successSnapshot.docs.filter((doc) => {
              const status = doc.data()?.status;
              return status !== "SUCCESSFUL";
            });

            if (docsToUpdate.length > 0) {
              // Use batch writes instead of individual updates
              const batch = admin.firestore().batch();
              for (const doc of docsToUpdate) {
                batch.update(doc.ref, { status: "SUCCESSFUL" });
              }
              await batch.commit();
              console.log(
                `Updated ${docsToUpdate.length} transaction(s) to SUCCESSFUL for bill ID: ${billIdSuccess}`,
              );

              // Send notifications using the first updated document
              const transactionDoc = docsToUpdate[0];
              const transactionData = transactionDoc.data();
              const userId = transactionData.userId;
              const amount = transactionData.amount;
              const bundle = transactionData.bundle || "bill";
              const phoneNumber = transactionData.phoneNumber || "";
              const network = transactionData.network || "";

              // Fetch user
              let userToken = null;
              let userEmailBillSuccess = null;
              if (userId) {
                const userRef = admin
                  .firestore()
                  .collection("users")
                  .doc(userId);
                const userDoc = await userRef.get();
                if (userDoc.exists) {
                  const userData = userDoc.data();
                  userToken = userData.deviceToken;
                  userEmailBillSuccess = userData.email;
                }
              }

              // Send user notification only when we changed status
              if (userToken) {
                const message = {
                  token: userToken,
                  notification: {
                    title: "Bill Payment Successful",
                    body: `Your ${amount.toFixed(
                      2,
                    )} ${network} purchase for ${phoneNumber} was successful.`,
                  },
                  ...FCM_CHANNEL,
                };
                await admin.messaging().send(message);
                console.log(`Sent notification to user ${userId}`);
                await saveNotification(userId, {
                  title: "Bill Payment Successful",
                  body: `Your ${amount.toFixed(2)} ${network} purchase for ${phoneNumber} was successful.`,
                  type: "bill_success",
                  amount,
                });
              }
              if (userEmailBillSuccess) {
                await sendNotifyEmail({
                  to: userEmailBillSuccess,
                  subject: `? Bill Payment Successful ? PadiPay`,
                  html: `<!DOCTYPE html><html><head><meta charset='UTF-8'/></head><body style='margin:0;padding:0;background:#f0f2f5;font-family:Helvetica,Arial,sans-serif;'><table width='100%' cellpadding='0' cellspacing='0' style='background:#f0f2f5;padding:40px 0;'><tr><td align='center'><table width='520' cellpadding='0' cellspacing='0' style='max-width:520px;width:100%;'><tr><td align='center' style='padding-bottom:24px;'><span style='font-size:22px;font-weight:700;color:#1a1a2e;'>Padi<span style='color:#10b981;'>Pay</span></span></td></tr><tr><td style='background:#fff;border-radius:16px;overflow:hidden;box-shadow:0 4px 24px rgba(0,0,0,.07);'><table width='100%' cellpadding='0' cellspacing='0'><tr><td style='background:linear-gradient(135deg,#10b981,#059669);height:5px;font-size:0;'>&nbsp;</td></tr><tr><td style='padding:40px 48px 36px;'><p style='margin:0 0 8px;font-size:13px;font-weight:600;letter-spacing:1.2px;text-transform:uppercase;color:#10b981;'>Transaction Update</p><h1 style='margin:0 0 16px;font-size:26px;font-weight:700;color:#0f0f1a;'>Bill Payment Successful</h1><p style='margin:0 0 24px;font-size:15px;color:#6b7280;line-height:1.6;'>Your bill payment was processed successfully.</p><table width='100%' cellpadding='8' cellspacing='0' style='background:#f9fafb;border-left:4px solid #10b981;border-radius:8px;margin:0 0 24px;'><tr><td><p style='margin:0;font-size:13px;color:#374151;'><strong>Amount:</strong> ${amount.toFixed(2)}</p><p style='margin:8px 0 0;font-size:13px;color:#374151;'><strong>Service:</strong> ${network}</p><p style='margin:8px 0 0;font-size:13px;color:#374151;'><strong>Recipient:</strong> ${phoneNumber}</p></td></tr></table></td></tr><tr><td style='padding:0 48px;'><div style='border-top:1px solid #f3f4f6;'></div></td></tr><tr><td style='padding:24px 48px;'><p style='margin:0;font-size:12px;color:#d1d5db;'>&copy; 2026 PadiPay</p></td></tr></table></td></tr></table></td></tr></table></body></html>`,
                });
              }
            } else {
              console.log(
                `No transaction status change needed for bill ID: ${billIdSuccess} (already SUCCESSFUL) ? skipping notification`,
              );
            }
          } catch (updateError) {
            console.error(
              `Firestore update error for success bill ID ${billIdSuccess}:`,
              updateError,
            );
          }
        } else if (!querySuccess) {
          console.error(
            `Query failed entirely after ${maxAttempts} attempts for bill ID: ${billIdSuccess}`,
          );
        } else {
          console.log(
            `Failed to find transaction after ${maxAttempts} attempts for bill ID: ${billIdSuccess}`,
          );
        }
        break;
      }
      case "bills.failed": {
        console.log("Bills failed");
        const billIdFailed = event.relationships.bill.data.id;
        let failedSnapshot;
        let attempts = 0;
        const maxAttempts = 5;
        let queryFailed = false;
        do {
          try {
            const failedQuery = admin
              .firestore()
              .collection("transactions")
              .where("reference", "==", billIdFailed);
            failedSnapshot = await failedQuery.get();
            if (!failedSnapshot.empty) {
              queryFailed = true;
              break;
            }
          } catch (queryError) {
            console.error(
              `Firestore query error for failed bill ID ${billIdFailed} (attempt ${
                attempts + 1
              }):`,
              queryError,
            );
            if (
              queryError.code === "failed-precondition" ||
              queryError.message.includes("index")
            ) {
              console.error(
                "Likely missing composite index on transactionId - check Firebase console",
              );
            }
          }
          attempts++;
          console.log(
            `Attempt ${attempts}: No transaction found for bill ID: ${billIdFailed}, retrying in 500ms...`,
          );
          if (attempts < maxAttempts) {
            await new Promise((resolve) => setTimeout(resolve, 500));
          }
        } while (attempts < maxAttempts);
        if (queryFailed && !failedSnapshot.empty) {
          try {
            const updatePromises = failedSnapshot.docs.map((doc) =>
              doc.ref.update({ status: "FAILED" }),
            );
            await Promise.all(updatePromises);
            console.log(
              `Updated ${failedSnapshot.size} transaction(s) to FAILED for bill ID: ${billIdFailed}`,
            );
          } catch (updateError) {
            console.error(
              `Firestore update error for failed bill ID ${billIdFailed}:`,
              updateError,
            );
          }

          // Send notifications
          if (failedSnapshot.size > 0) {
            const transactionDoc = failedSnapshot.docs[0];
            const transactionData = transactionDoc.data();
            const userId = transactionData.userId;
            const amount = transactionData.amount;
            const bundle = transactionData.bundle || "bill";
            const phoneNumber = transactionData.phoneNumber || "";
            const network = transactionData.network || "";

            // Fetch user
            let userToken = null;
            let userEmailBillFailed = null;
            if (userId) {
              const userRef = admin.firestore().collection("users").doc(userId);
              const userDoc = await userRef.get();
              if (userDoc.exists) {
                const userData = userDoc.data();
                userToken = userData.deviceToken;
                userEmailBillFailed = userData.email;
              }
            }

            // Send user notification
            if (userToken) {
              const message = {
                token: userToken,
                notification: {
                  title: "Bill Payment Failed",
                  body: `Your ${amount.toFixed(
                    2,
                  )} ${network} purchase for ${phoneNumber} failed. Please try again.`,
                },
                ...FCM_CHANNEL,
              };
              await admin.messaging().send(message);
              console.log(`Sent failure notification to user ${userId}`);
              await saveNotification(userId, {
                title: "Bill Payment Failed",
                body: `Your ${amount.toFixed(2)} ${network} purchase for ${phoneNumber} failed. Please try again.`,
                type: "bill_failed",
                amount,
              });
            }
            if (userEmailBillFailed) {
              await sendNotifyEmail({
                to: userEmailBillFailed,
                subject: `Bill Payment Failed`,
                html: `<!DOCTYPE html><html><head><meta charset='UTF-8'/></head><body style='margin:0;padding:0;background:#f0f2f5;font-family:Helvetica,Arial,sans-serif;'><table width='100%' cellpadding='0' cellspacing='0' style='background:#f0f2f5;padding:40px 0;'><tr><td align='center'><table width='520' cellpadding='0' cellspacing='0' style='max-width:520px;width:100%;'><tr><td align='center' style='padding-bottom:24px;'><span style='font-size:22px;font-weight:700;color:#1a1a2e;'>Padi<span style='color:#ef4444;'>Pay</span></span></td></tr><tr><td style='background:#fff;border-radius:16px;overflow:hidden;box-shadow:0 4px 24px rgba(0,0,0,.07);'><table width='100%' cellpadding='0' cellspacing='0'><tr><td style='background:linear-gradient(135deg,#ef4444,#dc2626);height:5px;font-size:0;'>&nbsp;</td></tr><tr><td style='padding:40px 48px 36px;'><p style='margin:0 0 8px;font-size:13px;font-weight:600;letter-spacing:1.2px;text-transform:uppercase;color:#ef4444;'>Transaction Failed</p><h1 style='margin:0 0 16px;font-size:26px;font-weight:700;color:#0f0f1a;'>Bill Payment Failed</h1><p style='margin:0 0 24px;font-size:15px;color:#6b7280;line-height:1.6;'>Your bill payment could not be processed. You have not been charged.</p><table width='100%' cellpadding='8' cellspacing='0' style='background:#fef2f2;border-left:4px solid #ef4444;border-radius:8px;margin:0 0 24px;'><tr><td><p style='margin:0;font-size:13px;color:#374151;'><strong>Amount:</strong> ${amount.toFixed(2)}</p><p style='margin:8px 0 0;font-size:13px;color:#374151;'><strong>Service:</strong> ${network}</p><p style='margin:8px 0 0;font-size:13px;color:#374151;'><strong>Recipient:</strong> ${phoneNumber}</p></td></tr></table><p style='margin:0;font-size:13px;color:#9ca3af;line-height:1.6;'>Please try again or contact support if the issue persists.</p></td></tr><tr><td style='padding:0 48px;'><div style='border-top:1px solid #f3f4f6;'></div></td></tr><tr><td style='padding:24px 48px;'><p style='margin:0;font-size:12px;color:#d1d5db;'>&copy; 2026 PadiPay</p></td></tr></table></td></tr></table></td></tr></table></body></html>`,
              });
            }
          }
        } else if (!queryFailed) {
          console.error(
            `Query failed entirely after ${maxAttempts} attempts for bill ID: ${billIdFailed}`,
          );
        } else {
          console.log(
            `Failed to find transaction after ${maxAttempts} attempts for bill ID: ${billIdFailed}`,
          );
        }
        break;
      }
      case "payment.received":
      case "payment.settled": {
        console.log(`Payment event: ${eventType}`);
        const payment = event.attributes.payment;
        const settlementAccountId = payment.settlementAccount.accountId;

        let accountData = null;
        let userId = null;
        let deviceToken = null;
        let foundIn = null;
        const maxAttempts = 5;

        // --- Try Users Collection First -------------------------------------
        let userFound = false;
        let attempts = 0;
        let userSnapshot = null;

        do {
          try {
            const userQuery = admin
              .firestore()
              .collection("users")
              .where(
                "getAnchorData.virtualAccount.data.id",
                "==",
                settlementAccountId,
              );
            userSnapshot = await userQuery.get();

            if (!userSnapshot.empty) {
              userFound = true;
              break;
            }
          } catch (e) {
            console.error(
              `Users query error for settlement account ID ${settlementAccountId} (attempt ${
                attempts + 1
              }):`,
              e,
            );
            if (
              e.code === "failed-precondition" ||
              (e.message && e.message.includes("index"))
            ) {
              console.error(
                "Likely missing composite index on getAnchorData.virtualAccount.data.id in users collection",
              );
            }
          }

          attempts++;
          console.log(
            `Attempt ${attempts}: No document found in users for ${settlementAccountId}, retrying in 500ms...`,
          );
          if (attempts < maxAttempts)
            await new Promise((resolve) => setTimeout(resolve, 500));
        } while (attempts < maxAttempts);

        if (userFound) {
          const userDoc = userSnapshot.docs[0];
          userId = userDoc.id;
          accountData = userDoc.data();
          deviceToken = accountData.deviceToken || null;
          foundIn = "users";
          console.log(`Match found in users collection ? userId: ${userId}`);
        }

        // --- If Not Found In Users ? Try Businesses Collection -----------------
        let businessFound = false;
        let businessSnapshot = null;
        if (!userFound) {
          attempts = 0;
          do {
            try {
              const businessQuery = admin
                .firestore()
                .collection("businesses")
                .where(
                  "getAnchorData.virtualAccount.data.id",
                  "==",
                  settlementAccountId,
                );
              businessSnapshot = await businessQuery.get();

              if (!businessSnapshot.empty) {
                businessFound = true;
                break;
              }
            } catch (e) {
              console.error(
                `Businesses query error for settlement account ID ${settlementAccountId} (attempt ${
                  attempts + 1
                }):`,
                e,
              );
              if (
                e.code === "failed-precondition" ||
                (e.message && e.message.includes("index"))
              ) {
                console.error(
                  "Likely missing composite index on getAnchorData.virtualAccount.data.id in businesses collection",
                );
              }
            }

            attempts++;
            console.log(
              `Attempt ${attempts}: No document found in businesses for ${settlementAccountId}, retrying in 500ms...`,
            );
            if (attempts < maxAttempts)
              await new Promise((resolve) => setTimeout(resolve, 500));
          } while (attempts < maxAttempts);

          if (businessFound) {
            const businessDoc = businessSnapshot.docs[0];
            userId = businessDoc.id;
            accountData = businessDoc.data();
            foundIn = "businesses";
            console.log(
              `Match found in businesses collection ? userId: ${userId}`,
            );

            // Fetch device token from users collection (doc ID = userId)
            try {
              const userSnap = await admin
                .firestore()
                .collection("users")
                .doc(userId)
                .get();
              if (userSnap.exists && userSnap.data()?.deviceToken) {
                deviceToken = userSnap.data().deviceToken;
              }
            } catch (e) {
              console.error(
                "Failed to fetch device token from users collection:",
                e,
              );
            }
          }
        }

        // --- If Not Found In Users or Businesses ? Try posStands array in Businesses --
        // Optimized: query businesses that have posStands array instead of scanning all
        let posStandFound = false;
        let posStandDoc = null;
        if (!userFound && !businessFound) {
          try {
            // Query only businesses that have posStands defined
            const businessesWithStands = await admin
              .firestore()
              .collection("businesses")
              .where("posStandAccountIds", "array-contains", settlementAccountId)
              .limit(1)
              .get();

            if (!businessesWithStands.empty) {
              posStandFound = true;
              posStandDoc = businessesWithStands.docs[0];
            } else {
              // Fallback: scan businesses with posStands (no retry loop)
              const allBusinesses = await admin
                .firestore()
                .collection("businesses")
                .get();
              for (const doc of allBusinesses.docs) {
                const data = doc.data();
                if (Array.isArray(data.posStands)) {
                  for (const stand of data.posStands) {
                    if (
                      stand &&
                      stand.accountData &&
                      stand.accountData.data &&
                      stand.accountData.data.id === settlementAccountId
                    ) {
                      posStandFound = true;
                      posStandDoc = doc;
                      break;
                    }
                  }
                }
                if (posStandFound) break;
              }
            }
          } catch (e) {
            console.error(
              `posStands search error for account ID ${settlementAccountId}:`,
              e,
            );
          }

          if (posStandFound && posStandDoc) {
            userId = posStandDoc.id;
            accountData = posStandDoc.data();
            foundIn = "posStand";
            console.log(
              `Match found in businesses.posStands for accountId: ${settlementAccountId} ? userId: ${userId}`,
            );

            // Fetch device token from users collection (doc ID = userId)
            try {
              const userSnap = await admin
                .firestore()
                .collection("users")
                .doc(userId)
                .get();
              if (userSnap.exists && userSnap.data()?.deviceToken) {
                deviceToken = userSnap.data().deviceToken;
              }
            } catch (e) {
              console.error(
                "Failed to fetch device token from users collection:",
                e,
              );
            }
          }
        }

        // --- Process Transaction & Notification if Match Found -----------------
        if (accountData) {
          // Use virtualAccount.data as the single source of truth (present in both collections)
          const vaData = accountData.getAnchorData?.virtualAccount?.data;

          if (!vaData && foundIn !== "posStand") {
            console.error(
              `virtualAccount.data missing for userId ${userId} in ${foundIn} collection`,
            );
            break;
          }

          // Prefer customer ID from virtualAccount relationships (standard in Anchor responses), fall back to old path
          let customerId = vaData?.relationships?.customer?.data?.id;
          if (!customerId && foundIn !== "posStand") {
            customerId = accountData.getAnchorData?.customerCreation?.data?.id;
          }

          if (!customerId && foundIn !== "posStand") {
            console.warn(
              `Customer ID not found in any known path for userId ${userId} (${foundIn}) ? using placeholder`,
            );
            customerId = "unknown-customer";
          }

          const customerType =
            foundIn === "users" ? "IndividualCustomer" : "BusinessCustomer";

          const bankName = vaData?.attributes?.bank?.name || "Unknown Bank";
          const bankCode = vaData?.attributes?.bank?.id || "unknown";

          const senderName =
            payment.counterParty?.accountName || "Unknown Sender";
          const senderAccountNumber = payment.counterParty?.accountNumber || "";
          const accountNumberMasked = senderAccountNumber
            ? `******${senderAccountNumber.slice(-4)}`
            : "";
          const amount = payment.amount;
          const currency = payment.currency;
          const narration = payment.narration || "";
          const paymentId = payment.paymentId;
          const paidAt = payment.paidAt;

          // SECURITY: Cross-validate the payment against Anchor's API before creating
          // any transaction record. HMAC signature only proves the sender knew the
          // webhook secret ? it does NOT prove the transaction is real. An insider
          // (Anchor staff or anyone with the leaked secret) could send a correctly
          // signed payload with a fabricated amount, crediting a user without any
          // real money moving. Fetching the payment from Anchor directly proves the
          // event is genuine and the claimed amount matches what Anchor has on record.
          const anchorApiSecretKey = getanchorSecretKey.value();
          const paymentVerifyUrl = `${BASE_URL}/payments/${encodeURIComponent(paymentId)}`;
          let crossValidationPassed = false;
          try {
            const apiPaymentResp = await makeApiRequest({
              url: paymentVerifyUrl,
              method: "GET",
              secretKey: anchorApiSecretKey,
            });
            const apiPayment = apiPaymentResp?.data;
            const apiStatus = apiPayment?.attributes?.status;
            const apiAmount = apiPayment?.attributes?.amount;

            if (!apiPayment?.id) {
              console.error(
                `payment.settled REJECTED ? paymentId ${paymentId} not found on Anchor API`,
              );
              break;
            }
            if (apiStatus !== "SETTLED" && apiStatus !== "SUCCESSFUL") {
              console.error(
                `payment.settled REJECTED ? Anchor API status is "${apiStatus}" for paymentId ${paymentId} (expected SETTLED)`,
              );
              break;
            }
            if (apiAmount !== amount) {
              console.error(
                `payment.settled REJECTED ? amount mismatch: webhook says ${amount}, Anchor API says ${apiAmount} for paymentId ${paymentId}`,
              );
              break;
            }
            crossValidationPassed = true;
            console.log(
              `payment.settled cross-validation PASSED for paymentId ${paymentId} (amount: ${amount})`,
            );
          } catch (cvError) {
            // If Anchor's API is temporarily unreachable, reject the event and let
            // Anchor retry the webhook rather than risk recording a forged payment.
            console.error(
              `payment.settled REJECTED ? Anchor API verification call failed for paymentId ${paymentId}:`,
              cvError,
            );
            break;
          }

          if (!crossValidationPassed) break;

          // Check for existing transaction to ensure idempotency
          let existingTx = null;
          try {
            // First check by reference field
            const existingByRef = await admin
              .firestore()
              .collection("transactions")
              .where("reference", "==", paymentId)
              .limit(1)
              .get();
            if (!existingByRef.empty) {
              existingTx = existingByRef.docs[0];
            } else {
              // Fallback: check api_response.data.id
              const existingByApiId = await admin
                .firestore()
                .collection("transactions")
                .where("api_response.data.id", "==", paymentId)
                .limit(1)
                .get();
              if (!existingByApiId.empty) existingTx = existingByApiId.docs[0];
            }
          } catch (e) {
            console.error("Error checking existing transaction:", e);
          }

          if (existingTx) {
            console.log(
              `Transaction already exists for payment ID: ${paymentId}, skipping creation`,
            );
          } else {
            // Create transaction document
            const transactionRef = admin
              .firestore()
              .collection("transactions")
              .doc();
            const transactionData = {
              account_number: accountNumberMasked,
              amount: amount / 100,
              api_response: {
                data: {
                  attributes: {
                    amount: amount,
                    createdAt: payment.createdAt,
                    currency: currency,
                    reference: payment.paymentReference,
                    status: "SUCCESSFUL",
                  },
                  id: paymentId,
                  relationships: {
                    account: {
                      data: {
                        id: settlementAccountId,
                        type: "DepositAccount",
                      },
                    },
                    counterParty: {
                      data: {
                        id: "external-cp",
                        type: "CounterParty",
                      },
                    },
                    customer: {
                      data: {
                        id: customerId,
                        type: customerType,
                      },
                    },
                    program: {
                      data: {
                        id: "Default",
                        type: "Program",
                      },
                    },
                  },
                  type: "BANK_TRANSFER",
                },
              },
              bankName,
              bank_code: bankCode,
              currency,
              reason: narration,
              senderName,
              reference: paymentId,
              timestamp: admin.firestore.Timestamp.fromDate(new Date(paidAt)),
              type: "deposit",
              userId,
            };

            await transactionRef.set(transactionData);
            console.log(
              `Created transaction for payment ID: ${paymentId} (found in ${foundIn})`,
            );

            // Auto-match pending storefront bank-transfer orders and fulfill data purchase.
            await tryMatchAndSettleStorefrontOrder({
              merchantUid: userId,
              payment,
            });

            // Send notification if device token exists (but first check
            // whether we recently already notified this user of a transfer.)
            if (deviceToken && foundIn !== "posStand") {
              let skipNotification = false;
              try {
                const userSnap = await admin
                  .firestore()
                  .collection("users")
                  .doc(userId)
                  .get();
                const last = userSnap.exists
                  ? userSnap.data()?.lastReceivedTransfer
                  : null;
                const depositAmt = amount / 100;
                if (
                  last &&
                  last.amount === depositAmt &&
                  last.timestamp &&
                  admin.firestore.Timestamp.now().toMillis() -
                    last.timestamp.toMillis() <
                    5 * 60 * 1000 // 5 minutes
                ) {
                  skipNotification = true;
                  console.log(
                    `Skipping payment notification for user ${userId} because a transfer notification was sent recently`,
                  );
                }
              } catch (err) {
                console.error(
                  "Error checking lastReceivedTransfer for skip:",
                  err,
                );
              }

              if (!skipNotification) {
                const formattedPaymentAmount = Number(amount / 100).toLocaleString("en-NG");
                const message = {
                  token: deviceToken,
                  notification: {
                    title: "Payment Received",
                    body: `You received ${formattedPaymentAmount} from ${senderName}`,
                  },
                  ...FCM_CHANNEL,
                };

                try {
                  await admin.messaging().send(message);
                  console.log(
                    `Notification sent to user ${userId} (account in ${foundIn})`,
                  );
                  await saveNotification(userId, {
                    title: "Payment Received",
                    body: `You received ${formattedPaymentAmount} from ${senderName}`,
                    type: "payment_received",
                    amount: amount / 100,
                  });
                } catch (e) {
                  console.error("Failed to send FCM notification:", e);
                }
                // Send email notification for deposit
                try {
                  const userEmailSnap = await admin
                    .firestore()
                    .collection("users")
                    .doc(userId)
                    .get();
                  const userDepositEmail = userEmailSnap.data()?.email;
                  if (userDepositEmail) {
                    await sendNotifyEmail({
                      to: userDepositEmail,
                      subject: `${(amount / 100).toLocaleString("en-NG")} received ? PadiPay`,
                      html: `<!DOCTYPE html><html><head><meta charset='UTF-8'/></head><body style='margin:0;padding:0;background:#f0f2f5;font-family:Helvetica,Arial,sans-serif;'><table width='100%' cellpadding='0' cellspacing='0' style='background:#f0f2f5;padding:40px 0;'><tr><td align='center'><table width='520' cellpadding='0' cellspacing='0' style='max-width:520px;width:100%;'><tr><td align='center' style='padding-bottom:24px;'><span style='font-size:22px;font-weight:700;color:#1a1a2e;'>Padi<span style='color:#10b981;'>Pay</span></span></td></tr><tr><td style='background:#fff;border-radius:16px;overflow:hidden;box-shadow:0 4px 24px rgba(0,0,0,.07);'><table width='100%' cellpadding='0' cellspacing='0'><tr><td style='background:linear-gradient(135deg,#10b981,#059669);height:5px;font-size:0;'>&nbsp;</td></tr><tr><td style='padding:40px 48px 36px;'><p style='margin:0 0 8px;font-size:13px;font-weight:600;letter-spacing:1.2px;text-transform:uppercase;color:#10b981;'>Payment Received</p><h1 style='margin:0 0 16px;font-size:26px;font-weight:700;color:#0f0f1a;'>${(amount / 100).toLocaleString("en-NG")} Credited</h1><p style='margin:0 0 24px;font-size:15px;color:#6b7280;line-height:1.6;'>A payment has been credited to your PadiPay account.</p><table width='100%' cellpadding='8' cellspacing='0' style='background:#f9fafb;border-left:4px solid #10b981;border-radius:8px;margin:0 0 24px;'><tr><td><p style='margin:0;font-size:13px;color:#374151;'><strong>Amount:</strong> ${(amount / 100).toLocaleString("en-NG")}</p><p style='margin:8px 0 0;font-size:13px;color:#374151;'><strong>From:</strong> ${senderName}</p>${narration ? `<p style='margin:8px 0 0;font-size:13px;color:#374151;'><strong>Narration:</strong> ${narration}</p>` : ""}</td></tr></table></td></tr><tr><td style='padding:0 48px;'><div style='border-top:1px solid #f3f4f6;'></div></td></tr><tr><td style='padding:24px 48px;'><p style='margin:0;font-size:12px;color:#d1d5db;'>&copy; 2026 PadiPay</p></td></tr></table></td></tr></table></td></tr></table></body></html>`,
                    });
                  }
                } catch (emailErr) {
                  console.error(
                    "[email] payment.settled email error:",
                    emailErr,
                  );
                }
              }
            }
            // If foundIn is posStand, send notification to business owner's deviceToken
            if (deviceToken && foundIn === "posStand") {
              const formattedPosStandAmount = Number(amount / 100).toLocaleString("en-NG");
              const message = {
                token: deviceToken,
                notification: {
                  title: "POS Stand Payment Received",
                  body: `Your POS stand received ${
                    formattedPosStandAmount
                  } from ${senderName}`,
                },
                ...FCM_CHANNEL,
              };
              try {
                await admin.messaging().send(message);
                console.log(
                  `Notification sent to business owner ${userId} for POS stand payment.`,
                );
                await saveNotification(userId, {
                  title: "POS Stand Payment Received",
                  body: `Your POS stand received ${formattedPosStandAmount} from ${senderName}`,
                  type: "payment_received",
                  amount: amount / 100,
                });
              } catch (e) {
                console.error(
                  "Failed to send FCM notification for POS stand:",
                  e,
                );
              }
            }
          }
        } else {
          console.error(
            `No matching document found in users, businesses, or posStand for settlement account ID: ${settlementAccountId}`,
          );
        }

        break;
      }
      default:
        console.log(`Unhandled event type: ${eventType}`);
    }
    // Acknowledge the event
    res.status(200).send("OK");
  } catch (error) {
    console.error("Webhook processing error:", error);
    res.status(400).json({ error: "Invalid payload" });
  }
});

exports.getanchorWebhook = onRequest(
  {
    // SECURITY: getanchorSecretKey is needed for cross-validation API calls
    // inside the webhook handler (verifying events against Anchor's API).
    secrets: [
        anchorWebhookSecret,
        anchorWebhookSecretSecondary,
        getanchorSecretKey,
        smtpHost,
        smtpUser,
        smtpPass,
    ],
  },
  app,
);

// ADD THESE HELPERS ONCE (anywhere in your webhook file, outside the switch)

const findEntityRef = async (customerId) => {
  // Query businesses and users in parallel instead of sequentially
  const [businessSnap, userSnap] = await Promise.all([
    admin
      .firestore()
      .collection("businesses")
      .where("kybCreation.data.id", "==", customerId)
      .limit(1)
      .get(),
    admin
      .firestore()
      .collection("users")
      .where("getAnchorData.customerCreation.data.id", "==", customerId)
      .limit(1)
      .get(),
  ]);

  if (!businessSnap.empty)
    return admin.firestore().collection("businesses").doc(businessSnap.docs[0].id);

  if (!userSnap.empty)
    return admin.firestore().collection("users").doc(userSnap.docs[0].id);

  console.error("Entity not found for customerId:", customerId);
  return null;
};

const getDeviceToken = async (customerId) => {
  const entityRef = await findEntityRef(customerId);
  if (!entityRef) return null;

  const snap = await entityRef.get();
  const data = snap.data() || {};

  // Direct token if exists
  if (data.deviceToken) return data.deviceToken;

  // For business accounts, token is in users collection with same uid
  if (entityRef.path.startsWith("businesses/")) {
    const userSnap = await admin
      .firestore()
      .collection("users")
      .doc(entityRef.id)
      .get();
    return userSnap.exists ? userSnap.data()?.deviceToken || null : null;
  }

  return null;
};

// Helper: send notification email via SMTP
const sendNotifyEmail = async ({ to, subject, html, text }) => {
  try {
    if (!html && !text) return;
    const messageId = await sendViaSMTP({ to, subject, html, text });
    console.log("[sendNotifyEmail] Sent to:", to, "| MessageId:", messageId);
  } catch (err) {
    console.error("[sendNotifyEmail] Error:", err.message || err);
  }
};

exports.sendAdminLoginEmail = onCall(
  {
    secrets: [smtpHost, smtpUser, smtpPass],
  },
  async (request) => {
    if (!request.auth) {
      throw new HttpsError("unauthenticated", "Authentication is required.");
    }

    const adminDoc = await db.collection("admins").doc(request.auth.uid).get();
    if (!adminDoc.exists) {
      throw new HttpsError("permission-denied", "Admin profile not found.");
    }

    const adminData = adminDoc.data() || {};
    const to = String(adminData.email || request.auth.token.email || "").trim();
    if (!to) {
      throw new HttpsError("failed-precondition", "Admin email is missing.");
    }

    const { ipAddress, userAgent } = request.data || {};
    const name = adminData.name || to.split("@")[0] || "Admin";
    const loggedAt = new Date().toLocaleString("en-NG", { timeZone: "Africa/Lagos" });

    await sendNotifyEmail({
      to,
      subject: "PadiPay Admin login detected",
      html: `
        <div style="font-family:Arial,sans-serif;max-width:600px;margin:0 auto;padding:24px;color:#111827;">
          <h2 style="margin:0 0 16px;">Admin login detected</h2>
          <p style="margin:0 0 16px;">Hello ${name}, your admin account just signed in to PadiPay.</p>
          <div style="background:#f9fafb;border:1px solid #e5e7eb;border-radius:12px;padding:16px;">
            <p style="margin:0 0 8px;"><strong>Time:</strong> ${loggedAt}</p>
            <p style="margin:0 0 8px;"><strong>IP:</strong> ${ipAddress || "Unavailable"}</p>
            <p style="margin:0;"><strong>Device:</strong> ${userAgent || "Unavailable"}</p>
          </div>
          <p style="margin:16px 0 0;color:#6b7280;">If this was not you, reset your password immediately and review admin activity.</p>
        </div>
      `,
      text: `Admin login detected\n\nHello ${name}, your admin account just signed in to PadiPay.\nTime: ${loggedAt}\nIP: ${ipAddress || "Unavailable"}\nDevice: ${userAgent || "Unavailable"}\n\nIf this was not you, reset your password immediately and review admin activity.`,
    });

    return { success: true };
  },
);

exports.sendBrmLoginEmail = onCall(
  {
    secrets: [smtpHost, smtpUser, smtpPass],
  },
  async (request) => {
    if (!request.auth) {
      throw new HttpsError("unauthenticated", "Authentication is required.");
    }

    const brmDoc = await db.collection("brms").doc(request.auth.uid).get();
    if (!brmDoc.exists) {
      throw new HttpsError("permission-denied", "BRM profile not found.");
    }

    const brmData = brmDoc.data() || {};
    const to = String(brmData.email || request.auth.token.email || "").trim();
    if (!to) {
      throw new HttpsError("failed-precondition", "BRM email is missing.");
    }

    const { userAgent } = request.data || {};
    const name = brmData.full_name || brmData.first_name || "BRM Agent";
    const loggedAt = new Date().toLocaleString("en-NG", { timeZone: "Africa/Lagos" });

    await sendNotifyEmail({
      to,
      subject: "PadiPay BRM login detected",
      html: `
        <div style="font-family:Arial,sans-serif;max-width:600px;margin:0 auto;padding:24px;color:#111827;">
          <h2 style="margin:0 0 16px;">BRM portal login detected</h2>
          <p style="margin:0 0 16px;">Hello ${name}, your BRM portal account was just used to sign in.</p>
          <div style="background:#f9fafb;border:1px solid #e5e7eb;border-radius:12px;padding:16px;">
            <p style="margin:0 0 8px;"><strong>Time:</strong> ${loggedAt}</p>
            <p style="margin:0 0 8px;"><strong>Referral code:</strong> ${brmData.referral_code || "Unavailable"}</p>
            <p style="margin:0;"><strong>Device:</strong> ${userAgent || "Unavailable"}</p>
          </div>
          <p style="margin:16px 0 0;color:#6b7280;">If this was not you, reset your BRM password immediately.</p>
        </div>
      `,
      text: `BRM portal login detected\n\nHello ${name}, your BRM portal account was just used to sign in.\nTime: ${loggedAt}\nReferral code: ${brmData.referral_code || "Unavailable"}\nDevice: ${userAgent || "Unavailable"}\n\nIf this was not you, reset your BRM password immediately.`,
    });

    return { success: true };
  },
);

exports.sendBrmWelcomeEmail = onCall(
  {
    secrets: [smtpHost, smtpUser, smtpPass],
  },
  async (request) => {
    if (!request.auth) {
      throw new HttpsError("unauthenticated", "Authentication is required.");
    }

    const callerDoc = await db.collection("admins").doc(request.auth.uid).get();
    if (!callerDoc.exists || callerDoc.data()?.role !== "admin") {
      throw new HttpsError("permission-denied", "Only admins can send BRM welcome emails.");
    }

    const {
      email,
      firstName,
      lastName,
      password,
      referralCode,
      loginUrl,
    } = request.data || {};

    if (!email || !firstName || !lastName || !password || !referralCode) {
      throw new HttpsError(
        "invalid-argument",
        "email, firstName, lastName, password and referralCode are required.",
      );
    }

    const name = `${firstName} ${lastName}`.trim();
    const portalUrl = loginUrl || "https://padipay.co/brm/login";

    await sendNotifyEmail({
      to: String(email).trim().toLowerCase(),
      subject: "Your PadiPay BRM account is ready",
      html: `
        <div style="font-family:Arial,sans-serif;max-width:600px;margin:0 auto;padding:24px;color:#111827;">
          <h2 style="margin:0 0 16px;">Welcome to PadiPay BRM Portal</h2>
          <p style="margin:0 0 16px;">Hello ${name}, your BRM account has been created by the PadiPay admin team.</p>
          <div style="background:#f9fafb;border:1px solid #e5e7eb;border-radius:12px;padding:16px;">
            <p style="margin:0 0 8px;"><strong>Login URL:</strong> <a href="${portalUrl}">${portalUrl}</a></p>
            <p style="margin:0 0 8px;"><strong>Email:</strong> ${String(email).trim()}</p>
            <p style="margin:0 0 8px;"><strong>Password:</strong> ${password}</p>
            <p style="margin:0;"><strong>Referral code:</strong> ${referralCode}</p>
          </div>
          <p style="margin:16px 0 0;color:#6b7280;">For security, sign in and change this password as soon as possible.</p>
        </div>
      `,
      text: `Welcome to PadiPay BRM Portal\n\nHello ${name}, your BRM account has been created.\nLogin URL: ${portalUrl}\nEmail: ${String(email).trim()}\nPassword: ${password}\nReferral code: ${referralCode}\n\nFor security, sign in and change this password as soon as possible.`,
    });

    return { success: true };
  },
);

// -- Super Agent Portal Functions ----------------------------------------

// -- Super Agent Program (Business Model) -------------------------------

exports.getSuperAgentProgramSettings = onCall(async (request) => {
  await requireAdminCaller(request);
  const settings = await getSuperAgentProgramSettings();
  return { settings };
});

exports.updateSuperAgentProgramSettings = onCall(async (request) => {
  const adminUid = await requireAdminCaller(request);
  const {
    perNipTransferAmount,
    verifiedBusinessBonusAmount,
    starThresholds,
  } = request.data || {};

  if (typeof perNipTransferAmount !== "number" || perNipTransferAmount < 0) {
    throw new HttpsError("invalid-argument", "perNipTransferAmount must be a non-negative number.");
  }
  if (typeof verifiedBusinessBonusAmount !== "number" || verifiedBusinessBonusAmount < 0) {
    throw new HttpsError("invalid-argument", "verifiedBusinessBonusAmount must be a non-negative number.");
  }
  if (!starThresholds || typeof starThresholds !== "object") {
    throw new HttpsError("invalid-argument", "starThresholds is required.");
  }

  const normalizedThresholds = {};
  for (let i = 1; i <= 5; i++) {
    const raw = starThresholds[i] ?? starThresholds[String(i)];
    const value = Number(raw);
    if (Number.isNaN(value) || value < 0) {
      throw new HttpsError("invalid-argument", `starThresholds.${i} must be a non-negative number.`);
    }
    normalizedThresholds[i] = value;
  }

  await db.collection("settings").doc("superAgentProgram").set({
    perNipTransferAmount,
    verifiedBusinessBonusAmount,
    starThresholds: normalizedThresholds,
    updatedAt: admin.firestore.FieldValue.serverTimestamp(),
    updatedBy: adminUid,
  }, { merge: true });

  return { success: true };
});

exports.setBusinessSuperAgentStatus = onCall(
  { secrets: [smtpHost, smtpUser, smtpPass] },
  async (request) => {
    const adminUid = await requireAdminCaller(request);
    const { businessId, isSuperAgent } = request.data || {};

    if (!businessId || typeof isSuperAgent !== "boolean") {
      throw new HttpsError("invalid-argument", "businessId and boolean isSuperAgent are required.");
    }

    const businessRef = db.collection("businesses").doc(String(businessId));
    const businessSnap = await businessRef.get();
    if (!businessSnap.exists) {
      throw new HttpsError("not-found", "Business account not found.");
    }

    const data = businessSnap.data() || {};
    const updates = {
      isSuperAgent,
      superAgentStatusUpdatedAt: admin.firestore.FieldValue.serverTimestamp(),
      superAgentStatusUpdatedBy: adminUid,
    };

    if (isSuperAgent && !data.superAgentReferralCode) {
      const code = await generateBusinessSuperAgentCode();
      updates.superAgentReferralCode = code;
      updates.superAgentEnabledAt = admin.firestore.FieldValue.serverTimestamp();
      updates.superAgentTotalEarnings = Number(data.superAgentTotalEarnings || 0);
      updates.superAgentAvailableEarnings = Number(data.superAgentAvailableEarnings || 0);
      updates.superAgentStars = Number(data.superAgentStars || 0);
    }

    if (!isSuperAgent) {
      updates.superAgentDisabledAt = admin.firestore.FieldValue.serverTimestamp();
    }

    await businessRef.set(updates, { merge: true });

    if (isSuperAgent) {
      const to = String(data.businessEmail || data.email || "").trim().toLowerCase();
      if (to) {
        const name = String(data.businessName || "Business Owner").trim();
        const referralCode = updates.superAgentReferralCode || data.superAgentReferralCode || "N/A";
        await sendNotifyEmail({
          to,
          subject: "You are now a PadiPay Super Agent",
          html: `<div style="font-family:Arial,sans-serif;max-width:600px;margin:0 auto;padding:24px;color:#111827;"><h2 style="margin:0 0 16px;">Welcome to the PadiPay Super Agent Program</h2><p style="margin:0 0 12px;">Hello ${name}, your business account has been enabled as a Super Agent.</p><p style="margin:0 0 8px;"><strong>Referral code:</strong> ${referralCode}</p><p style="margin:0;color:#6b7280;">You can now earn rewards when referred businesses verify and transact.</p></div>`,
          text: `Hello ${name}, your business account is now a PadiPay Super Agent. Referral code: ${referralCode}.`,
        });
      }
    }

    return {
      success: true,
      businessId,
      isSuperAgent,
      superAgentReferralCode: updates.superAgentReferralCode || data.superAgentReferralCode || null,
    };
  },
);

exports.sendSuperAgentLoginEmail = onCall(
  { secrets: [smtpHost, smtpUser, smtpPass] },
  async (request) => {
    if (!request.auth) {
      throw new HttpsError("unauthenticated", "Authentication is required.");
    }

    const agentDoc = await db.collection("superAgents").doc(request.auth.uid).get();
    if (!agentDoc.exists) {
      throw new HttpsError("permission-denied", "Super Agent profile not found.");
    }

    const agentData = agentDoc.data() || {};
    const to = String(agentData.email || "").trim();
    if (!to) {
      throw new HttpsError("failed-precondition", "Super Agent email is missing.");
    }

    const { userAgent } = request.data || {};
    const name = agentData.full_name || agentData.first_name || "Super Agent";
    const loggedAt = new Date().toLocaleString("en-NG", { timeZone: "Africa/Lagos" });

    await sendNotifyEmail({
      to,
      subject: "PadiPay Super Agent login detected",
      html: `
        <div style="font-family:Arial,sans-serif;max-width:600px;margin:0 auto;padding:24px;color:#111827;">
          <h2 style="margin:0 0 16px;">Super Agent portal login detected</h2>
          <p style="margin:0 0 16px;">Hello ${name}, your Super Agent account was just used to sign in.</p>
          <div style="background:#f9fafb;border:1px solid #e5e7eb;border-radius:12px;padding:16px;">
            <p style="margin:0 0 8px;"><strong>Time:</strong> ${loggedAt}</p>
            <p style="margin:0 0 8px;"><strong>Referral code:</strong> ${agentData.referral_code || "Unavailable"}</p>
            <p style="margin:0;"><strong>Device:</strong> ${userAgent || "Unavailable"}</p>
          </div>
          <p style="margin:16px 0 0;color:#6b7280;">If this was not you, reset your password immediately.</p>
        </div>
      `,
      text: `Super Agent portal login detected\n\nHello ${name}, your Super Agent account was just used to sign in.\nTime: ${loggedAt}\nReferral code: ${agentData.referral_code || "Unavailable"}\nDevice: ${userAgent || "Unavailable"}\n\nIf this was not you, reset your password immediately.`,
    });

    return { success: true };
  },
);

exports.sendSuperAgentWelcomeEmail = onCall(
  { secrets: [smtpHost, smtpUser, smtpPass] },
  async (request) => {
    if (!request.auth) {
      throw new HttpsError("unauthenticated", "Authentication is required.");
    }

    const callerDoc = await db.collection("admins").doc(request.auth.uid).get();
    if (!callerDoc.exists || callerDoc.data()?.role !== "admin") {
      throw new HttpsError("permission-denied", "Only admins can send Super Agent welcome emails.");
    }

    const { email, firstName, lastName, password, referralCode, loginUrl } = request.data || {};

    if (!email || !firstName || !lastName || !password || !referralCode) {
      throw new HttpsError(
        "invalid-argument",
        "email, firstName, lastName, password and referralCode are required.",
      );
    }

    const name = `${firstName} ${lastName}`.trim();
    const portalUrl = loginUrl || "https://padipay.co/super-agent/login";

    await sendNotifyEmail({
      to: String(email).trim().toLowerCase(),
      subject: "Your PadiPay Super Agent account is ready",
      html: `
        <div style="font-family:Arial,sans-serif;max-width:600px;margin:0 auto;padding:24px;color:#111827;">
          <h2 style="margin:0 0 16px;">Welcome to PadiPay Super Agent Portal</h2>
          <p style="margin:0 0 16px;">Hello ${name}, your Super Agent account has been created by the PadiPay admin team.</p>
          <div style="background:#f9fafb;border:1px solid #e5e7eb;border-radius:12px;padding:16px;">
            <p style="margin:0 0 8px;"><strong>Login URL:</strong> <a href="${portalUrl}">${portalUrl}</a></p>
            <p style="margin:0 0 8px;"><strong>Email:</strong> ${String(email).trim()}</p>
            <p style="margin:0 0 8px;"><strong>Password:</strong> ${password}</p>
            <p style="margin:0;"><strong>Referral code:</strong> ${referralCode}</p>
          </div>
          <p style="margin:16px 0 0;color:#6b7280;">For security, sign in and change this password as soon as possible.</p>
          <p style="margin:8px 0 0;color:#6b7280;">Share your referral code with business owners to earn commissions on their NIP transfers.</p>
        </div>
      `,
      text: `Welcome to PadiPay Super Agent Portal\n\nHello ${name}, your Super Agent account has been created.\nLogin URL: ${portalUrl}\nEmail: ${String(email).trim()}\nPassword: ${password}\nReferral code: ${referralCode}\n\nFor security, sign in and change this password as soon as possible.`,
    });

    return { success: true };
  },
);

// List Billers (generic for any category)
exports.safehavenGetServiceCategories = onCallLogged(
  "safehavenGetServiceCategories",
  { secrets: [safehavenClientId, safehavenPrivateKey, safehavenCompanyUrl] },
  async (data, context) => {
    await ensureVerifiedOrStandUser(data.auth);
    validateData(data.data, [
      {
        key: "category",
        message: "Category is required",
        validator: (v) =>
          ["airtime", "data", "electricity", "television"].includes(
            v.toLowerCase(),
          ),
      },
    ]);

    const category = data.data.category.trim().toLowerCase();

    const servicesResp = await safehavenRequest({
      path: "/vas/services",
      method: "GET",
    });
    const services = Array.isArray(servicesResp.data) ? servicesResp.data : [];

    const keywords = {
      airtime: ["airtime"],
      data: ["data"],
      electricity: ["electricity", "power", "utility"],
      television: ["television", "cable", "tv"],
    };
    const lookup = keywords[category] || [category];

    const service = services.find((item) => {
      const haystack = `${item?.name || ""} ${item?.identifier || ""}`.toLowerCase();
      return lookup.some((word) => haystack.includes(word));
    });

    if (!service?._id) {
      throw new HttpsError("not-found", `No Safehaven service found for ${category}`);
    }

    const categoriesResp = await safehavenRequest({
      path: `/vas/service/${encodeURIComponent(service._id)}/service-categories`,
      method: "GET",
    });
    const billers = Array.isArray(categoriesResp.data) ? categoriesResp.data : [];

    return {
      data: billers.map((biller) => ({
        id: biller._id || biller.identifier,
        type: "Biller",
        attributes: {
          name: biller.name || biller.identifier || "",
          slug: biller.identifier || biller._id,
          category,
          logoUrl: biller.logoUrl || null,
          amountType: biller.isFixedAmount ? "FIXED" : "VARIABLE",
        },
        _safehaven: biller,
      })),
    };
  },
);

// Get Biller Products (generic for any biller)
exports.safehavenGetCategoryProducts = onCallLogged(
  "safehavenGetCategoryProducts",
  { secrets: [safehavenClientId, safehavenPrivateKey, safehavenCompanyUrl] },
  async (data, context) => {
    await ensureVerifiedOrStandUser(data.auth);
    validateData(data.data, [
      { key: "billerId", message: "Biller ID is required" },
    ]);

    const serviceCategoryId = data.data.billerId.trim();

    const resp = await safehavenRequest({
      path: `/vas/service-category/${encodeURIComponent(serviceCategoryId)}/products`,
      method: "GET",
    });
    const products = Array.isArray(resp.data) ? resp.data : [];

    return {
      data: products.map((product) => {
        const amountKobo =
          product.amount == null ? 0 : Math.round(Number(product.amount) * 100);
        return {
          id: product.bundleCode || product.slug || product.name,
          type: "BillerProduct",
          attributes: {
            slug: product.bundleCode || product.slug || product.name,
            name: product.name || "",
            duration: product.duration || null,
            isAmountFixed: Boolean(product.isAmountFixed),
            price: {
              minimumAmount: amountKobo,
              maximumAmount: product.isAmountFixed ? amountKobo : null,
            },
          },
          _safehaven: product,
        };
      }),
    };
  },
);
exports.uploadDocument = onCall(
  { secrets: [getanchorSecretKey] },
  async (data, context) => {
    await ensureVerifiedOrStandUser(data.auth);
    await _assertAnchorLegacyEnabled();

    const secretKey = getanchorSecretKey.value();

    if (secretKey.length === 0) {
      throw new HttpsError(
        "invalid-argument",
        "Getanchor Secret Key is not set",
      );
    }

    const payload = data.data;
    console.log(payload);

    const { customerId, documentId, storagePath, fileName, textData } = payload;

    if (!customerId || !documentId) {
      throw new HttpsError(
        "invalid-argument",
        "customerId and documentId are required",
      );
    }

    const url = `https://api.sandbox.getanchor.co/api/v1/documents/upload-document/${encodeURIComponent(
      customerId,
    )}/${encodeURIComponent(documentId)}`;

    const formData = new FormData();
    let hasData = false;

    if (storagePath) {
      const bucket = admin.storage().bucket(); // default bucket
      const file = bucket.file(storagePath.trim());

      const [metadata] = await file.getMetadata().catch((err) => {
        throw new HttpsError("not-found", "File not found in storage");
      });

      const usedFileName =
        fileName?.trim() || file.name.split("/").pop() || "document";

      // Download file to buffer ? create Blob (required by Node.js/undici FormData for file parts)
      const [buffer] = await file.download();

      const blob = new Blob([buffer], {
        type: metadata.contentType || "application/octet-stream",
      });

      formData.append("fileData", blob, usedFileName);
      hasData = true;
    }

    if (textData && textData.trim().length > 0) {
      formData.append("textData", textData.trim());
      hasData = true;
    }

    if (!hasData) {
      throw new HttpsError(
        "invalid-argument",
        "Must provide either file or text data",
      );
    }

    const options = {
      method: "POST",
      headers: {
        accept: "application/json",
        "x-anchor-key": secretKey,
        // FormData sets the correct Content-Type + boundary automatically
      },
      body: formData,
    };

    const response = await fetch(url, options);

    if (!response.ok) {
      const errorText = await response.text();
      console.error("Anchor upload failed:", response.status, errorText);
      throw new HttpsError(
        "internal",
        `Anchor upload failed: ${response.status} ${errorText}`,
      );
    }

    const json = await response.json();

    return json;
  },
);
exports.fetchCustomer = onCall(
  { secrets: [getanchorSecretKey] },
  async (data, context) => {
    await ensureVerifiedOrStandUser(data.auth);

    const secretKey = getanchorSecretKey.value();
    if (secretKey.length === 0) {
      throw new HttpsError(
        "invalid-argument",
        "Getanchor Secret Key is not set",
      );
    }

    validateData(data.data, [
      { key: "customerId", message: "Customer ID is required" },
    ]);

    const customerId = data.data.customerId.trim();
    
    const url = `${BASE_URL}/customers/${encodeURIComponent(customerId)}`;

    const response = await makeApiRequest({ url, method: "GET", secretKey });

    // <<< THIS IS ADDED ? logs the full raw Anchor API response to Cloud Functions logs
    console.log("=== ANCHOR FETCH CUSTOMER RAW RESPONSE ===");
    console.log(JSON.stringify(response, null, 2));
    console.log("==============================================");

    return response;
  },
);

exports.fetchCustomerVirtualAccount = onCall(
  { secrets: [getanchorSecretKey] },
  async (data, context) => {
    await ensureVerifiedOrStandUser(data.auth);

    const secretKey = getanchorSecretKey.value();
    if (secretKey.length === 0) {
      throw new HttpsError(
        "invalid-argument",
        "Getanchor Secret Key is not set",
      );
    }

    validateData(data.data, [
      { key: "customerId", message: "Customer ID is required" },
    ]);

    const customerId = data.data.customerId.trim();
    
    const url = `${BASE_URL}/customers/${encodeURIComponent(customerId)}?include=DepositAccount`;

    const response = await makeApiRequest({ url, method: "GET", secretKey });

    // <<< THIS IS ADDED ? logs the full raw Anchor API response to Cloud Functions logs
    console.log("=== ANCHOR FETCH CUSTOMER RAW RESPONSE ===");
    console.log(JSON.stringify(response, null, 2));
    console.log("==============================================");

    return response;
  },
);

exports.fetchCustomerAccount = onCall(
  { secrets: [getanchorSecretKey] },
  async (data, context) => {
    await ensureVerifiedOrStandUser(data.auth);
    const secretKey = getanchorSecretKey.value();
    if (secretKey.length === 0) {
      throw new HttpsError(
        "invalid-argument",
        "Getanchor Secret Key is not set",
      );
    }

    validateData(data.data, [
      { key: "accountId", message: "Account ID is required" },
    ]);

    const accountId = data.data.accountId.trim();
    
    const url = `${BASE_URL}/accounts/${encodeURIComponent(accountId)}`;

    return makeApiRequest({ url, method: "GET", secretKey });
  },
);
// Verify meter number or smart card number before payment
exports.safehavenVerifyVas = onCallLogged(
  "safehavenVerifyVas",
  { secrets: [safehavenClientId, safehavenPrivateKey, safehavenCompanyUrl] },
  async (data, context) => {
    await ensureVerifiedOrStandUser(data.auth);
    validateData(data.data, [
      { key: "serviceCategoryId", message: "Service category ID is required" },
      { key: "entityNumber", message: "Entity number (meter/card number) is required" },
    ]);

    const resp = await safehavenRequest({
      path: "/vas/verify",
      method: "POST",
      body: {
        serviceCategoryId: data.data.serviceCategoryId.trim(),
        entityNumber: data.data.entityNumber.trim(),
      },
    });

    return { data: resp?.data || resp };
  },
);

// Initiate Bill Payment (generic for airtime, data, electricity, cabletv)
exports.safehavenPurchaseVas = onCallLogged(
  "safehavenPurchaseVas",
  { secrets: [safehavenClientId, safehavenPrivateKey, safehavenCompanyUrl] },
  async (data, context) => {
    await ensureVerifiedOrStandUser(data.auth);
    const uid = data.auth?.uid;
    if (!uid) throw new HttpsError("unauthenticated", "User is not authenticated");

    validateData(data.data, [
      {
        key: "type",
        message: "Type is required",
        validator: (v) =>
          ["Airtime", "Data", "Electricity", "Television"].includes(v),
      },
      { key: "accountId", message: "Account ID is required" },
      {
        key: "amount",
        message: "Valid amount is required",
        validator: (v) => typeof v === "number" && v > 0,
      },
      { key: "reference", message: "Reference is required" },
    ]);

    const type = data.data.type.trim();
    const accountId = data.data.accountId.trim();
    const amount = data.data.amount;
    const reference = data.data.reference.trim();
    const serviceCategoryRaw = (data.data.provider || data.data.productSlug || "").trim();
    if (!serviceCategoryRaw) {
      throw new HttpsError("invalid-argument", "Provider or product slug is required");
    }

    let serviceCategoryId = serviceCategoryRaw;
    const looksLikeObjectId = /^[a-f0-9]{24}$/i.test(serviceCategoryRaw);
    if (!looksLikeObjectId) {
      const servicesResp = await safehavenRequest({
        path: "/vas/services",
        method: "GET",
      });
      const services = Array.isArray(servicesResp.data) ? servicesResp.data : [];

      const typeToServiceKeywords = {
        Airtime: ["airtime"],
        Data: ["data"],
        Electricity: ["electricity", "power", "utility"],
        Television: ["television", "cable", "tv"],
      };

      const lookup = typeToServiceKeywords[type] || [type.toLowerCase()];
      const service = services.find((item) => {
        const haystack = `${item?.name || ""} ${item?.identifier || ""}`.toLowerCase();
        return lookup.some((word) => haystack.includes(word));
      });

      if (service?._id) {
        const categoriesResp = await safehavenRequest({
          path: `/vas/service/${encodeURIComponent(service._id)}/service-categories`,
          method: "GET",
        });
        const categories = Array.isArray(categoriesResp.data) ? categoriesResp.data : [];
        const target = serviceCategoryRaw.toLowerCase();

        const matchedCategory = categories.find((item) => {
          const idText = String(item?._id || "").toLowerCase();
          const identifierText = String(item?.identifier || "").toLowerCase();
          const nameText = String(item?.name || "").toLowerCase();
          return idText === target ||
            identifierText === target ||
            nameText === target ||
            nameText.includes(target);
        });

        if (matchedCategory?._id) {
          serviceCategoryId = String(matchedCategory._id);
        }
      }
    }

    const acctInfo = await _getSafehavenAccountForUser(uid);
    let debitAccountNumber = acctInfo?.accountNumber || "";
    if (!debitAccountNumber || (accountId && acctInfo?.accountId && acctInfo.accountId !== accountId)) {
      const accountResp = await safehavenRequest({
        path: `/accounts/${encodeURIComponent(accountId)}`,
        method: "GET",
      });
      debitAccountNumber = accountResp?.data?.accountNumber || debitAccountNumber;
    }
    if (!debitAccountNumber) {
      throw new HttpsError("failed-precondition", "Virtual account not set up");
    }

    let safehavenPath = "";
    let requestPayload = {};
    switch (type) {
      case "Airtime":
        validateData(data.data, [
          { key: "phoneNumber", message: "Phone number is required" },
        ]);
        safehavenPath = "/vas/pay/airtime";
        requestPayload = {
          amount: amount / 100,
          channel: "WEB",
          serviceCategoryId,
          debitAccountNumber,
          phoneNumber: data.data.phoneNumber.trim(),
        };
        break;
      case "Data":
        validateData(data.data, [
          { key: "phoneNumber", message: "Phone number is required" },
          { key: "productSlug", message: "Product slug is required" },
        ]);
        safehavenPath = "/vas/pay/data";
        requestPayload = {
          amount: amount / 100,
          channel: "WEB",
          serviceCategoryId,
          bundleCode: data.data.productSlug.trim(),
          debitAccountNumber,
          phoneNumber: data.data.phoneNumber.trim(),
        };
        break;
      case "Electricity":
        validateData(data.data, [
          { key: "meterAccountNumber", message: "Meter number is required" },
          { key: "vendType", message: "Vend type is required (call safehavenVerifyVas first)" },
        ]);
        safehavenPath = "/vas/pay/utility";
        requestPayload = {
          amount: amount / 100,
          channel: "WEB",
          serviceCategoryId,
          debitAccountNumber,
          meterNumber: data.data.meterAccountNumber.trim(),
          vendType: data.data.vendType.trim(),
          externalReference: reference,
        };
        break;
      case "Television":
        validateData(data.data, [
          { key: "smartCardNumber", message: "Smart card number is required" },
        ]);
        safehavenPath = "/vas/pay/cable-tv";
        requestPayload = {
          amount: amount / 100,
          channel: "WEB",
          serviceCategoryId,
          bundleCode: data.data.productSlug?.trim() || serviceCategoryId,
          debitAccountNumber,
          cardNumber: data.data.smartCardNumber.trim(),
        };
        break;
      default:
        throw new HttpsError("invalid-argument", "Invalid bill type");
    }

    const resp = await safehavenRequest({
      path: safehavenPath,
      method: "POST",
      body: requestPayload,
    });

    const bill = resp?.data || {};
    const baseAttributes = {
      amount,
      reference,
      status: bill.status || (resp?.responseCode === "00" ? "successful" : "PENDING"),
      channel: requestPayload.channel || "WEB",
      providerReference: bill.reference || bill.id || reference,
      receiver: bill.receiver || null,
      message: resp?.message || null,
      failureReason: resp?.message || null,
      createdAt: new Date().toISOString(),
      detail: {
        provider: bill?.receiver?.distribution || serviceCategoryId,
        product: data.data.productSlug || serviceCategoryId,
        token: bill?.token || bill?.unitsToken || null,
        units: bill?.units || null,
      },
    };

    if (type === "Airtime" || type === "Data") {
      baseAttributes.phoneNumber = data.data.phoneNumber?.trim() || null;
    }
    if (type === "Television") {
      baseAttributes.smartCardNumber = data.data.smartCardNumber?.trim() || null;
      baseAttributes.detail.smartCardNumber = baseAttributes.smartCardNumber;
    }
    if (type === "Electricity") {
      baseAttributes.meterNumber = data.data.meterAccountNumber?.trim() || null;
      baseAttributes.meterAccountNumber = baseAttributes.meterNumber;
    }

    return {
      data: {
        id: bill.id || bill.reference || reference,
        type,
        attributes: baseAttributes,
        _safehaven: resp,
      },
    };
  },
);
exports.sendTransactionNotification = onCall(
  { secrets: [getanchorSecretKey] },
  async (data, context) => {
    await ensureVerifiedOrStandUser(data.auth);
    const secretKey = getanchorSecretKey.value();
    if (secretKey.length === 0) {
      throw new HttpsError(
        "invalid-argument",
        "Getanchor Secret Key is not set",
      );
    }

    validateData(data.data, [
      { key: "transactionAmount", message: "Transaction amount is required" },

      {
        key: "destinationAccountId",
        message: "Destination account ID is required",
      },
    ]);

    const transactionAmount = data.data.transactionAmount;

    const destinationAccountId = data.data.destinationAccountId.trim();

    const url =
      "https://api.sandbox.getanchor.co/api/v1/transaction-notification";

    const payload = {
      data: {
        type: "Notification",
        attributes: {
          transactionAmount,
          sourceAccount: {
            accountName: "",
            accountNumber: "",
          },
        },
        relationships: {
          destinationAccount: {
            data: {
              id: destinationAccountId,
              type: "VirtualNuban",
            },
          },
        },
      },
    };

    return makeApiRequest({ url, method: "POST", secretKey, payload });
  },
);

const bridgecardValidateData = (data, requiredFields) => {
  if (!data || typeof data !== "object") {
    throw new HttpsError("invalid-argument", "Invalid data format");
  }

  requiredFields.forEach(({ key, message, validator }) => {
    const rawValue = data[key];
    const value = typeof rawValue === "string" ? rawValue.trim() : rawValue;

    if (
      value === undefined ||
      value === null ||
      value === "" ||
      (validator && !validator(value))
    ) {
      throw new HttpsError("invalid-argument", message);
    }
  });
};

// Helper function to make API requests
// SECURITY: Always pass secretKey from the Firebase Secret Manager (bridgecardSecretKey.value()).
// Never hardcode the API token here ? it would be committed to source control and
// exposed in Cloud Functions logs. All callers must supply the resolved secret.
const bridgecardMakeApiRequest = async ({
  url,
  method,
  secretKey,
  body = null,
}) => {
  const headers = {
    accept: "application/json",
    token: `Bearer ${secretKey}`,
  };
  if (method === "POST" || method === "PUT" || method === "PATCH") {
    headers["content-type"] = "application/json";
  }

  const options = { method, headers };
  if (body) {
    options.body = JSON.stringify(body);
  }

  console.log(`Request to ${url}:`, {
    method,
    headers: { ...headers, token: "[REDACTED]" },
    body: body ? JSON.stringify(body) : null,
  });

  try {
    const response = await fetch(url, options);
    const responseText = await response.text();

    console.log(`Response status for ${url}:`, response.status);
    console.log(`Response body for ${url}:`, responseText);

    if (!response.ok) {
      throw new HttpsError(
        "internal",
        `HTTP ${response.status}: ${responseText}`,
      );
    }

    const json = JSON.parse(responseText);
    if (json.status !== "success") {
      throw new HttpsError(
        "internal",
        `Bridgecard API error: ${json.message || "Unknown error"}`,
      );
    }

    return json;
  } catch (err) {
    console.error(`Fetch error for ${url}:`, err);
    throw new HttpsError("internal", err.message);
  }
};

exports.bridgecardCreateCardholderAsynchronous = onCall(
  { secrets: [bridgecardSecretKey] },
  async (data, context) => {
    await ensureVerifiedOrStandUser(data.auth);
    const secretKey = bridgecardSecretKey.value();
    if (secretKey.length === 0) {
      throw new HttpsError(
        "invalid-argument",
        "Bridgecard Secret Key is not set",
      );
    }

    bridgecardValidateData(data.data, [
      { key: "first_name", message: "First name is required" },
      { key: "last_name", message: "Last name is required" },
      { key: "address", message: "Address is required" },
      { key: "phone", message: "Phone is required" },
      { key: "email_address", message: "Email address is required" },
      { key: "identity", message: "Identity is required" },
    ]);

    const body = {
      first_name: data.data.first_name.trim(),
      last_name: data.data.last_name.trim(),
      address: data.data.address,
      phone: data.data.phone.trim(),
      email_address: data.data.email_address.trim(),
      identity: data.data.identity,
      meta_data: data.data.meta_data || {},
    };

    const url = `${bridgecardBaseUrl}cardholder/register_cardholder`;

    return bridgecardMakeApiRequest({ url, method: "POST", secretKey, body });
  },
);

exports.bridgecardCreateUsdCard = onCall(
  { secrets: [bridgecardSecretKey] },
  async (data, context) => {
    await ensureVerifiedOrStandUser(data.auth);
    const secretKey = bridgecardSecretKey.value();
    if (secretKey.length === 0) {
      throw new HttpsError(
        "invalid-argument",
        "Bridgecard Secret Key is not set",
      );
    }

    bridgecardValidateData(data.data, [
      { key: "cardholder_id", message: "Cardholder ID is required" },
      { key: "card_type", message: "Card type is required" },
      { key: "card_brand", message: "Card brand is required" },
      { key: "card_currency", message: "Card currency is required" },
      { key: "card_limit", message: "Card limit is required" },
      { key: "funding_amount", message: "Funding amount is required" },
      { key: "pin", message: "PIN is required" },
    ]);

    const encryptedPin = AES256.encrypt(data.data.pin.trim(), secretKey);

    const body = {
      cardholder_id: data.data.cardholder_id.trim(),
      card_type: data.data.card_type.trim(),
      card_brand: data.data.card_brand.trim(),
      card_currency: data.data.card_currency.trim(),
      card_limit: data.data.card_limit,
      transaction_reference: data.data.transaction_reference
        ? data.data.transaction_reference.trim()
        : "",
      funding_amount: data.data.funding_amount,
      pin: encryptedPin,
      meta_data: data.data.meta_data || {},
    };

    const url = `${bridgecardBaseUrl}cards/create_card`;

    return bridgecardMakeApiRequest({ url, method: "POST", secretKey, body });
  },
);

exports.bridgecardCreateNgnCard = onCall(
  { secrets: [bridgecardSecretKey] },
  async (data, context) => {
    await ensureVerifiedOrStandUser(data.auth);
    const secretKey = bridgecardSecretKey.value();
    if (secretKey.length === 0) {
      throw new HttpsError(
        "invalid-argument",
        "Bridgecard Secret Key is not set",
      );
    }

    bridgecardValidateData(data.data, [
      { key: "cardholder_id", message: "Cardholder ID is required" },
      { key: "card_type", message: "Card type is required" },
      { key: "card_brand", message: "Card brand is required" },
      { key: "card_currency", message: "Card currency is required" },
      { key: "pin", message: "PIN is required" },
      { key: "nin", message: "NIN is required" },
    ]);

    const encryptedPin = AES256.encrypt(data.data.pin.trim(), secretKey);

    const body = {
      cardholder_id: data.data.cardholder_id.trim(),
      card_type: data.data.card_type.trim(),
      card_brand: data.data.card_brand.trim(),
      card_currency: data.data.card_currency.trim(),
      pin: encryptedPin,
      nin: data.data.nin.trim(),
      meta_data: data.data.meta_data || {},
    };

    const url = `${bridgecardBaseUrl}cards/create_card`;

    return bridgecardMakeApiRequest({ url, method: "POST", secretKey, body });
  },
);

exports.bridgecardFundIssuingWallet = onCall(
  { secrets: [bridgecardSecretKey] },
  async (data, context) => {
    await ensureVerifiedOrStandUser(data.auth);
    const secretKey = bridgecardSecretKey.value();
    if (secretKey.length === 0) {
      throw new HttpsError(
        "invalid-argument",
        "Bridgecard Secret Key is not set",
      );
    }

    bridgecardValidateData(data.data, [
      { key: "currency", message: "Currency is required" },
      { key: "amount", message: "Amount is required" },
    ]);

    const body = {
      amount: data.data.amount.trim(),
    };

    const url = `${bridgecardBaseUrl}cards/fund_issuing_wallet?currency=${encodeURIComponent(
      data.data.currency.trim(),
    )}`;

    return bridgecardMakeApiRequest({ url, method: "PATCH", secretKey, body });
  },
);

exports.bridgecardGetIssuingWalletBalance = onCall(
  { secrets: [bridgecardSecretKey] },
  async (data, context) => {
    await ensureVerifiedOrStandUser(data.auth);
    const secretKey = bridgecardSecretKey.value();
    if (secretKey.length === 0) {
      throw new HttpsError(
        "invalid-argument",
        "Bridgecard Secret Key is not set",
      );
    }

    const url = `${bridgecardBaseUrl}cards/get_issuing_wallet_balance`;

    return bridgecardMakeApiRequest({ url, method: "GET", secretKey });
  },
);

exports.bridgecardGetFxRate = onCall(
  { secrets: [bridgecardSecretKey] },
  async (data, context) => {
    await ensureVerifiedOrStandUser(data.auth);
    const secretKey = bridgecardSecretKey.value();
    if (secretKey.length === 0) {
      throw new HttpsError(
        "invalid-argument",
        "Bridgecard Secret Key is not set",
      );
    }

    const url = `https://issuecards.api.bridgecard.co/v1/issuing/cards/fx-rate`;

    return bridgecardMakeApiRequest({ url, method: "GET", secretKey });
  },
);

exports.bridgecardGetAllStates = onCall(
  { secrets: [bridgecardSecretKey] },
  async (data, context) => {
    await ensureVerifiedOrStandUser(data.auth);
    const secretKey = bridgecardSecretKey.value();
    if (secretKey.length === 0) {
      throw new HttpsError(
        "invalid-argument",
        "Bridgecard Secret Key is not set",
      );
    }

    bridgecardValidateData(data.data, [
      { key: "country", message: "Country is required" },
    ]);

    const url = `${bridgecardBaseUrl}cardholder/get_all_states?country=${encodeURIComponent(
      data.data.country.trim(),
    )}`;

    return bridgecardMakeApiRequest({ url, method: "GET", secretKey });
  },
);

exports.bridgecardWebhookHandler = onRequest(
  { secrets: [bridgecardSecretKey, bridgecardWebhookSecret] },
  async (req, res) => {
    if (req.method !== "POST") {
      return res.status(405).send("Method Not Allowed");
    }

    const signature = req.headers["x-webhook-signature"];
    if (!signature) {
      return res.status(401).send("Missing signature");
    }

    const apiKey = bridgecardSecretKey.value();
    const webhookKey = bridgecardWebhookSecret.value();
    if (apiKey.length === 0 || webhookKey.length === 0) {
      return res.status(500).send("Secrets not set");
    }

    let decrypted;
    try {
      decrypted = AES256.decrypt(signature, apiKey);
    } catch (err) {
      console.error("Decryption error:", err);
      return res.status(401).send("Invalid signature");
    }

    if (decrypted !== webhookKey) {
      return res.status(401).send("Signature mismatch");
    }

    const event = req.body.event;
    const eventData = req.body.data;

    // Handle the event (add your logic here, e.g., update database)
    console.log("Received webhook event:", event, eventData);

    // Helper function to find user by cardholder_id
    async function findUser(cardholderId) {
      const querySnapshot = await db
        .collection("users")
        .where("bridgeCard.cardholder_id", "==", cardholderId)
        .get();
      if (!querySnapshot.empty) {
        return querySnapshot.docs[0];
      }
      return null;
    }

    // Helper function to send notification and email
    async function sendNotification(userDoc, title, body) {
      const userData = userDoc.data();
      const deviceToken = userData.deviceToken;
      const email = userData.email;

      // Send push notification
      if (deviceToken) {
        const message = {
          notification: {
            title: title,
            body: body,
          },
          token: deviceToken,
          ...FCM_CHANNEL,
        };
        try {
          await admin.messaging().send(message);
          console.log("Notification sent successfully");
        } catch (err) {
          console.error("Error sending notification:", err);
        }
      }

      // Send email notification
      if (email) {
        try {
          await sendNotifyEmail({
            to: email,
            subject: title,
            text: body,
            html: `<p>${body}</p>`,
          });
          console.log("Email notification sent successfully to:", email);
        } catch (err) {
          console.error("Error sending email notification:", err);
        }
      }
    }

    // Helper function to add transaction
    async function addTransaction(userDoc, event, eventData) {
      const userId = userDoc.id;
      const transactionRef = admin
        .firestore()
        .collection("transactions")
        .doc(eventData.transaction_reference || Date.now().toString());
      await transactionRef.set({
        userId: userId,
        event: event,
        ...eventData,
        timestamp: admin.firestore.FieldValue.serverTimestamp(),
      });
      console.log(`Transaction added for event: ${event}`);
    }

    const cardholderId = eventData.cardholder_id;
    if (cardholderId) {
      const userDoc = await findUser(cardholderId);
      if (userDoc) {
        if (
          event === "cardholder_verification.successful" ||
          event === "cardholder_verification.failed"
        ) {
          const isActive = eventData.is_active;
          await userDoc.ref.update({
            "bridgeCard.is_active": isActive,
          });
          if (eventData.error_description) {
            await userDoc.ref.update({
              "bridgeCard.error_description": eventData.error_description,
            });
          }
          const status = event.split(".")[1];
          // await sendNotification(
          //   userDoc,
          //   "Cardholder Verification",
          //   `Your verification ${status}.`,
          // );
        }

        if (event === "card_creation_event.successful") {
          const currency = eventData.currency;
          await sendNotification(
            userDoc,
            currency + " Card Created",
            `Your ${currency} card has been created successfully!`,
          );
        }

        if (event === "card_creation_event.failed") {
          const currency = eventData.currency;
          const reason = eventData.reason || "Unknown reason";
          await sendNotification(
            userDoc,
            currency + " Card Creation Failed",
            `Your ${currency} card creation failed: ${reason}`,
          );
        }

        if (event === "card_credit_event.successful") {
          await addTransaction(userDoc, event, eventData);
          const amount = eventData.amount;
          const currency = eventData.currency;
          await sendNotification(
            userDoc,
            "Card Funded",
            `Your card has been funded with ${amount / 100} ${currency}.`,
          );
        }

        if (event === "card_credit_event.failed") {
          await addTransaction(userDoc, event, eventData);
          const amount = eventData.amount;
          const currency = eventData.currency;
          await sendNotification(
            userDoc,
            "Card Funding Failed",
            `Funding of ${amount} ${currency} to your card failed.`,
          );
        }

        if (event === "card_unload_event.successful") {
          await addTransaction(userDoc, event, eventData);
          const amount = eventData.amount;
          const currency = eventData.currency;
          await sendNotification(
            userDoc,
            "Card Unloaded",
            `Your card has been unloaded by ${amount} ${currency}.`,
          );
        }

        if (event === "card_unload_event.failed") {
          await addTransaction(userDoc, event, eventData);
          const amount = eventData.amount;
          const currency = eventData.currency;
          await sendNotification(
            userDoc,
            "Card Unload Failed",
            `Unloading ${amount} ${currency} from your card failed.`,
          );
        }

        if (event === "card_debit_event.successful") {
          await addTransaction(userDoc, event, eventData);
          const amount = eventData.amount;
          const currency = eventData.currency;
          const description = eventData.description || "Unknown merchant";
          await sendNotification(
            userDoc,
            "Card Debited",
            `Your card was debited ${amount} ${currency} at ${description}.`,
          );
        }

        if (event === "card_debit_event.declined") {
          await addTransaction(userDoc, event, eventData);
          const amount = eventData.amount;
          const currency = eventData.currency;
          const declineReason = eventData.decline_reason || "Unknown reason";
          await sendNotification(
            userDoc,
            "Transaction Declined",
            `A transaction of ${amount} ${currency} was declined: ${declineReason}`,
          );
        }

        if (event === "card_reversal_event.successful") {
          await addTransaction(userDoc, event, eventData);
          const amount = eventData.amount;
          const currency = eventData.currency;
          await sendNotification(
            userDoc,
            "Card Reversal",
            `A reversal of ${amount} ${currency} has been applied to your card.`,
          );
        }

        if (event === "card_delete_event.notification") {
          const currency = eventData.currency;
          const potentialDeleteDate = eventData.potential_delete_date;
          await sendNotification(
            userDoc,
            currency + " Card Deletion Notification",
            `Your ${currency} card will be deleted on ${potentialDeleteDate} due to insufficient funds for maintenance.`,
          );
        }

        if (event === "card_delete_event.successful") {
          const cardId = eventData.card_id;
          const currency = eventData.currency;

          // Delete the card document from the cards subcollection
          const cardsQuerySnapshot = await userDoc.ref
            .collection("cards")
            .where("card_id", "==", cardId)
            .get();

          if (!cardsQuerySnapshot.empty) {
            const cardDoc = cardsQuerySnapshot.docs[0];
            await cardDoc.ref.delete();
            console.log(`Card document ${cardId} deleted successfully`);
          }

          await sendNotification(
            userDoc,
            currency + " Card Deleted",
            `Your ${currency} card has been deleted.`,
          );
        }

        // Deprecated events - handle if necessary, but skipping notifications
        if (event === "card_declined_transaction_fee_charge_event.successful") {
          await addTransaction(userDoc, event, eventData);
          console.log(
            "Handled deprecated event: card_declined_transaction_fee_charge_event.successful",
          );
        }

        if (event === "3d_secure_otp_event.generated") {
          console.log(
            "Handled deprecated event: 3d_secure_otp_event.generated",
          );
          // Optionally send OTP if still needed, but since deprecated, skip
        }
      } else {
        console.log(`No user found for cardholder_id: ${cardholderId}`);
      }
    } else {
      console.log("No cardholder_id in event data");
    }

    // Respond with 200 to acknowledge
    return res.status(200).send("Webhook received");
  },
);
exports.bridgecardGetCardDetails = onCall(
  { secrets: [bridgecardSecretKey] },
  async (data, context) => {
    await ensureVerifiedOrStandUser(data.auth);
    const secretKey = bridgecardSecretKey.value();
    if (secretKey.length === 0) {
      throw new HttpsError(
        "invalid-argument",
        "Bridgecard Secret Key is not set",
      );
    }
    bridgecardValidateData(data.data, [
      { key: "card_id", message: "Card id is required" },
    ]);
    const card_id = data.data.card_id;
    const url =
      `https://issuecards-api-bridgecard-co.relay.evervault.com/v1/issuing/sandbox/cards/get_card_details?card_id=` +
      card_id;

    return bridgecardMakeApiRequest({ url, method: "GET", secretKey });
  },
);
exports.bridgecardGetCardTransactions = onCall(
  { secrets: [bridgecardSecretKey] },
  async (data, context) => {
    await ensureVerifiedOrStandUser(data.auth);
    const secretKey = bridgecardSecretKey.value();
    if (secretKey.length === 0) {
      throw new HttpsError(
        "invalid-argument",
        "Bridgecard Secret Key is not set",
      );
    }
    bridgecardValidateData(data.data, [
      { key: "card_id", message: "Card id is required" },
    ]);
    const card_id = data.data.card_id;
    const url =
      `https://issuecards.api.bridgecard.co/v1/issuing/sandbox/cards/get_card_transactions?card_id=` +
      card_id;

    return bridgecardMakeApiRequest({ url, method: "GET", secretKey });
  },
);

exports.dailyUpdateBanks = onSchedule(
  { schedule: "0 0 * * *", secrets: [getanchorSecretKey] },
  async (event) => {
    const secretKey = getanchorSecretKey.value();
    if (secretKey.length === 0) {
      throw new Error("Getanchor Secret Key is not set");
    }
    
    const url = `${BASE_URL}/banks`;
    const response = await makeApiRequest({ url, method: "GET", secretKey });
    const banks = response.data;
    const batch = db.batch();
    for (const bank of banks) {
      const docRef = db.collection("banks").doc(bank.id.toString());
      batch.set(docRef, { name: bank.attributes.name });
    }
    await batch.commit();
    console.log("Banks updated successfully");
  },
);

exports.dailyUpdateBillers = onSchedule(
  { schedule: "0 0 * * *", secrets: [getanchorSecretKey] },
  async (event) => {
    const secretKey = getanchorSecretKey.value();
    if (secretKey.length === 0) {
      throw new Error("Getanchor Secret Key is not set");
    }
    const categories = ["airtime", "data", "television", "electricity"];
    for (const category of categories) {
      const billersUrl = `${BASE_URL}/bills/billers?category=${encodeURIComponent(
        category,
      )}`;
      const billersResponse = await makeApiRequest({
        url: billersUrl,
        method: "GET",
        secretKey,
      });
      const billers = billersResponse.data;
      await admin
        .firestore()
        .collection("billers")
        .doc(category)
        .set({ data: billers });
      console.log(`Billers for ${category} updated`);

      if (category !== "airtime" && category !== "electricity") {
        for (const biller of billers) {
          const billerId = biller.id;
          const productsUrl = `${BASE_URL}/bills/billers/${encodeURIComponent(
            billerId,
          )}/products`;
          const productsResponse = await makeApiRequest({
            url: productsUrl,
            method: "GET",
            secretKey,
          });
          const products = productsResponse.data;
          const docId = `${category}_${billerId}`;
          await admin
            .firestore()
            .collection("products")
            .doc(docId)
            .set({ data: products });
          console.log(`Products for ${category} biller ${billerId} updated`);
        }
      }
    }
  },
);

exports.createStrowalletNairaCard = onCall(
  { secrets: [strowalletPublicKey] },
  async (data, context) => {
    await ensureVerifiedOrStandUser(data.auth);

    // Validate required inputs from data
    const { customerId, type, brand } = data.data;
    if (!customerId || !type || !brand) {
      throw new HttpsError(
        "invalid-argument",
        "Missing required parameters: customerId, type, and brand.",
      );
    }

    const publicKey = strowalletPublicKey.value();
    if (publicKey.length === 0) {
      throw new HttpsError(
        "invalid-argument",
        "Strowallet public key is not set.",
      );
    }

    // Construct URL with query params (mode and provider hardcoded per doc)
    const url = `https://strowallet.com/api/naira_createcard/?public_key=${encodeURIComponent(
      publicKey,
    )}&customerId=${encodeURIComponent(customerId)}&type=${encodeURIComponent(
      type,
    )}&brand=${encodeURIComponent(brand)}&mode=sandbox&provider=black`;
    console.log("Strowallet API Request URL:", url);

    // Make the API request (adapted from sample style; uses fetch directly since no custom helper provided)
    try {
      const response = await fetch(url, {
        method: "POST",
        headers: { accept: "application/json" },
      });

      if (!response.ok) {
        throw new Error(`HTTP error! status: ${response.status}`);
      }

      const json = await response.json();
      return json;
    } catch (error) {
      console.error("Strowallet API error:", error);
      throw new HttpsError("internal", error.message);
    }
  },
);
exports.createStrowalletNairaCardUser = onCall(
  { secrets: [strowalletPublicKey] },
  async (data, context) => {
    await ensureVerifiedOrStandUser(data.auth);

    // Validate required inputs from data
    const {
      firstname,
      lastname,
      email,
      phone,
      nin,
      dob,
      name,
      line1,
      city,
      state,
    } = data.data;
    const missing = [];
    if (!firstname) missing.push("firstname");
    if (!lastname) missing.push("lastname");
    if (!email) missing.push("email");
    if (!phone) missing.push("phone");
    if (!nin) missing.push("nin");
    if (!dob) missing.push("dob");
    if (!name) missing.push("name");
    if (!line1) missing.push("line1");
    if (!city) missing.push("city");
    if (!state) missing.push("state");
    if (missing.length > 0) {
      throw new HttpsError(
        "invalid-argument",
        `Missing required parameters: ${missing.join(", ")}.`,
      );
    }

    const publicKey = strowalletPublicKey.value();
    if (publicKey.length === 0) {
      throw new HttpsError(
        "invalid-argument",
        "Strowallet public key is not set.",
      );
    }

    // Construct URL with query params (mode and provider hardcoded per doc)
    const url = `https://strowallet.com/api/naira_carduser/?public_key=${encodeURIComponent(
      publicKey,
    )}&firstname=${encodeURIComponent(firstname)}&lastname=${encodeURIComponent(
      lastname,
    )}&email=${encodeURIComponent(email)}&phone=${encodeURIComponent(
      phone,
    )}&nin=${encodeURIComponent(nin)} &dob=${encodeURIComponent(
      dob,
    )}&name=${encodeURIComponent(name)}&line1=${encodeURIComponent(
      line1,
    )}&city=${encodeURIComponent(city)}&state=${encodeURIComponent(
      state,
    )}&mode=sandbox&provider=black`;

    console.log("Strowallet API Request URL:", url);

    // Make the API request (adapted from sample style; uses fetch directly since no custom helper provided)
    try {
      const response = await fetch(url, {
        method: "POST",
        headers: { accept: "application/json" },
      });

      if (!response.ok) {
        const errorText = await response.text();
        console.log("Strowallet API Error Response:", {
          status: response.status,
          body: errorText,
        });
        throw new HttpsError(
          "internal",
          errorText || `HTTP error! status: ${response.status}`,
        );
      }

      const json = await response.json();
      console.log("Strowallet API Response:", json);
      return json;
    } catch (error) {
      console.error("Strowallet API error:", error);
      throw new HttpsError("internal", error.message);
    }
  },
);
exports.fetchStrowalletNairaCard = onCall(
  { secrets: [strowalletPublicKey] }, // Assumes strowalletPublicKey secret is configured in Firebase
  async (data, context) => {
    await ensureVerifiedOrStandUser(data.auth);

    // Validate required inputs from data
    const { card_id } = data.data;
    if (!card_id) {
      throw new HttpsError(
        "invalid-argument",
        "Missing required parameter: card_id.",
      );
    }

    const publicKey = strowalletPublicKey.value();
    if (publicKey.length === 0) {
      throw new HttpsError(
        "invalid-argument",
        "Strowallet public key is not set.",
      );
    }

    // Construct URL with query params (mode hardcoded per doc)
    const url = `https://strowallet.com/api/naira_viewcard/?public_key=${encodeURIComponent(
      publicKey,
    )}&card_id=${encodeURIComponent(card_id)}&mode=sandbox`;

    // Make the API request (uses fetch directly)
    try {
      const response = await fetch(url, {
        method: "GET",
        headers: { accept: "application/json" },
      });

      if (!response.ok) {
        throw new Error(`HTTP error! status: ${response.status}`);
      }

      const json = await response.json();
      return json;
    } catch (error) {
      console.error("Strowallet API error:", error);
      throw new HttpsError("internal", "Failed to fetch Naira card.");
    }
  },
);

exports.fetchNairaCardHistory = onCall(
  { secrets: [strowalletPublicKey] }, // Assumes strowalletPublicKey secret is configured in Firebase
  async (data, context) => {
    await ensureVerifiedOrStandUser(data.auth);

    // Validate required inputs from data
    const { card_id } = data.data;
    if (!card_id) {
      throw new HttpsError(
        "invalid-argument",
        "Missing required parameter: card_id.",
      );
    }

    const publicKey = strowalletPublicKey.value();
    if (publicKey.length === 0) {
      throw new HttpsError(
        "invalid-argument",
        "Strowallet public key is not set.",
      );
    }

    // Construct URL with query params (mode hardcoded per doc)
    const url = `https://strowallet.com/api/naira_cardhistory/?public_key=${encodeURIComponent(
      publicKey,
    )}&card_id=${encodeURIComponent(card_id)}&mode=sandbox`;

    // Make the API request (uses fetch directly)
    try {
      const response = await fetch(url, {
        method: "GET",
        headers: { accept: "application/json" },
      });

      if (!response.ok) {
        throw new Error(`HTTP error! status: ${response.status}`);
      }

      const json = await response.json();
      return json;
    } catch (error) {
      console.error("Strowallet API error:", error);
      throw new HttpsError("internal", "Failed to fetch Naira card history.");
    }
  },
);

exports.changeNairaCardPin = onCall(
  { secrets: [strowalletPublicKey] }, // Assumes strowalletPublicKey secret is configured in Firebase
  async (data, context) => {
    await ensureVerifiedOrStandUser(data.auth);

    // Validate required inputs from data
    const { card_id, old_pin, new_pin } = data.data;
    if (!card_id || !old_pin || !new_pin) {
      throw new HttpsError(
        "invalid-argument",
        "Missing required parameters: card_id, old_pin, and new_pin.",
      );
    }

    const publicKey = strowalletPublicKey.value();
    if (publicKey.length === 0) {
      throw new HttpsError(
        "invalid-argument",
        "Strowallet public key is not set.",
      );
    }

    // Construct URL with query params (mode hardcoded per doc)
    const url = `https://strowallet.com/api/naira_changepin/?public_key=${encodeURIComponent(
      publicKey,
    )}&card_id=${encodeURIComponent(card_id)}&old_pin=${encodeURIComponent(
      old_pin,
    )}&new_pin=${encodeURIComponent(new_pin)}&mode=sandbox`;

    // Make the API request (uses fetch directly)
    try {
      const response = await fetch(url, {
        method: "POST",
        headers: { accept: "application/json" },
      });

      if (!response.ok) {
        throw new Error(`HTTP error! status: ${response.status}`);
      }

      const json = await response.json();
      return json;
    } catch (error) {
      console.error("Strowallet API error:", error);
      throw new HttpsError("internal", "Failed to change Naira card PIN.");
    }
  },
);

exports.updateNairaCardStatus = onCall(
  { secrets: [strowalletPublicKey] }, // Assumes strowalletPublicKey secret is configured in Firebase
  async (data, context) => {
    await ensureVerifiedOrStandUser(data.auth);

    // Validate required inputs from data
    const { card_id, status } = data.data;
    if (!card_id || !status) {
      throw new HttpsError(
        "invalid-argument",
        "Missing required parameters: card_id and status.",
      );
    }

    const publicKey = strowalletPublicKey.value();
    if (publicKey.length === 0) {
      throw new HttpsError(
        "invalid-argument",
        "Strowallet public key is not set.",
      );
    }

    // Construct URL with query params (mode hardcoded per doc)
    const url = `https://strowallet.com/api/naira_ChangeStatus/?public_key=${encodeURIComponent(
      publicKey,
    )}&card_id=${encodeURIComponent(card_id)}&status=${encodeURIComponent(
      status,
    )}&mode=sandbox`;

    // Make the API request (uses fetch directly)
    try {
      const response = await fetch(url, {
        method: "PUT",
        headers: { accept: "application/json" },
      });

      if (!response.ok) {
        throw new Error(`HTTP error! status: ${response.status}`);
      }

      const json = await response.json();
      return json;
    } catch (error) {
      console.error("Strowallet API error:", error);
      throw new HttpsError("internal", "Failed to update Naira card status.");
    }
  },
);

exports.bridgecardFundNairaCard = onCall(
  { secrets: [bridgecardSecretKey] },
  async (data, context) => {
    await ensureVerifiedOrStandUser(data.auth);
    const secretKey = bridgecardSecretKey.value();
    if (secretKey.length === 0) {
      throw new HttpsError(
        "invalid-argument",
        "Bridgecard Secret Key is not set",
      );
    }
    console.log("Bridgecard Secret Key:", secretKey);
    bridgecardValidateData(data.data, [
      { key: "card_id", message: "Card id is required" },
      { key: "amount", message: "Amount is required" },
      {
        key: "transaction_reference",
        message: "Transaction reference is required",
      },
    ]);
    const url =
      "https://issuecards.api.bridgecard.co/v1/issuing/sandbox/naira_cards/fund_naira_card";
    const body = {
      card_id: data.data.card_id,
      amount: data.data.amount,
      transaction_reference: data.data.transaction_reference,
    };

    return bridgecardMakeApiRequest({ url, method: "POST", secretKey, body });
  },
);
exports.bridgecardFundUsdCard = onCall(
  { secrets: [bridgecardSecretKey] },
  async (data, context) => {
    if (!data.auth?.token?.email_verified) {
      throw new HttpsError(
        "unauthenticated",
        "You must be signed in to call this function.",
      );
    }
    const secretKey = bridgecardSecretKey.value();

    if (secretKey.length === 0) {
      throw new HttpsError(
        "invalid-argument",
        "Bridgecard Secret Key is not set",
      );
    }
    bridgecardValidateData(data.data, [
      { key: "card_id", message: "Card id is required" },
      { key: "amount", message: "Amount is required" },
      {
        key: "transaction_reference",
        message: "Transaction reference is required",
      },
    ]);
    const url =
      "https://issuecards.api.bridgecard.co/v1/issuing/sandbox/cards/fund_card_asynchronously";
    const requestBody = {
      card_id: data.data.card_id,
      amount: data.data.amount,
      transaction_reference: data.data.transaction_reference,
      currency: "USD",
    };

    return bridgecardMakeApiRequest({
      url,
      method: "PATCH",
      secretKey,
      body: requestBody,
    });
  },
);
exports.sendWithdrawalPin = onCall(async (data, context) => {
  await ensureVerifiedOrStandUser(data.auth);

  const { requestId } = data.data;

  if (!requestId) {
    throw new HttpsError("invalid-argument", "Missing requestId.");
  }

  try {
    const requestRef = admin
      .firestore()
      .collection("pending_withdrawals")
      .doc(requestId);
    const requestDoc = await requestRef.get();
    if (!requestDoc.exists) {
      throw new HttpsError("not-found", "Request not found.");
    }
    const requestData = requestDoc.data();
    if (requestData.status !== "pending") {
      throw new HttpsError("failed-precondition", "Request no longer pending.");
    }
    const {
      recipientUid,
      recipientCollection,
      amount,
      remark,
      initiatorUid,
      pin,
      initiatorDetails,
    } = requestData;

    // Fetch recipient details
    const recipientRef = admin
      .firestore()
      .collection(recipientCollection)
      .doc(recipientUid);
    const recipientDoc = await recipientRef.get();
    if (!recipientDoc.exists) {
      throw new HttpsError("not-found", "Recipient not found.");
    }
    const recipientData_ = recipientDoc.data();
    const deviceToken = recipientData_.deviceToken; // FCM token

    if (!deviceToken) {
      throw new HttpsError(
        "failed-precondition",
        "The user can't receive code at the moment.",
      );
    }

    // Format amount with commas
    const formattedAmount = Number(amount).toLocaleString("en-NG", {
      minimumFractionDigits: 0,
    });

    // Data-only payload for custom handling
    const payload = {
      data: {
        type: "withdrawal_request",
        requestId: requestId,
        amount: amount.toString(),
        remark: remark || "Withdrawal Request",
        initiatorUid: initiatorUid,
        initiatorName: initiatorDetails.accountName || "Unknown",
        title: "Withdrawal Request", // For local display
        body: `Withdrawal request from ${
          initiatorDetails.accountName || "Unknown"
        }: ${formattedAmount}. PIN: ${pin}.`, // For local display, includes PIN for now
        action: "NOTIFICATION_OPENED",
      },
      android: {
        priority: "high", // High priority for Android to avoid throttling
      },
      apns: {
        payload: {
          aps: {
            contentAvailable: 1, // Wake iOS for data-only
          },
        },
      },
    };
    try {
      const response = await admin.messaging().send({
        token: deviceToken,
        ...payload,
      });
      console.log("High-priority data-only notification sent:", response);
    } catch (fcmError) {
      console.error("FCM send failed:", fcmError);
      // Don't throw; allow request to proceed
    }

    // Log for audit
    await admin.firestore().collection("audit_logs").add({
      type: "withdrawal_notification_sent",
      requestId: requestId,
      initiatorUid: initiatorUid,
      recipientUid: recipientUid,
      amount: amount,
      timestamp: admin.firestore.FieldValue.serverTimestamp(),
    });

    return { success: true, message: "Notification sent successfully." };
  } catch (error) {
    console.error("Error sending notification:", error);
    throw error;
  }
});
exports.cancelWithdrawalRequest = onCall(async (data, context) => {
  await ensureVerifiedOrStandUser(data.auth);

  const { requestId, reason } = data.data;

  if (!requestId) {
    throw new HttpsError("invalid-argument", "Missing requestId.");
  }

  try {
    const requestRef = admin
      .firestore()
      .collection("pending_withdrawals")
      .doc(requestId);
    const requestDoc = await requestRef.get();
    if (!requestDoc.exists) {
      throw new HttpsError("not-found", "Request not found.");
    }
    const requestData = requestDoc.data();
    if (requestData.status !== "pending") {
      throw new HttpsError("failed-precondition", "Request no longer pending.");
    }

    // Update status and invalidate PIN
    await requestRef.update({
      status: reason === "expired" ? "expired" : "cancelled",
      pin: null,
      cancelledAt: admin.firestore.FieldValue.serverTimestamp(),
      cancelReason: reason,
    });

    // Fetch recipient deviceToken and initiator name
    const recipientUid = requestData.recipientUid;
    const recipientCollection = requestData.recipientCollection;
    const initiatorUid = requestData.initiatorUid;

    const recipientRef = admin
      .firestore()
      .collection(recipientCollection)
      .doc(recipientUid);
    const recipientDoc = await recipientRef.get();
    if (!recipientDoc.exists) {
      console.error("Recipient not found for cancel notification");
      return { success: true, message: "Request cancelled." };
    }
    const recipientData = recipientDoc.data();
    const deviceToken = recipientData.deviceToken;

    if (deviceToken) {
      let initiatorName = "Unknown";
      const busDoc = await admin
        .firestore()
        .collection("businesses")
        .doc(initiatorUid)
        .get();
      if (busDoc.exists) {
        initiatorName = busDoc.data().business_data?.name || "Unknown";
      } else {
        const userDoc = await admin
          .firestore()
          .collection("users")
          .doc(initiatorUid)
          .get();
        if (userDoc.exists) {
          initiatorName = userDoc.data().displayName || "Unknown";
        }
      }

      const payload = {
        notification: {
          title: "Withdrawal Request Cancelled",
          body: `The withdrawal request from ${initiatorName} has been ${reason}.`,
        },
        data: {
          type: "withdrawal_cancelled",
          requestId: requestId,
          status: reason,
        },
        android: {
          priority: "high", // High priority for Android to avoid throttling
        },
      };
      try {
        const response = await admin.messaging().send({
          token: deviceToken,
          ...payload,
        });
        console.log("Cancel notification sent:", response);
      } catch (fcmError) {
        console.error("FCM cancel notification failed:", fcmError);
      }
    }

    return {
      success: true,
      message: "Request cancelled and notification sent.",
    };
  } catch (error) {
    console.error("Error cancelling request:", error);
    throw error;
  }
});

exports.getGetAnchorCustomerIdByEmail = onRequest(
  { secrets: [padiLoanApiSecret] },
  async (req, res) => {
    try {
      // Only allow POST requests
      if (req.method !== "POST") {
        return res.status(405).json({ error: "Method not allowed" });
      }

      // Verify the secret key from request header
      const authHeader = req.headers.authorization;
      const secret = padiLoanApiSecret.value();

      if (!authHeader || authHeader !== `Bearer ${secret}`) {
        return res.status(401).json({ error: "Unauthorized" });
      }

      // Get email and phone from request body
      const { email, phone } = req.body;

      if (
        (!email || typeof email !== "string" || !email.trim()) &&
        (!phone || typeof phone !== "string" || !phone.trim())
      ) {
        return res
          .status(400)
          .json({ error: "Valid email or phone is required" });
      }

      let userSnapshot = null;

      // Try matching by email first
      if (email && typeof email === "string" && email.trim()) {
        userSnapshot = await admin
          .firestore()
          .collection("users")
          .where("email", "==", email.trim())
          .limit(1)
          .get();
      }

      // If no match by email, try by phone
      if (
        userSnapshot?.empty &&
        phone &&
        typeof phone === "string" &&
        phone.trim()
      ) {
        userSnapshot = await admin
          .firestore()
          .collection("users")
          .where(
            "getAnchorData.customerCreation.data.attributes.phoneNumber",
            "==",
            phone.trim(),
          )
          .limit(1)
          .get();
      }

      if (!userSnapshot || userSnapshot.empty) {
        return res.json({ success: false, customerId: null });
      }

      const userData = userSnapshot.docs[0].data();

      // Check if getAnchorData.customerCreation.data.id exists
      const customerId =
        userData?.getAnchorData?.customerCreation?.data?.id || null;

      if (!customerId) {
        return res.json({ success: false, customerId: null });
      }

      return res.json({ success: true, customerId });
    } catch (error) {
      console.error("Error fetching customer ID:", error);
      return res.status(500).json({ error: "Internal server error" });
    }
  },
);

exports.getGetAnchorCustomerTierByEmail = onRequest(
  { secrets: [padiLoanApiSecret] },
  async (req, res) => {
    try {
      // Only allow POST requests
      if (req.method !== "POST") {
        return res.status(405).json({ error: "Method not allowed" });
      }

      // Verify the secret key from request header
      const authHeader = req.headers.authorization;
      const secret = padiLoanApiSecret.value();

      if (!authHeader || authHeader !== `Bearer ${secret}`) {
        return res.status(401).json({ error: "Unauthorized" });
      }

      // Get email from request body
      const { email } = req.body;

      if (!email || typeof email !== "string" || !email.trim()) {
        return res.status(400).json({ error: "Valid email is required" });
      }

      // Query Firestore for user with this email
      const userSnapshot = await admin
        .firestore()
        .collection("users")
        .where("email", "==", email.trim())
        .limit(1)
        .get();

      if (userSnapshot.empty) {
        return res.json({ success: false, tier: null });
      }

      const userData = userSnapshot.docs[0].data();

      // Check if getAnchorData.tier exists
      const tier = userData?.getAnchorData?.tier;

      if (tier === undefined || tier === null) {
        return res.json({ success: false, tier: null });
      }

      return res.json({ success: true, tier });
    } catch (error) {
      console.error("Error fetching customer tier:", error);
      return res.status(500).json({ error: "Internal server error" });
    }
  },
);
exports.createStandUser = onCall(async (data, context) => {
  const { email, password, parentBusinessId, standId } = data.data;

  try {
    const userRecord = await admin.auth().createUser({
      email: email,
      password: password,
      emailVerified: false,
    });

    // Store stand user info
    await admin.firestore().collection("standUsers").doc(userRecord.uid).set({
      email: email,
      parentBusinessId: parentBusinessId,
      standId: standId,
      createdAt: admin.firestore.FieldValue.serverTimestamp(),
    });

    return { success: true, uid: userRecord.uid };
  } catch (error) {
    throw new HttpsError("internal", error.message);
  }
});

exports.deleteStandUser = onCall(async (data, context) => {
  const { email } = data.data;

  if (!email) {
    throw new HttpsError("invalid-argument", "Email is required");
  }

  try {
    // Find user by email
    const userRecord = await admin.auth().getUserByEmail(email);

    // Delete user from Firebase Auth
    await admin.auth().deleteUser(userRecord.uid);

    // Delete stand user info from standUsers collection
    await admin
      .firestore()
      .collection("standUsers")
      .doc(userRecord.uid)
      .delete();

    return {
      success: true,
      message: `Stand user with email ${email} deleted.`,
    };
  } catch (error) {
    throw new HttpsError("internal", error.message);
  }
});
exports.updateStandUser = onCall(async (data, context) => {
  const { oldEmail, newEmail, newPassword } = data.data;

  if (!oldEmail || !newEmail || !newPassword) {
    throw new HttpsError(
      "invalid-argument",
      "oldEmail, newEmail, and newPassword are required",
    );
  }

  try {
    // Find user by old email
    const userRecord = await admin.auth().getUserByEmail(oldEmail);

    // Update email if changed
    if (oldEmail !== newEmail) {
      await admin.auth().updateUser(userRecord.uid, { email: newEmail });
    }

    // Update password
    await admin.auth().updateUser(userRecord.uid, { password: newPassword });

    // Update standUsers doc
    await admin
      .firestore()
      .collection("standUsers")
      .doc(userRecord.uid)
      .update({
        email: newEmail,
      });

    return { success: true, message: `Stand user updated.` };
  } catch (error) {
    throw new HttpsError("internal", error.message);
  }
});

exports.qoreidWebhook = onRequest(
  {
    secrets: [qoreidWebhookSecret, smtpHost, smtpUser, smtpPass],
  },
  async (req, res) => {
    console.log("Request ", req);
    if (req.method !== "POST") {
      res.status(405).send("Method Not Allowed");
      return;
    }

    const signature = req.headers["x-verifyme-signature"];

    if (typeof signature !== "string") {
      res.status(400).send("Missing or invalid signature");
      return;
    }

    const secret = qoreidWebhookSecret.value();

    if (secret.length === 0) {
      console.error("QoreID webhook secret not set");
      res.status(500).send("Server configuration error");
      return;
    }

    const rawBody = req.rawBody;

    if (!rawBody) {
      res.status(400).send("Missing raw body");
      return;
    }

    const payloadString = rawBody.toString("utf8");

    const hmac = crypto.createHmac("sha512", secret);
    hmac.update(payloadString);
    const computedHash = hmac.digest("hex");

    if (
      !crypto.timingSafeEqual(Buffer.from(computedHash), Buffer.from(signature))
    ) {
      res.status(401).send("Invalid signature");
      return;
    }

    let payload;
    try {
      payload = JSON.parse(payloadString);
    } catch (error) {
      res.status(400).send("Invalid JSON");
      return;
    }

    console.log("Received QoreID webhook:", payload);

    // Fixed: payload is flat, no 'data' wrapper
    if (!payload.applicant || !payload.applicant.email || !payload.id) {
      console.warn("Incomplete payload, skipping processing");
      res.status(200).send("OK");
      return;
    }

    const email = payload.applicant.email.trim().toLowerCase();
    const verificationId = payload.id.toString();
    const currentState = payload.status?.state || "unknown";
    const verificationStatus = payload.status?.status || "unknown"; // 'verified' or 'unverified'

    // Determine approval: approved only if complete AND verified
    const approved =
      currentState === "complete" && verificationStatus === "verified"
        ? "approved"
        : currentState === "complete"
          ? "rejected"
          : "pending";

    const db = getFirestore();

    // Find user by email
    const usersSnapshot = await db
      .collection("users")
      .where("email", "==", email)
      .limit(1)
      .get();

    if (usersSnapshot.empty) {
      console.warn(`No user found with email: ${email}`);
      res.status(200).send("OK");
      return;
    }

    const userDocRef = usersSnapshot.docs[0].ref;
    const userData = usersSnapshot.docs[0].data();
    const deviceToken = userData.deviceToken;

    // Update verification data with correct interpretation
    await userDocRef.update({
      "qoreIdData.verification.state": currentState,
      "qoreIdData.verification.id": verificationId,
      "qoreIdData.verification.approved": approved,
      "qoreIdData.verification.summary": payload.summary || null,
      "qoreIdData.verification.metadata": payload.metadata || null,
      "qoreIdData.verification.applicant": payload.applicant || null,
    });

    // Send notification
    if (
      deviceToken &&
      typeof deviceToken === "string" &&
      deviceToken.length > 0
    ) {
      let title = "ID Verification Update";
      let body = `Your verification is now ${currentState}.`;

      if (currentState === "complete") {
        title = "ID Verification Complete";
        body =
          verificationStatus === "verified"
            ? "Your ID has been successfully verified!"
            : "Verification failed. Please try again or contact support.";
      }

      const message = {
        notification: { title, body },
        token: deviceToken,
        ...FCM_CHANNEL,
      };

      try {
        await getMessaging().send(message);
        console.log("FCM notification sent successfully");
      } catch (error) {
        console.error("Error sending FCM notification:", error);
      }
    }

    // Send KYC email notification
    if (email) {
      const kycApproved = approved === "approved";
      const kycRejected = currentState === "complete" && !kycApproved;
      const kycSubject = kycApproved
        ? "? Identity Verified ? PadiPay"
        : kycRejected
          ? "? Identity Verification Failed ? PadiPay"
          : "ID Verification Update ? PadiPay";
      const kycColor = kycApproved
        ? "#10b981"
        : kycRejected
          ? "#ef4444"
          : "#4f46e5";
      const kycGradient = kycApproved
        ? "linear-gradient(135deg,#10b981,#059669)"
        : kycRejected
          ? "linear-gradient(135deg,#ef4444,#dc2626)"
          : "linear-gradient(135deg,#4f46e5,#7c3aed)";
      const kycHeading = kycApproved
        ? "Identity Verified Successfully"
        : kycRejected
          ? "Identity Verification Failed"
          : "Verification In Progress";
      const kycBody = kycApproved
        ? "Your identity has been successfully verified. You can now access all PadiPay features."
        : kycRejected
          ? "Unfortunately, we could not verify your identity at this time. Please try again or contact support."
          : `Your verification is currently ${currentState}. We'll notify you once it's complete.`;
      await sendNotifyEmail({
        to: email,
        subject: kycSubject,
        html: `<!DOCTYPE html><html><head><meta charset='UTF-8'/></head><body style='margin:0;padding:0;background:#f0f2f5;font-family:Helvetica,Arial,sans-serif;'><table width='100%' cellpadding='0' cellspacing='0' style='background:#f0f2f5;padding:40px 0;'><tr><td align='center'><table width='520' cellpadding='0' cellspacing='0' style='max-width:520px;width:100%;'><tr><td align='center' style='padding-bottom:24px;'><span style='font-size:22px;font-weight:700;color:#1a1a2e;'>Padi<span style='color:${kycColor};'>Pay</span></span></td></tr><tr><td style='background:#fff;border-radius:16px;overflow:hidden;box-shadow:0 4px 24px rgba(0,0,0,.07);'><table width='100%' cellpadding='0' cellspacing='0'><tr><td style='background:${kycGradient};height:5px;font-size:0;'>&nbsp;</td></tr><tr><td style='padding:40px 48px 36px;'><p style='margin:0 0 8px;font-size:13px;font-weight:600;letter-spacing:1.2px;text-transform:uppercase;color:${kycColor};'>Identity Verification</p><h1 style='margin:0 0 16px;font-size:26px;font-weight:700;color:#0f0f1a;'>${kycHeading}</h1><p style='margin:0 0 24px;font-size:15px;color:#6b7280;line-height:1.6;'>${kycBody}</p></td></tr><tr><td style='padding:0 48px;'><div style='border-top:1px solid #f3f4f6;'></div></td></tr><tr><td style='padding:24px 48px;'><p style='margin:0;font-size:12px;color:#d1d5db;'>&copy; 2026 PadiPay</p></td></tr></table></td></tr></table></td></tr></table></body></html>`,
      });
    }

    res.status(200).send("OK");
  },
);
// SECURITY: Internal service endpoint ? requires Bearer token auth using PADILOAN_API_SECRET.
// Never expose this function to end-users or client apps; it returns raw financial account data.
exports.findUserByBvn = onRequest({ secrets: [padiLoanApiSecret] }, async (req, res) => {
  try {
    if (req.method !== "POST") {
      return res
        .status(405)
        .json({ error: "method_not_allowed", message: "Use HTTP POST" });
    }

    // SECURITY: Validate Bearer token on every request. Use timing-safe string
    // comparison is not needed here as Firebase Functions runs over HTTPS and
    // the secret is never sent in the URL. The check is still server-side only.
    const authHeader = req.headers.authorization;
    const secret = padiLoanApiSecret.value();
    if (!authHeader || authHeader !== `Bearer ${secret}`) {
      return res.status(401).json({ error: "Unauthorized" });
    }

    const rawBvn = req.body && req.body.bvn;
    const bvn = typeof rawBvn === "string" ? rawBvn.trim() : rawBvn;

    if (!bvn) {
      return res.status(400).json({
        error: "invalid-argument",
        message: "bvn is required in JSON body as 'bvn'",
      });
    }

    const usersRef = db.collection("users");
    const snapshot = await usersRef
      .where("qoreIdData.verification.metadata.idNumber", "==", bvn)
      .limit(1)
      .get();

    if (snapshot.empty) {
      return res.status(404).json({
        error: "not_found",
        message: "No user found for provided BVN",
      });
    }

    const doc = snapshot.docs[0];
    const getAnchorData = doc.data().getAnchorData || null;

    return res.status(200).json({ getAnchorData });
  } catch (err) {
    console.error("findUserByBvn error:", err);
    const status = err?.httpStatus || 500;
    return res.status(status).json({ error: err.message || "internal_error" });
  }
});
// Fetch all customers (supports optional query params in `data.data`)
exports.fetchAllCustomers = onCall(
  { secrets: [getanchorSecretKey] },
  async (data, context) => {
    const secretKey = getanchorSecretKey.value();
    if (!secretKey || secretKey.length === 0) {
      throw new HttpsError(
        "invalid-argument",
        "Getanchor Secret Key is not set",
      );
    }

    // Optional query params may be provided in data.data (e.g., page, pageSize, q)
    const params = data && data.data ? data.data : {};
    const urlObj = new URL(`${BASE_URL}/customers`);
    Object.keys(params).forEach((k) => {
      const v = params[k];
      if (v !== undefined && v !== null && v !== "") {
        urlObj.searchParams.append(k, String(v));
      }
    });

    const url = urlObj.toString();

    return makeApiRequest({ url, method: "GET", secretKey });
  },
);

// ==================== TERMII OTP FUNCTIONS ====================

// Auto-request PadiPay sender ID if none exist
async function autoRequestPadiPaySenderId(apiKey) {
  console.log("[autoRequestPadiPaySenderId] Requesting PadiPay sender ID");
  const url = "https://api.ng.termii.com/api/sender-id/request";
  const bodyPayload = {
    api_key: apiKey,
    sender_id: "PadiPay",
    use_case: "OTP and transactional messages for payment platform",
    company: "All Good Technologies",
  };
  console.log("[autoRequestPadiPaySenderId] URL:", url);
  console.log(
    "[autoRequestPadiPaySenderId] Payload:",
    JSON.stringify(bodyPayload),
  );

  try {
    const res = await fetch(url, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(bodyPayload),
    });

    let responseStatus = res.status;
    console.log(
      "[autoRequestPadiPaySenderId] Response status:",
      responseStatus,
    );

    let text = "";
    try {
      text = await res.text();
      console.log("[autoRequestPadiPaySenderId] Response text:", text);
    } catch (textErr) {
      console.error(
        "[autoRequestPadiPaySenderId] Error reading response text:",
        textErr.message,
      );
      throw new Error("Failed to read response: " + textErr.message);
    }

    if (!res.ok) {
      console.error(
        "[autoRequestPadiPaySenderId] API error status:",
        responseStatus,
        "text:",
        text,
      );
      throw new Error(`Termii API returned ${responseStatus}: ${text}`);
    }

    if (!text || text.trim() === "") {
      console.error("[autoRequestPadiPaySenderId] Empty response from Termii");
      throw new Error("Empty response when requesting PadiPay sender ID");
    }

    let data;
    try {
      data = JSON.parse(text);
      console.log(
        "[autoRequestPadiPaySenderId] Parsed response:",
        JSON.stringify(data),
      );
    } catch (parseErr) {
      console.error(
        "[autoRequestPadiPaySenderId] Error parsing JSON:",
        parseErr.message,
      );
      throw new Error("Failed to parse response: " + parseErr.message);
    }

    console.log(
      "[autoRequestPadiPaySenderId] PadiPay sender ID request submitted successfully, status will be pending",
    );
    console.warn(
      "[autoRequestPadiPaySenderId] PadiPay is pending approval - cannot send OTP until approved by Termii admin",
    );
    throw new Error(
      "PadiPay sender ID is pending approval. Please wait for Termii to approve your request or use an existing sender ID.",
    );
  } catch (err) {
    console.error("[autoRequestPadiPaySenderId] Exception:", err.message);
    throw err;
  }
}

// Helper: fetch the first active Termii sender ID for this account.
// Only returns a sender ID that is ACTIVE and ready to use.
// If none exist, auto-request PadiPay and throw error.
async function getTermiiSenderId(apiKey) {
  const url = `https://api.ng.termii.com/api/sender-id?api_key=${encodeURIComponent(apiKey)}`;
  console.log("[getTermiiSenderId] URL:", url);

  try {
    const res = await fetch(url, {
      method: "GET",
      headers: { "Content-Type": "application/json" },
    });
    console.log("[getTermiiSenderId] Response status:", res.status);

    const text = await res.text();
    console.log("[getTermiiSenderId] Response text:", text);

    if (!res.ok) {
      console.error(
        "[getTermiiSenderId] API error status:",
        res.status,
        "text:",
        text,
      );
      throw new Error(`Termii API returned status ${res.status}`);
    }

    if (!text || text.trim() === "") {
      console.warn(
        "[getTermiiSenderId] Empty response, no sender IDs available, auto-requesting PadiPay",
      );
      await autoRequestPadiPaySenderId(apiKey);
      // If we reach here, throw error (autoRequestPadiPaySenderId will throw)
      throw new Error("No sender IDs registered and auto-request failed");
    }

    const data = JSON.parse(text);
    console.log("[getTermiiSenderId] Response:", JSON.stringify(data));

    // Look for active sender ID
    const active = (data.content || []).find((s) => s.status === "active");
    if (active) {
      console.log(
        "[getTermiiSenderId] Found active sender_id:",
        active.sender_id,
      );
      return active.sender_id;
    }

    // List all sender IDs for debugging
    console.log(
      "[getTermiiSenderId] Available sender IDs:",
      (data.content || []).map((s) => `${s.sender_id}(${s.status})`).join(", "),
    );

    // No active sender ID found, auto-request PadiPay
    console.warn(
      "[getTermiiSenderId] No active sender IDs found, auto-requesting PadiPay",
    );
    await autoRequestPadiPaySenderId(apiKey);
    // If we reach here, throw error (autoRequestPadiPaySenderId will throw)
    throw new Error("No active sender IDs and auto-request failed");
  } catch (err) {
    console.error("[getTermiiSenderId] Exception:", err.message);
    throw err;
  }
}

exports.fetchTermiiSenderIds = onCall({ secrets: [termiiApiKey] }, async () => {
  const apiKey = termiiApiKey.value();
  const url = `https://api.ng.termii.com/api/sender-id?api_key=${encodeURIComponent(apiKey)}`;
  console.log("[fetchTermiiSenderIds] URL:", url);

  try {
    const res = await fetch(url, {
      method: "GET",
      headers: { "Content-Type": "application/json" },
    });
    console.log("[fetchTermiiSenderIds] Response status:", res.status);

    const text = await res.text();
    console.log("[fetchTermiiSenderIds] Response text:", text);

    if (!res.ok) {
      console.error("[fetchTermiiSenderIds] API error:", res.status);
      throw new HttpsError("internal", `Termii API error: ${res.status}`);
    }

    if (!text || text.trim() === "") {
      console.error("[fetchTermiiSenderIds] Empty response");
      throw new HttpsError("internal", "Empty response from Termii API");
    }

    const data = JSON.parse(text);
    console.log("[fetchTermiiSenderIds] Response:", JSON.stringify(data));
    return data;
  } catch (err) {
    console.error("[fetchTermiiSenderIds] Error:", err.message);
    if (err instanceof HttpsError) throw err;
    throw new HttpsError(
      "internal",
      "Failed to fetch sender IDs: " + (err.message || String(err)),
    );
  }
});

exports.requestTermiiSenderId = onCall(
  { secrets: [termiiApiKey] },
  async (request) => {
    const { sender_id, use_case, company } = request.data || {};
    if (!sender_id || !use_case || !company) {
      throw new HttpsError(
        "invalid-argument",
        "sender_id, use_case, and company are required",
      );
    }

    const url = "https://api.ng.termii.com/api/sender-id/request";
    const bodyPayload = {
      api_key: termiiApiKey.value(),
      sender_id,
      use_case,
      company,
    };
    console.log("[requestTermiiSenderId] URL:", url);
    console.log(
      "[requestTermiiSenderId] Payload:",
      JSON.stringify(bodyPayload),
    );

    try {
      const res = await fetch(url, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(bodyPayload),
      });
      console.log("[requestTermiiSenderId] Response status:", res.status);

      const text = await res.text();
      console.log("[requestTermiiSenderId] Response text:", text);

      if (!text || text.trim() === "") {
        console.error("[requestTermiiSenderId] Empty response");
        throw new HttpsError("internal", "Empty response from Termii API");
      }

      const data = JSON.parse(text);
      console.log("[requestTermiiSenderId] Response:", JSON.stringify(data));

      if (!res.ok) {
        console.error(
          "[requestTermiiSenderId] API error:",
          res.status,
          JSON.stringify(data),
        );
        throw new HttpsError(
          "internal",
          data.message || `Failed to request sender ID (${res.status})`,
        );
      }

      return data;
    } catch (err) {
      console.error("[requestTermiiSenderId] Error:", err.message);
      if (err instanceof HttpsError) throw err;
      throw new HttpsError(
        "internal",
        "Failed to request sender ID: " + (err.message || String(err)),
      );
    }
  },
);

exports.sendOTP = onCall({ secrets: [termiiApiKey] }, async (request) => {
  const { phone } = request.data;
  if (!phone || typeof phone !== "string") {
    throw new HttpsError("invalid-argument", "Phone number is required");
  }

  // Termii expects international format without leading +
  const formattedPhone = phone.startsWith("+") ? phone.slice(1) : phone;

  // Check for existing non-expired OTP for this phone
  const existingSnap = await db
    .collection("smsOtps")
    .where("phone", "==", formattedPhone)
    .where("expiresAt", ">", Date.now())
    .where("used", "==", false)
    .limit(1)
    .get();

  let termiiPinId, code;

  if (!existingSnap.empty) {
    // Reuse existing OTP
    const existingDoc = existingSnap.docs[0];
    termiiPinId = existingDoc.data().termiiPinId;
    code = existingDoc.data().code;
    console.log(
      "[sendOTP] Reusing existing OTP for phone:",
      formattedPhone,
      "pinId:",
      termiiPinId,
    );
    return { pinId: termiiPinId, code };
  }

  // Generate new code and send via Termii
  code = String(Math.floor(100000 + Math.random() * 900000));

  // Dynamically resolve the first active sender ID for this account
  const apiKey = termiiApiKey.value();
  let senderId;
  try {
    senderId = await getTermiiSenderId(apiKey);
  } catch (err) {
    console.error("[sendOTP] getTermiiSenderId error:", err.message);
    throw new HttpsError(
      "internal",
      `Failed to get sender ID: ${err.message || "No active sender IDs available"}`,
    );
  }

  const url = "https://api.ng.termii.com/api/sms/otp/send";
  const bodyPayload = {
    api_key: apiKey,
    message_type: "NUMERIC",
    pin_type: "NUMERIC",
    to: formattedPhone,
    from: senderId,
    channel: "dnd",
    pin_attempts: 3,
    pin_time_to_live: 10,
    pin_length: 6,
    pin_placeholder: "< 000000 >",
    message_text:
      "Your PadiPay verification code is < 000000 >. Valid for 10 minutes. Do not share this code.",
  };
  console.log("[sendOTP] URL:", url);
  console.log("[sendOTP] Payload:", JSON.stringify(bodyPayload));

  const response = await fetch(url, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(bodyPayload),
  });

  const data = await response.json();
  console.log("[sendOTP] Response:", JSON.stringify(data));
  if (!response.ok || !data.pinId) {
    console.error("[sendOTP] Error:", JSON.stringify(data));
    throw new HttpsError(
      "internal",
      `Termii API error: ${data.message || data.detail || "Failed to send OTP"}`,
    );
  }

  termiiPinId = data.pinId;

  // Store OTP in Firestore for tracking and potential reuse
  const expiresAt = Date.now() + 10 * 60 * 1000; // 10 minutes
  await db.collection("smsOtps").add({
    phone: formattedPhone,
    code,
    termiiPinId,
    expiresAt,
    used: false,
    createdAt: admin.firestore.FieldValue.serverTimestamp(),
  });

  return { pinId: termiiPinId, code };
});

exports.verifyOTP = onCall({ secrets: [termiiApiKey] }, async (request) => {
  const { pinId, pin } = request.data;
  if (!pinId || typeof pinId !== "string" || !pin || typeof pin !== "string") {
    throw new HttpsError("invalid-argument", "pinId and pin are required");
  }

  const url = "https://api.ng.termii.com/api/sms/otp/verify";
  const bodyPayload = {
    api_key: termiiApiKey.value(),
    pin_id: pinId,
    pin,
  };
  console.log("[verifyOTP] URL:", url);
  console.log("[verifyOTP] Payload:", JSON.stringify(bodyPayload));

  const response = await fetch(url, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(bodyPayload),
  });

  const data = await response.json();
  console.log("[verifyOTP] Response:", JSON.stringify(data));
  if (!response.ok) {
    console.error("[verifyOTP] Error:", JSON.stringify(data));
    throw new HttpsError(
      "internal",
      `Termii verification failed: ${data.message || data.detail || "Invalid or expired code"}`,
    );
  }

  const verified = data.verified === "True" || data.verified === true;
  return { verified };
});

// Send regular SMS via Termii (for invitations, notifications, etc.)
// SECURITY: Requires verified Firebase Auth user or standUser exemption.
// Without this guard any Firebase user (even unverified) could send arbitrary
// SMS to any number at company expense ? enabling spam and financial abuse.
exports.sendTermiiSMS = onCall({ secrets: [termiiApiKey] }, async (request) => {
  await ensureVerifiedOrStandUser(request.auth);

  const { phoneNumber, message } = request.data;

  if (!phoneNumber || typeof phoneNumber !== "string") {
    throw new HttpsError("invalid-argument", "phoneNumber is required");
  }
  if (!message || typeof message !== "string") {
    throw new HttpsError("invalid-argument", "message is required");
  }

  // Termii expects international format without leading +
  const formattedPhone = phoneNumber.startsWith("+")
    ? phoneNumber.slice(1)
    : phoneNumber;

  // Get the active sender ID for this account
  const apiKey = termiiApiKey.value();
  let senderId;
  try {
    senderId = await getTermiiSenderId(apiKey);
  } catch (err) {
    console.error("[sendTermiiSMS] getTermiiSenderId error:", err.message);
    throw new HttpsError(
      "internal",
      `Failed to get sender ID: ${err.message || "No active sender IDs available"}`,
    );
  }

  const url = "https://api.ng.termii.com/api/sms/send";
  const bodyPayload = {
    api_key: apiKey,
    to: formattedPhone,
    from: senderId,
    sms: message,
    channel: "dnd",
    type: "plain",
  };
  console.log("[sendTermiiSMS] URL:", url);
  console.log("[sendTermiiSMS] Payload:", JSON.stringify(bodyPayload));

  const response = await fetch(url, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(bodyPayload),
  });

  const data = await response.json();
  console.log("[sendTermiiSMS] Response:", JSON.stringify(data));

  if (!response.ok || data.status !== "success") {
    console.error("[sendTermiiSMS] Error:", JSON.stringify(data));
    throw new HttpsError(
      "internal",
      `Termii API error: ${data.message || data.detail || "Failed to send SMS"}`,
    );
  }

  return { messageId: data.message_id, recipient: formattedPhone };
});

// ==================== SMTP EMAIL FUNCTIONS ====================

/**
 * sendEmail - general-purpose email sender via NodeMailer SMTP.
 *
 * Request data:
 *   to          {string|string[]}  Recipient address(es)
 *   subject     {string}           Email subject
 *   text        {string}           Plain-text body (required if html is not provided)
 *   html        {string}           HTML body (optional; if both text and html are given,
 *                                  a multipart/alternative message is sent)
 *   replyTo     {string}           Optional reply-to address
 *
 * Convenience fields (can be used instead of building html/text manually):
 *   code        {string}           If provided, wraps the value in a styled OTP email
 *                                  (sets both html and text automatically)
 *
 * Returns: { messageId: string }
 */
exports.sendEmail = onCall(
  {
    secrets: [smtpHost, smtpUser, smtpPass],
  },
  async (request) => {
    const { to, subject, text, html, replyTo, code } = request.data || {};

    if (!to || !subject) {
      throw new Error("'to' and 'subject' are required.");
    }

    const recipients = Array.isArray(to) ? to : [to];

    // Build body - OTP convenience wrapper takes priority
    let resolvedText = text;
    let resolvedHtml = html;

    if (code) {
      resolvedText = `Your PadiPay verification code is: ${code}\n\nThis code is valid for 10 minutes. Do not share it with anyone.`;
      resolvedHtml = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>Your PadiPay Verification Code</title>
</head>
<body style="margin:0;padding:0;background-color:#f0f2f5;font-family:'Helvetica Neue',Helvetica,Arial,sans-serif;">
  <table width="100%" cellpadding="0" cellspacing="0" style="background-color:#f0f2f5;padding:40px 0;">
    <tr>
      <td align="center">
        <table width="520" cellpadding="0" cellspacing="0" style="max-width:520px;width:100%;">

          <!-- Header -->
          <tr>
            <td align="center" style="padding-bottom:24px;">
              <span style="font-size:22px;font-weight:700;color:#1a1a2e;letter-spacing:-0.5px;">Padi<span style="color:#4f46e5;">Pay</span></span>
            </td>
          </tr>

          <!-- Card -->
          <tr>
            <td style="background:#ffffff;border-radius:16px;overflow:hidden;box-shadow:0 4px 24px rgba(0,0,0,0.07);">

              <!-- Top accent bar -->
              <tr>
                <td style="background:linear-gradient(135deg,#4f46e5 0%,#7c3aed 100%);height:5px;font-size:0;line-height:0;">&nbsp;</td>
              </tr>

              <!-- Body -->
              <tr>
                <td style="padding:40px 48px 36px;">
                  <p style="margin:0 0 8px;font-size:13px;font-weight:600;letter-spacing:1.2px;text-transform:uppercase;color:#4f46e5;">Security Code</p>
                  <h1 style="margin:0 0 16px;font-size:26px;font-weight:700;color:#0f0f1a;line-height:1.2;">Verify your identity</h1>
                  <p style="margin:0 0 32px;font-size:15px;color:#6b7280;line-height:1.6;">Use the one-time code below to complete your sign-in. For security, it expires in <strong style="color:#374151;">10 minutes</strong>.</p>

                  <!-- OTP Box -->
                  <table width="100%" cellpadding="0" cellspacing="0">
                    <tr>
                      <td align="center" style="background:#f5f3ff;border:1.5px solid #e0d9ff;border-radius:12px;padding:28px 24px;">
                        <span style="font-size:42px;font-weight:800;letter-spacing:14px;color:#4f46e5;font-variant-numeric:tabular-nums;">${code}</span>
                      </td>
                    </tr>
                  </table>

                  <p style="margin:28px 0 0;font-size:13px;color:#9ca3af;line-height:1.6;">If you did not request this code, you can safely ignore this email. Someone may have entered your email address by mistake.</p>
                </td>
              </tr>

              <!-- Divider -->
              <tr>
                <td style="padding:0 48px;"><div style="border-top:1px solid #f3f4f6;"></div></td>
              </tr>

              <!-- Footer -->
              <tr>
                <td style="padding:24px 48px;">
                  <p style="margin:0;font-size:12px;color:#d1d5db;">&copy; 2026 PadiPay &middot; <a href="https://padipay.co" style="color:#d1d5db;text-decoration:none;">padipay.co</a></p>
                </td>
              </tr>

            </td>
          </tr>

        </table>
      </td>
    </tr>
  </table>
</body>
</html>`.trim();
    }

    if (!resolvedText && !resolvedHtml) {
      throw new Error("Provide at least one of: 'text', 'html', or 'code'.");
    }

    console.log("[sendEmail] Sending to:", recipients, "| Subject:", subject);

    try {
      const messageId = await sendViaSMTP({
        to: recipients,
        subject,
        html: resolvedHtml,
        text: resolvedText,
        replyTo,
      });
      console.log("[sendEmail] MessageId:", messageId);
      return { messageId };
    } catch (err) {
      console.error("[sendEmail] Error:", err.message || String(err));
      throw new Error(`Failed to send email: ${err.message || String(err)}`);
    }
  },
);

/**
 * synthesizeNeuralSpeech - Generate high-quality neural speech audio (MP3).
 * Returns base64-encoded audio bytes for client playback.
 */
exports.synthesizeNeuralSpeech = onCall(async (request) => {
  if (!request.auth) {
    throw new HttpsError("unauthenticated", "Authentication required");
  }

  const { text, voiceStyle, voiceLanguage } = request.data || {};
  if (!text || typeof text !== "string") {
    throw new HttpsError("invalid-argument", "'text' is required");
  }

  const normalizedText = text.trim();
  if (!normalizedText) {
    throw new HttpsError("invalid-argument", "'text' cannot be empty");
  }

  if (normalizedText.length > 300) {
    throw new HttpsError(
      "invalid-argument",
      "'text' must be 300 characters or less",
    );
  }

  const style = String(voiceStyle || "female").toLowerCase() === "male" ? "male" : "female";
  const language =
    String(voiceLanguage || "english").toLowerCase() === "pidgin"
      ? "pidgin"
      : "english";

  const voiceName = style === "male" ? "en-GB-Neural2-D" : "en-GB-Neural2-F";

  const [response] = await ttsClient.synthesizeSpeech({
    input: { text: normalizedText },
    voice: {
      languageCode: "en-GB",
      name: voiceName,
      ssmlGender: style === "male" ? "MALE" : "FEMALE",
    },
    audioConfig: {
      audioEncoding: "MP3",
      speakingRate: language === "pidgin" ? 1.1 : 1.0,
      pitch: style === "male" ? -2.0 : 1.0,
    },
  });

  if (!response.audioContent) {
    throw new HttpsError("internal", "Neural TTS returned empty audio");
  }

  const audioBuffer = Buffer.isBuffer(response.audioContent)
    ? response.audioContent
    : Buffer.from(response.audioContent, "base64");

  return {
    ok: true,
    engine: "google-cloud-neural",
    voiceName,
    audioContentBase64: audioBuffer.toString("base64"),
    mimeType: "audio/mpeg",
  };
});

// ==================== END SMTP EMAIL FUNCTIONS ====================

// ==================== EMAIL OTP FUNCTIONS ====================

/**
 * sendEmailOTP - generate a 6-digit OTP, store it in Firestore, and email it via SMTP.
 * Returns { pinId } that must be passed to verifyEmailOTP.
 */
exports.sendEmailOTP = onCall(
  {
    secrets: [smtpHost, smtpUser, smtpPass],
  },
  async (request) => {
    const { email, purpose } = request.data || {};
    if (!email || typeof email !== "string" || !email.includes("@")) {
      throw new HttpsError(
        "invalid-argument",
        "Valid email address is required.",
      );
    }

    const normalizedEmail = email.toLowerCase().trim();
    const purposeVal = purpose || "verify";

    // Check for existing non-expired OTP for this email and purpose
    const existingSnap = await db
      .collection("emailOtps")
      .where("email", "==", normalizedEmail)
      .where("purpose", "==", purposeVal)
      .where("expiresAt", ">", Date.now())
      .where("used", "==", false)
      .limit(1)
      .get();

    let code, docRef;
    let isReusing = false;

    if (!existingSnap.empty) {
      // Reuse existing OTP
      docRef = existingSnap.docs[0].ref;
      code = existingSnap.docs[0].data().code;
      isReusing = true;
      console.log(
        "[sendEmailOTP] Reusing existing OTP for email:",
        normalizedEmail,
        "purpose:",
        purposeVal,
        "code:",
        code,
      );
    } else {
      // Generate new code
      code = String(Math.floor(100000 + Math.random() * 900000));
      const expiresAt = Date.now() + 10 * 60 * 1000; // 10 minutes

      // Store code in Firestore
      docRef = await db.collection("emailOtps").add({
        email: normalizedEmail,
        code,
        expiresAt,
        used: false,
        purpose: purposeVal,
        createdAt: admin.firestore.FieldValue.serverTimestamp(),
      });
    }

    const host = smtpHost.value();
    const user = smtpUser.value();
    const pass = smtpPass.value();

    if (!host || !user || !pass) {
      await docRef.delete();
      throw new HttpsError(
        "internal",
        "SMTP credentials are not configured. Contact support.",
      );
    }

    const isPasswordResetPurpose =
      typeof purposeVal === "string" &&
      ["password_reset", "reset", "forgot_password"].includes(
        purposeVal.toLowerCase(),
      );

    const subject = isPasswordResetPurpose
      ? "Reset your password"
      : "Verify your email";

    const html = isPasswordResetPurpose
      ? `<p>Your password reset code is <b>${code}</b>. It expires in 10 minutes.</p>`
      : `<!DOCTYPE html>
<html>
  <head>
    <meta charset="UTF-8" />
    <meta name="viewport" content="width=device-width,initial-scale=1" />
  </head>
  <body style="margin:0;padding:0;background:#f3f5fb;font-family:Arial,sans-serif;">
    <table width="100%" cellpadding="0" cellspacing="0" style="padding:24px 12px;background:#f3f5fb;">
      <tr>
        <td align="center">
          <table width="520" cellpadding="0" cellspacing="0" style="max-width:520px;width:100%;background:#ffffff;border-radius:14px;overflow:hidden;box-shadow:0 6px 24px rgba(15,23,42,0.08);">
            <tr>
              <td style="background:#1d4ed8;height:6px;"></td>
            </tr>
            <tr>
              <td style="padding:28px 28px 10px;">
                <p style="margin:0 0 8px;font-size:12px;letter-spacing:0.5px;text-transform:uppercase;color:#1d4ed8;font-weight:700;">PadiPay</p>
                <h1 style="margin:0 0 10px;font-size:24px;line-height:1.25;color:#111827;">Verify your email address</h1>
                <p style="margin:0;font-size:14px;line-height:1.7;color:#4b5563;">Use the code below to verify your email. This code expires in 10 minutes.</p>
              </td>
            </tr>
            <tr>
              <td style="padding:18px 28px 6px;">
                <div style="background:#eff6ff;border:1px solid #bfdbfe;border-radius:12px;padding:16px;text-align:center;">
                  <span style="font-size:34px;letter-spacing:6px;font-weight:800;color:#1e3a8a;">${code}</span>
                </div>
              </td>
            </tr>
            <tr>
              <td style="padding:10px 28px 28px;">
                <p style="margin:0;font-size:12px;line-height:1.6;color:#6b7280;">If you did not request this code, you can safely ignore this email.</p>
              </td>
            </tr>
          </table>
        </td>
      </tr>
    </table>
  </body>
</html>`;

    const plainText = isPasswordResetPurpose
      ? `Your password reset code is ${code}. It expires in 10 minutes.`
      : `Your email verification code is ${code}. It expires in 10 minutes.`;

    const params = {
      to: normalizedEmail,
      subject,
      html,
      text: plainText,
    };

    console.log(
      "[sendEmailOTP] Sending OTP to email:",
      normalizedEmail,
      "purpose:",
      purpose || "verify",
    );
    try {
      const messageId = await sendViaSMTP(params);
      console.log("[sendEmailOTP] MessageId:", messageId);
    } catch (err) {
      if (!isReusing) {
        await docRef.delete();
      }
      console.error("[sendEmailOTP] SMTP error:", err.message || String(err));
      throw new HttpsError(
        "internal",
        `Email sending failed: ${err.message || "Unknown error"}`,
      );
    }

    return { pinId: docRef.id };
  },
);

/**
 * verifyEmailOTP ? verify a code previously sent by sendEmailOTP.
 * Returns { verified: boolean }.
 */
exports.verifyEmailOTP = onCall(async (request) => {
  const { pinId, code } = request.data || {};
  if (!pinId || !code) {
    throw new HttpsError("invalid-argument", "pinId and code are required.");
  }

  const docRef = db.collection("emailOtps").doc(pinId);
  const snap = await docRef.get();

  if (!snap.exists) {
    return { verified: false };
  }

  const data = snap.data();

  if (data.used) {
    return { verified: false };
  }

  if (Date.now() > data.expiresAt) {
    return { verified: false };
  }

  // SECURITY: Brute-force protection ? limit OTP guess attempts per pinId.
  // A 6-digit OTP has 1,000,000 possible values; without this an attacker with a
  // stolen pinId could enumerate all codes before expiry.
  // After MAX_ATTEMPTS failures the document is locked (used=true) and
  // the caller must request a fresh OTP.
  const MAX_ATTEMPTS = 5;
  const attempts = (data.attempts || 0) + 1;
  if (attempts > MAX_ATTEMPTS) {
    await docRef.update({ used: true }); // lock it out permanently
    throw new HttpsError("resource-exhausted", "Too many incorrect attempts. Request a new OTP.");
  }

  if (data.code !== String(code)) {
    await docRef.update({ attempts }); // persist incremented counter
    return { verified: false };
  }

  await docRef.update({ used: true });

  // If this OTP was for email verification, mark the user as verified in Firebase Auth
  if (data.email) {
    try {
      const authUser = await admin.auth().getUserByEmail(data.email);
      if (!authUser.emailVerified) {
        await admin.auth().updateUser(authUser.uid, { emailVerified: true });
        console.log(
          "[verifyEmailOTP] Marked emailVerified=true for:",
          data.email,
        );
      }
    } catch (err) {
      // Non-fatal ? user may already be verified or not exist yet
      console.warn(
        "[verifyEmailOTP] Could not mark emailVerified:",
        err.message,
      );
    }
  }

  console.log("[verifyEmailOTP] Verified pinId:", pinId);
  return { verified: true, email: data.email };
});

// ==================== END EMAIL OTP FUNCTIONS ====================

// ==================== PASSWORD RESET OTP FUNCTIONS ====================

/**
 * sendPasswordResetOTP ? send OTP to email for password reset
 * Verifies user exists in Firebase Auth before sending
 * Returns { pinId } that must be passed to verifyPasswordResetOTP
 */
exports.sendPasswordResetOTP = onCall(
  {
    secrets: [smtpHost, smtpUser, smtpPass],
  },
  async (request) => {
    const { email, userType, lenderName, lenderBrandColor } =
      request.data || {};
    if (!email || typeof email !== "string" || !email.includes("@")) {
      throw new HttpsError(
        "invalid-argument",
        "Valid email address is required.",
      );
    }

    const normalizedEmail = email.toLowerCase().trim();

    // Verify user exists in Firebase Auth
    let authUser;
    try {
      authUser = await admin.auth().getUserByEmail(normalizedEmail);
      console.log(
        "[sendPasswordResetOTP] User found in Firebase Auth:",
        normalizedEmail,
      );
    } catch (err) {
      console.error(
        "[sendPasswordResetOTP] User not found in Firebase Auth:",
        normalizedEmail,
      );
      throw new HttpsError(
        "not-found",
        "No account found with this email address.",
      );
    }

    // Determine user type if not provided
    let finalUserType = userType || "user";
    if (!userType) {
      try {
        const userDoc = await db.collection("users").doc(authUser.uid).get();
        if (userDoc.exists()) {
          finalUserType = userDoc.data()?.userType || "user";
        }
      } catch (err) {
        console.warn(
          "[sendPasswordResetOTP] Could not determine user type, defaulting to user",
        );
      }
    }

    const code = String(Math.floor(100000 + Math.random() * 900000));
    const expiresAt = Date.now() + 10 * 60 * 1000; // 10 minutes for password reset

    // Store code in Firestore under passwordResetOtps collection
    const docRef = await db.collection("passwordResetOtps").add({
      email: normalizedEmail,
      code,
      expiresAt,
      used: false,
      createdAt: admin.firestore.FieldValue.serverTimestamp(),
    });

    const host = smtpHost.value();
    const user = smtpUser.value();
    const pass = smtpPass.value();

    if (!host || !user || !pass) {
      await docRef.delete();
      throw new HttpsError(
        "internal",
        "SMTP credentials are not configured. Contact support.",
      );
    }

    const subject = "Reset your password";
    const html = `<p>Your password reset code is <b>${code}</b>. It expires in 10 minutes.</p>`;
    const plainText = `Your password reset code is ${code}. It expires in 10 minutes.`;

    const params = {
      to: normalizedEmail,
      subject,
      html,
      text: plainText,
    };

    console.log(
      "[sendPasswordResetOTP] Sending password reset OTP to email:",
      normalizedEmail,
      "userType:",
      finalUserType,
    );
    try {
      const messageId = await sendViaSMTP(params);
      console.log("[sendPasswordResetOTP] MessageId:", messageId);
    } catch (err) {
      await docRef.delete();
      console.error(
        "[sendPasswordResetOTP] SMTP error:",
        err.message || String(err),
      );
      throw new HttpsError(
        "internal",
        `Email sending failed: ${err.message || "Unknown error"}`,
      );
    }

    return { pinId: docRef.id };
  },
);

/**
 * verifyPasswordResetOTP ? verify password reset OTP code
 * Returns { verified: boolean, resetToken: string } if verified
 */
exports.verifyPasswordResetOTP = onCall(async (request) => {
  const { pinId, code } = request.data || {};
  if (!pinId || !code) {
    throw new HttpsError("invalid-argument", "pinId and code are required.");
  }

  const docRef = db.collection("passwordResetOtps").doc(pinId);
  const snap = await docRef.get();

  if (!snap.exists) {
    return { verified: false };
  }

  const data = snap.data();

  if (data.used) {
    return { verified: false };
  }

  if (Date.now() > data.expiresAt) {
    return { verified: false };
  }

  // SECURITY: Brute-force protection ? same pattern as verifyEmailOTP.
  // Prevents guessing the 6-digit code before it expires.
  const MAX_ATTEMPTS = 5;
  const attempts = (data.attempts || 0) + 1;
  if (attempts > MAX_ATTEMPTS) {
    await docRef.update({ used: true });
    throw new HttpsError("resource-exhausted", "Too many incorrect attempts. Request a new OTP.");
  }

  if (data.code !== String(code)) {
    await docRef.update({ attempts }); // persist incremented counter
    return { verified: false };
  }

  // Mark as used and generate reset token.
  // SECURITY: crypto.randomBytes gives 256 bits of entropy. Never use Math.random()
  // for security tokens ? it is not cryptographically secure.
  const resetToken = crypto.randomBytes(32).toString("hex");
  await docRef.update({
    used: true,
    resetToken,
    resetTokenExpiresAt: Date.now() + 30 * 60 * 1000, // 30 minutes to reset password
  });

  console.log(
    "[verifyPasswordResetOTP] Verified pinId:",
    pinId,
    "for email:",
    data.email,
  );
  return { verified: true, resetToken, email: data.email };
});

/**
 * resetPasswordWithOTP ? reset password using verified OTP token
 * Requires the resetToken from verifyPasswordResetOTP
 */
exports.resetPasswordWithOTP = onCall(async (request) => {
  const { email, resetToken, newPassword } = request.data || {};

  if (!email || !resetToken || !newPassword) {
    throw new HttpsError(
      "invalid-argument",
      "email, resetToken, and newPassword are required.",
    );
  }

  if (newPassword.length < 6) {
    throw new HttpsError(
      "invalid-argument",
      "New password must be at least 6 characters long.",
    );
  }

  const normalizedEmail = email.toLowerCase().trim();

  // Find the password reset OTP record with this token
  const otpsSnap = await db
    .collection("passwordResetOtps")
    .where("email", "==", normalizedEmail)
    .where("resetToken", "==", resetToken)
    .limit(1)
    .get();

  if (otpsSnap.empty) {
    throw new HttpsError("invalid-argument", "Invalid or expired reset token.");
  }

  const otpDoc = otpsSnap.docs[0];
  const otpData = otpDoc.data();

  // Check if token has expired
  if (Date.now() > otpData.resetTokenExpiresAt) {
    throw new HttpsError(
      "invalid-argument",
      "Reset token has expired. Please request a new one.",
    );
  }

  // Find user by email
  const usersSnap = await db
    .collection("users")
    .where("email", "==", normalizedEmail)
    .limit(1)
    .get();

  if (usersSnap.empty) {
    throw new HttpsError("invalid-argument", "User not found.");
  }

  const userId = usersSnap.docs[0].id;

  try {
    // Update Firebase Auth password
    await admin.auth().updateUser(userId, { password: newPassword });
    console.log("[resetPasswordWithOTP] Password reset for user:", userId);

    // Mark reset token as expired
    await otpDoc.ref.update({ resetTokenExpiresAt: 0 });

    return { success: true, message: "Password reset successfully." };
  } catch (err) {
    console.error(
      "[resetPasswordWithOTP] Error resetting password:",
      err.message || String(err),
    );
    throw new HttpsError(
      "internal",
      "Failed to reset password. Please try again.",
    );
  }
});

// ==================== END PASSWORD RESET OTP FUNCTIONS ====================


// ==================== ATM TRANSACTION RECONCILIATION ====================
// Safe Haven MFB Kimono ? card transaction lookup by RRN.
// Auth: RS256 client assertion ? OAuth2 access_token (cached per instance).

let _safehavenToken = null;
let _safehavenAtmTokenExpiresAt = 0;
let _safehavenApiBase = null;
let _safehavenAtmTokenCacheKey = null;

function _base64UrlEncode(buf) {
  return buf.toString("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=/g, "");
}

async function _getSafehavenAccessToken(clientId, privateKeyPem, companyUrl, apiBase) {
  const now = Math.floor(Date.now() / 1000);
  const cacheKey = `${apiBase}|${clientId}`;

  // Return cached token if still valid (60 s grace buffer)
  if (
    _safehavenToken &&
    _safehavenApiBase === apiBase &&
    _safehavenAtmTokenCacheKey === cacheKey &&
    _safehavenAtmTokenExpiresAt > now + 60
  ) {
    console.log("[SafeHaven] Reusing cached access token");
    return {accessToken: _safehavenToken, apiBase: _safehavenApiBase};
  }

  console.log("[SafeHaven] Generating new client assertion for clientId=", clientId);

  const authBases = [apiBase].filter((v) => typeof v === "string" && v.length > 0);

  const attempts = [];

  for (const apiBase of authBases) {
    try {
      // Build RS256 JWT client assertion for the current auth base.
      const header = _base64UrlEncode(Buffer.from(JSON.stringify({alg: "RS256", typ: "JWT"})));
      const payload = _base64UrlEncode(Buffer.from(JSON.stringify({
        iss: companyUrl,
        sub: clientId,
        aud: apiBase,
        iat: now,
        exp: now + 3600,
      })));

      const signingInput = `${header}.${payload}`;
      const signer = crypto.createSign("RSA-SHA256");
      signer.update(signingInput);
      signer.end();
      const signature = _base64UrlEncode(signer.sign({key: privateKeyPem, format: "pem"}));
      const clientAssertion = `${signingInput}.${signature}`;

      console.log("[SafeHaven] Exchanging client assertion for access token on", apiBase);

      // OAuth 2.0 requires application/x-www-form-urlencoded.
      const tokenRes = await fetch(`${apiBase}/oauth2/token`, {
        method: "POST",
        headers: {"Content-Type": "application/x-www-form-urlencoded", "Accept": "application/json"},
        body: new URLSearchParams({
          grant_type: "client_credentials",
          client_id: clientId,
          client_assertion: clientAssertion,
          client_assertion_type: "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
        }).toString(),
      });

      const tokenBody = await tokenRes.json();
      console.log(
        "[SafeHaven] Token exchange base=" + apiBase +
        " HTTP=" + tokenRes.status +
        " body=" + JSON.stringify(tokenBody),
      );

      if (!tokenRes.ok || !tokenBody.access_token) {
        attempts.push(`base=${apiBase} HTTP ${tokenRes.status} ${JSON.stringify(tokenBody)}`);
        continue;
      }

      const expiresIn = typeof tokenBody.expires_in === "number" ? tokenBody.expires_in : 3600;
      _safehavenToken = tokenBody.access_token;
      _safehavenAtmTokenExpiresAt = now + expiresIn;
      _safehavenApiBase = apiBase;
      _safehavenAtmTokenCacheKey = cacheKey;

      console.log(`[SafeHaven] Access token obtained from ${apiBase}, expires in ${expiresIn}s`);
      return {accessToken: _safehavenToken, apiBase: _safehavenApiBase};
    } catch (err) {
      attempts.push(`base=${apiBase} error=${err.message || String(err)}`);
    }
  }

  throw new Error(`Safe Haven token exchange failed. Attempts: ${attempts.join(" | ")}`);
}

exports.reconcileAtmTransaction = onCall(
  { secrets: [safehavenClientId, safehavenPrivateKey, safehavenCompanyUrl] },
  async (data, context) => {
    await ensureVerifiedOrStandUser(data.auth);

    const { rrn, transactionDocId } = data.data;
    const pendingFailAfterMinutes = Number(data?.data?.pendingFailAfterMinutes || 10);
    if (!rrn || typeof rrn !== "string" || rrn.trim().length === 0) {
      throw new HttpsError("invalid-argument", "RRN is required");
    }

    const safehavenConfig = await _resolveSafehavenConfig();
    const clientId = safehavenConfig.clientId;
    const privateKey = safehavenConfig.privateKeyPem;
    const companyUrl = safehavenConfig.companyUrl;
    const preferredApiBase = safehavenConfig.baseUrl;

    if (!clientId || !privateKey || !companyUrl) {
      throw new HttpsError("internal", "Safe Haven credentials are not configured");
    }

    // Obtain a valid access token
    let accessToken;
    let apiBase;
    try {
      const authResult = await _getSafehavenAccessToken(
        clientId,
        privateKey,
        companyUrl,
        preferredApiBase,
      );
      accessToken = authResult.accessToken;
      apiBase = authResult.apiBase;
    } catch (authErr) {
      console.error("[Reconcile] Auth error:", authErr);
      throw new HttpsError("internal", `Safe Haven auth failed: ${authErr.message}`);
    }

    const url =
      `${apiBase}/kimono/get-records?` +
      `retrievalReferenceNumber=${encodeURIComponent(rrn.trim())}`;

    console.log(`[Reconcile] Fetching RRN=${rrn} from Safe Haven`);

    let raw;
    try {
      const response = await fetch(url, {
        method: "GET",
        headers: {
          "Authorization": `Bearer ${accessToken}`,
          "Content-Type": "application/json",
          "Accept": "application/json",
        },
      });
      raw = await response.json();
      console.log(`[Reconcile] RRN=${rrn} HTTP=${response.status} raw:`, JSON.stringify(raw));
    } catch (fetchErr) {
      console.error(`[Reconcile] Fetch error for RRN=${rrn}:`, fetchErr);
      throw new HttpsError("internal", `Failed to reach Safe Haven: ${fetchErr.message}`);
    }

    // Parse status
    // Safe Haven Kimono returns: { statusCode, data: { responseCode, status, ... } }
    let reconciledStatus = "pending";
    let responseCode = null;
    let safeHavenStatus = null;

    try {
      const record = Array.isArray(raw?.data) ? raw.data[0] : raw?.data;
      responseCode    = record?.responseCode ?? record?.field39 ?? null;
      safeHavenStatus = record?.status ?? null;

      if (responseCode === "00" || safeHavenStatus === "Successful") {
        reconciledStatus = "success";
      } else if (responseCode != null && responseCode !== "00") {
        reconciledStatus = "failed";
      } else if (safeHavenStatus != null && safeHavenStatus !== "Pending") {
        reconciledStatus = "failed";
      }
    } catch (parseErr) {
      console.warn(`[Reconcile] Could not parse Safe Haven response for RRN=${rrn}:`, parseErr);
    }

    console.log(
      `[Reconcile] RRN=${rrn} resolved status=${reconciledStatus}` +
      ` responseCode=${responseCode} safeHavenStatus=${safeHavenStatus}`
    );

    let txRef = null;
    let txData = null;
    let previousStatus = null;
    if (transactionDocId) {
      try {
        txRef = db.collection("transactions").doc(transactionDocId);
        const txSnap = await txRef.get();
        if (txSnap.exists) {
          txData = txSnap.data() || null;
          previousStatus = txData?.status || null;
        }
      } catch (txReadErr) {
        console.error(`[Reconcile] Failed to read transaction doc ${transactionDocId}:`, txReadErr);
      }
    }

    // If Safe Haven still has no record and this tx has stayed pending too long,
    // treat it as a definitive failure.
    if (
      transactionDocId &&
      txData &&
      reconciledStatus === "pending" &&
      previousStatus === "pending"
    ) {
      const createdMs = typeof txData?.timestamp?.toMillis === "function"
        ? txData.timestamp.toMillis()
        : typeof txData?.createdAtFirestore?.toMillis === "function"
          ? txData.createdAtFirestore.toMillis()
          : 0;

      if (createdMs > 0) {
        const ageMs = Date.now() - createdMs;
        const thresholdMs = Math.max(1, pendingFailAfterMinutes) * 60 * 1000;
        if (ageMs >= thresholdMs) {
          reconciledStatus = "failed";
          responseCode = responseCode ?? "TIMEOUT_NOT_FOUND";
          safeHavenStatus = safeHavenStatus ?? "NOT_FOUND_TIMEOUT";
          console.log(
            `[Reconcile] RRN=${rrn} pending for ${Math.floor(ageMs / 60000)}m with no Safe Haven record; marking failed`,
          );
        }
      }
    }

    // Update Firestore if docId provided and status is resolved
    if (transactionDocId && reconciledStatus !== "pending") {
      try {
        await db.collection("transactions").doc(transactionDocId).update({
          status: reconciledStatus,
          reconciledAt: admin.firestore.FieldValue.serverTimestamp(),
          reconciliationResponseCode: responseCode,
          reconciliationSafeHavenStatus: safeHavenStatus,
          reconciliationRaw: raw,
        });
        console.log(`[Reconcile] Updated doc ${transactionDocId} => ${reconciledStatus}`);
      } catch (updateErr) {
        console.error(`[Reconcile] Failed to update Firestore doc ${transactionDocId}:`, updateErr);
      }
    }

    // Send notification from backend when a pending ATM transaction becomes resolved.
    // This keeps notifications consistent even when reconciliation runs in background.
    if (
      txRef &&
      txData &&
      reconciledStatus !== "pending" &&
      txData?.userId &&
      !txData?.reconciliationNotificationSentAt &&
      previousStatus !== reconciledStatus
    ) {
      const userId = txData.userId;
      const amount = Number(txData?.amount || 0);
      const formattedAmount = Number.isFinite(amount) ? amount.toFixed(2) : "0.00";
      const statusTitle = reconciledStatus === "success"
        ? "ATM Payment Confirmed"
        : "ATM Payment Update";
      const statusBody = reconciledStatus === "success"
        ? `Your ATM card payment of NGN ${formattedAmount} has been confirmed successfully.`
        : `Your ATM card payment of NGN ${formattedAmount} could not be confirmed and is marked as failed.`;

      try {
        const userRef = db.collection("users").doc(userId);
        const userSnap = await userRef.get();
        const deviceToken = userSnap.exists ? userSnap.data()?.deviceToken : null;

        if (deviceToken) {
          await admin.messaging().send({
            token: deviceToken,
            notification: {
              title: statusTitle,
              body: statusBody,
            },
            ...FCM_CHANNEL,
          });
        }

        await saveNotification(userId, {
          title: statusTitle,
          body: `${statusBody} (RRN: ${rrn.trim()})`,
          type: reconciledStatus === "success" ? "atm_reconcile_success" : "atm_reconcile_failed",
          amount,
        });

        await txRef.update({
          reconciliationNotificationSentAt: admin.firestore.FieldValue.serverTimestamp(),
          reconciliationNotifiedStatus: reconciledStatus,
        });
        console.log(`[Reconcile] Notification sent for doc ${transactionDocId} => ${reconciledStatus}`);
      } catch (notifyErr) {
        console.error(`[Reconcile] Notification failed for doc ${transactionDocId}:`, notifyErr);
      }
    }

    return { status: reconciledStatus, responseCode, safeHavenStatus };
  },
);

const _toMillis = (v) => {
  if (!v) return 0;
  if (typeof v?.toMillis === "function") return v.toMillis();
  const t = Date.parse(String(v));
  return Number.isFinite(t) ? t : 0;
};

const _normalizeStatementItems = (raw) => {
  if (Array.isArray(raw?.data)) return raw.data;
  if (Array.isArray(raw?.data?.items)) return raw.data.items;
  if (Array.isArray(raw?.items)) return raw.items;
  return [];
};

const _findStatementMatch = (pendingTx, statementItems, usedIds) => {
  const txAmount = Number(pendingTx?.amount || 0);
  const txTime = _toMillis(pendingTx?.timestamp || pendingTx?.createdAtFirestore);
  if (!Number.isFinite(txAmount) || txAmount <= 0 || !txTime) return null;

  let best = null;
  let bestScore = Number.MAX_SAFE_INTEGER;

  for (const item of statementItems) {
    if (!item || usedIds.has(item._id)) continue;
    if (String(item?.type || "").toLowerCase() !== "credit") continue;

    const amount = Number(item?.amount || 0);
    if (!Number.isFinite(amount) || amount <= 0) continue;
    if (Math.abs(amount - txAmount) > 0.01) continue;

    const stTime = _toMillis(item?.transactionDate || item?.valueDate || item?.createdAt);
    if (!stTime) continue;

    const diffMs = Math.abs(stTime - txTime);
    // Keep matching window conservative: 48 hours.
    if (diffMs > 48 * 60 * 60 * 1000) continue;

    if (diffMs < bestScore) {
      best = item;
      bestScore = diffMs;
    }
  }

  return best;
};

exports.backfillAtmTransactionsFromStatement = onCall(
  { secrets: [safehavenClientId, safehavenPrivateKey, safehavenCompanyUrl], timeoutSeconds: 300 },
  async (data, context) => {
    await ensureVerifiedOrStandUser(data.auth);

    const daysBack = Number(data?.data?.daysBack || 7);
    const userId = data?.auth?.uid;
    if (!userId) {
      throw new HttpsError("unauthenticated", "Authentication required");
    }

    const safehavenConfig = await _resolveSafehavenConfig();
    const clientId = safehavenConfig.clientId;
    const privateKey = safehavenConfig.privateKeyPem;
    const companyUrl = safehavenConfig.companyUrl;
    const preferredApiBase = safehavenConfig.baseUrl;
    if (!clientId || !privateKey || !companyUrl) {
      throw new HttpsError("internal", "Safe Haven credentials are not configured");
    }

    let accessToken;
    let apiBase;
    try {
      const authResult = await _getSafehavenAccessToken(
        clientId,
        privateKey,
        companyUrl,
        preferredApiBase,
      );
      accessToken = authResult.accessToken;
      apiBase = authResult.apiBase;
    } catch (authErr) {
      throw new HttpsError("internal", `Safe Haven auth failed: ${authErr.message}`);
    }

    // 1) Resolve default account ID via /accounts
    let accountId = null;
    try {
      const accountsRes = await fetch(`${apiBase}/accounts?page=0&limit=25`, {
        method: "GET",
        headers: {
          "Authorization": `Bearer ${accessToken}`,
          "Content-Type": "application/json",
          "Accept": "application/json",
        },
      });
      const accountsRaw = await accountsRes.json();
      const accounts = Array.isArray(accountsRaw?.data) ? accountsRaw.data : [];
      const preferred = accounts.find((a) => a?.isDefault === true) || accounts[0];
      accountId = preferred?._id || null;
    } catch (e) {
      console.error("[Backfill] Failed to fetch accounts:", e);
    }

    if (!accountId) {
      throw new HttpsError("failed-precondition", "Unable to resolve Safe Haven account ID from /accounts");
    }

    // 2) Fetch account statement (try known URL shapes)
    const from = new Date(Date.now() - Math.max(1, daysBack) * 24 * 60 * 60 * 1000).toISOString();
    const to = new Date().toISOString();
    const statementUrls = [
      `${apiBase}/accounts/${accountId}/statement?page=0&limit=100&fromDate=${encodeURIComponent(from)}&toDate=${encodeURIComponent(to)}`,
      `${apiBase}/accounts/statement?accountId=${encodeURIComponent(accountId)}&page=0&limit=100&fromDate=${encodeURIComponent(from)}&toDate=${encodeURIComponent(to)}`,
      `${apiBase}/statement?accountId=${encodeURIComponent(accountId)}&page=0&limit=100&fromDate=${encodeURIComponent(from)}&toDate=${encodeURIComponent(to)}`,
    ];

    let statementItems = [];
    let statementSourceUrl = null;
    for (const url of statementUrls) {
      try {
        const res = await fetch(url, {
          method: "GET",
          headers: {
            "Authorization": `Bearer ${accessToken}`,
            "Content-Type": "application/json",
            "Accept": "application/json",
          },
        });
        const raw = await res.json();
        const items = _normalizeStatementItems(raw);
        if (res.ok && items.length >= 0) {
          statementItems = items;
          statementSourceUrl = url;
          break;
        }
      } catch (e) {
        console.warn("[Backfill] Statement fetch failed for URL:", url, e?.message || e);
      }
    }

    if (!statementSourceUrl) {
      throw new HttpsError("internal", "Unable to fetch account statement from known endpoints");
    }

    // 3) Reconcile pending ATM docs with statement items by amount + closest timestamp
    const sinceTs = admin.firestore.Timestamp.fromMillis(Date.now() - Math.max(1, daysBack) * 24 * 60 * 60 * 1000);
    const pendingSnap = await db.collection("transactions")
      .where("userId", "==", userId)
      .where("type", "==", "atm_payment")
      .where("status", "==", "pending")
      .where("timestamp", ">=", sinceTs)
      .get();

    const usedStatementIds = new Set();
    let reconciledCount = 0;

    for (const doc of pendingSnap.docs) {
      const tx = doc.data() || {};
      const match = _findStatementMatch(tx, statementItems, usedStatementIds);
      if (!match) continue;

      try {
        const safeHavenRrn = String(match?.paymentReference || "");
        await doc.ref.update({
          status: "success",
          safeHavenRrn: safeHavenRrn || tx.safeHavenRrn || "",
          reconciledAt: admin.firestore.FieldValue.serverTimestamp(),
          reconciliationSource: "safehaven_statement",
          statementTransactionId: match?._id || null,
          statementPaymentReference: match?.paymentReference || null,
          statementProviderChannel: match?.providerChannel || null,
          statementMatchedAt: admin.firestore.FieldValue.serverTimestamp(),
        });
        usedStatementIds.add(match?._id);
        reconciledCount += 1;

        const amount = Number(tx?.amount || 0);
        await saveNotification(userId, {
          title: "ATM Payment Confirmed",
          body: `A pending ATM payment of NGN ${Number.isFinite(amount) ? amount.toFixed(2) : "0.00"} was confirmed from statement reconciliation.`,
          type: "atm_reconcile_success",
          amount,
        });
      } catch (e) {
        console.error(`[Backfill] Failed to reconcile pending tx ${doc.id}:`, e);
      }
    }

    // 4) Save statement credits not found in DB as imported records
    let importedCount = 0;
    for (const item of statementItems) {
      try {
        if (String(item?.type || "").toLowerCase() !== "credit") continue;
        if (!item?._id) continue;

        const existing = await db.collection("transactions")
          .where("statementTransactionId", "==", item._id)
          .limit(1)
          .get();
        if (!existing.empty) continue;

        const amount = Number(item?.amount || 0);
        if (!Number.isFinite(amount) || amount <= 0) continue;

        await db.collection("transactions").add({
          userId,
          type: "atm_payment_imported",
          amount,
          rrn: String(item?.paymentReference || item?._id || ""),
          reference: String(item?.paymentReference || item?._id || ""),
          safeHavenRrn: String(item?.paymentReference || ""),
          terminalId: null,
          status: "success",
          currency: "NGN",
          source: "safehaven_statement",
          statementTransactionId: item?._id,
          statementPaymentReference: item?.paymentReference || null,
          statementProvider: item?.provider || null,
          statementProviderChannel: item?.providerChannel || null,
          statementNarration: item?.narration || null,
          statementRaw: item,
          timestamp: admin.firestore.FieldValue.serverTimestamp(),
          importedAt: admin.firestore.FieldValue.serverTimestamp(),
        });
        importedCount += 1;
      } catch (e) {
        console.error("[Backfill] Failed to import statement row:", e);
      }
    }

    console.log(`[Backfill] accountId=${accountId} statementRows=${statementItems.length} reconciled=${reconciledCount} imported=${importedCount}`);

    return {
      ok: true,
      accountId,
      statementRows: statementItems.length,
      reconciledCount,
      importedCount,
      statementSourceUrl,
    };
  },
);
// ==================== END ATM TRANSACTION RECONCILIATION ====================

// ==================== SUDO AFRICA ? CARDS ====================
const SUDO_BASE_URL = "https://api.sudo.africa";
const SUDO_SANDBOX_BASE_URL = "https://api.sandbox.sudo.africa";
const SUDO_API_KEY_PLACEHOLDER = "__SUDO_API_KEY_PLACEHOLDER__";

// Runtime key override: set appConfig/sudo { secretKeyOverride: "test_key" } in Firestore
// to switch to sandbox without redeployment. Delete the field (or set to "") to use
// the secret key on production URL.
let _sudoKeyOverrideCache = null;
let _sudoKeyOverrideFetchedAt = 0;
const _SUDO_KEY_CACHE_TTL_MS = 60000; // 1 minute

// Returns { apiKey, baseUrl } - sandbox when Firestore override is present, prod otherwise
const _resolveSudoApiConfig = async (fallbackApiKey) => {
  const normalizedFallback =
    fallbackApiKey === SUDO_API_KEY_PLACEHOLDER
      ? ""
      : String(fallbackApiKey || "").trim();
  const now = Date.now();

  if (now - _sudoKeyOverrideFetchedAt < _SUDO_KEY_CACHE_TTL_MS) {
    const apiKey = _sudoKeyOverrideCache || normalizedFallback;
    const baseUrl = _sudoKeyOverrideCache ? SUDO_SANDBOX_BASE_URL : SUDO_BASE_URL;
    return { apiKey, baseUrl };
  }

  try {
    const doc = await db.collection("appConfig").doc("sudo").get();
    const data = doc.exists ? (doc.data() || {}) : {};
    const override = String(
      data.secretKeyOverride || data.apiKeyOverride || "",
    ).trim();

    _sudoKeyOverrideCache = override;
    _sudoKeyOverrideFetchedAt = now;

    const apiKey = override || normalizedFallback;
    const baseUrl = override ? SUDO_SANDBOX_BASE_URL : SUDO_BASE_URL;
    return { apiKey, baseUrl };
  } catch (e) {
    console.warn(
      "Failed to read sudo key override from Firestore, using secret:",
      e.message,
    );
    return { apiKey: normalizedFallback, baseUrl: SUDO_BASE_URL };
  }
};

const sudoRequest = async ({ url, method, apiKey, body }) => {
  const { apiKey: resolvedApiKey, baseUrl: resolvedBaseUrl } =
    await _resolveSudoApiConfig(apiKey);

  if (!resolvedApiKey) {
    throw new HttpsError("internal", "Sudo API key is not configured.");
  }

  const normalizedUrl = String(url || "").trim();
  if (!normalizedUrl) {
    throw new HttpsError("invalid-argument", "URL is required");
  }

  const resolvedUrl = /^https?:\/\//i.test(normalizedUrl)
    ? normalizedUrl
      .replace(SUDO_BASE_URL, resolvedBaseUrl)
      .replace(SUDO_SANDBOX_BASE_URL, resolvedBaseUrl)
    : `${resolvedBaseUrl}${normalizedUrl.startsWith("/") ? "" : "/"}${normalizedUrl}`;

  const headers = {
    Authorization: `Bearer ${resolvedApiKey}`,
    accept: "application/json",
  };

  if (body !== undefined) {
    headers["Content-Type"] = "application/json";
  }

  console.log(
    "Sudo request:",
    JSON.stringify({
      url: resolvedUrl,
      method,
      headers: {
        ...headers,
        Authorization: "Bearer [redacted]",
      },
      body: body !== undefined ? body : null,
    }),
  );

  const options = { method, headers };
  if (body !== undefined) {
    options.body = JSON.stringify(body);
  }

  return fetch(resolvedUrl, options);
};

// ??? Customers ???

// Create a Sudo customer
exports.sudoCreateCustomer = onCall(
  { secrets: [sudoApiKey] },
  async (data) => {
    await ensureVerifiedOrStandUser(data.auth);
    const {
      type, name, phoneNumber, status, emailAddress,
      billingAddress, individual, company,
    } = data.data;

    if (!type || !name || !phoneNumber || !status || !billingAddress) {
      throw new HttpsError(
        "invalid-argument",
        "Missing required parameters: type, name, phoneNumber, status, billingAddress.",
      );
    }

    const apiKey = sudoApiKey.value() || SUDO_API_KEY_PLACEHOLDER;
    if (!apiKey) throw new HttpsError("internal", "Sudo API key is not configured.");

    const body = { type, name, phoneNumber, status, billingAddress };
    if (emailAddress) body.emailAddress = emailAddress;
    if (individual) body.individual = individual;
    if (company) body.company = company;

    try {
      const response = await sudoRequest({
        url: `${SUDO_BASE_URL}/customers`,
        method: "POST",
        apiKey,
        body,
      });

      const json = await response.json();
      console.log("Sudo createCustomer response:", JSON.stringify(json));
      if (!response.ok) {
        console.error("Sudo createCustomer error:", json);
        throw new HttpsError("internal", json.message || `HTTP ${response.status}`);
      }
      return json;
    } catch (err) {
      if (err instanceof HttpsError) throw err;
      console.error("Sudo createCustomer error:", err);
      throw new HttpsError("internal", err.message);
    }
  },
);

// Create a Sudo account
exports.sudoCreateAccount = onCall(
  { secrets: [sudoApiKey] },
  async (data) => {
    await ensureVerifiedOrStandUser(data.auth);
    const { customerId, type, currency, accountType } = data.data;

    if (!customerId) {
      throw new HttpsError("invalid-argument", "customerId is required.");
    }

    const apiKey = sudoApiKey.value() || SUDO_API_KEY_PLACEHOLDER;
    if (!apiKey) throw new HttpsError("internal", "Sudo API key is not configured.");

    const body = {
      customerId,
      type: type || "account",
      currency: currency || "NGN",
      accountType: accountType || "Savings",
    };

    try {
      const response = await sudoRequest({
        url: `${SUDO_BASE_URL}/accounts`,
        method: "POST",
        apiKey,
        body,
      });

      const json = await response.json();
      console.log("Sudo createAccount response:", JSON.stringify(json));
      if (!response.ok) {
        console.error("Sudo createAccount error:", json);
        throw new HttpsError("internal", JSON.stringify(json.message) || `HTTP ${response.status}`);
      }
      return json;
    } catch (err) {
      if (err instanceof HttpsError) throw err;
      console.error("Sudo createAccount error:", err);
      throw new HttpsError("internal", err.message);
    }
  },
);

// Fund a Sudo account then create a card (runs server-side; updates Firestore + sends notification)
exports.sudoFundAndCreateCard = onCall(
  { secrets: [sudoApiKey, smtpHost, smtpUser, smtpPass], timeoutSeconds: 120 },
  async (data) => {
    await ensureVerifiedOrStandUser(data.auth);
    const flowId = `SFC-${Date.now()}-${Math.random().toString(36).slice(2, 8).toUpperCase()}`;
    const {
      userId,
      cardDocId,
      customerId,
      debitAccountId,
      fundingSourceId,
      type,
      brand,
      currency,
      fundAmount,
      usdNgnRate,
      fundAmountNgnEquivalent,
      cardNumber,
      issuerCountry,
    } = data.data;

    console.log("[sudoFundAndCreateCard] START", {
      flowId,
      uid: data.auth?.uid || null,
      userId,
      cardDocId,
      type,
      brand,
      currency,
      hasCustomerId: !!customerId,
      hasDebitAccountId: !!debitAccountId,
      hasFundingSourceId: !!fundingSourceId,
      hasCardNumber: !!cardNumber,
      fundAmount,
      issuerCountry,
    });

    if (!userId || !cardDocId) {
      throw new HttpsError("invalid-argument", "Missing required parameters: userId, cardDocId.");
    }

    // Anonymous cards resolve customer from company Firestore doc; no caller-provided IDs needed
    const isAnonymousCard = (type || "").toLowerCase() === "anonymous";
    if (!isAnonymousCard && !customerId) {
      throw new HttpsError("invalid-argument", "Missing required parameters: customerId.");
    }

    const resolvedCurrency = (currency || "NGN").toUpperCase();
    const resolvedFundAmount = (typeof fundAmount === "number" && fundAmount >= 1) ? fundAmount : 5000;
    const apiKey = sudoApiKey.value() || SUDO_API_KEY_PLACEHOLDER;
    if (!apiKey) throw new HttpsError("internal", "Sudo API key is not configured.");

    const db = admin.firestore();
    const cardRef = db.collection("users").doc(userId).collection("cards").doc(cardDocId);
    const cardDocSnap = await cardRef.get();
    const cardDocData = cardDocSnap.exists ? (cardDocSnap.data() || {}) : {};

    const toPositiveNumber = (value) => {
      if (typeof value === "number" && Number.isFinite(value) && value > 0) return value;
      if (typeof value === "string") {
        const parsed = Number(value);
        if (Number.isFinite(parsed) && parsed > 0) return parsed;
      }
      return null;
    };

    if (!cardDocSnap.exists) {
      console.warn("[sudoFundAndCreateCard] card document not found at start", { flowId, userId, cardDocId });
    }

    // Extracts a human-readable string from a Sudo API message field (may be string or array)
    const parseSudoMessage = (message) => {
      if (!message) return null;
      if (typeof message === "string") return message;
      if (Array.isArray(message)) {
        // Each item may have { constraints: { key: "text" } }
        const texts = message.flatMap((m) => {
          if (m && m.constraints) return Object.values(m.constraints);
          if (typeof m === "string") return [m];
          return [];
        });
        return texts.length > 0 ? texts.join("; ") : JSON.stringify(message);
      }
      return JSON.stringify(message);
    };

    const sendAndSaveNotification = async (title, body, type = "card") => {
      try {
        const userDoc = await db.collection("users").doc(userId).get();
        const deviceToken = userDoc.data()?.deviceToken;
        if (deviceToken) {
          await admin.messaging().send({ token: deviceToken, notification: { title, body }, ...FCM_CHANNEL });
        }
      } catch (notifErr) {
        console.error("Push notification send error:", notifErr);
      }
      await saveNotification(userId, { title, body, type });
    };

    const sendCardEmail = async (subject, html, text) => {
      try {
        const userDoc = await db.collection("users").doc(userId).get();
        const email = userDoc.data()?.emailAddress || userDoc.data()?.email;
        if (email) {
          await sendNotifyEmail({ to: email, subject, html, text });
        }
      } catch (emailErr) {
        console.error("[sudoFundAndCreateCard] Email send error:", emailErr.message);
      }
    };

    try {
      // Resolve effective Sudo customer ID
      // For anonymous cards, use company Firestore doc; for standard cards, use caller-provided value
      let effectiveCustomerId = customerId || "";
      let anonymousCompanyName = null; // set when isAnonymousCard to persist nameOnCard in Firestore
      let resolvedUsdNgnRate = null;
      let resolvedFundAmountNgnEquivalent = null;
      if (isAnonymousCard) {
        const companyRef = db.collection("company").doc("sudoAccountDetails");
        const companySnap = await companyRef.get();

        // Auto-create the Firestore doc with defaults if it doesn't exist yet
        if (!companySnap.exists) {
          console.log("[sudoFundAndCreateCard] company/sudoAccountDetails missing ? creating with defaults...");
          await companyRef.set({
            name: "PadiPay Technologies Ltd",
            phoneNumber: "2348000000000",
            emailAddress: "cards@padipay.co",
            billingAddress: {
              line1: "1 Example Street",
              city: "Lagos Island",
              state: "Lagos",
              country: "NG",
              postalCode: "100001",
            },
            company: {
              name: "PadiPay Technologies Ltd",
              identity: { type: "CAC", number: "RC-0000000" },
              officer: {
                firstName: "Company",
                lastName: "Officer",
                phone: "2348000000000",
                email: "officer@padipay.co",
                identity: { type: "BVN", number: "00000000000" },
                dob: "1990/01/01",
              },
            },
            sudoCustomerId: "",
          });
          console.log("[sudoFundAndCreateCard] company/sudoAccountDetails created with defaults ? update real values in Firebase Console.");
        }

        // Re-read after potential creation
        const companyData = (companySnap.exists ? companySnap : await companyRef.get()).data() || {};
        let companyCustomerId = companyData.sudoCustomerId || "";

        // Auto-create company Sudo customer if not yet provisioned
        if (!companyCustomerId) {
          console.log("[sudoFundAndCreateCard] Provisioning company Sudo customer for anonymous cards...");
          const custBody = {
            type: "company",
            name: companyData.name || "PadiPay Technologies Ltd",
            phoneNumber: companyData.phoneNumber || "",
            emailAddress: companyData.emailAddress || "",
            status: "active",
            ...(companyData.billingAddress ? { billingAddress: companyData.billingAddress } : {}),
            company: {
              name: companyData.company?.name || companyData.name || "PadiPay Technologies Ltd",
              ...(companyData.company?.identity ? { identity: companyData.company.identity } : {}),
              ...(companyData.company?.officer ? {
                officer: {
                  firstName: companyData.company.officer.firstName || "",
                  lastName: companyData.company.officer.lastName || "",
                  phone: companyData.company.officer.phone || "",
                  email: companyData.company.officer.email || "",
                  ...(companyData.company.officer.identity ? { identity: companyData.company.officer.identity } : {}),
                  ...(companyData.company.officer.dob ? { dob: companyData.company.officer.dob } : {}),
                },
              } : {}),
            },
          };
          const custRes = await sudoRequest({
            url: `${SUDO_BASE_URL}/customers`,
            method: "POST",
            apiKey,
            body: custBody,
          });
          const custJson = await custRes.json();
          console.log("[sudoFundAndCreateCard] Company customer create response:", JSON.stringify(custJson));
          if (!custRes.ok) throw new Error(custJson.message || "Failed to create company Sudo customer");
          companyCustomerId = custJson.data?._id;
          if (!companyCustomerId) throw new Error("No _id in company Sudo customer response");
          await companyRef.update({ sudoCustomerId: companyCustomerId });
          console.log("[sudoFundAndCreateCard] Company Sudo customer created:", companyCustomerId);
        }

        effectiveCustomerId = companyCustomerId;
        if (!effectiveCustomerId) {
          throw new Error("Company Sudo customer could not be provisioned. Please try again or contact support.");
        }
        anonymousCompanyName = companyData.name || "All Good Technologies Limited";
        console.log(`[sudoFundAndCreateCard] Anonymous card: company customerId=${effectiveCustomerId}`);
      }

      if (resolvedCurrency === "USD") {
        const companyRateSnap = await db.collection("company").doc("sudoAccountDetails").get();
        const companyRateData = companyRateSnap.exists ? (companyRateSnap.data() || {}) : {};

        resolvedUsdNgnRate =
          toPositiveNumber(usdNgnRate) ||
          toPositiveNumber(cardDocData.usdNgnRate) ||
          toPositiveNumber(companyRateData.usdNgnRate);

        if (!resolvedUsdNgnRate) {
          throw new Error(
            "USD/NGN rate is not configured. Please contact support before creating a USD card.",
          );
        }

        resolvedFundAmountNgnEquivalent =
          toPositiveNumber(fundAmountNgnEquivalent) ||
          Number((resolvedFundAmount * resolvedUsdNgnRate).toFixed(2));
      }

      // Step 0: Auto-update customer with phone, email and identity details
      // Sudo requires these before allowing card creation, so we do it every time (idempotent)
      // Skipped for anonymous cards (company customer; no per-user identity update)
      if (!isAnonymousCard) try {
        const userDoc = await db.collection("users").doc(userId).get();
        const uData = userDoc.data() || {};
        const firstName = uData.firstName || "";
        const lastName = uData.lastName || "";
        const phone = uData.phone || "";
        const email = uData.emailAddress || uData.email || "";
        const bvn = uData.bvn || "";
        const dob = uData.dateOfBirth || ""; // expected as YYYY-MM-DD or similar
        const addr = uData.address || {};

        // Format phone to E.164-style Nigerian number expected by Sudo
        let formattedPhone = phone.replace(/\D/g, "");
        if (formattedPhone.startsWith("0") && formattedPhone.length === 11) {
          formattedPhone = "234" + formattedPhone.substring(1);
        } else if (formattedPhone.length === 10 && !formattedPhone.startsWith("234")) {
          formattedPhone = "234" + formattedPhone;
        }

        // Format DOB to YYYY/MM/DD (Sudo's required format) from DD/MM/YYYY stored in Firestore
        let formattedDob = dob;
        if (dob && dob.includes("/")) {
          const parts = dob.split("/");
          if (parts.length === 3) {
            if (parts[0].length === 4) {
              // Already YYYY/MM/DD ? reformat slashes just in case
              formattedDob = `${parts[0]}/${parts[1].padStart(2, "0")}/${parts[2].padStart(2, "0")}`;
            } else {
              // Assume DD/MM/YYYY ? convert to YYYY/MM/DD
              formattedDob = `${parts[2]}/${parts[1].padStart(2, "0")}/${parts[0].padStart(2, "0")}`;
            }
          }
        } else if (dob && dob.includes("-")) {
          // Handle YYYY-MM-DD ? YYYY/MM/DD
          formattedDob = dob.replace(/-/g, "/");
        }

        const updateBody = {
          phoneNumber: formattedPhone || phone,
          emailAddress: email,
          individual: {
            firstName,
            lastName,
            // dateOfBirth goes at the individual level as `dob`, format YYYY/MM/DD
            ...(formattedDob ? { dob: formattedDob } : {}),
            ...(bvn ? {
              identity: {
                type: "BVN",
                number: bvn,
              },
            } : {}),
          },
          ...(addr.street ? {
            billingAddress: {
              line1: addr.street,
              city: addr.city || "",
              state: addr.state || "",
              country: addr.country || "NG",
              postalCode: String(addr.postalCode || "000000"),
            },
          } : {}),
        };

        console.log(`[sudoFundAndCreateCard] Step 0: Updating customer ${customerId} with identity data`);
        const updateRes = await sudoRequest({
          url: `${SUDO_BASE_URL}/customers/${encodeURIComponent(customerId)}`,
          method: "PUT",
          apiKey,
          body: updateBody,
        });
        const updateJson = await updateRes.json();
        console.log("[sudoFundAndCreateCard] Customer update response:", JSON.stringify(updateJson));
        if (!updateRes.ok) {
          console.warn("[sudoFundAndCreateCard] Customer update failed (non-fatal):", updateJson.message);
        }
      } catch (updateErr) {
        console.warn("[sudoFundAndCreateCard] Customer update step failed (non-fatal):", updateErr.message);
      }

      // Step 1: Resolve debitAccountId
      // Sudo requires debitAccountId on /cards. Sudo limits ONE NGN + ONE USD account per business,
      // so all cards (anonymous or not) share the same business-level settlement accounts.
      // Resolution order: company Firestore doc -> caller-provided -> GET /accounts -> error.
      let effectiveDebitAccountId = "";
      {
        const companyRef = db.collection("company").doc("sudoAccountDetails");
        const companySnap = await companyRef.get();
        const companyData = companySnap.exists ? (companySnap.data() || {}) : {};
        const accountField = resolvedCurrency === "USD" ? "sudoUsdAccountId" : "sudoNgnAccountId";

        // 1. Check company doc first
        effectiveDebitAccountId = companyData[accountField] || "";

        // 2. If caller passed a known account ID, adopt it
        if (!effectiveDebitAccountId && debitAccountId && typeof debitAccountId === "string" && debitAccountId.length === 24) {
          effectiveDebitAccountId = debitAccountId;
          console.log(`[sudoFundAndCreateCard] Adopting caller-provided debitAccountId: ${effectiveDebitAccountId}`);
          await companyRef.set({ [accountField]: effectiveDebitAccountId }, { merge: true });
        }

        // 3. GET /accounts to find the business settlement account
        if (!effectiveDebitAccountId) {
          try {
            const accsRes = await sudoRequest({
              url: `${SUDO_BASE_URL}/accounts`,
              method: "GET",
              apiKey,
            });
            const accsJson = await accsRes.json();
            console.log(`[sudoFundAndCreateCard] GET /accounts:`, JSON.stringify(accsJson));
            if (accsRes.ok && Array.isArray(accsJson.data)) {
              const match = accsJson.data.find((a) =>
                (a.type || "").toLowerCase() === "account" &&
                (a.currency || "").toUpperCase() === resolvedCurrency
              );
              if (match?._id && typeof match._id === "string" && match._id.length === 24) {
                effectiveDebitAccountId = match._id;
                await companyRef.set({ [accountField]: effectiveDebitAccountId }, { merge: true });
                console.log(`[sudoFundAndCreateCard] Found ${resolvedCurrency} settlement account: ${effectiveDebitAccountId}`);
              }
            }
          } catch (listErr) {
            console.warn("[sudoFundAndCreateCard] GET /accounts failed:", listErr.message);
          }
        }

        if (!effectiveDebitAccountId) {
          throw new Error(
            `Card setup incomplete: no ${resolvedCurrency} settlement account found. ` +
            `Please contact support or try again.`
          );
        }

        console.log(`[sudoFundAndCreateCard] Resolved debitAccountId (${resolvedCurrency}): ${effectiveDebitAccountId}`);
      }

      // Step 1.5: Resolve fundingSourceId.
      // USD cards require an active default funding source; other currencies use an active gateway source.
      // Resolution order: company Firestore doc -> caller-provided -> GET /fundingsources -> auto-create -> error.
      let effectiveFundingSourceId = "";
      {
        const companyRef = db.collection("company").doc("sudoAccountDetails");
        const companySnap = await companyRef.get();
        const companyData = companySnap.exists ? (companySnap.data() || {}) : {};
        const needsDefaultFundingSource = resolvedCurrency === "USD";
        const requiredFundingType = needsDefaultFundingSource ? "default" : "gateway";
        const fundingSourceField = needsDefaultFundingSource
          ? "sudoUsdFundingSourceId"
          : "sudoFundingSourceId";

        const fetchFundingSources = async () => {
          try {
            const fsRes = await sudoRequest({
              url: `${SUDO_BASE_URL}/fundingsources`,
              method: "GET",
              apiKey,
            });
            const fsJson = await fsRes.json();
            console.log("[sudoFundAndCreateCard] GET /fundingsources:", JSON.stringify(fsJson));
            if (fsRes.ok && Array.isArray(fsJson.data)) {
              return fsJson.data;
            }
          } catch (fsErr) {
            console.warn("[sudoFundAndCreateCard] GET /fundingsources failed:", fsErr.message);
          }
          return [];
        };

        const isActiveRequiredType = (f) =>
          (f?.type || "").toLowerCase() === requiredFundingType &&
          (f?.status || "").toLowerCase() === "active" &&
          f?.isDeleted !== true;

        const firstActiveRequiredType = (sources) =>
          sources.find((f) => isActiveRequiredType(f) && f?.isDefault === true) ||
          sources.find((f) => isActiveRequiredType(f));

        const fundingSources = await fetchFundingSources();
        const activeFundingSource = firstActiveRequiredType(fundingSources);
        const activeFundingSourceId = activeFundingSource?._id && typeof activeFundingSource._id === "string"
          ? activeFundingSource._id
          : "";

        // 1. Check company doc first
        const companyFundingSourceId = (companyData[fundingSourceField] || "").toString();
        if (companyFundingSourceId) {
          const companySource = fundingSources.find((f) => (f?._id || "").toString() === companyFundingSourceId);
          if (companySource && isActiveRequiredType(companySource)) {
            effectiveFundingSourceId = companyFundingSourceId;
          } else {
            console.warn(
              `[sudoFundAndCreateCard] Ignoring inactive/stale company ${requiredFundingType} fundingSourceId: ${companyFundingSourceId}`,
            );
            await companyRef.set({ [fundingSourceField]: "" }, { merge: true });
          }
        }

        // 2. If caller passed one, adopt it and persist for subsequent card creations
        if (!effectiveFundingSourceId && fundingSourceId && typeof fundingSourceId === "string") {
          const callerFundingSourceId = fundingSourceId.trim();
          const callerSource = fundingSources.find((f) => (f?._id || "").toString() === callerFundingSourceId);
          if (callerSource && isActiveRequiredType(callerSource)) {
            effectiveFundingSourceId = callerFundingSourceId;
            await companyRef.set({ [fundingSourceField]: effectiveFundingSourceId }, { merge: true });
            console.log(
              `[sudoFundAndCreateCard] Adopting caller-provided active ${requiredFundingType} fundingSourceId: ${effectiveFundingSourceId}`,
            );
          } else {
            console.warn(
              `[sudoFundAndCreateCard] Ignoring caller fundingSourceId because it is not an active ${requiredFundingType} source: ${callerFundingSourceId}`,
            );
          }
        }

        // 3. Use active funding source from /fundingsources for this currency profile
        if (!effectiveFundingSourceId && activeFundingSourceId) {
          effectiveFundingSourceId = activeFundingSourceId;
          await companyRef.set({ [fundingSourceField]: effectiveFundingSourceId }, { merge: true });
          console.log(
            `[sudoFundAndCreateCard] Using active ${requiredFundingType} fundingSourceId from /fundingsources: ${effectiveFundingSourceId}`,
          );
        }

        // 4. Auto-create required funding source type if still not resolved
        if (!effectiveFundingSourceId) {
          try {
            console.log(
              `[sudoFundAndCreateCard] No active ${requiredFundingType} fundingSourceId found - auto-creating ${requiredFundingType} funding source...`,
            );
            const createFsRes = await sudoRequest({
              url: `${SUDO_BASE_URL}/fundingsources`,
              method: "POST",
              apiKey,
              body: { type: requiredFundingType, status: "active" },
            });
            const createFsJson = await createFsRes.json();
            console.log("[sudoFundAndCreateCard] Auto-create fundingSource response:", JSON.stringify(createFsJson));
            const createdId = createFsJson?.data?._id;
            if (createFsRes.ok && createdId && typeof createdId === "string") {
              effectiveFundingSourceId = createdId;
              await companyRef.set({ [fundingSourceField]: effectiveFundingSourceId }, { merge: true });
              console.log(
                `[sudoFundAndCreateCard] Auto-created ${requiredFundingType} fundingSourceId: ${effectiveFundingSourceId}`,
              );
            } else {
              console.error("[sudoFundAndCreateCard] Auto-create fundingSource failed:", createFsJson?.message || `HTTP ${createFsRes.status}`);
            }
          } catch (createFsErr) {
            console.error("[sudoFundAndCreateCard] Auto-create fundingSource error:", createFsErr.message);
          }
        }

        if (effectiveFundingSourceId) {
          console.log(`[sudoFundAndCreateCard] Resolved fundingSourceId: ${effectiveFundingSourceId}`);
        } else {
          throw new Error(
            `Card setup incomplete: no active ${requiredFundingType} fundingSourceId found and auto-create failed. ` +
            "Please verify Sudo funding sources and try again."
          );
        }
      }

      // Step 2: Create the card
      const isPhysical = (type || "virtual") === "physical";
      const resolvedIssuerCountry = issuerCountry || (resolvedCurrency === "USD" ? "USA" : "NGA");
      const normalizePhysicalBrand = (rawBrand) => {
        const val = (rawBrand || "").toString().toLowerCase();
        if (val.includes("afrigo")) return "AfriGo";
        if (val.includes("verve")) return "Verve";
        return "Verve";
      };
      const isLinkedPhysicalError = (msg) =>
        /already linked|not fetched/i.test((msg || "").toString());

      let currentInventoryCardDocId = cardDocData.inventoryCardDocId || null;
      let currentPhysicalCardNumber = "";
      const currentPhysicalBrand = normalizePhysicalBrand(brand || cardDocData.scheme || "Verve");

      const reserveReplacementPhysicalNumber = async () => {
        const nextInvSnap = await db
          .collection("physical_card_inventory")
          .where("brand", "==", currentPhysicalBrand)
          .where("status", "==", "unassigned")
          .limit(1)
          .get();

        if (nextInvSnap.empty) return null;

        const nextInvDoc = nextInvSnap.docs[0];
        const nextInvData = nextInvDoc.data() || {};
        const nextNumber = (nextInvData.cardNumber || "").toString().trim();
        if (!nextNumber) return null;

        const etaDate =
          cardDocData?.physicalCardTracking?.etaDate ||
          new Date(Date.now() + 14 * 24 * 60 * 60 * 1000).toISOString();

        await nextInvDoc.ref.update({
          status: "assigned",
          assignedUserId: userId,
          assignedAt: admin.firestore.FieldValue.serverTimestamp(),
          updatedAt: admin.firestore.FieldValue.serverTimestamp(),
          tracking: {
            status: "pending",
            note: "Order confirmed. Card is being prepared.",
            etaDate,
            updatedAt: admin.firestore.FieldValue.serverTimestamp(),
          },
        });

        await cardRef.update({
          inventoryCardDocId: nextInvDoc.id,
          assignedPhysicalCardNumber: nextNumber,
          physicalCardDelivered: false,
          physicalCardTracking: {
            status: "pending",
            note: "Order confirmed. Card is being prepared.",
            etaDate,
          },
          updatedAt: admin.firestore.FieldValue.serverTimestamp(),
        });

        return { nextInventoryCardDocId: nextInvDoc.id, nextNumber };
      };

      // Resolve physical card number from inventory-backed Firestore assignment first,
      // then fallback to caller payload for backward compatibility.
      if (isPhysical) {
        currentPhysicalCardNumber = (
          cardDocData.assignedPhysicalCardNumber ||
          cardDocData.cardNumber ||
          cardNumber ||
          ""
        ).toString().trim();

        if (!currentPhysicalCardNumber) {
          throw new Error(
            "Physical card creation requires an assigned inventory card number, but none was found.",
          );
        }

        const maskedPhysical =
          currentPhysicalCardNumber.length > 4
            ? `${"*".repeat(currentPhysicalCardNumber.length - 4)}${currentPhysicalCardNumber.slice(-4)}`
            : currentPhysicalCardNumber;

        console.log("[sudoFundAndCreateCard] Physical number resolved", {
          flowId,
          source: cardDocData.assignedPhysicalCardNumber
            ? "cardDoc.assignedPhysicalCardNumber"
            : cardDocData.cardNumber
              ? "cardDoc.cardNumber"
              : cardNumber
                ? "payload.cardNumber"
                : "none",
          maskedPhysical,
          inventoryCardDocId: cardDocData.inventoryCardDocId || null,
        });
      }
      const maxCreateAttempts = isPhysical ? 2 : 1;
      let cardData = null;
      for (let attempt = 1; attempt <= maxCreateAttempts; attempt++) {
        const cardReference = `PADI-${Date.now()}-${Math.random().toString(36).substring(2, 8).toUpperCase()}`;
        const cardBody = {
          customerId: effectiveCustomerId,
          type: isAnonymousCard ? "virtual" : (type || "virtual"),
          currency: resolvedCurrency,
          status: "active",
          brand: brand || "Verve",
          debitAccountId: effectiveDebitAccountId,
          ...(effectiveFundingSourceId ? { fundingSourceId: effectiveFundingSourceId } : {}),
          amount: resolvedFundAmount,
          issuerCountry: resolvedIssuerCountry,
          ...(isPhysical && {
            number: currentPhysicalCardNumber,
            cardReference,
          }),
        };

        console.log("[sudoFundAndCreateCard] Creating card", {
          flowId,
          attempt,
          type: cardBody.type,
          brand: cardBody.brand,
          currency: cardBody.currency,
          issuerCountry: cardBody.issuerCountry,
          hasNumber: !!cardBody.number,
          cardReference: cardBody.cardReference || null,
          inventoryCardDocId: currentInventoryCardDocId,
        });

        const cardResponse = await sudoRequest({
          url: `${SUDO_BASE_URL}/cards`,
          method: "POST",
          apiKey,
          body: cardBody,
        });
        const cardJson = await cardResponse.json();
        console.log("[sudoFundAndCreateCard] createCard response", {
          flowId,
          attempt,
          ok: cardResponse.ok,
          statusCode: cardJson?.statusCode || cardResponse.status,
          cardId: cardJson?.data?._id || null,
          message: cardJson?.message || null,
        });

        if (cardResponse.ok && !(cardJson.statusCode && cardJson.statusCode >= 400)) {
          cardData = cardJson.data;
          break;
        }

        const msg = parseSudoMessage(cardJson.message) || "Card creation failed";
        if (isPhysical && attempt < maxCreateAttempts && isLinkedPhysicalError(msg)) {
          console.warn("[sudoFundAndCreateCard] Physical PAN already linked; rotating inventory and retrying", {
            flowId,
            attempt,
            inventoryCardDocId: currentInventoryCardDocId,
            reason: msg,
          });

          if (currentInventoryCardDocId) {
            await db
              .collection("physical_card_inventory")
              .doc(currentInventoryCardDocId)
              .set(
                {
                  status: "invalid_linked",
                  invalidReason: msg,
                  invalidatedAt: admin.firestore.FieldValue.serverTimestamp(),
                  updatedAt: admin.firestore.FieldValue.serverTimestamp(),
                },
                { merge: true },
              )
              .catch((invErr) => {
                console.warn("[sudoFundAndCreateCard] Failed to mark invalid inventory PAN", {
                  flowId,
                  inventoryCardDocId: currentInventoryCardDocId,
                  error: invErr.message,
                });
              });
          }

          const replacement = await reserveReplacementPhysicalNumber();
          if (!replacement) {
            throw new Error(
              `${msg}. No replacement physical card number is available for ${currentPhysicalBrand}.`,
            );
          }

          currentInventoryCardDocId = replacement.nextInventoryCardDocId;
          currentPhysicalCardNumber = replacement.nextNumber;

          console.log("[sudoFundAndCreateCard] Physical PAN rotated", {
            flowId,
            nextInventoryCardDocId: currentInventoryCardDocId,
            maskedPhysical:
              currentPhysicalCardNumber.length > 4
                ? `${"*".repeat(currentPhysicalCardNumber.length - 4)}${currentPhysicalCardNumber.slice(-4)}`
                : currentPhysicalCardNumber,
          });

          continue;
        }

        throw new Error(msg);
      }

      if (!cardData) {
        throw new Error("Card creation failed after retry.");
      }

      const cardId = cardData?._id;

      if (!cardId) {
        throw new Error(`Card creation succeeded but no _id returned: ${JSON.stringify(cardData)}`);
      }

      // Step 3: Update Firestore card doc to active
      await cardRef.update({
        status: "active",
        card_id: cardId,
        sudoCardData: cardData,
        provider: "sudo",
        sudoAccountId: effectiveDebitAccountId,
        ...(resolvedCurrency === "USD" && resolvedUsdNgnRate
          ? {
              usdNgnRate: resolvedUsdNgnRate,
              fundAmountUsd: resolvedFundAmount,
              fundAmountNgnEquivalent: resolvedFundAmountNgnEquivalent,
            }
          : {}),
        ...(isAnonymousCard && anonymousCompanyName ? { nameOnCard: anonymousCompanyName } : {}),
      });
      console.log("[sudoFundAndCreateCard] Card saved", { flowId, cardId, userId, cardDocId });

      // Step 3.5: Auto-change card PIN from Sudo default to user's chosen PIN
      try {
        const latestCardDocSnap = await cardRef.get();
        const userPin = latestCardDocSnap.data()?.pin;
        if (userPin && typeof userPin === "string" && userPin.length === 4) {
          const defaultPinResponse = await sudoRequest({
            url: `${SUDO_BASE_URL}/cards/${cardId}/secure-data/defaultPin`,
            method: "GET",
            apiKey,
          });
          const defaultPinJson = await defaultPinResponse.json();
          const defaultPin = defaultPinJson.data?.defaultPin;
          if (defaultPin) {
            await sudoRequest({
              url: `${SUDO_BASE_URL}/cards/${cardId}/pin`,
              method: "PUT",
              apiKey,
              body: { oldPin: defaultPin, newPin: userPin },
            });
            console.log("[sudoFundAndCreateCard] PIN auto-changed", { flowId, cardId });
          } else {
            console.warn("[sudoFundAndCreateCard] Could not retrieve default PIN", { flowId, cardId });
          }
        }
      } catch (pinErr) {
        console.warn("[sudoFundAndCreateCard] PIN auto-change failed (non-fatal)", {
          flowId,
          cardId,
          error: pinErr.message,
        });
      }

      // Step 4: Notify user and save to notifications collection
      await sendAndSaveNotification(
        "Your card is ready! ??",
        `Your ${resolvedCurrency} virtual card has been created successfully.`,
        "card_created"
      );

      // Step 5: Send confirmation email
      await sendCardEmail(
        `Your ${resolvedCurrency} Card is Ready! ?? ? PadiPay`,
        `<div style="font-family:Arial,sans-serif;max-width:600px;margin:0 auto;padding:24px;color:#111827;">
          <h2 style="margin:0 0 16px;color:#10b981;">Your ${resolvedCurrency} Card is Ready! ??</h2>
          <p style="margin:0 0 16px;">Great news! Your ${resolvedCurrency} virtual card has been created successfully on PadiPay.</p>
          <div style="background:#f9fafb;border:1px solid #e5e7eb;border-radius:12px;padding:16px;margin:0 0 16px;">
            <p style="margin:0 0 8px;"><strong>Card type:</strong> ${type || "Virtual"}</p>
            <p style="margin:0;"><strong>Currency:</strong> ${resolvedCurrency}</p>
          </div>
          <p style="margin:0 0 16px;">You can now use your card for online payments. Open the PadiPay app to view your card details.</p>
          <p style="margin:0;color:#6b7280;font-size:13px;">If you did not request this card, please contact PadiPay support immediately.</p>
        </div>`,
        `Your ${resolvedCurrency} card has been created successfully on PadiPay. Open the app to view your card details.`
      );

      console.log("[sudoFundAndCreateCard] SUCCESS", { flowId, userId, cardDocId, cardId });
      return { success: true, cardId, flowId };
    } catch (err) {
      console.error("[sudoFundAndCreateCard] ERROR", {
        flowId,
        userId,
        cardDocId,
        type,
        currency: resolvedCurrency,
        error: err.message,
        stack: err.stack,
      });

      // If a physical card inventory PAN was assigned for this attempt,
      // release it back to inventory so it can be reused on future requests.
      try {
        const failedCardSnap = await cardRef.get();
        const failedCardData = failedCardSnap.exists ? (failedCardSnap.data() || {}) : {};
        const isPhysicalCard = (failedCardData.type || type || "").toString().toLowerCase() === "physical";
        const inventoryCardDocId = (failedCardData.inventoryCardDocId || "").toString();

        if (isPhysicalCard && inventoryCardDocId) {
          const inventoryRef = db.collection("physical_card_inventory").doc(inventoryCardDocId);
          const inventorySnap = await inventoryRef.get();
          const inventoryData = inventorySnap.exists ? (inventorySnap.data() || {}) : {};
          const inventoryStatus = (inventoryData.status || "").toString().toLowerCase();
          const assignedUserId = (inventoryData.assignedUserId || "").toString();
          const assignedCardDocId = (inventoryData.assignedCardDocId || "").toString();

          if (inventorySnap.exists) {
            await inventoryRef.update({
              status: "unassigned",
              assignedUserId: admin.firestore.FieldValue.delete(),
              assignedAt: admin.firestore.FieldValue.delete(),
              assignedCardDocId: admin.firestore.FieldValue.delete(),
              assignedCardDocPath: admin.firestore.FieldValue.delete(),
              tracking: {
                status: "pending",
                note: "Released after failed card creation",
                updatedAt: admin.firestore.FieldValue.serverTimestamp(),
              },
              updatedAt: admin.firestore.FieldValue.serverTimestamp(),
            });

            await cardRef.update({
              inventoryCardDocId: admin.firestore.FieldValue.delete(),
              assignedPhysicalCardNumber: admin.firestore.FieldValue.delete(),
              physicalCardDelivered: admin.firestore.FieldValue.delete(),
              physicalCardTracking: admin.firestore.FieldValue.delete(),
              inventoryAssignmentReleasedAt: admin.firestore.FieldValue.serverTimestamp(),
              inventoryAssignmentReleaseReason: err.message || "unknown",
            });

            console.log("[sudoFundAndCreateCard] Released physical inventory assignment after failure", {
              flowId,
              inventoryCardDocId,
              userId,
              cardDocId,
              previousStatus: inventoryStatus || null,
            });
          } else {
            console.warn("[sudoFundAndCreateCard] Skipped inventory release", {
              flowId,
              inventoryCardDocId,
              reason: "inventory document not found",
              inventoryStatus,
              assignedUserId,
              assignedCardDocId,
            });
          }
        }
      } catch (releaseErr) {
        console.error("[sudoFundAndCreateCard] Failed to release physical inventory assignment", {
          flowId,
          userId,
          cardDocId,
          error: releaseErr.message,
        });
      }

      // Mark card as failed
      await cardRef
        .update({
          status: "failed",
          lastServerError: err.message || "unknown",
          lastServerErrorAt: admin.firestore.FieldValue.serverTimestamp(),
          flowId,
        })
        .catch(() => {});

      // Only surface user-friendly Sudo messages (card brand/type availability).
      // Technical errors (account IDs, validation, internal config) use a generic message.
      const rawMsg = err.message || "";
      const isUserFriendly = /not available at the moment/i.test(rawMsg);
      const userMsg = isUserFriendly
        ? `We couldn't create your card: ${rawMsg}`
        : "We couldn't create your card. Please try again later.";
      const emailReason = isUserFriendly
        ? `<p style="margin:0 0 16px;"><strong>Reason:</strong> ${rawMsg}</p>`
        : "";

      await sendAndSaveNotification(
        "Card creation failed",
        userMsg,
        "card_failed"
      );
      await sendCardEmail(
        `Card Creation Failed ? PadiPay`,
        `<div style="font-family:Arial,sans-serif;max-width:600px;margin:0 auto;padding:24px;color:#111827;">
          <h2 style="margin:0 0 16px;color:#ef4444;">Card Creation Failed</h2>
          <p style="margin:0 0 16px;">Unfortunately, we were unable to create your ${resolvedCurrency} card on PadiPay.</p>
          ${emailReason}<p style="margin:0 0 16px;">Please try again from the app. If the problem persists, contact PadiPay support.</p>
        </div>`,
        `${userMsg} If the problem persists, contact PadiPay support.`
      );
      throw new HttpsError("internal", err.message);
    }
  },
);

// Get all Sudo customers
exports.sudoChangeCardPin = onCall(
  { secrets: [sudoApiKey] },
  async (data) => {
    await ensureVerifiedOrStandUser(data.auth);
    const { cardId, oldPin, newPin } = data.data || {};
    console.log(`[sudoChangeCardPin] Called for cardId: ${cardId}, uid: ${data.auth?.uid}`);

    if (!cardId || typeof cardId !== "string") throw new HttpsError("invalid-argument", "cardId is required.");
    if (!oldPin || typeof oldPin !== "string" || oldPin.length !== 4) throw new HttpsError("invalid-argument", "oldPin must be a 4-digit string.");
    if (!newPin || typeof newPin !== "string" || newPin.length !== 4) throw new HttpsError("invalid-argument", "newPin must be a 4-digit string.");

    const apiKey = sudoApiKey.value() || SUDO_API_KEY_PLACEHOLDER;
    if (!apiKey) throw new HttpsError("internal", "Sudo API key is not configured.");

    try {
      const response = await sudoRequest({
        url: `${SUDO_BASE_URL}/cards/${cardId}/pin`,
        method: "PUT",
        apiKey,
        body: { oldPin, newPin },
      });

      const json = await response.json();
      console.log("[sudoChangeCardPin] Response:", JSON.stringify(json));

      if (!response.ok) {
        const msg = json.message || `HTTP ${response.status}`;
        throw new HttpsError("internal", msg);
      }

      // Update Firestore pin field so local verification stays in sync
      const uid = data.auth?.uid;
      if (uid) {
        try {
          const cardsSnap = await db.collection("cards")
            .where("user_id", "==", uid)
            .where("card_id", "==", cardId)
            .limit(1)
            .get();
          if (!cardsSnap.empty) {
            await cardsSnap.docs[0].ref.update({ pin: newPin });
            console.log(`[sudoChangeCardPin] Firestore pin updated for cardId: ${cardId}`);
          } else {
            console.warn(`[sudoChangeCardPin] No Firestore card doc found for cardId: ${cardId}, uid: ${uid}`);
          }
        } catch (fsErr) {
          console.warn("[sudoChangeCardPin] Firestore pin update failed (non-fatal):", fsErr.message);
        }
      }

      console.log(`[sudoChangeCardPin] Success for cardId: ${cardId}`);
      return { success: true };
    } catch (err) {
      if (err instanceof HttpsError) throw err;
      console.error("[sudoChangeCardPin] Error:", err);
      throw new HttpsError("internal", err.message);
    }
  },
);

exports.sudoGetCustomers = onCall(
  { secrets: [sudoApiKey] },
  async (data) => {
    await ensureVerifiedOrStandUser(data.auth);
    const { page, limit } = data.data || {};

    const apiKey = sudoApiKey.value() || SUDO_API_KEY_PLACEHOLDER;
    if (!apiKey) throw new HttpsError("internal", "Sudo API key is not configured.");

    const params = new URLSearchParams();
    if (page !== undefined) params.append("page", String(page));
    if (limit !== undefined) params.append("limit", String(limit));

    try {
      const response = await sudoRequest({
        url: `${SUDO_BASE_URL}/customers?${params.toString()}`,
        method: "GET",
        apiKey,
      });

      const json = await response.json();
      console.log("Sudo getCustomers response:", JSON.stringify(json));
      if (!response.ok) {
        console.error("Sudo getCustomers error:", json);
        throw new HttpsError("internal", json.message || `HTTP ${response.status}`);
      }
      return json;
    } catch (err) {
      if (err instanceof HttpsError) throw err;
      console.error("Sudo getCustomers error:", err);
      throw new HttpsError("internal", err.message);
    }
  },
);

// Get a single Sudo customer
exports.sudoGetCustomer = onCall(
  { secrets: [sudoApiKey] },
  async (data) => {
    await ensureVerifiedOrStandUser(data.auth);
    const { customerId } = data.data;
    if (!customerId) throw new HttpsError("invalid-argument", "customerId is required.");

    const apiKey = sudoApiKey.value() || SUDO_API_KEY_PLACEHOLDER;
    if (!apiKey) throw new HttpsError("internal", "Sudo API key is not configured.");

    try {
      const response = await sudoRequest({
        url: `${SUDO_BASE_URL}/customers/${encodeURIComponent(customerId)}`,
        method: "GET",
        apiKey,
      });

      const json = await response.json();
      console.log("Sudo getCustomer response:", JSON.stringify(json));
      if (!response.ok) {
        console.error("Sudo getCustomer error:", json);
        throw new HttpsError("internal", json.message || `HTTP ${response.status}`);
      }
      return json;
    } catch (err) {
      if (err instanceof HttpsError) throw err;
      console.error("Sudo getCustomer error:", err);
      throw new HttpsError("internal", err.message);
    }
  },
);

// Update a Sudo customer
exports.sudoUpdateCustomer = onCall(
  { secrets: [sudoApiKey] },
  async (data) => {
    await ensureVerifiedOrStandUser(data.auth);
    const { customerId, ...updateFields } = data.data;
    if (!customerId) throw new HttpsError("invalid-argument", "customerId is required.");

    const apiKey = sudoApiKey.value() || SUDO_API_KEY_PLACEHOLDER;
    if (!apiKey) throw new HttpsError("internal", "Sudo API key is not configured.");

    try {
      const response = await sudoRequest({
        url: `${SUDO_BASE_URL}/customers/${encodeURIComponent(customerId)}`,
        method: "PUT",
        apiKey,
        body: updateFields,
      });

      const json = await response.json();
      console.log("Sudo updateCustomer response:", JSON.stringify(json));
      if (!response.ok) {
        console.error("Sudo updateCustomer error:", json);
        throw new HttpsError("internal", json.message || `HTTP ${response.status}`);
      }
      return json;
    } catch (err) {
      if (err instanceof HttpsError) throw err;
      console.error("Sudo updateCustomer error:", err);
      throw new HttpsError("internal", err.message);
    }
  },
);

// ??? Funding Sources ???

// Create a funding source (Gateway)
exports.sudoCreateFundingSource = onCall(
  { secrets: [sudoApiKey] },
  async (data) => {
    await ensureVerifiedOrStandUser(data.auth);
    const { type, status, jitGateway } = data.data;
    if (!type || !status) {
      throw new HttpsError("invalid-argument", "type and status are required.");
    }

    const apiKey = sudoApiKey.value() || SUDO_API_KEY_PLACEHOLDER;
    if (!apiKey) throw new HttpsError("internal", "Sudo API key is not configured.");

    const body = { type, status };
    if (jitGateway) body.jitGateway = jitGateway;
    console.log("[sudoCreateFundingSource] request body:", JSON.stringify(body));

    try {
      const response = await sudoRequest({
        url: `${SUDO_BASE_URL}/fundingsources`,
        method: "POST",
        apiKey,
        body,
      });

      const json = await response.json();
      console.log(`[sudoCreateFundingSource] response status: ${response.status}`);
      console.log("Sudo createFundingSource response:", JSON.stringify(json));
      if (!response.ok) {
        console.error("Sudo createFundingSource error:", json);
        throw new HttpsError("internal", json.message || `HTTP ${response.status}`);
      }

      // Persist created funding source for downstream card creation calls
      try {
        const createdFundingSourceId = json?.data?._id;
        if (createdFundingSourceId && typeof createdFundingSourceId === "string") {
          await admin
            .firestore()
            .collection("company")
            .doc("sudoAccountDetails")
            .set({ sudoFundingSourceId: createdFundingSourceId }, { merge: true });
          console.log(`[sudoCreateFundingSource] Saved sudoFundingSourceId: ${createdFundingSourceId}`);
        }
      } catch (persistErr) {
        console.warn("[sudoCreateFundingSource] Failed to persist sudoFundingSourceId:", persistErr.message);
      }

      return json;
    } catch (err) {
      if (err instanceof HttpsError) throw err;
      console.error("Sudo createFundingSource error:", err);
      throw new HttpsError("internal", err.message);
    }
  },
);

// Get all funding sources
exports.sudoGetFundingSources = onCall(
  { secrets: [sudoApiKey] },
  async (data) => {
    await ensureVerifiedOrStandUser(data.auth);

    const apiKey = sudoApiKey.value() || SUDO_API_KEY_PLACEHOLDER;
    if (!apiKey) throw new HttpsError("internal", "Sudo API key is not configured.");

    try {
      const response = await sudoRequest({
        url: `${SUDO_BASE_URL}/fundingsources`,
        method: "GET",
        apiKey,
      });

      const json = await response.json();
      console.log("Sudo getFundingSources response:", JSON.stringify(json));
      if (!response.ok) {
        console.error("Sudo getFundingSources error:", json);
        throw new HttpsError("internal", json.message || `HTTP ${response.status}`);
      }
      return json;
    } catch (err) {
      if (err instanceof HttpsError) throw err;
      console.error("Sudo getFundingSources error:", err);
      throw new HttpsError("internal", err.message);
    }
  },
);

// Get a single funding source
exports.sudoGetFundingSource = onCall(
  { secrets: [sudoApiKey] },
  async (data) => {
    await ensureVerifiedOrStandUser(data.auth);
    const { fundingSourceId } = data.data;
    if (!fundingSourceId) throw new HttpsError("invalid-argument", "fundingSourceId is required.");

    const apiKey = sudoApiKey.value() || SUDO_API_KEY_PLACEHOLDER;
    if (!apiKey) throw new HttpsError("internal", "Sudo API key is not configured.");

    try {
      const response = await sudoRequest({
        url: `${SUDO_BASE_URL}/fundingsources/${encodeURIComponent(fundingSourceId)}`,
        method: "GET",
        apiKey,
      });

      const json = await response.json();
      console.log("Sudo getFundingSource response:", JSON.stringify(json));
      if (!response.ok) {
        console.error("Sudo getFundingSource error:", json);
        throw new HttpsError("internal", json.message || `HTTP ${response.status}`);
      }
      return json;
    } catch (err) {
      if (err instanceof HttpsError) throw err;
      console.error("Sudo getFundingSource error:", err);
      throw new HttpsError("internal", err.message);
    }
  },
);

// Update a funding source
exports.sudoUpdateFundingSource = onCall(
  { secrets: [sudoApiKey] },
  async (data) => {
    await ensureVerifiedOrStandUser(data.auth);
    const { fundingSourceId, status, jitGateway } = data.data;
    if (!fundingSourceId) throw new HttpsError("invalid-argument", "fundingSourceId is required.");

    const apiKey = sudoApiKey.value() || SUDO_API_KEY_PLACEHOLDER;
    if (!apiKey) throw new HttpsError("internal", "Sudo API key is not configured.");

    const body = {};
    if (status) body.status = status;
    if (jitGateway) body.jitGateway = jitGateway;

    try {
      const response = await sudoRequest({
        url: `${SUDO_BASE_URL}/fundingsources/${encodeURIComponent(fundingSourceId)}`,
        method: "PUT",
        apiKey,
        body,
      });

      const json = await response.json();
      console.log("Sudo updateFundingSource response:", JSON.stringify(json));
      if (!response.ok) {
        console.error("Sudo updateFundingSource error:", json);
        throw new HttpsError("internal", json.message || `HTTP ${response.status}`);
      }
      return json;
    } catch (err) {
      if (err instanceof HttpsError) throw err;
      console.error("Sudo updateFundingSource error:", err);
      throw new HttpsError("internal", err.message);
    }
  },
);

// ??? Cards ???

// Create a card
exports.sudoCreateCard = onCall(
  { secrets: [sudoApiKey] },
  async (data) => {
    await ensureVerifiedOrStandUser(data.auth);
    const {
      customerId, type, currency, status, fundingSourceId,
      brand, number, enable2FA, issuerCountry, metadata,
      spendingControls, bankCode, accountNumber,
      debitAccountId, amount, sendPINSMS, expirationDate,
    } = data.data;

    if (!customerId || !type || !currency || !status) {
      throw new HttpsError(
        "invalid-argument",
        "Missing required parameters: customerId, type, currency, status.",
      );
    }

    const apiKey = sudoApiKey.value() || SUDO_API_KEY_PLACEHOLDER;
    if (!apiKey) throw new HttpsError("internal", "Sudo API key is not configured.");

    const body = { customerId, type, currency, status };
    if (fundingSourceId) body.fundingSourceId = fundingSourceId;
    if (brand) body.brand = brand;
    if (number) body.number = number;
    if (enable2FA !== undefined) body.enable2FA = enable2FA;
    if (issuerCountry) body.issuerCountry = issuerCountry;
    if (metadata) body.metadata = metadata;
    if (spendingControls) body.spendingControls = spendingControls;
    if (bankCode) body.bankCode = bankCode;
    if (accountNumber) body.accountNumber = accountNumber;
    if (debitAccountId) body.debitAccountId = debitAccountId;
    if (amount !== undefined) body.amount = amount;
    if (sendPINSMS !== undefined) body.sendPINSMS = sendPINSMS;
    if (expirationDate) body.expirationDate = expirationDate;

    try {
      const response = await sudoRequest({
        url: `${SUDO_BASE_URL}/cards`,
        method: "POST",
        apiKey,
        body,
      });

      const json = await response.json();
      console.log("Sudo createCard response:", JSON.stringify(json));
      if (!response.ok) {
        console.error("Sudo createCard error:", json);
        return { error: true, statusCode: response.status, ...json };
      }
      return json;
    } catch (err) {
      if (err instanceof HttpsError) throw err;
      console.error("Sudo createCard error:", err);
      throw new HttpsError("internal", err.message);
    }
  },
);

// Get all cards
exports.sudoGetCards = onCall(
  { secrets: [sudoApiKey] },
  async (data) => {
    await ensureVerifiedOrStandUser(data.auth);
    const { page, limit } = data.data || {};

    const apiKey = sudoApiKey.value() || SUDO_API_KEY_PLACEHOLDER;
    if (!apiKey) throw new HttpsError("internal", "Sudo API key is not configured.");

    const params = new URLSearchParams();
    if (page !== undefined) params.append("page", String(page));
    if (limit !== undefined) params.append("limit", String(limit));

    try {
      const response = await sudoRequest({
        url: `${SUDO_BASE_URL}/cards?${params.toString()}`,
        method: "GET",
        apiKey,
      });

      const json = await response.json();
      console.log("Sudo getCards response:", JSON.stringify(json));
      if (!response.ok) {
        console.error("Sudo getCards error:", json);
        throw new HttpsError("internal", json.message || `HTTP ${response.status}`);
      }
      return json;
    } catch (err) {
      if (err instanceof HttpsError) throw err;
      console.error("Sudo getCards error:", err);
      throw new HttpsError("internal", err.message);
    }
  },
);

// Get cards for a specific customer
exports.sudoGetCustomerCards = onCall(
  { secrets: [sudoApiKey] },
  async (data) => {
    await ensureVerifiedOrStandUser(data.auth);
    const { customerId, page, limit } = data.data;
    if (!customerId) throw new HttpsError("invalid-argument", "customerId is required.");

    const apiKey = sudoApiKey.value() || SUDO_API_KEY_PLACEHOLDER;
    if (!apiKey) throw new HttpsError("internal", "Sudo API key is not configured.");

    const params = new URLSearchParams();
    if (page !== undefined) params.append("page", String(page));
    if (limit !== undefined) params.append("limit", String(limit));

    try {
      const response = await sudoRequest({
        url: `${SUDO_BASE_URL}/cards/customer/${encodeURIComponent(customerId)}?${params.toString()}`,
        method: "GET",
        apiKey,
      });

      const json = await response.json();
      console.log("Sudo getCustomerCards response:", JSON.stringify(json));
      if (!response.ok) {
        console.error("Sudo getCustomerCards error:", json);
        throw new HttpsError("internal", json.message || `HTTP ${response.status}`);
      }
      return json;
    } catch (err) {
      if (err instanceof HttpsError) throw err;
      console.error("Sudo getCustomerCards error:", err);
      throw new HttpsError("internal", err.message);
    }
  },
);

// Get a single card
exports.sudoGetCard = onCall(
  { secrets: [sudoApiKey] },
  async (data) => {
    await ensureVerifiedOrStandUser(data.auth);
    const { cardId } = data.data;
    if (!cardId) throw new HttpsError("invalid-argument", "cardId is required.");

    const apiKey = sudoApiKey.value() || SUDO_API_KEY_PLACEHOLDER;
    if (!apiKey) throw new HttpsError("internal", "Sudo API key is not configured.");

    try {
      const response = await sudoRequest({
        url: `${SUDO_BASE_URL}/cards/${encodeURIComponent(cardId)}`,
        method: "GET",
        apiKey,
      });

      const json = await response.json();
      console.log("Sudo getCard response:", JSON.stringify(json));
      if (!response.ok) {
        console.error("Sudo getCard error:", json);
        throw new HttpsError("internal", json.message || `HTTP ${response.status}`);
      }
      return json;
    } catch (err) {
      if (err instanceof HttpsError) throw err;
      console.error("Sudo getCard error:", err);
      throw new HttpsError("internal", err.message);
    }
  },
);

// Fetch all Sudo accounts for this business (GET /accounts) ? used to recover lost account references
exports.sudoGetAccounts = onCall(
  { secrets: [sudoApiKey] },
  async (data) => {
    await ensureVerifiedOrStandUser(data.auth);
    const { currency } = data.data || {};
    const apiKey = sudoApiKey.value() || SUDO_API_KEY_PLACEHOLDER;
    if (!apiKey) throw new HttpsError("internal", "Sudo API key is not configured.");

    try {
      const params = new URLSearchParams({ limit: "100", currency: currency || "ALL" });
      const response = await sudoRequest({
        url: `${SUDO_BASE_URL}/accounts?${params.toString()}`,
        method: "GET",
        apiKey,
      });
      const json = await response.json();
      console.log("[sudoGetAccounts] Response:", JSON.stringify(json));
      if (!response.ok) throw new HttpsError("internal", json.message || `HTTP ${response.status}`);
      return json;
    } catch (err) {
      if (err instanceof HttpsError) throw err;
      throw new HttpsError("internal", err.message);
    }
  },
);

// Fetch the real-time balance of a Sudo account (GET /accounts/{id}/balance)
exports.sudoGetAccountBalance = onCall(
  { secrets: [sudoApiKey] },
  async (data) => {
    await ensureVerifiedOrStandUser(data.auth);
    const { accountId } = data.data;
    if (!accountId) throw new HttpsError("invalid-argument", "accountId is required.");

    const apiKey = sudoApiKey.value() || SUDO_API_KEY_PLACEHOLDER;
    if (!apiKey) throw new HttpsError("internal", "Sudo API key is not configured.");

    try {
      const response = await sudoRequest({
        url: `${SUDO_BASE_URL}/accounts/${encodeURIComponent(accountId)}/balance`,
        method: "GET",
        apiKey,
      });
      const json = await response.json();
      if (!response.ok) {
        throw new HttpsError("internal", json.message || `HTTP ${response.status}`);
      }
      return json;
    } catch (err) {
      if (err instanceof HttpsError) throw err;
      throw new HttpsError("internal", err.message);
    }
  },
);

// Generate a short-lived card token for PCI-DSS compliant secure data display
// via Sudo's SecureProxy SDK. The token is returned to the client which uses it
// to render card PAN/CVV2/PIN directly from SecureProxy's servers in a WebView
// ? sensitive data never passes through our backend.
exports.sudoGenerateCardToken = onCall(
  { secrets: [sudoApiKey] },
  async (data) => {
    await ensureVerifiedOrStandUser(data.auth);
    const { cardId } = data.data;
    if (!cardId) throw new HttpsError("invalid-argument", "cardId is required.");

    const apiKey = sudoApiKey.value() || SUDO_API_KEY_PLACEHOLDER;
    if (!apiKey) throw new HttpsError("internal", "Sudo API key is not configured.");

    try {
      const response = await sudoRequest({
        url: `${SUDO_BASE_URL}/cards/${encodeURIComponent(cardId)}/token`,
        method: "GET",
        apiKey,
      });
      const json = await response.json();
      if (!response.ok || (json.statusCode && json.statusCode >= 400)) {
        throw new HttpsError("internal", json.message || `HTTP ${response.status}`);
      }
      // Return only the token ? not the full API key
      return { token: json.data?.token };
    } catch (err) {
      if (err instanceof HttpsError) throw err;
      console.error("sudoGenerateCardToken error:", err);
      throw new HttpsError("internal", err.message);
    }
  },
);

// Send default card PIN
exports.sudoSendDefaultCardPin = onCall(
  { secrets: [sudoApiKey] },
  async (data) => {
    await ensureVerifiedOrStandUser(data.auth);
    const { cardId } = data.data;
    if (!cardId) throw new HttpsError("invalid-argument", "cardId is required.");

    const apiKey = sudoApiKey.value() || SUDO_API_KEY_PLACEHOLDER;
    if (!apiKey) throw new HttpsError("internal", "Sudo API key is not configured.");

    try {
      const response = await sudoRequest({
        url: `${SUDO_BASE_URL}/cards/${encodeURIComponent(cardId)}/send-pin`,
        method: "PUT",
        apiKey,
      });

      const json = await response.json();
      console.log("Sudo sendDefaultCardPin response:", JSON.stringify(json));
      if (!response.ok) {
        console.error("Sudo sendDefaultCardPin error:", json);
        throw new HttpsError("internal", json.message || `HTTP ${response.status}`);
      }
      return json;
    } catch (err) {
      if (err instanceof HttpsError) throw err;
      console.error("Sudo sendDefaultCardPin error:", err);
      throw new HttpsError("internal", err.message);
    }
  },
);

// Change card PIN
exports.sudoChangeCardPin = onCall(
  { secrets: [sudoApiKey] },
  async (data) => {
    await ensureVerifiedOrStandUser(data.auth);
    const { cardId, oldPin, newPin } = data.data;
    if (!cardId || !oldPin || !newPin) {
      throw new HttpsError("invalid-argument", "cardId, oldPin, and newPin are required.");
    }

    const apiKey = sudoApiKey.value() || SUDO_API_KEY_PLACEHOLDER;
    if (!apiKey) throw new HttpsError("internal", "Sudo API key is not configured.");

    try {
      const response = await sudoRequest({
        url: `${SUDO_BASE_URL}/cards/${encodeURIComponent(cardId)}/pin`,
        method: "PUT",
        apiKey,
        body: { oldPin, newPin },
      });

      const json = await response.json();
      console.log("Sudo changeCardPin response:", JSON.stringify(json));
      if (!response.ok) {
        console.error("Sudo changeCardPin error:", json);
        throw new HttpsError("internal", json.message || `HTTP ${response.status}`);
      }
      return json;
    } catch (err) {
      if (err instanceof HttpsError) throw err;
      console.error("Sudo changeCardPin error:", err);
      throw new HttpsError("internal", err.message);
    }
  },
);

// Enroll card for 2FA
exports.sudoEnrollCard2FA = onCall(
  { secrets: [sudoApiKey] },
  async (data) => {
    await ensureVerifiedOrStandUser(data.auth);
    const { cardId } = data.data;
    if (!cardId) throw new HttpsError("invalid-argument", "cardId is required.");

    const apiKey = sudoApiKey.value() || SUDO_API_KEY_PLACEHOLDER;
    if (!apiKey) throw new HttpsError("internal", "Sudo API key is not configured.");

    try {
      const response = await sudoRequest({
        url: `${SUDO_BASE_URL}/cards/${encodeURIComponent(cardId)}/enroll2fa`,
        method: "PUT",
        apiKey,
      });

      const json = await response.json();
      console.log("Sudo enrollCard2FA response:", JSON.stringify(json));
      if (!response.ok) {
        console.error("Sudo enrollCard2FA error:", json);
        throw new HttpsError("internal", json.message || `HTTP ${response.status}`);
      }
      return json;
    } catch (err) {
      if (err instanceof HttpsError) throw err;
      console.error("Sudo enrollCard2FA error:", err);
      throw new HttpsError("internal", err.message);
    }
  },
);

// Update a card
exports.sudoUpdateCard = onCall(
  { secrets: [sudoApiKey] },
  async (data) => {
    await ensureVerifiedOrStandUser(data.auth);
    const { cardId, ...updateFields } = data.data;
    if (!cardId) throw new HttpsError("invalid-argument", "cardId is required.");

    const apiKey = sudoApiKey.value() || SUDO_API_KEY_PLACEHOLDER;
    if (!apiKey) throw new HttpsError("internal", "Sudo API key is not configured.");

    try {
      const response = await sudoRequest({
        url: `${SUDO_BASE_URL}/cards/${encodeURIComponent(cardId)}`,
        method: "PUT",
        apiKey,
        body: updateFields,
      });

      const json = await response.json();
      console.log("Sudo updateCard response:", JSON.stringify(json));
      if (!response.ok) {
        console.error("Sudo updateCard error:", json);
        throw new HttpsError("internal", json.message || `HTTP ${response.status}`);
      }
      return json;
    } catch (err) {
      if (err instanceof HttpsError) throw err;
      console.error("Sudo updateCard error:", err);
      throw new HttpsError("internal", err.message);
    }
  },
);

// Digitalize a card
exports.sudoDigitalizeCard = onCall(
  { secrets: [sudoApiKey] },
  async (data) => {
    await ensureVerifiedOrStandUser(data.auth);
    const { cardId } = data.data;
    const platform = String(data.data?.platform || "android").trim().toLowerCase();
    if (!cardId) throw new HttpsError("invalid-argument", "cardId is required.");

    const apiKey = sudoApiKey.value() || SUDO_API_KEY_PLACEHOLDER;
    if (!apiKey) throw new HttpsError("internal", "Sudo API key is not configured.");

    try {
      const tryDigitalize = async (targetCardId) => {
        const response = await sudoRequest({
          url: `${SUDO_BASE_URL}/cards/digitalize/${encodeURIComponent(targetCardId)}`,
          method: "PUT",
          apiKey,
          body: {platform},
        });
        const json = await response.json();
        return {response, json};
      };

      let effectiveCardId = cardId;
      let matchedCard = null;
      let {response, json} = await tryDigitalize(effectiveCardId);

      // Some Sudo accounts may require digitalization by providerReference
      // instead of card _id. If we get "Card not found", resolve and retry.
      const isCardNotFound =
        !response.ok &&
        String(json?.message || "").toLowerCase().includes("card not found");

      if (isCardNotFound) {
        const cardsResponse = await sudoRequest({
          url: `${SUDO_BASE_URL}/cards?limit=100`,
          method: "GET",
          apiKey,
        });
        const cardsJson = await cardsResponse.json();
        const cards = Array.isArray(cardsJson?.data) ? cardsJson.data : [];

        const match = cards.find((c) => {
          const id = String(c?._id || "");
          const providerRef = String(c?.providerReference || "");
          return id === String(cardId) || providerRef === String(cardId);
        });
        matchedCard = match || null;

        if (match) {
          const matchStatus = String(match?.status || "").toLowerCase();
          if (matchStatus && matchStatus !== "active") {
            throw new HttpsError(
              "failed-precondition",
              `Card exists but is ${matchStatus}. Activate card before digitalization.`,
            );
          }

          const byProviderRef = String(match?.providerReference || "").trim();
          if (byProviderRef && byProviderRef !== String(cardId)) {
            effectiveCardId = byProviderRef;
            const retry = await tryDigitalize(effectiveCardId);
            response = retry.response;
            json = retry.json;
          }
        }
      }

      console.log("Sudo digitalizeCard response:", JSON.stringify({
        effectiveCardId,
        responseStatus: response.status,
        body: json,
      }));

      if (!response.ok) {
        console.error("Sudo digitalizeCard error:", json);
        throw new HttpsError("internal", json.message || `HTTP ${response.status}`);
      }

      const payload = (json && typeof json === "object") ? (json.data || json) : {};
      const registrationData = payload?.registrationData || payload?.registration || payload?.onboardingData || {};

      const asString = (v) => (typeof v === "string" ? v.trim() : "");

      const jwtToken =
        asString(payload?.jwtToken) ||
        asString(payload?.jwt_token) ||
        asString(payload?.token) ||
        asString(payload?.onboardingToken) ||
        asString(payload?.onboarding_token) ||
        asString(payload?.digitalizationToken) ||
        asString(payload?.digitalization_token) ||
        asString(registrationData?.jwtToken) ||
        asString(registrationData?.jwt_token) ||
        asString(registrationData?.token) ||
        asString(registrationData?.onboardingToken) ||
        asString(registrationData?.onboarding_token);

      const walletId =
        asString(payload?.walletId) ||
        asString(payload?.wallet_id) ||
        asString(registrationData?.walletId) ||
        asString(registrationData?.wallet_id);

      const paymentAppInstanceId =
        asString(payload?.paymentAppInstanceId) ||
        asString(payload?.payment_app_instance_id) ||
        asString(registrationData?.paymentAppInstanceId) ||
        asString(registrationData?.payment_app_instance_id);

      const accountId =
        asString(payload?.accountId) ||
        asString(payload?.account_id) ||
        asString(registrationData?.accountId) ||
        asString(registrationData?.account_id) ||
        cardId;

      const candidatesSet = new Set([
        asString(cardId),
        asString(effectiveCardId),
        asString(payload?.cardId),
        asString(payload?.card_id),
        asString(accountId),
        asString(matchedCard?._id),
        asString(matchedCard?.providerReference),
        asString(matchedCard?.account?._id),
        asString(matchedCard?.account?.providerReference),
      ].filter(Boolean));

      const accountIdCandidates = Array.from(candidatesSet);

      return {
        ok: true,
        walletId,
        paymentAppInstanceId,
        accountId,
        accountIdCandidates,
        jwtToken,
        data: payload,
      };
    } catch (err) {
      if (err instanceof HttpsError) throw err;
      console.error("Sudo digitalizeCard error:", err);
      throw new HttpsError("internal", err.message);
    }
  },
);

// Order physical cards
exports.sudoOrderPhysicalCards = onCall(
  { secrets: [sudoApiKey] },
  async (data) => {
    await ensureVerifiedOrStandUser(data.auth);
    const {
      debitAccountId, brand, currency, allocation, expedite,
      shippingMethod, shippingAddress, customerId, design, nameOnCards,
    } = data.data;

    if (!debitAccountId || !brand || !currency || allocation === undefined ||
        expedite === undefined || !shippingMethod || !shippingAddress) {
      throw new HttpsError(
        "invalid-argument",
        "Missing required parameters for ordering physical cards.",
      );
    }

    const apiKey = sudoApiKey.value() || SUDO_API_KEY_PLACEHOLDER;
    if (!apiKey) throw new HttpsError("internal", "Sudo API key is not configured.");

    const body = {
      debitAccountId, brand, currency, allocation,
      expedite, shippingMethod, shippingAddress,
    };
    if (customerId) body.customerId = customerId;
    if (design) body.design = design;
    if (nameOnCards) body.nameOnCards = nameOnCards;

    try {
      const response = await sudoRequest({
        url: `${SUDO_BASE_URL}/cards/order`,
        method: "POST",
        apiKey,
        body,
      });

      const json = await response.json();
      console.log("Sudo orderPhysicalCards response:", JSON.stringify(json));
      if (!response.ok) {
        console.error("Sudo orderPhysicalCards error:", json);
        throw new HttpsError("internal", json.message || `HTTP ${response.status}`);
      }
      return json;
    } catch (err) {
      if (err instanceof HttpsError) throw err;
      console.error("Sudo orderPhysicalCards error:", err);
      throw new HttpsError("internal", err.message);
    }
  },
);

// Get transactions for a card
exports.sudoGetCardTransactions = onCall(
  { secrets: [sudoApiKey] },
  async (data) => {
    await ensureVerifiedOrStandUser(data.auth);
    const { cardId, page, limit, fromDate, toDate } = data.data;
    if (!cardId) throw new HttpsError("invalid-argument", "cardId is required.");

    const apiKey = sudoApiKey.value() || SUDO_API_KEY_PLACEHOLDER;
    if (!apiKey) throw new HttpsError("internal", "Sudo API key is not configured.");

    const params = new URLSearchParams();
    if (page !== undefined) params.append("page", String(page));
    if (limit !== undefined) params.append("limit", String(limit));
    if (fromDate) params.append("fromDate", fromDate);
    if (toDate) params.append("toDate", toDate);

    try {
      const response = await sudoRequest({
        url: `${SUDO_BASE_URL}/cards/${encodeURIComponent(cardId)}/transactions?${params.toString()}`,
        method: "GET",
        apiKey,
      });

      const json = await response.json();
      console.log("Sudo getCardTransactions response:", JSON.stringify(json));
      if (!response.ok) {
        console.error("Sudo getCardTransactions error:", json);
        throw new HttpsError("internal", json.message || `HTTP ${response.status}`);
      }
      return json;
    } catch (err) {
      if (err instanceof HttpsError) throw err;
      console.error("Sudo getCardTransactions error:", err);
      throw new HttpsError("internal", err.message);
    }
  },
);

// Sudo webhook receiver ? handles all Gateway funding source events.
// Events: authorization.request, card.balance, transaction.created,
//         authorization.declined, transaction.refund, card.terminated
exports.sudoWebhook = onRequest(
  { secrets: [sudoWebhookSecret, getanchorSecretKey, smtpHost, smtpUser, smtpPass] },
  async (req, res) => {
    if (req.method !== "POST") {
      res.status(405).send("Method Not Allowed");
      return;
    }
    console.log("[sudoWebhook] Received request with headers:", JSON.stringify(req.headers));

    const payload = req.body || {};
    const eventType = payload?.type || "unknown";
    const eventData = payload?.data || {};
    const eventObject = eventData?.object || {};
    console.log(`[sudoWebhook] ${eventType}`, JSON.stringify(payload));

    // -- Helpers ------------------------------------------------------------

    // Find a user's Firestore userId and cardDoc from a Sudo card _id.
    const findUserByCardId = async (sudoCardId) => {
      if (!sudoCardId) return null;
      try {
        const snap = await db.collectionGroup("cards").where("card_id", "==", sudoCardId).limit(1).get();
        if (snap.empty) return null;
        return { userId: snap.docs[0].ref.parent.parent.id, cardDoc: snap.docs[0] };
      } catch (e) {
        console.warn("[sudoWebhook] findUserByCardId error:", e);
        return null;
      }
    };

    // Push notification + Firestore notification save.
    const notifyUser = async (userId, title, body, type = "card", emailHtml = null) => {
      try {
        const userSnap = await db.collection("users").doc(userId).get();
        const userData = userSnap.data() || {};
        const token = userData.deviceToken;
        if (token) await admin.messaging().send({ token, notification: { title, body }, ...FCM_CHANNEL });
        // Send email
        const email = userData.email;
        if (email) {
          const html = emailHtml || `<p>${body}</p>`;
          await sendNotifyEmail({ to: email, subject: title, html, text: body });
        }
      } catch (e) {
        console.warn("[sudoWebhook] push/email error:", e);
      }
      await saveNotification(userId, { title, body, type });
    };

    // Fetch user's live NGN balance from Anchor (in kobo).
    const getAnchorBalanceKobo = async (userId) => {
      try {
        const userSnap = await db.collection("users").doc(userId).get();
        const accountId = userSnap.data()?.getAnchorData?.virtualAccount?.data?.id;
        if (!accountId) return null;
        const json = await makeApiRequest({
          url: `${BASE_URL}/accounts/balance/${encodeURIComponent(accountId)}`,
          method: "GET",
          secretKey: getanchorSecretKey.value(),
        });
        return json?.data?.availableBalance ?? null;
      } catch (e) {
        console.warn("[sudoWebhook] getAnchorBalance error:", e.message);
        return null;
      }
    };

    // Save raw event for debugging.
    const saveRaw = () =>
      db.collection("sudo_webhooks").add({
        eventType, payload,
        receivedAt: admin.firestore.FieldValue.serverTimestamp(),
      }).catch(() => {});

    try {
      saveRaw();

      // -- authorization.request ------------------------------------------
      // Must respond synchronously: approve ("00") or decline ("51").
      if (eventType === "authorization.request") {
        const sudoCardId = eventObject?.card?._id || eventObject?.card;
        const pendingAmount = eventObject?.pendingRequest?.amount ?? eventObject?.amount ?? 0;
        const currency = (eventObject?.currency || "NGN").toUpperCase();

        const found = await findUserByCardId(sudoCardId);
        if (!found) {
          console.warn("[sudoWebhook] authorization.request: card not found:", sudoCardId);
          return res.status(200).json({ statusCode: 200, data: { responseCode: "14" } }); // Invalid card
        }

        // Check if the card is frozen by the user
        const cardData = found.cardDoc.data() || {};

        // Decline all transactions on terminated/deleted cards
        if (cardData.deleted === true) {
          const displayAmountDel = currency === "NGN"
            ? `?${pendingAmount.toLocaleString("en-NG", {minimumFractionDigits: 2, maximumFractionDigits: 2})}`
            : `$${pendingAmount.toLocaleString("en-US", {minimumFractionDigits: 2, maximumFractionDigits: 2})}`;
          const merchantDel = eventObject?.merchant?.name || "Unknown merchant";
          console.log(`[sudoWebhook] Auth DECLINED (card terminated) ? card:${sudoCardId}`);
          await notifyUser(found.userId, "Transaction Declined", `A ${displayAmountDel} payment at ${merchantDel} was declined. This card has been terminated.`, "card_declined");
          if (eventObject?._id) {
            await db.collection("sudo_declined_auths").doc(eventObject._id).set({ declinedAt: admin.firestore.FieldValue.serverTimestamp(), declineReason: "card_terminated" });
            await db.collection("users").doc(found.userId).collection("transactions").doc(eventObject._id).set({
              type: "card_declined", source: "sudo_card", amount: pendingAmount, currency,
              merchant: merchantDel, cardId: sudoCardId, declineReason: "card_terminated",
              status: "declined", sudoEventId: eventObject._id,
              timestamp: admin.firestore.FieldValue.serverTimestamp(),
            });
          }
          return res.status(200).json({ statusCode: 200, data: { responseCode: "14" } }); // Invalid card number
        }

        if (cardData.frozen === true) {
          const displayAmount = currency === "NGN"
            ? `?${pendingAmount.toLocaleString('en-NG', {minimumFractionDigits: 2, maximumFractionDigits: 2})}`
            : `$${pendingAmount.toLocaleString('en-US', {minimumFractionDigits: 2, maximumFractionDigits: 2})}`;
          const merchant = eventObject?.merchant?.name || "Unknown merchant";
          console.log(`[sudoWebhook] Auth DECLINED (frozen) ? card:${sudoCardId} amount:${pendingAmount} ${currency}`);
          const frozenEmailHtml = `<div style="font-family:sans-serif;max-width:520px;margin:0 auto;padding:24px;"><h2 style="color:#c62828;">Card Frozen ? Transaction Declined</h2><p>A <strong>${displayAmount}</strong> payment at <strong>${merchant}</strong> was blocked because your virtual card is frozen.</p><p>To unfreeze your card, open PadiPay &rarr; Cards &rarr; tap your card &rarr; tap <em>Unfreeze Card</em>.</p><p style="color:#888;font-size:12px;">If you did not freeze your card, contact support immediately.</p></div>`;
          await notifyUser(
            found.userId,
            "Card Frozen ? Transaction Declined",
            `A ${displayAmount} transaction at ${merchant} was declined because your card is frozen.`,
            "card_declined",
            frozenEmailHtml
          );
          if (eventObject?._id) {
            await db.collection("sudo_declined_auths").doc(eventObject._id).set({ declinedAt: admin.firestore.FieldValue.serverTimestamp(), declineReason: "card_frozen" });
            await db.collection("users").doc(found.userId).collection("transactions").doc(eventObject._id).set({
              type: "card_declined", source: "sudo_card", amount: pendingAmount, currency,
              merchant, cardId: sudoCardId, declineReason: "card_frozen",
              status: "declined", sudoEventId: eventObject._id,
              timestamp: admin.firestore.FieldValue.serverTimestamp(),
            });
          }
          return res.status(200).json({ statusCode: 200, data: { responseCode: "62" } }); // Restricted card
        }

        // Check card channel restrictions (pos / atm / web)
        const txChannel = (eventObject?.transactionMetadata?.channel ||
          eventObject?.terminal?.terminalType || "").toLowerCase();
        const channels = cardData.channels || {};
        // Default: all channels allowed. Only block if explicitly set to false.
        let channelAllowed = true;
        let channelLabel = txChannel;
        if (txChannel === "pos" && channels.pos === false) channelAllowed = false;
        else if (txChannel === "atm" && channels.atm === false) channelAllowed = false;
        else if ((txChannel === "web" || txChannel === "internet" || txChannel === "ecommerce") && channels.web === false) {
          channelAllowed = false;
          channelLabel = "web";
        }

        if (!channelAllowed) {
          const displayAmount = currency === "NGN"
            ? `?${pendingAmount.toLocaleString('en-NG', {minimumFractionDigits: 2, maximumFractionDigits: 2})}`
            : `$${pendingAmount.toLocaleString('en-US', {minimumFractionDigits: 2, maximumFractionDigits: 2})}`;
          const merchant = eventObject?.merchant?.name || "Unknown merchant";
          console.log(`[sudoWebhook] Auth DECLINED (channel blocked: ${channelLabel}) ? card:${sudoCardId} amount:${pendingAmount} ${currency}`);
          const channelName = channelLabel.toUpperCase();
          const channelFriendly = channelLabel === 'pos' ? 'POS (in-store)' : channelLabel === 'atm' ? 'ATM' : 'Online (Web)';
          const notifTitle = `${channelFriendly} Transaction Declined`;
          const notifBody = `A ${displayAmount} payment at ${merchant} was declined. ${channelFriendly} transactions are turned off on your card.`;
          const emailHtml = `
<div style="font-family:sans-serif;max-width:520px;margin:0 auto;padding:24px;">
  <h2 style="color:#c62828;">Transaction Declined</h2>
  <p>A payment was blocked on your PadiPay virtual card.</p>
  <table style="width:100%;border-collapse:collapse;margin:16px 0;">
    <tr><td style="padding:8px 0;color:#666;">Merchant</td><td style="padding:8px 0;font-weight:600;">${merchant}</td></tr>
    <tr><td style="padding:8px 0;color:#666;">Amount</td><td style="padding:8px 0;font-weight:600;">${displayAmount}</td></tr>
    <tr><td style="padding:8px 0;color:#666;">Reason</td><td style="padding:8px 0;font-weight:600;color:#c62828;">${channelName} transactions are disabled</td></tr>
  </table>
  <div style="background:#fff3e0;border-left:4px solid #e65100;padding:14px 18px;border-radius:6px;margin:16px 0;">
    <strong>How to enable ${channelFriendly} transactions:</strong><br>
    Open PadiPay &rarr; Cards &rarr; tap your card &rarr; tap the <em>\u2022\u2022\u2022</em> menu &rarr; <strong>Card Channels</strong> &rarr; turn on <strong>${channelName}</strong>.
  </div>
  <p style="color:#888;font-size:12px;">If you did not attempt this transaction, your card details may be compromised ? freeze your card immediately from the app.</p>
</div>`;
          await notifyUser(found.userId, notifTitle, notifBody, "card_declined", emailHtml);
          if (eventObject?._id) {
            await db.collection("sudo_declined_auths").doc(eventObject._id).set({ declinedAt: admin.firestore.FieldValue.serverTimestamp(), declineReason: "channel_blocked", channelLabel });
            await db.collection("users").doc(found.userId).collection("transactions").doc(eventObject._id).set({
              type: "card_declined", source: "sudo_card", amount: pendingAmount, currency,
              merchant, cardId: sudoCardId, declineReason: "channel_blocked", declineChannelLabel: channelLabel,
              status: "declined", sudoEventId: eventObject._id,
              timestamp: admin.firestore.FieldValue.serverTimestamp(),
            });
          }
          return res.status(200).json({ statusCode: 200, data: { responseCode: "57" } }); // Transaction not permitted to cardholder
        }

        // Check card merchant restrictions
        const incomingMerchantName = eventObject?.merchant?.name || "";
        if (incomingMerchantName && incomingMerchantName !== "Unknown merchant") {
          const merchantKey = incomingMerchantName.trim().toLowerCase().replace(/[^a-z0-9]+/g, "_").replace(/^_+|_+$/, "");
          const blockedMerchants = cardData.blockedMerchants || {};
          if (merchantKey && blockedMerchants[merchantKey] === false) {
            const displayAmount = currency === "NGN"
              ? `?${pendingAmount.toLocaleString("en-NG", { minimumFractionDigits: 2, maximumFractionDigits: 2 })}`
              : `$${pendingAmount.toLocaleString("en-US", { minimumFractionDigits: 2, maximumFractionDigits: 2 })}`;
            console.log(`[sudoWebhook] Auth DECLINED (merchant blocked: ${merchantKey}) ? card:${sudoCardId} amount:${pendingAmount} ${currency}`);
            const notifTitle = "Merchant Transaction Declined";
            const notifBody = `A ${displayAmount} payment at ${incomingMerchantName} was declined. This merchant is blocked on your card.`;
            const emailHtml = `
<div style="font-family:sans-serif;max-width:520px;margin:0 auto;padding:24px;">
  <h2 style="color:#c62828;">Transaction Declined</h2>
  <p>A payment was blocked on your PadiPay virtual card.</p>
  <table style="width:100%;border-collapse:collapse;margin:16px 0;">
    <tr><td style="padding:8px 0;color:#666;">Merchant</td><td style="padding:8px 0;font-weight:600;">${incomingMerchantName}</td></tr>
    <tr><td style="padding:8px 0;color:#666;">Amount</td><td style="padding:8px 0;font-weight:600;">${displayAmount}</td></tr>
    <tr><td style="padding:8px 0;color:#666;">Reason</td><td style="padding:8px 0;font-weight:600;color:#c62828;">This merchant is blocked on your card</td></tr>
  </table>
  <div style="background:#fff3e0;border-left:4px solid #e65100;padding:14px 18px;border-radius:6px;margin:16px 0;">
    <strong>To unblock this merchant:</strong><br>
    Open PadiPay &rarr; Cards &rarr; tap your card &rarr; tap the <em>\u2022\u2022\u2022</em> menu &rarr; <strong>Manage Merchants</strong> &rarr; turn on <strong>${incomingMerchantName}</strong>.
  </div>
  <p style="color:#888;font-size:12px;">If you did not attempt this transaction, your card details may be compromised ? freeze your card immediately from the app.</p>
</div>`;
            await notifyUser(found.userId, notifTitle, notifBody, "card_declined", emailHtml);
            if (eventObject?._id) {
              await db.collection("sudo_declined_auths").doc(eventObject._id).set({ declinedAt: admin.firestore.FieldValue.serverTimestamp(), declineReason: "merchant_blocked", merchantKey });
              await db.collection("users").doc(found.userId).collection("transactions").doc(eventObject._id).set({
                type: "card_declined", source: "sudo_card", amount: pendingAmount, currency,
                merchant: incomingMerchantName, cardId: sudoCardId, declineReason: "merchant_blocked", declineMerchantKey: merchantKey,
                status: "declined", sudoEventId: eventObject._id,
                timestamp: admin.firestore.FieldValue.serverTimestamp(),
              });
            }
            return res.status(200).json({ statusCode: 200, data: { responseCode: "57" } });
          }
        }

        let approve = true; // Default approve if Anchor balance check is unavailable
        let balanceConfirmed = false; // Only true when we got a real balance reading
        let prefundTransferId = null;
        let prefundLogKey = eventObject?._id || null;
        let authDeclineReason = "insufficient_funds";

        if (currency === "NGN") {
          const balanceKobo = await getAnchorBalanceKobo(found.userId);
          if (balanceKobo !== null) {
            // Sudo sends amount in naira, Anchor balance is in kobo ? convert to compare
            approve = balanceKobo >= pendingAmount * 100;
            balanceConfirmed = true;
          }
        }
        // USD cards: Sudo settlement account covers it ? no prefund needed.

        // -- Prefund: transfer user ? company before approving ----------
        // Only when we confirmed the user has sufficient balance (not just defaulting approve).
        if (approve && balanceConfirmed && currency === "NGN") {
          const amountKobo = Math.round(pendingAmount * 100);
          if (!prefundLogKey) prefundLogKey = `${sudoCardId}_${Date.now()}`;
          try {
            const userSnap = await db.collection("users").doc(found.userId).get();
            const userVaData = userSnap.data()?.getAnchorData?.virtualAccount?.data;
            const companySnap = await db.collection("company").doc("account_details").get();
            if (!userVaData?.id || !companySnap.exists || !companySnap.data()?.accountId) {
              throw new Error("Missing user or company account details for prefund");
            }
            const prefundIdempotencyKey = `sudo_prefund_${prefundLogKey}`;
            const prefundResult = await makeApiRequest({
              url: `${BASE_URL}/transfers`,
              method: "POST",
              secretKey: getanchorSecretKey.value(),
              body: {
                data: {
                  attributes: {
                    account: { id: userVaData.id },
                    destinationAccount: { id: companySnap.data().accountId },
                    amount: amountKobo,
                    currency: "NGN",
                    narration: `Card prefund ${sudoCardId}`,
                  },
                  type: "Transfer",
                },
              },
              idempotencyKey: prefundIdempotencyKey,
            });
            const prefundStatus = prefundResult?.data?.attributes?.status;
            prefundTransferId = prefundResult?.data?.id ?? null;
            if (prefundStatus === "FAILED") {
              throw new Error(prefundResult?.data?.attributes?.failureReason || "Prefund transfer returned FAILED");
            }
            // Log prefund ? internal only, not shown in user UI
            await db.collection("sudo_card_prefunds").doc(prefundLogKey).set({
              userId: found.userId, cardId: sudoCardId,
              amountKobo, currency: "NGN",
              transferId: prefundTransferId,
              idempotencyKey: prefundIdempotencyKey,
              status: "prefunded",
              createdAt: admin.firestore.FieldValue.serverTimestamp(),
            });
            console.log(`[sudoWebhook] Prefund user?company OK ? transferId:${prefundTransferId} amountKobo:${amountKobo}`);
          } catch (prefundErr) {
            approve = false;
            authDeclineReason = "prefund_failed";
            console.error(`[sudoWebhook] Prefund transfer failed (auth:${prefundLogKey}):`, prefundErr.message);
            await db.collection("sudo_card_prefunds").doc(prefundLogKey).set({
              userId: found.userId, cardId: sudoCardId,
              amountKobo, currency: "NGN",
              status: "prefund_failed",
              error: prefundErr.message,
              createdAt: admin.firestore.FieldValue.serverTimestamp(),
            }).catch(() => {});
          }
        }

        if (!approve) {
          if (eventObject?._id) {
            await db.collection("sudo_declined_auths").doc(eventObject._id).set({ declinedAt: admin.firestore.FieldValue.serverTimestamp(), declineReason: authDeclineReason });
          }
          const displayAmount = currency === "NGN"
            ? `?${pendingAmount.toLocaleString("en-NG", { minimumFractionDigits: 2, maximumFractionDigits: 2 })}`
            : `$${pendingAmount.toLocaleString("en-US", { minimumFractionDigits: 2, maximumFractionDigits: 2 })}`;
          const merchant = eventObject?.merchant?.name || "Unknown merchant";
          const insufficientEmailHtml = `<div style="font-family:sans-serif;max-width:520px;margin:0 auto;padding:24px;"><h2 style="color:#c62828;">Transaction Declined</h2><p>A <strong>${displayAmount}</strong> payment at <strong>${merchant}</strong> was declined due to insufficient wallet balance.</p><p>Please top up your PadiPay wallet and try again.</p><p style="color:#888;font-size:12px;">If you did not attempt this transaction, please contact PadiPay support.</p></div>`;
          await notifyUser(
            found.userId,
            "Transaction Declined",
            `A ${displayAmount} payment at ${merchant} was declined ? insufficient balance.`,
            "card_declined",
            insufficientEmailHtml
          );
        }
        const responseCode = approve ? "00" : "51";
        const respBody = { statusCode: 200, data: { responseCode } };
        console.log(`[sudoWebhook] Auth ${approve ? "APPROVED" : "DECLINED"} ? card:${sudoCardId} amount:${pendingAmount} ${currency} | response: ${JSON.stringify(respBody)}`);

        // If a prefund was completed but something goes wrong before we can confirm
        // the approval to Sudo, reverse the transfer (company ? user).
        if (approve && prefundTransferId) {
          try {
            return res.status(200).json(respBody);
          } catch (sendErr) {
            console.error(`[sudoWebhook] Response failed after prefund ? reversing transfer for auth:${prefundLogKey}`, sendErr.message);
            try {
              const userSnap = await db.collection("users").doc(found.userId).get();
              const userVaData = userSnap.data()?.getAnchorData?.virtualAccount?.data;
              const companySnap = await db.collection("company").doc("account_details").get();
              if (userVaData?.id && companySnap.exists && companySnap.data()?.accountId) {
                const reversalKey = `sudo_prefund_reversal_${prefundLogKey}`;
                const reversalResult = await makeApiRequest({
                  url: `${BASE_URL}/transfers`,
                  method: "POST",
                  secretKey: getanchorSecretKey.value(),
                  body: {
                    data: {
                      attributes: {
                        account: { id: companySnap.data().accountId },
                        destinationAccount: { id: userVaData.id },
                        amount: Math.round(pendingAmount * 100),
                        currency: "NGN",
                        narration: `Card prefund reversal ${sudoCardId}`,
                      },
                      type: "Transfer",
                    },
                  },
                  idempotencyKey: reversalKey,
                });
                const reversalTransferId = reversalResult?.data?.id ?? null;
                console.log(`[sudoWebhook] Reversal company?user OK ? transferId:${reversalTransferId}`);
                await db.collection("sudo_card_prefunds").doc(prefundLogKey).update({
                  status: "reversed",
                  reversalTransferId,
                  reversalIdempotencyKey: reversalKey,
                  reversalAt: admin.firestore.FieldValue.serverTimestamp(),
                }).catch(() => {});
              }
            } catch (reversalErr) {
              console.error(`[sudoWebhook] Reversal ALSO FAILED ? MANUAL INTERVENTION NEEDED auth:${prefundLogKey}`, reversalErr.message);
              await db.collection("sudo_card_prefunds").doc(prefundLogKey).update({
                status: "reversal_failed",
                reversalError: reversalErr.message,
                reversalAttemptedAt: admin.firestore.FieldValue.serverTimestamp(),
              }).catch(() => {});
            }
            throw sendErr;
          }
        }

        return res.status(200).json(respBody);
      }

      // -- card.balance ---------------------------------------------------
      // Respond with the user's PadiPay wallet balance (in kobo for NGN).
      if (eventType === "card.balance") {
        const sudoCardId = eventObject?._id; // docs: data.object._id = Card ID
        const currency = (eventObject?.currency || "NGN").toUpperCase();
        let balance = 0;
        const found = await findUserByCardId(sudoCardId);
        if (found && currency === "NGN") {
          const b = await getAnchorBalanceKobo(found.userId);
          if (b !== null) balance = b;
        }
        return res.status(200).json({ statusCode: 200, data: { responseCode: "00", balance } });
      }

      // -- transaction.created -------------------------------------------
      if (eventType === "transaction.created") {
        const sudoCardId = eventObject?.card?._id || eventObject?.card;
        const amount = Math.abs(eventObject?.amount ?? 0);
        const currency = (eventObject?.currency || "NGN").toUpperCase();
        const merchant = eventObject?.merchant?.name || "Unknown merchant";
        const channel = eventObject?.transactionMetadata?.channel || "card";
        const ref = eventObject?.transactionMetadata?.reference || eventObject?.terminal?.rrn || "";
        const displayAmount = currency === "NGN"
          ? `?${amount.toLocaleString("en-NG", {minimumFractionDigits: 2, maximumFractionDigits: 2})}`
          : `$${amount.toLocaleString("en-US", {minimumFractionDigits: 2, maximumFractionDigits: 2})}`;

        // Check if the authorization was declined.
        // In transaction.created, eventObject.authorization is just the auth ID string (not an object),
        // so we look up the sudo_declined_auths collection that authorization.request populates.
        const txStatus = (eventObject?.status || eventObject?.transactionStatus || "").toLowerCase();
        let declineReason = null;
        let declineChannelLabel = null;
        let wasDeclined =
          eventObject?.authorization?.approved === false ||
          txStatus === "declined" ||
          txStatus === "failed";
        if (!wasDeclined) {
          const authId = typeof eventObject?.authorization === "string"
            ? eventObject.authorization
            : (eventObject?.authorization?._id || null);
          if (authId) {
            const declinedDoc = await db.collection("sudo_declined_auths").doc(authId).get();
            if (declinedDoc.exists) {
              wasDeclined = true;
              const declinedData = declinedDoc.data() || {};
              declineReason = declinedData.declineReason || null;
              declineChannelLabel = declinedData.channelLabel || null;
              await db.collection("sudo_declined_auths").doc(authId).delete();
              console.log(`[sudoWebhook] transaction.created: auth ${authId} found in declined cache ? treating as declined (reason: ${declineReason})`);
            }
          }
        }

        const found = await findUserByCardId(sudoCardId);
        if (found) {
          // Dedup: if authorization.declined already wrote a card_declined doc for this
          // reference, skip ? prevents duplicate entries when both events fire for the same tx.
          let skipWrite = false;
          if (!wasDeclined && ref) {
            const dupSnap = await db.collection("users").doc(found.userId)
              .collection("transactions")
              .where("reference", "==", ref)
              .where("type", "==", "card_declined")
              .limit(1)
              .get();
            if (!dupSnap.empty) {
              skipWrite = true;
              console.log(`[sudoWebhook] transaction.created skipped ? card_declined already exists for ref:${ref}`);
            }
          }

          if (!skipWrite) {
            if (wasDeclined) {
              console.log(`[sudoWebhook] transaction.created for DECLINED auth ? skipping spend notification. card:${sudoCardId} amount:${amount} ${currency}`);
            } else {
              await notifyUser(
                found.userId, "Card Transaction",
                `${displayAmount} spent at ${merchant} via ${channel}`,
                "card_transaction",
                `<div style="font-family:sans-serif;max-width:520px;margin:0 auto;padding:24px;"><h2 style="color:#2e7d32;">Card Transaction</h2><table style="width:100%;border-collapse:collapse;margin:16px 0;"><tr><td style="padding:8px 0;color:#666;">Merchant</td><td style="padding:8px 0;font-weight:600;">${merchant}</td></tr><tr><td style="padding:8px 0;color:#666;">Amount</td><td style="padding:8px 0;font-weight:600;">${displayAmount}</td></tr><tr><td style="padding:8px 0;color:#666;">Channel</td><td style="padding:8px 0;font-weight:600;">${channel.toUpperCase()}</td></tr></table><p style="color:#888;font-size:12px;">If you did not authorise this transaction, freeze your card immediately from the PadiPay app.</p></div>`
              );
            }
            await db.collection("users").doc(found.userId).collection("transactions").add({
              type: wasDeclined ? "card_declined" : "card_debit", source: "sudo_card",
              amount, currency, merchant, channel, reference: ref,
              cardId: sudoCardId, sudoEventId: payload?._id || null,
              status: wasDeclined ? "declined" : "approved",
              ...(wasDeclined && declineReason ? { declineReason, ...(declineChannelLabel ? { declineChannelLabel } : {}) } : {}),
              timestamp: admin.firestore.FieldValue.serverTimestamp(),
            });

            // -- Subscription tracking (approved debits only) -------------
            if (!wasDeclined && merchant && merchant !== "Unknown merchant") {
              const merchantKey = merchant.trim().toLowerCase().replace(/[^a-z0-9]+/g, "_").replace(/^_+|_+$/, "");
              if (merchantKey) {
                const subRef = db.collection("users").doc(found.userId).collection("card_subscriptions").doc(merchantKey);
                try {
                  const subSnap = await subRef.get();
                  const now = admin.firestore.Timestamp.now();
                  if (subSnap.exists) {
                    const existing = subSnap.data();
                    const history = (existing.chargeHistory || []).slice(-11); // keep last 12 entries
                    history.push(now);
                    // Estimate period from gaps between last few charges (in ms)
                    let estimatedNextMs = null;
                    if (history.length >= 2) {
                      const gaps = [];
                      for (let i = 1; i < history.length; i++) {
                        const a = history[i - 1].toMillis ? history[i - 1].toMillis() : history[i - 1];
                        const b = history[i].toMillis ? history[i].toMillis() : history[i];
                        gaps.push(b - a);
                      }
                      const avgGap = gaps.reduce((s, g) => s + g, 0) / gaps.length;
                      estimatedNextMs = now.toMillis() + avgGap;
                    }
                    await subRef.update({
                      merchantName: merchant,
                      lastChargedAt: now,
                      lastAmount: amount,
                      currency,
                      cardId: sudoCardId,
                      chargeHistory: history,
                      ...(estimatedNextMs ? { estimatedNextChargeAt: admin.firestore.Timestamp.fromMillis(estimatedNextMs) } : {}),
                    });
                  } else {
                    await subRef.set({
                      merchantKey,
                      merchantName: merchant,
                      lastChargedAt: now,
                      lastAmount: amount,
                      currency,
                      cardId: sudoCardId,
                      chargeHistory: [now],
                      estimatedNextChargeAt: null,
                      reminderEnabled: true,
                      reminderDaysBefore: 3,
                      createdAt: now,
                    });
                  }
                } catch (subErr) {
                  console.warn("[sudoWebhook] subscription tracking error:", subErr.message);
                }
              }
            }
          }
        }
        console.log(`[sudoWebhook] transaction.created processed ? card:${sudoCardId} amount:${amount} ${currency} declined:${wasDeclined}`);
        return res.status(200).json({ ok: true });
      }

      // -- authorization.declined ----------------------------------------
      if (eventType === "authorization.declined") {
        const sudoCardId = eventObject?.card?._id || eventObject?.card;
        const amount = Math.abs(eventObject?.amount ?? 0);
        const currency = (eventObject?.currency || "NGN").toUpperCase();
        const merchant = eventObject?.merchant?.name || "Unknown merchant";
        const reason = eventObject?.requestHistory?.[0]?.narration || "Transaction declined";
        const authDeclinedRef = eventObject?.transactionMetadata?.reference || eventObject?.terminal?.rrn || "";
        const authId = eventObject?._id || null;
        const displayAmount = currency === "NGN"
          ? `?${amount.toLocaleString("en-NG", {minimumFractionDigits: 2, maximumFractionDigits: 2})}`
          : `$${amount.toLocaleString("en-US", {minimumFractionDigits: 2, maximumFractionDigits: 2})}`;

        const found = await findUserByCardId(sudoCardId);
        if (found) {
          // Dedup: if authorization.request already handled this auth (frozen/channel/merchant/deleted),
          // the auth ID is in sudo_declined_auths. Skip to avoid duplicate notification + transaction.
          let alreadyHandled = false;
          if (authId) {
            const declinedDoc = await db.collection("sudo_declined_auths").doc(authId).get();
            if (declinedDoc.exists) {
              alreadyHandled = true;
              await db.collection("sudo_declined_auths").doc(authId).delete();
              console.log(`[sudoWebhook] authorization.declined: auth ${authId} already handled by authorization.request ? skipping duplicate`);
            }
          }

          if (!alreadyHandled) {
            await notifyUser(
              found.userId,
              "Transaction Declined",
              `${displayAmount} at ${merchant} was declined: ${reason}`,
              "card_declined",
              `<div style="font-family:sans-serif;max-width:520px;margin:0 auto;padding:24px;"><h2 style="color:#c62828;">Transaction Declined</h2><table style="width:100%;border-collapse:collapse;margin:16px 0;"><tr><td style="padding:8px 0;color:#666;">Merchant</td><td style="padding:8px 0;font-weight:600;">${merchant}</td></tr><tr><td style="padding:8px 0;color:#666;">Amount</td><td style="padding:8px 0;font-weight:600;">${displayAmount}</td></tr><tr><td style="padding:8px 0;color:#666;">Reason</td><td style="padding:8px 0;font-weight:600;color:#c62828;">${reason}</td></tr></table><p style="color:#888;font-size:12px;">If you did not attempt this transaction, your card details may be compromised ? freeze your card immediately from the app.</p></div>`
            );
            await db.collection("users").doc(found.userId).collection("transactions").add({
              type: "card_declined", source: "sudo_card",
              amount, currency, merchant, reason, cardId: sudoCardId,
              reference: authDeclinedRef || null,
              sudoEventId: payload?._id || null,
              status: "declined",
              timestamp: admin.firestore.FieldValue.serverTimestamp(),
            });
          }
        }
        return res.status(200).json({ ok: true });
      }

      // -- transaction.refund --------------------------------------------
      if (eventType === "transaction.refund") {
        const sudoCardId = eventObject?.card?._id || eventObject?.card;
        const amount = Math.abs(eventObject?.amount ?? 0);
        const currency = (eventObject?.currency || "NGN").toUpperCase();
        const merchant = eventObject?.merchant?.name || "Unknown merchant";
        const ref = eventObject?.transactionMetadata?.reference || eventObject?.terminal?.rrn || "";
        const displayAmount = currency === "NGN"
          ? `?${amount.toLocaleString("en-NG", {minimumFractionDigits: 2, maximumFractionDigits: 2})}`
          : `$${amount.toLocaleString("en-US", {minimumFractionDigits: 2, maximumFractionDigits: 2})}`;

        const found = await findUserByCardId(sudoCardId);
        if (found) {
          await notifyUser(
            found.userId,
            "Card Refund",
            `${displayAmount} refund from ${merchant} has been processed`,
            "card_refund",
            `<div style="font-family:sans-serif;max-width:520px;margin:0 auto;padding:24px;"><h2 style="color:#2e7d32;">Card Refund Processed</h2><p>A refund of <strong>${displayAmount}</strong> from <strong>${merchant}</strong> has been credited to your account.</p></div>`
          );
          await db.collection("users").doc(found.userId).collection("transactions").add({
            type: "card_refund", source: "sudo_card",
            amount, currency, merchant, reference: ref, cardId: sudoCardId,
            sudoEventId: payload?._id || null,
            timestamp: admin.firestore.FieldValue.serverTimestamp(),
          });
        }
        return res.status(200).json({ ok: true });
      }

      // -- card.terminated -----------------------------------------------
      // For this event, data has no .object ? the card data is in payload.data directly.
      if (eventType === "card.terminated") {
        const sudoCardId = eventData?._id;
        const currency = (eventData?.currency || "").toUpperCase();
        const maskedPan = eventData?.maskedPan || "";
        const last4 = maskedPan.slice(-4) || eventData?.last4 || "****";

        const found = await findUserByCardId(sudoCardId);
        if (found) {
          await found.cardDoc.ref.update({
            status: "terminated",
            terminatedAt: admin.firestore.FieldValue.serverTimestamp(),
          }).catch(() => {});
          await notifyUser(
            found.userId,
            "Card Terminated",
            `Your ${currency} card ending in ${last4} has been terminated`,
            "card_terminated",
            `<div style="font-family:sans-serif;max-width:520px;margin:0 auto;padding:24px;"><h2 style="color:#c62828;">Card Terminated</h2><p>Your ${currency} virtual card ending in <strong>${last4}</strong> has been permanently terminated and can no longer be used.</p><p>If you did not request this, please contact PadiPay support immediately.</p></div>`
          );
        }
        return res.status(200).json({ ok: true });
      }

      // Unknown event ? ack receipt.
      res.status(200).json({ ok: true, message: "Event received" });
    } catch (err) {
      console.error("[sudoWebhook] Error:", err);
      // For gateway events that need a sync response, still send a valid structure.
      if (["authorization.request", "card.balance"].includes(eventType)) {
        return res.status(200).json({ statusCode: 200, data: { responseCode: "00" } });
      }
      res.status(500).json({ ok: false, error: err.message });
    }
  },
);

// ==================== END SUDO AFRICA ? CARDS ====================

// -- Subscription Reminder ? runs daily at 08:00 WAT (07:00 UTC) --------------
exports.dailySubscriptionReminders = onSchedule(
  { schedule: "0 7 * * *", timeZone: "Africa/Lagos" },
  async () => {
    const now = Date.now();
    const THREE_DAYS_MS = 3 * 24 * 60 * 60 * 1000;
    const SEVEN_DAYS_MS = 7 * 24 * 60 * 60 * 1000;

    // Query all card_subscriptions across all users where:
    //   reminderEnabled == true AND estimatedNextChargeAt is set
    let subSnaps;
    try {
      subSnaps = await db.collectionGroup("card_subscriptions")
        .where("reminderEnabled", "==", true)
        .where("estimatedNextChargeAt", "!=", null)
        .get();
    } catch (e) {
      console.error("[dailySubscriptionReminders] query error:", e);
      return;
    }

    let sent = 0;
    for (const doc of subSnaps.docs) {
      try {
        const sub = doc.data();
        const nextTs = sub.estimatedNextChargeAt?.toMillis?.();
        if (!nextTs) continue;

        const daysUntil = (nextTs - now) / (24 * 60 * 60 * 1000);
        const reminderDays = sub.reminderDaysBefore ?? 3;

        // Only remind if we're within the reminder window and charge hasn't happened yet
        if (daysUntil < 0 || daysUntil > reminderDays + 1) continue;

        // Avoid re-sending: check if we already sent a reminder in the last 24h
        const lastReminderMs = sub.lastReminderSentAt?.toMillis?.() ?? 0;
        if (now - lastReminderMs < 23 * 60 * 60 * 1000) continue;

        // userId is the parent of card_subscriptions
        const userId = doc.ref.parent.parent?.id;
        if (!userId) continue;

        const currency = sub.currency || "NGN";
        const symbol = currency === "NGN" ? "?" : "$";
        const locale = currency === "NGN" ? "en-NG" : "en-US";
        const displayAmount = `${symbol}${(sub.lastAmount || 0).toLocaleString(locale, { minimumFractionDigits: 2, maximumFractionDigits: 2 })}`;
        const merchantName = sub.merchantName || sub.merchantKey;
        const nextDate = new Date(nextTs).toLocaleDateString("en-NG", { day: "numeric", month: "short", year: "numeric" });

        const daysLabel = daysUntil < 1 ? "today" : daysUntil < 2 ? "tomorrow" : `in ${Math.ceil(daysUntil)} days`;

        const notifTitle = `${merchantName} charge due ${daysLabel}`;
        const notifBody = `Your last ${displayAmount} charge to ${merchantName} was on ${new Date(sub.lastChargedAt.toMillis()).toLocaleDateString("en-NG", { day: "numeric", month: "short" })}. Next expected: ${nextDate}. Open PadiPay to block it if needed.`;

        const emailHtml = `
<div style="font-family:sans-serif;max-width:520px;margin:0 auto;padding:24px;">
  <h2 style="color:#e65100;">Subscription Reminder</h2>
  <p>A charge from <strong>${merchantName}</strong> is expected <strong>${daysLabel}</strong> (${nextDate}).</p>
  <table style="width:100%;border-collapse:collapse;margin:16px 0;">
    <tr><td style="padding:8px 0;color:#666;">Merchant</td><td style="padding:8px 0;font-weight:600;">${merchantName}</td></tr>
    <tr><td style="padding:8px 0;color:#666;">Expected amount</td><td style="padding:8px 0;font-weight:600;">${displayAmount}</td></tr>
    <tr><td style="padding:8px 0;color:#666;">Expected date</td><td style="padding:8px 0;font-weight:600;">${nextDate}</td></tr>
  </table>
  <div style="background:#fff3e0;border-left:4px solid #e65100;padding:14px 18px;border-radius:6px;margin:16px 0;">
    <strong>Don't want this charge?</strong><br>
    Open PadiPay &rarr; Cards &rarr; tap your card &rarr; <em>Manage Merchants</em> &rarr; turn off <strong>${merchantName}</strong>.
  </div>
  <p style="color:#888;font-size:12px;">To turn off these reminders, open PadiPay &rarr; Cards &rarr; Subscriptions &rarr; tap ${merchantName} &rarr; disable reminder.</p>
</div>`;

        await saveNotification(userId, { title: notifTitle, body: notifBody, type: "subscription_reminder" });
        try {
          const userSnap = await db.collection("users").doc(userId).get();
          const userData = userSnap.data() || {};
          if (userData.deviceToken) {
            await admin.messaging().send({ token: userData.deviceToken, notification: { title: notifTitle, body: notifBody }, ...FCM_CHANNEL });
          }
          if (userData.email) {
            await sendNotifyEmail({ to: userData.email, subject: notifTitle, html: emailHtml, text: notifBody });
          }
        } catch (pushErr) {
          console.warn("[dailySubscriptionReminders] push/email error:", pushErr.message);
        }

        await doc.ref.update({ lastReminderSentAt: admin.firestore.Timestamp.now() });
        sent++;
        console.log(`[dailySubscriptionReminders] Reminder sent ? user:${userId} merchant:${merchantName}`);
      } catch (docErr) {
        console.warn("[dailySubscriptionReminders] error processing sub:", doc.ref.path, docErr.message);
      }
    }
    console.log(`[dailySubscriptionReminders] Done ? ${sent} reminder(s) sent`);
  },
);











// ============================================================
// SUPER AGENT ? Banking Functions
// These callables authenticate via the superAgents collection
// instead of ensureVerifiedOrStandUser (which requires email_verified).
// ============================================================

/** Guard: caller must be an active super agent. */
async function ensureSuperAgent(auth) {
  if (!auth || !auth.uid) {
    throw new HttpsError("unauthenticated", "User must be authenticated");
  }
  const snap = await db.collection("superAgents").doc(auth.uid).get();
  if (!snap.exists) {
    throw new HttpsError("permission-denied", "Not a registered Super Agent");
  }
  const agent = snap.data();
  if (agent.status !== "active") {
    throw new HttpsError("permission-denied", "Super Agent account is suspended");
  }
}

/**
 * Create a counterparty for a Super Agent NIP transfer.
 * Same as createCounterparty but uses ensureSuperAgent guard.
 */
exports.createSuperAgentCounterparty = onCall(
  { secrets: [getanchorSecretKey] },
  async (data) => {
    await ensureSuperAgent(data.auth);
    const secretKey = getanchorSecretKey.value();
    if (!secretKey) throw new HttpsError("invalid-argument", "Getanchor Secret Key is not set");

    validateData(data.data, [
      { key: "accountName", message: "Account name is required" },
      { key: "accountType", message: "Account type is required" },
      { key: "bankName", message: "Bank name is required" },
      { key: "accountNumber", message: "Account number is required" },
      { key: "bankId", message: "Bank id is required" },
    ]);

    const accountName = data.data.accountName.trim();
    const bankName = data.data.bankName.trim();
    const accountNumber = data.data.accountNumber.trim();
    const bankId = data.data.bankId.trim();
    const accountType = data.data.accountType.trim();

    const url = `${BASE_URL}/counterparties`;
    const body = {
      data: {
        attributes: {
          accountName,
          accountNumber,
          bank: { name: bankName, accountNumber },
        },
        relationships: {
          bank: { data: { id: bankId, type: accountType } },
        },
        type: "CounterParty",
      },
    };
    return makeApiRequest({ url, method: "POST", secretKey, body });
  },
);

/**
 * Create a NIP transfer from a Super Agent's virtual account.
 * Same as createNipTransfer but uses ensureSuperAgent guard.
 */
exports.createSuperAgentNipTransfer = onCall(
  { secrets: [getanchorSecretKey] },
  async (data) => {
    await ensureSuperAgent(data.auth);
    const secretKey = getanchorSecretKey.value();
    if (!secretKey) throw new HttpsError("invalid-argument", "Getanchor Secret Key is not set");

    validateData(data.data, [
      { key: "accountId", message: "Account ID is required" },
      { key: "accountType", message: "Account Type is required" },
      { key: "counterpartyId", message: "Counterparty ID is required" },
      { key: "amount", message: "Valid amount is required", validator: (v) => typeof v === "number" && v > 0 },
      { key: "currency", message: "Currency is required" },
      { key: "idempotencyKey", message: "Idempotency key is required" },
    ]);

    const accountId = data.data.accountId.trim();
    const accountType = data.data.accountType.trim();
    const counterpartyId = data.data.counterpartyId.trim();
    const amount = data.data.amount;
    const currency = data.data.currency.trim();
    const narration = data.data.narration?.trim() || "";
    const idempotencyKey = data.data.idempotencyKey.trim();

    const url = `${BASE_URL}/transfers`;
    const attributes = { amount, currency };
    if (narration) attributes.narration = narration;
    const body = {
      data: {
        attributes,
        relationships: {
          account: { data: { id: accountId, type: accountType } },
          counterParty: { data: { id: counterpartyId, type: "CounterParty" } },
        },
        type: "NIPTransfer",
      },
    };
    return makeApiRequest({ url, method: "POST", secretKey, body, idempotencyKey });
  },
);

/**
 * Verify account number (name enquiry) for Super Agent transfer.
 * Same as verifyAccountNumber but uses ensureSuperAgent guard.
 */
exports.superAgentVerifyAccountNumber = onCall(
  { secrets: [getanchorSecretKey] },
  async (data) => {
    await ensureSuperAgent(data.auth);
    const secretKey = getanchorSecretKey.value();
    if (!secretKey) throw new HttpsError("invalid-argument", "Getanchor Secret Key is not set");

    validateData(data.data, [
      { key: "accountNumber", message: "Account number is required" },
      { key: "bankId", message: "Bank ID is required" },
    ]);

  const accountNumber = data.data.accountNumber.trim();
  const bankIdOrBankCode = data.data.bankId.trim();
  const url = `${BASE_URL}/payments/verify-account/${encodeURIComponent(bankIdOrBankCode)}/${encodeURIComponent(accountNumber)}`;
    return makeApiRequest({ url, method: "GET", secretKey });
  },
);

/**
 * Fetch balance for a Super Agent's virtual account.
 */
exports.superAgentFetchBalance = onCall(
  { secrets: [getanchorSecretKey] },
  async (data) => {
    await ensureSuperAgent(data.auth);
    const secretKey = getanchorSecretKey.value();
    if (!secretKey) throw new HttpsError("invalid-argument", "Getanchor Secret Key is not set");

    validateData(data.data, [
      { key: "accountId", message: "Account ID is required" },
    ]);

    const accountId = data.data.accountId.trim();
    const url = `${BASE_URL}/accounts/balance/${encodeURIComponent(accountId)}`;
    return makeApiRequest({ url, method: "GET", secretKey });
  },
);

