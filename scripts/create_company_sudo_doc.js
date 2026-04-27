/**
 * One-time script to create the company/sudoAccountDetails Firestore document.
 * Edit the placeholder values below before running.
 *
 * Usage:
 *   cd D:\Dev\padi_pay-functions\functions
 *   node ..\scripts\create_company_sudo_doc.js
 *
 * Requires: GOOGLE_APPLICATION_CREDENTIALS env var pointing to a service account key,
 * or run from a machine/emulator that already has Firebase credentials.
 */

const admin = require("firebase-admin");

// Initialize with project ID — credentials come from environment
if (!admin.apps.length) {
  admin.initializeApp({
    credential: admin.credential.applicationDefault(),
  });
}

const db = admin.firestore();

const companyDoc = {
  // ── Company identity ──────────────────────────────────────────
  name: "PadiPay Technologies Ltd",          // Legal company name
  phoneNumber: "2348000000000",              // E.164 without + (e.g. "2348012345678")
  emailAddress: "cards@padipay.co",          // Company email for Sudo
  billingAddress: {
    line1: "1 Example Street",
    city: "Lagos Island",
    state: "Lagos",
    country: "NG",
    postalCode: "100001",
  },
  company: {
    name: "PadiPay Technologies Ltd",
    identity: {
      type: "CAC",                           // "CAC" or "TIN"
      number: "RC-0000000",                  // Registration / TIN number
    },
    officer: {
      firstName: "Company",
      lastName: "Officer",
      phone: "2348000000000",
      email: "officer@padipay.co",
      identity: {
        type: "BVN",
        number: "00000000000",               // Officer's BVN (11 digits)
      },
      dob: "1990/01/01",                    // YYYY/MM/DD format
    },
  },

  // ── Written back by the server after Sudo customer/account creation ──
  sudoCustomerId: "",
  sudoNgnAccountId: "",
  sudoUsdAccountId: "",
};

async function main() {
  const ref = db.collection("company").doc("sudoAccountDetails");
  const snap = await ref.get();
  if (snap.exists) {
    console.log("Document already exists. Merging missing fields only.");
    await ref.set(companyDoc, { merge: true });
  } else {
    await ref.set(companyDoc);
    console.log("Created company/sudoAccountDetails successfully.");
  }
  console.log("Done. Edit the values via Firebase Console, then fill in the Sudo IDs after running sudoInitCompanyAccount.");
  process.exit(0);
}

main().catch((err) => {
  console.error("Error:", err);
  process.exit(1);
});
