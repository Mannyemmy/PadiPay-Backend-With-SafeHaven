/**
 * One-time recovery script: restores a user's sudoAccount in Firestore
 * by fetching all Sudo accounts and matching against the user's sudoCustomerId.
 *
 * Usage:
 *   cd D:\Dev\padi_pay-functions\functions
 *   $env:SUDO_API_KEY="your_sudo_api_key_here"
 *   $env:USER_DOC_ID="vZKg4A65ShNjV8IChWTsxVOfMNx1"
 *   node ..\scripts\recover_sudo_account.js
 */

const admin = require("firebase-admin");

if (!admin.apps.length) {
  admin.initializeApp({ credential: admin.credential.applicationDefault() });
}

const SUDO_BASE_URL = "https://api.sandbox.sudo.cards";
const SUDO_API_KEY = process.env.SUDO_API_KEY;
const USER_DOC_ID = process.env.USER_DOC_ID;

if (!SUDO_API_KEY) { console.error("Set $env:SUDO_API_KEY"); process.exit(1); }
if (!USER_DOC_ID) { console.error("Set $env:USER_DOC_ID"); process.exit(1); }

async function main() {
  const db = admin.firestore();

  // 1. Get user's sudoCustomerId from Firestore
  const userSnap = await db.collection("users").doc(USER_DOC_ID).get();
  if (!userSnap.exists) { console.error("User doc not found"); process.exit(1); }
  const userData = userSnap.data();
  const customerId =
    userData?.sudoCustomer?.data?._id ||
    userData?.sudoCustomer?._id;
  if (!customerId) { console.error("No sudoCustomer._id found in user doc"); process.exit(1); }
  console.log("User sudoCustomerId:", customerId);

  // 2. Fetch all NGN accounts from Sudo
  const res = await fetch(
    `${SUDO_BASE_URL}/accounts?limit=100&currency=NGN&type=account`,
    { headers: { Authorization: `Bearer ${SUDO_API_KEY}`, accept: "application/json" } }
  );
  const json = await res.json();
  console.log("Sudo accounts response status:", res.status);
  if (!res.ok) { console.error("Sudo error:", json); process.exit(1); }

  const accounts = json.data || [];
  console.log(`Fetched ${accounts.length} NGN account(s)`);

  // 3. Find the account belonging to this customer
  const matched = accounts.find(a => a.customerId === customerId || a.customer?._id === customerId || a.customer === customerId);
  if (!matched) {
    console.log("All accounts:", JSON.stringify(accounts, null, 2));
    console.error(`No account found for customerId ${customerId}. Check above list manually.`);
    process.exit(1);
  }

  console.log("Matched account:", JSON.stringify(matched, null, 2));

  // 4. Write back to Firestore in the same shape as the original sudoAccount
  await db.collection("users").doc(USER_DOC_ID).update({
    sudoAccount: { data: matched },
  });
  console.log("sudoAccount restored to Firestore successfully.");
  process.exit(0);
}

main().catch(err => { console.error(err); process.exit(1); });
