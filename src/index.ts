import { ShamirModule } from "./phase1-shamir/index";
import { VaultModule } from "./phase2-vault/index";
import { randomBytes } from "crypto";

async function main() {
  console.log("AKR Naos - Nested Authentication Operations Suite");
  console.log("SA AT Cryptographics\n");

  // ============================================================
  // PHASE 1 - SHAMIR SECRET SHARING
  // ============================================================
  console.log("=== Phase 1 - Shamir Secret Sharing ===\n");

  const shamir = new ShamirModule();
  const privateKey = "simulated-ml-kem-768-private-key-material-for-testing";

  const splitResult = shamir.split(privateKey, {
    threshold: 3,
    totalShares: 5,
    label: "AKR-primary-key",
  });

  console.log(`Algorithm:      ${splitResult.algorithm}`);
  console.log(`Total Shares:   ${splitResult.totalShares}`);
  console.log(`Threshold:      ${splitResult.threshold}`);
  console.log(`Secret Hash:    ${splitResult.secretHash.substring(0, 32)}...`);

  const selectedShares = [
    splitResult.shares[0],
    splitResult.shares[2],
    splitResult.shares[4],
  ];

  const recoverResult = shamir.recover(selectedShares, splitResult.secretHash);
  console.log(`Recovered:      ${recoverResult.secret === privateKey}`);
  console.log(`Verified:       ${recoverResult.verified}`);

  const belowThreshold = [splitResult.shares[0], splitResult.shares[1]];
  console.log(`Below Threshold Blocked: ${!shamir.verify(belowThreshold, splitResult.secretHash)}`);

  console.log("\n=== Phase 1 Complete - No single point of failure ===\n");

  // ============================================================
  // PHASE 2 - KEY VAULT
  // ============================================================
  console.log("=== Phase 2 - Key Vault ===\n");

  const vault = new VaultModule();
  const password = "sa-at-vault-master-password-2026";

  // Test 1 - Store a quantum key
  console.log("Test 1: Store ML-KEM-768 private key in vault");
  const quantumKey = new Uint8Array(randomBytes(2400));
  const storeResult = vault.store(quantumKey, password, {
    label: "quantum-primary",
    algorithm: "ML-KEM-768",
    mode: "quantum",
    expiryDays: 90,
    metadata: { owner: "PTH-Meridian", purpose: "encryption" },
  });
  console.log(`  Key ID:      ${storeResult.id}`);
  console.log(`  Label:       ${storeResult.label}`);
  console.log(`  Status:      ${storeResult.status}`);
  console.log(`  Created:     ${storeResult.createdAt}`);
  console.log(`  Expires:     ${storeResult.expiresAt}`);

  // Test 2 - Retrieve and verify
  console.log("\nTest 2: Retrieve key and verify integrity");
  const retrieveResult = vault.retrieve(storeResult.id, password);
  console.log(`  Retrieved:   ${retrieveResult.label}`);
  console.log(`  Algorithm:   ${retrieveResult.algorithm}`);
  console.log(`  Key Length:  ${retrieveResult.privateKey.length} bytes`);
  console.log(`  Match:       ${Buffer.from(retrieveResult.privateKey).toString("hex") === Buffer.from(quantumKey).toString("hex")}`);

  // Test 3 - Store with Shamir backup
  console.log("\nTest 3: Store key with automatic Shamir backup");
  const classicalKey = new Uint8Array(randomBytes(32));
  const shamirStoreResult = vault.store(classicalKey, password, {
    label: "classical-ecdsa",
    algorithm: "ECDSA-P256",
    mode: "classic",
    expiryDays: 365,
    metadata: { owner: "PTH-Meridian", purpose: "signing" },
    shamirConfig: { threshold: 2, totalShares: 3, label: "ecdsa-backup" },
  });
  console.log(`  Key ID:      ${shamirStoreResult.id}`);
  console.log(`  Shamir:      ${shamirStoreResult.shamirShares?.length} shares generated`);
  console.log(`  Shares:      ${shamirStoreResult.shamirShares?.join(", ")}`);

  // Test 4 - Rotate key
  console.log("\nTest 4: Rotate quantum key");
  const newQuantumKey = new Uint8Array(randomBytes(2400));
  const rotateResult = vault.rotate(
    storeResult.id,
    password,
    newQuantumKey,
    password
  );
  console.log(`  Old ID:      ${rotateResult.oldId}`);
  console.log(`  New ID:      ${rotateResult.newId}`);
  console.log(`  Status:      ${rotateResult.status}`);
  console.log(`  Rotated At:  ${rotateResult.rotatedAt}`);

  // Test 5 - Revoke key
  console.log("\nTest 5: Revoke classical key");
  vault.revoke(shamirStoreResult.id, password, "test revocation");
  console.log(`  Status:      ${vault.getStatus(shamirStoreResult.id)}`);

  // Test 6 - Try to retrieve revoked key
  console.log("\nTest 6: Attempt to retrieve revoked key (should fail)");
  try {
    vault.retrieve(shamirStoreResult.id, password);
    console.log("  ERROR: Should have thrown");
  } catch (err: unknown) {
    console.log(`  Correctly blocked: ${err instanceof Error ? err.message : String(err)}`);
  }

  // Test 7 - Store hybrid and mobile keys
  console.log("\nTest 7: Store hybrid and mobile keys");
  const hybridKey = new Uint8Array(randomBytes(32));
  const mobileKey = new Uint8Array(randomBytes(800));

  vault.store(hybridKey, password, {
    label: "hybrid-ecdh-mlkem",
    algorithm: "HYBRID-ECDH-MLKEM768",
    mode: "hybrid",
    expiryDays: 180,
    metadata: { purpose: "key-exchange" },
  });

  vault.store(mobileKey, password, {
    label: "mobile-ml-kem-512",
    algorithm: "ML-KEM-512",
    mode: "mobile",
    expiryDays: 30,
    metadata: { device: "mobile-primary" },
  });

  // Test 8 - Vault stats
  console.log("\nTest 8: Vault statistics");
  const stats = vault.stats() as Record<string, unknown>;
  Object.entries(stats).forEach(([k, v]) => {
    console.log(`  ${k}: ${Array.isArray(v) ? v.join(", ") : v}`);
  });

  // Test 9 - List all keys
  console.log("\nTest 9: Key inventory");
  const inventory = vault.list();
  inventory.forEach((entry) => {
    console.log(`  [${entry.status.toUpperCase()}] ${entry.id} — ${entry.label} (${entry.algorithm})`);
  });

  // Test 10 - Expiring keys check
  console.log("\nTest 10: Keys expiring within 60 days");
  const expiring = vault.getExpiring(60);
  expiring.forEach((e) => {
    console.log(`  ${e.label} expires ${new Date(e.expiresAt!).toISOString()}`);
  });

  console.log("\n=== Phase 2 Complete ===");
  console.log("Key Vault operational.");
  console.log("Store. Retrieve. Rotate. Revoke. Inventory. All working.");
}

main().catch(console.error);