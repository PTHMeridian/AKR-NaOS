import { KDFModule, KDF_PROFILES } from "./phase2-vault/kdf";
import { VaultModule } from "./phase2-vault/index";
import { ShamirModule } from "./phase1-shamir/index";
import { PKIModule } from "./phase3-pki/index";
import { SecureChannelModule } from "./phase4-channel/index";
import { AuditModule } from "./phase5-audit/index";
import { IdentityWallet } from "./phase6-wallet/index";
import { randomBytes } from "crypto";

async function main() {
  console.log("AKR Naos - Nested Authentication Operations Suite");
  console.log("SA AT Cryptographics");
  console.log("Step 1 - Argon2id KDF Upgrade");
  console.log("=".repeat(60) + "\n");

  // ============================================================
  // KDF MODULE TESTS
  // ============================================================
  console.log("=== KDF Module - Argon2id ===\n");

  const kdf = new KDFModule();

  // Test 1 - Security profiles
  console.log("Test 1: Security profiles");
  const profiles = ["INTERACTIVE", "MODERATE", "SENSITIVE"] as const;
  const profileMap = {
    INTERACTIVE: KDF_PROFILES.INTERACTIVE,
    MODERATE: KDF_PROFILES.MODERATE,
    SENSITIVE: KDF_PROFILES.SENSITIVE,
  };
  for (const name of profiles) {
    const info = kdf.getSecurityInfo(profileMap[name]) as Record<string, unknown>;
    console.log("  " + name + ":");
    console.log("    Memory:       " + info.memoryCost);
    console.log("    Time Cost:    " + info.timeCost);
    console.log("    Parallelism:  " + info.parallelism);
    console.log("    Hash Length:  " + info.hashLength);
    console.log("    Attack Cost:  " + info.relativeAttackCost);
  }

  // Test 2 - Key derivation
  console.log("\nTest 2: Derive key from password");
  const password = "sa-at-vault-master-password-2026";
  const start2 = Date.now();
  const derived = await kdf.deriveKeyForVault(password);
  const time2 = Date.now() - start2;
  console.log("  Algorithm:    " + derived.algorithm);
  console.log("  Key Length:   " + derived.key.length + " bytes");
  console.log("  Salt Length:  " + derived.salt.length + " bytes");
  console.log("  Time:         " + time2 + "ms");
  console.log("  Key Preview:  " + derived.key.toString("hex").substring(0, 32) + "...");

  // Test 3 - Same password + same salt = same key (deterministic)
  console.log("\nTest 3: Deterministic derivation (same password + salt = same key)");
  const derived2 = await kdf.deriveKey(password, derived.salt);
  const match = derived.key.toString("hex") === derived2.key.toString("hex");
  console.log("  Keys match:   " + match);

  // Test 4 - Same password + different salt = different key
  console.log("\nTest 4: Different salt = different key");
  const derived3 = await kdf.deriveKeyForVault(password);
  const noMatch = derived.key.toString("hex") !== derived3.key.toString("hex");
  console.log("  Keys differ:  " + noMatch);

  // Test 5 - Password hashing and verification
  console.log("\nTest 5: Password hashing and verification");
  const hash = await kdf.hash(password);
  console.log("  Hash:         " + hash.substring(0, 40) + "...");
  const verify1 = await kdf.verify(password, hash);
  const verify2 = await kdf.verify("wrong-password", hash);
  console.log("  Correct pwd:  " + verify1.valid + " (" + verify1.timeTaken + "ms)");
  console.log("  Wrong pwd:    " + verify2.valid + " (" + verify2.timeTaken + "ms)");

  // Test 6 - Sensitive profile
  console.log("\nTest 6: Sensitive profile (high security)");
  const start6 = Date.now();
  const sensitiveDerived = await kdf.deriveKeyForSensitive(password);
  const time6 = Date.now() - start6;
  console.log("  Algorithm:    " + sensitiveDerived.algorithm);
  console.log("  Key Length:   " + sensitiveDerived.key.length + " bytes");
  console.log("  Time:         " + time6 + "ms");
  console.log("  (Slower = more secure against brute force)");

  // Test 7 - Serialization roundtrip
  console.log("\nTest 7: Config serialization roundtrip");
  const serialized = kdf.serializeConfig(derived);
  const deserialized = kdf.deserializeConfig(serialized);
  const saltMatch = deserialized.salt.toString("hex") === derived.salt.toString("hex");
  console.log("  Serialized:   " + serialized.substring(0, 60) + "...");
  console.log("  Salt match:   " + saltMatch);
  console.log("  Algorithm:    " + deserialized.algorithm);

  // ============================================================
  // VAULT WITH ARGON2ID
  // ============================================================
  console.log("\n=== Vault with Argon2id KDF ===\n");

  const vault = new VaultModule();
  const vaultPassword = "sa-at-vault-master-password-2026";

  // Test 8 - Store with Argon2id
  console.log("Test 8: Store key with Argon2id encryption");
  const quantumKey = new Uint8Array(randomBytes(2400));
  const startStore = Date.now();
  const storeResult = await vault.store(quantumKey, vaultPassword, {
    label: "quantum-primary",
    algorithm: "ML-KEM-768",
    mode: "quantum",
    expiryDays: 90,
    metadata: { owner: "PTH-Meridian" },
  });
  const timeStore = Date.now() - startStore;
  console.log("  Key ID:       " + storeResult.id);
  console.log("  KDF:          " + storeResult.kdfAlgorithm);
  console.log("  Status:       " + storeResult.status);
  console.log("  Store time:   " + timeStore + "ms");

  // Test 9 - Retrieve and verify
  console.log("\nTest 9: Retrieve with Argon2id verification");
  const startRetrieve = Date.now();
  const retrieved = await vault.retrieve(storeResult.id, vaultPassword);
  const timeRetrieve = Date.now() - startRetrieve;
  const keyMatch = Buffer.from(retrieved.privateKey).toString("hex") === Buffer.from(quantumKey).toString("hex");
  console.log("  Retrieved:    " + retrieved.label);
  console.log("  Key match:    " + keyMatch);
  console.log("  Retrieve time:" + timeRetrieve + "ms");

  // Test 10 - Wrong password rejected
  console.log("\nTest 10: Wrong password rejection");
  try {
    await vault.retrieve(storeResult.id, "wrong-password");
    console.log("  ERROR: Should have failed");
  } catch (err: unknown) {
    console.log("  Correctly rejected: " + (err instanceof Error ? err.message.substring(0, 50) : String(err)));
  }

  // Test 11 - Sensitive key storage
  console.log("\nTest 11: Sensitive key storage (high security profile)");
  const rootCAKey = new Uint8Array(randomBytes(32));
  const startSensitive = Date.now();
  const sensitiveResult = await vault.store(rootCAKey, vaultPassword, {
    label: "root-ca-signing-key",
    algorithm: "ML-DSA-65",
    mode: "quantum",
    expiryDays: 3650,
    sensitive: true,
    metadata: { purpose: "root-ca", classification: "TOP-SECRET" },
  });
  const timeSensitive = Date.now() - startSensitive;
  console.log("  Key ID:       " + sensitiveResult.id);
  console.log("  KDF:          " + sensitiveResult.kdfAlgorithm);
  console.log("  Store time:   " + timeSensitive + "ms (slower = more secure)");

  // Test 12 - Vault stats
  console.log("\nTest 12: Vault statistics");
  const stats = vault.stats() as Record<string, unknown>;
  Object.entries(stats).forEach(([k, v]) => {
    console.log("  " + k + ": " + v);
  });

  console.log("\n" + "=".repeat(60));
  console.log("=== Step 1 Complete - Argon2id KDF ===");
  console.log("=".repeat(60));
  console.log("");
  console.log("REPLACED:  SHA-256 iterative loop (100k iterations)");
  console.log("WITH:      Argon2id memory-hard KDF");
  console.log("");
  console.log("INTERACTIVE profile:  64MB RAM, 3 iterations");
  console.log("SENSITIVE profile:    1GB RAM, 5 iterations");
  console.log("");
  console.log("GPU brute force:      Economically infeasible");
  console.log("ASIC optimization:    Defeated by memory hardness");
  console.log("Quantum speedup:      Partially mitigated");
  console.log("");
  console.log("Vault KDF:            UPGRADED");
  console.log("Key derivation:       PRODUCTION GRADE");
}

main().catch(console.error);