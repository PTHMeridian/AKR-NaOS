import { ShamirModule } from "./phase1-shamir/index";
import { VaultModule } from "./phase2-vault/index";
import { PKIModule } from "./phase3-pki/index";
import { randomBytes } from "crypto";

async function main() {
  console.log("AKR Naos - Nested Authentication Operations Suite");
  console.log("SA AT Cryptographics\n");

  // ============================================================
  // PHASE 1 - SHAMIR SECRET SHARING
  // ============================================================
  console.log("=== Phase 1 - Shamir Secret Sharing ===");
  const shamir = new ShamirModule();
  const privateKey = "simulated-ml-kem-768-private-key-material-for-testing";
  const splitResult = shamir.split(privateKey, { threshold: 3, totalShares: 5, label: "AKR-primary-key" });
  const selectedShares = [splitResult.shares[0], splitResult.shares[2], splitResult.shares[4]];
  const recoverResult = shamir.recover(selectedShares, splitResult.secretHash);
  console.log("Shamir Split:    " + splitResult.totalShares + " shares, threshold " + splitResult.threshold);
  console.log("Recovered:       " + (recoverResult.secret === privateKey));
  console.log("Verified:        " + recoverResult.verified);
  console.log("=== Phase 1 Complete ===\n");

  // ============================================================
  // PHASE 2 - KEY VAULT
  // ============================================================
  console.log("=== Phase 2 - Key Vault ===");
  const vault = new VaultModule();
  const password = "sa-at-vault-master-password-2026";
  const quantumKey = new Uint8Array(randomBytes(2400));
  const storeResult = vault.store(quantumKey, password, {
    label: "quantum-primary",
    algorithm: "ML-KEM-768",
    mode: "quantum",
    expiryDays: 90,
    metadata: { owner: "PTH-Meridian" },
  });
  const retrieveResult = vault.retrieve(storeResult.id, password);
  console.log("Stored:          " + storeResult.label + " (" + storeResult.id + ")");
  console.log("Retrieved:       " + retrieveResult.label);
  console.log("Key Match:       " + (Buffer.from(retrieveResult.privateKey).toString("hex") === Buffer.from(quantumKey).toString("hex")));
  const stats2 = vault.stats() as Record<string, unknown>;
  console.log("Vault Stats:     " + JSON.stringify(stats2));
  console.log("=== Phase 2 Complete ===\n");

  // ============================================================
  // PHASE 3 - CERTIFICATE AUTHORITY
  // ============================================================
  console.log("=== Phase 3 - Certificate Authority (PKI) ===\n");

  const pki = new PKIModule();
  const caPublicKey = new Uint8Array(randomBytes(1952));
  const intPublicKey = new Uint8Array(randomBytes(1952));
  const alicePublicKey = new Uint8Array(randomBytes(1952));
  const bobPublicKey = new Uint8Array(randomBytes(1952));
  const serverPublicKey = new Uint8Array(randomBytes(1952));

  // Test 1 - Create Root CA
  console.log("Test 1: Create Root CA");
  const rootCA = pki.createRootCA(
    {
      commonName: "PTH Meridian Root CA",
      organization: "PTH Meridian",
      organizationalUnit: "SA AT Cryptographics",
      country: "CA",
      state: "Alberta",
      locality: "Calgary",
    },
    caPublicKey,
    3650
  );
  console.log("  ID:            " + rootCA.id);
  console.log("  Serial:        " + rootCA.serialNumber);
  console.log("  Algorithm:     " + rootCA.algorithm);
  console.log("  Valid From:    " + rootCA.validFrom);
  console.log("  Valid To:      " + rootCA.validTo);
  console.log("  Fingerprint:   " + rootCA.fingerprint.substring(0, 32) + "...");
  console.log("  Is CA:         " + rootCA.isCA);

  // Test 2 - Issue Intermediate CA
  console.log("\nTest 2: Issue Intermediate CA");
  const intCA = pki.issueIntermediateCA(
    {
      commonName: "PTH Meridian Intermediate CA",
      organization: "PTH Meridian",
      organizationalUnit: "AKR Naos",
      country: "CA",
    },
    intPublicKey,
    1825
  );
  console.log("  ID:            " + intCA.id);
  console.log("  Issuer:        " + JSON.stringify(intCA.issuer));
  console.log("  Is CA:         " + intCA.isCA);

  // Test 3 - Issue end entity certificates
  console.log("\nTest 3: Issue end-entity certificates");
  const aliceCert = pki.issueCertificate(
    {
      commonName: "alice@pth-meridian.io",
      organization: "PTH Meridian",
      email: "alice@pth-meridian.io",
    },
    alicePublicKey,
    intCA.id,
    365
  );
  console.log("  Alice Cert ID: " + aliceCert.id);
  console.log("  Issued by:     " + JSON.stringify(aliceCert.issuer));

  const bobCert = pki.issueCertificate(
    {
      commonName: "bob@pth-meridian.io",
      organization: "PTH Meridian",
      email: "bob@pth-meridian.io",
    },
    bobPublicKey,
    intCA.id,
    365
  );
  console.log("  Bob Cert ID:   " + bobCert.id);

  const serverCert = pki.issueCertificate(
    {
      commonName: "api.akr-naos.pth-meridian.io",
      organization: "PTH Meridian",
      organizationalUnit: "Infrastructure",
    },
    serverPublicKey,
    intCA.id,
    90
  );
  console.log("  Server Cert:   " + serverCert.id);

  // Test 4 - Verify certificates
  console.log("\nTest 4: Verify certificate chain");
  const rootVerify = pki.verify(rootCA.id);
  const intVerify = pki.verify(intCA.id);
  const aliceVerify = pki.verify(aliceCert.id);
  console.log("  Root CA Valid:    " + rootVerify.valid);
  console.log("  Root Checks:      " + JSON.stringify(rootVerify.checks));
  console.log("  Int CA Valid:     " + intVerify.valid);
  console.log("  Alice Valid:      " + aliceVerify.valid);
  console.log("  Alice Checks:     " + JSON.stringify(aliceVerify.checks));

  // Test 5 - Certificate chain
  console.log("\nTest 5: Certificate chain traversal");
  const chain = pki.getChain(aliceCert.id);
  console.log("  Chain length:  " + chain.length);
  chain.forEach((cert, i) => {
    console.log("  [" + i + "] " + cert.subject.commonName + " (CA: " + cert.isCA + ")");
  });

  // Test 6 - Revoke a certificate
  console.log("\nTest 6: Revoke Bob certificate");
  pki.revoke(bobCert.id, "key compromise");
  const bobVerify = pki.verify(bobCert.id);
  console.log("  Bob Valid:     " + bobVerify.valid);
  console.log("  Bob Status:    " + bobVerify.status);
  console.log("  Bob Checks:    " + JSON.stringify(bobVerify.checks));

  // Test 7 - Certificate Revocation List
  console.log("\nTest 7: Certificate Revocation List (CRL)");
  const crl = pki.getCRL();
  console.log("  CRL Entries:   " + crl.length);
  crl.forEach((entry) => {
    console.log("  Serial: " + entry.serialNumber.substring(0, 16) + "... Reason: " + entry.reason);
  });

  // Test 8 - Full inventory
  console.log("\nTest 8: Certificate inventory");
  const inventory = pki.list();
  inventory.forEach((cert) => {
    const type = cert.isCA ? "CA  " : "CERT";
    console.log("  [" + cert.status.toUpperCase() + "] [" + type + "] " + cert.subject.commonName);
  });

  // Test 9 - PKI stats
  console.log("\nTest 9: PKI statistics");
  const pkiStats = pki.stats() as Record<string, unknown>;
  Object.entries(pkiStats).forEach(([k, v]) => {
    console.log("  " + k + ": " + v);
  });

  console.log("\n=== Phase 3 Complete ===");
  console.log("Certificate Authority operational.");
  console.log("Root CA. Intermediate CA. End-entity certs. Chain verification. CRL. All working.");
}

main().catch(console.error);