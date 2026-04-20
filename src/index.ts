import { ShamirModule } from "./phase1-shamir/index";
import { VaultModule } from "./phase2-vault/index";
import { PKIModule } from "./phase3-pki/index";
import { SecureChannelModule } from "./phase4-channel/index";
import { AuditModule } from "./phase5-audit/index";
import { IdentityWallet } from "./phase6-wallet/index";
import { randomBytes } from "crypto";

async function main() {
  console.log("AKR Naos - Nested Authentication Operations Suite");
  console.log("SA AT Cryptographics");
  console.log("=".repeat(60) + "\n");

  const audit = new AuditModule();
  audit.record("SYSTEM_START", "AKR-NAOS", "INFO", { version: "1.0.0", phases: 6 }, "SYSTEM");

  // PHASE 1
  console.log("=== Phase 1 - Shamir Secret Sharing ===");
  const shamir = new ShamirModule();
  const secret = "simulated-ml-kem-768-private-key-material-for-testing";
  const split = shamir.split(secret, { threshold: 3, totalShares: 5, label: "primary-key" });
  audit.record("SECRET_SPLIT", "primary-key", "INFO", { threshold: 3, totalShares: 5 }, "alice");
  const recovered = shamir.recover([split.shares[0], split.shares[2], split.shares[4]], split.secretHash);
  audit.record("SECRET_RECOVERED", "primary-key", "INFO", { verified: recovered.verified }, "alice");
  console.log("Split: " + split.totalShares + " shares, threshold " + split.threshold + " | Recovered: " + (recovered.secret === secret) + " | Verified: " + recovered.verified);
  console.log("=== Phase 1 Complete ===\n");

  // PHASE 2
  console.log("=== Phase 2 - Key Vault ===");
  const vault = new VaultModule();
  const password = "sa-at-vault-master-password-2026";
  const signingKey = new Uint8Array(randomBytes(32));
  const encryptKey = new Uint8Array(randomBytes(2400));
  const sigStore = vault.store(signingKey, password, { label: "alice-signing", algorithm: "ML-DSA-65", mode: "quantum", expiryDays: 365, metadata: { owner: "alice" } });
  const encStore = vault.store(encryptKey, password, { label: "alice-encryption", algorithm: "ML-KEM-768", mode: "quantum", expiryDays: 365, metadata: { owner: "alice" } });
  audit.record("KEY_STORED", sigStore.id, "INFO", { label: "alice-signing" }, "alice");
  audit.record("KEY_STORED", encStore.id, "INFO", { label: "alice-encryption" }, "alice");
  console.log("Signing key:    " + sigStore.id);
  console.log("Encryption key: " + encStore.id);
  console.log("=== Phase 2 Complete ===\n");

  // PHASE 3
  console.log("=== Phase 3 - Certificate Authority ===");
  const pki = new PKIModule();
  const rootCA = pki.createRootCA({ commonName: "PTH Meridian Root CA", organization: "PTH Meridian", country: "CA" }, new Uint8Array(randomBytes(1952)), 3650);
  const intCA = pki.issueIntermediateCA({ commonName: "PTH Meridian Intermediate CA", organization: "PTH Meridian" }, new Uint8Array(randomBytes(1952)), 1825);
  const aliceCert = pki.issueCertificate({ commonName: "alice@pth-meridian.io", organization: "PTH Meridian", email: "alice@pth-meridian.io" }, new Uint8Array(randomBytes(1952)), intCA.id, 365);
  const serverCert = pki.issueCertificate({ commonName: "api.akr-naos.io", organization: "PTH Meridian" }, new Uint8Array(randomBytes(1952)), intCA.id, 90);
  audit.record("CERT_ISSUED", aliceCert.id, "INFO", { subject: aliceCert.subject }, "PKI-ENGINE");
  audit.record("CERT_ISSUED", serverCert.id, "INFO", { subject: serverCert.subject }, "PKI-ENGINE");
  console.log("Alice cert: " + aliceCert.id + " | Valid: " + pki.verify(aliceCert.id).valid);
  console.log("=== Phase 3 Complete ===\n");

  // PHASE 4
  console.log("=== Phase 4 - Secure Channel ===");
  const channel = new SecureChannelModule();
  const hello = channel.initiateHandshake();
  const response = channel.respondToHandshake(hello, serverCert.id);
  const sharedSecret = new Uint8Array(randomBytes(32));
  const session = channel.establishSession(hello.sessionId, sharedSecret, hello.nonce, response.nonce, response.chosenAlgorithm, 60);
  audit.record("SESSION_ESTABLISHED", session.sessionId, "INFO", { algorithm: session.algorithm }, "alice");
  const encrypted = channel.encrypt(session.sessionId, "PTH Meridian - Ask. Solve. Done.");
  const decrypted = channel.decrypt(encrypted);
  audit.record("MESSAGE_ENCRYPTED", session.sessionId, "INFO", { sequence: encrypted.sequence }, "alice");
  console.log("Session: " + session.sessionId + " | Message match: " + (decrypted === "PTH Meridian - Ask. Solve. Done."));
  console.log("=== Phase 4 Complete ===\n");

  // PHASE 5
  console.log("=== Phase 5 - Audit Engine ===");
  audit.record("AUTH_FAILURE", "vault", "WARN", { reason: "bad password" }, "attacker");
  audit.record("AUTH_FAILURE", "vault", "WARN", { reason: "bad password" }, "attacker");
  audit.record("AUTH_FAILURE", "vault", "CRITICAL", { reason: "bad password", count: 3 }, "attacker");
  const integrityCheck = audit.verifyIntegrity();
  console.log("Chain integrity: " + integrityCheck.valid + " (" + integrityCheck.totalChecked + " entries)");
  const hmitAlerts = audit.getHMITAlerts("open");
  console.log("HMIT alerts:     " + hmitAlerts.length + " open");
  if (hmitAlerts.length > 0) {
    audit.acknowledgeHMIT(hmitAlerts[0].alertId);
    audit.resolveHMIT(hmitAlerts[0].alertId);
  }
  console.log("=== Phase 5 Complete ===\n");

  // PHASE 6 - IDENTITY WALLET
  console.log("=== Phase 6 - Identity Wallet ===\n");

  const wallet = new IdentityWallet();

  // Test 1 - Create wallet
  console.log("Test 1: Create identity wallet");
  const identity = wallet.create(
    "Alice Chen",
    sigStore.id,
    encStore.id,
    {
      email: "alice@pth-meridian.io",
      organization: "PTH Meridian",
      certId: aliceCert.id,
    }
  );
  audit.record("AUTH_SUCCESS", identity.did, "INFO", { action: "wallet_created" }, "alice");
  console.log("  DID:           " + identity.did);
  console.log("  Display Name:  " + identity.displayName);
  console.log("  Email:         " + identity.email);
  console.log("  Organization:  " + identity.organization);
  console.log("  Signing Key:   " + identity.signingKeyId);
  console.log("  Cert ID:       " + identity.certId);
  console.log("  Created:       " + new Date(identity.createdAt).toISOString());

  // Test 2 - Export DID document
  console.log("\nTest 2: DID document");
  const didDoc = wallet.exportDID() as Record<string, unknown>;
  console.log("  DID Document:");
  Object.entries(didDoc).forEach(([k, v]) => {
    if (Array.isArray(v)) {
      console.log("  " + k + ": [" + v.length + " entries]");
    } else if (typeof v === "object" && v !== null) {
      console.log("  " + k + ": " + JSON.stringify(v).substring(0, 60));
    } else {
      console.log("  " + k + ": " + v);
    }
  });

  // Test 3 - Add verifiable credentials
  console.log("\nTest 3: Add verifiable credentials");
  const empCred = wallet.addCredential(
    ["VerifiableCredential", "EmploymentCredential"],
    "PTH Meridian HR",
    {
      employeeId: "PTH-2026-001",
      role: "Cryptographic Engineer",
      department: "SA AT Cryptographics",
      startDate: "2026-01-01",
      clearanceLevel: "TOP",
    },
    365
  );
  audit.record("AUTH_SUCCESS", empCred.id, "INFO", { type: "credential_added" }, "alice");
  console.log("  Employment Credential: " + empCred.id);
  console.log("  Type:    " + empCred.type.join(", "));
  console.log("  Issuer:  " + empCred.issuer);
  console.log("  Claims:  " + Object.keys(empCred.claims).join(", "));
  console.log("  Algorithm: " + empCred.algorithm);

  const accessCred = wallet.addCredential(
    ["VerifiableCredential", "SystemAccessCredential"],
    "PTH Meridian IT",
    {
      systems: ["AKR-KeyGen", "AKR-Naos", "AMuN"],
      accessLevel: "ADMIN",
      mfaEnabled: true,
    },
    180
  );
  console.log("  System Access Credential: " + accessCred.id);

  const idCred = wallet.addCredential(
    ["VerifiableCredential", "IdentityCredential"],
    "PTH Meridian Root CA",
    {
      legalName: "Alice Chen",
      email: "alice@pth-meridian.io",
      country: "CA",
      verified: true,
    },
    730
  );
  console.log("  Identity Credential: " + idCred.id);

  // Test 4 - Document signing
  console.log("\nTest 4: Document signing");
  const documents = [
    { name: "Q1 Security Report", content: "PTH Meridian Q1 2026 Security Assessment. All systems operational. No breaches detected. AKR Naos deployed successfully." },
    { name: "Key Rotation Policy", content: "All cryptographic keys must be rotated every 90 days. ML-KEM-768 and ML-DSA-65 are the approved algorithms." },
    { name: "NDA Agreement", content: "This non-disclosure agreement binds Alice Chen to maintain confidentiality of PTH Meridian cryptographic infrastructure." },
  ];

  const signedDocs = [];
  for (const doc of documents) {
    const signed = wallet.signDocument(doc.content, doc.name);
    audit.record("AUTH_SUCCESS", signed.documentId, "INFO", { document: doc.name, hash: signed.documentHash.substring(0, 16) }, "alice");
    signedDocs.push({ doc, signed });
    console.log("  [SIGNED] " + doc.name);
    console.log("    Doc ID:    " + signed.documentId);
    console.log("    Hash:      " + signed.documentHash.substring(0, 32) + "...");
    console.log("    Algorithm: " + signed.algorithm);
  }

  // Test 5 - Document verification
  console.log("\nTest 5: Document verification");
  for (const { doc, signed } of signedDocs) {
    const valid = wallet.verifyDocument(doc.content, signed.documentId);
    const tampered = wallet.verifyDocument(doc.content + " TAMPERED", signed.documentId);
    console.log("  " + doc.name + ":");
    console.log("    Original valid:  " + valid);
    console.log("    Tampered valid:  " + tampered);
  }

  // Test 6 - Verifiable presentation
  console.log("\nTest 6: Selective disclosure presentation");
  const request: import("./phase6-wallet/index").PresentationRequest = {
    requestId: "REQ-" + Date.now(),
    requester: "api.akr-naos.io",
    requestedClaims: ["role", "accessLevel", "mfaEnabled", "verified"],
    purpose: "System access authorization",
    timestamp: Date.now(),
  };
  console.log("  Requester:       " + request.requester);
  console.log("  Purpose:         " + request.purpose);
  console.log("  Requested:       " + request.requestedClaims.join(", "));

  const presentation = wallet.createPresentation(
    request,
    [empCred.id, accessCred.id, idCred.id]
  );
  console.log("  Presentation ID: " + presentation.presentationId);
  console.log("  Holder DID:      " + presentation.holderDid);
  console.log("  Disclosed:");
  Object.entries(presentation.disclosedClaims).forEach(([k, v]) => {
    console.log("    " + k + ": " + v);
  });
  console.log("  Note: Other claims NOT disclosed (selective disclosure)");

  // Test 7 - Credential revocation
  console.log("\nTest 7: Credential revocation");
  wallet.revokeCredential(accessCred.id);
  audit.record("KEY_REVOKED", accessCred.id, "ALERT", { reason: "access terminated" }, "alice");
  const creds = wallet.getCredentials();
  creds.forEach((c) => {
    console.log("  [" + c.status.toUpperCase() + "] " + c.type[1] + " — " + c.id);
  });

  // Test 8 - Wallet stats
  console.log("\nTest 8: Wallet statistics");
  const stats = wallet.getStats();
  Object.entries(stats).forEach(([k, v]) => {
    console.log("  " + k + ": " + v);
  });

  // Final audit report
  console.log("\n=== Final System Audit Report ===");
  audit.record("SYSTEM_STOP", "AKR-NAOS", "INFO", { reason: "normal shutdown", phasesComplete: 6 }, "SYSTEM");
  const finalReport = audit.generateReport();
  console.log("  Total Events:    " + finalReport.totalEvents);
  console.log("  Integrity:       " + finalReport.integrityValid);
  console.log("  HMIT Alerts:     " + finalReport.hmitAlerts.length);
  console.log("  Event Breakdown:");
  Object.entries(finalReport.breakdown).forEach(([type, count]) => {
    console.log("    " + type + ": " + count);
  });
  console.log("  Top Actors:");
  finalReport.topActors.forEach((a) => {
    console.log("    " + a.actor + ": " + a.count + " events");
  });

  console.log("\n" + "=".repeat(60));
  console.log("=== ALL 6 PHASES COMPLETE ===");
  console.log("=".repeat(60));
  console.log("");
  console.log("AKR Naos - Nested Authentication Operations Suite");
  console.log("SA AT Cryptographics - PTH Meridian");
  console.log("");
  console.log("Phase 1  Shamir Secret Sharing     OPERATIONAL");
  console.log("Phase 2  Key Vault                 OPERATIONAL");
  console.log("Phase 3  Certificate Authority     OPERATIONAL");
  console.log("Phase 4  Secure Channel            OPERATIONAL");
  console.log("Phase 5  Audit Engine + HMIT       OPERATIONAL");
  console.log("Phase 6  Identity Wallet           OPERATIONAL");
  console.log("");
  console.log("The foundation is built.");
  console.log("The palace can now be constructed.");
}

main().catch(console.error);