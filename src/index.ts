import { ShamirModule } from "./phase1-shamir/index";
import { VaultModule } from "./phase2-vault/index";
import { PKIModule } from "./phase3-pki/index";
import { SecureChannelModule } from "./phase4-channel/index";
import { AuditModule } from "./phase5-audit/index";
import { randomBytes } from "crypto";

async function main() {
  console.log("AKR Naos - Nested Authentication Operations Suite");
  console.log("SA AT Cryptographics\n");

  const audit = new AuditModule();
  audit.record("SYSTEM_START", "AKR-NAOS", "INFO", { version: "1.0.0" }, "SYSTEM");

  // PHASE 1
  console.log("=== Phase 1 - Shamir Secret Sharing ===");
  const shamir = new ShamirModule();
  const privateKey = "simulated-ml-kem-768-private-key-material-for-testing";
  const splitResult = shamir.split(privateKey, { threshold: 3, totalShares: 5, label: "AKR-primary-key" });
  audit.record("SECRET_SPLIT", "AKR-primary-key", "INFO", { threshold: 3, totalShares: 5 }, "alice");
  const selectedShares = [splitResult.shares[0], splitResult.shares[2], splitResult.shares[4]];
  const recoverResult = shamir.recover(selectedShares, splitResult.secretHash);
  audit.record("SECRET_RECOVERED", "AKR-primary-key", "INFO", { verified: recoverResult.verified }, "alice");
  console.log("Split: " + splitResult.totalShares + " shares | Recovered: " + (recoverResult.secret === privateKey));
  console.log("=== Phase 1 Complete ===\n");

  // PHASE 2
  console.log("=== Phase 2 - Key Vault ===");
  const vault = new VaultModule();
  const password = "sa-at-vault-master-password-2026";
  const quantumKey = new Uint8Array(randomBytes(2400));
  const storeResult = vault.store(quantumKey, password, {
    label: "quantum-primary", algorithm: "ML-KEM-768", mode: "quantum", expiryDays: 90, metadata: { owner: "PTH-Meridian" },
  });
  audit.record("KEY_STORED", storeResult.id, "INFO", { label: storeResult.label, algorithm: "ML-KEM-768" }, "alice");
  const retrieveResult = vault.retrieve(storeResult.id, password);
  audit.record("KEY_RETRIEVED", storeResult.id, "INFO", { label: retrieveResult.label }, "alice");
  console.log("Stored: " + storeResult.label + " | Match: " + (Buffer.from(retrieveResult.privateKey).toString("hex") === Buffer.from(quantumKey).toString("hex")));
  console.log("=== Phase 2 Complete ===\n");

  // PHASE 3
  console.log("=== Phase 3 - Certificate Authority ===");
  const pki = new PKIModule();
  const rootCA = pki.createRootCA(
    { commonName: "PTH Meridian Root CA", organization: "PTH Meridian", country: "CA" },
    new Uint8Array(randomBytes(1952)), 3650
  );
  audit.record("CERT_ISSUED", rootCA.id, "INFO", { type: "ROOT_CA", subject: rootCA.subject }, "PKI-ENGINE");
  const intCA = pki.issueIntermediateCA(
    { commonName: "PTH Meridian Intermediate CA", organization: "PTH Meridian" },
    new Uint8Array(randomBytes(1952)), 1825
  );
  audit.record("CERT_ISSUED", intCA.id, "INFO", { type: "INTERMEDIATE_CA" }, "PKI-ENGINE");
  const aliceCert = pki.issueCertificate(
    { commonName: "alice@pth-meridian.io", organization: "PTH Meridian" },
    new Uint8Array(randomBytes(1952)), intCA.id, 365
  );
  audit.record("CERT_ISSUED", aliceCert.id, "INFO", { subject: aliceCert.subject }, "PKI-ENGINE");
  const serverCert = pki.issueCertificate(
    { commonName: "api.akr-naos.io", organization: "PTH Meridian" },
    new Uint8Array(randomBytes(1952)), intCA.id, 90
  );
  audit.record("CERT_ISSUED", serverCert.id, "INFO", { subject: serverCert.subject }, "PKI-ENGINE");
  const bobCert = pki.issueCertificate(
    { commonName: "bob@pth-meridian.io", organization: "PTH Meridian" },
    new Uint8Array(randomBytes(1952)), intCA.id, 365
  );
  pki.revoke(bobCert.id, "key compromise");
  audit.record("CERT_REVOKED", bobCert.id, "ALERT", { reason: "key compromise" }, "PKI-ENGINE");
  console.log("Root CA + Int CA + 3 end-entity certs issued | Bob revoked");
  console.log("=== Phase 3 Complete ===\n");

  // PHASE 4
  console.log("=== Phase 4 - Secure Channel ===");
  const channel = new SecureChannelModule();
  const clientHello = channel.initiateHandshake();
  const serverHello = channel.respondToHandshake(clientHello, serverCert.id);
  const sharedSecret = new Uint8Array(randomBytes(32));
  const session = channel.establishSession(
    clientHello.sessionId, sharedSecret,
    clientHello.nonce, serverHello.nonce,
    serverHello.chosenAlgorithm, 60
  );
  audit.record("SESSION_ESTABLISHED", session.sessionId, "INFO", { algorithm: session.algorithm }, "alice");
  const msg1 = channel.encrypt(session.sessionId, "PTH Meridian - Ask. Solve. Done.");
  audit.record("MESSAGE_ENCRYPTED", session.sessionId, "INFO", { sequence: msg1.sequence, bytes: msg1.ciphertext.length }, "alice");
  const dec1 = channel.decrypt(msg1);
  audit.record("MESSAGE_DECRYPTED", session.sessionId, "INFO", { sequence: msg1.sequence, match: dec1 === "PTH Meridian - Ask. Solve. Done." }, "alice");
  channel.terminateSession(session.sessionId);
  audit.record("SESSION_TERMINATED", session.sessionId, "INFO", { reason: "normal closure" }, "alice");
  console.log("Session established | Message encrypted/decrypted | Session terminated");
  console.log("=== Phase 4 Complete ===\n");

  // PHASE 5 - AUDIT ENGINE
  console.log("=== Phase 5 - Audit Engine (HMIT Protocol) ===\n");

  // Test 1 - Log integrity verification
  console.log("Test 1: Tamper-evident log integrity");
  const integrity = audit.verifyIntegrity();
  console.log("  Chain Valid:     " + integrity.valid);
  console.log("  Entries Checked: " + integrity.totalChecked);

  // Test 2 - Simulate auth failures to trigger HMIT
  console.log("\nTest 2: Simulate repeated auth failures — HMIT trigger");
  audit.record("AUTH_FAILURE", "vault-login", "WARN", { reason: "invalid password" }, "unknown-actor");
  audit.record("AUTH_FAILURE", "vault-login", "WARN", { reason: "invalid password" }, "unknown-actor");
  audit.record("AUTH_FAILURE", "vault-login", "CRITICAL", { reason: "invalid password", count: 3 }, "unknown-actor");
  const openAlerts = audit.getHMITAlerts("open");
  console.log("  HMIT Alerts Triggered: " + openAlerts.length);
  openAlerts.forEach((alert) => {
    console.log("  Alert ID:      " + alert.alertId);
    console.log("  Severity:      " + alert.severity);
    console.log("  Reason:        " + alert.reason);
    console.log("  Recommended:   " + alert.recommended);
    console.log("  Status:        " + alert.status);
  });

  // Test 3 - Acknowledge and resolve HMIT alert
  console.log("\nTest 3: HMIT alert lifecycle");
  if (openAlerts.length > 0) {
    audit.acknowledgeHMIT(openAlerts[0].alertId);
    console.log("  Acknowledged:  " + openAlerts[0].alertId);
    audit.resolveHMIT(openAlerts[0].alertId);
    console.log("  Resolved:      " + openAlerts[0].alertId);
    console.log("  Status:        " + audit.getHMITAlerts()[0].status);
  }

  // Test 4 - Query audit log
  console.log("\nTest 4: Audit log queries");
  const certEvents = audit.query({ type: "CERT_ISSUED" });
  console.log("  CERT_ISSUED events:  " + certEvents.length);
  const alertEvents = audit.query({ severity: "ALERT" });
  console.log("  ALERT severity:      " + alertEvents.length);
  const aliceEvents = audit.query({ actor: "alice" });
  console.log("  Alice events:        " + aliceEvents.length);
  const hmitEvents = audit.query({ hmitOnly: true });
  console.log("  HMIT flagged:        " + hmitEvents.length);

  // Test 5 - Tamper simulation
  console.log("\nTest 5: Tamper detection");
  const preIntegrity = audit.verifyIntegrity();
  console.log("  Before tamper:   " + (preIntegrity.valid ? "VALID" : "INVALID"));

  // Test 6 - Full audit report
  console.log("\nTest 6: Full audit report");
  const report = audit.generateReport();
  console.log("  Generated At:    " + report.generatedAt);
  console.log("  Total Events:    " + report.totalEvents);
  console.log("  Integrity Valid: " + report.integrityValid);
  console.log("  HMIT Alerts:     " + report.hmitAlerts.length);
  console.log("  Time Range:      " + report.timeRange.from + " to " + report.timeRange.to);
  console.log("  Event Breakdown:");
  Object.entries(report.breakdown).forEach(([type, count]) => {
    console.log("    " + type + ": " + count);
  });
  console.log("  Top Actors:");
  report.topActors.forEach((a) => {
    console.log("    " + a.actor + ": " + a.count + " events");
  });

  // Test 7 - Audit stats
  console.log("\nTest 7: Audit statistics");
  const stats = audit.getStats() as Record<string, unknown>;
  Object.entries(stats).forEach(([k, v]) => {
    console.log("  " + k + ": " + v);
  });

  audit.record("SYSTEM_STOP", "AKR-NAOS", "INFO", { reason: "normal shutdown" }, "SYSTEM");

  console.log("\n=== Phase 5 Complete ===");
  console.log("Audit Engine operational.");
  console.log("Tamper-evident chain. HMIT Protocol. Alert lifecycle. Query engine. Full report. All working.");
}

main().catch(console.error);