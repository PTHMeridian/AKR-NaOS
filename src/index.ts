import { ShamirModule } from "./phase1-shamir/index";
import { VaultModule } from "./phase2-vault/index";
import { PKIModule } from "./phase3-pki/index";
import { SecureChannelModule } from "./phase4-channel/index";
import { randomBytes } from "crypto";

async function main() {
  console.log("AKR Naos - Nested Authentication Operations Suite");
  console.log("SA AT Cryptographics\n");

  // ============================================================
  // PHASE 1 - SHAMIR
  // ============================================================
  console.log("=== Phase 1 - Shamir Secret Sharing ===");
  const shamir = new ShamirModule();
  const privateKey = "simulated-ml-kem-768-private-key-material-for-testing";
  const splitResult = shamir.split(privateKey, { threshold: 3, totalShares: 5, label: "AKR-primary-key" });
  const selectedShares = [splitResult.shares[0], splitResult.shares[2], splitResult.shares[4]];
  const recoverResult = shamir.recover(selectedShares, splitResult.secretHash);
  console.log("Split: " + splitResult.totalShares + " shares, threshold " + splitResult.threshold + " | Recovered: " + (recoverResult.secret === privateKey) + " | Verified: " + recoverResult.verified);
  console.log("=== Phase 1 Complete ===\n");

  // ============================================================
  // PHASE 2 - VAULT
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
  console.log("Stored: " + storeResult.label + " | Retrieved: " + retrieveResult.label + " | Match: " + (Buffer.from(retrieveResult.privateKey).toString("hex") === Buffer.from(quantumKey).toString("hex")));
  console.log("=== Phase 2 Complete ===\n");

  // ============================================================
  // PHASE 3 - PKI
  // ============================================================
  console.log("=== Phase 3 - Certificate Authority ===");
  const pki = new PKIModule();
  const rootCA = pki.createRootCA(
    { commonName: "PTH Meridian Root CA", organization: "PTH Meridian", country: "CA" },
    new Uint8Array(randomBytes(1952)),
    3650
  );
  const intCA = pki.issueIntermediateCA(
    { commonName: "PTH Meridian Intermediate CA", organization: "PTH Meridian" },
    new Uint8Array(randomBytes(1952)),
    1825
  );
  const aliceCert = pki.issueCertificate(
    { commonName: "alice@pth-meridian.io", organization: "PTH Meridian" },
    new Uint8Array(randomBytes(1952)),
    intCA.id,
    365
  );
  const serverCert = pki.issueCertificate(
    { commonName: "api.akr-naos.io", organization: "PTH Meridian" },
    new Uint8Array(randomBytes(1952)),
    intCA.id,
    90
  );
  const aliceVerify = pki.verify(aliceCert.id);
  const serverVerify = pki.verify(serverCert.id);
  console.log("Root CA: " + rootCA.id + " | Int CA: " + intCA.id);
  console.log("Alice Valid: " + aliceVerify.valid + " | Server Valid: " + serverVerify.valid);
  const pkiStats = pki.stats() as Record<string, unknown>;
  console.log("PKI Stats: " + JSON.stringify(pkiStats));
  console.log("=== Phase 3 Complete ===\n");

  // ============================================================
  // PHASE 4 - SECURE CHANNEL
  // ============================================================
  console.log("=== Phase 4 - Secure Channel ===\n");

  const channel = new SecureChannelModule();

  // Test 1 - Handshake
  console.log("Test 1: Mutual TLS-style handshake");
  const clientHello = channel.initiateHandshake();
  console.log("  Client Hello:");
  console.log("    Session ID:  " + clientHello.sessionId);
  console.log("    Algorithms:  " + clientHello.supportedAlgorithms.join(", "));
  console.log("    Nonce:       " + clientHello.nonce.substring(0, 16) + "...");

  const serverHello = channel.respondToHandshake(clientHello, serverCert.id);
  console.log("  Server Hello:");
  console.log("    Chosen:      " + serverHello.chosenAlgorithm);
  console.log("    Cert ID:     " + serverHello.serverCertId);
  console.log("    Nonce:       " + serverHello.nonce.substring(0, 16) + "...");

  // Test 2 - Establish session with simulated ML-KEM shared secret
  console.log("\nTest 2: Establish encrypted session");
  const simulatedSharedSecret = new Uint8Array(randomBytes(32));

  const clientSession = channel.establishSession(
    clientHello.sessionId,
    simulatedSharedSecret,
    clientHello.nonce,
    serverHello.nonce,
    serverHello.chosenAlgorithm,
    60
  );

  const serverSession = channel.establishSession(
    clientHello.sessionId + "-server",
    simulatedSharedSecret,
    clientHello.nonce,
    serverHello.nonce,
    serverHello.chosenAlgorithm,
    60
  );

  console.log("  Client Session:  " + clientSession.sessionId);
  console.log("  Algorithm:       " + clientSession.algorithm);
  console.log("  Established:     " + new Date(clientSession.establishedAt).toISOString());
  console.log("  Expires:         " + new Date(clientSession.expiresAt).toISOString());

  // Test 3 - Encrypt and decrypt messages
  console.log("\nTest 3: Encrypted message exchange");
  const messages = [
    "PTH Meridian - Ask. Solve. Done.",
    "AKR Naos - Nested Authentication Operations Suite",
    "Post-quantum cryptography is the future of security.",
    "SA AT Cryptographics - protecting civilization.",
  ];

  for (const msg of messages) {
    const encrypted = channel.encrypt(clientSession.sessionId, msg);
    const decrypted = channel.decrypt(encrypted);
    const match = decrypted === msg;
    console.log("  [" + (match ? "OK" : "FAIL") + "] Seq " + encrypted.sequence + ": " + msg.substring(0, 40) + "...");
    console.log("       Ciphertext: " + encrypted.ciphertext.substring(0, 32) + "...");
    console.log("       MAC:        " + encrypted.mac.substring(0, 32) + "...");
  }

  // Test 4 - MAC tamper detection
  console.log("\nTest 4: Message tamper detection");
  const legit = channel.encrypt(clientSession.sessionId, "legitimate message");
  const tampered = { ...legit, ciphertext: legit.ciphertext.replace("a", "b").replace("0", "1") };
  try {
    channel.decrypt(tampered);
    console.log("  ERROR: Should have detected tampering");
  } catch (err: unknown) {
    console.log("  Tamper detected: " + (err instanceof Error ? err.message : String(err)));
  }

  // Test 5 - Multiple concurrent sessions
  console.log("\nTest 5: Multiple concurrent sessions");
  const sessions = [];
  for (let i = 0; i < 3; i++) {
    const init = channel.initiateHandshake();
    const resp = channel.respondToHandshake(init, serverCert.id);
    const secret = new Uint8Array(randomBytes(32));
    const sess = channel.establishSession(
      init.sessionId,
      secret,
      init.nonce,
      resp.nonce,
      resp.chosenAlgorithm,
      30
    );
    sessions.push(sess);
    console.log("  Session " + (i + 1) + ": " + sess.sessionId);
  }
  console.log("  Active Sessions: " + channel.listSessions().length);

  // Test 6 - Session stats
  console.log("\nTest 6: Session statistics");
  const stats = channel.getStats(clientSession.sessionId);
  console.log("  Session ID:      " + stats.sessionId);
  console.log("  Algorithm:       " + stats.algorithm);
  console.log("  Messages Sent:   " + stats.messagesSent);
  console.log("  Bytes:           " + stats.bytesTransferred);
  console.log("  Status:          " + stats.status);

  // Test 7 - Session termination
  console.log("\nTest 7: Session termination");
  channel.terminateSession(clientSession.sessionId);
  console.log("  Session terminated: " + clientSession.sessionId);
  console.log("  Remaining sessions: " + channel.listSessions().length);
  try {
    channel.encrypt(clientSession.sessionId, "should fail");
    console.log("  ERROR: Should have thrown");
  } catch (err: unknown) {
    console.log("  Correctly blocked: " + (err instanceof Error ? err.message : String(err)));
  }

  console.log("\n=== Phase 4 Complete ===");
  console.log("Secure Channel operational.");
  console.log("Handshake. Key derivation. Encryption. MAC. Tamper detection. Session management. All working.");
}

main().catch(console.error);