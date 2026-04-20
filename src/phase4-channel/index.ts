import { randomBytes, createHash, createHmac } from "crypto";

export interface HandshakeInit {
  sessionId: string;
  supportedAlgorithms: string[];
  timestamp: number;
  nonce: string;
}

export interface HandshakeResponse {
  sessionId: string;
  chosenAlgorithm: string;
  serverCertId: string;
  timestamp: number;
  nonce: string;
}

export interface SessionKeys {
  encryptKey: Buffer;
  macKey: Buffer;
  sessionId: string;
  algorithm: string;
  establishedAt: number;
  expiresAt: number;
}

export interface SecureMessage {
  sessionId: string;
  ciphertext: string;
  mac: string;
  iv: string;
  sequence: number;
  timestamp: number;
}

export interface ChannelStats {
  sessionId: string;
  algorithm: string;
  establishedAt: string;
  expiresAt: string;
  messagesSent: number;
  messagesReceived: number;
  bytesTransferred: number;
  status: string;
}

export class SecureChannelModule {
  private sessions: Map<string, SessionKeys> = new Map();
  private messageCounters: Map<string, number> = new Map();
  private bytesTransferred: Map<string, number> = new Map();

  private generateSessionId(): string {
    return "SES-" + Date.now() + "-" + randomBytes(8).toString("hex").toUpperCase();
  }

  private deriveSessionKeys(
    sharedSecret: Uint8Array,
    nonce1: string,
    nonce2: string
  ): { encryptKey: Buffer; macKey: Buffer } {
    const material = Buffer.concat([
      Buffer.from(sharedSecret),
      Buffer.from(nonce1, "hex"),
      Buffer.from(nonce2, "hex"),
    ]);

    const master = createHash("sha512").update(material).digest();
    const encryptKey = master.slice(0, 32);
    const macKey = master.slice(32, 64);

    return { encryptKey, macKey };
  }

  private xorEncrypt(data: Buffer, key: Buffer, iv: Buffer): Buffer {
    let keyStream = createHash("sha256")
      .update(Buffer.concat([key, iv]))
      .digest();
    const result = Buffer.alloc(data.length);

    for (let i = 0; i < data.length; i++) {
      if (i > 0 && i % 32 === 0) {
        keyStream = createHash("sha256")
          .update(Buffer.concat([keyStream, Buffer.from([i >> 8]), Buffer.from([i & 0xff])]))
          .digest();
      }
      result[i] = data[i] ^ keyStream[i % 32];
    }
    return result;
  }

  initiateHandshake(): HandshakeInit {
    const sessionId = this.generateSessionId();
    const nonce = randomBytes(32).toString("hex");

    return {
      sessionId,
      supportedAlgorithms: [
        "ML-KEM-768+ML-DSA-65",
        "ML-KEM-512+ML-DSA-44",
        "HYBRID-ECDH-MLKEM768+ECDSA-ML-DSA",
      ],
      timestamp: Date.now(),
      nonce,
    };
  }

  respondToHandshake(
    init: HandshakeInit,
    serverCertId: string
  ): HandshakeResponse {
    const preferred = "ML-KEM-768+ML-DSA-65";
    const chosen = init.supportedAlgorithms.includes(preferred)
      ? preferred
      : init.supportedAlgorithms[0];

    return {
      sessionId: init.sessionId,
      chosenAlgorithm: chosen,
      serverCertId,
      timestamp: Date.now(),
      nonce: randomBytes(32).toString("hex"),
    };
  }

  establishSession(
    sessionId: string,
    sharedSecret: Uint8Array,
    clientNonce: string,
    serverNonce: string,
    algorithm: string,
    sessionMinutes: number = 60
  ): SessionKeys {
    const { encryptKey, macKey } = this.deriveSessionKeys(
      sharedSecret,
      clientNonce,
      serverNonce
    );

    const now = Date.now();
    const session: SessionKeys = {
      encryptKey,
      macKey,
      sessionId,
      algorithm,
      establishedAt: now,
      expiresAt: now + sessionMinutes * 60 * 1000,
    };

    this.sessions.set(sessionId, session);
    this.messageCounters.set(sessionId, 0);
    this.bytesTransferred.set(sessionId, 0);

    return session;
  }

  encrypt(sessionId: string, plaintext: string): SecureMessage {
    const session = this.sessions.get(sessionId);
    if (!session) throw new Error("Session not found: " + sessionId);
    if (Date.now() > session.expiresAt) {
      this.sessions.delete(sessionId);
      throw new Error("Session expired: " + sessionId);
    }

    const sequence = (this.messageCounters.get(sessionId) || 0) + 1;
    this.messageCounters.set(sessionId, sequence);

    const iv = randomBytes(16);
    const data = Buffer.from(plaintext, "utf8");
    const ciphertext = this.xorEncrypt(data, session.encryptKey, iv);

    const macData = Buffer.concat([
      Buffer.from(sessionId),
      iv,
      ciphertext,
      Buffer.from(String(sequence)),
    ]);
    const mac = createHmac("sha256", session.macKey)
      .update(macData)
      .digest("hex");

    const bytes = (this.bytesTransferred.get(sessionId) || 0) + data.length;
    this.bytesTransferred.set(sessionId, bytes);

    return {
      sessionId,
      ciphertext: ciphertext.toString("hex"),
      mac,
      iv: iv.toString("hex"),
      sequence,
      timestamp: Date.now(),
    };
  }

  decrypt(msg: SecureMessage): string {
    const session = this.sessions.get(msg.sessionId);
    if (!session) throw new Error("Session not found: " + msg.sessionId);
    if (Date.now() > session.expiresAt) {
      this.sessions.delete(msg.sessionId);
      throw new Error("Session expired: " + msg.sessionId);
    }

    const iv = Buffer.from(msg.iv, "hex");
    const ciphertext = Buffer.from(msg.ciphertext, "hex");

    const macData = Buffer.concat([
      Buffer.from(msg.sessionId),
      iv,
      ciphertext,
      Buffer.from(String(msg.sequence)),
    ]);
    const expectedMac = createHmac("sha256", session.macKey)
      .update(macData)
      .digest("hex");

    if (expectedMac !== msg.mac) {
      throw new Error("MAC verification failed — message tampered or corrupted");
    }

    const plaintext = this.xorEncrypt(ciphertext, session.encryptKey, iv);
    return plaintext.toString("utf8");
  }

  terminateSession(sessionId: string): void {
    if (!this.sessions.has(sessionId)) {
      throw new Error("Session not found: " + sessionId);
    }
    this.sessions.delete(sessionId);
    this.messageCounters.delete(sessionId);
    this.bytesTransferred.delete(sessionId);
  }

  getStats(sessionId: string): ChannelStats {
    const session = this.sessions.get(sessionId);
    if (!session) throw new Error("Session not found: " + sessionId);

    const expired = Date.now() > session.expiresAt;

    return {
      sessionId,
      algorithm: session.algorithm,
      establishedAt: new Date(session.establishedAt).toISOString(),
      expiresAt: new Date(session.expiresAt).toISOString(),
      messagesSent: this.messageCounters.get(sessionId) || 0,
      messagesReceived: this.messageCounters.get(sessionId) || 0,
      bytesTransferred: this.bytesTransferred.get(sessionId) || 0,
      status: expired ? "expired" : "active",
    };
  }

  listSessions(): string[] {
    return Array.from(this.sessions.keys());
  }
}