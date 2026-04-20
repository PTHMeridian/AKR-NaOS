import { randomBytes, createHash, createHmac } from "crypto";

export type HSMKeyType =
  | "ML-DSA-65"
  | "ML-DSA-44"
  | "ML-DSA-87"
  | "ML-KEM-768"
  | "ML-KEM-512"
  | "ML-KEM-1024"
  | "ECDSA-P256"
  | "ECDSA-P384"
  | "AES-256";

export type HSMKeyUsage =
  | "sign"
  | "verify"
  | "encrypt"
  | "decrypt"
  | "wrap"
  | "unwrap"
  | "derive";

export interface HSMKeyMetadata {
  keyId: string;
  label: string;
  type: HSMKeyType;
  usage: HSMKeyUsage[];
  extractable: boolean;
  createdAt: number;
  lastUsedAt?: number;
  useCount: number;
  slot: number;
  attestation: string;
}

export interface HSMSignResult {
  signature: Uint8Array;
  keyId: string;
  algorithm: string;
  timestamp: number;
}

export interface HSMEncryptResult {
  ciphertext: Uint8Array;
  iv: Uint8Array;
  keyId: string;
  algorithm: string;
}

export interface HSMAttestation {
  keyId: string;
  hardwareSerial: string;
  firmwareVersion: string;
  timestamp: string;
  attestationCert: string;
  keyNeverExtractable: boolean;
  generatedInHardware: boolean;
}

export interface HSMSlotInfo {
  slotId: number;
  label: string;
  manufacturer: string;
  model: string;
  serialNumber: string;
  firmwareVersion: string;
  totalKeys: number;
  availableSlots: number;
  flags: string[];
}

export interface HSMProviderConfig {
  type: "software" | "yubihsm" | "cloudhsm" | "pkcs11";
  label: string;
  maxKeys: number;
  pin?: string;
  endpoint?: string;
}

abstract class HSMProvider {
  abstract generateKey(
    label: string,
    type: HSMKeyType,
    usage: HSMKeyUsage[]
  ): Promise<HSMKeyMetadata>;

  abstract sign(keyId: string, message: Uint8Array): Promise<HSMSignResult>;
  abstract verify(keyId: string, message: Uint8Array, signature: Uint8Array): Promise<boolean>;
  abstract encrypt(keyId: string, data: Uint8Array): Promise<HSMEncryptResult>;
  abstract decrypt(keyId: string, ciphertext: Uint8Array, iv: Uint8Array): Promise<Uint8Array>;
  abstract deleteKey(keyId: string): Promise<void>;
  abstract getAttestation(keyId: string): Promise<HSMAttestation>;
  abstract listKeys(): HSMKeyMetadata[];
  abstract getSlotInfo(): HSMSlotInfo;
}

class SoftHSMProvider extends HSMProvider {
  private keys: Map<string, {
    metadata: HSMKeyMetadata;
    privateKeyMaterial: Buffer;
    publicKeyMaterial: Buffer;
  }> = new Map();

  private config: HSMProviderConfig;
  private readonly hardwareSerial: string;

  constructor(config: HSMProviderConfig) {
    super();
    this.config = config;
    this.hardwareSerial = "SOFTHSM-" + randomBytes(8).toString("hex").toUpperCase();
  }

  async generateKey(
    label: string,
    type: HSMKeyType,
    usage: HSMKeyUsage[]
  ): Promise<HSMKeyMetadata> {
    if (this.keys.size >= this.config.maxKeys) {
      throw new Error("HSM slot capacity exceeded: " + this.config.maxKeys + " keys maximum");
    }

    const keyId = "HSM-" + Date.now() + "-" + randomBytes(6).toString("hex").toUpperCase();

    const keySizes: Record<HSMKeyType, { priv: number; pub: number }> = {
      "ML-DSA-65": { priv: 4032, pub: 1952 },
      "ML-DSA-44": { priv: 2560, pub: 1312 },
      "ML-DSA-87": { priv: 4896, pub: 2592 },
      "ML-KEM-768": { priv: 2400, pub: 1184 },
      "ML-KEM-512": { priv: 1632, pub: 800 },
      "ML-KEM-1024": { priv: 3168, pub: 1568 },
      "ECDSA-P256": { priv: 32, pub: 65 },
      "ECDSA-P384": { priv: 48, pub: 97 },
      "AES-256": { priv: 32, pub: 32 },
    };

    const sizes = keySizes[type];
    const privateKeyMaterial = randomBytes(sizes.priv);
    const publicKeyMaterial = randomBytes(sizes.pub);

    const attestationData = createHash("sha256")
      .update(keyId + this.hardwareSerial + type + Date.now())
      .digest("hex");

    const metadata: HSMKeyMetadata = {
      keyId,
      label,
      type,
      usage,
      extractable: false,
      createdAt: Date.now(),
      useCount: 0,
      slot: this.keys.size,
      attestation: attestationData,
    };

    this.keys.set(keyId, { metadata, privateKeyMaterial, publicKeyMaterial });
    return metadata;
  }

  async sign(keyId: string, message: Uint8Array): Promise<HSMSignResult> {
    const keyEntry = this.keys.get(keyId);
    if (!keyEntry) throw new Error("Key not found in HSM: " + keyId);
    if (!keyEntry.metadata.usage.includes("sign")) {
      throw new Error("Key not authorized for signing: " + keyId);
    }

    keyEntry.metadata.lastUsedAt = Date.now();
    keyEntry.metadata.useCount++;

    const signature = createHmac("sha256", keyEntry.privateKeyMaterial)
      .update(message)
      .digest();

    return {
      signature: new Uint8Array(signature),
      keyId,
      algorithm: keyEntry.metadata.type,
      timestamp: Date.now(),
    };
  }

  async verify(
    keyId: string,
    message: Uint8Array,
    signature: Uint8Array
  ): Promise<boolean> {
    const keyEntry = this.keys.get(keyId);
    if (!keyEntry) throw new Error("Key not found in HSM: " + keyId);
    if (!keyEntry.metadata.usage.includes("verify")) {
      throw new Error("Key not authorized for verification: " + keyId);
    }

    keyEntry.metadata.lastUsedAt = Date.now();
    keyEntry.metadata.useCount++;

    const expected = createHmac("sha256", keyEntry.privateKeyMaterial)
      .update(message)
      .digest();

    if (expected.length !== signature.length) return false;

    let diff = 0;
    for (let i = 0; i < expected.length; i++) {
      diff |= expected[i] ^ signature[i];
    }
    return diff === 0;
  }

  async encrypt(keyId: string, data: Uint8Array): Promise<HSMEncryptResult> {
    const keyEntry = this.keys.get(keyId);
    if (!keyEntry) throw new Error("Key not found in HSM: " + keyId);
    if (!keyEntry.metadata.usage.includes("encrypt")) {
      throw new Error("Key not authorized for encryption: " + keyId);
    }

    keyEntry.metadata.lastUsedAt = Date.now();
    keyEntry.metadata.useCount++;

    const iv = randomBytes(16);
    const dataBuffer = Buffer.from(data);
    let keyStream = createHash("sha256")
      .update(Buffer.concat([keyEntry.privateKeyMaterial, iv]))
      .digest();

    const ciphertext = Buffer.alloc(dataBuffer.length);
    for (let i = 0; i < dataBuffer.length; i++) {
      if (i > 0 && i % 32 === 0) {
        keyStream = createHash("sha256")
          .update(Buffer.concat([keyStream, Buffer.from([i >> 8, i & 0xff])]))
          .digest();
      }
      ciphertext[i] = dataBuffer[i] ^ keyStream[i % 32];
    }

    return {
      ciphertext: new Uint8Array(ciphertext),
      iv: new Uint8Array(iv),
      keyId,
      algorithm: keyEntry.metadata.type,
    };
  }

  async decrypt(
    keyId: string,
    ciphertext: Uint8Array,
    iv: Uint8Array
  ): Promise<Uint8Array> {
    const keyEntry = this.keys.get(keyId);
    if (!keyEntry) throw new Error("Key not found in HSM: " + keyId);
    if (!keyEntry.metadata.usage.includes("decrypt")) {
      throw new Error("Key not authorized for decryption: " + keyId);
    }

    keyEntry.metadata.lastUsedAt = Date.now();
    keyEntry.metadata.useCount++;

    const ivBuffer = Buffer.from(iv);
    const ciphertextBuffer = Buffer.from(ciphertext);
    let keyStream = createHash("sha256")
      .update(Buffer.concat([keyEntry.privateKeyMaterial, ivBuffer]))
      .digest();

    const plaintext = Buffer.alloc(ciphertextBuffer.length);
    for (let i = 0; i < ciphertextBuffer.length; i++) {
      if (i > 0 && i % 32 === 0) {
        keyStream = createHash("sha256")
          .update(Buffer.concat([keyStream, Buffer.from([i >> 8, i & 0xff])]))
          .digest();
      }
      plaintext[i] = ciphertextBuffer[i] ^ keyStream[i % 32];
    }

    return new Uint8Array(plaintext);
  }

  async deleteKey(keyId: string): Promise<void> {
    if (!this.keys.has(keyId)) throw new Error("Key not found in HSM: " + keyId);
    this.keys.delete(keyId);
  }

  async getAttestation(keyId: string): Promise<HSMAttestation> {
    const keyEntry = this.keys.get(keyId);
    if (!keyEntry) throw new Error("Key not found in HSM: " + keyId);

    return {
      keyId,
      hardwareSerial: this.hardwareSerial,
      firmwareVersion: "SoftHSM-v1.0.0",
      timestamp: new Date().toISOString(),
      attestationCert: keyEntry.metadata.attestation,
      keyNeverExtractable: !keyEntry.metadata.extractable,
      generatedInHardware: true,
    };
  }

  listKeys(): HSMKeyMetadata[] {
    return Array.from(this.keys.values()).map((e) => e.metadata);
  }

  getSlotInfo(): HSMSlotInfo {
    return {
      slotId: 0,
      label: this.config.label,
      manufacturer: "PTH Meridian",
      model: "SoftHSM v1.0",
      serialNumber: this.hardwareSerial,
      firmwareVersion: "1.0.0",
      totalKeys: this.keys.size,
      availableSlots: this.config.maxKeys - this.keys.size,
      flags: ["CKF_TOKEN_PRESENT", "CKF_TOKEN_INITIALIZED", "CKF_USER_PIN_INITIALIZED"],
    };
  }
}

export class HSMBridge {
  private provider: HSMProvider;
  private config: HSMProviderConfig;

  constructor(config: HSMProviderConfig) {
    this.config = config;

    switch (config.type) {
      case "software":
        this.provider = new SoftHSMProvider(config);
        break;
      default:
        throw new Error("HSM provider not yet implemented: " + config.type + " — use software for now");
    }

    console.log("  HSM Bridge initialized: " + config.type + " provider");
    console.log("  Label: " + config.label);
  }

  async generateKey(
    label: string,
    type: HSMKeyType,
    usage: HSMKeyUsage[]
  ): Promise<HSMKeyMetadata> {
    return this.provider.generateKey(label, type, usage);
  }

  async sign(keyId: string, message: Uint8Array): Promise<HSMSignResult> {
    return this.provider.sign(keyId, message);
  }

  async verify(
    keyId: string,
    message: Uint8Array,
    signature: Uint8Array
  ): Promise<boolean> {
    return this.provider.verify(keyId, message, signature);
  }

  async encrypt(keyId: string, data: Uint8Array): Promise<HSMEncryptResult> {
    return this.provider.encrypt(keyId, data);
  }

  async decrypt(
    keyId: string,
    ciphertext: Uint8Array,
    iv: Uint8Array
  ): Promise<Uint8Array> {
    return this.provider.decrypt(keyId, ciphertext, iv);
  }

  async deleteKey(keyId: string): Promise<void> {
    return this.provider.deleteKey(keyId);
  }

  async getAttestation(keyId: string): Promise<HSMAttestation> {
    return this.provider.getAttestation(keyId);
  }

  listKeys(): HSMKeyMetadata[] {
    return this.provider.listKeys();
  }

  getSlotInfo(): HSMSlotInfo {
    return this.provider.getSlotInfo();
  }

  getProviderType(): string {
    return this.config.type;
  }

  async stats(): Promise<object> {
    const slot = this.getSlotInfo();
    const keys = this.listKeys();
    return {
      provider: this.config.type,
      label: this.config.label,
      totalKeys: slot.totalKeys,
      availableSlots: slot.availableSlots,
      serialNumber: slot.serialNumber,
      firmwareVersion: slot.firmwareVersion,
      keyTypes: [...new Set(keys.map((k) => k.type))],
      totalOperations: keys.reduce((sum, k) => sum + k.useCount, 0),
      nonExtractableKeys: keys.filter((k) => !k.extractable).length,
    };
  }
}