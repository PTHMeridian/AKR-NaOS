import { randomBytes, createHash, createHmac } from "crypto";
import { KDFModule } from "./kdf";
import { ShamirModule } from "../phase1-shamir/index";
import type { ShamirConfig } from "../types/index";

export interface VaultEntry {
  id: string;
  label: string;
  algorithm: string;
  mode: string;
  encryptedKey: string;
  iv: string;
  mac: string;
  kdfSalt: string;
  kdfConfig: string;
  publicKey?: string;
  createdAt: number;
  expiresAt?: number;
  rotatedAt?: number;
  revokedAt?: number;
  status: "active" | "rotated" | "revoked" | "expired";
  metadata: Record<string, string>;
}

export interface VaultStoreResult {
  id: string;
  label: string;
  status: string;
  createdAt: string;
  expiresAt?: string;
  kdfAlgorithm: string;
  shamirShares?: string[];
}

export interface VaultRetrieveResult {
  id: string;
  label: string;
  privateKey: Uint8Array;
  algorithm: string;
  mode: string;
  status: string;
}

export interface VaultRotateResult {
  oldId: string;
  newId: string;
  label: string;
  rotatedAt: string;
  status: string;
}

export class VaultModule {
  private vault: Map<string, VaultEntry> = new Map();
  private shamir: ShamirModule = new ShamirModule();
  private kdf: KDFModule = new KDFModule();

  private generateId(): string {
    return "VLT-" + Date.now() + "-" + randomBytes(4).toString("hex").toUpperCase();
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

  private computeMAC(encryptedKey: Buffer, iv: Buffer, id: string, macKey: Buffer): string {
    return createHmac("sha256", macKey)
      .update(Buffer.concat([encryptedKey, iv, Buffer.from(id)]))
      .digest("hex");
  }

  async store(
    privateKey: Uint8Array,
    password: string,
    options: {
      label: string;
      algorithm: string;
      mode: string;
      publicKey?: Uint8Array;
      expiryDays?: number;
      metadata?: Record<string, string>;
      shamirConfig?: ShamirConfig;
      sensitive?: boolean;
    }
  ): Promise<VaultStoreResult> {
    const id = this.generateId();

    const derived = options.sensitive
      ? await this.kdf.deriveKeyForSensitive(password)
      : await this.kdf.deriveKeyForVault(password);

    const encKey = derived.key.slice(0, 16);
    const macKey = derived.key.slice(16, 32);

    const iv = randomBytes(16);
    const keyData = Buffer.from(privateKey);
    const encrypted = this.xorEncrypt(keyData, encKey, iv);
    const mac = this.computeMAC(encrypted, iv, id, macKey);

    const entry: VaultEntry = {
      id,
      label: options.label,
      algorithm: options.algorithm,
      mode: options.mode,
      encryptedKey: encrypted.toString("hex"),
      iv: iv.toString("hex"),
      mac,
      kdfSalt: derived.salt.toString("hex"),
      kdfConfig: this.kdf.serializeConfig(derived),
      publicKey: options.publicKey
        ? Buffer.from(options.publicKey).toString("hex")
        : undefined,
      createdAt: Date.now(),
      expiresAt: options.expiryDays
        ? Date.now() + options.expiryDays * 24 * 60 * 60 * 1000
        : undefined,
      status: "active",
      metadata: options.metadata || {},
    };

    this.vault.set(id, entry);

    const result: VaultStoreResult = {
      id,
      label: options.label,
      status: "active",
      createdAt: new Date(entry.createdAt).toISOString(),
      expiresAt: entry.expiresAt
        ? new Date(entry.expiresAt).toISOString()
        : undefined,
      kdfAlgorithm: "Argon2id",
    };

    if (options.shamirConfig) {
      const keyHex = Buffer.from(privateKey).toString("hex");
      const splitResult = this.shamir.split(keyHex, options.shamirConfig);
      result.shamirShares = splitResult.shares.map((s) => s.share.substring(0, 16) + "...");
      entry.metadata["shamirHash"] = splitResult.secretHash;
      entry.metadata["shamirThreshold"] = String(options.shamirConfig.threshold);
      entry.metadata["shamirTotal"] = String(options.shamirConfig.totalShares);
    }

    return result;
  }

  async retrieve(id: string, password: string): Promise<VaultRetrieveResult> {
    const entry = this.vault.get(id);
    if (!entry) throw new Error("Key not found: " + id);
    if (entry.status === "revoked") throw new Error("Key has been revoked: " + id);
    if (entry.expiresAt && Date.now() > entry.expiresAt) {
      entry.status = "expired";
      throw new Error("Key has expired: " + id);
    }

    const { salt, config } = this.kdf.deserializeConfig(entry.kdfConfig);
    const derived = await this.kdf.deriveKey(password, salt, config);

    const encKey = derived.key.slice(0, 16);
    const macKey = derived.key.slice(16, 32);

    const iv = Buffer.from(entry.iv, "hex");
    const encrypted = Buffer.from(entry.encryptedKey, "hex");

    const expectedMAC = this.computeMAC(encrypted, iv, id, macKey);
    if (expectedMAC !== entry.mac) {
      throw new Error("Authentication failed — invalid password or corrupted vault entry");
    }

    const decrypted = this.xorEncrypt(encrypted, encKey, iv);

    return {
      id: entry.id,
      label: entry.label,
      privateKey: new Uint8Array(decrypted),
      algorithm: entry.algorithm,
      mode: entry.mode,
      status: entry.status,
    };
  }

  async rotate(
    id: string,
    oldPassword: string,
    newPrivateKey: Uint8Array,
    newPassword: string
  ): Promise<VaultRotateResult> {
    const oldEntry = this.vault.get(id);
    if (!oldEntry) throw new Error("Key not found: " + id);
    if (oldEntry.status === "revoked") throw new Error("Cannot rotate revoked key: " + id);

    await this.retrieve(id, oldPassword);
    oldEntry.status = "rotated";
    oldEntry.rotatedAt = Date.now();

    const newResult = await this.store(newPrivateKey, newPassword, {
      label: oldEntry.label + "-rotated",
      algorithm: oldEntry.algorithm,
      mode: oldEntry.mode,
      metadata: { ...oldEntry.metadata, previousId: id },
    });

    return {
      oldId: id,
      newId: newResult.id,
      label: oldEntry.label,
      rotatedAt: new Date().toISOString(),
      status: "rotated",
    };
  }

  async revoke(id: string, password: string, reason?: string): Promise<void> {
    const entry = this.vault.get(id);
    if (!entry) throw new Error("Key not found: " + id);
    await this.retrieve(id, password);
    entry.status = "revoked";
    entry.revokedAt = Date.now();
    entry.metadata["revokeReason"] = reason || "manually revoked";
  }

  list(): Omit<VaultEntry, "encryptedKey" | "iv" | "mac" | "kdfSalt" | "kdfConfig">[] {
    return Array.from(this.vault.values()).map(
      ({ encryptedKey, iv, mac, kdfSalt, kdfConfig, ...safe }) => safe
    );
  }

  getStatus(id: string): string {
    const entry = this.vault.get(id);
    if (!entry) throw new Error("Key not found: " + id);
    if (entry.expiresAt && Date.now() > entry.expiresAt) return "expired";
    return entry.status;
  }

  getExpiring(withinDays: number): Omit<VaultEntry, "encryptedKey" | "iv" | "mac" | "kdfSalt" | "kdfConfig">[] {
    const cutoff = Date.now() + withinDays * 24 * 60 * 60 * 1000;
    return this.list().filter(
      (e) => e.expiresAt && e.expiresAt <= cutoff && e.status === "active"
    );
  }

  stats(): object {
    const entries = this.list();
    return {
      total: entries.length,
      active: entries.filter((e) => e.status === "active").length,
      rotated: entries.filter((e) => e.status === "rotated").length,
      revoked: entries.filter((e) => e.status === "revoked").length,
      expired: entries.filter((e) => e.status === "expired").length,
      kdfAlgorithm: "Argon2id",
      algorithms: [...new Set(entries.map((e) => e.algorithm))],
      modes: [...new Set(entries.map((e) => e.mode))],
    };
  }
}