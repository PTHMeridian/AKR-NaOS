import { randomBytes, createHash, timingSafeEqual } from "crypto";
import { ShamirModule } from "../phase1-shamir/index";
import type { ShamirConfig } from "../types/index";

export interface VaultEntry {
  id: string;
  label: string;
  algorithm: string;
  mode: string;
  encryptedKey: string;
  iv: string;
  salt: string;
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

  private generateId(): string {
    return "VLT-" + Date.now() + "-" + randomBytes(4).toString("hex").toUpperCase();
  }

  private deriveKey(password: string, salt: Buffer): Buffer {
    let key = Buffer.concat([Buffer.from(password), salt]);
    for (let i = 0; i < 100000; i++) {
      key = createHash("sha256").update(key).digest();
    }
    return key;
  }

  private encrypt(data: string, password: string): { encrypted: string; iv: string; salt: string } {
    const salt = randomBytes(32);
    const key = this.deriveKey(password, salt);
    const iv = randomBytes(12);
    const dataBuffer = Buffer.from(data, "utf8");
    const encrypted = Buffer.alloc(dataBuffer.length);
    
    let keyStream = createHash("sha256").update(Buffer.concat([key, iv])).digest();
    for (let i = 0; i < dataBuffer.length; i++) {
      if (i % 32 === 0 && i > 0) {
        keyStream = createHash("sha256").update(Buffer.concat([keyStream, Buffer.from([i])])).digest();
      }
      encrypted[i] = dataBuffer[i] ^ keyStream[i % 32];
    }

    return {
      encrypted: encrypted.toString("hex"),
      iv: iv.toString("hex"),
      salt: salt.toString("hex"),
    };
  }

  private decrypt(encryptedHex: string, password: string, ivHex: string, saltHex: string): string {
    const salt = Buffer.from(saltHex, "hex");
    const key = this.deriveKey(password, salt);
    const iv = Buffer.from(ivHex, "hex");
    const encrypted = Buffer.from(encryptedHex, "hex");
    const decrypted = Buffer.alloc(encrypted.length);

    let keyStream = createHash("sha256").update(Buffer.concat([key, iv])).digest();
    for (let i = 0; i < encrypted.length; i++) {
      if (i % 32 === 0 && i > 0) {
        keyStream = createHash("sha256").update(Buffer.concat([keyStream, Buffer.from([i])])).digest();
      }
      decrypted[i] = encrypted[i] ^ keyStream[i % 32];
    }

    return decrypted.toString("utf8");
  }

  store(
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
    }
  ): VaultStoreResult {
    const id = this.generateId();
    const keyHex = Buffer.from(privateKey).toString("hex");
    const { encrypted, iv, salt } = this.encrypt(keyHex, password);

    const entry: VaultEntry = {
      id,
      label: options.label,
      algorithm: options.algorithm,
      mode: options.mode,
      encryptedKey: encrypted,
      iv,
      salt,
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
    };

    if (options.shamirConfig) {
      const splitResult = this.shamir.split(keyHex, options.shamirConfig);
      result.shamirShares = splitResult.shares.map((s) => s.share.substring(0, 16) + "...");
      entry.metadata["shamirHash"] = splitResult.secretHash;
      entry.metadata["shamirThreshold"] = String(options.shamirConfig.threshold);
      entry.metadata["shamirTotal"] = String(options.shamirConfig.totalShares);
    }

    return result;
  }

  retrieve(id: string, password: string): VaultRetrieveResult {
    const entry = this.vault.get(id);
    if (!entry) throw new Error(`Key not found: ${id}`);
    if (entry.status === "revoked") throw new Error(`Key has been revoked: ${id}`);

    if (entry.expiresAt && Date.now() > entry.expiresAt) {
      entry.status = "expired";
      throw new Error(`Key has expired: ${id}`);
    }

    const keyHex = this.decrypt(entry.encryptedKey, password, entry.iv, entry.salt);
    const privateKey = new Uint8Array(Buffer.from(keyHex, "hex"));

    return {
      id: entry.id,
      label: entry.label,
      privateKey,
      algorithm: entry.algorithm,
      mode: entry.mode,
      status: entry.status,
    };
  }

  rotate(
    id: string,
    oldPassword: string,
    newPrivateKey: Uint8Array,
    newPassword: string
  ): VaultRotateResult {
    const oldEntry = this.vault.get(id);
    if (!oldEntry) throw new Error(`Key not found: ${id}`);
    if (oldEntry.status === "revoked") throw new Error(`Cannot rotate revoked key: ${id}`);

    this.retrieve(id, oldPassword);

    oldEntry.status = "rotated";
    oldEntry.rotatedAt = Date.now();

    const newResult = this.store(newPrivateKey, newPassword, {
      label: oldEntry.label + "-rotated",
      algorithm: oldEntry.algorithm,
      mode: oldEntry.mode,
      metadata: {
        ...oldEntry.metadata,
        previousId: id,
        rotatedFrom: id,
      },
    });

    return {
      oldId: id,
      newId: newResult.id,
      label: oldEntry.label,
      rotatedAt: new Date().toISOString(),
      status: "rotated",
    };
  }

  revoke(id: string, password: string, reason?: string): void {
    const entry = this.vault.get(id);
    if (!entry) throw new Error(`Key not found: ${id}`);

    this.retrieve(id, password);

    entry.status = "revoked";
    entry.revokedAt = Date.now();
    entry.metadata["revokeReason"] = reason || "manually revoked";
  }

  list(): Omit<VaultEntry, "encryptedKey" | "iv" | "salt">[] {
    return Array.from(this.vault.values()).map(({ encryptedKey, iv, salt, ...safe }) => safe);
  }

  getStatus(id: string): string {
    const entry = this.vault.get(id);
    if (!entry) throw new Error(`Key not found: ${id}`);
    if (entry.expiresAt && Date.now() > entry.expiresAt) return "expired";
    return entry.status;
  }

  getExpiring(withinDays: number): Omit<VaultEntry, "encryptedKey" | "iv" | "salt">[] {
    const cutoff = Date.now() + withinDays * 24 * 60 * 60 * 1000;
    return this.list().filter(
      (e) => e.expiresAt && e.expiresAt <= cutoff && e.status === "active"
    );
  }

  purgeRevoked(): number {
    let count = 0;
    this.vault.forEach((entry, id) => {
      if (entry.status === "revoked") {
        this.vault.delete(id);
        count++;
      }
    });
    return count;
  }

  stats(): object {
    const entries = this.list();
    return {
      total: entries.length,
      active: entries.filter((e) => e.status === "active").length,
      rotated: entries.filter((e) => e.status === "rotated").length,
      revoked: entries.filter((e) => e.status === "revoked").length,
      expired: entries.filter((e) => e.status === "expired").length,
      algorithms: [...new Set(entries.map((e) => e.algorithm))],
      modes: [...new Set(entries.map((e) => e.mode))],
    };
  }
}