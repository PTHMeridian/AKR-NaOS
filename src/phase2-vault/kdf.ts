import * as argon2 from "argon2";
import { randomBytes } from "crypto";

export interface KDFConfig {
  memoryCost: number;
  timeCost: number;
  parallelism: number;
  hashLength: number;
  saltLength: number;
}

export interface DerivedKey {
  key: Buffer;
  salt: Buffer;
  config: KDFConfig;
  algorithm: string;
}

export interface KDFVerifyResult {
  valid: boolean;
  algorithm: string;
  timeTaken: number;
}

export const KDF_PROFILES = {
  INTERACTIVE: {
    memoryCost: 65536,
    timeCost: 3,
    parallelism: 4,
    hashLength: 32,
    saltLength: 32,
  } as KDFConfig,

  MODERATE: {
    memoryCost: 262144,
    timeCost: 4,
    parallelism: 4,
    hashLength: 32,
    saltLength: 32,
  } as KDFConfig,

  SENSITIVE: {
    memoryCost: 1048576,
    timeCost: 5,
    parallelism: 8,
    hashLength: 64,
    saltLength: 32,
  } as KDFConfig,
};

export class KDFModule {

  async deriveKey(
    password: string,
    salt?: Buffer,
    config: KDFConfig = KDF_PROFILES.INTERACTIVE
  ): Promise<DerivedKey> {
    const usedSalt = salt || randomBytes(config.saltLength);

    const raw = await argon2.hash(password, {
      type: argon2.argon2id,
      memoryCost: config.memoryCost,
      timeCost: config.timeCost,
      parallelism: config.parallelism,
      hashLength: config.hashLength,
      salt: usedSalt,
      raw: true,
    });

    return {
      key: Buffer.from(raw),
      salt: usedSalt,
      config,
      algorithm: "Argon2id",
    };
  }

  async deriveKeyForVault(password: string, salt?: Buffer): Promise<DerivedKey> {
    return this.deriveKey(password, salt, KDF_PROFILES.INTERACTIVE);
  }

  async deriveKeyForSensitive(password: string, salt?: Buffer): Promise<DerivedKey> {
    return this.deriveKey(password, salt, KDF_PROFILES.SENSITIVE);
  }

  async verify(
    password: string,
    storedHash: string
  ): Promise<KDFVerifyResult> {
    const start = Date.now();
    const valid = await argon2.verify(storedHash, password);
    const timeTaken = Date.now() - start;

    return {
      valid,
      algorithm: "Argon2id",
      timeTaken,
    };
  }

  async hash(password: string, config: KDFConfig = KDF_PROFILES.INTERACTIVE): Promise<string> {
    return argon2.hash(password, {
      type: argon2.argon2id,
      memoryCost: config.memoryCost,
      timeCost: config.timeCost,
      parallelism: config.parallelism,
      hashLength: config.hashLength,
    });
  }

  serializeConfig(derived: DerivedKey): string {
    return JSON.stringify({
      salt: derived.salt.toString("hex"),
      config: derived.config,
      algorithm: derived.algorithm,
    });
  }

  deserializeConfig(serialized: string): { salt: Buffer; config: KDFConfig; algorithm: string } {
    const parsed = JSON.parse(serialized);
    return {
      salt: Buffer.from(parsed.salt, "hex"),
      config: parsed.config,
      algorithm: parsed.algorithm,
    };
  }

  getSecurityInfo(config: KDFConfig): object {
    const memoryMB = config.memoryCost / 1024;
    const attackCostEstimate = config.memoryCost * config.timeCost * config.parallelism;
    return {
      algorithm: "Argon2id",
      memoryCost: config.memoryCost + " KB (" + memoryMB.toFixed(0) + " MB)",
      timeCost: config.timeCost + " iterations",
      parallelism: config.parallelism + " threads",
      hashLength: config.hashLength + " bytes",
      relativeAttackCost: attackCostEstimate.toLocaleString(),
      resistances: [
        "GPU acceleration",
        "ASIC optimization",
        "Time-memory tradeoff",
        "Rainbow tables",
        "Brute force",
        "Quantum speedup (Grover partial resistance)",
      ],
    };
  }
}