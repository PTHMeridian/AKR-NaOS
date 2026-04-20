import * as secrets from "secrets.js-grempe";
import { createHash } from "crypto";
import type {
  ShamirShare,
  ShamirSplitResult,
  ShamirRecoverResult,
  ShamirConfig,
} from "../types/index";

export class ShamirModule {

  split(secret: string, config: ShamirConfig): ShamirSplitResult {
    const { threshold, totalShares, label } = config;

    if (threshold < 2) throw new Error("Threshold must be at least 2");
    if (totalShares < threshold) throw new Error("Total shares must be >= threshold");
    if (totalShares > 255) throw new Error("Total shares cannot exceed 255");
    if (!secret || secret.length === 0) throw new Error("Secret cannot be empty");

    const hexSecret = Buffer.from(secret, "utf8").toString("hex");
    const rawShares = secrets.share(hexSecret, totalShares, threshold);

    const shares: ShamirShare[] = rawShares.map((share, index) => ({
      id: index + 1,
      share,
      label: label ? `${label}-${index + 1}` : `share-${index + 1}`,
    }));

    const secretHash = createHash("sha256")
      .update(secret)
      .digest("hex");

    return {
      shares,
      threshold,
      totalShares,
      secretHash,
      algorithm: "Shamir-GF256",
      createdAt: Date.now(),
    };
  }

  splitBytes(secretBytes: Uint8Array, config: ShamirConfig): ShamirSplitResult {
    const hexSecret = Buffer.from(secretBytes).toString("hex");
    return this.split(hexSecret, config);
  }

  recover(shares: ShamirShare[], expectedHash?: string): ShamirRecoverResult {
    if (!shares || shares.length === 0) throw new Error("No shares provided");

    const rawShares = shares.map((s) => s.share);

    let hexSecret: string;
    try {
      hexSecret = secrets.combine(rawShares);
    } catch (err) {
      throw new Error("Failed to combine shares — invalid or insufficient shares");
    }

    const recovered = Buffer.from(hexSecret, "hex").toString("utf8");
    const recoveredHash = createHash("sha256").update(recovered).digest("hex");

    const verified = expectedHash ? recoveredHash === expectedHash : true;

    return {
      secret: recovered,
      verified,
      algorithm: "Shamir-GF256",
      recoveredAt: Date.now(),
    };
  }

  recoverToBytes(shares: ShamirShare[], expectedHash?: string): Uint8Array {
    const result = this.recover(shares, expectedHash);
    return Buffer.from(result.secret, "hex");
  }

  verify(shares: ShamirShare[], secretHash: string): boolean {
    try {
      const result = this.recover(shares, secretHash);
      return result.verified;
    } catch {
      return false;
    }
  }

  distributeShares(
    shares: ShamirShare[],
    destinations: string[]
  ): Map<string, ShamirShare> {
    if (destinations.length !== shares.length) {
      throw new Error("Destinations count must match shares count");
    }
    const distribution = new Map<string, ShamirShare>();
    shares.forEach((share, index) => {
      distribution.set(destinations[index], share);
    });
    return distribution;
  }

  getShareInfo(result: ShamirSplitResult): object {
    return {
      algorithm: result.algorithm,
      threshold: result.threshold,
      totalShares: result.totalShares,
      secretHash: result.secretHash,
      createdAt: new Date(result.createdAt).toISOString(),
      shareIds: result.shares.map((s) => s.id),
      shareLabels: result.shares.map((s) => s.label),
      securityNote: `Any ${result.threshold} of ${result.totalShares} shares required to recover`,
    };
  }
}