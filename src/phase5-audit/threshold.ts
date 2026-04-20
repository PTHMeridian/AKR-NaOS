import { createHash, createHmac, randomBytes } from "crypto";

export interface ThresholdParticipant {
  id: string;
  label: string;
  publicShare: string;
  createdAt: number;
}

export interface ThresholdSession {
  sessionId: string;
  operation: string;
  message: string;
  messageHash: string;
  threshold: number;
  totalParticipants: number;
  participants: ThresholdParticipant[];
  partialSignatures: Map<string, PartialSignature>;
  status: "pending" | "collecting" | "complete" | "failed" | "expired";
  createdAt: number;
  expiresAt: number;
  completedAt?: number;
  finalSignature?: string;
  initiator: string;
}

export interface PartialSignature {
  participantId: string;
  label: string;
  partial: string;
  timestamp: number;
  verified: boolean;
}

export interface ThresholdKeyShare {
  participantId: string;
  label: string;
  share: string;
  publicShare: string;
  threshold: number;
  totalParticipants: number;
  groupPublicKey: string;
  createdAt: number;
}

export interface ThresholdSignResult {
  sessionId: string;
  operation: string;
  message: string;
  signature: string;
  signers: string[];
  threshold: number;
  totalParticipants: number;
  completedAt: string;
  valid: boolean;
}

export interface ThresholdVerifyResult {
  valid: boolean;
  sessionId: string;
  signers: string[];
  threshold: number;
  operation: string;
  verifiedAt: string;
}

export class ThresholdSignatureModule {
  private keyShares: Map<string, ThresholdKeyShare[]> = new Map();
  private sessions: Map<string, ThresholdSession> = new Map();
  private readonly sessionTTLMs: number;

  constructor(sessionTTLMinutes: number = 30) {
    this.sessionTTLMs = sessionTTLMinutes * 60 * 1000;
  }

  private generateId(prefix: string): string {
    return prefix + "-" + Date.now() + "-" + randomBytes(6).toString("hex").toUpperCase();
  }

  private hashMessage(message: string): string {
    return createHash("sha256").update(message).digest("hex");
  }

  private computePartialSignature(
    share: string,
    messageHash: string,
    participantId: string
  ): string {
    return createHmac("sha256", Buffer.from(share, "hex"))
      .update(messageHash + participantId)
      .digest("hex");
  }

  private combinePartialSignatures(
    partials: PartialSignature[],
    messageHash: string,
    groupPublicKey: string
  ): string {
    const sorted = [...partials].sort((a, b) =>
      a.participantId.localeCompare(b.participantId)
    );

    const combined = sorted.reduce((acc, partial) => {
      const contribution = createHash("sha256")
        .update(acc + partial.partial + partial.participantId)
        .digest("hex");
      return contribution;
    }, messageHash);

    return createHash("sha256")
      .update(combined + groupPublicKey)
      .digest("hex");
  }

  generateKeyShares(
    groupLabel: string,
    threshold: number,
    participants: Array<{ id: string; label: string }>,
    algorithm: string = "ML-DSA-65"
  ): ThresholdKeyShare[] {
    if (threshold < 2) throw new Error("Threshold must be at least 2");
    if (threshold > participants.length) {
      throw new Error("Threshold cannot exceed participant count");
    }
    if (participants.length > 255) {
      throw new Error("Maximum 255 participants supported");
    }

    const groupSecret = randomBytes(32).toString("hex");
    const groupPublicKey = createHash("sha256")
      .update(groupSecret + groupLabel + algorithm)
      .digest("hex");

    const shares: ThresholdKeyShare[] = participants.map((participant, index) => {
      const share = createHash("sha256")
        .update(groupSecret + participant.id + index.toString())
        .digest("hex");

      const publicShare = createHash("sha256")
        .update(share + participant.id)
        .digest("hex");

      return {
        participantId: participant.id,
        label: participant.label,
        share,
        publicShare,
        threshold,
        totalParticipants: participants.length,
        groupPublicKey,
        createdAt: Date.now(),
      };
    });

    this.keyShares.set(groupLabel, shares);
    return shares;
  }

  initiateSession(
    groupLabel: string,
    operation: string,
    message: string,
    initiator: string
  ): ThresholdSession {
    const shares = this.keyShares.get(groupLabel);
    if (!shares) throw new Error("Key shares not found for group: " + groupLabel);

    const sessionId = this.generateId("TSIG");
    const messageHash = this.hashMessage(message);

    const session: ThresholdSession = {
      sessionId,
      operation,
      message,
      messageHash,
      threshold: shares[0].threshold,
      totalParticipants: shares[0].totalParticipants,
      participants: shares.map((s) => ({
        id: s.participantId,
        label: s.label,
        publicShare: s.publicShare,
        createdAt: s.createdAt,
      })),
      partialSignatures: new Map(),
      status: "collecting",
      createdAt: Date.now(),
      expiresAt: Date.now() + this.sessionTTLMs,
      initiator,
    };

    this.sessions.set(sessionId, session);
    return session;
  }

  contributeSignature(
    sessionId: string,
    participantId: string,
    share: ThresholdKeyShare
  ): PartialSignature {
    const session = this.sessions.get(sessionId);
    if (!session) throw new Error("Session not found: " + sessionId);
    if (session.status === "complete") throw new Error("Session already complete");
    if (session.status === "expired" || Date.now() > session.expiresAt) {
      session.status = "expired";
      throw new Error("Session has expired: " + sessionId);
    }

    const isParticipant = session.participants.some((p) => p.id === participantId);
    if (!isParticipant) {
      throw new Error("Participant not authorized for this session: " + participantId);
    }

    if (session.partialSignatures.has(participantId)) {
      throw new Error("Participant has already signed: " + participantId);
    }

    if (share.participantId !== participantId) {
      throw new Error("Key share does not belong to participant: " + participantId);
    }

    const partial = this.computePartialSignature(
      share.share,
      session.messageHash,
      participantId
    );

    const partialSig: PartialSignature = {
      participantId,
      label: share.label,
      partial,
      timestamp: Date.now(),
      verified: true,
    };

    session.partialSignatures.set(participantId, partialSig);

    if (session.partialSignatures.size >= session.threshold) {
      this.finalizeSession(session);
    }

    return partialSig;
  }

  private finalizeSession(session: ThresholdSession): void {
    const shares = this.keyShares.get(
      Array.from(this.keyShares.entries()).find(([, shares]) =>
        shares.some((s) => s.totalParticipants === session.totalParticipants)
      )?.[0] || ""
    );

    const groupPublicKey = shares?.[0]?.groupPublicKey || "unknown";
    const partials = Array.from(session.partialSignatures.values());
    const finalSig = this.combinePartialSignatures(
      partials,
      session.messageHash,
      groupPublicKey
    );

    session.finalSignature = finalSig;
    session.status = "complete";
    session.completedAt = Date.now();
  }

  getSessionStatus(sessionId: string): {
    status: string;
    signaturesCollected: number;
    threshold: number;
    signers: string[];
    remaining: string[];
  } {
    const session = this.sessions.get(sessionId);
    if (!session) throw new Error("Session not found: " + sessionId);

    if (Date.now() > session.expiresAt && session.status !== "complete") {
      session.status = "expired";
    }

    const signers = Array.from(session.partialSignatures.keys());
    const remaining = session.participants
      .filter((p) => !signers.includes(p.id))
      .map((p) => p.label);

    return {
      status: session.status,
      signaturesCollected: session.partialSignatures.size,
      threshold: session.threshold,
      signers: Array.from(session.partialSignatures.values()).map((s) => s.label),
      remaining,
    };
  }

  finalizeSignature(sessionId: string): ThresholdSignResult {
    const session = this.sessions.get(sessionId);
    if (!session) throw new Error("Session not found: " + sessionId);
    if (session.status !== "complete") {
      throw new Error(
        "Session not complete — " +
        session.partialSignatures.size +
        " of " +
        session.threshold +
        " signatures collected"
      );
    }

    return {
      sessionId: session.sessionId,
      operation: session.operation,
      message: session.message,
      signature: session.finalSignature!,
      signers: Array.from(session.partialSignatures.values()).map((s) => s.label),
      threshold: session.threshold,
      totalParticipants: session.totalParticipants,
      completedAt: new Date(session.completedAt!).toISOString(),
      valid: true,
    };
  }

  verify(result: ThresholdSignResult, groupLabel: string): ThresholdVerifyResult {
    const shares = this.keyShares.get(groupLabel);
    if (!shares) throw new Error("Key shares not found: " + groupLabel);

    const session = this.sessions.get(result.sessionId);
    if (!session) throw new Error("Session not found: " + result.sessionId);

    const groupPublicKey = shares[0].groupPublicKey;
    const partials = Array.from(session.partialSignatures.values());
    const recomputed = this.combinePartialSignatures(
      partials,
      session.messageHash,
      groupPublicKey
    );

    const valid = recomputed === result.signature &&
      result.signers.length >= result.threshold;

    return {
      valid,
      sessionId: result.sessionId,
      signers: result.signers,
      threshold: result.threshold,
      operation: result.operation,
      verifiedAt: new Date().toISOString(),
    };
  }

  listSessions(): Array<{
    sessionId: string;
    operation: string;
    status: string;
    signaturesCollected: number;
    threshold: number;
    initiator: string;
    createdAt: string;
  }> {
    return Array.from(this.sessions.values()).map((s) => ({
      sessionId: s.sessionId,
      operation: s.operation,
      status: s.status,
      signaturesCollected: s.partialSignatures.size,
      threshold: s.threshold,
      initiator: s.initiator,
      createdAt: new Date(s.createdAt).toISOString(),
    }));
  }

  getStats(): object {
    const sessions = Array.from(this.sessions.values());
    const groups = Array.from(this.keyShares.keys());
    return {
      totalGroups: groups.length,
      groupLabels: groups,
      totalSessions: sessions.length,
      completeSessions: sessions.filter((s) => s.status === "complete").length,
      pendingSessions: sessions.filter((s) => s.status === "collecting").length,
      expiredSessions: sessions.filter((s) => s.status === "expired").length,
      totalParticipants: Array.from(this.keyShares.values())
        .reduce((sum, shares) => sum + shares.length, 0),
    };
  }
}