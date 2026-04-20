import { createHash, randomBytes } from "crypto";

export type AuditEventType =
  | "KEY_GENERATED"
  | "KEY_STORED"
  | "KEY_RETRIEVED"
  | "KEY_ROTATED"
  | "KEY_REVOKED"
  | "KEY_EXPIRED"
  | "SECRET_SPLIT"
  | "SECRET_RECOVERED"
  | "CERT_ISSUED"
  | "CERT_REVOKED"
  | "CERT_VERIFIED"
  | "SESSION_ESTABLISHED"
  | "SESSION_TERMINATED"
  | "MESSAGE_ENCRYPTED"
  | "MESSAGE_DECRYPTED"
  | "TAMPER_DETECTED"
  | "AUTH_SUCCESS"
  | "AUTH_FAILURE"
  | "ANOMALY_DETECTED"
  | "HMIT_ALERT"
  | "SYSTEM_START"
  | "SYSTEM_STOP";

export type AuditSeverity = "INFO" | "WARN" | "ALERT" | "CRITICAL";

export interface AuditEvent {
  id: string;
  sequence: number;
  type: AuditEventType;
  severity: AuditSeverity;
  timestamp: number;
  actor: string;
  target?: string;
  details: Record<string, unknown>;
  previousHash: string;
  hash: string;
  hmitFlag: boolean;
}

export interface AuditQuery {
  type?: AuditEventType;
  severity?: AuditSeverity;
  actor?: string;
  fromTime?: number;
  toTime?: number;
  hmitOnly?: boolean;
  limit?: number;
}

export interface AuditReport {
  generatedAt: string;
  totalEvents: number;
  integrityValid: boolean;
  breakdown: Record<string, number>;
  hmitAlerts: AuditEvent[];
  anomalies: AuditEvent[];
  topActors: Array<{ actor: string; count: number }>;
  timeRange: { from: string; to: string };
}

export interface HMITAlert {
  alertId: string;
  triggeredAt: string;
  severity: AuditSeverity;
  reason: string;
  relatedEvents: string[];
  recommended: string;
  status: "open" | "acknowledged" | "resolved";
}

export class AuditModule {
  private log: AuditEvent[] = [];
  private hmitAlerts: Map<string, HMITAlert> = new Map();
  private authFailures: Map<string, number> = new Map();
  private readonly HMIT_AUTH_FAILURE_THRESHOLD = 3;
  private readonly HMIT_RAPID_KEY_THRESHOLD = 10;

  private generateId(): string {
    return "AUD-" + Date.now() + "-" + randomBytes(4).toString("hex").toUpperCase();
  }

  private computeHash(event: Omit<AuditEvent, "hash">): string {
    const data = JSON.stringify({
      id: event.id,
      sequence: event.sequence,
      type: event.type,
      severity: event.severity,
      timestamp: event.timestamp,
      actor: event.actor,
      target: event.target,
      details: event.details,
      previousHash: event.previousHash,
    });
    return createHash("sha256").update(data).digest("hex");
  }

  private getPreviousHash(): string {
    if (this.log.length === 0) return "0".repeat(64);
    return this.log[this.log.length - 1].hash;
  }

  private checkAnomalies(event: AuditEvent): void {
    if (event.type === "AUTH_FAILURE") {
      const actor = event.actor;
      const failures = (this.authFailures.get(actor) || 0) + 1;
      this.authFailures.set(actor, failures);

      if (failures >= this.HMIT_AUTH_FAILURE_THRESHOLD) {
        this.triggerHMIT(
          "CRITICAL",
          "Repeated authentication failures detected for actor: " + actor,
          [event.id],
          "Investigate and consider revoking credentials for: " + actor
        );
        this.authFailures.set(actor, 0);
      }
    }

    const recentKeyEvents = this.log
      .filter(
        (e) =>
          e.type === "KEY_GENERATED" &&
          e.actor === event.actor &&
          Date.now() - e.timestamp < 60000
      );

    if (recentKeyEvents.length >= this.HMIT_RAPID_KEY_THRESHOLD) {
      this.triggerHMIT(
        "ALERT",
        "Rapid key generation detected — possible automated attack",
        recentKeyEvents.map((e) => e.id),
        "Review key generation patterns for actor: " + event.actor
      );
    }
  }

  private triggerHMIT(
    severity: AuditSeverity,
    reason: string,
    relatedEvents: string[],
    recommended: string
  ): HMITAlert {
    const alertId = "HMIT-" + Date.now() + "-" + randomBytes(4).toString("hex").toUpperCase();

    const alert: HMITAlert = {
      alertId,
      triggeredAt: new Date().toISOString(),
      severity,
      reason,
      relatedEvents,
      recommended,
      status: "open",
    };

    this.hmitAlerts.set(alertId, alert);

    this.record(
      "HMIT_ALERT",
      "HMIT-PROTOCOL",
      severity,
      { alertId, reason, recommended },
      "HMIT-ENGINE"
    );

    return alert;
  }

  record(
    type: AuditEventType,
    target: string,
    severity: AuditSeverity,
    details: Record<string, unknown>,
    actor: string = "SYSTEM"
  ): AuditEvent {
    const id = this.generateId();
    const sequence = this.log.length + 1;
    const previousHash = this.getPreviousHash();

    const hmitFlag =
      severity === "CRITICAL" ||
      severity === "ALERT" ||
      type === "TAMPER_DETECTED" ||
      type === "AUTH_FAILURE" ||
      type === "ANOMALY_DETECTED" ||
      type === "HMIT_ALERT" ||
      type === "KEY_REVOKED" ||
      type === "CERT_REVOKED";

    const partial: Omit<AuditEvent, "hash"> = {
      id,
      sequence,
      type,
      severity,
      timestamp: Date.now(),
      actor,
      target,
      details,
      previousHash,
      hmitFlag,
    };

    const hash = this.computeHash(partial);
    const event: AuditEvent = { ...partial, hash };

    this.log.push(event);
    this.checkAnomalies(event);

    return event;
  }

  verifyIntegrity(): { valid: boolean; firstInvalid?: number; totalChecked: number } {
    let previousHash = "0".repeat(64);

    for (let i = 0; i < this.log.length; i++) {
      const event = this.log[i];

      if (event.previousHash !== previousHash) {
        return { valid: false, firstInvalid: i, totalChecked: i + 1 };
      }

      const recomputed = this.computeHash({
        id: event.id,
        sequence: event.sequence,
        type: event.type,
        severity: event.severity,
        timestamp: event.timestamp,
        actor: event.actor,
        target: event.target,
        details: event.details,
        previousHash: event.previousHash,
        hmitFlag: event.hmitFlag,
      });

      if (recomputed !== event.hash) {
        return { valid: false, firstInvalid: i, totalChecked: i + 1 };
      }

      previousHash = event.hash;
    }

    return { valid: true, totalChecked: this.log.length };
  }

  query(params: AuditQuery): AuditEvent[] {
    let results = [...this.log];

    if (params.type) results = results.filter((e) => e.type === params.type);
    if (params.severity) results = results.filter((e) => e.severity === params.severity);
    if (params.actor) results = results.filter((e) => e.actor === params.actor);
    if (params.fromTime) results = results.filter((e) => e.timestamp >= params.fromTime!);
    if (params.toTime) results = results.filter((e) => e.timestamp <= params.toTime!);
    if (params.hmitOnly) results = results.filter((e) => e.hmitFlag);
    if (params.limit) results = results.slice(-params.limit);

    return results;
  }

  generateReport(): AuditReport {
    const events = this.log;
    const integrity = this.verifyIntegrity();

    const breakdown: Record<string, number> = {};
    const actorCount: Record<string, number> = {};

    events.forEach((e) => {
      breakdown[e.type] = (breakdown[e.type] || 0) + 1;
      actorCount[e.actor] = (actorCount[e.actor] || 0) + 1;
    });

    const topActors = Object.entries(actorCount)
      .map(([actor, count]) => ({ actor, count }))
      .sort((a, b) => b.count - a.count)
      .slice(0, 5);

    const hmitAlerts = events.filter((e) => e.type === "HMIT_ALERT");
    const anomalies = events.filter((e) => e.type === "ANOMALY_DETECTED");

    const times = events.map((e) => e.timestamp);

    return {
      generatedAt: new Date().toISOString(),
      totalEvents: events.length,
      integrityValid: integrity.valid,
      breakdown,
      hmitAlerts,
      anomalies,
      topActors,
      timeRange: {
        from: times.length ? new Date(Math.min(...times)).toISOString() : "N/A",
        to: times.length ? new Date(Math.max(...times)).toISOString() : "N/A",
      },
    };
  }

  getHMITAlerts(status?: "open" | "acknowledged" | "resolved"): HMITAlert[] {
    const alerts = Array.from(this.hmitAlerts.values());
    return status ? alerts.filter((a) => a.status === status) : alerts;
  }

  acknowledgeHMIT(alertId: string): void {
    const alert = this.hmitAlerts.get(alertId);
    if (!alert) throw new Error("HMIT alert not found: " + alertId);
    alert.status = "acknowledged";
  }

  resolveHMIT(alertId: string): void {
    const alert = this.hmitAlerts.get(alertId);
    if (!alert) throw new Error("HMIT alert not found: " + alertId);
    alert.status = "resolved";
  }

  getStats(): object {
    const integrity = this.verifyIntegrity();
    return {
      totalEvents: this.log.length,
      hmitFlags: this.log.filter((e) => e.hmitFlag).length,
      openAlerts: this.getHMITAlerts("open").length,
      integrityValid: integrity.valid,
      chainLength: this.log.length,
      firstEntry: this.log.length ? new Date(this.log[0].timestamp).toISOString() : "N/A",
      lastEntry: this.log.length ? new Date(this.log[this.log.length - 1].timestamp).toISOString() : "N/A",
    };
  }
}