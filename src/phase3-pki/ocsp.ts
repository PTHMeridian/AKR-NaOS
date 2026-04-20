import { createHash, randomBytes } from "crypto";

export type CertStatus = "good" | "revoked" | "unknown";

export type RevocationReason =
  | "unspecified"
  | "keyCompromise"
  | "cACompromise"
  | "affiliationChanged"
  | "superseded"
  | "cessationOfOperation"
  | "certificateHold"
  | "removeFromCRL"
  | "privilegeWithdrawn"
  | "aACompromise";

export interface OCSPRequest {
  requestId: string;
  certId: string;
  serialNumber: string;
  issuerDN: string;
  nonce?: string;
  requestedAt: number;
  requestor?: string;
}

export interface OCSPResponse {
  requestId: string;
  certId: string;
  serialNumber: string;
  status: CertStatus;
  thisUpdate: string;
  nextUpdate: string;
  revokedAt?: string;
  revocationReason?: RevocationReason;
  nonce?: string;
  responseSignature: string;
  responderId: string;
  cacheHit: boolean;
  responseTime: number;
}

export interface OCSPCacheEntry {
  response: OCSPResponse;
  cachedAt: number;
  expiresAt: number;
}

export interface OCSPStats {
  totalRequests: number;
  cacheHits: number;
  cacheMisses: number;
  goodResponses: number;
  revokedResponses: number;
  unknownResponses: number;
  averageResponseTime: number;
  cacheSize: number;
  uptime: string;
}

export class OCSPResponder {
  private certStatusRegistry: Map<string, {
    status: CertStatus;
    revokedAt?: number;
    reason?: RevocationReason;
    issuerDN: string;
  }> = new Map();

  private cache: Map<string, OCSPCacheEntry> = new Map();
  private readonly cacheTTLMs: number;
  private readonly responderId: string;
  private startedAt: number = Date.now();

  private stats = {
    totalRequests: 0,
    cacheHits: 0,
    cacheMisses: 0,
    goodResponses: 0,
    revokedResponses: 0,
    unknownResponses: 0,
    totalResponseTime: 0,
  };

  constructor(responderId: string, cacheTTLSeconds: number = 300) {
    this.responderId = responderId;
    this.cacheTTLMs = cacheTTLSeconds * 1000;
  }

  registerCertificate(
    serialNumber: string,
    issuerDN: string,
    status: CertStatus = "good"
  ): void {
    this.certStatusRegistry.set(serialNumber, {
      status,
      issuerDN,
    });
    this.invalidateCache(serialNumber);
  }

  revokeCertificate(
    serialNumber: string,
    reason: RevocationReason = "unspecified"
  ): void {
    const entry = this.certStatusRegistry.get(serialNumber);
    if (!entry) throw new Error("Certificate not registered: " + serialNumber);

    this.certStatusRegistry.set(serialNumber, {
      ...entry,
      status: "revoked",
      revokedAt: Date.now(),
      reason,
    });

    this.invalidateCache(serialNumber);
  }

  private invalidateCache(serialNumber: string): void {
    const keysToDelete: string[] = [];
    this.cache.forEach((_, key) => {
      if (key.includes(serialNumber)) keysToDelete.push(key);
    });
    keysToDelete.forEach((k) => this.cache.delete(k));
  }

  private getCacheKey(serialNumber: string, nonce?: string): string {
    return serialNumber + (nonce ? ":" + nonce : "");
  }

  private signResponse(response: Omit<OCSPResponse, "responseSignature">): string {
    const data = JSON.stringify({
      certId: response.certId,
      serialNumber: response.serialNumber,
      status: response.status,
      thisUpdate: response.thisUpdate,
      nextUpdate: response.nextUpdate,
      revokedAt: response.revokedAt,
      nonce: response.nonce,
      responderId: response.responderId,
    });
    return createHash("sha256")
      .update(data + this.responderId)
      .digest("hex");
  }

  query(request: OCSPRequest): OCSPResponse {
    const start = Date.now();
    this.stats.totalRequests++;

    const cacheKey = this.getCacheKey(request.serialNumber, request.nonce);
    const cached = this.cache.get(cacheKey);

    if (cached && Date.now() < cached.expiresAt && !request.nonce) {
      this.stats.cacheHits++;
      const responseTime = Date.now() - start;
      this.stats.totalResponseTime += responseTime;
      return { ...cached.response, cacheHit: true, responseTime };
    }

    this.stats.cacheMisses++;

    const certEntry = this.certStatusRegistry.get(request.serialNumber);
    const now = new Date();
    const nextUpdate = new Date(now.getTime() + this.cacheTTLMs);

    let status: CertStatus = "unknown";
    let revokedAt: string | undefined;
    let revocationReason: RevocationReason | undefined;

    if (certEntry) {
      status = certEntry.status;
      if (certEntry.status === "revoked" && certEntry.revokedAt) {
        revokedAt = new Date(certEntry.revokedAt).toISOString();
        revocationReason = certEntry.reason;
      }
    }

    const partial = {
      requestId: request.requestId,
      certId: request.certId,
      serialNumber: request.serialNumber,
      status,
      thisUpdate: now.toISOString(),
      nextUpdate: nextUpdate.toISOString(),
      revokedAt,
      revocationReason,
      nonce: request.nonce,
      responderId: this.responderId,
      cacheHit: false,
      responseTime: 0,
    };

    const signature = this.signResponse(partial);
    const responseTime = Date.now() - start;
    this.stats.totalResponseTime += responseTime;

    const response: OCSPResponse = {
      ...partial,
      responseSignature: signature,
      responseTime,
    };

    if (status === "good") this.stats.goodResponses++;
    else if (status === "revoked") this.stats.revokedResponses++;
    else this.stats.unknownResponses++;

    if (!request.nonce) {
      this.cache.set(cacheKey, {
        response,
        cachedAt: Date.now(),
        expiresAt: Date.now() + this.cacheTTLMs,
      });
    }

    return response;
  }

  verifyResponse(response: OCSPResponse): boolean {
    const { responseSignature, ...rest } = response;
    const data = JSON.stringify({
      certId: rest.certId,
      serialNumber: rest.serialNumber,
      status: rest.status,
      thisUpdate: rest.thisUpdate,
      nextUpdate: rest.nextUpdate,
      revokedAt: rest.revokedAt,
      nonce: rest.nonce,
      responderId: rest.responderId,
    });
    const expected = createHash("sha256")
      .update(data + this.responderId)
      .digest("hex");
    return expected === responseSignature;
  }

  batchQuery(requests: OCSPRequest[]): OCSPResponse[] {
    return requests.map((r) => this.query(r));
  }

  buildRequest(
    certId: string,
    serialNumber: string,
    issuerDN: string,
    requestor?: string,
    useNonce: boolean = false
  ): OCSPRequest {
    return {
      requestId: "OCSP-REQ-" + Date.now() + "-" + randomBytes(4).toString("hex").toUpperCase(),
      certId,
      serialNumber,
      issuerDN,
      nonce: useNonce ? randomBytes(16).toString("hex") : undefined,
      requestedAt: Date.now(),
      requestor,
    };
  }

  purgExpiredCache(): number {
    let count = 0;
    const now = Date.now();
    this.cache.forEach((entry, key) => {
      if (now > entry.expiresAt) {
        this.cache.delete(key);
        count++;
      }
    });
    return count;
  }

  getStats(): OCSPStats {
    const uptimeMs = Date.now() - this.startedAt;
    const uptimeSecs = Math.floor(uptimeMs / 1000);
    const uptimeMins = Math.floor(uptimeSecs / 60);
    const uptimeHours = Math.floor(uptimeMins / 60);

    return {
      totalRequests: this.stats.totalRequests,
      cacheHits: this.stats.cacheHits,
      cacheMisses: this.stats.cacheMisses,
      goodResponses: this.stats.goodResponses,
      revokedResponses: this.stats.revokedResponses,
      unknownResponses: this.stats.unknownResponses,
      averageResponseTime: this.stats.totalRequests > 0
        ? Math.round(this.stats.totalResponseTime / this.stats.totalRequests)
        : 0,
      cacheSize: this.cache.size,
      uptime: uptimeHours + "h " + (uptimeMins % 60) + "m " + (uptimeSecs % 60) + "s",
    };
  }
}