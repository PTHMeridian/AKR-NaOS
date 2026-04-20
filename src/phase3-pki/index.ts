import { randomBytes, createHash } from "crypto";

export interface CertificateSubject {
  commonName: string;
  organization?: string;
  organizationalUnit?: string;
  country?: string;
  state?: string;
  locality?: string;
  email?: string;
}

export interface CertificateInfo {
  id: string;
  serialNumber: string;
  subject: CertificateSubject;
  issuer: CertificateSubject;
  publicKey: string;
  algorithm: string;
  isCA: boolean;
  validFrom: string;
  validTo: string;
  issuedAt: number;
  fingerprint: string;
  status: "valid" | "revoked" | "expired";
  revokedAt?: number;
  revokeReason?: string;
  parentId?: string;
}

export interface IssueCertResult {
  id: string;
  serialNumber: string;
  subject: CertificateSubject;
  issuer: CertificateSubject;
  algorithm: string;
  isCA: boolean;
  validFrom: string;
  validTo: string;
  fingerprint: string;
  status: string;
}

export interface VerifyCertResult {
  valid: boolean;
  subject: CertificateSubject;
  issuer: CertificateSubject;
  algorithm: string;
  validFrom: string;
  validTo: string;
  fingerprint: string;
  status: string;
  checks: {
    notExpired: boolean;
    notRevoked: boolean;
    issuerKnown: boolean;
    signatureAlgorithmValid: boolean;
  };
}

export interface CRLEntry {
  serialNumber: string;
  revokedAt: number;
  reason: string;
}

export class PKIModule {
  private certs: Map<string, CertificateInfo> = new Map();
  private crl: Map<string, CRLEntry> = new Map();
  private rootId: string | null = null;

  private generateSerial(): string {
    return randomBytes(16).toString("hex").toUpperCase();
  }

  private generateId(): string {
    return "CERT-" + Date.now() + "-" + randomBytes(4).toString("hex").toUpperCase();
  }

  private generateFingerprint(
    subject: CertificateSubject,
    publicKey: string,
    serial: string
  ): string {
    return createHash("sha256")
      .update(JSON.stringify(subject) + publicKey + serial)
      .digest("hex")
      .toUpperCase()
      .match(/.{2}/g)!
      .join(":");
  }

  private formatSubject(subject: CertificateSubject): string {
    const parts = [];
    if (subject.country) parts.push("C=" + subject.country);
    if (subject.state) parts.push("ST=" + subject.state);
    if (subject.locality) parts.push("L=" + subject.locality);
    if (subject.organization) parts.push("O=" + subject.organization);
    if (subject.organizationalUnit) parts.push("OU=" + subject.organizationalUnit);
    parts.push("CN=" + subject.commonName);
    if (subject.email) parts.push("E=" + subject.email);
    return parts.join(", ");
  }

  createRootCA(
    subject: CertificateSubject,
    publicKey: Uint8Array,
    validityDays: number = 3650
  ): IssueCertResult {
    if (this.rootId) throw new Error("Root CA already exists");

    const id = this.generateId();
    const serial = this.generateSerial();
    const now = Date.now();
    const fingerprint = this.generateFingerprint(
      subject,
      Buffer.from(publicKey).toString("hex"),
      serial
    );

    const cert: CertificateInfo = {
      id,
      serialNumber: serial,
      subject,
      issuer: subject,
      publicKey: Buffer.from(publicKey).toString("hex"),
      algorithm: "ML-DSA-65",
      isCA: true,
      validFrom: new Date(now).toISOString(),
      validTo: new Date(now + validityDays * 86400000).toISOString(),
      issuedAt: now,
      fingerprint,
      status: "valid",
    };

    this.certs.set(id, cert);
    this.rootId = id;

    console.log("  Root CA created: " + this.formatSubject(subject));

    return {
      id,
      serialNumber: serial,
      subject,
      issuer: subject,
      algorithm: cert.algorithm,
      isCA: true,
      validFrom: cert.validFrom,
      validTo: cert.validTo,
      fingerprint,
      status: "valid",
    };
  }

  issueIntermediateCA(
    subject: CertificateSubject,
    publicKey: Uint8Array,
    validityDays: number = 1825
  ): IssueCertResult {
    if (!this.rootId) throw new Error("Root CA must exist before issuing intermediate CA");

    const root = this.certs.get(this.rootId)!;
    if (root.status !== "valid") throw new Error("Root CA is not valid");

    const id = this.generateId();
    const serial = this.generateSerial();
    const now = Date.now();
    const fingerprint = this.generateFingerprint(
      subject,
      Buffer.from(publicKey).toString("hex"),
      serial
    );

    const cert: CertificateInfo = {
      id,
      serialNumber: serial,
      subject,
      issuer: root.subject,
      publicKey: Buffer.from(publicKey).toString("hex"),
      algorithm: "ML-DSA-65",
      isCA: true,
      validFrom: new Date(now).toISOString(),
      validTo: new Date(now + validityDays * 86400000).toISOString(),
      issuedAt: now,
      fingerprint,
      status: "valid",
      parentId: this.rootId,
    };

    this.certs.set(id, cert);
    console.log("  Intermediate CA issued: " + this.formatSubject(subject));

    return {
      id,
      serialNumber: serial,
      subject,
      issuer: root.subject,
      algorithm: cert.algorithm,
      isCA: true,
      validFrom: cert.validFrom,
      validTo: cert.validTo,
      fingerprint,
      status: "valid",
    };
  }

  issueCertificate(
    subject: CertificateSubject,
    publicKey: Uint8Array,
    issuerId: string,
    validityDays: number = 365
  ): IssueCertResult {
    const issuerCert = this.certs.get(issuerId);
    if (!issuerCert) throw new Error("Issuer certificate not found: " + issuerId);
    if (!issuerCert.isCA) throw new Error("Issuer is not a CA");
    if (issuerCert.status !== "valid") throw new Error("Issuer certificate is not valid");

    const id = this.generateId();
    const serial = this.generateSerial();
    const now = Date.now();
    const fingerprint = this.generateFingerprint(
      subject,
      Buffer.from(publicKey).toString("hex"),
      serial
    );

    const cert: CertificateInfo = {
      id,
      serialNumber: serial,
      subject,
      issuer: issuerCert.subject,
      publicKey: Buffer.from(publicKey).toString("hex"),
      algorithm: "ML-DSA-65",
      isCA: false,
      validFrom: new Date(now).toISOString(),
      validTo: new Date(now + validityDays * 86400000).toISOString(),
      issuedAt: now,
      fingerprint,
      status: "valid",
      parentId: issuerId,
    };

    this.certs.set(id, cert);
    return {
      id,
      serialNumber: serial,
      subject,
      issuer: issuerCert.subject,
      algorithm: cert.algorithm,
      isCA: false,
      validFrom: cert.validFrom,
      validTo: cert.validTo,
      fingerprint,
      status: "valid",
    };
  }

  verify(id: string): VerifyCertResult {
    const cert = this.certs.get(id);
    if (!cert) throw new Error("Certificate not found: " + id);

    const now = Date.now();
    const notExpired = now < new Date(cert.validTo).getTime();
    const notRevoked = !this.crl.has(cert.serialNumber);
    const issuerKnown = cert.isCA && !cert.parentId
      ? true
      : cert.parentId
      ? this.certs.has(cert.parentId)
      : false;
    const signatureAlgorithmValid = cert.algorithm === "ML-DSA-65";

    if (!notExpired) cert.status = "expired";

    return {
      valid: notExpired && notRevoked && issuerKnown && signatureAlgorithmValid,
      subject: cert.subject,
      issuer: cert.issuer,
      algorithm: cert.algorithm,
      validFrom: cert.validFrom,
      validTo: cert.validTo,
      fingerprint: cert.fingerprint,
      status: cert.status,
      checks: {
        notExpired,
        notRevoked,
        issuerKnown,
        signatureAlgorithmValid,
      },
    };
  }

  revoke(id: string, reason: string = "unspecified"): void {
    const cert = this.certs.get(id);
    if (!cert) throw new Error("Certificate not found: " + id);
    if (cert.status === "revoked") throw new Error("Certificate already revoked");

    cert.status = "revoked";
    cert.revokedAt = Date.now();
    cert.revokeReason = reason;

    this.crl.set(cert.serialNumber, {
      serialNumber: cert.serialNumber,
      revokedAt: Date.now(),
      reason,
    });
  }

  getChain(id: string): CertificateInfo[] {
    const chain: CertificateInfo[] = [];
    let current = this.certs.get(id);
    while (current) {
      chain.push(current);
      current = current.parentId ? this.certs.get(current.parentId) : undefined;
    }
    return chain;
  }

  getCRL(): CRLEntry[] {
    return Array.from(this.crl.values());
  }

  list(): Omit<CertificateInfo, "publicKey">[] {
    return Array.from(this.certs.values()).map(({ publicKey, ...safe }) => safe);
  }

  stats(): object {
    const certs = this.list();
    return {
      total: certs.length,
      valid: certs.filter((c) => c.status === "valid").length,
      revoked: certs.filter((c) => c.status === "revoked").length,
      expired: certs.filter((c) => c.status === "expired").length,
      cas: certs.filter((c) => c.isCA).length,
      endEntities: certs.filter((c) => !c.isCA).length,
      crlEntries: this.crl.size,
      algorithm: "ML-DSA-65",
    };
  }
}