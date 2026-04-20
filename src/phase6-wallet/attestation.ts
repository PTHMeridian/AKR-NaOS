import { createHash, createHmac, randomBytes } from "crypto";

export type AttestationLevel =
  | "NONE"
  | "SOFTWARE"
  | "HSM_SIMULATED"
  | "HSM_HARDWARE"
  | "FIPS_140_2_L2"
  | "FIPS_140_2_L3"
  | "FIPS_140_3_L3"
  | "COMMON_CRITERIA_EAL4";

export interface AttestationCertificate {
  certId: string;
  subject: string;
  issuer: string;
  serialNumber: string;
  validFrom: string;
  validTo: string;
  publicKey: string;
  signature: string;
  level: AttestationLevel;
}

export interface KeyAttestationStatement {
  statementId: string;
  keyId: string;
  keyLabel: string;
  keyType: string;
  keyUsage: string[];
  hardwareSerial: string;
  firmwareVersion: string;
  generatedAt: string;
  neverExtractable: boolean;
  generatedInHardware: boolean;
  attestationLevel: AttestationLevel;
  securityProperties: string[];
  certChain: AttestationCertificate[];
  rootFingerprint: string;
  statementSignature: string;
  verifiable: boolean;
}

export interface AttestationVerifyResult {
  valid: boolean;
  keyId: string;
  attestationLevel: AttestationLevel;
  hardwareSerial: string;
  firmwareVersion: string;
  neverExtractable: boolean;
  generatedInHardware: boolean;
  certChainValid: boolean;
  rootTrusted: boolean;
  securityProperties: string[];
  verifiedAt: string;
  findings: string[];
}

export interface AttestationPolicy {
  minimumLevel: AttestationLevel;
  requireNeverExtractable: boolean;
  requireHardwareGeneration: boolean;
  trustedRoots: string[];
  maxKeyAgeDays?: number;
  allowedKeyTypes: string[];
}

const LEVEL_ORDER: AttestationLevel[] = [
  "NONE",
  "SOFTWARE",
  "HSM_SIMULATED",
  "HSM_HARDWARE",
  "FIPS_140_2_L2",
  "FIPS_140_2_L3",
  "FIPS_140_3_L3",
  "COMMON_CRITERIA_EAL4",
];

export class AttestationModule {
  private statements: Map<string, KeyAttestationStatement> = new Map();
  private trustedRoots: Map<string, AttestationCertificate> = new Map();
  private manufacturerKey: string;
  private rootKey: string;
  private rootCert: AttestationCertificate;
  private manufacturerCert: AttestationCertificate;

  constructor() {
    this.rootKey = randomBytes(32).toString("hex");
    this.manufacturerKey = randomBytes(32).toString("hex");

    this.rootCert = this.createCert(
      "PTH-ATTEST-ROOT-CA",
      "PTH Meridian Attestation Root CA",
      "PTH Meridian Attestation Root CA",
      this.rootKey,
      this.rootKey,
      "FIPS_140_3_L3",
      3650
    );

    this.manufacturerCert = this.createCert(
      "PTH-ATTEST-MFR-CA",
      "PTH Meridian Device Manufacturer CA",
      "PTH Meridian Attestation Root CA",
      this.manufacturerKey,
      this.rootKey,
      "FIPS_140_3_L3",
      1825
    );

    this.trustedRoots.set(this.rootCert.certId, this.rootCert);
  }

  private createCert(
    certId: string,
    subject: string,
    issuer: string,
    subjectKey: string,
    signingKey: string,
    level: AttestationLevel,
    validityDays: number
  ): AttestationCertificate {
    const serial = randomBytes(16).toString("hex").toUpperCase();
    const now = new Date();
    const expiry = new Date(now.getTime() + validityDays * 86400000);

    const publicKey = createHash("sha256")
      .update(subjectKey + subject)
      .digest("hex");

    const toSign = subject + issuer + serial + publicKey;
    const signature = createHmac("sha256", Buffer.from(signingKey, "hex"))
      .update(toSign)
      .digest("hex");

    return {
      certId,
      subject,
      issuer,
      serialNumber: serial,
      validFrom: now.toISOString(),
      validTo: expiry.toISOString(),
      publicKey,
      signature,
      level,
    };
  }

  private createDeviceCert(
    hardwareSerial: string,
    firmwareVersion: string
  ): AttestationCertificate {
    const deviceKey = createHash("sha256")
      .update(hardwareSerial + firmwareVersion + this.manufacturerKey)
      .digest("hex");

    return this.createCert(
      "PTH-DEVICE-" + hardwareSerial,
      "PTH Meridian HSM " + hardwareSerial,
      "PTH Meridian Device Manufacturer CA",
      deviceKey,
      this.manufacturerKey,
      "HSM_SIMULATED",
      365
    );
  }

  private signStatement(statement: Omit<KeyAttestationStatement, "statementSignature">): string {
    const data = JSON.stringify({
      keyId: statement.keyId,
      keyType: statement.keyType,
      hardwareSerial: statement.hardwareSerial,
      firmwareVersion: statement.firmwareVersion,
      generatedAt: statement.generatedAt,
      neverExtractable: statement.neverExtractable,
      rootFingerprint: statement.rootFingerprint,
    });

    return createHmac("sha256", Buffer.from(this.rootKey, "hex"))
      .update(data)
      .digest("hex");
  }

  generateAttestation(
    keyId: string,
    keyLabel: string,
    keyType: string,
    keyUsage: string[],
    hardwareSerial: string,
    firmwareVersion: string,
    neverExtractable: boolean,
    generatedInHardware: boolean,
    level: AttestationLevel = "HSM_SIMULATED"
  ): KeyAttestationStatement {
    const statementId = "ATT-" + Date.now() + "-" + randomBytes(6).toString("hex").toUpperCase();

    const deviceCert = this.createDeviceCert(hardwareSerial, firmwareVersion);

    const certChain: AttestationCertificate[] = [
      deviceCert,
      this.manufacturerCert,
      this.rootCert,
    ];

    const rootFingerprint = createHash("sha256")
      .update(this.rootCert.publicKey + this.rootCert.subject)
      .digest("hex");

    const securityProperties: string[] = [];
    if (neverExtractable) securityProperties.push("KEY_NEVER_EXTRACTABLE");
    if (generatedInHardware) securityProperties.push("GENERATED_IN_HARDWARE");
    if (level !== "NONE" && level !== "SOFTWARE") securityProperties.push("HARDWARE_PROTECTION");
    if (level === "FIPS_140_2_L2" || level === "FIPS_140_2_L3" || level === "FIPS_140_3_L3") {
      securityProperties.push("FIPS_VALIDATED");
    }
    if (level === "COMMON_CRITERIA_EAL4") securityProperties.push("COMMON_CRITERIA_EAL4");
    securityProperties.push("TAMPER_EVIDENT");
    securityProperties.push("AUDIT_LOGGED");

    const partial: Omit<KeyAttestationStatement, "statementSignature"> = {
      statementId,
      keyId,
      keyLabel,
      keyType,
      keyUsage,
      hardwareSerial,
      firmwareVersion,
      generatedAt: new Date().toISOString(),
      neverExtractable,
      generatedInHardware,
      attestationLevel: level,
      securityProperties,
      certChain,
      rootFingerprint,
      verifiable: true,
    };

    const signature = this.signStatement(partial);
    const statement: KeyAttestationStatement = { ...partial, statementSignature: signature };

    this.statements.set(keyId, statement);
    return statement;
  }

  verify(
    statement: KeyAttestationStatement,
    policy: AttestationPolicy
  ): AttestationVerifyResult {
    const findings: string[] = [];
    let valid = true;

    const recomputed = this.signStatement({
      statementId: statement.statementId,
      keyId: statement.keyId,
      keyLabel: statement.keyLabel,
      keyType: statement.keyType,
      keyUsage: statement.keyUsage,
      hardwareSerial: statement.hardwareSerial,
      firmwareVersion: statement.firmwareVersion,
      generatedAt: statement.generatedAt,
      neverExtractable: statement.neverExtractable,
      generatedInHardware: statement.generatedInHardware,
      attestationLevel: statement.attestationLevel,
      securityProperties: statement.securityProperties,
      certChain: statement.certChain,
      rootFingerprint: statement.rootFingerprint,
      verifiable: statement.verifiable,
    });

    const signatureValid = recomputed === statement.statementSignature;
    if (!signatureValid) {
      findings.push("FAIL: Statement signature invalid — attestation tampered");
      valid = false;
    } else {
      findings.push("PASS: Statement signature valid");
    }

    const certChainValid = this.verifyCertChain(statement.certChain);
    if (!certChainValid) {
      findings.push("FAIL: Certificate chain invalid");
      valid = false;
    } else {
      findings.push("PASS: Certificate chain valid");
    }

    const rootTrusted = Array.from(this.trustedRoots.values()).some(
      (root) => root.publicKey === statement.certChain[statement.certChain.length - 1].publicKey
    );
    if (!rootTrusted) {
      findings.push("FAIL: Root certificate not trusted");
      valid = false;
    } else {
      findings.push("PASS: Root certificate trusted");
    }

    const statementLevel = LEVEL_ORDER.indexOf(statement.attestationLevel);
    const minimumLevel = LEVEL_ORDER.indexOf(policy.minimumLevel);
    if (statementLevel < minimumLevel) {
      findings.push("FAIL: Attestation level " + statement.attestationLevel + " below minimum " + policy.minimumLevel);
      valid = false;
    } else {
      findings.push("PASS: Attestation level meets minimum requirement");
    }

    if (policy.requireNeverExtractable && !statement.neverExtractable) {
      findings.push("FAIL: Policy requires never-extractable key");
      valid = false;
    } else if (policy.requireNeverExtractable) {
      findings.push("PASS: Key is never-extractable");
    }

    if (policy.requireHardwareGeneration && !statement.generatedInHardware) {
      findings.push("FAIL: Policy requires hardware-generated key");
      valid = false;
    } else if (policy.requireHardwareGeneration) {
      findings.push("PASS: Key generated in hardware");
    }

    if (!policy.allowedKeyTypes.includes(statement.keyType)) {
      findings.push("FAIL: Key type " + statement.keyType + " not in allowed types");
      valid = false;
    } else {
      findings.push("PASS: Key type allowed by policy");
    }

    if (policy.maxKeyAgeDays) {
      const keyAge = (Date.now() - new Date(statement.generatedAt).getTime()) / 86400000;
      if (keyAge > policy.maxKeyAgeDays) {
        findings.push("FAIL: Key age " + keyAge.toFixed(1) + " days exceeds maximum " + policy.maxKeyAgeDays);
        valid = false;
      } else {
        findings.push("PASS: Key age within policy limit");
      }
    }

    return {
      valid,
      keyId: statement.keyId,
      attestationLevel: statement.attestationLevel,
      hardwareSerial: statement.hardwareSerial,
      firmwareVersion: statement.firmwareVersion,
      neverExtractable: statement.neverExtractable,
      generatedInHardware: statement.generatedInHardware,
      certChainValid,
      rootTrusted,
      securityProperties: statement.securityProperties,
      verifiedAt: new Date().toISOString(),
      findings,
    };
  }

  private verifyCertChain(chain: AttestationCertificate[]): boolean {
    if (chain.length === 0) return false;
    for (let i = 0; i < chain.length - 1; i++) {
      if (chain[i].issuer !== chain[i + 1].subject) return false;
    }
    const root = chain[chain.length - 1];
    return root.issuer === root.subject || root.subject.includes("Root");
  }

  getStatement(keyId: string): KeyAttestationStatement | undefined {
    return this.statements.get(keyId);
  }

  listStatements(): Array<{
    keyId: string;
    keyLabel: string;
    keyType: string;
    level: AttestationLevel;
    neverExtractable: boolean;
    generatedAt: string;
  }> {
    return Array.from(this.statements.values()).map((s) => ({
      keyId: s.keyId,
      keyLabel: s.keyLabel,
      keyType: s.keyType,
      level: s.attestationLevel,
      neverExtractable: s.neverExtractable,
      generatedAt: s.generatedAt,
    }));
  }

  getRootFingerprint(): string {
    return createHash("sha256")
      .update(this.rootCert.publicKey + this.rootCert.subject)
      .digest("hex");
  }

  getStats(): object {
    const stmts = Array.from(this.statements.values());
    const levelCounts: Record<string, number> = {};
    stmts.forEach((s) => {
      levelCounts[s.attestationLevel] = (levelCounts[s.attestationLevel] || 0) + 1;
    });

    return {
      totalStatements: stmts.length,
      trustedRoots: this.trustedRoots.size,
      neverExtractable: stmts.filter((s) => s.neverExtractable).length,
      hardwareGenerated: stmts.filter((s) => s.generatedInHardware).length,
      levelBreakdown: levelCounts,
      rootFingerprint: this.getRootFingerprint().substring(0, 32) + "...",
    };
  }
}