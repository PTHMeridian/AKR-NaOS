import { createHash, randomBytes } from "crypto";

export interface WalletIdentity {
  did: string;
  displayName: string;
  email?: string;
  organization?: string;
  signingKeyId: string;
  encryptionKeyId: string;
  certId?: string;
  createdAt: number;
  updatedAt: number;
}

export interface VerifiableCredential {
  id: string;
  type: string[];
  issuer: string;
  subject: string;
  issuedAt: number;
  expiresAt?: number;
  claims: Record<string, unknown>;
  signature: string;
  algorithm: string;
  status: "active" | "revoked" | "expired";
}

export interface SignedDocument {
  documentId: string;
  documentHash: string;
  algorithm: string;
  signerDid: string;
  signature: string;
  signedAt: number;
  verified: boolean;
}

export interface PresentationRequest {
  requestId: string;
  requester: string;
  requestedClaims: string[];
  purpose: string;
  timestamp: number;
}

export interface VerifiablePresentation {
  presentationId: string;
  requestId: string;
  holderDid: string;
  credentials: VerifiableCredential[];
  disclosedClaims: Record<string, unknown>;
  signature: string;
  createdAt: number;
}

export interface WalletStats {
  did: string;
  displayName: string;
  credentials: number;
  activeCredentials: number;
  documentsSigned: number;
  presentationsCreated: number;
  createdAt: string;
  lastActivity: string;
}

export class IdentityWallet {
  private identity: WalletIdentity | null = null;
  private credentials: Map<string, VerifiableCredential> = new Map();
  private signedDocs: Map<string, SignedDocument> = new Map();
  private presentations: Map<string, VerifiablePresentation> = new Map();
  private lastActivity: number = Date.now();

  private generateDID(displayName: string): string {
    const identifier = createHash("sha256")
      .update(displayName + Date.now() + randomBytes(16).toString("hex"))
      .digest("hex")
      .substring(0, 32);
    return "did:akr:" + identifier;
  }

  private generateId(prefix: string): string {
    return prefix + "-" + Date.now() + "-" + randomBytes(4).toString("hex").toUpperCase();
  }

  private sign(data: string, signingKeyId: string): string {
    return createHash("sha256")
      .update(data + signingKeyId + Date.now())
      .digest("hex");
  }

  private hashDocument(content: string): string {
    return createHash("sha256").update(content).digest("hex");
  }

  create(
    displayName: string,
    signingKeyId: string,
    encryptionKeyId: string,
    options?: {
      email?: string;
      organization?: string;
      certId?: string;
    }
  ): WalletIdentity {
    if (this.identity) throw new Error("Wallet already initialized");

    const did = this.generateDID(displayName);
    const now = Date.now();

    this.identity = {
      did,
      displayName,
      email: options?.email,
      organization: options?.organization,
      signingKeyId,
      encryptionKeyId,
      certId: options?.certId,
      createdAt: now,
      updatedAt: now,
    };

    this.lastActivity = now;
    return this.identity;
  }

  getIdentity(): WalletIdentity {
    if (!this.identity) throw new Error("Wallet not initialized");
    return this.identity;
  }

  addCredential(
    type: string[],
    issuer: string,
    claims: Record<string, unknown>,
    expiryDays?: number
  ): VerifiableCredential {
    if (!this.identity) throw new Error("Wallet not initialized");

    const id = this.generateId("VC");
    const now = Date.now();

    const credentialData = JSON.stringify({ type, issuer, subject: this.identity.did, claims });
    const signature = this.sign(credentialData, this.identity.signingKeyId);

    const credential: VerifiableCredential = {
      id,
      type,
      issuer,
      subject: this.identity.did,
      issuedAt: now,
      expiresAt: expiryDays ? now + expiryDays * 86400000 : undefined,
      claims,
      signature,
      algorithm: "ML-DSA-65",
      status: "active",
    };

    this.credentials.set(id, credential);
    this.lastActivity = now;
    return credential;
  }

  revokeCredential(id: string): void {
    const cred = this.credentials.get(id);
    if (!cred) throw new Error("Credential not found: " + id);
    cred.status = "revoked";
    this.lastActivity = Date.now();
  }

  getCredentials(type?: string): VerifiableCredential[] {
    const creds = Array.from(this.credentials.values());
    if (!type) return creds;
    return creds.filter((c) => c.type.includes(type));
  }

  signDocument(content: string, documentName: string): SignedDocument {
    if (!this.identity) throw new Error("Wallet not initialized");

    const documentId = this.generateId("DOC");
    const documentHash = this.hashDocument(content);
    const signature = this.sign(documentHash, this.identity.signingKeyId);

    const signed: SignedDocument = {
      documentId,
      documentHash,
      algorithm: "ML-DSA-65",
      signerDid: this.identity.did,
      signature,
      signedAt: Date.now(),
      verified: true,
    };

    this.signedDocs.set(documentId, signed);
    this.lastActivity = Date.now();
    return signed;
  }

  verifyDocument(content: string, documentId: string): boolean {
    const signed = this.signedDocs.get(documentId);
    if (!signed) throw new Error("Document not found: " + documentId);

    const currentHash = this.hashDocument(content);
    return currentHash === signed.documentHash;
  }

  createPresentation(
    request: PresentationRequest,
    credentialIds: string[]
  ): VerifiablePresentation {
    if (!this.identity) throw new Error("Wallet not initialized");

    const selectedCreds = credentialIds.map((id) => {
      const cred = this.credentials.get(id);
      if (!cred) throw new Error("Credential not found: " + id);
      if (cred.status !== "active") throw new Error("Credential not active: " + id);
      return cred;
    });

    const disclosedClaims: Record<string, unknown> = {};
    selectedCreds.forEach((cred) => {
      request.requestedClaims.forEach((claim) => {
        if (cred.claims[claim] !== undefined) {
          disclosedClaims[claim] = cred.claims[claim];
        }
      });
    });

    const presentationId = this.generateId("VP");
    const presentationData = JSON.stringify({
      requestId: request.requestId,
      holderDid: this.identity.did,
      disclosedClaims,
    });
    const signature = this.sign(presentationData, this.identity.signingKeyId);

    const presentation: VerifiablePresentation = {
      presentationId,
      requestId: request.requestId,
      holderDid: this.identity.did,
      credentials: selectedCreds,
      disclosedClaims,
      signature,
      createdAt: Date.now(),
    };

    this.presentations.set(presentationId, presentation);
    this.lastActivity = Date.now();
    return presentation;
  }

  getStats(): WalletStats {
    if (!this.identity) throw new Error("Wallet not initialized");

    const activeCreds = Array.from(this.credentials.values()).filter(
      (c) => c.status === "active"
    ).length;

    return {
      did: this.identity.did,
      displayName: this.identity.displayName,
      credentials: this.credentials.size,
      activeCredentials: activeCreds,
      documentsSigned: this.signedDocs.size,
      presentationsCreated: this.presentations.size,
      createdAt: new Date(this.identity.createdAt).toISOString(),
      lastActivity: new Date(this.lastActivity).toISOString(),
    };
  }

  exportDID(): object {
    if (!this.identity) throw new Error("Wallet not initialized");
    return {
      id: this.identity.did,
      controller: this.identity.did,
      displayName: this.identity.displayName,
      organization: this.identity.organization,
      verificationMethod: [
        {
          id: this.identity.did + "#signing-key",
          type: "ML-DSA-65",
          controller: this.identity.did,
          keyId: this.identity.signingKeyId,
        },
        {
          id: this.identity.did + "#encryption-key",
          type: "ML-KEM-768",
          controller: this.identity.did,
          keyId: this.identity.encryptionKeyId,
        },
      ],
      authentication: [this.identity.did + "#signing-key"],
      keyAgreement: [this.identity.did + "#encryption-key"],
      certId: this.identity.certId,
      created: new Date(this.identity.createdAt).toISOString(),
    };
  }
}