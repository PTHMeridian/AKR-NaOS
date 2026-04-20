export interface ShamirShare {
  id: number;
  share: string;
  label?: string;
}

export interface ShamirSplitResult {
  shares: ShamirShare[];
  threshold: number;
  totalShares: number;
  secretHash: string;
  algorithm: string;
  createdAt: number;
}

export interface ShamirRecoverResult {
  secret: string;
  verified: boolean;
  algorithm: string;
  recoveredAt: number;
}

export interface ShamirConfig {
  threshold: number;
  totalShares: number;
  label?: string;
}