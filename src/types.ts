/** Shared types for Legacy Lock vault operations. */

export type IsoTimestamp = string;

export type ReleaseCondition = {
  /** Unix seconds. Claim is rejected until this time. */
  unlockAt: number;
  /** Optional human label for the condition (never used in crypto). */
  label?: string;
};

export type HeirRecord = {
  /** Public id for the heir (not secret). */
  heirId: string;
  /** Hex SHA-256 commitment of the heir paper secret. */
  secretCommitment: string;
};

export type VaultIntent = {
  /** Free-form legacy instruction / payload the owner wants heirs to receive. */
  payload: string;
  heirs: HeirRecord[];
  condition: ReleaseCondition;
};

export type SealedVault = {
  version: 1;
  vaultId: string;
  createdAt: IsoTimestamp;
  condition: ReleaseCondition;
  heirs: HeirRecord[];
  /** AES-256-GCM ciphertext (base64). */
  ciphertext: string;
  /** AES-GCM IV (base64). */
  iv: string;
  /** Salt used for key derivation (base64). */
  salt: string;
  /** SHA-256 over canonical public fields + ciphertext. */
  packageHash: string;
};

export type ClaimRequest = {
  vault: SealedVault;
  heirId: string;
  /** Paper secret for the claiming heir (never stored by Kinhold). */
  paperSecret: string;
  /** Owner passphrase used at seal time. */
  passphrase: string;
  /** Current unix seconds (injectable for tests). */
  now?: number;
  /** Previously spent nullifiers (hex). */
  spentNullifiers?: ReadonlySet<string> | readonly string[];
};

export type ClaimResult = {
  payload: string;
  nullifier: string;
  receipt: VaultReceipt;
};

export type VaultReceipt = {
  version: 1;
  vaultId: string;
  heirId: string;
  packageHash: string;
  nullifier: string;
  claimedAt: IsoTimestamp;
  receiptHash: string;
};

export type RegisterPackageInput = {
  vaultId: string;
  packageHash: string;
  unlockAt: number;
  heirCommitments: string[];
};
