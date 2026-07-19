import { canonicalJson, sha256Hex } from './crypto.js';
import type { VaultReceipt } from './types.js';

export function buildReceipt(input: {
  vaultId: string;
  heirId: string;
  packageHash: string;
  nullifier: string;
  claimedAt: string;
}): VaultReceipt {
  const base = {
    version: 1 as const,
    vaultId: input.vaultId,
    heirId: input.heirId,
    packageHash: input.packageHash,
    nullifier: input.nullifier,
    claimedAt: input.claimedAt,
  };
  const receiptHash = sha256Hex(`kinhold:legacy-lock:v1:receipt:${canonicalJson(base)}`);
  return { ...base, receiptHash };
}

export function verifyReceipt(receipt: VaultReceipt): boolean {
  const expected = buildReceipt(receipt);
  return expected.receiptHash === receipt.receiptHash;
}
