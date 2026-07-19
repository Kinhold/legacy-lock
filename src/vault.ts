import { randomUUID } from 'node:crypto';
import { commitPaperSecret, verifyPaperSecret } from './commit.js';
import { assertUnlocked } from './condition.js';
import {
  canonicalJson,
  decryptAesGcm,
  deriveKey,
  encryptAesGcm,
  randomBytesBase64,
  sha256Hex,
} from './crypto.js';
import { assertNullifierFresh, deriveNullifier } from './nullifier.js';
import { buildReceipt } from './receipt.js';
import type { ClaimRequest, ClaimResult, SealedVault, VaultIntent } from './types.js';

function packageHashOf(vault: Omit<SealedVault, 'packageHash'>): string {
  return sha256Hex(`kinhold:legacy-lock:v1:package:${canonicalJson(vault)}`);
}

export function sealVault(intent: VaultIntent, passphrase: string): SealedVault {
  if (!intent.payload.trim()) throw new Error('empty_payload');
  if (!passphrase || passphrase.length < 12) throw new Error('passphrase_too_short');
  if (!intent.heirs.length) throw new Error('no_heirs');
  for (const heir of intent.heirs) {
    if (!heir.heirId.trim()) throw new Error('invalid_heir_id');
    if (!/^[a-f0-9]{64}$/.test(heir.secretCommitment)) throw new Error('invalid_heir_commitment');
  }
  if (!Number.isFinite(intent.condition.unlockAt) || intent.condition.unlockAt < 0) {
    throw new Error('invalid_unlock_at');
  }

  const salt = randomBytesBase64(16);
  const key = deriveKey(passphrase, salt);
  const { ciphertext, iv } = encryptAesGcm(intent.payload, key);

  const draft: Omit<SealedVault, 'packageHash'> = {
    version: 1,
    vaultId: randomUUID(),
    createdAt: new Date().toISOString(),
    condition: {
      unlockAt: Math.floor(intent.condition.unlockAt),
      ...(intent.condition.label ? { label: intent.condition.label } : {}),
    },
    heirs: intent.heirs.map((h) => ({
      heirId: h.heirId.trim(),
      secretCommitment: h.secretCommitment.toLowerCase(),
    })),
    ciphertext,
    iv,
    salt,
  };

  return {
    ...draft,
    packageHash: packageHashOf(draft),
  };
}

export function verifyPackageIntegrity(vault: SealedVault): boolean {
  const { packageHash, ...rest } = vault;
  return packageHashOf(rest) === packageHash;
}

/**
 * Claim flow — archive claim_legacy + Discovery + nullifier rules:
 * 1. time gate
 * 2. heir paper-secret commitment
 * 3. fresh nullifier
 * 4. decrypt with owner passphrase
 * 5. issue receipt
 */
export function claimVault(request: ClaimRequest): ClaimResult {
  if (!verifyPackageIntegrity(request.vault)) {
    throw new Error('package_tampered');
  }

  const now = request.now ?? Math.floor(Date.now() / 1000);
  assertUnlocked(request.vault.condition, now);

  const heir = request.vault.heirs.find((h) => h.heirId === request.heirId);
  if (!heir) throw new Error('heir_not_found');
  if (!verifyPaperSecret(request.paperSecret, heir.secretCommitment)) {
    throw new Error('heir_secret_invalid');
  }

  const nullifier = deriveNullifier(request.paperSecret, request.vault.vaultId, request.heirId);
  assertNullifierFresh(nullifier, request.spentNullifiers);

  const key = deriveKey(request.passphrase, request.vault.salt);
  let payload: string;
  try {
    payload = decryptAesGcm(request.vault.ciphertext, request.vault.iv, key);
  } catch {
    throw new Error('decryption_failed');
  }

  const claimedAt = new Date(now * 1000).toISOString();
  const receipt = buildReceipt({
    vaultId: request.vault.vaultId,
    heirId: request.heirId,
    packageHash: request.vault.packageHash,
    nullifier,
    claimedAt,
  });

  return { payload, nullifier, receipt };
}

export function createHeir(heirId: string, paperSecret: string) {
  return {
    heirId: heirId.trim(),
    secretCommitment: commitPaperSecret(paperSecret),
    /** Caller must store the paper secret offline. Never persist it with the vault. */
    paperSecretHint: 'Store this paper secret offline. Kinhold never stores it.',
  };
}

export { commitPaperSecret, verifyPaperSecret } from './commit.js';
export { assertUnlocked, isUnlocked } from './condition.js';
export { deriveNullifier } from './nullifier.js';
export { buildReceipt, verifyReceipt } from './receipt.js';
