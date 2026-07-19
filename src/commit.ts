import { sha256Hex } from './crypto.js';

/**
 * Heir paper-secret commitment.
 * Extracted rule from aztec-30-day-challenge Discovery.nr:
 *   computed = hash(secret_nullifier); assert(computed == stored_hash)
 * We use SHA-256 for portable Node/browser execution (not Pedersen/Aztec Field).
 */
export function commitPaperSecret(paperSecret: string): string {
  const normalized = paperSecret.trim();
  if (normalized.length < 16) {
    throw new Error('paper_secret_too_short');
  }
  return sha256Hex(`kinhold:legacy-lock:v1:heir:${normalized}`);
}

export function verifyPaperSecret(paperSecret: string, commitment: string): boolean {
  try {
    return commitPaperSecret(paperSecret) === commitment;
  } catch {
    return false;
  }
}
