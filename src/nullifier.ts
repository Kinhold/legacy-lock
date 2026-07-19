import { hmacSha256Hex } from './crypto.js';

/**
 * One-time claim nullifier.
 * Archive rule: Nullifier = Hash(Secret Key, Note Index) — spent publicly once.
 */
export function deriveNullifier(paperSecret: string, vaultId: string, heirId: string): string {
  return hmacSha256Hex(paperSecret, `kinhold:legacy-lock:v1:nullifier:${vaultId}:${heirId}`);
}

export function assertNullifierFresh(
  nullifier: string,
  spent: ReadonlySet<string> | readonly string[] | undefined,
): void {
  if (!/^[a-f0-9]{64}$/.test(nullifier)) {
    throw new Error('invalid_nullifier');
  }
  if (!spent) return;
  const set = spent instanceof Set ? spent : new Set(spent);
  if (set.has(nullifier)) {
    throw new Error('nullifier_already_spent');
  }
}
