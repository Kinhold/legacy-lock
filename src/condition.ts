import type { ReleaseCondition } from './types.js';

/**
 * Temporal gate from aztec-30-day-challenge claim_legacy / Nav_Note_01:
 *   assert(current_time >= unlock_timestamp)
 */
export function assertUnlocked(condition: ReleaseCondition, nowUnixSeconds: number): void {
  if (!Number.isFinite(condition.unlockAt) || condition.unlockAt < 0) {
    throw new Error('invalid_unlock_at');
  }
  if (!Number.isFinite(nowUnixSeconds) || nowUnixSeconds < 0) {
    throw new Error('invalid_now');
  }
  if (nowUnixSeconds < condition.unlockAt) {
    throw new Error('vault_still_sealed');
  }
}

export function isUnlocked(condition: ReleaseCondition, nowUnixSeconds: number): boolean {
  try {
    assertUnlocked(condition, nowUnixSeconds);
    return true;
  } catch {
    return false;
  }
}
