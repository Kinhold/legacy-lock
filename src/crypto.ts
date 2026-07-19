import {
  createCipheriv,
  createDecipheriv,
  createHash,
  createHmac,
  pbkdf2Sync,
  randomBytes,
  timingSafeEqual,
} from 'node:crypto';

const PBKDF2_ITERATIONS = 210_000;
const KEY_LEN = 32;

export function sha256Hex(data: string | Uint8Array): string {
  return createHash('sha256').update(data).digest('hex');
}

export function hmacSha256Hex(key: string | Uint8Array, data: string | Uint8Array): string {
  return createHmac('sha256', key).update(data).digest('hex');
}

export function randomBytesBase64(size: number): string {
  return randomBytes(size).toString('base64');
}

export function deriveKey(passphrase: string, saltBase64: string): Buffer {
  const salt = Buffer.from(saltBase64, 'base64');
  if (salt.length < 16) {
    throw new Error('salt_too_short');
  }
  return pbkdf2Sync(passphrase, salt, PBKDF2_ITERATIONS, KEY_LEN, 'sha256');
}

export function encryptAesGcm(plaintext: string, key: Buffer): { ciphertext: string; iv: string } {
  const iv = randomBytes(12);
  const cipher = createCipheriv('aes-256-gcm', key, iv);
  const enc = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()]);
  const tag = cipher.getAuthTag();
  return {
    ciphertext: Buffer.concat([enc, tag]).toString('base64'),
    iv: iv.toString('base64'),
  };
}

export function decryptAesGcm(ciphertextBase64: string, ivBase64: string, key: Buffer): string {
  const raw = Buffer.from(ciphertextBase64, 'base64');
  if (raw.length < 17) {
    throw new Error('ciphertext_too_short');
  }
  const data = raw.subarray(0, raw.length - 16);
  const tag = raw.subarray(raw.length - 16);
  const iv = Buffer.from(ivBase64, 'base64');
  const decipher = createDecipheriv('aes-256-gcm', key, iv);
  decipher.setAuthTag(tag);
  return Buffer.concat([decipher.update(data), decipher.final()]).toString('utf8');
}

/** Constant-time hex compare. */
export function safeEqualHex(a: string, b: string): boolean {
  try {
    const ba = Buffer.from(a, 'hex');
    const bb = Buffer.from(b, 'hex');
    if (ba.length !== bb.length || ba.length === 0) return false;
    return timingSafeEqual(ba, bb);
  } catch {
    return false;
  }
}

export function canonicalJson(value: unknown): string {
  return JSON.stringify(sortKeys(value));
}

function sortKeys(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(sortKeys);
  if (value && typeof value === 'object') {
    const obj = value as Record<string, unknown>;
    const out: Record<string, unknown> = {};
    for (const key of Object.keys(obj).sort()) {
      out[key] = sortKeys(obj[key]);
    }
    return out;
  }
  return value;
}
