import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import {
  claimVault,
  commitPaperSecret,
  createHeir,
  deriveNullifier,
  isUnlocked,
  sealVault,
  verifyPackageIntegrity,
  verifyReceipt,
} from '../src/index.js';

const PASSPHRASE = 'test-passphrase-strong';
const PAPER_A = 'paper-secret-alpha-00123456789';
const PAPER_B = 'paper-secret-beta-00987654321';

describe('Legacy Lock core rules', () => {
  it('commits paper secrets deterministically', () => {
    const a = commitPaperSecret(PAPER_A);
    const b = commitPaperSecret(PAPER_A);
    assert.equal(a, b);
    assert.equal(a.length, 64);
    assert.notEqual(a, commitPaperSecret(PAPER_B));
  });

  it('rejects short paper secrets', () => {
    assert.throws(() => commitPaperSecret('too-short'), /paper_secret_too_short/);
  });

  it('seals and claims after unlock time', () => {
    const heir = createHeir('heir-a', PAPER_A);
    const unlockAt = Math.floor(Date.now() / 1000) - 60;
    const vault = sealVault(
      {
        payload: 'Executor: release wallet seed under sealed letter.',
        heirs: [{ heirId: heir.heirId, secretCommitment: heir.secretCommitment }],
        condition: { unlockAt, label: 'available now' },
      },
      PASSPHRASE,
    );

    assert.equal(vault.version, 1);
    assert.ok(verifyPackageIntegrity(vault));
    assert.equal(isUnlocked(vault.condition, unlockAt), true);

    const claim = claimVault({
      vault,
      heirId: 'heir-a',
      paperSecret: PAPER_A,
      passphrase: PASSPHRASE,
      now: unlockAt + 1,
    });

    assert.equal(claim.payload, 'Executor: release wallet seed under sealed letter.');
    assert.equal(claim.nullifier.length, 64);
    assert.ok(verifyReceipt(claim.receipt));
    assert.equal(claim.receipt.vaultId, vault.vaultId);
  });

  it('blocks claim before unlock time', () => {
    const heir = createHeir('heir-a', PAPER_A);
    const unlockAt = Math.floor(Date.now() / 1000) + 86_400;
    const vault = sealVault(
      {
        payload: 'sealed until tomorrow',
        heirs: [{ heirId: heir.heirId, secretCommitment: heir.secretCommitment }],
        condition: { unlockAt },
      },
      PASSPHRASE,
    );

    assert.throws(
      () =>
        claimVault({
          vault,
          heirId: 'heir-a',
          paperSecret: PAPER_A,
          passphrase: PASSPHRASE,
          now: unlockAt - 10,
        }),
      /vault_still_sealed/,
    );
  });

  it('rejects wrong paper secret', () => {
    const heir = createHeir('heir-a', PAPER_A);
    const unlockAt = Math.floor(Date.now() / 1000) - 1;
    const vault = sealVault(
      {
        payload: 'payload',
        heirs: [{ heirId: heir.heirId, secretCommitment: heir.secretCommitment }],
        condition: { unlockAt },
      },
      PASSPHRASE,
    );

    assert.throws(
      () =>
        claimVault({
          vault,
          heirId: 'heir-a',
          paperSecret: PAPER_B,
          passphrase: PASSPHRASE,
          now: unlockAt + 1,
        }),
      /heir_secret_invalid/,
    );
  });

  it('rejects wrong passphrase', () => {
    const heir = createHeir('heir-a', PAPER_A);
    const unlockAt = Math.floor(Date.now() / 1000) - 1;
    const vault = sealVault(
      {
        payload: 'payload',
        heirs: [{ heirId: heir.heirId, secretCommitment: heir.secretCommitment }],
        condition: { unlockAt },
      },
      PASSPHRASE,
    );

    assert.throws(
      () =>
        claimVault({
          vault,
          heirId: 'heir-a',
          paperSecret: PAPER_A,
          passphrase: 'definitely-wrong-passphrase',
          now: unlockAt + 1,
        }),
      /decryption_failed/,
    );
  });

  it('detects package tampering', () => {
    const heir = createHeir('heir-a', PAPER_A);
    const unlockAt = Math.floor(Date.now() / 1000) - 1;
    const vault = sealVault(
      {
        payload: 'payload',
        heirs: [{ heirId: heir.heirId, secretCommitment: heir.secretCommitment }],
        condition: { unlockAt },
      },
      PASSPHRASE,
    );
    const tampered = {
      ...vault,
      ciphertext: Buffer.from(vault.ciphertext, 'base64')
        .map((byte, index) => (index === 0 ? byte ^ 0xff : byte))
        .toString('base64'),
    };
    assert.equal(verifyPackageIntegrity(tampered), false);
    assert.throws(
      () =>
        claimVault({
          vault: tampered,
          heirId: 'heir-a',
          paperSecret: PAPER_A,
          passphrase: PASSPHRASE,
          now: unlockAt + 1,
        }),
      /package_tampered/,
    );
  });

  it('enforces one-time nullifier spend', () => {
    const heir = createHeir('heir-a', PAPER_A);
    const unlockAt = Math.floor(Date.now() / 1000) - 1;
    const vault = sealVault(
      {
        payload: 'payload',
        heirs: [{ heirId: heir.heirId, secretCommitment: heir.secretCommitment }],
        condition: { unlockAt },
      },
      PASSPHRASE,
    );

    const first = claimVault({
      vault,
      heirId: 'heir-a',
      paperSecret: PAPER_A,
      passphrase: PASSPHRASE,
      now: unlockAt + 1,
    });

    assert.throws(
      () =>
        claimVault({
          vault,
          heirId: 'heir-a',
          paperSecret: PAPER_A,
          passphrase: PASSPHRASE,
          now: unlockAt + 2,
          spentNullifiers: [first.nullifier],
        }),
      /nullifier_already_spent/,
    );

    const expected = deriveNullifier(PAPER_A, vault.vaultId, 'heir-a');
    assert.equal(first.nullifier, expected);
  });

  it('supports multiple heirs with independent secrets', () => {
    const a = createHeir('wyatt', PAPER_A);
    const b = createHeir('julianna', PAPER_B);
    const unlockAt = Math.floor(Date.now() / 1000) - 1;
    const vault = sealVault(
      {
        payload: 'shared instruction',
        heirs: [
          { heirId: a.heirId, secretCommitment: a.secretCommitment },
          { heirId: b.heirId, secretCommitment: b.secretCommitment },
        ],
        condition: { unlockAt },
      },
      PASSPHRASE,
    );

    const claimA = claimVault({
      vault,
      heirId: 'wyatt',
      paperSecret: PAPER_A,
      passphrase: PASSPHRASE,
      now: unlockAt + 1,
    });
    const claimB = claimVault({
      vault,
      heirId: 'julianna',
      paperSecret: PAPER_B,
      passphrase: PASSPHRASE,
      now: unlockAt + 1,
      spentNullifiers: [claimA.nullifier],
    });

    assert.equal(claimA.payload, claimB.payload);
    assert.notEqual(claimA.nullifier, claimB.nullifier);
  });
});
