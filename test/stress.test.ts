import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { performance } from 'node:perf_hooks';
import { claimVault, createHeir, sealVault, verifyPackageIntegrity } from '../src/index.js';

const PASSPHRASE = 'stress-passphrase-ok';
const PAPER = 'stress-paper-secret-0123456789';

describe('Legacy Lock stress', () => {
  it('seals and verifies 80 vaults under 20s', () => {
    const start = performance.now();
    const heir = createHeir('heir-stress', PAPER);
    const unlockAt = Math.floor(Date.now() / 1000) - 1;

    for (let i = 0; i < 80; i += 1) {
      const vault = sealVault(
        {
          payload: `instruction-${i}-${'x'.repeat(256)}`,
          heirs: [{ heirId: heir.heirId, secretCommitment: heir.secretCommitment }],
          condition: { unlockAt },
        },
        PASSPHRASE,
      );
      assert.ok(verifyPackageIntegrity(vault));
      const claim = claimVault({
        vault,
        heirId: 'heir-stress',
        paperSecret: PAPER,
        passphrase: PASSPHRASE,
        now: unlockAt + 1,
      });
      assert.ok(claim.payload.startsWith(`instruction-${i}-`));
    }

    const elapsed = performance.now() - start;
    assert.ok(elapsed < 20_000, `elapsed ${elapsed}ms`);
  });

  it('handles large payload (512 KiB) seal/claim', () => {
    const heir = createHeir('heir-big', PAPER);
    const unlockAt = Math.floor(Date.now() / 1000) - 1;
    const payload = 'P'.repeat(512 * 1024);
    const vault = sealVault(
      {
        payload,
        heirs: [{ heirId: heir.heirId, secretCommitment: heir.secretCommitment }],
        condition: { unlockAt },
      },
      PASSPHRASE,
    );
    const claim = claimVault({
      vault,
      heirId: 'heir-big',
      paperSecret: PAPER,
      passphrase: PASSPHRASE,
      now: unlockAt + 1,
    });
    assert.equal(claim.payload.length, payload.length);
    assert.equal(claim.payload, payload);
  });

  it('rejects concurrent double-claim via spent set', () => {
    const heir = createHeir('heir-race', PAPER);
    const unlockAt = Math.floor(Date.now() / 1000) - 1;
    const vault = sealVault(
      {
        payload: 'once',
        heirs: [{ heirId: heir.heirId, secretCommitment: heir.secretCommitment }],
        condition: { unlockAt },
      },
      PASSPHRASE,
    );

    const spent = new Set<string>();
    const first = claimVault({
      vault,
      heirId: 'heir-race',
      paperSecret: PAPER,
      passphrase: PASSPHRASE,
      now: unlockAt + 1,
      spentNullifiers: spent,
    });
    spent.add(first.nullifier);

    let failures = 0;
    for (let i = 0; i < 50; i += 1) {
      try {
        claimVault({
          vault,
          heirId: 'heir-race',
          paperSecret: PAPER,
          passphrase: PASSPHRASE,
          now: unlockAt + 2 + i,
          spentNullifiers: spent,
        });
      } catch (error) {
        assert.match(String(error), /nullifier_already_spent/);
        failures += 1;
      }
    }
    assert.equal(failures, 50);
  });
});
