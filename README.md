# Legacy Lock

Zero-knowledge inheritance vault for Kinhold.

Seal a legacy instruction. Bind it to heir paper secrets. Enforce a time lock. Issue a one-time claim receipt.

Extracted from the pure rules in the Aztec 30-day challenge archive (`claim_legacy`, Discovery heir verification, nullifiers, temporal gates) — rewritten as a portable, tested package. The archive remains historical. This package is the product.

## What this is

| Capability | Behavior |
| --- | --- |
| Seal | AES-256-GCM encrypt payload; public package hash |
| Heir commitment | SHA-256 commitment of paper secret (secret never stored) |
| Time lock | Claim rejected until `unlockAt` |
| Nullifier | One claim per heir secret per vault |
| Receipt | Hash-chained claim receipt |

## What this is not

- Not the unfinished Aztec contract drafts in `aztec-30-day-challenge`
- Not a claim that Aztec Noir proofs are generated in this package
- Not a place to store paper secrets or passphrases

## Install

```bash
pnpm install
pnpm run build
pnpm run check
```

## Library

```ts
import {
  createHeir,
  sealVault,
  claimVault,
  verifyPackageIntegrity,
} from '@kinhold/legacy-lock';

const heir = createHeir('heir-1', 'offline-paper-secret-min-16chars');
const vault = sealVault(
  {
    payload: 'Release the custody packet to the executor.',
    heirs: [{ heirId: heir.heirId, secretCommitment: heir.secretCommitment }],
    condition: { unlockAt: Math.floor(Date.now() / 1000) + 86400 },
  },
  'owner-passphrase-min-12',
);

verifyPackageIntegrity(vault); // true
```

## CLI

```bash
pnpm run build
node bin/legacy-lock.mjs heir-create --id heir-1 --secret 'offline-paper-secret-min-16chars'
node bin/legacy-lock.mjs seal --payload ./instruction.txt --passphrase 'owner-passphrase-min-12' --unlock-at 1893456000 --heir heir-1:<commitment> --out vault.json
node bin/legacy-lock.mjs verify --vault vault.json
node bin/legacy-lock.mjs claim --vault vault.json --heir heir-1 --secret 'offline-paper-secret-min-16chars' --passphrase 'owner-passphrase-min-12' --now 1893456001
```

## Provenance

Rules mapped from:

- `org/aztec-30-day-challenge/circuits/circuits/src/main.nr` → `claim_legacy` time gate
- `org/aztec-30-day-challenge/circuits/src/Discovery.nr` → heir secret commitment check
- `org/aztec-30-day-challenge/logbook/Nav_Note_01.md` → nullifier + temporal constraints

## License

MIT
