#!/usr/bin/env node
import { readFileSync, writeFileSync } from 'node:fs';
import {
  claimVault,
  createHeir,
  sealVault,
  verifyPackageIntegrity,
  verifyReceipt,
} from '../dist/index.js';

function usage() {
  console.log(`legacy-lock — Kinhold inheritance vault

Usage:
  legacy-lock heir-create --id <heirId> --secret <paperSecret>
  legacy-lock seal --payload <file|-> --passphrase <pass> --unlock-at <unix> --heir <id:commitment>[,id:commitment...]
  legacy-lock verify --vault <file>
  legacy-lock claim --vault <file> --heir <id> --secret <paperSecret> --passphrase <pass> [--now <unix>]
`);
}

function arg(name) {
  const idx = process.argv.indexOf(name);
  if (idx === -1) return undefined;
  return process.argv[idx + 1];
}

const cmd = process.argv[2];

try {
  if (cmd === 'heir-create') {
    const id = arg('--id');
    const secret = arg('--secret');
    if (!id || !secret) throw new Error('missing --id/--secret');
    const heir = createHeir(id, secret);
    console.log(JSON.stringify(heir, null, 2));
  } else if (cmd === 'seal') {
    const payloadPath = arg('--payload');
    const passphrase = arg('--passphrase');
    const unlockAt = Number(arg('--unlock-at'));
    const heirArg = arg('--heir');
    if (!payloadPath || !passphrase || !heirArg || !Number.isFinite(unlockAt)) {
      throw new Error('missing seal args');
    }
    const payload =
      payloadPath === '-' ? readFileSync(0, 'utf8') : readFileSync(payloadPath, 'utf8');
    const heirs = heirArg.split(',').map((part) => {
      const [heirId, secretCommitment] = part.split(':');
      if (!heirId || !secretCommitment) throw new Error('bad --heir format id:commitment');
      return { heirId, secretCommitment };
    });
    const vault = sealVault({ payload, heirs, condition: { unlockAt } }, passphrase);
    const out = arg('--out') ?? `vault-${vault.vaultId}.json`;
    writeFileSync(out, JSON.stringify(vault, null, 2));
    console.log(JSON.stringify({ out, vaultId: vault.vaultId, packageHash: vault.packageHash }, null, 2));
  } else if (cmd === 'verify') {
    const vaultPath = arg('--vault');
    if (!vaultPath) throw new Error('missing --vault');
    const vault = JSON.parse(readFileSync(vaultPath, 'utf8'));
    console.log(JSON.stringify({ ok: verifyPackageIntegrity(vault), vaultId: vault.vaultId }, null, 2));
  } else if (cmd === 'claim') {
    const vaultPath = arg('--vault');
    const heirId = arg('--heir');
    const paperSecret = arg('--secret');
    const passphrase = arg('--passphrase');
    const now = arg('--now') ? Number(arg('--now')) : undefined;
    if (!vaultPath || !heirId || !paperSecret || !passphrase) throw new Error('missing claim args');
    const vault = JSON.parse(readFileSync(vaultPath, 'utf8'));
    const result = claimVault({ vault, heirId, paperSecret, passphrase, now });
    console.log(
      JSON.stringify(
        {
          payload: result.payload,
          nullifier: result.nullifier,
          receipt: result.receipt,
          receiptOk: verifyReceipt(result.receipt),
        },
        null,
        2,
      ),
    );
  } else {
    usage();
    process.exit(cmd ? 1 : 0);
  }
} catch (error) {
  console.error(String(error?.message ?? error));
  process.exit(1);
}
