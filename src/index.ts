export type {
  ClaimRequest,
  ClaimResult,
  HeirRecord,
  RegisterPackageInput,
  ReleaseCondition,
  SealedVault,
  VaultIntent,
  VaultReceipt,
} from './types.js';

export {
  claimVault,
  commitPaperSecret,
  createHeir,
  deriveNullifier,
  isUnlocked,
  sealVault,
  verifyPackageIntegrity,
  verifyPaperSecret,
  verifyReceipt,
} from './vault.js';
