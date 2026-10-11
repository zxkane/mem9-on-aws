/** Prospective source-owned observation tariff. No runtime or funding handle. */
import {nonrootHash as hash} from './production-nonroot-contracts.mjs';

export const PRODUCTION_CONTROL_COMPOSITION_RUNTIME_POLICY=Object.freeze({version:1,kind:'github-main-runtime-observation-policy',
 runtimeBytes:268435456,mappedFilesIncludingNode:128,totalFiles:130,mapsBytes:65536,manifestBytes:1048576,recheckRecordBytes:4096,
 streamBytes:65536,fullRechecks:6,normalFileEntryCharge:1061,cleanupFileEntryCharge:152,nodeMajor:24,platform:'linux',architectures:Object.freeze(['arm64','x64']),
 kernelPseudoFile:Object.freeze({name:'anon_inode:[io_uring]',permissions:'rw-s',deviceMajor:'0',positiveInode:true})});
export const PRODUCTION_CONTROL_COMPOSITION_RUNTIME_POLICY_HASH=hash(PRODUCTION_CONTROL_COMPOSITION_RUNTIME_POLICY);
export const CONTROL_COMPOSITION_RUNTIME_PHASES=Object.freeze(['packs','source','base','composed','published','captured']);
export const CONTROL_COMPOSITION_RUNTIME_NORMAL_LOCAL=4617105520;
export const CONTROL_COMPOSITION_RUNTIME_CLEANUP_LOCAL=2490368;
export const CONTROL_COMPOSITION_RUNTIME_VALIDATION_LOCAL=15925360;
export const CONTROL_COMPOSITION_RUNTIME_ENTRY='.github/actions/control-composition/dist/index.mjs';
export const CONTROL_COMPOSITION_RUNTIME_TOOLCHAIN='.github/actions/control-composition/dist/toolchain.json';
