import {authenticateImageArchiveBinding} from './production-image-custody.mjs';
import {restoreArchivedImageCopyVerification} from './production-image-graph.mjs';
import {restoreArchivedImageFilesystem} from './production-image-filesystem.mjs';
/** Reconstruct immutable evidence custody without downloading old blob bodies.
 * Full proof/review verification and fresh serving-state checks still follow.
 * These handles are rejected by initial copy and proof-construction paths.
 */
export function restoreImageVerificationEvidence({proof,graphEvidence,filesystemEvidence,data,review},expected){
 const binding=authenticateImageArchiveBinding({proof,data,review},expected);
 const graphVerification=restoreArchivedImageCopyVerification(binding,graphEvidence);
 const filesystemVerification=restoreArchivedImageFilesystem(binding,filesystemEvidence,graphVerification);
 return {graphVerification,filesystemVerification};
}
