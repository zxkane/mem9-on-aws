import {nonrootDeploymentFixture} from '../production-nonroot-provenance.fixture.mjs';
import {sha} from './fixture.mjs';
import {readControlSourceFile,describeControlCopyClosure} from '../lib/production-control-source.mjs';
import {nonrootHash as hash} from '../lib/production-nonroot-contracts.mjs';
import {describeProductionControlCompositionRecipe,inspectProductionControlBuildContract,
 PRODUCTION_CONTROL_COMPOSITION_ACTION as action,PRODUCTION_CONTROL_COMPOSITION_ENTRY as entry,
 PRODUCTION_CONTROL_COMPOSITION_TOOLCHAIN as toolchainPath} from '../lib/production-control-composition-recipe.mjs';

// A synthetic reviewed contract for the real small OCI producer below. This
// fixture supplies no native runtime or source verification success handle.
export async function nativeContract(f){
 const legacy=await nonrootDeploymentFixture(),file=path=>{const b=Buffer.from('synthetic '+path);return {path,gitMode:'100644',sha256:sha(b),bytes:b.length,blob:{sha256:sha(b),bytesLength:b.length}};};
 const actionSource=file(action),bundle=file(entry),toolchain=file(toolchainPath),files=[actionSource,bundle,toolchain];
 const recipe=describeProductionControlCompositionRecipe({dockerfile:(await readControlSourceFile(f.src.context,'docker/bootstrap/Dockerfile')).file,
  context:await describeControlCopyClosure(f.src.context),ignoreFiles:{bytesHash:sha('[]'),canonicalHash:hash([]),bytesLength:2},
  preparation:{version:1,kind:'git-file-closure',tree:f.source.candidateTree,files,closureHash:hash(files)},actionSource,bundle,toolchain,plan:f.plan});
 return inspectProductionControlBuildContract({...legacy.contract,version:2,repository:f.source.repository,prNumber:f.source.prNumber,
  candidate:{...legacy.contract.candidate,revision:f.source.candidateRevision,tree:f.source.candidateTree,baseRevision:f.source.baseRevision},recipe,
  output:{account:f.input.base.image.account,region:f.input.base.image.region,repositoryName:'mem9-on-aws/bootstrap'}});
}
