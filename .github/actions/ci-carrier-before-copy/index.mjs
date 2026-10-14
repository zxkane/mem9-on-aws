import {fileURLToPath} from 'node:url';
import {runCarrierBeforeCopy} from '../../../scripts/lib/ci-carrier-worker.mjs';
export {runCarrierBeforeCopy};

if(process.argv[1]===fileURLToPath(import.meta.url)){
 const env=process.env;
 const valid=process.argv.length===2&&Object.keys(env).filter(k=>k.startsWith('INPUT_')).every(k=>['INPUT_GRANT_COMMITMENT','INPUT_CONTEXT_COMMITMENT'].includes(k))&&process.versions.node.split('.')[0]==='24';
 Promise.resolve().then(()=>{if(!valid)throw Error('CarrierActionInput');return runCarrierBeforeCopy(env);})
  .then(record=>console.log(JSON.stringify(record)))
  .catch(()=>{console.error(JSON.stringify({kind:'carrier-build-held',code:'CarrierActionFailed'}));process.exitCode=1;});
}
