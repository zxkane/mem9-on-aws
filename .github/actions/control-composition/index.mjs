import {fileURLToPath} from 'node:url';
import {runProductionControlCompositionMain} from '../../../scripts/lib/production-control-composition-main.mjs';
import {writeProductionControlCompositionActionOutput} from '../../../scripts/lib/production-control-composition-outputs.mjs';
export {runProductionControlCompositionMain};

if(process.argv[1]===fileURLToPath(import.meta.url)){
 const controller=new AbortController(),cancel=()=>controller.abort(Error('ControlCompositionActionCancelled'));
 process.once('SIGINT',cancel);process.once('SIGTERM',cancel);
 try{
  if(process.argv.length!==2)throw Error('ControlCompositionActionArguments');
  const result=await runProductionControlCompositionMain({env:process.env,signal:controller.signal});
  controller.signal.throwIfAborted();
  const marker=await writeProductionControlCompositionActionOutput(result,process.env);
  controller.signal.throwIfAborted();console.log(marker);
 }catch{
  console.error(JSON.stringify({kind:'native-control-composition-held',code:'ControlCompositionActionFailed'}));process.exitCode=1;
 }finally{process.off('SIGINT',cancel);process.off('SIGTERM',cancel);}
}
