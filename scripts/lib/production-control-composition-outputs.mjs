import {open,realpath} from 'node:fs/promises';
import {constants} from 'node:fs';
import {resolve,sep} from 'node:path';
import {compositionNeed as need} from './production-control-composition.mjs';
import {inspectProductionControlCompositionCommitment} from './production-control-composition-reader.mjs';
import {CONTROL_COMPOSITION_MAIN_OUTPUT_BYTES as MAX} from './production-control-composition-main-policy.mjs';

export function productionControlCompositionActionOutput(result){
 need(result&&Object.keys(result).sort().join()==='commitment,digest,imageTag,kind,version'&&[1,2].includes(result.version)&&result.kind==='native-control-composition-action-result','ControlCompositionActionResult');
 const c=inspectProductionControlCompositionCommitment(result.commitment);
 need(c.version===result.version&&result.digest===c.rootDigest&&result.imageTag==='mem9-'+c.mainRevision.slice(0,7),'ControlCompositionActionResult');
 const json=JSON.stringify(c),text='image_tag='+result.imageTag+'\ndigest='+result.digest+'\ncommitment='+json+'\n';
 const marker='MEM9_CONTROL_COMPOSITION_CAPTURE '+json;
 need(Buffer.byteLength(text)<=MAX&&Buffer.byteLength(marker)<=MAX,'ControlCompositionActionOutput');
 return Object.freeze({text,marker});
}

/** Only content-free, schema-checked outputs enter the original runner file.
 * The original composition child prepaid this bounded operation before work. */
export async function writeProductionControlCompositionActionOutput(result,env){
 const output=productionControlCompositionActionOutput(result),path=env.GITHUB_OUTPUT,root=env.RUNNER_TEMP;
 need(typeof root==='string'&&resolve(root)===root&&typeof path==='string'&&resolve(path)===path&&path.startsWith(root+sep)&&
  await realpath(root)===root&&await realpath(path)===path,'ControlCompositionOutputPath');
 const fd=await open(path,constants.O_WRONLY|constants.O_APPEND|constants.O_NOFOLLOW|constants.O_NONBLOCK);
 try{
  const s=await fd.stat();need(s.isFile()&&s.nlink===1&&s.uid===process.getuid(),'ControlCompositionOutputFile');
  await fd.writeFile(output.text);await fd.sync();
 }finally{await fd.close();}
 return output.marker;
}
