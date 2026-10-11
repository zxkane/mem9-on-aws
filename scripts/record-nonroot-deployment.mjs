import {resolve} from 'node:path';
import {pathToFileURL} from 'node:url';
import {completeSstPostApplyCapture} from './lib/nonroot-postapply-capture.mjs';

export async function main(args=process.argv.slice(2),env=process.env){
 if(args.length!==1||args[0]!=='complete'||env.GITHUB_JOB!=='deploy-prod')throw Error('PostApplyCaptureArguments');
 return completeSstPostApplyCapture(env);
}
if(process.argv[1]&&import.meta.url===pathToFileURL(resolve(process.argv[1])).href)main().then(v=>console.log(JSON.stringify(v))).catch(()=>{console.error('PostApplyCaptureHeld');process.exitCode=1;});
