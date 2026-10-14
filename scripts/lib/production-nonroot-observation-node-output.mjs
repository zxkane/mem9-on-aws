/** Fixed bounded writer consuming the reviewed encoder source/export. */
import {encodeObservationFrames,observationFrameEncoderSource} from './production-nonroot-observation-frames.mjs';
import * as observationOutputFs from 'node:fs';
export {observationFrameEncoderSource as observationNodeEncoderSource} from './production-nonroot-observation-frames.mjs';

/** Actual writer used by the fixed observer. All collection/helper FDs must
 * already be closed by its caller. Success here only means complete writes;
 * it cannot certify observer exit, remote log delivery or native completion. */
function nodeOutputFactory(fs,encoder){
 return async function writeNodeObservationFrames({fd,stdoutFd,binding,capture,bytes,deadlineMs}){
 const need=(v,c)=>{if(!v)throw Error(c);};
 need(Number.isSafeInteger(fd)&&fd>=0&&Number.isSafeInteger(stdoutFd)&&stdoutFd>=0&&fd!==stdoutFd,'DataObservationOutputDescriptor');
 need(Number.isSafeInteger(deadlineMs)&&Date.now()<deadlineMs,'DataObservationOutputExpired');
 const output=fs.fstatSync(fd),application=fs.fstatSync(stdoutFd);
 need(output.isFIFO()&&application.isFIFO()&&(output.dev!==application.dev||output.ino!==application.ino),'DataObservationOutputSeparation');
 const originalFlags=fs.readFileSync('/proc/self/fdinfo/'+fd,'utf8');
 const writer=fs.openSync('/proc/self/fd/'+fd,fs.constants.O_WRONLY|fs.constants.O_NONBLOCK);
 let written=0;
 try{
  const opened=fs.fstatSync(writer);
  need(opened.isFIFO()&&opened.dev===output.dev&&opened.ino===output.ino,'DataObservationOutputDescriptor');
  const frames=encoder({binding,capture,bytes});
  for(const frame of frames){
   need(Date.now()<deadlineMs,'DataObservationOutputExpired');
   need(fs.readFileSync('/proc/self/fdinfo/'+fd,'utf8')===originalFlags,'DataObservationOutputFlags');
   // Exactly one attempt. EAGAIN/short writes invalidate this capture; no
   // retry, shared-OFD flag change, unbounded buffer or renewed deadline.
   const n=fs.writeSync(writer,frame);need(n===frame.length,'DataObservationOutputShort');written+=n;
  }
  return {frames:frames.length,bytes:written};
 }finally{
  fs.closeSync(writer);
  need(fs.readFileSync('/proc/self/fdinfo/'+fd,'utf8')===originalFlags,'DataObservationOutputFlags');
 }
 };
}
export const writeNodeObservationFrames=nodeOutputFactory(observationOutputFs,encodeObservationFrames);

export function observationNodeOutputSource(){
 return observationFrameEncoderSource()+`\nimport * as observationOutputFs from 'node:fs';
const writeNodeObservationFrames=(${Function.prototype.toString.call(nodeOutputFactory)})(observationOutputFs,encodeObservationFrames);`;
}
