import {createHash} from 'node:crypto';

export function canaryBenchmarkContent(validationId,phase,index,warmup=false){
  if(!/^[a-f0-9]{32}$/.test(validationId??'')||!['baseline','loaded'].includes(phase)||!Number.isInteger(index)||index<0||index>=500)throw Error('McpCanaryFailure');
  return `Synthetic memory benchmark ${validationId} ${phase.padEnd(8,'_')} ${warmup?'warmup':'sample'} ${String(index).padStart(3,'0')}. This record is temporary validation data.`;
}

export function canaryBenchmarkHashes(validationId){
  const hashes=new Set();
  for(const phase of ['baseline','loaded'])for(const warmup of [false,true])for(let index=0;index<(warmup?5:500);index++){
    hashes.add(createHash('sha256').update(canaryBenchmarkContent(validationId,phase,index,warmup)).digest('hex'));
  }
  return hashes;
}
