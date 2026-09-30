import {createHash} from 'node:crypto';

export function probeRoleName(stage){
  if(!/^pr-[1-9][0-9]*$/.test(stage??''))throw Error('PreviewAdminProbeOnly');
  return 'mem9_probe_'+createHash('sha256').update(stage).digest('hex').slice(0,12);
}

export function validateProbeCredential(stage,credential){
  if(credential?.username!==probeRoleName(stage)||!/^[A-Za-z0-9]{32,128}$/.test(credential.password??'')||
    typeof credential.salt!=='string'||credential.salt.length<16)throw Error('InvalidProbeCredential');
  return credential;
}
