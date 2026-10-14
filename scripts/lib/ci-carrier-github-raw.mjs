import {parseCiSmokeJson} from './ci-smoke-evidence.mjs';
const need=(v,c)=>{if(!v)throw Error(c);};
export function carrierArtifactLocation(value){
 const u=new URL(value);need(u.protocol==='https:'&&!u.username&&!u.password&&!u.port&&!u.hash&&/^[a-z0-9]+\.blob\.core\.windows\.net$/.test(u.hostname)&&u.pathname.length>1&&u.searchParams.has('sig')&&new Set(u.searchParams.keys()).size===[...u.searchParams.keys()].length,'CarrierArtifactSignedUrl');return u;
}
export function createCarrierGithubRaw({http,env,repository,actor,checkCredential=async()=>{}}){
 need(/^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/.test(repository)&&['ci','owner'].includes(actor),'CarrierHttpRepository');
 let token=env.GH_TOKEN??env.GITHUB_TOKEN,closed=false;need(typeof token==='string'&&token.length>0&&token.length<=65536,'CarrierHttpGithubCredential');
 const headers=async()=>{need(!closed,'CarrierHttpGithubClosed');await checkCredential();need((env.GH_TOKEN??env.GITHUB_TOKEN)===token,'CarrierHttpCredentialChanged');return {authorization:'Bearer '+token,accept:'application/vnd.github+json','user-agent':'mem9-carrier','x-github-api-version':'2026-03-10'};};
 const prefix='repos/'+repository+'/';
 const pathCheck=(path,method)=>{
  need(typeof path==='string'&&!path.includes('..')&&!path.startsWith('/')&&!/[#\\\x00-\x20]/.test(path),'CarrierHttpGithubPath');
  need(path==='user'&&actor==='owner'&&method==='GET'||path.startsWith(prefix),'CarrierHttpGithubScope');
  if(method!=='GET')need(actor==='owner'&&method==='POST'&&(path===prefix+'actions/workflows/infra-ci.yml/dispatches'||new RegExp('^'+prefix.replace(/[.*+?^${}()|[\]\\]/g,'\\$&')+'statuses/[a-f0-9]{40}$').test(path)),'CarrierHttpGithubWrite');
 };
 const decode=bytes=>parseCiSmokeJson(new TextDecoder('utf-8',{fatal:true}).decode(bytes));
 return Object.freeze({close(){closed=true;token='';},
  async api({path,method='GET',body,binary=false}){
   pathCheck(path,method);need(!body||method==='POST','CarrierHttpGithubBody');
   if(binary){need(actor==='owner'&&method==='GET'&&new RegExp('^'+prefix.replace(/[.*+?^${}()|[\]\\]/g,'\\$&')+'actions/artifacts/[1-9][0-9]*/zip$').test(path),'CarrierHttpArtifactPath');
    const first=await http.request('artifact-redirect',{url:'https://api.github.com/'+path,headers:await headers(),statuses:[302]});let url;try{url=carrierArtifactLocation(first.headers.location);}finally{first.bytes.fill(0);}
    // The delegated URL has its own original slot; never forward GitHub authorization.
    return (await http.request('artifact-download',{url:url.href,headers:{'user-agent':'mem9-carrier'},statuses:[200]})).bytes;
   }
   const r=await http.request('github',{url:'https://api.github.com/'+path,method,headers:await headers(),body:body?Buffer.from(JSON.stringify(body)):Buffer.alloc(0),statuses:method==='POST'?[200,201]:[200]});try{return decode(r.bytes);}finally{r.bytes.fill(0);}
  },
  async setSecret({name,bytes,seal}){
   need(actor==='owner'&&name==='MEM9_CARRIER_WORKER_CONFIG'&&bytes instanceof Uint8Array&&bytes.length>0&&bytes.length<=49152&&typeof seal==='function','CarrierHttpSecretInput');
   const path=prefix+'environments/preview-ci/secrets/',r=await http.request('secret-key',{url:'https://api.github.com/'+path+'public-key',headers:await headers()});let key;try{key=decode(r.bytes);}finally{r.bytes.fill(0);}
   need(typeof key.key_id==='string'&&key.key_id.length>0&&key.key_id.length<=1024&&typeof key.key==='string'&&Buffer.from(key.key,'base64').length===32&&Buffer.from(key.key,'base64').toString('base64')===key.key,'CarrierHttpSecretKey');
   const encrypted=await seal({publicKey:Buffer.from(key.key,'base64'),plaintext:bytes});need(encrypted instanceof Uint8Array&&encrypted.length===bytes.length+48,'CarrierHttpSealedSecret');
   const payload=Buffer.from(JSON.stringify({encrypted_value:Buffer.from(encrypted).toString('base64'),key_id:key.key_id}));
   try{await http.request('secret-put',{url:'https://api.github.com/'+path+name,method:'PUT',headers:{...await headers(),'content-type':'application/json'},body:payload,statuses:[201,204]});}finally{payload.fill(0);encrypted.fill(0);}
  },
 });
}
