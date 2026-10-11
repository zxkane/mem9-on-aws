/** Fixed STS response grammar before the SDK XML decoder. In particular,
 * attributes cannot shadow modeled children and entity/DTD expansion is not
 * a second, unbounded input channel. Namespace metadata is root-only. */
export function inspectCompositionStsXml(bytes,action){
 const fail=()=>{throw Error('ControlCompositionStsXml');};
 if(!(bytes instanceof Uint8Array)||bytes.length>131072||!['AssumeRoleWithWebIdentity','GetCallerIdentity'].includes(action))fail();
 let text=new TextDecoder('utf-8',{fatal:true}).decode(bytes).trim();
 text=text.replace(/^<\?xml\s+version=(["'])1\.0\1(?:\s+encoding=(["'])UTF-8\2)?\s*\?>\s*/i,'');
 if(/<!|<\?/.test(text))fail();
 const root=action+'Response',result=action+'Result';
 const children={
  [root]:new Set([result,'ResponseMetadata']),ResponseMetadata:new Set(['RequestId']),
  [result]:new Set(action==='GetCallerIdentity'?['Account','Arn','UserId']:
   ['Credentials','AssumedRoleUser','SubjectFromWebIdentityToken','Audience','Provider','PackedPolicySize']),
  Credentials:new Set(['AccessKeyId','SecretAccessKey','SessionToken','Expiration']),AssumedRoleUser:new Set(['Arn','AssumedRoleId']),
 };
 const stack=[];let at=0,count=0,ended=false;
 const re=/<(\/?)([A-Za-z][A-Za-z0-9]*)([^>]*)>/g;
 for(const match of text.matchAll(re)){
  const gap=text.slice(at,match.index);if(gap.includes('<')||gap.includes('>')||(!stack.length&&gap.trim()))fail();
  if(stack.length&&children[stack.at(-1).name]&&gap.trim())fail();
  at=match.index+match[0].length;if(++count>128)fail();
  const [,closing,name,tail]=match;
  if(closing){if(tail.trim()||stack.at(-1)?.name!==name)fail();stack.pop();if(!stack.length)ended=true;continue;}
  if(ended||stack.length>8)fail();
  const empty=/\/\s*$/.test(tail),attributes=empty?tail.replace(/\/\s*$/,''):tail;
  if(!stack.length){
   if(name!==root)fail();
   if(attributes.trim()&&!/^\s+xmlns=(["'])https:\/\/sts\.amazonaws\.com\/doc\/2011-06-15\/\1\s*$/.test(attributes))fail();
  }else{
   if(attributes.trim())fail();
   const parent=stack.at(-1);if(!children[parent.name]?.has(name)||parent.seen.has(name))fail();parent.seen.add(name);
  }
  if(!empty)stack.push({name,seen:new Set()});else if(!stack.length)ended=true;
 }
 if(!ended||stack.length||text.slice(at).trim())fail();
 return true;
}
