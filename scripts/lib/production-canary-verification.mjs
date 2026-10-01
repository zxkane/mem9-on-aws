import {isDeepStrictEqual} from 'node:util';
import {createHash} from 'node:crypto';

const canonical=value=>Array.isArray(value)?value.map(canonical):value&&typeof value==='object'?Object.fromEntries(Object.keys(value).sort().map(key=>[key,canonical(value[key])])):value;
export const canaryEvidenceHash=value=>createHash('sha256').update(JSON.stringify(canonical(value))).digest('hex');

const fail=()=>{throw Error('ProductionCanaryReceiptMismatch');};
const object=value=>value&&typeof value==='object'&&!Array.isArray(value);
const without=(value,keys)=>Object.fromEntries(Object.entries(value).filter(([key])=>!keys.includes(key)));
function byId(rows){
  if(!Array.isArray(rows))fail();
  const map=new Map(rows.map(row=>[row?.id,row]));
  if(map.size!==rows.length||[...map.keys()].some(id=>typeof id!=='string'||!id))fail();return map;
}
function sameRows(left,right){
  const a=byId(left),b=byId(right);
  return a.size===b.size&&[...a].every(([id,row])=>isDeepStrictEqual(row,b.get(id)));
}
function protectedRow(row){
  const tags=row.tags??[];
  const tagged=Array.isArray(tags)?tags.some(tag=>['protected','pinned'].includes(tag)):
    typeof tags==='string'?['protected','pinned'].includes(tags):object(tags)&&['protected','pinned'].some(key=>Object.hasOwn(tags,key));
  return row.memory_type!=='insight'||(row.metadata?.protected!=null&&String(row.metadata.protected)!=='false')||tagged;
}

export function verifyProtectedCanaryBaseline(baseline,currentRows){
  const reject=()=>{throw Error('ProtectedCanaryBaselineChanged');};
  const index=rows=>{
    if(!Array.isArray(rows)||rows.length>100000)reject();
    const entries=rows.map(row=>{
      if(typeof row?.id!=='string'||!row.id||typeof row.namespace_id!=='string'||!row.namespace_id||!/^[a-f0-9]{64}$/.test(row.digest??''))reject();
      return [row.namespace_id+'/'+row.id,row.digest];
    });
    const map=new Map(entries);if(map.size!==rows.length)reject();return map;
  };
  const before=index(baseline),after=index(currentRows);
  // Last-writer metadata cannot rule out an earlier forbidden update. A
  // legitimate foreground edit therefore leaves this proof indeterminate.
  for(const [key,digest] of before)if(after.get(key)!==digest)reject();
  return {protectedRows:before.size};
}

// Runs only inside the owned AWS administrative task. Raw before/post images
// never leave that task; callers receive counts and an opaque receipt-set hash.
export function verifyCanaryReceipt(receipt,action,currentRows){
  const before=receipt.before_images,after=receipt.post_images;
  if(action.kind!=='MERGE'||receipt.result?.status!=='applied'||!Array.isArray(before)||before.length<2||before.length>10||
    !sameRows(before,action.members)||!sameRows(after,currentRows)||before.length!==after.length||
    receipt.result.changed_rows!==before.length||action.cost?.total!==before.length||action.cost.archive!==0||action.cost.mark!==0)fail();
  const prior=byId(before),post=byId(after),target=action.output?.target;
  if(!prior.has(target)||[...prior.keys()].some(id=>!post.has(id)))fail();
  const targetBefore=prior.get(target),targetAfter=post.get(target);
  let expectedContent=targetBefore.content;
  if(!before.every(row=>typeof row.content==='string'&&expectedContent.includes(row.content))){
    const unique=new Map();
    const ordered=[...before].sort((a,b)=>String(a.created_at??'\uffff').localeCompare(String(b.created_at??'\uffff'))||a.id.localeCompare(b.id));
    for(const row of ordered)if(!unique.has(row.content))unique.set(row.content,row);
    expectedContent=[...unique.values()].map(row=>row.content).join('\n\n');
  }
  if(action.output.content!==expectedContent)fail();
  if(before.some(row=>row.namespace_id!==receipt.namespace_id||row.state!=='active'||protectedRow(row)||
      typeof row.content!=='string'||!action.output.content.includes(row.content)))fail();
  if(!object(targetAfter.metadata)||!object(targetAfter.metadata.consolidation)||targetAfter.state!=='active'||targetAfter.content!==action.output.content||
    !isDeepStrictEqual(targetAfter.tags,action.output.tags)||!isDeepStrictEqual(targetAfter.metadata,action.output.metadata)||
    !isDeepStrictEqual(targetAfter.tags,targetBefore.tags??[])||
    !isDeepStrictEqual(without(targetAfter.metadata,['consolidation']),without(targetBefore.metadata??{},['consolidation']))||
    !isDeepStrictEqual(without(targetAfter.metadata?.consolidation??{},['sources']),without(targetBefore.metadata?.consolidation??{},['sources']))||
    !object(targetAfter.metadata?.consolidation)||
    !sameRows(targetAfter.metadata.consolidation.sources,before.map(row=>without(row,['embedding']))))fail();
  for(const [id,row] of prior){
    const actual=post.get(id);
    if(actual.namespace_id!==row.namespace_id||actual.version!==row.version+1)fail();
    if(id===target){
      if(!isDeepStrictEqual(without(row,['content','tags','metadata','embedding','version','updated_at','updated_by_principal_id']),
        without(actual,['content','tags','metadata','embedding','version','updated_at','updated_by_principal_id'])))fail();
      if(action.cost.rewrite===0&&!isDeepStrictEqual(row.embedding,actual.embedding))fail();
    }else{
      if(actual.state!=='deleted'||actual.superseded_by!==target||
        !isDeepStrictEqual(without(row,['state','superseded_by','version','updated_at','updated_by_principal_id']),
          without(actual,['state','superseded_by','version','updated_at','updated_by_principal_id'])))fail();
    }
  }
  return {changedRows:before.length,sourceRows:before.length-1};
}

export function verifyCanaryReceiptChains(entries,currentRows){
  if(!Array.isArray(entries)||!entries.length||entries.length>20)fail();
  const histories=new Map();let changedRows=0,sourceRows=0;
  for(const {receipt,action} of entries){
    const result=verifyCanaryReceipt(receipt,action,receipt.post_images);
    changedRows+=result.changedRows;sourceRows+=result.sourceRows;
    const after=byId(receipt.post_images);
    for(const before of receipt.before_images){
      const key=receipt.namespace_id+'/'+before.id,list=histories.get(key)??[];
      list.push({before,after:after.get(before.id)});histories.set(key,list);
    }
  }
  if(changedRows>20)fail();
  const current=new Map(currentRows.map(row=>[row.namespace_id+'/'+row.id,row]));
  if(current.size!==histories.size)fail();
  for(const [key,history] of histories){
    history.sort((a,b)=>a.before.version-b.before.version);
    for(let i=1;i<history.length;i++)if(!isDeepStrictEqual(history[i-1].after,history[i].before))fail();
    if(!isDeepStrictEqual(history.at(-1).after,current.get(key)))fail();
  }
  return {receipts:entries.length,changedRows,sourceRows};
}
