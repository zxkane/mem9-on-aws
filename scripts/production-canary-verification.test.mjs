import {describe,it,expect} from 'vitest';
import {verifyCanaryReceipt,verifyCanaryReceiptChains,verifyProtectedCanaryBaseline} from './lib/production-canary-verification.mjs';
function fixture(){
  const before=['a','b'].map(id=>({id,namespace_id:'namespace',state:'active',memory_type:'insight',content:'Synthetic fact',tags:[],metadata:{},embedding:'[1,0,0]',version:1,superseded_by:null}));
  const sources=before.map(({embedding,...row})=>row);
  const output={target:'a',content:'Synthetic fact',tags:[],metadata:{consolidation:{sources}}};
  const after=[{...before[0],...output,metadata:output.metadata,version:2},{...before[1],state:'deleted',superseded_by:'a',version:2}];
  delete after[0].target;
  const action={kind:'MERGE',members:before,output,cost:{total:2,rewrite:0,delete:1,archive:0,mark:0}};
  return {receipt:{namespace_id:'namespace',result:{status:'applied',changed_rows:2},before_images:before,post_images:after},action,current:structuredClone(after)};
}
describe('real-data canary receipt verification',()=>{
  it('verifies lossless provenance, unchanged vectors and the actual committed post-image',()=>{
    const f=fixture();expect(verifyCanaryReceipt(f.receipt,f.action,f.current)).toEqual({changedRows:2,sourceRows:1});
  });
  it.each(['content','embedding','provenance','protected','current','count'])('rejects corrupted %s evidence',kind=>{
    const f=fixture();
    if(kind==='content')f.action.output.content='Lost fact';
    if(kind==='embedding')f.receipt.post_images[0].embedding='[0,1,0]';
    if(kind==='provenance')f.receipt.post_images[0].metadata.consolidation.sources=[];
    if(kind==='protected')f.receipt.before_images[0].memory_type='pinned';
    if(kind==='current')f.current[0].version=3;
    if(kind==='count')f.receipt.result.changed_rows=1;
    expect(()=>verifyCanaryReceipt(f.receipt,f.action,f.current)).toThrow('ProductionCanaryReceiptMismatch');
  });
  it('checks each survivor version chain and compares only its final post-image to current data',()=>{
    const first=fixture(),second=fixture();
    const survivor=structuredClone(first.receipt.post_images[0]);
    const donor={...structuredClone(first.receipt.before_images[1]),id:'c'};
    second.receipt.before_images=[survivor,donor];second.action.members=second.receipt.before_images;
    second.action.output.metadata={...survivor.metadata,consolidation:{sources:second.receipt.before_images.map(({embedding,...row})=>row)}};
    second.receipt.post_images=[{...survivor,metadata:second.action.output.metadata,version:3},{...donor,state:'deleted',superseded_by:'a',version:2}];
    const current=[second.receipt.post_images[0],first.receipt.post_images[1],second.receipt.post_images[1]];
    const entries=[{receipt:second.receipt,action:second.action},{receipt:first.receipt,action:first.action}];
    expect(verifyCanaryReceiptChains(entries,current)).toEqual({receipts:2,changedRows:4,sourceRows:2});
    second.receipt.before_images[0].version=9;
    expect(()=>verifyCanaryReceiptChains(entries,current)).toThrow('ProductionCanaryReceiptMismatch');
  });
});
describe('protected memory canary baseline',()=>{
  const baseline=()=>[{id:'protected',namespace_id:'namespace',digest:'a'.repeat(64)}];
  it('requires the original protected rows unchanged while permitting later additions',()=>{
    expect(verifyProtectedCanaryBaseline(baseline(),[...baseline(),{id:'later',namespace_id:'namespace',digest:'b'.repeat(64)}])).toEqual({protectedRows:1});
  });
  it.each(['missing','changed','namespace','duplicate'])('keeps promotion closed for %s protected baseline evidence',kind=>{
    const before=baseline(),after=baseline();
    if(kind==='missing')after.length=0;
    if(kind==='changed')Object.assign(after[0],{digest:'b'.repeat(64),version:3,updated_by_principal_id:'foreground'});
    if(kind==='namespace')after[0].namespace_id='another';
    if(kind==='duplicate')after.push({...after[0]});
    expect(()=>verifyProtectedCanaryBaseline(before,after)).toThrow('ProtectedCanaryBaselineChanged');
  });
});
