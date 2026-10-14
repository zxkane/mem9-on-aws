import {it,expect} from 'vitest';
import {previewPostRuntimeFixture} from './production-nonroot-preview-provider.fixture.mjs';
import {collectPreviewPostRuntimeFacts} from './lib/production-nonroot-preview-postruntime.mjs';
const scope={stage:'pr-7',account:'123456789012',region:'ap-northeast-1',sourceTree:'a'.repeat(40)};
it('checks common authority once and every distinct exact purpose definition',async()=>{
 const f=previewPostRuntimeFixture(scope),facts=await collectPreviewPostRuntimeFacts(f);
 expect(facts['post-runtime-fixture-route'].bindings).toHaveLength(5);
 expect(f.calls.filter(c=>c.api==='GetRoleCommand')).toHaveLength(2);
 expect(f.calls.filter(c=>c.api==='DescribeTaskDefinitionCommand')).toHaveLength(5);
 expect(f.calls.some(c=>c.api==='RunTaskCommand'||c.api==='GetParametersCommand')).toBe(false);
});
it('does not invent routes for an absent post-runtime deployment',async()=>{
 const f=previewPostRuntimeFixture(scope);f.parameters.clear();expect(await collectPreviewPostRuntimeFacts(f)).toEqual({});expect(f.calls).toEqual([]);
});
it.each(['source','state','definition','policy'])('rejects %s drift without falling back to another route',async defect=>{
 const f=previewPostRuntimeFixture(scope);
 if(defect==='source')f.scope={...scope,sourceTree:'b'.repeat(40)};
 if(defect==='state'){const p=f.parameters.get('/mem9-on-aws/pr-7/runtime/production-state');p.Value=JSON.stringify({...JSON.parse(p.Value),phase:'applying'});}
 if(defect==='definition'){const [arn,old]=f.guarded.definitions.entries().next().value,value=structuredClone(old);value.taskDefinition.containerDefinitions[0].user='0';f.guarded.definitions.set(arn,value);}
 if(defect==='policy'){const send=f.send;f.send=async(service,command)=>command.constructor.name==='ListRolePoliciesCommand'?{PolicyNames:['unreviewed'],IsTruncated:false}:send(service,command);}
 await expect(collectPreviewPostRuntimeFacts(f)).rejects.toThrow();
});
