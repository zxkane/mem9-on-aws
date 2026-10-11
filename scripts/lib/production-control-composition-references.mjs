/** Exact planned-download occurrences, not a hash exemption. Callers retain
 * ordinary references (even identical ones) and independently replay the full
 * original accounting before treating any resulting proof as authenticated. */
import {copyNonrootJson,inspectNonrootRecord,nonrootHash as hash} from './production-nonroot-contracts.mjs';
import {inspectFutureFundingPlan} from './ci-smoke-grants.mjs';
import {inspectProductionControlBuildContract,inspectProductionControlCompositionRecipe} from './production-control-composition-recipe.mjs';
import {compositionNeed as need} from './production-control-composition.mjs';

export function selectProductionControlCompositionFunding({record,recordRef,contract:rawContract}){
 const contract=inspectProductionControlBuildContract(rawContract);need(contract.version===2,'ControlCompositionDescriptorVersion');
 inspectNonrootRecord('JsonRef',recordRef);need(hash(record)===recordRef.canonicalHash&&record.version===3&&record.kind==='nonroot-cache-read-accounting'&&Array.isArray(record.fundingPlans)&&Array.isArray(record.events),'ControlCompositionDescriptorAccounting');
 const expected={repository:contract.repository,prNumber:contract.prNumber,candidateRevision:contract.candidate.revision,candidateTree:contract.candidate.tree,baseRevision:contract.candidate.baseRevision};
 const descriptors=[];let matched=0,selection;
 for(const [i,raw]of record.fundingPlans.entries()){
  const f=inspectFutureFundingPlan(raw);
  for(const [j,consumer]of f.plan.consumers.entries()){
   if(!consumer.composition)continue;
   need(++matched===1&&hash(f.plan.source)===hash(expected),'ControlCompositionDescriptorSource');
   const p=consumer.composition.plan;
   inspectProductionControlCompositionRecipe(contract.recipe,{plan:p});
   need(p.input.base.image.account===contract.output.account&&p.input.base.image.region===contract.output.region,'ControlCompositionDescriptorScope');
   const paid=record.events.filter(e=>e.type==='prepayment'&&e.data.planHash===f.planHash);
   need(paid.length===1&&hash(paid[0].data)===hash({allocationId:f.planHash,planHash:f.planHash,scopeHash:f.scopeHash,charge:f.budget,reserveDebit:f.budget}),'ControlCompositionDescriptorPrepayment');
   selection={grantSetId:f.plan.grantSetId,plan:p,fundingPlanHash:f.planHash};
   for(const name of Object.keys(p.input.packs))descriptors.push({document:recordRef,path:['fundingPlans',String(i),'consumers',String(j),'composition','plan','input','packs',name,'ref'],ref:p.input.packs[name].ref,
    compositionPlanHash:p.planHash,fundingPlanHash:f.planHash});
  }
 }
 need(matched===1,'ControlCompositionDescriptorRequired');return copyNonrootJson({...selection,descriptors});
}
export function inspectProductionControlCompositionPackDescriptors(input){
 if(inspectProductionControlBuildContract(input.contract).version===1)return Object.freeze([]);
 return selectProductionControlCompositionFunding(input).descriptors;
}
export function isProductionControlCompositionPackDescriptor(rows,document,path,value){
 const found=rows.filter(r=>hash(r.document)===document&&r.path.length===path.length&&r.path.every((p,i)=>p===path[i]));
 if(!found.length)return false;need(found.length===1,'ControlCompositionDescriptorAmbiguous');
 inspectNonrootRecord('ByteRef',value);need(hash(found[0].ref)===hash(value),'ControlCompositionDescriptorChanged');return true;
}
