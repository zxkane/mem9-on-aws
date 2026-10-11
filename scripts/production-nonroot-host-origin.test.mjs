import {describe,it,expect} from 'vitest';
import {inspectNonrootRecord} from './lib/production-nonroot-contracts.mjs';
const h=x=>x.repeat(64),b=x=>({sha256:h(x),bytesLength:10}),j={bytesHash:h('a'),canonicalHash:h('b'),bytesLength:2};
const historical=()=>({kind:'historical-host-audit',authenticatedArchiveAnchor:j,sourceFiles:j,historicalInvocation:j,priorReview:j,exactCode:b('a'),expandedSource:b('b'),codeHash:h('a'),sourceHash:h('b')});
const derived=()=>({version:2,kind:'reviewed-derived-host-audit',ancestor:historical(),sourceFiles:j,deltaReview:j,derivation:j,exactCode:b('c'),expandedSource:b('d'),codeHash:h('c'),sourceHash:h('d')});
describe('closed historical and reviewed-derived HOST alternatives',()=>{
 it('preserves the historical record and recognizes a separately labelled descendant',()=>{
  expect(inspectNonrootRecord('LegacyHostOriginV1',historical())).toEqual(historical());
  expect(inspectNonrootRecord('CarrierHostOrigin',historical())).toEqual(historical());
  expect(inspectNonrootRecord('CarrierHostOrigin',derived())).toEqual(derived());
  expect(()=>inspectNonrootRecord('LegacyHostOriginV1',derived())).toThrow();
  expect(()=>inspectNonrootRecord('ReviewedHostOriginV2',historical())).toThrow();
 });
 it.each(['historicalInvocation','executionTest','grant','passed','futureReceipt'])('rejects %s on the static descendant',key=>{
  expect(()=>inspectNonrootRecord('ReviewedHostOriginV2',{...derived(),[key]:j})).toThrow();
 });
 it('rejects mismatched bytes, missing review and recursive/mislabelled ancestors',()=>{
  for(const mutate of [x=>x.codeHash=h('e'),x=>delete x.deltaReview,x=>x.ancestor=derived(),x=>x.kind='historical-host-audit',x=>{x.exactCode=b('a');x.codeHash=h('a');}]){const v=derived();mutate(v);expect(()=>inspectNonrootRecord('CarrierHostOrigin',v)).toThrow();}
 });
});
