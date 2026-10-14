import {afterEach,expect,it,vi} from 'vitest';
import {measureNonrootDataFacts,copyNonrootDataFacts} from './lib/production-nonroot-data-facts-work.mjs';

afterEach(()=>vi.restoreAllMocks());
it('matches encoded JSON bytes and the documented tariff for a small independent example',()=>{
 const value={title:'é',flags:[true,null]},bytes=Buffer.byteLength(JSON.stringify(value));let used=0;
 const paid={current(){},debit(n){used+=n;}};
 expect(measureNonrootDataFacts(value,paid)).toEqual({bytes,nodes:5});expect(used).toBe(344);
 const before=used,copy=copyNonrootDataFacts(value,paid);expect(copy).toEqual(value);
 expect(used-before).toBe(344+8*bytes+32*5);copy.flags[0]=false;expect(value.flags[0]).toBe(true);
});
it.each([
 {name:'escaped characters',value:'"\\\0\n'},
 {name:'Unicode and a lone surrogate',value:'😀é中\ud800'},
 {name:'numeric array',value:[0,-0,1e30,0.000001,false,null]},
])('measures JSON encoding without losing data: $name',({value})=>{
 const paid={current(){},debit(){}};
 expect(measureNonrootDataFacts(value,paid).bytes).toBe(Buffer.byteLength(JSON.stringify(value)));
 expect(copyNonrootDataFacts(value,paid)).toEqual(value);
});
it('retains the full filesystem domain beyond small proof JSON byte and node limits',()=>{
 const value=Array.from({length:65536},(_,i)=>({path:'synthetic/'+String(i)+'x'.repeat(64)}));
 const bytes=Buffer.byteLength(JSON.stringify(value));expect(bytes).toBeGreaterThan(4*1024*1024);
 const geometry=measureNonrootDataFacts(value,{current(){},debit(){}});
 expect(geometry.bytes).toBe(bytes);expect(geometry.nodes).toBeGreaterThan(100000);
});
it('rejects a final-copy budget one unit short before cloning and retains previous debits',()=>{
 const value={title:'é',flags:[true,null]},limit=344+8*Buffer.byteLength(JSON.stringify(value))+32*5-1;
 let used=0;const clone=vi.spyOn(globalThis,'structuredClone');
 expect(()=>copyNonrootDataFacts(value,{current(){},debit(n){if(used+n>limit)throw Error('SyntheticBudgetShort');used+=n;}})).toThrow('SyntheticBudgetShort');
 expect(clone).not.toHaveBeenCalled();expect(used).toBe(344);
});
it('rejects owner retirement by a successful debit before covered traversal or clone',()=>{
 let closed=false,used=0;const clone=vi.spyOn(globalThis,'structuredClone');
 expect(()=>copyNonrootDataFacts({value:'synthetic'},{current(){if(closed)throw Error('SyntheticClosed');},debit(n){used+=n;closed=true;}})).toThrow('SyntheticClosed');
 expect(used).toBeGreaterThan(0);expect(clone).not.toHaveBeenCalled();
});
it('rechecks original work after the actual clone and keeps every paid unit',()=>{
 const value={title:'é',flags:[true,null]},clone=globalThis.structuredClone;let used=0,closed=false;
 vi.spyOn(globalThis,'structuredClone').mockImplementation(v=>{const result=clone(v);closed=true;return result;});
 expect(()=>copyNonrootDataFacts(value,{current(){if(closed)throw Error('SyntheticClosed');},debit(n){used+=n;}})).toThrow('SyntheticClosed');
 expect(used).toBe(344+8*Buffer.byteLength(JSON.stringify(value))+32*5);
});
it('rejects getters and sparse arrays without invoking code or cloning partial data',()=>{
 const getter=vi.fn(()=> 'not DATA'),value=Object.defineProperty({},'value',{enumerable:true,get:getter}),clone=vi.spyOn(globalThis,'structuredClone');
 for(const input of [value,new Array(2)])expect(()=>copyNonrootDataFacts(input,{current(){},debit(){}})).toThrow('NonrootDataFactsFilesystemValue');
 expect(getter).not.toHaveBeenCalled();expect(clone).not.toHaveBeenCalled();
});
