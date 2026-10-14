import {describe,it,expect} from 'vitest';
import {readFileSync} from 'node:fs';
import {createHash} from 'node:crypto';
import {readReviewedRecoveryFixture} from './ci-smoke-recovery.fixture.mjs';
import {CI_SMOKE_POLICY} from './lib/ci-smoke-policy.mjs';
const pins=[...new Map(CI_SMOKE_POLICY.rows.filter(row=>row.rule.kind==='safe-recovery').flatMap(row=>row.rule.entryFiles).map(pin=>[pin.path,pin])).values()];
const pin=pins.find(p=>p.path==='scripts/lib/production-image-deployment-bundle.mjs');
const sha=b=>createHash('sha256').update(b).digest('hex');
describe('reviewed recovery fixture bytes',()=>{
  it('keeps exact checkout bytes without consulting a fallback',()=>{
    const original=readReviewedRecoveryFixture(pin,Buffer.from('different checkout'));
    expect(readReviewedRecoveryFixture(pin,original,()=>{throw Error('unexpected fallback');})).toBe(original);
  });
  it('loads committed reviewed bytes for changed checkout source, without repository history',()=>{
    const bytes=readReviewedRecoveryFixture(pin,Buffer.from('changed implementation'));
    expect(bytes.length).toBe(pin.bytes);expect(sha(bytes)).toBe(pin.sha256);
  });
  it('supplies every policy pin from current checkout or the exact retained preimage',()=>{
    for(const row of pins){const bytes=readReviewedRecoveryFixture(row,readFileSync(new URL('../'+row.path,import.meta.url)));expect(bytes.length).toBe(row.bytes);expect(sha(bytes)).toBe(row.sha256);}
  });
  it('rejects corrupted and wrong-length retained bytes',()=>{
    const original=readReviewedRecoveryFixture(pin,Buffer.from('changed implementation'));
    const corrupt=Buffer.from(original);corrupt[0]^=1;
    for(const bytes of [corrupt,original.subarray(1)])expect(()=>readReviewedRecoveryFixture(pin,Buffer.from('changed'),()=>bytes)).toThrow('ReviewedRecoveryFixtureBytesMissing:'+pin.path);
    expect(()=>readReviewedRecoveryFixture({...pin,bytes:pin.bytes+1},Buffer.from('changed'))).toThrow('ReviewedRecoveryFixtureBytesMissing:'+pin.path);
  });
  it('rejects an absent or invalid preimage instead of accepting current bytes',()=>{
    expect(()=>readReviewedRecoveryFixture({...pin,sha256:'0'.repeat(64)},Buffer.from('changed'))).toThrow('ReviewedRecoveryFixtureBytesMissing:'+pin.path);
    expect(()=>readReviewedRecoveryFixture({...pin,sha256:'../unreviewed'},Buffer.from('changed'))).toThrow('ReviewedRecoveryFixtureBytesMissing:'+pin.path);
  });
});
