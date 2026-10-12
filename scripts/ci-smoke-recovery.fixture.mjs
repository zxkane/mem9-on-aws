// Synthetic Git-backed tests use exact reviewed recovery preimages. The
// committed fixture keeps clean/shallow checkouts independent of Git history;
// it does not update production policy or approve current recovery source.
import {readFileSync} from 'node:fs';
import {createHash} from 'node:crypto';

export function readReviewedRecoveryFixture(pin,checkoutBytes,readFixture=readFileSync){
  const missing=cause=>Error('ReviewedRecoveryFixtureBytesMissing:'+pin.path,{cause});
  if(!/^[a-f0-9]{64}$/.test(pin.sha256)||!Number.isSafeInteger(pin.bytes)||pin.bytes<1||pin.bytes>16*1024*1024)throw missing();
  const matches=bytes=>Buffer.isBuffer(bytes)&&bytes.length===pin.bytes&&createHash('sha256').update(bytes).digest('hex')===pin.sha256;
  if(matches(checkoutBytes))return checkoutBytes;
  let bytes;
  try{bytes=readFixture(new URL('./fixtures/ci-smoke-recovery/'+pin.sha256+'.txt',import.meta.url));}
  catch(error){throw missing(error);}
  if(!matches(bytes))throw missing();
  return bytes;
}
