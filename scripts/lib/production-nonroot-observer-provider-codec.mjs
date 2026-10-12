/** The installed observer's JSON SDK codec, used without a service client,
 * credential provider, transport, request, or reconstructed runtime handle. */
import {hasObserverSdkAction,decodeObserverSdkResponse} from './production-nonroot-observer-sdk.mjs';
import {parseAcquisitionJson} from './ci-smoke-acquisition-format.mjs';
import {need} from './production-nonroot-engineering-json.mjs';

export async function decodeArchivedObserverProviderResponse(action,raw,{reader,region}){
 reader.current();reader.paid.debit(131072);reader.current();
 need(hasObserverSdkAction(action)&&raw instanceof Uint8Array&&raw.byteLength<=33554432,'ObserverArchivedCodecInput');
 // Region stays an explicit scope binding even though this codec does no IO.
 need(typeof region==='string'&&/^[a-z]{2}(?:-[a-z]+)+-[0-9]+$/.test(region),'ObserverArchivedCodecRegion');
 reader.paid.debit(64*raw.byteLength+65536);reader.current();
 if(raw.byteLength===0)return {};
 parseAcquisitionJson(raw,33554432);
 // The string branch runs the original reviver/schema synchronously; the
 // resumed caller checks the same payer before encoding decoded Date values.
 const value=await decodeObserverSdkResponse(action,new TextDecoder('utf-8',{fatal:true}).decode(raw));
 reader.current();
 need(value&&typeof value==='object'&&!Array.isArray(value),'ObserverArchivedSdkResponseShape');
 const result=JSON.parse(JSON.stringify(value,(key,v)=>key==='$metadata'?undefined:v));
 reader.current();return result;
}
