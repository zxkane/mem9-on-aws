import {test,afterEach,vi} from 'vitest';
import assert from 'node:assert/strict';
import http from 'node:http';
import {Resolver} from 'node:dns/promises';
import {Writable,PassThrough} from 'node:stream';
import {EventEmitter} from 'node:events';
import {peerDelivery,peerInputs} from './production-nonroot-observer-peer.fixture.mjs';
import {deriveObserverPeerInventory,inspectObserverPeerInventory,selectObserverPrivatePeer} from './lib/production-nonroot-observer-peer-inventory.mjs';
import {inspectObserverControlDelivery,observerDataHash,encodeObserverControlDelivery,bindObserverControlOverrides} from './lib/production-nonroot-observer-delivery.mjs';
import {runObserverRouteProbe} from './lib/production-nonroot-observer-route-probe.mjs';

// Only the context admission boundary is synthetic. The active route function,
// request ordering, peer selection and physical cleanup execute unchanged.
// These tests do not assert native provider/kernel admission or contact AWS.
vi.mock('./lib/production-nonroot-observer-control-context.mjs',async original=>({...await original(),requireObserverControlContext:context=>context}));
afterEach(()=>vi.restoreAllMocks());
const good='10.0.0.11',foreign='10.0.0.99';

async function transportCase(mode){
 const d=peerDelivery(),seen={signed:0,escaped:[],destroy:{request:0,response:0},off:{request:0,response:0},observations:[]};let current=true;
 const context={deliveryVersion:d.version,deliveryHash:observerDataHash(d),identity:{},assertCurrent(){assert.ok(current,'ExpiredRequest');},now:()=>Date.now(),
  beginRequest:slot=>({slot}),requestLimits:()=>({requestBytes:65536,responseBytes:1048576,deadlineMs:d.deadlineMs}),assertRequest(){context.assertCurrent();},chargeWire(){},retainIo(){},
  selectPrivatePeer:(permit,dns)=>selectObserverPrivatePeer(d,permit.slot,dns),finishRequest(_permit,row){seen.observations.push(row);},failRequest(){},
  withCredentials:fn=>fn({privateHeaders:()=>({headers:{'x-mem9-transport':'synthetic-envelope'}}),ingressHeaders:()=>({})})};
 vi.spyOn(Resolver.prototype,'resolve4').mockImplementation(async()=>{if(mode==='expired')current=false;return mode==='foreign'?[foreign]:mode==='second'?[foreign,good]:[good];});
 vi.spyOn(http,'request').mockImplementation((url,options,callback)=>{
  if(options.headers['x-mem9-transport'])seen.signed++;
  const req=new Writable({autoDestroy:false,write(_b,_e,next){next();}}),socket=new EventEmitter();options.lookup(new URL(url).hostname,{},(_e,address)=>socket.remoteAddress=address);req.socket=socket;queueMicrotask(()=>req.emit('socket',socket));
  req.once('finish',()=>queueMicrotask(()=>{
   const res=new PassThrough({autoDestroy:mode!=='off'});res.statusCode=options.headers['x-mem9-transport']?503:401;res.headers={};res.socket=socket;
   for(const [name,obj]of [['request',req],['response',res]]){
    const destroy=obj.destroy.bind(obj),off=obj.off.bind(obj);let thrown=false;
    obj.destroy=(...args)=>{seen.destroy[name]++;const result=destroy(...args);if(!thrown&&(mode==='response'&&name==='response'||mode==='wire'&&name==='request')){thrown=true;throw Error('SyntheticDestroy');}return result;};
    obj.off=(event,fn)=>{if(event==='close'){seen.off[name]++;if(mode==='off'&&name==='request')throw Error('SyntheticOff');}return off(event,fn);};
   }
   if(mode==='response')res.socket={remoteAddress:foreign};
   try{callback(res);if(mode==='wire')socket.emit('data','invalid-chunk');else if(mode!=='response')res.end('{"error":"synthetic"}');}
   catch(error){seen.escaped.push(error.message);}
  }));return req;
 });
 try{seen.result=await runObserverRouteProbe(d,context);}catch(error){seen.error=error.message;}return seen;
}

test('active CONTROL sends no authenticated headers to DNS outside the original RUNNING task',async()=>{
 const s=await transportCase('foreign');assert.equal(s.signed,0);assert.equal(s.error,'ObserverPeerRunningDestination');
});
test('active CONTROL selects the eligible second DNS address without rewriting the DNS list',async()=>{
 const s=await transportCase('second');assert.equal(s.error,undefined);assert.equal(s.signed,1);assert.equal(s.observations[1].attemptedAddress,good);assert.deepEqual(s.observations[1].dnsAddresses,[foreign,good]);
});
test('resumed expired request cannot dispatch signed headers',async()=>{
 const s=await transportCase('expired');assert.equal(s.signed,0);assert.ok(s.error);
});
for(const mode of ['response','wire'])test('active '+mode+' callback attempts both destroys without an escaping exception',async()=>{
 const s=await transportCase(mode);assert.deepEqual(s.escaped,[]);assert.ok(s.destroy.request>0&&s.destroy.response>0);assert.equal(s.error,'ObserverRouteCloseUnknown');
});
test('cleanup attempts every close-listener removal after the first removal throws',async()=>{
 const s=await transportCase('off');assert.ok(s.off.request>0&&s.off.response>0);assert.equal(s.error,'ObserverRouteCloseUnknown');
});
test('planning null never authorizes a live destination; legacy selection remains unchanged',()=>{
 const d=peerDelivery();d.peerInventory=null;assert.throws(()=>inspectObserverPeerInventory(d.peerInventory,d),/ObserverPeerInventoryRequired/);
 assert.equal(selectObserverPrivatePeer(peerDelivery(2),'private-auth',[foreign,good]),foreign);
});
for(const key of ['owner','operation','caseName','sampleIndex','sourceTree','inputHash','quoteHash'])test('peer projection rejects changed '+key,()=>{
 const d=peerDelivery();d.peerInventory[key]=key==='sampleIndex'?0:'0'.repeat(64);assert.throws(()=>inspectObserverPeerInventory(d.peerInventory,d));
});
test('complete source inventory rejects missing pages, foreign service and changed action',()=>{
 const d=peerDelivery();for(const change of [x=>x.originals.pop(),x=>x.originals[1].action='DescribeServices',x=>x.originals[1].input.serviceName='foreign',x=>x.originals[1].value.nextToken='more']){const x=peerInputs(d);change(x);assert.throws(()=>deriveObserverPeerInventory(x));}
});
test('STOPPED-only and ambiguous addresses never authorize private authentication',()=>{
 const d=peerDelivery();d.peerInventory.tasks[0].lastStatus='STOPPED';assert.throws(()=>selectObserverPrivatePeer(d,'private-auth',[good]),/ObserverPeerRunningDestination/);
 d.peerInventory.tasks[0].lastStatus='RUNNING';d.peerInventory.tasks.push({...d.peerInventory.tasks[0],taskArn:d.peerInventory.tasks[0].taskArn.replace(/b{32}$/,'c'.repeat(32))});assert.throws(()=>selectObserverPrivatePeer(d,'private-auth',[good]),/ObserverPeerAmbiguous/);
});
test('complete populated delivery fits existing encoded override bounds',()=>{
 const d=peerDelivery(),encoded=encodeObserverControlDelivery(d),o=bindObserverControlOverrides({containerOverrides:[{name:d.containerName}]},d.containerName,encoded);assert.ok(JSON.stringify(o).length<=8192);
});

test('delivery inspection rejects an accessor version without invoking it',()=>{
 let calls=0;const value={};Object.defineProperty(value,'version',{enumerable:true,get(){calls++;return 3;}});
 assert.throws(()=>inspectObserverControlDelivery(value));assert.equal(calls,0);
});
test('delivery inspection rejects a Proxy without invoking its traps',()=>{
 let calls=0;const value=new Proxy({version:3},{get(target,key){calls++;return target[key];}});
 assert.throws(()=>inspectObserverControlDelivery(value));assert.equal(calls,0);
});

for(const field of ['tasks','originals'])test('delivery inspection rejects nested '+field+' Proxy without invoking traps',()=>{
 const delivery=peerDelivery();let calls=0;
 delivery.peerInventory[field]=new Proxy(delivery.peerInventory[field],{get(target,key,receiver){calls++;return Reflect.get(target,key,receiver);}});
 assert.throws(()=>inspectObserverControlDelivery(delivery));assert.equal(calls,0);
});
