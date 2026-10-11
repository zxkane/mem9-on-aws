// The same bounded single-member ZIP parser used by R7. No extraction or authority.
import {inflateRawSync,crc32} from 'node:zlib';
import {parseNonrootJson} from './production-nonroot-contracts.mjs';
const need=(v,c)=>{if(!v)throw Error(c);};
const bytes=v=>{need(v instanceof Uint8Array,'CarrierArtifactBytes');return Buffer.from(v);};
const hex=v=>typeof v==='string'&&/^[a-f0-9]{64}$/.test(v);
const exact=(v,k)=>need(v&&Object.keys(v).sort().join()===k.sort().join(),'CarrierArtifactFields');
const parse=(v,maxBytes)=>parseNonrootJson(new TextDecoder('utf-8',{fatal:true}).decode(v),{maxBytes});
export function parseCarrierStartupArtifact(input){
 const b=bytes(input);need(b.length>=120&&b.length<=65536,'CiAllowanceArtifactZip');const end=b.length-22;
 need(b.readUInt32LE(end)===0x06054b50&&b.readUInt16LE(end+4)===0&&b.readUInt16LE(end+6)===0&&b.readUInt16LE(end+8)===1&&b.readUInt16LE(end+10)===1&&b.readUInt16LE(end+20)===0,'CiAllowanceArtifactZip');
 const central=b.readUInt32LE(end+16),centralSize=b.readUInt32LE(end+12);
 need(central>=30&&central+centralSize===end&&central+46<=end&&b.readUInt32LE(central)===0x02014b50,'CiAllowanceArtifactZip');
 const flags=b.readUInt16LE(central+8),method=b.readUInt16LE(central+10),crc=b.readUInt32LE(central+16),packed=b.readUInt32LE(central+20),size=b.readUInt32LE(central+24),nameLength=b.readUInt16LE(central+28),extraLength=b.readUInt16LE(central+30),commentLength=b.readUInt16LE(central+32),mode=b.readUInt32LE(central+38)>>>16;
 need([0,8,0x800,0x808].includes(flags)&&[0,8].includes(method)&&size>0&&size<=1024&&packed<=65536&&b.readUInt16LE(central+34)===0&&b.readUInt32LE(central+42)===0&&commentLength===0&&extraLength===0&&nameLength===10&&central+46+nameLength===end,'CiAllowanceArtifactZip');
 need((mode&0xf000)===0||(mode&0xf000)===0x8000,'CiAllowanceArtifactZipType');
 need(b.subarray(central+46,central+56).toString()==='claim.json'&&b.readUInt32LE(0)===0x04034b50&&b.readUInt16LE(6)===flags&&b.readUInt16LE(8)===method&&b.readUInt16LE(26)===10&&b.readUInt16LE(28)===0&&b.subarray(30,40).toString()==='claim.json','CiAllowanceArtifactZip');
 const dataEnd=40+packed;need(dataEnd<=central,'CiAllowanceArtifactZip');
 if(flags&8){
  need(b.readUInt32LE(14)===0&&b.readUInt32LE(18)===0&&b.readUInt32LE(22)===0&&central-dataEnd===16&&b.readUInt32LE(dataEnd)===0x08074b50&&b.readUInt32LE(dataEnd+4)===crc&&b.readUInt32LE(dataEnd+8)===packed&&b.readUInt32LE(dataEnd+12)===size,'CiAllowanceArtifactZip');
 }else need(dataEnd===central&&b.readUInt32LE(14)===crc&&b.readUInt32LE(18)===packed&&b.readUInt32LE(22)===size,'CiAllowanceArtifactZip');
 const payload=method===0?b.subarray(40,dataEnd):inflateRawSync(b.subarray(40,dataEnd),{maxOutputLength:1024});
 need(payload.length===size&&crc32(payload)===crc,'CiAllowanceArtifactZipIntegrity');const value=parse(payload,1024);exact(value,['nonce','scopeHash']);need(hex(value.nonce)&&hex(value.scopeHash),'CiAllowanceArtifactPayload');return value;
}
