/** Aggregate wire policy; member, manifest and historical credit limits stay
 * independent. A larger prospective archive never restores old payment. */
export const NONROOT_LEGACY_ARCHIVE_CREDIT_BYTES=33554432;
export const NONROOT_ARCHIVE_CAPACITY_V1=Object.freeze({version:1,rawBytes:33554432,wireBytes:33554432});
export const NONROOT_ARCHIVE_CAPACITY_V2=Object.freeze({version:2,rawBytes:268435456,wireBytes:402653184,documentBytes:406851584});
// Existing source bounds:4MiB manifest,20000 members,78-byte object names.
// Base64 padding contributes at most two bytes per member before expansion.
const R=NONROOT_ARCHIVE_CAPACITY_V2.rawBytes,M=4194304,N=20000;
const exportWireUpper=128+6*M+104*N+4*Math.ceil((R+2*N)/3);
export const NONROOT_CONTROL_ARCHIVE_LOCAL_V2=Object.freeze({
 extensionPasses:5,
 open:4096*(N+1)+8*(R+M)+4*exportWireUpper,
 snapshot:4*R+32*(128+N*336)+4096*N,
 reader:4*NONROOT_ARCHIVE_CAPACITY_V2.wireBytes+4096,
});
export function nonrootArchiveCapacityForVersion(version){
 if(version===1)return NONROOT_ARCHIVE_CAPACITY_V1;
 if(version===2)return NONROOT_ARCHIVE_CAPACITY_V2;
 throw Error('NonrootArchiveCapacityVersion');
}
