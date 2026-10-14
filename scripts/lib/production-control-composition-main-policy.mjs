// Closed entry/output work, added once to the prospective CI child before
// its original payment. Eight bounded processing passes plus eight file
// metadata operations cover validation, JSON/output framing and publication.
export const CONTROL_COMPOSITION_MAIN_OUTPUT_BYTES=16384;
export const CONTROL_COMPOSITION_MAIN_OUTPUT_CHARGE=Object.freeze({
 ecrRequests:0,httpBodyBytes:0,uncompressedBytes:0,processedEntries:0,
 logicalBytes:8*CONTROL_COMPOSITION_MAIN_OUTPUT_BYTES+8*4096,
});
