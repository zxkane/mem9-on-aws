/** Synthetic transport response mutation; never part of a production source. */
export function digestAliases(response,defect){
 const r=structuredClone(response),first=r.images[0];
 r.images=[{...first,imageId:{...first.imageId,imageTag:first.imageId.imageTag??'alias-a'}},{...first,imageId:{...first.imageId,imageTag:'alias-b'}}];
 if(defect==='top')r.unreviewed=true;
 if(defect==='image')r.images[1].unreviewed=true;
 if(defect==='id')r.images[1].imageId.unreviewed=true;
 if(defect==='bytes')r.images[1].imageManifest+=' ';
 if(defect==='scope')r.images[1].registryId='0'.repeat(12);
 if(defect==='media')r.images[1].imageManifestMediaType='application/vnd.docker.distribution.manifest.v2+json';
 return r;
}
