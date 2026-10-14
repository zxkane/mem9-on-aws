const need=(value,code)=>{if(!value)throw Error(code);};
const git=value=>typeof value==='string'&&/^[a-f0-9]{40}$/.test(value);

export function inspectCiSmokeCommitApi(api){
 need(api==='rest'||api==='git-database','CiSmokeCommitApi');return api;
}
export function ciSmokeCommitPath(revision,api){
 inspectCiSmokeCommitApi(api);need(git(revision),'CiSmokeCommitRevision');
 return (api==='git-database'?'git/commits/':'commits/')+revision;
}
export function ciSmokeCommitTree(commit,api){
 inspectCiSmokeCommitApi(api);
 if(!commit||typeof commit!=='object'||Array.isArray(commit))return undefined;
 // The selected endpoint determines the layout. Never guess from the fields
 // present, or admit a hybrid that can be interpreted as either API response.
 if(api==='git-database')return Object.hasOwn(commit,'commit')?undefined:commit.tree?.sha;
 return Object.hasOwn(commit,'tree')?undefined:commit.commit?.tree?.sha;
}
export function gitDatabaseCommitSource(sourceRevision,candidateRevision){
 return {api:'git-database',sourcePath:ciSmokeCommitPath(sourceRevision,'git-database'),candidatePath:ciSmokeCommitPath(candidateRevision,'git-database')};
}
export function ciSmokeProvenanceCommitApi(provenance,sourceRevision,candidateRevision){
 // Legacy authenticated provenance has no selector. The additional record
 // preserves the capture's API identity; it does not supply authorization.
 if(!Object.hasOwn(provenance,'commitSource'))return 'rest';
 const source=provenance.commitSource;
 need(source&&typeof source==='object'&&!Array.isArray(source)&&Object.keys(source).sort().join()==='api,candidatePath,sourcePath','CiSmokeCommitSource');
 const expected=gitDatabaseCommitSource(sourceRevision,candidateRevision);
 need(Object.keys(expected).every(key=>source[key]===expected[key]),'CiSmokeCommitSource');
 return 'git-database';
}
