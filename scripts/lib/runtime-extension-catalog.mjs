import {createHash} from 'node:crypto';

export function extensionVersion(value){
  if(!/^[0-9]+(?:\.[0-9]+){1,3}$/.test(value??''))throw Error('InvalidExtensionVersion');
  return value;
}
function canonical(value){
  if(Array.isArray(value))return value.map(canonical);
  if(value&&typeof value==='object')return Object.fromEntries(Object.keys(value).sort().map(key=>[key,canonical(value[key])]));
  return value;
}
export const extensionCatalogDigest=catalog=>createHash('sha256').update(JSON.stringify(canonical(catalog))).digest('hex');

export function validateExtensionCatalog(catalog){
  if(!catalog||Object.keys(catalog).sort().join()!=='availableVersions,installedVersion,ownerName,postgresVersion,reachableTargets,scratchSource')throw Error('InvalidExtensionCatalog');
  extensionVersion(catalog.postgresVersion);extensionVersion(catalog.installedVersion);extensionVersion(catalog.scratchSource);
  if(typeof catalog.ownerName!=='string'||!catalog.ownerName.length||catalog.ownerName.length>63||
    !Array.isArray(catalog.availableVersions)||!catalog.availableVersions.length||catalog.availableVersions.length>100||
    !Array.isArray(catalog.reachableTargets)||catalog.reachableTargets.length>100)throw Error('InvalidExtensionCatalog');
  for(const list of [catalog.availableVersions,catalog.reachableTargets]){
    list.forEach(extensionVersion);
    if(JSON.stringify(list)!==JSON.stringify([...new Set(list)].sort()))throw Error('InvalidExtensionCatalog');
  }
  if(catalog.reachableTargets.includes(catalog.installedVersion)||!catalog.availableVersions.includes(catalog.scratchSource))throw Error('InvalidExtensionCatalog');
  return catalog;
}

export async function readExtensionCatalog(db){
  const installed=(await db.query("SELECT extversion,extowner::regrole::text AS owner FROM pg_extension WHERE extname='vector'")).rows[0];
  if(!installed)throw Error('VectorExtensionRequired');
  const number=Number((await db.query('SHOW server_version_num')).rows[0]?.server_version_num);
  if(!Number.isInteger(number)||number<100000||number>999999)throw Error('InvalidPostgresVersion');
  const postgresVersion=Math.floor(number/10000)+'.'+(number%10000);
  const available=(await db.query("SELECT version FROM pg_available_extension_versions WHERE name='vector' ORDER BY version")).rows.map(row=>row.version);
  const reachable=(await db.query(`SELECT target FROM pg_extension_update_paths('vector')
    WHERE source=$1 AND target<>source AND path IS NOT NULL ORDER BY target`,[installed.extversion])).rows.map(row=>row.target);
  const older=(await db.query(`SELECT p.source FROM pg_extension_update_paths('vector') p
    JOIN pg_available_extension_versions v ON v.name='vector' AND v.version=p.source
    WHERE p.target=$1 AND p.source<>p.target AND p.path IS NOT NULL ORDER BY p.source DESC LIMIT 1`,[installed.extversion])).rows[0]?.source;
  return validateExtensionCatalog({postgresVersion,installedVersion:installed.extversion,ownerName:installed.owner,
    availableVersions:[...new Set(available)].sort(),reachableTargets:[...new Set(reachable)].sort(),scratchSource:older??installed.extversion});
}

export function assertExtensionMaintenance(acceptance,catalog,engineVersion){
  validateExtensionCatalog(catalog);
  const evidence=acceptance?.extensionMaintenance;
  if(acceptance?.engineVersion!==engineVersion||engineVersion!==catalog.postgresVersion||
    !evidence||!evidence.catalog||evidence.authorityVerified!==true||evidence.alterCommandAccepted!==true||evidence.vectorOperationsVerified!==true||
    evidence.createCommandAccepted!==true||evidence.dropCommandAccepted!==true||
    !['performed','no_upgrade_available'].includes(evidence.upgradeStatus)||
    extensionCatalogDigest(evidence.catalog)!==extensionCatalogDigest(catalog))throw Error('ExtensionMaintenanceEvidenceMismatch');
  // A new reachable target needs its own upgrade and restore rehearsal.
  if(catalog.reachableTargets.length)throw Error('ExtensionUpgradeRehearsalRequired');
  if(evidence.upgradeStatus==='performed'){
    if(evidence.sourceVersion===evidence.targetVersion||evidence.sourceVersion!==catalog.scratchSource||evidence.targetVersion!==catalog.installedVersion)throw Error('ExtensionUpgradeReceiptMissing');
  }else if(evidence.sourceVersion!==catalog.installedVersion||evidence.targetVersion!==catalog.installedVersion)throw Error('ExtensionUpgradeStatusMismatch');
}
