import {describe,it,expect} from 'vitest';
import {assertExtensionMaintenance,extensionCatalogDigest,validateExtensionCatalog} from './lib/runtime-extension-catalog.mjs';
const catalog={postgresVersion:'17.4',installedVersion:'0.8.0',ownerName:'rdsadmin',availableVersions:['0.8.0'],reachableTargets:[],scratchSource:'0.8.0'};
const evidence={catalog,authorityVerified:true,alterCommandAccepted:true,vectorOperationsVerified:true,createCommandAccepted:true,dropCommandAccepted:true,
  upgradeStatus:'no_upgrade_available',sourceVersion:'0.8.0',targetVersion:'0.8.0'};
const acceptance={engineVersion:'17.4',extensionMaintenance:evidence};
describe('extension maintenance release evidence',()=>{
  it('certifies only the exact current tuple when no upgrade exists',()=>{
    expect(()=>assertExtensionMaintenance(acceptance,catalog,'17.4')).not.toThrow();
    expect(extensionCatalogDigest(catalog)).toBe(extensionCatalogDigest(Object.fromEntries(Object.entries(catalog).reverse())));
  });
  it.each([
    {postgresVersion:'17.5'}, {installedVersion:'0.8.1'}, {ownerName:'other'},
    {availableVersions:['0.7.0','0.8.0']}, {reachableTargets:['0.8.1']},
  ])('rejects live tuple drift %o',patch=>{
    expect(()=>assertExtensionMaintenance(acceptance,{...catalog,...patch},'17.4')).toThrow();
  });
  it('does not equate unchanged catalogs with authority or a real version upgrade',()=>{
    expect(()=>assertExtensionMaintenance({...acceptance,extensionMaintenance:{...evidence,alterCommandAccepted:false}},catalog,'17.4')).toThrow();
    expect(()=>assertExtensionMaintenance({...acceptance,extensionMaintenance:{...evidence,upgradeStatus:'performed'}},catalog,'17.4')).toThrow('ExtensionUpgradeReceiptMissing');
  });
  it('blocks a reachable new target even if a stale operator flag says no upgrade',()=>{
    const current={...catalog,reachableTargets:['0.8.1']};
    expect(()=>assertExtensionMaintenance({...acceptance,extensionMaintenance:{...evidence,catalog:current}},current,'17.4')).toThrow('ExtensionUpgradeRehearsalRequired');
  });
  it('rejects malformed or unsorted catalog fields',()=>{
    expect(()=>validateExtensionCatalog({...catalog,availableVersions:['0.8.0','0.7.0']})).toThrow();
    expect(()=>validateExtensionCatalog({...catalog,installedVersion:"0.8.0'; unsafe"})).toThrow();
  });
});
