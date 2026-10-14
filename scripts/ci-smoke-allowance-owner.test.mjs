import {it,expect,vi} from 'vitest';
import {respondCiOwnerAllowance} from './lib/ci-smoke-allowance-owner.mjs';

it.each([undefined,{}, {kind:'ci-owner-publication-preparation'}, {verified:true}])('rejects a serialized preparation before GitHub or AWS (%j)',async preparation=>{
 const githubApi=vi.fn(),downloadArtifact=vi.fn(),requestHandler={handle:vi.fn(),destroy:vi.fn()};
 await expect(respondCiOwnerAllowance({preparation,config:{},scope:{},grantSet:{},roleArn:'unused',credentialsRef:{},maximumExpiresMs:1},{githubApi,downloadArtifact,requestHandler})).rejects.toThrow('CiOwnerPreparationRequired');
 expect(githubApi).not.toHaveBeenCalled();expect(downloadArtifact).not.toHaveBeenCalled();expect(requestHandler.handle).not.toHaveBeenCalled();
});
it('rejects a caller-selected operation or state directory before transport',async()=>{
 const githubApi=vi.fn();await expect(respondCiOwnerAllowance({preparation:{},config:{},scope:{},grantSet:{},roleArn:'unused',credentialsRef:{},maximumExpiresMs:1,directory:'/alternate'},{githubApi})).rejects.toThrow('CiAllowanceOwnerFields');expect(githubApi).not.toHaveBeenCalled();
});
