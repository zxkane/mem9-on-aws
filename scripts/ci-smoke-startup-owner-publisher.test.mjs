import {it,expect,vi} from 'vitest';
import {publishCiOwnerRunBinding} from './lib/ci-smoke-startup-owner-publisher.mjs';

it.each([undefined,{}, {kind:'ci-owner-publication-preparation'}, {verified:true,config:{}}])('rejects an absent or serialized preparation before any transport (%j)',async preparation=>{
 const githubApi=vi.fn(),requestHandler={handle:vi.fn(),destroy:vi.fn()};
 await expect(publishCiOwnerRunBinding({preparation,runId:1,runAttempt:1,storage:{bucket:'example-artifacts',kmsKeyArn:'unused',roleArn:'unused'},credentialsRef:{path:'/unopened',sha256:'a'.repeat(64)}},{env:{},githubApi,requestHandler})).rejects.toThrow('CiOwnerPreparationRequired');
 expect(githubApi).not.toHaveBeenCalled();expect(requestHandler.handle).not.toHaveBeenCalled();
});
it('rejects caller-selected extra operations before any transport',async()=>{
 const githubApi=vi.fn(),requestHandler={handle:vi.fn(),destroy:vi.fn()};
 await expect(publishCiOwnerRunBinding({preparation:{},runId:1,runAttempt:1,storage:{},credentialsRef:{},retry:true},{env:{},githubApi,requestHandler})).rejects.toThrow();
 expect(githubApi).not.toHaveBeenCalled();expect(requestHandler.handle).not.toHaveBeenCalled();
});
