import {it,expect} from 'vitest';
import {nonrootDeploymentFixture} from './production-nonroot-provenance.fixture.mjs';
import {collectNonrootControlRuntime,verifyNonrootControlRuntimeObservation} from './lib/production-nonroot-observation.mjs';

it('does not adopt JSON runtime observations or serialized graph handles',async()=>{
 const f=await nonrootDeploymentFixture();
 expect(()=>verifyNonrootControlRuntimeObservation({},f.build,f.options())).toThrow('NonrootRuntimeObservationRequired');
 const options=f.options();options.controlVerification.graph=structuredClone(options.controlVerification.graph);
 await expect(collectNonrootControlRuntime(f.build,options)).rejects.toThrow();
});
