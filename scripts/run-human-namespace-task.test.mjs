import {describe,it,expect} from 'vitest';
import {HumanAcceptanceError} from './lib/human-namespace-acceptance.mjs';
import {humanTaskFailureCode} from './run-human-namespace-task.mjs';

describe('human acceptance failure diagnostics',()=>{
  it('preserves a preflight rejection before private fixture records exist',()=>{
    expect(humanTaskFailureCode(new HumanAcceptanceError('database_runtime_binding_mismatch'))).toBe('database_runtime_binding_mismatch');
  });
  it('keeps credentials and arbitrary exception messages out of task logs',()=>{
    const secret='synthetic-private-diagnostic';
    expect(humanTaskFailureCode(new Error(secret))).toBe('operator_failure');
    expect(humanTaskFailureCode({name:'HumanAcceptanceError',message:secret})).toBe('operator_failure');
    expect(humanTaskFailureCode(new HumanAcceptanceError('invalid secret='+secret))).toBe('operator_failure');
    expect(humanTaskFailureCode(new Error(secret),{name:'TimeoutError',message:secret,stack:secret})).toBe('TimeoutError');
  });
});
