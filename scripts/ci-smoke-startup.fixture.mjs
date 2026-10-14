// Filesystem stand-in for completed GitHub responses in concurrency tests.
import {open,link,unlink} from 'node:fs/promises';
import {randomBytes} from 'node:crypto';

export async function publishStartupFixtureJson(path,value,{beforeWrite}={}){
 const temporary=path+'.'+randomBytes(16).toString('hex')+'.tmp';
 const fd=await open(temporary,'wx',0o600);
 try{
  try{await beforeWrite?.();await fd.writeFile(JSON.stringify(value));await fd.sync();}
  finally{await fd.close();}
  // Same-directory hard link publishes the complete inode atomically and
  // retains the fixture's create-once semantics: an existing target fails.
  await link(temporary,path);
 }finally{await unlink(temporary);}
}
