/** Original finite command templates as DATA. No command execution. */
import {resolve,join} from 'node:path';
import {nonrootHash as hash} from './production-nonroot-contracts.mjs';
import {CI_SMOKE_HEALTH_COMMAND} from './ci-smoke-evidence.mjs';
const LABEL='mem9-ci-smoke-invocation';
const ROLES=['server','database','busybox','invalid-migration','invalid-timeout','no-server-health'];
const need=(v,c)=>{if(!v)throw Error(c);};
const exact=(v,keys)=>need(v&&typeof v==='object'&&!Array.isArray(v)&&Object.keys(v).sort().join()===keys.slice().sort().join(),'SmokeInputFields');
const DB_SCRIPT=`set -eu
umask 077
openssl req -x509 -newkey rsa:2048 -nodes -days 1 -subj /CN=mnemo-smoke-db -keyout /tls/server.key -out /tls/server.crt >/dev/null 2>&1
printf '%s' "$POSTGRES_PASSWORD" > /tls/password
initdb --pgdata=/pgdata --username=mnemo --pwfile=/tls/password --auth-local=trust --auth-host=scram-sha-256 --no-sync >/dev/null
rm /tls/password
printf 'local all all trust\nhostssl all all all scram-sha-256\nhostnossl all all all reject\n' > /tls/pg_hba.conf
printf 'CREATE DATABASE mnemo;\n' | postgres --single -D /pgdata template1 >/dev/null
exec postgres -D /pgdata -c listen_addresses=* -c unix_socket_directories=/var/run/postgresql -c ssl=on -c ssl_cert_file=/tls/server.crt -c ssl_key_file=/tls/server.key -c hba_file=/tls/pg_hba.conf -c log_min_error_statement=panic -c log_error_verbosity=terse -c log_statement=none -c log_connections=off -c log_disconnections=off -c logging_collector=off -c shared_buffers=32MB -c max_connections=20`;
const waitThen=script=>`IFS= read -r ready; [ "$ready" = go ]; ${script}`;
const roleCommand=role=>role==='server'?['-ceu','exec /usr/local/bin/entrypoint.sh']:role==='database'?['-ceu',DB_SCRIPT]:
 role==='busybox'?['-ceu',waitThen('command -v wget; exec busybox --list')]:role==='no-server-health'?['-ceu',waitThen("exec /bin/sh -c '"+CI_SMOKE_HEALTH_COMMAND+"'")]:['-ceu',waitThen('exec /usr/local/bin/entrypoint.sh')];
const mountPlans=role=>role==='database'?[['/pgdata',536870912,0o700],['/tls',16777216,0o700],['/var/run/postgresql',16777216,0o755],['/var/lib/postgresql/data',1048576,0o700]]:role==='server'?[['/tmp',268435456,0o700]]:[];
function containerCreateArgs(role,{invocationId,images,workDirectory}){
 const user=role==='database'?'999:999':'1000:1000',name='mem9-smoke-'+invocationId.slice(0,24)+'-'+role;
 const args=['create','--pull','never','--platform','linux/arm64','--name',name,'--label',LABEL+'='+invocationId,'--user',user,'--cap-drop','ALL','--security-opt','no-new-privileges=true',
  '--read-only','--tty=false','--pids-limit',role==='database'?'96':'64','--memory',role==='database'?'768m':'512m','--cpus','1','--network',['server','database'].includes(role)?'mem9-ci-smoke-'+invocationId.slice(0,24):'none','--env-file',join(workDirectory,role+'.env')];
 if(!['server','database'].includes(role))args.push('--interactive');
 for(const [path,size,mode]of mountPlans(role))args.push('--tmpfs',`${path}:rw,noexec,nosuid,nodev,uid=${user.split(':')[0]},gid=${user.split(':')[1]},mode=${mode.toString(8)},size=${size}`);
 args.push('--entrypoint','/bin/sh',images[role==='database'?'database':'server'].qualifiedImage,...roleCommand(role));return args;
}

/** Resolve only the pinned producer's finite argv templates. Bindings must
 * come from the independently authenticated host journal/image selection.
 * This validates arguments, not job provenance or the fourteen result checks. */
export function expectedCiSmokeCommandCatalog({catalog,bindings,...unknown}){
 exact(unknown,[]);exact(bindings,['invocationId','rootDirectory','nodeExecutable','workDirectory','outputDirectory','images','containers','networkId']);
 const b=bindings;need(/^[a-f0-9]{64}$/.test(b.invocationId)&&/^[a-f0-9]{64}$/.test(b.networkId),'SmokeCatalogBindings');
 for(const key of ['rootDirectory','nodeExecutable','workDirectory','outputDirectory'])need(typeof b[key]==='string'&&b[key].startsWith('/')&&!/[\0\r\n]/.test(b[key])&&resolve(b[key])===b[key],'SmokeCatalogBindings');
 exact(b.containers,ROLES);need(new Set(Object.values(b.containers)).size===ROLES.length&&Object.values(b.containers).every(id=>/^[a-f0-9]{64}$/.test(id)),'SmokeCatalogBindings');
 exact(b.images,['server','database']);for(const i of Object.values(b.images)){exact(i,['qualifiedImage','rootDigest','arm64Digest','configDigest']);need(typeof i.qualifiedImage==='string'&&/^[A-Za-z0-9._:/-]+@sha256:[a-f0-9]{64}$/.test(i.qualifiedImage)&&i.qualifiedImage.endsWith('@'+i.rootDigest),'SmokeCatalogBindings');for(const k of ['rootDigest','arm64Digest','configDigest'])need(/^sha256:[a-f0-9]{64}$/.test(i[k]),'SmokeCatalogBindings');}
 need(Array.isArray(catalog)&&catalog.length>0&&catalog.length<=1024,'SmokeCommandLimit');
 const helper=(mode,...args)=>[b.nodeExecutable,join(b.rootDirectory,'scripts/lib/mnemo-nonroot-smoke-helper.mjs'),mode,...args];
 return catalog.map((row,index)=>{
  exact(row,['sequence','commandKey','containerId','argv']);need(row.sequence===index&&Array.isArray(row.argv)&&row.argv.length>=1&&row.argv.length<=128&&row.argv.every(a=>typeof a==='string'&&a.length>0&&!a.includes('\0')),'SmokeCatalogRow');
  const role=ROLES.find(r=>b.containers[r]===row.containerId),id=row.containerId,user=role==='database'?'999:999':'1000:1000',key=row.commandKey,allowed=[];
  const add=(condition,argv)=>{if(condition)allowed.push(argv);};
  add(key==='create-network'&&id===null,['docker','network','create','--driver','bridge','--internal','--label',LABEL+'='+b.invocationId,'mem9-ci-smoke-'+b.invocationId.slice(0,24)]);
  if(key==='create-container'&&role)allowed.push(['docker',...containerCreateArgs(role,b)]);
  if(key==='inspect-container'&&role){allowed.push(['docker','inspect',id],['docker','inspect','--format','{{json .State}}',id]);if(['server','database'].includes(role))allowed.push(['docker','inspect','--format','{{json .HostConfig}}',id]);}
  if(key==='inspect-processes'&&role){allowed.push(helper('pids',id,user));const pid=row.argv.at(-1);if(/^[1-9][0-9]{0,9}$/.test(pid))allowed.push(helper('process',id,user,pid));}
  const negativeRoles={'busybox-wget':'busybox','reject-migration':'invalid-migration','reject-timeout':'invalid-timeout','health-absent':'no-server-health'};
  add(Object.hasOwn(negativeRoles,key)&&negativeRoles[key]===role,['docker','start','--attach','--interactive',id]);
  add(key==='start-container'&&role==='server',['docker','start',id]);
  add(key==='start-container'&&role==='database',['docker','exec','--user','999:999',id,'pg_isready','--username','mnemo','--dbname','mnemo']);
  add(key==='generate-tls'&&role==='database',['docker','start',id]);
  add(['health-before','health-after'].includes(key)&&role==='server',['docker','exec','--user','1000:1000',id,'/bin/sh','-c',CI_SMOKE_HEALTH_COMMAND]);
  add(['stat-tls','tls-query','plaintext-query','relations-query'].includes(key)&&role==='database',helper(key,id));
  add(key==='collect-logs'&&['server','database'].includes(role),['docker','logs',id]);
  add(key==='scan-logs'&&id===null,helper('scan-logs',join(b.workDirectory,'scan.json')));
  add(key==='validate-emf'&&id===null,[b.nodeExecutable,join(b.rootDirectory,'scripts/validate-emf-event.mjs'),'--docker-stream']);
  add(key==='inspect-network'&&id===null,['docker','network','inspect',b.networkId]);
  add(key==='stop-server'&&role==='server',['docker','stop','--timeout','10',id]);
  add(['remove-owned','inventory-owned'].includes(key)&&id===null,helper(key,join(b.outputDirectory,'owned-resources.json')));
  need(allowed.some(argv=>hash(argv)===hash(row.argv)),'SmokeUnplannedCommandArguments');return structuredClone(row);
 });
}

export {containerCreateArgs};
