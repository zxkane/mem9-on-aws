import {
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { delimiter, join, resolve } from "node:path";
import { spawnSync } from "node:child_process";
import { afterEach, describe, expect, it } from "vitest";
import { runtimeRoleName } from "./lib/runtime-credentials.mjs";
import {nonrootPreviewFixture} from './nonroot-preview.fixture.mjs';

const script = resolve("scripts/run-bootstrap-task.sh");
const temporaryPaths = [];

afterEach(() => {
  for (const path of temporaryPaths.splice(0)) {
    rmSync(path, { force: true, recursive: true });
  }
});

function runFixture({
  runtimeVerify = false,
  stage = "pr-42",
  metadataStage = stage,
  marker = "1",
  containerCount = 1,
  duplicate = false,
  exitCode = runtimeVerify ? 0 : 1,
  readable = true,
  malformed = false,
  wrongArn = false,
  inherited = false,
  operation = "",
  launchFailure = false,
  missingMap = false,
  changedMap = false,
} = {}) {
  const directory = mkdtempSync(join(tmpdir(), "mem9-bootstrap-runner-"));
  temporaryPaths.push(directory);
  const bin = join(directory, "bin");
  const calls = join(directory, "calls.jsonl");
  mkdirSync(bin);
  const guarded=/^pr-[1-9][0-9]*$/.test(stage)?nonrootPreviewFixture({stage,cluster:'mem9-on-aws-'+stage+'-Cluster-example',
    purposes:[runtimeVerify?'bootstrap-runtime-verify':'bootstrap-schema-seed'],
    environment:inherited?[{name:'MEM9_RUNTIME_BOOTSTRAP_DEADLINE',value:'1'},{name:'MEM9_RUNTIME_INVOCATION',value:'stale'}]:[],
    logGroup:'/sst/cluster/mem9-pr-42/bootstrap/Mem9Bootstrap',logStreamPrefix:'/service'}):undefined;
  const previewFile=join(directory,'preview.json');
  writeFileSync(previewFile,JSON.stringify(guarded?{parameters:[...guarded.parameters.values()],observation:guarded.records[0].observation}:null),{mode:0o600});
  writeFileSync(join(bin,'git'),'#!/usr/bin/env node\nif(process.argv[2]==="rev-parse")console.log("a".repeat(40));\n',{mode:0o755});

  writeFileSync(
    join(bin, "aws"),
    `#!/usr/bin/env node
import { appendFileSync,readFileSync } from "node:fs";
const args = process.argv.slice(2);
appendFileSync(process.env.AWS_CALLS, JSON.stringify(args) + "\\n");
const option = (name) => {
  const index = args.indexOf(name);
  return index === -1 ? undefined : args[index + 1];
};
const command = args.slice(0, 2).join(" ");
const fixture=JSON.parse(process.env.BOOTSTRAP_TEST_CONFIG);
const preview=JSON.parse(readFileSync(process.env.BOOTSTRAP_PREVIEW_FIXTURE,'utf8'));
if(command === 'sts get-caller-identity'){
 console.log(JSON.stringify({Account:'123456789012'}));
}else if(command === 'ssm get-parameters'){
 const start=args.indexOf('--names')+1,end=args.findIndex((v,i)=>i>=start&&v.startsWith('--')),names=args.slice(start,end<0?undefined:end);
 const count=readFileSync(process.env.AWS_CALLS,'utf8').trim().split('\\n').map(JSON.parse).filter(a=>a[0]==='ssm'&&a[1]==='get-parameters').length;
 const Parameters=names.map(Name=>{const p=preview?.parameters.find(p=>p.Name===Name);return p?{...p,Version:p.Version+(fixture.changedMap&&count>1?1:0)}:undefined;}).filter(Boolean);
 console.log(JSON.stringify({Parameters,InvalidParameters:fixture.missingMap?[names[0]]:[]}));
}else if (command === "ssm get-parameter") {
  const values = {
    "cluster-name": "mem9-pr-42-cluster",
    "task-def-arn": "arn:aws:ecs:ap-northeast-1:123456789012:task-definition/mem9-bootstrap:7",
    "task-sg-id": "sg-bootstrap",
    "subnet-ids": "subnet-a,subnet-b"
  };
  process.stdout.write(values[option("--name").split("/").at(-1)] + "\\n");
} else if (command === "ecs describe-task-definition") {
  if(!fixture.readable){process.stderr.write("fixture metadata unavailable");process.exit(3);}
  if(fixture.malformed){process.stdout.write("not-json");process.exit(0);}
  if(preview){
    const o=preview.observation,c=o.taskDefinition.containerDefinitions[0];
    if(fixture.wrongArn)o.taskDefinition.taskDefinitionArn='wrong-definition';
    if(fixture.metadataStage!==process.env.STAGE)c.environment.find(e=>e.name==='MEM9_STAGE').value=fixture.metadataStage;
    if(fixture.marker!=='1'&&fixture.runtimeVerify)c.environment.find(e=>e.name==='MEM9_RUNTIME_BOOTSTRAP_VERSION').value=fixture.marker;
    if(fixture.duplicate)c.environment.push(c.environment[0]);
    if(fixture.containerCount!==1)o.taskDefinition.containerDefinitions.push({...c,name:'OtherContainer'});
    console.log(JSON.stringify(o));process.exit(0);
  }
  console.log(JSON.stringify({
    taskDefinition: {
      taskDefinitionArn:fixture.wrongArn?"wrong-definition":"arn:aws:ecs:ap-northeast-1:123456789012:task-definition/mem9-bootstrap:7",
      containerDefinitions: Array.from({length:fixture.containerCount},(_,index)=>({
        name: index===0?"Mem9Bootstrap":"OtherContainer",
        environment: fixture.runtimeVerify?[
          {name:"MEM9_BOOTSTRAP_OPERATION",value:"runtime-verify"},
          {name:"MEM9_STAGE",value:fixture.metadataStage},
          {name:"MEM9_RUNTIME_BOOTSTRAP_VERSION",value:fixture.marker},
          ...(fixture.inherited?[{name:"MEM9_RUNTIME_BOOTSTRAP_DEADLINE",value:"1"},{name:"MEM9_RUNTIME_INVOCATION",value:"stale"}]:[]),
          ...(fixture.duplicate?[{name:"MEM9_BOOTSTRAP_OPERATION",value:"runtime-bootstrap"}]:[])
        ]:(fixture.operation?[{name:"MEM9_BOOTSTRAP_OPERATION",value:fixture.operation}]:[]),
        logConfiguration: {
          options: {
            "awslogs-group": "/sst/cluster/mem9-pr-42/bootstrap/Mem9Bootstrap",
            "awslogs-stream-prefix": "/service"
          }
        }
      }))
    }
  }));
} else if (command === "ecs run-task") {
  if(fixture.launchFailure){console.log(JSON.stringify({failures:[{reason:"fixture capacity failure"}],tasks:[]}));process.exit(0);}
  console.log(JSON.stringify({
    failures: [],
    tasks: [{
      taskArn: "arn:aws:ecs:ap-northeast-1:123456789012:task/mem9-pr-42-cluster/task-private"
    }]
  }));
} else if (command === "ecs describe-tasks") {
  const query = option("--query");
  if (query.includes("lastStatus")) process.stdout.write("STOPPED\\n");
  else if (query.includes("exitCode")) process.stdout.write(String(fixture.exitCode)+"\\n");
  else if (query.includes("stoppedReason")) {
    process.stdout.write("Essential container in task exited\\n");
  } else {
    console.log(JSON.stringify({ tasks: [] }));
  }
} else if (command === "logs filter-log-events") {
  console.log(JSON.stringify({
    events: Array.from({ length: 205 }, (_, index) => ({
      message: index === 204
        ? "preview namespace preparation failed: fixture failure"
        : \`schema notice \${index}\`
    }))
  }));
} else {
  console.error("unexpected aws command:", command);
  process.exit(2);
}
`,
    { mode: 0o755 },
  );
  writeFileSync(join(bin, "sleep"), "#!/usr/bin/env bash\nexit 0\n", {
    mode: 0o755,
  });

  const before = Date.now();
  const result = spawnSync("bash", [script], {
    encoding: "utf8",
    env: {
      ...process.env,
      AWS_CALLS: calls,
      AWS_REGION: "ap-northeast-1",
      BOOTSTRAP_TEST_CONFIG: JSON.stringify({
        runtimeVerify,
        metadataStage,
        marker,
        containerCount,
        duplicate,
        exitCode,
        readable,
        malformed,
        wrongArn,
        inherited,
        operation,
        launchFailure,
        missingMap,changedMap,
      }),
      BOOTSTRAP_PREVIEW_FIXTURE:previewFile,
      PATH: `${bin}${delimiter}${process.env.PATH}`,
      STAGE: stage,
    },
  });
  const callRecords = readFileSync(calls, "utf8")
    .trim()
    .split("\n")
    .filter(Boolean)
    .map((line) => JSON.parse(line));
  return { callRecords, result, before, after: Date.now(),guarded };
}

describe("schema bootstrap ECS runner", () => {
  it("gives each declared runtime verification a fresh bounded context and matching idempotency token", () => {
    const nonces = [];
    for (const stage of ["prod", "prod", "pr-42"]) {
      const { callRecords, result, before, after } = runFixture({
        runtimeVerify: true,
        stage,
        inherited: true,
      });
      expect(result.status).toBe(0);
      const runs = callRecords.filter(
        (a) => a[0] === "ecs" && a[1] === "run-task",
      );
      expect(runs).toHaveLength(1);
      const args = runs[0],
        get = (name) => args[args.indexOf(name) + 1];
      expect(args).toContain("--overrides");
      expect(args).toContain("--client-token");
      const overrides = JSON.parse(get("--overrides"));
      expect(Object.keys(overrides)).toEqual(["containerOverrides"]);
      expect(overrides.containerOverrides).toHaveLength(1);
      const container = overrides.containerOverrides[0];
      expect(Object.keys(container).sort()).toEqual(["environment", "name"]);
      expect(container.name).toBe("Mem9Bootstrap");
      expect(container.environment).toHaveLength(2);
      const env = Object.fromEntries(
        container.environment.map((x) => [x.name, x.value]),
      );
      expect(Object.keys(env).sort()).toEqual([
        "MEM9_RUNTIME_BOOTSTRAP_DEADLINE",
        "MEM9_RUNTIME_INVOCATION",
      ]);
      expect(env.MEM9_RUNTIME_INVOCATION).toMatch(/^[a-f0-9]{32}$/);
      expect(get("--client-token")).toBe(env.MEM9_RUNTIME_INVOCATION);
      const deadline = Number(env.MEM9_RUNTIME_BOOTSTRAP_DEADLINE);
      expect(deadline).toBeGreaterThanOrEqual(before + 840000);
      expect(deadline).toBeLessThanOrEqual(after + 840000);
      expect(deadline).toBeLessThan(before + 900000);
      expect(result.stdout).toContain("runtime verification passed");
      expect(
        callRecords.some((a) => a[0] === "ssm" && !['get-parameter','get-parameters'].includes(a[1])),
      ).toBe(false);
      nonces.push(env.MEM9_RUNTIME_INVOCATION);
    }
    expect(new Set(nonces).size).toBe(3);
  });

  it("rejects inconsistent runtime-verification metadata before launching any task", () => {
    for (const options of [
      { metadataStage: "pr-7" },
      { marker: "0" },
      { containerCount: 2 },
      { duplicate: true },
      { stage: "arbitrary" },
      { readable: false },
      { malformed: true },
      { wrongArn: true },
    ]) {
      const { callRecords, result } = runFixture({
        runtimeVerify: true,
        stage: "prod",
        ...options,
      });
      expect(result.status).not.toBe(0);
      expect(
        callRecords.some((a) => a[0] === "ecs" && a[1] === "run-task"),
      ).toBe(false);
    }
  });

  it("leaves the legacy bootstrap launch context unchanged", () => {
    for (const operation of [
      "",
      "namespace-status",
      "runtime-bootstrap",
      "runtime-admin-probe",
    ]) {
      const { callRecords } = runFixture({ operation,stage:'prod' });
      const args = callRecords.find(
        (a) => a[0] === "ecs" && a[1] === "run-task",
      );
      expect(args).not.toContain("--overrides");
      expect(args).not.toContain("--client-token");
    }
  });

  it("does not launch a second task when ECS rejects the verification launch", () => {
    const { callRecords, result } = runFixture({
      runtimeVerify: true,
      stage: "prod",
      launchFailure: true,
    });
    expect(result.status).toBe(1);
    expect(
      callRecords.filter((a) => a[0] === "ecs" && a[1] === "run-task"),
    ).toHaveLength(1);
    expect(
      callRecords.some((a) => a[0] === "ecs" && a[1] === "describe-tasks"),
    ).toBe(false);
  });
  it('uses the guarded purpose revision and holds missing or changed maps without a legacy preview fallback',()=>{
    const good=runFixture({runtimeVerify:true,exitCode:0});expect(good.result.status,good.result.stderr).toBe(0);
    const run=good.callRecords.find(a=>a[0]==='ecs'&&a[1]==='run-task');
    expect(run[run.indexOf('--task-definition')+1]).toBe(good.guarded.map.bindings[0].taskDefinitionArn);
    expect(run).toContain('--disable-execute-command');
    for(const flag of ['missingMap','changedMap']){
      const f=runFixture({runtimeVerify:true,[flag]:true});expect(f.result.status).not.toBe(0);
      expect(f.callRecords.some(a=>a[0]==='ecs'&&a[1]==='run-task')).toBe(false);
    }
  });

  it("satisfies the real verifier configuration guard while preserving invalid deadline rejection", () => {
    const directory = mkdtempSync(join(tmpdir(), "mem9-runtime-deadline-"));
    temporaryPaths.push(directory);
    const blocker = join(directory, "block-network.cjs");
    writeFileSync(
      blocker,
      `require(${JSON.stringify(resolve("node_modules/pg"))}).Client.prototype.connect=async function(){throw new Error("TestNetworkDisabled");};`,
      { mode: 0o600 },
    );
    const { callRecords } = runFixture({ runtimeVerify: true, stage: "prod" });
    const call = callRecords.find((a) => a[0] === "ecs" && a[1] === "run-task");
    const override = JSON.parse(call[call.indexOf("--overrides") + 1]);
    const context = Object.fromEntries(
      override.containerOverrides[0].environment.map((x) => [x.name, x.value]),
    );
    const env = {
      ...process.env,
      MEM9_STAGE: "prod",
      MEM9_BOOTSTRAP_OPERATION: "runtime-verify",
      MEM9_DB_HOST: "127.0.0.1",
      MEM9_DB_PORT: "1",
      MEM9_DB_NAME: "fixture",
      MEM9_TENANT_ID: "f".repeat(32),
      MEM9_DB_SECRET: JSON.stringify({
        username: "unused",
        password: "unused",
      }),
      MEM9_RUNTIME_DB_SECRET: JSON.stringify({
        username: runtimeRoleName("prod"),
        password: "a".repeat(32),
        salt: "b".repeat(16),
      }),
    };
    delete env.MEM9_RUNTIME_BOOTSTRAP_DEADLINE;
    const invoke = (values) => {
      const r = spawnSync(
        process.execPath,
        ["--require", blocker, resolve("scripts/runtime-bootstrap.mjs")],
        { encoding: "utf8", env: { ...env, ...values }, timeout: 5000 },
      );
      expect(r.error).toBeUndefined();
      expect(r.status).toBe(1);
      expect(r.stdout, r.stderr).not.toBe("");
      return JSON.parse(r.stdout.trim());
    };
    expect(invoke(context)).toMatchObject({
      event: "runtime_bootstrap_failed",
      phase: "connection",
      errorClass: "TestNetworkDisabled",
    });
    for (const value of [
      undefined,
      String(Date.now() - 1000),
      String(Date.now() + 3600000),
    ]) {
      expect(
        invoke(
          value === undefined ? {} : { MEM9_RUNTIME_BOOTSTRAP_DEADLINE: value },
        ),
      ).toMatchObject({
        event: "runtime_bootstrap_failed",
        phase: "configuration",
        errorClass: "RuntimeBootstrapExpired",
      });
    }
  });

  it("prints the failed task's exact awslogs stream with existing deploy-role permissions", () => {
    const { callRecords, result } = runFixture();
    const output = result.stdout + result.stderr;

    expect(result.status).toBe(1);
    expect(output).toContain(
      "preview namespace preparation failed: fixture failure",
    );
    expect(output).not.toContain("schema notice 0");
    const logCall = callRecords.find(
      ([service, operation]) =>
        service === "logs" && operation === "filter-log-events",
    );
    expect(logCall).toEqual(
      expect.arrayContaining([
        "--log-group-name",
        "/sst/cluster/mem9-pr-42/bootstrap/Mem9Bootstrap",
        "--log-stream-name-prefix",
        "/service/Mem9Bootstrap/task-private",
      ]),
    );
    expect(logCall).not.toContain("--limit");
    expect(
      callRecords.some(
        ([service, operation]) =>
          service === "logs" &&
          [
            "describe-log-groups",
            "describe-log-streams",
            "get-log-events",
          ].includes(operation),
      ),
    ).toBe(false);
  });
});
