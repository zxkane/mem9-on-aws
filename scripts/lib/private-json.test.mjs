import {afterEach, beforeEach, describe, expect, it, vi} from 'vitest';
import {constants} from 'node:fs';
import {execFile} from 'node:child_process';
import {promisify} from 'node:util';
import {tmpdir} from 'node:os';
import {join} from 'node:path';

// Permanent security cases for #335. Every open/stat/read/rename below reaches
// the kernel; hooks only schedule deterministic adversarial changes between
// syscalls. SDK clients are never instantiated and no cloud calls are made.
const hooks = vi.hoisted(() => ({handles: new Map(), opened: [], reads: []}));
vi.mock('node:fs/promises', async importOriginal => {
  const fs = await importOriginal();
  return {...fs,
    lstat: async path => {
      const stat = await fs.lstat(path);
      await hooks.afterStat?.(path, stat);
      return stat;
    },
    open: async (path, ...args) => {
      const anchored = /^\/proc\/self\/fd\/(\d+)\/(.+)$/.exec(path);
      const logical = anchored ? join(hooks.handles.get(Number(anchored[1])).path, anchored[2]) : path;
      await hooks.beforeOpen?.(logical, path);
      const handle = await fs.open(path, ...args), fd = handle.fd;
      hooks.handles.set(fd, {path: logical, handle});
      hooks.opened.push({path: logical, fd, flags: args[0]});
      const stat = handle.stat.bind(handle), read = handle.read.bind(handle), close = handle.close.bind(handle);
      handle.stat = async () => {
        const result = await stat();
        await hooks.afterStat?.(logical, result);
        return result;
      };
      handle.read = async (...readArgs) => {
        await hooks.beforeRead?.(logical);
        const result = await read(...readArgs);
        hooks.reads.push(result.bytesRead);
        return result;
      };
      handle.close = async () => {
        try {await close();} finally {hooks.handles.delete(fd);}
        await hooks.afterClose?.(logical);
      };
      await hooks.afterOpen?.(logical, handle);
      return handle;
    },
  };
});
const fs = await vi.importActual('node:fs/promises');
// Use the adapter's public export as well, so extraction cannot silently break
// existing consumers. The child process below also exercises this export.
const privateJson = await import('./service-nonroot-aws.mjs');
const exec = promisify(execFile), maxBytes = 8 * 1024 * 1024;
let root, path;
beforeEach(async () => {
  root = await fs.realpath(await fs.mkdtemp(join(tmpdir(), 'private-json-test-')));
  path = join(root, 'evidence.json');
  await fs.writeFile(path, '{"trusted":true}', {mode: 0o600});
  hooks.opened = []; hooks.reads = [];
});
afterEach(async () => {
  for (const name of ['beforeOpen', 'afterOpen', 'afterStat', 'beforeRead', 'afterClose']) delete hooks[name];
  const leaked = [...hooks.handles.values()];
  // Clean leaked descriptors even on a failed regression, then fail explicitly.
  await Promise.all(leaked.map(({handle}) => handle.close()));
  await fs.rm(root, {recursive: true, force: true});
  expect(leaked.map(({path}) => path)).toEqual([]);
});
function onceAfterStat(target, action) {
  hooks.afterStat = async (name, stat) => {
    if (name === target) {delete hooks.afterStat; await action(stat);}
  };
}
async function replaceFile(kind) {
  await fs.rename(path, `${path}.original`);
  if (kind === 'file') await fs.writeFile(path, '{"attacker":true}', {mode: 0o600});
  if (kind === 'symlink') {
    await fs.writeFile(join(root, 'attacker.json'), '{"attacker":true}', {mode: 0o600});
    await fs.symlink(join(root, 'attacker.json'), path);
  }
  if (kind === 'directory') await fs.mkdir(path, {mode: 0o700});
  if (kind === 'fifo') await exec('mkfifo', ['-m', '600', path]);
}

describe('private JSON real filesystem boundary', () => {
  it.each([0o600, 0o400])('accepts owner mode %s through read-only descriptors', async mode => {
    await fs.chmod(path, mode);
    expect(await privateJson.readPrivateJson(path)).toEqual({trusted: true});
    for (const opened of hooks.opened) {
      expect(opened.flags & constants.O_NOFOLLOW).toBe(constants.O_NOFOLLOW);
      expect(opened.flags & constants.O_NONBLOCK).toBe(constants.O_NONBLOCK);
      expect(opened.flags & (constants.O_WRONLY | constants.O_RDWR)).toBe(0);
      if (opened.path !== path) expect(opened.flags & constants.O_DIRECTORY).toBe(constants.O_DIRECTORY);
    }
  });
  it.each([0o644, 0o640, 0o604, 0o660])('rejects nonprivate file mode %s before reading', async mode => {
    await fs.chmod(path, mode);
    await expect(privateJson.readPrivateJson(path)).rejects.toThrow('PrivateEvidenceRequired');
    expect(hooks.reads).toEqual([]);
  });
  it.each([undefined, null, {}, Buffer.from('/tmp/example'), '', 'relative.json', '/tmp/../tmp/example', '//tmp/example', '/tmp/./example', '/tmp/example/', '/tmp/a\0b'])('rejects noncanonical input %j before filesystem access', async input => {
    await expect(privateJson.readPrivateJson(input)).rejects.toThrow('PrivateEvidenceRequired');
    expect(hooks.opened).toEqual([]);
  });
  it('retains ENOENT for missing files and missing ancestors', async () => {
    await expect(privateJson.readPrivateJson(join(root, 'absent.json'))).rejects.toMatchObject({code: 'ENOENT'});
    await expect(privateJson.readPrivateJson(join(root, 'absent', 'file.json'))).rejects.toMatchObject({code: 'ENOENT'});
  });
  it.each(['symlink', 'directory'])('rejects a %s leaf', async kind => {
    await replaceFile(kind);
    await expect(privateJson.readPrivateJson(path)).rejects.toThrow();
    expect(hooks.reads).toEqual([]);
  });
  it('rejects an actual owner-only FIFO without waiting for a writer', async () => {
    await replaceFile('fifo');
    expect((await fs.lstat(path)).mode & 0o777).toBe(0o600);
    // A child deadline detects a missing O_NONBLOCK without stranding a libuv
    // worker (and the test runner) in a blocking FIFO open.
    const url = new URL('./service-nonroot-aws.mjs', import.meta.url).href;
    const script = `import {readPrivateJson} from ${JSON.stringify(url)};
      try {await readPrivateJson(process.argv[1]); process.exitCode=2;}
      catch(error) {if(!error.message.includes('PrivateEvidenceRequired')) throw error;}`;
    await exec(process.execPath, ['--input-type=module', '-e', script, path], {timeout: 4000});
  });
  it.each([0o777, 0o770, 0o722])('rejects writable parent mode %s', async mode => {
    await fs.chmod(root, mode);
    await expect(privateJson.readPrivateJson(path)).rejects.toThrow('PrivateEvidenceRequired');
    expect(hooks.reads).toEqual([]);
  });
  it('accepts a caller-owned non-writable-by-others parent', async () => {
    await fs.chmod(root, 0o755);
    expect(await privateJson.readPrivateJson(path)).toEqual({trusted: true});
  });
  it.each(['file', 'parent'])('rejects a different %s owner before reading', async target => {
    onceAfterStat(target === 'file' ? path : root, stat => {stat.uid = process.getuid() + 1;});
    await expect(privateJson.readPrivateJson(path)).rejects.toThrow('PrivateEvidenceRequired');
    expect(hooks.reads).toEqual([]);
  });
  it('rejects symlinks in ancestors, including a private leaf parent', async () => {
    const actual = join(root, 'actual'), redirected = join(root, 'redirected');
    await fs.mkdir(join(actual, 'private'), {recursive: true, mode: 0o700});
    await fs.writeFile(join(actual, 'private', 'file.json'), '{}', {mode: 0o600});
    await fs.symlink(actual, redirected);
    await expect(privateJson.readPrivateJson(join(redirected, 'private', 'file.json'))).rejects.toThrow();
    await expect(privateJson.assertPrivateDirectory(redirected)).rejects.toThrow();
  });
  it.each(['file', 'symlink', 'directory', 'fifo'])('keeps reading the validated inode after a leaf %s swap', async kind => {
    onceAfterStat(path, async () => {
      // Fail safely on the original pathname reader before installing a FIFO.
      if (kind === 'fifo') expect(hooks.opened.some(entry => entry.path === path)).toBe(true);
      await replaceFile(kind);
    });
    expect(await privateJson.readPrivateJson(path)).toEqual({trusted: true});
  });
  it.each(['symlink', 'directory'])('anchors the opened parent across a %s replacement', async kind => {
    const parent = join(root, 'parent');
    await fs.mkdir(parent, {mode: 0o700});
    path = join(parent, 'evidence.json');
    await fs.writeFile(path, '{"trusted":true}', {mode: 0o600});
    hooks.afterOpen = async logical => {
      if (logical !== parent) return;
      delete hooks.afterOpen;
      await fs.rename(parent, `${parent}.original`);
      if (kind === 'symlink') {
        await fs.mkdir(join(root, 'attacker'), {mode: 0o700});
        await fs.symlink(join(root, 'attacker'), parent);
      } else await fs.mkdir(parent, {mode: 0o700});
      await fs.writeFile(path, '{"attacker":true}', {mode: 0o600});
    };
    expect(await privateJson.readPrivateJson(path)).toEqual({trusted: true});
    expect(hooks.afterOpen).toBeUndefined();
  });
  it('anchors an intermediate directory before opening the private parent', async () => {
    const ancestor = join(root, 'ancestor'), parent = join(ancestor, 'private');
    await fs.mkdir(parent, {recursive: true, mode: 0o700});
    path = join(parent, 'evidence.json');
    await fs.writeFile(path, '{"trusted":true}', {mode: 0o600});
    hooks.afterOpen = async logical => {
      if (logical !== ancestor) return;
      delete hooks.afterOpen;
      await fs.rename(ancestor, `${ancestor}.original`);
      await fs.mkdir(join(root, 'attacker', 'private'), {recursive: true, mode: 0o700});
      await fs.symlink(join(root, 'attacker'), ancestor);
      await fs.writeFile(path, '{"attacker":true}', {mode: 0o600});
    };
    expect(await privateJson.readPrivateJson(path)).toEqual({trusted: true});
    expect(hooks.afterOpen).toBeUndefined();
  });
  it('rejects a symlink swapped into a not-yet-opened component', async () => {
    const parent = join(root, 'parent');
    await fs.mkdir(parent, {mode: 0o700});
    await fs.writeFile(join(parent, 'file.json'), '{}', {mode: 0o600});
    hooks.beforeOpen = async logical => {
      if (logical !== parent) return;
      delete hooks.beforeOpen;
      await fs.rename(parent, `${parent}.original`);
      await fs.symlink(`${parent}.original`, parent);
    };
    await expect(privateJson.readPrivateJson(join(parent, 'file.json'))).rejects.toThrow();
  });
  it('does not report missing procfs as missing evidence', async () => {
    hooks.beforeOpen = async (_logical, raw) => {
      if (raw.startsWith('/proc/self/fd/') && raw.endsWith('/.')) {
        throw Object.assign(new Error('synthetic missing procfs'), {code: 'ENOENT'});
      }
    };
    await expect(privateJson.readPrivateJson(path)).rejects.toThrow('PrivateEvidenceTraversalUnavailable');
    expect(hooks.handles.size).toBe(0);
  });
  it('attempts all descriptor closes even when one close reports an error', async () => {
    hooks.afterClose = async logical => {
      if (logical === path) throw new Error('synthetic close failure');
    };
    await expect(privateJson.readPrivateJson(path)).rejects.toThrow('PrivateEvidenceCleanupFailed');
    expect(hooks.handles.size).toBe(0);
  });
  it.each([false, true])('preserves every close failure with missing evidence=%s', async missing => {
    const failures = [];
    hooks.afterClose = async () => {
      const failure = new Error('synthetic close failure');
      failures.push(failure);
      throw failure;
    };
    const error = await privateJson.readPrivateJson(missing ? join(root, 'absent.json') : path).catch(error => error);
    expect(error).toBeInstanceOf(AggregateError);
    expect(error.code).toBeUndefined();
    expect(failures.length).toBeGreaterThan(1);
    expect(error.errors.slice(missing ? 1 : 0)).toEqual(failures);
    if (missing) expect(error.errors[0]).toMatchObject({code: 'ENOENT'});
    expect(hooks.handles.size).toBe(0);
  });
  it('validates private directories with anchored traversal and releases their descriptors', async () => {
    await privateJson.assertPrivateDirectory(root);
    expect(hooks.handles.size).toBe(0);
    await fs.chmod(root, 0o777);
    await expect(privateJson.assertPrivateDirectory(root)).rejects.toThrow('PrivateEvidenceRequired');
    expect(hooks.handles.size).toBe(0);
  });
  it('accepts exactly 8 MiB, rejects the next byte before parsing', async () => {
    await fs.writeFile(path, ' '.repeat(maxBytes - 2) + '{}');
    expect(await privateJson.readPrivateJson(path)).toEqual({});
    await fs.appendFile(path, ' ');
    await expect(privateJson.readPrivateJson(path)).rejects.toThrow('PrivateEvidenceRequired');
  });
  it('bounds actual reads to 8 MiB + 1 after a file grows beyond its stat size', async () => {
    onceAfterStat(path, () => fs.appendFile(path, ' '.repeat(maxBytes * 2)));
    await expect(privateJson.readPrivateJson(path)).rejects.toThrow('PrivateEvidenceRequired');
    expect(hooks.reads.reduce((sum, bytes) => sum + bytes, 0)).toBe(maxBytes + 1);
  });
  it('closes every opened descriptor on parse, stat, metadata, open and read failures', async () => {
    const baseline = (await fs.readdir('/proc/self/fd')).length;
    for (const failure of ['parse', 'stat', 'metadata', 'open', 'read']) {
      await fs.writeFile(path, failure === 'parse' ? '{' : '{}');
      if (failure === 'stat') onceAfterStat(path, () => {throw new Error('synthetic stat failure');});
      if (failure === 'metadata') onceAfterStat(path, stat => {stat.uid = process.getuid() + 1;});
      if (failure === 'open') hooks.beforeOpen = async logical => {if (logical === path) throw new Error('synthetic open failure');};
      if (failure === 'read') hooks.beforeRead = async () => {throw new Error('synthetic read failure');};
      await expect(privateJson.readPrivateJson(path)).rejects.toThrow();
      delete hooks.beforeOpen; delete hooks.beforeRead;
      expect(hooks.handles.size).toBe(0);
      expect((await fs.readdir('/proc/self/fd')).length).toBe(baseline);
    }
    await fs.writeFile(path, '{}');
    expect(await privateJson.readPrivateJson(path)).toEqual({});
    expect((await fs.readdir('/proc/self/fd')).length).toBe(baseline);
  });
});
