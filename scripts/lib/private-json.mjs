import assert from 'node:assert/strict';
import {constants} from 'node:fs';
import {open} from 'node:fs/promises';
import {basename, dirname, resolve} from 'node:path';

const maxBytes = 8 * 1024 * 1024;
const readFlags = constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK;
const directoryFlags = readFlags | constants.O_DIRECTORY;

function canonicalPath(path) {
  assert(typeof path === 'string' && !path.includes('\0') && resolve(path) === path, 'PrivateEvidenceRequired');
  // Fail closed: the traversal below depends on Linux procfs descriptor links.
  assert(process.platform === 'linux' && constants.O_NOFOLLOW && constants.O_NONBLOCK && constants.O_DIRECTORY, 'PrivateEvidenceTraversalUnavailable');
}
function privateDirectory(stat) {
  assert(stat.isDirectory() && stat.uid === process.getuid() && (stat.mode & 0o022) === 0, 'PrivateEvidenceRequired');
}

async function withPrivateDirectory(path, consume) {
  canonicalPath(path);
  const handles = [];
  const errors = [];
  const acquire = async (name, flags) => {
    const handle = await open(name, flags);
    handles.push(handle);
    return handle;
  };
  try {
    let directory = await acquire('/', directoryFlags);
    // Distinguish unavailable procfs from an absent input/journal. ENOENT from
    // a real component remains ENOENT; a missing traversal backend must not.
    try {await acquire(`/proc/self/fd/${directory.fd}/.`, directoryFlags);}
    catch {throw new Error('PrivateEvidenceTraversalUnavailable');}
    for (const component of path.split('/').filter(Boolean)) {
      // Only one validated component follows the pinned directory. O_NOFOLLOW
      // therefore protects every component, not just the final JSON filename.
      directory = await acquire(`/proc/self/fd/${directory.fd}/${component}`, directoryFlags);
    }
    privateDirectory(await directory.stat());
    return await consume(directory, acquire);
  } catch (error) {
    errors.push(error);
    throw error;
  } finally {
    // Attempt every close even if one fails. Never depend on GC to release FDs.
    const results = await Promise.allSettled(handles.reverse().map(handle => handle.close()));
    const closeErrors = results.filter(result => result.status === 'rejected').map(result => result.reason);
    // A cleanup failure must never look like an ordinary missing input (ENOENT).
    // Retain the primary error and every cleanup error for accurate attribution.
    if (closeErrors.length) throw new AggregateError([...errors, ...closeErrors], 'PrivateEvidenceCleanupFailed');
  }
}

/** Checks a directory only; callers reading evidence must use readPrivateJson
 * so directory validation and the read share the same anchored descriptors. */
export async function assertPrivateDirectory(path) {
  await withPrivateDirectory(path, async () => {});
}

export async function readPrivateJson(path) {
  canonicalPath(path);
  return withPrivateDirectory(dirname(path), async (directory, acquire) => {
    const file = await acquire(`/proc/self/fd/${directory.fd}/${basename(path)}`, readFlags);
    const stat = await file.stat();
    assert(stat.isFile() && stat.uid === process.getuid() && (stat.mode & 0o077) === 0 && stat.size <= maxBytes, 'PrivateEvidenceRequired');
    // Do not use readFile: a validated small regular file can grow after fstat.
    const buffer = Buffer.alloc(maxBytes + 1);
    let size = 0;
    while (size < buffer.length) {
      const {bytesRead} = await file.read(buffer, size, Math.min(64 * 1024, buffer.length - size), size);
      if (bytesRead === 0) break;
      size += bytesRead;
    }
    assert(size <= maxBytes, 'PrivateEvidenceRequired');
    return JSON.parse(buffer.toString('utf8', 0, size));
  });
}
