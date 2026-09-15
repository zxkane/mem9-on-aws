import { createHash, randomBytes } from "node:crypto";
import { lstat, open, rename, unlink } from "node:fs/promises";
import { HumanAcceptanceError } from "./human-namespace-acceptance.mjs";

export function humanTargetFingerprint(manifest, namespaceIds) {
  if (
    namespaceIds.length !== 2 ||
    new Set(namespaceIds).size !== 2 ||
    namespaceIds.some((id) => typeof id !== "string" || !id)
  )
    throw new HumanAcceptanceError("distinct_preview_namespaces_required");
  return createHash("sha256")
    .update(
      JSON.stringify([
        manifest.accountId,
        manifest.region,
        manifest.userPoolId,
        manifest.database.resourceId,
        manifest.database.name,
        namespaceIds,
      ]),
    )
    .digest("hex");
}

export async function writePrivateRecord(path, value, { beforeRename } = {}) {
  try {
    const existing = await lstat(path);
    if (!existing.isFile() || existing.uid !== process.getuid())
      throw new HumanAcceptanceError("private_record_owner_mismatch");
  } catch (error) {
    if (error.code !== "ENOENT") throw error;
  }
  const temporary = `${path}.${randomBytes(8).toString("hex")}.local.json`;
  try {
    const file = await open(temporary, "wx", 0o600);
    try {
      await file.writeFile(JSON.stringify(value));
      await file.sync();
    } finally {
      await file.close();
    }
    await beforeRename?.();
    await rename(temporary, path);
  } finally {
    await unlink(temporary).catch((error) => {
      if (error.code !== "ENOENT") throw error;
    });
  }
}

export function acceptanceHttpEvents(events, hash) {
  const statuses = [];
  for (const event of events) {
    let message = event.message,
      record;
    try {
      record = JSON.parse(message);
      if (typeof record.message === "string")
        record = JSON.parse(record.message);
    } catch {
      const start = message.indexOf(
        '{"event":"namespace_acceptance_http_error"',
      );
      if (start < 0) continue;
      try {
        record = JSON.parse(message.slice(start).trim());
      } catch {
        continue;
      }
    }
    if (
      record?.event === "namespace_acceptance_http_error" &&
      record.request_hash === hash &&
      Number.isInteger(record.status)
    )
      statuses.push(record.status);
  }
  return statuses;
}
