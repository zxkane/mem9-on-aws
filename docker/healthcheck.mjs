// Node is already present in both sidecars; no curl/SSH library is needed.
try {
  const response = await fetch(process.argv[2], {
    signal: AbortSignal.timeout(4000),
    redirect: "error",
  });
  await response.body?.cancel();
  process.exit(response.ok ? 0 : 1);
} catch {
  process.exit(1);
}
