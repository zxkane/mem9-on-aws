interface StringOutput {
  apply(callback: (value: string) => string): unknown;
}

/**
 * SST enables a pseudo-terminal for every Fargate container. Disable it only
 * for a named non-interactive process; all other synthesized container
 * settings remain SST-owned.
 */
export function disableTaskContainerPseudoTerminal(
  args: Record<string, unknown>,
  containerName: string,
): void {
  const definitions = args.containerDefinitions as StringOutput | undefined;
  if (!definitions || typeof definitions.apply !== "function") {
    throw new Error("task definition containerDefinitions output not found");
  }

  args.containerDefinitions = definitions.apply((raw) => {
    const parsed = JSON.parse(raw) as {
      name: string;
      pseudoTerminal?: boolean;
    }[];
    const target = parsed.find(
      (container) => container.name === containerName,
    );
    if (!target) {
      throw new Error(
        `${containerName} container not found in task definition`,
      );
    }
    target.pseudoTerminal = false;
    return JSON.stringify(parsed);
  });
}

export function disableMnemoServerPseudoTerminal(
  args: Record<string, unknown>,
): void {
  disableTaskContainerPseudoTerminal(args, "mnemo-server");
}
