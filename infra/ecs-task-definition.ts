interface StringOutput {
  apply(callback: (value: string) => string): unknown;
}

/**
 * SST enables a pseudo-terminal for every Fargate container. Disable it only
 * for the non-interactive process whose stdout carries one EMF document per
 * line; all other synthesized container settings remain SST-owned.
 */
export function disableMnemoServerPseudoTerminal(
  args: Record<string, unknown>,
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
    const mnemo = parsed.find((container) => container.name === "mnemo-server");
    if (!mnemo) {
      throw new Error("mnemo-server container not found in task definition");
    }
    mnemo.pseudoTerminal = false;
    return JSON.stringify(parsed);
  });
}
