#!/usr/bin/env node
import { readFile } from "node:fs/promises";
import { verifyHumanOperatorOutput } from "./lib/human-namespace-cases.mjs";

const path = process.argv[2];
if (!path) throw new Error("output file is required");
const result = verifyHumanOperatorOutput(await readFile(path, "utf8"));
process.stdout.write(JSON.stringify(result) + "\n");
