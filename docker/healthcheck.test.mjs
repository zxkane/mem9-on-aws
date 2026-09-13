import { createServer } from "node:http";
import { spawn } from "node:child_process";
import { once } from "node:events";
import { describe, expect, it } from "vitest";

const script = new URL("./healthcheck.mjs", import.meta.url).pathname;

describe("container health check", () => {
  it.each([200, 204, 302, 404, 503])("reports HTTP %i correctly", async (status) => {
    const server = createServer((req, res) => {
      res.writeHead(status, { location: "/healthy" });
      res.end();
    }).listen(0, "127.0.0.1");
    await once(server, "listening");
    try {
      const child = spawn(process.execPath, [script, `http://127.0.0.1:${server.address().port}/health`]);
      const [code] = await once(child, "exit");
      expect(code).toBe(status >= 200 && status < 300 ? 0 : 1);
    } finally {
      server.closeAllConnections();
      await new Promise((resolve) => server.close(resolve));
    }
  });

  it("fails when the endpoint does not respond within the deadline", async () => {
    const server = createServer(() => {}).listen(0, "127.0.0.1");
    await once(server, "listening");
    try {
      const child = spawn(process.execPath, [script, `http://127.0.0.1:${server.address().port}/health`]);
      expect((await once(child, "exit"))[0]).toBe(1);
    } finally {
      server.closeAllConnections();
      await new Promise((resolve) => server.close(resolve));
    }
  }, 7000);

  it("fails on connection refusal", async () => {
    const child = spawn(process.execPath, [script, "http://127.0.0.1:0/health"]);
    expect((await once(child, "exit"))[0]).toBe(1);
  });
});
