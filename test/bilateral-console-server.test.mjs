import assert from "node:assert/strict";
import test from "node:test";

import { createConsoleServer } from "../src/bilateral/coordination/console-server.mjs";

test("console serves only fixed read-only no-store routes on loopback", async (t) => {
  const app = createConsoleServer({ projection: () => ({ paymentMoved: false }) });
  await new Promise((resolve) => app.listen(0, "127.0.0.1", resolve));
  t.after(() => app.close());
  const port = app.address().port;
  const home = await fetch(`http://127.0.0.1:${port}/`);
  assert.equal(home.status, 200); assert.equal(home.headers.get("cache-control"), "no-store");
  assert.match(home.headers.get("content-security-policy"), /default-src 'none'/);
  assert.equal((await fetch(`http://127.0.0.1:${port}/../package.json`)).status, 404);
  assert.equal((await fetch(`http://127.0.0.1:${port}/v1/console/session`, { method: "POST" })).status, 405);
  assert.deepEqual(await (await fetch(`http://127.0.0.1:${port}/v1/console/session`)).json(), { paymentMoved: false });
});
