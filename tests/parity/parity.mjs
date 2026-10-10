// Copyright 2026 Daher Alfawares
// SPDX-License-Identifier: Apache-2.0

// Runs one scenario on Google's Firebase JS SDK and on Ember at once, against the
// Firestore emulator, and checks both are told the same things in the same order:
// a missing document, then made, changed twice, and deleted. Each snapshot is compared
// by whether it exists and what it holds.
//
//     node tests/parity/parity.mjs        (from the repository, with build/listen built)

import { spawn } from "node:child_process";
import { initializeApp } from "firebase/app";
import { connectFirestoreEmulator, doc, getFirestore, onSnapshot, terminate } from "firebase/firestore";

const project = "demo-ember-parity";
const emulator = process.env.FIRESTORE_EMULATOR_HOST ?? "localhost:8080";
const [host, port] = emulator.split(":");
const path = `parity/run-${process.pid}`;
const api = `http://${emulator}/v1/projects/${project}/databases/(default)/documents/${path}`;
const owner = { Authorization: "Bearer owner", "Content-Type": "application/json" };
const pause = (ms) => new Promise((done) => setTimeout(done, ms));

// What's compared: whether it exists, and its fields, as plain JSON with sorted keys.
function sorted(value) {
  if (Array.isArray(value)) return value.map(sorted);
  if (value && typeof value === "object") return Object.fromEntries(Object.keys(value).sort().map((k) => [k, sorted(value[k])]));
  return value;
}
const line = (exists, data) => JSON.stringify({ exists, data: exists ? sorted(data) : null });

const js = [];
const firestore = getFirestore(initializeApp({ projectId: project }));
connectFirestoreEmulator(firestore, host, Number(port));
const unsubscribe = onSnapshot(doc(firestore, path), (s) => js.push(line(s.exists(), s.data())));

const cpp = [];
const child = spawn("build/listen", [project, path], { env: { ...process.env, FIRESTORE_EMULATOR_HOST: emulator } });
let buffered = "";
child.stdout.on("data", (chunk) => {
  buffered += chunk;
  let at;
  while ((at = buffered.indexOf("\n")) >= 0) {
    const s = JSON.parse(buffered.slice(0, at));
    buffered = buffered.slice(at + 1);
    cpp.push(line(s.exists, s.data));
  }
});

async function write(fields) {
  const r = await fetch(api, { method: "PATCH", headers: owner, body: JSON.stringify({ fields }) });
  if (!r.ok) throw new Error(`writing: ${r.status} ${await r.text()}`);
}

await pause(1500);
await write({ title: { stringValue: "made" }, count: { integerValue: "1" } });
await pause(800);
await write({ title: { stringValue: "changed" }, count: { integerValue: "2" }, done: { booleanValue: false } });
await pause(800);
await write({ title: { stringValue: "changed again" }, count: { integerValue: "3" }, tags: { arrayValue: { values: [{ stringValue: "a" }] } } });
await pause(800);
await fetch(api, { method: "DELETE", headers: owner });
await pause(1500);

unsubscribe();
await terminate(firestore);
child.kill();

const same = js.length === cpp.length && js.every((l, i) => l === cpp[i]);
console.log(`JS SDK, ${js.length} snapshots:\n  ${js.join("\n  ")}`);
console.log(`Ember, ${cpp.length} snapshots:\n  ${cpp.join("\n  ")}`);
console.log(same ? "ok: Ember is told what the JS SDK is told, in the same order" : "FAIL: Ember and the JS SDK were told different things");
process.exit(same ? 0 : 1);
