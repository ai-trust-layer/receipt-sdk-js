import * as ed from "@noble/ed25519";
import fs from "node:fs";

const PRIV = Buffer.alloc(32, 0x01); // aceeași cheie ca în testele Py
function canonicalizeSubset(r) {
  const keys = ["id","issued_at","input_hash","output_hash","model_version","policy_version"];
  const obj = {}; for (const k of keys) obj[k] = r[k];
  return JSON.stringify(obj);
}

const r = {
  id: "rec_js_001",
  issued_at: "2025-09-10T12:00:00Z",
  input_hash: "a".repeat(64),
  output_hash: "b".repeat(64),
  model_version: "gpt-x-2025-09-01",
  policy_version: "policy-v1.0"
};

const pub = await ed.getPublicKey(PRIV);
const msg = new TextEncoder().encode(canonicalizeSubset(r));
const sig = await ed.sign(msg, PRIV);

r.signature = {
  alg: "ed25519",
  kid: "ed25519:" + Buffer.from(pub).toString("hex"),
  sig: Buffer.from(sig).toString("base64")
};

if (process.argv[1] === new URL(import.meta.url).pathname) {
  process.stdout.write(JSON.stringify(r));
} else {
  fs.writeFileSync("signed.json", JSON.stringify(r));
}
