import * as ed from "@noble/ed25519";

const SUBSET_KEYS = ["id","issued_at","input_hash","output_hash","model_version","policy_version"];
const canonicalizeSubset = (r) => {
  const obj = {};
  for (const k of SUBSET_KEYS) {
    if (r[k] === undefined) throw new Error(`missing ${k}`);
    obj[k] = r[k];
  }
  return JSON.stringify(obj);
};

const PRIV = Buffer.alloc(32, 0x01);

const r = {
  id: "rec_js_interop",
  issued_at: "2025-09-10T12:00:00Z",
  input_hash: "a".repeat(64),
  output_hash: "b".repeat(64),
  model_version: "gpt-x-2025-09-01",
  policy_version: "policy-v1.0"
};

const msg = new TextEncoder().encode(canonicalizeSubset(r));
const pub = await ed.getPublicKey(PRIV);
const sig = await ed.sign(msg, PRIV);

r.signature = {
  alg: "ed25519",
  kid: "ed25519:" + Buffer.from(pub).toString("hex"),
  sig: Buffer.from(sig).toString("base64")
};

process.stdout.write(JSON.stringify(r));
