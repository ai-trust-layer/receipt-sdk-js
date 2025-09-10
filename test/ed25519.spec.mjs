import assert from "node:assert/strict";
import * as ed25519 from "@noble/ed25519";
import { sha512 } from "@noble/hashes/sha512";
ed25519.etc.sha512Sync = (...m) => sha512(...m);

import { canonicalizeSubset, verifySignature } from "../src/index.mjs";

const PRIV_HEX = "0101010101010101010101010101010101010101010101010101010101010101";

function mkReceiptBase() {
  return {
    id: "rec_test_001",
    issued_at: "2025-09-10T12:00:00Z",
    input_hash:  "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    output_hash: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
    model_version: "gpt-x-2025-09-01",
    policy_version: "policy-v1.0"
  };
}

async function sign(receipt) {
  const msg = new TextEncoder().encode(canonicalizeSubset(receipt));
  const priv = Buffer.from(PRIV_HEX, "hex");
  const pub = await ed25519.getPublicKey(priv);
  const sig = await ed25519.sign(msg, priv);
  const kid = "ed25519:" + Buffer.from(pub).toString("hex");
  return { sig_b64: Buffer.from(sig).toString("base64"), kid };
}

(async () => {
  // valid
  {
    const r = mkReceiptBase();
    const { sig_b64, kid } = await sign(r);
    r.signature = { alg: "ed25519", kid, sig: sig_b64 };
    const res = await verifySignature(r);
    assert.equal(res.ok, true);
  }
  // invalid sig
  {
    const r = mkReceiptBase();
    const { sig_b64, kid } = await sign(r);
    // alter one byte
    const buf = Buffer.from(sig_b64, "base64");
    buf[0] ^= 0xff;
    r.signature = { alg: "ed25519", kid, sig: Buffer.from(buf).toString("base64") };
    const res = await verifySignature(r);
    assert.equal(res.ok, false);
    assert.equal(res.reason, "bad_signature");
  }
  // not provided
  {
    const r = mkReceiptBase();
    const res = await verifySignature(r);
    assert.equal(res.ok, false);
    assert.equal(res.reason, "not_provided");
  }
  console.log("ed25519.spec: PASS");
})().catch(e => { console.error(e); process.exit(1); });
