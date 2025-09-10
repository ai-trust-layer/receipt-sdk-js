#!/usr/bin/env node
import fs from "node:fs";
import * as ed25519 from "@noble/ed25519";
import { sha512 } from "@noble/hashes/sha512";
ed25519.etc.sha512Sync = (...m) => sha512(...m);

function canonicalizeSubset(receipt) {
  const keys = ["id","issued_at","input_hash","output_hash","model_version","policy_version"];
  const obj = {};
  for (const k of keys) if (receipt[k] !== undefined) obj[k] = receipt[k];
  const sortObj = (o) => {
    if (Array.isArray(o)) return o.map(sortObj);
    if (o && typeof o === "object") {
      const out = {};
      for (const k of Object.keys(o).sort()) out[k] = sortObj(o[k]);
      return out;
    }
    return o;
  };
  return JSON.stringify(sortObj(obj));
}

async function verifySignature(receipt) {
  const s = receipt?.signature;
  if (!s) return { ok:false, reason:"not_provided" };
  if (s.alg !== "ed25519") return { ok:false, reason:"alg_unsupported" };
  if (!s.sig) return { ok:false, reason:"sig_missing" };
  let pubHex = null;
  if (typeof s.kid === "string" && s.kid.startsWith("ed25519:")) pubHex = s.kid.split(":")[1];
  if (!pubHex) return { ok:false, reason:"kid_unresolved" };
  const msg = new TextEncoder().encode(canonicalizeSubset(receipt));
  const sig = Buffer.from(s.sig, "base64");
  const pub = Buffer.from(pubHex, "hex");
  const ok = await ed25519.verify(sig, msg, pub);
  return ok ? { ok:true } : { ok:false, reason:"bad_signature" };
}

const file = process.argv[2];
if (!file) { console.error("Usage: receipt-verify <receipt.json>"); process.exit(2); }
const r = JSON.parse(fs.readFileSync(file, "utf8"));
const res = await verifySignature(r);
if (!r.signature) console.log("signature: not present");
else console.log(res.ok ? "signature: PASS" : `signature: FAIL (${res.reason||"unknown"})`);
