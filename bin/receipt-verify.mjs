#!/usr/bin/env node
import fs from "node:fs";
import { verifySignature } from "../src/index.mjs";

const file = process.argv[2];
if (!file) {
  console.error("Usage: receipt-verify <receipt.json>");
  process.exit(2);
}
const r = JSON.parse(fs.readFileSync(file, "utf8"));

let sigLine = "signature: not present";
if (r.signature) {
  const res = await verifySignature(r);
  sigLine = res.ok ? "signature: PASS" : `signature: FAIL (${res.reason||'unknown'})`;
}

console.log(`File: ${file}`);
console.log(sigLine);
process.exit(0);
