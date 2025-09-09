import Ajv from "ajv";
import addFormats from "ajv-formats";
import { createHash } from "crypto";
import { readFileSync } from "fs";

export function validateSchema(receipt, schemaPath) {
  const schema = JSON.parse(readFileSync(schemaPath,"utf8"));
  const ajv = new Ajv({ allErrors:true, strict:false });
  addFormats(ajv);
  const validate = ajv.compile(schema);
  const ok = validate(receipt);
  return { ok, errors: ok ? [] : validate.errors };
}

export function sha256Hex(buf) {
  return createHash("sha256").update(buf).digest("hex");
}

export function verifyHashes({ input, output, receipt }) {
  const inputHash = sha256Hex(Buffer.isBuffer(input)?input:Buffer.from(input));
  const outputHash = sha256Hex(Buffer.isBuffer(output)?output:Buffer.from(output));
  const okIn = (receipt.input_hash||"").toLowerCase() === inputHash.toLowerCase();
  const okOut = (receipt.output_hash||"").toLowerCase() === outputHash.toLowerCase();
  return { ok: okIn && okOut, input: okIn, output: okOut };
}

export async function verifySignature(){ return { ok:true, note:"stub" }; }
export async function verifyAnchor(){ return { ok:true, note:"stub" }; }

export function computeTrustScore(parts) {
  const w = { schema:0.5, hashes:0.4, signature:0.05, anchor:0.05 };
  let s = 0;
  if (parts.schema) s += 100*w.schema;
  if (parts.hashes) s += 100*w.hashes;
  if (parts.signature) s += 100*w.signature;
  if (parts.anchor) s += 100*w.anchor;
  return Math.round(s);
}
