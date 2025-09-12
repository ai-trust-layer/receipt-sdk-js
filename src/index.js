import Ajv from "ajv/dist/2020.js";
import addFormats from "ajv-formats";
import draft7 from "ajv/dist/refs/json-schema-draft-07.json" assert { type: "json" };
import { createHash } from "crypto";
import { readFileSync } from "fs";

export function validateSchema(receipt, schemaPath) {
  const schema = JSON.parse(readFileSync(schemaPath,"utf8"));
  const ajv = new Ajv({ allErrors:true, strict:false });
  ajv.addMetaSchema(draft7);
  addFormats(ajv);
  const validate = ajv.compile(schema);
  const ok = validate(receipt);
  return { ok, errors: ok ? [] : validate.errors };
}

export function sha256Hex(buf) {
  return createHash("sha256").update(buf).digest("hex");
}

function norm(h) {
  if (!h || typeof h !== 'string') return "";
  return h.toLowerCase().replace(/^sha256:/, "");
}

export function verifyHashes({ input, output, receipt }) {
  const inHash = sha256Hex(Buffer.isBuffer(input)?input:Buffer.from(input));
  const outHash = sha256Hex(Buffer.isBuffer(output)?output:Buffer.from(output));
  const okIn = norm(receipt.input_hash) === inHash.toLowerCase();
  const okOut = norm(receipt.output_hash) === outHash.toLowerCase();
  return { ok: okIn && okOut, input: okIn, output: okOut };
}

// Stubs (înlocuibile ulterior cu implementări reale)
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
