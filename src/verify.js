const fs = require('fs');
const crypto = require('crypto');
const Ajv = require('ajv');
const addFormats = require('ajv-formats');

const SCHEMA = JSON.parse(fs.readFileSync(__dirname + '/../schema/receipt.schema.json','utf8'));
const ajv = new Ajv({allErrors:true, strict:false});
addFormats(ajv);
const validate = ajv.compile(SCHEMA);

function validateSchema(receipt) {
  const ok = validate(receipt);
  return { ok, errors: ok ? [] : validate.errors };
}

function sha256Hex(buf) { return crypto.createHash('sha256').update(buf).digest('hex'); }
function stripPrefix(v){ return (v||'').replace(/^sha256:/i,'').toLowerCase(); }
function parseHex(hex){ return Buffer.from((hex||'').replace(/^0x/,''), 'hex'); }

function verifyHashes({ receipt, inputPath, outputPath, saltHex=null, mode='prefix' }) {
  const res = []; const salt = saltHex ? parseHex(saltHex) : null;

  if (receipt.input_hash && inputPath) {
    const data = fs.readFileSync(inputPath);
    const buf = salt ? (mode==='suffix' ? Buffer.concat([data,salt]) : Buffer.concat([salt,data])) : data;
    res.push({ field:'input_hash', ok: stripPrefix(receipt.input_hash) === sha256Hex(buf) });
  }
  if (receipt.output_hash && outputPath) {
    const data = fs.readFileSync(outputPath);
    const buf = salt ? (mode==='suffix' ? Buffer.concat([data,salt]) : Buffer.concat([salt,data])) : data;
    res.push({ field:'output_hash', ok: stripPrefix(receipt.output_hash) === sha256Hex(buf) });
  }
  const ok = res.length ? res.every(r=>r.ok) : true;
  return { ok, details: res };
}

function verifySignature(/*receipt*/){ return { ok:false, reason:'not_implemented' }; }

function verifyAnchor(receipt){
  const prs = Array.isArray(receipt.proof_refs) ? receipt.proof_refs : [];
  const ok = prs.every(p => p && typeof p.type==='string' && typeof p.network==='string' && typeof p.tx==='string');
  return { ok, count: prs.length };
}

module.exports = { validateSchema, verifyHashes, verifySignature, verifyAnchor };
