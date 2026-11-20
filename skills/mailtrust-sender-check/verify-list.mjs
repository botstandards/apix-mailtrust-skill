#!/usr/bin/env node
// Fetch the mailtrust mail-domain list, VERIFY its Ed25519 signature, and look up a sender domain.
//
// Wire contract (C2): GET /mail-domain-list returns { key_id, alg:"Ed25519", payload, signature },
// payload + signature base64url WITHOUT padding. The signature covers the EXACT decoded payload bytes —
// there is no canonicalisation. The directory ALSO serves its keys at GET /mail-domain-list/keys, but a
// client must NEVER trust a key the server hands it (that would be circular — a hostile response could
// supply its own key and a list signed with it). We PIN the signing key(s) below, out of band, and verify
// ONLY against those — the same model the mailtrust add-on uses.
//
// Usage:  node verify-list.mjs [sender-domain]
//   env MAILTRUST_BASE overrides the directory base URL (default https://mailtrust.api-index.org).
// Exit code 2 means the list did not verify — never trust it then.
import crypto from 'node:crypto';

const BASE = process.env.MAILTRUST_BASE || 'https://mailtrust.api-index.org';
const SPKI_PREFIX = Buffer.from('302a300506032b6570032100', 'hex'); // Ed25519 SubjectPublicKeyInfo header
const b64u = (s) => Buffer.from(s, 'base64url');

// Trust anchor: the mailtrust list-signing key(s), PINNED here out of band. Confirm each value against a
// trusted source (the directory operator's published raw key), NEVER by fetching it. On rotation, add the
// announced next key here in a new skill release, then drop the retired one — exactly like the add-on's
// addon/src/list/pinned-keys. Value = raw 32-byte Ed25519 public key, base64url without padding.
const PINNED_KEYS = {
  'mdl-2026-11': 'UHr213FCpcc_IGuqeWEvmR_hSCnmYSXkPOxzyRXTbQU',
};

function publicKey(rawB64u) {
  const raw = b64u(rawB64u);
  if (raw.length !== 32) throw new Error('public key must be 32 raw bytes');
  return crypto.createPublicKey({ key: Buffer.concat([SPKI_PREFIX, raw]), format: 'der', type: 'spki' });
}

async function getJson(path) {
  const r = await fetch(BASE + path, { headers: { accept: 'application/json' } });
  if (!r.ok) throw new Error(`GET ${path} -> HTTP ${r.status}`);
  return r.json();
}

// Returns { keyId, list, stale, ageSeconds }. Throws if the signature does not verify.
export async function fetchVerifiedList() {
  const env = await getJson('/mail-domain-list');
  if (env.alg !== 'Ed25519') throw new Error(`unexpected alg: ${env.alg}`);
  const pinned = PINNED_KEYS[env.key_id];
  if (!pinned) {
    throw new Error(`list is signed with key_id "${env.key_id}", which is NOT pinned in this skill — do ` +
      `not trust it. If mailtrust rotated its signing key, update PINNED_KEYS from a trusted source.`);
  }
  const payload = b64u(env.payload);
  const ok = crypto.verify(null, payload, publicKey(pinned), b64u(env.signature));
  if (!ok) throw new Error('SIGNATURE INVALID against the pinned key — do not trust this list');
  const list = JSON.parse(payload.toString('utf8'));
  const ageSeconds = Math.round((Date.now() - Date.parse(list.generated_at)) / 1000);
  return { keyId: env.key_id, list, stale: ageSeconds > list.max_age_seconds, ageSeconds };
}

// The directory's verdict for one domain. Green = accountable (NOT "harmless").
export function lookup(list, domain) {
  const d = String(domain).trim().toLowerCase().replace(/\.$/, '');
  const entry = (list.entries || []).find((e) => (e.mail_domain || '').toLowerCase() === d);
  if (entry && entry.status === 'active') {
    return {
      verdict: 'green', meaning: 'a verified organisation is accountable (not "harmless")',
      org: entry.legal_name, org_level: entry.org_level, org_id: entry.org_id,
      dkim_expected: entry.attestation, // {mode:"listed", keys:[{selector,sha256}]} or {mode:"self_hosted", endpoint}
      similar_to: entry.similar_to && entry.similar_to.length ? entry.similar_to : undefined,
    };
  }
  if (entry && entry.status === 'revoked') {
    return { verdict: 'red', meaning: 'trust was revoked for this domain', org_id: entry.org_id };
  }
  const look = (list.lookalike_corpus || []).find((c) => (c.primary_domain || '').toLowerCase() === d);
  return {
    verdict: 'grey', meaning: 'not listed — no statement possible',
    note: look ? `resembles the protected domain of "${look.legal_name}"` : undefined,
  };
}

if (process.argv[1] && process.argv[1].endsWith('verify-list.mjs')) {
  try {
    const { keyId, list, stale, ageSeconds } = await fetchVerifiedList();
    console.error(`OK  list verified — key_id=${keyId}, seq=${list.seq}, entries=${(list.entries || []).length}, age=${ageSeconds}s${stale ? '  (STALE: treat every lookup as grey)' : ''}`);
    const domain = process.argv[2];
    if (!domain) { console.log('pass a sender domain to look it up:  node verify-list.mjs example.com'); process.exit(0); }
    const result = stale ? { verdict: 'grey', meaning: 'the list is stale — no current statement' } : lookup(list, domain);
    console.log(JSON.stringify({ domain, ...result }, null, 2));
  } catch (e) {
    console.error(`FAIL  ${e.message}`);
    process.exit(2);
  }
}
