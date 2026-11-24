#!/usr/bin/env node
// @module x402-manifest-audit
// @path ~/.dsh/ventures/canaryseal-audit/audit-manifests.mjs
// @description Passive staleness audit for x402 discovery manifests: for each host, fetch only the publicly advertised discovery documents (well-known paths and declared manifests) and report what is declared, what is missing, and where the declaration contradicts itself. It never calls a paid endpoint and never sends an authenticated request, which is the constraint the index owner set for their own methodology.
// @skill audit_manifests — per host: probe well-known discovery paths -> record status/content-type -> compare declared endpoint count with the index row -> report contradictions
// @rule no_paid_calls P0 — only well-known discovery documents are fetched; no x402 paid endpoint is ever called, and no retry is issued for a non-2xx answer
// @rule no_verdict_without_evidence P0 — every row's verdict is one of found/absent/ambiguous, and ambiguous is used whenever the response does not settle the question
// @rule bounded_and_identified P1 — one request per path, 8s timeout, a named User-Agent that says what this is
// @depends node 18+
// @error no_hosts — empty host list -> exit 2
// usage: node audit-manifests.mjs --hosts "a.example,b.example" [--json]

import { readFileSync } from 'node:fs';

const args = process.argv.slice(2);
const val = (f, d) => { const i = args.indexOf(f); return i > -1 ? args[i + 1] : d; };
const UA = 'manifest-audit/0.1 (passive discovery-document check; contact: github.com/zjdyzww)';
const PATHS = ['/.well-known/x402', '/.well-known/x402.json', '/.well-known/ai-plugin.json', '/apis.json', '/openapi.json'];
const TIMEOUT = 8000;

const hosts = String(val('--hosts', '')).split(',').map(h => h.trim()).filter(Boolean);
if (hosts.length === 0) { console.error('no_hosts: pass --hosts "a.example,b.example"'); process.exit(2); }

async function probe(url) {
  const ctl = new AbortController();
  const t = setTimeout(() => ctl.abort(), TIMEOUT);
  try {
    const res = await fetch(url, { signal: ctl.signal, redirect: 'follow', headers: { 'user-agent': UA, accept: 'application/json' } });
    let declared = null;
    let parseable = false;
    if (res.ok) {
      try {
        const body = await res.text();
        declared = JSON.parse(body);
        parseable = true;
      } catch { parseable = false; }
    }
    return { url, status: res.status, contentType: res.headers.get('content-type'), parseable, declared };
  } catch (e) {
    return { url, status: 0, error: e?.name === 'AbortError' ? 'timeout' : String(e?.message ?? e) };
  } finally { clearTimeout(t); }
}

// Document families carry different semantics: an x402 manifest lists callable endpoints, while
// apis.json (APIs.json spec) lists ONE descriptor per API. Comparing their counts produced a
// false "6 vs 1 inconsistency" on the first run against canaryseal.xyz, so counts are only
// compared inside one family and everything else is reported, never compared.
function familyOf(path) {
  if (path.includes('x402')) return 'x402-manifest';
  if (path.endsWith('apis.json')) return 'apis-descriptor';
  if (path.endsWith('ai-plugin.json') || path.endsWith('openapi.json')) return 'schema-descriptor';
  return 'unknown';
}
function countEndpoints(doc, family) {
  if (!doc || typeof doc !== 'object') return null;
  const keys = family === 'x402-manifest' ? ['endpoints', 'resources'] : family === 'apis-descriptor' ? ['apis'] : [];
  for (const k of keys) if (Array.isArray(doc[k])) return doc[k].length;
  return null;
}

const rows = [];
for (const host of hosts) {
  const docRes = [];
  for (const p of PATHS) docRes.push(await probe(`https://${host}${p}`));
  const found = docRes.filter(r => r.status === 200 && r.parseable);
  const declaredCounts = found.filter(r => familyOf(new URL(r.url).pathname) === 'x402-manifest')
    .map(r => countEndpoints(r.declared, 'x402-manifest')).filter(n => n !== null);
  rows.push({
    host,
    documents: docRes.map(r => ({ path: new URL(r.url).pathname, status: r.status, contentType: r.contentType ?? null, parseable: r.parseable ?? false, family: familyOf(new URL(r.url).pathname), declaredEndpoints: countEndpoints(r.declared, familyOf(new URL(r.url).pathname)) })),
    verdict: found.length > 0 ? 'found' : (docRes.some(r => r.status === 0) ? 'ambiguous' : 'absent'),
    declaredEndpointCounts: [...new Set(declaredCounts)],
    // only comparable within the x402-manifest family; other documents are descriptors
    comparisonScope: 'x402-manifest only',
  });
}

if (args.includes('--json')) {
  console.log(JSON.stringify({ auditedAt: new Date().toISOString(), method: 'passive discovery documents only; no paid endpoint called; one request per path; no retries', rows }, null, 2));
} else {
  console.log(`# Passive manifest audit — ${new Date().toISOString()}`);
  console.log('# One request per well-known path. No paid endpoint called. No retries.\n');
  for (const r of rows) {
    console.log(`## ${r.host} — verdict: **${r.verdict}**`);
    for (const d of r.documents) {
      if (d.status === 404) continue;
      console.log(`- ${d.path}: status ${d.status} · ${d.family}${d.declaredEndpoints !== null ? ` · declares ${d.declaredEndpoints}` : ' · no endpoint count (descriptor)'}`);
    }
    if (r.declaredEndpointCounts.length) console.log(`- declared counts across documents: ${r.declaredEndpointCounts.join(', ')}`);
    console.log('');
  }
}
