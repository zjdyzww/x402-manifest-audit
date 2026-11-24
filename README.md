# Passive manifest audit — and the false positive it caught on its first run

A small tool that answers one question about an x402 provider: **do its public discovery documents still say what they used to say?** It fetches only the well-known discovery paths, one request per path, a named User-Agent, no retries, and it never calls a paid endpoint. The distinction matters: passive inspection can tell you a listing is malformed; it cannot tell you an endpoint still answers. This tool stays on the passive side of that line on purpose.

```bash
node audit-manifests.mjs --hosts "provider.example,another.example"
node audit-manifests.mjs --hosts "provider.example" --json
```

## The interesting part: its first real run produced a false positive

Run against `canaryseal.xyz`, the first version reported an inconsistency:

```
/.well-known/x402  -> declares 6 endpoints
/apis.json         -> declares 1
```

That reads like a provider contradicting itself. It was not. `apis.json` follows the APIs.json spec, which lists **one descriptor per API**; the x402 manifest lists **callable endpoints**. Six and one are answers to different questions. The tool was comparing across document families.

The fix is in the code: every document is classified (`x402-manifest`, `apis-descriptor`, `schema-descriptor`), counts are only compared **within** the x402-manifest family, and the JSON output states `comparisonScope: "x402-manifest only"` so no reader can mistake a descriptor count for a contradiction.

After the fix the same host reports:

```
/.well-known/x402       -> x402-manifest · declares 6
/.well-known/x402.json  -> x402-manifest · declares 6      (family consistent)
/apis.json              -> apis-descriptor · no endpoint count (descriptor)
```

## Why publish the bug

Because "I found an inconsistency in your data" is a claim that must survive the question *"or is my parser wrong?"* — and on the first run, it did not. A screening tool that has never been run against an answer you already know is not a screening tool; it is a hypothesis generator. This one was run, it was wrong, and the wrongness is documented here rather than quietly patched.

## What it does not do

- No paid endpoint is called; no authenticated request is made.
- No retries: a non-2xx answer is recorded as it came.
- No verdict when the response is ambiguous — `ambiguous` is a first-class outcome, not a failure.
- It does not verify schema validity or price correctness. It reports what is declared and whether documents of the same family agree.

## Licence

CC0-1.0. Reuse it, including the criticism.
