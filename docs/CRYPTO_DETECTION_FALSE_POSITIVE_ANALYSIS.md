# Python crypto detection: root-cause analysis and fix (fork-local)

**Status:** Fixed in this fork. Not yet proposed upstream to CycloneDX/cdxgen.

**Summary:** Scanning a real Python codebase (a crypto SDK using
`cryptography`'s `AESGCM`, `ec.ECDSA`, `HKDF`, and `argon2-cffi`'s
`hash_secret_raw`) with `-t python --include-crypto --profile research`
produced a `cryptographic-asset` component named **`dsa`** (OID
`1.2.840.10040.4.1`, classical Digital Signature Algorithm) — the
codebase only ever implements ECDSA, never classical DSA. `sha-256` was
correctly detected. AES-256-GCM, HKDF, and Argon2id were not detected at
all. This document is the actual root-cause trace behind that result,
not a guess — every claim below was verified by reading this repo's own
source and by running patched/unpatched versions against real code.

## The false positive: `dsa` matched inside `ecdsa`

`findCryptoAlgos()` in `lib/inventory/cbomutils.js` (called from
`lib/evinser/evinser.js`'s `collectReachableFrames()`, on code snippets
atom tags as part of a "crypto flow") scans raw source text for every
one of the ~499 names in `data/crypto-oid.json`:

```js
// before
for (const algoName of Object.keys(cbomCryptoOids)) {
  if (cleanCode.includes(cleanStr(algoName))) { ... }
}
```

`cleanStr()` lowercases and deletes every character that isn't
`[0-9a-z ]` — no separator is substituted, so `"ec_dsa"` and
`"ecdsa"` both collapse to the identical string `"ecdsa"`. `"dsa"` is a
real dictionary key (ANSI X9.57's `id-dsa`, OID `1.2.840.10040.4.1`).
`"ecdsa"` was **not** a dictionary key at all — only hash-specific
compounds like `ecdsaWithSHA256` existed. So the only way any DSA-family
algorithm was ever detected in this codebase was accidental: `"dsa"`
matched as a plain substring of `"ecdsa"`, wherever that word appeared —
including inside an **error message string**,
`f"ecdsa signature must be exactly {n} bytes"`, which is what actually
triggered it. The real algorithm call site,
`ec.ECDSA(hashes.SHA256())`, would never have produced any match on its
own, because no bare `"ecdsa"` key existed to match against.

This is a real bug, not a one-off: `.includes()` has no notion of a
shorter candidate being a fragment of a longer, more specific candidate
that also matches. Any dictionary name that happens to be a substring of
a longer, unrelated word — in code, a comment, or a string literal, since
`cleanCode` is raw source text with no distinction between them — will
match.

## The fix: longest-match-wins, not word boundaries

A tempting fix is word-boundary regex (`\bdsa\b`). That would break a
real, intentional behavior: `cleanStr()`'s separator-deletion is what
lets a dictionary entry like `"sha-256"` match differently punctuated
source text like `SHA256` (no hyphen) once both are cleaned to
`"sha256"`. Word-boundary matching relies on separators surviving as
boundaries; `cleanStr()` deletes them by design. Introducing word
boundaries would silently stop matching real, currently-working
detections that depend on punctuation-insensitive comparison.

The fix implemented here (`findCryptoAlgos()`) keeps the same
substring-scan approach, but records the **position** of every match,
and drops any match that is fully contained within a *strictly longer*
match:

```js
// after (abridged -- see lib/inventory/cbomutils.js for the full version)
const rawMatches = [];
for (const algoName of Object.keys(cbomCryptoOids)) {
  const needle = cleanStr(algoName);
  let idx = cleanCode.indexOf(needle);
  while (idx !== -1) {
    rawMatches.push({ algoName, start: idx, end: idx + needle.length });
    idx = cleanCode.indexOf(needle, idx + 1);
  }
}
const isSubsumedByALongerMatch = (m) =>
  rawMatches.some(
    (other) =>
      other !== m &&
      other.start <= m.start &&
      other.end >= m.end &&
      other.end - other.start > m.end - m.start,
  );
```

With `"ecdsa"` now present as its own dictionary entry (see below), its
match at the same text position as `"dsa"` fully contains it, so `"dsa"`
is suppressed and only `"ecdsa"` is reported. This generalizes: it fixes
the whole *class* of "shorter name is a substring of a longer, unrelated
name" bug, not just this one instance, and doesn't touch `cleanStr()` or
risk the `sha-256`/`SHA256` case.

## Two missing dictionary entries, added with real, researched OIDs

`data/crypto-oid.json` had every `ecdsaWith*` hash-specific variant but
no bare `"ecdsa"` entry, and no `"hkdf"` entry of any kind. Both are
added:

- **`ecdsa`** → `1.2.840.10045.2.1` (ANSI X9.62 `id-ecPublicKey`). This
  is the EC key type identifier, the closest real analog to how the
  existing bare `"dsa"` entry represents the DSA key type (`id-dsa`) —
  X9.62 has no single hash-agnostic "ECDSA algorithm" OID the way X9.57
  has one for DSA; per-hash variants (`ecdsaWithSHA256`, etc.) are
  separate, more specific entries, unaffected by this change.
- **`hkdf`** → `1.2.840.113549.1.9.16.3.28` (RFC 8619
  `id-alg-hkdf-with-sha256`). HKDF itself (RFC 5869) has no
  hash-agnostic OID; RFC 8619 only defines per-hash variants
  (SHA-256/384/512). This bare entry uses the SHA-256 variant's OID as a
  representative default — matching on the bare word `"hkdf"` doesn't
  verify which hash was actually used, and the entry's description says
  so explicitly.
- **Argon2/Argon2id: deliberately not added.** No registered ASN.1 OID
  exists for Argon2 anywhere. RFC 9106 (the Argon2 RFC) does not define
  one, and this is a known, currently-open gap in the standards
  ecosystem itself — see
  [CycloneDX/specification#756](https://github.com/CycloneDX/specification/issues/756).
  Fabricating an OID to force an entry into this dictionary would be a
  worse data-integrity error than the current absence, so Argon2 usage
  remains undetectable via this OID-keyed matching approach until a real
  OID exists to register.

## What this fix does *not* address

AES-256-GCM (via `cryptography`'s `AESGCM` class) was **not** detected
before this fix, and is **still not** detected after it, despite `"aes"`
already being a valid dictionary entry that *would* match the cleaned
text `"aesgcm"` as a substring. The reason is upstream of
`findCryptoAlgos()` entirely: that function only ever runs on code
snippets that atom's semantic analysis has already tagged as part of a
"crypto flow" (`collectReachableFrames()`'s `tagStr.includes("crypto")`
check, in `lib/evinser/evinser.js`). The code region containing the real
`AESGCM(key)` call was never tagged as a crypto flow in the first place,
so it never reached `findCryptoAlgos()` at all — no amount of dictionary
or matching-logic fixing in this file changes that. The same is true for
Argon2id's `hash_secret_raw` call. Fixing this would mean changing
atom's own Python crypto-flow classification, which is a compiled
binary from a separate upstream project (`@appthreat/atom`), not
JavaScript source in this repository — out of scope for this fix, and
plausibly out of reach for a source-level patch here at all.

## Verification performed

- Before this fix: scanning a real Python package containing exactly
  these four crypto calls (`AESGCM`, `ec.ECDSA`, `HKDF`,
  `argon2.hash_secret_raw`) via the actual CLI (`-t python
  --include-crypto --profile research`) reported `sha-256` and `dsa`
  only.
- After this fix, same package, same command: reports `sha-256`,
  `ecdsa`, and `hkdf`. `dsa` no longer appears. AES-256-GCM and Argon2id
  still don't appear, consistent with the unaddressed root cause above
  — not silently claimed as fixed.
- `lib/inventory/cbomutils.poku.js` has new regression tests for
  `findCryptoAlgos()`: the dsa/ecdsa containment case, that real
  standalone `"dsa"` usage still gets detected (this fix doesn't
  suppress *legitimate* DSA usage, only the substring artifact), and
  that bare HKDF is now detected at all.
