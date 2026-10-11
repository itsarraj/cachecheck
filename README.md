# cachecheck

Audits a live URL's HTTP caching headers (`Cache-Control`, `ETag`,
`Last-Modified`, `Expires`) for common misconfigurations — the kind that
usually go unnoticed until someone's manually inspecting response
headers in browser devtools after a caching bug report.

## Installation

```sh
cargo install --path .
```

## Usage

```bash
cachecheck https://example.com/static/app.js
```

Exit code `1` if anything is found.

## Rules checked

- **`no_cache_headers`** — neither `Cache-Control` nor `Expires` is set
  at all; caching behavior is left entirely to client defaults, which
  differ across browsers/CDNs/proxies.
- **`no_store_with_validators`** — `Cache-Control: no-store` is set
  alongside an `ETag` or `Last-Modified` header. Those validators exist
  to support conditional revalidation, which `no-store` explicitly
  forbids — they're dead weight on the response.
- **`etag_without_cache_control`** — an `ETag` is present but
  `Cache-Control` is missing, a validator with no caching policy
  actually attached to it.
- **`expires_in_the_past`** — the `Expires` header parses to a real
  date that's already passed, and `Cache-Control` doesn't already say
  `no-cache`/`no-store` (which would make an already-past `Expires`
  intentional rather than a stale hardcoded leftover).

## Status: built and verified against a real local HTTP server, not just unit fixtures

- **11 unit tests** (`cargo test --lib`): every rule's positive and
  negative case (a clean `max-age` response has zero findings;
  `no-store` alone with no validators is clean; `Expires` in the future
  is clean; a malformed `Expires` value is ignored rather than causing
  an error), case-insensitive header name lookup (`Cache-Control` vs.
  `cache-control`), and the `no-cache`/`no-store` override that makes a
  past `Expires` intentional rather than flagged.
- **Live-verified against a real local HTTP server**, not just the pure
  audit function in isolation: ran a real Python `http.server` on a real
  local port with three real endpoints — one returning a clean
  `Cache-Control: public, max-age=3600`, one returning both `ETag` and
  `Cache-Control: no-store` together, and one returning no caching
  headers at all. The actual compiled binary made a real HTTP request to
  each and correctly reported zero issues, the `no_store_with_validators`
  finding, and the `no_cache_headers` finding respectively, with the
  right exit codes (`0`, `1`, `1`).

**Not done / deliberately deferred**: `Vary` header auditing (a
`Vary: *` effectively disables caching entirely and is worth flagging,
but isn't checked here); CDN-specific headers (`CDN-Cache-Control`,
`Surrogate-Control`) aren't considered, only the standard HTTP caching
headers; no crawl mode — this checks exactly one URL per run, not a
whole site's asset list.
