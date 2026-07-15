# WWM static host seeder recipes

These recipes publish an exported `STATIC_HOST_SEEDER` bundle. This class is experimental, unrewarded, and outside production custody accounting. A deployment is not authorized merely because its files are public: the coordinator owner must add the exact origin and failure-domain metadata to `source_allowlist`, then the coordinator must verify the live HTTPS host.

## 1. Export and verify the canonical bundle

Create a coordinate selection file. Coordinates may arrive in any order; duplicate or out-of-range rows are rejected and the exported inventory is strictly ordered.

```json
{
  "coordinates": [
    { "stripe": 0, "position": 0 },
    { "stripe": 227, "position": 6 },
    { "stripe": 453, "position": 11 }
  ]
}
```

Set a 32-byte Ed25519 seed as 64 lowercase hex characters in a private environment variable. Do not put the seed on the command line or in the bundle.

```sh
noos-artifact-service export-web-bundle \
  --store-root /var/lib/noos-artifacts \
  --consensus-root /var/lib/noos-consensus-placeholder \
  --quota-bytes 8589934592 \
  --output-root /srv/noos-wwm-web-capacity \
  --origin https://shares.example.org \
  --chain-id <canonical-lowercase-hex32> \
  --genesis-hash <canonical-lowercase-hex32> \
  --coordinates ./coordinates.json \
  --host-signing-seed-env WWM_WEB_HOST_SIGNING_SEED \
  --valid-from <unix-seconds-now> \
  --expires-at <unix-seconds-within-31-days> \
  --license deploy/wwm/licenses/Bonsai-27B/LICENSE.txt \
  --notice deploy/wwm/licenses/Bonsai-27B/NOTICE.txt \
  --report ./web-bundle-export-report.json

noos-artifact-service verify-web-bundle \
  --store-root /var/lib/noos-artifacts \
  --consensus-root /var/lib/noos-consensus-placeholder \
  --quota-bytes 8589934592 \
  --bundle-root /srv/noos-wwm-web-capacity \
  --origin https://shares.example.org \
  --chain-id <same-canonical-lowercase-hex32> \
  --genesis-hash <same-canonical-lowercase-hex32> \
  --report ./web-bundle-verification-report.json
```

The exporter reads the canonical artifact manifest and share bytes from the isolated artifact store. It computes transport SHA-256 itself and verifies every selected `(stripe, position)` against the canonical `noos-da` share commitment and probe root. No command accepts a precomputed share digest as proof.

## 2. Publish without transforming bytes

Choose one recipe:

- **Nginx:** install `nginx.conf` as a dedicated server block, substitute `NOOS_WWM_STATIC_HOST`, configure the certificate/key through the surrounding Nginx configuration, and keep the bundle at `/srv/noos-wwm-web-capacity`.
- **Caddy:** set `NOOS_WWM_STATIC_HOST` to the hostname only and install `Caddyfile`. Caddy obtains HTTPS certificates; no `encode` directive is enabled.
- **Cloudflare Pages or Netlify:** copy `_headers` into the deployment root beside the exported bundle. Do not add an SPA fallback or redirect rule over the canonical paths. Disable provider-side transformation for `application/octet-stream` if the account has an additional optimization feature enabled.
- **CloudFront:** apply `cloudfront.tf`; attach the share policies to `/shares/*`, the manifest policies only to `/.well-known/noos/wwm-web-capacity-v1.json`, the inventory policies only to `/inventory-v1.json`, and the legal policies to `/LICENSE.txt` and `/NOTICE.txt`. Leave all compression flags false. The inventory cache policy has zero TTL and its response policy requires revalidation; do not merge it back into the 60-second manifest policy. The origin must return the exported files directly, not a rewrite or signed-URL redirect.

Every share response must be the exact 1,047,552-byte identity representation with `Content-Length`, `Accept-Ranges: bytes`, `Access-Control-Allow-Origin: *`, and an `immutable` cache-control token. The live verifier rejects redirects, wrong origins, transformed bytes, missing range/CORS/cache headers, bad lengths, bad license/NOTICE hashes, bad transport SHA-256 values, and any share that fails canonical `noos-da` verification.

### Renew a signed manifest without exposing stale inventory

Treat the fixed `/inventory-v1.json` path as mutable signed metadata even though shares, `LICENSE.txt`, and `NOTICE.txt` stay immutable. Every recipe sends `Cache-Control: public, max-age=0, no-cache, must-revalidate` for inventory and keeps the host manifest at `public, max-age=60, must-revalidate`.

Renew in stages: first remove or withhold the new well-known manifest, then publish the new inventory and invalidate any provider cache for `/inventory-v1.json`. Fetch that exact public HTTPS URL without following redirects and confirm its bytes and SHA-256 match the pending signed manifest. Only after the new inventory is visible may the 60-second manifest be published. This ordering can briefly make the host unavailable, which is the required fail-closed behavior; never publish the new manifest first. Do not purge or rewrite immutable shares, `LICENSE.txt`, or `NOTICE.txt` during renewal.

## 3. Add explicit owner authorization

Render one exact `source_allowlist` entry. The command validates the canonical HTTPS origin and the three bounded failure-domain fields; it never edits coordinator configuration automatically.

```sh
python tools/operations/wwm_static_host.py source-record \
  --origin https://shares.example.org \
  --provider example-cdn \
  --region eu-west \
  --control-cluster example-account-a \
  --output ./source-allowlist-entry.json
```

Insert that exact object into the coordinator's `source_allowlist` and restart only the isolated `noos-web-capacityd` process. Do not add the hosting origin to browser mutation CORS unless it also serves the browser capacity UI; source authorization and browser request authorization are separate lists.

## 4. Verify the live host through the coordinator

Use a canonical HTTPS request origin already present in the coordinator's `registered_origins` and deployed `authorize_mutation` allowlist. The operator command sends no cookie or authorization credential and refuses coordinator redirects. For local fixtures, `--allow-http-loopback` relaxes only `--coordinator-origin`; both `--request-origin` and `--host-origin` remain canonical HTTPS.

```sh
python tools/operations/wwm_static_host.py register \
  --coordinator-origin https://capacity.example.org \
  --request-origin https://operator.example.org \
  --host-origin https://shares.example.org \
  --timeout-seconds 15 \
  --output ./static-host-registration-report.json
```

Success is HTTP 201 with `participant_class=STATIC_HOST_SEEDER`, `admission_class=StatelessReissueable`, `production_custody=false`, and `rewards=false`. Retain the export, local verification, and coordinator registration reports together. A failed live probe is a failed registration; do not bypass it by editing the coordinator database.

## 5. Expire or withdraw a host honestly

Remove `/.well-known/noos/wwm-web-capacity-v1.json` to withdraw the host, or let its signed validity interval expire. The coordinator revalidates active hosts at least once every 60 seconds. A missing, invalid, unauthorized, or expired manifest deactivates that origin for future assignments; a later recovery requires a new successful registration. Host refresh uses a generation check, so an old failed probe cannot deactivate a newer successful registration.

Withdrawal does **not** recall an assignment already issued to a browser and does **not** erase bytes from browsers, CDNs, intermediary caches, mirrors, or other third parties. The shares were intentionally public under Apache-2.0 and immutable caching was part of the signed transport policy. UI and operator copy must say “stops future assignments,” never “deletes all copies” or “erases the model from the web.” Local browser deletion, when requested, applies only to that app-owned browser namespace.
