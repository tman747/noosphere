# Wallet live submission

## Public iPhone wallet

The installable Harbor PWA is served at
`https://wwm.mindchain.network/wallet/`. On iPhone it requires Safari 17 or
newer; install it with **Share → Add to Home Screen**. It generates an Ed25519
key in the browser, stores only an AES-256-GCM encrypted vault in IndexedDB,
and sends canonical transaction bytes plus signatures through the scoped
public-testnet wallet gateway. Users must download the encrypted backup before
clearing Safari data.

The same-origin gateway exposes only fixed wallet operations: chain-bound
transfer construction, exact validator simulation, signed-envelope relay, and
a valueless `NOOS_TEST` faucet. Faucet claims are serialized, persisted, and
limited per account, client address, and day. Generic WWM gateway routes remain
read-only. The wallet is public-testnet-only (`production = false`) and must
never be presented as a mainnet or value-bearing wallet.

## Desktop wallet

The desktop shell reads immutable chain identities from
[`chain-profiles.json`](chain-profiles.json). The checked-in
`local-live-devnet` profile matches `python tools/e2e/local_devnet.py run`
at `127.0.0.1:18080`. The runner uses a fixed developer genesis identity and
retains state under `C:/tmp/noosphere-local-devnet`, so wallets do not silently
switch chains across restarts. A different deployment must add a concrete
profile with its actual chain ID, genesis hash, API version, HTTPS
public/indexer origin, and maximum acceptable status age. Runtime identity
fields are never entered or overridden in the transaction form.

Before signing, the shell fetches `/api/status`, matches the full configured
identity, checks freshness, and reads every `/api/v1/notes/{noteid}` input.
It builds the transaction through the existing `noos-cli` canonical builder,
decodes the result as `noos_lumen::objects::TransactionV1`, checks note-value
conservation, implicit single-account nonce shape, expiry/output birth height,
and the declared byte resource limit, then signs the canonical txid with the
purpose-separated wallet key under the Lumen transaction-signature domain.
The resulting witnesses are decoded as `TransactionWitnessesV1` before use.

Immediately before submission, status and note funds are fetched again. The
shell POSTs exactly `{"tx":"<lowercase hex>","witnesses":"<lowercase hex>"}`
to `/api/v1/transactions`. Only HTTP 200/202 with a well-formed, matching
protocol txid and one of `MEMPOOL`, `INCLUDED`, `JUSTIFIED`, or `FINALIZED` is
shown as success. Transport errors, stale/wrong-chain status, upstream
rejection, `REVERTED`/`REJECTED`, malformed JSON, and txid mismatch remain
errors.

The current form intentionally supports only complete note transfers: one
fee-payer account (the derived signing key), one or more live note inputs,
matching outputs, no fee authorization, actions, object access, or evidence,
and one lock reveal per input. All required Lumen fields must be supplied;
the shell only supplies profile-bound `chain_id`, fixed `format_version = 1`,
and the computed witness root. Seeds cross only the local webview-to-Tauri
command boundary; derived private keys remain in the local Rust process. No
secret material is logged, returned, persisted, or sent to the public API.
