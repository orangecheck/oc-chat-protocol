# oc chat — specification (v0)

**Status:** draft. OC Chat is a **mode of OC Lock**, not a new verb. It extends the OC Lock v2 envelope ([`oc-lock-protocol/SPEC.md`](https://github.com/orangecheck/oc-lock-protocol/blob/main/SPEC.md)) with two `kind` values and a thin threading / postage / seal layer. The base cryptography (X25519 ECDH + HKDF-SHA256 + AES-256-GCM, RFC 8785 canonicalization, BIP-322 identity binding) is **unchanged and not restated here** — read the OC Lock spec first.

This document uses the key words MUST, MUST NOT, SHOULD, MAY per [RFC 2119](https://www.rfc-editor.org/rfc/rfc2119).

## 0. Notation

- `env` — an OC Lock envelope (OC Lock SPEC §4.1).
- `canonical(x)` — RFC 8785 canonical bytes of `x`, LF-terminated, with `recipients[]` sorted by `device_id` ascending (OC Lock SPEC §5).
- `SHA-256(x)` — 32-byte digest; hex unless stated.
- `addr` — a Bitcoin address; the user's identity (OC Lock SPEC §2).
- A **device record** — a kind-30078 Nostr event binding an X25519 `device_pk` to `addr` via BIP-322 (OC Lock SPEC §3).

## 1. What OC Chat adds

OC Chat is OC Lock operating continuously over a thread, plus three things the base protocol does not have:

1. A **recipient-independent content id** so a held envelope can be re-keyed after the fact (§3).
2. Three canonical **send modes** — `speak-now`, `pay-to-reach`, `seal-til-block` (§4) — each adding exactly one Bitcoin-unique property (identity, Lightning preimage, block-height predicate).
3. **Encrypted threading** with a verifiable hash-chain (§5).

Everything else (group keys, double-ratchet forward secrecy, the CLTV-witness seal) is a registry extension under reserved kinds (§10), not a canonical surface.

## 2. Envelope kinds

OC Chat introduces two new values for the OC Lock envelope `kind` field, alongside the existing `"identity"` and `"payment"`:

| `kind` | Mode | New fields |
|---|---|---|
| `"chat"` | `speak-now` / `pay-to-reach` | optional `postage` (§6) |
| `"chat-seal"` | `seal-til-block` | `seal` (§7) |

A conforming OC Lock implementation that does not understand these kinds MUST reject them (OC Lock SPEC §9 unknown-`kind` handling) rather than mis-decrypt. The transport (§8) is OC Lock's gift-wrap, unchanged.

## 3. Content addressing for chat kinds (the recipient-exclusion rule) — NORMATIVE

This is the one cryptographic rule that differs from base OC Lock, and it is load-bearing.

In base OC Lock, the envelope `id` is `SHA-256(canonical(env | id="", sig.value=""))` and the AEAD AAD is `SHA-256(canonical(env | id="", ciphertext="", sig.value="", recipients[*].wrapped_key=""))` — both include the `recipients[]` identities. That makes the envelope un-re-keyable: changing `recipients[]` after sealing changes the `id` (breaking the BIP-322 signature) and the AAD (breaking the ciphertext tag).

For `kind ∈ { "chat", "chat-seal" }`, the `recipients[]` array is **delivery routing, not content**, and is excluded from both:

```
chat_aad      = SHA-256( canonical( env | id="", ciphertext="", sig.value="", recipients=[] ) )   // 32 bytes, the GCM AAD
chat_envelope_id = SHA-256( canonical( env | id="", sig.value="", recipients=[] ) )                // hex, committed by sig
```

Consequences a conforming implementation MUST honor:

1. The `id` commits to everything **except** `recipients[]`: `v`, `kind`, `alg`, `from`, `ciphertext`, `nonce_ct`, `hint`, `created_at`, `expires_at`, `payment`, `postage` (§6), `seal` (§7). Changing any of these changes the `id`.
2. The sender's `sig.value` is BIP-322 over `chat_envelope_id` (OC Lock SPEC §4.2).
3. A holder MAY replace `recipients[]` entirely (a **re-wrap**, §7.3) and the `id`, `sig`, and ciphertext tag remain valid. The re-wrap output is a **detached `recipients[]` entry** the client merges locally; it MUST NOT recompute the signed `id`.
4. The ciphertext AAD is `chat_aad`, which is also recipient-independent, so the GCM tag survives a re-wrap.

> Test vector `vc04-seal-rewrap-stability` proves this end-to-end: a `chat-seal` envelope sealed to a beacon device (`id = 21fcec92…`) is re-wrapped to a recipient device; `id_after == id_before` and the recipient's ciphertext tag verifies.

`recipients[]` entries are otherwise structured exactly as OC Lock SPEC §4.1 (`address`, `device_id`, `device_pk`, `eph_pk`, `wrapped_key`, `nonce_kek`) and sorted by `device_id` in any canonical form that includes them (wire interop), even though they do not enter the `id`.

## 4. The three canonical send modes

### 4.1 `speak-now` (free)

`kind="chat"`, no `postage`, no `seal`. An identity-mode envelope sealed to the recipient's device keys (OC Lock SPEC §4.2). Per-device X25519 authenticates the send; **the sender does NOT sign each message with BIP-322** — BIP-322 is performed once per device at device-record binding time (OC Lock SPEC §3.2). `sig.value` MAY therefore be a per-device key attestation rather than a wallet signature; clients that require wallet-grade sender proof MAY still populate it. Receiving is never gated by payment.

Free-tier anti-spam is recipient policy, enforced by the recipient client, not the protocol: require a mutual contact, OR a BIP-322 proof of control of a funded/aged UTXO. Neither involves a payment.

### 4.2 `pay-to-reach` (paid, peer-to-peer)

`kind="chat"` with a `postage` block (§6). A stranger's first message to a recipient who has published a postage floor MUST carry a valid Lightning preimage proving payment to the recipient. Messages lacking valid postage are placed by the recipient client in a pending tray, not the inbox. The payment is **sender → recipient direct**; no OC service is in the path (§6.4).

### 4.3 `seal-til-block` (the timelock mode)

`kind="chat-seal"` with a `seal` block (§7). The `content_key` is wrapped to a **named beacon** device, not the recipient; the beacon releases it only after the Bitcoin chain passes `seal.unlock_block`. **This is beacon-enforced policy, not Bitcoin consensus** (§7, SECURITY.md). The word "trustless" MUST NOT be used to describe a `kind="chat-seal"` envelope whose `seal.anchor` is `"beacon"`.

## 5. Threading

Thread state is **inside the encrypted payload**, never the plaintext envelope (OC Lock SPEC §7.2 declines plaintext ordering). The decrypted payload of a chat envelope is UTF-8 JSON:

```json
{
  "body": "<message text or a typed structure>",
  "conversation_id": "<stable thread label>",
  "seq": <integer, monotonic per sender within the thread>,
  "parent_id": "<chat_envelope_id of the parent message, or null for the first>",
  "recv_queue": "<optional; base64url; my durable-inbox queue_id (§8.1) for this conversation — deposit future messages to me here>"
}
```

- `conversation_id` is a stable label. The RECOMMENDED default is `SHA-256` of the two Bitcoin addresses sorted ascending and joined with `:` — a deterministic 1:1 thread id requiring no negotiation.
- `recv_queue` is the optional durable-inbox handshake (§8.1.3): the sender advertises its own per-conversation `queue_id` so the peer routes durable deposits to it instead of the bootstrap queue. It is carried inside the AEAD-sealed payload so the inbox operator never learns the mapping. A client that omits it simply keeps using the bootstrap queue.
- **`parent_id` MUST equal the `chat_envelope_id` of the message it replies to** (or `null` for the first in a thread). This makes each thread a verifiable hash-chain: a client MUST order and validate by the `parent_id` chain, and MUST NOT trust `created_at` (which is plaintext and untrusted) for ordering. A missing parent is a detectable gap.

This gives per-thread tamper-evidence. It is NOT a transport-layer anti-replay or anti-reorder guarantee: a relay can still withhold or delay delivery (§SECURITY).

## 6. Postage (anti-spam)

### 6.1 Recipient policy
A recipient MAY publish a postage policy: a `floor_sats` and a Lightning receiving endpoint resolving to a wallet the **recipient** controls. The published endpoint string MUST live inside a record **signed by the recipient's Bitcoin identity** (e.g. the kind-30078-bound directory listing, §8.2) — otherwise an attacker substitutes their own endpoint and the §6.3 recipient-binding binds to the wrong party. No OC service mints, proxies, or relays this invoice.

The endpoint is a **BOLT12 offer (RECOMMENDED, stronger)** or — the **shipped v0 rail** — an **LNURL Lightning Address** (LUD-16) with **LUD-18 payerData**. v0 ships LNURL because BOLT12 `invoice_request` cannot reliably echo a per-DM nonce today (§6.3). For the binding to hold, the recipient endpoint MUST mint a **fresh per-DM invoice** committing the sender's nonce; a static/reusable invoice degrades the proof to settlement-evidence-only.

### 6.2 Sender postage block
In v0, `postage` rides **inside the encrypted `ChatBody`** (§5), NOT as a top-level envelope field — the shipped OC Lock `seal()` cannot take a `postage` parameter, so it cannot commit it in the `chat_envelope_id` field-by-field. Integrity therefore rests on the AEAD: `postage` is inside the ciphertext, which IS committed in the `id` and signed by the device, so any tamper changes the ciphertext → the `id` → breaks the signature. (True §3 per-field commitment is a deferred lock-core change.)

```jsonc
"postage": {
  "floor_sats":   <integer>,
  "amount_sats":  <integer, >= floor_sats>,
  "payment_hash": "<64-char hex>",
  "preimage":     "<64-char hex>",
  "nonce":        "<hex; the sender's per-DM nonce, carried in payerData>",
  "recipient":    "<recipient btc address — must match the endpoint's identifier>",
  // carrier fields the recipient needs to re-verify the binding OFFLINE:
  "bolt11":         "<the paid invoice; carries payment_hash + the description_hash 'h' tag>",
  "lnurl_metadata": "<the recipient endpoint's metadata, VERBATIM bytes>",
  "payerdata":      "<the url-encoded payerData the sender sent (carries the nonce)>"
}
```

### 6.3 Verification (recipient-side, mostly offline) — NORMATIVE
This was a blocking open item; v0 **specifies** a recipient-side, per-DM, non-replayable construction (honestly **not** a transferable third-party proof). A recipient verifying inbound `postage` MUST:

1. **Settlement:** `SHA-256(preimage) == payment_hash` — the load-bearing Lightning bearer proof.
2. **Binding (re-derived by OC itself):** decode `bolt11`, read its description-hash (`h`) tag, and assert it equals `SHA-256( lnurl_metadata || urlDecode(payerdata) )`. The verifier MUST recompute this hash **itself** — wallets stopped enforcing the LNURL description-hash (lnurl PR #234, 2026-05) — and MUST hash the **verbatim** `lnurl_metadata` bytes (never `JSON.stringify(JSON.parse(x))`, which reorders and breaks the match).
3. **Recipient:** the `lnurl_metadata` `text/identifier` equals the claimed `recipient`, resolved from an identity-signed endpoint (§6.1).
4. **Amount:** the `bolt11` carries an explicit amount AND `amount_sats >= floor_sats` (reject amountless invoices).
5. **Nonce:** the in-body `nonce` is the one committed in `payerdata`.
6. **Anti-replay:** the `payment_hash` is not in the recipient's **local spent-ledger** (one-time use). On accept, record it.

The recipient does **NOT** re-enforce the invoice's expiry: the preimage already proves the HTLC settled, and a short (e.g. 1h) invoice expiry would wrongly reject valid postage that took longer than that to *deliver*. Invoice freshness is the **sender's** pay-time concern (don't pay an expired invoice); per-DM freshness is supplied by the nonce + the spent-ledger.

All checks pass + not-spent → inbox. Any fail OR already-spent → the message is **held in the Requests tray** (§6 free-tier path), never dropped.

**Why this is non-replayable (and its honest ceiling):** because the recipient's *own* endpoint minted the per-DM invoice committing **this** recipient + amount + nonce into the description-hash, a preimage replayed to a *different* recipient fails the binding there (that recipient never minted that metadata/nonce); a preimage replayed to the *same* recipient is caught by the local spent-ledger. The residual ceiling is named in SECURITY S7: this is **recipient-scoped**, not a proof a third party who sees only `{preimage, nonce}` can verify; the recipient's LNURL endpoint is a **named trust anchor**; and a cold observer can check the hash/binding but cannot independently confirm the HTLC settled.

### 6.4 No OC payment rail
OC operates no postage gateway. Any Lightning gateway in a recipient's postage path is operated by a NAMED third party, never OC. Zap receipts (NIP-57) MUST NOT be used as postage proof — they are server-signed and forgeable; only the BOLT11/BOLT12 preimage is a bearer proof.

## 7. Seal (`seal-til-block`)

### 7.1 Seal block
```json
"seal": {
  "unlock_block":    <integer Bitcoin block height>,
  "anchor":          "beacon" | "cltv",
  "beacon_id":       "<named beacon identifier, e.g. 'drand:quicknet'>",
  "beacon_url":      "<https endpoint of the beacon>",
  "redundant_beacon":<null | a second beacon descriptor>,
  "confirmations":   <integer k, blocks past unlock_block before release>,
  "cltv_outpoint":   "<optional; reserved for anchor='cltv' (§7.4)>"
}
```

`seal` is committed in the `id` (§3): changing `unlock_block` or any beacon field changes the `id` and breaks the sender signature.

### 7.2 Sealing
The sender wraps `content_key` to the **beacon's** device key (the beacon publishes a device record like any recipient), sets `kind="chat-seal"` and the `seal` block, and signs. The intended recipient receives the ciphertext immediately but holds no key.

### 7.3 Release (re-wrap)
After block `unlock_block + confirmations` confirms:
1. The recipient authenticates to the beacon over OC sign-in (BIP-322 challenge-response).
2. The beacon verifies `chain_tip >= unlock_block + confirmations` against its own Bitcoin node (and, for `anchor="beacon"` with a drand backend, that the corresponding drand round has elapsed).
3. The beacon unwraps `content_key` with its `device_sk` and re-wraps it for the recipient's authenticated device, returning a **detached `recipients[]` entry** (§3.3).
4. The recipient merges the entry and decrypts. The `id` and ciphertext tag are unchanged (§3, vector `vc04`).

The recipient SHOULD independently re-check `unlock_block` against their own node or a named explorer before trusting the release.

### 7.4 Trust posture (NORMATIVE honesty)
- For `anchor="beacon"`: the seal is **enforced by the named beacon, not by Bitcoin consensus**. A colluding beacon threshold can release early; beacon disappearance permanently bricks the seal. Block height is the **predicate the beacon honors**, not the enforcer. Implementations MUST surface the beacon identity and this risk at compose time and MUST NOT label the envelope "trustless".
- For `anchor="cltv"` (reserved, not shipped in v0): `content_key` is committed to a P2WSH output encumbered by `OP_CHECKLOCKTIMEVERIFY` at `unlock_block`; spending after the height reveals the key in the witness, so any chain observer extracts it — Bitcoin consensus is the enforcer. `cltv_outpoint` carries the outpoint. This is the structural upgrade path; a deployment MUST NOT advertise it as available until a conformance vector and a browser-shippable witness-extraction build exist.

### 7.5 Redundant beacons
If `redundant_beacon` is set, `content_key` is escrowed independently to BOTH beacons so EITHER release unlocks. Implementations MUST disclose that this **halves brick risk but doubles early-release surface**: either beacon's threshold can decrypt the body early. A sealed message's UI MUST read "readable early by {named quorum}", not "unlocks at block N".

### 7.6 v0 in-ciphertext drand-tlock profile — NORMATIVE (what ships)

§7.2–7.3 describe the spec-pure path: a beacon *device* re-wraps `content_key` on authenticated release, and the `seal` block is a committed top-level envelope field. That path needs an `@orangecheck/lock-core` change — the shipped `lock-core@1.0.1` exposes only `EnvelopeKind = 'identity' | 'payment'`, no `chat-seal` kind, and no committed top-level `seal` field. It is the named **upgrade target** (vectors `vc03`/`vc04`), NOT what v0 deploys.

**v0 deploys the in-ciphertext drand-tlock profile**, identical in shape to the postage carrier (§6.2):

- The readable `body` is the **empty string**. The real text is `AES-256-GCM(key = R, nonce, plaintext = text)` carried as `seal.locked_ct` + `seal.nonce`, where `R` is a fresh 32-byte reveal secret.
- `R` is **timelock-encrypted to a future drand round** (`seal.tlock`, an age-armored `tlock` blob), released by the named beacon `drand:quicknet` — NOT by an OC beacon device, and with **no OC re-wrap endpoint** (drand IS the beacon; anyone can decrypt `R` once the round's BLS signature publishes).
- The seal block rides **inside the encrypted ChatBody**, so its integrity rests on the AEAD: the ciphertext is committed in the envelope `id` and device-Schnorr-signed (§4.1), so tampering with `unlock_block` (or any seal field) breaks the signature (`vc13`).

v0-profile `seal` fields (in addition to `unlock_block`, `confirmations`, `anchor:"beacon"`, `beacon_id:"drand:quicknet"`, `beacon_url`):

```json
"round":        <integer drand quicknet round, derived from unlock_block>,
"chain_hash":   "52db9ba7…",   // quicknet chain hash — binds tlock to this beacon
"chain_anchor": "mempool.space" | "blockstream.info",
"tlock":        "<age-armored drand tlock ciphertext of R>",
"locked_ct":    "<base64url AES-256-GCM(R, nonce, utf8(text))>",
"nonce":        "<base64url 12-byte nonce>"
```

**Round derivation.** `round = roundAt(now + max(0, unlock_block − current_tip) × 600000ms)` against quicknet (`genesis 1692803367`, `period 3s`). The block→time leg is an **approximation** (~10 min/block); its std-dev is ≈ `10min · sqrt(N_blocks)` — hours at weekly horizons, unbounded worst case. The displayed unit is the block height; timing is approximate (`vc10`).

**Hard chain gate (NORMATIVE).** A conforming v0 recipient **MUST NOT** surface the body until it independently confirms `chain_tip ≥ unlock_block + confirmations` against `chain_anchor` (a named explorer) **or its own node — EVEN IF `tlock` has already yielded `R`.** A sealed message therefore opens at the **later** of (the drand round elapsing, the chain reaching the height). This makes the displayed "readable ~at block N" true on a conforming client; reading it early requires BOTH a drand-threshold collusion AND a non-conforming client. On release the recipient SHOULD record the observed block hash at `unlock_block` as an offline-verifiable receipt.

**Ed25519 verdict (NORMATIVE honesty).** The key release rests entirely on drand (a threshold-BLS beacon, Bitcoin-independent): swap block height for an NTP clock and the construction is byte-identical, so **this leg FAILS the Ed25519 substitution test** (WHY H5). The `unlock_block` is a condition the recipient *verifies* against public chain data — offline-verifiable, but it does not hold the key. v0 MUST say this on every seal surface, MUST NOT let the seal carry the Bitcoin claim alone, and MUST cap the horizon (reference build: ≤ 4320 blocks / ~30 days) while the beacon durability-SLA + key-resharing open items (SECURITY S3/S11) are unresolved.

## 8. Transport

OC Chat uses OC Lock's gift-wrap unchanged: the canonical chat envelope is the opaque inner blob of a NIP-59 gift-wrap (Nostr kind-1059) signed by an ephemeral, discarded Schnorr key, `created_at` rounded to the minute, with the recipient inbox pubkey in the `p` tag and an advisory `ct` tag `oc-chat/v1`. The recipient's chat inbox pubkey is `HKDF(device_sk)` (so publishing a device record IS creating an inbox; no second ceremony). A relay sees an ephemeral pubkey, an inbox pubkey, and an opaque blob — no sender, no real timestamp, no content. Durable delivery (store-and-forward beyond relay retention) is specified in §8.1.

## 8.1 Durable inbox routing — per-conversation queue IDs — NORMATIVE

§8's gift-wrap rendezvous is best-effort: a relay MAY garbage-collect an event before an offline recipient connects (SECURITY S10), so an offline recipient plus a swept relay event is a lost message. A conforming deployment therefore SHOULD provide a **store-and-forward inbox** — an operator-run queue that retains the *opaque* gift-wrap inner blob (the canonical chat envelope, §3) until the recipient drains it. This is the free-tier floor (PROTOCOL Flow 1), **not** a paid feature; a paid tier extends only the retention horizon, multi-device fan-out, and history depth — durability of basic delivery is never the paywall.

The inbox operator MUST be unable to (a) read any message — it holds ciphertext only (the envelope's GCM-sealed `ciphertext`), never a key; or (b) **link** two conversations of one recipient, or link a queue to a Bitcoin identity. The published device inbox pubkey (§8) is a single value per device; routing every conversation to it would let an operator that *retains* enumerate a recipient's whole correspondence — the relay leak of SECURITY S6, made worse by persistence. Durable routing therefore uses an **opaque per-conversation queue id** derived from a recipient secret, never the device pubkey.

### 8.1.1 Derivation

Let `device_sk` be the recipient device's 32-byte X25519 private key and `conversation_id` the stable thread label (§5). Define:

```
queue_seed   = HKDF-SHA256( ikm = device_sk, salt = "" , info = "oc-lock-chat/inbox-queue-seed/v1", L = 32 )
queue_id(c)  = base64url( HMAC-SHA256( key = queue_seed, msg = utf8(conversation_id) ) )      // 43 chars, unpadded
```

- `queue_seed` is a per-device secret. It MUST NOT be published and MUST NOT leave the device unencrypted.
- `queue_id(c)` is a 32-byte tag rendered base64url **without padding**. It is unguessable without `queue_seed`, and two conversations on the same device produce unrelated ids — so the operator sees N independent queues, not one recipient (test vector `vc06`).
- A device recomputes `queue_id` for any conversation it participates in from `queue_seed` + `conversation_id`, holding **no stored queue↔conversation map**. Because the id binds to `device_sk`, each of a recipient's devices has its own per-conversation queue; the multi-device backfill (PROTOCOL Flow 2, SECURITY S8) carries history to a device added later.

### 8.1.2 Bootstrap (first contact)

A sender reaching a recipient for the first time cannot yet compute `queue_id(c)` (it derives from a secret the sender lacks). The first inbound message of a new conversation is deposited to the recipient's **bootstrap queue**, derivable by anyone holding the recipient's device record:

```
bootstrap_id = base64url( SHA-256( utf8( "oc-lock-chat/inbox-bootstrap/v1:" || inbox_pubkey_hex ) ) )
```

where `inbox_pubkey_hex` is the recipient's published §8 inbox pubkey (lowercase hex). The bootstrap queue carries the same recipient-linkability the relay `p` tag does (SECURITY S6) and MUST be disclosed as such; it is used only until a per-conversation queue is established.

### 8.1.3 Handshake

To migrate a conversation off the bootstrap queue, each party advertises **its own** receiving `queue_id` inside the encrypted payload (§5 `recv_queue`). A party that has learned its peer's `recv_queue` MUST deposit subsequent messages for that conversation there, and SHOULD stop using the peer's bootstrap queue. Because `recv_queue` travels inside the AEAD-sealed payload, the operator never learns the bootstrap↔per-conversation mapping and cannot link the two.

### 8.1.4 Operator obligations — NORMATIVE

A store-and-forward inbox operator MUST:

1. Store the gift-wrap inner blob **byte-for-byte** — preserving the envelope `id`, `sig`, and ciphertext GCM tag, and preserving unknown fields (§13). A re-wrap fan-out (§3.3) is a detached `recipients[]` merge and MUST NOT recompute the signed `id`.
2. Route **solely** on the opaque `queue_id` / `bootstrap_id`. It MUST NOT require, store, or index a Bitcoin address, a device pubkey, or any plaintext thread metadata.
3. Hold **no** key material of any party.
4. Treat the queue as **availability, not authority**: a draining recipient re-verifies authenticity from the artifact alone (BIP-322 device-record binding + `chat_envelope_id`), exactly as for a relay-delivered message. The operator endpoint is a NAMED trust anchor for *availability* and MUST be surfaced plainly.

The Ed25519 substitution test passes by inheritance: the queue is an ordinary mailbox that asserts no Bitcoin claim of its own, but the authority of every message it holds derives from the BIP-322-rooted device record (§0), which collapses under substitution.

## 8.2 Discoverability directory (opt-in) — NORMATIVE

§8 lets a sender who already knows your Bitcoin address reach you (your kind-30078 device record IS your inbox). The directory adds the missing half: being **found by a human-readable handle** without the searcher knowing your address — strictly opt-in, revocable, and graduated. **The default is invisible:** a conforming client publishes NO directory record unless the user explicitly opts in.

### 8.2.1 The listing record

A listing is an **addressable** (NIP-33-replaceable) Nostr event, **kind 30114**, signed by the user's **inbox key** (`deriveNostrKey(device_sk)` — the same key that signs gift-wraps, §8):

```
d-tag   = "oc-lock-chat-dir:" || base64url( SHA-256( "oc-lock-chat-dir/v1:" || lower(handle) ) )   // unpadded
content = canonical JSON {
  "v": 1, "handle": "<[a-z0-9_]{3,32}>", "address": "<bitcoin address the inbox key is bound to>",
  "inbox_pubkey": "<hex; the §8.2 reachability pointer = the event pubkey>",
  "display_name"?: "<=48 chars", "bio"?: "<=80 chars", "avatar"?: "<https url>",
  "opted_in": true, "created_at": <unix seconds>
}
listing_id = SHA-256( canonical(content) )   // hex, content-addressed (invariant 4)
```

The `d`-tag is a **salted hash of the handle** — a conforming directory is **lookup-by-known-handle, never enumerate-all** (there is NO `GET /all` and no bulk-dump). It is keyed by the handle hash, not the raw address (a raw-address key would be deterministically enumerable). `canonical(x)` is §0's RFC 8785 + LF-terminator.

### 8.2.2 The Bitcoin gate — NORMATIVE (this is what makes the directory belong to this family)

A bare listing is **not** Bitcoin-load-bearing: *"address X, here is my inbox key, signed by X"* substitutes perfectly to an Ed25519 npub signed by an npub. A conforming resolver therefore MUST refuse to honor a handle unless **all three** hold:

1. The kind-30114 event is signed by `inbox_pubkey`.
2. `inbox_pubkey` is bound to `address` via a valid kind-30078 device record (the existing BIP-322 binding, OC Lock §3). **The directory inherits its Bitcoin proof from the device record — no second wallet ceremony.**
3. **`address` clears the UTXO floor:** it controls at least one confirmed UTXO of age ≥ the deployment's `dir_utxo_floor`. This is the load-bearing hook — an Ed25519 keypair has **no analog to an aged, funded UTXO**, so a handle costs Bitcoin maturity to claim (Sybil-resistance doubling as anti-squat). UTXO state is **public chain data**, so the check preserves offline-verifiability (invariant 5). The floor is deployment-set; the RECOMMENDED v0 floor is *funded + ≥ 144 confirmations (~1 day)*, with the actual UTXO age surfaced as a graduated trust signal (older = more trusted).

A handle whose claimant fails (2) or (3) MUST be treated as un-listed. Handle uniqueness is **first-writer-wins, best-effort across relays, explicitly NOT global consensus** — the address is the trust root; the handle is a non-authoritative display label. A `did:oc`-only identity (the session bridge, no Bitcoin address) MAY publish a bridge listing but MUST NOT claim a scarce handle under (3); a conforming client surfaces it with a muted "via ochk.io" tier and prompts attaching a Bitcoin address to graduate.

### 8.2.3 The social-graph firewall — NORMATIVE

The listing record MUST NOT contain, reference, or be co-indexed with any `queue_id`, `recv_queue` (§8.1.3), `conversation_id`, contact list, or message-routing metadata. **The directory reveals a NODE — "this identity is reachable" — and NEVER an EDGE — who messages whom.** The only reachability pointer it republishes is `inbox_pubkey`, which a sender who resolved your handle needs anyway and which the device record already exposes.

### 8.2.4 Revocation

Self-removal = publish a replacement kind-30114 event with the **same d-tag**, `opted_in: false` and the optional fields stripped, signed by the inbox key (reusing the OC Lock §3.5/§3.6 tombstone precedent). Because the event is NIP-33-addressable, the tombstone **replaces** the prior record at conforming relays. A conforming client MUST treat a tombstone — or an absent record — as not-discoverable, MUST refuse to resolve the handle, and MUST treat a tombstone seen on ANY relay as authoritative even if a stale live copy exists elsewhere; it SHOULD additionally fire a NIP-09 deletion request. **Revocation is forward-effective only** (NORMATIVE honesty, surfaced at opt-in time): a tombstone stops new resolution on conforming relays; it cannot retract copies on non-conforming relays, archives, or scrapers. The promise is "stop new discovery," never "delete yourself completely." Removal does not unsend or break existing conversations.

### 8.2.5 Resolution

To find a user, a client computes the `d`-tag from the queried handle, fetches the kind-30114 events for that `d`-tag across its relay set (freshest `created_at` wins; a tombstone wins over any live copy), verifies §8.2.2 (1)–(3), and on success surfaces `address` + profile + a trust tier so the user can start a thread. First-contact still passes the recipient's §4.1 anti-spam policy — **being listed is not a free-message bypass.** Privacy-sensitive resolution SHOULD query relays directly, NOT a third-party indexer (which would learn who-searches-for-whom). The relay/index operator is a NAMED availability anchor and MUST NOT be relied on as authority.

## 9. Errors

In addition to OC Lock SPEC §6 codes:

| Code | Meaning |
|---|---|
| `E_BLOCK_UNMET` | Seal release requested before `unlock_block + confirmations` confirmed. |
| `E_BEACON_UNAVAILABLE` | Seal beacon did not respond or could not be reached. |
| `E_NO_POSTAGE` | `pay-to-reach` envelope from a non-contact lacked valid postage for the recipient's floor. |
| `E_BAD_POSTAGE` | `SHA-256(preimage) != payment_hash`, or the `nonce`/`recipient`/`amount` binding did not match. |
| `E_THREAD_GAP` | `parent_id` does not resolve to a held parent envelope id. |
| `E_QUEUE_ROUTE` | A durable-inbox deposit/drain referenced a `queue_id` the caller is not entitled to, or a malformed (non-base64url / wrong-length) queue id. |
| `E_DIR_UNVERIFIED` | A kind-30114 listing failed §8.2.2: bad signature, `inbox_pubkey` not bound to `address` via a kind-30078 record, or `address` did not clear the UTXO floor. The handle resolves as un-listed. |
| `E_DIR_REVOKED` | The resolved listing is a tombstone (`opted_in: false`) or absent — the handle is not discoverable. |

## 10. Nostr kind registry

OC Chat claims a fresh block above OC Find's (unratified) 30094–30109 reservation. d-tags are **verb-rooted** (`oc-lock-chat-*`) because chat is a mode of the lock verb, not a brand of its own.

| Kind | Object | `d`-tag prefix | Notes |
|---|---|---|---|
| 30110 | thread / channel descriptor (addressable, NIP-33-replaceable) | `oc-lock-chat-ch:` | one active descriptor per `conversation_id`. |
| 30111 | message envelope (when published addressably rather than gift-wrapped) | `oc-lock-chat-msg:` | gift-wrap (kind-1059) is the default DM transport; 30111 is for public/channel posts. |
| 30112 | seal / block-height anchor descriptor | `oc-lock-chat-seal:` | references the sealed envelope id + `unlock_block` + beacon. |
| 30113 | reserved (group-key rotation) | `oc-lock-chat-*:` | registry extension; not canonical v0. |
| **30114** | **discoverability directory / reachability listing** (addressable, NIP-33-replaceable) | `oc-lock-chat-dir:` | §8.2. d-tag = salted handle hash; opt-in, UTXO-gated, revocable by tombstone. |
| 30115 | reserved (postage-policy record) | `oc-lock-chat-*:` | registry extension; not canonical v0. |

The transport gift-wrap remains Nostr kind-1059 (NIP-59, not an OC-allocated kind). Device records remain kind-30078 (OC Lock SPEC §11). Allocating these required widening the family range past 30099; the workspace `KINDS.md` and `oc-agent-protocol/SPEC.md §4` are the rolled-up source of truth.

## 11. Compliance checklist

A client is OC Chat v0 compliant iff it:

- [ ] Reuses OC Lock §4.2 wrapping verbatim for `content_key`.
- [ ] Computes `chat_aad` and `chat_envelope_id` with `recipients=[]` for `kind ∈ {chat, chat-seal}` (§3) and reproduces the test vectors.
- [ ] Carries `conversation_id`/`seq`/`parent_id` inside the encrypted payload and orders by the `parent_id` hash-chain, never by `created_at` (§5).
- [ ] If it offers durable store-and-forward, derives `queue_id`/`bootstrap_id` per §8.1, routes the inbox solely on those opaque ids (no address/device-pubkey index), stores the blob byte-for-byte, and reproduces vector `vc06`.
- [ ] If it offers the directory (§8.2), publishes a kind-30114 listing ONLY on explicit opt-in (default invisible), derives the salted-handle `d`-tag (vector `vc07`), refuses to resolve a handle unless the §8.2.2 gate passes (signature + kind-30078 binding + UTXO floor), enforces the §8.2.3 social-graph firewall, honors tombstones (vector `vc08`), and never exposes a bulk-dump endpoint.
- [ ] For `pay-to-reach` (§6): carries `postage` in the `ChatBody` (§6.2), and on receive runs the full §6.3 verification — re-derives the description-hash binding `SHA-256(lnurl_metadata‖payerdata)` ITSELF over verbatim bytes, checks `SHA-256(preimage)==payment_hash` + amount + expiry + identifier + the local spent-ledger — routing a failing/replayed message to the Requests tray, and NEVER claims transferable third-party proof.
- [ ] Wraps to the beacon and performs release re-wrap as a detached `recipients[]` merge for `seal-til-block` (§7), and NEVER labels a v0 beacon seal "trustless".
- [ ] Surfaces every trust anchor (beacon id/url, relay, redundant beacon) and the early-release / brick risks at compose time.
- [ ] Operates no OC payment rail for postage (§6.4).
- [ ] Emits §9 + OC Lock §6 error codes.

## 12. Security model

See [`SECURITY.md`](./SECURITY.md). In brief, OC Chat inherits OC Lock's guarantees (authenticity, confidentiality, identity binding) and gaps (no per-message forward secrecy, plaintext envelope metadata, no delivery guarantee) and adds: a beacon-trust posture for seals (not offline-verifiable in v0), a seal-existence metadata leak, and an offline-verifiable Lightning postage proof.

## 13. Versioning

OC Chat versions with OC Lock's `envelope.v` (currently 2). New `kind` values and new optional blocks (`postage`, `seal` sub-fields) are additive; clients MUST preserve unknown fields when relaying and MAY ignore them when decrypting. Incompatible changes increment `envelope.v`.

## 14. IANA / external identifiers

- Nostr kinds: **30110–30112** + **30114** (directory, §8.2), addressable, d-tag namespace `oc-lock-chat-*` claimed by this spec; transport reuses kind-1059 (NIP-59).
- Advisory gift-wrap content tag: `ct = "oc-chat/v1"`.
- Directory d-tag salt label: `"oc-lock-chat-dir/v1:"`.

## 15. Acknowledgements

OC Chat extends [OC Lock](https://github.com/orangecheck/oc-lock-protocol) and the OrangeCheck identity primitive. The "Bitcoin as identity, not access oracle" framing — which is why the daily messenger leans on BIP-322 identity rather than a chain transaction in the send path — is owed to [Bram Kanstein](https://bramk.substack.com/). See OC Lock `WHY.md`.
