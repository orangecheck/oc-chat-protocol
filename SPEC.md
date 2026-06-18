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
| `"chat-channel"` | public channel post (§8.3) | `channel_id`, `write_proof` (§8.3.2) |

A conforming OC Lock implementation that does not understand these kinds MUST reject them (OC Lock SPEC §9 unknown-`kind` handling) rather than mis-decrypt. The transport (§8) is OC Lock's gift-wrap, unchanged.

**NORMATIVE amendment for `chat-channel` (do not undersell).** Unlike `chat`/`chat-seal`, a v1 `chat-channel` post is **public** (§8.3) — there is no recipient set, no key-wrapping, and no AEAD ciphertext over a body. Its `recipients[]` MUST be empty; a non-empty `recipients[]` on a `chat-channel` envelope is `E_CHANNEL_RECIPIENTS` and the post MUST be rejected (this is what makes the §8.2 social-graph leak structurally absent for public channels — there is nothing to leak). The post body is plaintext, content-addressed, and BIP-322-rooted by the author's device signature; the recipient-exclusion `chat_envelope_id` rule of §3 still applies (`recipients=[]` is the steady state, not a re-wrap).

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

A first message that does not clear the recipient's policy is **delivered and decrypted, never dropped** — it is placed in a distinct **filtered/pending** state and shown to the recipient set apart from the main inbox (the "Requests" surface), so the recipient always sees that someone reached them. Acceptance is a client-local, **explicit and revocable allowlist**: the recipient approving a sender (e.g. by opening their filtered conversation) lets that sender reach the inbox normally thereafter, and the recipient MAY revoke at any time. This allowlist is private — it MUST NOT be published, carried on the wire, or co-indexed with the directory listing (the §8.2.3 social-graph firewall). A recipient MAY signal acceptance to a sender only by replying; clients MUST NOT emit a separate "your request was opened" receipt (it would be a read-receipt-style metadata leak).

### 4.2 `pay-to-reach` (paid, peer-to-peer)

`kind="chat"` with a `postage` block (§6). A stranger's first message to a recipient who has published a postage floor MUST carry a valid Lightning preimage proving payment to the recipient. Messages lacking valid postage are still delivered to the recipient but placed in the **filtered/pending** state (the "Requests" surface, §4.1), not the main inbox. The payment is **sender → recipient direct**; no OC service is in the path (§6.4).

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

### 5.1 Attachments — E2EE

A message MAY carry a file via an optional `attachment` field in the ChatBody:

```json
"attachment": { "name": "<file name>", "type": "<MIME>", "size": <raw bytes>, "data": "<base64 of the raw bytes>" }
```

Because the WHOLE ChatBody is AES-256-GCM-sealed to each recipient device (the same envelope as the text), the file is **end-to-end encrypted and tamper-evident**: no server — relay or durable inbox — ever holds a plaintext file, and altering it breaks the content-addressed `id` and the device signature (§4.1). This is the **inline v0 profile**: the bytes ride in the ciphertext, so the file size is bounded to what fits a gift-wrap event (the reference client caps inline attachments at ~100KB raw). The recipient validates the parsed `attachment` shape + size defensively even though the AEAD authenticates it.

Larger files are the **blob-store upgrade** (not v0): encrypt the file under a fresh per-file key, upload the ciphertext blob out-of-band to a store that sees only ciphertext, and carry `{ blob_ref, key, nonce }` inside the sealed ChatBody so only the recipient can fetch + decrypt — keeping the no-plaintext-on-a-server invariant while removing the inline size cap.

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

All checks pass + not-spent → inbox. Any fail OR already-spent → the message is **delivered but held in the filtered/pending state** (the "Requests" surface, §4.1 free-tier path), never dropped.

**Why this is non-replayable (and its honest ceiling):** because the recipient's *own* endpoint minted the per-DM invoice committing **this** recipient + amount + nonce into the description-hash, a preimage replayed to a *different* recipient fails the binding there (that recipient never minted that metadata/nonce); a preimage replayed to the *same* recipient is caught by the local spent-ledger. The residual ceiling is named in SECURITY S7: this is **recipient-scoped**, not a proof a third party who sees only `{preimage, nonce}` can verify; the recipient's LNURL endpoint is a **named trust anchor**; and a cold observer can check the hash/binding but cannot independently confirm the HTLC settled.

### 6.4 No OC payment rail
OC operates no postage gateway. Any Lightning gateway in a recipient's postage path is operated by a NAMED third party, never OC. Zap receipts (NIP-57) MUST NOT be used as postage proof — they are server-signed and forgeable; only the BOLT11/BOLT12 preimage is a bearer proof.

### 6.5 Named-Fedimint custodial fallback — NORMATIVE (institutional last-mile)
A recipient with no Lightning endpoint of their own (an institution, a non-technical staff member) MAY name a **Fedimint federation** as their postage last-mile. The federation's LNURL/Lightning-Address endpoint is published in the recipient's own kind-30078-bound listing (§6.1, §8.2.1) exactly like any other endpoint — so the §6.3 verification is unchanged and endpoint-agnostic (the sender re-derives the same description-hash binding and pays directly; the preimage is the same bearer proof). The structural difference is custody: the **federation** receives the sats and settles ecash to the recipient's federation account.

- **OC stays absent + non-custodial (NORMATIVE).** OC touches no sats, runs no guardian share, holds no hot wallet, and is never in the HTLC path — the federation custodies and settles, exactly as the family corollary requires ("federations settle to users; OC has no payout hot wallet"). This is the §6.4 named-third-party gateway, instantiated by a federation rather than a solo node.
- **Named trust anchor.** The federation is surfaced in plaintext in the listing — its `federation_id`, human name, and invite — so a sender sees who custodies before paying (§invariant 8). A sender MUST be able to decline a federation-fronted endpoint it does not trust.
- **Deployment gate (NORMATIVE).** Because a federation custodies inbound funds, a deployment MUST clear a money-transmitter analysis (WHY §19 open question #5) before enabling the Fedimint postage path. The spec specifies the *mechanism*; a deployment ships it only after that analysis. `E_FEDIMINT_UNAVAILABLE` (the named federation/endpoint did not respond) and `E_FEDIMINT_BINDING_MISMATCH` (the federation-fronted invoice failed the §6.3 binding) are the failure codes.
- **Ed25519 verdict.** Lightning settlement IS the Bitcoin-load-bearing hook (a preimage has no Ed25519 analog) — unchanged from §6. The fallback adds custody convenience, not a new Bitcoin claim, and is honest that the federation is a trusted custodian, not a trustless rail.

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

### 7.7 Standing delivery (dead-man's-switch) — NORMATIVE

A **standing delivery** is a *composition* over §7.6, not new crypto. The author seals a message to a recipient with a NEAR deadline, then **re-arms** ("checks in") before each deadline by re-sealing the SAME content to a LATER `unlock_block` under a shared **`standing_id`** (a fresh CSPRNG id carried INSIDE the encrypted seal body, so relays never learn a switch exists). The recipient groups received seals by `standing_id` and treats only the **latest check-in — the MAX `unlock_block`** — as live, opening it (per the §7.6 hard chain gate) when that block passes; lower-`unlock_block` check-ins in the group are **superseded and MUST NOT be opened**. Stop checking in → the last deadline passes → the message delivers. **The switch fires on silence.**

- **Safety of max-wins (NORMATIVE).** A relay can RAISE a group's max only by delivering a real, author-device-signed later check-in; it cannot forge one and cannot lower the max — so it can **never make the switch fire earlier** than the author's last real check-in. It CAN drop a fresh check-in or a cancel — so a dead-man's-switch can be made to *fire* but **NOT reliably *suppressed*** by a third party. That asymmetry is intended (a hostile party censoring your check-in is exactly when the switch should fire).
- **Horizon + cadence.** v0 inherits the §7.6 ~30-day horizon cap, so a single arm is ≤ 4320 blocks out and a live standing delivery **requires a check-in at least every ~30 days**; a missed window IS the trigger. There is no protocol "cancel" that a hostile relay can't drop — cancellation is best-effort (push the deadline forward, or send a cancel the recipient honors if delivered).
- **Second check-in channel (RECOMMENDED).** An institutional deployment SHOULD arm a non-app check-in path so an app/relay outage is not a false trigger; v0 surfaces this in copy, does not enforce it.

## 8. Transport

The canonical chat envelope travels as the inner blob of a Nostr kind-1059 gift-wrap signed by an ephemeral, discarded Schnorr key, `created_at` rounded to the minute, with the recipient inbox pubkey in the `p` tag. The recipient's chat inbox pubkey is `HKDF(device_sk)` (so publishing a device record IS creating an inbox; no second ceremony). Durable delivery (store-and-forward beyond relay retention) is specified in §8.1.

**Wrap encryption (NORMATIVE — `ct = "oc-chat/v2"`).** The wrap `content` MUST be encrypted to the recipient inbox key, NOT merely encoded. The chat envelope's own plaintext fields (`from.address`, `recipients[*].address`/`device_id`/`device_pk`, full-precision `created_at`) plus the sender's stable device pubkey would otherwise hand every relay — and the §8.1 inbox operator — the full who-talks-to-whom graph, voiding §8.1.4. Construction:

```
shared   = x( ECDH(eph_sk, lift_x(inbox_pk)) )          # x-coordinate only — negation-safe for BIP-340 x-only keys
key      = HKDF-SHA256(ikm=shared, salt="oc-chat/v2", info=eph_pk_hex || inbox_pk_hex, L=32)
content  = base64url( nonce(12) || AES-256-GCM(key, nonce, payload_json) )
```

where `eph_sk` is the SAME ephemeral key that signs the outer event (`event.pubkey` is the ECDH counterpart the recipient uses; binding `key` to the `(eph_pk, inbox_pk)` pair stops cross-wrap key reuse). A conforming publisher MUST emit `oc-chat/v2`; a recipient SHOULD also accept the legacy plain-base64 `oc-chat/v1` for messages already in flight, and MUST treat a v2 wrap that fails the AEAD as not addressed to it. A relay then sees: an ephemeral pubkey, an inbox pubkey, a minute-rounded timestamp, and ciphertext — no sender identity, no recipient Bitcoin address, no device set, no content. The inbox `p` tag and timing remain visible (the §8.1.2 disclosure).

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
  "display_name"?: "<=48 chars", "bio"?: "<=80 chars", "avatar"?: "<small inline raster data: URL, ≤24KB>",
  "opted_in": true, "created_at": <unix seconds>
}
listing_id = SHA-256( canonical(content) )   // hex, content-addressed (invariant 4)
```

**`avatar` is an inline `data:` raster URL, NOT an external link (NORMATIVE).** A profile image rides as a small `data:image/(png|jpeg|webp|gif);base64,…` URL inside the signed content — content-addressed (it changes `listing_id`, so it can't be swapped under a fixed handle), offline-verifiable, and with **no third-party fetch**. An external `https` avatar URL is forbidden: loading it would turn every directory lookup into a **tracking pixel** that leaks the viewer's IP + timing to the image host (and a non-content-addressed image can be swapped after signing). A conforming client downscales any picked image to a small square (reference clients: ~128px webp) and MUST render an avatar ONLY if it is a bounded raster `data:` URL — never `image/svg+xml`, `text/html`, or any non-raster type (the `data:`/blob-URL XSS class); an unsafe or oversized avatar is dropped, the listing still resolves.

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

## 8.3 Channels — NORMATIVE (v1: public)

A **channel** is a composition, not a new verb and not a new mode: a kind-30110 governance **descriptor** + kind-30111 **posts** + (opt-in) a kind-30114 directory listing + a Bitcoin-priced **write gate**. v1 ships **public** channels (public read, signed posts, Bitcoin-gated write); private/encrypted channels are reserved behind the *same* descriptor (§8.3.7). One descriptor, phased by the `read` + `encryption` fields.

A public channel makes **no E2EE claim** — it uses OC Lock's *identity binding* (BIP-322 device signatures) and OC Chat's *Bitcoin-priced access control*, not its confidentiality. Clients MUST NOT carry the DM "relays learn nothing" headline onto channel posts (S-CH-4).

### 8.3.1 Channel descriptor — kind 30110 (addressable, NIP-33-replaceable)

One descriptor per channel, signed by the **founder's inbox key** (`deriveNostrKey(device_sk)`), BIP-322-rooted to `founder_address` via that device's kind-30078 record. It is the single source of truth for identity, roles, and the read/write policy. Content-addressed (invariant 4). The `read` + `encryption` fields are the phase switch.

```jsonc
// kind 30110, addressable.
// d-tag = "oc-lock-chat-ch:" || base64url( SHA-256("oc-lock-chat-ch/v1:" || channel_id) )
// signed by the FOUNDER inbox key; bound to founder_address via kind-30078.
{
  "v": 1,
  "channel_id": "<hex = SHA-256('oc-lock-chat-ch/v1:' || founder_address || ':' || slug)>",
  "slug": "<[a-z0-9-]{3,48}; NON-authoritative display label (S17)>",
  "founder_address": "<bitcoin address OR did:oc:...; the channel's trust root>",
  "founder_inbox_pubkey": "<hex; the event pubkey; bound to founder_address via kind-30078>",

  "read": "public",          // "public" (v1) | "members" (reserved, §8.3.7)
  "encryption": null,        // null ⇒ public (v1). Reserved private block in §8.3.7.

  "write": {                 // EXACTLY ONE policy (§8.3.3)
    "policy": "utxo-floor",  // "utxo-floor" | "allowlist" | "founder" | "open" (pay-to-post ⇒ kind-30115)
    "utxo_floor_confs": 144, // utxo-floor: min UTXO age (blocks)
    "utxo_floor_sats": 0,    // utxo-floor: min value counting toward the age test
    "allowlist_root": null,  // allowlist: hex SHA-256 of the canonical sorted writer-address list
    "rooted": true           // MUST be true for utxo-floor; MUST be false for allowlist/founder/open
  },

  "admins": [ "<address or did:oc>", ... ],      // may replace the descriptor + post any tombstone
  "moderators": [ "<address or did:oc>", ... ],  // may post removal tombstones ONLY

  "title": "<=80>", "description": "<=280>", "avatar": "<https, optional>", "rules": "<=1000, optional>",
  "directory_opt_in": false, // §8.3.6: list in kind-30114 (default invisible)
  "created_at": <unix s>,
  "supersedes": "<descriptor_id of the prior version, or null for genesis>",
  "status": "closed",        // §8.3.8 lifecycle. OMITTED when active (absent ⇒ active); present only to retire.
  "successor_channel_id": "<hex, optional>" // §8.3.8: a replacement channel a closed one points to
}
// descriptor_id = SHA-256( canonical(content) )   // hex, content-addressed (§0; vc14)
// authorship    = the kind-30110 event's schnorr signature by an inbox key bound to the author's address via
//                 the kind-30078 device record (the SAME trust root as DMs + the directory §8.2 — NOT a second
//                 per-edit BIP-322 wallet ceremony). Genesis: the event pubkey IS founder_inbox_pubkey, bound to
//                 founder_address. Supersede: the signing inbox key is bound to a PRIOR-epoch admin (or founder).
```

Normative rules a conforming client MUST honor:

- **`channel_id` binds to `founder_address`.** Identity is `SHA-256(founder_address || slug)`; the founder's address is the trust root. Two founders may reuse a `slug` → different `channel_id`s. The slug is non-authoritative (S17); the client MUST render `founder_address` + its trust tier alongside the slug. No global slug consensus (first-writer-wins, best-effort).
- **The descriptor is a governance hash-chain.** Every change (add admin, raise the floor, change policy) is a new kind-30110 at the same d-tag with `supersedes` → the prior `descriptor_id`. A client MUST validate the new descriptor's signing inbox key is **device-bound (kind-30078) to the founder OR to an address in the *prior* `admins` set** — making governance tamper-evident and offline-verifiable (the §5 `parent_id` trick applied to governance) while reusing the device-record trust root instead of a per-edit wallet ceremony. A descriptor not so authored is `E_CH_UNAUTHORIZED`. The Bitcoin-load-bearing claim is carried by the **write policy** (§8.3.3), not the descriptor signature — so a `did:oc`-only founder can still open a public channel; its write tier just renders non-rooted unless the policy is `utxo-floor`.
- **Exactly one `write.policy`, with a `rooted` flag that MUST match it** (§8.3.3): `utxo-floor` MUST set `rooted:true`; `allowlist`/`founder`/`open` MUST set `rooted:false`. A mismatch is `E_CH_POLICY_INVALID`. This makes the Bitcoin claim a property of the artifact, not a UI label.

### 8.3.2 Channel post — kind 30111 (`chat-channel`)

A public post is an addressable kind-30111 event, the `chat-channel` envelope (§3), `recipients=[]`, plaintext body, signed by the **author's inbox key** bound to `author_address` via kind-30078.

```jsonc
// kind 30111, addressable. d-tag = "oc-lock-chat-msg:" || base64url(SHA-256(channel_id || ":" || post_id))
// PLUS an indexable single-letter scope tag ["t", channel_id] so a reader can fetch ONE channel's posts
// relay-side via {"#t": [channel_id]} (the d-tag is a per-post point key, not a channel list filter).
{
  "v": 1, "kind": "chat-channel",
  "channel_id": "<hex; the §8.3.1 channel this belongs to>",
  "author_address": "<bitcoin address or did:oc>",
  "author_inbox_pubkey": "<hex; bound to author_address via kind-30078>",
  "body": "<plaintext, <=4096>",
  "attachment": { "name": "<str>", "type": "<mime>", "size": <int>, "data": "<base64>" },  // OPTIONAL, see below
  "seq": <int>, "parent_id": "<prior post_id or null>",   // null for an independent top-level post (see ordering)
  "write_proof": { ... }      // §8.3.3, REQUIRED iff the channel's write.policy is "utxo-floor"
}
// post_id = SHA-256( canonical(content) )   // hex, content-addressed (§0; vc16). write_proof is committed;
//           write_proof.control_sig is NOT — it and the author device sig sign post_id and are attached to
//           the kind-30111 event, not the hashed content. The event-level `created_at` (the NIP-01 wall-clock)
//           and the ["t", channel_id] scope tag are likewise NOT part of post_id — the id stays stable
//           regardless of when the event is stamped or how it is routed.
```

**Optional `attachment`** (a single inline file, same shape as the §5 DM attachment) carries `{name, type, size, data}` where `data` is the base64 of the raw bytes. Unlike a DM attachment — sealed inside the E2EE `ChatBody` — a channel attachment is **PUBLIC**: it lives in the plaintext post content, is committed to `post_id` (so it is tamper-evident and any edit yields a new id), and is readable by anyone who can read the channel. Clients SHOULD cap it at the same small inline ceiling as DM files (reference clients use 100 KiB) and SHOULD treat an attachment that fails the §5 shape check as a malformed post (`E_CH_MALFORMED`, MUST NOT render). It is a convenience for small images/snippets, not a file-hosting layer; large media belongs behind a link.

A conforming reader MUST: (1) verify the author device signature + kind-30078 binding (§4.1) — a post with no resolvable event/signature is `E_CH_UNAUTHORIZED` and MUST NOT render (authorship is never optional); (2) evaluate the channel's `write.policy` against the post (§8.3.3) — a post failing the gate is `E_CH_WRITE_DENIED` and MUST NOT render; (3) confirm the author is permitted to write (a reader-only channel role posting is `E_CH_NOT_WRITER`); (4) **order the feed deterministically.** A public multi-author channel has **no single hash-chain** (independent broadcasters), so a top-level post sets `parent_id:null` and the feed is ordered by the event `created_at` as a **display hint, tie-broken by the content-addressed `post_id`** so any two clients agree. `created_at` is untrusted (a relay may backdate) and MUST NOT be treated as authoritative; the `post_id` tiebreak makes the order stable + reproducible. When `parent_id` is non-null it threads an explicit reply, and a client SHOULD render the reply under its parent. (This relaxes the §5 DM rule, which assumes a single two-party chain; channels are fan-out.)

### 8.3.3 Write / join policies (the Bitcoin-load-bearing axis)

- **`utxo-floor` (canonical default, `rooted:true`).** The author proves control of a funded, **unspent** UTXO of age ≥ `utxo_floor_confs` (and value ≥ `utxo_floor_sats`) — the §8.2.2 directory gate, applied to write. The proof is **height-anchored** and verified against **public chain data** (the reader's own node/explorer — invariant 5), **deduped to one query per distinct UTXO-owning address per render batch** (not per post) so it is neither a rendering-DoS nor a fail-open-muting bug:

  ```jsonc
  "write_proof": {
    "outpoint": "<txid:vout>",
    "value_sats": <int>,
    "anchor_block_height": <int>,        // the height at which age is measured
    "anchor_block_hash": "<hex>",        // pins the anchor; the reader checks tip_height - anchor_height + 1 >= confs
    "control_sig": "<BIP-322 by the UTXO's address over post_id>"
  }
  ```
  A reader verifies, all against the reader's own node/explorer and **fail-closed** (an unverifiable proof drops the post — it MUST NOT render unverified): **(1) the `outpoint` is an UNSPENT output OWNED BY the UTXO-controlling address** (it appears in that address's UTXO set), carrying **exactly** `value_sats`, confirmed at `anchor_block_height` with the block hash equal to `anchor_block_hash` — this binds the author-asserted `value_sats`/`anchor_block_height` to real, current chain state so they cannot be fabricated; (2) `control_sig` BIP-322 over `post_id` by that address; (3) `value_sats >= utxo_floor_sats`; (4) `current_tip_height - anchor_block_height + 1 >= utxo_floor_confs`. Any failure ⇒ `E_CHAN_FLOOR`. **This leg passes the Ed25519 substitution test** — proving control of a funded, aged, unspent UTXO has no Ed25519 analog; spam is priced in Bitcoin maturity. (NORMATIVE history: earlier drafts skipped the on-chain `outpoint` check "to avoid a live query," which left `value_sats`/`anchor_block_height` as forgeable claims a `control_sig` over any unfunded address would clear — defeating the Bitcoin gate. The per-outpoint-deduped, fail-closed query restores the load-bearing property without the per-post-DoS hazard the original wording feared.)
- **`allowlist` (`rooted:false`).** Writers are the addresses whose canonical sorted list hashes to `allowlist_root`; a post includes a membership proof (the address + its position). Offline-verifiable, but a signature-only allowlist **fails the Ed25519 test** — it is not Bitcoin-load-bearing. Rendered "via ochk.io" muted tier.
- **`founder` (`rooted:false`).** Only `founder_address` + `admins` may post (an announcement channel). Same Ed25519 verdict.
- **`open` (`rooted:false`).** Anyone with a valid device may post. Legal but defaulted-against; no spam resistance beyond device-record cost.
- **`pay-to-post`** (Lightning postage per post, §6) is a **kind-30115 registry extension, NOT v1-canonical** — it needs an invoice round-trip + an operator-local spent-ledger and is not offline-verifiable, so it does not belong in the offline-verifiable v1 core. It is the *other* rooted policy when it ships.

**Ed25519 verdict (NORMATIVE honesty).** Only `utxo-floor` (and the deferred `pay-to-post`) carry the Bitcoin claim. `allowlist`/`founder`/`open` do not — the `rooted:false` flag is structural, and the reference client MUST render a non-rooted channel in the muted "via ochk.io" tier exactly as a `did:oc` identity renders. Membership-by-signature alone is not a Bitcoin gate, and v1 says so on every surface.

### 8.3.4 Roles

Five roles, all enforced **offline by signature** against the current descriptor epoch: **founder** (the trust root; may do anything, including replace the descriptor), **admin** (may replace the descriptor + post any tombstone), **moderator** (may post removal tombstones only), **writer** (may post, gated by §8.3.3), **reader** (read only; a reader post is `E_CH_NOT_WRITER`). For a public channel, read is universal; the interesting axis is write.

### 8.3.5 Moderation (tombstones)

An admin/moderator removes a post by publishing a kind-30111 **removal tombstone** (`body:""`, a `removes` field naming the target `post_id`, signed by a roster moderator/admin). Removal is **forward-effective only** (S14/S15): conforming clients hide the target on sight of a valid tombstone, but copies already scraped/archived are not retracted. A tombstone by a non-roster signer is `E_CH_UNAUTHORIZED`.

### 8.3.6 Composition with the directory (§8.2)

A channel with `directory_opt_in:true` MAY publish a kind-30114 listing whose `address` = `founder_address` and whose content carries the `slug` and the `channel_id` — so a channel is discoverable by handle under the *same* opt-in, UTXO-gated (the founder address clears the §8.2.2 funded+aged floor), tombstone-revocable directory rules as a person. Default invisible. The §8.2.3 social-graph firewall holds: a public channel reveals a NODE (the channel exists, its founder), never an edge set (public channels have no member roster).

**The handle→channel mapping is content-bound (NORMATIVE).** A channel listing MUST carry `slug`, and its `channel_id` MUST equal `SHA-256("oc-lock-chat-ch/v1:" || founder_address || ":" || lower(slug))` (the §8.3.1 channel-id derivation). A resolver MUST recompute this and **drop any listing whose `channel_id` is not so derived**. Because the listing is signed by an inbox key device-bound to `founder_address`, a derivable `channel_id` can only ever point at a channel that *this* founder rooted — so a handle can never redirect to a channel its lister did not found. Without this bind, `channel_id` is a free field and the §8.2.2 UTXO floor would prove only that the *lister* is Bitcoin-real, not that they have any authority over the channel the handle resolves to (a handle-hijack). The binding is offline-self-proving: it needs only the listing event, not a second descriptor fetch.

**A directory handle is Bitcoin-gated; a `did:oc` founder cannot claim one (NORMATIVE).** The §8.3.1 descriptor permits a `did:oc`-only founder to open a public channel (its write tier just renders non-rooted), but the §8.2.2 anti-squat floor applies unchanged to the directory **handle**: a scarce `@handle` requires the `founder_address` to clear a funded+aged UTXO, which a `did:oc` identity has no analog for. So a `did:oc`-founded channel MUST NOT publish a kind-30114 listing, and a resolver MUST treat any listing whose `founder_address` is a `did:oc` as un-listed — exactly as §8.2.2 forbids a `did:oc` person from claiming a scarce handle. A conforming client surfaces this honestly (the channel is still fully usable and shareable by its `founder_address`+`slug` or `channel_id`) and prompts founding with a Bitcoin address to become handle-discoverable. The `channel_id` itself is bound to the *original* `founder_address` (§8.3.1), so a channel rooted at `did:oc` cannot graduate its existing handle by later attaching a Bitcoin address — it must be re-founded under that address.

**Separate handle namespace (NORMATIVE).** Channel listings use a **distinct d-tag namespace** from people listings (§8.2.1) so a channel handle can never collide with a person's: `d-tag = "oc-lock-chat-chdir:" || base64url(SHA-256("oc-lock-chat-chdir/v1:" || lower(handle)))` (people use `oc-lock-chat-dir:`). The listing is signed by the **founder inbox key** (`founder_inbox_pubkey`, bound to `founder_address` via kind-30078); a resolver honors it only if the event pubkey equals `founder_inbox_pubkey`, that key is device-bound to `founder_address`, and the address clears the UTXO floor — so only the founder can list a channel, and the same anti-squat gate applies. This keeps the shared people-resolution path (§8.2.5) untouched.

### 8.3.7 Private channels (RESERVED — not v1)

`read:"members"` + an `encryption` block (`scheme ∈ {rewrap, sender-keys, mls}`) under the **same** kind-30110 descriptor enables private channels in a later phase, using the kind-30113 group-key rotation record (reserved, §10). The descriptor, roles, write gates, moderation, and governance chain are inherited unchanged; only an `encryption` block + the kind-30113 epoch machine are added. v1 does not implement this; the public-channel descriptor is forward-compatible by a flag, not a format break. The S9 member-to-member leak and forward-secrecy limits apply only to those phases (SECURITY S-CH-6/7).

### 8.3.8 Channel close (retire) — NORMATIVE

A founder MAY **close** (retire) a channel. Because a channel is content-addressed and its posts are public on relays the protocol does not control, **close is forward-effective only — it is NOT deletion** and a conforming client MUST NOT present it as erasure (S-CH-8, mirroring the §8.2.4 / S15 rule for directory tombstones). Close is a **descriptor revision**, not a new kind:

- **Mechanism.** Publish a kind-30110 supersede at the channel's d-tag with `status:"closed"` (`supersedes` → the prior `descriptor_id`), inheriting the §8.3.1 governance chain (freshest valid descriptor wins, NIP-01 keep-latest). `status` is **OMITTED when active** (an active descriptor is byte-identical to a pre-`status` one — vc14/vc15 unaffected) and present only as `"closed"`. A client that resolves a `status:"closed"` descriptor MUST render the channel **read-only** (history visible, no composer) and SHOULD show the optional `successor_channel_id` as a **user-confirmed link** (never an auto-redirect; render its founder address + trust tier).
- **Authority (NORMATIVE).** The `status` transition (close OR re-open) is **founder-only**. An admin-signed supersede that changes `status` is `E_CH_UNAUTHORIZED` — closing a channel others rely on is exactly the governance coup §8.3.1 forbids. Re-open = a later founder-signed `status:"active"` (omit the field) supersede; the lifecycle is reversible and every transition is a signed, dated, auditable artifact.
- **Write gate.** A closed channel denies every new post with `E_CH_CLOSED`, but **still accepts removal tombstones** (§8.3.5) so moderation survives close. Already-propagated posts are unaffected.
- **SHOULD also.** On close a client SHOULD (a) fire the §8.3.6 kind-30114 directory tombstone (`opted_in:false`) to pull the @handle from discovery, and (b) emit a best-effort [NIP-09](https://nips.nostr.com/9) kind-5 deletion request at the descriptor address — but MUST treat NIP-09 as a non-guaranteed *request* (relays MAY ignore it; the request is itself a permanent public record), never as success.
- **Honest ceiling (NORMATIVE).** Close **cannot** erase the descriptor or any post (the id is the bytes), retract copies on non-conforming relays / archives / scrapers (S14), force a relay to forget, or reclaim the `channel_id` (bound to `founder_address`). The client copy MUST say so plainly. [NIP-62](https://nips.nostr.com/62) "vanish" is a stronger future option but binds only relays that implement it, so it does not change this ceiling — out of v1.

## 8.4 Relay AUTH (NIP-42) — NORMATIVE (institutional metadata hardening)

§8's transport leaves one disclosed residue: the recipient inbox pubkey in the kind-1059 `p` tag, plus the bare fact of a connection, are visible to any observer of an open relay (SECURITY S6). [NIP-42](https://nips.nostr.com/42) lets a relay demand an authenticated connection before it serves or accepts events, so an **unauthenticated** observer never sees the `p` tag at all. This is the institutional privacy posture: pair an `auth-required` relay with the v2 encrypted wrap (§8) and a relay learns nothing about who is reachable except to clients it has admitted.

**Handshake.** On an `auth-required` relay the server sends `["AUTH", <challenge>]`; the client replies `["AUTH", <signed kind-22242 event>]` where the kind-22242 event carries tags `["relay", <relay-url>]` and `["challenge", <challenge>]`, a recent `created_at`, empty `content`, and a Schnorr signature. A client MUST perform this exchange before publishing or subscribing on such a relay, and MUST re-attempt a publish/subscribe that a relay rejects with an `auth-required:` `OK`/`CLOSED` message after completing AUTH (`E_RELAY_AUTH_REQUIRED`).

**Which key signs (NORMATIVE).** The kind-22242 event is **not** the gift-wrap and MUST NOT be signed by an identity key, and (because AUTH is per-connection while a connection carries many independently-keyed gift-wraps) MUST NOT be tied to any one message's ephemeral wrap key. The default is a **fresh, per-connection ephemeral key** generated only for the handshake and discarded with the socket: the relay learns one random pubkey that links to no identity and no message — pure access-gating that closes the S6 observer leak with zero new disclosure. A relay that instead **allow-lists** specific members (a single-org institutional relay) MAY require a designated stable credential key; the client config names it per relay (`auth_key`), and absent that, the per-connection ephemeral key is used. The relay it authenticates to is a **named trust anchor** (§invariant 8): it now gatekeeps the metadata it once leaked, so its URL is surfaced in the client's relay settings, never implicit.

**Ed25519 verdict (NORMATIVE honesty).** Relay AUTH is **not** Bitcoin-load-bearing — it works identically with any Schnorr keypair and any relay; it carries no Bitcoin claim and proves no identity by itself (the per-connection key is deliberately random). It is a metadata-privacy hardening that *rides on* the identity already proven by the §3 device record and BIP-322 binding. The shared public relay (`relay.ochk.io`) is open by default; AUTH is an opt-in posture for self-hosted / institutional relays, and a conforming client MUST surface that an `auth-required` relay sees the connection metadata of clients it admits.

## 8.5 Source-intake mode — NORMATIVE (institutional composition, no new crypto)

Source-intake (a SecureDrop-shaped one-way tip line) is a **composition of shipped primitives**, not a new envelope kind or ceremony: a public **intake channel** (§8.3, kind-30110, `write:"open"` or `utxo-floor`) is the org's advertised drop, where a **source** the org does not pre-know posts material (kind-30111) under an ephemeral or throwaway identity; the org reads the public post and **replies privately** by gift-wrapping a speak-now DM (§8) to the post's `author_inbox_pubkey`. No new kind, no new crypto: the public submission is an ordinary channel post; the private reply is an ordinary kind-1059 wrap to the source's inbox key.

- **Source identity.** A source SHOULD use a fresh device key (its own `did:oc` session bridge or a throwaway) so the intake post and the source's other activity are unlinkable. The org stays Bitcoin-rooted (the intake channel's founder is a Bitcoin identity, and `utxo-floor` write pricing — if set — is the org's anti-flood gate). A conforming source client MUST be able to receive the org's private reply at the bootstrap queue (§8.1.2) derived from the source's ephemeral inbox key, and that ephemeral session MUST survive the client's sign-in flow.
- **Metadata.** The submission is public by the source's choice (it is a tip line). The reply is a normal wrap — recipient `p` tag visible per §8.1.2 — and an `auth-required` relay (§8.4) on the org's side closes even that to unauthed observers. The §8.2.3 social-graph firewall holds: a public intake channel reveals that the drop exists and who founds it, never the set of sources.
- **Ed25519 verdict.** Source-intake adds **no** Bitcoin mechanism of its own — it is transport composition; whatever Bitcoin claim it carries is the intake channel's write policy (`utxo-floor` ⇒ rooted, else the muted "via ochk.io" tier). Honest: the value is the *composition* (anonymous in, authenticated private reply out), not a new load-bearing primitive. Trust anchors — the relay(s) and the org's founding identity — are named in plaintext.

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
| `E_CHANNEL_RECIPIENTS` | A `chat-channel` envelope (§8.3) carried a non-empty `recipients[]` — a v1 channel post is public and recipient-less. |
| `E_CH_POLICY_INVALID` | A kind-30110 descriptor's `write.rooted` flag did not match its `write.policy` (§8.3.3): `utxo-floor` must be `rooted:true`; `allowlist`/`founder`/`open` must be `rooted:false`. |
| `E_CH_UNAUTHORIZED` | A descriptor replacement or moderation tombstone was signed by an address not in the prior epoch's founder/admin (descriptor) or roster moderator/admin (tombstone) set. |
| `E_CH_WRITE_DENIED` | A `chat-channel` post failed the channel's `write.policy` gate (§8.3.3). |
| `E_CH_NOT_WRITER` | The post author holds a reader-only role on the channel. |
| `E_CHAN_FLOOR` | A `utxo-floor` channel post's `write_proof` failed: bad `control_sig`, `value_sats` below floor, or UTXO age below `utxo_floor_confs` at the anchor. |
| `E_CH_CLOSED` | The channel is closed (§8.3.8, `status:"closed"`): new posts are denied; only removal tombstones are accepted. Forward-effective, founder-reversible. |
| `E_RELAY_AUTH_REQUIRED` | An `auth-required` relay (§8.4) rejected a publish/subscribe pending NIP-42 AUTH. A client MUST complete the kind-22242 handshake and re-attempt. |
| `E_FEDIMINT_UNAVAILABLE` | A named-Fedimint postage endpoint (§6.5) did not respond or could not be reached. |
| `E_FEDIMINT_BINDING_MISMATCH` | A federation-fronted postage invoice (§6.5) failed the §6.3 description-hash / nonce / amount binding. |

## 10. Nostr kind registry

OC Chat claims a fresh block above OC Find's (unratified) 30094–30109 reservation. d-tags are **verb-rooted** (`oc-lock-chat-*`) because chat is a mode of the lock verb, not a brand of its own.

| Kind | Object | `d`-tag prefix | Notes |
|---|---|---|---|
| 30110 | **channel descriptor** (addressable, NIP-33-replaceable) | `oc-lock-chat-ch:` | §8.3.1. Governance hash-chain; one active descriptor per `channel_id`; d-tag salt `oc-lock-chat-ch/v1:`. |
| 30111 | **channel post** (`chat-channel`; addressable) | `oc-lock-chat-msg:` | §8.3.2. Public, signed, recipient-less. gift-wrap (kind-1059) stays the DM transport; 30111 is the channel/public-post carrier. |
| 30112 | seal / block-height anchor descriptor | `oc-lock-chat-seal:` | references the sealed envelope id + `unlock_block` + beacon. |
| 30113 | reserved (group-key rotation) | `oc-lock-chat-*:` | registry extension; not canonical v0. |
| **30114** | **discoverability directory / reachability listing** (addressable, NIP-33-replaceable) | `oc-lock-chat-dir:` | §8.2. d-tag = salted handle hash; opt-in, UTXO-gated, revocable by tombstone. |
| 30115 | reserved (postage-policy record) | `oc-lock-chat-*:` | registry extension; not canonical v0. |

The transport gift-wrap remains Nostr kind-1059 (NIP-59, not an OC-allocated kind). Device records remain kind-30078 (OC Lock SPEC §11). Relay AUTH (§8.4) uses **kind-22242** — a [NIP-42](https://nips.nostr.com/42) ephemeral handshake event, signed per connection and never stored; it is a Nostr protocol kind, NOT an OC-allocated or content-addressed artifact. Allocating these required widening the family range past 30099; the workspace `KINDS.md` and `oc-agent-protocol/SPEC.md §4` are the rolled-up source of truth.

## 11. Compliance checklist

A client is OC Chat v0 compliant iff it:

- [ ] Reuses OC Lock §4.2 wrapping verbatim for `content_key`.
- [ ] Computes `chat_aad` and `chat_envelope_id` with `recipients=[]` for `kind ∈ {chat, chat-seal}` (§3) and reproduces the test vectors.
- [ ] Carries `conversation_id`/`seq`/`parent_id` inside the encrypted payload and orders by the `parent_id` hash-chain, never by `created_at` (§5).
- [ ] If it offers durable store-and-forward, derives `queue_id`/`bootstrap_id` per §8.1, routes the inbox solely on those opaque ids (no address/device-pubkey index), stores the blob byte-for-byte, and reproduces vector `vc06`.
- [ ] If it offers the directory (§8.2), publishes a kind-30114 listing ONLY on explicit opt-in (default invisible), derives the salted-handle `d`-tag (vector `vc07`), refuses to resolve a handle unless the §8.2.2 gate passes (signature + kind-30078 binding + UTXO floor), enforces the §8.2.3 social-graph firewall, honors tombstones (vector `vc08`), and never exposes a bulk-dump endpoint.
- [ ] For `pay-to-reach` (§6): carries `postage` in the `ChatBody` (§6.2), and on receive runs the full §6.3 verification — re-derives the description-hash binding `SHA-256(lnurl_metadata‖payerdata)` ITSELF over verbatim bytes, checks `SHA-256(preimage)==payment_hash` + amount + expiry + identifier + the local spent-ledger — routing a failing/replayed message to the filtered/pending state (delivered, never dropped), and NEVER claims transferable third-party proof.
- [ ] Wraps to the beacon and performs release re-wrap as a detached `recipients[]` merge for `seal-til-block` (§7), and NEVER labels a v0 beacon seal "trustless".
- [ ] Surfaces every trust anchor (beacon id/url, relay, redundant beacon) and the early-release / brick risks at compose time.
- [ ] Operates no OC payment rail for postage (§6.4).
- [ ] If it offers public channels (§8.3): publishes a founder-rooted kind-30110 descriptor with exactly one `write.policy` and a matching `rooted` flag (`E_CH_POLICY_INVALID` otherwise); validates the governance hash-chain on every descriptor replacement (`supersedes` + prior-epoch admin signature); rejects a `chat-channel` post with non-empty `recipients[]` (`E_CHANNEL_RECIPIENTS`); on `utxo-floor`, verifies the height-anchored `write_proof` against public chain data — the `outpoint` is unspent, owned by the UTXO address, and carries the exact `value_sats`/height/hash claimed — deduped per-outpoint (not per-post) and fail-closed; renders a non-rooted channel (`allowlist`/`founder`/`open`) in the muted "via ochk.io" tier; honors removal tombstones (forward-effective only); and reproduces vectors `vc14`–`vc17`.
- [ ] If it supports an `auth-required` relay (§8.4): completes the kind-22242 NIP-42 handshake before publish/subscribe (`E_RELAY_AUTH_REQUIRED` otherwise), signs the challenge with a fresh per-connection ephemeral key by default (or a configured `auth_key`), surfaces the AUTH relay as a named trust anchor, and NEVER presents AUTH as making a relay trustless.
- [ ] If it offers source-intake (§8.5): warns the source at submission time that the intake post is public + permanent (only the org's reply is E2EE), defaults the source to a fresh throwaway identity, and never claims SecureDrop-grade anonymity for the inbound leg (S-M7-2).
- [ ] If it offers a named-Fedimint postage fallback (§6.5): surfaces the federation as a named plaintext custodian before the sender pays, lets the sender decline a federation-fronted endpoint, keeps OC out of custody (the federation settles), and does not enable the path absent a money-transmitter analysis (`E_FEDIMINT_*`).
- [ ] Emits §9 + OC Lock §6 error codes.

## 12. Security model

See [`SECURITY.md`](./SECURITY.md). In brief, OC Chat inherits OC Lock's guarantees (authenticity, confidentiality, identity binding) and gaps (no per-message forward secrecy, plaintext envelope metadata, no delivery guarantee) and adds: a beacon-trust posture for seals (not offline-verifiable in v0), a seal-existence metadata leak, and an offline-verifiable Lightning postage proof.

## 13. Versioning

OC Chat versions with OC Lock's `envelope.v` (currently 2). New `kind` values and new optional blocks (`postage`, `seal` sub-fields) are additive; clients MUST preserve unknown fields when relaying and MAY ignore them when decrypting. Incompatible changes increment `envelope.v`.

## 14. IANA / external identifiers

- Nostr kinds: **30110** (channel descriptor, §8.3.1), **30111** (channel post, §8.3.2), **30112** (seal), **30114** (directory, §8.2), addressable, d-tag namespace `oc-lock-chat-*` claimed by this spec; **30113** reserved (group-key rotation, private channels §8.3.7), **30115** reserved (`pay-to-post`, §8.3.3); transport reuses kind-1059 (NIP-59).
- Gift-wrap content tag: `ct = "oc-chat/v2"` (encrypted wrap, §8 normative). `"oc-chat/v1"` (plain base64) is legacy — accepted on receive only, never published.
- Directory d-tag salt label: `"oc-lock-chat-dir/v1:"`. Channel descriptor d-tag salt label: `"oc-lock-chat-ch/v1:"`.

## 15. Acknowledgements

OC Chat extends [OC Lock](https://github.com/orangecheck/oc-lock-protocol) and the OrangeCheck identity primitive. The "Bitcoin as identity, not access oracle" framing — which is why the daily messenger leans on BIP-322 identity rather than a chain transaction in the send path — is owed to [Bram Kanstein](https://bramk.substack.com/). See OC Lock `WHY.md`.
