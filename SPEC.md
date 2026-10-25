# oc chat — specification (v0.1)

**Status:** draft. OC Chat is a **mode of OC Lock**, not a new verb. It extends the OC Lock v2 envelope ([`oc-lock-protocol/SPEC.md`](https://github.com/orangecheck/oc-lock-protocol/blob/main/SPEC.md)) with two `kind` values and a thin threading / postage / seal layer. The base cryptography (X25519 ECDH + HKDF-SHA256 + AES-256-GCM, RFC 8785 canonicalization, BIP-322 identity binding) is **unchanged and not restated here** — read the OC Lock spec first.

This document uses the key words MUST, MUST NOT, SHOULD, MAY per [RFC 2119](https://www.rfc-editor.org/rfc/rfc2119).

## 0. Notation

- `env` — an OC Lock envelope (OC Lock SPEC §4.1).
- `canonical(x)` — RFC 8785 canonical bytes of `x`, LF-terminated, with `recipients[]` sorted by `device_id` ascending (OC Lock SPEC §5).
- `SHA-256(x)` — 32-byte digest; hex unless stated.
- `addr` — a Bitcoin address; the user's identity (OC Lock SPEC §2).
- A **device record** — a kind-30078 Nostr event binding an X25519 `device_pk` to `addr` via BIP-322 (OC Lock SPEC §3).
- An **inbox key is bound to `addr`** only as OC Lock SPEC §3.4 authorizes it: a v3 record binds its signed `nostr_pk`; a v2 record binds its `event.pubkey` only while it is the sole pubkey carrying that `(addr, device_id)` and no v3 record exists for it, and from 2027-01-21T00:00:00Z by the reader's clock binds no key at all (OC Lock 2.3.0). Publishers MUST emit v3 records. A BIP-322-valid revocation seen on any relay retires every bind of that `device_id` whose signed `created_at` is not later than its signed `revoked_at` (OC Lock SPEC §3.5 and LIFECYCLE §1.1, from OC Lock 2.1.0), whichever Nostr key carried either record, even while another relay still serves the bind. A bind dated later than the reader's clock plus a skew allowance is not live yet, and a revocation is dated no earlier than the latest `created_at` among that device's binds (OC Lock 2.2.0). A `did:oc` session device is bound as §8.6 specifies.

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

> **v0 STATUS — read before implementing.** `@orangecheck/lock-core` ships
> `EnvelopeKind = 'identity' | 'payment'` and no `chat`/`chat-seal` kind, so a
> v0 `speak-now` / `pay-to-reach` / `seal-til-block` message goes out as a base
> OC Lock `"identity"` envelope carrying `hint: "oc-chat/v1"`, with base OC Lock
> content addressing (recipient-INCLUSIVE `id` and AAD). §7.6 defines that
> profile and marks it NORMATIVE — *what ships*. This table and §3 describe the
> **upgrade target**, whose vectors are `vc03` / `vc04`.
>
> So a reader comparing the shipped wire against §2/§3 alone will conclude the
> client is non-conformant. It is not; it conforms to §7.6. Do not "fix" the
> client to match this table without also landing the lock-core kinds — that
> would change the `id` of every message ever sent.

**NORMATIVE amendment for `chat-channel` (do not undersell).** Unlike `chat`/`chat-seal`, a v1 `chat-channel` post is **public** (§8.3) — there is no recipient set, no key-wrapping, and no AEAD ciphertext over a body. Its `recipients[]` MUST be empty; a non-empty `recipients[]` on a `chat-channel` envelope is `E_CHANNEL_RECIPIENTS` and the post MUST be rejected (this is what makes the §8.2 social-graph leak structurally absent for public channels — there is nothing to leak). The post body is plaintext, content-addressed, and BIP-322-rooted by the author's device signature; the recipient-exclusion `chat_envelope_id` rule of §3 still applies (`recipients=[]` is the steady state, not a re-wrap).

## 3. Content addressing for chat kinds (the recipient-exclusion rule) — NORMATIVE for the upgrade target

This is the one cryptographic rule that differs from base OC Lock, and it is load-bearing **for the §7.2–7.3 beacon-device re-wrap path**.

> **NOT the v0 wire.** The rule exists so a held envelope can be re-keyed after
> sealing (§1.1, §7.3) — that is its entire purpose. The shipped v0 profile
> (§7.6) does not re-wrap anything: the reveal secret is timelock-encrypted to a
> drand round and rides *inside* the ciphertext, so `recipients[]` is never
> replaced and nothing needs to survive a re-key. v0 therefore uses base OC Lock
> addressing, where `recipients[]` IS included in both the `id` and the AAD.
>
> Both halves matter and are easy to miss: §3 changes the **AAD** as well as the
> `id`, so an implementation that computes `chat_aad` cannot decrypt a v0
> envelope, and vice versa. Landing this rule is a wire break, not a relabelling.

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

Free-tier anti-spam is recipient policy, enforced by the recipient client, not the protocol: require a mutual contact, OR a BIP-322 proof of control of a funded/aged UTXO. Neither involves a payment. The envelope's `from.address` counts for either only when its device signature verifies under a key a device record binds to that address; until then it names an address and proves nothing about it.

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
   **Payee (NORMATIVE):** every carrier field is supplied by the sender, who can mint and pay an invoice on a node of their own that carries the recipient's identifier and a matching description-hash. The recipient MUST therefore check that the `bolt11` is signed by a node its own endpoint issues invoices from (the key recovered from the BOLT 11 signature, which MUST match an explicit `n` field when present), and SHOULD check that `lnurl_metadata` equals, byte for byte, the metadata its endpoint serves. The recipient learns its node set by requesting an unpaid invoice from its own endpoint when it sets a floor. A recipient that does not know its node set MUST treat postage as unverified.
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

where `inbox_pubkey_hex` is the recipient's published §8 inbox pubkey (lowercase hex). The bootstrap queue carries the same recipient-linkability the relay `p` tag does (SECURITY S6) and MUST be disclosed as such; it is used only until a per-conversation queue is established. Anyone can deposit to it; draining and acknowledging it follow §8.1.5.

### 8.1.3 Handshake

To migrate a conversation off the bootstrap queue, each party advertises **its own** receiving `queue_id` inside the encrypted payload (§5 `recv_queue`). A party that has learned its peer's `recv_queue` MUST deposit subsequent messages for that conversation there, and SHOULD stop using the peer's bootstrap queue. Because `recv_queue` travels inside the AEAD-sealed payload, the operator never learns the bootstrap↔per-conversation mapping and cannot link the two.

### 8.1.4 Operator obligations — NORMATIVE

A store-and-forward inbox operator MUST:

1. Store the gift-wrap inner blob **byte-for-byte** — preserving the envelope `id`, `sig`, and ciphertext GCM tag, and preserving unknown fields (§13). A re-wrap fan-out (§3.3) is a detached `recipients[]` merge and MUST NOT recompute the signed `id`.
2. Route **solely** on the opaque `queue_id` / `bootstrap_id`. It MUST NOT require, store, or index a Bitcoin address, a device pubkey, or any plaintext thread metadata, except that it checks, and MUST NOT store, the inbox pubkey of a §8.1.5 proof.
3. Hold **no** key material of any party.
4. Treat the queue as **availability, not authority**: a draining recipient re-verifies authenticity from the artifact alone (BIP-322 device-record binding + `chat_envelope_id`), exactly as for a relay-delivered message. The operator endpoint is a NAMED trust anchor for *availability* and MUST be surfaced plainly.

The Ed25519 substitution test passes by inheritance: the queue is an ordinary mailbox that asserts no Bitcoin claim of its own, but the authority of every message it holds derives from the BIP-322-rooted device record (§0), which collapses under substitution.

### 8.1.5 Bootstrap proofs — NORMATIVE

Anyone holding a device record can derive its `bootstrap_id` (§8.1.2), so that id alone cannot authorize reading or acknowledging the bootstrap queue. A device proves the queue is its own with a BIP-340 signature by its inbox key:

```
proof   = { "inbox_pubkey": <lowercase x-only hex>, "ts": <unix seconds>, "sig": <hex> }
message = utf8( "oc-lock-chat/inbox-proof/v1:" || action || ":" || bootstrap_id || ":" || decimal(ts) [ || ":" || ids ] )
ids     = hex( SHA-256( utf8( join("\n", sorted(distinct(envelope_ids))) ) ) )   // an "ack" only
sig     = BIP-340( inbox_sk, SHA-256(message) )            // action is "drain" or "ack"
```

An ack's proof covers exactly the envelope ids of its request, so a proof seen once acknowledges nothing else.

where `bootstrap_id` is derived from `inbox_pubkey` per §8.1.2. An operator checking a proof derives `bootstrap_id` from `inbox_pubkey`, verifies `sig` for the action requested, MUST refuse a proof whose `ts` is more than 600 seconds from its own clock, and MUST NOT store `inbox_pubkey`.

The first valid proof for a bootstrap queue that holds messages marks the queue proven. From then on the operator MUST NOT return messages from that queue to a drain that carries no valid proof for it, and MUST refuse an acknowledgement of it that carries none (`E_QUEUE_ROUTE`), writing nothing. When it first marks a queue it SHOULD return again the messages acknowledged in that queue and not yet swept. It MAY drop the mark of a queue that holds no messages and has had no deposit for 30 days; the next proof marks it again. A queue never proven, and every per-conversation queue (§8.1.1, unguessable without `queue_seed`), is drained and acknowledged by its id alone, so a client that sends no proofs keeps receiving. A conforming client SHOULD send a proof with every drain and acknowledgement of its bootstrap queue (vector `vc21`).

A proof carries no Bitcoin claim: any Schnorr key proves its own queue. It keeps a party without the inbox key from reading or acknowledging a device's first contacts; the authority of the messages is still the BIP-322-rooted device record (§8.1.4 (4)).

## 8.2 Discoverability directory (opt-in) — NORMATIVE

§8 lets a sender who already knows your Bitcoin address reach you (your kind-30078 device record IS your inbox). The directory adds the missing half: being **found by a human-readable handle** without the searcher knowing your address — strictly opt-in, revocable, and graduated. **The default is invisible:** a conforming client publishes NO directory record unless the user explicitly opts in.

A handle belongs to the first claim **anchored in Bitcoin** that still stands (§8.2.5). The order is a block height no claimant chooses, so a claim made after the holder's costs nothing to dismiss, and two holders can never tie the handle up.

### 8.2.1 The listing record and its claim

A listing is an **addressable** (NIP-33-replaceable) Nostr event, **kind 30114**, signed by the user's **inbox key** (`deriveNostrKey(device_sk)` — the same key that signs gift-wraps, §8):

```
d-tag   = "oc-lock-chat-dir:" || base64url( SHA-256( "oc-lock-chat-dir/v1:" || lower(handle) ) )   // unpadded
content = canonical JSON {
  "v": 2, "handle": "<[a-z0-9_]{3,32}>", "address": "<bitcoin address the inbox key is bound to>",
  "inbox_pubkey": "<hex; the §8.2 reachability pointer = the event pubkey>",
  "claim": { "outpoint": "<txid:vout>", "nonce": "<64 lowercase hex>", "ots": "<base64 OpenTimestamps proof>" },
  "display_name"?: "<=48 chars", "bio"?: "<=80 chars", "avatar"?: "<small inline raster data: URL, ≤24KB>",
  "opted_in": true, "created_at": <unix seconds>
}
listing_id = SHA-256( canonical(content) )   // hex, content-addressed (invariant 4)
```

The **claim** is what orders the handle. It names the coin that backs it and is anchored to Bitcoin with OpenTimestamps (OC Stamp SPEC §6):

```
claim_id = SHA-256( canonical({ "v": 1, "handle": lower(handle), "address": address,
                                "outpoint": "<txid:vout>", "nonce": "<64 hex>" }) )
```

- `outpoint` is a transaction output paying to `address`: the coin that backs the claim (§8.2.2 (3)). `txid` is 64 lowercase hex, `vout` a decimal integer.
- `nonce` is 32 bytes, 64 lowercase hex. A client draws it at random for a new claim; it makes each claim its own (§8.2.4).
- `ots` is a proof that walks from `claim_id` (the raw 32 bytes) to Bitcoin attestations (OC Stamp SPEC §6.1–§6.3).

A reader recomputes `claim_id` from the listing's own `handle`, `address` and the claim's `outpoint` and `nonce`, so a claim cannot be carried into a listing for another address or handle.

**The claim's anchor** is the lowest block height among the proof's Bitcoin attestations that verify (OC Stamp SPEC §6.3: the header at that height, its hash, its Merkle root) and have **at least 6 confirmations** at the reader's tip (`tip − height + 1 ≥ 6`). A claim with no such attestation (a pending proof, a broken one, one over another digest, or one anchored in the last 5 blocks) is **unanchored**.

**`avatar` is an inline `data:` raster URL, NOT an external link (NORMATIVE).** A profile image rides as a small `data:image/(png|jpeg|webp|gif);base64,…` URL inside the signed content — content-addressed (it changes `listing_id`, so it can't be swapped under a fixed handle), offline-verifiable, and with **no third-party fetch**. An external `https` avatar URL is forbidden: loading it would turn every directory lookup into a **tracking pixel** that leaks the viewer's IP + timing to the image host (and a non-content-addressed image can be swapped after signing). A conforming client downscales any picked image to a small square (reference clients: ~128px webp) and MUST render an avatar ONLY if it is a bounded raster `data:` URL — never `image/svg+xml`, `text/html`, or any non-raster type (the `data:`/blob-URL XSS class); an unsafe or oversized avatar is dropped, the listing still resolves.

The `d`-tag is a **salted hash of the handle** — a conforming directory is **lookup-by-known-handle, never enumerate-all** (there is NO `GET /all` and no bulk-dump). It is keyed by the handle hash, not the raw address (a raw-address key would be deterministically enumerable). `canonical(x)` is §0's RFC 8785 + LF-terminator.

A `v: 1` listing (0.3 and earlier) carries no claim and holds no handle, except through §8.2.8.

### 8.2.2 The Bitcoin gate — NORMATIVE (this is what makes the directory belong to this family)

A bare listing is **not** Bitcoin-load-bearing: *"address X, here is my inbox key, signed by X"* substitutes perfectly to an Ed25519 npub signed by an npub. A conforming resolver therefore MUST refuse to honor a claim unless **all four** hold:

1. The kind-30114 event is signed by `inbox_pubkey`.
2. `inbox_pubkey` is bound to `address` via a valid kind-30078 device record (the existing BIP-322 binding, OC Lock §3). **The directory inherits its Bitcoin proof from the device record — no second wallet ceremony.**
3. **The claim's coin cleared the floor at its anchor, and still does.** The `outpoint` pays to `address`, carries at least the deployment's `dir_floor_sats`, confirmed at a height no later than `anchor − dir_floor_confs`, and has not been spent by a transaction with 6 or more confirmations. A spend still in the mempool or with fewer confirmations does not count. The RECOMMENDED v0 floor is a funded output and `dir_floor_confs = 144` (about a day). An Ed25519 keypair has **no analog to a coin that was already aged when the claim was anchored and has not moved since** — so a place in line costs Bitcoin maturity, paid before the place is taken. UTXO state is **public chain data**, so the check preserves offline-verifiability (invariant 5).
4. The claim is **anchored** (§8.2.1).

A claim that fails (3) with an answered read fails for good: the outputs that qualify at its anchor can only be spent, never added. A reader MAY remember its `claim_id` as dead, keeping what it saw (the spending `txid` and its height, or the coin's confirmation height); a directory relay MAY drop it.

Handle order is **by anchor, not by consensus**: the address is the trust root; the handle is a non-authoritative display label (S17). A `did:oc`-only identity (the session bridge, no Bitcoin address) MAY publish a bridge listing but MUST NOT claim a scarce handle under (3); a conforming client surfaces it with a muted "via ochk.io" tier and prompts attaching a Bitcoin address to graduate.

### 8.2.3 The social-graph firewall — NORMATIVE

The listing record MUST NOT contain, reference, or be co-indexed with any `queue_id`, `recv_queue` (§8.1.3), `conversation_id`, contact list, or message-routing metadata. **The directory reveals a NODE — "this identity is reachable" — and NEVER an EDGE — who messages whom.** The only reachability pointer it republishes is `inbox_pubkey`, which a sender who resolved your handle needs anyway and which the device record already exposes. The claim's `outpoint` is public chain data the user chose to name; it adds no edge.

### 8.2.4 Revocation

Self-removal = publish a replacement kind-30114 event with the **same d-tag**, `opted_in: false`, an `"ends": "<claim_id>"` naming the claim it withdraws (a tombstone carries no claim of its own), and the optional fields stripped, signed by the inbox key (reusing the OC Lock §3.5/§3.6 tombstone precedent). Because the event is NIP-33-addressable, the tombstone **replaces** the prior record at conforming relays. A conforming client MUST treat a tombstone — or an absent record — as not-discoverable, MUST refuse to resolve the handle to that address, and MUST treat a tombstone seen on ANY relay as authoritative over that same owner's older live copies even if a stale one exists elsewhere. A tombstone withdraws only its own author's claim: it counts only when it passes §8.2.2 (1)–(2) for the `address` it names. **A `claim_id` that a counted tombstone ends never counts again**, so listing again takes a new claim with a new `nonce` and a new anchor, behind every claim anchored before it. A tombstone SHOULD additionally fire a NIP-09 deletion request. **Revocation is forward-effective only** (NORMATIVE honesty, surfaced at opt-in time): a tombstone stops new resolution on conforming relays; it cannot retract copies on non-conforming relays, archives, or scrapers. The promise is "stop new discovery," never "delete yourself completely." Removal does not unsend or break existing conversations.

Editing a listing (name, bio, avatar) or listing it from another device bound to the same address keeps its claim, and with it the claim's place.

### 8.2.5 Resolution

To find a user, a client computes the `d`-tag from the queried handle, reads the kind-30114 events for it (§8.2.6), and:

1. **Drops, before any read,** every record that is not `v: 2` with a matching `handle`, and every live listing (`opted_in: true`) whose `claim_id` does not recompute or whose claim is unanchored. An unanchored claim never holds a handle and costs a reader no read. A tombstone carries no claim and is kept for step 3.
2. Orders the live listings left by **(anchor height, `claim_id`)** ascending. Two claims anchored in one block are ordered by `claim_id`.
3. **Walks that order.** For each listing:
   - **The binding comes first.** The first time the walk meets an `address`, it reads which keys are bound to it (§8.2.2 (2)), once, and keeps the answer. A record signed by a key not bound to the `address` it names belongs to nobody and carries no weight, as a listing or as a tombstone. A listing whose key only a v2 record binds stops resolving from 2027-01-21 (§0) until its device re-binds as v3, which binds the same key.
   - **The address's state** is its freshest record, by `created_at`, among the records signed by its bound keys (§8.2.2 (1)–(2)): a live listing, or a tombstone if it opted out. `created_at` is compared only within one address, never across addresses. A claim that a tombstone signed by a bound key `ends` is ended (§8.2.4).
   - If the state is a live listing carrying this claim, and the claim is not ended, the walk reads the claim's coin (§8.2.2 (3)). If the coin passes, **this claim holds the handle**, and claims after it are never read. Otherwise the walk goes on to the next listing.
4. **No answer is not a failure.** If the binding read or the coin read for a claim before the holder gets no answer (no relay answered, the chain source refused, timed out or was rate-limited), the walk stops with `E_DIR_UNRESOLVED`. Passing over such a claim would hand the handle to a later claimant. A claim is passed over only when its read answered and showed it fails.
5. A resolver bounds its work: at most 256 distinct addresses read for bindings and at most 64 claims read for their coin. A walk that reaches a bound before a holder ends `E_DIR_UNRESOLVED`. Records dropped in step 1 never count toward a bound. A claim found only by the public audit is walked under the audit's own bounds (§8.2.6).
6. A walk that ends without a holder is `E_DIR_REVOKED` if a tombstone signed by a bound key is the state of an address it read, else `E_DIR_UNVERIFIED`.

`E_DIR_UNRESOLVED` means the read could not settle the handle. A conforming client says so and offers the address route ("message them by their address"); it MUST NOT present it as contested or as not listed.

On success the client surfaces `address` + profile + a trust tier so the user can start a thread. A client SHOULD remember which address a handle resolved to for each contact and say so when it later resolves elsewhere, rather than follow it silently; threads are keyed by address and never move. First-contact still passes the recipient's §4.1 anti-spam policy — **being listed is not a free-message bypass.** Privacy-sensitive resolution SHOULD query relays directly, NOT a third-party indexer (which would learn who-searches-for-whom). The relay/index operator is a NAMED availability anchor and MUST NOT be relied on as authority.

### 8.2.6 Where claims are read — directory relays and the public audit

A public relay answers newest-first up to its own limit and checks nothing, so anyone can place any number of records under a `d`-tag. No query shape finds the earliest anchors among them. A deployment therefore names **directory relays**: relays that admit a kind-30114 event only if it passes §8.2.2 (1)–(4) at write time (a tombstone: (1)–(2) and a known `ends`). The reference deployment's directory relay is **`wss://relay.ochk.io`** (a NAMED availability anchor, invariant 8).

- **A directory relay orders nothing.** Order is anchors anyone can check, and a reader re-verifies every record it uses. A directory relay can withhold a claim, never reorder or forge one, and a withheld claim's own OTS proof shows the omission.
- **Its write gate** checks cheapest first (signature, proof walk, header, binding, then one coin lookup), caches what it learns (a dead claim is dead for good, §8.2.2), keeps at most one live claim per `outpoint` per `d`-tag namespace, and holds a global budget for chain reads. When the budget is spent it refuses with NIP-01 `OK false "rate-limited: …"`, never by admitting unchecked.
- **A client publishes** a listing to the deployment's directory relays and to at least 2 public relays.
- **A reader** reads each directory relay **completely** (`limit` pages, `until` = the oldest `created_at` seen, inclusive, with duplicate ids dropped, until a page adds nothing new; a full page that adds nothing is a stalled read and the relay incomplete) and walks what it found (§8.2.5).
- **The public audit.** A reader also reads 2 or more public relays with a small budget of its own: at most 2 pages each, at most 64 addresses read for bindings and at most 16 coin reads for claims found only there. It walks one order: the records from every relay it read go through §8.2.5 together, and each record found only on a public relay is an **audit claim**. An audit claim that passes holds the handle, by the rule's own order. The first audit claim the walk cannot finish (a read without an answer, an exhausted audit budget) ends the audit: every later audit claim is passed over, while the claims from directory relays are walked as before. So public records can never turn a directory answer into `E_DIR_UNRESOLVED`, and a directory walk that stops with `E_DIR_UNRESOLVED` at a claim lets no audit claim anchored after that claim hold. A stalled public read ends the audit before it starts. A record signed by a key bound to its address counts toward that address's state (§8.2.5) wherever it was found.
- **With no directory relay answering,** the public read is the walk itself, not an audit: §8.2.5 (4)–(5) apply to it, with 64 addresses and 16 coin reads as its bounds, so a read without an answer before a holder is `E_DIR_UNRESOLVED`.

### 8.2.7 Making a claim — NORMATIVE for conforming clients

- **Anchor before revealing.** A client builds the claim, submits `claim_id` to at least 2 OpenTimestamps calendars run by different parties (OC Stamp SPEC §6.1), and publishes the listing **only once its anchor has 6 confirmations**. Publishing earlier would show the handle to anyone able to anchor into the same block.
- **Before publishing, it resolves the handle** (§8.2.5). If an earlier claim already holds it, the client says so and lets the user keep the place in line or pick another handle.
- **It names the coin.** The client shows which coin backs the handle and says plainly that spending it releases the handle for good, to whoever is next in line, and that a new claim goes to the back of the line. Consolidating, sweeping or mixing the wallet that holds the coin spends it.
- Anchoring usually takes a few hours (calendars commit about hourly, then 6 blocks), longer when fees are high. The user is reachable by address meanwhile.

### 8.2.8 Listings from before claims

A `v: 1` listing has no claim. A deployment MAY anchor one for it, with `nonce` = that listing's `listing_id` and `outpoint` = a coin of its address old enough at the anchor, and ship the claim with its own reader, which then treats exactly that `v: 1` listing as carrying it. The listing's own device republishes it as `v: 2` with the same claim, which every reader honors. No other `v: 1` listing holds a handle.

## 8.3 Channels — NORMATIVE (v1: public)

A **channel** is a composition, not a new verb and not a new mode: a kind-30110 governance **descriptor** + kind-30111 **posts** + (opt-in) a kind-30114 directory listing + a Bitcoin-priced **write gate**. v1 ships **public** channels (public read, signed posts, Bitcoin-gated write); private/encrypted channels are reserved behind the *same* descriptor (§8.3.7). One descriptor, phased by the `read` + `encryption` fields.

A public channel makes **no E2EE claim** — it uses OC Lock's *identity binding* (BIP-322 device signatures) and OC Chat's *Bitcoin-priced access control*, not its confidentiality. Clients MUST NOT carry the DM "relays learn nothing" headline onto channel posts (S-CH-4).

### 8.3.1 Channel descriptor — kind 30110 (addressable, one coordinate per version)

One descriptor per channel, signed by the **founder's inbox key** (`deriveNostrKey(device_sk)`), BIP-322-rooted to `founder_address` via that device's kind-30078 record. It is the single source of truth for identity, roles, and the read/write policy. Content-addressed (invariant 4). The `read` + `encryption` fields are the phase switch.

```jsonc
// kind 30110, addressable. Every version of the descriptor has its own coordinate:
// d-tag = "oc-lock-chat-ch:" || descriptor_id      (hex; the genesis included)
// t-tag = channel_id                                (indexed; a reader fetches every version with {"#t": [channel_id]})
// s-tag = supersedes                                (indexed; every version but the genesis; a reader walks forward by it)
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
//                 From 0.3.0 the event also carries that device record in its `binding` tag (below).
```

Normative rules a conforming client MUST honor:

- **`channel_id` binds to `founder_address`.** Identity is `SHA-256(founder_address || slug)`; the founder's address is the trust root. Two founders may reuse a `slug` → different `channel_id`s. The slug is non-authoritative (S17); the client MUST render `founder_address` + its trust tier alongside the slug. No global slug consensus (first-writer-wins, best-effort).
- **Resolve by `channel_id`, not by d-tag.** The d-tag is a relay lookup key anyone can publish under. A resolver MUST ignore every kind-30110 event whose `channel_id` differs from the channel being resolved before choosing among governance chains, so another founder's valid chain can never stand in for this channel.
- **Every version keeps its own coordinate.** A publisher MUST give each version (genesis and every supersede) the d-tag `"oc-lock-chat-ch:" || descriptor_id` and a `t` tag equal to `channel_id`, so that no version replaces another at a relay, and MUST give every version but the genesis an `s` tag equal to its `supersedes`. A publisher MUST NOT publish at the legacy d-tag.
- **Reading every version.** A resolver MUST fetch `{"kinds":[30110],"#t":[channel_id]}` and, for channels published before 0.3.0, also the legacy coordinate `{"kinds":[30110],"#d":["oc-lock-chat-ch:" || base64url(SHA-256("oc-lock-chat-ch/v1:" || channel_id))]}`, and resolve over every answer together, keeping every copy. Anyone can publish under the `t` tag, so a resolver MUST read every version a relay holds under it, paging with `until` past the relay's limit up to a bound it states (the reference reader reads 2,000 events per relay). Two narrower reads find the chain however much else sits under the `t` and `s` tags, and a resolver SHOULD make both. Each asks for one key at a time, `"authors":[key]`, for every inbox key the role holder's device records have ever bound (§0, §8.6), revoked keys included. Those are the keys its verified bind records bind; for a device no bind record of which remains, the key that carried its verified revocation; and the `nostr_pk` of every §8.6 host revocation. A device's own revocation has the pubkey, kind and d-tag of its bind record, so a relay keeps it in place of that record, and the revoked key is found only through it. A revocation carried by a fresh key leaves the bind in place and adds no key:
  - **The founder's keys.** It reads `{"kinds":[30110],"#t":[channel_id],"authors":[key]}` for each of the founder's keys. The resolver knows `founder_address` from the address it came by, or from any version whose `founder_address` and `slug` derive the `channel_id`.
  - **Forward by `s`.** From each version those reads return, it reads `{"kinds":[30110],"#s":[descriptor_id],"authors":[key]}` for each key of the founder and of every address in that version's `admins`, and goes on forward from what that returns. The next version can only be signed by one of those keys, and an earlier version stands on its binding whatever has happened to the key since, so a revoked key may have signed a version the chain still needs. A resolver MUST NOT walk forward from a version an open read alone returned: anyone can publish one.

  Reading one key at a time means that whoever holds a key, a thief included, can crowd only that key's own versions out of its answers; the walk back below recovers those from any later version. A resolver MAY bound how many keys it reads for one address and how many of these reads it makes, and states its bounds (the reference reader reads 32 keys per address and makes 256 reads). For a device whose own revocation replaced its bind, copies of that revocation under other keys cannot be told from the original, so each adds a key; enough copies push an address past the bound, and the resolver then reports the channel as not read, never a version it did not reach. When a version's `supersedes` names a version it has not read, the resolver MUST fetch that one by its exact d-tag, `"oc-lock-chat-ch:" || descriptor_id`, and go on back the same way, and MAY bound how many it asks for at once.
- **A cut-off read is not an answer.** Anyone can fill a bound. When an open read stopped at the resolver's bound on any relay, the resolver MUST report that the channel could not be read, never that it does not exist, unless a chain resolves and the narrower reads were complete: every key lookup was answered, no bound stopped them, and the founder was known. Otherwise a version it did not read may be newer than the one it found.
- **The descriptor is a governance hash-chain.** Every change (add admin, raise the floor, change policy) is a new kind-30110 version, at its own coordinate, with `supersedes` → the prior `descriptor_id`. A client MUST validate the new descriptor's signing inbox key is **device-bound (kind-30078) to the founder OR to an address in the *prior* `admins` set** — making governance tamper-evident and offline-verifiable (the §5 `parent_id` trick applied to governance) while reusing the device-record trust root instead of a per-edit wallet ceremony. A descriptor not so authored is `E_CH_UNAUTHORIZED`. The Bitcoin-load-bearing claim is carried by the **write policy** (§8.3.3), not the descriptor signature — so a `did:oc`-only founder can still open a public channel; its write tier just renders non-rooted unless the policy is `utxo-floor`.
- **Every version carries its signer's binding.** A publisher MUST add to every version event a `binding` tag whose value is the JSON text of the kind-30078 device record that binds the event's `pubkey`: an OC Lock v3 record (§0) for a Bitcoin address, or a §8.6 session record with its `vouch` for a `did:oc`. The record is evidence, outside `descriptor_id`. A resolver accepts it when its Nostr signature verifies and, for an address, its BIP-322 signature over the v3 statement verifies with the statement's `nostr_pk` equal to the event's `pubkey`; for a `did:oc`, when its `vouch` verifies as §8.6 states (a retired host key included, under §8.6's rule for retired keys), with `nostr_pk` equal to the event's `pubkey`. The address or `did:oc` the record names is the principal that signed the version, for the authority rules of this section. A version without a `binding` tag (published before 0.3.0) is signed by a principal only while a record on the relays binds its key (§0, §8.6); a key only a v2 record binds is bound by nothing from 2027-01-21, until its device re-binds as v3.
- **Earlier versions stand on their binding; the last version needs a live key.** A version with a later version after it on the chain being resolved is authorized by its `binding` alone. A later revocation of that key does not undo it: the hash links fix its place in the chain. The last version of a chain is authorized only if its binding is also live: no OC Lock §3.5 revocation (for an address) or §8.6 revocation (for a `did:oc`) seen on any relay retires it, and it is not dated ahead of the reader's clock (OC Lock 2.2.0). When the last version fails this, the chain resolves as the chain that ends at the version before it, by the same rule. The fork rule below counts only versions on a chain that resolves. No rule here compares a version's own `created_at` with a binding or a revocation.
- **A revoking client keeps its channels.** Before a client revokes a device it has replaced (a routine rotation), it SHOULD publish from a live device a supersede, with unchanged settings, of every channel whose last version that device signed, so that the revocation does not move those channels back one version. When the device may be in someone else's hands, the client MUST NOT re-sign the last version as it stands. It MUST show the user every version that device signed, on any branch; then publish from a live device a copy of each version after the genesis that the device signed on the path to the version the user confirms, so that each counts as signed with a live binding under the fork rule; then publish a supersede of the confirmed version. When that device's key is the channel's `founder_inbox_pubkey`, the client instead publishes from a live device a new genesis carrying the confirmed version's settings (below).
- **Versions published before 0.3.0 move to their own coordinate.** A client that reads a version without a `binding` tag, signed by a key it holds, SHOULD republish the same content at that version's 0.3.0 coordinate with its `t`, `s` and `binding` tags while a record still binds the key. The `descriptor_id` is unchanged, so the republished event is another copy of the same version (below).
- **A founder can re-sign a channel.** When no version of a channel verifies, or when the device whose key is `founder_inbox_pubkey` is revoked, the founder MAY publish a new genesis for the same `channel_id` from a bound device, carrying the channel's settings over. Posts are keyed by `channel_id` and stay. Reading it needs no new rule: the new genesis starts a chain, and the fork rule ranks it against the others.
- **At a fork, the founder's live branch wins.** When two or more versions on chains that resolve supersede the same parent, or are geneses of the same `channel_id`, each is ranked: first, a version the founder signed with a binding that is live; second, a version the founder signed with a binding since revoked; third, any other. Every branch through a version ranked below the best at that fork is overruled, however long it grows. A tip is a version that no version on a resolving chain supersedes, so a closed version that a re-open supersedes is not a tip. Among the tips left, a tip whose `status` is `"closed"` wins; then the longest chain; then the freshest `created_at` of the descriptor content, the signed field that every copy shares; then the lowest `descriptor_id`, compared as lowercase hex. Every reader that holds the same versions therefore picks the same tip. The first rank keeps the founder's decisions ahead of an admin's fork from an earlier version (such as one from before the founder removed that admin); the second keeps a founder key's earlier decisions ahead of an admin's fork after that key is revoked, and puts the founder's live device ahead of both.
- **A descriptor may arrive in several events; any authorized copy counts.** The signing key is in the event, outside `descriptor_id`, so the same descriptor can be carried by events under different keys. A resolver MUST keep every event that carries a given `descriptor_id` and MUST accept the descriptor if any one copy is authored as this section requires; a copy that fails MUST NOT void one that passes. The descriptor counts as founder-signed for the fork rule above if any authorized copy is the founder's, and as founder-signed with a live binding if any such copy's binding is live, and the `created_at` it competes with is that of an authorized copy, never an unauthorized one.
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

An admin/moderator removes a post by publishing a kind-30111 **removal tombstone** (`body:""`, a `removes` field naming the target `post_id`, signed by a roster moderator/admin). Removal is **forward-effective only** (S14/S15): conforming clients hide the target on sight of a valid tombstone, but copies already scraped/archived are not retracted. A tombstone by a non-roster signer is `E_CH_UNAUTHORIZED`. A post that carries `removes` is a tombstone whatever its `body`: a client writes `body:""`, and a reader MUST NOT refuse a removal for its body, which grants nothing; refusing it would leave the post up.

### 8.3.6 Composition with the directory (§8.2)

A channel with `directory_opt_in:true` MAY publish a kind-30114 listing whose `address` = `founder_address` and whose content carries the `slug` and the `channel_id` — so a channel is discoverable by handle under the *same* opt-in, claim-ordered (a claim anchored in Bitcoin and backed by a coin of `founder_address` that cleared the §8.2.2 floor at its anchor), tombstone-revocable directory rules as a person. Default invisible. The §8.2.3 social-graph firewall holds: a public channel reveals a NODE (the channel exists, its founder), never an edge set (public channels have no member roster).

**The handle→channel mapping is content-bound (NORMATIVE).** A channel listing MUST carry `slug`, and its `channel_id` MUST equal `SHA-256("oc-lock-chat-ch/v1:" || founder_address || ":" || lower(slug))` (the §8.3.1 channel-id derivation). A resolver MUST recompute this and **drop any opted-in listing whose `channel_id` is not so derived**. A tombstone (`opted_in: false`) points at no channel: it withdraws its founder's claim to the handle under §8.2.4 and §8.2.5, and a resolver MUST NOT drop it for its `slug`, `channel_id` or `title`, missing or otherwise. A client still writes them. Because the listing is signed by an inbox key device-bound to `founder_address`, a derivable `channel_id` can only ever point at a channel that *this* founder rooted — so a handle can never redirect to a channel its lister did not found. Without this bind, `channel_id` is a free field and the §8.2.2 gate would prove only that the *lister* is Bitcoin-real, not that they have any authority over the channel the handle resolves to (a handle-hijack). The binding is offline-self-proving: it needs only the listing event, not a second descriptor fetch.

**A directory handle is Bitcoin-gated; a `did:oc` founder cannot claim one (NORMATIVE).** The §8.3.1 descriptor permits a `did:oc`-only founder to open a public channel (its write tier just renders non-rooted), but the §8.2.2 anti-squat floor applies unchanged to the directory **handle**: a scarce `@handle` requires a claim backed by a coin of `founder_address` that cleared the floor at its anchor, which a `did:oc` identity has no analog for. So a `did:oc`-founded channel MUST NOT publish a kind-30114 listing, and a resolver MUST treat any listing whose `founder_address` is a `did:oc` as un-listed — exactly as §8.2.2 forbids a `did:oc` person from claiming a scarce handle. A conforming client surfaces this honestly (the channel is still fully usable and shareable by its `founder_address`+`slug` or `channel_id`) and prompts founding with a Bitcoin address to become handle-discoverable. The `channel_id` itself is bound to the *original* `founder_address` (§8.3.1), so a channel rooted at `did:oc` cannot graduate its existing handle by later attaching a Bitcoin address — it must be re-founded under that address.

**Separate handle namespace (NORMATIVE).** Channel listings use a **distinct d-tag namespace** from people listings (§8.2.1) so a channel handle can never collide with a person's: `d-tag = "oc-lock-chat-chdir:" || base64url(SHA-256("oc-lock-chat-chdir/v1:" || lower(handle)))` (people use `oc-lock-chat-dir:`). The listing is signed by the **founder inbox key** (`founder_inbox_pubkey`, bound to `founder_address` via kind-30078); a resolver honors it only if the event pubkey equals `founder_inbox_pubkey`, that key is device-bound to `founder_address`, and its claim (§8.2.1, with `address` = `founder_address`) passes §8.2.2 (3)–(4) — so only the founder can list a channel, and the same gate applies. Resolution follows §8.2.5 with `founder_address` as the owner: drop unanchored claims first, group by founder, order by anchor, a tombstone withdraws only its founder's claim, and the first founder whose claim stands holds the handle. This keeps the shared people-resolution path (§8.2.5) untouched.

### 8.3.7 Private channels (RESERVED — not v1)

`read:"members"` + an `encryption` block (`scheme ∈ {rewrap, sender-keys, mls}`) under the **same** kind-30110 descriptor enables private channels in a later phase, using the kind-30113 group-key rotation record (reserved, §10). The descriptor, roles, write gates, moderation, and governance chain are inherited unchanged; only an `encryption` block + the kind-30113 epoch machine are added. v1 does not implement this; the public-channel descriptor is forward-compatible by a flag, not a format break. The S9 member-to-member leak and forward-secrecy limits apply only to those phases (SECURITY S-CH-6/7).

### 8.3.8 Channel close (retire) — NORMATIVE

A founder MAY **close** (retire) a channel. Because a channel is content-addressed and its posts are public on relays the protocol does not control, **close is forward-effective only — it is NOT deletion** and a conforming client MUST NOT present it as erasure (S-CH-8, mirroring the §8.2.4 / S15 rule for directory tombstones). Close is a **descriptor revision**, not a new kind:

- **Mechanism.** Publish a kind-30110 supersede with `status:"closed"` (`supersedes` → the prior `descriptor_id`), at its own coordinate and inheriting the §8.3.1 governance chain. `status` is **OMITTED when active** (an active descriptor is byte-identical to a pre-`status` one — vc14/vc15 unaffected) and present only as `"closed"`. A client that resolves a `status:"closed"` descriptor MUST render the channel **read-only** (history visible, no composer) and SHOULD show the optional `successor_channel_id` as a **user-confirmed link** (never an auto-redirect; render its founder address + trust tier).
- **Among the branches the §8.3.1 ranking leaves, a fork never undoes a close.** A closed tip wins over every other tip that ranking leaves, so a close stands against an edit published beside it from another device or an outdated view. To re-open, the founder supersedes every closed tip; a close that arrives later closes the channel again until it is superseded too.
- **Authority (NORMATIVE).** The `status` transition (close OR re-open) and any change to `successor_channel_id` are **founder-only**. An admin-signed supersede that changes `status`, or whose `successor_channel_id` differs from its parent's, is `E_CH_UNAUTHORIZED` whatever the channel's status — closing a channel others rely on, or pointing its readers elsewhere, is exactly the governance coup §8.3.1 forbids. Re-open = a later founder-signed `status:"active"` (omit the field) supersede of every closed tip; the lifecycle is reversible and every transition is a signed, dated, auditable artifact.
- **Write gate.** A closed channel denies every new post with `E_CH_CLOSED`, but **still accepts removal tombstones** (§8.3.5) so moderation survives close. Already-propagated posts are unaffected.
- **On close.** A client SHOULD fire the §8.3.6 kind-30114 directory tombstone (`opted_in:false`) to pull the @handle from discovery, and MUST NOT request deletion ([NIP-09](https://nips.nostr.com/9)) of any descriptor version: a reader needs every version to walk the chain, and the close is itself a version.
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

## 8.6 Session devices (`did:oc`) — NORMATIVE

A `did:oc` identity (the ochk.io session bridge, no Bitcoin address) publishes a kind-30078 **session device record** under `d = "oc-chat:device:" || did_oc`, with tags `addr = did_oc`, `device_id`, `device_pk`, `auth = "session"`, an empty `binding_sig`, and a `vouch`. It has no BIP-322 signature, and its Nostr self-signature proves only that some key published it — so it is bound to its `did_oc` only by the **vouch** of the ochk.io auth host, the named trust anchor that authenticates `did:oc` sessions.

**Obtaining a vouch.** The device's authenticated session calls `POST https://ochk.io/api/chat/device-vouch` with `{ device_pk, nostr_pk, device_id, pop }`, where `pop` is a BIP-340 signature by the device's Nostr key over

```
SHA-256( "oc-chat:device-vouch-request:v1\n" || "did_oc: " || did_oc || "\n" || "device_pk: " || device_pk || "\n"
         || "nostr_pk: " || nostr_pk || "\n" || "device_id: " || device_id || "\n" )
```

and `did_oc` is the session's own. The host returns a compact JWS (`alg: "EdDSA"`, `typ: "oc-chat-device-vouch"`, `kid` from its JWKS) whose payload is the plain-text statement

```
"oc-chat:device-vouch:v1\n" || "did_oc: " || did_oc || "\n" || "device_pk: " || device_pk || "\n"
|| "nostr_pk: " || nostr_pk || "\n" || "device_id: " || device_id || "\n" || "issued_at: " || unix_seconds || "\n"
```

The payload is not a JSON claims set, so no session-token verifier can accept a vouch as a session.

**Verifying.** A resolver MUST bind a session record's `event.pubkey` to `did_oc` only when the event's Nostr signature verifies and its `vouch` verifies against a key published at `https://ochk.io/.well-known/jwks.json` with every statement field equal to the record's `did_oc`, `device_pk`, `event.pubkey` and `device_id`. A record without a valid vouch is unbound; a resolver that cannot load the host keys binds nothing. The auth host MUST keep every key it has signed vouches with in that JWKS after it rotates to a new one, marked `"status": "retired"` with its `retired_at` (unix seconds), so that a vouch a channel version carries (§8.3.1) still verifies. A retired key verifies only a vouch whose signed `issued_at` is before its `retired_at`. A key the host removes from the JWKS verifies nothing: every channel version vouched under it stops verifying, and its founder re-signs the channel (§8.3.1). Retirement is for routine rotation: a key that is or may be compromised MUST be removed from the JWKS, never marked retired, because its holder could sign a vouch dated before its `retired_at`.

**Revocation.** A session device is revoked in either of two ways. A resolver honours either on any relay, whichever Nostr key carried the record:

- **By its own key:** a record that key publishes at the same coordinate with `device_pk = "revoked"`. It retires that key's bind for that `device_id`.
- **By the auth host:** a kind-30078 record at `d = "oc-chat:device:" || did_oc` with tags `addr = did_oc`, `device_id`, `device_pk = "revoked"`, `auth = "session"` and `revocation`, with `created_at` equal to its `revoked_at`. Its content is the plain-text statement below, and its `revocation` tag is a compact JWS over those exact bytes (`alg: "EdDSA"`, `typ: "oc-chat-device-revoke"`, `kid` from the host's JWKS):

```
"oc-chat:device-revoke:v1\n" || "did_oc: " || did_oc || "\n" || "device_id: " || device_id || "\n"
|| "nostr_pk: " || nostr_pk || "\n" || "revoked_at: " || unix_seconds || "\n"
```

A host revocation counts when the JWS verifies against a key in the JWKS (a retired key only for a `revoked_at` before its `retired_at`), its statement equals the content, and its `did_oc` equals the d-tag's and `addr`. It retires every bind of that `did_oc` and `device_id` whose vouch's `issued_at` is at or before the latest such `revoked_at`. The device is the one the statement names: a resolver MUST NOT refuse a host revocation for its `device_id`, `device_pk` or `auth` tag. A resolver reads each named line of the statement by name, and refuses one that names a field twice; it MUST NOT refuse one for a line it does not know, so the host can add a line (a reason, say) without stopping revocations. The JWS covers every line either way. Both times are the host's own, so no time a device chose decides it. The host publishes each record under a fresh Nostr key, so that no record replaces another, and revokes only a device of the signed-in account's own `did_oc`, after a recent sign-in.

The host that vouches for a session device can also revoke it: it is the same named trust anchor. This is how a session device lost with its key is cut off. The host MUST NOT vouch again for a `did_oc` and `device_id`, or a `nostr_pk`, it has revoked: a device that comes back registers a new key, which the account's other devices can see. A device that reads a revocation of itself, its own or the host's, MUST NOT ask for a new vouch and SHOULD stop sending. A holder of a sign-in at the host can register a new device, so revoking a device MUST end, in the same step, the host sign-in that obtained that device's vouch, and a host that cannot tell which sign-in that was MUST end every other sign-in of the account; the host SHOULD offer to end the account's other sign-ins too.

**Trust posture (NORMATIVE honesty).** This tier is not offline-verifiable and not Bitcoin-load-bearing: a compromised auth host can vouch for any key under any `did:oc`, or revoke any session device. Clients render it as `session`, never `verified` (unless the step-up below resolves), and prompt attaching a Bitcoin address to graduate.

**Stepping up to a Bitcoin address (NORMATIVE).** A session device MAY also be bound to a Bitcoin address: an OC Lock device record (kind-30078, `d = "oc-lock:device:" || addr`) published under the same Nostr key `K`, binding `K` to `addr` as §0 states, by a BIP-322 signature over a v3 statement that signs `K`. A receiver that has authenticated a message under a session record (above), signed by `K`, SHOULD look up the kind-30078 records published by `K` (`{"kinds":[30078],"authors":[K]}`) and resolve every Bitcoin `addr` they name exactly as §0 resolves any address: the BIP-322 signature verifies, the record binds `K`, and no revocation seen on any relay retires the bind.

- If `K` is bound to such an address, the receiver MUST render the message as verified and name the address: "verified · `addr`". When more than one resolves, it names the lexicographically smallest.
- Otherwise it MUST render the message as `session`. A receiver MUST NOT step a message up on an address merely linked to the account at the auth host, on a binding of `addr` to a different key, or on a record whose binding does not resolve.
- The step-up does not change the sender. The message still comes from the `did:oc`, and the link between `K` and the `did:oc` still rests on the ochk.io auth host's vouch, the named trust anchor. What the step-up adds is offline-verifiable and Bitcoin-load-bearing: the holder of `addr` controls the key that signed the message.
- A receiver that records the key that signed each message MAY re-label messages it already holds from `K` once the step-up resolves. A revocation it sees later applies to messages it receives after; it need not re-label earlier ones.

Vector `vc18` covers a bound key and a revoked bind.

## 9. Errors

In addition to OC Lock SPEC §6 codes:

| Code | Meaning |
|---|---|
| `E_BLOCK_UNMET` | Seal release requested before `unlock_block + confirmations` confirmed. |
| `E_BEACON_UNAVAILABLE` | Seal beacon did not respond or could not be reached. |
| `E_NO_POSTAGE` | `pay-to-reach` envelope from a non-contact lacked valid postage for the recipient's floor. |
| `E_BAD_POSTAGE` | `SHA-256(preimage) != payment_hash`, or the `nonce`/`recipient`/`amount` binding did not match, or the invoice was not signed by one of the recipient's own nodes (§6.3). |
| `E_THREAD_GAP` | `parent_id` does not resolve to a held parent envelope id. |
| `E_QUEUE_ROUTE` | A durable-inbox deposit/drain referenced a `queue_id` the caller is not entitled to, or a malformed (non-base64url / wrong-length) queue id. |
| `E_DIR_UNVERIFIED` | No claim for the handle passes §8.2.2: an unanchored claim, a bad signature, `inbox_pubkey` not bound to `address` via a kind-30078 record, or a coin that did not clear the floor at the anchor. The handle resolves as un-listed. |
| `E_DIR_UNRESOLVED` | The read could not settle the handle (§8.2.5): a read for a claim before the holder got no answer, or the walk reached a bound. Not a verdict on any claimant; the client offers the address route. |
| `E_DIR_CONTESTED` | Retired in 0.4: handles are ordered by anchor (§8.2.5), so two holders cannot tie one up. A 0.4 resolver never returns it. |
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
| 30110 | **channel descriptor** (addressable, one coordinate per version) | `oc-lock-chat-ch:` | §8.3.1. Governance hash-chain; d-tag `oc-lock-chat-ch:` ‖ `descriptor_id`, `t` = `channel_id`, `s` = `supersedes`. The salted legacy d-tag (`oc-lock-chat-ch/v1:`) is read, never written. |
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
- [ ] If it offers durable store-and-forward, derives `queue_id`/`bootstrap_id` per §8.1, routes the inbox solely on those opaque ids (no address/device-pubkey index), stores the blob byte-for-byte, gates a proven bootstrap queue on §8.1.5 proofs, and reproduces vectors `vc06` and `vc21`.
- [ ] If it offers the directory (§8.2), publishes a kind-30114 listing ONLY on explicit opt-in (default invisible), derives the salted-handle `d`-tag (vector `vc07`), orders claims by anchor and refuses to resolve a handle to a claim unless the §8.2.2 gate passes (signature + kind-30078 binding + a coin that cleared the floor at the anchor + an anchor with 6 confirmations), stops with `E_DIR_UNRESOLVED` rather than pass over a claim whose read got no answer (§8.2.5), reads directory relays completely and runs the public audit (§8.2.6), anchors before publishing (§8.2.7), enforces the §8.2.3 social-graph firewall, honors tombstones (vector `vc08`), and never exposes a bulk-dump endpoint (vectors `vc22`–`vc24`).
- [ ] For `pay-to-reach` (§6): carries `postage` in the `ChatBody` (§6.2), and on receive runs the full §6.3 verification — re-derives the description-hash binding `SHA-256(lnurl_metadata‖payerdata)` ITSELF over verbatim bytes, checks `SHA-256(preimage)==payment_hash` + amount + expiry + identifier + the local spent-ledger — routing a failing/replayed message to the filtered/pending state (delivered, never dropped), and NEVER claims transferable third-party proof.
- [ ] Wraps to the beacon and performs release re-wrap as a detached `recipients[]` merge for `seal-til-block` (§7), and NEVER labels a v0 beacon seal "trustless".
- [ ] Surfaces every trust anchor (beacon id/url, relay, redundant beacon) and the early-release / brick risks at compose time.
- [ ] Operates no OC payment rail for postage (§6.4).
- [ ] If it offers public channels (§8.3): publishes a founder-rooted kind-30110 descriptor with exactly one `write.policy` and a matching `rooted` flag (`E_CH_POLICY_INVALID` otherwise); publishes each version with its `t` and `s` tags; fetches every descriptor version by `#t` (plus the legacy d-tag), reads the founder's and admins' keys, revoked ones included, one key per read, walks forward by `#s` only from versions those reads returned, reports a read cut off at its bound as not read unless those reads were complete, and validates the governance hash-chain over them (`supersedes` + prior-epoch admin signature, any authorized copy of a `descriptor_id` counting, `status` and `successor_channel_id` changed by the founder only) and picks the tip as §8.3.1 orders it (a closed tip, the longest chain, the freshest signed `created_at`, the lowest `descriptor_id`); carries a `binding` tag on every version it publishes, authorizes earlier versions by their binding and the last version only while its binding is live; re-signs before revoking a device; rejects a `chat-channel` post with non-empty `recipients[]` (`E_CHANNEL_RECIPIENTS`); on `utxo-floor`, verifies the height-anchored `write_proof` against public chain data — the `outpoint` is unspent, owned by the UTXO address, and carries the exact `value_sats`/height/hash claimed — deduped per-outpoint (not per-post) and fail-closed; renders a non-rooted channel (`allowlist`/`founder`/`open`) in the muted "via ochk.io" tier; honors removal tombstones (forward-effective only); and reproduces vectors `vc14`–`vc17`, `vc19` and `vc20`.
- [ ] If it supports an `auth-required` relay (§8.4): completes the kind-22242 NIP-42 handshake before publish/subscribe (`E_RELAY_AUTH_REQUIRED` otherwise), signs the challenge with a fresh per-connection ephemeral key by default (or a configured `auth_key`), surfaces the AUTH relay as a named trust anchor, and NEVER presents AUTH as making a relay trustless.
- [ ] If it offers source-intake (§8.5): warns the source at submission time that the intake post is public + permanent (only the org's reply is E2EE), defaults the source to a fresh throwaway identity, and never claims SecureDrop-grade anonymity for the inbound leg (S-M7-2).
- [ ] If it offers a named-Fedimint postage fallback (§6.5): surfaces the federation as a named plaintext custodian before the sender pays, lets the sender decline a federation-fronted endpoint, keeps OC out of custody (the federation settles), and does not enable the path absent a money-transmitter analysis (`E_FEDIMINT_*`).
- [ ] If it accepts `did:oc` session devices (§8.6): binds a session record only through a vouch that verifies against the ochk.io JWKS, renders it as `session`, steps a message up to "verified · `addr`" only when §0 resolution binds the signing key to `addr` (vector `vc18`), and never asks for a new vouch for a device it has read a revocation of.
- [ ] Emits §9 + OC Lock §6 error codes.

## 12. Security model

See [`SECURITY.md`](./SECURITY.md). In brief, OC Chat inherits OC Lock's guarantees (authenticity, confidentiality, identity binding) and gaps (no per-message forward secrecy, plaintext envelope metadata, no delivery guarantee) and adds: a beacon-trust posture for seals (not offline-verifiable in v0), a seal-existence metadata leak, and an offline-verifiable Lightning postage proof.

## 13. Versioning

OC Chat versions with OC Lock's `envelope.v` (currently 2). New `kind` values and new optional blocks (`postage`, `seal` sub-fields) are additive; clients MUST preserve unknown fields when relaying and MAY ignore them when decrypting. Incompatible changes increment `envelope.v`.

## 14. IANA / external identifiers

- Nostr kinds: **30110** (channel descriptor, §8.3.1), **30111** (channel post, §8.3.2), **30112** (seal), **30114** (directory, §8.2), addressable, d-tag namespace `oc-lock-chat-*` claimed by this spec; **30113** reserved (group-key rotation, private channels §8.3.7), **30115** reserved (`pay-to-post`, §8.3.3); transport reuses kind-1059 (NIP-59).
- Gift-wrap content tag: `ct = "oc-chat/v2"` (encrypted wrap, §8 normative). `"oc-chat/v1"` (plain base64) is legacy — accepted on receive only, never published.
- Directory d-tag salt label: `"oc-lock-chat-dir/v1:"`. Channel descriptor d-tag: `"oc-lock-chat-ch:" || descriptor_id`; the salt label `"oc-lock-chat-ch/v1:"` derives the legacy d-tag, which readers still fetch.

## 15. Acknowledgements

OC Chat extends [OC Lock](https://github.com/orangecheck/oc-lock-protocol) and the OrangeCheck identity primitive. The "Bitcoin as identity, not access oracle" framing — which is why the daily messenger leans on BIP-322 identity rather than a chain transaction in the send path — is owed to [Bram Kanstein](https://bramk.substack.com/). See OC Lock `WHY.md`.
