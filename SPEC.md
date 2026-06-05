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
  "parent_id": "<chat_envelope_id of the parent message, or null for the first>"
}
```

- `conversation_id` is a stable label. The RECOMMENDED default is `SHA-256` of the two Bitcoin addresses sorted ascending and joined with `:` — a deterministic 1:1 thread id requiring no negotiation.
- **`parent_id` MUST equal the `chat_envelope_id` of the message it replies to** (or `null` for the first in a thread). This makes each thread a verifiable hash-chain: a client MUST order and validate by the `parent_id` chain, and MUST NOT trust `created_at` (which is plaintext and untrusted) for ordering. A missing parent is a detectable gap.

This gives per-thread tamper-evidence. It is NOT a transport-layer anti-replay or anti-reorder guarantee: a relay can still withhold or delay delivery (§SECURITY).

## 6. Postage (anti-spam)

### 6.1 Recipient policy
A recipient MAY publish a postage policy (out of band, e.g. in their profile / device-record metadata): a `floor_sats` and a Lightning receiving endpoint — a BOLT12 offer (RECOMMENDED) or a BOLT11/LNURL-pay fallback — resolving to a wallet or gateway the **recipient** controls. No OC service mints or proxies this invoice.

### 6.2 Sender postage block
A `pay-to-reach` envelope carries:

```json
"postage": {
  "floor_sats":  <integer>,
  "amount_sats": <integer, >= floor_sats>,
  "payment_hash":"<64-char hex>",
  "preimage":    "<64-char hex>",
  "nonce":       "<hex, the per-DM nonce committed by the recipient endpoint>",
  "recipient":   "<recipient btc address>"
}
```

### 6.3 Verification (offline)
A recipient (or any observer) MUST verify `SHA-256(preimage) == payment_hash`. Because `postage` is part of the `chat_envelope_id` (§3), `payment_hash`, `nonce`, `amount_sats`, and `recipient` are committed by the sender's signature and cannot be altered. The `nonce` MUST be one the recipient's endpoint minted for THIS payment (binding the preimage to `recipient + amount + nonce`), so a preimage cannot be replayed as proof of payment to a third party.

> **Open normative item (blocking `pay-to-reach`):** how a recipient endpoint mints a per-DM invoice bound to `nonce` when the sender is a stranger and OC is out of the invoice path. BOLT12 `invoice_request` may not carry the nonce; a recipient-published nonce-commitment step is the likely construction. Until specified, a deployment MUST treat the preimage as proof-of-settlement only, NOT as non-replayable third-party proof. See WHY.md H9 and SECURITY.md S7.

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

## 8. Transport

OC Chat uses OC Lock's gift-wrap unchanged: the canonical chat envelope is the opaque inner blob of a NIP-59 gift-wrap (Nostr kind-1059) signed by an ephemeral, discarded Schnorr key, `created_at` rounded to the minute, with the recipient inbox pubkey in the `p` tag and an advisory `ct` tag `oc-chat/v1`. The recipient's chat inbox pubkey is `HKDF(device_sk)` (so publishing a device record IS creating an inbox; no second ceremony). A relay sees an ephemeral pubkey, an inbox pubkey, and an opaque blob — no sender, no real timestamp, no content. Durable delivery (store-and-forward beyond relay retention) is an implementation concern, not protocol; see PROTOCOL.md.

## 9. Errors

In addition to OC Lock SPEC §6 codes:

| Code | Meaning |
|---|---|
| `E_BLOCK_UNMET` | Seal release requested before `unlock_block + confirmations` confirmed. |
| `E_BEACON_UNAVAILABLE` | Seal beacon did not respond or could not be reached. |
| `E_NO_POSTAGE` | `pay-to-reach` envelope from a non-contact lacked valid postage for the recipient's floor. |
| `E_BAD_POSTAGE` | `SHA-256(preimage) != payment_hash`, or the `nonce`/`recipient`/`amount` binding did not match. |
| `E_THREAD_GAP` | `parent_id` does not resolve to a held parent envelope id. |

## 10. Nostr kind registry

OC Chat claims a fresh block above OC Find's (unratified) 30094–30109 reservation. d-tags are **verb-rooted** (`oc-lock-chat-*`) because chat is a mode of the lock verb, not a brand of its own.

| Kind | Object | `d`-tag prefix | Notes |
|---|---|---|---|
| 30110 | thread / channel descriptor (addressable, NIP-33-replaceable) | `oc-lock-chat-ch:` | one active descriptor per `conversation_id`. |
| 30111 | message envelope (when published addressably rather than gift-wrapped) | `oc-lock-chat-msg:` | gift-wrap (kind-1059) is the default DM transport; 30111 is for public/channel posts. |
| 30112 | seal / block-height anchor descriptor | `oc-lock-chat-seal:` | references the sealed envelope id + `unlock_block` + beacon. |
| 30113–30115 | reserved (group-key rotation, mailbox index, postage-policy record) | `oc-lock-chat-*:` | registry extensions; not canonical v0. |

The transport gift-wrap remains Nostr kind-1059 (NIP-59, not an OC-allocated kind). Device records remain kind-30078 (OC Lock SPEC §11). Allocating these required widening the family range past 30099; the workspace `KINDS.md` and `oc-agent-protocol/SPEC.md §4` are the rolled-up source of truth.

## 11. Compliance checklist

A client is OC Chat v0 compliant iff it:

- [ ] Reuses OC Lock §4.2 wrapping verbatim for `content_key`.
- [ ] Computes `chat_aad` and `chat_envelope_id` with `recipients=[]` for `kind ∈ {chat, chat-seal}` (§3) and reproduces the test vectors.
- [ ] Carries `conversation_id`/`seq`/`parent_id` inside the encrypted payload and orders by the `parent_id` hash-chain, never by `created_at` (§5).
- [ ] Verifies `SHA-256(preimage) == payment_hash` and the `nonce`/`recipient`/`amount` binding for `pay-to-reach` (§6).
- [ ] Wraps to the beacon and performs release re-wrap as a detached `recipients[]` merge for `seal-til-block` (§7), and NEVER labels a v0 beacon seal "trustless".
- [ ] Surfaces every trust anchor (beacon id/url, relay, redundant beacon) and the early-release / brick risks at compose time.
- [ ] Operates no OC payment rail for postage (§6.4).
- [ ] Emits §9 + OC Lock §6 error codes.

## 12. Security model

See [`SECURITY.md`](./SECURITY.md). In brief, OC Chat inherits OC Lock's guarantees (authenticity, confidentiality, identity binding) and gaps (no per-message forward secrecy, plaintext envelope metadata, no delivery guarantee) and adds: a beacon-trust posture for seals (not offline-verifiable in v0), a seal-existence metadata leak, and an offline-verifiable Lightning postage proof.

## 13. Versioning

OC Chat versions with OC Lock's `envelope.v` (currently 2). New `kind` values and new optional blocks (`postage`, `seal` sub-fields) are additive; clients MUST preserve unknown fields when relaying and MAY ignore them when decrypting. Incompatible changes increment `envelope.v`.

## 14. IANA / external identifiers

- Nostr kinds: **30110–30112** (addressable), d-tag namespace `oc-lock-chat-*` claimed by this spec; transport reuses kind-1059 (NIP-59).
- Advisory gift-wrap content tag: `ct = "oc-chat/v1"`.

## 15. Acknowledgements

OC Chat extends [OC Lock](https://github.com/orangecheck/oc-lock-protocol) and the OrangeCheck identity primitive. The "Bitcoin as identity, not access oracle" framing — which is why the daily messenger leans on BIP-322 identity rather than a chain transaction in the send path — is owed to [Bram Kanstein](https://bramk.substack.com/). See OC Lock `WHY.md`.
