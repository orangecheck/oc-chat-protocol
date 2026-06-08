# OC Chat test vectors

Fixed inputs, fixed outputs. Any conforming OC Chat implementation MUST produce byte-identical results. OC Chat reuses the OC Lock v2 envelope crypto verbatim (X25519 + HKDF-SHA256 + AES-256-GCM, RFC 8785 canonicalization), so these vectors were generated with the same `@orangecheck/lock-crypto` primitives and the `@orangecheck/lock-core` canonicalizer. The generator self-checks by reproducing the `id` of every `oc-lock-protocol/test-vectors/*.json` fixture before emitting these — if the canonicalizer drifts, generation aborts.

## The one rule that differs from OC Lock

For OC Chat envelopes (`kind="chat"` and `kind="chat-seal"`), the content-addressed `id` **and** the AEAD AAD **exclude the entire `recipients[]` array** (see [SPEC §3](../SPEC.md)). In base OC Lock, `recipients[]` is inside the signed `id` and the AAD; in OC Chat it is mutable delivery routing, not content. This is what lets a `seal-til-block` beacon (or a payment-mode relay) **re-wrap** the content key for a new recipient after release **without** breaking the `id`, the sender's BIP-322 signature, or the ciphertext GCM tag.

## Vectors

| File | Exercises |
|---|---|
| `vc01-speak-now.json` | `kind=chat` single recipient; threading (`conversation_id`/`seq`/`parent_id`) carried INSIDE the encrypted payload. Round-trips. |
| `vc02-multi-device.json` | One `content_key` fanned out to two device keys of the same Bitcoin address. |
| `vc03-seal-til-block.json` | `kind=chat-seal`; `content_key` wrapped to a NAMED beacon; `seal{}` predicate committed in the `id`. |
| `vc04-seal-rewrap-stability.json` | **CRITICAL.** Post-release re-wrap (beacon → recipient) preserves `id` (`id_after == id_before`) AND the ciphertext GCM tag still authenticates. Proves the recipient-exclusion rule. |
| `vc05-pay-to-reach.json` | `kind=chat` + `postage{}` with a real Lightning preimage; `sha256(preimage) == payment_hash` verifies OFFLINE; `payment_hash`/`nonce`/`amount` committed in the `id` (replay-binding). |
| `vc06-inbox-queue-id.json` | Durable-inbox routing (SPEC §8.1): `queue_seed = HKDF(device_sk)`, `queue_id = base64url(HMAC(queue_seed, conversation_id))`, plus the derivable `bootstrap_id`. Proves two conversations on one device yield UNLINKABLE opaque queue ids — the operator sees N queues, never a recipient. |
| `vc07-directory-dtag.json` | Directory listing d-tag (SPEC §8.2.1): `d-tag = "oc-lock-chat-dir:" + base64url(SHA-256("oc-lock-chat-dir/v1:" + lower(handle)))`. Salted-handle hash → lookup-by-known-handle, never enumerate-all. |
| `vc08-directory-listing.json` | Directory listing content-addressing + tombstone (SPEC §8.2.1/§8.2.4): `listing_id = SHA-256(canonical(content))`; the tombstone (`opted_in:false`) shares the d-tag and supersedes the listing with a distinct id. |

## Conformance

Given a vector's `inputs`, a compliant implementation MUST:

1. Wrap `content_key` per recipient exactly as in OC Lock SPEC §4.2.
2. Compute the AAD as `SHA-256(canonical(envelope | id="", ciphertext="", sig.value="", recipients=[]))` for chat kinds.
3. Compute `id` as `SHA-256(canonical(envelope | id="", sig.value="", recipients=[]))` for chat kinds.
4. Reproduce `expected.id` (and for `vc04`, `id_after == id_before` with `ciphertext_tag_verifies == true`).
5. For `vc05`, verify `SHA-256(preimage) == payment_hash`.
6. For `vc06`, derive `queue_seed`/`queue_id`/`bootstrap_id` per SPEC §8.1 and reproduce `expected`, including `queue_id != queue_id_2` (unlinkability).

Canonicalization is RFC 8785 plus the OC Lock constraint that `recipients[]` (when present in the canonical form) is sorted by `device_id` ascending — irrelevant to the chat `id`, which excludes `recipients[]`, but preserved for wire interop.
