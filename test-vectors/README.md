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
| `vc09-postage-binding.json` | pay-to-reach postage verification (SPEC §6.3): `payment_hash = SHA-256(preimage)`, the LUD-18 binding `description_hash = SHA-256(metadata‖payerdata)` re-derived over verbatim bytes, and the spent-ledger replay branch (valid→inbox, replayed→Requests). |
| `vc10-round-for-block.json` | seal-til-block v0 round derivation (SPEC §7.6): the drand quicknet round for a target block from genesis + period. |
| `vc11-tlock-body-roundtrip.json` | seal-til-block v0 body-lock (SPEC §7.6): AES-256-GCM body seal under the reveal secret `R`, round-trip. |
| `vc12-tlock-elapsed-round-decrypt.json` | seal-til-block v0 timelock (SPEC §7.6), captured LIVE against drand quicknet: tlock-decrypt of an elapsed round. |
| `vc13-seal-id-stability.json` | seal-til-block v0 tamper-evidence (SPEC §7.6): the in-ciphertext seal block is committed by the content-addressed id. |
| `vc14-channel-descriptor.json` | Channel descriptor identity (SPEC §8.3.1): `channel_id = SHA-256('oc-lock-chat-ch/v1:'‖founder‖':'‖slug)`, the d-tag, and `descriptor_id = SHA-256(canonical(content))`; asserts the `utxo-floor ⇒ rooted:true` policy match. |
| `vc15-channel-governance.json` | Channel governance hash-chain (SPEC §8.3.1): a superseding descriptor (`supersedes` → prior `descriptor_id`) is a distinct content-addressed artifact at the SAME d-tag. |
| `vc16-channel-post.json` | Public channel post content-addressing + recipient-exclusion (SPEC §8.3.2/§3): `post_id = SHA-256(canonical(content))`, the post d-tag, and the `E_CHANNEL_RECIPIENTS` rule for a non-empty `recipients[]`. |
| `vc17-channel-utxo-write-proof.json` | Height-anchored UTXO write-proof arithmetic (SPEC §8.3.3): the offline age gate `tip - anchor + 1 >= confs` for a clearing proof and below-floor (age + value) rejections → `E_CHAN_FLOOR`. |

## Conformance

Given a vector's `inputs`, a compliant implementation MUST:

1. Wrap `content_key` per recipient exactly as in OC Lock SPEC §4.2.
2. Compute the AAD as `SHA-256(canonical(envelope | id="", ciphertext="", sig.value="", recipients=[]))` for chat kinds.
3. Compute `id` as `SHA-256(canonical(envelope | id="", sig.value="", recipients=[]))` for chat kinds.
4. Reproduce `expected.id` (and for `vc04`, `id_after == id_before` with `ciphertext_tag_verifies == true`).
5. For `vc05`, verify `SHA-256(preimage) == payment_hash`.
6. For `vc06`, derive `queue_seed`/`queue_id`/`bootstrap_id` per SPEC §8.1 and reproduce `expected`, including `queue_id != queue_id_2` (unlinkability).
7. For `vc14`–`vc17` (channels §8.3), compute `channel_id`/`descriptor_id`/`post_id` as `SHA-256(canonical(content))` with the §0 canonicalization (sorted-key compact + trailing LF), derive the `oc-lock-chat-ch:`/`oc-lock-chat-msg:` d-tags via the salted-hash rule, and reproduce the `utxo-floor` age arithmetic `tip − anchor + 1 ≥ confs`.

Canonicalization is RFC 8785 plus the OC Lock constraint that `recipients[]` (when present in the canonical form) is sorted by `device_id` ascending — irrelevant to the chat `id`, which excludes `recipients[]`, but preserved for wire interop.

## Whether a `canonical` field carries its trailing LF — it varies

Canonical form is always LF-terminated (§0). Whether the **stored string** in
these files includes that byte is not uniform, so check before you hash:

| field | in these files | therefore |
| --- | --- | --- |
| `canonical` (vc01, the only envelope vector that stores one) | **includes** the `\n` | `id == SHA-256(canonical)` |
| `listing_canonical`, `descriptor_canonical`, `post_canonical` (vc08, vc14, vc16) | **omits** the `\n` | `id == SHA-256(canonical + "\n")` |

Worth stating plainly because the mistake is silent either way: hashing with
the wrong number of trailing bytes yields a well-formed 64-hex digest that
simply is not the `id`, with nothing pointing at the missing or extra byte.

For cross-protocol work: `oc-vote-protocol` stores `poll_canonical` /
`reveal_canonical` **with** the LF, like the envelope layer here. Every
protocol canonicalizes identically — LF-terminated, per §0, `lock-core`'s and
`vote-core`'s `canonicalBytes` — so this is presentation only, never a
canonicalization difference.

## Known divergence: the shipped `lock-core` does not apply §3's recipient rule

`vc01`–`vc05` cannot currently be round-tripped through
`@orangecheck/lock-core` (1.0.x). Recording it here because a conformance
vector that fails for a known reason is information, and one that fails
silently is rot.

§3 computes a chat envelope's id with `recipients` **emptied**:

```
id = SHA-256(canonical(envelope | id="", sig.value="", recipients=[]))
```

`vc01`'s `canonical` shows exactly that — `"recipients":[]` — while the
envelope it describes carries one recipient. lock-core's `computeEnvelopeId`
blanks only `id` and `sig.value` and leaves `recipients` populated, so it
derives a different id for the same envelope and `unseal()` rejects this
vector with `LockError: envelope id mismatch`.

**Nothing is broken for users today.** `oc-chat-web` seals and unseals through
the same lock-core, so its ids are self-consistent, and the re-wrap path that
recipient-exclusion exists to protect (`vc04`) is not implemented —
seal-til-block releases by the recipient decrypting locally via tlock, and
nobody re-wraps.

**Interop is broken, which is what these vectors are for.** A second
implementation following §3 would reject every envelope OC Chat sends, and OC
Chat would reject every envelope it receives. Resolving it means changing
either §3 or lock-core's id rule; the latter changes the id of every message
ever sent, so it is a deliberate decision about a published package and a wire
format rather than a quiet patch.
