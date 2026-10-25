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
| `vc14-channel-descriptor.json` | Channel descriptor identity (SPEC §8.3.1): `channel_id = SHA-256('oc-lock-chat-ch/v1:'‖founder‖':'‖slug)`, the version d-tag and `t` tag, the legacy d-tag readers still fetch, and `descriptor_id = SHA-256(canonical(content))`; asserts the `utxo-floor ⇒ rooted:true` policy match. |
| `vc15-channel-governance.json` | Channel governance hash-chain (SPEC §8.3.1): a superseding descriptor (`supersedes` → prior `descriptor_id`) is a distinct content-addressed artifact at its own d-tag (`oc-lock-chat-ch:` ‖ `descriptor_id`), and both versions carry `t` = `channel_id`. |
| `vc16-channel-post.json` | Public channel post content-addressing + recipient-exclusion (SPEC §8.3.2/§3): `post_id = SHA-256(canonical(content))`, the post d-tag, and the `E_CHANNEL_RECIPIENTS` rule for a non-empty `recipients[]`. |
| `vc17-channel-utxo-write-proof.json` | Height-anchored UTXO write-proof arithmetic (SPEC §8.3.3): the offline age gate `tip - anchor + 1 >= confs` for a clearing proof and below-floor (age + value) rejections → `E_CHAN_FLOOR`. |
| `vc18-session-step-up.json` | A `did:oc` session message steps up (SPEC §8.6): records published by the signing key name a Bitcoin address, §0 resolution binds the key to it, so the message reads "verified · address"; the same bind retired by a BIP-322 revocation stays `session`. |
| `vc19-channel-version-coordinates.json` | Per-version coordinates (SPEC §8.3.1, 0.3.0): each version at `d = "oc-lock-chat-ch:" ‖ descriptor_id` with `t = channel_id`; which versions the `#t` filter and the legacy `#d` filter return; the exact-d-tag fetch for a version a `supersedes` names that no page returned; that a relay keeping the newest event per coordinate keeps every version; and, under 7,500 newer junk events, the per-key reads (every key the founder and admins have bound, revoked ones included) that still find an admin's versions, one of them signed with a key the admin has since revoked, the versions the reader walks forward from, and the not-read answer a reader without the founder gives. |
| `vc20-channel-version-binding.json` | Version bindings, the fork rank and session-device revocation (SPEC §8.3.1, §8.6, 0.3.0), with real BIP-322, Schnorr and Ed25519 signatures: an admin's self-revocation does not undo its edit or what follows; a revoked key's own last version falls back; a stolen key's version counts until the key is revoked, a live key's successor keeps it in the chain, and the founder's fork from a live device then outranks it; a thief's longer fork from the genesis wins until a live device copies the versions the stolen key signed; a thief's own genesis wins until the inbox key is revoked, after which the founder's new genesis outranks it; an unverifiable channel is re-signed with a new genesis; a did:oc vouch under a retired host key verifies only if issued before the key retired, survives its device's own revocation, and fails if the host drops the key; a version from a stolen session device fails once the host revokes that device, and a vouch the host issues after that revocation binds the device again; and the tip order at a fork (0.3.2): a closed tip beats a later edit and a longer branch, a re-open's supersede means the close is no longer a tip, the later signed `created_at` wins whatever the events' `created_at` says, equal signed `created_at` falls to the lowest `descriptor_id`, a close on a branch through a revoked founder key loses to the live founder key, and of two closes with one re-opened the other still wins; and the founder-only successor (0.3.2): an admin's supersede that changes `successor_channel_id`, of a closed channel or an active one, is unauthorized, so a close built on it does not resolve. |
| `vc21-inbox-bootstrap-proof.json` | Bootstrap inbox proof (SPEC §8.1.5, 0.3.5): a BIP-340 signature by the inbox key over the action, the `bootstrap_id` it derives and `ts`; the drain and ack messages, digests and signatures, the ack's digest of its envelope ids; a drain proof does not verify as an ack, nor an ack for other ids; the 600-second window. |
| `vc22-directory-claim-id.json` | Directory claim id (SPEC §8.2.1, 0.4.0): `claim_id = SHA-256(canonical({v:1, handle, address, outpoint, nonce}))`; the same outpoint and nonce in a listing for another address give another id; the legacy form with `nonce` = a v1 `listing_id` (§8.2.8); a channel listing's claim with `address` = `founder_address` and its `channel_id` (§8.3.6). |
| `vc23-directory-claim-anchor.json` | A claim's anchor (SPEC §8.2.1, 0.4.0): a bare OpenTimestamps proof over `claim_id` with two Bitcoin attestations and synthetic headers; the anchor is the lowest attestation whose header has the attested Merkle root; a mismatching header is passed over; a proof over another digest anchors nothing; 5 confirmations is unanchored, 6 anchored, also for the higher attestation when the lower one's header mismatches. |
| `vc24-directory-resolution.json` | Directory resolution (SPEC §8.2.5-§8.2.6, 0.4.0) over checked facts, binding first: each record's signing key and each address's binding read. Cases: a later funded claimant ignored; unanchored claims cost no read; a spend releases a handle at `dir_repoint_blocks + 6` confirmations and not one fewer; coins at anchor-144 pass and at anchor-143 fail; a binding, header or coin read without an answer before the holder is `E_DIR_UNRESOLVED`, and for an audit claim ends the audit; a same-block tie; a tombstone by a bound key ends a claim for good, even when the same claim is listed again; a tombstone, a newer listing or an earlier-anchored listing under an unbound key changes nothing; the public audit finding a withheld earlier claim, an audit it cannot finish leaving the directory answer, and no audit claim holding after a directory walk stops unresolved; the legacy entry; 65 failing claims before the holder reach the coin-read bound, and after it are never read; 65 claims under unbound keys before the holder cost binding reads only, and 257 distinct addresses reach the binding-read bound. |
| `vc25-directory-repoints.json` | Re-points (SPEC §8.2.9, 0.4.0): `repoint_id = SHA-256(canonical({v:1, claim, prev, outpoint, nonce}))`, which differs for another claim. Cases on the vc24 walk: a re-point in time keeps the handle; a late one loses it; one carried only under a key not bound to the address is ignored; one too early for its coin ends the chain where it stands; the claim stands inside the window with no re-point yet; a chain of two; no re-point rescues a coin that failed the floor at the claim's anchor; a re-point made before the spend; no answer for a re-point's coin or its anchor's header is `E_DIR_UNRESOLVED`; a coin of another address is invalid; links after a failed one cost no read; a list that does not chain, and one of 17, are dropped before any read. |

## Conformance

Given a vector's `inputs`, a compliant implementation MUST:

1. Wrap `content_key` per recipient exactly as in OC Lock SPEC §4.2.
2. Compute the AAD as `SHA-256(canonical(envelope | id="", ciphertext="", sig.value="", recipients=[]))` for chat kinds.
3. Compute `id` as `SHA-256(canonical(envelope | id="", sig.value="", recipients=[]))` for chat kinds.
4. Reproduce `expected.id` (and for `vc04`, `id_after == id_before` with `ciphertext_tag_verifies == true`).
5. For `vc05`, verify `SHA-256(preimage) == payment_hash`.
6. For `vc06`, derive `queue_seed`/`queue_id`/`bootstrap_id` per SPEC §8.1 and reproduce `expected`, including `queue_id != queue_id_2` (unlinkability).
7. For `vc14`–`vc17` (channels §8.3), compute `channel_id`/`descriptor_id`/`post_id` as `SHA-256(canonical(content))` with the §0 canonicalization (sorted-key compact + trailing LF), derive the `oc-lock-chat-ch:`/`oc-lock-chat-msg:` d-tags via the salted-hash rule, and reproduce the `utxo-floor` age arithmetic `tip − anchor + 1 ≥ confs`.
8. For `vc18` (session step-up, §8.6), for each case serve `records_by_author` to the `authors` lookup and `records_by_address` to the address lookup, resolve the address as §0 does (BIP-322, v3 binding of the signing key, revocations), and reproduce `expected.display` and, when verified, `expected.address`.

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

## Why some vectors do not round-trip through the shipped client

These vectors cover the **upgrade target**, not the v0 wire, and that is by
design rather than drift. SPEC §7.6 — "v0 in-ciphertext drand-tlock profile —
NORMATIVE (what ships)" — states it directly: §7.2–7.3 need an
`@orangecheck/lock-core` change, `lock-core@1.0.1` exposes only
`EnvelopeKind = 'identity' | 'payment'`, and that path is "the named **upgrade
target** (vectors `vc03`/`vc04`), NOT what v0 deploys".

An earlier version of this note (mine) called it a "known divergence" and read
as though the client were non-conformant. It is not: it conforms to §7.6. §2
and §3 now carry a v0 signpost so the next reader does not repeat that.

The mechanical detail is still worth having written down. `oc-chat-web`'s send path calls
`@orangecheck/lock-core`'s `seal()` **without a `kind`**, so lock-core applies
its default and the envelope goes out as `kind: "identity"`, marked only by
`hint: "oc-chat/v1"`. lock-core's `EnvelopeKind` is `'identity' | 'payment'`;
it does not model `chat` or `chat-seal` at all, and all four of
`oc-lock-protocol`'s own vectors are `identity` — they pass, so lock-core is
correct for what it models. OC Chat's two kinds and its recipient-excluding id rule are the upgrade
target; §7.6 is what v0 deploys. The recipient-exclusion rule exists solely to
let a held envelope be re-keyed (§7.3), and the v0 seal never re-keys anything
— the reveal secret is timelock-encrypted to a drand round and rides inside the
ciphertext, so there is nothing to re-wrap.

| | upgrade target (vc01, vc03) | v0 profile — what ships (§7.6) |
|---|---|---|
| `kind` | `"chat"` / `"chat-seal"` | `"identity"` |
| id | `recipients` emptied before hashing | `recipients` left populated |
| marker | the `kind` field | `hint: "oc-chat/v1"` |

So `unseal()` rejects `vc01` with `LockError: envelope id mismatch`:
`vc01`'s `canonical` shows `"recipients":[]` while the envelope carries one,
and lock-core's `computeEnvelopeId` blanks only `id` and `sig.value`.

**Nothing is broken for users today.** `oc-chat-web` seals and unseals through
the same lock-core, so its ids are self-consistent, and the re-wrap path that
recipient-exclusion exists to protect (`vc04`) is not implemented —
seal-til-block releases by the recipient decrypting locally via tlock, and
nobody re-wraps. No code reads `kind` to decide anything.

**Interop is what breaks, which is what these vectors are for.** A second
implementation built from this spec would reject every envelope OC Chat sends
and send envelopes OC Chat rejects. Closing it means either implementing the
chat kinds and the recipient-excluding id in lock-core — which changes the id
of every message ever sent — or amending §3 to describe what is actually on
the wire. That is a deliberate decision about a published package and a wire
format, not a quiet patch.
