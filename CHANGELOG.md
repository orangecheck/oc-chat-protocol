# Changelog

All notable changes to the OC Chat protocol.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased] — 2026-06

### Added
- Initial OC Chat protocol specification. OC Chat is a **mode of OC Lock**, not a new verb: it adds two envelope `kind` values (`chat`, `chat-seal`) to the OC Lock v2 envelope and a thin threading/postage/seal layer on top of the unchanged X25519 + AES-256-GCM crypto.
- **`SPEC.md`** — normative: the recipient-exclusion `id`/AAD rule for chat kinds (§3), the three canonical send modes `speak-now` / `pay-to-reach` / `seal-til-block` (§4), encrypted threading with a hash-chain `parent_id` (§5), postage preimage-binding and replay defense (§6), the seal beacon release protocol (§7), error codes (§9), and the Nostr kind allocation 30110–30112 with the `oc-lock-chat-*` d-tag namespace (§10).
- **`PROTOCOL.md`** — narrative walkthrough: five flows (speak-now, multi-device, pay-to-reach, seal-til-block + release, standing-delivery).
- **`SECURITY.md`** — threat model + ≥10 attack scenarios, including the SEAL's beacon-trust posture, the OR-double-seal early-release asymmetry, and the seal-metadata leak.
- **`WHY.md`** — hypothesis-by-hypothesis rationale, including the Ed25519 substitution test run out loud on the seal.
- **`test-vectors/`** — six reproducible fixtures, including `vc04` proving re-wrap `id`/tag stability and `vc06` proving per-conversation queue-id unlinkability.
- **`SPEC.md §6`** — pay-to-reach postage specified (was a blocking open item). The recipient publishes an **identity-signed** Lightning Address; the sender's fresh per-DM **nonce** (LUD-18 payerData) makes the recipient's own endpoint mint a BOLT11 whose **description-hash commits recipient + amount + nonce**, which the recipient **re-derives itself** (wallets dropped it, lnurl #234) over verbatim bytes. Postage rides in the **encrypted ChatBody** (v0; lock-core `seal()` can't commit it as an envelope field), carrying `bolt11`/`lnurl_metadata`/`payerdata` for offline re-verification. Replay defense = the binding (cross-recipient) + a **local spent-`payment_hash` ledger** (same-recipient). S7 promoted to "specified, recipient-scoped — **not** third-party-transferable", with the named ceiling (the endpoint is a trust anchor; bearer-proof not on-chain-settlement-proof). vc05 reconciled to body-carried; new vector `vc09` (preimage→payment_hash, the LUD-18 binding, the replay branch). Bitcoin-load-bearing: the preimage is a settled-HTLC bearer proof (no Ed25519 analog).
- **`SPEC.md §8.2`** — opt-in discoverability directory (kind **30114**, d-tag `oc-lock-chat-dir:<salted handle hash>`): a NIP-33-replaceable listing signed by the inbox key, found by a human-readable handle. **Default invisible.** The Bitcoin gate (§8.2.2) is load-bearing — a resolver honors a handle only if the inbox key is bound to the address via the kind-30078 device record AND the address clears a funded+aged UTXO floor (no Ed25519 analog → Sybil/anti-squat); a bare signed-presence listing fails the substitution test. Social-graph firewall (§8.2.3): reveals a node, never an edge. Tombstone revocation (§8.2.4), forward-effective only. New error codes `E_DIR_UNVERIFIED`/`E_DIR_REVOKED`; SECURITY S14–S17 (scrapeable oracle, forward-only revocation, intentional deanonymization, non-authoritative handles); vectors `vc07` (d-tag) + `vc08` (listing id + tombstone). NOT OC Find — OC Find is an unbuilt research idea; its reserved 30094–30109 block is left untouched.
- **`SPEC.md §8.1`** — durable-inbox routing made normative: opaque per-conversation `queue_id = base64url(HMAC-SHA256(HKDF-SHA256(device_sk), conversation_id))`, a derivable first-contact `bootstrap_id`, the in-payload `recv_queue` handshake (§5), and four operator obligations (ciphertext-only, route-on-opaque-id, hold-no-keys, availability-not-authority). Closes the S6/S10 gap where the inbox routing key was named but unspecified — without it a store-and-forward operator could link a recipient's conversations. Free-tier floor; the paid tier extends only retention/multi-device/history.

### Honesty notes (normative posture, not marketing)
- The `seal-til-block` unlock is **beacon-enforced policy, not consensus**. The v0 beacon is **drand quicknet tlock** (named, not OC-controlled). The word "trustless" MUST NOT appear on any v0 seal surface. A Bitcoin-consensus-enforced seal (CLTV-witness) is a structurally pre-wired upgrade path (`seal.cltv_outpoint`), not shipped.
- OC operates **no payment rail** for postage. Sender and recipient transact directly; OC verifies the preimage offline and never custodies sats.

### Depends on
- `oc-lock-protocol` v2 (envelope format §4, canonicalization §5, device records §3). This spec amends OC Lock SPEC §4.5 (chat mode) and §4.6 (seal mode); see that repo's CHANGELOG.
