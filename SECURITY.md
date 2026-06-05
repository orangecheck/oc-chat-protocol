# Security Policy

## Reporting a vulnerability

Email **security@ochk.io** with a description, reproduction steps (a minimal test vector is ideal), an impact assessment, and whether you want credit. We aim to acknowledge within 48 hours. Do not file public issues for suspected vulnerabilities. Protocol-level concerns (a clause that is unsound, not an implementation bug) get subject prefix `[protocol]`.

## Scope

This document covers the **OC Chat protocol specification** in this repository. OC Chat is a mode of OC Lock and inherits OC Lock's security model ([`oc-lock-protocol/SECURITY.md`](https://github.com/orangecheck/oc-lock-protocol/blob/main/SECURITY.md)) — read it first. This file covers only what OC Chat adds or changes.

## Threat model

The adversary may: control and observe relays; run a malicious relay; seize a device; observe all network traffic as a passive global observer; operate or collude with a seal beacon; and compel the service operator (state actor). We assume Bitcoin's security holds, BIP-322 verification is correct, the user's runtime is not compromised, and randomness is strong.

## What OC Chat proves (inherited + new)

- **Confidentiality & authenticity** of every message (OC Lock §7.1): X25519 + AES-256-GCM to device keys; per-device key authenticates sends; the BIP-322 device-record binding is offline-verifiable.
- **Sender-metadata hiding from relays**: NIP-59 gift-wrap with an ephemeral, discarded Schnorr key and minute-rounded `created_at`.
- **Tamper-evident threading**: `parent_id` is the content-addressed `id` of the parent (§5), so a thread is a per-sender hash-chain.
- **Re-wrap integrity**: chat-kind `id`/AAD exclude `recipients[]`, so a beacon/relay re-wrap cannot forge content or break the signature (vector `vc04`).
- **Offline payment proof**: a Lightning preimage, `SHA-256(preimage) == payment_hash`, verifiable by anyone with no service.

## What OC Chat does NOT solve — attack scenarios

**S1 — Device seizure decrypts history (no per-message forward secrecy).** An attacker who seizes a device and extracts `device_sk` decrypts every past message wrapped to it — potentially years. Mitigation is coarse only (90-day rotation). *This is the single most dangerous gap for journalists protecting sources; it is disclosed in bold on any surface targeting them, who are told to use Signal for forward-secrecy-critical work.*

**S2 — Seal beacon colludes to release early.** For `kind="chat-seal"`, the `content_key` is escrowed to a beacon committee. A colluding threshold can decrypt the message body **before** `unlock_block` — this is strictly weaker than `speak-now`, where no third party ever holds key material. The product's "relays learn nothing" claim is TRUE for `speak-now` and FALSE for `seal-til-block`. The UI MUST label a sealed message "readable early by {named quorum}".

**S3 — Seal beacon disappears (permanent brick).** If the named beacon is sunset, every ciphertext sealed to it is permanently unrecoverable (the drand `fastnet` sunset, Nov 2024, is the precedent). A multi-year inheritance/standing-delivery seal is a promise that depends on the beacon existing and cooperating years out. The compose flow MUST force acknowledgement of brick risk; a durability SLA and a key-resharing-on-disband protocol are open items that MUST be resolved before any multi-year seal UI ships.

**S4 — Redundant double-seal doubles the early-release surface.** `redundant_beacon` halves brick risk (S3) but means EITHER committee can independently decrypt the body early (S2). Security for early-release degrades to the weaker committee. Opt-in only, with the asymmetry disclosed.

**S5 — Seal-existence metadata leak.** The `seal` block (`unlock_block`, `beacon_id`, `beacon_url`) is plaintext. A passive observer learns "this party has a message scheduled to open near block N via beacon B" — for a dead-man's-switch, that an irreversible disclosure is armed and its deadline. Additionally, the beacon is in the metadata graph of every sealed thread (it holds the wrapped key). Minimize/encrypt seal predicate metadata where feasible; this leak is a named non-protection.

**S6 — Recipient-pubkey leak on public relays.** NIP-59 places the recipient inbox pubkey in the kind-1059 `p` tag; a relay storing those events can enumerate who *receives*. Mitigated only on NIP-42 AUTH-enforced relays and by per-conversation queue IDs on a sealed inbox — NOT on arbitrary public relays. The free tier leaks recipient-pubkey to whatever relay stores it; this is disclosed.

**S7 — Postage replay.** A preimage proves *a* payment settled, not *which* DM it was for. Without binding `payment_hash` to `recipient + amount + nonce` (committed in the `id`, §6), a preimage could be replayed as "proof of payment" to a third party who did not mint it. The binding requires the recipient endpoint to mint a per-DM invoice with OC out of the path (§6.3) — an open construction. Until specified, a deployment MUST treat the preimage as settlement evidence only, not non-replayable third-party proof, and MUST NOT claim otherwise.

**S8 — Multi-device portability cliff.** A device added *after* a message was sent was never in `recipients[]` and cannot decrypt that message; the sealed-inbox ciphertext was wrapped to prior device keys. "Multi-device history" is bounded to messages sent after the device existed, unless a backfill (old-device re-wrap, or a BIP-322-retrievable sealed key-bundle) is implemented. Disclose the bound.

**S9 — Envelope plaintext metadata.** Base OC Lock exposes `from.address`, `recipients[*].address`, `hint`, `created_at` in plaintext (OC Lock §7.2). Threading is encrypted, but a raw `speak-now` envelope still leaks sender/recipient. Group chat would leak the social graph in cleartext unless addresses are redacted and delivered out-of-band — designed-around, not solved, in v0 (which is why groups are held until MLS).

**S10 — Message ordering / freshness / delivery.** `created_at` is untrusted; `parent_id` gives per-thread tamper-evidence but NOT a transport-layer anti-reorder/anti-replay guarantee — a relay can withhold, delay, or reorder *delivery*. An offline recipient plus a garbage-collected relay event = a lost message unless a store-and-forward queue retains it.

**S11 — Standing-delivery false-fire.** A beacon outage could trigger an irreversible disclosure that the owner intended to prevent by checking in. A mandatory **second check-in channel** is required so a single beacon's liveness cannot release alone — and that channel must not itself become the single point of failure it removes (an open design item).

**S12 — Account-loss = history-loss; no recovery without the Bitcoin key.** No account means a lost Bitcoin key loses history and contacts. Social-recovery (N-of-M) is roadmapped and named, never pretended trivial. For the burner-phone / seized-device persona, the BIP-322 device-link ceremony assumes the wallet is reachable on the new device — which may be false; an encrypted device-export (signed by the old device) is required before claiming "daily messenger" onboarding parity.

**S13 — Post-quantum.** X25519, secp256k1, and BLS12-381 (the seal beacon) are classically secure only. Long-range seals carry quantum risk over their lifetime.

## Custody / money boundary (non-protection of a different kind)

OC operates no payment rail for postage; sender and recipient transact directly and OC verifies the preimage offline. The subscription BTCPay store is inbound-only with no outbound leg. The seal beacon releases a key share, never funds, and OC holds no share. Any custodial Lightning fallback is a NAMED Fedimint federation that custodies — OC is never a guardian. These boundaries are load-bearing for both the no-custody invariant and the money-transmitter posture; weakening any of them (an OC-operated postage gateway, a held user balance, an OC-held bond HTLC) reintroduces custody and is forbidden.

## Normative compliance (security-critical)

A conforming implementation MUST:

1. Reproduce the test vectors, including `vc04` (re-wrap `id`/tag stability) and `vc05` (preimage verification).
2. Never label a `kind="chat-seal"` envelope with `anchor="beacon"` as "trustless," and surface the beacon identity + early-release/brick risk at compose time.
3. Order threads by the `parent_id` hash-chain, never by `created_at`.
4. Verify postage offline and enforce the `nonce`/`recipient`/`amount` binding (subject to S7's open construction).
5. Operate no OC payment rail for postage; name any third-party gateway.
6. Disclose S1 (no per-message FS) on any surface marketed to high-threat users.
