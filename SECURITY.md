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

**S6 — Recipient-pubkey leak on public relays.** NIP-59 places the recipient inbox pubkey in the kind-1059 `p` tag; a relay storing those events can enumerate who *receives*. On the **durable store-and-forward inbox** (SPEC §8.1) this is mitigated by opaque per-conversation `queue_id`s (`HMAC(HKDF(device_sk), conversation_id)`): the operator sees N unlinkable queues, never a recipient pubkey or a Bitcoin address, and the bootstrap↔per-conversation migration is exchanged inside the AEAD payload (§8.1.3). The residual leak is the **bootstrap queue** (first message of a new conversation, derived from the published inbox pubkey) and any message ridden over an arbitrary public relay — both disclosed; a NIP-42 AUTH-enforced relay narrows the relay case.

**S7 — Postage replay (now specified, with a named ceiling).** A preimage proves *a* payment settled, not *which* DM it was for. v0 binds it via the recipient's LNURL endpoint minting a fresh per-DM invoice whose description-hash commits `recipient + amount + nonce` (LUD-18 payerData), which the recipient re-derives itself (§6.3), plus a **local spent-`payment_hash` ledger** (one-time use). This makes a preimage **non-replayable to the recipient** (replay to a *different* recipient fails the binding; replay to the *same* recipient fails the ledger). The honest ceiling, which MUST be disclosed and MUST NOT be over-claimed:
> - **Recipient-scoped, NOT third-party transferable.** A party seeing only `{preimage, nonce}` — without the recipient-signed invoice + carrier fields — cannot verify the binding. Never render a verified-postage badge as "proof anyone can verify."
> - **The recipient's LNURL endpoint is a NAMED trust anchor**, not removed: it chooses what the invoice commits to and MUST mint a fresh per-DM invoice; a pre-minted shared invoice reintroduces replay. The endpoint string MUST be identity-signed (§6.1) and surfaced plaintext.
> - **Wallets no longer enforce the description-hash** (lnurl PR #234, 2026-05) — OC MUST recompute `SHA-256(metadata‖payerData)` itself, over the **verbatim** metadata bytes, or the binding silently does nothing.
> - **The spent-ledger is local** and per-recipient-device — best-effort across that recipient's synced devices, not a global consensus ledger.
> - **Bearer proof, not on-chain settlement proof.** A cold observer can check `SHA-256(preimage)==payment_hash` and the binding, but cannot independently confirm the HTLC settled on the network. The preimage proves payment *sent*, not payment *exclusive*.

**S8 — Multi-device portability cliff.** A device added *after* a message was sent was never in `recipients[]` and cannot decrypt that message; the sealed-inbox ciphertext was wrapped to prior device keys. "Multi-device history" is bounded to messages sent after the device existed, unless a backfill (old-device re-wrap, or a BIP-322-retrievable sealed key-bundle) is implemented. Disclose the bound.

**S9 — Envelope plaintext metadata.** Base OC Lock exposes `from.address`, `recipients[*].address`, `hint`, `created_at` in plaintext (OC Lock §7.2). Threading is encrypted, but a raw `speak-now` envelope still leaks sender/recipient. Group chat would leak the social graph in cleartext unless addresses are redacted and delivered out-of-band — designed-around, not solved, in v0 (which is why groups are held until MLS).

**S10 — Message ordering / freshness / delivery.** `created_at` is untrusted; `parent_id` gives per-thread tamper-evidence but NOT a transport-layer anti-reorder/anti-replay guarantee — a relay can withhold, delay, or reorder *delivery*. An offline recipient plus a garbage-collected relay event = a lost message **unless a store-and-forward queue retains it (SPEC §8.1)** — which is why the durable inbox is the free-tier floor, not a paid add-on. The queue does not add an anti-reorder guarantee (the recipient still orders by the `parent_id` chain on drain); it closes only the *loss* hole, and an operator that withholds a queued blob is detectable as a `parent_id` gap (`E_THREAD_GAP`).

**S11 — Standing-delivery false-fire.** A beacon outage could trigger an irreversible disclosure that the owner intended to prevent by checking in. A mandatory **second check-in channel** is required so a single beacon's liveness cannot release alone — and that channel must not itself become the single point of failure it removes (an open design item).

**S12 — Account-loss = history-loss; no recovery without the Bitcoin key.** No account means a lost Bitcoin key loses history and contacts. Social-recovery (N-of-M) is roadmapped and named, never pretended trivial. For the burner-phone / seized-device persona, the BIP-322 device-link ceremony assumes the wallet is reachable on the new device — which may be false; an encrypted device-export (signed by the old device) is required before claiming "daily messenger" onboarding parity.

**S13 — Post-quantum.** X25519, secp256k1, and BLS12-381 (the seal beacon) are classically secure only. Long-range seals carry quantum risk over their lifetime.

**S14 — The directory is a reachability oracle, and listings are scrapeable.** The opt-in directory (§8.2) reveals a NODE — "this identity is reachable" — never an EDGE (the social-graph firewall, §8.2.3). But any directory that answers "is handle/address X reachable?" is an oracle a stranger can probe one identifier at a time. The salted-handle `d`-tag stops BULK enumeration, not TARGETED confirmation of a guessed handle. And anything published to a listing is public and **permanently harvestable** — once a relay/indexer/archive has crawled it, revocation cannot retract it. Signal's own conclusion holds: enumeration "cannot be fully prevented"; the threat model is *who may ask*, not *can anyone ask*. Default is invisible; choose the lowest disclosure that meets your need.

**S15 — Directory revocation is forward-effective only.** A tombstone (§8.2.4) stops new resolution on conforming relays/clients; it cannot make a non-conforming relay, an archive, or `nostr.band`/Vertex forget an already-indexed plaintext handle. A client MUST NOT present removal as "delete yourself completely" — it is "revoke the record and stop new resolution." Disclose this verbatim at opt-in.

**S16 — A public handle is an intentional deanonymization.** Publishing a handle binds a human-friendly name to your Bitcoin address — whose on-chain history is itself public — and links to your cross-family `ochk.io/u/<addr>` footprint. If you keep your chat identity separate from your on-chain history, listing collapses that pseudonymity. This is a feature, not a bug, *for the user who chooses it* — but it MUST be stated plainly, and the Tier-0 invisible default is the mitigation.

**S17 — Handles are non-authoritative; the address is the trust root.** Handle uniqueness is first-writer-wins, best-effort across relays, NOT global consensus — squatting is deterred by the UTXO-age gate (§8.2.2) but not eliminated. A client MUST render the address (and trust tier) alongside any handle and MUST verify §8.2.2's BIP-322 binding + UTXO floor before honoring a handle; an unverified handle resolves as un-listed (`E_DIR_UNVERIFIED`). The relay/index operator is a NAMED availability anchor and a potential who-looks-up-whom observation point if it logs access patterns — privacy-sensitive resolution MUST NOT route through a centralized indexer.

## Custody / money boundary (non-protection of a different kind)

OC operates no payment rail for postage; sender and recipient transact directly and OC verifies the preimage offline. The subscription BTCPay store is inbound-only with no outbound leg. The seal beacon releases a key share, never funds, and OC holds no share. Any custodial Lightning fallback is a NAMED Fedimint federation that custodies — OC is never a guardian. These boundaries are load-bearing for both the no-custody invariant and the money-transmitter posture; weakening any of them (an OC-operated postage gateway, a held user balance, an OC-held bond HTLC) reintroduces custody and is forbidden.

## Normative compliance (security-critical)

A conforming implementation MUST:

1. Reproduce the test vectors, including `vc04` (re-wrap `id`/tag stability) and `vc05` (preimage verification).
2. Never label a `kind="chat-seal"` envelope with `anchor="beacon"` as "trustless," and surface the beacon identity + early-release/brick risk at compose time.
3. Order threads by the `parent_id` hash-chain, never by `created_at`.
4. Verify postage per §6.3 — re-derive the LNURL description-hash binding ITSELF (wallets dropped it), enforce `preimage`/amount/expiry/identifier/nonce + the local spent-`payment_hash` ledger — and disclose the S7 ceiling (recipient-scoped, not third-party-transferable; the endpoint is a named anchor).
5. Operate no OC payment rail for postage; name any third-party gateway.
6. Disclose S1 (no per-message FS) on any surface marketed to high-threat users.
7. If it offers the directory (§8.2): publish a listing ONLY on explicit opt-in (default invisible); refuse to honor a handle unless §8.2.2 passes (signature + kind-30078 binding + UTXO floor); enforce the §8.2.3 social-graph firewall; honor tombstones as authoritative; and disclose S14–S16 (scrapeable oracle, forward-only revocation, deanonymization) at opt-in time, never marketing "delete yourself completely."
