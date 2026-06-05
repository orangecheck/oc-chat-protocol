# Why OC Chat is shaped this way

> This is the rationale, hypothesis by hypothesis. The spec says *what*; this says *why*, and is honest about what we gave up. We-voice throughout.

OC Chat exists because `lock.ochk.io` proved the crypto and the transport work, but its chat is unusable — a wallet signature per message, no push, lost-while-offline messages, no device migration. We could not fix that inside a file-drop tool. So we extracted a real messenger. The constraint we set ourselves: change the UX, not the cryptography, and stay inside the OrangeCheck invariants.

## H1 — Chat is a mode of OC Lock, not a seventh verb

We considered making "chat" its own protocol family. We rejected it. The six verbs (attest, lock, vote, stamp, agent, pledge) are complete; an unmet need reduces to a new *mode* of a verb or a composition. Messaging is continuous confidentiality — it *is* the lock verb, operating over a thread. So OC Chat adds two `kind` values to the OC Lock envelope and ships a thin dependent spec, exactly as `oc-find-protocol` depends on OrangeOS. Verb count stays six. The reference crypto is unchanged `@orangecheck/lock-*`.

## H2 — A Bitcoin address is the right identity, and it is the whole wedge

Every rival anchors identity to a phone number (Signal, WhatsApp — KYC-adjacent), a rootless keypair you cannot prove you own (SimpleX, Session, Keet, Nostr npub), or another chain (XMTP, Status). A Bitcoin address is the only identity that is simultaneously self-sovereign, chain-verifiable (BIP-322), discoverable, *and* able to carry a Lightning preimage and a block-height clock. We do not win on "better crypto" — we win on the account model. Run the Ed25519 substitution test on identity: replace the Bitcoin address with an Ed25519 npub and the discovery + the UTXO-age anti-spam floor + the postage proof all collapse. Identity is genuinely Bitcoin-load-bearing.

## H3 — Kill the per-message signature; keep the device key

The single worst thing about the old chat is a BIP-322 wallet popup on every send. We hypothesize this is pure UX debt with no security value: the per-device X25519 key already authenticates every message, and the device's authority comes from the *one* BIP-322 binding signature in its kind-30078 record (verifiable offline, forever). So we move BIP-322 to registration only. This takes the send loop from 5–10s to sub-second at zero cost to authenticity. It is the highest-leverage decision in the protocol and it is why we did NOT rebuild on MLS/Waku/Hypercore — the failure was UX, not the substrate.

## H4 — The block-height seal ships beacon-enforced, and we say so

We want "a message the chain unlocks at block N." The honest truth (OC Lock `WHY.md` is the postmortem) is that there is no browser-shippable, consensus-enforced decrypt-at-height primitive today: adaptor-signature / CLTV-witness extraction has no shippable secp256k1 WASM build, and the PSBT loop is UX death. So v0 reuses OC Lock payment-mode's re-wrap pattern, generalizing the release predicate from "payment confirmed" to "block height reached," with the key escrowed to a **named beacon**. We refuse to call this "trustless." We refuse to ship CLTV-witness as the default and re-walk the v1 graveyard. Instead the envelope carries an optional `seal.cltv_outpoint` so the consensus-enforced path can be added later **without a format break** — structurally pre-wired, not promised.

## H5 — Run the Ed25519 substitution test on the seal, out loud

Here is the test the family demands, applied to `seal-til-block`, with the uncomfortable answer stated plainly:

> Replace Bitcoin with an Ed25519 world. Does the v0 seal still work? **Yes — almost entirely.** The seal's enforcement is a BLS/threshold committee that watches a clock and releases a key. Swap "block height N" for "NTP timestamp T" and the machinery is identical; this is literally drand/tlock, which is Bitcoin-independent. So **the v0 seal, in isolation, FAILS the substitution test.**

We do not paper over this. The BLS threshold is load-bearing for *enforcement*; Bitcoin block height is load-bearing only as the *predicate the committee voluntarily honors*. A height oracle can lie exactly as a timestamp oracle can — nothing in secp256k1 prevents a lying committee. What keeps the *product* Bitcoin-load-bearing is **not** the seal: it is `speak-now`'s BIP-322 identity + UTXO-age anti-spam, and `pay-to-reach`'s Lightning preimage, and the unshipped Layer-C CLTV-witness where the chain finally becomes the enforcer. We never let the seal alone carry the Bitcoin claim. That is the honest framing the family invariants require, and it is non-negotiable in every surface.

## H6 — drand quicknet is the v0 beacon; the Fedimint beacon does not exist yet

An earlier design claimed an "OC Fedimint guardian federation running threshold-BLS, reusing `oc-guardian-kit` / `me.ochk.io`" as the seal beacon. **That was false and we struck it.** Fedimint's threshold cryptography signs *funds custody*; it does not do threshold-*decryption* of an externally-supplied content key gated on a block height. There is no such module. Building one (DKG over a decryption keypair, a height-gated reveal protocol, per-seal share storage) is a real, named, months-long guardian-protocol workstream — not "reuse." So v0 ships **drand quicknet tlock**, named in-envelope and in-UI as "League of Entropy, ~12-of-22 BLS, NOT OC-controlled." We hedge its catastrophic-failure precedent (drand `fastnet` was sunset and permanently bricked its ciphertexts) with an optional redundant co-beacon — and we disclose the cost of that hedge (H7).

## H7 — A redundant beacon halves brick risk but doubles early-release risk

It is tempting to escrow the key to two beacons "so either firing unlocks." We allow it, but we refuse to sell it as pure upside. "Either unlocks" means the same `content_key` is recoverable from EITHER committee, so EITHER committee can decrypt the body early — security degrades to the *weaker* committee for early-release while improving liveness. For a dead-man's-switch this asymmetry is material. So a sealed message's UI must read "readable early by {named quorum}," not "unlocks at block N," and the redundant beacon is opt-in with the trade-off stated.

## H8 — recipients are routing, not content (the re-wrap fix)

A subtle but load-bearing decision. In base OC Lock the envelope `id` and the AEAD AAD both include `recipients[]`. That makes a sealed envelope un-re-keyable: when a beacon (or a payment relay) re-wraps the key for the eventual recipient, it mutates `recipients[]`, which breaks the `id` (and the BIP-322 signature over it) and the ciphertext GCM tag. An adversarial review caught that the first design would have shipped un-round-trippable sealed messages. The fix: for chat kinds, the `id` and AAD **exclude `recipients[]` entirely** — the recipient set is mutable delivery routing, the *content* is what's addressed. Re-wrap then preserves the `id`, the signature, and the tag. Test vector `vc04` proves it with real crypto.

## H9 — Postage is a preimage, sender→recipient direct, and the replay-binding is the hard part

Anti-spam should be priced, not filtered — *sats as signal*. The proof must be a **bearer proof of settled sats**: the BOLT11/BOLT12 preimage, verifiable offline as `SHA-256(preimage) == payment_hash`. We explicitly reject NIP-57 zap receipts (the NIP-57 spec itself says a zap receipt is "not a proof of payment" — server-signed, forgeable) and we reject per-message Lightning for all sends (the Sphinx/Juggernaut model requires every user to run a node and is effectively abandoned). Postage gates only stranger→inbox; contacts message free; a free-tier alternative is a BIP-322 UTXO-age floor (no sats, but it links the message to an on-chain address). The honest open problem: binding the preimage to `recipient + amount + nonce` so it cannot be replayed as third-party proof requires the recipient endpoint to mint a per-DM invoice without OC in the path — which BOLT12 `invoice_request` may not support today. We treat this as a **blocking** item on `pay-to-reach`, not a footnote.

## H10 — OC never touches the sats

OC's only money flow is **inbound** subscription billing to a dedicated BTCPay store (the vault/fleet pattern). Postage is sender→recipient **direct** — OC operates no gateway and is structurally absent from the path; any Fedimint gateway in a recipient's postage path is a NAMED third party. The subscription store has no outbound leg (no refunds, proration, sats-credit, or referral payout — a held balance would be custody). This keeps the no-custody invariant intact and keeps OC clear of money-transmitter analysis. The seal beacon is a key-share release, not a fund flow; OC holds no share.

## H11 — Threads are a hash-chain, not a timestamp sort

The old chat sorts messages by `created_at`, which is plaintext and minute-rounded — attacker-and-relay-influenceable. We move ordering into the ciphertext: `parent_id` MUST equal the content-addressed `id` of the parent message, making each thread a tamper-evident hash-chain. This is the only cryptographic anti-reorder available without a ratchet. It does not prevent a relay from *withholding* delivery — we do not claim transport-layer anti-replay.

## H12 — We cede per-message forward secrecy, in writing

Compromising a device key decrypts that device's whole history. We provide only coarse forward secrecy via 90-day key rotation. We do not implement a double ratchet in v0 (it needs relay-synchronized session state the lock model declines). This is a real gap against Signal, and we refuse to market parity. We say it plainly and we route forward-secrecy-critical users — journalists protecting sources above all — to use Signal, and we put the device-seizure caveat in bold on the tier that targets them. The double ratchet is roadmapped as a registry extension, not claimed.

## What we still don't have

- A consensus-enforced seal (Layer C CLTV-witness). Pre-wired, not shipped.
- A privacy-clean, wallet-supported per-DM postage invoice (H9). Blocks `pay-to-reach`.
- Per-message forward secrecy (H12).
- Group chat without social-graph leakage at the relay. Held until Marmot/MLS is production-ready.
- Account/device recovery without the Bitcoin key. Social-recovery roadmapped.
- Post-quantum confidentiality. X25519/secp256k1/BLS12-381 are classically secure only; long-range seals carry quantum risk.

## Acknowledgement

The reframing that makes this buildable — Bitcoin as identity, not access oracle — is owed to [Bram Kanstein](https://bramk.substack.com/). It is why the daily messenger leans on a BIP-322 identity instead of a chain transaction in the send path, and why we were able to delete the per-message signature without deleting the security.
