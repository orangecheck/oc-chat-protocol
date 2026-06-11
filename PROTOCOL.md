# OC Chat — protocol walkthrough

A narrative companion to [SPEC.md](./SPEC.md). The spec has the normative rules; this explains the flows and the *why*.

## The problem

`lock.ochk.io` already proved you can send a Bitcoin-identity-bound, end-to-end-encrypted message. But it was built as a one-shot file-drop, then bent into a chat — and it shows: the wallet had to sign **every** message, there was no real push, messages sent while you were offline could vanish, and there was no way to move to a new phone. OC Chat is the protocol for messaging done as messaging: continuous threads, durable delivery, postage, and a block-height seal — on the same crypto.

## The mental model

```
  one BIP-322 signature per device, ever
        │
        ▼
  device_pk (X25519) ──published──▶ Nostr kind-30078  (find me by my bitcoin address)
        │                                   │
        │ inbox pubkey = HKDF(device_sk)     │ fetch by addr
        ▼                                   ▼
  every message: seal an OC Lock envelope ─▶ gift-wrap (kind-1059) ─▶ relay ─▶ recipient
                 (no per-message wallet popup)
```

The recipient's inbox pubkey is derived from the device key, so *publishing a device record is creating an inbox*. After the one binding signature, sending and receiving are zero-click.

## Flow 1 — speak-now (the daily driver)

1. Alice types Bob's Bitcoin address. The app fetches Bob's kind-30078 device record and verifies the BIP-322 binding signature offline.
2. Alice writes "gm". The app builds the payload `{body:"gm", conversation_id, seq:1, parent_id:null}`, seals it to Bob's device key with a fresh `content_key` (OC Lock §4.2), and computes the `chat_envelope_id` **excluding `recipients[]`** (SPEC §3).
3. **No wallet popup.** The per-device key authenticates the send; BIP-322 was spent once at registration. The send loop is sub-second, not the 5–10s of the old lock chat.
4. The envelope is gift-wrapped (ephemeral Schnorr key, `created_at` minute-rounded) and published. The relay sees a throwaway pubkey, Bob's inbox pubkey, and an opaque blob.
5. Bob's inbox subscription receives it, finds his `device_id`, unwraps `content_key`, decrypts, and chains it by `parent_id`. Total on-screen time: under a second.

Durable delivery: relays are best-effort and may garbage-collect events. A conforming deployment SHOULD provide at least a best-effort store-and-forward so a message sent while Bob is offline still arrives — this is the free-tier floor, not a paid feature. It works by depositing the same opaque gift-wrap blob to an operator-run queue keyed by an **opaque per-conversation `queue_id`** (`HMAC(HKDF(device_sk), conversation_id)`, SPEC §8.1): the first message of a new conversation lands on Bob's derivable *bootstrap* queue, then both sides exchange per-conversation `queue_id`s inside the encrypted payload (`recv_queue`) and migrate off it, so the operator sees unlinkable queues of ciphertext it can neither read nor tie to a Bitcoin address. A paid sealed inbox adds only long-horizon retention, multi-device fan-out, and history depth on top of that same queue — durability of basic delivery is never the paywall.

## Flow 2 — multi-device

Bob has a laptop and a phone, each with its own device key and its own kind-30078 record. Alice's client wraps the one `content_key` once per active device (vector `vc02`). A new device is authorized by a **BIP-322 signature from Bob's primary wallet** over a link statement naming the new `device_pk` — Bitcoin-load-bearing and auditable.

**Portability cliff (disclosed):** a message sent *before* a device existed was never wrapped to it, so the new device cannot read it without a backfill — either the old device re-wraps the `content_key` to the new `device_pk`, or a sealed key-bundle is retrieved by BIP-322 proof from the same address. A deployment promising "multi-device history" MUST implement one of these and state the limit.

## Flow 3 — pay-to-reach (a stranger reaches you)

1. Bob publishes a postage policy: `floor_sats: 100` and a BOLT12 offer resolving to **his own** wallet.
2. Carol (a stranger) wants to message Bob. Her wallet fetches an invoice **directly** from Bob's offer (OC is not in the path), pays it, and obtains the preimage.
3. Carol's client embeds `postage{payment_hash, preimage, nonce, amount_sats, recipient}` in the sealed envelope (vector `vc05`). Because `postage` is in the `id`, the binding can't be altered.
4. Bob's client verifies `SHA-256(preimage) == payment_hash` **offline** and that the `nonce` is one his endpoint minted for this payment. Valid → inbox. Invalid/absent → delivered but filtered/pending (the "Requests" surface), never dropped; Bob can approve Carol to let her reach his inbox normally thereafter.

OC collects nothing. This is *sats as signal* — attention priced, not filtered — and it is the inverse of hashcash: the cost is hardware-neutral and accrues to the recipient as value. Contacts message for free; only stranger→inbox is gated.

## Flow 4 — seal-til-block + release

Alice wants the contents readable only after block 900000.

**Seal.** Alice picks a named beacon (default: drand quicknet). She wraps `content_key` to the **beacon's** device key, sets `kind="chat-seal"` and `seal{unlock_block:900000, anchor:"beacon", beacon_id:"drand:quicknet", beacon_url, confirmations:6}`, and signs (vector `vc03`). Bob receives the ciphertext immediately but holds no key. The compose UI forces Alice to acknowledge: *the named beacon can release early if its threshold colludes, and the seal is permanently bricked if the beacon disappears.*

**Release.** After block 900006 confirms:
1. Bob authenticates to the beacon over BIP-322.
2. The beacon checks `tip >= 900006` against its own node, unwraps `content_key`, re-wraps it for Bob's device, and returns a **detached `recipients[]` entry**.
3. Bob merges the entry and decrypts. The `id` and the ciphertext tag are unchanged — proven by vector `vc04`, the whole reason chat-kind `id`/AAD exclude `recipients[]`.

This is the same re-wrap machinery as OC Lock payment mode (Flow 2 there), with the release predicate generalized from "payment confirmed" to "block height reached." It is beacon-enforced policy; see WHY.md H4 for why we ship this and not the CLTV-witness path yet, and SECURITY.md for the trust posture.

## Flow 5 — standing-delivery (dead-man's-switch)

A journalist arms a disclosure: a `seal-til-block` envelope to a trusted recipient, set to release at a future height, **unless** the journalist checks in before then. Check-in re-anchors the seal (pushes `unlock_block` forward) via a fresh sealed envelope superseding the prior. If check-ins stop, the chain reaches the height and the beacon releases.

This is the one seal use case with real, repeat, high-stakes demand. It also has the sharpest failure mode: a beacon outage could false-fire an irreversible disclosure. A conforming deployment MUST provide a mandatory **second check-in channel** so a single beacon's liveness cannot trigger release alone — and MUST state plainly that a multi-year seal depends on the named beacon existing and cooperating that far out (the drand `fastnet` sunset, which permanently bricked its ciphertexts, is the cautionary precedent).

## Flow 6 — institutional / source-intake (M7)

The institutional tier is composition, not new crypto. A newsroom founds a **public intake channel** (§8.3, `write:"open"` — a Bitcoin-gated `utxo-floor` if it wants to price out flooding) and publishes its handle. A **source** the newsroom does not pre-know opens OC Chat under a fresh throwaway identity and posts material to that channel (an ordinary kind-30111 post). The newsroom reads the public post and clicks **"Message privately"**: the client opens a `speak-now` gift-wrap (§8) to the source's inbox key — the **reply** is end-to-end encrypted even though the **intake** was public. Neither the relay nor the newsroom learns a link between the source's public submission and any other identity beyond what the source itself chose to reveal in the post (S-M7-2: the inbound post is permanent and public — that is the honest boundary, *not* a SecureDrop-grade anonymity claim).

Two institutional hardenings ride on top, both opt-in and owner-operated. The newsroom can run its **own NIP-42 AUTH relay** (§8.4) so the recipient inbox tags on its private replies never appear to a passive observer of a public relay — the relay becomes a named trust anchor it controls (S-M7-1; AUTH is a metadata hardening, not a Bitcoin claim). And a staff recipient with no Lightning node can name a **Fedimint federation** as their postage last-mile (§6.5) — the federation custodies and settles, OC touches no sats — so pay-to-reach works for an institution without anyone running an LN node, at the cost of trusting the named federation (S-M7-3; gated on a money-transmitter analysis).

## What's different from the lock.ochk.io chat

| Concern | lock.ochk.io chat (v0 prototype) | OC Chat |
|---|---|---|
| Send | BIP-322 wallet popup every message (5–10s) | sub-second; BIP-322 once at registration |
| Ordering | sorts by untrusted minute-rounded `created_at` | hash-chain `parent_id` |
| Offline delivery | message can vanish if the relay GC's it | best-effort store-and-forward on the free tier |
| Anti-spam | none | postage (paid) or a free BIP-322 UTXO floor |
| Future delivery | none | `seal-til-block` |
| Re-keying a held envelope | breaks `id` + tag | `id`/AAD exclude `recipients[]` (re-wrap safe) |

## Where to go next

- [SPEC.md](./SPEC.md) — normative rules.
- [WHY.md](./WHY.md) — every design decision and its rationale.
- [SECURITY.md](./SECURITY.md) — threat model and what v0 does not solve.
