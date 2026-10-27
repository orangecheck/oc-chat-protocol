# OC Chat Protocol

**Bitcoin-identity messaging: your address is your inbox.**

OC Chat is a decentralized, end-to-end-encrypted messaging protocol where the identity is a **Bitcoin address** (BIP-322), the anti-spam is **Lightning postage paid directly to the recipient**, and a message can be **sealed to open only at a future Bitcoin block height**.

It is **not a new verb.** OC Chat is a *mode of [OC Lock](https://github.com/orangecheck/oc-lock-protocol)* — it reuses OC Lock's envelope crypto (X25519 ECDH + AES-256-GCM, BIP-322 identity binding, RFC 8785 canonicalization) verbatim and adds two envelope `kind` values plus a thin threading / postage / seal layer. The way `vault.ochk.io` is OC Lock Flow 4 + Lightning, `chat.ochk.io` is OC Lock + threads + postage + a block-height seal.

## What this repo is

The **normative protocol specification**. Prose + fixtures only; no code.

| File | What it is |
|---|---|
| [`SPEC.md`](./SPEC.md) | Normative: the recipient-exclusion `id`/AAD rule, the three send modes, threading, postage, the seal beacon protocol, error codes, kind allocation. |
| [`PROTOCOL.md`](./PROTOCOL.md) | Narrative walkthrough — six flows with diagrams. |
| [`WHY.md`](./WHY.md) | Hypothesis-by-hypothesis rationale, including the Ed25519 substitution test run out loud on the seal. |
| [`SECURITY.md`](./SECURITY.md) | Threat model and attack scenarios. |
| [`test-vectors/`](./test-vectors/) | 25 reproducible fixtures (`vc01`–`vc25`), including `vc04` proving re-wrap `id`/tag stability. |
| [`CHANGELOG.md`](./CHANGELOG.md) | Version history. |

## The three modes

```
 speak-now      kind=chat            free 1:1 E2EE. BIP-322 identity is the account.
 pay-to-reach   kind=chat + postage  a stranger pays Lightning postage to YOU to land in
                                      your inbox. OC never touches the sats.
 seal-til-block kind=chat-seal        a named beacon releases the key only after the chain
                                      passes block N. Beacon-enforced, NOT consensus.
```

Each mode adds exactly one Bitcoin-unique property: **identity** (BIP-322), **a settled-sats preimage** (Lightning), **a block-height predicate** (Bitcoin). Everything past these is a registry extension, not a new canonical surface.

## How it works (one paragraph)

You sign in once, with a Bitcoin wallet or with an orangecheck account. Your browser generates an X25519 device key and publishes it to Nostr as a kind-30078 record. A wallet binds it to your Bitcoin address with a BIP-322 signature (OC Lock). An account without an address has it vouched for by the ochk.io auth host instead (SPEC §8.6): a named trust anchor, and a weaker tier that carries no Bitcoin claim. To message someone, you fetch their device key by Bitcoin address, seal an OC Lock envelope to it, and gift-wrap it over Nostr (NIP-59) so relays learn nothing — not who, not when, not what. Threading lives inside the ciphertext as a hash-chain. A stranger attaches a Lightning preimage (paid to your own wallet) to reach you. To seal a message for the future, you wrap its key to a **named** beacon that releases it after a Bitcoin block height — and the protocol is honest that, until the CLTV-witness upgrade ships, that beacon is a trust anchor, not the chain.

## Layers

```
┌──────────────────────────────────────────────────────────────────┐
│  chat.ochk.io           threads, postage UI, seal compose        │
├──────────────────────────────────────────────────────────────────┤
│  oc-chat-protocol       kind=chat / chat-seal, threading, seal   │
│  oc-lock-protocol       envelope crypto, canonicalization        │
│  @orangecheck/lock-*    X25519 ECDH, HKDF, AES-256-GCM           │
├──────────────────────────────────────────────────────────────────┤
│  OrangeCheck            identity (BIP-322 sign-in, did_oc)       │
│  Nostr                  device directory (30078) + gift-wrap     │
│  Lightning              postage preimage; drand beacon for seal  │
│  Bitcoin                address ownership + block-height clock   │
└──────────────────────────────────────────────────────────────────┘
```

## Honest by design

- The `seal-til-block` v0 unlock is **beacon-enforced, not Bitcoin-consensus-enforced**. We name the beacon (drand quicknet) and we ban the word "trustless" from v0 seal surfaces. The consensus-enforced path (CLTV-witness) is structurally pre-wired, not shipped.
- We do **not** match Signal's per-message forward secrecy in v0. Compromising a device key decrypts its history. We say so; FS-critical users should use Signal.
- OC operates **no payment rail** for postage. Sender and recipient transact directly; OC only verifies the preimage, offline, and never custodies sats.

## Related

- [`orangecheck/oc-lock-protocol`](https://github.com/orangecheck/oc-lock-protocol) — the confidentiality verb OC Chat extends.
- [`orangecheck/oc-packages`](https://github.com/orangecheck/oc-packages) — the `@orangecheck/lock-*` reference crypto.
- [chat.ochk.io](https://chat.ochk.io) — reference web client, live and in testing.
- [ochk.io](https://ochk.io) — OrangeCheck umbrella.

## Status

0.4.0 (2026-10-27). Before 1.0, a minor version can change the wire; [`CHANGELOG.md`](./CHANGELOG.md) says when it does. The reference web client at [chat.ochk.io](https://chat.ochk.io) runs 0.4.0 and is in testing. No `@orangecheck/chat-*` package is published yet.

## Acknowledgements

OC Chat owes its founding premise — Bitcoin as an identity substrate, "access as projection of force" made meaningful only when it costs something real — to [**Bram Kanstein**](https://bramk.substack.com/). See OC Lock's `WHY.md`.

## License

MIT; see [LICENSE](./LICENSE).
