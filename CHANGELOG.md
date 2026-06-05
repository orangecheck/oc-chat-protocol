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
- **`test-vectors/`** — five reproducible fixtures, including `vc04` proving re-wrap `id`/tag stability.

### Honesty notes (normative posture, not marketing)
- The `seal-til-block` unlock is **beacon-enforced policy, not consensus**. The v0 beacon is **drand quicknet tlock** (named, not OC-controlled). The word "trustless" MUST NOT appear on any v0 seal surface. A Bitcoin-consensus-enforced seal (CLTV-witness) is a structurally pre-wired upgrade path (`seal.cltv_outpoint`), not shipped.
- OC operates **no payment rail** for postage. Sender and recipient transact directly; OC verifies the preimage offline and never custodies sats.

### Depends on
- `oc-lock-protocol` v2 (envelope format §4, canonicalization §5, device records §3). This spec amends OC Lock SPEC §4.5 (chat mode) and §4.6 (seal mode); see that repo's CHANGELOG.
