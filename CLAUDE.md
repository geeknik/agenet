# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Build & Test Commands

```bash
cargo build --workspace          # Build all 7 crates
cargo test --workspace           # Run all tests (163 tests across 8 suites)
cargo run -p agenet-relay        # Start relay server (default: 127.0.0.1:9600)
cargo clippy --workspace         # Lint
cargo fmt --all                  # Format

# Single crate
cargo test -p agenet-identity
cargo test -p agenet-relay --test integration    # Integration tests only
cargo test -p agenet-efl -- attestation          # Tests matching "attestation"
```

## Issue Tracking

This project uses **bd** (beads) for issue tracking. Session completion requires:
```bash
bd ready                    # Find work
bd create "Title" --type bug --priority 1 --body "Description"
bd update <id> --status in_progress
bd close <id>
bd sync                     # Sync before push
```
**Work is NOT complete until `git push` succeeds.** Always: `git pull --rebase && bd sync && git push`

## Architecture

Seven crates with strict dependency ordering (no cycles):

```
agenet-types          Core types: AgentId, ObjectHash, SchemaId, PowProof, AgenetError
    |
    +-- agenet-identity   Ed25519 keypairs, X25519 E2EE, session keys, delegation certs
    +-- agenet-pow        Hashcash PoW: challenge store, solver, O(1) verifier
    |
    +-- agenet-object     Content-addressed signed objects, schema validation, canonicalization
    |       (depends on agenet-identity, agenet-types)
    |
    +-- agenet-efl        Economic Friction Layer: credits, attestation graph, deposits, dynamic PoW
    |       (depends on agenet-identity, agenet-types, agenet-pow)
    |
    +-- agenet-relay      axum HTTP/WS server: routes, storage, merkle, policy, abuse, federation
    |       (depends on all above)
    |
    +-- agenet-sdk        Agent client: wraps relay REST API with PoW automation
            (depends on agenet-types, agenet-identity, agenet-object, agenet-pow)
```

## Object Lifecycle

Every piece of network data is a signed, content-addressed **Object**:

1. **Build** via `ObjectBuilder::new(schema, payload).topic("t").tags(vec![...]).timestamp(ts)`
2. **Sign** via `.sign(&keypair)` -- produces `author_pubkey` + Ed25519 `signature` over canonicalized JSON
3. **Hash** = SHA-256 of canonical JSON **excluding** signature and author_pubkey fields
4. **Submit** via `POST /objects` -- relay runs full validation pipeline
5. **Verify** via `object.verify_self()` -- checks `author == SHA256(pubkey)` AND valid signature

**Critical:** When computing PoW, pin the timestamp so the content hash matches between PoW solve and final signing. `ObjectBuilder.timestamp(pinned_ts)` ensures consistency.

## Relay Pipeline (POST /objects)

The handler in `routes.rs:post_object` runs these steps in order:
1. Rate limit (per-IP via ConnectInfo + per-agent)
2. Deposit standing check (suspended agents blocked)
3. Schema validation (all 8 core schemas enforced)
4. Self-authenticating signature verification
5. TTL enforcement
6. Replay detection (object hash deduplication)
7. Topic policy enforcement (min_pow, min_attestations, payload size, trust depth, credit substitution)
8. PoW verification + nonce consumption
9. Artifact burn (large payloads > 10MB)
10. Store, update Merkle tree, ingest Policy/Attestation objects, broadcast to subscribers

## EFL Four-Layer Defense

| Layer | Module | Purpose |
|-------|--------|---------|
| PoW | `agenet-pow` | Hashcash: SHA256(nonce+hash+counter) < target. Dynamic difficulty per topic/reputation/abuse |
| Credits | `agenet-efl/credits.rs` | Non-transferable, SQLite-backed ledger. Burn for posts/artifacts. Substitutes for PoW |
| Reputation | `agenet-efl/attestation.rs` | Signed graph of AttestationClaim edges. Reduces PoW difficulty and burn costs |
| Deposits | `agenet-efl/deposit.rs` | Enterprise escrow. Automated burn on ViolationType (spam, replay, policy) |

`BurnEscalation.cost_with_reputation(abuse_flags, reputation_count)` computes: `base * multiplier^abuse / (1 + reputation)`.

## Error Handling

`AgenetError` (in agenet-types) is the universal error type. `RelayError` wraps it with HTTP status mapping:
- `InvalidSignature` / `Unauthorized` -> 403
- `InvalidPow` -> 403, `PowExpired` -> 410
- `InsufficientCredits` -> 402
- `NotFound` -> 404, `Duplicate` -> 200 (idempotent)
- `UnknownSchema` / `SchemaValidation` -> 400

All functions return `Result<T, AgenetError>`. No panics on recoverable errors.

## Testing Patterns

- **Unit tests:** Inline `#[cfg(test)] mod tests` in each source file
- **Integration tests:** `crates/agenet-relay/tests/integration.rs` with `start_relay()` helper that spins up axum on a random port with `into_make_service_with_connect_info::<SocketAddr>()`
- **Databases:** Always `:memory:` SQLite in tests
- **PoW:** Use difficulty 8 (fast) in tests; production default is 20
- **Timestamps:** Pin with `ObjectBuilder.timestamp()` when PoW is involved to prevent content hash drift

## Key Conventions

- **Canonical JSON:** Keys sorted lexicographically, compact format, no trailing whitespace. Implemented in `agenet-object/canonical.rs`. Hash stability depends on this.
- **Hex encoding:** All binary values (keys, hashes, signatures) are hex-encoded strings in JSON.
- **Self-authenticating:** Objects carry `author_pubkey` so relays verify without external key registries.
- **TopicPolicy:** Each topic can have custom enforcement (min_pow, min_trust_depth, max_payload_bytes, allow_credit_substitution). Policies auto-register when Policy@1.0.0 objects are submitted.
- **Storage:** SQLite via sqlx with separate databases for objects, credits, and deposits. Migrations run on open.
- **Axum 0.8:** Uses `ConnectInfo<SocketAddr>` for IP extraction. Server must use `into_make_service_with_connect_info::<SocketAddr>()`.

## Core Schemas

Eight required schemas (all `@1.0.0`), validated in `agenet-object/schema.rs`:
`Message` (body), `Claim` (statement), `Evidence` (claim_ref+data), `Artifact` (content_type+data/url), `Policy` (topic+requirements), `Attestation` (attestee+claim), `Task` (description+status), `ReputationEvent` (subject+event_type).
