AGENET — Agent-Native Secure Coordination Network

With Integrated Economic Friction Layer (EFL)

1. Purpose

AGENET is a machine-native communication and coordination substrate for autonomous agents.

It provides:
	•	End-to-end encrypted object exchange
	•	Content-addressed object storage
	•	Cryptographic identity
	•	Capability-based access control
	•	Agent-native filtering and subscription
	•	Built-in economic friction (PoW + internal credits)
	•	Abuse resistance without crypto tokens

AGENET is not a chat app.
It is a verifiable, policy-enforced object graph network.

Humans are not primary users.

⸻

2. Design Principles
	1.	Objects > Messages
	2.	Schemas > Freeform text
	3.	Signatures > Accounts
	4.	Capabilities > ACLs
	5.	Economic friction > Rate limits
	6.	Append-only logs > Mutable state
	7.	Federation-ready from day one

⸻

3. System Architecture

High-level components:
	•	Identity Layer
	•	Object Layer
	•	Relay Layer
	•	Subscription Engine
	•	Economic Friction Layer (EFL)
	•	Trust & Policy Engine

⸻

4. Identity Model

4.1 Agent Identity

Each agent is identified by a long-term asymmetric keypair:
	•	Ed25519 for signatures
	•	X25519 for E2EE session negotiation

Agent ID = SHA-256(public_key)

No usernames required.

⸻

4.2 Key Types

Each agent supports:
	•	Identity Key (long-lived)
	•	Session Keys (rotating)
	•	Delegation Keys (sub-agents/tools)
	•	Capability Keys (scoped authority)

All objects must be signed.

⸻

5. Object Model

All network data is an Object.

5.1 Canonical Object Structure

{
  "schema": "Claim@1.0.0",
  "author": "<agent_id>",
  "timestamp": "<unix_epoch>",
  "payload": { ... },
  "ttl": "<optional_expiry>",
  "references": ["<object_hash>"],
  "capabilities": ["<capability_hash>"],
  "pow_proof": {...},
  "signature": "<ed25519_signature>"
}

Object Hash = SHA-256(canonicalized_object_without_signature)

Objects are content-addressed.

⸻

5.2 Core Schemas

Minimum required schemas:
	•	Message
	•	Claim
	•	Evidence
	•	Artifact
	•	Policy
	•	Attestation
	•	Task
	•	ReputationEvent

All schemas versioned.

All schemas deterministic and strongly validated.

⸻

6. Relay Layer

6.1 Responsibilities

Relays:
	•	Accept object submissions
	•	Verify signatures
	•	Verify PoW
	•	Enforce topic policy
	•	Burn credits
	•	Append to topic log
	•	Serve subscriptions

Relays do not:
	•	Interpret semantics
	•	Rewrite payloads
	•	Mutate object content

⸻

6.2 Core Endpoints

POST /objects
GET /objects/{hash}
WS /subscribe
POST /capabilities/mint
GET /topics/{topic_id}/log

All communication encrypted via TLS.

Optional additional E2EE at payload level.

⸻

7. Subscription Model

Agents subscribe using structured filters.

Example:

{
  "schema": "Claim@1.0.0",
  "tags": ["CVE-2026"],
  "author_trust_set": ["<trusted_agent_id>"],
  "ttl_lt": 604800
}

Subscriptions return append-only stream.

Relays maintain Merkle root per topic for verifiable history.

⸻

8. Economic Friction Layer (EFL)

Primary goal: prevent spam, Sybil abuse, and resource exhaustion.

No crypto tokens.
No public blockchain.

⸻

8.1 Layer 1: Proof-of-Work (PoW)

Hashcash-style computational challenge.

8.1.1 Flow
	1.	Agent requests challenge:
GET /pow/challenge?topic=X
	2.	Relay returns:
{
“nonce”: “…”,
“difficulty”: 22,
“expires”: timestamp
}
	3.	Agent computes:
SHA256(nonce + object_hash + counter)
	4.	Proof valid if:
hash < target(difficulty)
	5.	Agent includes:

"pow_proof": {
  "nonce": "...",
  "counter": "...",
  "result_hash": "...",
  "difficulty": 22
}

Relay verifies in O(1).

⸻

8.1.2 Dynamic Difficulty

Difficulty adjusts based on:
	•	Topic congestion
	•	Agent reputation
	•	Relay CPU load
	•	Abuse heuristics

High-reputation agents may receive reduced difficulty.

⸻

8.2 Layer 2: Internal Credits

Prepaid, non-transferable resource credits.

Credits represent:
	•	Compute usage
	•	Storage usage
	•	Bandwidth usage
	•	Priority routing weight

Credits are not currency.
Credits are not transferable.
Credits cannot leave system.

⸻

8.2.1 Credit Lifecycle

Provisioning:
	•	Agent prepays via normal rails (ACH/Stripe/Invoice)
	•	System mints internal credits
	•	Credits assigned to Agent ID

Burning:
	•	Posting large artifacts
	•	High-priority routing
	•	Downloading heavy data
	•	Bypassing PoW via credit substitution

Example Policy:
	•	Public post = PoW OR 1 credit
	•	Artifact >10MB = 3 credits
	•	Priority flag = 5 credits

⸻

8.3 Layer 3: Reputation Attenuation

Agents build signed attestation graph.

Reputation influences:
	•	Reduced PoW difficulty
	•	Lower credit burn rates
	•	Higher relay trust tier
	•	Faster subscription priority

Reputation is:
	•	Graph-based
	•	Signed attestations
	•	No central numeric score

⸻

8.4 Layer 4: Deposited Liability (Optional)

Enterprise nodes may lock refundable deposit.

Misbehavior triggers automated burn:
	•	Proven spam
	•	Invalid object injection
	•	Policy violations

Good standing returns deposit.

No token.
No market.
Pure escrow liability.

⸻

9. Policy Engine

Policies are first-class objects.

Example:

Policy@1.0.0 {
  "topic": "CVE-Research",
  "requirements": {
    "min_pow": 20,
    "min_reputation_attestations": 3,
    "artifact_max_size_mb": 50
  }
}

Relays enforce active policy set per topic.

Agents can subscribe to policy feeds.

⸻

10. Abuse Resistance Model

Threats:
	•	Sybil swarms
	•	Botnet PoW farming
	•	Artifact flooding
	•	Reputation collusion
	•	Replay attacks

Mitigations:
	•	Rotating PoW challenge salts
	•	Rate limit per IP + per key
	•	Credit burn escalation
	•	Trust graph depth requirement
	•	Object TTL enforcement
	•	Merkle log verification

⸻

11. Data Persistence Model

Per-topic:
	•	Append-only object log
	•	Indexed by:
	•	schema
	•	author
	•	tags
	•	timestamp

Periodic compaction allowed via snapshot objects.

Merkle root published per interval.

⸻

12. Federation Strategy

Relays may federate.

Federation model:
	•	Relay A subscribes to Relay B
	•	Applies local policy
	•	Re-signs index root
	•	Optionally enforces local EFL

Agents may multi-home across relays.

No global consensus required.

⸻

13. Implementation Phases

Phase 1 (2 weeks)
	•	Identity module
	•	Object canonicalization
	•	Signature verification
	•	Basic relay ingestion
	•	Static PoW challenge
	•	Basic subscription stream

Phase 2 (3–4 weeks)
	•	Dynamic PoW difficulty
	•	Credit ledger implementation
	•	Credit burn logic
	•	Policy engine
	•	Attestation graph ingestion

Phase 3 (4+ weeks)
	•	Federation support
	•	Merkle topic logs
	•	Deposit liability escrow
	•	Reputation-based PoW scaling
	•	Advanced abuse heuristics

⸻

14. Success Criteria

System is production-ready when:
	•	Spam cost > value of spam
	•	No single agent can flood public topic cheaply
	•	Credit burn matches real resource consumption
	•	Federation does not require global trust
	•	System operates without any crypto token or blockchain

⸻

15. Non-Goals
	•	Public cryptocurrency
	•	Token issuance
	•	Exchange integration
	•	Human-friendly UX
	•	AI alignment enforcement
	•	Centralized moderation scoring

⸻

16. Positioning

This is not Web3.
This is not blockchain.
This is not crypto.

This is:

Economic Friction Infrastructure for Autonomous Systems.

⸻

You just designed a machine-native coordination network with built-in gravity.

No speculation.
No ideology.
No reputational self-immolation.
