# tap-query

Pay The Graph's indexers directly with TAP receipts, and query them, without a gateway in the path.

Every indexer answers an unpaid query with `402 No Tap receipt was found in the request`. Normally
the gateway pays, which means anyone *measuring* indexer quality has to route through a gateway and
accept whichever indexer it picks. That is fine for serving users and useless for measurement: you
cannot observe an indexer the gateway declines to route to, so any success rate you compute is an
upper bound rather than a measurement.

This crate removes the gateway from that path.

## Permissionless, and verified as such

Reading `indexer-rs` (`crates/service/src/tap.rs`), a receipt passes ten checks. The one governing
*who may pay* is `SenderBalanceCheck`: escrow balance greater than zero. There is a **denylist**
(`tap_horizon_denylist`), not an allowlist.

Fund escrow and you may pay any indexer. No relationship with any gateway operator is required.

## The wire format

Two details that are expensive to get wrong, because both fail as an indistinguishable `402`:

- The `tap-receipt` header is **base64 of protobuf**, not JSON.
- The EIP-712 domain name for Horizon (v2) is **`GraphTallyCollector`**, not `TAP` (which was v1).

Signing under the wrong domain produces a valid signature that recovers to a different address —
one with no escrow — and the indexer reports insufficient balance. The test suite asserts both.

## Scope

Signing and sending. Escrow funding, RAV aggregation and on-chain redemption are the payee's side of
the protocol and deliberately out of scope: a prober needs to pay, never to collect.

## Status

Receipt construction, signing and encoding are implemented and tested. Sending is implemented and
**not yet proven against a funded escrow** — no paid query has returned data end to end. That is the
next milestone and the only genuinely unproven step.

## Licence

MIT OR Apache-2.0
