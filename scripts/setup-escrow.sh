#!/usr/bin/env bash
# Authorise a prober signing key and fund escrow so it can pay one indexer.
#
# Run this yourself, with your own key. It never leaves your machine and nothing here writes a key
# to disk.
#
#   AUTHORIZER_PK=0x...  ./setup-escrow.sh                 # dry run, sends nothing
#   AUTHORIZER_PK=0x...  ./setup-escrow.sh --execute       # actually sends
#
# Two separate things have to be true before an indexer will serve a paid query, and they are
# independent - getting one without the other fails in a way that looks identical:
#
#   1. the SIGNER is authorised by an AUTHORIZER on GraphTallyCollector
#   2. the AUTHORIZER has escrow deposited for (collector, receiver)
#
# Escrow is keyed on (payer, collector, receiver), so step 2 is per indexer. Probing N indexers
# means N deposits, each locking capital with a thawing period to withdraw. The query fees are
# trivial; the locked capital is the real cost of coverage.
set -euo pipefail

export PATH="$HOME/.foundry/bin:$PATH"

RPC="${RPC:-https://arb1.arbitrum.io/rpc}"
CHAIN_ID=42161

# Arbitrum One, from packages/horizon/addresses.json. GraphTallyCollector cross-checked against
# SubgraphService.getGraphTallyCollector() on-chain.
COLLECTOR=0x8f69F5C07477Ac46FBc491B1E6D91E2bb0111A9e
ESCROW=0xf6Fcc27aAf1fcD8B254498c9794451d82afC673E
GRT=0x9623063377AD1B27544C965cCd7342f7EA7e88C7

# Receiver = the indexer to be paid. ellipfra by default.
RECEIVER="${RECEIVER:-0xf92f430dd8567b0d466358c79594ab58d919a6d4}"
# How much to lock in escrow for that indexer. 10 GRT is plenty for probing: at ~0.00073 GRT a
# query that is over 13,000 queries.
DEPOSIT_GRT="${DEPOSIT_GRT:-10}"
# Proof validity window.
DEADLINE_SECS="${DEADLINE_SECS:-3600}"

EXECUTE=0
[[ "${1:-}" == "--execute" ]] && EXECUTE=1

: "${AUTHORIZER_PK:?set AUTHORIZER_PK to the funded account private key}"

AUTHORIZER=$(cast wallet address --private-key "$AUTHORIZER_PK")

# The prober's signing key. Generated fresh unless you supply one: the signer only ever signs
# receipts, never moves funds, so it is the key that belongs on a server. The authorizer holds the
# money and should not.
if [[ -n "${SIGNER_PK:-}" ]]; then
  SIGNER=$(cast wallet address --private-key "$SIGNER_PK")
  GENERATED=0
else
  SIGNER_PK=$(cast wallet new --json | python3 -c 'import json,sys; print(json.load(sys.stdin)[0]["private_key"])')
  SIGNER=$(cast wallet address --private-key "$SIGNER_PK")
  GENERATED=1
fi

DEADLINE=$(( $(date +%s) + DEADLINE_SECS ))
DEPOSIT_WEI=$(cast to-wei "$DEPOSIT_GRT" ether)

echo "authorizer  $AUTHORIZER   (holds funds, signs the transactions)"
echo "signer      $SIGNER   (signs receipts only)"
echo "receiver    $RECEIVER   (the indexer being paid)"
echo "deposit     $DEPOSIT_GRT GRT"
echo "deadline    $DEADLINE"
echo

# ── the authorisation proof ───────────────────────────────────────────────────
# Authorizable._verifyAuthorizationProof:
#   keccak256(abi.encodePacked(chainid, address(this), "authorizeSignerProof", deadline, msg.sender))
# then toEthSignedMessageHash, recovered against the signer.
#
# encodePacked means no padding between elements and no length prefix on the string, so this is
# built by hand rather than with abi-encode, which would pad every field to 32 bytes and produce a
# hash the contract never computes.
CHAIN_HEX=$(printf '%064x' "$CHAIN_ID")
DEADLINE_HEX=$(printf '%064x' "$DEADLINE")
DOMAIN_HEX=$(printf 'authorizeSignerProof' | xxd -p -c 256)
PACKED="0x${CHAIN_HEX}${COLLECTOR#0x}${DOMAIN_HEX}${DEADLINE_HEX}${AUTHORIZER#0x}"
MESSAGE_HASH=$(cast keccak "$PACKED")

# The signer signs that hash as an EIP-191 personal message.
#
# NOT --no-hash. cast treats a 0x-prefixed argument as hex bytes and applies the Ethereum Signed
# Message prefix before signing, which is exactly what the contract recomputes via
# toEthSignedMessageHash. --no-hash signs the bare hash, producing a signature that recovers to a
# different address and reverts as AuthorizableInvalidSignerProof.
PROOF=$(cast wallet sign --private-key "$SIGNER_PK" "$MESSAGE_HASH")

# Verify locally before spending gas: recovery must return the signer, or authorizeSigner reverts
# with AuthorizableInvalidSignerProof and the gas is gone.
# verify takes MESSAGE then SIGNATURE positionally, and applies the same prefix as sign.
RECOVERED=$(cast wallet verify --address "$SIGNER" "$MESSAGE_HASH" "$PROOF" >/dev/null 2>&1 && echo "$SIGNER" || echo "MISMATCH")
echo "packed      $PACKED"
echo "hash        $MESSAGE_HASH"
echo "proof       ${PROOF:0:20}...  recovers to: $RECOVERED"
if [[ "$RECOVERED" == "MISMATCH" ]]; then
  echo
  echo "proof does not recover to the signer. not sending anything." >&2
  echo "the packed encoding is the usual culprit - see Authorizable.sol:165" >&2
  exit 1
fi
echo

echo "would send, in order:"
echo "  1. GraphTallyCollector.authorizeSigner($SIGNER, $DEADLINE, <proof>)"
echo "  2. GRT.approve($ESCROW, $DEPOSIT_WEI)"
echo "  3. PaymentsEscrow.deposit($COLLECTOR, $RECEIVER, $DEPOSIT_WEI)"
echo

if [[ "$EXECUTE" -eq 0 ]]; then
  echo "DRY RUN. re-run with --execute to send."
  if [[ "$GENERATED" -eq 1 ]]; then
    echo
    echo "NOTE: a signer key was generated for this dry run and is NOT the one you would end up"
    echo "with on --execute. set SIGNER_PK yourself so the key you authorise is the key you keep."
  fi
  exit 0
fi

if [[ "$GENERATED" -eq 1 ]]; then
  echo "generated signer private key (store this on the prober box, nowhere else):"
  echo "  $SIGNER_PK"
  echo
fi

echo "1/3 authorising signer..."
cast send "$COLLECTOR" "authorizeSigner(address,uint256,bytes)" "$SIGNER" "$DEADLINE" "$PROOF" \
  --private-key "$AUTHORIZER_PK" --rpc-url "$RPC" >/dev/null
echo "    authorized: $(cast call "$COLLECTOR" 'isAuthorized(address,address)(bool)' "$AUTHORIZER" "$SIGNER" --rpc-url "$RPC")"

echo "2/3 approving GRT to escrow..."
cast send "$GRT" "approve(address,uint256)" "$ESCROW" "$DEPOSIT_WEI" \
  --private-key "$AUTHORIZER_PK" --rpc-url "$RPC" >/dev/null

echo "3/3 depositing escrow for the indexer..."
cast send "$ESCROW" "deposit(address,address,uint256)" "$COLLECTOR" "$RECEIVER" "$DEPOSIT_WEI" \
  --private-key "$AUTHORIZER_PK" --rpc-url "$RPC" >/dev/null
echo "    balance: $(cast call "$ESCROW" 'getBalance(address,address,address)(uint256)' "$AUTHORIZER" "$COLLECTOR" "$RECEIVER" --rpc-url "$RPC")"

echo
echo "done. now prove a paid query end to end:"
echo
echo "  TAP_VERIFIER=$COLLECTOR TAP_PAYER=$AUTHORIZER SIGNER_PK=<the signer key> \\"
echo "    cargo run --example probe -- <indexer_url> $RECEIVER <allocation> <deployment>"
