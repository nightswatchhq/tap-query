#!/usr/bin/env bash
# Authorise a prober signing key and fund escrow so it can pay one indexer.
#
#   AUTHORIZER_PK=0x... SIGNER_PK=0x... ./setup-escrow.sh              # preflight only, sends nothing
#   AUTHORIZER_PK=0x... SIGNER_PK=0x... ./setup-escrow.sh --execute    # sends
#
# Safe to re-run. Every step checks whether it is already done and skips it, so a run that failed
# halfway can simply be run again.
#
# Two independent things must be true before an indexer serves a paid query, and missing either one
# produces a 402 that looks identical:
#
#   1. the SIGNER is authorised by the AUTHORIZER on GraphTallyCollector
#   2. the AUTHORIZER has escrow deposited for (collector, receiver)
#
# Escrow is keyed on (payer, collector, receiver), so step 2 is per indexer. Query fees are trivial;
# the locked capital is the real cost of coverage.
#
# NOTE: no `set -e`. Failures are checked and reported explicitly, because a bare exit part-way
# through a sequence of transactions tells you nothing about which ones landed.
set -uo pipefail

export PATH="$HOME/.foundry/bin:$PATH"

RPC="${RPC:-https://arb1.arbitrum.io/rpc}"
CHAIN_ID=42161

# Arbitrum One, from packages/horizon/addresses.json. GraphTallyCollector cross-checked on-chain
# against SubgraphService.getGraphTallyCollector().
COLLECTOR=0x8f69F5C07477Ac46FBc491B1E6D91E2bb0111A9e
ESCROW=0xf6Fcc27aAf1fcD8B254498c9794451d82afC673E
GRT=0x9623063377AD1B27544C965cCd7342f7EA7e88C7

RECEIVER="${RECEIVER:-0xf92f430dd8567b0d466358c79594ab58d919a6d4}"   # ellipfra
DEPOSIT_GRT="${DEPOSIT_GRT:-10}"
DEADLINE_SECS="${DEADLINE_SECS:-3600}"

PROBE_URL="${PROBE_URL:-https://graph-l2prod.ellipfra.com/}"
PROBE_ALLOC="${PROBE_ALLOC:-0x1b4a6c9695132f4bcd554100ca86c8dc94dbf444}"
PROBE_DEPLOYMENT="${PROBE_DEPLOYMENT:-Qmbsc6XQWbiv4DfLVfaNciScqYLyDWUYjWzrFBbzzmRsMB}"

EXECUTE=0
[[ "${1:-}" == "--execute" ]] && EXECUTE=1

# ── output ────────────────────────────────────────────────────────────────────
if [[ -t 1 ]]; then G=$'\e[32m'; Y=$'\e[33m'; R=$'\e[31m'; B=$'\e[1m'; N=$'\e[0m'; else G=; Y=; R=; B=; N=; fi
ok()   { echo "  ${G}ok${N}    $*"; }
warn() { echo "  ${Y}warn${N}  $*"; }
fail() { echo "  ${R}FAIL${N}  $*"; }
step() { echo; echo "${B}$*${N}"; }
die()  { echo; fail "$*"; echo; exit 1; }

next_command() {
  echo
  echo "prove a paid query end to end:"
  echo
  echo "  TAP_VERIFIER=$COLLECTOR TAP_PAYER=$AUTHORIZER SIGNER_PK=\$SIGNER_PK \\"
  echo "    cargo run --example probe -- $PROBE_URL $RECEIVER \\"
  echo "      $PROBE_ALLOC $PROBE_DEPLOYMENT"
  echo
  echo "HTTP 200 with subgraph data means the whole pipeline works."
}

step "preflight"

command -v cast >/dev/null || die "foundry's 'cast' is not on PATH. install: curl -L https://foundry.paradigm.xyz | bash"
ok "cast present"

[[ -n "${AUTHORIZER_PK:-}" ]] || die "set AUTHORIZER_PK - the funded account that pays gas and holds escrow"
[[ -n "${SIGNER_PK:-}" ]]     || die "set SIGNER_PK - a FRESH key for the prober. it only signs receipts and never moves funds, so it is the one that belongs on a server"

AUTHORIZER=$(cast wallet address --private-key "$AUTHORIZER_PK" 2>/dev/null) || die "AUTHORIZER_PK is not a valid private key"
SIGNER=$(cast wallet address --private-key "$SIGNER_PK" 2>/dev/null)         || die "SIGNER_PK is not a valid private key"
[[ "$AUTHORIZER" != "$SIGNER" ]] || warn "authorizer and signer are the same key - it works, but then the key on your server holds your funds"

ACTUAL_CHAIN=$(cast chain-id --rpc-url "$RPC" 2>/dev/null) || die "cannot reach RPC $RPC"
[[ "$ACTUAL_CHAIN" == "$CHAIN_ID" ]] || die "RPC reports chain $ACTUAL_CHAIN, expected $CHAIN_ID (Arbitrum One). the addresses in this script are mainnet only"
ok "rpc ok, chain $ACTUAL_CHAIN"

# A typo'd address accepts calls silently and returns nothing, surfacing much later as an
# inexplicable revert. Check there is code at each one.
for pair in "collector:$COLLECTOR" "escrow:$ESCROW" "grt:$GRT"; do
  name="${pair%%:*}"; addr="${pair##*:}"
  code=$(cast code "$addr" --rpc-url "$RPC" 2>/dev/null)
  [[ ${#code} -gt 2 ]] || die "$name at $addr has no contract code on chain $ACTUAL_CHAIN"
done
ok "collector, escrow and grt all have code"

ETH_WEI=$(cast balance "$AUTHORIZER" --rpc-url "$RPC" 2>/dev/null || echo 0)
GRT_WEI=$(cast call "$GRT" "balanceOf(address)(uint256)" "$AUTHORIZER" --rpc-url "$RPC" 2>/dev/null | awk '{print $1}')
GRT_WEI="${GRT_WEI:-0}"
DEPOSIT_WEI=$(cast to-wei "$DEPOSIT_GRT" ether)

echo
ok "authorizer  $AUTHORIZER"
ok "  eth       $(cast from-wei "$ETH_WEI") ETH"
ok "  grt       $(cast from-wei "$GRT_WEI") GRT"
ok "signer      $SIGNER"
ok "receiver    $RECEIVER   (indexer to be paid)"
ok "deposit     $DEPOSIT_GRT GRT"

# python rather than bc: bc is not guaranteed present, and these are 256-bit values.
too_small() { python3 -c "import sys; sys.exit(0 if int(sys.argv[1]) < int(sys.argv[2]) else 1)" "$1" "$2"; }
if too_small "$ETH_WEI" 1000000000000000; then
  warn "low ETH for gas - three Arbitrum transactions want roughly 0.001 ETH"
fi
if too_small "$GRT_WEI" "$DEPOSIT_WEI"; then
  die "authorizer holds $(cast from-wei "$GRT_WEI") GRT, less than the $DEPOSIT_GRT GRT deposit"
fi

# ── what is already true ──────────────────────────────────────────────────────
step "current state"

ALREADY_AUTH=$(cast call "$COLLECTOR" "isAuthorized(address,address)(bool)" "$AUTHORIZER" "$SIGNER" --rpc-url "$RPC" 2>/dev/null)
ESCROW_BAL=$(cast call "$ESCROW" "getBalance(address,address,address)(uint256)" "$AUTHORIZER" "$COLLECTOR" "$RECEIVER" --rpc-url "$RPC" 2>/dev/null | awk '{print $1}')
ESCROW_BAL="${ESCROW_BAL:-0}"

[[ "$ALREADY_AUTH" == "true" ]] && ok "signer already authorised" || warn "signer not authorised yet"
[[ "$ESCROW_BAL" != "0" ]] && ok "escrow funded: $(cast from-wei "$ESCROW_BAL") GRT" || warn "no escrow for this indexer yet"

if [[ "$ALREADY_AUTH" == "true" && "$ESCROW_BAL" != "0" ]]; then
  step "nothing to do"
  ok "already set up"
  next_command
  exit 0
fi

# ── the authorisation proof ───────────────────────────────────────────────────
step "authorisation proof"

# Authorizable._verifyAuthorizationProof (Authorizable.sol:165):
#   keccak256(abi.encodePacked(chainid, address(this), "authorizeSignerProof", deadline, msg.sender))
# then toEthSignedMessageHash, recovered against the signer.
#
# encodePacked has no padding and no length prefix on the string, so this is assembled by hand.
# cast abi-encode would pad every field to 32 bytes and produce a hash the contract never computes.
DEADLINE=$(( $(date +%s) + DEADLINE_SECS ))
CHAIN_HEX=$(printf '%064x' "$CHAIN_ID")
DEADLINE_HEX=$(printf '%064x' "$DEADLINE")
DOMAIN_HEX=$(printf 'authorizeSignerProof' | xxd -p -c 256)
PACKED="0x${CHAIN_HEX}${COLLECTOR#0x}${DOMAIN_HEX}${DEADLINE_HEX}${AUTHORIZER#0x}"
MESSAGE_HASH=$(cast keccak "$PACKED")

# NOT --no-hash. cast treats 0x-prefixed input as hex bytes and applies the Ethereum Signed Message
# prefix, which is what the contract recomputes. --no-hash signs the bare hash, recovers to a
# different address, and reverts as AuthorizableInvalidSignerProof.
PROOF=$(cast wallet sign --private-key "$SIGNER_PK" "$MESSAGE_HASH" 2>/dev/null) || die "could not sign the proof"

if cast wallet verify --address "$SIGNER" "$MESSAGE_HASH" "$PROOF" >/dev/null 2>&1; then
  ok "proof recovers to the signer"
else
  fail "proof does NOT recover to $SIGNER"
  echo "        packed  $PACKED"
  echo "        hash    $MESSAGE_HASH"
  die "not sending - authorizeSigner would revert and the gas would be wasted"
fi
ok "deadline $DEADLINE"

# ── plan ──────────────────────────────────────────────────────────────────────
step "plan"
if [[ "$ALREADY_AUTH" == "true" ]]; then
  ok "skip  authorizeSigner (already authorised)"
else
  echo "  send  GraphTallyCollector.authorizeSigner($SIGNER, $DEADLINE, <proof>)"
fi
if [[ "$ESCROW_BAL" == "0" ]]; then
  echo "  send  GRT.approve($ESCROW, $DEPOSIT_WEI)"
  echo "  send  PaymentsEscrow.deposit($COLLECTOR, $RECEIVER, $DEPOSIT_WEI)"
else
  ok "skip  approve and deposit (escrow already funded)"
fi

if [[ "$EXECUTE" -eq 0 ]]; then
  step "dry run"
  ok "nothing sent. re-run with --execute"
  exit 0
fi

# ── execute ───────────────────────────────────────────────────────────────────
# Reports the tx hash and the receipt status for each send, and treats a reverted receipt as a
# failure. `cast send` exits zero on a mined-but-reverted transaction, so checking status matters.
send() {
  local label="$1"; shift
  echo "  sending $label ..."
  local out rc
  out=$(cast send "$@" --private-key "$AUTHORIZER_PK" --rpc-url "$RPC" --json 2>&1); rc=$?
  if [[ $rc -ne 0 ]]; then
    fail "$label did not send"
    echo "$out" | sed 's/^/        /' | head -12
    return 1
  fi
  local tx status
  tx=$(echo "$out" | python3 -c 'import json,sys; print(json.load(sys.stdin).get("transactionHash",""))' 2>/dev/null)
  status=$(echo "$out" | python3 -c 'import json,sys; print(json.load(sys.stdin).get("status",""))' 2>/dev/null)
  if [[ "$status" == "0x1" || "$status" == "1" ]]; then
    ok "$label  $tx"
    return 0
  fi
  fail "$label reverted (status ${status:-unknown})  $tx"
  return 1
}

if [[ "$ALREADY_AUTH" != "true" ]]; then
  step "1/3 authorise signer"
  send "authorizeSigner" "$COLLECTOR" "authorizeSigner(address,uint256,bytes)" "$SIGNER" "$DEADLINE" "$PROOF" \
    || die "authorizeSigner failed. usual causes: the signer is already authorised by a different account, or the deadline passed"
  # Verify on chain rather than trusting the receipt.
  [[ "$(cast call "$COLLECTOR" 'isAuthorized(address,address)(bool)' "$AUTHORIZER" "$SIGNER" --rpc-url "$RPC" 2>/dev/null)" == "true" ]] \
    || die "transaction succeeded but isAuthorized still reads false"
  ok "confirmed on chain"
fi

if [[ "$ESCROW_BAL" == "0" ]]; then
  step "2/3 approve GRT"
  send "approve" "$GRT" "approve(address,uint256)" "$ESCROW" "$DEPOSIT_WEI" || die "approve failed"

  step "3/3 deposit escrow"
  send "deposit" "$ESCROW" "deposit(address,address,uint256)" "$COLLECTOR" "$RECEIVER" "$DEPOSIT_WEI" \
    || die "deposit failed. check whether the approve actually landed"
  NEW_BAL=$(cast call "$ESCROW" "getBalance(address,address,address)(uint256)" "$AUTHORIZER" "$COLLECTOR" "$RECEIVER" --rpc-url "$RPC" 2>/dev/null | awk '{print $1}')
  [[ "${NEW_BAL:-0}" != "0" ]] || die "deposit succeeded but the balance still reads zero"
  ok "confirmed on chain: $(cast from-wei "$NEW_BAL") GRT in escrow"
fi

step "done"
ok "signer authorised and escrow funded for $RECEIVER"
next_command
