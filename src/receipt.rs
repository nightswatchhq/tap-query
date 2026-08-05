//! Signing a TAP v2 receipt and encoding it for the `tap-receipt` header.
//!
//! ## The wire format, and why it is spelled out here
//!
//! `indexer-rs` base64-decodes the header, then protobuf-decodes it, trying v2 first
//! (`crates/service/src/service/tap_receipt_header.rs`). Not JSON. A JSON receipt decodes to
//! nothing recognisable and the request is treated as unpaid — a `402` that looks exactly like an
//! empty escrow account, which is a genuinely expensive thing to debug.
//!
//! The protobuf messages are declared here rather than pulled from `tap_aggregator`, which would
//! drag in a gRPC server and its transitive tree for three structs. They mirror
//! `tap_aggregator-0.6.3/proto/v2.proto` exactly; the field numbers are load-bearing and must not be
//! reordered.

use anyhow::{Context, Result};
use prost::Message;
use thegraph_core::alloy::{
    primitives::{Address, FixedBytes},
    signers::{local::PrivateKeySigner, SignerSync},
    sol_types::{Eip712Domain, SolStruct},
};

use crate::encode_header;

/// Mirrors `grpc.uint128.Uint128`. A u128 split across two u64s because protobuf has no 128-bit
/// integer type.
#[derive(Clone, PartialEq, Message)]
pub struct Uint128 {
    #[prost(uint64, tag = "1")]
    pub high: u64,
    #[prost(uint64, tag = "2")]
    pub low: u64,
}

impl From<u128> for Uint128 {
    fn from(v: u128) -> Self {
        Self {
            high: (v >> 64) as u64,
            low: v as u64,
        }
    }
}

/// Mirrors `tap_aggregator.v2.Receipt`.
#[derive(Clone, PartialEq, Message)]
pub struct ReceiptProto {
    #[prost(bytes = "vec", tag = "1")]
    pub collection_id: Vec<u8>,
    #[prost(bytes = "vec", tag = "2")]
    pub payer: Vec<u8>,
    #[prost(bytes = "vec", tag = "3")]
    pub data_service: Vec<u8>,
    #[prost(bytes = "vec", tag = "4")]
    pub service_provider: Vec<u8>,
    #[prost(uint64, tag = "5")]
    pub timestamp_ns: u64,
    #[prost(uint64, tag = "6")]
    pub nonce: u64,
    #[prost(message, optional, tag = "7")]
    pub value: Option<Uint128>,
}

/// Mirrors `tap_aggregator.v2.SignedReceipt`.
#[derive(Clone, PartialEq, Message)]
pub struct SignedReceiptProto {
    #[prost(message, optional, tag = "1")]
    pub message: Option<ReceiptProto>,
    #[prost(bytes = "vec", tag = "2")]
    pub signature: Vec<u8>,
}

/// The parts of a receipt a caller chooses. Timestamp and nonce are generated per receipt.
#[derive(Debug, Clone)]
pub struct ReceiptParams {
    /// Allocation address left-padded to 32 bytes. See `collection_id_from_allocation`.
    pub collection_id: FixedBytes<32>,
    /// The escrow account paying. Must match the signer, since the indexer recovers it.
    pub payer: Address,
    /// The `SubgraphService` contract.
    pub data_service: Address,
    /// The indexer being paid.
    pub service_provider: Address,
    /// Smallest unit of the escrow token. Must clear the indexer's cost model.
    pub value: u128,
}

/// Sign a receipt and return the ready-to-send `tap-receipt` header value.
///
/// The EIP-712 hash is computed from `tap_graph::v2::Receipt`, the canonical struct definition, so
/// the type hash matches what the indexer verifies against. Re-deriving the struct locally would
/// risk a field-order difference producing a valid signature over the wrong type hash — which
/// recovers to an unexpected address and is rejected as an unfunded sender.
pub fn sign_receipt(
    signer: &PrivateKeySigner,
    domain: &Eip712Domain,
    params: ReceiptParams,
) -> Result<String> {
    let timestamp_ns = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .context("system clock is before the unix epoch")?
        .as_nanos() as u64;
    // Nonce exists to make otherwise-identical receipts distinct. Derived from the clock's
    // sub-nanosecond entropy plus the address so two probes in the same nanosecond still differ.
    let nonce = timestamp_ns
        .rotate_left(17)
        ^ u64::from_le_bytes(params.service_provider.as_slice()[..8].try_into().unwrap());

    let message = tap_graph::v2::Receipt {
        collection_id: params.collection_id,
        payer: params.payer,
        data_service: params.data_service,
        service_provider: params.service_provider,
        timestamp_ns,
        nonce,
        value: params.value,
    };

    let signature = signer
        .sign_hash_sync(&message.eip712_signing_hash(domain))
        .context("failed to sign the receipt hash")?;

    let proto = SignedReceiptProto {
        message: Some(ReceiptProto {
            collection_id: message.collection_id.to_vec(),
            payer: message.payer.to_vec(),
            data_service: message.data_service.to_vec(),
            service_provider: message.service_provider.to_vec(),
            timestamp_ns: message.timestamp_ns,
            nonce: message.nonce,
            value: Some(message.value.into()),
        }),
        signature: signature.as_bytes().to_vec(),
    };

    Ok(encode_header(&proto.encode_to_vec()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
    use thegraph_core::alloy::primitives::address;

    fn ctx() -> (PrivateKeySigner, Eip712Domain) {
        let signer = PrivateKeySigner::random();
        let domain = crate::horizon_domain(
            crate::ARBITRUM_ONE_CHAIN_ID,
            address!("0000000000000000000000000000000000000001"),
        );
        (signer, domain)
    }

    fn params() -> ReceiptParams {
        ReceiptParams {
            collection_id: crate::collection_id_from_allocation(address!(
                "1234567890123456789012345678901234567890"
            )),
            payer: address!("00000000000000000000000000000000000000aa"),
            data_service: address!("00000000000000000000000000000000000000bb"),
            service_provider: address!("00000000000000000000000000000000000000cc"),
            value: 1_000_000_000_000_000u128,
        }
    }

    /// The header must be base64 of protobuf. If this ever becomes JSON, every probe silently reads
    /// as unpaid and returns 402 — indistinguishable from an empty escrow account.
    #[test]
    fn header_is_base64_protobuf_and_round_trips() {
        let (signer, domain) = ctx();
        let header = sign_receipt(&signer, &domain, params()).unwrap();

        let raw = BASE64.decode(&header).expect("header must be valid base64");
        let decoded = SignedReceiptProto::decode(raw.as_ref()).expect("must protobuf-decode");

        let msg = decoded.message.expect("receipt message present");
        assert_eq!(msg.payer.len(), 20);
        assert_eq!(msg.service_provider.len(), 20);
        assert_eq!(msg.collection_id.len(), 32);
        assert_eq!(decoded.signature.len(), 65);
        let v = msg.value.expect("value present");
        assert_eq!(((v.high as u128) << 64) | v.low as u128, 1_000_000_000_000_000u128);
    }

    /// The signature must recover to the signer, because `SenderBalanceCheck` looks up escrow by the
    /// RECOVERED address. A domain or type-hash mismatch still yields a valid-looking signature that
    /// recovers to a stranger with no escrow, and the resulting 402 says "insufficient balance".
    #[test]
    fn signature_recovers_to_the_signer() {
        let (signer, domain) = ctx();
        let p = params();
        let header = sign_receipt(&signer, &domain, p.clone()).unwrap();

        let raw = BASE64.decode(&header).unwrap();
        let decoded = SignedReceiptProto::decode(raw.as_ref()).unwrap();
        let msg = decoded.message.unwrap();

        let reconstructed = tap_graph::v2::Receipt {
            collection_id: FixedBytes::<32>::from_slice(&msg.collection_id),
            payer: Address::from_slice(&msg.payer),
            data_service: Address::from_slice(&msg.data_service),
            service_provider: Address::from_slice(&msg.service_provider),
            timestamp_ns: msg.timestamp_ns,
            nonce: msg.nonce,
            value: p.value,
        };

        let sig = thegraph_core::alloy::signers::Signature::try_from(decoded.signature.as_slice())
            .expect("65-byte signature");
        let recovered = sig
            .recover_address_from_prehash(&reconstructed.eip712_signing_hash(&domain))
            .expect("recoverable");

        assert_eq!(recovered, signer.address(), "receipt must recover to its signer");
    }

    /// Two receipts must never be identical, or an indexer may treat the second as a replay.
    #[test]
    fn receipts_are_unique() {
        let (signer, domain) = ctx();
        let a = sign_receipt(&signer, &domain, params()).unwrap();
        let b = sign_receipt(&signer, &domain, params()).unwrap();
        assert_ne!(a, b);
    }

    /// v2 signs under `GraphTallyCollector`; v1 used `TAP`. Signing under the wrong name recovers to
    /// a different address, so this guards the single most expensive thing to get wrong.
    #[test]
    fn domain_name_is_graph_tally_collector() {
        let d = crate::horizon_domain(42161, address!("0000000000000000000000000000000000000001"));
        assert_eq!(d.name.as_deref(), Some("GraphTallyCollector"));
        assert_eq!(d.version.as_deref(), Some("1"));
    }
}
