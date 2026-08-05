//! Pay The Graph's indexers directly, without a gateway.
//!
//! Every indexer answers an unpaid query with `402 No Tap receipt was found in the request`. The
//! gateway normally handles payment, which means anyone measuring indexer quality has to route
//! through a gateway and accept whichever indexer it picks. That is fine for serving users and
//! useless for measurement: you cannot observe an indexer the gateway declines to route to, so
//! failures it already avoids are invisible and any success rate you compute is an upper bound.
//!
//! This crate removes the gateway from that path. Sign a TAP receipt, attach it, query the indexer
//! you actually want.
//!
//! ## Permissionless by design
//!
//! Worth stating because it is not obvious and it is the reason this crate can exist. Reading
//! `indexer-rs` (`crates/service/src/tap.rs`), a receipt passes ten checks, and the one governing
//! *who may pay* is `SenderBalanceCheck`: escrow balance greater than zero. There is a **denylist**
//! (`tap_horizon_denylist`), not an allowlist. No relationship with any gateway operator is
//! required — fund escrow and you may pay any indexer.
//!
//! ## Scope
//!
//! Signing and sending. Escrow funding, RAV aggregation and on-chain redemption are the payee's
//! side of the protocol and deliberately out of scope: a prober only needs to pay, never to collect.

use anyhow::{Context, Result};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use thegraph_core::alloy::{
    primitives::{FixedBytes, U256},
    sol_types::Eip712Domain,
};

pub mod receipt;

pub use receipt::{sign_receipt, ReceiptParams};

/// Re-exported so callers do not have to depend on `thegraph-core` just to name an address, and so
/// they cannot accidentally pull a different alloy version than the one receipts are signed with.
pub use thegraph_core::alloy::primitives::Address;
/// Re-exported for the same reason as `Address`: callers must sign with the same alloy version the
/// receipts are built with, and pulling their own risks a silent second copy in the tree.
pub use thegraph_core::alloy::signers::local::PrivateKeySigner;

/// EIP-712 domain for Horizon (TAP v2) receipts.
///
/// Mirrors `tap_core::tap_eip712_domain(chain_id, verifier, TapVersion::V2)`, reproduced here so a
/// caller can see exactly what is being signed. The domain name is **`GraphTallyCollector`** for v2
/// (v1 used `"TAP"`); signing under the wrong name produces a well-formed receipt that recovers to
/// the wrong address, which an indexer rejects in a way indistinguishable from an unfunded escrow.
pub fn horizon_domain(chain_id: u64, verifier: Address) -> Eip712Domain {
    thegraph_core::alloy::sol_types::eip712_domain! {
        name: "GraphTallyCollector",
        version: "1",
        chain_id: chain_id,
        verifying_contract: verifier,
    }
}

/// Arbitrum One.
pub const ARBITRUM_ONE_CHAIN_ID: u64 = 42161;

/// A collection identifier, as the receipt carries it.
///
/// Under Horizon this is the allocation address left-padded into 32 bytes — the low 20 bytes are the
/// allocation, the high 12 are zero. Matches `CollectionId::from(AllocationId)` in `thegraph-core`.
/// Constructing it by hand rather than depending on that conversion keeps the wire format explicit,
/// because getting it wrong yields a receipt that verifies and then fails allocation-eligibility.
pub fn collection_id_from_allocation(allocation: Address) -> FixedBytes<32> {
    let mut buf = [0u8; 32];
    buf[12..].copy_from_slice(allocation.as_slice());
    FixedBytes::<32>::from(buf)
}

/// Everything needed to pay one indexer for one query.
#[derive(Debug, Clone)]
pub struct PaymentContext {
    /// Chain the escrow and collector live on.
    pub chain_id: u64,
    /// The `GraphTallyCollector` contract — the EIP-712 verifying contract.
    pub verifier: Address,
    /// The `SubgraphService` contract. Checked by the indexer's `DataServiceCheck` against its own
    /// allowed list, so a mismatch is rejected even when everything else is valid.
    pub data_service: Address,
    /// The escrow account paying. Recovered from the signature, so it must match the funded account.
    pub payer: Address,
}

/// A client that pays for what it queries.
pub struct PaidQueryClient {
    http: reqwest::Client,
    signer: PrivateKeySigner,
    ctx: PaymentContext,
}

impl PaidQueryClient {
    pub fn new(signer: PrivateKeySigner, ctx: PaymentContext, timeout: std::time::Duration) -> Result<Self> {
        Ok(Self {
            http: reqwest::Client::builder().timeout(timeout).build()?,
            signer,
            ctx,
        })
    }

    /// The address receipts will be signed by, which is the escrow account that must hold a balance.
    pub fn signer_address(&self) -> Address {
        self.signer.address()
    }

    /// Query one indexer for one deployment, paying for it.
    ///
    /// `indexer_url` is the indexer's service endpoint; the deployment path is appended, matching
    /// what the gateway does. `value` is in the escrow token's smallest unit and must clear the
    /// indexer's cost model — `MinimumValue` rejects an underpriced receipt, so paying too little
    /// looks like a refusal to serve rather than a pricing error.
    pub async fn query(
        &self,
        indexer_url: &str,
        indexer_address: Address,
        allocation: Address,
        deployment_ipfs_hash: &str,
        query: &str,
        value: u128,
    ) -> Result<PaidResponse> {
        let params = ReceiptParams {
            collection_id: collection_id_from_allocation(allocation),
            payer: self.ctx.payer,
            data_service: self.ctx.data_service,
            service_provider: indexer_address,
            value,
        };
        let header = sign_receipt(&self.signer, &self.ctx.domain(), params)
            .context("failed to sign TAP receipt")?;

        let url = format!(
            "{}/subgraphs/id/{}",
            indexer_url.trim_end_matches('/'),
            deployment_ipfs_hash
        );

        let started = std::time::Instant::now();
        let resp = self
            .http
            .post(&url)
            .header("tap-receipt", header)
            .header("content-type", "application/json")
            .body(query.to_string())
            .send()
            .await
            .context("indexer request failed")?;

        let status = resp.status().as_u16();
        let body = resp.text().await.unwrap_or_default();

        Ok(PaidResponse {
            status,
            body,
            latency_ms: started.elapsed().as_millis() as u64,
        })
    }
}

impl PaymentContext {
    pub fn domain(&self) -> Eip712Domain {
        horizon_domain(self.chain_id, self.verifier)
    }
}

#[derive(Debug, Clone)]
pub struct PaidResponse {
    pub status: u16,
    pub body: String,
    pub latency_ms: u64,
}

impl PaidResponse {
    /// A 402 means the receipt was refused, and the body says why.
    ///
    /// Distinguishing "escrow empty" from "receipt malformed" matters more than it looks: both
    /// arrive as 402, and treating a signing bug as an unfunded account sends you off to add money
    /// that will not help.
    pub fn payment_refused(&self) -> Option<&str> {
        (self.status == 402).then_some(self.body.as_str())
    }
}

/// Convenience: base64 of the protobuf encoding, which is what the `tap-receipt` header carries.
///
/// NOT JSON. `indexer-rs` base64-decodes then protobuf-decodes, trying v2 first. A JSON receipt
/// decodes to nothing recognisable and the query is treated as unpaid.
pub(crate) fn encode_header(bytes: &[u8]) -> String {
    BASE64.encode(bytes)
}

/// Escrow balance is checked as `> 0`, so this is a convenience rather than a rule.
pub fn has_balance(balance: U256) -> bool {
    balance > U256::ZERO
}
