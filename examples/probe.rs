//! Send one signed receipt to a real indexer and report exactly why it was accepted or refused.
//!
//! Run with a RANDOM key and no escrow on purpose. A rejection that names our address and complains
//! about *balance* proves everything upstream of funding is correct: the header decoded, the
//! protobuf parsed, the EIP-712 domain matched, and the signature recovered to the address we
//! signed with. Only the money is missing.
//!
//! A rejection that says the receipt is missing or malformed means the opposite, and no amount of
//! funding would fix it.
//!
//! Usage:
//!   cargo run --example probe -- <indexer_url> <indexer_address> <allocation> <deployment>

use std::time::Duration;

use tap_query::{PaidQueryClient, PaymentContext, ARBITRUM_ONE_CHAIN_ID};
use thegraph_core::alloy::{primitives::Address, signers::local::PrivateKeySigner};

/// GraphTallyCollector on Arbitrum One — the EIP-712 verifying contract for Horizon receipts.
/// Override with TAP_VERIFIER when the deployment differs.
const DEFAULT_VERIFIER: &str = "0x0000000000000000000000000000000000000000";
/// SubgraphService — checked by the indexer's DataServiceCheck. Override with TAP_DATA_SERVICE.
const DEFAULT_DATA_SERVICE: &str = "0xb2Bb92d0DE618878E438b55D5846cfecD9301105";

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.len() < 4 {
        eprintln!("usage: probe <indexer_url> <indexer_address> <allocation> <deployment>");
        std::process::exit(2);
    }
    let (url, indexer, allocation, deployment) = (&args[0], &args[1], &args[2], &args[3]);

    let verifier: Address = std::env::var("TAP_VERIFIER")
        .unwrap_or_else(|_| DEFAULT_VERIFIER.into())
        .parse()?;
    let data_service: Address = std::env::var("TAP_DATA_SERVICE")
        .unwrap_or_else(|_| DEFAULT_DATA_SERVICE.into())
        .parse()?;

    // A real signer if one is supplied, otherwise random and unfunded - random still proves the
    // wire format, because the refusal names the address it recovered.
    let signer: PrivateKeySigner = match std::env::var("SIGNER_PK") {
        Ok(pk) => pk.parse().map_err(|e| anyhow::anyhow!("bad SIGNER_PK: {e}"))?,
        Err(_) => PrivateKeySigner::random(),
    };
    // The payer is the escrow account that authorised the signer. They are usually different
    // addresses: the signer signs receipts, the payer holds the money.
    let payer: Address = match std::env::var("TAP_PAYER") {
        Ok(a) => a.parse()?,
        Err(_) => signer.address(),
    };

    let ctx = PaymentContext {
        chain_id: ARBITRUM_ONE_CHAIN_ID,
        verifier,
        data_service,
        payer,
    };

    // Captured before the signer moves into the client, since the verdict below needs it.
    let signer_address = signer.address();
    println!("signing as   {signer_address}");
    println!("payer        {payer}");
    println!("verifier     {verifier}");
    println!("data_service {data_service}");
    println!("indexer      {indexer}");
    println!("allocation   {allocation}");
    println!();

    let client = PaidQueryClient::new(signer, ctx, Duration::from_secs(30))?;
    let resp = client
        .query(
            url,
            indexer.parse()?,
            allocation.parse()?,
            deployment,
            r#"{"query":"{ _meta { block { number } } }"}"#,
            1_000_000_000_000u128,
        )
        .await?;

    println!("HTTP {} in {}ms", resp.status, resp.latency_ms);
    println!("{}", resp.body.chars().take(400).collect::<String>());
    println!();

    // The whole point of the exercise.
    let body = resp.body.to_lowercase();
    if resp.status == 200 {
        println!("=> SERVED. receipt accepted and paid for.");
    } else if body.contains("balance") || body.contains("escrow") || body.contains("no sender") {
        // The refusal usually quotes the address it recovered. If that is NOT our signer, the
        // problem is the domain or encoding, not the funding - and an earlier version of this
        // example happily reported success in exactly that case.
        let ours = format!("{signer_address:?}").to_lowercase();
        if body.contains(&ours[2..]) {
            println!("=> WIRE FORMAT VERIFIED. It decoded our receipt and recovered OUR address,");
            println!("   refusing only for escrow. Authorise this signer and fund it.");
        } else {
            println!("=> ADDRESS MISMATCH. It recovered someone else, so the domain or encoding is");
            println!("   wrong. Check TAP_VERIFIER - funding will not fix this.");
        }
    } else if body.contains("denylist") {
        // Distinct from unfunded: the indexer's tap-agent tracks escrow via the escrow subgraph and
        // denylists senders it believes are empty. After a fresh deposit there is a propagation
        // delay before it removes you, so this is usually "wait", not "wrong".
        println!("=> DENYLISTED. Their tap-agent has not seen the escrow deposit yet, or has");
        println!("   denylisted this sender. Usually transient after funding - retry later.");
    } else if body.contains("no tap receipt") || body.contains("not found") {
        println!("=> RECEIPT NOT SEEN. Header name or encoding is wrong; funding would not help.");
    } else if body.contains("signature") || body.contains("recover") || body.contains("invalid") {
        println!("=> SIGNATURE REJECTED. Domain, type hash or encoding is wrong.");
    } else {
        println!("=> Unrecognised rejection; read the body above.");
    }
    Ok(())
}
