use alloy::{
    primitives::address,
    providers::{Provider, ProviderBuilder, WsConnect},
    rpc::types::{BlockNumberOrTag, Filter},
};
use eyre::Result;
use futures_util::stream::StreamExt;

#[tokio::main]
async fn main() -> Result<()> {
    let rpc_urls: Vec<String> = std::env::var("RPC_URLS")
        .unwrap_or(
            "wss://interop-devnet-0.optimism.io/,wss://interop-devnet-1.optimism.io/".to_string(),
        )
        .split(',')
        .map(|s| s.to_string())
        .collect();

    for rpc_url in rpc_urls {
        subscribe_to_events(&rpc_url).await?;
    }

    Ok(())
}

async fn subscribe_to_events(rpc_url: &str) -> Result<()> {
    let ws = WsConnect::new(rpc_url);
    let provider = ProviderBuilder::new().on_ws(ws).await?;

    // Create a filter to watch for l2-l2 events
    let l2_l2_xdomain_messenger_address = address!("4200000000000000000000000000000000000023");
    let filter = Filter::new()
        .address(l2_l2_xdomain_messenger_address)
        .event("SentMessage(uint256,address,uint256,address,bytes)")
        .from_block(BlockNumberOrTag::Latest);

    // Subscribe to logs.
    let sub = provider.subscribe_logs(&filter).await?;
    let mut stream = sub.into_stream();

    while let Some(log) = stream.next().await {
        println!("L2 contract token logs: {log:?}");
        //if we it matches, then we do next section.
    }

    Ok(())
}
