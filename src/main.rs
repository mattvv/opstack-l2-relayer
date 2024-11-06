use alloy::{
    primitives::{address, Address, U256},
    providers::{Provider, ProviderBuilder, WsConnect},
    rpc::types::{BlockNumberOrTag, Filter},
};

use alloy_rpc_types_eth::Log;
use eyre::Result;
use futures_util::stream::StreamExt;

struct Identifier {
    origin: Address,
    block_number: U256,
    log_index: U256,
    timestamp: U256,
    chain_id: U256,
}

struct SentMessage {
    destination: U256,
    target: Address,
    message_nonce: U256,
    sender: Address,
    message: Vec<u8>,
    block_number: U256,
    timestamp: U256,

    chain_id: U256,
}

impl SentMessage {
    fn from_log(chain_id: U256, log: Log) -> Self {
        let block_number = U256::from(log.block_number.unwrap());
        let timestamp = U256::from(log.block_timestamp.unwrap());

        let topics = log.topics();
        if topics.len() != 4 {
            panic!("Invalid number of topics");
        }

        let log_data = log.data().clone();
        log_data.data.len();
        if log_data.data.len() < 20 {
            panic!("Invalid data length");
        }

        let _signature = topics[0];

        let dest_bytes = topics[1].as_slice();
        let destination = U256::from_be_slice(dest_bytes);

        let target = Address::from_word(topics[2].into());
        let message_nonce: U256 = topics[3].into();

        let sender_bytes = log_data.data[0..20].to_vec();
        let sender = Address::from_slice(&sender_bytes);

        let message = log_data.data[20..].to_vec();

        Self {
            destination,
            target,
            message_nonce,
            sender,
            message,
            block_number,
            timestamp,
            chain_id,
        }
    }

    fn id(&self) -> Identifier {
        Identifier {
            origin: self.sender,
            block_number: self.block_number,
            log_index: self.message_nonce,
            timestamp: self.timestamp,
            chain_id: self.chain_id,
        }
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let rpc_urls: Vec<String> = std::env::var("RPC_URLS")
        .unwrap_or(
            "https://interop-devnet-0.optimism.io/,https://interop-devnet-1.optimism.io/"
                .to_string(),
        )
        .split(',')
        .map(|s| s.to_string())
        .collect();

    let mut handles = Vec::new();
    for rpc_url in rpc_urls {
        if rpc_url.starts_with("ws") {
            let handle = tokio::spawn(async move { subscribe_to_events_ws(&rpc_url).await });
            handles.push(handle);
            continue;
        }

        let handle = tokio::spawn(async move { subscribe_to_events_http(&rpc_url).await });
        handles.push(handle);
    }

    for handle in handles {
        handle.await??;
    }

    Ok(())
}

async fn subscribe_to_events_ws(rpc_url: &str) -> Result<()> {
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

async fn subscribe_to_events_http(rpc_url: &str) -> Result<()> {
    let provider = ProviderBuilder::new().on_http(rpc_url.parse().expect("Invalid RPC"));

    let l2_l2_xdomain_messenger_address = address!("4200000000000000000000000000000000000023");
    let filter = Filter::new()
        .address(l2_l2_xdomain_messenger_address)
        .event("SentMessage(uint256,address,uint256,address,bytes)")
        .from_block(BlockNumberOrTag::Latest);

    let latest_block = provider.get_block_number().await?;

    let mut from_block = latest_block;
    loop {
        println!("Checking RPC: {} from block {}", rpc_url, from_block);
        let latest_block = provider.get_block_number().await?;
        let logs = provider
            .get_logs(&filter.clone().from_block(from_block))
            .await?;
        for log in logs {
            println!("L2 contract token logs: {log:?}");
        }

        from_block = latest_block;
        tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;
    }
}
