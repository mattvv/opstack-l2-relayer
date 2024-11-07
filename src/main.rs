use alloy::core::sol;
use alloy::hex::ToHexExt;
use alloy::network::Ethereum;
use alloy::primitives::Bytes;
use alloy::providers::{PendingTransactionBuilder, RootProvider};
use alloy::transports::http::Client;
use alloy::{
    hex,
    network::EthereumWallet,
    primitives::{address, Address, U256},
    providers::{
        fillers::{
            BlobGasFiller, ChainIdFiller, FillProvider, GasFiller, JoinFill, NonceFiller,
            WalletFiller,
        },
        Provider, ProviderBuilder,
    },
    rpc::types::{BlockNumberOrTag, Filter},
    signers::local::PrivateKeySigner,
};
use alloy_rpc_types_eth::Log;
use alloy_transport_http::Http;
use std::collections::HashMap;
use std::sync::Arc;
// use alloy::alloy_sol_types::SolEvent;
use alloy::sol_types::{SolEvent, SolValue};
use eyre::Result;

const CROSS_DOMAIN_MESSENGER_ADDR: Address = address!("4200000000000000000000000000000000000023");

// const PRIVATE_KEY: &str = "96d4318ac13f2d9d131bd323a2e04a6913723b0f4ee052da6f9317b1fb50f910";

sol! {
    #[derive(Debug)]
    struct Identifier {
        address origin;
        uint256 blockNumber;
        uint256 logIndex;
        uint256 timestamp;
        uint256 chainId;
    }

    event SentMessage(
        uint256 indexed destination, address indexed target, uint256 indexed messageNonce, address sender, bytes message
    );

    #[sol(rpc)]
    contract L2ToL2CrossDomainMessenger {
        function relayMessage(Identifier calldata _id, bytes calldata _sentMessage) external payable;
    }
}

struct SentMessageWrapper {
    event: SentMessage,

    block_number: U256,
    log_index: u64,
    timestamp: U256,
    chain_id: U256,
}

impl SentMessageWrapper {
    // pub fn encode_event_data(&self) -> Result<(Vec<[u8; 32]>, Bytes), alloy::sol_types::Error> {
    //
    //     self.event.encode_data();
    //     // Get the event signature topic (keccak256 hash of the event signature)
    //     let sig_topic = self.selector();
    //
    //     // Encode indexed parameters
    //     let destination_topic = self.destination.encode_packed();
    //     let target_topic = self.target.encode_packed();
    //     let nonce_topic = self.message_nonce.encode_packed();
    //
    //     // Create topics array (signature + indexed parameters)
    //     let topics = vec![
    //         sig_topic,
    //         destination_topic,
    //         target_topic,
    //         nonce_topic,
    //     ];
    //
    //     // Encode non-indexed parameters
    //     let data = self.encode_data()?;
    //
    //     Ok((topics, data))
    // }

    pub fn from_log(chain_id: U256, log: Log) -> SentMessageWrapper {
        let block_number = U256::from(log.block_number.unwrap());
        let timestamp = U256::from(log.block_timestamp.unwrap_or(1730888072));
        let log_index = log.log_index.unwrap_or_default();

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

        let target = Address::from_word(topics[2]);
        let message_nonce: U256 = topics[3].into();

        let sender_bytes = log_data.data[0..20].to_vec();
        let sender = Address::from_slice(&sender_bytes);

        let message = Bytes::from(log_data.data[20..].to_vec());

        let event = SentMessage {
            destination,
            target,
            messageNonce: message_nonce,
            sender,
            message,
        };

        Self {
            event,
            block_number,
            log_index,
            timestamp,
            chain_id,
        }
    }

    pub fn id(&self) -> Identifier {
        Identifier {
            origin: CROSS_DOMAIN_MESSENGER_ADDR,
            blockNumber: self.block_number,
            logIndex: U256::from(self.log_index),
            timestamp: self.timestamp,
            chainId: U256::from(self.chain_id),
        }
    }

    // pub fn message(&self) -> Bytes {
    //     let mut selector = SentMessage::SIGNATURE_HASH.to_vec();

    //     let mut destination = self.event.destination.abi_encode();
    //     println!("Destination: {:?}", destination);
    //     let mut target = self.event.target.abi_encode();
    //     println!("Target: {:?}", target);
    //     let mut nonce = self.event.messageNonce.abi_encode();
    //     println!("Nonce: {:?}", nonce);
    //     let mut sender = self.event.sender.abi_encode();
    //     println!("Sender: {:?}", sender);

    //     selector.append(&mut destination);
    //     selector.append(&mut target);
    //     selector.append(&mut nonce);
    //     selector.append(&mut sender);

    //     let mut data = self.event.encode_data();
    //     selector.append(&mut data);

    //     Bytes::from(selector)
    //     // Bytes::from(self.event.encode_data())
    //     // self.event.message.clone()
    // }

    // pub fn serialized(&self) -> String {
    //     let ld = self.event.encode_log_data();
    //     ld.

    // }
}

async fn send_relay_message(
    provider: &HttpProvider,
    sent_message: SentMessageWrapper,
    payload: Vec<u8>,
) -> alloy_contract::Result<PendingTransactionBuilder<Http<Client>, Ethereum>> {
    let contract = L2ToL2CrossDomainMessenger::new(CROSS_DOMAIN_MESSENGER_ADDR, provider);
    let id = sent_message.id();

    // let msg = sent_message.message();

    // let mut selector = SentMessage::SIGNATURE_HASH.to_vec();
    // selector.append(&mut  payload);
    let msg = Bytes::from(payload);
    println!("selector: {:?}", SentMessage::SIGNATURE_HASH);
    println!("Sending relay message\nID:{:?}\nMsg:{:?}", id, msg);
    contract.relayMessage(id, msg).send().await
}

// type HttpProvider = FillProvider<JoinFill<alloy::providers::Identity, WalletFiller<EthereumWallet>>, RootProvider<Http<Client>>, alloy_transport_http::Http<Client>, Ethereum>;
type HttpProvider = FillProvider<
    JoinFill<
        JoinFill<
            alloy::providers::Identity,
            JoinFill<GasFiller, JoinFill<BlobGasFiller, JoinFill<NonceFiller, ChainIdFiller>>>,
        >,
        WalletFiller<EthereumWallet>,
    >,
    RootProvider<alloy_transport_http::Http<Client>>,
    alloy_transport_http::Http<Client>,
    Ethereum,
>;

async fn create_rpc_map(rpc_urls: Vec<String>) -> Result<HashMap<U256, HttpProvider>> {
    let mut providers = HashMap::new();

    let private_key = hex::decode(
        std::env::var("PRIVATE_KEY")
            .unwrap_or_else(|_| {
                "96d4318ac13f2d9d131bd323a2e04a6913723b0f4ee052da6f9317b1fb50f910".to_string()
            })
            .trim_start_matches("0x"),
    )
    .expect("Invalid private key");
    let signer = PrivateKeySigner::from_slice(&private_key)?;
    let wallet = EthereumWallet::from(signer);

    for rpc_url in rpc_urls {
        let provider = ProviderBuilder::new()
            .with_recommended_fillers()
            .wallet(wallet.clone())
            // .with_retry(RetryOptions::default())
            .on_http(rpc_url.parse().expect("Invalid RPC"));
        let chain_id = U256::from(provider.get_chain_id().await?);
        providers.insert(chain_id, provider);
    }
    Ok(providers)
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
    let rpc_map: Arc<_> = Arc::new(create_rpc_map(rpc_urls).await?);

    let mut handles = Vec::new();

    let entries: Vec<_> = rpc_map
        .iter()
        .map(|(chain_id, provider)| (*chain_id, provider.clone()))
        .collect();

    for (chain_id, provider) in entries {
        let rpc_map = rpc_map.clone();
        let handle = tokio::spawn(async move {
            let r = subscribe_to_events_http(chain_id, &provider, rpc_map).await;
            if let Err(e) = r {
                println!("Error: {:?}", e);
            }
        });
        handles.push(handle);
    }

    for handle in handles {
        let r = handle.await;
        if let Err(e) = r {
            println!("Error: {:?}", e);
        }
    }

    Ok(())
}

async fn subscribe_to_events_http(
    chain_id: U256,
    provider: &HttpProvider,
    rpc_map: Arc<HashMap<U256, HttpProvider>>,
) -> Result<()> {
    // async fn subscribe_to_events_http(rpc_url: &str) -> Result<()> {
    // let provider = ProviderBuilder::new().on_http(rpc_url.parse().expect("Invalid RPC"));
    // let chain_id = provider.get_chain_id().await?;

    let l2_l2_xdomain_messenger_address = address!("4200000000000000000000000000000000000023");
    let filter = Filter::new()
        .address(l2_l2_xdomain_messenger_address)
        .event("SentMessage(uint256,address,uint256,address,bytes)")
        // .from_block(BlockNumberOrTag::Latest);
        .from_block(BlockNumberOrTag::Number(69499));

    let latest_block = provider.get_block_number().await?;

    let mut from_block = latest_block;
    loop {
        println!("Checking chain: {} from block {}", chain_id, from_block);
        let latest_block_result = provider.get_block_number().await;
        if let Err(e) = latest_block_result {
            println!("Error: {:?}", e);
            continue;
        }
        let latest_block = latest_block_result.unwrap();

        let logs_result = provider
            .get_logs(&filter.clone().from_block(from_block))
            .await;
        if let Err(e) = logs_result {
            println!("Error: {:?}", e);
            continue;
        }
        let logs = logs_result.unwrap();

        for log in logs {
            // let mut out = Vec::<u8>::new();
            // log.stv_abi_encode_packed_to(&mut out);
            println!("L2 contract token logs: {log:?}");

            let mut payload = Vec::<u8>::new();

            let topics = log.inner.data.topics();

            topics[0].abi_encode_packed_to(&mut payload);
            topics[1].abi_encode_packed_to(&mut payload);
            topics[2].abi_encode_packed_to(&mut payload);
            topics[3].abi_encode_packed_to(&mut payload);
            log.inner.data.data.abi_encode_packed_to(&mut payload);

            // topics[0].encode(&mut payload);
            // topics[1].encode(&mut payload);
            // topics[2].encode(&mut payload);
            // log.inner.data.data.encode(&mut payload);

            // log.inner.encode(&mut payload);
            // log_data.stv_abi_encode_packed_to(&mut payload);
            // log.inner.stv_abi_encode_packed_to(&mut payload);
            println!("Serialized log: {:?}", payload.encode_hex());

            let sent_message = SentMessageWrapper::from_log(chain_id, log);

            let dest = sent_message.event.destination;
            println!("Relaying to chain: {}", dest);
            let dest_provider = rpc_map
                .get(&dest)
                .unwrap_or_else(|| panic!("[NOT FOUND] Destination Chain ID: {}", dest));
            println!("Relaying to chain: {}", dest);
            let pending_tx_builder_result =
                send_relay_message(dest_provider, sent_message, payload).await;
            if let Err(e) = pending_tx_builder_result {
                println!("Error: {:?}", e);
                continue;
            }

            let pending_tx_builder = pending_tx_builder_result.unwrap();
            let result = pending_tx_builder.get_receipt().await;
            if let Err(e) = result {
                println!("Error: {:?}", e);
                continue;
            }

            let receipt = result.unwrap();
            println!("Relay message sent: {:?}", receipt);
            println!("In block: {:?}", receipt.block_number);
            println!("Tx hash: {:?}", receipt.transaction_hash);
        }

        from_block = latest_block;
        tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
    }
}

// async fn subscribe_to_events_ws(rpc_url: &str) -> Result<()> {
//     let ws = WsConnect::new(rpc_url);
//     let provider = ProviderBuilder::new().on_ws(ws).await?;

//     // Create a filter to watch for l2-l2 events
//     let l2_l2_xdomain_messenger_address = address!("4200000000000000000000000000000000000023");
//     let filter = Filter::new()
//         .address(l2_l2_xdomain_messenger_address)
//         .event("SentMessage(uint256,address,uint256,address,bytes)")
//         .from_block(BlockNumberOrTag::Latest);

//     // Subscribe to logs.
//     let sub = provider.subscribe_logs(&filter).await?;
//     let mut stream = sub.into_stream();

//     while let Some(log) = stream.next().await {
//         println!("L2 contract token logs: {log:?}");
//         //if we it matches, then we do next section.
//     }

//     Ok(())
// }

// 382409ac69001e11931a28435afef442cbfd20d9891907e8fa373ba7d351f320
// 000000000000000000000000000000000000000000000000000000000147a7b9
// 0000000000000000000000002b2fd43555ab19289396cd5505d3557ebbd85c81
// 0000000000000000000000002b2fd43555ab19289396cd5505d3557ebbd85c81
// 0000000000000000000000000000000000000000000000000000000000000040
// 0000000000000000000000000000000000000000000000000000000000000004
// c4f9fd2700000000000000000000000000000000000000000000000000000000
