# L2-to-L2 Message Relayer

A Rust application that relays messages between Optimism L2 chains by monitoring cross-domain messenger events.

## Prerequisites

- Docker installed on your system
- Access to Optimism L2 RPC endpoints

## Building and Running with Docker

1. Build the Docker image:
```bash
docker build -t l2-relayer .
```

2. Run the container:
```bash
docker run -e RPC_URLS="https://rpc1.optimism.io,https://rpc2.optimism.io" l2-relayer
```

### Environment Variables

- `RPC_URLS`: Comma-separated list of RPC endpoints for the Optimism L2 chains you want to relay messages between.
- `PRIVATE_KEY`: Private key used to sign transactions. Default: `0x0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef`.

Example:
```bash
RPC_URLS=https://interop-devnet-0.optimism.io/,https://interop-devnet-1.optimism.io/
PRIVATE_KEY=0x0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
```

## How it Works

The relayer:
1. Connects to multiple L2 chains using the provided RPC endpoints
2. Monitors for `SentMessage` events on each chain's CrossDomainMessenger contract
3. When a message is detected, relays it to the destination chain specified in the event

## Development

To modify the application:

1. Clone the repository
2. Make your changes to the Rust code
3. Rebuild the Docker image:
```bash
docker build -t l2-relayer .
```
4. Run the container:
```bash
docker run l2-relayer
```
