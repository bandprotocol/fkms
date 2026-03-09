# FKMS: Falcon Key Management Service

## Overview

`fkms` is a Key Management Service (KMS) written in Rust, designed to sign transactions originating from [Falcon](https://github.com/bandprotocol/falcon). It provides secure key management and signing capabilities for EVM-compatible blockchains and XRPL (secp256k1), supporting both local and AWS KMS-backed signers. The service exposes a gRPC API for signing and key management operations, and is designed to be easily configurable and extensible with middleware (e.g., authentication).

## Prerequisites
Before building and running `fkms`, ensure the following dependency is installed:
- [Rust](https://www.rust-lang.org/tools/install)



## Installation

1. **Clone the repository:**
   ```sh
   git clone https://github.com/bandprotocol/fkms.git
   cd fkms
   ```
2. **Build and install the binary:**

    By default, the `fkms` binary is compiled with the local feature enabled, supporting local key management. If you wish to enable additional features (such as AWS KMS integration), you can specify them explicitly during installation:
    - Default (local signer only)
      ```sh
      cargo install --path .
      ```
    - With AWS KMS support:
      ```sh
      cargo install --path . --features aws
      ```
    - Local, AWS, and TSS KMS support:
      ```sh
      cargo install --path . --features local,aws,tss
      ```
   This will compile and install the fkms executable 

## Configuration

The default configuration file is located at `$HOME/.fkms/config.toml`. You can generate a default config with:

```sh
fkms config init
```

### Example `config.toml`

```toml
[server]
host = "127.0.0.1"
port = 50051

[logging]
log_level = ""

[signer_config]

# Local signers using various sources
[[signer_config.local_signer_configs]]
type = "private_key"
env_variable = "PRIVATE_KEY_1"
encoding = "hex"
chain_type = "evm"

[[signer_config.local_signer_configs]]
type         = "mnemonic"
env_variable = "MNEMONIC_1"
coin_type = 60
account = 0
index = 0
```

### Supported Local Signer Types

| Type          | Description                                    | Required Fields                                |
| --------------| ---------------------------------------------- | -----------------------------------------------|
| `private_key` | Load private key from an environment variable (Currently support only EVM) | `env_variable`, `encoding`                     |
| `mnemonic`    | Load mnemonic from an environment variable     | `env_variable`, `coin_type`, `account`, `index`|

## Encoding Options
- `hex`: The key is encoded in hexadecimal (0-9, a-f)
- `base64`: The key is base64-encoded

> Environment variable must be defined in a `.env` file or via  shell environment.
> Example .env file:
```env
PRIVATE_KEY_1=abc123456789deadbeef...
MNEMONIC="test test test test test test test test test test test junk"
TSS_PUBLIC_KEY=0306be2adaf05e8ffc701c9241d6e147fcd7ff4f72e1da6aacd7158fa2a3919354
```

## Usage

### CLI Commands

- **Initialize config:**
  ```sh
  fkms config init [--path <config-path>] [--override]
  ```
- **Validate config:**
  ```sh
  fkms config validate [--path <config-path>]
  ```
- **List keys:**
  ```sh
  fkms key list [--path <config-path>]
  ```
- **Start server:**
  ```sh
  fkms start [--path <config-path>]
  ```

## API

### Generate protobufs (Rust)
The Rust server uses `tonic-build`. Rebuilding the project regenerates server/client code:

```sh
cargo clean
cargo build
```

The gRPC API is defined in [`proto/fkms/v1/signer.proto`](proto/fkms/v1/signer.proto):

- `SignEvm(SignEvmRequest)`: Sign a message with a given address (EVM)
- `SignXrpl(SignXrplRequest)`: Sign a message with a given address (XRPL)
- `GetSignerAddresses(GetSignerAddressesRequest)`: List available signer addresses

### Example: SignEvmRequest

```proto
message SignEvmRequest {
  string address = 1;
  bytes tx_message = 2;
}
```

### Example: SignEvmResponse

```proto
message SignEvmResponse {
  bytes signature = 1;
}
```

### Example: SignXrplRequest

```proto
message SignXrplRequest {
  XrplSignerPayload signer_payload = 1;
  Tss tss = 2;
}
```

### Example: SignXrplResponse

```proto
message SignXrplResponse {
  bytes tx_blob = 1;
}
```

### Example: GetSignerAddressesRequest

```proto
message GetSignerAddressesRequest {}
```

### Example: GetSignerAddressesResponse

```proto
message GetSignerAddressesResponse {
  repeated string addresses = 1;
}
```

### Example: XrplSignerPayload

```proto
message XrplSignerPayload {
  string account = 1;
  uint64 oracle_id = 2;
  string fee = 3;
  uint64 sequence = 4;
  uint64 last_updated_time = 5;
}
```

### Example: Tss

```proto
message Tss {
  bytes message = 1;
  bytes random_addr = 2;
  bytes signature_s = 3;
}
```

### XRPL Signing Notes

- The server computes the XRPL-standard SHA512Half digest of `message` (SHA-512, then taking the first 32 bytes) before signing.
- Signatures are returned as DER-encoded ECDSA bytes.

## Extending

- **Middleware:** Add authentication or other middleware by enabling the `middleware` feature and configuring as needed.
- **AWS KMS:** Enable the `aws` feature and configure AWS signers in the config.
