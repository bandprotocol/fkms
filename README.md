# FKMS: Falcon Key Management Service

## Overview

`fkms` is a Key Management Service (KMS) written in Rust, designed to sign transactions originating from [Falcon](https://github.com/bandprotocol/falcon). It provides secure key management and signing capabilities for EVM-compatible blockchains, supporting both local and AWS KMS-backed signers. The service exposes a gRPC API for signing and key management operations, and is designed to be easily configurable and extensible with middleware (e.g., authentication).

## Installation

1. **Clone the repository:**
   ```sh
   git clone https://github.com/bandprotocol/fkms.git
   cd fkms
   ```
2. **Build the binary:**
   ```sh
   cargo install --path .
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
log_level = "info"

[signer_config]

# Local signers using various sources
[[signer_config.local_signer_configs]]
type = "env"
env_variable = "PRIVATE_KEY_1"
encoding = "hex"

[[signer_config.local_signer_configs]]
type = "file"
path = "/path/to/private_key.txt"
encoding = "base64"

[[signer_config.local_signer_configs]]
type = "private_key"
private_key = "abcdef0123456789..."
encoding = "hex"
```

### Supported Local Signer Types

| Type          | Description                                    | Required Fields           |
| --------------| ---------------------------------------------- | --------------------------|
| `env`         | Load private key from an environment  variable | `env_variable`, `encoding`|
| `file`        | Load private key from a file path              | `path`, `encoding`        |
| `private_key` | Use an inline private key                      | `private_key`, `encoding` |

## Encoding Options
- `hex`: The key is encoded in hexadecimal (0-9, a-f)
- `base64`: The key is base64-encoded

> For type = `env`, you must define the environment variable in a `.env` file or via your shell environment.
> Example .env file:
```env
PRIVATE_KEY_1=abc123456789deadbeef...
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

The gRPC API is defined in [`proto/kms/v1/signer.proto`](proto/kms/v1/signer.proto):

- `SignEvm(SignEvmRequest)`: Sign a message with a given address
- `GetSignerAddresses(GetSignerAddressesRequest)`: List available signer addresses

### Example: SignEvmRequest

```proto
message SignEvmRequest {
  string address = 1;
  bytes message = 2;
}
```

### Example: GetSignerAddressesResponse

```proto
message GetSignerAddressesResponse {
  repeated string addresses = 1;
}
```

## Extending

- **Middleware:** Add authentication or other middleware by enabling the `middleware` feature and configuring as needed.
- **AWS KMS:** Enable the `aws` feature and configure AWS signers in the config.
