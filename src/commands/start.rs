use crate::commands::utils::{
    get_config, get_evm_local_signers_from_config, get_xrpl_local_signers_from_config,
};
use crate::proto;
use crate::proto::fkms::v1::fkms_service_server::FkmsServiceServer;
use crate::server::builder::ServerBuilder;
use crate::signer::{EvmSigner, XrplSigner};
use crate::verifier::tss::signature::SignatureVerifier;
use anyhow::anyhow;
use std::env;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::str::FromStr;
use tonic::transport::Server;
use tracing::{Level, info};

pub async fn start(path: PathBuf) -> anyhow::Result<()> {
    let config = get_config(path)?;

    // setup logging
    tracing_subscriber::fmt()
        .with_max_level(Level::from_str(&config.logging.log_level)?)
        .init();

    let mut builder = ServerBuilder::default();

    #[cfg(feature = "local")]
    {
        let signer_configs = &config.signer_config.local_signer_configs;
        let evm_signers = get_evm_local_signers_from_config(signer_configs)?;
        for signer in evm_signers {
            info!("initialized evm local signer: {}", signer.evm_address());
            builder.with_evm_signer(signer);
        }

        let xrpl_signers = get_xrpl_local_signers_from_config(signer_configs)?;
        for signer in xrpl_signers {
            info!("initialized xrpl local signer: {}", signer.xrpl_address());
            builder.with_xrpl_signer(signer);
        }
    }

    // load tss public key
    let tss_public_key = load_tss_public_key()?;
    builder.with_tss_signature_verifier(SignatureVerifier::new(tss_public_key));

    #[cfg(feature = "aws")]
    {
        // TODO: Implement AWS signer support
    }

    let server = builder.build();
    let reflection_server = tonic_reflection::server::Builder::configure()
        .register_encoded_file_descriptor_set(proto::fkms::v1::FILE_DESCRIPTOR_SET)
        .build_v1()?;

    info!(
        "starting server on {:?}:{:?}",
        &config.server.host, config.server.port
    );

    Server::builder()
        .add_service(FkmsServiceServer::new(server))
        .add_service(reflection_server)
        .serve(SocketAddr::from((config.server.host, config.server.port)))
        .await?;

    Ok(())
}

// Load TSS secp256k1 public key in 33-byte compressed SEC1 hex format
// (1-byte prefix 0x02/0x03 + 32-byte x-coordinate), e.g.
// 03235b757dbddd3c149327b5eb54b0cd3f522ef6c4976e57c336321444c1325b02
pub fn load_tss_public_key() -> anyhow::Result<[u8; 33]> {
    let tss_pubkey =
        env::var("TSS_PUBLIC_KEY").map_err(|e| anyhow!("TSS_PUBLIC_KEY not set: {}", e))?;
    let bytes = hex::decode(tss_pubkey).map_err(|e| anyhow!("Invalid hex string: {}", e))?;

    let array: [u8; 33] = bytes
        .try_into()
        .map_err(|v: Vec<u8>| anyhow!("Invalid length: expected 33 bytes, got {}", v.len()))?;

    Ok(array)
}
