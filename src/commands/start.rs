use crate::commands::utils::get_config;
use crate::commands::utils::get_local_signers_from_config;
use crate::config::signer::local::ChainType;
use crate::config::tss::group::Group;
use crate::proto;
use crate::proto::fkms::v1::fkms_service_server::FkmsServiceServer;
use crate::server::builder::ServerBuilder;
use crate::signer::Signer;
use crate::verifier::tss::signature::SignatureVerifier;
use anyhow::anyhow;
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
        let signer_groups = get_local_signers_from_config(signer_configs)?;
        for (chain_type, signers) in signer_groups {
            match chain_type {
                ChainType::Evm => {
                    for signer in signers {
                        info!("initialized local evm signer: {}", signer.address());
                        builder.with_evm_signer(signer);
                    }
                }
                ChainType::Xrpl => {
                    for signer in signers {
                        info!("initialized local xrpl signer: {}", signer.address());
                        builder.with_xrpl_signer(signer);
                    }
                }
            }
        }
    }

    // Load TSS secp256k1 public key in 33-byte compressed SEC1 hex format
    // (1-byte prefix 0x02/0x03 + 32-byte x-coordinate), e.g.
    // 03235b757dbddd3c149327b5eb54b0cd3f522ef6c4976e57c336321444c1325b02
    if config.tss.enable_verify {
        let tss_verifier = init_tss_verifier(config.tss.groups)?;
        builder.with_tss_signature_verifier(tss_verifier);
    }

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

fn init_tss_verifier(groups: Vec<Group>) -> anyhow::Result<SignatureVerifier> {
    if groups.is_empty() {
        return Err(anyhow!("No TSS groups configured"));
    }
    let tss_verifier = SignatureVerifier::new(groups);
    Ok(tss_verifier)
}
