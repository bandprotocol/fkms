use crate::commands::utils::{get_config, get_local_signers_from_config};
use crate::proto;
use crate::proto::kms::v1::kms_evm_service_server::KmsEvmServiceServer;
use crate::server::builder::ServerBuilder;
use crate::signer::EvmSigner;
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
        let signers = get_local_signers_from_config(signer_configs)?;
        for signer in signers {
            info!("initialized local signer: {}", signer.evm_address());
            builder.with_evm_signer(signer);
        }
    }

    #[cfg(feature = "aws")]
    {
        // TODO: Implement AWS signer support
    }

    let server = builder.build();
    let reflection_server = tonic_reflection::server::Builder::configure()
        .register_encoded_file_descriptor_set(proto::kms::v1::FILE_DESCRIPTOR_SET)
        .build_v1()?;

    info!(
        "starting server on {:?}:{:?}",
        &config.server.host, config.server.port
    );

    Server::builder()
        .add_service(KmsEvmServiceServer::new(server))
        .add_service(reflection_server)
        .serve(SocketAddr::from((config.server.host, config.server.port)))
        .await?;

    Ok(())
}
