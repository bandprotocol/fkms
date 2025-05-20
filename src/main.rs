mod proto;
mod server;
mod signer;

use crate::proto::kms::v1::kms_evm_service_server::KmsEvmServiceServer;
use crate::server::ServerBuilder;
use crate::signer::provider::local::LocalSigningProvider;
use std::env;
use std::net::SocketAddr;
use tonic::transport::Server;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // TODO: Change placeholder main to cli
    let pk = env::var("PRIVATE_KEY")?;
    let evm_signer = LocalSigningProvider::new(&hex::decode(pk)?)?;
    let signing_server = ServerBuilder::default()
        .with_evm_signer(evm_signer)?
        .build();
    let reflection_server = tonic_reflection::server::Builder::configure()
        .register_encoded_file_descriptor_set(proto::kms::v1::FILE_DESCRIPTOR_SET)
        .build_v1()?;

    Server::builder()
        .add_service(KmsEvmServiceServer::new(signing_server))
        .add_service(reflection_server)
        .serve(SocketAddr::from(([127, 0, 0, 1], 50051)))
        .await?;
    Ok(())
}
