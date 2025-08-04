use crate::commands::utils::{get_config, get_local_signers_from_config};
use crate::proto;
use crate::proto::kms::v1::kms_evm_service_server::KmsEvmServiceServer;
use crate::server::builder::ServerBuilder;
use crate::server::middleware::auth::store::sql::SqlDb;
use crate::server::middleware::auth::AuthMiddlewareLayer;
use crate::signer::EvmSigner;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::str::FromStr;
use sea_orm::DatabaseConnection;
use tonic::transport::Server;
use sea_orm::entity::prelude::*;
use tracing::{Level, info};
mod users {
    use sea_orm::entity::prelude::*;

    #[derive(Clone, Debug, PartialEq, DeriveEntityModel)]
    #[sea_orm(table_name = "users")]
    pub struct Model {
        #[sea_orm(primary_key)]
        pub api_key: String,
    }

    #[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
    pub enum Relation {}

    impl ActiveModelBehavior for ActiveModel {}
}
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

    // let layer = tower::ServiceBuilder::new()
    //     // Apply our own middleware
    //     .layer(MyMiddlewareLayer::default())
    //     // Interceptors can be also be applied as middleware
    //     .layer(tonic::service::InterceptorLayer::new(intercept))
    //     .into_inner();



    // Initialize the database connection
    let db_conn = DatabaseConnection::Disconnected;
    let store = SqlDb::<users::Entity>::new(db_conn);
    let auth_layer = AuthMiddlewareLayer::new(store, None); // Use default header

    let layer = tower::ServiceBuilder::new().layer(auth_layer).into_inner();

    let server = builder.build();
    let reflection_server = tonic_reflection::server::Builder::configure()
        .register_encoded_file_descriptor_set(proto::kms::v1::FILE_DESCRIPTOR_SET)
        .build_v1()?;

    info!(
        "starting server on {:?}:{:?}",
        &config.server.host, config.server.port
    );

    Server::builder()
    .layer(layer)
        .add_service(KmsEvmServiceServer::new(server))
        .add_service(reflection_server)
        .serve(SocketAddr::from((config.server.host, config.server.port)))
        .await?;

    Ok(())
}