use crate::proto::kms::v1::kms_evm_service_server::KmsEvmService;
use crate::proto::kms::v1::{
    GetSignerAddressesRequest, GetSignerAddressesResponse, SignEvmRequest, SignEvmResponse,
};
use crate::server::Server;
use crate::signer::signature::Signature;
use sha3::Digest;
use tonic::{Request, Response, Status};
use tracing::{error, info, instrument, warn};

#[tonic::async_trait]
impl KmsEvmService for Server {
    #[instrument(skip(self, request))]
    async fn sign_evm(
        &self,
        request: Request<SignEvmRequest>,
    ) -> Result<Response<SignEvmResponse>, Status> {
        let sign_evm_request = request.into_inner();
        match self.evm_signers.get(&sign_evm_request.address) {
            Some(signer) => {
                if let Some(price_verifier) = &self.price_verifier {
                    let _ = price_verifier.verify_message(&sign_evm_request.message).await?;
                }
                match signer
                    .sign(&sha3::Keccak256::digest(&sign_evm_request.message))
                    .await
                {
                    Ok(s) => {
                        let response = SignEvmResponse {
                            signature: s.into_vec(),
                        };
                        info!("successfully signed evm message");
                        Ok(Response::new(response))
                    }
                    Err(e) => {
                        error!("failed to sign evm message: {:?}", e);
                        Err(Status::internal(format!("Failed to sign message: {e}")))
                    }
                }
            }
            None => {
                warn!("no signer found for {}", sign_evm_request.address);
                Err(Status::not_found("Signer not found"))
            }
        }
    }

    #[instrument(skip(self, _request))]
    async fn get_signer_addresses(
        &self,
        _request: Request<GetSignerAddressesRequest>,
    ) -> Result<Response<GetSignerAddressesResponse>, Status> {
        info!("Got get_signer_addresses request");
        let response = GetSignerAddressesResponse {
            addresses: self.evm_signers.keys().cloned().collect(),
        };
        Ok(Response::new(response))
    }
}
