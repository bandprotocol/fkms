use crate::proto::kms::v1::kms_evm_service_server::KmsEvmService;
use crate::proto::kms::v1::{
    GetSignerAddressesRequest, GetSignerAddressesResponse, SignEvmRequest, SignEvmResponse,
};
use crate::server::Server;
use sha3::Digest;
use tonic::{Request, Response, Status};

#[tonic::async_trait]
impl KmsEvmService for Server {
    async fn sign_evm(
        &self,
        request: Request<SignEvmRequest>,
    ) -> Result<Response<SignEvmResponse>, Status> {
        let sign_evm_request = request.into_inner();
        match self.evm_signers.get(&sign_evm_request.address) {
            Some(signer) => {
                match signer
                    .sign(&sha3::Keccak256::digest(&sign_evm_request.message))
                    .await
                {
                    Ok((signature, v)) => {
                        let (r, s) = signature.split_bytes();

                        let mut eth_signature = Vec::with_capacity(65);
                        eth_signature.extend_from_slice(r.as_slice());
                        eth_signature.extend_from_slice(s.as_slice());

                        eth_signature.push(v.to_byte());

                        let response = SignEvmResponse {
                            signature: eth_signature,
                        };
                        Ok(Response::new(response))
                    }
                    Err(e) => Err(Status::internal(format!("Failed to sign message: {}", e))),
                }
            }
            None => Err(Status::not_found("Signer not found")),
        }
    }

    async fn get_signer_addresses(
        &self,
        _: Request<GetSignerAddressesRequest>,
    ) -> Result<Response<GetSignerAddressesResponse>, Status> {
        let response = GetSignerAddressesResponse {
            addresses: self.evm_signers.keys().cloned().collect(),
        };
        Ok(Response::new(response))
    }
}
