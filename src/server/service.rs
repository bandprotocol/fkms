use crate::codec;
use crate::codec::xrpl::deserialize_tx;
use crate::proto::fkms::v1::fkms_service_server::FkmsService;
use crate::proto::fkms::v1::{
    GetSignerAddressesRequest, GetSignerAddressesResponse, SignEvmRequest, SignEvmResponse,
    SignXrplRequest, SignXrplResponse,
};
use crate::server::Server;
use crate::signer::signature::Signature;
use crate::verifier::tss::message::{evm, xrpl};
use k256::sha2::Sha512;
use serde_json::Value;
use sha3::Digest;
use tonic::{Request, Response, Status};
use tracing::{error, info, instrument, warn};

#[tonic::async_trait]
impl FkmsService for Server {
    #[instrument(skip(self, request))]
    async fn sign_evm(
        &self,
        request: Request<SignEvmRequest>,
    ) -> Result<Response<SignEvmResponse>, Status> {
        let sign_evm_request = request.into_inner();

        let tss = sign_evm_request
            .tss
            .ok_or_else(|| Status::invalid_argument("tss field is required and cannot be null"))?;

        evm::verify_message(&sign_evm_request.tx_message, &tss.message).map_err(|e| {
            error!("failed to verify evm message: {:?}", e);
            Status::internal(format!("Failed to verify message: {e}"))
        })?;

        if let Some(verifier) = &self.tss_signature_verifier {
            verifier
                .verify(&tss.message, &tss.random_addr, &tss.signature_s)
                .map_err(|e| {
                    error!("failed to verify tss message: {:?}", e);
                    Status::internal(format!("Failed to verify message: {e}"))
                })?;
        }

        for hook in &self.evm_pre_sign_hooks {
            hook.call(&sign_evm_request.tx_message).await?;
        }

        match self.evm_signers.get(&sign_evm_request.address) {
            Some(signer) => {
                match signer
                    .sign(&sha3::Keccak256::digest(&sign_evm_request.tx_message))
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

    #[instrument(skip(self, request))]
    async fn sign_xrpl(
        &self,
        request: Request<SignXrplRequest>,
    ) -> Result<Response<SignXrplResponse>, Status> {
        let sign_xrpl_request = request.into_inner();

        let tss = sign_xrpl_request
            .tss
            .ok_or_else(|| Status::invalid_argument("tss field is required and cannot be null"))?;

        xrpl::verify_message(&sign_xrpl_request.tx_message, &tss.message).map_err(|e| {
            error!("failed to verify xrpl message: {:?}", e);
            Status::internal(format!("Failed to verify message: {e}"))
        })?;

        if let Some(verifier) = &self.tss_signature_verifier {
            verifier
                .verify(&tss.message, &tss.random_addr, &tss.signature_s)
                .map_err(|e| {
                    error!("failed to verify tss message: {:?}", e);
                    Status::internal(format!("Failed to verify message: {e}"))
                })?;
        }

        for hook in &self.xrpl_pre_sign_hooks {
            hook.call(&sign_xrpl_request.tx_message).await?;
        }

        match self.xrpl_signers.get(&sign_xrpl_request.address) {
            Some(signer) => {
                let mut tx = deserialize_tx(&sign_xrpl_request.tx_message).map_err(|e| {
                    error!("failed to deserialize xrpl message: {:?}", e);
                    Status::internal(format!("Failed to deserialize xrpl message: {e}"))
                })?;

                let public_key = signer.public_key(true);
                let new_tx = codec::xrpl::encode_tx_with_fields(
                    &mut tx,
                    vec![(
                        "SigningPubKey".into(),
                        Value::String(hex::encode(public_key)),
                    )],
                    true,
                )
                .map_err(|e| {
                    error!("failed to combine encoded tx with public key: {:?}", e);
                    Status::internal(format!("Failed to combine encoded tx with public key: {e}"))
                })?;

                let digest = &Sha512::digest(&new_tx)[..32];
                match signer.sign(digest).await {
                    Ok(s) => {
                        let signature = s.into_vec();
                        let tx_blob = codec::xrpl::encode_tx_with_fields(
                            &mut tx,
                            vec![(
                                "TxnSignature".to_string(),
                                Value::String(hex::encode(signature)),
                            )],
                            false,
                        )
                        .map_err(|e| {
                            error!("failed to create tx blob: {:?}", e);
                            Status::internal(format!("Failed to create tx blob: {e}"))
                        })?;
                        info!("successfully signed xrpl message");
                        Ok(Response::new(SignXrplResponse { tx_blob }))
                    }
                    Err(e) => {
                        error!("failed to sign xrpl message: {:?}", e);
                        Err(Status::internal(format!("Failed to sign message: {e}")))
                    }
                }
            }
            None => {
                warn!("no signer found for {}", sign_xrpl_request.address);
                Err(Status::not_found("Signer not found"))
            }
        }
    }
}
