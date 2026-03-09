use crate::codec::evm::decode_tx;
use crate::codec::tss::decode_tss_message;
use crate::codec::xrpl::create_signing_payload;
use crate::codec::xrpl::{encode_for_signing, encode_with_signature};
use crate::proto::fkms::v1::fkms_service_server::FkmsService;
use crate::proto::fkms::v1::{
    GetSignerAddressesRequest, GetSignerAddressesResponse, SignEvmRequest, SignEvmResponse,
    SignXrplRequest, SignXrplResponse,
};
use crate::server::Server;
use crate::signer::signature::Signature;
use k256::sha2::Sha512;
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

        // decode tx, verify decoded prices, and tss message
        let evm_tx = decode_tx(&sign_evm_request.tx_message)
            .map_err(|e| Status::internal(format!("Failed to decode tx: {e}")))?;

        let decoded_tss_message = decode_tss_message(&evm_tx.tss.message)
            .map_err(|e| Status::internal(format!("Failed to decode TSS message: {}", e)))?;
        let signal_prices = decoded_tss_message
            .signal_prices()
            .map_err(|e| Status::internal(format!("Failed to get signal prices: {}", e)))?;

        // run pre sign hooks
        for hook in &self.pre_sign_hooks {
            hook.call(&signal_prices).await?;
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

    #[instrument(skip(self, request))]
    async fn sign_xrpl(
        &self,
        request: Request<SignXrplRequest>,
    ) -> Result<Response<SignXrplResponse>, Status> {
        let sign_xrpl_request = request.into_inner();

        let signer_payload = sign_xrpl_request.signer_payload.ok_or_else(|| {
            Status::invalid_argument("signer_payload field is required and cannot be null")
        })?;

        let tss = sign_xrpl_request
            .tss
            .ok_or_else(|| Status::invalid_argument("tss field is required and cannot be null"))?;

        // verify tss signature
        if let Some(verifier) = &self.tss_signature_verifier {
            verifier
                .verify(&tss.message, &tss.random_addr, &tss.signature_s)
                .map_err(|e| {
                    error!("failed to verify tss message: {:?}", e);
                    Status::internal(format!("Failed to verify tss signature: {e}"))
                })?;
        }

        // extract prices from tss message
        let decoded_tss_message = decode_tss_message(&tss.message)
            .map_err(|e| Status::internal(format!("Failed to decode TSS message: {}", e)))?;
        let prices = decoded_tss_message
            .signal_prices()
            .map_err(|e| Status::internal(format!("Failed to get signal prices: {}", e)))?;

        // run pre sign hooks
        for hook in &self.pre_sign_hooks {
            hook.call(&prices).await?;
        }

        match self.xrpl_signers.get(&signer_payload.account) {
            Some(signer) => {
                let public_key = hex::encode(signer.public_key());
                let mut signing_payload = create_signing_payload(
                    &prices,
                    signer_payload.account,
                    signer_payload.oracle_id,
                    signer_payload.fee,
                    signer_payload.sequence,
                    signer_payload.last_updated_time,
                    public_key,
                )
                .map_err(|e| {
                    error!("failed to create signing payload: {:?}", e);
                    Status::internal(format!("Failed to create signing payload: {e}"))
                })?;

                let tx = encode_for_signing(&signing_payload).map_err(|e| {
                    error!("failed to encode for signing: {:?}", e);
                    Status::internal(format!("Failed to encode for signing: {e}"))
                })?;

                // Sign with sha512half
                let digest = &Sha512::digest(&tx)[..32];
                match signer.sign(digest).await {
                    Ok(s) => {
                        let signature = s.into_vec();
                        let tx_blob =
                            encode_with_signature(&mut signing_payload, hex::encode(signature))
                                .map_err(|e| {
                                    error!("failed to encode with signature: {:?}", e);
                                    Status::internal(format!(
                                        "Failed to encode with signature: {e}"
                                    ))
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
                warn!("no signer found for {}", signer_payload.account);
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
        let mut addresses = Vec::new();
        addresses.extend(self.evm_signers.keys().cloned());
        addresses.extend(self.xrpl_signers.keys().cloned());
        let response = GetSignerAddressesResponse { addresses };
        Ok(Response::new(response))
    }
}
