use crate::codec::evm::decode_tx;
use crate::codec::icon::{
    create_signing_payload as create_icon_signing_payload, encode_tx_for_signing, sign_tx,
};
use crate::codec::tss::decode_tss_message;
use crate::codec::xrpl::create_signing_payload;
use crate::codec::xrpl::{encode_for_signing, encode_with_signature};
use crate::config::signer::local::ChainType;
use crate::proto::fkms::v1::ChainType as proto_chain_type;
use crate::proto::fkms::v1::fkms_service_server::FkmsService;
use crate::proto::fkms::v1::{
    GetSignerAddressesRequest, GetSignerAddressesResponse, SignEvmRequest, SignEvmResponse,
    SignIconRequest, SignIconResponse, SignXrplRequest, SignXrplResponse, Signers,
};
use crate::server::Server;
use k256::sha2::Sha512;
use sha3::{Digest, Sha3_256};
use std::collections::HashMap;
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
        let evm_tx = decode_tx(&sign_evm_request.message)
            .map_err(|e| Status::internal(format!("Failed to decode tx: {e}")))?;

        let decoded_tss_message = decode_tss_message(&evm_tx.tss.message)
            .map_err(|e| Status::internal(format!("Failed to decode TSS message: {e}")))?;

        // run pre sign hooks
        for hook in &self.pre_sign_hooks {
            hook.call(&decoded_tss_message.packet).await?;
        }

        match self
            .signers
            .get(&(ChainType::Evm, sign_evm_request.address.clone()))
        {
            Some(signer) => {
                match signer
                    .sign(&sha3::Keccak256::digest(&sign_evm_request.message))
                    .await
                {
                    Ok(s) => {
                        let response = SignEvmResponse { signature: s };
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
                .verify_signature(&tss.message, &tss.random_addr, &tss.signature_s)
                .map_err(|e| {
                    error!("failed to verify tss message: {:?}", e);
                    Status::invalid_argument(format!("Failed to verify tss signature: {e}"))
                })?;
        }

        // extract prices from tss message
        let decoded_tss_message = decode_tss_message(&tss.message)
            .map_err(|e| Status::internal(format!("Failed to decode TSS message: {e}")))?;
        let tunnel_packet = decoded_tss_message.packet;

        // run pre sign hooks
        for hook in &self.pre_sign_hooks {
            hook.call(&tunnel_packet).await?;
        }

        match self
            .signers
            .get(&(ChainType::Xrpl, signer_payload.account.clone()))
        {
            Some(signer) => {
                let public_key = hex::encode(signer.public_key());
                let signals: Vec<(String, u64)> = tunnel_packet
                    .signals
                    .iter()
                    .map(|sp| (sp.signal.clone(), sp.price))
                    .collect();
                let mut signing_payload = create_signing_payload(
                    &signals,
                    &signer_payload.account,
                    signer_payload.oracle_id,
                    &signer_payload.fee,
                    signer_payload.sequence,
                    tunnel_packet.timestamp,
                    &public_key,
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
                    Ok(signature) => {
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

    #[instrument(skip(self, request))]
    async fn sign_icon(
        &self,
        request: Request<SignIconRequest>,
    ) -> Result<Response<SignIconResponse>, Status> {
        let sign_icon_request = request.into_inner();

        let signer_payload = sign_icon_request.signer_payload.ok_or_else(|| {
            Status::invalid_argument("signer_payload field is required and cannot be null")
        })?;

        let tss = sign_icon_request
            .tss
            .ok_or_else(|| Status::invalid_argument("tss field is required and cannot be null"))?;

        // verify tss signature
        if let Some(verifier) = &self.tss_signature_verifier {
            verifier
                .verify_signature(&tss.message, &tss.random_addr, &tss.signature_s)
                .map_err(|e| {
                    error!("failed to verify tss message: {:?}", e);
                    Status::invalid_argument(format!("Failed to verify tss signature: {e}"))
                })?;
        }

        // extract prices from tss message
        let decoded_tss_message = decode_tss_message(&tss.message)
            .map_err(|e| Status::internal(format!("Failed to decode TSS message: {e}")))?;
        let tunnel_packet = decoded_tss_message.packet;

        // run pre sign hooks
        for hook in &self.pre_sign_hooks {
            hook.call(&tunnel_packet).await?;
        }

        match self
            .signers
            .get(&(ChainType::Icon, signer_payload.relayer.clone()))
        {
            Some(signer) => {
                let signals: Vec<(String, u64)> = tunnel_packet
                    .signals
                    .iter()
                    .filter_map(|sp| {
                        let parts: Vec<&str> = sp.signal.split(':').collect();
                        if parts.len() == 2 {
                            let base_quote: Vec<&str> = parts[1].split('-').collect();
                            if base_quote.len() == 2 && base_quote[1] == "USD" {
                                return Some((base_quote[0].to_string(), sp.price));
                            }
                        }
                        None
                    })
                    .collect();

                let resolved_time = u64::try_from(tunnel_packet.timestamp)
                    .map_err(|_| Status::invalid_argument("Timestamp must be non-negative"))?;
                let icon_tx = create_icon_signing_payload(
                    &signer_payload.relayer,
                    &signer_payload.contract_address,
                    signer_payload.step_limit,
                    &signals,
                    &signer_payload.network_id,
                    resolved_time,
                    tunnel_packet.sequence,
                )
                .map_err(|e| {
                    error!("failed to create signing payload: {:?}", e);
                    Status::internal(format!("Failed to create signing payload: {e}"))
                })?;

                let signing_data = encode_tx_for_signing(&icon_tx).map_err(|e| {
                    Status::internal(format!("Failed to encode tx for signing: {e}"))
                })?;

                // Sign with SHA3-256
                let digest = Sha3_256::digest(&signing_data);

                match signer.sign(&digest).await {
                    Ok(signature) => {
                        let signed_tx = icon_tx;
                        let tx_params = sign_tx(&signed_tx, &signature)
                            .map_err(|e| Status::internal(format!("Failed to sign tx: {e}")))?;

                        info!("successfully signed icon message");
                        Ok(Response::new(SignIconResponse { tx_params }))
                    }
                    Err(e) => {
                        error!("failed to sign icon message: {:?}", e);
                        Err(Status::internal(format!("Failed to sign message: {e}")))
                    }
                }
            }
            None => {
                warn!("no signer found for {}", signer_payload.relayer);
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

        let mut grouped: HashMap<ChainType, Vec<String>> = HashMap::new();
        for (chain, address) in self.signers.keys() {
            grouped
                .entry(chain.clone())
                .or_default()
                .push(address.clone());
        }

        let signers = grouped
            .into_iter()
            .map(|(ct, addresses)| {
                let proto_ct = match ct {
                    ChainType::Evm => proto_chain_type::Evm,
                    ChainType::Xrpl => proto_chain_type::Xrpl,
                    ChainType::Icon => proto_chain_type::Icon,
                };
                Signers {
                    chain_type: proto_ct as i32,
                    addresses,
                }
            })
            .collect();

        Ok(Response::new(GetSignerAddressesResponse { signers }))
    }
}
