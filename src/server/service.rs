use crate::codec::cosmwasm_secret::{
    SignSecretTxParams, encrypt_secret_execute_msg, secret_execute_msg_json, sign_secret_tx,
};
use crate::codec::evm::decode_tx;
use crate::codec::flow;
use crate::codec::icon::{
    create_signing_payload as create_icon_signing_payload, encode_tx_for_signing, sign_tx,
};
use crate::codec::soroban;
use crate::codec::tss::decode_tss_message;
use crate::codec::xrpl::create_signing_payload;
use crate::codec::xrpl::{encode_for_signing, encode_with_signature};
use crate::config::signer::local::ChainType;
use crate::proto::fkms::v1::ChainType as proto_chain_type;
use crate::proto::fkms::v1::fkms_service_server::FkmsService;
use crate::proto::fkms::v1::{
    GetSignerAddressesRequest, GetSignerAddressesResponse, SignEvmRequest, SignEvmResponse,
    SignFlowRequest, SignFlowResponse, SignIconRequest, SignIconResponse, SignSecretRequest,
    SignSecretResponse, SignSorobanRequest, SignSorobanResponse, SignXrplRequest, SignXrplResponse,
    Signers,
};
use crate::server::Server;
use crate::server::utils::filter_usd_signal;
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
                    .filter_map(filter_usd_signal)
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
                    .filter_map(filter_usd_signal)
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

    #[instrument(skip(self, request))]
    async fn sign_flow(
        &self,
        request: Request<SignFlowRequest>,
    ) -> Result<Response<SignFlowResponse>, Status> {
        let sign_flow_request = request.into_inner();

        let signer_payload = sign_flow_request.signer_payload.ok_or_else(|| {
            Status::invalid_argument("signer_payload field is required and cannot be null")
        })?;

        let tss = sign_flow_request
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
            .map_err(|e| Status::internal(format!("Failed to decode TSS message: {}", e)))?;
        let tunnel_packet = decoded_tss_message.packet;

        // run pre sign hooks
        for hook in &self.pre_sign_hooks {
            hook.call(&tunnel_packet).await?;
        }

        match self
            .signers
            .get(&(ChainType::Flow, signer_payload.address.clone()))
        {
            Some(signer) => {
                let signals: Vec<(String, u64)> = tunnel_packet
                    .signals
                    .iter()
                    .filter_map(filter_usd_signal)
                    .collect();

                let resolve_time = u64::try_from(tunnel_packet.timestamp)
                    .map_err(|_| Status::invalid_argument("Timestamp must be non-negative"))?;
                let request_id = tunnel_packet.sequence;

                let payload_rlp = flow::build_payload_rlp(
                    &signals,
                    &signer_payload.address,
                    signer_payload.compute_limit,
                    &signer_payload.block_id,
                    signer_payload.key_index,
                    signer_payload.sequence,
                    &signer_payload.script,
                    resolve_time,
                    request_id,
                )
                .map_err(|e| {
                    error!("failed to build flow payload RLP: {:?}", e);
                    Status::internal(format!("Failed to build flow payload RLP: {e}"))
                })?;

                let envelope_hash = flow::build_transaction_envelope_hash(&payload_rlp);

                match signer.sign(&envelope_hash).await {
                    Ok(signature) => {
                        let tx_blob = flow::encode_signed_transaction(
                            &payload_rlp,
                            signer_payload.key_index,
                            &signature,
                        )
                        .map_err(|e| {
                            error!("failed to encode signed flow transaction: {:?}", e);
                            Status::internal(format!("Failed to encode signed transaction: {e}"))
                        })?;

                        info!("successfully signed flow transaction");
                        Ok(Response::new(SignFlowResponse { tx_blob }))
                    }
                    Err(e) => {
                        error!("failed to sign flow transaction: {:?}", e);
                        Err(Status::internal(format!("Failed to sign message: {e}")))
                    }
                }
            }
            None => {
                warn!("no signer found for {}", signer_payload.address);
                Err(Status::not_found("Signer not found"))
            }
        }
    }

    #[instrument(skip(self, request))]
    async fn sign_soroban(
        &self,
        request: Request<SignSorobanRequest>,
    ) -> Result<Response<SignSorobanResponse>, Status> {
        let sign_soroban_request = request.into_inner();

        let signer_payload = sign_soroban_request.signer_payload.ok_or_else(|| {
            Status::invalid_argument("signer_payload field is required and cannot be null")
        })?;

        let tss = sign_soroban_request
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
            .get(&(ChainType::Soroban, signer_payload.source_account.clone()))
        {
            Some(signer) => {
                let signals: Vec<(String, u64)> = tunnel_packet
                    .signals
                    .iter()
                    .filter_map(filter_usd_signal)
                    .collect();

                let resolve_time = u64::try_from(tunnel_packet.timestamp)
                    .map_err(|_| Status::invalid_argument("Timestamp must be non-negative"))?;
                let request_id = tunnel_packet.sequence;

                let base_fee: u32 = signer_payload
                    .fee
                    .parse()
                    .map_err(|_| Status::invalid_argument("fee must be a valid u32"))?;

                // build a V0 transaction for simulation.
                let mut base_tx = soroban::build_base_tx(
                    &signer_payload.source_account,
                    &signer_payload.contract_address,
                    base_fee,
                    signer_payload.sequence,
                    &signals,
                    resolve_time,
                    request_id,
                )
                .map_err(|e| {
                    error!("failed to build soroban base tx: {:?}", e);
                    Status::internal(format!("Failed to build base transaction: {e}"))
                })?;

                // Step 2 – simulate to obtain SorobanTransactionData and resource fee.
                let (soroban_data, min_resource_fee) =
                    soroban::simulate_transaction(&signer_payload.rpc_urls, &base_tx)
                        .await
                        .map_err(|e| {
                            error!("simulateTransaction failed: {:?}", e);
                            Status::internal(format!("Failed to simulate transaction: {e}"))
                        })?;

                // Step 3 – rebuild with V1 ext and sign the final hash.
                let unsigned_tx =
                    soroban::build_unsigned_tx(&mut base_tx, soroban_data, min_resource_fee)
                        .map_err(|e| {
                            error!("failed to build soroban final tx: {:?}", e);
                            Status::internal(format!("Failed to build final transaction: {e}"))
                        })?;

                let tx_hash =
                    soroban::compute_tx_hash(&signer_payload.network_passphrase, &unsigned_tx);

                match signer.sign(&tx_hash).await {
                    Ok(signature) => {
                        let tx_blob = soroban::encode_signed_envelope(
                            &unsigned_tx,
                            signer.public_key(),
                            &signature,
                        )
                        .map_err(|e| {
                            error!("failed to encode signed soroban envelope: {:?}", e);
                            Status::internal(format!("Failed to encode signed envelope: {e}"))
                        })?;

                        info!("successfully signed soroban transaction");
                        Ok(Response::new(SignSorobanResponse { tx_blob }))
                    }
                    Err(e) => {
                        error!("failed to sign soroban transaction: {:?}", e);
                        Err(Status::internal(format!("Failed to sign message: {e}")))
                    }
                }
            }
            None => {
                warn!("no signer found for {}", signer_payload.source_account);
                Err(Status::not_found("Signer not found"))
            }
        }
    }

    #[instrument(skip(self, request))]
    async fn sign_secret(
        &self,
        request: Request<SignSecretRequest>,
    ) -> Result<Response<SignSecretResponse>, Status> {
        let sign_secret_request = request.into_inner();

        let signer_payload = sign_secret_request.signer_payload.ok_or_else(|| {
            Status::invalid_argument("signer_payload field is required and cannot be null")
        })?;
        let tss = sign_secret_request
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

        let decoded_tss_message = decode_tss_message(&tss.message)
            .map_err(|e| Status::internal(format!("Failed to decode TSS message: {e}")))?;
        let tunnel_packet = decoded_tss_message.packet;

        for hook in &self.pre_sign_hooks {
            hook.call(&tunnel_packet).await?;
        }

        match self
            .signers
            .get(&(ChainType::Secret, signer_payload.sender.clone()))
        {
            Some(signer) => {
                let signals: Vec<(String, u64)> = tunnel_packet
                    .signals
                    .iter()
                    .filter_map(filter_usd_signal)
                    .collect();
                let symbols: Vec<String> = signals.iter().map(|(sym, _)| sym.clone()).collect();
                let rates: Vec<u64> = signals.iter().map(|(_, rate)| *rate).collect();

                let resolve_time = u64::try_from(tunnel_packet.timestamp)
                    .map_err(|_| Status::invalid_argument("Timestamp must be non-negative"))?;
                let request_id = tunnel_packet.sequence;

                let execute_msg_json =
                    secret_execute_msg_json(symbols, rates, resolve_time, request_id).map_err(
                        |e| Status::internal(format!("Failed to build execute msg json: {e}")),
                    )?;

                let encrypted_execute_msg = encrypt_secret_execute_msg(
                    &signer_payload.code_hash,
                    &signer_payload.pubkey,
                    &execute_msg_json,
                )
                .map_err(|e| Status::internal(format!("Failed to encrypt execute msg: {e}")))?;

                let pk_bytes = signer.private_key().ok_or_else(|| {
                    Status::invalid_argument("Signer private key is required for Secret signing")
                })?;

                let secret_params = SignSecretTxParams {
                    signer_private_key: pk_bytes.to_vec(),
                    sender_address_bech32: signer_payload.sender.clone(),
                    contract_address_bech32: signer_payload.contract_address.clone(),
                    encrypted_execute_msg,
                    chain_id: signer_payload.chain_id.clone(),
                    account_number: signer_payload.account_number,
                    sequence: signer_payload.sequence,
                    gas_limit: signer_payload.gas_limit,
                    gas_prices: signer_payload.gas_prices.clone(),
                    memo: signer_payload.memo.clone(),
                };

                let tx_blob = sign_secret_tx(secret_params)
                    .map_err(|e| Status::internal(format!("Failed to sign Secret tx: {e}")))?;

                info!("successfully signed secret cosmwasm message");
                Ok(Response::new(SignSecretResponse { tx_blob }))
            }
            None => {
                warn!("no signer found for {}", signer_payload.sender);
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
                    ChainType::Flow => proto_chain_type::Flow,
                    ChainType::Soroban => proto_chain_type::Soroban,
                    ChainType::Secret => proto_chain_type::Secret,
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
