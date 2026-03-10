use crate::signer::Signer;
use crate::signer::signature::Signature;
use crate::signer::signature::ecdsa::EcdsaSignature;
use aws_config::SdkConfig;
use aws_sdk_kms::Client;
use aws_sdk_kms::primitives::Blob;
use k256::ecdsa::{self, VerifyingKey};
use k256::pkcs8::DecodePublicKey;
use k256::sha2::Digest;
use sha3::Keccak256;

pub struct AwsSigner {
    client: Client,
    key_id: String,
    compressed_pk: Vec<u8>,
    uncompressed_pk: Vec<u8>,
}

impl AwsSigner {
    pub async fn new(config: &SdkConfig, key_id: String) -> Result<Self, anyhow::Error> {
        let client = Client::new(config);

        let resp = client
            .get_public_key()
            .key_id(key_id.clone())
            .send()
            .await?;
        let der_encoded_pk = resp
            .public_key
            .ok_or(anyhow::Error::msg("no public key found"))?
            .into_inner();
        let verifying_key = VerifyingKey::from_public_key_der(&der_encoded_pk)?;

        let compressed_pk = verifying_key.to_encoded_point(true).as_bytes().to_vec();
        let uncompressed_pk = verifying_key.to_encoded_point(false).as_bytes().to_vec();

        Ok(Self {
            client,
            key_id,
            compressed_pk,
            uncompressed_pk,
        })
    }

    pub async fn sign_ecsda(&self, message: &[u8]) -> Result<EcdsaSignature, anyhow::Error> {
        let sign_output = self
            .client
            .sign()
            .key_id(&self.key_id)
            .message(Blob::new(message))
            .signing_algorithm(aws_sdk_kms::types::SigningAlgorithmSpec::EcdsaSha256)
            .send()
            .await?;

        let signature_blob = sign_output
            .signature
            .ok_or(anyhow::Error::msg("no signature found"))?;

        let signature = ecdsa::Signature::from_der(signature_blob.as_ref())?;

        let digest = Keccak256::new_with_prefix(message);
        let recovery_id = find_recovery_id(digest, &signature);
        Ok((signature, recovery_id))
    }
}

#[async_trait::async_trait]
impl Signer for AwsSigner {
    async fn sign_ecdsa(&self, message: &[u8]) -> anyhow::Result<Vec<u8>> {
        Ok(self.sign_ecsda(message).await?.into_vec())
    }

    async fn sign_der(&self, _: &[u8]) -> anyhow::Result<Vec<u8>> {
        Err(anyhow::Error::msg("der signing currently not support"))
    }

    fn public_key(&self, compressed: bool) -> &[u8] {
        if compressed {
            &self.compressed_pk
        } else {
            &self.uncompressed_pk
        }
    }
}

fn find_recovery_id<D: Digest>(digest: D, signature: &ecdsa::Signature) -> ecdsa::RecoveryId {
    // unwrap here as this should never fail
    let recovery_id_0 = ecdsa::RecoveryId::from_byte(0).unwrap();
    if VerifyingKey::recover_from_digest(digest, signature, recovery_id_0).is_ok() {
        recovery_id_0
    } else {
        ecdsa::RecoveryId::from_byte(1).unwrap()
    }
}
