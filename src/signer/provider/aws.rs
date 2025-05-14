use crate::signer::provider::SigningProvider;
use aws_config::SdkConfig;
use aws_sdk_kms::Client;
use aws_sdk_kms::primitives::Blob;
use k256::ecdsa::{self, VerifyingKey};
use k256::elliptic_curve::sec1::ToEncodedPoint;
use k256::pkcs8::DecodePublicKey;

pub struct AwsKmsSigningProvider {
    client: Client,
    key_id: String,
    ecsda_public_key: Vec<u8>,
}

impl AwsKmsSigningProvider {
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
        let ecsda_public_key = verifying_key
            .as_affine()
            .to_encoded_point(false)
            .to_bytes()
            .to_vec();

        Ok(Self {
            client,
            key_id,
            ecsda_public_key,
        })
    }

    pub async fn sign_ecsda(&self, message: &[u8]) -> Result<ecdsa::Signature, anyhow::Error> {
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
        Ok(signature)
    }
}

#[async_trait::async_trait]
impl SigningProvider<ecdsa::Signature> for AwsKmsSigningProvider {
    async fn sign(&self, message: &[u8]) -> Result<ecdsa::Signature, anyhow::Error> {
        self.sign_ecsda(message).await
    }

    fn public_key(&self) -> &[u8] {
        self.ecsda_public_key.as_slice()
    }
}
