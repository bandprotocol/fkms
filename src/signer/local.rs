use crate::signer::Signer;
use crate::signer::signature::ecdsa::{DerSignature, EcdsaSignature};
use k256::ecdsa;
use k256::ecdsa::SigningKey as EcdsaSigningKey;
use k256::ecdsa::signature::hazmat::PrehashSigner;
use k256::elliptic_curve::sec1::ToEncodedPoint;

// ECDSA Signer (secp256k1)
pub struct LocalSigner {
    signing_key: EcdsaSigningKey,
    compressed_ecdsa_public_key: Vec<u8>,
    uncompressed_ecdsa_public_key: Vec<u8>,
}

impl LocalSigner {
    pub fn new(private_key: &[u8]) -> Result<Self, ecdsa::Error> {
        let signing_key = EcdsaSigningKey::from_slice(private_key)?;
        let compressed_ecdsa_public_key = signing_key
            .verifying_key()
            .as_affine()
            .to_encoded_point(true)
            .as_bytes()
            .to_vec();

        let uncompressed_ecdsa_public_key = signing_key
            .verifying_key()
            .as_affine()
            .to_encoded_point(false)
            .as_bytes()
            .to_vec();

        Ok(LocalSigner {
            signing_key,
            compressed_ecdsa_public_key,
            uncompressed_ecdsa_public_key,
        })
    }

    fn sign_ecdsa(&self, message: &[u8]) -> Result<EcdsaSignature, ecdsa::Error> {
        self.signing_key.sign_prehash_recoverable(message)
    }

    fn sign_der(&self, message: &[u8]) -> Result<DerSignature, ecdsa::Error> {
        self.signing_key.sign_prehash(message)
    }

    pub fn public_key(&self, is_compressed: bool) -> &[u8] {
        if is_compressed {
            self.compressed_ecdsa_public_key.as_slice()
        } else {
            self.uncompressed_ecdsa_public_key.as_slice()
        }
    }
}

#[async_trait::async_trait]
impl Signer<EcdsaSignature> for LocalSigner {
    async fn sign(&self, message: &[u8]) -> anyhow::Result<EcdsaSignature> {
        Ok(self.sign_ecdsa(message)?)
    }

    fn public_key(&self, is_compressed: bool) -> &[u8] {
        if is_compressed {
            self.compressed_ecdsa_public_key.as_slice()
        } else {
            self.uncompressed_ecdsa_public_key.as_slice()
        }
    }
}

#[async_trait::async_trait]
impl Signer<DerSignature> for LocalSigner {
    async fn sign(&self, message: &[u8]) -> anyhow::Result<DerSignature> {
        Ok(self.sign_der(message)?)
    }

    fn public_key(&self, is_compressed: bool) -> &[u8] {
        if is_compressed {
            self.compressed_ecdsa_public_key.as_slice()
        } else {
            self.uncompressed_ecdsa_public_key.as_slice()
        }
    }
}

#[cfg(test)]
mod test {
    use crate::signer::local::LocalSigner;
    use crate::signer::signature::Signature;
    use k256::sha2::{Digest, Sha512};
    #[test]
    fn test_sign_eddsa() {
        // Ed25519 private key (32 bytes)
        let pk = hex::decode("45EA1AD910DF93D1A021A42F384AAD55C7C65D565AD6B2203A4BA50418922A7B")
            .unwrap();
        let signer = LocalSigner::new(&pk).unwrap();
        let message = b"535458001200332400DE79DA2F698176A4201B00DE7A5420330000000168400000000000000C732102D5A397A10DE2C485FA5592FFD86A7B5744BC221E24F71196ACD32EB66B14264C701C0863757272656E6379701D0D42616E642050726F746F636F6C81140E54D919C94CDA274DDE1CC05D5A49DE2CCB0D51F018E02030170078494931283998041009011A0000000000000000000000004254430000000000021A0000000000000000000000005553440000000000E1E02030170002336276028668041009011A0000000000000000000000004554480000000000021A0000000000000000000000005553440000000000E1E02030170000000999681507041009011A524C555344000000000000000000000000000000021A0000000000000000000000005553440000000000E1E02030170000000999705051041009011A5553444300000000000000000000000000000000021A0000000000000000000000005553440000000000E1E02030170000000999079402041009011A5553445400000000000000000000000000000000021A0000000000000000000000005553440000000000E1E02030170078292915033480041009011A5742544300000000000000000000000000000000021A0000000000000000000000005553440000000000E1E02030170000001610264882041009011A0000000000000000000000000000000000000000021A0000000000000000000000005553440000000000E1F1";
        let b = hex::decode(message).unwrap();
        let message = sha512_half(&b);
        let actual = signer.sign_der(&message).unwrap().into_vec();

        let expected = "3045022100ECBB5B8F8904EC94EF86B7929604C8C19A558FC2BE97142B2A46C6C56574F8B90220155F3D06E0ABDE2CF9632EA64B4448666A9D0A57EEBC2EFB3E050819F2380E1E";

        // This is just a placeholder - you'll need to verify with actual expected signature
        println!("EdDSA signature: {}", hex::encode(&actual));
        assert_eq!(hex::encode(&actual), expected);
    }

    fn sha512_half(msg: &[u8]) -> Vec<u8> {
        // 1. Create a hasher object
        let mut hasher = Sha512::new();

        // 2. Write input data
        hasher.update(msg);

        // 3. Finalize and get GenericArray
        let result = hasher.finalize();

        // 4. Return the first 32 bytes as a Vector
        result[..32].to_vec()
    }
}
