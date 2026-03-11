use crate::config::tss::group::Group;
use anyhow::anyhow;
use k256::{
    AffinePoint, ProjectivePoint, PublicKey, Scalar,
    elliptic_curve::{PrimeField, sec1::ToEncodedPoint},
};
use std::ops::Neg;
use std::time::{SystemTime, UNIX_EPOCH};
use tiny_keccak::{Hasher, Keccak};
use tracing::warn;

const CONTEXT_STRING: &[u8] = b"BAND-TSS-secp256k1-v0";

pub struct SignatureVerifier {
    groups: Vec<Group>,
}

impl SignatureVerifier {
    pub fn new(groups: Vec<Group>) -> Self {
        Self { groups }
    }

    pub fn verify_signature(
        &self,
        tss_message: &[u8],
        random_addr: &[u8],
        signature_s: &[u8],
    ) -> anyhow::Result<()> {
        let current_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| anyhow!("Failed to get current time"))?
            .as_secs();

        for group in &self.groups {
            // check is expired
            if current_time > group.expired_time {
                warn!("TSS group is expired");
                continue;
            }
            match Self::verify(group.public_key, tss_message, random_addr, signature_s) {
                Ok(_) => return Ok(()),
                Err(e) => warn!("failed to verify TSS signature: {}", e),
            }
        }
        Err(anyhow!("All TSS verification failed"))
    }

    fn verify(
        group_public_key: [u8; 33],
        tss_message: &[u8],
        random_addr: &[u8],
        signature_s: &[u8],
    ) -> anyhow::Result<()> {
        // 1. Validate Input Lengths
        let r_addr_bytes: [u8; 20] = random_addr
            .try_into()
            .map_err(|_| anyhow!("Invalid random_addr length: expected 20 bytes"))?;

        let s_bytes_raw: [u8; 32] = signature_s
            .try_into()
            .map_err(|_| anyhow!("Invalid signature_s length: expected 32 bytes"))?;

        // 2. Derive hashed_message
        let mut hasher = Keccak::v256();
        hasher.update(tss_message);
        let mut hashed_message = [0u8; 32];
        hasher.finalize(&mut hashed_message);

        // 3. Parse Group Public Key (Q)
        let pub_key = PublicKey::from_sec1_bytes(&group_public_key)
            .map_err(|e| anyhow!("Failed to parse group public key: {}", e))?;
        let q = ProjectivePoint::from(pub_key.as_affine());

        // 4. Parse Signature S (s)
        let s_field_bytes = k256::FieldBytes::from_slice(&s_bytes_raw);
        let s = Scalar::from_repr(*s_field_bytes)
            .into_option()
            .ok_or_else(|| anyhow!("Invalid signature S: scalar out of range"))?;

        // 5. Compute Challenge (c)
        let challenge_scalar =
            Self::compute_challenge(&group_public_key, r_addr_bytes, hashed_message)?;

        // 6. Verify: R' = sG - cQ
        let generator = ProjectivePoint::GENERATOR;
        let neg_c = challenge_scalar.neg();
        let r_prime: ProjectivePoint = (generator * s) + (q * neg_c);
        let r_prime_affine = r_prime.to_affine();

        if r_prime_affine == AffinePoint::IDENTITY {
            return Err(anyhow!("Verification failed: R' is point at infinity"));
        }

        // 7. Derived R' Address must match the provided random_addr
        let derived_addr = Self::point_to_address(&r_prime_affine)?;

        if derived_addr != r_addr_bytes {
            return Err(anyhow!(
                "Address mismatch: expected {}, derived {}",
                hex::encode(r_addr_bytes),
                hex::encode(derived_addr)
            ));
        }

        Ok(())
    }

    fn compute_challenge(
        group_public_key: &[u8],
        r_addr: [u8; 20],
        msg_hash: [u8; 32],
    ) -> anyhow::Result<Scalar> {
        let mut hasher = Keccak::v256();
        hasher.update(CONTEXT_STRING);
        hasher.update(&[0]);
        hasher.update(b"challenge");
        hasher.update(&[0]);
        hasher.update(&r_addr);

        let parity = group_public_key[0]
            .checked_add(25)
            .ok_or_else(|| anyhow!("band_prefix overflow when computing challenge"))?;
        hasher.update(&[parity]);
        hasher.update(&group_public_key[1..33]);
        hasher.update(&msg_hash);

        let mut output = [0u8; 32];
        hasher.finalize(&mut output);

        let scalar_bytes = k256::FieldBytes::from_slice(&output);
        Scalar::from_repr(*scalar_bytes)
            .into_option()
            .ok_or_else(|| anyhow!("Computed challenge is not a valid scalar"))
    }

    fn point_to_address(point: &AffinePoint) -> anyhow::Result<[u8; 20]> {
        let encoded = point.to_encoded_point(false);

        // Use context to provide more info if coordinates are somehow missing
        let x = encoded
            .x()
            .ok_or_else(|| anyhow!("Failed to extract X coordinate from R'"))?;
        let y = encoded
            .y()
            .ok_or_else(|| anyhow!("Failed to extract Y coordinate from R'"))?;

        let mut hasher = Keccak::v256();
        hasher.update(x);
        hasher.update(y);

        let mut hash = [0u8; 32];
        hasher.finalize(&mut hash);

        let mut addr = [0u8; 20];
        addr.copy_from_slice(&hash[12..]);
        Ok(addr)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hex_literal::hex;

    #[test]
    fn test_band_tss_verification_expired_group() {
        let verifier = SignatureVerifier::new(vec![]);

        let raw_data = hex!("64617461");

        let r_address = hex!("c53ec7134bad7bca43a34b6a0cf9eb1daa531d3e");
        let signature_s = hex!("DF8DE9F4F2A046EB25EC45194AD2ED4B3D2339BAEDA82C97DD1AF02CDD63F98F");

        assert!(
            verifier
                .verify_signature(&raw_data, &r_address, &signature_s)
                .is_err()
        );
    }

    #[test]
    fn test_band_tss_verification_1() {
        // 1. Setup the Group Public Key
        // Based on your snippet: Prefix 0x02 or 0x03 (compressed) + X coordinate
        // If parity was 28 (even), prefix is 0x02.
        let mut group_pk = [0u8; 33];
        group_pk.copy_from_slice(&hex!(
            "030B03A4E74E06E18DE6BFD16A06E6401BC1FE74A983817C4AC3C1E2F4048E0A4C"
        ));

        let verifier = SignatureVerifier::new(vec![Group {
            public_key: group_pk,
            expired_time: u64::MAX,
        }]);

        // 2. Prepare the Inputs
        let raw_data = hex!("64617461");

        let r_address = hex!("c53ec7134bad7bca43a34b6a0cf9eb1daa531d3e");
        let signature_s = hex!("DF8DE9F4F2A046EB25EC45194AD2ED4B3D2339BAEDA82C97DD1AF02CDD63F98F");

        // 3. Execution
        let result = verifier.verify_signature(&raw_data, &r_address, &signature_s);

        assert!(
            result.is_ok(),
            "Verification failed! Check if the group_pk prefix (0x02/0x03) matches the Go source."
        );
    }

    #[test]
    fn test_band_tss_verification_2() {
        // 1. Setup the Group Public Key
        // Based on your snippet: Prefix 0x02 or 0x03 (compressed) + X coordinate
        // If parity was 28 (even), prefix is 0x02.
        let mut group_pk = [0u8; 33];
        group_pk.copy_from_slice(&hex!(
            "0306be2adaf05e8ffc701c9241d6e147fcd7ff4f72e1da6aacd7158fa2a3919354"
        ));

        let verifier = SignatureVerifier::new(vec![Group {
            public_key: group_pk,
            expired_time: u64::MAX,
        }]);

        // 2. Prepare the Inputs
        let raw_data = hex!(
            "C4166DC10C647058665EAC4CC84ACBD9547094DB4241CEE6B39B54D11EFA9FB00000000069842F270000000000F45CA3D3813E0CCBA0AD5A000000000000000000000000000000000000000000000000000000000000002000000000000000000000000000000000000000000000000000000000000021EF00000000000000000000000000000000000000000000000000000000000000600000000000000000000000000000000000000000000000000000000069842F2700000000000000000000000000000000000000000000000000000000000000070000000000000000000000000000000000000000000043533A4254432D555344000000000000000000000000000000000000000000000000000040222E4113840000000000000000000000000000000000000000000043533A4554482D555344000000000000000000000000000000000000000000000000000001E8AEF33FE0000000000000000000000000000000000000000043533A524C5553442D555344000000000000000000000000000000000000000000000000000000003B97DF5B00000000000000000000000000000000000000000043533A555344432D555344000000000000000000000000000000000000000000000000000000003B9791C800000000000000000000000000000000000000000043533A555344542D555344000000000000000000000000000000000000000000000000000000003B7C085E00000000000000000000000000000000000000000043533A574254432D5553440000000000000000000000000000000000000000000000000000403E2BAE62BF0000000000000000000000000000000000000000000043533A5852502D5553440000000000000000000000000000000000000000000000000000000055D7DF3B"
        );

        let r_address = hex!("9E446B99E550A61A204BEE41D34702093D1EE4CA");
        let signature_s = hex!("F8A67A9390C1C428498FCA262D6BA5D662BC8E5E2F48D4D4134E81ADF0A32A2D");

        // 3. Execution
        let result = verifier.verify_signature(&raw_data, &r_address, &signature_s);

        assert!(
            result.is_ok(),
            "Verification failed! Check if the group_pk prefix (0x02/0x03) matches the Go source."
        );
    }
}
