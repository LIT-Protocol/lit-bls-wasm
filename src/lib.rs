use blsful::{
    Bls12381G1Impl, Bls12381G2Impl, BlsSignatureImpl, PublicKey, Signature, SignatureSchemes,
    SignatureShare, TimeCryptCiphertext,
};
use serde::{de::DeserializeOwned, Serialize};
use wasm_bindgen::prelude::wasm_bindgen;
use wasm_bindgen::JsValue;

const SIGNATURE_G2_PUBLIC_KEY_HEX_LENGTH: usize = 96;
const SIGNATURE_G1_PUBLIC_KEY_HEX_LENGTH: usize = 192;
const SIGNATURE_G1_SHARE_HEX_LENGTH: usize = 122;
const SIGNATURE_G2_SHARE_HEX_LENGTH: usize = 218;

#[wasm_bindgen]
#[doc = "Initialize function for the wasm library"]
pub fn initialize() {
    std::panic::set_hook(Box::new(console_error_panic_hook::hook));
}

#[wasm_bindgen]
#[doc = "Encrypts the data to the public key and identity. All inputs are hex encoded strings."]
pub fn encrypt(public_key: &str, message: &str, identity: &str) -> Result<String, String> {
    let message = hex::decode(message).map_err(|e| format!("Failed to parse message: {}", e))?;
    let identity = hex::decode(identity).map_err(|e| format!("Failed to parse identity: {}", e))?;
    match public_key.len() {
        96 => encrypt_time_lock::<Bls12381G2Impl>(public_key, message, identity),
        192 => encrypt_time_lock::<Bls12381G1Impl>(public_key, message, identity),
        _ => Err("Invalid public key length".to_string()),
    }
}

pub fn encrypt_time_lock<C: BlsSignatureImpl + Serialize>(
    public_key: &str,
    message: Vec<u8>,
    identity: Vec<u8>,
) -> Result<String, String> {
    let key = serde_json::from_str::<PublicKey<C>>(&format!("\"{}\"", public_key))
        .map_err(|e| format!("Failed to parse public key: {}", e))?;
    key.encrypt_time_lock(SignatureSchemes::ProofOfPossession, message, identity)
        .map_err(|e| format!("Failed to encrypt: {}", e))
        .map(|ciphertext| {
            let mut output = Vec::new();
            ciborium::into_writer(&ciphertext, &mut output).unwrap();
            hex::encode(output)
        })
}

#[wasm_bindgen]
#[doc = "Verifies the decryption shares are valid and decrypts the data."]
pub fn verify_and_decrypt_with_signature_shares(
    public_key: &str,
    identity: &str,
    ciphertext: &str,
    shares: JsValue,
) -> Result<String, String> {
    let shares = serde_wasm_bindgen::from_value::<Vec<String>>(shares)
        .map_err(|e| format!("Failed to parse shares: {}", e))?;

    if shares.len() < 2 {
        return Err("At least two shares are required".to_string());
    }
    let ciphertext =
        hex::decode(ciphertext).map_err(|e| format!("Failed to parse ciphertext: {}", e))?;
    let identity = hex::decode(identity).map_err(|e| format!("Failed to parse identity: {}", e))?;

    match public_key.len() {
        SIGNATURE_G2_PUBLIC_KEY_HEX_LENGTH => {
            verify_and_decrypt::<Bls12381G2Impl>(public_key, &identity, &ciphertext, &shares)
        }
        SIGNATURE_G1_PUBLIC_KEY_HEX_LENGTH => {
            verify_and_decrypt::<Bls12381G1Impl>(public_key, &identity, &ciphertext, &shares)
        }
        _ => Err("Invalid shares".to_string()),
    }
}

fn verify_and_decrypt<C: BlsSignatureImpl + DeserializeOwned>(
    public_key: &str,
    identity: &[u8],
    ciphertext: &[u8],
    shares: &[String],
) -> Result<String, String> {
    let key = serde_json::from_str::<PublicKey<C>>(&format!("\"{}\"", public_key))
        .map_err(|e| format!("Failed to parse public key: {}", e))?;
    let signature = combine_signature_shares::<C>(shares)?;
    signature
        .verify(&key, identity)
        .map_err(|e| format!("Failed to verify signature: {}", e))?;
    let ciphertext =
        ciborium::de::from_reader::<TimeCryptCiphertext<C>, _>(std::io::Cursor::new(ciphertext))
            .map_err(|e| format!("Failed to parse ciphertext: {}", e))?;
    Option::<Vec<u8>>::from(ciphertext.decrypt(&signature))
        .map(hex::encode)
        .ok_or_else(|| "Failed to decrypt".to_string())
}

#[wasm_bindgen]
#[doc = "Decrypts the data with signature shares."]
pub fn decrypt_with_signature_shares(ciphertext: &str, shares: JsValue) -> Result<String, String> {
    let shares = serde_wasm_bindgen::from_value::<Vec<String>>(shares)
        .map_err(|e| format!("Failed to parse shares: {}", e))?;

    if shares.len() < 2 {
        return Err("At least two shares are required".to_string());
    }

    let ciphertext =
        hex::decode(ciphertext).map_err(|e| format!("Failed to parse ciphertext: {}", e))?;

    match shares[0].len() {
        SIGNATURE_G1_SHARE_HEX_LENGTH => decrypt_time_lock::<Bls12381G1Impl>(&ciphertext, &shares),
        SIGNATURE_G2_SHARE_HEX_LENGTH => decrypt_time_lock::<Bls12381G2Impl>(&ciphertext, &shares),
        _ => Err("Invalid shares".to_string()),
    }
}

pub fn decrypt_time_lock<C: BlsSignatureImpl + DeserializeOwned>(
    ciphertext: &[u8],
    shares: &[String],
) -> Result<String, String> {
    let decryption_key = combine_signature_shares::<C>(shares)?;
    let ciphertext = ciborium::de::from_reader::<TimeCryptCiphertext<C>, _>(ciphertext)
        .map_err(|e| format!("Failed to parse ciphertext: {}", e))?;
    Option::<Vec<u8>>::from(ciphertext.decrypt(&decryption_key))
        .map(hex::encode)
        .ok_or_else(|| "Failed to decrypt".to_string())
}

fn combine_signature_shares<C: BlsSignatureImpl + DeserializeOwned>(
    shares: &[String],
) -> Result<Signature<C>, String> {
    let mut signature_shares = Vec::with_capacity(shares.len());
    for share in shares {
        let share = serde_json::from_str::<SignatureShare<C>>(share)
            .map_err(|e| format!("Failed to parse share: {}", e))?;
        signature_shares.push(share);
    }
    Signature::from_shares(&signature_shares)
        .map_err(|e| format!("Failed to combine signature shares: {}", e))
}

#[cfg(test)]
mod tests {
    use super::*;
    use blsful::*;
    use k256::ecdsa::SigningKey;
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;

    fn get_crypto_rng() -> ChaCha20Rng {
        ChaCha20Rng::from_entropy()
    }

    #[test]
    fn works() {
        const ID: &[u8] = b"encrypt_decrypt_works";
        let sk = Bls12381G2::new_secret_key();
        let shares = sk.split_with_rng(2, 3, &mut get_crypto_rng()).unwrap();
        let sig_shares = shares
            .iter()
            .map(|s| s.sign(SignatureSchemes::ProofOfPossession, ID).unwrap())
            .collect::<Vec<_>>();
        let hex_shares = sig_shares
            .iter()
            .map(|s| serde_json::to_string(&s).unwrap())
            .collect::<Vec<_>>();
        let pk = sk.public_key();
        let hex_pk = serde_json::to_string(&pk).unwrap();
        let user_sk = SigningKey::random(&mut get_crypto_rng());
        let sk_bytes = user_sk.to_bytes();

        let res = encrypt_time_lock::<Bls12381G2Impl>(
            &rem_first_and_last(hex_pk.clone()),
            sk_bytes.to_vec(),
            ID.to_vec(),
        );
        assert!(res.is_ok());
        let ciphertext = res.unwrap();
        let res = decrypt_time_lock::<Bls12381G2Impl>(
            &hex::decode(ciphertext.clone()).unwrap(),
            &hex_shares,
        );
        assert!(res.is_ok());
        let plaintext = res.unwrap();
        assert_eq!(sk_bytes.to_vec(), hex::decode(plaintext).unwrap());

        let res = verify_and_decrypt::<Bls12381G2Impl>(
            &rem_first_and_last(hex_pk),
            ID,
            hex::decode(&ciphertext).unwrap().as_slice(),
            &hex_shares,
        );
        assert!(res.is_ok());
        let plaintext = res.unwrap();
        assert_eq!(sk_bytes.to_vec(), hex::decode(plaintext).unwrap());
    }

    fn rem_first_and_last(value: String) -> String {
        let mut chars = value.chars();
        chars.next();
        chars.next_back();
        chars.as_str().to_string()
    }
}
