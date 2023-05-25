use base64_light::{base64_decode, base64_encode_bytes};
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
    let message = base64_decode(message);
    let identity = base64_decode(identity);
    match public_key.len() {
        96 => encrypt_time_lock::<Bls12381G2Impl>(public_key, message, identity),
        192 => encrypt_time_lock::<Bls12381G1Impl>(public_key, message, identity),
        _ => Err("Invalid public key length. Must be 96 or 192 hexits.".to_string()),
    }
}

pub fn encrypt_time_lock<C: BlsSignatureImpl + Serialize>(
    public_key: &str,
    message: Vec<u8>,
    identity: Vec<u8>,
) -> Result<String, String> {
    let key = serde_json::from_str::<PublicKey<C>>(&quote(public_key))
        .map_err(|_e| "Failed to parse public key as a json hex string".to_string())?;
    key.encrypt_time_lock(SignatureSchemes::ProofOfPossession, message, identity)
        .map_err(|_e| "Unable to encrypt data".to_string())
        .map(|ciphertext| {
            let output = serde_bare::to_vec(&ciphertext).unwrap();
            base64_encode_bytes(&output)
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
        .map_err(|_e| "Failed to parse shares".to_string())?;

    if shares.len() < 2 {
        return Err("At least two shares are required".to_string());
    }
    let ciphertext = base64_decode(ciphertext);
    let identity = base64_decode(identity);

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
    let key = serde_json::from_str::<PublicKey<C>>(&quote(public_key))
        .map_err(|_e| "Failed to hex decode public key".to_string())?;
    let signature = combine_signature_shares::<C>(shares)?;
    signature
        .verify(&key, identity)
        .map_err(|_e| "Failed to verify signature".to_string())?;
    let ciphertext = serde_bare::from_slice::<TimeCryptCiphertext<C>>(ciphertext)
        .map_err(|_e| "Failed to hex decode ciphertext".to_string())?;
    Option::<Vec<u8>>::from(ciphertext.decrypt(&signature))
        .map(|c| base64_encode_bytes(&c))
        .ok_or_else(|| "Failed to decrypt".to_string())
}

#[wasm_bindgen]
#[doc = "Decrypts the data with signature shares."]
pub fn decrypt_with_signature_shares(ciphertext: &str, shares: JsValue) -> Result<String, String> {
    let shares = serde_wasm_bindgen::from_value::<Vec<String>>(shares)
        .map_err(|_e| "Failed to parse shares".to_string())?;

    if shares.len() < 2 {
        return Err("At least two shares are required".to_string());
    }

    let ciphertext = base64_decode(ciphertext);

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
    let ciphertext = serde_bare::from_slice::<TimeCryptCiphertext<C>>(ciphertext)
        .map_err(|_e| "Failed to parse ciphertext".to_string())?;
    Option::<Vec<u8>>::from(ciphertext.decrypt(&decryption_key))
        .map(|c| base64_encode_bytes(&c))
        .ok_or_else(|| "Failed to decrypt".to_string())
}

fn combine_signature_shares<C: BlsSignatureImpl + DeserializeOwned>(
    shares: &[String],
) -> Result<Signature<C>, String> {
    let mut signature_shares = Vec::with_capacity(shares.len());
    for share in shares {
        let share = serde_json::from_str::<SignatureShare<C>>(share)
            .map_err(|_e| "Failed to parse share".to_string())?;
        signature_shares.push(share);
    }
    Signature::from_shares(&signature_shares)
        .map_err(|_e| "Failed to combine signature shares".to_string())
}

fn quote(s: &str) -> String {
    let mut ss = String::with_capacity(s.len() + 2);
    ss.push('"');
    ss.push_str(s);
    ss.push('"');
    ss
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
        let res = decrypt_time_lock::<Bls12381G2Impl>(&base64_decode(&ciphertext), &hex_shares);
        assert!(res.is_ok());
        let plaintext = res.unwrap();
        assert_eq!(sk_bytes.to_vec(), base64_decode(&plaintext));

        let res = verify_and_decrypt::<Bls12381G2Impl>(
            &rem_first_and_last(hex_pk),
            ID,
            base64_decode(&ciphertext).as_slice(),
            &hex_shares,
        );
        assert!(res.is_ok());
        let plaintext = res.unwrap();
        assert_eq!(sk_bytes.to_vec(), base64_decode(&plaintext));
    }

    #[test]
    fn size() {
        const ID: &[u8] = b"size";
        let sk = Bls12381G2::new_secret_key();
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
        println!("bare size = {}", base64_decode(&ciphertext).len());
        // compare to CBOR
        let bin_ciphertext = base64_decode(&ciphertext);
        let obj_ciphertext =
            serde_bare::from_slice::<TimeCryptCiphertext<Bls12381G2Impl>>(&bin_ciphertext).unwrap();
        let mut cbor = Vec::new();
        ciborium::into_writer(&obj_ciphertext, &mut cbor).unwrap();
        println!("cbor size = {}", cbor.len());
    }

    fn rem_first_and_last(value: String) -> String {
        let mut chars = value.chars();
        chars.next();
        chars.next_back();
        chars.as_str().to_string()
    }
}
