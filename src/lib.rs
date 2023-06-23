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
    let signature = combine_signature_shares_inner::<C>(shares)?;
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
    let decryption_key = combine_signature_shares_inner::<C>(shares)?;
    let ciphertext = serde_bare::from_slice::<TimeCryptCiphertext<C>>(ciphertext)
        .map_err(|_e| "Failed to parse ciphertext".to_string())?;
    Option::<Vec<u8>>::from(ciphertext.decrypt(&decryption_key))
        .map(|c| base64_encode_bytes(&c))
        .ok_or_else(|| "Failed to decrypt".to_string())
}

#[wasm_bindgen]
#[doc = "Combines the signature shares into a single signature."]
pub fn combine_signature_shares(shares: JsValue) -> Result<String, String> {
    let shares = serde_wasm_bindgen::from_value::<Vec<String>>(shares)
        .map_err(|_e| "Failed to parse shares".to_string())?;

    if shares.len() < 2 {
        return Err("At least two shares are required".to_string());
    }

    match shares[0].len() {
        SIGNATURE_G1_SHARE_HEX_LENGTH => combine_signature_shares_inner::<Bls12381G1Impl>(&shares).map(|s| hex::encode(s.as_raw_value().to_compressed())),
        SIGNATURE_G2_SHARE_HEX_LENGTH => combine_signature_shares_inner::<Bls12381G2Impl>(&shares).map(|s| hex::encode(s.as_raw_value().to_compressed())),
        _ => Err("Invalid shares".to_string()),
    }
}

fn combine_signature_shares_inner<C: BlsSignatureImpl + DeserializeOwned>(
    shares: &[String],
) -> Result<Signature<C>, String> {
    let mut signature_shares = Vec::with_capacity(shares.len());
    for share in shares {
        let share = serde_json::from_str::<SignatureShare<C>>(share)
            .map_err(|_e| "Failed to parse share".to_string())?;
        signature_shares.push(share);
    }
    Signature::from_shares(&signature_shares)
        .map_err(|_e| format!("Failed to combine signature shares: {}", _e))
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
    fn test_combine_signature_shares_inner() {
        let res = combine_signature_shares_inner::<Bls12381G2Impl>(&vec![
            r#"{"ProofOfPossession":"0292575ada70fcd604499062a0518c61726d3172f3d58bcafdaed1475b7beee4f4e46a88e326378961dd877d1ca0db2989170535dbf5c773fa9933fd8ca0260b9e762ee7a81ea2957e7cb3211f1e43973eab8e418fde6e316c35e9bb3221bd50af"}"#.to_string(),
            r#"{"ProofOfPossession":"01b6ce4a8bc406706315287bc7615c225206bfc26e75b532ec7299b9ad538b184b7bf91ba953199f207c8502806276f14c0b8864343888b060f8d4c8f58514563d788b54344401470178621500d053cbfc5322baa15d1125c830762a8a5b07a273"}"#.to_string(),
            r#"{"ProofOfPossession":"038c6a9a1aa415b49cffced6fa2054718bfda766a160e4968dc72cad861cfdbe2248eb0b93ebde19c026383692c0ad05311335fa9d96e5c58e1d004059f1cfd4429d3b2e3a2284b9060dfb9c97996feec169c37e20a32ffce93e4ee44af53c9587"}"#.to_string(),
        ]);
        assert!(res.is_ok());
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
