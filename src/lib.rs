use base64_light::{base64_decode, base64_encode_bytes};
use blsful::inner_types::{G1Projective, G2Projective, GroupEncoding};
use blsful::{
    Bls12381G1Impl, Bls12381G2Impl, BlsSignatureImpl, PublicKey, Signature, SignatureSchemes,
    SignatureShare, TimeCryptCiphertext,
};
use serde::{de::DeserializeOwned, Serialize};
use wasm_bindgen::prelude::wasm_bindgen;
use wasm_bindgen::JsValue;

const SIGNATURE_G2_PUBLIC_KEY_HEX_LENGTH: usize = 96;
const SIGNATURE_G1_PUBLIC_KEY_HEX_LENGTH: usize = 192;

const SIGNATURE_G1_SHARE_JSON_LENGTH_V1: usize = 122;
const SIGNATURE_G1_SHARE_JSON_LENGTH: usize = 210;
const SIGNATURE_G2_SHARE_JSON_LENGTH: usize = 306;
const SIGNATURE_G2_SHARE_JSON_LENGTH_V1: usize = 218;

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
        SIGNATURE_G2_PUBLIC_KEY_HEX_LENGTH => {
            encrypt_time_lock::<Bls12381G2Impl>(public_key, message, identity)
        }
        SIGNATURE_G1_PUBLIC_KEY_HEX_LENGTH => {
            encrypt_time_lock::<Bls12381G1Impl>(public_key, message, identity)
        }
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
        SIGNATURE_G2_PUBLIC_KEY_HEX_LENGTH => verify_and_decrypt::<
            Bls12381G2Impl,
            blsful2::Bls12381G2Impl,
        >(public_key, &identity, &ciphertext, &shares),
        SIGNATURE_G1_PUBLIC_KEY_HEX_LENGTH => verify_and_decrypt::<
            Bls12381G1Impl,
            blsful2::Bls12381G1Impl,
        >(public_key, &identity, &ciphertext, &shares),
        _ => Err("Invalid shares".to_string()),
    }
}

pub fn verify_and_decrypt<
    C: BlsSignatureImpl + DeserializeOwned,
    CC: blsful2::BlsSignatureImpl + DeserializeOwned,
>(
    public_key: &str,
    identity: &[u8],
    ciphertext: &[u8],
    shares: &[String],
) -> Result<String, String> {
    let key = serde_json::from_str::<PublicKey<C>>(&quote(public_key))
        .map_err(|_e| "Failed to hex decode public key".to_string())?;
    let signature = combine_signature_shares_inner::<C>(shares)
        .or_else(|_| combine_signature_shares_inner_v1::<C, CC>(shares))?;
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
        SIGNATURE_G1_SHARE_JSON_LENGTH_V1 | SIGNATURE_G1_SHARE_JSON_LENGTH => {
            decrypt_time_lock::<Bls12381G1Impl, blsful2::Bls12381G1Impl>(&ciphertext, &shares)
        }
        SIGNATURE_G2_SHARE_JSON_LENGTH_V1 | SIGNATURE_G2_SHARE_JSON_LENGTH => {
            decrypt_time_lock::<Bls12381G2Impl, blsful2::Bls12381G2Impl>(&ciphertext, &shares)
        }
        _ => Err("Invalid shares".to_string()),
    }
}

pub fn decrypt_time_lock<
    C: BlsSignatureImpl + DeserializeOwned,
    CC: blsful2::BlsSignatureImpl + DeserializeOwned,
>(
    ciphertext: &[u8],
    shares: &[String],
) -> Result<String, String> {
    let decryption_key = combine_signature_shares_inner::<C>(shares)
        .or_else(|_| combine_signature_shares_inner_v1::<C, CC>(shares))?;
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
        SIGNATURE_G1_SHARE_JSON_LENGTH_V1 | SIGNATURE_G1_SHARE_JSON_LENGTH => {
            combine_signature_shares_inner::<Bls12381G1Impl>(&shares)
                .or_else(|_| {
                    combine_signature_shares_inner_v1::<Bls12381G1Impl, blsful2::Bls12381G1Impl>(
                        &shares,
                    )
                })
                .map(|s| hex::encode(s.as_raw_value().to_bytes()))
        }
        SIGNATURE_G2_SHARE_JSON_LENGTH_V1 | SIGNATURE_G2_SHARE_JSON_LENGTH => {
            combine_signature_shares_inner::<Bls12381G2Impl>(&shares)
                .or_else(|_| {
                    combine_signature_shares_inner_v1::<Bls12381G2Impl, blsful2::Bls12381G2Impl>(
                        &shares,
                    )
                })
                .map(|s| hex::encode(s.as_raw_value().to_bytes()))
        }
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

fn combine_signature_shares_inner_v1<
    C: BlsSignatureImpl,
    CC: blsful2::BlsSignatureImpl + DeserializeOwned,
>(
    shares: &[String],
) -> Result<Signature<C>, String> {
    let mut signature_shares = Vec::with_capacity(shares.len());
    for share in shares {
        let old_share_format = serde_json::from_str::<blsful2::SignatureShare<CC>>(share)
            .map_err(|_e| "Failed to parse share".to_string())?;
        let bytes = Vec::<u8>::from(&old_share_format);
        let share = SignatureShare::from_v1_inner_bytes(&bytes)
            .map_err(|_e| "Failed to parse share".to_string())?;

        signature_shares.push(share);
    }
    Signature::from_shares(&signature_shares)
        .map_err(|_e| format!("Failed to combine signature shares: {}", _e))
}

#[wasm_bindgen]
#[doc = "Verifies the signature."]
pub fn verify_signature(public_key: &str, message: &str, signature: &str) -> Result<(), String> {
    let message = base64_decode(message);
    let signature = base64_decode(signature);
    match public_key.len() {
        SIGNATURE_G2_PUBLIC_KEY_HEX_LENGTH => {
            verify_signature_inner_g2(public_key, &message, &signature)
        }
        SIGNATURE_G1_PUBLIC_KEY_HEX_LENGTH => {
            verify_signature_inner_g1(public_key, &message, &signature)
        }
        _ => Err("Invalid public key length. Must be 96 or 192 hexits.".to_string()),
    }
}

pub fn verify_signature_inner_g2(
    public_key: &str,
    message: &[u8],
    signature: &[u8],
) -> Result<(), String> {
    let key = serde_json::from_str::<PublicKey<Bls12381G2Impl>>(&quote(public_key))
        .map_err(|_e| "Failed to hex decode public key".to_string())?;

    // The compressed signature of 96 bytes.
    let g2_projective = G2Projective::from_compressed(
        &signature
            .try_into()
            .map_err(|_e| "Failed to cast to compressed byte slice".to_string())?,
    )
    .unwrap();
    let signature: Signature<Bls12381G2Impl> = Signature::ProofOfPossession(g2_projective);

    signature
        .verify(&key, message)
        .map_err(|_e| "Failed to verify signature".to_string())?;

    Ok(())
}

pub fn verify_signature_inner_g1(
    public_key: &str,
    message: &[u8],
    signature: &[u8],
) -> Result<(), String> {
    let key = serde_json::from_str::<PublicKey<Bls12381G1Impl>>(&quote(public_key))
        .map_err(|_e| "Failed to hex decode public key".to_string())?;

    // The compressed signature of 48 bytes.
    let g1_projective = G1Projective::from_compressed(
        &signature
            .try_into()
            .map_err(|_e| "Failed to cast to compressed byte slice".to_string())?,
    )
    .unwrap();
    let signature: Signature<Bls12381G1Impl> = Signature::ProofOfPossession(g1_projective);

    signature
        .verify(&key, message)
        .map_err(|_e| "Failed to verify signature".to_string())?;

    Ok(())
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
    fn test_verify_signature() {
        let res = verify_signature_inner_g2(
            "ad1bd6c66f849ccbcc20fa08c26108f3df7db0068df032cc184779cc967159da4dd5669de563af7252b540f0759aee5a",
            &[101, 121, 74, 104, 98, 71, 99, 105, 79, 105, 74, 67, 84, 70, 77, 120, 77, 105, 48, 122, 79, 68, 69, 105, 76, 67, 74, 48, 101, 88, 65, 105, 79, 105, 74, 75, 86, 49, 81, 105, 102, 81, 46, 101, 121, 74, 112, 99, 51, 77, 105, 79, 105, 74, 77, 83, 86, 81, 105, 76, 67, 74, 122, 100, 87, 73, 105, 79, 105, 73, 119, 101, 68, 81, 121, 78, 84, 108, 108, 78, 68, 81, 50, 78, 122, 65, 119, 78, 84, 77, 48, 79, 84, 70, 108, 78, 50, 73, 48, 90, 109, 85, 48, 89, 84, 69, 121, 77, 71, 77, 51, 77, 71, 74, 108, 77, 87, 86, 104, 90, 68, 89, 48, 78, 109, 73, 105, 76, 67, 74, 106, 97, 71, 70, 112, 98, 105, 73, 54, 73, 109, 86, 48, 97, 71, 86, 121, 90, 88, 86, 116, 73, 105, 119, 105, 97, 87, 70, 48, 73, 106, 111, 120, 78, 106, 103, 51, 78, 84, 89, 121, 77, 106, 99, 49, 76, 67, 74, 108, 101, 72, 65, 105, 79, 106, 69, 50, 79, 68, 99, 50, 77, 68, 85, 48, 78, 122, 85, 115, 73, 109, 70, 106, 89, 50, 86, 122, 99, 48, 78, 118, 98, 110, 82, 121, 98, 50, 120, 68, 98, 50, 53, 107, 97, 88, 82, 112, 98, 50, 53, 122, 73, 106, 112, 98, 101, 121, 74, 106, 98, 50, 53, 48, 99, 109, 70, 106, 100, 69, 70, 107, 90, 72, 74, 108, 99, 51, 77, 105, 79, 105, 73, 105, 76, 67, 74, 106, 97, 71, 70, 112, 98, 105, 73, 54, 73, 109, 86, 48, 97, 71, 86, 121, 90, 88, 86, 116, 73, 105, 119, 105, 99, 51, 82, 104, 98, 109, 82, 104, 99, 109, 82, 68, 98, 50, 53, 48, 99, 109, 70, 106, 100, 70, 82, 53, 99, 71, 85, 105, 79, 105, 73, 105, 76, 67, 74, 116, 90, 88, 82, 111, 98, 50, 81, 105, 79, 105, 73, 105, 76, 67, 74, 119, 89, 88, 74, 104, 98, 87, 86, 48, 90, 88, 74, 122, 73, 106, 112, 98, 73, 106, 112, 49, 99, 50, 86, 121, 81, 87, 82, 107, 99, 109, 86, 122, 99, 121, 74, 100, 76, 67, 74, 121, 90, 88, 82, 49, 99, 109, 53, 87, 89, 87, 120, 49, 90, 86, 82, 108, 99, 51, 81, 105, 79, 110, 115, 105, 89, 50, 57, 116, 99, 71, 70, 121, 89, 88, 82, 118, 99, 105, 73, 54, 73, 106, 48, 105, 76, 67, 74, 50, 89, 87, 120, 49, 90, 83, 73, 54, 73, 106, 66, 52, 78, 68, 73, 49, 79, 85, 85, 48, 78, 68, 89, 51, 77, 68, 65, 49, 77, 122, 81, 53, 77, 85, 85, 51, 89, 106, 82, 71, 82, 84, 82, 66, 77, 84, 73, 119, 81, 122, 99, 119, 89, 109, 85, 120, 90, 85, 70, 69, 78, 106, 81, 50, 89, 105, 74, 57, 102, 86, 48, 115, 73, 109, 86, 50, 98, 85, 78, 118, 98, 110, 82, 121, 89, 87, 78, 48, 81, 50, 57, 117, 90, 71, 108, 48, 97, 87, 57, 117, 99, 121, 73, 54, 98, 110, 86, 115, 98, 67, 119, 105, 99, 50, 57, 115, 85, 110, 66, 106, 81, 50, 57, 117, 90, 71, 108, 48, 97, 87, 57, 117, 99, 121, 73, 54, 98, 110, 86, 115, 98, 67, 119, 105, 100, 87, 53, 112, 90, 109, 108, 108, 90, 69, 70, 106, 89, 50, 86, 122, 99, 48, 78, 118, 98, 110, 82, 121, 98, 50, 120, 68, 98, 50, 53, 107, 97, 88, 82, 112, 98, 50, 53, 122, 73, 106, 112, 117, 100, 87, 120, 115, 102, 81],
            &base64_decode("trkIFY8XLxWAHvErjc5sEMfyEMjDVW0m4zSEiO8Ladb-F2vsaUmBMPIR4axyHdayDJ7_qdxUsxM1Xt/AUMcYRCVbUqNZZmkAGtOFGODAjieGdv9Q3aPnsrQXkDzW0ITP"),
        );
        assert!(res.is_ok());
    }

    #[test]
    fn test_combine_signature_shares_inner() {
        let res = combine_signature_shares_inner_v1::<Bls12381G2Impl, blsful2::Bls12381G2Impl>(&vec![
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
        let res = decrypt_time_lock::<Bls12381G2Impl, blsful2::Bls12381G2Impl>(
            &base64_decode(&ciphertext),
            &hex_shares,
        );
        assert!(res.is_ok());
        let plaintext = res.unwrap();
        assert_eq!(sk_bytes.to_vec(), base64_decode(&plaintext));

        let res = verify_and_decrypt::<Bls12381G2Impl, blsful2::Bls12381G2Impl>(
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
