use lit_bls_wasm::{
    decrypt_with_signature_shares, encrypt, initialize, verify_and_decrypt_with_signature_shares,
};

use blsful::{Bls12381G2, SignatureSchemes};
use k256::ecdsa::SigningKey;
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use wasm_bindgen_test::*;

fn get_crypto_rng() -> ChaCha20Rng {
    ChaCha20Rng::from_entropy()
}

#[wasm_bindgen_test]
fn encrypt_decrypt_works() {
    initialize();

    // Setup
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
    let js_shares = serde_wasm_bindgen::to_value(&hex_shares).unwrap();
    let pk = sk.public_key();
    let hex_pk = rem_first_and_last(serde_json::to_string(&pk).unwrap());
    let user_sk = SigningKey::random(&mut get_crypto_rng());
    let sk_bytes = user_sk.to_bytes();
    let hex_sk = hex::encode(&sk_bytes);

    // Encrypt
    let res = encrypt(&hex_pk, &hex_sk, &hex::encode(ID));
    assert!(res.is_ok());
    let ciphertext = res.unwrap();

    // Decrypt method 1
    let res = decrypt_with_signature_shares(&ciphertext, js_shares.clone());
    assert!(res.is_ok());
    let hex_plaintext = res.unwrap();
    assert_eq!(hex_plaintext, hex_sk);

    // // Decrypt method 2
    let res =
        verify_and_decrypt_with_signature_shares(&hex_pk, &hex::encode(ID), &ciphertext, js_shares);
    assert!(res.is_ok());
    let hex_plaintext = res.unwrap();
    assert_eq!(hex_plaintext, hex_sk);
}

fn rem_first_and_last(value: String) -> String {
    let mut chars = value.chars();
    chars.next();
    chars.next_back();
    chars.as_str().to_string()
}
