use libsecp256k1::{Message, PublicKey, RecoveryId, SecretKey, Signature};
use rand::rngs::OsRng;
use sha3::{Digest, Keccak256};

const SIGN_PAYLOAD: &'static str = "Test123123!";

fn main() {
    // SecretKey instance
    // Sample of parsing HEXSTRING to secret key instance:
    // let secret_key_hex: String = "ABCDEF123456....".into();
    // let secret_key = SecretKey::parse_slice(hex::decode(&secret_key_hex).unwrap().as_slice()).unwrap();

    // In this case, we use random secret key.
    let mut rng = OsRng;
    let secret_key = SecretKey::random(&mut rng);
    println!("Secret key: 0x{}", hex::encode(secret_key.serialize()));
    // Sign it
    let personal_signature = personal_sign(SIGN_PAYLOAD, &secret_key);
    println!("Signature: 0x{}", hex::encode(&personal_signature));

    // Try to recover it.
    let recovered_public_key = personal_sign_recover(&personal_signature, SIGN_PAYLOAD);
    println!(
        "Original public key:  0x{}",
        hex::encode(PublicKey::from_secret_key(&secret_key).serialize()),
    );
    println!(
        "Recovered public key: 0x{}",
        hex::encode(recovered_public_key.serialize()),
    );
}

/// Format and hash message in `personal_sign` format.
///
/// NOTE: `payload.len()` is byte count, not Unicode codepoint count.
/// i.e.    `"🐴".len() == 3`
fn personal_sign_digest(payload: &str) -> [u8; 32] {
    let personal_message = format!("\x19Ethereum Signed Message:\n{}{}", payload.len(), payload);

    let mut hasher = Keccak256::new();
    hasher.update(personal_message);
    hasher.finalize().into()
}

/// `web3.eth.personal.sign()`
fn personal_sign(payload: &str, secret_key: &SecretKey) -> Vec<u8> {
    let digest = personal_sign_digest(payload);

    // Sign the digest.
    let (r_and_s, v) = libsecp256k1::sign(&Message::parse(&digest), secret_key);
    // Rebuild the sig into a [u8; 65]
    let mut signature: Vec<u8> = vec![];
    signature.extend_from_slice(&r_and_s.r.b32()); // r (32 bytes)
    signature.extend_from_slice(&r_and_s.s.b32()); // s (32 bytes)
    signature.push(v.serialize()); // v (1 byte)
    if signature.len() != 65 {
        panic!("Signature length is not 65 bytes");
    }
    signature
}

/// Recover public key from a personal_sign signature.
fn personal_sign_recover(sig_r_s_recovery: &Vec<u8>, plain_payload: &str) -> PublicKey {
    let digest = personal_sign_digest(plain_payload);

    let mut recovery_id = sig_r_s_recovery
        .get(64)
        .expect("Signature length is not 65 bytes")
        .clone();
    if recovery_id == 27 || recovery_id == 28 {
        recovery_id = 27;
    }
    if recovery_id != 0 && recovery_id != 1 {
        panic!("Invalid signature: Recovery ID not recognized.")
    }

    let signature = Signature::parse_standard_slice(&sig_r_s_recovery.as_slice()[0..64]).unwrap();
    let public_key = libsecp256k1::recover(
        &Message::parse(&digest),
        &signature,
        &RecoveryId::parse(recovery_id).unwrap(),
    )
    .unwrap();

    public_key
}
