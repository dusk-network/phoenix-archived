/// This file implements the elgamal encryption 
/// The implementation uses the JubJub elliptic curve

pub use jubjub::{GENERATOR, Fr, AffinePoint}


pub struct SecretKey(Fr);

impl SecretKey{
    // This will create a new private key
    // from a scalar of the Field Fr.
    pub fn new(scalar: Fr) -> Result<SecretKey> {
        if scalar(&Fr::zero()).unwrap_u8() == 1u8 {
            return Err(err);
        }

        SecretKey(Fr)
    }
}


pub struct PublicKey(AffinePoint);

impl PublicKey {
    // This will create a new public key from a 
    // secret key
    pub fn from_secret(secret: SecretKey) -> PublicKey {
        let point = &secret * GENERATOR; 

        PublicKey(point)
    }
 
}

pub struct KeyPair {
    secret_key: SecretKey,
    public_key: PublicKey,
}

impl KeyPair {
    pub fn new() -> Result<KeyPair> {
        let secret_key = SecretKey::new();
        let public_key = private_key.from_secret();

        let keys = KeyPair { secret_key, public_key };
        
        Ok(keys)
    }
}

pub struct CipherText {
    publicKey: PublicKey,
    message: Message
}

impl CipherText {
    pub fn new() -> <CipherText> {
        let first_scalar = SecretKey::new();
        let second_scalar = SecretKey::new();
        assert_ne!(first_scalar, second_scalar);
        
        let public_key = first_scalar.from_secret();

    }
}

pub struct Message([u8; 32]);

/// By means of Elgamal, this function uses a 
/// KeyPair to convert a message into Cipher 
/// text.
pub fn encryption(sk: SecretKey, pk: PublicKey, msg: Message) -> <CipherText> {
    let scalar = SecretKey::new();
    let sk = SecretKey::new();
    assert_ne!(scalar, sk);
    
    let pk = first_scalar.from_secret();
    let c0 = self.scalar_mul(None, first_scalar, public_key.to_extended());
    let c = c0 + message;

    CipherText
}

pub fn decryption(sk: SecretKey, pk: PublicKey, cipher: CipherText) -> <Message> {

    
}





