use crate::SecretKey;

#[test]
fn sk_from_bytes() {
    let bytes = b"some bytes".to_vec();

    let sk_a = SecretKey::from(bytes.clone());
    let sk_b = SecretKey::from(bytes);

    assert_eq!(sk_a, sk_b);
}
