use std::path::Path;

fn main() {
    let phoenix = Path::new("dusk-protobuf/phoenix/phoenix.proto");
    let rusk = Path::new("dusk-protobuf/phoenix/rusk.proto");
    let proto_dir = phoenix
        .parent()
        .expect("proto file should reside in a directory");

    tonic_build::configure()
        .compile(&[phoenix, rusk], &[proto_dir])
        .unwrap();
}
