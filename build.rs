fn main() {
    tonic_build::compile_protos("dusk-protobuf/rusk/rusk.proto").unwrap();
}
