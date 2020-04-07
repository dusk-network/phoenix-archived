fn main() {
    tonic_build::compile_protos("dusk-protobuf/phoenix/rusk.proto").unwrap();
}
