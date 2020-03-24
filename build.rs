fn main() {
    tonic_build::compile_protos("dusk-protobuf/phoenix/phoenix.proto").unwrap();
}
