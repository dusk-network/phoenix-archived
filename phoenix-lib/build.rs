fn main() {
    tonic_build::compile_protos("../proto/phoenix/phoenix.proto").unwrap();
}
