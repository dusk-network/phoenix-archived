fn main() {
    tonic_build::compile_protos("proto/phoenix/field.proto").unwrap();
    tonic_build::compile_protos("proto/phoenix/keys.proto").unwrap();
    tonic_build::compile_protos("proto/phoenix/note.proto").unwrap();
    tonic_build::compile_protos("proto/phoenix/phoenix.proto").unwrap();
    tonic_build::compile_protos("proto/phoenix/transaction.proto").unwrap();
}
