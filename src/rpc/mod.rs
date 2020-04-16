/// General type conversion from/to rpc types
pub mod types;

tonic::include_proto!("rusk");

#[cfg(test)]
mod tests;
