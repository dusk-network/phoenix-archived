/// General type conversion from/to rpc types
pub mod types;

tonic::include_proto!("phoenix");

#[cfg(test)]
mod tests;
