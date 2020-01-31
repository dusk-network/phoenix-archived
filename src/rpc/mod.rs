pub mod server;
pub mod types;

tonic::include_proto!("phoenix");

pub use server::Server;
