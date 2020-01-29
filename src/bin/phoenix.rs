use phoenix::{rpc, Db};
use tonic::transport::Server;
use tracing::info;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let addr = "[::1]:50051".parse().unwrap();

    let db = Db::new().unwrap();
    let phoenix = rpc::Server::new(db);

    let subscriber = tracing_subscriber::fmt::Subscriber::builder()
        .with_max_level(tracing::Level::TRACE)
        .finish();
    tracing::subscriber::set_global_default(subscriber)?;

    info!("Listening on {}...", addr);

    // TODO - Check why tonic isnt submitting logs to tracing subscribed handler
    Server::builder()
        .add_service(rpc::phoenix_server::PhoenixServer::new(phoenix))
        .serve(addr)
        .await?;

    Ok(())
}
