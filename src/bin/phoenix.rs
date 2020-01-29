use phoenix::{rpc, Db, NoteGenerator, Scalar, SecretKey, TransparentNote};
use tonic::transport::Server;
use tracing::{error, info};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let addr = "127.0.0.1:8051".parse().unwrap();

    let subscriber = tracing_subscriber::fmt::Subscriber::builder()
        .with_max_level(tracing::Level::TRACE)
        .finish();
    tracing::subscriber::set_global_default(subscriber)?;

    let db = Db::new().unwrap();

    // TODO - Note only for demo, remove this
    let a = Scalar::from(5u64);
    let b = Scalar::from(7u64);
    let value = 1000000;
    let sk = SecretKey::new(a, b);
    let pk = sk.public_key();
    let note = Box::new(TransparentNote::output(&pk, value).0);
    error!("{} dusk note created for ({:?}, {:?})", value, a, b);
    db.store_unspent_note(note).unwrap();

    let phoenix = rpc::Server::new(db);

    info!("Listening on {}...", addr);

    // TODO - Check why tonic isnt submitting logs to tracing subscribed handler
    Server::builder()
        .add_service(rpc::phoenix_server::PhoenixServer::new(phoenix))
        .serve(addr)
        .await?;

    Ok(())
}
