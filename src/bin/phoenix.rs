use phoenix::{rpc, Db, NoteGenerator, Scalar, SecretKey, TransparentNote};
use tonic::transport::Server;
use tracing::{info, warn};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let addr = "127.0.0.1:8051".parse().unwrap();

    let subscriber = tracing_subscriber::fmt::Subscriber::builder()
        .with_max_level(tracing::Level::TRACE)
        .finish();
    tracing::subscriber::set_global_default(subscriber)?;

    let db = Db::new().unwrap();

    // TODO - Note only for demo, remove this
    let a = Scalar::from_bits([
        127, 113, 230, 186, 76, 5, 242, 4, 214, 165, 11, 193, 150, 170, 233, 197, 161, 206, 191,
        18, 20, 173, 101, 155, 122, 232, 56, 121, 66, 172, 49, 6,
    ]);
    let b = Scalar::from_bits([
        253, 185, 198, 145, 54, 108, 119, 39, 67, 127, 254, 81, 183, 79, 15, 80, 160, 16, 27, 123,
        114, 84, 23, 103, 147, 151, 232, 207, 121, 6, 16, 12,
    ]);
    let value = 100;
    let sk = SecretKey::new(a, b);
    let pk = sk.public_key();
    let note = Box::new(TransparentNote::output(&pk, value).0);
    warn!("{} dusk note created for 'dusk'", value);
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
