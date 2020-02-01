use phoenix::{rpc, Db, NoteGenerator, ObfuscatedNote, SecretKey};

use clap::{App, Arg, SubCommand};
use tonic::transport::Server;
use tracing::{info, warn};

const NAME: Option<&'static str> = option_env!("CARGO_PKG_NAME");
const VERSION: Option<&'static str> = option_env!("CARGO_PKG_VERSION");
const AUTHORS: Option<&'static str> = option_env!("CARGO_PKG_AUTHORS");

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let matches = App::new(NAME.unwrap())
        .version(VERSION.unwrap())
        .author(AUTHORS.unwrap())
        .arg(
            Arg::with_name("bind")
                .short("b")
                .long("bind")
                .value_name("BIND")
                .help("Bind the server to listen on the specified address")
                .default_value("0.0.0.0:8051")
                .takes_value(true)
                .display_order(1),
        )
        .arg(
            Arg::with_name("log-level")
                .short("l")
                .long("log-level")
                .value_name("LOG")
                .possible_values(&["error", "warn", "info", "debug", "trace"])
                .default_value("info")
                .help("Output log level")
                .takes_value(true),
        )
        .subcommand(
            SubCommand::with_name("note")
                .about("Create a new unspent note on initialization. Usage: note <SEED> <VALUE>")
                .arg(
                    Arg::with_name("seed")
                        .help("Seed of the secret key")
                        .required(true),
                )
                .arg(
                    Arg::with_name("value")
                        .help("Value of the unspent note")
                        .required(true),
                ),
        )
        .get_matches();

    let bind = matches.value_of("bind").unwrap();
    let addr = bind.parse().unwrap();

    let log = match matches
        .value_of("log-level")
        .expect("Failed parsing log-level arg")
    {
        "error" => tracing::Level::ERROR,
        "warn" => tracing::Level::WARN,
        "info" => tracing::Level::INFO,
        "debug" => tracing::Level::DEBUG,
        "trace" => tracing::Level::TRACE,
        _ => unreachable!(),
    };

    let subscriber = tracing_subscriber::fmt::Subscriber::builder()
        .with_max_level(log)
        .finish();
    tracing::subscriber::set_global_default(subscriber)?;

    let db = Db::new().unwrap();

    if let Some(matches) = matches.subcommand_matches("note") {
        let seed = matches
            .value_of("seed")
            .expect("The seed for the secret key is mandatory to create a new note");
        let pk = SecretKey::from(seed.as_bytes().to_vec()).public_key();

        let value: u64 = matches
            .value_of("value")
            .expect("The seed for the secret key is mandatory to create a new note")
            .parse()
            .unwrap();

        let note = Box::new(ObfuscatedNote::output(&pk, value).0);

        warn!("Note created for '{}' with {}", seed, value);
        db.store_unspent_note(note).unwrap();
    }

    let phoenix = rpc::Server::new(db);

    info!("Listening on {}...", addr);
    Server::builder()
        .add_service(rpc::phoenix_server::PhoenixServer::new(phoenix))
        .serve(addr)
        .await?;

    Ok(())
}
