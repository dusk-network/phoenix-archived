use std::convert::TryFrom;
use std::sync::Mutex;

use console::Style;
use console::{style, Emoji};
use dialoguer::{theme::ColorfulTheme, Input, OrderList, PasswordInput};
use indicatif::{MultiProgress, ProgressBar};
use phoenix_lib::{rpc, Note, Nullifier, ObfuscatedNote, SecretKey, TransparentNote, ViewKey};
use tonic::transport::Channel;
use tonic::IntoRequest;

pub use error::Error;

pub mod error;

lazy_static::lazy_static! {
    static ref THEME: ColorfulTheme = ColorfulTheme {
        values_style: Style::new().yellow().dim(),
        indicator_style: Style::new().yellow().bold(),
        yes_style: Style::new().yellow().dim(),
        no_style: Style::new().yellow().dim(),
        ..ColorfulTheme::default()
    };

    static ref ADDR: Mutex<String> = Mutex::new("http://127.0.0.1:8051".to_owned());
}

static LOOKING_GLASS: Emoji<'_, '_> = Emoji("🔍  ", "");
static PAPER: Emoji<'_, '_> = Emoji("📃  ", "");

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Flow {
    Continue = 0,
    ShouldQuit = 1,
}

pub async fn client() -> Result<rpc::phoenix_client::PhoenixClient<Channel>, Error> {
    let addr = (&*ADDR).lock().map(|a| String::from(&*a))?;

    Ok(rpc::phoenix_client::PhoenixClient::connect(addr).await?)
}

pub fn input_sk() -> Result<SecretKey, Error> {
    Ok(PasswordInput::with_theme(theme())
        .with_prompt("Secret")
        .interact()
        .map(|s| SecretKey::from(s.into_bytes()))?)
}

pub fn show_pk_from_sk() -> Result<Flow, Error> {
    let sk = input_sk()?;

    println!("{}", sk.public_key());

    Ok(Flow::Continue)
}

pub async fn scan() -> Result<Flow, Error> {
    let sk = input_sk()?;
    let vk: rpc::ViewKey = sk.view_key().into();

    println!(
        "{} {}Querying Phoenix server...",
        style("[1/3]").bold().dim(),
        LOOKING_GLASS
    );

    println!("VK: {}", ViewKey::try_from(vk.clone()).unwrap());

    let mut client = client().await?;
    let notes = client
        .full_scan_owned_notes(vk.into_request())
        .await?
        .into_inner()
        .notes;

    println!("{} {}Parsing notes...", style("[2/3]").bold().dim(), PAPER);

    let mb = MultiProgress::new();

    let pb_notes = mb.add(ProgressBar::new(notes.len() as u64));
    let pb_nullifiers = mb.add(ProgressBar::new(notes.len() as u64));

    let notes: Vec<Result<(String, Nullifier, u64), Error>> = notes
        .into_iter()
        .map(|note| {
            let note_type = match rpc::NoteType::try_from(note.note_type) {
                Ok(n) => n,
                Err(e) => return Err(Error::from(e)),
            };

            let pos = note
                .pos
                .as_ref()
                .cloned()
                .ok_or(Error::UnexpectedResponse(
                    "The provided note doesn't contain its position".to_owned(),
                ))?
                .pos;

            let value = note.value;

            let nullifier = match note_type {
                rpc::NoteType::Transparent => {
                    TransparentNote::try_from(note)?.generate_nullifier(&sk)
                }
                rpc::NoteType::Obfuscated => {
                    ObfuscatedNote::try_from(note)?.generate_nullifier(&sk)
                }
            };

            pb_notes.inc(1);

            Ok((
                format!("{:?}, position {}, value {}", note_type, pos, value),
                nullifier,
                value,
            ))
        })
        .collect();

    println!(
        "{} {}Querying nullifiers status...",
        style("[3/3]").bold().dim(),
        LOOKING_GLASS
    );

    let mut items = vec![];
    let mut balance = 0;
    for result in notes {
        let (note, nullifier, value) = result?;

        let nullifier = rpc::NullifierStatusRequest {
            nullifier: Some(nullifier.into()),
        };
        let status = client
            .nullifier_status(nullifier.into_request())
            .await?
            .into_inner();

        if status.unspent {
            items.push(note);
            balance += value;
        }

        pb_nullifiers.inc(1);
    }

    println!("Balance: {}", balance);
    OrderList::with_theme(&ColorfulTheme::default())
        .items(&items[..])
        .interact()
        .unwrap();

    Ok(Flow::Continue)
}

pub async fn connect() -> Result<Flow, Error> {
    let addr = (&*ADDR).lock().map(|a| String::from(&*a))?;
    let addr = Input::<String>::with_theme(theme())
        .default(addr)
        .with_prompt("Server address")
        .interact()?;
    (&*ADDR).lock().map(|mut a| *a = addr.clone())?;

    let mut client = client().await?;
    let response = client
        .echo(
            rpc::EchoMethod {
                m: "Ping!".to_owned(),
            }
            .into_request(),
        )
        .await?
        .into_inner();

    if response.m.as_str() != "Ping!" {
        return Err(Error::UnexpectedResponse(format!(
            "Unexpected echo response: {}",
            response.m
        )));
    }

    println!("Connected!");
    Ok(Flow::Continue)
}

pub fn theme() -> &'static ColorfulTheme {
    &*THEME
}
