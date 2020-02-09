use std::convert::TryFrom;
use std::sync::Mutex;

use console::Style;
use console::{style, Emoji};
use dialoguer::{
    theme::ColorfulTheme, Checkboxes, Confirmation, Input, OrderList, PasswordInput, Select,
    Validator,
};
use indicatif::{MultiProgress, ProgressBar};
use phoenix_lib::{
    rpc, Note, NoteGenerator, NoteUtxoType, ObfuscatedNote, PublicKey, SecretKey, Transaction,
    TransactionItem, TransparentNote,
};
use tonic::transport::Channel;
use tonic::IntoRequest;

pub use error::Error;

pub mod error;

#[cfg(test)]
mod tests;

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

pub struct ValidatePk {}
impl Validator for ValidatePk {
    type Err = Error;

    fn validate(&self, text: &str) -> Result<(), Self::Err> {
        Ok(PublicKey::try_from(text.to_string()).map(|_| ())?)
    }
}

pub struct ValidateAmount {}
impl Validator for ValidateAmount {
    type Err = Error;

    fn validate(&self, text: &str) -> Result<(), Self::Err> {
        text.parse::<u64>()
            .map(|_| ())
            .map_err(|_| Error::InvalidInput)
    }
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

pub fn input_pk() -> Result<PublicKey, Error> {
    let pk = Input::<String>::with_theme(theme())
        .with_prompt("Public key")
        .validate_with(ValidatePk {})
        .interact()?;

    Ok(PublicKey::try_from(pk)?)
}

pub fn input_amount(prompt: &str) -> Result<u64, Error> {
    Ok(Input::<String>::with_theme(theme())
        .with_prompt(prompt)
        .validate_with(ValidateAmount {})
        .interact()?
        .parse()
        .map_err(|_| Error::InvalidInput)?)
}

pub fn show_pk_from_sk() -> Result<Flow, Error> {
    let sk = input_sk()?;

    println!("{}", sk.public_key());

    Ok(Flow::Continue)
}

pub async fn query_inputs(sk: SecretKey) -> Result<Vec<TransactionItem>, Error> {
    let vk: rpc::ViewKey = sk.view_key().into();

    println!(
        "{} {}Querying Phoenix server...",
        style("[1/3]").bold().dim(),
        LOOKING_GLASS
    );

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

    let all_items: Vec<Result<TransactionItem, Error>> = notes
        .into_iter()
        .map(|note| {
            let note_type = match rpc::NoteType::try_from(note.note_type) {
                Ok(n) => n,
                Err(e) => return Err(Error::from(e)),
            };

            let tx_item = match note_type {
                rpc::NoteType::Transparent => {
                    TransparentNote::try_from(note)?.to_transaction_input(sk)
                }
                rpc::NoteType::Obfuscated => {
                    ObfuscatedNote::try_from(note)?.to_transaction_input(sk)
                }
            };

            pb_notes.inc(1);
            Ok(tx_item)
        })
        .collect();

    pb_notes.finish_and_clear();

    println!(
        "{} {}Querying nullifiers status...",
        style("[3/3]").bold().dim(),
        LOOKING_GLASS
    );

    let mut items = vec![];
    for result in all_items {
        let item = result?;
        let nullifier = item.nullifier().clone();

        let nullifier = rpc::NullifierStatusRequest {
            nullifier: Some(nullifier.into()),
        };
        let status = client
            .nullifier_status(nullifier.into_request())
            .await?
            .into_inner();

        if status.unspent {
            items.push(item);
        }

        pb_nullifiers.inc(1);
    }

    pb_nullifiers.finish_and_clear();

    Ok(items)
}

pub async fn scan() -> Result<Flow, Error> {
    let (items, values): (Vec<String>, Vec<u64>) = query_inputs(input_sk()?)
        .await?
        .into_iter()
        .map(|item| {
            (
                format!(
                    "{:?}, position {}, value {}",
                    item.note_type(),
                    item.idx().pos,
                    item.value()
                ),
                item.value(),
            )
        })
        .unzip();

    println!("Balance: {}", values.iter().sum::<u64>());
    OrderList::with_theme(&ColorfulTheme::default())
        .items(&items[..])
        .interact()?;

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

pub fn push_transaction_output(
    tx: &mut Transaction,
    prompt: &str,
    mut value: u64,
) -> Result<(), Error> {
    let pk = input_pk()?;
    if value == 0 {
        value = input_amount(prompt)?;
    }
    let note_type = Select::with_theme(theme())
        .with_prompt("Note type")
        .default(0)
        .item("Obfuscated")
        .item("Transparent")
        .interact()?;

    let item = match note_type {
        0 => {
            let (n, b) = ObfuscatedNote::output(&pk, value);
            n.to_transaction_output(value, b, pk)
        }
        _ => {
            let (n, b) = TransparentNote::output(&pk, value);
            n.to_transaction_output(value, b, pk)
        }
    };

    tx.push(item);

    Ok(())
}

pub async fn transaction() -> Result<Flow, Error> {
    let pb_tx = ProgressBar::new(2);

    pb_tx.inc(1);
    let mut tx = Transaction::default();
    pb_tx.inc(1);

    pb_tx.finish_and_clear();

    loop {
        let fee = tx.fee().value();
        let (inputs, outputs) = tx
            .items()
            .iter()
            .map(|item| {
                (
                    if item.utxo() == NoteUtxoType::Input {
                        item.value()
                    } else {
                        0
                    },
                    if item.utxo() == NoteUtxoType::Output {
                        item.value()
                    } else {
                        0
                    },
                )
            })
            .fold((0, 0), |(i, o), (ii, io)| (i + ii, o + io));

        let option = Select::with_theme(theme())
            .with_prompt(
                format!("Tx inputs: {}, outputs: {}, fee: {}", inputs, outputs, fee).as_str(),
            )
            .default(0)
            .item("Add output note")
            .item("Remove outputs")
            .item("Add input note")
            .item("Remove inputs")
            .item("Set fee value")
            .item("Prove")
            .item("Verify")
            .item("Submit")
            .item("Close")
            .interact()?;

        match option {
            0 => push_transaction_output(&mut tx, "Value", 0)?,
            1 => {
                let (index, selections): (Vec<usize>, Vec<String>) = tx
                    .items()
                    .iter()
                    .enumerate()
                    .filter_map(|(i, item)| {
                        if item.utxo() == NoteUtxoType::Output {
                            Some((
                                i,
                                format!(
                                    "{:?}, pk {}..., value {}",
                                    item.note_type(),
                                    &format!("{}", item.pk())[0..10],
                                    item.value()
                                ),
                            ))
                        } else {
                            None
                        }
                    })
                    .unzip();

                if selections.is_empty() {
                    println!("No outputs found");
                } else {
                    let selection = Select::with_theme(&ColorfulTheme::default())
                        .with_prompt("Select the output note to remove")
                        .default(0)
                        .items(&selections[..])
                        .interact_opt()?;

                    if let Some(selection) = selection {
                        tx.remove_item(index[selection]);
                    }
                }
            }
            2 => {
                let (descriptions, items): (Vec<String>, Vec<TransactionItem>) =
                    query_inputs(input_sk()?)
                        .await?
                        .into_iter()
                        .map(|item| {
                            (
                                format!(
                                    "{:?}, position {}, value {}",
                                    item.note_type(),
                                    item.idx().pos,
                                    item.value()
                                ),
                                item,
                            )
                        })
                        .unzip();

                let defaults: Vec<bool> = items.iter().map(|_| false).collect();

                if descriptions.is_empty() {
                    println!("No inputs available");
                } else {
                    Checkboxes::with_theme(&ColorfulTheme::default())
                        .with_prompt("Select the inputs")
                        .items(&descriptions[..])
                        .defaults(&defaults[..])
                        .interact()?
                        .into_iter()
                        .for_each(|i| tx.push(items[i].clone()));
                }
            }
            3 => {
                let (index, selections): (Vec<usize>, Vec<String>) = tx
                    .items()
                    .iter()
                    .enumerate()
                    .filter_map(|(i, item)| {
                        if item.utxo() == NoteUtxoType::Input {
                            Some((
                                i,
                                format!(
                                    "{:?}, position {}, value {}",
                                    item.note_type(),
                                    item.idx().pos,
                                    item.value()
                                ),
                            ))
                        } else {
                            None
                        }
                    })
                    .unzip();

                if selections.is_empty() {
                    println!("No inputs found");
                } else {
                    let selection = Select::with_theme(&ColorfulTheme::default())
                        .with_prompt("Select the inputs note to remove")
                        .default(0)
                        .items(&selections[..])
                        .interact_opt()?;

                    if let Some(selection) = selection {
                        tx.remove_item(index[selection]);
                    }
                }
            }
            4 => {
                let fee_value = input_amount("Fee value")?;
                let pk = PublicKey::default();
                let (n, b) = TransparentNote::output(&pk, fee_value);
                let fee = n.to_transaction_output(fee_value, b, pk);
                tx.set_fee(fee);

                if inputs > outputs + fee_value {
                    let diff = inputs - outputs - fee_value;
                    println!("Inserting an output of amount {} as change", diff);
                    push_transaction_output(&mut tx, "Change", diff)?;
                }
            }
            5 => println!("{}", tx.prove().is_ok()),
            6 => println!("{}", tx.prove().and_then(|_| tx.verify()).is_ok()),
            7 => {
                let pb_tx = ProgressBar::new(2);

                let mut list = tx
                    .items()
                    .iter()
                    .map(|item| match item.utxo() {
                        NoteUtxoType::Input => format!(
                            "{:?} input, position {}, value {}",
                            item.note_type(),
                            item.note().idx().pos,
                            item.value()
                        ),
                        NoteUtxoType::Output => format!(
                            "{:?} output, pk {}..., value {}",
                            item.note_type(),
                            &format!("{}", item.pk())[0..10],
                            item.value()
                        ),
                    })
                    .collect::<Vec<String>>();

                if list.is_empty() {
                    println!("The transaction contain no items!");
                } else if tx.prove().is_err() {
                    println!("The transaction did not prove correctly!");
                } else {
                    list.push(format!(
                        "Fee {:?}, {:?}, value {}",
                        tx.fee().utxo(),
                        tx.fee().note_type(),
                        tx.fee().value()
                    ));

                    OrderList::with_theme(&ColorfulTheme::default())
                        .with_prompt("Transaction items")
                        .items(&list[..])
                        .interact()?;

                    let addr = (&*ADDR).lock().map(|a| String::from(&*a))?;
                    if Confirmation::new()
                        .with_text(format!("The transaction {} will be sent to the following Phoenix server: {}. Confirm?", hex::encode(tx.hash().as_bytes()), addr).as_str())
                        .interact()?
                    {
                        pb_tx.inc(1);

                        let transactions = vec![tx.into()];
                        let request = rpc::StoreTransactionsRequest {transactions};

                        let mut client = client().await?;
                        client
                            .store_transactions(request.into_request())
                            .await?;

                        println!("The transaction was stored on the server.");

                        pb_tx.inc(1);
                        pb_tx.finish_and_clear();
                        break;
                    }
                    pb_tx.finish_and_clear();
                }
            }
            _ => break,
        }
    }

    Ok(Flow::Continue)
}

pub fn theme() -> &'static ColorfulTheme {
    &*THEME
}
