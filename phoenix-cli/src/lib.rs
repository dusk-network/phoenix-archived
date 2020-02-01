use std::sync::Mutex;

use console::Style;
use dialoguer::{theme::ColorfulTheme, PasswordInput};
use phoenix_lib::SecretKey;

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

    static ref ADDR: Mutex<String> = Mutex::new("127.0.0.1:8051".to_owned());
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Flow {
    Continue = 0,
    ShouldQuit = 1,
}

pub fn input_sk(prompt: &str) -> Result<SecretKey, Error> {
    Ok(PasswordInput::with_theme(theme())
        .with_prompt(prompt)
        .interact()
        .map(|s| SecretKey::from(s.into_bytes()))?)
}

pub fn show_pk_from_sk() -> Result<Flow, Error> {
    let sk = input_sk("Secret")?;

    println!("{}", sk.public_key());

    Ok(Flow::Continue)
}

pub fn theme() -> &'static ColorfulTheme {
    &*THEME
}
