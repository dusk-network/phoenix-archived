use phoenix_cli::{connect, scan, show_pk_from_sk, theme, Flow};

use dialoguer::Select;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut state = Flow::Continue;

    while state == Flow::Continue {
        let tick = match Select::with_theme(theme())
            .with_prompt("~>")
            .default(0)
            .item("New transaction")
            .item("Scan unspent notes")
            .item("Public Address")
            .item("Connect to Phoenix server")
            .item("Quit")
            .interact()
            .expect("Failed to render root menu")
        {
            0 => Ok(Flow::Continue),
            1 => scan().await,
            2 => show_pk_from_sk(),
            3 => connect().await,
            _ => Ok(Flow::ShouldQuit),
        }
        .map(|f| state = f);

        if let Err(e) = tick {
            eprintln!("Error: {}", e);
        }
    }

    println!("Bye!");
    Ok(())
}
