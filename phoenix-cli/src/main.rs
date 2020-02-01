use phoenix_cli::{show_pk_from_sk, theme, Flow};

use dialoguer::Select;

fn main() {
    let mut state = Flow::Continue;

    while state == Flow::Continue {
        let tick = match Select::with_theme(theme())
            .with_prompt("~>")
            .default(0)
            .item("New transaction")
            .item("Scan unspent notes")
            .item("Public Address")
            .item("Connect to Phoenix")
            .item("Quit")
            .interact()
            .expect("Failed to render root menu")
        {
            0 => Ok(Flow::Continue),
            1 => Ok(Flow::Continue),
            2 => show_pk_from_sk(),
            3 => Ok(Flow::Continue),
            _ => Ok(Flow::ShouldQuit),
        }
        .map(|f| state = f);

        if let Err(e) = tick {
            println!("{}", e);
        }
    }

    println!("Bye!");
}
