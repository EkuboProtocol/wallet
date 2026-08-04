//! Manual harness for the paged list prompt.
//!
//! Run `cargo run --example paged_select_demo -- 40` in a terminal and drive
//! the list with the arrow keys, PageUp/PageDown, and Home/End. The chosen
//! index is printed to stdout, so the prompt can also be exercised through a
//! pseudo-terminal by piping key escape sequences in and asserting on the
//! output.

use ekubo_wallet::paged_list::PagedSelect;

fn main() -> std::io::Result<()> {
    let count: usize = std::env::args()
        .nth(1)
        .and_then(|argument| argument.parse().ok())
        .unwrap_or(40);
    let mut select = PagedSelect::new(format!("{count} demo item(s)"));
    for index in 0..count {
        select = select.item(index, format!("item {index}"), "");
    }
    // The same chrome budget the CLI's transaction browser reserves.
    match select
        .page_rows(|| ekubo_wallet::render::interactive_list_rows(6))
        .interact()
    {
        Ok(choice) => println!("chose {choice}"),
        Err(error) if error.kind() == std::io::ErrorKind::Interrupted => println!("cancelled"),
        Err(error) => return Err(error),
    }
    Ok(())
}
