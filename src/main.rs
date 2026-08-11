fn main() {
    let arguments = std::env::args_os().skip(1).collect::<Vec<_>>();
    let hidden_startup = match arguments.as_slice() {
        [] => false,
        [argument] if argument == "--hidden-startup" => true,
        _ => {
            eprintln!("Ekubo Wallet does not accept command-line operations.");
            std::process::exit(2);
        }
    };
    let result = if hidden_startup {
        ekubo_wallet::desktop::run_desktop_hidden()
    } else {
        ekubo_wallet::run_desktop()
    };
    if let Err(error) = result {
        let message = format!("Ekubo Wallet could not start: {error:#}");
        eprintln!("{message}");
        let _ = notify_rust::Notification::new()
            .summary("Ekubo Wallet could not start")
            .body(&message)
            .show();
        std::process::exit(1);
    }
}
