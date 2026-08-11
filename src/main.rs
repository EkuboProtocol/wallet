fn main() {
    if let Err(error) = ekubo_wallet::run_desktop() {
        let message = format!("Ekubo Wallet could not start: {error:#}");
        eprintln!("{message}");
        let _ = notify_rust::Notification::new()
            .summary("Ekubo Wallet could not start")
            .body(&message)
            .show();
        std::process::exit(1);
    }
}
