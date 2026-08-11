fn main() {
    // Startup failures are surfaced by the native shell; this binary has no
    // terminal-compatible fallback or alternate executable mode.
    if ekubo_wallet::run_desktop().is_err() {
        std::process::exit(1);
    }
}
