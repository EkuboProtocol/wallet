//! What the model says about the transactions a wallet actually sees.
//!
//! Hand-built rather than sampled, so the cases that matter -- an unlimited
//! allowance, an operator grant, a call nothing decoded, the approve-then-act
//! plan that is most of what a wallet signs -- are all present rather than
//! left to chance.
use ekubo_wallet_preview::slots::{CallSummary, PlanDocument};

const USDC: &str = "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48";
const ROUTER: &str = "0xdef1c0ded9bec7f1a1670819833240f027b25eff";
const SELF: &str = "0x1c2F7C7Ffa55c9677e88b233FbAB9E7c78133162";
const NFT: &str = "0xBd3531dA5CF5857e7CfAA92426877b022e612cf8";

fn call(description: &str, warnings: &[&str], target: &str, value: &str) -> CallSummary {
    CallSummary {
        description: (!description.is_empty()).then(|| description.to_owned()),
        details: Vec::new(),
        warnings: warnings.iter().map(|w| (*w).to_owned()).collect(),
        target: target.to_owned(),
        native_value: value.to_owned(),
    }
}

fn main() {
    let engine = ekubo_wallet_preview::cpu::load().expect("weights load");
    let cases: Vec<(&str, PlanDocument)> = vec![
        (
            "approve 100 USDC, then swap on 0x",
            PlanDocument {
                calls: vec![
                    call(
                        &format!("approve spender {ROUTER} for 100 USDC ({USDC})"),
                        &[],
                        &format!("USDC ({USDC})"),
                        "0 ETH",
                    ),
                    call("0x Protocol \u{2014} Swap", &[], ROUTER, "0 ETH"),
                ],
            },
        ),
        (
            "UNLIMITED approval, then swap",
            PlanDocument {
                calls: vec![
                    call(
                        &format!(
                            "approve spender {ROUTER} for 115792089237316195423570985008687907853269984665640564039457.584007913129639935 USDC ({USDC})"
                        ),
                        &[
                            "Call 1 sets an unlimited allowance: the spender may draw this token whenever it likes, without asking again.",
                        ],
                        &format!("USDC ({USDC})"),
                        "0 ETH",
                    ),
                    call("0x Protocol \u{2014} Swap", &[], ROUTER, "0 ETH"),
                ],
            },
        ),
        (
            "setApprovalForAll on an NFT collection",
            PlanDocument {
                calls: vec![call(
                    &format!(
                        "setApprovalForAll: grant operator {ROUTER} control of all {NFT} tokens"
                    ),
                    &[&format!(
                        "Call 1 grants {ROUTER} blanket operator control of every {NFT} token held by this wallet."
                    )],
                    NFT,
                    "0 ETH",
                )],
            },
        ),
        (
            "a call nothing decoded, with no value",
            PlanDocument {
                calls: vec![call("", &[], ROUTER, "0 ETH")],
            },
        ),
        (
            "a call nothing decoded, SENDING 2.5 ETH",
            PlanDocument {
                calls: vec![call(
                    "",
                    &["Call 1 sends native value to a contract this wallet could not decode."],
                    ROUTER,
                    "2.5 ETH",
                )],
            },
        ),
        (
            "approve, act, then something undecoded",
            PlanDocument {
                calls: vec![
                    call(
                        &format!("approve spender {ROUTER} for 250.75 USDC ({USDC})"),
                        &[],
                        &format!("USDC ({USDC})"),
                        "0 ETH",
                    ),
                    call("Aave DAO \u{2014} Supply", &[], ROUTER, "0 ETH"),
                    call("", &[], NFT, "0 ETH"),
                ],
            },
        ),
        (
            "a plain transfer to a stranger",
            PlanDocument {
                calls: vec![call(
                    &format!("transfer 1250.5 USDC ({USDC}) to {ROUTER}"),
                    &[],
                    &format!("USDC ({USDC})"),
                    "0 ETH",
                )],
            },
        ),
        (
            "a transfer to the owner's own account",
            PlanDocument {
                calls: vec![call(
                    &format!("transfer 1250.5 USDC ({USDC}) to {SELF} (your account savings)"),
                    &[],
                    &format!("USDC ({USDC})"),
                    "0 ETH",
                )],
            },
        ),
        (
            "revoking an allowance",
            PlanDocument {
                calls: vec![call(
                    &format!("revoke USDC ({USDC}) allowance for spender {ROUTER}"),
                    &[],
                    &format!("USDC ({USDC})"),
                    "0 ETH",
                )],
            },
        ),
    ];

    let documents: Vec<PlanDocument> = cases.iter().map(|(_, d)| d.clone()).collect();
    let previews = engine.preview_all(&documents);
    for ((name, document), preview) in cases.iter().zip(previews) {
        println!("\n=== {name} ===");
        for c in &document.calls {
            println!(
                "   in  : {}",
                c.description.as_deref().unwrap_or("(nothing decoded)")
            );
        }
        println!(
            "   OUT : [{} / {}] {}",
            preview.class,
            preview.risk,
            if preview.summary.is_empty() {
                "(no summary)"
            } else {
                &preview.summary
            }
        );
    }
}
