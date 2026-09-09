//! End-to-end card examples with the actual embedded neural weights.
use ekubo_wallet_preview::{PlanDocument, cpu};
use serde::Deserialize;

#[derive(Deserialize)]
struct Example {
    name: String,
    document: PlanDocument,
    expected: Option<String>,
    contains: Vec<String>,
    excludes: Vec<String>,
}

fn main() -> Result<(), String> {
    let engine = cpu::load().map_err(|e| e.to_string())?;
    let mut failures = 0;
    for line in include_str!("../../model/card-examples.jsonl").lines() {
        let example: Example = serde_json::from_str(line).map_err(|e| e.to_string())?;
        let preview = futures::executor::block_on(
            engine.card_all_async(std::slice::from_ref(&example.document)),
        )?
        .remove(0);
        let ok = preview.summary.chars().count() <= 100
            && example
                .expected
                .as_ref()
                .is_none_or(|expected| expected == &preview.summary)
            && example
                .contains
                .iter()
                .all(|text| preview.summary.contains(text))
            && example
                .excludes
                .iter()
                .all(|text| !preview.summary.contains(text));
        failures += usize::from(!ok);
        println!(
            "{}",
            serde_json::json!({"name":example.name,"document":example.document,"summary":preview.summary,"class":preview.class.corpus_name(),"risk":preview.risk.corpus_name(),"basis":format!("{:?}",preview.basis),"passed":ok})
        );
    }
    if failures > 0 {
        return Err(format!("{failures} card examples failed"));
    }
    Ok(())
}
