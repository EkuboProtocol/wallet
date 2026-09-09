//! Evaluate committed weights through the deployment path. `--count 0` runs
//! every strictly held-out example; JSONL predictions make errors inspectable.
use burn::tensor::backend::Backend;
use ekubo_wallet_preview::{
    infer::PreviewEngine,
    slots::slotize,
    taxonomy::{CLASS_COUNT, TransactionClass},
    training::{self, Labeled, Partition},
    vocab,
};
use rand::{SeedableRng as _, seq::SliceRandom as _};
use std::{collections::BTreeSet, path::PathBuf};

struct Arguments {
    corpus: PathBuf,
    count: usize,
    cpu: bool,
}

fn arguments() -> Result<Arguments, String> {
    let mut corpus = None;
    let mut count = 25;
    let mut cpu = false;
    let mut args = std::env::args().skip(1);
    while let Some(flag) = args.next() {
        let value = args.next().ok_or_else(|| format!("{flag} needs a value"))?;
        match flag.as_str() {
            "--corpus" => corpus = Some(PathBuf::from(value)),
            "--count" => count = value.parse().map_err(|_| "invalid count")?,
            "--device" => {
                cpu = match value.as_str() {
                    "cpu" => true,
                    "gpu" => false,
                    _ => return Err("--device must be cpu or gpu".into()),
                }
            }
            _ => return Err(format!("unknown argument {flag}")),
        }
    }
    Ok(Arguments {
        corpus: corpus.ok_or("--corpus is required")?,
        count,
        cpu,
    })
}

fn main() -> Result<(), String> {
    let args = arguments()?;
    let text = std::fs::read_to_string(args.corpus).map_err(|e| e.to_string())?;
    let mut examples = Vec::new();
    for line in text.lines().filter(|line| !line.trim().is_empty()) {
        let example: Labeled = serde_json::from_str(line).map_err(|e| e.to_string())?;
        if training::partition(&example.formats, 10) == Partition::HeldOut {
            examples.push(example);
        }
    }
    // Shuffle reproducibly so a sample is not just the corpus's first formats.
    examples.shuffle(&mut rand::rngs::StdRng::seed_from_u64(20_260_909));
    if args.count > 0 {
        examples.truncate(args.count);
    }
    if examples.is_empty() {
        return Err("no held-out examples".into());
    }
    if args.cpu {
        evaluate(
            &ekubo_wallet_preview::cpu::load().map_err(|e| e.to_string())?,
            &examples,
        );
    } else {
        evaluate(
            &ekubo_wallet_preview::gpu::load().map_err(|e| e.to_string())?,
            &examples,
        );
    }
    Ok(())
}

fn evaluate<B: Backend>(engine: &PreviewEngine<B>, examples: &[Labeled]) {
    let mut class_right = 0;
    let mut risk_right = 0;
    let mut critical_missed = 0;
    let mut critical = 0;
    let mut exact = 0;
    let mut empty = 0;
    let mut slots_right = 0;
    let mut seen = [0_usize; CLASS_COUNT];
    let mut right = [0_usize; CLASS_COUNT];
    let started = std::time::Instant::now();
    for chunk in examples.chunks(8) {
        let documents: Vec<_> = chunk.iter().map(|e| e.document.clone()).collect();
        for (example, preview) in chunk.iter().zip(engine.preview_all(&documents)) {
            let expected = TransactionClass::from_corpus_name(&example.class)
                .unwrap_or(TransactionClass::Unrecognized);
            seen[expected.index()] += 1;
            if preview.class == expected {
                class_right += 1;
                right[expected.index()] += 1;
            }
            if preview.risk.corpus_name() == example.risk {
                risk_right += 1;
            }
            if example.risk == "critical" {
                critical += 1;
                if preview.risk.corpus_name() != "critical" {
                    critical_missed += 1;
                }
            }
            let slots = slotize(&example.document);
            let tokens: Vec<_> = example
                .summary_pieces
                .iter()
                .map(|p| vocab::token_of(p))
                .collect();
            let target = ekubo_wallet_preview::infer::render_summary(&slots, &tokens);
            exact += usize::from(preview.summary == target);
            empty += usize::from(preview.summary.is_empty());
            // Extract both sets from rendered text. Action slots contain other
            // values, so comparing target token IDs with text matches would
            // count nested values only on the prediction side.
            let covered = |text: &str| -> BTreeSet<&str> {
                slots
                    .slots
                    .iter()
                    .filter(|slot| text.contains(&slot.text))
                    .map(|slot| slot.text.as_str())
                    .collect()
            };
            let expected_slots = covered(&target);
            let predicted_slots = covered(&preview.summary);
            slots_right += usize::from(expected_slots == predicted_slots);
            println!(
                "{}",
                serde_json::json!({
                    "formats": example.formats, "document": example.document,
                    "expected_class": example.class,
                    "class": preview.class.corpus_name(), "expected_risk": example.risk,
                    "risk": preview.risk.corpus_name(), "expected_summary": target,
                    "summary": preview.summary,
                })
            );
        }
    }
    eprintln!(
        "{}",
        serde_json::json!({
            "examples": examples.len(), "class_correct": class_right, "risk_correct": risk_right,
            "critical_examples": critical, "critical_underestimated": critical_missed,
            "summary_exact": exact, "summary_empty": empty, "slot_text_coverage_exact": slots_right,
            "elapsed_ms": started.elapsed().as_millis(),
        })
    );
    for i in 0..CLASS_COUNT {
        eprintln!(
            "{}: {}/{}",
            TransactionClass::from_index(i).corpus_name(),
            right[i],
            seen[i]
        );
    }
}
