//! Isolated inference benchmark: no corpus parsing or model training. Run under
//! `taskset` and `/usr/bin/time -v` to measure one-core latency and peak RSS.
use burn::tensor::backend::Backend;
use ekubo_wallet_preview::{CallSummary, PlanDocument, infer::PreviewEngine};
use std::time::{Duration, Instant};

fn main() -> Result<(), String> {
    let started = Instant::now();
    if std::env::args().nth(1).as_deref() == Some("gpu") {
        bench(
            &ekubo_wallet_preview::gpu::load().map_err(|e| e.to_string())?,
            started,
        );
    } else {
        bench(
            &ekubo_wallet_preview::cpu::load().map_err(|e| e.to_string())?,
            started,
        );
    }
    Ok(())
}

fn plan(calls: usize) -> PlanDocument {
    PlanDocument {
        simulation: None,
        calls: (0..calls)
            .map(|i| CallSummary {
                description: Some("Ethena — Cooldown shares".into()),
                details: vec![format!("Amount: {} USDC", i + 1)],
                target: "0x1111111254EEB25477B68fb85Ed929f73A960582".into(),
                native_value: "0 ETH".into(),
                warnings: vec![],
                evidence: None,
            })
            .collect(),
    }
}

fn bench<B: Backend>(engine: &PreviewEngine<B>, started: Instant) {
    let one = plan(1);
    let preview = run(engine, std::slice::from_ref(&one)).remove(0);
    println!(
        "{}",
        serde_json::json!({"cold_load_and_first_ms": started.elapsed().as_millis(), "summary": preview.summary})
    );
    let mut near_limit = plan(1);
    near_limit.calls[0].details.push("additional ".repeat(440));
    let slots = ekubo_wallet_preview::slots::slotize(&near_limit);
    assert!(!slots.truncated);
    assert_eq!(
        ekubo_wallet_preview::slots::width_for(slots.tokens.len()),
        512
    );
    for (name, documents) in [
        ("one_call", vec![one.clone()]),
        ("eight_requests", vec![one; 8]),
        ("64_call_plan", vec![plan(64)]),
        ("4096_call_plan", vec![plan(4096)]),
        ("4096_distinct_readings", vec![distinct_readings()]),
        ("8MiB_calldata", vec![large_calldata()]),
        ("near_limit_call", vec![near_limit.clone()]),
        ("eight_near_limit_requests", vec![near_limit; 8]),
    ] {
        let _ = run(engine, &documents);
        let mut samples: Vec<Duration> = (0..20)
            .map(|_| {
                let started = Instant::now();
                std::hint::black_box(run(engine, &documents));
                started.elapsed()
            })
            .collect();
        samples.sort_unstable();
        println!(
            "{}",
            serde_json::json!({"case": name, "iterations": samples.len(), "p50_us": samples[10].as_micros(), "p95_us": samples[18].as_micros()})
        );
    }
}

fn run<B: Backend>(
    engine: &PreviewEngine<B>,
    documents: &[PlanDocument],
) -> Vec<ekubo_wallet_preview::TransactionPreview> {
    if std::env::args().nth(2).as_deref() == Some("legacy") {
        futures::executor::block_on(engine.legacy_all_async(documents)).expect("legacy inference")
    } else {
        futures::executor::block_on(engine.card_all_async(documents)).expect("card inference")
    }
}

fn large_calldata() -> PlanDocument {
    let mut document = plan(1);
    document.calls[0].evidence = Some(ekubo_wallet_preview::slots::CallEvidence {
        calldata: format!("0x{}", "ab".repeat(8 * 1024 * 1024)),
        ..ekubo_wallet_preview::slots::CallEvidence::default()
    });
    document
}

fn distinct_readings() -> PlanDocument {
    let mut document = plan(4096);
    for (index, call) in document.calls.iter_mut().enumerate() {
        let words: Vec<_> = (0..12)
            .map(|bit| {
                if index & (1 << bit) == 0 {
                    "swap"
                } else {
                    "approve"
                }
            })
            .collect();
        call.details.push(format!("Context: {}", words.join(" ")));
    }
    document
}
