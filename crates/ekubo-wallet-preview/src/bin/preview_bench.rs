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
        calls: (0..calls)
            .map(|i| CallSummary {
                description: Some("Ethena — Cooldown shares".into()),
                details: vec![format!("Amount: {} USDC", i + 1)],
                target: "0x1111111254EEB25477B68fb85Ed929f73A960582".into(),
                native_value: "0 ETH".into(),
                warnings: vec![],
            })
            .collect(),
    }
}

fn bench<B: Backend>(engine: &PreviewEngine<B>, started: Instant) {
    let one = plan(1);
    let preview = engine.preview(&one);
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
        ("near_limit_call", vec![near_limit.clone()]),
        ("eight_near_limit_requests", vec![near_limit; 8]),
    ] {
        let _ = engine.preview_all(&documents);
        let mut samples: Vec<Duration> = (0..20)
            .map(|_| {
                let started = Instant::now();
                std::hint::black_box(engine.preview_all(&documents));
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
