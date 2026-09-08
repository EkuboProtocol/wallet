//! Generate the transaction-preview model's training corpus.
//!
//! Reads the call spec written by `scripts/preview-corpus-spec.py`, synthesizes
//! plans against it, interprets each one through the vendored clear-signing
//! engine, and writes one JSON record per line.
//!
//! Two modes, because labeling and training want different things:
//!
//!   * `--samples 1 --calls 1` writes one record per interpretable format --
//!     the sheet a human labels, small enough to read; and
//!   * the default writes many value-varied, multi-call plans -- the corpus
//!     the model is fitted on.

use ekubo_wallet_preview::{
    corpus::{self, CallSpec, Fixtures},
    slots::PlanDocument,
};
use rand::{RngExt as _, SeedableRng as _, rngs::StdRng, seq::IndexedRandom as _};
use std::{
    collections::BTreeSet,
    io::{BufWriter, Write as _},
    path::PathBuf,
};

struct Arguments {
    spec: PathBuf,
    out: PathBuf,
    samples: usize,
    max_calls: usize,
    seed: u64,
}

fn parse_arguments() -> Result<Arguments, String> {
    let mut spec = None;
    let mut out = None;
    let mut samples = 24_usize;
    let mut max_calls = 3_usize;
    let mut seed = 20_260_908_u64;
    let mut arguments = std::env::args().skip(1);
    while let Some(flag) = arguments.next() {
        let mut value = || {
            arguments
                .next()
                .ok_or_else(|| format!("{flag} needs a value"))
        };
        match flag.as_str() {
            "--spec" => spec = Some(PathBuf::from(value()?)),
            "--out" => out = Some(PathBuf::from(value()?)),
            "--samples" => samples = value()?.parse().map_err(|_| "--samples must be a number")?,
            "--calls" => max_calls = value()?.parse().map_err(|_| "--calls must be a number")?,
            "--seed" => seed = value()?.parse().map_err(|_| "--seed must be a number")?,
            other => return Err(format!("unrecognized flag {other}")),
        }
    }
    Ok(Arguments {
        spec: spec.ok_or("--spec is required")?,
        out: out.ok_or("--out is required")?,
        samples,
        max_calls: max_calls.max(1),
        seed,
    })
}

fn main() -> Result<(), String> {
    let arguments = parse_arguments()?;
    let text = std::fs::read_to_string(&arguments.spec)
        .map_err(|error| format!("reading {}: {error}", arguments.spec.display()))?;
    let specs: Vec<CallSpec> =
        serde_json::from_str(&text).map_err(|error| format!("parsing the spec: {error}"))?;
    let specs = corpus::deduplicate(specs);
    eprintln!("{} distinct interpretable formats in the spec", specs.len());

    let mut rng = StdRng::seed_from_u64(arguments.seed);
    let file = std::fs::File::create(&arguments.out)
        .map_err(|error| format!("creating {}: {error}", arguments.out.display()))?;
    let mut writer = BufWriter::new(file);

    let mut written = 0_usize;
    let mut covered = BTreeSet::new();
    for _ in 0..arguments.samples {
        let fixtures = Fixtures::new(&mut rng);
        for spec in &specs {
            let calls = rng.random_range(1..=arguments.max_calls);
            let Some(example) = build(spec, &specs, calls, &fixtures, &mut rng) else {
                continue;
            };
            covered.insert(format!("{}::{}", spec.descriptor, spec.canonical));
            writeln!(
                writer,
                "{}",
                serde_json::to_string(&example).map_err(|error| error.to_string())?
            )
            .map_err(|error| error.to_string())?;
            written += 1;
        }
    }
    writer.flush().map_err(|error| error.to_string())?;

    // Coverage is the generator's own correctness check, and it is keyed the
    // same way the spec is deduplicated -- by (descriptor, signature) -- so
    // the fraction is formats that produced a reading over formats attempted,
    // not two different populations compared. A format that never produced one
    // means its signature, address, or include chain is wrong somewhere.
    eprintln!(
        "wrote {written} examples covering {}/{} formats ({}%)",
        covered.len(),
        specs.len(),
        100 * covered.len() / specs.len().max(1)
    );
    Ok(())
}

/// Build one plan: the named format first, then further calls drawn at random.
///
/// The first call is the one the plan is *about*, and it leads, because that is
/// how a real plan reads -- an approval precedes the swap it exists for, but
/// the swap is the reason the owner is being asked.
fn build(
    spec: &CallSpec,
    pool: &[CallSpec],
    calls: usize,
    fixtures: &Fixtures,
    rng: &mut StdRng,
) -> Option<corpus::Example> {
    let mut summaries = Vec::new();
    let mut formats = Vec::new();
    let mut protocols = Vec::new();
    let mut chosen = spec;
    for index in 0..calls {
        if index > 0 {
            chosen = pool.choose(rng)?;
        }
        let Some(summary) = corpus::synthesize(chosen, fixtures, rng) else {
            // The leading call is what the plan is about, so a format that
            // will not interpret means there is no example here at all. A
            // later one failing just makes for a shorter plan.
            if index == 0 {
                return None;
            }
            continue;
        };
        summaries.push(summary);
        formats.push(format!("{}::{}", chosen.descriptor, chosen.canonical));
        protocols.push(chosen.protocol.clone());
    }
    Some(corpus::record(
        &PlanDocument { calls: summaries },
        formats,
        protocols,
    ))
}
