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

/// How many single-call plans of each standard shape to emit per round.
///
/// Sized against the roughly 1100 descriptor formats a round also emits, so
/// the ordinary token call is well represented without drowning out the
/// protocols the registry exists to describe.
const HEAD_PLANS_PER_ROUND: usize = 90;

struct Arguments {
    spec: PathBuf,
    out: PathBuf,
    samples: usize,
    seed: u64,
}

fn parse_arguments() -> Result<Arguments, String> {
    let mut spec = None;
    let mut out = None;
    let mut samples = 24_usize;
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
            "--seed" => seed = value()?.parse().map_err(|_| "--seed must be a number")?,
            other => return Err(format!("unrecognized flag {other}")),
        }
    }
    Ok(Arguments {
        spec: spec.ok_or("--spec is required")?,
        out: out.ok_or("--out is required")?,
        samples,
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
        // The head of the distribution, which the registry does not describe:
        // plain token calls, and calls nothing decodes at all. A wallet signs
        // far more of these than it does any vendored protocol's, and
        // "unrecognized" is an answer the model only learns from examples
        // where it is the right one.
        for _ in 0..HEAD_PLANS_PER_ROUND {
            for summary in [
                corpus::synthesize_standard(&fixtures, &mut rng),
                corpus::synthesize_opaque(&fixtures, &mut rng),
            ]
            .into_iter()
            .flatten()
            {
                let example = corpus::record(
                    &PlanDocument {
                        simulation: None,
                        calls: vec![summary],
                    },
                    vec![String::new()],
                    vec![String::new()],
                );
                writeln!(
                    writer,
                    "{}",
                    serde_json::to_string(&example).map_err(|error| error.to_string())?
                )
                .map_err(|error| error.to_string())?;
                written += 1;
            }
        }
        for spec in &specs {
            let Some(example) = build(spec, &specs, &fixtures, &mut rng) else {
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
/// The shapes a real execution plan comes in.
///
/// A generator that drew every call at random would produce plans that are
/// mostly incoherent -- a swap, a governance vote and a bridge in one
/// signature -- and since a plan of unrelated calls is by definition a batch,
/// the corpus would have been two thirds batches. Real plans are coherent:
/// most are a single call, and the commonest multi-call plan by far is an
/// approval followed by the one action it exists for.
enum Shape {
    /// One call. The majority of what a wallet signs.
    Single,
    /// A standard token approval, then the action it enables.
    ApproveThen,
    /// Two calls of the same protocol.
    SameProtocol,
    /// Genuinely unrelated calls. This is what `batch` should mean.
    Mixed(usize),
}

impl Shape {
    fn sample(rng: &mut StdRng) -> Self {
        match rng.random_range(0..100) {
            0..=54 => Self::Single,
            55..=79 => Self::ApproveThen,
            80..=91 => Self::SameProtocol,
            _ => Self::Mixed(rng.random_range(3..6)),
        }
    }
}

/// One call of a plan, with the descriptor it came from when it had one.
type Built = (
    ekubo_wallet_preview::slots::CallSummary,
    Option<(String, String, String)>,
);

fn build(
    spec: &CallSpec,
    pool: &[CallSpec],
    fixtures: &Fixtures,
    rng: &mut StdRng,
) -> Option<corpus::Example> {
    let lead = from_spec(spec, fixtures, rng)?;
    let mut built = vec![lead];
    match Shape::sample(rng) {
        Shape::Single => {}
        Shape::ApproveThen => {
            // The approval precedes the action it exists for, so it is
            // inserted ahead of the call this example is about.
            if let Some(summary) = corpus::synthesize_approval(fixtures, rng) {
                built.insert(0, (summary, None));
            }
        }
        Shape::SameProtocol => {
            let sibling = pool
                .iter()
                .filter(|other| other.protocol == spec.protocol)
                .collect::<Vec<_>>();
            if let Some(other) = sibling.choose(rng)
                && let Some(call) = from_spec(other, fixtures, rng)
            {
                built.push(call);
            }
        }
        Shape::Mixed(count) => {
            for _ in 1..count {
                let call = match rng.random_range(0..10) {
                    0..=6 => pool
                        .choose(rng)
                        .and_then(|other| from_spec(other, fixtures, rng)),
                    7 | 8 => corpus::synthesize_standard(fixtures, rng).map(|call| (call, None)),
                    _ => corpus::synthesize_opaque(fixtures, rng).map(|call| (call, None)),
                };
                if let Some(call) = call {
                    built.push(call);
                }
            }
        }
    }

    let mut summaries = Vec::new();
    let mut formats = Vec::new();
    let mut protocols = Vec::new();
    for (summary, keyed) in built {
        summaries.push(summary);
        // A call with no descriptor behind it is keyed by the empty string,
        // which the label table reads as "no intent" and falls back to
        // classifying from the decoded text.
        let (format, protocol) = keyed.map_or_else(
            || (String::new(), String::new()),
            |(descriptor, canonical, protocol)| (format!("{descriptor}::{canonical}"), protocol),
        );
        formats.push(format);
        protocols.push(protocol);
    }
    Some(corpus::record(
        &PlanDocument {
            simulation: None,
            calls: summaries,
        },
        formats,
        protocols,
    ))
}

fn from_spec(spec: &CallSpec, fixtures: &Fixtures, rng: &mut StdRng) -> Option<Built> {
    corpus::synthesize(spec, fixtures, rng).map(|summary| {
        (
            summary,
            Some((
                spec.descriptor.clone(),
                spec.canonical.clone(),
                spec.protocol.clone(),
            )),
        )
    })
}
