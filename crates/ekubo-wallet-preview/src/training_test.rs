use super::*;

type TestBackend = burn::backend::NdArray;

fn labeled(summary: &[&str], input: &[&str]) -> Labeled {
    Labeled {
        formats: vec!["registry/x/calldata-y.json::f()".to_owned()],
        input_pieces: input.iter().map(|piece| (*piece).to_string()).collect(),
        summary_pieces: summary.iter().map(|piece| (*piece).to_string()).collect(),
        class: "swap".to_owned(),
        risk: "routine".to_owned(),
    }
}

/// The property the copy head is trained by: a slot reference in the target is
/// the *input position* holding it, offset past the vocabulary -- not the
/// reference's own vocabulary id. Getting this wrong would teach the word head
/// to recite "<s0>" and leave the copy head untrained.
#[test]
fn a_slot_reference_becomes_a_position_target_not_a_word_target() {
    let vocabulary = vocab::size();
    let encoded = encode(
        &labeled(&["swap", "<s0>"], &["<call>", "<amount>", "<s0>", "swap"]),
        vocabulary,
    )
    .expect("the example encodes");
    let last = encoded.summary_targets[encoded.summary_targets.len() - 2];
    assert_eq!(
        last,
        vocabulary + 2,
        "the reference must name input position 2, where <s0> sits"
    );
    assert_ne!(last, vocab::token_of("<s0>") as usize);
}

/// The decoder is fed vocabulary ids and scored against the joint space. This
/// is not a stylistic separation: the input goes through an embedding table
/// with one row per vocabulary entry, so feeding back a copy's
/// `vocabulary + position` reads off the end of it -- which is exactly how the
/// first CPU training run died, inside burn's `select`.
#[test]
fn nothing_fed_to_the_decoder_is_outside_the_vocabulary() {
    let vocabulary = vocab::size();
    let encoded = encode(
        &labeled(
            &["swap", "<s0>", "for", "<s1>"],
            &["<call>", "<amount>", "<s0>", "<token>", "<s1>", "swap"],
        ),
        vocabulary,
    )
    .expect("the example encodes");
    for token in &encoded.summary_inputs {
        assert!(
            (*token as usize) < vocabulary,
            "{token} is not a row of the embedding table"
        );
    }
    // A copy is fed back as the slot's own token, exactly as inference does.
    assert_eq!(encoded.summary_inputs[2], vocab::slot_token(0).unwrap());
    assert_eq!(
        encoded.summary_inputs.len(),
        encoded.summary_targets.len(),
        "every fed position must have something to predict"
    );
}

#[test]
fn a_summary_naming_a_slot_the_input_lacks_is_dropped() {
    assert!(
        encode(
            &labeled(&["swap", "<s3>"], &["<call>", "<amount>", "<s0>"]),
            vocab::size()
        )
        .is_none(),
        "a target the model cannot reach must not become training signal"
    );
}

#[test]
fn a_summary_word_outside_the_vocabulary_is_dropped() {
    assert!(
        encode(
            &labeled(&["frobnicate"], &["<call>", "swap"]),
            vocab::size()
        )
        .is_none()
    );
}

#[test]
fn a_class_the_enum_does_not_have_is_dropped() {
    let mut example = labeled(&["swap"], &["<call>", "swap"]);
    example.class = "flash_loan".to_owned();
    assert!(encode(&example, vocab::size()).is_none());
}

#[test]
fn only_positions_holding_a_slot_reference_are_copyable() {
    let encoded = encode(
        &labeled(&["swap", "<s0>"], &["<call>", "<amount>", "<s0>", "swap"]),
        vocab::size(),
    )
    .expect("the example encodes");
    assert_eq!(encoded.copyable, [false, false, true, false]);
}

/// Padding to the longest member, and a short summary in a batch of long ones
/// padded with PAD so the loss can ignore it.
#[test]
fn a_batch_pads_every_row_to_the_shape_it_was_given() {
    let device = burn::backend::ndarray::NdArrayDevice::default();
    let short = encode(&labeled(&["swap"], &["<call>", "swap"]), vocab::size()).unwrap();
    let long = encode(
        &labeled(
            &["swap", "<s0>", "for", "<s1>"],
            &["<call>", "<amount>", "<s0>", "<token>", "<s1>", "swap"],
        ),
        vocab::size(),
    )
    .unwrap();
    let shape = Shape {
        width: 32,
        count: 2,
    };
    let batch = batch::<TestBackend>(&[short, long], shape, &device);
    assert_eq!(batch.input.dims(), [2, 32]);
    let pad: Vec<bool> = batch.pad.into_data().to_vec().unwrap();
    assert_eq!(&pad[..2], &[false, false]);
    assert!(
        pad[2..32].iter().all(|padded| *padded),
        "the short row pads out"
    );
    assert!(
        pad[32..38].iter().all(|padded| !*padded),
        "the long row does not"
    );
}

/// The held-out split runs along formats, not examples, so the eval measures
/// reading a descriptor the model never saw.
#[test]
fn the_split_never_puts_one_format_on_both_sides() {
    let examples: Vec<Encoded> = (0..400)
        .filter_map(|index| {
            let mut example = labeled(&["swap"], &["<call>", "swap"]);
            example.formats = vec![format!("registry/p/calldata-{}.json::f()", index % 50)];
            encode(&example, vocab::size())
        })
        .collect();
    let (train, evaluate) = split(examples, 5);
    assert!(!train.is_empty() && !evaluate.is_empty());
    let held: std::collections::BTreeSet<&String> = evaluate
        .iter()
        .flat_map(|example| example.formats.iter())
        .collect();
    for example in &train {
        for format in &example.formats {
            assert!(!held.contains(format), "{format} is on both sides");
        }
    }
}

#[test]
fn class_weights_lift_a_rare_class_without_letting_it_dominate() {
    let mut examples = Vec::new();
    for index in 0..1000 {
        let mut example = encode(&labeled(&["swap"], &["<call>", "swap"]), vocab::size()).unwrap();
        example.class = if index < 990 {
            TransactionClass::Withdraw.index()
        } else {
            TransactionClass::Borrow.index()
        };
        examples.push(example);
    }
    let weights = class_weights(&examples);
    let common = weights[TransactionClass::Withdraw.index()];
    let rare = weights[TransactionClass::Borrow.index()];
    assert!(rare > common, "the rare class must be weighted up");
    assert!(
        rare / common <= 16.0,
        "a 99:1 imbalance must not become a 99:1 weight, or the model shouts the rare class"
    );
    assert!(weights.iter().all(|weight| *weight > 0.0));
}

/// The same format lands on the same side on every machine and every run.
#[test]
fn the_split_is_stable_across_runs() {
    assert_eq!(
        hash("registry/lido/calldata-stETH.json::approve(address,uint256)"),
        hash("registry/lido/calldata-stETH.json::approve(address,uint256)")
    );
    assert_ne!(hash("a"), hash("b"));
}

/// Every batch has one of five fixed shapes. A shape that varies with the
/// batch is a shape cubecl compiles a new kernel and reserves new buffers for,
/// and on a 2 GB integrated GPU that is fatal rather than merely slow -- the
/// first two runs of this died before finishing an epoch.
#[test]
fn every_batch_has_one_of_the_fixed_shapes() {
    let mut rng = <rand::rngs::StdRng as rand::SeedableRng>::seed_from_u64(1);
    let examples: Vec<Encoded> = (1..200)
        .filter_map(|index| {
            let input: Vec<&str> = std::iter::repeat_n("swap", index % 60 + 1).collect();
            let mut example = labeled(&["swap"], &input);
            example.formats = vec![format!("f{index}")];
            encode(&example, vocab::size())
        })
        .collect();
    let batched = batches(&examples, &mut rng);
    assert!(!batched.is_empty());
    let mut shapes = std::collections::BTreeSet::new();
    for (shape, chunk) in &batched {
        assert_eq!(
            chunk.len(),
            shape.count,
            "a batch must be exactly its shape"
        );
        for example in chunk {
            assert!(
                example.input.len() <= shape.width || shape.width == 512,
                "an example of {} was put in a width-{} bucket",
                example.input.len(),
                shape.width
            );
        }
        shapes.insert((shape.width, shape.count));
    }
    assert!(
        shapes.len() <= 5,
        "more than five distinct shapes reached the GPU: {shapes:?}"
    );
}

/// Every example is trained on. A trailing partial batch is filled by cycling
/// that bucket's own members rather than dropped.
#[test]
fn no_example_is_dropped_to_keep_a_shape_fixed() {
    let mut rng = <rand::rngs::StdRng as rand::SeedableRng>::seed_from_u64(7);
    let examples: Vec<Encoded> = (1..97)
        .filter_map(|index| {
            let input: Vec<&str> = std::iter::repeat_n("swap", index % 40 + 1).collect();
            let mut example = labeled(&["swap"], &input);
            example.formats = vec![format!("f{index}")];
            encode(&example, vocab::size())
        })
        .collect();
    let batched = batches(&examples, &mut rng);
    let seen: std::collections::BTreeSet<String> = batched
        .iter()
        .flat_map(|(_, chunk)| chunk.iter().flat_map(|e| e.formats.iter().cloned()))
        .collect();
    for example in &examples {
        for format in &example.formats {
            assert!(seen.contains(format), "{format} was dropped");
        }
    }
}

/// A summary is padded to one width too, because the step count is another
/// shape axis.
#[test]
fn summaries_are_padded_to_one_fixed_width() {
    let device = burn::backend::ndarray::NdArrayDevice::default();
    let short = encode(&labeled(&["swap"], &["<call>", "swap"]), vocab::size()).unwrap();
    let shape = Shape {
        width: 32,
        count: 2,
    };
    let batch = batch::<TestBackend>(&[short.clone(), short], shape, &device);
    assert_eq!(batch.prefix.dims(), [2, SUMMARY_WIDTH - 1]);
    assert_eq!(batch.target.dims(), [2, SUMMARY_WIDTH - 1]);
    assert_eq!(batch.input.dims(), [2, 32]);
}
