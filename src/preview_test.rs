use super::*;

fn interpretation(description: Option<&str>) -> StepInterpretation {
    StepInterpretation {
        candidates: Vec::new(),
        step: 1,
        description: description.map(ToOwned::to_owned),
        details: vec!["Amount: 1.5 USDC".to_owned()],
        warnings: Vec::new(),
    }
}

#[test]
fn a_call_summary_restates_the_interpretation_the_review_already_holds() {
    let summary = call_summary(
        &interpretation(Some("swap tokens")),
        "USDC (0xA0b8)".to_owned(),
        "0 ETH".to_owned(),
    );
    assert_eq!(summary.description.as_deref(), Some("swap tokens"));
    assert_eq!(summary.details, ["Amount: 1.5 USDC"]);
    assert_eq!(summary.target, "USDC (0xA0b8)");
}

/// Asking for nothing must not stand up a GPU device.
#[test]
fn an_empty_batch_answers_without_touching_the_model() {
    assert!(previews(Vec::new()).is_empty());
}

/// Whatever the model's state, a caller gets a map it can read. This is the
/// contract the review list depends on: previews are supplemental, so their
/// absence is ordinary rather than an error to surface.
#[test]
fn an_unavailable_model_answers_an_empty_map_rather_than_failing() {
    let plans = vec![(
        Uuid::nil(),
        PlanDocument {
            calls: vec![call_summary(
                &interpretation(Some("swap tokens")),
                "0xA0b8".to_owned(),
                "0 ETH".to_owned(),
            )],
        },
    )];
    let answered = previews(plans);
    assert!(answered.is_empty() || answered.contains_key(&Uuid::nil()));
}

#[test]
fn unchanged_interpretations_reuse_previews_but_changed_warnings_do_not() {
    let id = Uuid::new_v4();
    let mut cache = PreviewCache::new();
    let document = PlanDocument {
        calls: vec![CallSummary {
            description: Some("swap tokens".into()),
            ..CallSummary::default()
        }],
    };
    let expected = TransactionPreview::unrecognized();
    let first = cached_previews(vec![(id, document.clone())], &mut cache, |documents| {
        assert_eq!(documents.len(), 1);
        Ok(vec![expected.clone()])
    })
    .unwrap();
    let second = cached_previews(vec![(id, document.clone())], &mut cache, |_| {
        panic!("unchanged plan was inferred twice")
    })
    .unwrap();
    assert_eq!(first, second);
    let mut changed = document;
    changed.calls[0].warnings.push("unlimited allowance".into());
    cached_previews(vec![(id, changed.clone())], &mut cache, |documents| {
        assert_eq!(documents, [changed]);
        Ok(vec![expected])
    })
    .unwrap();
    cached_previews(vec![], &mut cache, |_| panic!("empty queue inferred")).unwrap();
    assert!(cache.is_empty(), "settled requests must leave the cache");
}
