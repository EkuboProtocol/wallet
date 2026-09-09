use super::*;

type TestBackend = burn::backend::NdArray;

/// The weights are committed to git, so their size is a repository concern and
/// not only a runtime one: every retrain writes a new copy into history.
#[test]
fn the_committed_weights_stay_small_enough_to_live_in_git() {
    const CEILING: usize = 12 * 1024 * 1024;
    assert!(
        size() <= CEILING,
        "the weights are {} bytes, over the {CEILING}-byte ceiling; retrain at half precision or shrink the model",
        size()
    );
}

/// A checkout that has not run the training pipeline still builds and still
/// runs. It simply has no previews.
#[test]
fn absent_weights_are_reported_rather_than_panicking() {
    let device = burn::backend::ndarray::NdArrayDevice::default();
    match load::<TestBackend>(&device) {
        Ok(_) => assert!(present(), "a model loaded, so weights must be present"),
        Err(LoadError::Absent) => assert!(!present()),
        Err(LoadError::Mismatched(reason)) => {
            // Expected while a retrain is outstanding; the dedicated test
            // below is what checks the refusal is well formed.
            assert!(reason.contains("retrain"), "{reason}");
        }
    }
}

/// Weights that do not match this build must be refused, not loaded.
///
/// burn does not check this. A record whose tensors are the wrong shape loads
/// silently -- confirmed against a build whose vocabulary had shrunk by two
/// entries, which accepted weights sized for the old one and would then have
/// read every learned word off by two. A preview that is missing is ordinary;
/// one that is fluent and systematically wrong is what this crate exists to
/// prevent, so the check is ours to make.
#[test]
fn weights_fitted_against_a_different_build_are_refused() {
    let expected = fingerprint();
    assert!(
        expected.contains("vocab=") && expected.contains("classes="),
        "the fingerprint must name the things a retrain changes: {expected}"
    );
    let device = burn::backend::ndarray::NdArrayDevice::default();
    match load::<TestBackend>(&device) {
        Ok(_) => assert_eq!(
            super::FINGERPRINT.trim(),
            expected,
            "weights loaded, so the committed fingerprint must match this build"
        ),
        Err(LoadError::Absent) => assert!(!present()),
        Err(LoadError::Mismatched(reason)) => {
            assert!(
                reason.contains("retrain"),
                "a mismatch must say what to do about it: {reason}"
            );
        }
    }
}

/// Every constant a retrain would change appears in the fingerprint. A
/// forgotten one is a retrain that should have been forced and was not.
#[test]
fn the_fingerprint_covers_everything_that_changes_a_tensor() {
    let expected = fingerprint();
    for key in [
        "vocab=", "classes=", "risks=", "d_model=", "slots=", "input=", "summary=",
    ] {
        assert!(expected.contains(key), "{key} missing from {expected}");
    }
}
