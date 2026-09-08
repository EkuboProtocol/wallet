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
            panic!("the committed weights do not match this build: {reason}")
        }
    }
}
