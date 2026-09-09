use super::*;

#[test]
fn every_class_round_trips_through_its_index() {
    for (index, class) in CLASSES.iter().enumerate() {
        assert_eq!(class.index(), index);
        assert_eq!(TransactionClass::from_index(index), *class);
    }
}

#[test]
fn every_class_round_trips_through_its_corpus_name() {
    for class in CLASSES {
        assert_eq!(
            TransactionClass::from_corpus_name(class.corpus_name()),
            Some(class)
        );
    }
}

#[test]
fn corpus_names_are_distinct() {
    let mut names: Vec<&str> = CLASSES.iter().map(|class| class.corpus_name()).collect();
    names.sort_unstable();
    let count = names.len();
    names.dedup();
    assert_eq!(names.len(), count);
}

#[test]
fn an_unknown_corpus_name_is_refused_rather_than_folded_into_unrecognized() {
    assert_eq!(TransactionClass::from_corpus_name("flash_loan"), None);
    assert_eq!(RiskBand::from_corpus_name("severe"), None);
}

/// A class index past the enum is only reachable from weights that disagree
/// with this build. It saturates instead of panicking.
#[test]
fn an_out_of_range_class_index_reads_as_unrecognized() {
    assert_eq!(
        TransactionClass::from_index(CLASS_COUNT),
        TransactionClass::Unrecognized
    );
    assert_eq!(
        TransactionClass::from_index(usize::MAX),
        TransactionClass::Unrecognized
    );
}

/// The safe reading of a risk index nothing recognizes is the one that asks
/// for more attention, not less.
#[test]
fn an_out_of_range_risk_index_reads_as_critical() {
    assert_eq!(RiskBand::from_index(RISK_COUNT), RiskBand::Critical);
    assert_eq!(RiskBand::from_index(usize::MAX), RiskBand::Critical);
}

#[test]
fn unrecognized_stays_last_so_older_weights_keep_their_meanings() {
    assert_eq!(CLASSES[CLASS_COUNT - 1], TransactionClass::Unrecognized);
}

#[test]
fn every_risk_round_trips() {
    for (index, risk) in RISKS.iter().enumerate() {
        assert_eq!(risk.index(), index);
        assert_eq!(RiskBand::from_index(index), *risk);
        assert_eq!(RiskBand::from_corpus_name(risk.corpus_name()), Some(*risk));
    }
}
