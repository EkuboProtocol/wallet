use super::*;

#[test]
fn permissions_do_not_displace_the_main_swap() {
    use TransactionClass::{Approval, Revocation, Swap};
    for classes in [
        vec![Approval, Swap],
        vec![Swap, Revocation],
        vec![Approval, Swap, Revocation],
    ] {
        let values = scores(&classes);
        let principal = (0..values.len())
            .max_by(|a, b| values[*a].total_cmp(&values[*b]))
            .unwrap();
        assert_eq!(classes[principal], Swap);
    }
}

#[test]
fn all_calls_contribute_and_long_plans_have_finite_scores() {
    let mut calls = vec![TransactionClass::Approval; 4095];
    calls.push(TransactionClass::Supply);
    let output = scores(&calls);
    assert_eq!(output.len(), calls.len());
    assert!(output.iter().all(|score| score.is_finite()));
    assert!(scores(&[]).is_empty());
}
