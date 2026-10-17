//! L1352: the founder's verified passport stands in for exactly the voucher step.
use super::super::founder_decision;
use crbk::{Decision, GateFailure, GateLevel, Missing, MissingGate, Requirement};

fn gate(gate: &str, level: GateLevel, reason: GateFailure) -> MissingGate {
    MissingGate {
        requirement: Requirement {
            gate: gate.into(),
            level,
            provider: None,
        },
        reason,
    }
}

fn voucher() -> MissingGate {
    gate("cvch", GateLevel::Community, GateFailure::ProofRequired)
}

fn decision(missing: Vec<Missing>) -> Decision {
    Decision {
        allowed: missing.is_empty(),
        missing,
    }
}

#[test]
fn only_the_missing_voucher_is_waived() {
    let waived = founder_decision(decision(vec![Missing::Gates {
        needed: 1,
        alternatives: vec![voucher()],
    }]));
    assert!(waived.allowed);
    assert!(waived.missing.is_empty());
}

#[test]
fn every_other_gate_still_applies() {
    let other = gate("age", GateLevel::Community, GateFailure::ProofRequired);
    let waived = founder_decision(decision(vec![Missing::Gates {
        needed: 2,
        alternatives: vec![voucher(), other.clone()],
    }]));
    assert!(!waived.allowed);
    assert_eq!(
        waived.missing,
        vec![Missing::Gates {
            needed: 1,
            alternatives: vec![other],
        }]
    );
}

#[test]
fn one_of_and_threshold_groups_count_the_voucher_once() {
    let other = gate("age", GateLevel::Community, GateFailure::ProofRequired);
    // any_of: the voucher alternative satisfies the group.
    assert!(
        founder_decision(decision(vec![Missing::Gates {
            needed: 1,
            alternatives: vec![other.clone(), voucher()],
        }]))
        .allowed
    );
    // k_of_n needing two: the voucher is one pass, one more is still needed.
    let waived = founder_decision(decision(vec![Missing::Gates {
        needed: 2,
        alternatives: vec![
            other.clone(),
            voucher(),
            gate("pay", GateLevel::Community, GateFailure::ProofRequired),
        ],
    }]));
    assert!(!waived.allowed);
    assert!(
        matches!(&waived.missing[..], [Missing::Gates { needed: 1, alternatives }] if alternatives.len() == 2)
    );
}

#[test]
fn disabled_global_and_membership_requirements_stay() {
    let disabled = gate("cvch", GateLevel::Community, GateFailure::Disabled);
    let provider = gate("cvch", GateLevel::Community, GateFailure::ProviderDisabled);
    let global = gate("cvch", GateLevel::Global, GateFailure::ProofRequired);
    for kept in [disabled, provider, global] {
        let original = decision(vec![Missing::Gates {
            needed: 1,
            alternatives: vec![kept],
        }]);
        assert_eq!(founder_decision(original.clone()), original);
    }
    let membership = decision(vec![Missing::Membership {
        allowed: Default::default(),
    }]);
    assert_eq!(founder_decision(membership.clone()), membership);
    let unavailable = decision(vec![Missing::ActionUnavailable]);
    assert_eq!(founder_decision(unavailable.clone()), unavailable);
}

#[test]
fn an_allowed_decision_stays_allowed() {
    assert_eq!(founder_decision(decision(vec![])), decision(vec![]));
}
