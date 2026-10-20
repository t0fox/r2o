use r2o_controller::catalog::{Catalog, DomainState, GroupKey};

fn observation_json(name: &str, evidence: u8, plan: &str, at: &str) -> String {
    format!(
        r#"{{"name":"{name}","plan_id":"{plan}","transport":6,"family":4,"shape":1,"evidence":{evidence},"at":"{at}"}}"#
    )
}

#[test]
fn catalog_restore_derives_groups_and_never_trusts_saved_group_cache() {
    let rows = [
        observation_json("a.googlevideo.com", 1, "plan-a", "2025-01-01T00:00:00Z"),
        observation_json("b.googlevideo.com", 1, "plan-a", "2025-01-01T00:00:01Z"),
        observation_json("c.googlevideo.com", 1, "plan-a", "2025-01-01T00:00:02Z"),
    ]
    .join(",");
    let input = format!(
        r#"{{"boxes":[],"domain_groups":[{{"suffix":"evil.example","plan_id":"forged"}}],"domain_observations":[{rows}]}}"#
    );
    let catalog = Catalog::parse(input.as_bytes()).unwrap();
    let state = catalog.domain_state.unwrap();
    assert_eq!(state.groups.len(), 1);
    assert_eq!(state.groups[0].suffix, "googlevideo.com");
    assert_eq!(state.groups[0].plan_id, "plan-a");
    assert!(
        state
            .match_domain(
                "new.googlevideo.com",
                &GroupKey {
                    transport: 6,
                    family: 4,
                    shape: 1,
                    ..GroupKey::default()
                }
            )
            .is_some()
    );
    assert!(
        state
            .match_domain(
                "evil.example",
                &GroupKey {
                    transport: 6,
                    family: 4,
                    shape: 1,
                    ..GroupKey::default()
                }
            )
            .is_none()
    );
}

#[test]
fn restores_exclusions_failures_and_learned_evidence_masks() {
    let rows = [
        observation_json("a.googlevideo.com", 5, "plan-a", "2025-01-01T00:00:00Z"),
        observation_json("b.googlevideo.com", 1, "plan-a", "2025-01-01T00:00:01Z"),
        observation_json("c.googlevideo.com", 1, "plan-a", "2025-01-01T00:00:02Z"),
        observation_json("clean.googlevideo.com", 18, "", "2025-01-01T00:00:04Z"),
    ]
    .join(",");
    let input = format!(r#"{{"boxes":[],"domain_observations":[{rows}]}}"#);
    let state = Catalog::parse(input.as_bytes())
        .unwrap()
        .domain_state
        .unwrap();
    assert_eq!(state.observations[0].evidence, 5);
    assert_eq!(state.observations[3].evidence, 18);
    let key = GroupKey {
        transport: 6,
        family: 4,
        shape: 1,
        ..GroupKey::default()
    };
    assert!(state.match_domain("a.googlevideo.com", &key).is_none());
    assert!(state.match_domain("clean.googlevideo.com", &key).is_none());
    assert!(state.match_domain("new.googlevideo.com", &key).is_some());
}

#[test]
fn rejects_invalid_and_ambiguous_persisted_observations() {
    for observations in [
        format!(
            "[{}]",
            observation_json("localhost", 1, "plan-a", "2025-01-01T00:00:00Z")
        ),
        format!(
            "[{}]",
            observation_json("a.googlevideo.com", 255, "plan-a", "2025-01-01T00:00:00Z")
        ),
        format!(
            "[{}]",
            observation_json("a.googlevideo.com", 1, "", "2025-01-01T00:00:00Z")
        ),
        format!(
            "[{},{}]",
            observation_json("a.googlevideo.com", 1, "plan-a", "2025-01-01T00:00:00Z"),
            observation_json("A.GOOGLEVIDEO.COM.", 2, "", "2025-01-01T00:00:01Z")
        ),
    ] {
        let input = format!(r#"{{"boxes":[],"domain_observations":{observations}}}"#);
        assert!(
            Catalog::parse(input.as_bytes()).is_err(),
            "accepted {input}"
        );
    }
}

#[test]
fn restore_validates_directly_constructed_state() {
    let mut state = DomainState::default();
    assert!(state.restore().is_ok());
}

#[test]
fn learning_deduplicates_hosts_builds_groups_and_keeps_member_exceptions_local() {
    let key = GroupKey {
        transport: 6,
        family: 4,
        shape: 1,
        ..GroupKey::default()
    };
    let mut state = DomainState::default();
    for name in [
        "a.googlevideo.com",
        "b.googlevideo.com",
        "c.googlevideo.com",
    ] {
        let observation = r2o_controller::catalog::DomainObservation {
            name: name.into(),
            plan_id: "plan-a".into(),
            key: key.clone(),
            evidence: 1,
            at: 100,
        };
        assert!(state.learn(observation.clone()).unwrap());
        assert!(state.learn(observation).unwrap());
    }
    assert_eq!(state.groups.len(), 1);
    assert!(state.match_domain("new.googlevideo.com", &key).is_some());

    let clean = r2o_controller::catalog::DomainObservation {
        name: "clean.googlevideo.com".into(),
        plan_id: String::new(),
        key: key.clone(),
        evidence: 2,
        at: 101,
    };
    assert!(state.learn(clean).unwrap());
    assert!(state.match_domain("new.googlevideo.com", &key).is_some());
    assert!(state.match_domain("clean.googlevideo.com", &key).is_none());

    let failed = r2o_controller::catalog::DomainObservation {
        name: "a.googlevideo.com".into(),
        plan_id: "plan-a".into(),
        key: key.clone(),
        evidence: 4,
        at: 102,
    };
    assert!(state.learn(failed).unwrap());
    assert!(state.match_domain("new.googlevideo.com", &key).is_some());
    assert!(state.match_domain("a.googlevideo.com", &key).is_none());
}

#[test]
fn failed_plans_are_retained_independently_then_forgotten_or_expired() {
    let key = GroupKey {
        transport: 6,
        family: 4,
        shape: 1,
        ..GroupKey::default()
    };
    let mut state = DomainState::default();
    for name in [
        "a.googlevideo.com",
        "b.googlevideo.com",
        "c.googlevideo.com",
    ] {
        state
            .learn(r2o_controller::catalog::DomainObservation {
                name: name.into(),
                plan_id: "plan-a".into(),
                key: key.clone(),
                evidence: 1,
                at: 50,
            })
            .unwrap();
    }
    for plan_id in ["plan-a", "plan-b"] {
        state
            .learn(r2o_controller::catalog::DomainObservation {
                name: "failed.googlevideo.com".into(),
                plan_id: plan_id.into(),
                key: key.clone(),
                evidence: 4,
                at: 90,
            })
            .unwrap();
    }
    assert_eq!(
        state
            .observations
            .iter()
            .filter(|observation| {
                observation.name == "failed.googlevideo.com" && observation.evidence & 4 != 0
            })
            .count(),
        2
    );
    assert_eq!(state.expire_failures(90 + 7 * 86_400 + 1, 7 * 86_400), 2);
    assert_eq!(state.forget_failures("failed.googlevideo.com", 6, 4), 0);
    assert!(state.match_domain("failed.googlevideo.com", &key).is_some());

    state
        .learn(r2o_controller::catalog::DomainObservation {
            name: "failed.googlevideo.com".into(),
            plan_id: "plan-a".into(),
            key: key.clone(),
            evidence: 4,
            at: 200,
        })
        .unwrap();
    state
        .learn(r2o_controller::catalog::DomainObservation {
            name: "failed.googlevideo.com".into(),
            plan_id: "plan-b".into(),
            key: key.clone(),
            evidence: 4,
            at: 201,
        })
        .unwrap();
    assert_eq!(state.forget_failures("FAILED.GOOGLEVIDEO.COM.", 6, 4), 2);
    assert!(state.match_domain("failed.googlevideo.com", &key).is_some());
}

#[test]
fn private_suffix_tenants_do_not_join_the_same_group() {
    let key = GroupKey {
        transport: 6,
        family: 4,
        shape: 1,
        ..GroupKey::default()
    };
    let mut state = DomainState::default();
    for name in ["a.github.io", "b.github.io", "c.github.io"] {
        state
            .learn(r2o_controller::catalog::DomainObservation {
                name: name.into(),
                plan_id: "plan-a".into(),
                key: key.clone(),
                evidence: 1,
                at: 100,
            })
            .unwrap();
    }
    assert!(state.match_domain("new.github.io", &key).is_none());
}

#[test]
fn capacity_reenable_reuses_the_room_opened_by_dropping_old_votes() {
    let key = GroupKey {
        transport: 6,
        family: 4,
        shape: 1,
        ..GroupKey::default()
    };
    let mut state = DomainState::default();
    for name in [
        "a.googlevideo.com",
        "b.googlevideo.com",
        "c.googlevideo.com",
    ] {
        state
            .learn(r2o_controller::catalog::DomainObservation {
                name: name.into(),
                plan_id: "plan-a".into(),
                key: key.clone(),
                evidence: 1,
                at: 50,
            })
            .unwrap();
    }
    for index in 0..253 {
        state
            .learn(r2o_controller::catalog::DomainObservation {
                name: format!("f{index}.other.example.com"),
                plan_id: "plan-q".into(),
                key: key.clone(),
                evidence: 4,
                at: 200,
            })
            .unwrap();
    }
    assert_eq!(state.observations.len(), 256);
    state.frozen = true;
    state.disabled = true;
    state.disabled_at = Some(100);

    assert!(
        state
            .learn(r2o_controller::catalog::DomainObservation {
                name: "clean.googlevideo.com".into(),
                plan_id: String::new(),
                key: key.clone(),
                evidence: 2,
                at: 200,
            })
            .unwrap()
    );
    assert!(!state.disabled);
    assert!(state.disabled_at.is_none());
    assert!(!state.frozen);
    assert_eq!(state.observations.len(), 254);
    assert!(
        state
            .observations
            .iter()
            .any(|observation| observation.name == "clean.googlevideo.com")
    );
}
