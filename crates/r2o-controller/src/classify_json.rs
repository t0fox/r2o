use crate::classify::ClassifyResult;
use crate::classify::TriState;

fn insert_tri_state(
    props: &mut serde_json::Map<String, serde_json::Value>,
    key: &str,
    state: TriState,
) {
    let value = match state {
        TriState::Unset => return,
        TriState::False => false,
        TriState::True => true,
    };
    props.insert(key.into(), serde_json::json!(value));
}

/// D2O's JSON report shape for fields represented by the Rust classifier.
pub fn result_json_value(result: &ClassifyResult, trigger_len: usize) -> serde_json::Value {
    let mut props = serde_json::Map::new();
    insert_tri_state(&mut props, "reassembles", result.props.reassembles);
    insert_tri_state(&mut props, "parses_l7", result.props.parses_l7);
    insert_tri_state(
        &mut props,
        "validates_checksum",
        result.props.validates_checksum,
    );
    insert_tri_state(
        &mut props,
        "tolerates_reorder",
        result.props.tolerates_reorder,
    );
    insert_tri_state(
        &mut props,
        "tolerates_left_overlap",
        result.props.tolerates_left_overlap,
    );
    insert_tri_state(
        &mut props,
        "counts_duplicates",
        result.props.counts_duplicates,
    );
    insert_tri_state(&mut props, "inspects_syn", result.props.inspects_syn);
    if result.props.hop_ttl.is_some_and(|ttl| ttl > 0) {
        props.insert("hop_ttl".into(), serde_json::json!(result.props.hop_ttl));
    }
    let trace = result
        .trace
        .iter()
        .map(|observation| {
            let mut entry = serde_json::Map::new();
            entry.insert("probe".into(), serde_json::json!(&observation.probe));
            if !observation.cuts.is_empty() {
                entry.insert("cuts".into(), serde_json::json!(&observation.cuts));
            }
            if !observation.delay.is_zero() {
                entry.insert(
                    "delay_ms".into(),
                    serde_json::json!(observation.delay.as_millis()),
                );
            }
            entry.insert("pass".into(), serde_json::json!(observation.pass));
            entry.insert("fail".into(), serde_json::json!(observation.fail));
            if let Some(error) = &observation.error {
                if !error.is_empty() {
                    entry.insert("err".into(), serde_json::json!(error));
                }
            }
            serde_json::Value::Object(entry)
        })
        .collect::<Vec<_>>();
    let mut value = serde_json::json!({
        "target": &result.target,
        "verdict": result.verdict.as_str(),
        "reason": &result.reason,
        "repeats": result.repeats,
        "probes": result.probes,
        "duration": format!("{}ms", result.duration.as_millis()),
        "trigger_len": trigger_len,
        "props": serde_json::Value::Object(props),
        "composed": result.composed,
        "raw_usable": result.raw_usable,
        "trace": trace,
    });
    if result.boundary.is_some_and(|boundary| boundary > 0) {
        value["boundary"] = serde_json::json!(result.boundary);
    }
    if result.split_pos.is_some_and(|split_pos| split_pos > 0) {
        value["split_pos"] = serde_json::json!(result.split_pos);
    }
    if let Some(reassembles) = result.reassembles {
        value["reassembles"] = serde_json::json!(reassembles);
    }
    if let Some(strategy) = result
        .strategy
        .as_deref()
        .filter(|strategy| !strategy.is_empty())
    {
        value["strategy"] = serde_json::json!(strategy);
    }
    if let Some(path) = result.path.as_deref().filter(|path| !path.is_empty()) {
        value["path"] = serde_json::json!(path);
    }
    if let Some(response) = &result.response {
        let verdict = match response.verdict {
            crate::response::ResponseVerdict::NotApplicable => "not_applicable",
            crate::response::ResponseVerdict::Clear => "clear",
            crate::response::ResponseVerdict::Blocked => "blocked",
            crate::response::ResponseVerdict::Flaky => "flaky",
        };
        value["response"] = serde_json::json!({
            "verdict": verdict,
            "reason": &response.reason,
            "target": response.target,
            "control": response.control,
        });
    }
    value
}
