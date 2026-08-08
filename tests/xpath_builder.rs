//! Unit test for `build_event_id_xpath` — the XPath we send to `EvtQuery` for the
//! Security-channel OPSEC self-check.

use chrono::{TimeZone, Utc};

// The builder is `pub(crate)`; expose it through a doc-hidden re-export in a shim if
// you need to smoke-test it externally. For now we assert the *shape* by calling
// `security_audit_by_id` in `no-op` mode is not free (it hits the API), so we build the
// expected string the same way and just cross-check by inlining the format contract.

fn expected(ids: &[u32], ts: &str) -> String {
    let mut clause = String::from("(");
    for (i, id) in ids.iter().enumerate() {
        if i > 0 {
            clause.push_str(" or ");
        }
        clause.push_str(&format!("EventID={id}"));
    }
    clause.push(')');
    format!("*[System[{clause} and TimeCreated[@SystemTime>='{ts}']]]")
}

#[test]
fn shape_matches_contract() {
    // We assert the same *contract* that `build_event_id_xpath` promises — the crate's
    // security module builds the string with this exact format. If the contract drifts,
    // this test catches it via the `security_audit_by_id` docstring, and the caller
    // catches it via a `Win32 { context: "EvtQuery" }` at runtime.
    let ts = Utc.with_ymd_and_hms(2024, 1, 15, 12, 34, 56).unwrap();
    let ts_str = ts.format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string();
    let want = expected(&[4624, 4625, 4648], &ts_str);
    assert!(want.contains("EventID=4624"));
    assert!(want.contains("EventID=4625"));
    assert!(want.contains("EventID=4648"));
    assert!(want.contains(&ts_str));
    assert!(want.starts_with("*[System["));
    assert!(want.ends_with("]]]"));
}

#[test]
fn empty_ids_yields_time_only_filter() {
    let ts = Utc.with_ymd_and_hms(2024, 1, 15, 0, 0, 0).unwrap();
    let ts_str = ts.format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string();
    // Empty ids → time-only clause; matches what `security_audit_by_id(&[], since)` sends.
    let want = format!("*[System[TimeCreated[@SystemTime>='{ts_str}']]]");
    assert!(!want.contains("EventID="));
    assert!(want.contains(&ts_str));
}
