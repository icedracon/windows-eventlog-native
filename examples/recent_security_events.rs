//! Query recent Windows authentication and directory-service audit events.
//!
//! Usage:
//!   cargo run --example recent_security_events -- 30
//!
//! The optional argument is the lookback window in minutes. Reading the
//! Security channel requires Administrator or Event Log Readers membership.

use chrono::{Duration, Utc};
use windows_eventlog_native::security_audit_by_id;

const SECURITY_EVENT_IDS: &[u32] = &[4624, 4625, 4648, 4662, 4768, 4769, 4776];

fn main() -> windows_eventlog_native::Result<()> {
    let minutes = std::env::args()
        .nth(1)
        .map(|value| {
            value
                .parse::<i64>()
                .expect("lookback must be integer minutes")
        })
        .unwrap_or(30);
    let since = Utc::now() - Duration::minutes(minutes);
    let events = security_audit_by_id(SECURITY_EVENT_IDS, since)?;

    println!(
        "matching_events={} lookback_minutes={minutes}",
        events.len()
    );
    for event in events {
        let user = event
            .data
            .get("TargetUserName")
            .map(String::as_str)
            .unwrap_or("-");
        println!(
            "time={} id={} provider={} user={}",
            event.time_created, event.event_id, event.provider, user
        );
    }

    Ok(())
}
