use chrono::{DateTime, Utc};

use crate::error::Result;
use crate::event::Event;
use crate::query::{EventLog, QueryDirection};

/// Fetch every Security-channel event whose `EventID` is in `ids` and whose
/// `SystemTime` is >= `since`.
///
/// Builds an XPath structured query and returns matches in reverse chronological order
/// (newest first) — that's the shape callers doing an OPSEC self-check want:
/// "did my scan just now show up as 4624/4625/4662/4768/4769/4776?"
///
/// Security channel requires the caller to be in **Event Log Readers** or Administrators;
/// otherwise this returns `Error::ChannelAccess`.
pub fn security_audit_by_id(ids: &[u32], since: DateTime<Utc>) -> Result<Vec<Event>> {
    let xpath = build_event_id_xpath(ids, since);
    let iter = EventLog::query("Security", &xpath, QueryDirection::Reverse)?;

    let mut out = Vec::new();
    for evt in iter {
        out.push(evt?);
    }
    Ok(out)
}

/// XPath builder — pulled out so it's unit-testable without touching the wevtapi.
///
/// Result shape:
/// `*[System[(EventID=4624 or EventID=4625) and TimeCreated[@SystemTime>='2024-…Z']]]`
pub(crate) fn build_event_id_xpath(ids: &[u32], since: DateTime<Utc>) -> String {
    // ISO-8601 UTC with milliseconds and trailing Z, as Windows XPath expects.
    let ts = since.format("%Y-%m-%dT%H:%M:%S%.3fZ");

    if ids.is_empty() {
        return format!("*[System[TimeCreated[@SystemTime>='{ts}']]]");
    }

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
