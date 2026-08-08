//! Smoke test: hit the real wevtapi on Windows, walk a few Application events.
//!
//! This must not fail on a stock box even with no recent events (empty iterator is
//! a valid outcome). It also can't rely on Security-channel access — CI/dev boxes
//! aren't guaranteed to run as admin.

#[cfg(windows)]
#[test]
fn application_channel_smoke() {
    use windows_eventlog_native::{EventLog, QueryDirection};

    // Widest possible XPath: everything currently in Application. We just want to prove
    // the Win32 round-trip works end-to-end (EvtQuery → EvtNext → EvtRender → parse).
    let iter = EventLog::query("Application", "*", QueryDirection::Reverse)
        .expect("EvtQuery on Application must succeed on any Windows box");

    let mut seen = 0usize;
    for evt in iter.take(3) {
        match evt {
            Ok(e) => {
                // Bare-minimum invariants the parser must satisfy on real payloads.
                assert!(!e.provider.is_empty(), "provider must be non-empty");
                assert!(!e.xml.is_empty(), "rendered xml must be non-empty");
                assert!(
                    e.event_id > 0 || e.record_id > 0,
                    "either event_id or record_id must be populated"
                );
                seen += 1;
            }
            Err(e) => panic!("iterator yielded error: {e}"),
        }
    }
    // If the Application log is genuinely empty on this box we still pass — the point
    // is that the FFI call chain did not blow up.
    eprintln!("application_channel_smoke: rendered {seen} event(s)");
}

#[cfg(not(windows))]
#[test]
fn non_windows_reports_unsupported() {
    use windows_eventlog_native::{EventLog, QueryDirection};
    let err = EventLog::query("Application", "*", QueryDirection::Forward).unwrap_err();
    let msg = format!("{err}");
    assert!(msg.contains("unsupported"), "got: {msg}");
}
