//! # windows-eventlog-native
//!
//! The 0.2 series implements native `EvtQuery` / `EvtNext` / `EvtRender`
//! iteration and structured XML parsing for local Windows Event Log channels.
//!
//! Powers OPSEC self-check: after running a scan, ask the log directly
//! "did I light up 4624/4625/4648/4662/4768/4769/4776?" without shelling out to
//! `wevtutil` or `Get-WinEvent`.
//!
//! ```no_run
//! use windows_eventlog_native::{EventLog, QueryDirection};
//!
//! # fn go() -> windows_eventlog_native::Result<()> {
//! let iter = EventLog::query(
//!     "Application",
//!     "*[System[TimeCreated[timediff(@SystemTime) <= 3600000]]]",
//!     QueryDirection::Forward,
//! )?;
//! for evt in iter.take(10) {
//!     let evt = evt?;
//!     println!("{} {} {}", evt.time_created, evt.event_id, evt.provider);
//! }
//! # Ok(()) }
//! ```

pub mod error;
pub mod event;
pub mod query;
pub mod security;

#[cfg(windows)]
pub(crate) mod platform;

pub use error::{Error, Result};
pub use event::{filetime_to_utc, parse_event_xml, rendered_xml, Event};
pub use query::{EventLog, QueryDirection};
pub use security::security_audit_by_id;
