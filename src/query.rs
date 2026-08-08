#[cfg(not(windows))]
use crate::error::Error;
use crate::error::Result;
use crate::event::Event;

/// Direction to walk the query result set.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QueryDirection {
    /// Oldest → newest (`EvtQueryForwardDirection`).
    Forward,
    /// Newest → oldest (`EvtQueryReverseDirection`).
    Reverse,
}

/// Public entry point.
///
/// `EventLog` is a zero-sized handle namespace; every method opens its own `EVT_HANDLE`
/// and returns an iterator that owns and closes it on drop.
pub struct EventLog;

impl EventLog {
    /// Open a channel with an XPath filter and stream matching events.
    ///
    /// `channel` is the log name (e.g. `"Application"`, `"Security"`, `"System"`).
    /// `xpath` is a structured-query fragment or `"*"` for everything.
    ///
    /// Security channel access requires membership in **Event Log Readers** or
    /// Administrators.
    pub fn query(
        channel: &str,
        xpath: &str,
        direction: QueryDirection,
    ) -> Result<Box<dyn Iterator<Item = Result<Event>>>> {
        #[cfg(windows)]
        {
            let iter = crate::platform::WinEventIter::open(channel, xpath, direction)?;
            Ok(Box::new(iter))
        }
        #[cfg(not(windows))]
        {
            let _ = (channel, xpath, direction);
            Err(Error::UnsupportedPlatform)
        }
    }
}
