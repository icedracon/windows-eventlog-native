//! Windows-only Win32 wrapper around `EvtQuery` / `EvtNext` / `EvtRender`.
//!
//! Structured for the two things a caller actually wants:
//!   * an `Iterator<Item = Result<Event>>` that owns the `EVT_HANDLE` query result set
//!     and closes it on drop, and
//!   * a small `render_xml` primitive that produces the RenderedXml payload each event
//!     is parsed from.

#![cfg(windows)]

use std::ffi::OsStr;
use std::os::windows::ffi::OsStrExt;

use windows::core::PCWSTR;
use windows::Win32::System::EventLog::{
    EvtClose, EvtNext, EvtQuery, EvtQueryChannelPath, EvtQueryForwardDirection,
    EvtQueryReverseDirection, EvtQueryTolerateQueryErrors, EvtRender, EvtRenderEventXml,
    EVT_HANDLE,
};

use crate::error::{Error, Result};
use crate::event::{parse_event_xml, Event};
use crate::query::QueryDirection;

fn to_wide(s: &str) -> Vec<u16> {
    OsStr::new(s)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect()
}

/// Owning iterator over a `EvtQuery` result set. Closes the underlying handle on drop.
pub struct WinEventIter {
    handle: EVT_HANDLE,
    channel: String,
    /// Small batch of event handles pulled per `EvtNext` call.
    batch: Vec<isize>,
    /// Position within `batch` of the next handle to render.
    cursor: usize,
    /// Number of valid entries in `batch`.
    filled: u32,
    /// Sticky end-of-stream flag so we don't call `EvtNext` again after ERROR_NO_MORE_ITEMS.
    exhausted: bool,
}

const BATCH: usize = 16;

impl WinEventIter {
    pub fn open(channel: &str, xpath: &str, direction: QueryDirection) -> Result<Self> {
        let path = to_wide(channel);
        let query = to_wide(xpath);

        let dir_flag = match direction {
            QueryDirection::Forward => EvtQueryForwardDirection.0,
            QueryDirection::Reverse => EvtQueryReverseDirection.0,
        };
        // TolerateQueryErrors: some legacy provider manifests are broken; without this,
        // a single publisher glitch in the channel makes EvtQuery fail outright.
        let flags = EvtQueryChannelPath.0 | dir_flag | EvtQueryTolerateQueryErrors.0;

        let handle = unsafe {
            EvtQuery(None, PCWSTR(path.as_ptr()), PCWSTR(query.as_ptr()), flags)
                .map_err(|e| Error::ChannelAccess(channel.to_string(), format!("EvtQuery: {e}")))?
        };

        Ok(Self {
            handle,
            channel: channel.to_string(),
            batch: vec![0isize; BATCH],
            cursor: 0,
            filled: 0,
            exhausted: false,
        })
    }

    /// Pull the next batch of raw event handles into `self.batch`.
    fn refill(&mut self) -> Result<()> {
        if self.exhausted {
            return Ok(());
        }
        self.cursor = 0;
        self.filled = 0;
        let mut returned: u32 = 0;
        let rc = unsafe {
            EvtNext(
                self.handle,
                &mut self.batch[..],
                /* timeout ms */ 5_000,
                /* flags */ 0,
                &mut returned as *mut u32,
            )
        };
        match rc {
            Ok(()) => {
                self.filled = returned;
                if returned == 0 {
                    self.exhausted = true;
                }
                Ok(())
            }
            Err(e) => {
                // ERROR_NO_MORE_ITEMS = 0x103 = 259. Normal end-of-set — swallow, mark
                // exhausted, do not surface as an error.
                let code = e.code().0 as u32 & 0xFFFF;
                if code == 259 {
                    self.exhausted = true;
                    Ok(())
                } else {
                    Err(Error::Win32 {
                        code: e.code().0 as u32,
                        context: "EvtNext",
                    })
                }
            }
        }
    }

    fn render_and_close(&self, raw: isize) -> Result<Event> {
        let evt_handle = EVT_HANDLE(raw);
        let xml = render_xml(evt_handle)?;
        // Close the per-event handle either way.
        unsafe {
            let _ = EvtClose(evt_handle);
        }
        parse_event_xml(&xml, &self.channel)
    }
}

impl Drop for WinEventIter {
    fn drop(&mut self) {
        // Close any still-buffered event handles first.
        for &raw in &self.batch[self.cursor..self.filled as usize] {
            if raw != 0 {
                unsafe {
                    let _ = EvtClose(EVT_HANDLE(raw));
                }
            }
        }
        if !self.handle.is_invalid() {
            unsafe {
                let _ = EvtClose(self.handle);
            }
        }
    }
}

impl Iterator for WinEventIter {
    type Item = Result<Event>;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            if (self.cursor as u32) < self.filled {
                let raw = self.batch[self.cursor];
                self.cursor += 1;
                return Some(self.render_and_close(raw));
            }
            if self.exhausted {
                return None;
            }
            if let Err(e) = self.refill() {
                return Some(Err(e));
            }
            if self.filled == 0 {
                return None;
            }
        }
    }
}

/// Render an event handle as `RenderedXml` (UTF-16 → UTF-8).
pub fn render_xml(event: EVT_HANDLE) -> Result<String> {
    let mut used: u32 = 0;
    let mut props: u32 = 0;

    // Size query: pass a NULL buffer to learn the required size.
    let probe = unsafe {
        EvtRender(
            None,
            event,
            EvtRenderEventXml.0,
            0,
            None,
            &mut used as *mut u32,
            &mut props as *mut u32,
        )
    };
    // Expected: ERROR_INSUFFICIENT_BUFFER (122) with `used` populated.
    match probe {
        Ok(()) => {
            // Zero-byte render — nothing to decode.
            return Ok(String::new());
        }
        Err(e) => {
            let code = e.code().0 as u32 & 0xFFFF;
            if code != 122 {
                return Err(Error::Win32 {
                    code: e.code().0 as u32,
                    context: "EvtRender(size probe)",
                });
            }
        }
    }

    // `used` is in bytes; the rendered payload is UTF-16 so allocate u16 slots.
    let u16_len = (used as usize + 1) / 2;
    let mut buf: Vec<u16> = vec![0u16; u16_len];
    let cap_bytes = (buf.len() * 2) as u32;

    unsafe {
        EvtRender(
            None,
            event,
            EvtRenderEventXml.0,
            cap_bytes,
            Some(buf.as_mut_ptr() as *mut _),
            &mut used as *mut u32,
            &mut props as *mut u32,
        )
        .map_err(|e| Error::Win32 {
            code: e.code().0 as u32,
            context: "EvtRender",
        })?;
    }

    // Trim trailing NUL(s) that EvtRender includes in `used`.
    let used_u16 = (used as usize) / 2;
    let end = buf[..used_u16]
        .iter()
        .position(|&c| c == 0)
        .unwrap_or(used_u16);
    String::from_utf16(&buf[..end]).map_err(|_| Error::Utf16)
}
