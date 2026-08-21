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

use core::ffi::c_void;
use core::ptr;
use win32_min::eventlog::{
    EvtClose, EvtNext, EvtQuery, EvtQueryChannelPath, EvtQueryForwardDirection,
    EvtQueryReverseDirection, EvtQueryTolerateQueryErrors, EvtRender, EvtRenderEventXml,
    EVT_HANDLE, NULL_EVT_HANDLE,
};
use win32_min::foundation::{GetLastError, PCWSTR};

use crate::error::{Error, Result};
use crate::event::{parse_event_xml, Event};
use crate::query::QueryDirection;

fn to_wide(s: &str) -> Vec<u16> {
    OsStr::new(s)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect()
}

/// Small helper: build `Error::Win32` from the last thread-local Win32 error code.
fn last_win32(context: &'static str) -> Error {
    let code = unsafe { GetLastError() };
    Error::Win32 { code, context }
}

/// Owning iterator over a `EvtQuery` result set. Closes the underlying handle on drop.
pub struct WinEventIter {
    handle: EVT_HANDLE,
    channel: String,
    /// Small batch of event handles pulled per `EvtNext` call.
    batch: Vec<EVT_HANDLE>,
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
            QueryDirection::Forward => EvtQueryForwardDirection,
            QueryDirection::Reverse => EvtQueryReverseDirection,
        };
        // TolerateQueryErrors: some legacy provider manifests are broken; without this,
        // a single publisher glitch in the channel makes EvtQuery fail outright.
        let flags = EvtQueryChannelPath | dir_flag | EvtQueryTolerateQueryErrors;

        let handle = unsafe {
            EvtQuery(
                NULL_EVT_HANDLE,
                PCWSTR(path.as_ptr()),
                PCWSTR(query.as_ptr()),
                flags,
            )
        };
        if handle == NULL_EVT_HANDLE {
            let code = unsafe { GetLastError() };
            return Err(Error::ChannelAccess(
                channel.to_string(),
                format!("EvtQuery: Win32 error {code:#010x}"),
            ));
        }

        Ok(Self {
            handle,
            channel: channel.to_string(),
            batch: vec![NULL_EVT_HANDLE; BATCH],
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
        let ok = unsafe {
            EvtNext(
                self.handle,
                self.batch.len() as u32,
                self.batch.as_mut_ptr(),
                /* timeout ms */ 5_000,
                /* flags */ 0,
                &mut returned,
            )
        };
        if ok != 0 {
            self.filled = returned;
            if returned == 0 {
                self.exhausted = true;
            }
            Ok(())
        } else {
            // ERROR_NO_MORE_ITEMS = 259. Normal end-of-set — swallow, mark
            // exhausted, do not surface as an error.
            let code = unsafe { GetLastError() };
            if code == 259 {
                self.exhausted = true;
                Ok(())
            } else {
                Err(Error::Win32 {
                    code,
                    context: "EvtNext",
                })
            }
        }
    }

    fn render_and_close(&self, evt_handle: EVT_HANDLE) -> Result<Event> {
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
            if raw != NULL_EVT_HANDLE {
                unsafe {
                    let _ = EvtClose(raw);
                }
            }
        }
        if self.handle != NULL_EVT_HANDLE {
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
            NULL_EVT_HANDLE,
            event,
            EvtRenderEventXml,
            0,
            ptr::null_mut(),
            &mut used,
            &mut props,
        )
    };
    // Expected: ERROR_INSUFFICIENT_BUFFER (122) with `used` populated.
    if probe != 0 {
        // Zero-byte render — nothing to decode.
        return Ok(String::new());
    }
    let code = unsafe { GetLastError() };
    if code != 122 {
        return Err(Error::Win32 {
            code,
            context: "EvtRender(size probe)",
        });
    }

    // `used` is in bytes; the rendered payload is UTF-16 so allocate u16 slots.
    let u16_len = (used as usize).div_ceil(2);
    let mut buf: Vec<u16> = vec![0u16; u16_len];
    let cap_bytes = (buf.len() * 2) as u32;

    let ok = unsafe {
        EvtRender(
            NULL_EVT_HANDLE,
            event,
            EvtRenderEventXml,
            cap_bytes,
            buf.as_mut_ptr() as *mut c_void,
            &mut used,
            &mut props,
        )
    };
    if ok == 0 {
        return Err(last_win32("EvtRender"));
    }

    // Trim trailing NUL(s) that EvtRender includes in `used`.
    let used_u16 = (used as usize) / 2;
    let end = buf[..used_u16]
        .iter()
        .position(|&c| c == 0)
        .unwrap_or(used_u16);
    String::from_utf16(&buf[..end]).map_err(|_| Error::Utf16)
}
