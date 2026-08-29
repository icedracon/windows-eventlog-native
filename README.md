# windows-eventlog-native

[![Crates.io](https://img.shields.io/crates/v/windows-eventlog-native.svg)](https://crates.io/crates/windows-eventlog-native)
[![Docs.rs](https://docs.rs/windows-eventlog-native/badge.svg)](https://docs.rs/windows-eventlog-native)
[![CI](https://github.com/icedracon/windows-eventlog-native/actions/workflows/ci.yml/badge.svg)](https://github.com/icedracon/windows-eventlog-native/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

Native Windows Event Log client for Rust — `EvtQuery` / `EvtNext` / `EvtRender` /
(eventually) `EvtSubscribe`. Streams parsed `Event` records from local
Security / System / Application channels with the `EventData` map already
extracted into a `HashMap<String, String>`, no `wevtutil` or `Get-WinEvent`
shell-out required.

## Status

**`0.2` tested companion crate.** Local query, iteration, XML rendering, and
structured event parsing are implemented on top of `win32-min`; APIs may still
evolve before 1.0. See the central
[`win32-min` ecosystem map](https://github.com/icedracon/win32-min/blob/master/ECOSYSTEM.md)
for compatibility and maturity information.

## What it does

Thin, allocation-conscious wrapper around the modern Event Log API
(`wevtapi.dll` — `EvtQuery`, `EvtNext`, `EvtRender` with `EvtRenderEventXml`).
Renders each event to `RenderedXml`, parses `<System>` + `<EventData>` via
`quick-xml`, and hands back a strongly-typed [`Event`] with the FILETIME already
converted to `chrono::DateTime<Utc>` and the `<Data Name="...">` children folded
into a map.

The intended consumer is red-team / OPSEC self-check tooling: after running a
scan or logon, ask the log directly *"did I light up 4624 / 4625 / 4648 / 4662 /
4768 / 4769 / 4776?"* without spawning a PowerShell child process.

## Usage

```rust
use windows_eventlog_native::{EventLog, QueryDirection};

let iter = EventLog::query(
    "Application",
    "*[System[TimeCreated[timediff(@SystemTime) <= 3600000]]]",
    QueryDirection::Forward,
)?;

for evt in iter.take(10) {
    let evt = evt?;
    println!("{} id={} provider={}", evt.time_created, evt.event_id, evt.provider);
    if let Some(user) = evt.data.get("TargetUserName") {
        println!("  user = {user}");
    }
}
```

Security-channel queries require membership in **Event Log Readers** or
**Administrators**. Application is always readable.

## Research workflow

Query common authentication and directory-service audit IDs from the last 30
minutes without invoking PowerShell or `wevtutil`:

```powershell
cargo run --example recent_security_events -- 30
```

The query is local and read-only. Security-channel permissions still apply.
See the ecosystem's
[`RESEARCH-WORKFLOWS.md`](https://github.com/icedracon/win32-min/blob/master/RESEARCH-WORKFLOWS.md)
for the complete workflow set.

## What works / what does not (this version)

- Working: RenderedXml parsing, `EventData` extraction, FILETIME conversion,
  error taxonomy, public API shape, `EvtQuery` / `EvtNext` iterator on
  `cfg(windows)` via `EvtRender(EvtRenderEventXml)`.
- Stubbed / TODO: `EvtSubscribe` push mode, `EVT_HANDLE` bookmarks, remote
  session (`EvtOpenSession`), message-string resolution via `EvtFormatMessage`.
- Not yet: EventLog channel enumeration, publisher metadata cache, high-volume
  batching via `EvtNext` array-size tuning.

Unsupported capabilities are kept out of the public workflow rather than
silently presented as complete.

## Related icedracon crates

- [`win32-min`](https://github.com/icedracon/win32-min) — verified,
  dependency-free Win32 ABI foundation used by this crate.
- [`windows-wmi-com`](https://github.com/icedracon/windows-wmi-com) —
  in-process WMI via COM (~10x faster than DCOM-over-RPC for local queries).
- [`winrm-pentest`](https://github.com/icedracon/winrm-pentest) — async WinRM
  2.0 client (NTLM/Kerberos/CredSSP) for cross-platform remote PowerShell.

Cluster: Windows-native higher-level telemetry + admin surfaces. This crate
covers the live event pipeline; the other two cover CIM/WMI and remote WSMan.

## Dependencies

- `win32-min >= 0.1.2, < 0.2` with only `eventlog` enabled.
- `quick-xml`, `chrono`, and `thiserror`; no async runtime or generated Windows
  bindings.

## License

MIT (c) 2026 [zevs](https://github.com/icedracon)
