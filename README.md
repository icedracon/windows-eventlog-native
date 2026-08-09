# windows-eventlog-native

[![Crates.io](https://img.shields.io/crates/v/windows-eventlog-native.svg)](https://crates.io/crates/windows-eventlog-native)
[![Docs.rs](https://docs.rs/windows-eventlog-native/badge.svg)](https://docs.rs/windows-eventlog-native)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

Native Windows Event Log client for Rust — `EvtQuery` / `EvtNext` / `EvtRender` /
(eventually) `EvtSubscribe`. Streams parsed `Event` records from local
Security / System / Application channels with the `EventData` map already
extracted into a `HashMap<String, String>`, no `wevtutil` or `Get-WinEvent`
shell-out required.

## Status

**`0.1.0-dev`** — pre-alpha, expect breaking changes before `0.1.0`. Part of the
[icedracon Rust offensive AD ecosystem](https://github.com/icedracon).

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

## What works / what does not (this version)

- Working: RenderedXml parsing, `EventData` extraction, FILETIME conversion,
  error taxonomy, public API shape, `EvtQuery` / `EvtNext` iterator on
  `cfg(windows)` via `EvtRender(EvtRenderEventXml)`.
- Stubbed / TODO: `EvtSubscribe` push mode, `EVT_HANDLE` bookmarks, remote
  session (`EvtOpenSession`), message-string resolution via `EvtFormatMessage`.
  See inline `// TODO(0.2):` markers.
- Not yet: EventLog channel enumeration, publisher metadata cache, high-volume
  batching via `EvtNext` array-size tuning.

Everything above the "working" line is fair game to fail on non-toy queries.

## Related icedracon crates

- [`windows-wmi-com`](https://github.com/icedracon/windows-wmi-com) —
  in-process WMI via COM (~10x faster than DCOM-over-RPC for local queries).
- [`winrm-pentest`](https://github.com/icedracon/winrm-pentest) — async WinRM
  2.0 client (NTLM/Kerberos/CredSSP) for cross-platform remote PowerShell.

Cluster: Windows-native higher-level telemetry + admin surfaces. This crate
covers the live event pipeline; the other two cover CIM/WMI and remote WSMan.

## License

MIT (c) 2026 [zevs](https://github.com/icedracon)
