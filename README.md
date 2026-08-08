# windows-eventlog-native

**STATUS: pre-alpha (0.1.0-dev)** — skeleton + partial implementation. Not published.

Native `EvtQuery` / `EvtNext` / `EvtRender` / `EvtSubscribe` wrapper for local Windows
Event Log channels (Security / System / Application). Produces a filterable stream of
parsed events with the `EventData` map already extracted into a `HashMap<String,String>`.

Powers OPSEC self-check flows: after running a scan, ask the log directly
"did I light up 4624 / 4625 / 4648 / 4662 / 4768 / 4769 / 4776?" without shelling out
to `wevtutil` or `Get-WinEvent`.

## Minimal usage

```rust
use windows_eventlog_native::{EventLog, QueryDirection};

let iter = EventLog::query(
    "Application",
    "*[System[TimeCreated[timediff(@SystemTime) <= 3600000]]]",
    QueryDirection::Forward,
)?;

for evt in iter {
    let evt = evt?;
    println!("{} {} {}", evt.time_created, evt.event_id, evt.provider);
    if let Some(user) = evt.data.get("TargetUserName") {
        println!("  user = {user}");
    }
}
```

Security-channel queries require membership in **Event Log Readers** or Administrators.
Application is always readable.

## Scope of 0.1.0-dev

Working: XML parse of RenderedXml, EventData extraction, filetime conversion, error taxonomy,
public API shape.

Partial: `EvtQuery` / `EvtNext` iterator wired to the Win32 API on `cfg(windows)`; render uses
`EvtRender` with `EvtRenderEventXml`.

Stubbed / TODO: `EvtSubscribe` push mode, bookmarks, remote sessions, message-string
resolution via `EvtFormatMessage`. See inline `// TODO(0.2):` markers.
