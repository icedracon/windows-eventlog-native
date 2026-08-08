use std::collections::HashMap;

use chrono::{DateTime, TimeZone, Utc};
use quick_xml::events::Event as XmlEvent;
use quick_xml::Reader;

use crate::error::{Error, Result};

/// A parsed Windows event.
///
/// `xml` is the raw RenderedXml payload from `EvtRender`; every other field is derived
/// from it. Keep `xml` around when the caller wants to inspect UserData / raw payload
/// fields we did not lift into `data`.
#[derive(Debug, Clone)]
pub struct Event {
    pub record_id: u64,
    pub event_id: u32,
    pub time_created: DateTime<Utc>,
    pub provider: String,
    pub channel: String,
    pub xml: String,
    /// Flattened `<EventData><Data Name="…">value</Data></EventData>` map.
    /// Nameless `<Data>` elements land under keys `Data_0`, `Data_1`, ….
    pub data: HashMap<String, String>,
}

/// Return the rendered XML for the event (same as `evt.xml`, provided per spec).
pub fn rendered_xml(e: &Event) -> String {
    e.xml.clone()
}

/// Parse a RenderedXml Event blob into an `Event`.
///
/// This is a hand-rolled quick-xml pass instead of pulling in `serde-xml-rs` — the XML
/// shape is stable and small (`<Event><System>…</System><EventData>…</EventData></Event>`).
pub fn parse_event_xml(xml: &str, default_channel: &str) -> Result<Event> {
    let mut reader = Reader::from_str(xml);
    reader.config_mut().trim_text(true);

    let mut record_id: u64 = 0;
    let mut event_id: u32 = 0;
    let mut time_created: Option<DateTime<Utc>> = None;
    let mut provider = String::new();
    let mut channel = String::from(default_channel);
    let mut data: HashMap<String, String> = HashMap::new();

    // State machine: which <Data Name="…"> are we currently inside, and are we inside
    // <EventData>? We also need to swallow the text nodes of <System>/<EventID>, etc.
    enum State {
        Idle,
        InSystemElement(&'static str), // event_id | record_id | channel_text
        InEventData,
        InDataNamed(String),
        InDataAnon(usize),
    }
    let mut state = State::Idle;
    let mut anon_counter = 0usize;
    let mut in_event_data = false;

    let mut buf = Vec::new();
    loop {
        match reader.read_event_into(&mut buf) {
            Ok(XmlEvent::Start(e)) => {
                let name = e.name();
                let local = std::str::from_utf8(name.as_ref()).unwrap_or("");
                match local {
                    "EventData" => {
                        in_event_data = true;
                        state = State::InEventData;
                    }
                    "Data" if in_event_data => {
                        let mut named: Option<String> = None;
                        for attr in e.attributes().flatten() {
                            if attr.key.as_ref() == b"Name" {
                                if let Ok(v) = attr.unescape_value() {
                                    named = Some(v.into_owned());
                                }
                            }
                        }
                        state = match named {
                            Some(n) => State::InDataNamed(n),
                            None => {
                                let idx = anon_counter;
                                anon_counter += 1;
                                State::InDataAnon(idx)
                            }
                        };
                    }
                    "Provider" => {
                        for attr in e.attributes().flatten() {
                            if attr.key.as_ref() == b"Name" {
                                if let Ok(v) = attr.unescape_value() {
                                    provider = v.into_owned();
                                }
                            }
                        }
                    }
                    "EventID" => state = State::InSystemElement("event_id"),
                    "EventRecordID" => state = State::InSystemElement("record_id"),
                    "Channel" => state = State::InSystemElement("channel"),
                    "TimeCreated" => {
                        for attr in e.attributes().flatten() {
                            if attr.key.as_ref() == b"SystemTime" {
                                if let Ok(v) = attr.unescape_value() {
                                    // Format: 2024-01-15T12:34:56.7891234Z
                                    if let Ok(t) = DateTime::parse_from_rfc3339(&v) {
                                        time_created = Some(t.with_timezone(&Utc));
                                    } else if let Ok(t) = chrono::NaiveDateTime::parse_from_str(
                                        v.trim_end_matches('Z'),
                                        "%Y-%m-%dT%H:%M:%S%.f",
                                    ) {
                                        time_created = Some(Utc.from_utc_datetime(&t));
                                    }
                                }
                            }
                        }
                    }
                    _ => {}
                }
            }
            Ok(XmlEvent::Empty(e)) => {
                // Self-closed <Data Name="X"/> is legal and means empty string.
                let name = e.name();
                let local = std::str::from_utf8(name.as_ref()).unwrap_or("");
                if local == "Data" && in_event_data {
                    let mut named: Option<String> = None;
                    for attr in e.attributes().flatten() {
                        if attr.key.as_ref() == b"Name" {
                            if let Ok(v) = attr.unescape_value() {
                                named = Some(v.into_owned());
                            }
                        }
                    }
                    match named {
                        Some(n) => {
                            data.insert(n, String::new());
                        }
                        None => {
                            data.insert(format!("Data_{}", anon_counter), String::new());
                            anon_counter += 1;
                        }
                    }
                } else if local == "TimeCreated" {
                    for attr in e.attributes().flatten() {
                        if attr.key.as_ref() == b"SystemTime" {
                            if let Ok(v) = attr.unescape_value() {
                                if let Ok(t) = DateTime::parse_from_rfc3339(&v) {
                                    time_created = Some(t.with_timezone(&Utc));
                                }
                            }
                        }
                    }
                } else if local == "Provider" {
                    for attr in e.attributes().flatten() {
                        if attr.key.as_ref() == b"Name" {
                            if let Ok(v) = attr.unescape_value() {
                                provider = v.into_owned();
                            }
                        }
                    }
                }
            }
            Ok(XmlEvent::Text(t)) => {
                let txt = t.unescape().map(|c| c.into_owned()).unwrap_or_default();
                match &state {
                    State::InSystemElement("event_id") => {
                        event_id = txt.trim().parse().unwrap_or(0);
                    }
                    State::InSystemElement("record_id") => {
                        record_id = txt.trim().parse().unwrap_or(0);
                    }
                    State::InSystemElement("channel") => {
                        channel = txt.trim().to_string();
                    }
                    State::InDataNamed(name) => {
                        data.entry(name.clone())
                            .and_modify(|s| s.push_str(&txt))
                            .or_insert_with(|| txt.clone());
                    }
                    State::InDataAnon(idx) => {
                        let key = format!("Data_{}", idx);
                        data.entry(key)
                            .and_modify(|s| s.push_str(&txt))
                            .or_insert_with(|| txt.clone());
                    }
                    _ => {}
                }
            }
            Ok(XmlEvent::End(e)) => {
                let name = e.name();
                let local = std::str::from_utf8(name.as_ref()).unwrap_or("");
                if local == "EventData" {
                    in_event_data = false;
                    state = State::Idle;
                } else if matches!(local, "EventID" | "EventRecordID" | "Channel" | "Data") {
                    state = if in_event_data {
                        State::InEventData
                    } else {
                        State::Idle
                    };
                }
            }
            Ok(XmlEvent::Eof) => break,
            Err(e) => return Err(Error::Xml(e.to_string())),
            _ => {}
        }
        buf.clear();
    }

    Ok(Event {
        record_id,
        event_id,
        time_created: time_created.unwrap_or_else(Utc::now),
        provider,
        channel,
        xml: xml.to_string(),
        data,
    })
}

/// Convert a Win32 `FILETIME` (100ns intervals since 1601-01-01 UTC) to `DateTime<Utc>`.
///
/// Kept public for callers that already hold a FILETIME from `EvtRender` with the
/// `EvtRenderEventValues` context (a future path — for XML rendering we use the
/// `TimeCreated/@SystemTime` string instead).
pub fn filetime_to_utc(ft: u64) -> Result<DateTime<Utc>> {
    // 11_644_473_600 = seconds between 1601-01-01 and 1970-01-01.
    const SEC_1601_TO_1970: i64 = 11_644_473_600;
    let ticks = ft as i128;
    let secs = (ticks / 10_000_000) as i64 - SEC_1601_TO_1970;
    let nsecs = ((ticks % 10_000_000) * 100) as u32;
    Utc.timestamp_opt(secs, nsecs)
        .single()
        .ok_or(Error::BadFileTime(ft))
}
