//! Structural test: parse a canned Security 4624 RenderedXml payload and check that
//! the fields we care about round-trip through `parse_event_xml`.

use windows_eventlog_native::{parse_event_xml, rendered_xml};

const SEC_4624: &str = r#"<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'>
  <System>
    <Provider Name='Microsoft-Windows-Security-Auditing' Guid='{54849625-5478-4994-A5BA-3E3B0328C30D}'/>
    <EventID>4624</EventID>
    <Version>2</Version>
    <Level>0</Level>
    <Task>12544</Task>
    <Opcode>0</Opcode>
    <Keywords>0x8020000000000000</Keywords>
    <TimeCreated SystemTime='2024-01-15T12:34:56.789Z'/>
    <EventRecordID>987654321</EventRecordID>
    <Correlation/>
    <Execution ProcessID='888' ThreadID='4444'/>
    <Channel>Security</Channel>
    <Computer>PC-01.corp.local</Computer>
    <Security/>
  </System>
  <EventData>
    <Data Name='SubjectUserSid'>S-1-5-18</Data>
    <Data Name='SubjectUserName'>PC-01$</Data>
    <Data Name='SubjectDomainName'>CORP</Data>
    <Data Name='TargetUserName'>zevs</Data>
    <Data Name='LogonType'>3</Data>
    <Data Name='IpAddress'>10.10.10.5</Data>
    <Data Name='EmptyField'/>
  </EventData>
</Event>"#;

#[test]
fn parse_security_4624() {
    let e = parse_event_xml(SEC_4624, "Security").expect("parse");
    assert_eq!(e.event_id, 4624);
    assert_eq!(e.record_id, 987_654_321);
    assert_eq!(e.provider, "Microsoft-Windows-Security-Auditing");
    assert_eq!(e.channel, "Security");
    assert_eq!(
        e.data.get("TargetUserName").map(String::as_str),
        Some("zevs")
    );
    assert_eq!(e.data.get("LogonType").map(String::as_str), Some("3"));
    assert_eq!(
        e.data.get("IpAddress").map(String::as_str),
        Some("10.10.10.5")
    );
    // Self-closed <Data Name='EmptyField'/> must land as empty string, not missing.
    assert_eq!(e.data.get("EmptyField").map(String::as_str), Some(""));
}

#[test]
fn parse_time_created_iso() {
    let e = parse_event_xml(SEC_4624, "Security").expect("parse");
    assert_eq!(
        e.time_created.format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string(),
        "2024-01-15T12:34:56.789Z"
    );
}

#[test]
fn rendered_xml_round_trip() {
    let e = parse_event_xml(SEC_4624, "Security").expect("parse");
    // rendered_xml() must give back the exact source XML, byte-for-byte.
    assert_eq!(rendered_xml(&e), SEC_4624);
}
