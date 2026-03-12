use ids_common::types::{Alert, Severity};

/// Convert an IDS severity level to the corresponding CEF numeric severity.
///
/// | Severity | CEF |
/// |----------|-----|
/// | Low      |  3  |
/// | Medium   |  5  |
/// | High     |  8  |
/// | Critical | 10  |
pub fn severity_to_cef(s: &Severity) -> u8 {
    match s {
        Severity::Low => 3,
        Severity::Medium => 5,
        Severity::High => 8,
        Severity::Critical => 10,
    }
}

/// Format an [`Alert`] as a CEF (ArcSight Common Event Format) string.
///
/// ```text
/// CEF:0|CPS-IDS|IDS-IPS|1.0|{category}|{description}|{severity}|src=... dst=... spt=... dpt=... msg=...
/// ```
pub fn format_cef(alert: &Alert) -> String {
    let cef_severity = severity_to_cef(&alert.severity);
    let category = format!("{:?}", alert.category);

    let src = alert
        .source_ip
        .map(|ip| ip.to_string())
        .unwrap_or_default();
    let dst = alert
        .dest_ip
        .map(|ip| ip.to_string())
        .unwrap_or_default();
    let spt = alert
        .source_port
        .map(|p| p.to_string())
        .unwrap_or_default();
    let dpt = alert
        .dest_port
        .map(|p| p.to_string())
        .unwrap_or_default();

    // Escape pipe characters inside the description so the CEF header stays
    // well-formed (pipes delimit CEF fields).
    let description = alert.description.replace('|', "\\|");
    let msg = alert.description.replace('=', "\\=");

    format!(
        "CEF:0|CPS-IDS|IDS-IPS|1.0|{category}|{description}|{cef_severity}|\
         src={src} dst={dst} spt={spt} dpt={dpt} msg={msg}"
    )
}

/// Format an [`Alert`] as an RFC 5424 syslog message.
///
/// ```text
/// <priority>1 timestamp hostname CPS-IDS - - - message
/// ```
///
/// The PRI value is computed as `facility * 8 + severity` where we use
/// facility 4 (security/auth) and map IDS severities to syslog numeric
/// severities.
pub fn format_syslog(alert: &Alert) -> String {
    // Map IDS severity -> syslog severity (lower = more severe)
    let syslog_severity: u8 = match alert.severity {
        Severity::Critical => 2, // critical
        Severity::High => 3,     // error
        Severity::Medium => 4,   // warning
        Severity::Low => 6,      // informational
    };

    // Facility 4 = security/authorization messages
    let facility: u8 = 4;
    let priority = facility * 8 + syslog_severity;

    let hostname = alert
        .hostname
        .as_deref()
        .unwrap_or("cps-ids");

    let timestamp = alert.timestamp.format("%Y-%m-%dT%H:%M:%S%.3fZ");

    // Structured data: include alert id and confidence
    let structured_data = format!(
        "[alert@0 id=\"{}\" confidence=\"{:.4}\" category=\"{:?}\" source=\"{:?}\"]",
        alert.id, alert.confidence, alert.category, alert.source,
    );

    format!(
        "<{priority}>1 {timestamp} {hostname} CPS-IDS - - {structured_data} {description}",
        description = alert.description,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use ids_common::types::{AlertSource, AttackCategory};
    use std::net::{IpAddr, Ipv4Addr};
    use uuid::Uuid;

    fn sample_alert() -> Alert {
        Alert {
            id: Uuid::nil(),
            timestamp: Utc::now(),
            severity: Severity::High,
            category: AttackCategory::DoS,
            source: AlertSource::Network,
            description: "DoS attack detected".into(),
            confidence: 0.92,
            model_source: "ensemble".into(),
            source_ip: Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))),
            dest_ip: Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2))),
            source_port: Some(54321),
            dest_port: Some(502),
            hostname: None,
            pid: None,
            affected_path: None,
            username: None,
        }
    }

    #[test]
    fn cef_contains_required_fields() {
        let cef = format_cef(&sample_alert());
        assert!(cef.starts_with("CEF:0|CPS-IDS|IDS-IPS|1.0|"));
        assert!(cef.contains("src=10.0.0.1"));
        assert!(cef.contains("dst=10.0.0.2"));
        assert!(cef.contains("spt=54321"));
        assert!(cef.contains("dpt=502"));
        assert!(cef.contains("|8|")); // High = 8
    }

    #[test]
    fn syslog_has_priority_and_timestamp() {
        let syslog = format_syslog(&sample_alert());
        // facility=4, severity=3 (High->error) => priority = 4*8+3 = 35
        assert!(syslog.starts_with("<35>1 "));
        assert!(syslog.contains("CPS-IDS"));
    }

    #[test]
    fn severity_mapping() {
        assert_eq!(severity_to_cef(&Severity::Low), 3);
        assert_eq!(severity_to_cef(&Severity::Medium), 5);
        assert_eq!(severity_to_cef(&Severity::High), 8);
        assert_eq!(severity_to_cef(&Severity::Critical), 10);
    }
}
