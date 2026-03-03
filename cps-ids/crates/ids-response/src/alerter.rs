use chrono::Utc;
use ids_common::types::{
    Alert, AttackCategory, DetectionMetadata, DetectionResult, Severity,
};
use uuid::Uuid;

/// Generates structured alerts from detection engine results.
pub struct Alerter;

impl Alerter {
    /// Map a [`DetectionResult`] into a fully populated [`Alert`].
    ///
    /// Severity is chosen based on the predicted attack category and then
    /// optionally downgraded when the model confidence is below 0.7.
    pub fn create_alert(result: &DetectionResult) -> Alert {
        // Base severity from attack category
        let mut severity = match result.predicted_category {
            AttackCategory::DoS | AttackCategory::U2R => Severity::Critical,
            AttackCategory::Probe => Severity::High,
            AttackCategory::R2L => Severity::Medium,
            AttackCategory::Unknown => Severity::High,
            AttackCategory::Normal => Severity::Low,
        };

        // Downgrade one level when confidence is low
        if result.confidence < 0.7 {
            severity = severity_downgrade(severity);
        }

        let description = format!(
            "{:?} attack detected by {} (confidence {:.2}%)",
            result.predicted_category,
            result.model_source,
            result.confidence * 100.0,
        );

        // Populate network / host fields from the detection metadata
        let (source_ip, dest_ip, source_port, dest_port, hostname, pid, affected_path, username) =
            match &result.metadata {
                DetectionMetadata::Network {
                    src_ip,
                    dst_ip,
                    src_port,
                    dst_port,
                    ..
                } => (
                    Some(*src_ip),
                    Some(*dst_ip),
                    Some(*src_port),
                    Some(*dst_port),
                    None,
                    None,
                    None,
                    None,
                ),
                DetectionMetadata::Host {
                    hostname,
                    pid,
                    affected_path,
                    username,
                } => (
                    None,
                    None,
                    None,
                    None,
                    Some(hostname.clone()),
                    *pid,
                    affected_path.clone(),
                    username.clone(),
                ),
            };

        Alert {
            id: Uuid::new_v4(),
            timestamp: Utc::now(),
            severity,
            category: result.predicted_category,
            source: result.event_source,
            description,
            confidence: result.confidence,
            model_source: result.model_source.clone(),
            source_ip,
            dest_ip,
            source_port,
            dest_port,
            hostname,
            pid,
            affected_path,
            username,
        }
    }
}

/// Lower a severity by one level. [`Severity::Low`] cannot go any lower.
pub fn severity_downgrade(s: Severity) -> Severity {
    match s {
        Severity::Critical => Severity::High,
        Severity::High => Severity::Medium,
        Severity::Medium => Severity::Low,
        Severity::Low => Severity::Low,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ids_common::types::AlertSource;
    use std::net::{IpAddr, Ipv4Addr};

    fn make_network_result(cat: AttackCategory, confidence: f64) -> DetectionResult {
        DetectionResult {
            event_source: AlertSource::Network,
            predicted_category: cat,
            confidence,
            model_source: "test-model".into(),
            feature_vector: vec![],
            metadata: DetectionMetadata::Network {
                src_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
                dst_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
                src_port: 12345,
                dst_port: 502,
                protocol: ids_common::types::Protocol::Tcp,
            },
        }
    }

    #[test]
    fn dos_high_confidence_is_critical() {
        let result = make_network_result(AttackCategory::DoS, 0.95);
        let alert = Alerter::create_alert(&result);
        assert_eq!(alert.severity, Severity::Critical);
    }

    #[test]
    fn dos_low_confidence_is_downgraded() {
        let result = make_network_result(AttackCategory::DoS, 0.5);
        let alert = Alerter::create_alert(&result);
        assert_eq!(alert.severity, Severity::High);
    }

    #[test]
    fn normal_stays_low_even_when_downgraded() {
        let result = make_network_result(AttackCategory::Normal, 0.3);
        let alert = Alerter::create_alert(&result);
        assert_eq!(alert.severity, Severity::Low);
    }

    #[test]
    fn network_fields_populated() {
        let result = make_network_result(AttackCategory::Probe, 0.9);
        let alert = Alerter::create_alert(&result);
        assert!(alert.source_ip.is_some());
        assert!(alert.dest_ip.is_some());
        assert_eq!(alert.source_port, Some(12345));
        assert_eq!(alert.dest_port, Some(502));
        assert!(alert.hostname.is_none());
    }

    #[test]
    fn host_fields_populated() {
        let result = DetectionResult {
            event_source: AlertSource::Host,
            predicted_category: AttackCategory::U2R,
            confidence: 0.85,
            model_source: "host-model".into(),
            feature_vector: vec![],
            metadata: DetectionMetadata::Host {
                hostname: "plc-01".into(),
                pid: Some(1234),
                affected_path: Some("/etc/shadow".into()),
                username: Some("root".into()),
            },
        };
        let alert = Alerter::create_alert(&result);
        assert_eq!(alert.hostname.as_deref(), Some("plc-01"));
        assert_eq!(alert.pid, Some(1234));
        assert!(alert.source_ip.is_none());
    }
}
