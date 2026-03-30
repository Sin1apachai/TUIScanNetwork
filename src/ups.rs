use std::collections::HashMap;
use std::time::{Duration, Instant};
use snmp2::{SyncSession, Oid, Value};
use anyhow::Result;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UpsVendor {
    APC,
    CyberPower,
    Eaton,
    Delta,
    Liebert,
    TrippLite,
    Socomec,
    RFC1628Standard,
    Unknown,
}

impl std::fmt::Display for UpsVendor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}

pub struct UpsDevice {
    pub vendor: UpsVendor,
    pub model: String,
    pub _firmware: String,
}

pub struct OidSnapshot {
    pub _timestamp: Instant,
    pub data: HashMap<String, String>, // OID -> Value
}

pub struct DiffResult {
    pub oid: String,
    pub old_value: String,
    pub new_value: String,
    pub change_type: String,
}

pub trait Uprober {
    fn identify_change(&self, oid: &str, old: &str, new: &str) -> Option<String>;
}

pub struct DefaultUprober;

impl Uprober for DefaultUprober {
    fn identify_change(&self, _oid: &str, old: &str, new: &str) -> Option<String> {
        if old == new {
            return None;
        }

        let old_val = old.parse::<i64>().ok();
        let new_val = new.parse::<i64>().ok();

        match (old_val, new_val) {
            (Some(v1), Some(v2)) => {
                // Heuristic: Battery Level (0-100, decreasing)
                if v1 > v2 && v1 <= 100 && v2 >= 0 {
                    return Some("Potential Battery Decrease".to_string());
                }
                
                // Heuristic: Voltage Drop (220/110 -> 0)
                if v1 > 50 && v2 == 0 {
                    return Some("Potential Voltage Drop (Power Failure)".to_string());
                }

                // Heuristic: Status Change
                if v1 != v2 {
                    return Some(format!("Status/Value Changed: {} -> {}", v1, v2));
                }
            }
            _ => {
                // String or other type change
                if old != new {
                    return Some("String/Status Change".to_string());
                }
            }
        }

        None
    }
}

/// Identifies if a target is a UPS and returns its metadata
pub async fn identify_ups(agent_addr: &str, community: &str) -> Result<Option<UpsDevice>> {
    let addr = agent_addr.to_string();
    let community = community.to_owned();

    tokio::task::spawn_blocking(move || {
        let timeout = Duration::from_secs(2);
        let mut session = SyncSession::new_v2c(&addr, community.as_bytes(), Some(timeout), 0)?;

        // OIDs to probe
        let sys_object_id = Oid::from(&[1, 3, 6, 1, 2, 1, 1, 2, 0]).unwrap();
        let sys_descr = Oid::from(&[1, 3, 6, 1, 2, 1, 1, 1, 0]).unwrap();
        let standard_ups = Oid::from(&[1, 3, 6, 1, 2, 1, 33, 1, 1, 1, 0]).into_iter().next(); // Generic UPS handle

        let mut vendor = UpsVendor::Unknown;
        let mut model = "Unknown Model".to_string();
        let firmware = "N/A".to_string();

        // 1. Check sysObjectID for Enterprise Prefix
        if let Ok(resp) = session.get(&sys_object_id) {
            if let Some(vb) = resp.varbinds.into_iter().next() {
                if let Value::ObjectIdentifier(oid) = vb.1 {
                    let oid_str = oid.to_string();
                    vendor = if oid_str.contains(".1.3.6.1.4.1.318") { UpsVendor::APC }
                        else if oid_str.contains(".1.3.6.1.4.1.3808") { UpsVendor::CyberPower }
                        else if oid_str.contains(".1.3.6.1.4.1.534") { UpsVendor::Eaton }
                        else if oid_str.contains(".1.3.6.1.4.1.2254") { UpsVendor::Delta }
                        else if oid_str.contains(".1.3.6.1.4.1.476") { UpsVendor::Liebert }
                        else if oid_str.contains(".1.3.6.1.4.1.850") { UpsVendor::TrippLite }
                        else if oid_str.contains(".1.3.6.1.4.1.455") { UpsVendor::Socomec }
                        else if oid_str.contains(".1.3.6.1.2.1.33") { UpsVendor::RFC1628Standard }
                        else { UpsVendor::Unknown };
                }
            }
        }

        // 2. Check sysDescr for keywords if vendor is still unknown
        if vendor == UpsVendor::Unknown {
            if let Ok(resp) = session.get(&sys_descr) {
                if let Some(vb) = resp.varbinds.into_iter().next() {
                    let desc = format!("{:?}", vb.1).to_lowercase();
                    if desc.contains("ups") || desc.contains("battery") || desc.contains("power management") {
                        vendor = UpsVendor::RFC1628Standard; // Assume standard if keywords match but OID didn't
                    }
                    model = if desc.len() > 30 { desc[..30].to_string() } else { desc };
                }
            }
        }

        // 3. Fallback: Probing standard UPS-MIB OID directly
        if vendor == UpsVendor::Unknown {
            if let Some(oid) = standard_ups {
                if session.get(&oid).is_ok() {
                    vendor = UpsVendor::RFC1628Standard;
                }
            }
        }

        if vendor != UpsVendor::Unknown {
            Ok(Some(UpsDevice { vendor, model, _firmware: firmware }))
        } else {
            Ok(None)
        }
    }).await?
}

/// Performs a full walk on a given root OID
pub async fn snmp_walk(agent_addr: &str, community: &str, root_oid_parts: &[u64]) -> Result<HashMap<String, String>> {
    let agent_addr = agent_addr.to_string();
    let community = community.to_owned();
    let root_parts = root_oid_parts.to_vec();

    tokio::task::spawn_blocking(move || {
        let timeout = Duration::from_millis(500);
        let mut session = SyncSession::new_v2c(&agent_addr, community.as_bytes(), Some(timeout), 0)?;
        
        let mut data = HashMap::new();
        let mut current_oid_parts = root_parts.clone();
        let mut count = 0;

        loop {
            // Safety break to prevent infinite walk on huge MIBs
            if count > 2000 { break; }
            count += 1;

            let current_oid = match Oid::from(&current_oid_parts) {
                Ok(o) => o,
                Err(_) => break,
            };

            let response = match session.getnext(&current_oid) {
                Ok(res) => res,
                Err(_) => break,
            };

            if let Some(varbind) = response.varbinds.into_iter().next() {
                let next_oid = varbind.0;
                let value_str = match &varbind.1 {
                    Value::Integer(i) => i.to_string(),
                    Value::Counter32(c) => c.to_string(),
                    Value::Unsigned32(u) => u.to_string(),
                    Value::Counter64(c) => c.to_string(),
                    Value::OctetString(b) => String::from_utf8_lossy(b).to_string(),
                    Value::ObjectIdentifier(o) => o.to_string(),
                    _ => format!("{:?}", varbind.1),
                };

                // Check if we are still in the subtree
                let next_oid_str = next_oid.to_string();
                let root_oid_str = Oid::from(&root_parts).map(|o| o.to_string()).unwrap_or_default();
                
                if !next_oid_str.starts_with(&root_oid_str) {
                    break;
                }

                data.insert(next_oid_str, value_str);
                
                // Update parts for next iteration
                let mut parts = Vec::new();
                if let Some(it) = next_oid.iter() {
                    for p in it {
                        parts.push(p);
                    }
                }
                current_oid_parts = parts;
            } else {
                break;
            }
        }

        Ok(data)
    }).await?
}

pub fn diff_snapshots(old: &OidSnapshot, new: &OidSnapshot, prober: &impl Uprober) -> Vec<DiffResult> {
    let mut results = Vec::new();

    for (oid, new_val) in &new.data {
        if let Some(old_val) = old.data.get(oid) {
            if let Some(change_type) = prober.identify_change(oid, old_val, new_val) {
                results.push(DiffResult {
                    oid: oid.clone(),
                    old_value: old_val.clone(),
                    new_value: new_val.clone(),
                    change_type,
                });
            }
        } else {
            // New OID appeared
            results.push(DiffResult {
                oid: oid.clone(),
                old_value: "N/A".to_string(),
                new_value: new_val.clone(),
                change_type: "New OID Discovered".to_string(),
            });
        }
    }

    results
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Instant;

    #[test]
    fn test_battery_decrease_heuristic() {
        let prober = DefaultUprober;
        let oid = ".1.3.6.1.4.1.318.1.1.1.2.1.1.0"; // APC Battery Capacity
        
        // Scenario: Battery drops from 100 to 95
        let result = prober.identify_change(oid, "100", "95");
        assert!(result.is_some());
        assert!(result.unwrap().contains("Battery Decrease"));
    }

    #[test]
    fn test_voltage_drop_heuristic() {
        let prober = DefaultUprober;
        let oid = ".1.3.6.1.4.1.318.1.1.1.3.2.1.0"; // APC Input Voltage
        
        // Scenario: Voltage drops from 230 to 0 (Power Outage)
        let result = prober.identify_change(oid, "230", "0");
        assert!(result.is_some());
        assert!(result.unwrap().contains("Voltage Drop"));
    }

    #[test]
    fn test_status_change_heuristic() {
        let prober = DefaultUprober;
        let oid = ".1.3.6.1.4.1.318.1.1.1.4.1.1.0"; // APC Output Status
        
        // Scenario: Status changes from 2 (onLine) to 3 (onBattery)
        let result = prober.identify_change(oid, "2", "3");
        assert!(result.is_some());
        assert!(result.unwrap().contains("Status/Value Changed"));
    }

    #[test]
    fn test_snapshot_diffing() {
        let mut data_a = HashMap::new();
        data_a.insert("oid.1".to_string(), "100".to_string());
        data_a.insert("oid.2".to_string(), "230".to_string());

        let mut data_b = HashMap::new();
        data_b.insert("oid.1".to_string(), "90".to_string()); // Change
        data_b.insert("oid.2".to_string(), "230".to_string()); // No change

        let snap_a = OidSnapshot { _timestamp: Instant::now(), data: data_a };
        let snap_b = OidSnapshot { _timestamp: Instant::now(), data: data_b };
        
        let diffs = diff_snapshots(&snap_a, &snap_b, &DefaultUprober);
        
        assert_eq!(diffs.len(), 1);
        assert_eq!(diffs[0].oid, "oid.1");
        assert!(diffs[0].change_type.contains("Battery"));
    }
}
