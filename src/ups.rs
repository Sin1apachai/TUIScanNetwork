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
        match self {
            UpsVendor::APC => write!(f, "APC"),
            UpsVendor::CyberPower => write!(f, "CyberPower"),
            UpsVendor::Eaton => write!(f, "Eaton"),
            UpsVendor::Delta => write!(f, "Delta"),
            UpsVendor::Liebert => write!(f, "Liebert"),
            UpsVendor::TrippLite => write!(f, "TrippLite"),
            UpsVendor::Socomec => write!(f, "Socomec"),
            UpsVendor::RFC1628Standard => write!(f, "RFC1628-Standard"),
            UpsVendor::Unknown => write!(f, "Unknown"),
        }
    }
}

pub struct UpsDevice {
    pub vendor: UpsVendor,
    pub model: String,
    pub _firmware: String,
}

pub struct OidSnapshot {
    pub _timestamp: Instant,
    pub data: HashMap<String, String>, 
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
        if old == new { return None; }
        let old_val = old.parse::<i64>().ok();
        let new_val = new.parse::<i64>().ok();
        match (old_val, new_val) {
            (Some(v1), Some(v2)) => {
                if v1 > v2 && v1 <= 100 && v2 >= 0 { return Some("Battery Drop".to_string()); }
                if v1 > 50 && v2 == 0 { return Some("Voltage Drop (Power Failure)".to_string()); }
                if v1 != v2 { return Some(format!("Changed ({} -> {})", v1, v2)); }
            }
            _ => { if old != new { return Some("Status Change".to_string()); } }
        }
        None
    }
}

pub async fn identify_ups(agent_addr: &str, community: &str) -> Result<Option<UpsDevice>> {
    let addr = agent_addr.to_string();
    let community = community.to_owned();
    tokio::task::spawn_blocking(move || {
        let timeout = Duration::from_secs(1);
        let mut session = SyncSession::new_v2c(&addr, community.as_bytes(), Some(timeout), 0)?;
        let sys_object_id = Oid::from(&[1, 3, 6, 1, 2, 1, 1, 2, 0]).unwrap();
        let sys_descr = Oid::from(&[1, 3, 6, 1, 2, 1, 1, 1, 0]).unwrap();
        let mut vendor = UpsVendor::Unknown;
        let mut model = "Unknown Model".to_string();
        if let Ok(resp) = session.get(&sys_object_id) {
            if let Some(vb) = resp.varbinds.into_iter().next() {
                if let Value::ObjectIdentifier(oid) = vb.1 {
                    let oid_str = oid.to_string();
                    vendor = if oid_str.contains(".1.3.6.1.4.1.318") { UpsVendor::APC }
                        else if oid_str.contains(".1.3.6.1.4.1.3808") { UpsVendor::CyberPower }
                        else if oid_str.contains(".1.3.6.1.4.1.534") { UpsVendor::Eaton }
                        else if oid_str.contains(".1.3.6.1.4.1.2254") { UpsVendor::Delta }
                        else if oid_str.contains(".1.3.6.1.4.1.476") { UpsVendor::Liebert }
                        else if oid_str.contains(".1.3.6.1.4.1.455") { UpsVendor::Socomec }
                        else if oid_str.contains(".1.3.6.1.2.1.33") { UpsVendor::RFC1628Standard }
                        else { UpsVendor::Unknown };
                }
            }
        }
        if vendor == UpsVendor::Unknown {
            if let Ok(resp) = session.get(&sys_descr) {
                if let Some(vb) = resp.varbinds.into_iter().next() {
                    let desc = clean_value(&vb.1).to_lowercase();
                    if desc.contains("ups") || desc.contains("battery") { vendor = UpsVendor::RFC1628Standard; }
                    model = if desc.len() > 40 { desc[..40].to_string() } else { desc };
                }
            }
        }
        if vendor != UpsVendor::Unknown { Ok(Some(UpsDevice { vendor, model, _firmware: "N/A".to_string() })) } else { Ok(None) }
    }).await?
}

pub async fn snmp_walk(agent_addr: &str, community: &str, root_oid_parts: &[u64]) -> Result<HashMap<String, String>> {
    let agent_addr = agent_addr.to_string();
    let community = community.to_owned();
    let root_parts = root_oid_parts.to_vec();
    tokio::task::spawn_blocking(move || {
        let timeout = Duration::from_millis(1000);
        let mut session = SyncSession::new_v2c(&agent_addr, community.as_bytes(), Some(timeout), 0)?;
        let mut data = HashMap::new();
        let mut current_oid_parts = root_parts.clone();
        let root_oid_str = Oid::from(&root_parts).map(|o| o.to_string()).unwrap_or_default();
        let mut count = 0;
        loop {
            if count > 2000 { break; }
            count += 1;
            let current_oid = Oid::from(&current_oid_parts).ok().unwrap();
            let response = match session.getnext(&current_oid) { 
                Ok(res) => res, 
                Err(_) => break, 
            };
            if let Some(varbind) = response.varbinds.into_iter().next() {
                let next_oid = varbind.0;
                let val_str = clean_value(&varbind.1);
                let next_oid_str = next_oid.to_string();
                if !next_oid_str.starts_with(&root_oid_str) { break; }
                data.insert(next_oid_str, val_str);
                current_oid_parts = next_oid.iter().unwrap().collect();
            } else { break; }
        }
        Ok(data)
    }).await?
}

pub fn diff_snapshots(old: &OidSnapshot, new: &OidSnapshot, prober: &impl Uprober) -> Vec<DiffResult> {
    let mut results = Vec::new();
    for (oid, new_val) in &new.data {
        if let Some(old_val) = old.data.get(oid) {
            if let Some(change_type) = prober.identify_change(oid, old_val, new_val) {
                results.push(DiffResult { oid: oid.clone(), old_value: old_val.clone(), new_value: new_val.clone(), change_type });
            }
        }
    }
    results
}

fn clean_value(val: &Value) -> String {
    match val {
        Value::Integer(i) => i.to_string(),
        Value::OctetString(b) => String::from_utf8_lossy(b).trim().to_string(),
        Value::ObjectIdentifier(o) => o.to_string(),
        Value::Counter32(c) => c.to_string(),
        Value::Unsigned32(u) => u.to_string(),
        Value::Counter64(c) => c.to_string(),
        Value::Timeticks(t) => format!("{}s", t / 100),
        _ => format!("{:?}", val),
    }
}
