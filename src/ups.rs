use std::collections::HashMap;
use std::time::{Duration, Instant};
use snmp2::{SyncSession, Oid, Value};
use snmp2::v3::{Security, Auth, AuthProtocol, Cipher};
use anyhow::Result;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UpsVendor { APC, CyberPower, Eaton, Delta, Liebert, TrippLite, Socomec, RFC1628Standard, Unknown }

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
            UpsVendor::RFC1628Standard => write!(f, "Standard-UPS"),
            UpsVendor::Unknown => write!(f, "Unknown Device"),
        }
    }
}

pub struct UpsDevice { pub vendor: UpsVendor, pub model: String, pub _firmware: String }
pub struct OidSnapshot { pub _timestamp: Instant, pub data: HashMap<String, String> }
pub struct DiffResult { pub oid: String, pub old_value: String, pub new_value: String, pub change_type: String }

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
                if v1 > 50 && v2 == 0 { return Some("Power Failure (Voltage 0)".to_string()); }
                if v1 != v2 { return Some(format!("Value Shift ({} -> {})", v1, v2)); }
            }
            _ => { if old != new { return Some("Status Update".to_string()); } }
        }
        None
    }
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

pub async fn identify_ups_v3(addr: &str, user: &str, pass: &str, priv_pass: &str, proto: AuthProtocol) -> Result<Option<UpsDevice>> {
    let addr = addr.to_string();
    let user = user.to_string();
    let pass = pass.to_string();
    let priv_pass = priv_pass.to_string();
    
    tokio::task::spawn_blocking(move || {
        let timeout = Duration::from_secs(2);
        let security = Security::new(user.as_bytes(), pass.as_bytes()).with_auth_protocol(proto).with_auth(Auth::AuthPriv { cipher: Cipher::Aes128, privacy_password: priv_pass.as_bytes().to_vec() });
        let mut session = SyncSession::new_v3(&addr, Some(timeout), 1, security)?;
        probe_vendor(&mut session)
    }).await?
}

pub async fn identify_ups_v2(addr: &str, community: &str) -> Result<Option<UpsDevice>> {
    let addr = addr.to_string();
    let comm = community.to_string();
    tokio::task::spawn_blocking(move || {
        let mut session = SyncSession::new_v2c(&addr, comm.as_bytes(), Some(Duration::from_secs(2)), 1)?;
        probe_vendor(&mut session)
    }).await?
}

fn probe_vendor(session: &mut SyncSession) -> Result<Option<UpsDevice>> {
    let sys_object_id = Oid::from(&[1, 3, 6, 1, 2, 1, 1, 2, 0]).unwrap();
    let mut vendor = UpsVendor::Unknown;
    let mut model = "Unknown".to_string();
    
    if let Ok(resp) = session.get(&sys_object_id) {
        if let Some(vb) = resp.varbinds.into_iter().next() {
            if let Value::ObjectIdentifier(oid) = vb.1 {
                let oid_str = oid.to_string();
                vendor = if oid_str.contains(".1.3.6.1.4.1.318") { UpsVendor::APC }
                    else if oid_str.contains(".1.3.6.1.4.1.3808") { UpsVendor::CyberPower }
                    else if oid_str.contains(".1.3.6.1.4.1.534") { UpsVendor::Eaton }
                    else if oid_str.contains(".1.3.6.1.2.1.33") { UpsVendor::RFC1628Standard }
                    else { UpsVendor::Unknown };
            }
        }
    }
    
    let sys_descr = Oid::from(&[1, 3, 6, 1, 2, 1, 1, 1, 0]).unwrap();
    if let Ok(resp) = session.get(&sys_descr) {
        if let Some(vb) = resp.varbinds.into_iter().next() {
            let desc = format!("{:?}", vb.1).to_lowercase();
            if vendor == UpsVendor::Unknown && (desc.contains("ups") || desc.contains("battery")) { vendor = UpsVendor::RFC1628Standard; }
            model = if desc.len() > 30 { desc[..30].to_string() } else { desc };
        }
    }

    if vendor != UpsVendor::Unknown { Ok(Some(UpsDevice { vendor, model, _firmware: "N/A".to_string() })) } else { Ok(None) }
}

pub async fn snmp_walk_v3(addr: &str, user: &str, pass: &str, priv_pass: &str, proto: AuthProtocol, root: &[u64]) -> Result<HashMap<String, String>> {
    let addr = addr.to_string();
    let user = user.to_string();
    let p1 = pass.to_string();
    let p2 = priv_pass.to_string();
    let root = root.to_vec();
    
    tokio::task::spawn_blocking(move || {
        let security = Security::new(user.as_bytes(), p1.as_bytes()).with_auth_protocol(proto).with_auth(Auth::AuthPriv { cipher: Cipher::Aes128, privacy_password: p2.as_bytes().to_vec() });
        let mut session = SyncSession::new_v3(&addr, Some(Duration::from_millis(1500)), 1, security)?;
        perform_walk(&mut session, &root)
    }).await?
}

pub async fn snmp_walk_v2(addr: &str, comm: &str, root: &[u64]) -> Result<HashMap<String, String>> {
    let addr = addr.to_string();
    let comm = comm.to_string();
    let root = root.to_vec();
    tokio::task::spawn_blocking(move || {
        let mut session = SyncSession::new_v2c(&addr, comm.as_bytes(), Some(Duration::from_millis(1500)), 1)?;
        perform_walk(&mut session, &root)
    }).await?
}

fn perform_walk(session: &mut SyncSession, root: &[u64]) -> Result<HashMap<String, String>> {
    let mut data = HashMap::new();
    let mut current_parts = root.to_vec();
    let root_str = Oid::from(root).unwrap().to_string();
    let mut count = 0;
    while count < 1000 {
        count += 1;
        let current_oid = Oid::from(&current_parts).unwrap();
        let resp = match session.getnext(&current_oid) { Ok(r) => r, Err(_) => break };
        if let Some(vb) = resp.varbinds.into_iter().next() {
            let next_oid = vb.0;
            let next_oid_str = next_oid.to_string();
            if !next_oid_str.starts_with(&root_str) { break; }
            data.insert(next_oid_str, format!("{:?}", vb.1));
            current_parts = next_oid.iter().unwrap().collect();
        } else { break; }
    }
    Ok(data)
}
