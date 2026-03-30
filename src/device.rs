use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DeviceCategory {
    UPS,
    RouterSwitch,
    Printer,
    NAS,
    Server,
    WebDevice,
    SSH,
    Alive,
    Unknown,
}

impl fmt::Display for DeviceCategory {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DeviceCategory::UPS => write!(f, "[UPS]"),
            DeviceCategory::RouterSwitch => write!(f, "[NET]"),
            DeviceCategory::Printer => write!(f, "[PRT]"),
            DeviceCategory::NAS => write!(f, "[NAS]"),
            DeviceCategory::Server => write!(f, "[SVR]"),
            DeviceCategory::WebDevice => write!(f, "[WEB]"),
            DeviceCategory::SSH => write!(f, "[SSH]"),
            DeviceCategory::Alive => write!(f, "[UP]"),
            DeviceCategory::Unknown => write!(f, "[???]"),
        }
    }
}

pub struct DeviceInfo {
    pub ip: String,
    pub category: DeviceCategory,
    pub _description: String,
    pub _sys_name: String,
}

/// Fingerprints a device based on sysDescr and sysObjectID
pub fn identify_category(descr: &str, oid: &str) -> DeviceCategory {
    let desc = descr.to_lowercase();
    let oid_str = oid.to_lowercase();

    // 1. UPS Heuristics
    if desc.contains("ups") || desc.contains("battery") || 
       oid_str.contains(".1.3.6.1.4.1.318") || // APC
       oid_str.contains(".1.3.6.1.4.1.3808") || // CyberPower
       oid_str.contains(".1.3.6.1.2.1.33") { // Standard UPS
        return DeviceCategory::UPS;
    }

    // 2. Printer Heuristics
    if desc.contains("printer") || desc.contains("pjl") || desc.contains("canon") || 
       desc.contains("brother") || desc.contains("hp laserjet") || desc.contains("ricoh") ||
       desc.contains("epson") || desc.contains("xerox") || desc.contains("lexmark") || 
       desc.contains("kyocera") || desc.contains("konica") || desc.contains("oki") {
        return DeviceCategory::Printer;
    }

    // 3. Router/Switch Heuristics
    if desc.contains("switch") || desc.contains("router") || desc.contains("mikrotik") ||
       desc.contains("cisco ios") || desc.contains("edgeos") || desc.contains("junos") {
        return DeviceCategory::RouterSwitch;
    }

    // 4. NAS Heuristics
    if desc.contains("synology") || desc.contains("qnap") || desc.contains("asustor") || desc.contains("truenas") {
        return DeviceCategory::NAS;
    }

    // 5. Server Heuristics (OS strings)
    if desc.contains("windows server") || desc.contains("debian") || desc.contains("ubuntu") || desc.contains("red hat") || desc.contains("esxi") {
        return DeviceCategory::Server;
    }

    DeviceCategory::Unknown
}
