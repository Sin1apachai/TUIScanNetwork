use anyhow::Result;
use crossterm::{
    event::{self, DisableMouseCapture, EnableMouseCapture, Event, KeyCode},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{
    backend::{Backend, CrosstermBackend},
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    widgets::{Block, Borders, Cell, Gauge, Paragraph, Row, Table, TableState},
    Frame, Terminal,
};
use snmp2::{SyncSession, Oid};
use snmp2::v3::{Security, Auth, AuthProtocol, Cipher};
use std::{
    io,
    sync::mpsc::{self, Receiver, Sender},
    time::{Duration, Instant},
};

use tui_scan_network::{ups, device, Config, EditMode, SecurityLevel};
use ups::{OidSnapshot, DiffResult, UpsDevice, DefaultUprober};
use device::{DeviceCategory, DeviceInfo};
use network_interface::{NetworkInterface, NetworkInterfaceConfig};

pub struct App {
    pub discovered_devices: Vec<DeviceInfo>,
    pub discovered_ips: Vec<String>,
    pub selected_index: usize,
    pub table_state: TableState,
    pub details_state: TableState,
    pub is_scanning: bool,
    pub scan_progress: u32,
    pub scan_total: u32,
    pub status: String,
    pub show_uprober: bool,
    pub show_config: bool,
    pub config: Config,
    pub selected_config_idx: usize,
    pub snmp_data: Vec<(String, String)>,
    pub snapshot_a: Option<OidSnapshot>,
    pub snapshot_b: Option<OidSnapshot>,
    pub diff_results: Vec<DiffResult>,
    pub is_walking: bool,
    pub identified_ups: Option<UpsDevice>,
    pub edit_mode: EditMode,
    pub temp_input: String,
    pub logs: Vec<String>,
    pub active_panel: usize, // 0: Devices, 1: Metrics
}

impl App {
    pub fn new() -> Self {
        let mut table_state = TableState::default();
        table_state.select(Some(0));
        Self {
            discovered_devices: Vec::new(),
            discovered_ips: Vec::new(),
            selected_index: 0,
            table_state,
            details_state: TableState::default(),
            is_scanning: false,
            scan_progress: 0,
            scan_total: 0,
            status: "Ready".to_string(),
            show_uprober: false,
            show_config: false,
            config: Config::default(),
            selected_config_idx: 0,
            snmp_data: Vec::new(),
            snapshot_a: None,
            snapshot_b: None,
            diff_results: Vec::new(),
            is_walking: false,
            identified_ups: None,
            edit_mode: EditMode::None,
            temp_input: String::new(),
            logs: vec!["System Started".to_string()],
            active_panel: 0,
        }
    }

    pub fn log(&mut self, msg: String) {
        self.logs.push(msg);
        if self.logs.len() > 10 { self.logs.remove(0); }
    }

    fn select_next(&mut self, tx: Sender<ScanMessage>) {
        if self.show_config { self.selected_config_idx = (self.selected_config_idx + 1) % 10; return; }
        if self.active_panel == 0 {
            if self.discovered_devices.is_empty() { return; }
            let i = match self.table_state.selected() {
                Some(i) => if i >= self.discovered_devices.len() - 1 { 0 } else { i + 1 },
                None => 0,
            };
            self.table_state.select(Some(i));
            self.selected_index = i;
            self.start_snmp_update(tx);
        } else {
            if self.snmp_data.is_empty() { return; }
            let i = match self.details_state.selected() {
                Some(i) => if i >= self.snmp_data.len() - 1 { 0 } else { i + 1 },
                None => 0,
            };
            self.details_state.select(Some(i));
        }
    }

    fn select_previous(&mut self, tx: Sender<ScanMessage>) {
        if self.show_config { self.selected_config_idx = if self.selected_config_idx == 0 { 9 } else { self.selected_config_idx - 1 }; return; }
        if self.active_panel == 0 {
            if self.discovered_devices.is_empty() { return; }
            let i = match self.table_state.selected() {
                Some(i) => if i == 0 { self.discovered_devices.len() - 1 } else { i - 1 },
                None => 0,
            };
            self.table_state.select(Some(i));
            self.selected_index = i;
            self.start_snmp_update(tx);
        } else {
            if self.snmp_data.is_empty() { return; }
            let i = match self.details_state.selected() {
                Some(i) => if i == 0 { self.snmp_data.len() - 1 } else { i - 1 },
                None => 0,
            };
            self.details_state.select(Some(i));
        }
    }

    fn start_snmp_update(&mut self, tx: Sender<ScanMessage>) {
        if self.discovered_devices.is_empty() { return; }
        self.snmp_data.clear();
        let ip = self.discovered_devices[self.selected_index].ip.clone();
        let cfg = (self.config.v3_user.clone(), self.config.v3_auth_pass.clone(), self.config.v3_priv_pass.clone(), self.config.v3_auth_protocol, self.config.community.clone(), self.config.snmp_port, 5000, self.config.v3_cipher, self.config.v3_level);

        tokio::spawn(async move {
            let agent_addr = format!("{}:{}", ip, cfg.5);
            let timeout = Duration::from_millis(cfg.6);
            let oids = [
                (".1.3.6.1.2.1.33.1.4.1.0", "Output Source (RFC)"),
                (".1.3.6.1.4.1.935.10.1.1.2.1.0", "UPS Status (EPPC)"),
                (".1.3.6.1.2.1.33.1.2.7.0", "Battery Temp (RFC C)"),
                (".1.3.6.1.4.1.935.10.1.1.2.2.0", "Battery Temp (EPPC C)"),
                (".1.3.6.1.2.1.33.1.3.3.1.3.1", "Input Voltage (RFC V)"),
                (".1.3.6.1.4.1.935.10.1.1.2.16.1.3.1", "Input Voltage (EPPC V)"),
                (".1.3.6.1.2.1.33.1.3.3.1.2.1", "Input Freq (RFC Hz)"),
                (".1.3.6.1.4.1.935.10.1.1.2.16.1.2.1", "Input Freq (EPPC Hz)"),
                (".1.3.6.1.2.1.33.1.4.4.1.5.1", "Output Load (RFC %)"),
                (".1.3.6.1.4.1.935.10.1.1.2.12.0", "Output Load (EPPC % )"),
                (".1.3.6.1.2.1.33.1.4.4.1.2.1", "Output Voltage (RFC V)"),
                (".1.3.6.1.4.1.935.10.1.1.2.5.0", "Output Voltage (EPPC V)"),
                (".1.3.6.1.2.1.33.1.4.2.0", "Output Freq (RFC Hz)"),
                (".1.3.6.1.4.1.935.10.1.1.2.6.0", "Output Freq (EPPC Hz)"),
                (".1.3.6.1.2.1.33.1.4.4.1.3.1", "Output Current (A)"),
                (".1.3.6.1.2.1.33.1.4.4.1.4.1", "Output Power (W)"),
                (".1.3.6.1.4.1.935.10.1.1.2.7.0", "Output Power (EPPC W)"),
                (".1.3.6.1.2.1.33.1.2.1.0", "Battery Status (RFC)"),
                (".1.3.6.1.2.1.33.1.2.4.0", "Battery Capacity (RFC %)"),
                (".1.3.6.1.4.1.935.10.1.1.3.4.0", "Battery Capacity (EPPC %)"),
                (".1.3.6.1.2.1.33.1.2.5.0", "Battery Voltage (RFC V)"),
                (".1.3.6.1.4.1.935.10.1.1.3.5.0", "Battery Voltage (EPPC V)"),
                (".1.3.6.1.4.1.935.1.1.1.2.2.1.0", "Battery Capacity (Big %)"),
                (".1.3.6.1.4.1.935.1.1.1.8.2.2.0", "Input Voltage L1 (Big V)"),
                (".1.3.6.1.4.1.935.1.1.1.8.2.3.0", "Input Voltage L2 (Big V)"),
                (".1.3.6.1.4.1.935.1.1.1.8.2.4.0", "Input Voltage L3 (Big V)"),
                (".1.3.6.1.4.1.935.1.1.1.8.2.5.0", "Input Current L1 (Big A)"),
                (".1.3.6.1.4.1.935.1.1.1.8.2.6.0", "Input Current L2 (Big A)"),
                (".1.3.6.1.4.1.935.1.1.1.8.2.7.0", "Input Current L3 (Big A)"),
                (".1.3.6.1.4.1.935.1.1.1.8.3.2.0", "Output Voltage L1 (Big V)"),
                (".1.3.6.1.4.1.935.1.1.1.8.3.3.0", "Output Voltage L2 (Big V)"),
                (".1.3.6.1.4.1.935.1.1.1.8.3.4.0", "Output Voltage L3 (Big V)"),
                (".1.3.6.1.4.1.935.1.1.1.8.3.5.0", "Output Current L1 (Big A)"),
                (".1.3.6.1.4.1.935.1.1.1.8.3.6.0", "Output Current L2 (Big A)"),
                (".1.3.6.1.4.1.935.1.1.1.8.3.7.0", "Output Current L3 (Big A)"),
                (".1.3.6.1.4.1.935.1.1.1.8.5.1.0", "Output Load L1 (Big %)"),
                (".1.3.6.1.4.1.935.1.1.1.8.5.2.0", "Output Load L2 (Big %)"),
                (".1.3.6.1.4.1.935.1.1.1.8.5.3.0", "Output Load L3 (Big %)"),
                (".1.3.6.1.4.1.935.1.1.1.4.2.2.0", "Output Freq (Big Hz)"),
                (".1.3.6.1.4.1.935.1.1.1.2.2.3.0", "Battery Temp (Big C)"),
                (".1.3.6.1.2.1.33.1.2.2.0", "Time On Battery"),
                (".1.3.6.1.2.1.33.1.2.3.0", "Backup Time (RFC Min)"),
                (".1.3.6.1.4.1.935.10.1.1.2.8.0", "Backup Time (EPPC Min)"),
                (".1.3.6.1.4.1.935.10.1.1.1.2.0", "Device Model"),
                (".1.3.6.1.4.1.935.1.1.1.1.1.1.0", "Device Model (Big)"),
                (".1.3.6.1.4.1.935.10.1.1.1.4.0", "Serial Number"),
                (".1.3.6.1.4.1.935.10.1.1.1.6.0", "NMC Firmware"),
                (".1.3.6.1.2.1.1.1.0", "System Desc"),
            ];

            let mut results = Vec::new();
            let mut snmp_success = false;

            // Step 1: Try SNMP V3
            if !cfg.0.is_empty() {
                let use_fallback;
                let mut session_opt = match SyncSession::new_v3(&agent_addr, Some(timeout), 2, 
                    Security::new(cfg.0.as_bytes(), cfg.1.as_bytes())
                        .with_auth_protocol(cfg.3)
                        .with_auth(match cfg.8 {
                            SecurityLevel::NoAuth => Auth::NoAuthNoPriv,
                            SecurityLevel::AuthNoPriv => Auth::AuthNoPriv,
                            SecurityLevel::AuthPriv => Auth::AuthPriv { cipher: cfg.7, privacy_password: cfg.2.as_bytes().to_vec() },
                        })
                ) {
                    Ok(s) => Some(s),
                    Err(_) => None,
                };

                if let Some(ref mut session) = session_opt {
                    let mut lib_any_success = false;
                    for (oid_str, label) in oids.iter() {
                        let parts: Vec<u64> = oid_str.split('.').filter(|s| !s.is_empty()).map(|s| s.parse::<u64>().unwrap_or(0)).collect();
                        if let Ok(oid) = Oid::from(&parts[..]) {
                            if let Ok(resp) = session.get(&oid) {
                                if let Some(vb) = resp.varbinds.into_iter().next() {
                                    let val = clean_snmp_value(oid_str, &vb.1);
                                    if !val.is_empty() && !val.contains("SUCH") {
                                        results.push((label.to_string(), val));
                                        lib_any_success = true;
                                        snmp_success = true;
                                    }
                                }
                            }
                        }
                    }
                    use_fallback = !lib_any_success;
                } else {
                    use_fallback = true;
                }

                if use_fallback {
                    // SYSTEM FALLBACK: If library fails, try system snmpget IN BATCH
                    let _ = tx.send(ScanMessage::Status("Trying system fallback (Batch)...".to_string()));
                    let auth_level = match cfg.8 {
                        SecurityLevel::NoAuth => "noAuthNoPriv",
                        SecurityLevel::AuthNoPriv => "authNoPriv",
                        SecurityLevel::AuthPriv => "authPriv",
                    };
                    let auth_proto = match cfg.3 {
                        snmp2::v3::AuthProtocol::Md5 => "MD5",
                        snmp2::v3::AuthProtocol::Sha1 => "SHA",
                        _ => "MD5",
                    };
                    let cipher_str = match cfg.7 {
                        Cipher::Aes128 => "AES",
                        Cipher::Des => "DES",
                        Cipher::Aes192 => "AES192",
                        Cipher::Aes256 => "AES256",
                    };
                    
                    let mut cmd = std::process::Command::new("snmpget");
                    cmd.args(&[
                        "-v", "3", 
                        "-u", &cfg.0, 
                        "-l", auth_level, 
                        "-a", auth_proto, 
                        "-A", &cfg.1, 
                        "-x", cipher_str, 
                        "-X", &cfg.2,
                        "-On",
                        "-t", "12",
                        "-r", "3",
                        &agent_addr
                    ]);
                    for (oid_str, _) in oids.iter() { cmd.arg(oid_str); }

                    match cmd.output() {
                        Ok(out) => {
                            let full_stdout = String::from_utf8_lossy(&out.stdout);
                            let full_stderr = String::from_utf8_lossy(&out.stderr);
                            
                            if !out.status.success() {
                                let _ = tx.send(ScanMessage::Status(format!("Fallbk Cmd Fail: {}", full_stderr.chars().take(50).collect::<String>())));
                            }

                            let mut match_count = 0;
                            for line in full_stdout.lines() {
                                if let Some((oid_part, val_raw)) = line.split_once(" = ") {
                                    let val = if let Some((_type, actual)) = val_raw.split_once(": ") { actual } else { val_raw }.trim();
                                    
                                    if let Some((oid_str, label)) = oids.iter().find(|(o, _)| oid_part.contains(o)) {
                                        let div_10_oids = [
                                            ".1.3.6.1.4.1.935.10.1.1.2.2.0",       // EPPC Temp
                                            ".1.3.6.1.4.1.935.10.1.1.2.16.1.3.1", // EPPC Input Volt
                                            ".1.3.6.1.4.1.935.10.1.1.2.16.1.2.1", // EPPC Input Freq
                                            ".1.3.6.1.4.1.935.10.1.1.2.5.0",       // EPPC Output Volt
                                            ".1.3.6.1.4.1.935.10.1.1.2.6.0",       // EPPC Output Freq
                                            ".1.3.6.1.4.1.935.10.1.1.3.5.0",       // EPPC Battery Volt
                                            ".1.3.6.1.4.1.935.10.1.1.2.12.0",      // EPPC Load %?
                                            ".1.3.6.1.4.1.935.1.1.1.3.2.1.0",     // Big Input V
                                            ".1.3.6.1.4.1.935.1.1.1.4.2.1.0",     // Big Output V
                                            ".1.3.6.1.4.1.935.1.1.1.4.2.2.0",     // Big Freq
                                            ".1.3.6.1.4.1.935.1.1.1.2.2.3.0",     // Big Temp
                                            ".1.3.6.1.4.1.935.1.1.1.8.2.2.0",     // Big In V L1
                                            ".1.3.6.1.4.1.935.1.1.1.8.2.3.0",     // Big In V L2
                                            ".1.3.6.1.4.1.935.1.1.1.8.2.4.0",     // Big In V L3
                                            ".1.3.6.1.4.1.935.1.1.1.8.3.2.0",     // Big Out V L1
                                            ".1.3.6.1.4.1.935.1.1.1.8.3.3.0",     // Big Out V L2
                                            ".1.3.6.1.4.1.935.1.1.1.8.3.4.0",     // Big Out V L3
                                            ".1.3.6.1.4.1.935.1.1.1.8.2.5.0",     // Big In A L1
                                            ".1.3.6.1.4.1.935.1.1.1.8.2.6.0",     // Big In A L2
                                            ".1.3.6.1.4.1.935.1.1.1.8.2.7.0",     // Big In A L3
                                            ".1.3.6.1.4.1.935.1.1.1.8.3.5.0",     // Big Out A L1
                                            ".1.3.6.1.4.1.935.1.1.1.8.3.6.0",     // Big Out A L2
                                            ".1.3.6.1.4.1.935.1.1.1.8.3.7.0",     // Big Out A L3
                                            ".1.3.6.1.4.1.318.1.1.1.2.2.2.0",      // APC Temp
                                            ".1.3.6.1.4.1.318.1.1.1.3.2.1.0",      // APC Input Volt
                                        ];
                                        let formatted_val = if div_10_oids.iter().any(|&o| oid_str.ends_with(o)) {
                                            if let Ok(v) = val.parse::<f32>() { format!("{:.1}", v / 10.0) } else { val.to_string() }
                                        } else { val.to_string() };

                                        if !formatted_val.contains("SUCH") && !formatted_val.contains("ERROR") {
                                            results.push((label.to_string(), formatted_val));
                                            snmp_success = true;
                                            match_count += 1;
                                        }
                                    }
                                }
                            }
                            if match_count > 0 {
                                let _ = tx.send(ScanMessage::Status(format!("Fallbk Success: Got {} values", match_count)));
                            }
                        }
                        Err(e) => {
                            let _ = tx.send(ScanMessage::Status(format!("Fallbk Exec Err: {}", e)));
                        }
                    }
                }
            }

            // Step 2: Try SNMP V2c fallback if V3 failed
            if !snmp_success {
                if let Ok(mut session) = SyncSession::new_v2c(&agent_addr, cfg.4.as_bytes(), Some(timeout), 2) {
                    for (oid_str, label) in oids.iter() {
                        let parts: Vec<u64> = oid_str.split('.').filter(|s| !s.is_empty()).map(|s| s.parse::<u64>().unwrap_or(0)).collect();
                        if let Ok(oid) = Oid::from(&parts[..]) {
                            if let Ok(resp) = session.get(&oid) { 
                                if let Some(vb) = resp.varbinds.into_iter().next() { 
                                    let val = clean_snmp_value(oid_str, &vb.1);
                                    if !val.is_empty() && !val.contains("SUCH") {
                                        results.push((label.to_string(), val));
                                        snmp_success = true;
                                    }
                                } 
                            }
                        }
                    }
                }
            }

            // Final Send - ONLY send values that were successfully retrieved
            if snmp_success {
                // Filter out empty or "No Such" results to keep UI clean
                let filtered_results: Vec<(String, String)> = results.into_iter()
                    .filter(|(_, val)| !val.is_empty() && !val.to_uppercase().contains("NO SUCH"))
                    .collect();

                if !filtered_results.is_empty() {
                    let _ = tx.send(ScanMessage::MetricUpdated(filtered_results));
                    let _ = tx.send(ScanMessage::Status("SNMP Update Success".to_string()));
                } else {
                    let _ = tx.send(ScanMessage::Status("SNMP Success but no metrics found".to_string()));
                }
            } else {
                let _ = tx.send(ScanMessage::Status("SNMP Failed (No Data Found)".to_string()));
            }

            // Identification
            let dev_res = if !cfg.0.is_empty() { 
                ups::identify_ups_v3(&agent_addr, &cfg.0, &cfg.1, &cfg.2, cfg.3, cfg.7, cfg.8).await 
            } else { 
                ups::identify_ups_v2(&agent_addr, &cfg.4).await 
            };
            if let Ok(Some(dev)) = dev_res { 
                let _ = tx.send(ScanMessage::UpsIdentified(agent_addr.split(':').next().unwrap_or("").to_string(), dev)); 
            }
        });
    }

    fn start_scan(&mut self, tx: Sender<ScanMessage>) {
        if self.is_scanning { return; }
        self.is_scanning = true;
        self.discovered_devices.clear();
        self.discovered_ips.clear();
        self.scan_progress = 0;
        self.status = "Discovery in progress...".to_string();
        
        let cfg = (self.config.v3_user.clone(), self.config.v3_auth_pass.clone(), self.config.v3_priv_pass.clone(), self.config.v3_auth_protocol, self.config.community.clone(), self.config.snmp_port, self.config.timeout_ms, self.config.concurrency, self.config.v3_cipher, self.config.v3_level);
        
        tokio::spawn(async move {
            let interfaces: Vec<NetworkInterface> = NetworkInterface::show().unwrap_or_default();
            let mut scan_targets = Vec::new();
            for iface in interfaces {
                for addr in iface.addr {
                    if let std::net::IpAddr::V4(ipv4) = addr.ip() {
                        if !ipv4.is_loopback() {
                            let ip_str = ipv4.to_string();
                            if let Some((prefix, _)) = ip_str.rsplit_once('.') { if !scan_targets.contains(&prefix.to_string()) { scan_targets.push(prefix.to_string()); } }
                        }
                    }
                }
            }

            let total_jobs = (scan_targets.len() * 254) as u32;
            let _ = tx.send(ScanMessage::Status(format!("Scanning {} addresses...", total_jobs)));
            
            let semaphore = std::sync::Arc::new(tokio::sync::Semaphore::new(cfg.7));
            for subnet in scan_targets {
                for i in 1..=254 {
                    let ip = format!("{}.{}", subnet, i);
                    let tx = tx.clone();
                    let sem = semaphore.clone();
                    let cfg = cfg.clone();
                    tokio::spawn(async move {
                        let _permit = sem.acquire().await.unwrap();
                        let agent_addr = format!("{}:{}", ip, cfg.5);
                        let ip_clone = ip.clone();
                        let result = tokio::task::spawn_blocking(move || {
                            let oid = Oid::from(&[1, 3, 6, 1, 2, 1, 1, 1, 0]).unwrap();
                            let timeout = Duration::from_millis(cfg.6);
                            // 1. Try SNMP V3
                            // 1. Try SNMP V2c (Lightweight Discovery)
                            if let Ok(mut session) = SyncSession::new_v2c(&agent_addr, cfg.4.as_bytes(), Some(timeout), 1) {
                                if let Ok(resp) = session.get(&oid) { if let Some(vb) = resp.varbinds.into_iter().next() { return Some(clean_snmp_value(".1.3.6.1.2.1.1.1.0", &vb.1)); } }
                            }
                            // 2. Port Scan Fallback (Web)
                            for port in [80, 443] {
                                if std::net::TcpStream::connect_timeout(&format!("{}:{}", ip_clone, port).parse().ok()?, Duration::from_millis(300)).is_ok() { 
                                    return Some(format!("Web (Port {})", port)); 
                                }
                            }
                            None
                        }).await.unwrap_or(None);

                        if let Some(desc) = result {
                            let info = DeviceInfo { ip: ip, category: device::identify_category(&desc, ""), _description: desc, _sys_name: "".to_string() };
                            let _ = tx.send(ScanMessage::Discovered(info));
                        }
                        let _ = tx.send(ScanMessage::Progress(1, total_jobs));
                    });
                }
            }
        });
    }

    fn start_ups_walk(&mut self, is_second: bool, tx: Sender<ScanMessage>) {
        if self.discovered_devices.is_empty() { return; }
        if self.is_walking { return; }
        self.is_walking = true;
        let ip = self.discovered_devices[self.selected_index].ip.clone();
        let cfg = (self.config.v3_user.clone(), self.config.v3_auth_pass.clone(), self.config.v3_priv_pass.clone(), self.config.v3_auth_protocol, self.config.community.clone());
        let cipher = self.config.v3_cipher;
        let level = self.config.v3_level;
        
        tokio::spawn(async move {
            let addr = format!("{}:161", ip);
            let root = [1, 3, 6, 1, 2, 1];
            let res = if !cfg.0.is_empty() {
                ups::snmp_walk_v3(&addr, &cfg.0, &cfg.1, &cfg.2, cfg.3, &root, cipher, level).await
            } else {
                ups::snmp_walk_v2(&addr, &cfg.4, &root).await
            };
            
            if let Ok(data) = res {
                let snap = OidSnapshot { _timestamp: Instant::now(), data };
                let _ = tx.send(ScanMessage::UpsResult(snap, is_second));
            } else { let _ = tx.send(ScanMessage::Status("Analysis Failed".to_string())); }
        });
    }
}

pub enum ScanMessage {
    Progress(u32, u32),
    Discovered(DeviceInfo),
    Status(String),
    UpsIdentified(String, UpsDevice),
    UpsResult(OidSnapshot, bool),
    MetricUpdated(Vec<(String, String)>),
    CommunityGuessed(String),
}

#[tokio::main]
async fn main() -> Result<()> {
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen, EnableMouseCapture)?;
    let mut terminal = Terminal::new(CrosstermBackend::new(stdout))?;
    let (tx, rx) = mpsc::channel();
    let mut app = App::new();
    let res = run_app(&mut terminal, &mut app, tx, rx).await;
    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen, DisableMouseCapture)?;
    terminal.show_cursor()?;
    res
}

async fn run_app<B: Backend>(terminal: &mut Terminal<B>, app: &mut App, tx: Sender<ScanMessage>, rx: Receiver<ScanMessage>) -> Result<()> 
where 
    <B as Backend>::Error: std::fmt::Debug + std::marker::Send + std::marker::Sync + 'static 
{
    loop {
        while let Ok(msg) = rx.try_recv() {
            match msg {
                ScanMessage::Progress(delta, total) => { app.scan_progress += delta; app.scan_total = total; if app.scan_progress >= total { app.is_scanning = false; app.status = "Discovery Finished".to_string(); } }
                ScanMessage::Discovered(info) => { if !app.discovered_ips.contains(&info.ip) { app.discovered_ips.push(info.ip.clone()); app.discovered_devices.push(info); } }
                ScanMessage::Status(s) => { let log_s = s.clone(); app.log(log_s); app.status = s; },
                ScanMessage::MetricUpdated(data) => { app.snmp_data = data; }
                ScanMessage::UpsIdentified(ip, dev) => { 
                    app.identified_ups = Some(dev);
                    if let Some(pos) = app.discovered_ips.iter().position(|x| *x == ip) {
                        app.discovered_devices[pos].category = DeviceCategory::UPS;
                    }
                }
                ScanMessage::UpsResult(snap, is_second) => {
                    app.is_walking = false;
                    if is_second {
                        app.snapshot_b = Some(snap);
                        if let (Some(a), Some(b)) = (&app.snapshot_a, &app.snapshot_b) { app.diff_results = ups::diff_snapshots(a, b, &DefaultUprober); }
                    } else { app.snapshot_a = Some(snap); }
                }
                ScanMessage::CommunityGuessed(comm) => { app.config.community = comm; app.start_snmp_update(tx.clone()); }
            }
        }
        terminal.draw(|f| draw(f, app)).map_err(|e| anyhow::anyhow!("{:?}", e))?;
        if event::poll(Duration::from_millis(100))? {
            if let Event::Key(key) = event::read()? {
                if let EditMode::Input(_name, idx) = app.edit_mode.clone() {
                    let idx_clone = idx;
                    match key.code {
                        KeyCode::Enter => {
                            match idx_clone {
                                0 => if let Ok(v) = app.temp_input.parse() { app.config.snmp_port = v; },
                                1 => if let Ok(v) = app.temp_input.parse() { app.config.timeout_ms = v; },
                                2 => if let Ok(v) = app.temp_input.parse() { app.config.concurrency = v; },
                                3 => app.config.v3_user = app.temp_input.clone(),
                                4 => app.config.v3_auth_pass = app.temp_input.clone(),
                                5 => app.config.v3_priv_pass = app.temp_input.clone(),
                                6 => { if app.temp_input.to_uppercase() == "MD5" { app.config.v3_auth_protocol = AuthProtocol::Md5; } else { app.config.v3_auth_protocol = AuthProtocol::Sha1; } },
                                7 => { if app.temp_input.to_uppercase() == "DES" { app.config.v3_cipher = Cipher::Des; } else { app.config.v3_cipher = Cipher::Aes128; } },
                                8 => { if app.temp_input.contains("Priv") { app.config.v3_level = SecurityLevel::AuthPriv; } else if app.temp_input.contains("NoPriv") { app.config.v3_level = SecurityLevel::AuthNoPriv; } else { app.config.v3_level = SecurityLevel::NoAuth; } },
                                9 => app.config.community = app.temp_input.clone(),
                                _ => {}
                            }
                            app.edit_mode = EditMode::None;
                            app.temp_input.clear();
                        }
                        KeyCode::Esc => { app.edit_mode = EditMode::None; app.temp_input.clear(); }
                        KeyCode::Char(c) => app.temp_input.push(c),
                        KeyCode::Backspace => { app.temp_input.pop(); }
                        _ => {}
                    }
                } else if let EditMode::ManualAdd = &app.edit_mode {
                    match key.code {
                        KeyCode::Enter => {
                            let ip = app.temp_input.clone();
                            if !app.discovered_ips.contains(&ip) {
                                app.discovered_ips.push(ip.clone());
                                app.discovered_devices.push(DeviceInfo { 
                                    ip: ip.clone(), 
                                    category: DeviceCategory::UPS, 
                                    _description: "Manual Add".to_string(), 
                                    _sys_name: "".to_string() 
                                });
                                app.table_state.select(Some(app.discovered_devices.len() - 1));
                                app.selected_index = app.discovered_devices.len() - 1;
                                app.start_snmp_update(tx.clone());
                            }
                            app.edit_mode = EditMode::None;
                            app.temp_input.clear();
                        }
                        KeyCode::Esc => { app.edit_mode = EditMode::None; app.temp_input.clear(); }
                        KeyCode::Char(c) => app.temp_input.push(c),
                        KeyCode::Backspace => { app.temp_input.pop(); }
                        _ => {}
                    }
                } else {
                    match key.code {
                        KeyCode::Char('q') => return Ok(()),
                        KeyCode::Char('a') => { app.edit_mode = EditMode::ManualAdd; app.temp_input.clear(); }
                        KeyCode::Char('s') => app.start_scan(tx.clone()),
                        KeyCode::Char('r') => app.start_snmp_update(tx.clone()),
                        KeyCode::Char('c') => app.show_config = !app.show_config,
                        KeyCode::Char('u') => { app.show_uprober = !app.show_uprober; if app.show_uprober { app.snapshot_a = None; app.snapshot_b = None; app.diff_results.clear(); app.start_ups_walk(false, tx.clone()); } }
                        KeyCode::Char('2') => if app.show_uprober { app.start_ups_walk(true, tx.clone()); }
                        KeyCode::Enter => if app.show_config {
                            let fields = ["SNMP Port", "Timeout", "Concurrency", "V3 User", "V3 Auth Pass", "V3 Priv Pass", "V3 Proto", "V3 Cipher", "V3 Level (Priv/NoPriv/None)", "V2 Community"];
                            app.edit_mode = EditMode::Input(fields[app.selected_config_idx].to_string(), app.selected_config_idx);
                            app.temp_input.clear();
                        }
                        KeyCode::Down => app.select_next(tx.clone()),
                        KeyCode::Up => app.select_previous(tx.clone()),
                        KeyCode::Tab => { app.active_panel = (app.active_panel + 1) % 2; if app.active_panel == 1 && app.details_state.selected().is_none() { app.details_state.select(Some(0)); } }
                        _ => {}
                    }
                }
            }
        }
    }
}

fn draw(f: &mut Frame, app: &mut App) {
    let chunks = Layout::default().direction(Direction::Vertical).constraints([Constraint::Min(3), Constraint::Length(6), Constraint::Length(3)]).split(f.area());
    if app.show_config { render_config_section(f, app, chunks[0]); }
    else {
        let main = Layout::default().direction(Direction::Horizontal).constraints([Constraint::Percentage(40), Constraint::Percentage(60)]).split(chunks[0]);
        render_device_list(f, app, main[0]);
        if app.show_uprober { render_uprober_view(f, app, main[1]); }
        else { render_details_view(f, app, main[1]); }
    }
    
    render_log_view(f, app, chunks[1]);

    if app.is_scanning { 
        let pct = if app.scan_total > 0 { ((app.scan_progress as f32 / app.scan_total as f32) * 100.0) as u16 } else { 0 };
        f.render_widget(Gauge::default().gauge_style(Style::default().fg(Color::Yellow)).percent(pct).label(format!("Scanning: {}/{}", app.scan_progress, app.scan_total)), chunks[1]); 
    }
    render_bottom_bar(f, app, chunks[2]);
}

fn render_bottom_bar(f: &mut Frame, app: &App, area: Rect) {
    match &app.edit_mode {
        EditMode::Input(name, _) => {
            let p = Paragraph::new(format!(" EDITING [{}] > {}_", name, app.temp_input))
                .block(Block::default().borders(Borders::ALL).border_style(Style::default().fg(Color::Yellow)))
                .style(Style::default().bg(Color::Blue).fg(Color::White).add_modifier(Modifier::BOLD));
            f.render_widget(p, area);
        }
        EditMode::ManualAdd => {
            let p = Paragraph::new(format!(" ENTER IP ADDRESS > {}_", app.temp_input))
                .block(Block::default().borders(Borders::ALL).border_style(Style::default().fg(Color::Magenta)))
                .style(Style::default().bg(Color::DarkGray).fg(Color::White).add_modifier(Modifier::BOLD));
            f.render_widget(p, area);
        }
        EditMode::None => {
            let help = if app.show_config { "ENTER: Edit | c: Close | Arrows: Move" } else { "a: Add IP | s: Scan | r: Refresh | c: Config | u: Uprober | q: Quit" };
            f.render_widget(Paragraph::new(format!(" {} | {}", help, app.status)).block(Block::default().borders(Borders::ALL).title("Status Bar")), area);
        }
    }
}

fn render_config_section(f: &mut Frame, app: &App, area: Rect) {
    let proto = match app.config.v3_auth_protocol { AuthProtocol::Md5 => "MD5", AuthProtocol::Sha1 => "SHA1", _ => "OTHER" };
    let cipher = match app.config.v3_cipher { Cipher::Aes128 => "AES", Cipher::Des => "DES", _ => "OTHER" };
    let level = match app.config.v3_level { SecurityLevel::NoAuth => "NoAuth", SecurityLevel::AuthNoPriv => "AuthNoPriv", SecurityLevel::AuthPriv => "AuthPriv" };
    let items = vec![
        ("SNMP Port", app.config.snmp_port.to_string()), 
        ("Timeout (ms)", app.config.timeout_ms.to_string()), 
        ("Concurrency", app.config.concurrency.to_string()), 
        ("V3 Username", app.config.v3_user.clone()), 
        ("V3 Auth Pass", app.config.v3_auth_pass.clone()), 
        ("V3 Priv Pass", app.config.v3_priv_pass.clone()), 
        ("V3 Protocol", proto.to_string()), 
        ("V3 Privacy", cipher.to_string()),
        ("V3 Level", level.to_string()),
        ("V2 Community", app.config.community.clone())
    ];
    let rows: Vec<Row> = items.iter().enumerate().map(|(i, (k, v))| {
        let style = if i == app.selected_config_idx { Style::default().bg(Color::Cyan).fg(Color::Black).add_modifier(Modifier::BOLD) } else { Style::default() };
        Row::new(vec![Cell::from(*k), Cell::from(v.clone())]).style(style)
    }).collect();
    f.render_widget(Table::new(rows, [Constraint::Percentage(40), Constraint::Percentage(60)]).block(Block::default().borders(Borders::ALL).title("--- SETTINGS ---")).header(Row::new(vec!["Parameter", "Value"]).style(Style::default().fg(Color::Yellow))), area);
}

fn render_device_list(f: &mut Frame, app: &mut App, area: Rect) {
    let rows: Vec<Row> = app.discovered_devices.iter().enumerate().map(|(i, d)| {
        let is_selected = Some(i) == app.table_state.selected();
        let style = if is_selected { Style::default().bg(if app.active_panel == 0 { Color::Yellow } else { Color::DarkGray }).fg(Color::Black).add_modifier(Modifier::BOLD) } 
                    else { if d.category == DeviceCategory::UPS { Style::default().fg(Color::Red) } else { Style::default().fg(Color::White) } };
        Row::new(vec![Cell::from(format!("[{}] {}", d.category, d.ip))]).style(style)
    }).collect();
    let block = Block::default()
        .borders(Borders::ALL)
        .title(" Devices Found ")
        .border_style(Style::default().fg(if app.active_panel == 0 { Color::Yellow } else { Color::Gray }));
    let table = Table::new(rows, [Constraint::Percentage(100)]).block(block);
    f.render_stateful_widget(table, area, &mut app.table_state);
}

fn render_details_view(f: &mut Frame, app: &mut App, area: Rect) {
    let rows: Vec<Row> = app.snmp_data.iter().enumerate().map(|(i, (l, v))| {
        let is_selected = Some(i) == app.details_state.selected();
        let style = if is_selected { Style::default().bg(if app.active_panel == 1 { Color::Cyan } else { Color::DarkGray }).fg(Color::Black).add_modifier(Modifier::BOLD) }
                    else { Style::default() };
        Row::new(vec![Cell::from(l.clone()), Cell::from(v.clone())]).style(style)
    }).collect();

    let block = Block::default()
        .borders(Borders::ALL)
        .title(" Live Metrics [Press Tab to Scroll] ")
        .border_style(Style::default().fg(if app.active_panel == 1 { Color::Cyan } else { Color::Gray }));

    let table = Table::new(rows, [Constraint::Percentage(40), Constraint::Percentage(60)])
        .block(block)
        .header(Row::new(vec!["Metric", "Value"]).style(Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)))
        .row_highlight_style(Style::default().add_modifier(Modifier::BOLD));
        
    f.render_stateful_widget(table, area, &mut app.details_state);
}

fn render_uprober_view(f: &mut Frame, app: &App, area: Rect) {
    let mut rows = vec![Row::new(vec![Cell::from("UPS Intelligence Analysis Engine").style(Style::default().fg(Color::Red).add_modifier(Modifier::BOLD))])];
    
    if let Some(dev) = &app.identified_ups {
        rows.push(Row::new(vec![Cell::from(format!("HARDWARE: {} | MODEL: {}", dev.vendor, dev.model)).style(Style::default().fg(Color::Cyan))]));
    }

    if app.is_walking {
        rows.push(Row::new(vec![Cell::from(">> FETCHING LIVE MIB DATA...").style(Style::default().fg(Color::Yellow))]));
    } else if app.snapshot_a.is_some() && app.snapshot_b.is_none() {
        rows.push(Row::new(vec![Cell::from("SNAPSHOT [A] CAPTURED!").style(Style::default().fg(Color::Green))]));
        rows.push(Row::new(vec![Cell::from("=> Press '2' to capture [B] and see dynamic changes").style(Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD))]));
    } else if app.snapshot_b.is_some() {
        rows.push(Row::new(vec![Cell::from("ANALYSIS COMPLETE (A vs B)").style(Style::default().fg(Color::Green))]));
    }

    if !app.diff_results.is_empty() {
        rows.push(Row::new(vec![Cell::from("--- DETECTED CHANGES ---").style(Style::default().fg(Color::Red))]));
        for res in &app.diff_results {
            rows.push(Row::new(vec![Cell::from(format!("• {}: {}", res.change_type, res.new_value)).style(Style::default().fg(Color::Yellow))]));
        }
    } else if let Some(snap) = &app.snapshot_a {
        rows.push(Row::new(vec![Cell::from("--- CURRENT LIVE VALUES ---").style(Style::default().fg(Color::DarkGray))]));
        let mut sorted_keys: Vec<_> = snap.data.keys().collect();
        sorted_keys.sort();
        for k in sorted_keys.iter().take(15) { // Show first 15 values to avoid clutter
            if let Some(v) = snap.data.get(*k) {
                rows.push(Row::new(vec![Cell::from(format!("{}: {}", k, v)).style(Style::default().fg(Color::Gray))]));
            }
        }
    }

    f.render_widget(Table::new(rows, [Constraint::Percentage(100)]).block(Block::default().borders(Borders::ALL).title("Uprober Analytics")), area);
}

fn render_log_view(f: &mut Frame, app: &App, area: Rect) {
    let log_msg = app.logs.join("\n");
    let p = Paragraph::new(log_msg)
        .block(Block::default().borders(Borders::ALL).title("--- SYSTEM LOGS ---"))
        .style(Style::default().fg(Color::DarkGray));
    f.render_widget(p, area);
}

fn clean_snmp_value(oid: &str, val: &snmp2::Value) -> String {
    let raw = match val {
        snmp2::Value::OctetString(b) => String::from_utf8_lossy(b).trim().to_string(),
        snmp2::Value::Integer(i) => i.to_string(),
        snmp2::Value::Counter32(c) => c.to_string(),
        snmp2::Value::Unsigned32(u) => u.to_string(),
        snmp2::Value::ObjectIdentifier(o) => o.to_string(),
        snmp2::Value::Timeticks(t) => {
            let total_seconds = t / 100;
            let hours = total_seconds / 3600;
            let minutes = (total_seconds % 3600) / 60;
            let seconds = total_seconds % 60;
            return format!("{:02}:{:02}:{:02}", hours, minutes, seconds);
        },
        _ => return format!("{:?}", val),
    };

    if raw.is_empty() || raw == "()" || raw == "None" || raw.contains("SUCH") || raw.contains("NULL") { return "".to_string(); }

    // RFC 1628 Output Source mapping
    if oid.ends_with(".1.3.6.1.2.1.33.1.4.1.0") {
        return match raw.as_str() {
            "1" => "Other".to_string(),
            "2" => "None".to_string(),
            "3" => "Normal (On-Line)".to_string(),
            "4" => "Bypass".to_string(),
            "5" => "Battery".to_string(),
            "6" => "Booster".to_string(),
            "7" => "Reducer".to_string(),
            _ => raw,
        };
    }

    // Units formatting (/10)
    let div_10_oids = [
        ".1.3.6.1.4.1.935.10.1.1.2.2.0",       // EPPC Temp
        ".1.3.6.1.4.1.935.10.1.1.2.16.1.3.1", // EPPC Input Volt
        ".1.3.6.1.4.1.935.10.1.1.2.16.1.2.1", // EPPC Input Freq
        ".1.3.6.1.4.1.935.10.1.1.2.5.0",       // EPPC Output Volt
        ".1.3.6.1.4.1.935.10.1.1.2.6.0",       // EPPC Output Freq
        ".1.3.6.1.4.1.935.10.1.1.3.5.0",       // EPPC Battery Volt
        ".1.3.6.1.4.1.935.10.1.1.2.12.0",      // EPPC Load %? (Need to check if it's /10)
        ".1.3.6.1.4.1.318.1.1.1.2.2.2.0",      // APC Temp
        ".1.3.6.1.4.1.318.1.1.1.3.2.1.0", // Input Volt
        ".1.3.6.1.4.1.318.1.1.1.3.2.4.0", // Input Freq
        ".1.3.6.1.4.1.318.1.1.1.4.2.1.0", // Output Volt
        ".1.3.6.1.4.1.318.1.1.1.4.2.2.0", // Output Freq
        ".1.3.6.1.4.1.318.1.1.1.4.2.4.0", // Output Current
        ".1.3.6.1.4.1.318.1.1.1.2.2.8.0", // Battery Volt
    ];

    if div_10_oids.iter().any(|&o| oid.ends_with(o)) {
        if let Ok(v) = raw.parse::<f32>() {
            return format!("{:.1}", v / 10.0);
        }
    }

    // APC Enum mapping
    if oid.ends_with(".1.3.6.1.4.1.318.1.1.1.4.1.1.0") { // Status
        return match raw.as_str() {
            "2" => "Line (On-Line)".to_string(),
            "3" => "On Battery".to_string(),
            "4" => "Boost (On-Line)".to_string(),
            "5" => "Sleeping".to_string(),
            "6" => "Software Bypass".to_string(),
            "7" => "Off".to_string(),
            "8" => "Rebooting".to_string(),
            "9" => "Switched Bypass".to_string(),
            "10" => "Hardware Bypass".to_string(),
            "11" => "SleepingUntilPower".to_string(),
            "12" => "Trim (On-Line)".to_string(),
            _ => raw,
        };
    }

    if oid.ends_with(".1.3.6.1.4.1.318.1.1.1.2.1.1.0") { // Battery Status
        return match raw.as_str() {
            "1" => "Unknown".to_string(),
            "2" => "Battery Normal".to_string(),
            "3" => "Battery Low".to_string(),
            "4" => "In Fault Condition".to_string(),
            _ => raw,
        };
    }

    // Backup Time formatting for APC (it returns Timeticks but sometimes we want custom string)
    if oid.ends_with(".1.3.6.1.4.1.318.1.1.1.2.2.3.0") && oid.contains("318") {
        // PowerNet returns Timeticks natively, clean_snmp_value already formats it as HH:MM:SS above
    }

    raw
}
