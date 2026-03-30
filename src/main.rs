use anyhow::{Result, anyhow};
use crossterm::{
    event::{self, DisableMouseCapture, EnableMouseCapture, Event, KeyCode},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{
    backend::{Backend, CrosstermBackend},
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    widgets::{Block, Borders, Cell, Gauge, Paragraph, Row, Table, TableState, Scrollbar, ScrollbarOrientation, ScrollbarState},
    Frame, Terminal,
};
use snmp2::{SyncSession, Oid};
use snmp2::v3::{Security, Auth, AuthProtocol, Cipher};
use std::{
    io,
    sync::mpsc::{self, Receiver, Sender},
    time::{Duration, Instant},
};
use chrono::Local;

mod ups;
mod device;
use ups::{OidSnapshot, DiffResult, UpsDevice, DefaultUprober};
use device::{DeviceCategory, DeviceInfo};
use network_interface::{NetworkInterface, NetworkInterfaceConfig};

#[derive(PartialEq)]
pub enum EditMode {
    None,
    Community,
    V3User,
    V3Auth,
    V3Priv,
    ConfigValue(usize),
}

pub struct Config {
    pub snmp_port: u16,
    pub trap_port: u16,
    pub timeout_ms: u64,
    pub concurrency: usize,
    pub probe_ports: Vec<u16>,
    pub custom_communities: Vec<String>,
    pub v3_auth_protocol: AuthProtocol, // ADDED
}

impl Default for Config {
    fn default() -> Self {
        Self {
            snmp_port: 161,
            trap_port: 162,
            timeout_ms: 1500,
            concurrency: 60,
            probe_ports: vec![80, 443, 445, 22],
            custom_communities: vec!["public".to_string(), "private".to_string(), "ERXUPS".to_string()],
            v3_auth_protocol: AuthProtocol::Sha1,
        }
    }
}

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
    pub community: String,
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

    // SNMP v3 Fields
    pub v3_enabled: bool,
    pub v3_user: String,
    pub v3_auth_pass: String,
    pub v3_priv_pass: String,
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
            community: "public".to_string(),
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
            v3_enabled: false,
            v3_user: String::new(),
            v3_auth_pass: String::new(),
            v3_priv_pass: String::new(),
        }
    }

    fn select_next(&mut self, tx: Sender<ScanMessage>) {
        if self.show_config {
            self.selected_config_idx = (self.selected_config_idx + 1) % 9; // UPDATED
            return;
        }
        if self.discovered_devices.is_empty() { return; }
        let i = match self.table_state.selected() {
            Some(i) => if i >= self.discovered_devices.len() - 1 { 0 } else { i + 1 },
            None => 0,
        };
        self.table_state.select(Some(i));
        self.selected_index = i;
        self.identified_ups = None;
        self.start_snmp_update(tx);
    }

    fn select_previous(&mut self, tx: Sender<ScanMessage>) {
        if self.show_config {
            self.selected_config_idx = if self.selected_config_idx == 0 { 8 } else { self.selected_config_idx - 1 };
            return;
        }
        if self.discovered_devices.is_empty() { return; }
        let i = match self.table_state.selected() {
            Some(i) => if i == 0 { self.discovered_devices.len() - 1 } else { i - 1 },
            None => 0,
        };
        self.table_state.select(Some(i));
        self.selected_index = i;
        self.identified_ups = None;
        self.start_snmp_update(tx);
    }

    fn start_snmp_update(&mut self, tx: Sender<ScanMessage>) {
        if self.discovered_devices.is_empty() { return; }
        self.snmp_data.clear();
        let ip = self.discovered_devices[self.selected_index].ip.clone();
        let community = self.community.clone();
        
        let v3_enabled = self.v3_enabled;
        let v3_user = self.v3_user.clone();
        let v3_auth = self.v3_auth_pass.clone();
        let v3_priv = self.v3_priv_pass.clone();
        let auth_proto = self.config.v3_auth_protocol; // USE CONFIG
        let snmp_port = self.config.snmp_port;
        let timeout = Duration::from_millis(self.config.timeout_ms);

        tokio::spawn(async move {
            let agent_addr = format!("{}:{}", ip, snmp_port);
            let oids = [
                (".1.3.6.1.2.1.1.1.0", "System Description"),
                (".1.3.6.1.2.1.1.3.0", "System Uptime"),
                (".1.3.6.1.2.1.1.5.0", "System Name"),
                (".1.3.6.1.2.1.1.6.0", "System Location"),
            ];

            let mut results = Vec::new();

            // Try SNMP v3 
            if v3_enabled {
                let security = Security::new(v3_user.as_bytes(), v3_auth.as_bytes())
                    .with_auth_protocol(auth_proto)
                    .with_auth(Auth::AuthPriv {
                        cipher: Cipher::Aes128,
                        privacy_password: v3_priv.as_bytes().to_vec(),
                    });
                
                if let Ok(mut session) = SyncSession::new_v3(&agent_addr, Some(timeout), 2, security) {
                    for (oid_str, label) in oids.iter() {
                        let parts: Vec<u64> = oid_str.split('.').filter(|s| !s.is_empty()).map(|s| s.parse::<u64>().unwrap_or(0)).collect();
                        if let Ok(oid) = Oid::from(&parts[..]) {
                            if let Ok(response) = session.get(&oid) {
                                if let Some(varbind) = response.varbinds.into_iter().next() {
                                    results.push((label.to_string(), format!("{:?}", varbind.1)));
                                }
                            }
                        }
                    }
                }
            }

            // Fallback v2c/v1
            if results.is_empty() {
                if let Ok(mut session) = SyncSession::new_v2c(&agent_addr, community.as_bytes(), Some(timeout), 2) {
                    for (oid_str, label) in oids.iter() {
                        let parts: Vec<u64> = oid_str.split('.').filter(|s| !s.is_empty()).map(|s| s.parse::<u64>().unwrap_or(0)).collect();
                        if let Ok(oid) = Oid::from(&parts[..]) {
                            if let Ok(response) = session.get(&oid) {
                                if let Some(varbind) = response.varbinds.into_iter().next() {
                                    results.push((label.to_string(), format!("{:?}", varbind.1)));
                                }
                            }
                        }
                    }
                }
            }
            if results.is_empty() {
                if let Ok(mut session) = SyncSession::new_v1(&agent_addr, community.as_bytes(), Some(timeout), 2) {
                    for (oid_str, label) in oids.iter() {
                        let parts: Vec<u64> = oid_str.split('.').filter(|s| !s.is_empty()).map(|s| s.parse::<u64>().unwrap_or(0)).collect();
                        if let Ok(oid) = Oid::from(&parts[..]) {
                            if let Ok(response) = session.get(&oid) {
                                if let Some(varbind) = response.varbinds.into_iter().next() {
                                    results.push((label.to_string(), format!("{:?}", varbind.1)));
                                }
                            }
                        }
                    }
                }
            }

            if !results.is_empty() {
                let _ = tx.send(ScanMessage::MetricUpdated(results));
            } else {
                let _ = tx.send(ScanMessage::Status("No response (timeout)".to_string()));
            }
        });
    }

    fn trigger_ups_identification(&mut self, tx: Sender<ScanMessage>) {
        if self.discovered_devices.is_empty() { return; }
        self.identified_ups = None;
        let ip = self.discovered_devices[self.selected_index].ip.clone();
        let community = self.community.clone();
        let port = self.config.snmp_port;
        tokio::spawn(async move {
            let addr = format!("{}:{}", ip, port);
            if let Ok(Some(device)) = ups::identify_ups(&addr, &community).await {
                let _ = tx.send(ScanMessage::UpsIdentified(device));
            }
        });
    }

    fn start_scan(&mut self, tx: Sender<ScanMessage>) {
        if self.is_scanning { return; }
        self.is_scanning = true;
        self.discovered_devices.clear();
        self.discovered_ips.clear();
        self.table_state.select(Some(0));
        self.selected_index = 0;
        self.scan_progress = 0;
        self.scan_total = 0;
        let community = self.community.clone();
        let v3_enabled = self.v3_enabled;
        let v3_user = self.v3_user.clone();
        let v3_auth = self.v3_auth_pass.clone();
        let v3_priv = self.v3_priv_pass.clone();
        let auth_proto = self.config.v3_auth_protocol;
        let snmp_port = self.config.snmp_port;
        let timeout_ms = self.config.timeout_ms;
        let concurrency = self.config.concurrency;
        let probe_ports = self.config.probe_ports.clone();
        
        self.status = "Discovering...".to_string();
        
        tokio::spawn(async move {
            let interfaces = NetworkInterface::show().unwrap_or_default();
            let mut scan_targets = Vec::new();
            for iface in interfaces {
                for addr in iface.addr {
                    if let std::net::IpAddr::V4(ipv4) = addr.ip() {
                        if !ipv4.is_loopback() {
                            let ip_str = ipv4.to_string();
                            if let Some((prefix, _)) = ip_str.rsplit_once('.') {
                                if !scan_targets.contains(&prefix.to_string()) { scan_targets.push(prefix.to_string()); }
                            }
                        }
                    }
                }
            }

            if scan_targets.is_empty() {
                let _ = tx.send(ScanMessage::Status("No active network".to_string()));
                return;
            }

            let total_ips = (scan_targets.len() * 254) as u32;
            let semaphore = std::sync::Arc::new(tokio::sync::Semaphore::new(concurrency));
            for subnet_prefix in scan_targets {
                let prefix_clone = subnet_prefix.clone();
                let tx_status = tx.clone();
                let _ = tx_status.send(ScanMessage::Status(format!("Scanning {}.x...", prefix_clone)));

                for i in 1..=254 {
                    let ip = format!("{}.{}", subnet_prefix, i);
                    let community = community.clone();
                    let tx = tx.clone();
                    let sem_clone = semaphore.clone();
                    let probe_ports = probe_ports.clone();
                    
                    let v3_cfg = (v3_enabled, v3_user.clone(), v3_auth.clone(), v3_priv.clone(), auth_proto);

                    tokio::spawn(async move {
                        let _permit = sem_clone.acquire().await.unwrap();
                        let agent_addr = format!("{}:{}", ip, snmp_port);
                        let ip_clone = ip.clone();
                        let result = tokio::task::spawn_blocking(move || {
                            let sys_descr_oid = Oid::from(&[1, 3, 6, 1, 2, 1, 1, 1, 0]).unwrap();
                            let timeout = Duration::from_millis(timeout_ms);
                            let mut snmp_res = None;
                            
                            // v3
                            if v3_cfg.0 {
                                let security = Security::new(v3_cfg.1.as_bytes(), v3_cfg.2.as_bytes())
                                    .with_auth_protocol(v3_cfg.4)
                                    .with_auth(Auth::AuthPriv {
                                        cipher: Cipher::Aes128,
                                        privacy_password: v3_cfg.3.as_bytes().to_vec(),
                                    });
                                if let Ok(mut session) = SyncSession::new_v3(&agent_addr, Some(timeout), 1, security) {
                                    if let Ok(resp) = session.get(&sys_descr_oid) {
                                        if let Some(vb) = resp.varbinds.into_iter().next() {
                                            let desc = format!("{:?}", vb.1);
                                            snmp_res = Some((device::identify_category(&desc, ""), desc));
                                        }
                                    }
                                }
                            }
                            // v2c fallback
                            if snmp_res.is_none() {
                                if let Ok(mut session) = SyncSession::new_v2c(&agent_addr, community.as_bytes(), Some(timeout), 1) {
                                    if let Ok(resp) = session.get(&sys_descr_oid) {
                                        if let Some(vb) = resp.varbinds.into_iter().next() {
                                            let desc = format!("{:?}", vb.1);
                                            snmp_res = Some((device::identify_category(&desc, ""), desc));
                                        }
                                    }
                                }
                            }
                            if let Some(res) = snmp_res { return Some(res); }
                            
                            // Ports
                            for port in probe_ports {
                                let addr = format!("{}:{}", ip_clone, port);
                                if let Ok(stream) = std::net::TcpStream::connect_timeout(&addr.parse().ok()?, Duration::from_millis(150)) {
                                    drop(stream);
                                    let cat = match port {
                                        80 | 443 | 445 => DeviceCategory::WebDevice,
                                        _ => DeviceCategory::Unknown,
                                    };
                                    return Some((cat, format!("Port {} Open", port)));
                                }
                            }
                            None
                        }).await.unwrap_or(None);
                        if let Some((cat, desc)) = result {
                            let info = DeviceInfo { ip: ip.to_string(), category: cat, _description: desc, _sys_name: "".to_string() };
                            let _ = tx.send(ScanMessage::Discovered(info));
                        }
                        let _ = tx.send(ScanMessage::Progress(1, total_ips));
                    });
                }
            }
        });
    }

    fn start_community_guess(&mut self, tx: Sender<ScanMessage>) {
        if self.discovered_devices.is_empty() { return; }
        let ip = self.discovered_devices[self.selected_index].ip.clone();
        let snmp_port = self.config.snmp_port;
        let timeout = Duration::from_millis(self.config.timeout_ms);
        let communities = self.config.custom_communities.clone();
        self.status = format!("Guessing {}...", ip);
        tokio::spawn(async move {
            let addr = format!("{}:{}", ip, snmp_port);
            let oid = Oid::from(&[1, 3, 6, 1, 2, 1, 1, 1, 0]).unwrap();
            for community in communities {
                if let Ok(mut session) = SyncSession::new_v2c(&addr, community.as_bytes(), Some(timeout), 1) {
                    if session.get(&oid).is_ok() { let _ = tx.send(ScanMessage::CommunityGuessed(community.to_string())); return; }
                }
            }
            let _ = tx.send(ScanMessage::Status("Guessing failed".to_string()));
        });
    }

    fn start_ups_walk(&mut self, is_second: bool, tx: Sender<ScanMessage>) {
        if self.discovered_devices.is_empty() { return; }
        if self.is_walking { return; }
        self.is_walking = true;
        let ip = self.discovered_devices[self.selected_index].ip.clone();
        let community = self.community.clone();
        tokio::spawn(async move {
            let root_oid = [1, 3, 6, 1, 2, 1];
            let addr = format!("{}:161", ip);
            if let Ok(data) = ups::snmp_walk(&addr, &community, &root_oid).await {
                let snapshot = OidSnapshot { _timestamp: Instant::now(), data };
                let _ = tx.send(ScanMessage::UpsResult(snapshot, is_second));
            } else { let _ = tx.send(ScanMessage::Status("Walk failed".to_string())); }
        });
    }
}

pub enum ScanMessage {
    Progress(u32, u32),
    Discovered(DeviceInfo),
    Status(String),
    UpsResult(OidSnapshot, bool),
    UpsIdentified(UpsDevice),
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

async fn run_app<B: Backend>(terminal: &mut Terminal<B>, app: &mut App, tx: Sender<ScanMessage>, rx: Receiver<ScanMessage>) -> Result<()> {
    loop {
        while let Ok(msg) = rx.try_recv() {
            match msg {
                ScanMessage::Progress(delta, total) => {
                    app.scan_progress += delta;
                    app.scan_total = total;
                    if app.scan_progress >= total { app.is_scanning = false; app.status = "Scan done".to_string(); }
                }
                ScanMessage::Discovered(info) => { if !app.discovered_ips.contains(&info.ip) { app.discovered_ips.push(info.ip.clone()); app.discovered_devices.push(info); } }
                ScanMessage::Status(s) => app.status = s,
                ScanMessage::UpsResult(snapshot, is_second) => {
                    app.is_walking = false;
                    if is_second { 
                        app.snapshot_b = Some(snapshot); 
                        if let (Some(a), Some(b)) = (&app.snapshot_a, &app.snapshot_b) {
                            let prober = DefaultUprober;
                            app.diff_results = ups::diff_snapshots(a, b, &prober);
                            app.status = format!("Analysis Complete ({} diffs)", app.diff_results.len());
                        }
                    } else { app.snapshot_a = Some(snapshot); app.status = "Snapshot A OK".to_string(); }
                }
                ScanMessage::UpsIdentified(device) => app.identified_ups = Some(device),
                ScanMessage::MetricUpdated(data) => {
                    app.snmp_data = data;
                    app.status = format!("Updated {}", Local::now().format("%H:%M:%S"));
                }
                ScanMessage::CommunityGuessed(comm) => { app.community = comm; app.status = "FOUND!".to_string(); app.start_snmp_update(tx.clone()); }
            }
        }
        terminal.draw(|f| draw(f, app)).map_err(|e| anyhow!("Draw error: {:?}", e))?;
        if event::poll(Duration::from_millis(100))? {
            if let Event::Key(key) = event::read()? {
                if let EditMode::ConfigValue(idx) = app.edit_mode {
                    match key.code {
                        KeyCode::Enter => {
                            match idx {
                                0 => if let Ok(v) = app.temp_input.parse() { app.config.snmp_port = v; },
                                1 => if let Ok(v) = app.temp_input.parse() { app.config.trap_port = v; },
                                2 => if let Ok(v) = app.temp_input.parse() { app.config.timeout_ms = v; },
                                3 => if let Ok(v) = app.temp_input.parse() { app.config.concurrency = v; },
                                4 => app.community = app.temp_input.clone(),
                                5 => app.v3_user = app.temp_input.clone(),
                                6 => app.v3_auth_pass = app.temp_input.clone(),
                                7 => app.v3_priv_pass = app.temp_input.clone(),
                                8 => {
                                    if app.temp_input.to_uppercase() == "MD5" { app.config.v3_auth_protocol = AuthProtocol::Md5; }
                                    else if app.temp_input.to_uppercase() == "SHA" || app.temp_input.to_uppercase() == "SHA1" { app.config.v3_auth_protocol = AuthProtocol::Sha1; }
                                }
                                _ => {}
                            }
                            app.edit_mode = EditMode::None;
                        }
                        KeyCode::Esc => app.edit_mode = EditMode::None,
                        KeyCode::Char(c) => app.temp_input.push(c),
                        KeyCode::Backspace => { app.temp_input.pop(); },
                        _ => {}
                    }
                } else if app.edit_mode != EditMode::None {
                    match key.code {
                        KeyCode::Enter => {
                            match app.edit_mode {
                                EditMode::Community => app.community = app.temp_input.clone(),
                                EditMode::V3User => app.v3_user = app.temp_input.clone(),
                                EditMode::V3Auth => app.v3_auth_pass = app.temp_input.clone(),
                                EditMode::V3Priv => app.v3_priv_pass = app.temp_input.clone(),
                                _ => {}
                            }
                            app.edit_mode = EditMode::None;
                        }
                        KeyCode::Esc => app.edit_mode = EditMode::None,
                        KeyCode::Char(c) => app.temp_input.push(c),
                        KeyCode::Backspace => { app.temp_input.pop(); },
                        _ => {}
                    }
                } else {
                    match key.code {
                        KeyCode::Char('q') => return Ok(()),
                        KeyCode::Char('s') => app.start_scan(tx.clone()),
                        KeyCode::Char('g') => app.start_community_guess(tx.clone()),
                        KeyCode::Char('r') => { app.start_snmp_update(tx.clone()); app.trigger_ups_identification(tx.clone()); }
                        KeyCode::Char('u') => {
                            app.show_uprober = !app.show_uprober;
                            if app.show_uprober {
                                app.snapshot_a = None;
                                app.snapshot_b = None;
                                app.start_ups_walk(false, tx.clone());
                            }
                        }
                        KeyCode::Char('c') => app.show_config = !app.show_config,
                        KeyCode::Char('i') => { app.edit_mode = EditMode::Community; app.temp_input = app.community.clone(); }
                        KeyCode::Char('v') => app.v3_enabled = !app.v3_enabled,
                        KeyCode::Char('U') => { app.edit_mode = EditMode::V3User; app.temp_input = app.v3_user.clone(); }
                        KeyCode::Char('A') => { app.edit_mode = EditMode::V3Auth; app.temp_input = app.v3_auth_pass.clone(); }
                        KeyCode::Char('P') => { app.edit_mode = EditMode::V3Priv; app.temp_input = app.v3_priv_pass.clone(); }
                        KeyCode::Enter => if app.show_config { app.edit_mode = EditMode::ConfigValue(app.selected_config_idx); app.temp_input = "".to_string(); }
                        KeyCode::Down => app.select_next(tx.clone()),
                        KeyCode::Up => app.select_previous(tx.clone()),
                        _ => {}
                    }
                }
            }
        }
    }
}

fn draw(f: &mut Frame, app: &mut App) {
    if app.show_config {
        render_config_page(f, app, f.area());
        return;
    }
    let chunks = Layout::default().direction(Direction::Vertical).constraints([Constraint::Min(3), Constraint::Length(1), Constraint::Length(3)]).split(f.area());
    let main_chunk = Layout::default().direction(Direction::Horizontal).constraints([Constraint::Percentage(35), Constraint::Percentage(65)]).split(chunks[0]);
    render_device_list(f, app, main_chunk[0]);
    if app.show_uprober {
        render_uprober_view(f, app, main_chunk[1]);
    } else {
        render_details(f, app, main_chunk[1]);
    }
    if app.is_scanning {
        let p = if app.scan_total > 0 { ((app.scan_progress as f32 / app.scan_total as f32) * 100.0) as u16 } else { 0 };
        f.render_widget(Gauge::default().gauge_style(Style::default().fg(Color::Yellow)).percent(p), chunks[1]);
    }
    render_status(f, app, chunks[2]);
    if let EditMode::ConfigValue(idx) = app.edit_mode {
        let area = centered_rect(60, 20, f.area());
        let help = match idx {
            8 => "Type 'MD5' or 'SHA' to change protocol",
            _ => "Enter New Value",
        };
        let input = Paragraph::new(app.temp_input.as_str()).block(Block::default().borders(Borders::ALL).title(help)).style(Style::default().fg(Color::Yellow));
        f.render_widget(ratatui::widgets::Clear, area);
        f.render_widget(input, area);
    } else if app.edit_mode != EditMode::None {
        let area = centered_rect(60, 20, f.area());
        let input = Paragraph::new(app.temp_input.as_str()).block(Block::default().borders(Borders::ALL).title("Input")).style(Style::default().fg(Color::Yellow));
        f.render_widget(ratatui::widgets::Clear, area);
        f.render_widget(input, area);
    }
}

fn render_config_page(f: &mut Frame, app: &App, area: Rect) {
    let auth_str = match app.config.v3_auth_protocol { AuthProtocol::Md5 => "MD5", AuthProtocol::Sha1 => "SHA1", _ => "OTHER" };
    let items = vec![
        ("SNMP Port", app.config.snmp_port.to_string()),
        ("Trap Port", app.config.trap_port.to_string()),
        ("Timeout (ms)", app.config.timeout_ms.to_string()),
        ("Concurrency", app.config.concurrency.to_string()),
        ("SNMP Community", app.community.clone()),
        ("V3 Username", app.v3_user.clone()),
        ("V3 Auth Pass", app.v3_auth_pass.clone()),
        ("V3 Priv Pass", app.v3_priv_pass.clone()),
        ("V3 Auth Proto", auth_str.to_string()), // NEW
    ];

    let rows: Vec<Row> = items.iter().enumerate().map(|(i, (k, v))| {
        let style = if i == app.selected_config_idx { Style::default().fg(Color::Black).bg(Color::Cyan).add_modifier(Modifier::BOLD) } else { Style::default() };
        Row::new(vec![Cell::from(*k), Cell::from(v.clone())]).style(style)
    }).collect();

    let table = Table::new(rows, [Constraint::Percentage(50), Constraint::Percentage(50)])
        .block(Block::default().borders(Borders::ALL).title("Config Center - Select Protocol with Enter and type MD5 or SHA"))
        .header(Row::new(vec!["Setting", "Value"]).style(Style::default().fg(Color::Yellow)));

    f.render_widget(table, area);
}

fn centered_rect(px: u16, py: u16, r: Rect) -> Rect {
    let popup = Layout::default().direction(Direction::Vertical).constraints([Constraint::Percentage((100 - py) / 2), Constraint::Percentage(py), Constraint::Percentage((100 - py) / 2)]).split(r);
    Layout::default().direction(Direction::Horizontal).constraints([Constraint::Percentage((100 - px) / 2), Constraint::Percentage(px), Constraint::Percentage((100 - px) / 2)]).split(popup[1])[1]
}

fn render_device_list(f: &mut Frame, app: &mut App, area: Rect) {
    let rows: Vec<Row> = app.discovered_devices.iter().enumerate().map(|(_, d)| {
        let color = match d.category { DeviceCategory::UPS => Color::LightRed, DeviceCategory::RouterSwitch => Color::Cyan, DeviceCategory::Printer => Color::Green, DeviceCategory::NAS => Color::Yellow, _ => Color::White };
        Row::new(vec![Cell::from(format!("{} {}", d.category, d.ip))]).style(Style::default().fg(color))
    }).collect();

    let table = Table::new(rows, [Constraint::Percentage(100)])
        .block(Block::default().borders(Borders::ALL).title("Network Map"))
        .row_highlight_style(Style::default().fg(Color::Black).bg(Color::Yellow).add_modifier(Modifier::BOLD))
        .highlight_symbol(">> ");

    f.render_stateful_widget(table, area, &mut app.table_state);

    let scrollbar = Scrollbar::default()
        .orientation(ScrollbarOrientation::VerticalRight)
        .begin_symbol(Some("↑"))
        .end_symbol(Some("↓"));
    let mut scrollbar_state = ScrollbarState::new(app.discovered_devices.len()).position(app.table_state.selected().unwrap_or(0));
    f.render_stateful_widget(scrollbar, area, &mut scrollbar_state);
}

fn render_details(f: &mut Frame, app: &mut App, area: Rect) {
    let rows: Vec<Row> = app.snmp_data.iter().map(|(l, v)| Row::new(vec![Cell::from(l.clone()).style(Style::default().add_modifier(Modifier::BOLD)), Cell::from(v.clone())])).collect();
    let title = if app.v3_enabled { format!("Details [V3: {}]", app.v3_user) } else { format!("Details [Comm: {}]", app.community) };
    
    let table = Table::new(rows, [Constraint::Percentage(40), Constraint::Percentage(60)])
        .header(Row::new(vec!["Metric", "Value"]).style(Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)))
        .block(Block::default().borders(Borders::ALL).title(title))
        .row_highlight_style(Style::default().bg(Color::DarkGray));

    f.render_stateful_widget(table, area, &mut app.details_state);

    let scrollbar = Scrollbar::default()
        .orientation(ScrollbarOrientation::VerticalRight);
    let mut scrollbar_state = ScrollbarState::new(app.snmp_data.len()).position(app.details_state.selected().unwrap_or(0));
    f.render_stateful_widget(scrollbar, area, &mut scrollbar_state);
}

fn render_uprober_view(f: &mut Frame, app: &App, area: Rect) {
    let mut text = vec![
        Row::new(vec![Cell::from("UPS Intelligence Prober").style(Style::default().fg(Color::Red).add_modifier(Modifier::BOLD))]),
        Row::new(vec![Cell::from("-------------------------")]),
    ];
    if let Some(device) = &app.identified_ups {
        text.push(Row::new(vec![Cell::from(format!("Vendor: {}", device.vendor))]));
        text.push(Row::new(vec![Cell::from(format!("Model:  {}", device.model))]));
    }
    for res in &app.diff_results {
        text.push(Row::new(vec![Cell::from(format!("• {}: {} -> {}", res.change_type, res.old_value, res.new_value))]));
    }
    f.render_widget(Table::new(text, [Constraint::Percentage(100)]).block(Block::default().borders(Borders::ALL).title("UPS Analysis Mode")), area);
}

fn render_status(f: &mut Frame, app: &App, area: Rect) {
    let mut help = if app.v3_enabled { "[V3 ACTIVE] i: set comm | v: v2c mode | U/A/P: config".to_string() } else { "[v2c mode] i: set comm | v: v3 mode | g: guess".to_string() };
    help.push_str(" | s: scan | r: refresh | c: config | u: prober | Arrows: select | q: quit");
    f.render_widget(Paragraph::new(help).block(Block::default().borders(Borders::ALL).title(format!("Controls | {}", app.status))), area);
}
