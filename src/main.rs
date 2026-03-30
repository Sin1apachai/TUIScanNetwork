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

mod ups;
mod device;
use ups::{OidSnapshot, DiffResult, UpsDevice, DefaultUprober};
use device::{DeviceCategory, DeviceInfo};
use network_interface::{NetworkInterface, NetworkInterfaceConfig};

#[derive(PartialEq)]
pub enum EditMode {
    None,
    Input(String, usize),
}

pub struct Config {
    pub snmp_port: u16,
    pub timeout_ms: u64,
    pub concurrency: usize,
    pub v3_user: String,
    pub v3_auth_pass: String,
    pub v3_priv_pass: String,
    pub v3_auth_protocol: AuthProtocol,
    pub community: String,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            snmp_port: 161,
            timeout_ms: 2000,
            concurrency: 60,
            v3_user: String::new(),
            v3_auth_pass: String::new(),
            v3_priv_pass: String::new(),
            v3_auth_protocol: AuthProtocol::Md5,
            community: "public".to_string(),
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
        }
    }

    fn select_next(&mut self, tx: Sender<ScanMessage>) {
        if self.show_config { self.selected_config_idx = (self.selected_config_idx + 1) % 8; return; }
        if self.discovered_devices.is_empty() { return; }
        let i = match self.table_state.selected() {
            Some(i) => if i >= self.discovered_devices.len() - 1 { 0 } else { i + 1 },
            None => 0,
        };
        self.table_state.select(Some(i));
        self.selected_index = i;
        self.start_snmp_update(tx);
    }

    fn select_previous(&mut self, tx: Sender<ScanMessage>) {
        if self.show_config { self.selected_config_idx = if self.selected_config_idx == 0 { 7 } else { self.selected_config_idx - 1 }; return; }
        if self.discovered_devices.is_empty() { return; }
        let i = match self.table_state.selected() {
            Some(i) => if i == 0 { self.discovered_devices.len() - 1 } else { i - 1 },
            None => 0,
        };
        self.table_state.select(Some(i));
        self.selected_index = i;
        self.start_snmp_update(tx);
    }

    fn start_snmp_update(&mut self, tx: Sender<ScanMessage>) {
        if self.discovered_devices.is_empty() { return; }
        self.snmp_data.clear();
        let ip = self.discovered_devices[self.selected_index].ip.clone();
        let cfg = (self.config.v3_user.clone(), self.config.v3_auth_pass.clone(), self.config.v3_priv_pass.clone(), self.config.v3_auth_protocol, self.config.community.clone(), self.config.snmp_port, self.config.timeout_ms);

        tokio::spawn(async move {
            let agent_addr = format!("{}:{}", ip, cfg.5);
            let timeout = Duration::from_millis(cfg.6);
            let oids = [(".1.3.6.1.2.1.1.1.0", "Desc"), (".1.3.6.1.2.1.1.3.0", "Up"), (".1.3.6.1.2.1.1.5.0", "Name"), (".1.3.6.1.2.1.1.6.0", "Location")];
            let mut results = Vec::new();

            if !cfg.0.is_empty() {
                let security = Security::new(cfg.0.as_bytes(), cfg.1.as_bytes()).with_auth_protocol(cfg.3).with_auth(Auth::AuthPriv { cipher: Cipher::Aes128, privacy_password: cfg.2.as_bytes().to_vec() });
                if let Ok(mut session) = SyncSession::new_v3(&agent_addr, Some(timeout), 2, security) {
                    for (oid_str, label) in oids.iter() {
                        let parts: Vec<u64> = oid_str.split('.').filter(|s| !s.is_empty()).map(|s| s.parse::<u64>().unwrap_or(0)).collect();
                        if let Ok(oid) = Oid::from(&parts[..]) {
                            if let Ok(resp) = session.get(&oid) { if let Some(vb) = resp.varbinds.into_iter().next() { results.push((label.to_string(), clean_snmp_value(&vb.1))); } }
                        }
                    }
                }
            }

            if results.is_empty() {
                if let Ok(mut session) = SyncSession::new_v2c(&agent_addr, cfg.4.as_bytes(), Some(timeout), 2) {
                    for (oid_str, label) in oids.iter() {
                        let parts: Vec<u64> = oid_str.split('.').filter(|s| !s.is_empty()).map(|s| s.parse::<u64>().unwrap_or(0)).collect();
                        if let Ok(oid) = Oid::from(&parts[..]) {
                            if let Ok(resp) = session.get(&oid) { if let Some(vb) = resp.varbinds.into_iter().next() { results.push((label.to_string(), clean_snmp_value(&vb.1))); } }
                        }
                    }
                }
            }

            if !results.is_empty() { let _ = tx.send(ScanMessage::MetricUpdated(results)); }

            // Step 2: Identification (Supports V3)
            let dev_res = if !cfg.0.is_empty() { 
                ups::identify_ups_v3(&agent_addr, &cfg.0, &cfg.1, &cfg.2, cfg.3).await 
            } else { 
                ups::identify_ups_v2(&agent_addr, &cfg.4).await 
            };
            if let Ok(Some(dev)) = dev_res { let _ = tx.send(ScanMessage::UpsIdentified(dev)); }
        });
    }

    fn start_scan(&mut self, tx: Sender<ScanMessage>) {
        if self.is_scanning { return; }
        self.is_scanning = true;
        self.discovered_devices.clear();
        self.discovered_ips.clear();
        self.scan_progress = 0;
        self.status = "Discovery in progress...".to_string();
        
        let cfg = (self.config.v3_user.clone(), self.config.v3_auth_pass.clone(), self.config.v3_priv_pass.clone(), self.config.v3_auth_protocol, self.config.community.clone(), self.config.snmp_port, self.config.timeout_ms, self.config.concurrency);
        
        tokio::spawn(async move {
            let interfaces = NetworkInterface::show().unwrap_or_default();
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
                            if !cfg.0.is_empty() {
                                let security = Security::new(cfg.0.as_bytes(), cfg.1.as_bytes()).with_auth_protocol(cfg.3).with_auth(Auth::AuthPriv { cipher: Cipher::Aes128, privacy_password: cfg.2.as_bytes().to_vec() });
                                if let Ok(mut session) = SyncSession::new_v3(&agent_addr, Some(timeout), 2, security) {
                                    if let Ok(resp) = session.get(&oid) { if let Some(vb) = resp.varbinds.into_iter().next() { return Some(clean_snmp_value(&vb.1)); } }
                                }
                            }
                            // 2. Try SNMP V2c
                            if let Ok(mut session) = SyncSession::new_v2c(&agent_addr, cfg.4.as_bytes(), Some(timeout), 2) {
                                if let Ok(resp) = session.get(&oid) { if let Some(vb) = resp.varbinds.into_iter().next() { return Some(clean_snmp_value(&vb.1)); } }
                            }
                            // 3. Port Scan Fallback (Web)
                            for port in [80, 443] {
                                if std::net::TcpStream::connect_timeout(&format!("{}:{}", ip_clone, port).parse().ok()?, Duration::from_millis(500)).is_ok() { 
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
        
        tokio::spawn(async move {
            let addr = format!("{}:161", ip);
            let root = [1, 3, 6, 1, 2, 1];
            let res = if !cfg.0.is_empty() {
                ups::snmp_walk_v3(&addr, &cfg.0, &cfg.1, &cfg.2, cfg.3, &root).await
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
    UpsIdentified(UpsDevice),
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
                ScanMessage::Status(s) => app.status = s,
                ScanMessage::MetricUpdated(data) => { app.snmp_data = data; app.status = "Metrics Updated".to_string(); }
                ScanMessage::UpsIdentified(dev) => app.identified_ups = Some(dev),
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
                if let EditMode::Input(_name, idx) = &app.edit_mode {
                    let idx_clone = *idx;
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
                                7 => app.config.community = app.temp_input.clone(),
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
                } else {
                    match key.code {
                        KeyCode::Char('q') => return Ok(()),
                        KeyCode::Char('s') => app.start_scan(tx.clone()),
                        KeyCode::Char('r') => app.start_snmp_update(tx.clone()),
                        KeyCode::Char('c') => app.show_config = !app.show_config,
                        KeyCode::Char('u') => { app.show_uprober = !app.show_uprober; if app.show_uprober { app.snapshot_a = None; app.snapshot_b = None; app.diff_results.clear(); app.start_ups_walk(false, tx.clone()); } }
                        KeyCode::Char('2') => if app.show_uprober { app.start_ups_walk(true, tx.clone()); }
                        KeyCode::Enter => if app.show_config {
                            let fields = ["SNMP Port", "Timeout", "Concurrency", "V3 User", "V3 Auth Pass", "V3 Priv Pass", "V3 Proto (MD5/SHA)", "V2 Community"];
                            app.edit_mode = EditMode::Input(fields[app.selected_config_idx].to_string(), app.selected_config_idx);
                            app.temp_input.clear();
                        }
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
    let chunks = Layout::default().direction(Direction::Vertical).constraints([Constraint::Min(3), Constraint::Length(1), Constraint::Length(3)]).split(f.area());
    if app.show_config { render_config_section(f, app, chunks[0]); }
    else {
        let main = Layout::default().direction(Direction::Horizontal).constraints([Constraint::Percentage(40), Constraint::Percentage(60)]).split(chunks[0]);
        render_device_list(f, app, main[0]);
        if app.show_uprober { render_uprober_view(f, app, main[1]); }
        else { render_details_view(f, app, main[1]); }
    }
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
        EditMode::None => {
            let help = if app.show_config { "ENTER: Edit | c: Close | Arrows: Move" } else { "s: Scan | r: Refresh | c: Config | u: Uprober | q: Quit" };
            f.render_widget(Paragraph::new(format!(" {} | {}", help, app.status)).block(Block::default().borders(Borders::ALL).title("Status Bar")), area);
        }
    }
}

fn render_config_section(f: &mut Frame, app: &App, area: Rect) {
    let proto = match app.config.v3_auth_protocol { AuthProtocol::Md5 => "MD5", AuthProtocol::Sha1 => "SHA1", _ => "OTHER" };
    let items = vec![("SNMP Port", app.config.snmp_port.to_string()), ("Timeout (ms)", app.config.timeout_ms.to_string()), ("Concurrency", app.config.concurrency.to_string()), ("V3 Username", app.config.v3_user.clone()), ("V3 Auth Pass", app.config.v3_auth_pass.clone()), ("V3 Priv Pass", app.config.v3_priv_pass.clone()), ("V3 Protocol", proto.to_string()), ("V2 Community", app.config.community.clone())];
    let rows: Vec<Row> = items.iter().enumerate().map(|(i, (k, v))| {
        let style = if i == app.selected_config_idx { Style::default().bg(Color::Cyan).fg(Color::Black).add_modifier(Modifier::BOLD) } else { Style::default() };
        Row::new(vec![Cell::from(*k), Cell::from(v.clone())]).style(style)
    }).collect();
    f.render_widget(Table::new(rows, [Constraint::Percentage(40), Constraint::Percentage(60)]).block(Block::default().borders(Borders::ALL).title("--- SETTINGS ---")).header(Row::new(vec!["Parameter", "Value"]).style(Style::default().fg(Color::Yellow))), area);
}

fn render_device_list(f: &mut Frame, app: &mut App, area: Rect) {
    let rows: Vec<Row> = app.discovered_devices.iter().enumerate().map(|(i, d)| {
        let is_selected = Some(i) == app.table_state.selected();
        let style = if is_selected { Style::default().bg(Color::Yellow).fg(Color::Black).add_modifier(Modifier::BOLD) } 
                    else { if d.category == DeviceCategory::UPS { Style::default().fg(Color::Red) } else { Style::default().fg(Color::White) } };
        Row::new(vec![Cell::from(format!("[{}] {}", d.category, d.ip))]).style(style)
    }).collect();
    let table = Table::new(rows, [Constraint::Percentage(100)]).block(Block::default().borders(Borders::ALL).title("Devices Found"));
    f.render_stateful_widget(table, area, &mut app.table_state);
}

fn render_details_view(f: &mut Frame, app: &mut App, area: Rect) {
    let rows: Vec<Row> = app.snmp_data.iter().map(|(l, v)| Row::new(vec![Cell::from(l.clone()), Cell::from(v.clone())])).collect();
    let table = Table::new(rows, [Constraint::Percentage(30), Constraint::Percentage(70)]).block(Block::default().borders(Borders::ALL).title("Live Metrics")).header(Row::new(vec!["Metric", "Value"]).style(Style::default().fg(Color::Green)));
    f.render_stateful_widget(table, area, &mut app.details_state);
}

fn render_uprober_view(f: &mut Frame, app: &App, area: Rect) {
    let mut text = vec![Row::new(vec![Cell::from("UPS Intelligence Analysis").style(Style::default().fg(Color::Red).add_modifier(Modifier::BOLD))])];
    if let Some(dev) = &app.identified_ups { text.push(Row::new(vec![Cell::from(format!("HW: {} | FW: {}", dev.vendor, dev.model))])); }
    if app.is_walking { text.push(Row::new(vec![Cell::from("Fetching real-time data...")])); }
    for res in &app.diff_results { text.push(Row::new(vec![Cell::from(format!("• {}: -> {}", res.change_type, res.new_value)).style(Style::default().fg(Color::Yellow))])); }
    f.render_widget(Table::new(text, [Constraint::Percentage(100)]).block(Block::default().borders(Borders::ALL).title("Uprober View")), area);
}

fn clean_snmp_value(val: &snmp2::Value) -> String {
    match val {
        snmp2::Value::OctetString(b) => String::from_utf8_lossy(b).trim().to_string(),
        snmp2::Value::Integer(i) => i.to_string(),
        snmp2::Value::Counter32(c) => c.to_string(),
        snmp2::Value::Unsigned32(u) => u.to_string(),
        snmp2::Value::ObjectIdentifier(o) => o.to_string(),
        snmp2::Value::Timeticks(t) => format!("{}s", t / 100),
        _ => format!("{:?}", val),
    }
}
