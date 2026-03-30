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
    widgets::{Block, Borders, Cell, Gauge, Paragraph, Row, Table},
    Frame, Terminal,
};
use snmp2::{SyncSession, Oid};
use std::{
    io,
    sync::mpsc::{self, Receiver, Sender},
    time::{Duration, Instant},
};
use chrono::Local;

mod ups;
mod device;
use ups::{OidSnapshot, DiffResult, DefaultUprober, UpsDevice};
use device::{DeviceCategory, DeviceInfo};
use network_interface::{NetworkInterface, NetworkInterfaceConfig};

#[derive(PartialEq)]
pub enum InputMode {
    Normal,
}

pub struct App {
    pub discovered_devices: Vec<DeviceInfo>,
    pub discovered_ips: Vec<String>,
    pub selected_index: usize,
    pub is_scanning: bool,
    pub scan_progress: u32,
    pub scan_total: u32,
    pub status: String,
    pub community: String,
    pub show_uprober: bool,
    pub snmp_data: Vec<(String, String)>,
    pub snapshot_a: Option<OidSnapshot>,
    pub snapshot_b: Option<OidSnapshot>,
    pub diff_results: Vec<DiffResult>,
    pub is_walking: bool,
    pub identified_ups: Option<UpsDevice>,
}

impl App {
    pub fn new() -> Self {
        Self {
            discovered_devices: Vec::new(),
            discovered_ips: Vec::new(),
            selected_index: 0,
            is_scanning: false,
            scan_progress: 0,
            scan_total: 0,
            status: "Ready".to_string(),
            community: "public".to_string(),
            show_uprober: false,
            snmp_data: Vec::new(),
            snapshot_a: None,
            snapshot_b: None,
            diff_results: Vec::new(),
            is_walking: false,
            identified_ups: None,
        }
    }

    fn start_snmp_update(&mut self, tx: Sender<ScanMessage>) {
        if self.discovered_devices.is_empty() { return; }
        self.snmp_data.clear();
        let ip = self.discovered_devices[self.selected_index].ip.clone();
        let community = self.community.clone();
        
        tokio::spawn(async move {
            let agent_addr = format!("{}:161", ip);
            let timeout = Duration::from_secs(2);
            let oids = [
                (".1.3.6.1.2.1.1.1.0", "System Description"),
                (".1.3.6.1.2.1.1.3.0", "System Uptime"),
                (".1.3.6.1.2.1.1.5.0", "System Name"),
                (".1.3.6.1.2.1.1.6.0", "System Location"),
            ];

            let mut results = Vec::new();
            // Try v2c
            if let Ok(mut session) = SyncSession::new_v2c(&agent_addr, community.as_bytes(), Some(timeout), 0) {
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
            
            // Fallback to v1 if no results
            if results.is_empty() {
                if let Ok(mut session) = SyncSession::new_v1(&agent_addr, community.as_bytes(), Some(timeout), 0) {
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
                let _ = tx.send(ScanMessage::Status("Device not responding to SNMP v1/v2c (check community)".to_string()));
            }
        });
    }

    fn trigger_ups_identification(&mut self, tx: Sender<ScanMessage>) {
        if self.discovered_devices.is_empty() { return; }
        self.identified_ups = None;
        let ip = self.discovered_devices[self.selected_index].ip.clone();
        let community = self.community.clone();
        tokio::spawn(async move {
            let addr = format!("{}:161", ip);
            if let Ok(Some(device)) = ups::identify_ups(&addr, &community).await {
                let _ = tx.send(ScanMessage::UpsIdentified(device));
            }
        });
    }

    fn start_scan(&mut self, tx: Sender<ScanMessage>) {
        self.is_scanning = true;
        self.discovered_devices.clear();
        self.discovered_ips.clear();
        self.selected_index = 0;
        self.scan_progress = 0;
        self.scan_total = 0;
        self.status = "Discovering networks...".to_string();
        
        let community = self.community.clone();

        tokio::spawn(async move {
            let interfaces = NetworkInterface::show().unwrap_or_default();
            let mut scan_targets = Vec::new();
            for iface in interfaces {
                for addr in iface.addr {
                    if let std::net::IpAddr::V4(ipv4) = addr.ip() {
                        if !ipv4.is_loopback() {
                            let ip_str = ipv4.to_string();
                            if let Some((prefix, _)) = ip_str.rsplit_once('.') {
                                if !scan_targets.contains(&prefix.to_string()) {
                                    scan_targets.push(prefix.to_string());
                                }
                            }
                        }
                    }
                }
            }

            let total_ips = (scan_targets.len() * 254) as u32;
            let semaphore = std::sync::Arc::new(tokio::sync::Semaphore::new(50));

            for subnet_prefix in scan_targets {
                for i in 1..=254 {
                    let ip = format!("{}.{}", subnet_prefix, i);
                    let community = community.clone();
                    let tx = tx.clone();
                    let sem_clone = semaphore.clone();

                    tokio::spawn(async move {
                        let _permit = sem_clone.acquire().await.unwrap();
                        let agent_addr = format!("{}:161", ip);
                        let ip_for_blocking = ip.clone();
                        
                        let result = tokio::task::spawn_blocking(move || {
                            let ip = ip_for_blocking;
                            let sys_descr_oid = Oid::from(&[1, 3, 6, 1, 2, 1, 1, 1, 0]).unwrap();
                            let sys_object_id = Oid::from(&[1, 3, 6, 1, 2, 1, 1, 2, 0]).unwrap();
                            let timeout = Duration::from_secs(5);

                            let mut snmp_res = None;
                            // 1. Try SNMP v2c
                            if let Ok(mut session) = SyncSession::new_v2c(&agent_addr, community.as_bytes(), Some(timeout), 0) {
                                if let Ok(resp) = session.get(&sys_descr_oid) {
                                    if let Some(vb) = resp.varbinds.into_iter().next() {
                                        let desc = format!("{:?}", vb.1);
                                        let obj_id = if let Ok(resp2) = session.get(&sys_object_id) {
                                            if let Some(vb2) = resp2.varbinds.into_iter().next() {
                                                format!("{:?}", vb2.1)
                                            } else { "".to_string() }
                                        } else { "".to_string() };
                                        let cat = device::identify_category(&desc, &obj_id);
                                        snmp_res = Some((cat, desc));
                                    }
                                }
                            }

                            // 2. Try SNMP v1 Fallback
                            if snmp_res.is_none() {
                                    if let Ok(mut session) = SyncSession::new_v1(&agent_addr, community.as_bytes(), Some(timeout), 0) {
                                        if let Ok(resp) = session.get(&sys_descr_oid) {
                                            if let Some(vb) = resp.varbinds.into_iter().next() {
                                                let desc = format!("{:?}", vb.1);
                                                let cat = device::identify_category(&desc, "");
                                                snmp_res = Some((cat, desc));
                                            }
                                        }
                                    }
                            }

                            if let Some(res) = snmp_res { return Some(res); }

                            let common_ports = [80, 443, 22, 161, 8080];
                            for port in common_ports {
                                let addr = format!("{}:{}", ip, port);
                                if let Ok(_) = std::net::TcpStream::connect_timeout(&addr.parse().unwrap(), Duration::from_secs(3)) {
                                    let cat = match port {
                                        80 | 443 | 8080 => DeviceCategory::WebDevice,
                                        22 => DeviceCategory::SSH,
                                        _ => DeviceCategory::Alive,
                                    };
                                    return Some((cat, format!("Detected port {}", port)));
                                }
                            }
                            None
                        }).await.unwrap_or(None);

                        if let Some((cat, desc)) = result {
                            let info = DeviceInfo { ip: ip.clone(), category: cat, _description: desc, _sys_name: "".to_string() };
                            let _ = tx.send(ScanMessage::Discovered(info));
                        }
                        let _ = tx.send(ScanMessage::Progress(1, total_ips));
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
        let community = self.community.clone();

        tokio::spawn(async move {
            let root_oid = [1, 3, 6, 1, 4, 1];
            let addr = format!("{}:161", ip);
            if let Ok(data) = ups::snmp_walk(&addr, &community, &root_oid).await {
                let snapshot = OidSnapshot { _timestamp: Instant::now(), data };
                let _ = tx.send(ScanMessage::UpsResult(snapshot, is_second));
            } else {
                let _ = tx.send(ScanMessage::Status("Walk failed".to_string()));
            }
        });
    }

    fn calculate_diffs(&mut self) {
        if let (Some(a), Some(b)) = (&self.snapshot_a, &self.snapshot_b) {
            let prober = DefaultUprober;
            self.diff_results = ups::diff_snapshots(a, b, &prober);
        }
    }
}

enum ScanMessage {
    Progress(u32, u32),
    Discovered(DeviceInfo),
    Status(String),
    UpsResult(OidSnapshot, bool),
    UpsIdentified(UpsDevice),
    MetricUpdated(Vec<(String, String)>),
}

#[tokio::main]
async fn main() -> Result<()> {
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen, EnableMouseCapture)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    let (tx, rx) = mpsc::channel();
    let mut app = App::new();

    let res = run_app(&mut terminal, &mut app, tx, rx).await;

    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen, DisableMouseCapture)?;
    terminal.show_cursor()?;
    res
}

async fn run_app<B: Backend>(
    terminal: &mut Terminal<B>,
    app: &mut App,
    tx: Sender<ScanMessage>,
    rx: Receiver<ScanMessage>,
) -> Result<()> {
    loop {
        while let Ok(msg) = rx.try_recv() {
            match msg {
                ScanMessage::Progress(delta, total) => {
                    app.scan_progress += delta;
                    app.scan_total = total;
                    if app.scan_progress >= total { 
                        app.is_scanning = false; 
                        app.status = format!("Scan complete: {} found", app.discovered_devices.len());
                    }
                }
                ScanMessage::Discovered(info) => {
                    if !app.discovered_ips.contains(&info.ip) {
                        app.discovered_ips.push(info.ip.clone());
                        app.discovered_devices.push(info);
                    }
                }
                ScanMessage::Status(s) => app.status = s,
                ScanMessage::UpsResult(snapshot, is_second) => {
                    app.is_walking = false;
                    if is_second { 
                        app.snapshot_b = Some(snapshot); 
                        app.calculate_diffs(); 
                        app.status = format!("Diff complete: {} changes", app.diff_results.len());
                    } else { 
                        app.snapshot_a = Some(snapshot); 
                        app.status = "Snap A complete. Press '2' after change.".to_string();
                    }
                }
                ScanMessage::UpsIdentified(device) => app.identified_ups = Some(device),
                ScanMessage::MetricUpdated(data) => {
                    app.snmp_data = data;
                    app.status = format!("Details updated at {}", Local::now().format("%H:%M:%S"));
                    
                    // Update category in real-time based on fetched description
                    if !app.discovered_devices.is_empty() {
                        let sys_descr = app.snmp_data.iter()
                            .find(|(l, _)| l.contains("System Description"))
                            .map(|(_, v)| v.clone())
                            .unwrap_or_default();
                        
                        if !sys_descr.is_empty() {
                            let new_cat = device::identify_category(&sys_descr, "");
                            if new_cat != DeviceCategory::Unknown {
                                app.discovered_devices[app.selected_index].category = new_cat;
                            }
                        }
                    }
                }
            }
        }

        terminal.draw(|f| draw(f, app)).map_err(|e| anyhow!("Draw error: {:?}", e))?;

        if event::poll(Duration::from_millis(100))? {
            if let Event::Key(key) = event::read()? {
                match key.code {
                    KeyCode::Char('q') => return Ok(()),
                    KeyCode::Char('s') => app.start_scan(tx.clone()),
                    KeyCode::Char('r') => {
                        app.start_snmp_update(tx.clone());
                        app.trigger_ups_identification(tx.clone());
                    }
                    KeyCode::Char('u') => app.show_uprober = !app.show_uprober,
                    KeyCode::Down => if !app.discovered_devices.is_empty() { 
                        app.selected_index = (app.selected_index + 1) % app.discovered_devices.len();
                        app.start_snmp_update(tx.clone());
                        app.trigger_ups_identification(tx.clone());
                    },
                    KeyCode::Up => if !app.discovered_devices.is_empty() { 
                        app.selected_index = if app.selected_index > 0 { app.selected_index - 1 } else { app.discovered_devices.len() - 1 };
                        app.start_snmp_update(tx.clone());
                        app.trigger_ups_identification(tx.clone());
                    },
                    KeyCode::Char('1') if app.show_uprober => app.start_ups_walk(false, tx.clone()),
                    KeyCode::Char('2') if app.show_uprober => app.start_ups_walk(true, tx.clone()),
                    KeyCode::Char('c') if app.show_uprober => { app.snapshot_a = None; app.snapshot_b = None; app.diff_results.clear(); }
                    _ => {}
                }
            }
        }
    }
}

fn draw(f: &mut Frame, app: &mut App) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Min(3),
            Constraint::Length(1),
            Constraint::Length(3),
        ])
        .split(f.area());

    let main_chunk = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage(35),
            Constraint::Percentage(65),
        ])
        .split(chunks[0]);

    render_device_list(f, app, main_chunk[0]);
    render_details(f, app, main_chunk[1]);
    
    if app.is_scanning {
        let percentage = if app.scan_total > 0 { ((app.scan_progress as f32 / app.scan_total as f32) * 100.0) as u16 } else { 0 };
        let gauge = Gauge::default()
            .block(Block::default())
            .gauge_style(Style::default().fg(Color::Yellow))
            .percent(percentage);
        f.render_widget(gauge, chunks[1]);
    }
    
    render_status(f, app, chunks[2]);
}

fn render_device_list(f: &mut Frame, app: &App, area: Rect) {
    let items: Vec<Row> = app.discovered_devices.iter().enumerate().map(|(i, d)| {
        let color = match d.category {
            DeviceCategory::UPS => Color::LightRed,
            DeviceCategory::RouterSwitch => Color::Cyan,
            DeviceCategory::Printer => Color::Green,
            DeviceCategory::NAS => Color::Yellow,
            DeviceCategory::Server => Color::Blue,
            DeviceCategory::WebDevice => Color::Green,
            DeviceCategory::SSH => Color::Magenta,
            DeviceCategory::Alive => Color::DarkGray,
            _ => Color::White,
        };
        let style = if i == app.selected_index {
            Style::default().fg(Color::Black).bg(Color::Yellow).add_modifier(Modifier::BOLD)
        } else {
            Style::default().fg(color)
        };
        Row::new(vec![Cell::from(format!("{} {}", d.category, d.ip))]).style(style)
    }).collect();

    let table = Table::new(items, [Constraint::Percentage(100)])
        .block(Block::default().borders(Borders::ALL).title(format!("Network Map ({})", app.discovered_devices.len())));
    f.render_widget(table, area);
}

fn render_details(f: &mut Frame, app: &App, area: Rect) {
    if app.show_uprober {
        let rows: Vec<Row> = app.diff_results.iter().map(|d| {
            Row::new(vec![
                Cell::from(d.oid.clone()),
                Cell::from(d.old_value.clone()),
                Cell::from(d.new_value.clone()),
                Cell::from(d.change_type.clone()),
            ]).style(Style::default().fg(Color::Yellow))
        }).collect();
        let table = Table::new(rows, [Constraint::Percentage(30), Constraint::Percentage(20), Constraint::Percentage(20), Constraint::Percentage(30)])
            .header(Row::new(vec!["OID", "Snap A", "Snap B", "Change"]).style(Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)))
            .block(Block::default().borders(Borders::ALL).title("UPS Prober (Delta Mode)"));
        f.render_widget(table, area);
    } else {
        let rows: Vec<Row> = app.snmp_data.iter().map(|(label, value)| {
            Row::new(vec![Cell::from(label.clone()).style(Style::default().add_modifier(Modifier::BOLD)), Cell::from(value.clone())])
        }).collect();
        let title = match &app.identified_ups {
            Some(u) => format!("Details [UPS: {} {}]", u.vendor, u.model),
            None => "Device Details".to_string(),
        };
        let table = Table::new(rows, [Constraint::Percentage(40), Constraint::Percentage(60)])
            .header(Row::new(vec!["Metric", "Value"]).style(Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)))
            .block(Block::default().borders(Borders::ALL).title(title));
        f.render_widget(table, area);
    }
}

fn render_status(f: &mut Frame, app: &App, area: Rect) {
    let help = "q: quit | s: scan | r: refresh | u: prober | Arrows: select";
    let footer = Paragraph::new(format!("{} | Status: {}", help, app.status)).block(Block::default().borders(Borders::ALL).title("Controls"));
    f.render_widget(footer, area);
}
