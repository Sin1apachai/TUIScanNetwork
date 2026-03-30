use anyhow::Result;
use chrono::Local;
use crossterm::{
    event::{self, DisableMouseCapture, EnableMouseCapture, Event, KeyCode},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{
    backend::{Backend, CrosstermBackend},
    layout::{Constraint, Direction, Layout, Position},
    style::{Color, Modifier, Style},
    widgets::{Block, Borders, Cell, Paragraph, Row, Table},
    Frame, Terminal,
};
use snmp2::{SyncSession, Oid};
use std::{
    io,
    sync::mpsc::{self, Receiver, Sender},
    time::{Duration, Instant},
};

mod ups;
mod device;
use ups::{OidSnapshot, DiffResult, DefaultUprober, UpsDevice};
use device::{DeviceCategory, DeviceInfo};

/// Input modes for user interaction
#[derive(PartialEq)]
enum InputMode {
    Normal,         // Browsing mode
    EditingIP,      // Editing IP Address
    Scanning,       // Scanning network
    UpsProbing,     // Probing UPS OIDs
}

/// App state structure
struct App {
    ip_address: String,           // Currently selected/edited IP
    community: String,            // SNMP Community string
    snmp_data: Vec<(String, String)>, // Fetched SNMP results (Label, Value)
    discovered_devices: Vec<DeviceInfo>, // List of IPs found during scan with metadata
    discovered_ips: Vec<String>,  // Keeps track for quick lookup
    status: String,               // Bottom status message
    input_mode: InputMode,        // Current input state
    cursor_position: usize,       // Cursor position for text entry
    is_scanning: bool,            // Indicator if a scan is running
    scan_progress: u32,           // Current scan count
    scan_total: u32,              // Total expected scan count
    selected_index: usize,        // Selected IP in discovery sidebar
    snapshot_a: Option<OidSnapshot>,
    snapshot_b: Option<OidSnapshot>,
    diff_results: Vec<DiffResult>,
    is_walking: bool,
    identified_ups: Option<UpsDevice>,
}

impl App {
    /// Initialize application state
    fn new() -> App {
        App {
            ip_address: "192.168.1.1".to_string(),
            community: "public".to_string(),
            snmp_data: Vec::new(),
            discovered_devices: Vec::new(),
            discovered_ips: Vec::new(),
            status: "Ready".to_string(),
            input_mode: InputMode::Normal,
            cursor_position: 0,
            is_scanning: false,
            scan_progress: 0,
            scan_total: 0,
            selected_index: 0,
            snapshot_a: None,
            snapshot_b: None,
            diff_results: Vec::new(),
            is_walking: false,
            identified_ups: None,
        }
    }

    // --- Input handling functions ---

    fn move_cursor_left(&mut self) {
        let cursor_moved_left = self.cursor_position.saturating_sub(1);
        self.cursor_position = self.clamp_cursor(cursor_moved_left);
    }

    fn move_cursor_right(&mut self) {
        let cursor_moved_right = self.cursor_position.saturating_add(1);
        self.cursor_position = self.clamp_cursor(cursor_moved_right);
    }

    fn enter_char(&mut self, new_char: char) {
        self.ip_address.insert(self.cursor_position, new_char);
        self.move_cursor_right();
    }

    fn delete_char(&mut self) {
        if self.cursor_position != 0 {
            let from_left_to_current_index = self.cursor_position - 1;
            let _ = self.ip_address.remove(from_left_to_current_index);
            self.move_cursor_left();
        }
    }

    fn clamp_cursor(&self, new_cursor_pos: usize) -> usize {
        new_cursor_pos.clamp(0, self.ip_address.len())
    }

    fn reset_cursor(&mut self) {
        self.cursor_position = self.ip_address.len();
    }

    // --- SNMP operations ---

    /// Fetch SNMP system info from the current IP
    fn update_snmp(&mut self) {
        let agent_addr = format!("{}:161", self.ip_address);
        let community = self.community.as_bytes();
        let timeout = Duration::from_secs(2);

        self.status = format!("Querying {}...", agent_addr);
        
        // Standard OIDs for system information
        let oids = [
            (".1.3.6.1.2.1.1.1.0", "System Description"),
            (".1.3.6.1.2.1.1.3.0", "System Uptime"),
            (".1.3.6.1.2.1.1.5.0", "System Name"),
            (".1.3.6.1.2.1.1.4.0", "System Contact"),
            (".1.3.6.1.2.1.1.6.0", "System Location"),
        ];

        // Create SNMP session
        let mut session = match SyncSession::new_v2c(&agent_addr, community, Some(timeout), 0) {
            Ok(s) => s,
            Err(e) => {
                self.status = format!("Connection failed: {}", e);
                return;
            }
        };

        let mut results = Vec::new();

        // Iterate and fetch each OID
        for (oid_str, label) in oids.iter() {
            let parts: Vec<u64> = oid_str
                .split('.')
                .filter(|s| !s.is_empty())
                .map(|s| s.parse::<u64>().unwrap_or(0))
                .collect();

            let oid = match Oid::from(&parts[..]) {
                Ok(o) => o,
                Err(e) => {
                    results.push((label.to_string(), format!("OID Error: {:?}", e)));
                    continue;
                }
            };

            match session.get(&oid) {
                Ok(response) => {
                    if let Some(varbind) = response.varbinds.into_iter().next() {
                        results.push((label.to_string(), format!("{:?}", varbind.1)));
                    } else {
                        results.push((label.to_string(), "No data".to_string()));
                    }
                }
                Err(e) => {
                    results.push((label.to_string(), format!("Error: {}", e)));
                }
            }
        }

        if !results.is_empty() {
            self.snmp_data = results;
            self.status = format!("Updated at {}", Local::now().format("%H:%M:%S"));
        } else {
            self.status = "Failed to fetch data".to_string();
        }
    }

    fn trigger_ups_identification(&mut self, tx: Sender<ScanMessage>) {
        self.identified_ups = None; // Reset previous identification
        self.start_ups_identification(tx);
    }

    // --- Concurrent network scan ---

    /// Start a network-wide scan for SNMP devices
    fn start_scan(&mut self, tx: Sender<ScanMessage>) {
        self.is_scanning = true;
        self.discovered_devices.clear();
        self.discovered_ips.clear();
        self.selected_index = 0;
        self.scan_progress = 0;
        self.scan_total = 254;
        self.status = "Starting parallel scan...".to_string();
        
        let subnet_prefix = match self.ip_address.rsplit_once('.') {
            Some((prefix, _)) => prefix.to_string(),
            None => {
                self.is_scanning = false;
                self.status = "Invalid IP for scanning".to_string();
                return;
            }
        };

        let community = self.community.clone();

        // Spawn async scan task
        tokio::spawn(async move {
            let mut handles = vec![];
            // Control concurrency to 50 probes at once (faster but still safe)
            let semaphore = std::sync::Arc::new(tokio::sync::Semaphore::new(50));

            for i in 1..=254 {
                let ip = format!("{}.{}", subnet_prefix, i);
                let community = community.clone();
                let tx = tx.clone();
                let sem_clone = semaphore.clone();

                let handle = tokio::spawn(async move {
                    let _permit = sem_clone.acquire().await.unwrap();
                    let agent_addr = format!("{}:161", ip);
                    // Wrapping blocking SNMP call in spawn_blocking
                    let result = tokio::task::spawn_blocking(move || {
                        let sys_descr_oid = Oid::from(&[1, 3, 6, 1, 2, 1, 1, 1, 0]).unwrap();
                        let sys_object_id = Oid::from(&[1, 3, 6, 1, 2, 1, 1, 2, 0]).unwrap();
                        let timeout = Duration::from_millis(1500);

                        // Try v2c then v1 as fallback
                        if let Ok(mut session) = SyncSession::new_v2c(&agent_addr, community.as_bytes(), Some(timeout), 0) {
                            if let Ok(resp) = session.get(&sys_descr_oid) {
                                if let Some(vb) = resp.varbinds.into_iter().next() {
                                    let desc = format!("{:?}", vb.1);
                                    let obj_id = if let Ok(resp2) = session.get(&sys_object_id) {
                                        if let Some(vb2) = resp2.varbinds.into_iter().next() {
                                            format!("{:?}", vb2.1)
                                        } else { "".to_string() }
                                    } else { "".to_string() };
                                    let category = device::identify_category(&desc, &obj_id);
                                    return Some((desc, category));
                                }
                            }
                        }
                        // Fallback to v1
                        if let Ok(mut session) = SyncSession::new_v1(&agent_addr, community.as_bytes(), Some(timeout), 0) {
                            if let Ok(resp) = session.get(&sys_descr_oid) {
                                if let Some(vb) = resp.varbinds.into_iter().next() {
                                    let desc = format!("{:?}", vb.1);
                                    let category = device::identify_category(&desc, "");
                                    return Some((desc, category));
                                }
                            }
                        }
                        None
                    }).await.unwrap_or(None);

                    if let Some((desc, category)) = result {
                        let info = DeviceInfo {
                            ip: ip.clone(),
                            category,
                            _description: desc,
                            _sys_name: "".to_string(),
                        };
                        let _ = tx.send(ScanMessage::Discovered(info));
                    }
                    let _ = tx.send(ScanMessage::Progress(1, 254));
                });
                handles.push(handle);
            }

            for h in handles {
                let _ = h.await;
            }
            let _ = tx.send(ScanMessage::Status("Scan complete.".to_string()));
        });
    }

    /// Start a full walk for UPS OID identification
    fn start_ups_walk(&mut self, is_second: bool, tx: Sender<ScanMessage>) {
        if self.is_walking { return; }
        self.is_walking = true;
        self.status = format!("Walking .1.3.6.1.4.1 ({} snapshot)...", if is_second { "Second" } else { "First" });
        
        let ip = self.ip_address.clone();
        let community = self.community.clone();

        tokio::spawn(async move {
            let root_oid = vec![1, 3];
            let addr = format!("{}:161", ip);
            
            match ups::snmp_walk(&addr, &community, &root_oid).await {
                Ok(data) => {
                    let snapshot = OidSnapshot {
                        _timestamp: Instant::now(),
                        data,
                    };
                    let _ = tx.send(ScanMessage::UpsResult(snapshot, is_second));
                }
                Err(e) => {
                    let _ = tx.send(ScanMessage::Status(format!("Walk failed: {}", e)));
                }
            }
        });
    }

    fn start_ups_identification(&mut self, tx: Sender<ScanMessage>) {
        let ip = self.ip_address.clone();
        let community = self.community.clone();
        tokio::spawn(async move {
            let addr = format!("{}:161", ip);
            if let Ok(Some(device)) = ups::identify_ups(&addr, &community).await {
                let _ = tx.send(ScanMessage::UpsIdentified(device));
            }
        });
    }

    fn calculate_diffs(&mut self) {
        if let (Some(a), Some(b)) = (&self.snapshot_a, &self.snapshot_b) {
            let prober = DefaultUprober;
            self.diff_results = ups::diff_snapshots(a, b, &prober);
            self.status = format!("Diff complete: found {} changes.", self.diff_results.len());
        }
    }
}

/// Message enum for communication between scanner and UI
enum ScanMessage {
    Progress(u32, u32),
    Discovered(DeviceInfo),
    Status(String),
    UpsResult(OidSnapshot, bool), // (Data, IsSecond)
    UpsIdentified(UpsDevice),
}

// --- Main execution block ---

#[tokio::main]
async fn main() -> Result<()> {
    // Terminal setup
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen, EnableMouseCapture)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    // Result channel
    let (tx, rx) = mpsc::channel();
    let mut app = App::new();

    // Application loop
    let res = run_app(&mut terminal, &mut app, tx, rx).await;

    // Restore terminal
    disable_raw_mode()?;
    execute!(
        terminal.backend_mut(),
        LeaveAlternateScreen,
        DisableMouseCapture
    )?;
    terminal.show_cursor()?;

    if let Err(err) = res {
        eprintln!("Error: {:?}", err);
    }

    Ok(())
}

/// Main loop function
async fn run_app<B: Backend>(
    terminal: &mut Terminal<B>,
    app: &mut App,
    tx: Sender<ScanMessage>,
    rx: Receiver<ScanMessage>,
) -> Result<()> {
    let tick_rate = Duration::from_millis(200);
    let mut last_tick = Instant::now();

    loop {
        // 1. Process scan results
        while let Ok(msg) = rx.try_recv() {
            match msg {
                ScanMessage::Progress(delta, total) => {
                    app.scan_progress += delta;
                    app.scan_total = total;
                    if app.scan_progress >= total {
                        app.is_scanning = false;
                        if app.input_mode == InputMode::Scanning {
                            app.input_mode = InputMode::Normal;
                        }
                        app.status = format!("Found {} devices.", app.discovered_devices.len());
                    }
                }
                ScanMessage::Discovered(info) => {
                    if !app.discovered_ips.contains(&info.ip) {
                        app.discovered_ips.push(info.ip.clone());
                        app.discovered_devices.push(info);
                    }
                }
                ScanMessage::Status(s) => {
                    app.status = s;
                }
                ScanMessage::UpsResult(snapshot, is_second) => {
                    app.is_walking = false;
                    let count = snapshot.data.len();
                    if is_second {
                        app.snapshot_b = Some(snapshot);
                        app.calculate_diffs();
                        app.status = format!("Snapshot B complete ({} OIDs). Found {} changes.", count, app.diff_results.len());
                    } else {
                        app.snapshot_a = Some(snapshot);
                        app.status = format!("Snapshot A complete ({} OIDs). Trigger change and press '2'.", count);
                    }
                }
                ScanMessage::UpsIdentified(device) => {
                    app.identified_ups = Some(device);
                }
            }
        }

        // 2. Draw UI
        terminal.draw(|f| ui(f, app)).map_err(|e| anyhow::anyhow!("Draw error: {}", e))?;

        // 3. Handle inputs
        let timeout = tick_rate
            .checked_sub(last_tick.elapsed())
            .unwrap_or_else(|| Duration::from_secs(0));

        if event::poll(timeout)? {
            if let Event::Key(key) = event::read()? {
                match app.input_mode {
                    InputMode::Normal => match key.code {
                        KeyCode::Char('q') => return Ok(()),
                        KeyCode::Char('e') => {
                            app.input_mode = InputMode::EditingIP;
                            app.reset_cursor();
                        }
                        KeyCode::Char('r') => {
                            app.update_snmp();
                            app.trigger_ups_identification(tx.clone());
                        }
                        KeyCode::Char('s') => {
                            if !app.is_scanning {
                                app.input_mode = InputMode::Scanning;
                                app.start_scan(tx.clone());
                            }
                        }
                        KeyCode::Down => {
                            if !app.discovered_devices.is_empty() {
                                app.selected_index = (app.selected_index + 1) % app.discovered_devices.len();
                                app.ip_address = app.discovered_devices[app.selected_index].ip.clone();
                                app.update_snmp();
                                app.trigger_ups_identification(tx.clone());
                            }
                        }
                        KeyCode::Up => {
                            if !app.discovered_devices.is_empty() {
                                if app.selected_index > 0 {
                                    app.selected_index -= 1;
                                } else {
                                    app.selected_index = app.discovered_devices.len() - 1;
                                }
                                app.ip_address = app.discovered_devices[app.selected_index].ip.clone();
                                app.update_snmp();
                                app.trigger_ups_identification(tx.clone());
                            }
                        }
                        KeyCode::Char('u') => {
                            app.input_mode = InputMode::UpsProbing;
                        }
                        _ => {}
                    },
                    InputMode::EditingIP => match key.code {
                        KeyCode::Enter => {
                            app.input_mode = InputMode::Normal;
                            app.update_snmp();
                            app.trigger_ups_identification(tx.clone());
                        }
                        KeyCode::Char(c) => app.enter_char(c),
                        KeyCode::Backspace => app.delete_char(),
                        KeyCode::Left => app.move_cursor_left(),
                        KeyCode::Right => app.move_cursor_right(),
                        KeyCode::Esc => app.input_mode = InputMode::Normal,
                        _ => {}
                    },
                    InputMode::Scanning => match key.code {
                        KeyCode::Esc => app.input_mode = InputMode::Normal,
                        _ => {}
                    },
                    InputMode::UpsProbing => match key.code {
                        KeyCode::Char('1') => {
                            app.start_ups_walk(false, tx.clone());
                        }
                        KeyCode::Char('2') => {
                            app.start_ups_walk(true, tx.clone());
                        }
                        KeyCode::Char('c') => {
                            app.snapshot_a = None;
                            app.snapshot_b = None;
                            app.diff_results.clear();
                        }
                        KeyCode::Esc => app.input_mode = InputMode::Normal,
                        _ => {}
                    },
                }
            }
        }

        if last_tick.elapsed() >= tick_rate {
            last_tick = Instant::now();
        }
    }
}

// --- UI Rendering ---

fn ui(f: &mut Frame, app: &App) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .margin(1)
        .constraints(
            [
                Constraint::Length(3), // IP field
                Constraint::Min(5),    // Main content
                Constraint::Length(1), // Progress bar
                Constraint::Length(3), // Status footer
            ]
            .as_ref(),
        )
        .split(f.area());

    // 1. IP Input
    let input = Paragraph::new(app.ip_address.as_str())
        .style(match app.input_mode {
            InputMode::Normal => Style::default(),
            InputMode::EditingIP => Style::default().fg(Color::Yellow),
            _ => Style::default(),
        })
        .block(Block::default().borders(Borders::ALL).title("Target IP Address (SNMPv2c)"));
    f.render_widget(input, chunks[0]);

    if app.input_mode == InputMode::EditingIP {
        f.set_cursor_position(Position {
            x: chunks[0].x + app.cursor_position as u16 + 1,
            y: chunks[0].y + 1,
        });
    }

    // 2. Main content split
    let main_chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(30), Constraint::Percentage(70)].as_ref())
        .split(chunks[1]);

    // Discovery Sidebar
    let ips: Vec<Row> = app
        .discovered_devices
        .iter()
        .map(|info| {
            let color = match info.category {
                DeviceCategory::UPS => Color::LightRed,
                DeviceCategory::RouterSwitch => Color::Cyan,
                DeviceCategory::Printer => Color::Green,
                DeviceCategory::NAS => Color::Yellow,
                DeviceCategory::Server => Color::Blue,
                DeviceCategory::Unknown => Color::White,
            };
            
            Row::new(vec![
                Cell::from(format!("{} {}", info.category, info.ip)).style(if info.ip == app.ip_address {
                    Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)
                } else {
                    Style::default().fg(color)
                })
            ])
        })
        .collect();

    let ips_table = Table::new(ips, [Constraint::Percentage(100)])
        .block(Block::default().borders(Borders::ALL).title(format!("Devices ({})", app.discovered_devices.len())))
        .row_highlight_style(Style::default().add_modifier(Modifier::REVERSED));
    f.render_widget(ips_table, main_chunks[0]);

    // Data Table
    let rows: Vec<Row> = app
        .snmp_data
        .iter()
        .map(|(label, value)| {
            Row::new(vec![
                Cell::from(label.clone()).style(Style::default().add_modifier(Modifier::BOLD)),
                Cell::from(value.clone()),
            ])
        })
        .collect();

    let table = Table::new(
        rows,
        [Constraint::Percentage(35), Constraint::Percentage(65)],
    )
    .header(
        Row::new(vec!["Metric", "Value"])
            .style(Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD))
    )
    .block(Block::default().borders(Borders::ALL).title(match &app.identified_ups {
        Some(ups) => format!("SNMP Results [Identified: {} {}]", ups.vendor, ups.model),
        None => "SNMP Results".to_string(),
    }))
    .row_highlight_style(Style::default().add_modifier(Modifier::REVERSED));

    if app.input_mode != InputMode::UpsProbing {
        f.render_widget(table, main_chunks[1]);
    } else {
        // UPS Identification Table
        let diff_rows: Vec<Row> = app
            .diff_results
            .iter()
            .map(|d| {
                Row::new(vec![
                    Cell::from(d.oid.clone()),
                    Cell::from(d.old_value.clone()),
                    Cell::from(d.new_value.clone()),
                    Cell::from(d.change_type.clone()),
                ])
                .style(if d.change_type.contains("Battery") || d.change_type.contains("Voltage") {
                    Style::default().fg(Color::LightRed).add_modifier(Modifier::BOLD)
                } else {
                    Style::default().fg(Color::Yellow)
                })
            })
            .collect();

        let diff_table = Table::new(
            diff_rows,
            [
                Constraint::Percentage(30),
                Constraint::Percentage(20),
                Constraint::Percentage(20),
                Constraint::Percentage(30),
            ],
        )
        .header(
            Row::new(vec!["OID", "Old Value", "New Value", "Possible Meaning"])
                .style(Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD))
        )
        .block(Block::default().borders(Borders::ALL).title("UPS OID Identification (Diff Results)"))
        .row_highlight_style(Style::default().add_modifier(Modifier::REVERSED));

        if app.diff_results.is_empty() {
            if app.snapshot_a.is_some() {
                let msg = Row::new(vec![
                    Cell::from("Snapshot A stored").style(Style::default().fg(Color::Yellow)),
                    Cell::from("-"),
                    Cell::from("-"),
                    Cell::from("Now trigger changes and press '2'"),
                ]);
                f.render_widget(Table::new(vec![msg], [Constraint::Percentage(30), Constraint::Percentage(20), Constraint::Percentage(20), Constraint::Percentage(30)])
                    .header(Row::new(vec!["OID", "Old Value", "New Value", "Possible Meaning"]).style(Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)))
                    .block(Block::default().borders(Borders::ALL).title("UPS OID Identification (Diff Results)")), main_chunks[1]);
            } else {
                let msg = Row::new(vec![
                    Cell::from("Waiting for Snapshot A").style(Style::default().fg(Color::DarkGray)),
                    Cell::from("-"),
                    Cell::from("-"),
                    Cell::from("Press '1' to start"),
                ]);
                f.render_widget(Table::new(vec![msg], [Constraint::Percentage(30), Constraint::Percentage(20), Constraint::Percentage(20), Constraint::Percentage(30)])
                    .header(Row::new(vec!["OID", "Old Value", "New Value", "Possible Meaning"]).style(Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)))
                    .block(Block::default().borders(Borders::ALL).title("UPS OID Identification (Diff Results)")), main_chunks[1]);
            }
        } else {
            f.render_widget(diff_table, main_chunks[1]);
        }
    }

    // 3. Scan progress
    if app.is_scanning {
        let percentage = if app.scan_total > 0 {
            (app.scan_progress as f32 / app.scan_total as f32 * 100.0) as u16
        } else {
            0
        };
        let scan_status = format!("Scanning: {}/{} ips ({}%)", app.scan_progress, app.scan_total, percentage);
        let progress = Paragraph::new(scan_status).style(Style::default().fg(Color::Yellow));
        f.render_widget(progress, chunks[2]);
    }

    // 4. Status bar
    let help_msg = match app.input_mode {
        InputMode::Normal => "q: quit | e: edit | s: scan | r: refresh | u: ups prober | Arrows: select",
        InputMode::EditingIP => "Enter: submit | Esc: cancel",
        InputMode::UpsProbing => "1: Snapshot A | 2: Snapshot B | c: Clear | Esc: back",
        _ => "Processing... Please wait",
    };
    
    let footer_text = format!("{} | Status: {}", help_msg, app.status);
    
    let footer = Paragraph::new(footer_text)
        .style(Style::default().fg(Color::DarkGray))
        .block(Block::default().borders(Borders::ALL).title("Controls & Status"));
    f.render_widget(footer, chunks[3]);
}
