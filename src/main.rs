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

/// Input modes for user interaction
#[derive(PartialEq)]
enum InputMode {
    Normal,         // Browsing mode
    EditingIP,      // Editing IP Address
    Scanning,       // Scanning network
}

/// App state structure
struct App {
    ip_address: String,           // Currently selected/edited IP
    community: String,            // SNMP Community string
    snmp_data: Vec<(String, String)>, // Fetched SNMP results (Label, Value)
    discovered_ips: Vec<String>,  // List of IPs found during scan
    status: String,               // Bottom status message
    input_mode: InputMode,        // Current input state
    cursor_position: usize,       // Cursor position for text entry
    is_scanning: bool,            // Indicator if a scan is running
    scan_progress: u32,           // Current scan count
    scan_total: u32,              // Total expected scan count
    selected_index: usize,        // Selected IP in discovery sidebar
}

impl App {
    /// Initialize application state
    fn new() -> App {
        App {
            ip_address: "192.168.1.1".to_string(),
            community: "public".to_string(),
            snmp_data: Vec::new(),
            discovered_ips: Vec::new(),
            status: "Ready".to_string(),
            input_mode: InputMode::Normal,
            cursor_position: 0,
            is_scanning: false,
            scan_progress: 0,
            scan_total: 0,
            selected_index: 0,
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

    // --- Concurrent network scan ---

    /// Start a network-wide scan for SNMP devices
    fn start_scan(&mut self, tx: Sender<ScanMessage>) {
        self.is_scanning = true;
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
            // Control concurrency to 20 probes at once
            let semaphore = std::sync::Arc::new(tokio::sync::Semaphore::new(20));

            for i in 1..=254 {
                let ip = format!("{}.{}", subnet_prefix, i);
                let community = community.clone();
                let tx = tx.clone();
                let sem_clone = semaphore.clone();

                let handle = tokio::spawn(async move {
                    let _permit = sem_clone.acquire().await.unwrap();
                    let agent_addr = format!("{}:161", ip);
                    let timeout = Duration::from_millis(500);
                    
                    let oid_parts = vec![1, 3, 6, 1, 2, 1, 1, 1, 0]; // sysDescr
                    let oid = Oid::from(&oid_parts).unwrap();
                    
                    // Wrapping blocking SNMP call in spawn_blocking
                    let result = tokio::task::spawn_blocking(move || {
                        if let Ok(mut session) = SyncSession::new_v2c(&agent_addr, community.as_bytes(), Some(timeout), 0) {
                            session.get(&oid).is_ok()
                        } else {
                            false
                        }
                    }).await.unwrap_or(false);

                    if result {
                        let _ = tx.send(ScanMessage::Discovered(ip));
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
}

/// Message enum for communication between scanner and UI
enum ScanMessage {
    Progress(u32, u32),
    Discovered(String),
    Status(String),
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
                        app.status = format!("Found {} devices.", app.discovered_ips.len());
                    }
                }
                ScanMessage::Discovered(ip) => {
                    if !app.discovered_ips.contains(&ip) {
                        app.discovered_ips.push(ip);
                    }
                }
                ScanMessage::Status(s) => {
                    app.status = s;
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
                        KeyCode::Char('r') => app.update_snmp(),
                        KeyCode::Char('s') => {
                            if !app.is_scanning {
                                app.input_mode = InputMode::Scanning;
                                app.start_scan(tx.clone());
                            }
                        }
                        KeyCode::Down => {
                            if !app.discovered_ips.is_empty() {
                                app.selected_index = (app.selected_index + 1) % app.discovered_ips.len();
                                app.ip_address = app.discovered_ips[app.selected_index].clone();
                                app.update_snmp();
                            }
                        }
                        KeyCode::Up => {
                            if !app.discovered_ips.is_empty() {
                                if app.selected_index > 0 {
                                    app.selected_index -= 1;
                                } else {
                                    app.selected_index = app.discovered_ips.len() - 1;
                                }
                                app.ip_address = app.discovered_ips[app.selected_index].clone();
                                app.update_snmp();
                            }
                        }
                        _ => {}
                    },
                    InputMode::EditingIP => match key.code {
                        KeyCode::Enter => {
                            app.input_mode = InputMode::Normal;
                            app.update_snmp();
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
        .discovered_ips
        .iter()
        .map(|ip| {
            Row::new(vec![Cell::from(ip.clone())])
                .style(if ip == &app.ip_address {
                    Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)
                } else {
                    Style::default()
                })
        })
        .collect();

    let ips_table = Table::new(ips, [Constraint::Percentage(100)])
        .block(Block::default().borders(Borders::ALL).title(format!("Discovery ({})", app.discovered_ips.len())))
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
    .block(Block::default().borders(Borders::ALL).title("SNMP Results"))
    .row_highlight_style(Style::default().add_modifier(Modifier::REVERSED));

    f.render_widget(table, main_chunks[1]);

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
        InputMode::Normal => "q: quit | e: edit | s: scan | r: refresh | Arrows: select",
        InputMode::EditingIP => "Enter: submit | Esc: cancel",
        _ => "Scanning... Please wait",
    };
    
    let footer_text = format!("{} | Status: {}", help_msg, app.status);
    
    let footer = Paragraph::new(footer_text)
        .style(Style::default().fg(Color::DarkGray))
        .block(Block::default().borders(Borders::ALL).title("Controls & Status"));
    f.render_widget(footer, chunks[3]);
}
