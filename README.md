# TUIScanNetwork - Rust SNMP TUI Scanner

A Terminal User Interface (TUI) application built with Rust for monitoring and scanning SNMP-enabled devices on a local network.

![Screenshot](Screenshot.png)

## Features
- **Network Discovery**: Instantly scan your local subnet (`/24`) for SNMP-responsive devices.
- **Concurrent Probing**: Uses `Tokio` to parallelize probes (20 IPs at once) for high performance.
- **Real-time Monitoring**: View standard system Metrics (`sysDesc`, `sysUptime`, `sysName`, etc.) directly from UI.
- **Full Navigation**: Cycle through discovered devices using arrow keys to see their specific metrics.
- **Manual Input**: Edit the target IP address and SNMP Community String on the fly.

## Requirements
- Rust (Latest Stable)
- An SNMP-enabled device in your network

## Dependencies
- `tokio`: Async runtime for parallel scanning
- `ratatui`: The modern TUI framework
- `crossterm`: Low-level terminal management
- `snmp2`: SNMP protocol client

## Getting Started

1. Clone the repository:
   ```bash
   git clone https://github.com/Sin1apachai/TUIScanNetwork.git
   cd TUIScanNetwork
   ```

2. Run the application:
   ```bash
   cargo run
   ```

## Controls
- **`s`**: Initiate a parallel scan of the current subnet.
- **`Up/Down Arrows`**: Switch between different discovered devices.
- **`e`**: Edit the current Target IP or Community String.
- **`r`**: Manually refresh the data for the selected IP.
- **`q`**: Quit the application.
- **`Esc`**: Cancel editing or scanning state.

## License
MIT
