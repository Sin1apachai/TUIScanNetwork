# 🚀 TUI Intelligent Network Scanner

A high-performance TUI network scanner written in Rust using SNMP. This tool is designed to identify and monitor common network devices (UPS, Routers, Switches, Printers, NAS, and Servers) and perform deep analysis (Probing) for UPS health monitoring without requiring complex MIB files.

## ✨ Key Features
- **Parallel Network Scanning**: Quickly scan subnets using SNMP v2c/v1.
- **Intelligent Fingerprinting**: Automatically categorizes devices as `[UPS]`, `[NET]`, `[PRT]`, `[NAS]`, `[SVR]`, etc.
- **UPS Probing & Diffing**: Heuristic OID discovery that identifies critical metrics (battery, voltage) by analyzing state changes.
- **Cross-Platform**: Native builds for macOS (Universal), Linux, and Windows.
- **Modern UI**: Full TUI experience using `ratatui`.

## 🛠️ Installation & Building

### Prerequisites
- [Rust](https://rustup.rs/) (Stable)
- `make` (Optional, for easy packaging)

### Build from source
```bash
cargo build --release
```

### Packaging for all platforms
```bash
# Add necessary targets
rustup target add aarch64-apple-darwin x86_64-apple-darwin x86_64-unknown-linux-gnu x86_64-pc-windows-gnu

# Build and package
make all
```

## ⌨️ Controls
- `s`: Start/Stop network scan.
- `r`: Refresh current device SNMP data.
- `u`: Enter/Exit UPS Prober mode.
- `e`: Edit target IP address.
- `Arrows`: Select discovered devices.
- `q`: Quit application.

## 📦 Project Structure
- `src/main.rs`: UI logic and async network scanning.
- `src/device.rs`: Device fingerprinting and identification logic.
- `src/ups.rs`: UPS-specific SNMP walk and delta analysis.

## 📝 License
MIT License. Feel free to use and contribute!
