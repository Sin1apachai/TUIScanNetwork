BINARY_NAME=tui_scan_network
VERSION=1.0.0
BUILD_DIR=dist

# Targets for each OS/Architecture
TARGET_MAC_ARM=aarch64-apple-darwin
TARGET_MAC_INTEL=x86_64-apple-darwin
TARGET_LINUX=x86_64-unknown-linux-gnu
TARGET_WINDOWS=x86_64-pc-windows-gnu

.PHONY: all clean build test package help

all: clean build package

help:
	@echo "TUI Scan Network Build System"
	@echo "Usage:"
	@echo "  make build         - Build binaries for all targets"
	@echo "  make package       - Create release packages (.tar.gz and .zip)"
	@echo "  make clean         - Remove build and dist directories"
	@echo "  make test          - Run unit tests"

build:
	@echo "Building for macOS (Apple Silicon)..."
	cargo build --release --target $(TARGET_MAC_ARM)
	@echo "Building for macOS (Intel)..."
	cargo build --release --target $(TARGET_MAC_INTEL)
	@echo "Building for Linux (x64)..."
	cargo build --release --target $(TARGET_LINUX)
	@echo "Building for Windows (x64)..."
	cargo build --release --target $(TARGET_WINDOWS)

package:
	@echo "Packaging releases..."
	mkdir -p $(BUILD_DIR)

	# macOS ARM
	tar -czf $(BUILD_DIR)/$(BINARY_NAME)-macos-arm64-v$(VERSION).tar.gz \
		-C target/$(TARGET_MAC_ARM)/release $(BINARY_NAME)
	
	# macOS Intel
	tar -czf $(BUILD_DIR)/$(BINARY_NAME)-macos-x64-v$(VERSION).tar.gz \
		-C target/$(TARGET_MAC_INTEL)/release $(BINARY_NAME)

	# Linux
	tar -czf $(BUILD_DIR)/$(BINARY_NAME)-linux-x64-v$(VERSION).tar.gz \
		-C target/$(TARGET_LINUX)/release $(BINARY_NAME)

	# Windows
	zip -j $(BUILD_DIR)/$(BINARY_NAME)-windows-x64-v$(VERSION).zip \
		target/$(TARGET_WINDOWS)/release/$(BINARY_NAME).exe

clean:
	@echo "Cleaning up..."
	cargo clean
	rm -rf $(BUILD_DIR)

test:
	@echo "Running tests..."
	cargo test
