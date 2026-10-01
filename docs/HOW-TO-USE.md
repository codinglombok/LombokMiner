# LombokMiner — How To Use

Complete guide: from compiling source to production deployment across all platforms.

---

## Table of Contents

1. [System Requirements](#1-system-requirements)
2. [Building from Source](#2-building-from-source)
   - [Windows](#21-windows)
   - [Linux (Ubuntu/Debian)](#22-linux-ubuntudebian)
   - [Linux (Fedora/RHEL/CentOS)](#23-linux-fedorarhelcentos)
   - [Linux (Arch)](#24-linux-arch)
   - [macOS](#25-macos)
   - [Raspberry Pi / ARM](#26-raspberry-pi--arm)
   - [FreeBSD](#27-freebsd)
3. [Binary Installation (No Compilation)](#3-binary-installation-no-compilation)
4. [Configuration](#4-configuration)
5. [Running LombokMiner](#5-running-lombokminer)
   - [CLI Commands](#51-cli-commands)
   - [Solo Mining](#52-solo-mining)
   - [Pool Mining](#53-pool-mining)
   - [CPU Mining (Multi-Thread)](#54-cpu-mining-multi-thread)
   - [Web Dashboard](#55-web-dashboard)
   - [Monitoring (Prometheus + Grafana)](#56-monitoring-prometheus--grafana)
6. [Docker](#6-docker)
   - [Build Image](#61-build-image)
   - [Docker Compose (Mining + Monitoring)](#62-docker-compose)
   - [Docker on Raspberry Pi](#63-docker-on-raspberry-pi)
7. [Deploy to VPS / Cloud](#7-deploy-to-vps--cloud)
   - [Ubuntu VPS (DigitalOcean/Linode/Vultr)](#71-ubuntu-vps)
   - [AWS EC2](#72-aws-ec2)
   - [Google Cloud / Azure](#73-google-cloud--azure)
   - [Systemd Service](#74-systemd-service)
8. [Deploy to Web Server / Shared Hosting](#8-deploy-to-web-server--shared-hosting)
   - [Dashboard Only (Static HTML)](#81-dashboard-only-static-html)
   - [cPanel / Shared Hosting](#82-cpanel--shared-hosting)
   - [Nginx Reverse Proxy](#83-nginx-reverse-proxy)
   - [Apache Reverse Proxy](#84-apache-reverse-proxy)
9. [Raspberry Pi & SBC](#9-raspberry-pi--sbc)
   - [Raspberry Pi 4/5 (Native)](#91-raspberry-pi-45-native)
   - [Raspberry Pi + ASIC USB](#92-raspberry-pi--asic-usb)
   - [Orange Pi / Rock Pi / Odroid](#93-orange-pi--rock-pi--odroid)
10. [Language Bindings](#10-language-bindings)
    - [Python](#101-python)
    - [PHP](#102-php)
    - [C/C++](#103-cc)
11. [Troubleshooting](#11-troubleshooting)
12. [Quick Reference](#12-quick-reference)

---

## 1. System Requirements

### Minimum

| Component | Specification |
|---|---|
| CPU | x86_64 or ARM64, 1 core |
| RAM | 128 MB (CLI), 256 MB (with dashboard) |
| Disk | 50 MB (binary + config) |
| OS | Linux, Windows 10+, macOS 12+, FreeBSD 13+ |
| Rust | 1.75+ (for building from source) |

### Recommended (Pool Mining)

| Component | Specification |
|---|---|
| CPU | 2+ cores (for multi-thread mining and network I/O) |
| RAM | 512 MB |
| Network | Stable connection to pool, latency < 100ms |
| OS | Linux (for server/headless), Windows/macOS (for desktop) |

### For Solo Mining

| Component | Additional |
|---|---|
| Disk | 600+ GB (full Bitcoin node via `bitcoind`) |
| RAM | 4+ GB (for `bitcoind`) |
| Network | Broadband; initial sync takes 1–3 days |

---

## 2. Building from Source

### 2.1 Windows

```powershell
# 1. Install Rust
#    Download from https://rustup.rs and run rustup-init.exe
#    Select "Default" when prompted

# 2. Open a new PowerShell / Terminal (so PATH is updated)
rustc --version    # Must be 1.75+
cargo --version

# 3. Clone and build
git clone https://github.com/codinglombok/lombokminer.git
cd lombokminer
cargo build --release

# 4. Binary is at:
#    target\release\lombokminer.exe

# 5. Test
.\target\release\lombokminer.exe selftest
.\target\release\lombokminer.exe info

# 6. (Optional) Add to PATH
$env:PATH += ";$PWD\target\release"
# Or copy to a folder already in PATH:
Copy-Item target\release\lombokminer.exe C:\Windows\
```

**Visual Studio Build Tools** — if `cargo build` fails with "link.exe not found":
```powershell
# Download Visual Studio Build Tools:
# https://visualstudio.microsoft.com/visual-cpp-build-tools/
# Install the "Desktop development with C++" component
```

### 2.2 Linux (Ubuntu/Debian)

```bash
# 1. Install Rust
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source ~/.cargo/env

# 2. Install build dependencies
sudo apt update
sudo apt install -y build-essential pkg-config

# 3. Clone and build
git clone https://github.com/codinglombok/lombokminer.git
cd lombokminer
cargo build --release

# 4. Install (optional)
sudo cp target/release/lombokminer /usr/local/bin/

# 5. Verify
lombokminer selftest
lombokminer info
```

**Static build (zero dependencies, fully portable binary):**
```bash
# Install musl toolchain
sudo apt install -y musl-tools
rustup target add x86_64-unknown-linux-musl

# Build static binary
cargo build --release --target x86_64-unknown-linux-musl

# Binary at: target/x86_64-unknown-linux-musl/release/lombokminer
# This can be copied to ANY Linux machine without installing anything
file target/x86_64-unknown-linux-musl/release/lombokminer
# → "statically linked"
```

### 2.3 Linux (Fedora/RHEL/CentOS)

```bash
# 1. Install Rust
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source ~/.cargo/env

# 2. Install build dependencies
sudo dnf groupinstall -y "Development Tools"
# or for CentOS/RHEL:
# sudo yum groupinstall -y "Development Tools"

# 3. Build
git clone https://github.com/codinglombok/lombokminer.git
cd lombokminer
cargo build --release

sudo cp target/release/lombokminer /usr/local/bin/
```

### 2.4 Linux (Arch)

```bash
sudo pacman -S rust git base-devel
git clone https://github.com/codinglombok/lombokminer.git
cd lombokminer
cargo build --release
sudo cp target/release/lombokminer /usr/local/bin/
```

### 2.5 macOS

```bash
# 1. Install Rust
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source ~/.cargo/env

# 2. Xcode Command Line Tools (if not already installed)
xcode-select --install

# 3. Build
git clone https://github.com/codinglombok/lombokminer.git
cd lombokminer
cargo build --release

# 4. Install
sudo cp target/release/lombokminer /usr/local/bin/

# 5. Apple Silicon (M1/M2/M3/M4) — native ARM build
# This happens automatically when Rust is installed on an ARM Mac.
# To cross-compile for Intel Mac:
rustup target add x86_64-apple-darwin
cargo build --release --target x86_64-apple-darwin
```

### 2.6 Raspberry Pi / ARM

```bash
# Raspberry Pi OS (64-bit) — native build
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source ~/.cargo/env

git clone https://github.com/codinglombok/lombokminer.git
cd lombokminer
cargo build --release
# Takes ~15–30 minutes on Pi 4 (4GB RAM)

sudo cp target/release/lombokminer /usr/local/bin/
lombokminer selftest
```

**Cross-compile from desktop (much faster):**
```bash
# On an x86_64 Linux machine:
rustup target add aarch64-unknown-linux-musl
sudo apt install -y gcc-aarch64-linux-gnu

# Create .cargo/config.toml
mkdir -p .cargo
cat > .cargo/config.toml << 'EOF'
[target.aarch64-unknown-linux-musl]
linker = "aarch64-linux-gnu-gcc"
EOF

cargo build --release --target aarch64-unknown-linux-musl

# Copy binary to Pi over SSH:
scp target/aarch64-unknown-linux-musl/release/lombokminer pi@raspberrypi:/usr/local/bin/
```

### 2.7 FreeBSD

```bash
pkg install rust git
git clone https://github.com/codinglombok/lombokminer.git
cd lombokminer
cargo build --release
cp target/release/lombokminer /usr/local/bin/
```

---

## 3. Binary Installation (No Compilation)

Download a pre-built binary from GitHub Releases:

```bash
# Linux x86_64
curl -LO https://github.com/codinglombok/lombokminer/releases/latest/download/lombokminer-x86_64-linux
chmod +x lombokminer-x86_64-linux
sudo mv lombokminer-x86_64-linux /usr/local/bin/lombokminer

# macOS (Apple Silicon)
curl -LO https://github.com/codinglombok/lombokminer/releases/latest/download/lombokminer-aarch64-darwin
chmod +x lombokminer-aarch64-darwin
sudo mv lombokminer-aarch64-darwin /usr/local/bin/lombokminer

# Windows — download .exe from browser
# https://github.com/codinglombok/lombokminer/releases/latest
```

Verify:
```bash
lombokminer selftest
```

---

## 4. Configuration

### Generate Default Config

```bash
lombokminer init
# Creates: lombokminer.toml
```

### Edit Config

```toml
# lombokminer.toml

[general]
mode = "pool"                    # "solo" for solo mining
log_level = "info"

[wallet]
address = "bc1p..."              # REQUIRED: your Bitcoin address (Taproot/SegWit)

[pool.primary]
url = "sv2://pool.braiins.com:3336"
protocol = "stratum_v2"
user = "your_worker_name"
password = "x"

[pool.backup]
url = "stratum+tcp://backup-pool.com:3333"
protocol = "stratum_v1"
user = "your_worker_name"
password = "x"

[hardware.cpu]
enabled = true
threads = 0                      # 0 = use all cores

[dashboard]
enabled = true
bind = "0.0.0.0:8080"           # Access from browser: http://IP:8080
```

### Validate an Address

```bash
lombokminer validate bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4
# Output:
#   Address: bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4
#   Type:    P2WPKH (SegWit v0)
#   Network: Mainnet
#   Valid
```

### View Loaded Config

```bash
lombokminer config
# Output: full JSON of the active configuration

lombokminer --config /path/to/custom.toml config
```

---

## 5. Running LombokMiner

### 5.1 CLI Commands

```bash
lombokminer selftest           # Verify: SHA-256d, crypto, wallet, mining
lombokminer bench -m 50 -t 4   # Benchmark 50M hashes, 4 threads
lombokminer info               # System info, CPU features, hashrate
lombokminer init               # Generate lombokminer.toml
lombokminer mine               # Start mining (reads from config)
lombokminer validate <address> # Validate a Bitcoin address
lombokminer config             # Display active configuration
```

### 5.2 Solo Mining

**Requirements:** Bitcoin Core (`bitcoind`) must be running and fully synced.

```bash
# 1. Install and sync Bitcoin Core
#    https://bitcoin.org/en/download
#    Wait for sync to complete (1–3 days, 600GB+ disk)

# 2. Configure bitcoind (bitcoin.conf):
#    server=1
#    rpcuser=miner
#    rpcpassword=strong_password_here
#    rpcallowip=127.0.0.1

# 3. Edit lombokminer.toml:
#    [general]
#    mode = "solo"
#
#    [wallet]
#    address = "bc1p..."
#
#    [solo]
#    bitcoind_rpc = "http://127.0.0.1:8332"
#    bitcoind_user = "miner"
#    bitcoind_pass = "strong_password_here"
#    coinbase_message = "/LombokMiner/"

# 4. Run
lombokminer mine
```

**IMPORTANT:** Solo mining with a CPU will never find a block on mainnet
(ETA: billions of years). Use for testnet/regtest or with ASIC hardware.

**Testnet (for learning/testing):**
```bash
# bitcoind -testnet
# Edit lombokminer.toml:
#   bitcoind_rpc = "http://127.0.0.1:18332"
lombokminer mine -b 207fffff    # Low difficulty, block found quickly
```

### 5.3 Pool Mining

```bash
# 1. Register at a pool (e.g., Braiins, F2Pool, AntPool, ViaBTC)
# 2. Get your worker name and pool URL

# 3. Edit lombokminer.toml:
#    [general]
#    mode = "pool"
#
#    [pool.primary]
#    url = "sv2://stratum.braiins.com:3336"
#    protocol = "stratum_v2"
#    user = "username.worker1"
#    password = "x"

# 4. Run
lombokminer mine
```

### 5.4 CPU Mining (Multi-Thread)

```bash
# Auto-detect all CPU cores
lombokminer mine -t 0

# Use 4 threads
lombokminer mine -t 4

# Benchmark first to find the optimal hashrate
lombokminer bench -m 100 -t 1    # 1 thread
lombokminer bench -m 100 -t 2    # 2 threads
lombokminer bench -m 100 -t 4    # 4 threads
lombokminer bench -m 100 -t 0    # all cores
# Compare results — sometimes N-1 threads is more optimal
```

### 5.5 Web Dashboard

```bash
# Ensure the dashboard is enabled in config:
#   [dashboard]
#   enabled = true
#   bind = "0.0.0.0:8080"

# Start the miner, then open a browser:
lombokminer mine &
# Dashboard: http://localhost:8080
# From another device on the network: http://MACHINE_IP:8080

# With authentication:
#   [dashboard]
#   auth = true
#   username = "admin"
#   password_hash = "..."
```

**Standalone dashboard (without the miner, demo mode):**
```bash
# Open dashboard/index.html directly in a browser
# Demo mode activates automatically with simulated data
```

### 5.6 Monitoring (Prometheus + Grafana)

```bash
# LombokMiner exposes metrics at /metrics (Prometheus text format)
# Default: http://127.0.0.1:9100/metrics

# prometheus.yml:
# scrape_configs:
#   - job_name: 'lombokminer'
#     static_configs:
#       - targets: ['localhost:9100']

# Available metrics:
#   lombokminer_hashrate_hps
#   lombokminer_shares_total{status="accepted|rejected|stale"}
#   lombokminer_device_temp_celsius{device="..."}
#   lombokminer_device_power_watts{device="..."}
#   lombokminer_pool_latency_ms{pool="..."}
#   lombokminer_uptime_seconds
#   lombokminer_blocks_found_total
```

---

## 6. Docker

### 6.1 Build Image

```dockerfile
# Dockerfile
FROM rust:1.80-slim AS builder

WORKDIR /build
COPY . .
RUN cargo build --release --bin lombokminer

FROM debian:bookworm-slim
COPY --from=builder /build/target/release/lombokminer /usr/local/bin/
COPY --from=builder /build/dashboard/index.html /opt/lombokminer/dashboard/

EXPOSE 8080 9100 4028
ENTRYPOINT ["lombokminer"]
CMD ["mine"]
```

**Ultra-minimal (static musl, FROM scratch):**
```dockerfile
# Dockerfile.static
FROM rust:1.80 AS builder

RUN apt-get update && apt-get install -y musl-tools
RUN rustup target add x86_64-unknown-linux-musl

WORKDIR /build
COPY . .
RUN cargo build --release --target x86_64-unknown-linux-musl --bin lombokminer

FROM scratch
COPY --from=builder /build/target/x86_64-unknown-linux-musl/release/lombokminer /lombokminer
COPY --from=builder /build/dashboard/index.html /dashboard/

EXPOSE 8080 9100 4028
ENTRYPOINT ["/lombokminer"]
CMD ["mine"]
```

```bash
# Build
docker build -t lombokminer:latest .

# Run
docker run -d \
  --name miner \
  -p 8080:8080 \
  -p 9100:9100 \
  -v $(pwd)/lombokminer.toml:/etc/lombokminer/lombokminer.toml:ro \
  lombokminer:latest mine

# View logs
docker logs -f miner

# Benchmark inside container
docker run --rm lombokminer:latest bench -m 50

# Self-test
docker run --rm lombokminer:latest selftest
```

### 6.2 Docker Compose (Mining + Monitoring)

```yaml
# docker-compose.yml
version: "3.8"

services:
  miner:
    build: .
    container_name: lombokminer
    restart: unless-stopped
    ports:
      - "8080:8080"    # Dashboard
      - "9100:9100"    # Prometheus metrics
      - "4028:4028"    # JSON-RPC API
    volumes:
      - ./lombokminer.toml:/etc/lombokminer/lombokminer.toml:ro
    command: mine

  prometheus:
    image: prom/prometheus:latest
    container_name: prometheus
    restart: unless-stopped
    ports:
      - "9090:9090"
    volumes:
      - ./prometheus.yml:/etc/prometheus/prometheus.yml:ro
      - prometheus_data:/prometheus

  grafana:
    image: grafana/grafana:latest
    container_name: grafana
    restart: unless-stopped
    ports:
      - "3000:3000"
    environment:
      - GF_SECURITY_ADMIN_PASSWORD=admin
    volumes:
      - grafana_data:/var/lib/grafana

volumes:
  prometheus_data:
  grafana_data:
```

```yaml
# prometheus.yml
global:
  scrape_interval: 15s

scrape_configs:
  - job_name: 'lombokminer'
    static_configs:
      - targets: ['miner:9100']
```

```bash
# Start the full stack
docker-compose up -d

# Access:
#   Dashboard:  http://localhost:8080
#   Prometheus: http://localhost:9090
#   Grafana:    http://localhost:3000 (admin/admin)
#
# In Grafana: Add data source → Prometheus → URL: http://prometheus:9090
```

### 6.3 Docker on Raspberry Pi

```bash
# Pi runs ARM64 — use a multi-arch build
docker buildx build --platform linux/arm64 -t lombokminer:arm64 .

# Or pull the pre-built ARM image:
docker run -d --name miner \
  -p 8080:8080 \
  -v ./lombokminer.toml:/etc/lombokminer/lombokminer.toml:ro \
  lombokminer:arm64 mine
```

---

## 7. Deploy to VPS / Cloud

### 7.1 Ubuntu VPS

```bash
# SSH into VPS
ssh root@your-vps-ip

# Install Rust + build
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
source ~/.cargo/env
apt update && apt install -y build-essential git

git clone https://github.com/codinglombok/lombokminer.git
cd lombokminer
cargo build --release
cp target/release/lombokminer /usr/local/bin/

# Generate config
lombokminer init
nano lombokminer.toml    # Edit wallet address and pool

# Test
lombokminer selftest

# Run as a service (see 7.4)
```

**Or upload a pre-built binary (faster):**
```bash
# On local machine — build a static binary
cargo build --release --target x86_64-unknown-linux-musl

# Upload to VPS
scp target/x86_64-unknown-linux-musl/release/lombokminer root@vps:/usr/local/bin/
scp lombokminer.toml root@vps:/etc/lombokminer/
```

### 7.2 AWS EC2

```bash
# Choose an instance: t3.medium (2 vCPU, 4GB) or c6i.xlarge (4 vCPU, compute-optimized)
# AMI: Ubuntu 22.04

# SSH in and install as in 7.1
# Security Group: open port 8080 (dashboard), 9100 (metrics)

# User data script (auto-install on launch):
#!/bin/bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
source /root/.cargo/env
apt-get update && apt-get install -y build-essential git
git clone https://github.com/codinglombok/lombokminer.git /opt/lombokminer
cd /opt/lombokminer && cargo build --release
cp target/release/lombokminer /usr/local/bin/
```

### 7.3 Google Cloud / Azure

Same procedure — create a VM instance with Ubuntu, then follow section 7.1.

**Google Cloud:**
```bash
gcloud compute instances create lombokminer \
  --machine-type=e2-medium \
  --image-family=ubuntu-2204-lts \
  --image-project=ubuntu-os-cloud
```

**Azure:**
```bash
az vm create --name lombokminer \
  --resource-group mining \
  --image Ubuntu2204 \
  --size Standard_B2s
```

### 7.4 Systemd Service

```bash
# Create a non-root user
sudo useradd -r -s /bin/false lombokminer
sudo mkdir -p /etc/lombokminer
sudo cp lombokminer.toml /etc/lombokminer/
sudo chown -R lombokminer:lombokminer /etc/lombokminer

# Create the service file
sudo tee /etc/systemd/system/lombokminer.service << 'EOF'
[Unit]
Description=LombokMiner Bitcoin Mining Software
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=lombokminer
Group=lombokminer
ExecStart=/usr/local/bin/lombokminer --config /etc/lombokminer/lombokminer.toml mine
Restart=always
RestartSec=10
StandardOutput=journal
StandardError=journal

# Security hardening
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
ReadOnlyPaths=/etc/lombokminer
PrivateTmp=yes

[Install]
WantedBy=multi-user.target
EOF

# Enable and start
sudo systemctl daemon-reload
sudo systemctl enable lombokminer
sudo systemctl start lombokminer

# Check status
sudo systemctl status lombokminer
sudo journalctl -u lombokminer -f    # Live logs
```

**Auto-restart, auto-start on boot, crash recovery** — all handled by systemd.

---

## 8. Deploy to Web Server / Shared Hosting

### 8.1 Dashboard Only (Static HTML)

The LombokMiner dashboard is a single HTML file — it can be hosted anywhere:

```bash
# Copy the dashboard to a web server
cp dashboard/index.html /var/www/html/miner-dashboard.html

# Open: http://your-server.com/miner-dashboard.html
# Demo mode activates (simulated data) since there is no WebSocket backend
```

**For a live dashboard (connected to the miner):**
The dashboard needs a WebSocket connection to the LombokMiner backend. Options:
1. Run the miner and dashboard on the same VPS
2. Use a reverse proxy (see 8.3/8.4) to forward WebSocket traffic

### 8.2 cPanel / Shared Hosting

**Shared hosting CANNOT run the miner binary** (no root/SSH access).
However, it can be used for:

**A. Dashboard monitoring (static HTML):**
```
1. Upload dashboard/index.html to public_html/ via File Manager
2. Rename to index.html or dashboard.html
3. Access: https://yourdomain.com/dashboard.html
4. Dashboard runs in demo mode
```

**B. PHP monitoring panel (connects to miner on a separate VPS):**
```php
<?php
// monitor.php — on shared hosting, fetches metrics from the VPS miner
$metricsUrl = 'http://your-vps-ip:9100/metrics';
$data = file_get_contents($metricsUrl);
header('Content-Type: text/plain');
echo $data;
?>
```

**C. PHP bindings (if the hosting has the FFI extension):**
```
1. Upload liblombokminer.so to hosting (via SSH/SFTP)
2. Upload bindings/php/LombokMiner.php
3. Only usable for hashing/validation, NOT mining
   (mining requires a long-running process, which shared hosting does not allow)
```

### 8.3 Nginx Reverse Proxy

```nginx
# /etc/nginx/sites-available/lombokminer
server {
    listen 80;
    server_name miner.yourdomain.com;

    # Dashboard
    location / {
        proxy_pass http://127.0.0.1:8080;
        proxy_http_version 1.1;
    }

    # WebSocket (real-time metrics)
    location /ws {
        proxy_pass http://127.0.0.1:8080;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_read_timeout 86400;
    }

    # Prometheus metrics (restrict to internal networks)
    location /metrics {
        proxy_pass http://127.0.0.1:9100;
        allow 127.0.0.1;
        allow 10.0.0.0/8;
        deny all;
    }
}
```

```bash
sudo ln -s /etc/nginx/sites-available/lombokminer /etc/nginx/sites-enabled/
sudo nginx -t && sudo systemctl reload nginx

# With HTTPS (Let's Encrypt):
sudo apt install -y certbot python3-certbot-nginx
sudo certbot --nginx -d miner.yourdomain.com
```

### 8.4 Apache Reverse Proxy

```apache
# /etc/apache2/sites-available/lombokminer.conf
<VirtualHost *:80>
    ServerName miner.yourdomain.com

    ProxyPreserveHost On

    # Dashboard
    ProxyPass / http://127.0.0.1:8080/
    ProxyPassReverse / http://127.0.0.1:8080/

    # WebSocket
    RewriteEngine On
    RewriteCond %{HTTP:Upgrade} websocket [NC]
    RewriteRule /ws(.*) ws://127.0.0.1:8080/ws$1 [P,L]
</VirtualHost>
```

```bash
sudo a2enmod proxy proxy_http proxy_wstunnel rewrite
sudo a2ensite lombokminer
sudo systemctl reload apache2
```

---

## 9. Raspberry Pi & SBC

### 9.1 Raspberry Pi 4/5 (Native)

```bash
# Raspberry Pi OS 64-bit (Bookworm)

# Install Rust
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source ~/.cargo/env

# Build (15–30 minutes on Pi 4)
git clone https://github.com/codinglombok/lombokminer.git
cd lombokminer
cargo build --release

# Install
sudo cp target/release/lombokminer /usr/local/bin/

# Test
lombokminer selftest
lombokminer info
# Output: aarch64 (NEON) backend, hashrate ~50–200 KH/s

# Mining (testnet — mainnet CPU mining is not realistic)
lombokminer mine -b 207fffff -t 4

# Dashboard (access from a phone/laptop on the same network)
# Edit lombokminer.toml:
#   [dashboard]
#   bind = "0.0.0.0:8080"
# Open: http://raspberrypi.local:8080
```

**Auto-start on boot:**
```bash
# Create a systemd service (same as section 7.4)
sudo systemctl enable lombokminer
sudo systemctl start lombokminer
```

### 9.2 Raspberry Pi + ASIC USB

```bash
# GekkoScience Compac F / NewPac / R909 USB miners
# Plug in via USB to the Pi

# LombokMiner auto-detects USB ASIC devices:
#   [hardware.asic]
#   enabled = true
#   auto_detect = true

# Check detection:
lsusb | grep -i "1a86\|0403\|10c4\|2100"
# If a USB device appears → ASIC detected

lombokminer info
# Output should list the ASIC device under devices

# Mining with ASIC:
#   [hardware.cpu]
#   enabled = false        # Disable CPU mining, let the ASIC handle it
#
#   [hardware.asic]
#   enabled = true
#   auto_detect = true

lombokminer mine
```

**USB permissions:**
```bash
# If ASIC is not detected — add udev rules
sudo tee /etc/udev/rules.d/99-asic.rules << 'EOF'
# GekkoScience
SUBSYSTEM=="usb", ATTR{idVendor}=="2100", MODE="0666"
# CH341 (Bitmain)
SUBSYSTEM=="usb", ATTR{idVendor}=="1a86", MODE="0666"
# FTDI
SUBSYSTEM=="usb", ATTR{idVendor}=="0403", MODE="0666"
# CP2102
SUBSYSTEM=="usb", ATTR{idVendor}=="10c4", MODE="0666"
EOF

sudo udevadm control --reload-rules
# Unplug and re-plug the ASIC
```

### 9.3 Orange Pi / Rock Pi / Odroid

Same procedure as Raspberry Pi — all ARM64 SBCs are supported:

```bash
# Ensure 64-bit OS (aarch64)
uname -m    # Must be: aarch64

# Install Rust and build as in section 9.1
# Cross-compile from a desktop also works (see section 2.6)
```

---

## 10. Language Bindings

### 10.1 Python

```bash
# 1. Build the shared library
cd lombokminer
cargo build --release -p lombokminer-ffi

# 2. Copy the library to your Python project
cp target/release/liblombokminer.so my_project/
# macOS: liblombokminer.dylib
# Windows: lombokminer.dll

# 3. Copy the Python wrapper
cp bindings/python/lombokminer/__init__.py my_project/lombokminer.py
```

```python
# my_script.py
from lombokminer import LombokMiner

miner = LombokMiner("./liblombokminer.so")

# SHA-256d
print(miner.sha256d(b"hello").hex())

# Address validation
valid, network = miner.validate_address("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4")
print(f"Valid: {valid}, Network: {network}")

# Mining (CPU)
header = bytes(80)  # 80-byte block header
nonce, hash_bytes = miner.mine_cpu(header, nbits=0x207fffff, threads=4)
if nonce is not None:
    print(f"Found nonce: {nonce}")

# Difficulty
print(f"Difficulty: {miner.difficulty(0x17034219)}")
```

### 10.2 PHP

```bash
# 1. Ensure PHP FFI extension is active
php -m | grep FFI
# If not listed: edit php.ini → extension=ffi

# 2. Build the shared library (same as Python)
cargo build --release -p lombokminer-ffi

# 3. Copy the library + PHP wrapper
cp target/release/liblombokminer.so /path/to/web/
cp bindings/php/LombokMiner.php /path/to/web/
```

```php
<?php
require_once 'LombokMiner.php';

$miner = new LombokMiner('/path/to/liblombokminer.so');

// SHA-256d
echo $miner->sha256dHex('hello') . "\n";

// Address validation
$result = $miner->validateAddress('bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4');
var_dump($result);
// ['valid' => true, 'network' => 'mainnet']

// Difficulty
echo "Difficulty: " . $miner->difficulty(0x17034219) . "\n";
```

### 10.3 C/C++

```bash
# 1. Build the static + shared library
cargo build --release -p lombokminer-ffi

# 2. Copy the header + library
cp bindings/headers/lombokminer.h /usr/local/include/
cp target/release/liblombokminer.a /usr/local/lib/
# or .so for shared linking
```

```c
// main.c
#include <stdio.h>
#include "lombokminer.h"

int main() {
    printf("LombokMiner %s\n", lombokminer_version());

    // Self-test
    if (lombokminer_selftest() != 0) {
        printf("SELF-TEST FAILED\n");
        return 1;
    }

    // SHA-256d
    uint8_t hash[32];
    lombokminer_sha256d((uint8_t*)"hello", 5, hash);
    printf("SHA-256d(hello) = ");
    for (int i = 0; i < 32; i++) printf("%02x", hash[i]);
    printf("\n");

    // Validate address
    int net = lombokminer_validate_address("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4");
    printf("Address: %s\n", net == 0 ? "mainnet" : "invalid");

    return 0;
}
```

```bash
# Compile (static link)
gcc -o miner main.c -L/usr/local/lib -llombokminer -lpthread -ldl -lm

# Compile (shared link)
gcc -o miner main.c -L./target/release -llombokminer -Wl,-rpath,./target/release
```

---

## 11. Troubleshooting

### Build Errors

| Error | Solution |
|---|---|
| `rustc not found` | Install Rust: `curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs \| sh` |
| `linker 'cc' not found` | Install build tools: `apt install build-essential` (Ubuntu) |
| `link.exe not found` (Windows) | Install Visual Studio Build Tools |
| `edition2024 required` | Rust version too old — run `rustup update` |
| Out of memory during compile | Reduce parallelism: `cargo build -j 1 --release` |
| Compile takes too long on Pi | Cross-compile from a desktop (see section 2.6), or use a pre-built binary |

### Runtime Errors

| Error | Solution |
|---|---|
| `config parse error` | Check TOML syntax: `lombokminer config` |
| `invalid wallet address` | Use `lombokminer validate <address>` to debug |
| `connection refused (pool)` | Check pool URL, port, and firewall |
| `selftest FAILED` | Binary may be corrupt — re-download or re-compile |
| Dashboard not accessible | Check `bind` in config; ensure the port is open in the firewall |

### Firewall

```bash
# UFW (Ubuntu)
sudo ufw allow 8080/tcp    # Dashboard
sudo ufw allow 9100/tcp    # Prometheus (only from monitoring server)

# firewalld (Fedora/CentOS)
sudo firewall-cmd --add-port=8080/tcp --permanent
sudo firewall-cmd --reload

# Windows Firewall
# Settings → Firewall → Allow an app → Add lombokminer.exe
```

---

## 12. Quick Reference

### CLI Commands

```
lombokminer selftest                  Verify all 12 components
lombokminer bench -m 50 -t 4         Benchmark 50M hashes, 4 threads
lombokminer info                      System info + hashrate
lombokminer init                      Generate lombokminer.toml
lombokminer mine                      Start mining (from config)
lombokminer mine -b 207fffff -t 2    Mine with custom difficulty, 2 threads
lombokminer validate <addr>           Validate a Bitcoin address
lombokminer config                    Display active config
lombokminer --config /path mine       Use a custom config file
```

### Default Ports

```
8080    Dashboard web UI
9100    Prometheus metrics (/metrics)
4028    JSON-RPC API
3336    Stratum V2 (outbound to pool)
3333    Stratum V1 (outbound to pool)
8332    bitcoind RPC (solo mining)
```

### Environment Variables

```bash
RUST_LOG=debug lombokminer mine       # Verbose logging
RUST_LOG=lombokminer=trace            # Trace-level for lombokminer only
```

### Platform Support Matrix

| Platform | Build | Test | Status |
|---|---|---|---|
| Linux x86_64 | Yes | Yes | Production |
| Linux aarch64 (Pi/ARM) | Yes | Yes | Production |
| Windows x86_64 | Yes | Yes | Production |
| macOS x86_64 (Intel) | Yes | Yes | Production |
| macOS aarch64 (Apple Silicon) | Yes | Yes | Production |
| Linux musl (static) | Yes | Yes | Production |
| FreeBSD | Yes | Yes | Supported |
| Docker (x86_64 + ARM64) | Yes | Yes | Production |

---

*LombokMiner v1.0.0 — Apache-2.0 — [github.com/codinglombok/lombokminer](https://github.com/codinglombok/lombokminer)*
