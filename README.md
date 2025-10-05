# Network Monitoring Dashboard

A comprehensive, real-time network monitoring solution built with Python, Flask, and Socket.IO. Features include device management, performance metrics, topology visualization, and an AI chatbot assistant.

![Network Monitoring](https://img.shields.io/badge/Python-3.8+-blue.svg)
![Flask](https://img.shields.io/badge/Flask-3.0+-green.svg)
![License](https://img.shields.io/badge/license-MIT-blue.svg)

## 🚀 Features

### Core Monitoring
- **Real-time Interface Monitoring** - Track bandwidth usage across all network interfaces
- **Latency & Packet Loss** - Monitor ping times, jitter, and packet loss to key targets
- **Device Discovery** - Automatic network device detection and status tracking
- **Performance Metrics** - CPU, memory, bandwidth tracking per device
- **Intrusion Detection** - SYN flood and port scan detection

### Dashboard & Visualization
- **Interactive Charts** - Real-time Chart.js visualizations for all metrics
- **KPI Cards** - Color-coded summary cards for quick status overview
- **Topology View** - Visual network map with status-colored nodes
- **Multi-tab Interface** - Organized views for Dashboard, Devices, Alerts, Reports, Topology

### Advanced Features
- **Historical Reports** - Time-series analysis with 1h/24h/7d windows
- **Data Export** - Export metrics to CSV/JSON format
- **SNMP Polling** - Optional SNMP support for router/switch monitoring
- **MongoDB Integration** - Persistent storage for historical analysis
- **AI Chatbot** - Built-in assistant for network queries
- **Role-Based Access** - Admin and viewer roles with session management

### Alerting System
- **Traffic Spike Detection** - Automatic anomaly detection
- **Device Down Alerts** - Notifications when devices become unreachable
- **Performance Warnings** - Alerts for high CPU/memory/latency
- **Multiple Channels** - Email (SMTP) and SMS (Twilio) support

## 📋 Prerequisites

- Python 3.8 or higher
- Windows/Linux/macOS
- Network access for monitoring

### Optional Dependencies
- MongoDB (for persistent storage)
- SNMP-enabled devices (for advanced monitoring)
- WinPcap/Npcap (for packet capture on Windows)

## 🛠️ Installation

### 1. Clone the Repository
```bash
git clone https://github.com/Agam0795/Network-Monitoring.git
cd Network-Monitoring
```

### 2. Install Required Packages
```bash
pip install flask flask-socketio psutil scapy
```

### 3. Install Optional Packages (Recommended)
```bash
# For MongoDB support
pip install pymongo

# For SNMP monitoring
pip install pysnmp

# For SMS alerts
pip install twilio
```

### 4. Run the Application
```bash
python app.py
```

The dashboard will be available at `http://localhost:5000`

## 🎯 Quick Start

### Default Login Credentials
- **Admin**: `admin` / `admin` (full access)
- **Viewer**: `viewer` / `viewer` (read-only)

### First Steps
1. Open your browser to `http://localhost:5000`
2. Click "Login" in the top-right corner
3. Use admin credentials to explore all features
4. Navigate to the **Devices** tab to add network devices
5. Check the **Dashboard** for real-time metrics
6. Try the **Chatbot** (💬 icon) for quick queries

## ⚙️ Configuration

### Environment Variables

```bash
# Security
export ADMIN_TOKEN="your-secure-token"
export SECRET_KEY="your-secret-key"
export ADMIN_PASS="admin-password"
export VIEWER_PASS="viewer-password"

# MongoDB (optional)
export MONGO_URI="mongodb://localhost:27017"
export MONGO_DB_NAME="network_monitor"

# SNMP Polling (optional)
export SNMP_POLL_ENABLED="1"
export SNMP_COMMUNITY="public"
export SNMP_PORT="161"

# Email Alerts (optional)
# Configure in app.py lines 48-53
```

### Application Settings

Edit `app.py` to customize:

```python
# Line 36-37: Server binding
BIND_HOST = '0.0.0.0'
BIND_PORT = 5000

# Line 43-44: Monitoring targets
PING_TARGETS = ["8.8.8.8", "1.1.1.1"]
PING_COUNT = 3

# Line 91-96: Performance thresholds
CONFIG = {
    "traffic_spike_factor": 3.0,
    "high_rtt_ms": 500,
    "high_loss_pct": 50,
    "warn_cpu_pct": 85,
    "warn_mem_pct": 90,
}
```

## 📊 Usage Examples

### Adding a Device
```javascript
// Via API
POST http://localhost:5000/devices
{
    "ip": "192.168.1.1",
    "label": "Main Router",
    "type": "Router",
    "mac": "00:11:22:33:44:55",
    "snmp_enabled": true
}
```

### Querying Reports
```bash
# Get summary report
curl "http://localhost:5000/reports/summary?range=24h"

# Export latency data as CSV
curl "http://localhost:5000/reports/export?kind=latency&format=csv&range=24h"

# Get topology
curl "http://localhost:5000/topology"
```

### Chatbot Queries
- "How many devices are up?"
- "What is the current latency?"
- "Show me network status"
- "How many alerts in the last hour?"

## 🗂️ Project Structure

```
Network-Monitoring/
├── app.py                          # Main application file
├── devices.json                    # Device persistence (auto-generated)
├── events.log                      # Alert log file (auto-generated)
├── README.md                       # This file
└── assets/                         # UI images
    ├── network-performance-monitoring-cpu-memory-disk1.avif
    ├── network-performance-monitoring-network-dashboards.avif
    ├── network-performance-monitoring-performance-monitors.avif
    └── network-performance-monitoring-traffic1.avif
```

## 🔌 API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/` | GET | Main dashboard |
| `/login` | GET/POST | User authentication |
| `/logout` | GET | User logout |
| `/whoami` | GET | Current user info |
| `/devices` | GET | List all devices |
| `/devices` | POST | Add new device (admin) |
| `/devices/<ip>` | DELETE | Remove device (admin) |
| `/summary` | GET | KPI summary |
| `/alerts` | GET | Recent alerts |
| `/config` | GET/POST | Runtime configuration |
| `/reports/summary` | GET | Report aggregates |
| `/reports/timeseries` | GET | Time-series data |
| `/reports/export` | GET | Export data (CSV/JSON) |
| `/topology` | GET | Network topology |
| `/top_talkers` | GET | Top bandwidth consumers |
| `/chat` | POST | Chatbot queries |

## 🎨 Screenshots

### Dashboard View
Real-time monitoring with interactive charts, KPI cards, and live updates.

### Device Management
Add, remove, and monitor network devices with status tracking.

### Reports & Analytics
Historical analysis with exportable data in multiple formats.

### Topology Visualization
Visual network map showing device relationships and status.

## 🛡️ Security Features

- Session-based authentication
- Role-based access control (Admin/Viewer)
- CSRF protection via Flask secret key
- Admin-only device management
- Secure MongoDB connections
- Input validation on all endpoints

## 🐛 Troubleshooting

### Port Already in Use
```bash
# Windows
Get-NetTCPConnection -LocalPort 5000 | Select-Object -ExpandProperty OwningProcess | Stop-Process -Force

# Linux/Mac
lsof -ti:5000 | xargs kill -9
```

### Packet Sniffing Not Working
On Windows, packet capture requires WinPcap or Npcap. The app works without it, but with reduced traffic analysis capabilities.

```bash
# Download and install Npcap
# https://npcap.com/#download
```

### MongoDB Connection Failed
Ensure MongoDB is running and the URI is correct:
```bash
# Check MongoDB status
mongod --version

# Test connection
mongo --eval "db.adminCommand('ping')"
```

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

## 📝 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 👤 Author

**Agam**
- GitHub: [@Agam0795](https://github.com/Agam0795)

## 🙏 Acknowledgments

- Flask and Flask-SocketIO for the web framework
- Chart.js for beautiful visualizations
- Scapy for network packet analysis
- psutil for system metrics
- Tailwind CSS for modern styling

## 📮 Support

For support, please open an issue in the GitHub repository or contact the maintainer.

---

**⭐ Star this repository if you find it helpful!**
