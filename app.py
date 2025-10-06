import time
import threading
import subprocess
import psutil
import collections
import random
import statistics
import smtplib
import json
import os
import socket
import ipaddress
import importlib
from datetime import datetime
from flask import Flask, render_template_string, request, jsonify, send_from_directory, abort, redirect, url_for, session
from flask_socketio import SocketIO, emit
import warnings
warnings.filterwarnings('ignore', category=DeprecationWarning)
from scapy.all import sniff, IP, TCP, UDP
import logging
logging.getLogger('scapy').setLevel(logging.ERROR)
try:
    from pymongo import MongoClient
except Exception:
    MongoClient = None
try:
    from pysnmp.hlapi import SnmpEngine, CommunityData, UdpTransportTarget, ContextData, ObjectType, ObjectIdentity, getCmd, nextCmd
except Exception:
    SnmpEngine = None

# -------- Configuration --------
BIND_HOST = '0.0.0.0'
BIND_PORT = 5000

SNAP_LEN = 65535
SNIFF_INTERFACE = None  # None means default; set to "eth0" if you want
METRIC_INTERVAL = 1.0   # seconds for sampling
HISTORY_LEN = 300       # keep last N samples

PING_TARGETS = ["8.8.8.8", "1.1.1.1"]  # hosts to monitor latency/loss
PING_COUNT = 3

ALERT_EMAIL_FROM = "monitor@example.com"
ALERT_EMAIL_TO = "you@example.com"
SMTP_SERVER = "smtp.example.com"
SMTP_PORT = 587
SMTP_USER = "smtp_user"
SMTP_PASS = "smtp_pass"

# Twilio placeholder
TWILIO_ENABLED = False
TWILIO_SID = "TWILIO_SID"
TWILIO_TOKEN = "TWILIO_TOKEN"
TWILIO_FROM = "+15550000000"
TWILIO_TO = "+15551112222"

# Simple RBAC (Admin token for write endpoints)
ADMIN_TOKEN = os.environ.get("ADMIN_TOKEN", "admin123")
# Demo accounts
ACCOUNTS = {
    "admin": {"password": os.environ.get("ADMIN_PASS", "admin"), "role": "admin"},
    "viewer": {"password": os.environ.get("VIEWER_PASS", "viewer"), "role": "viewer"},
}

# Devices persistence and discovery settings
DEVICES_FILE = os.path.join(os.path.dirname(__file__), "devices.json")
AUTO_DISCOVERY = True
DISCOVERY_INTERVAL = 60  # seconds
DEVICE_PING_INTERVAL = 10  # seconds

# MongoDB configuration
MONGO_URI = os.environ.get("MONGO_URI", "")
MONGO_DB_NAME = os.environ.get("MONGO_DB_NAME", "network_monitor")

# SNMP configuration
SNMP_POLL_ENABLED = os.environ.get("SNMP_POLL_ENABLED", "0") == "1"
SNMP_COMMUNITY = os.environ.get("SNMP_COMMUNITY", "public")
SNMP_PORT = int(os.environ.get("SNMP_PORT", "161"))

# Intrusion detection thresholds
PORTSCAN_PORTS_THRESHOLD = 20      # different destination ports within window
PORTSCAN_WINDOW = 10              # seconds
SYN_RATE_THRESHOLD = 500          # SYN packets per window (very aggressive threshold)
SYN_WINDOW = 5                    # seconds
TRAFFIC_SPIKE_FACTOR = 3.0        # spike factor over moving average

# Runtime-configurable thresholds (can be updated via /config)
CONFIG = {
    "traffic_spike_factor": TRAFFIC_SPIKE_FACTOR,
    "high_rtt_ms": 500,
    "high_loss_pct": 50,
    "warn_cpu_pct": 85,
    "warn_mem_pct": 90,
}

# -------- Global state --------
app = Flask(__name__)
socketio = SocketIO(app, cors_allowed_origins="*")  # eventlet/gthread works
app.secret_key = os.environ.get("SECRET_KEY", "dev-secret-key")

# Time-series stores
interface_history = collections.deque(maxlen=HISTORY_LEN)   # list of {timestamp, pernic bytes_sent/recv}
latency_history = collections.deque(maxlen=HISTORY_LEN)     # list of {timestamp, target, rtt_ms, loss_pct}
_jitter_map = collections.defaultdict(lambda: collections.deque(maxlen=20))  # host -> recent RTTs for jitter
uptime_info = {}
app_usage = collections.defaultdict(int)   # pid -> bytes
port_usage = collections.defaultdict(int)  # (localport, proto) -> bytes
device_usage = collections.defaultdict(int) # ip -> bytes

# Devices registry and in-app alerts
devices = {}  # ip -> {ip, label, type, mac, status, last_seen_ts, rtt_ms, loss_pct, cpu_pct, mem_pct, bw_up_bps, bw_down_bps}
alerts = collections.deque(maxlen=200)  # recent alerts for UI
ALERT_LOG_FILE = os.path.join(os.path.dirname(__file__), "events.log")

# MongoDB client/collections
mongo_client = None
mongo_db = None
col_interfaces = None
col_latency = None
col_alerts = None
col_devices = None
col_device_status = None

def init_mongo():
    global mongo_client, mongo_db, col_interfaces, col_latency, col_alerts, col_devices, col_device_status
    if not MONGO_URI or MongoClient is None:
        return
    try:
        mongo_client = MongoClient(MONGO_URI, serverSelectionTimeoutMS=5000)
        mongo_db = mongo_client[MONGO_DB_NAME]
        col_interfaces = mongo_db["interfaces"]
        col_latency = mongo_db["latency"]
        col_alerts = mongo_db["alerts"]
        col_devices = mongo_db["devices"]
        col_device_status = mongo_db["device_status"]
        # quick ping
        mongo_client.admin.command('ping')
        # helpful indexes for time-based queries
        try:
            col_interfaces.create_index("ts")
            col_latency.create_index("ts")
            col_alerts.create_index([("ts", 1), ("kind", 1)])
            col_devices.create_index("ip", unique=True)
            col_device_status.create_index([("ip", 1), ("ts", 1)])
        except Exception:
            pass
        print("MongoDB connected")
    except Exception as e:
        print("Mongo init failed:", e)

def db_insert(col, doc):
    try:
        if col:
            col.insert_one(doc)
    except Exception as e:
        print("Mongo insert failed:", e)

# For intrusion detection
recent_remote_ports = collections.defaultdict(lambda: collections.deque())  # src_ip -> deque of (timestamp, dstport)
recent_syn_times = collections.deque()  # timestamps of SYN packets
last_alert_times = {}  # kind -> timestamp to throttle
last_device_persist_ts = {}  # ip -> last ts persisted

# Map local TCP/UDP port -> pid (recomputed periodically)
port_to_pid = {}  # (laddr.ip, laddr.port, proto) -> pid
portmap_lock = threading.Lock()

# Helper: throttle alerts to once per X seconds per type
ALERT_THROTTLE_SECONDS = 60

def now_ts():
    return time.time()

# -------- Utilities: alerts --------
# Track if email is configured
_email_disabled_logged = False

def send_email_alert(subject, body):
    """
    Simple SMTP email. Configure SMTP_* constants above.
    """
    global _email_disabled_logged
    # Skip if using default unconfigured SMTP
    if SMTP_SERVER == "smtp.example.com":
        if not _email_disabled_logged:
            print("[INFO] Email alerts disabled (configure SMTP_SERVER to enable)")
            _email_disabled_logged = True
        return
    try:
        msg = f"From: {ALERT_EMAIL_FROM}\r\nTo: {ALERT_EMAIL_TO}\r\nSubject: {subject}\r\n\r\n{body}"
        server = smtplib.SMTP(SMTP_SERVER, SMTP_PORT, timeout=10)
        server.starttls()
        server.login(SMTP_USER, SMTP_PASS)
        server.sendmail(ALERT_EMAIL_FROM, [ALERT_EMAIL_TO], msg)
        server.quit()
        print("[ALERT] Email sent:", subject)
    except Exception as e:
        if not _email_disabled_logged:
            print("[ALERT] Email failed:", e)
            _email_disabled_logged = True

def record_alert(kind, subject, body):
    item = {"ts": now_ts(), "kind": kind, "subject": subject, "body": body}
    alerts.append(item)
    try:
        socketio.emit('alert', item)
    except Exception:
        pass
    # append to log file
    try:
        with open(ALERT_LOG_FILE, 'a', encoding='utf-8') as f:
            f.write(f"{datetime.fromtimestamp(item['ts']).isoformat()}\t{kind}\t{subject}\t{body}\n")
    except Exception:
        pass
    # persist to Mongo (if configured)
    try:
        db_insert(col_alerts, dict(item))
    except Exception:
        pass

_sms_disabled_logged = False

def send_sms_alert(text):
    """
    Placeholder for SMS (Twilio).
    """
    global _sms_disabled_logged
    if not TWILIO_ENABLED:
        if not _sms_disabled_logged:
            print("[INFO] SMS alerts disabled (set TWILIO_ENABLED=True to enable)")
            _sms_disabled_logged = True
        return
    try:
        twilio_rest = importlib.import_module('twilio.rest')
        TwilioClient = getattr(twilio_rest, 'Client')
        client = TwilioClient(TWILIO_SID, TWILIO_TOKEN)
        msg = client.messages.create(body=text, from_=TWILIO_FROM, to=TWILIO_TO)
        print("[ALERT] SMS sent:", msg.sid)
    except Exception as e:
        print("[ALERT] SMS failed:", e)

def maybe_alert(kind, subject, body):
    last = last_alert_times.get(kind, 0)
    if now_ts() - last < ALERT_THROTTLE_SECONDS:
        return
    last_alert_times[kind] = now_ts()
    # record in-app
    record_alert(kind, subject, body)
    # spawn senders in background
    threading.Thread(target=send_email_alert, args=(subject, body), daemon=True).start()
    threading.Thread(target=send_sms_alert, args=(subject + " " + (body[:140] if body else ""),), daemon=True).start()

# -------- Devices persistence and helpers --------
def load_devices():
    global devices
    try:
        if os.path.exists(DEVICES_FILE):
            with open(DEVICES_FILE, 'r', encoding='utf-8') as f:
                data = json.load(f)
                # normalize
                for ip, info in data.items():
                    info.setdefault('label', ip)
                    info.setdefault('type', 'Device')
                    info.setdefault('mac', '')
                    info.setdefault('snmp_enabled', False)
                    info.setdefault('status', 'unknown')
                    info.setdefault('last_seen_ts', 0)
                    info.setdefault('rtt_ms', None)
                    info.setdefault('loss_pct', None)
                    info.setdefault('cpu_pct', None)
                    info.setdefault('mem_pct', None)
                    info.setdefault('bw_up_bps', 0)
                    info.setdefault('bw_down_bps', 0)
                devices = data
        else:
            devices = {}
    except Exception as e:
        print("Failed to load devices:", e)
        devices = {}

def save_devices():
    try:
        with open(DEVICES_FILE, 'w', encoding='utf-8') as f:
            json.dump(devices, f, indent=2)
    except Exception as e:
        print("Failed to save devices:", e)

def current_user():
    return session.get('user')

def is_admin(req) -> bool:
    token = req.headers.get('X-Admin-Token') or req.args.get('token')
    if token == ADMIN_TOKEN:
        return True
    u = current_user()
    return bool(u and u.get('role') == 'admin')

# -------- Device discovery and monitoring --------
def classify_status(info):
    # Determine status based on loss/rtt/cpu/mem; 'down' if long stale or explicit down
    if info.get('status') == 'down':
        return 'down'
    warn = False
    if info.get('loss_pct') is not None and info['loss_pct'] > CONFIG.get('high_loss_pct', 50):
        warn = True
    if info.get('rtt_ms') is not None and info['rtt_ms'] > CONFIG.get('high_rtt_ms', 500):
        warn = True
    if info.get('cpu_pct') is not None and info['cpu_pct'] > CONFIG.get('warn_cpu_pct', 85):
        warn = True
    if info.get('mem_pct') is not None and info['mem_pct'] > CONFIG.get('warn_mem_pct', 90):
        warn = True
    return 'warning' if warn else 'up'
def iter_local_networks():
    nets = []
    try:
        for name, ifaddrs in psutil.net_if_addrs().items():
            for a in ifaddrs:
                if a.family == socket.AF_INET and a.netmask:
                    try:
                        network = ipaddress.IPv4Network(f"{a.address}/{a.netmask}", strict=False)
                        # Limit to reasonable size networks (avoid /8 scans)
                        if network.prefixlen >= 24:
                            nets.append(network)
                    except Exception:
                        pass
    except Exception:
        pass
    return nets

def ping_once(host: str, timeout_ms: int = 800):
    try:
        # Use Windows ping with single probe
        proc = subprocess.run(["ping", "-n", "1", "-w", str(timeout_ms), host], capture_output=True, text=True, timeout=(timeout_ms/1000.0 + 2))
        out = proc.stdout
        if proc.returncode != 0:
            return None
        # parse time=XXms
        for line in out.splitlines():
            if "time=" in line or "time<" in line:
                try:
                    if "time=" in line:
                        val = line.split("time=")[1].split("ms")[0]
                    else:
                        val = line.split("time<")[1].split("ms")[0]
                    return float(val)
                except Exception:
                    return 1.0
        return 1.0
    except Exception:
        return None

def device_discovery_loop():
    while True:
        if AUTO_DISCOVERY:
            nets = iter_local_networks()
            for net in nets:
                # Scan up to first 64 hosts to limit resource usage
                hosts = list(net.hosts())[:64]
                for ip in hosts:
                    ip_str = str(ip)
                    rtt = ping_once(ip_str, timeout_ms=500)
                    if rtt is not None:
                        info = devices.get(ip_str, {"ip": ip_str, "label": ip_str, "type": "Device", "mac": ""})
                        info["status"] = "up"
                        info["last_seen_ts"] = now_ts()
                        info["rtt_ms"] = rtt
                        info["loss_pct"] = 0.0
                        devices[ip_str] = info
                        socketio.emit('devices', list(devices.values()))
        time.sleep(DISCOVERY_INTERVAL)

def device_monitor_loop():
    while True:
        try:
            for ip, info in list(devices.items()):
                rtt = ping_once(ip, timeout_ms=800)
                if rtt is not None:
                    prev_status = info.get("status")
                    info["status"] = "up"
                    info["last_seen_ts"] = now_ts()
                    info["rtt_ms"] = rtt
                    info["loss_pct"] = 0.0
                    # recovery alert
                    if prev_status == 'down':
                        record_alert("recovery", f"Device recovered: {ip}", info.get('label', ip))
                else:
                    # if stale for > 2 intervals, mark down
                    if now_ts() - info.get("last_seen_ts", 0) > DEVICE_PING_INTERVAL * 2:
                        if info.get("status") != "down":
                            record_alert("device_down", f"Device down: {ip}", f"Label: {info.get('label', ip)}")
                        info["status"] = "down"
                        info["rtt_ms"] = None
                        info["loss_pct"] = None
                devices[ip] = info
            # After updates, compute warning status
            for ip, info in devices.items():
                if info.get('status') != 'down':
                    info['status'] = classify_status(info)
                # persist device status periodically or on change
                try:
                    ts = now_ts()
                    last_ts = last_device_persist_ts.get(ip, 0)
                    prev_status = info.get('_prev_status')
                    need = (ts - last_ts > 60) or (prev_status and prev_status != info.get('status'))
                    info['_prev_status'] = info.get('status')
                    if need:
                        last_device_persist_ts[ip] = ts
                        # upsert basic device doc
                        if col_devices:
                            db_insert(col_devices, {"ip": ip, "label": info.get('label') or ip, "type": info.get('type') or 'Device', "mac": info.get('mac','')}) if False else None
                            try:
                                col_devices.update_one({"ip": ip}, {"$set": {"label": info.get('label') or ip, "type": info.get('type') or 'Device', "mac": info.get('mac','')}}, upsert=True)
                            except Exception:
                                pass
                        # insert status sample
                        sample = {
                            "ts": ts,
                            "ip": ip,
                            "status": info.get('status'),
                            "rtt_ms": info.get('rtt_ms'),
                            "loss_pct": info.get('loss_pct'),
                            "cpu_pct": info.get('cpu_pct'),
                            "mem_pct": info.get('mem_pct'),
                            "bw_up_bps": info.get('bw_up_bps'),
                            "bw_down_bps": info.get('bw_down_bps'),
                        }
                        db_insert(col_device_status, sample)
                except Exception:
                    pass
            socketio.emit('devices', list(devices.values()))
        except Exception as e:
            print("device monitor error:", e)
        time.sleep(DEVICE_PING_INTERVAL)

# -------- Simulation of richer per-device metrics --------
def simulate_metrics_loop():
    # Simulate metrics every 2 seconds for demo
    while True:
        try:
            for ip, info in devices.items():
                if info.get('status') == 'down':
                    # keep zeroed metrics for down devices
                    info['cpu_pct'] = 0.0
                    info['mem_pct'] = info.get('mem_pct', 0.0)
                    info['bw_up_bps'] = 0
                    info['bw_down_bps'] = 0
                    continue
                # Smooth random walk for cpu/mem and bandwidth
                def smooth(val, step, lo, hi):
                    if val is None:
                        val = random.uniform(lo, hi)
                    val += random.uniform(-step, step)
                    return max(lo, min(hi, val))
                info['cpu_pct'] = round(smooth(info.get('cpu_pct'), 5, 5, 98), 1)
                info['mem_pct'] = round(smooth(info.get('mem_pct'), 3, 10, 96), 1)
                # jitter some loss for warnings
                info['loss_pct'] = max(0.0, round((info.get('loss_pct') or 0.0) + random.uniform(-1, 1), 1))
                # bandwidth up/down in bytes per second
                info['bw_up_bps'] = max(0, int(smooth(info.get('bw_up_bps'), 50000, 0, 2_000_000)))
                info['bw_down_bps'] = max(0, int(smooth(info.get('bw_down_bps'), 80000, 0, 4_000_000)))
                # latency jitter simulation if not present
                if info.get('rtt_ms') is None:
                    info['rtt_ms'] = round(random.uniform(10, 120), 1)
                else:
                    info['rtt_ms'] = round(max(1.0, info['rtt_ms'] + random.uniform(-5, 5)), 1)
                # recompute status and maybe warnings
                prev = info.get('status', 'unknown')
                now = classify_status(info)
                if prev != now:
                    if now == 'warning':
                        record_alert('warning', f'Performance issue on {ip}', f"RTT={info['rtt_ms']}ms CPU={info['cpu_pct']}% MEM={info['mem_pct']}% LOSS={info['loss_pct']}%")
                info['status'] = now
            # emit devices update
            socketio.emit('devices', list(devices.values()))
        except Exception as e:
            print('simulate metrics error:', e)
        time.sleep(2)

# -------- Port map builder --------
def rebuild_port_map():
    """
    Build mapping of local (ip,port,proto) -> pid using psutil.net_connections
    Run periodically (e.g., every 5 seconds)
    """
    global port_to_pid
    try:
        conns = psutil.net_connections(kind='inet')
    except Exception as e:
        print("Error fetching net connections:", e)
        return
    newmap = {}
    for c in conns:
        if c.laddr and c.pid:
            proto = 'tcp' if c.type == socket.SOCK_STREAM else 'udp'
            key = (c.laddr.ip, c.laddr.port, proto)
            # For listening with empty raddr: still map
            newmap[key] = c.pid
    with portmap_lock:
        port_to_pid = newmap

# -------- Packet handler (scapy) --------
import socket
def packet_handler(pkt):
    """
    Called by scapy for each packet. We use it to:
    - approximate per device (remote ip) usage
    - per port usage and map to pid if local port matches our port map
    - detect SYNs and possible port scans
    """
    ts = now_ts()
    try:
        if IP in pkt:
            ip = pkt[IP]
            src = ip.src
            dst = ip.dst
            plen = len(pkt)
            # record device traffic (counts bytes regardless of direction)
            device_usage[src] += plen
            device_usage[dst] += plen

            # Update port->pid mapping attempts
            proto = None
            lport = None
            rport = None
            is_local = False
            # determine if either src or dst is a local address
            local_ips = get_local_ips()
            if TCP in pkt:
                t = pkt[TCP]
                proto = 'tcp'
                sport = t.sport
                dport = t.dport
                # check if pkt is inbound or outbound relative to our host
                if src in local_ips:
                    laddr, lport = src, sport
                    raddr, rport = dst, dport
                    is_local = True
                elif dst in local_ips:
                    laddr, lport = dst, dport
                    raddr, rport = src, sport
                    is_local = True
                else:
                    # neither src nor dst local - ignore mapping
                    laddr = None
                # record SYNs for detection
                if t.flags & 0x02:  # SYN bit
                    recent_syn_times.append(ts)
                    # record remote port attempts
                    remote_ip = src
                    recent_remote_ports[remote_ip].append((ts, dport))
                    # clean old entries for this remote
                    dq = recent_remote_ports[remote_ip]
                    while dq and ts - dq[0][0] > PORTSCAN_WINDOW:
                        dq.popleft()

            elif UDP in pkt:
                u = pkt[UDP]
                proto = 'udp'
                sport = u.sport
                dport = u.dport
                if src in local_ips:
                    laddr, lport = src, sport
                    raddr, rport = dst, dport
                    is_local = True
                elif dst in local_ips:
                    laddr, lport = dst, dport
                    raddr, rport = src, sport
                    is_local = True
                else:
                    laddr = None
            else:
                proto = 'ip'
                laddr = None

            # map local port to pid and attrib bytes
            if is_local and laddr is not None and lport:
                with portmap_lock:
                    # try exact mapping
                    key = (laddr, lport, proto)
                    pid = port_to_pid.get(key)
                    # try wildcard ip mapping (0.0.0.0)
                    if not pid:
                        key2 = ("0.0.0.0", lport, proto)
                        pid = port_to_pid.get(key2)
                if pid:
                    app_usage[pid] += plen
                    port_usage[(lport, proto)] += plen
            # else we still record port usage by dst/sport if interesting
    except Exception as e:
        # avoid crashing sniff loop
        # print("packet handler error", e)
        pass

def get_local_ips():
    """Return set of local IPv4 addresses (cached)."""
    addrs = set()
    for name, ifaddrs in psutil.net_if_addrs().items():
        for a in ifaddrs:
            if a.family == socket.AF_INET:
                addrs.add(a.address)
    return addrs

# -------- Bandwidth monitor (per-interface) --------
def monitor_interfaces():
    prev = psutil.net_io_counters(pernic=True)
    prev_ts = now_ts()
    while True:
        time.sleep(METRIC_INTERVAL)
        ts = now_ts()
        try:
            cur = psutil.net_io_counters(pernic=True)
            sample = {"ts": ts, "interfaces": {}}
            for nic, stats in cur.items():
                pstats = prev.get(nic)
                if pstats:
                    sent_delta = stats.bytes_sent - pstats.bytes_sent
                    recv_delta = stats.bytes_recv - pstats.bytes_recv
                else:
                    sent_delta = stats.bytes_sent
                    recv_delta = stats.bytes_recv
                sample["interfaces"][nic] = {
                    "bytes_sent": sent_delta,
                    "bytes_recv": recv_delta,
                    "total": sent_delta + recv_delta
                }
            interface_history.append(sample)
            db_insert(col_interfaces, sample)
            prev = cur
            prev_ts = ts
            # check traffic spike anomaly
            total_now = sum(v["total"] for v in sample["interfaces"].values())
            # compute moving average over history
            totals = [sum(v["total"] for v in s["interfaces"].values()) for s in interface_history]
            if len(totals) > 10:
                avg = statistics.mean(totals)
                if avg > 0 and total_now > avg * TRAFFIC_SPIKE_FACTOR:
                    maybe_alert("traffic_spike",
                                "Traffic spike detected",
                                f"Traffic {total_now} bytes in last {METRIC_INTERVAL}s (> {TRAFFIC_SPIKE_FACTOR}x average {avg}).")
            # push update to clients
            socketio.emit('interfaces', sample)
        except Exception as e:
            print("interfaces monitor error:", e)

# -------- Latency & packet loss monitor --------
def ping_host(host, count=PING_COUNT):
    """
    Uses system ping to measure packet loss and avg rtt (ms). Works on Windows.
    Returns (rtt_ms_avg, loss_pct)
    """
    try:
        # Windows ping: '-n' count; '-w' timeout in milliseconds
        proc = subprocess.run(["ping", "-n", str(count), host], capture_output=True, text=True, timeout=10)
        out = proc.stdout
        if proc.returncode != 0:
            return None, 100.0
        # Windows ping output parsing
        rtt_avg = None
        loss_pct = None
        rtts = []
        for line in out.splitlines():
            # Look for "Lost = X (Y% loss)"
            if "Lost =" in line and "loss" in line:
                try:
                    loss_part = line.split("(")[1].split("%")[0]
                    loss_pct = float(loss_part)
                except:
                    pass
            # Look for "time=XXXms" or "time<XXXms"
            if "time=" in line or "time<" in line:
                try:
                    if "time=" in line:
                        time_part = line.split("time=")[1].split("ms")[0]
                    else:  # time<
                        time_part = line.split("time<")[1].split("ms")[0]
                    rtts.append(float(time_part))
                except:
                    pass
        if rtts:
            rtt_avg = sum(rtts) / len(rtts)
        return rtt_avg, loss_pct
    except Exception as e:
        # ping may require permissions or missing tool
        return None, None

def monitor_ping_targets():
    while True:
        for host in PING_TARGETS:
            rtt, loss = ping_host(host)
            # compute jitter as stdev of last rtts
            if rtt is not None:
                dq = _jitter_map[host]
                dq.append(rtt)
                jitter = statistics.pstdev(dq) if len(dq) > 1 else 0.0
            else:
                jitter = None
            sample = {"ts": now_ts(), "host": host, "rtt_ms": rtt, "loss_pct": loss, "jitter_ms": jitter}
            latency_history.append(sample)
            db_insert(col_latency, sample)
            socketio.emit('latency', sample)
            # check thresholds
            if loss is not None and loss > CONFIG.get("high_loss_pct", 50):
                maybe_alert("high_loss", f"High packet loss to {host}", f"Loss: {loss}%")
            if rtt is not None and rtt > CONFIG.get("high_rtt_ms", 500):
                maybe_alert("high_rtt", f"High RTT to {host}", f"RTT: {rtt} ms")
        time.sleep(10)

# -------- Uptime monitor --------
def monitor_uptime():
    boot = psutil.boot_time()
    while True:
        uptime_seconds = time.time() - boot
        uptime_info["boot_time"] = boot
        uptime_info["uptime_seconds"] = uptime_seconds
        uptime_info["now_ts"] = now_ts()
        socketio.emit('uptime', uptime_info)
        time.sleep(5)

# -------- Intrusion detection --------
def intrusion_detector():
    """
    - Port scan: many unique dst ports targeted by one remote IP within PORTSCAN_WINDOW
    - SYN flood: many SYN packets in short window
    """
    while True:
        ts = now_ts()
        # Clean SYN deque and evaluate rate
        while recent_syn_times and ts - recent_syn_times[0] > SYN_WINDOW:
            recent_syn_times.popleft()
        syn_count = len(recent_syn_times)
        if syn_count > SYN_RATE_THRESHOLD:
            maybe_alert("syn_flood", "Possible SYN flood detected", f"{syn_count} SYNs in last {SYN_WINDOW}s")
        # Port scan check
        for remote, dq in list(recent_remote_ports.items()):
            # dq contains (ts, port); remove stale
            while dq and ts - dq[0][0] > PORTSCAN_WINDOW:
                dq.popleft()
            unique_ports = set(p for t,p in dq)
            if len(unique_ports) >= PORTSCAN_PORTS_THRESHOLD:
                maybe_alert("portscan", "Possible port scan", f"{remote} targeted {len(unique_ports)} unique ports in {PORTSCAN_WINDOW}s")
                # after alert, clear to avoid repeat
                dq.clear()
        time.sleep(1)

# -------- Packet sniffing thread --------
def start_sniffer():
    # periodically rebuild port map
    def repmap_loop():
        while True:
            rebuild_port_map()
            time.sleep(5)
    threading.Thread(target=repmap_loop, daemon=True).start()

    # scapy sniff (blocking), but we'll run in a thread
    # Note: Packet sniffing requires WinPcap/Npcap on Windows
    try:
        sniff(prn=packet_handler, iface=SNIFF_INTERFACE, store=False, filter="ip")
    except Exception as e:
        # Silent fail - packet sniffing is optional; other monitoring continues
        pass

# -------- SNMP polling (optional) --------
def snmp_poll_loop():
    if not SNMP_POLL_ENABLED or SnmpEngine is None:
        return
    engine = SnmpEngine()
    while True:
        try:
            for ip, info in list(devices.items()):
                if not info or not info.get('snmp_enabled'):
                    continue
                target = UdpTransportTarget((ip, SNMP_PORT), timeout=1, retries=0)
                community = CommunityData(SNMP_COMMUNITY, mpModel=0)
                ctx = ContextData()
                # Example OIDs: hrProcessorLoad(.1.3.6.1.2.1.25.3.3.1.2), memAvailReal(.1.3.6.1.4.1.2021.4.6.0) [UCD-SNMP]
                # Fallback to ifInOctets/ifOutOctets on ifIndex 1 for demo
                try:
                    # CPU via hrProcessorLoad average over entries
                    cpu_vals = []
                    for (errInd, errStat, errIdx, varBinds) in nextCmd(engine, community, target, ctx, ObjectType(ObjectIdentity('1.3.6.1.2.1.25.3.3.1.2'))):
                        if errInd or errStat:
                            break
                        for vb in varBinds:
                            try:
                                cpu_vals.append(int(vb[1]))
                            except Exception:
                                pass
                    if cpu_vals:
                        info['cpu_pct'] = float(sum(cpu_vals)/len(cpu_vals))
                    # Simple interface octets (if 1)
                    # Note: real implementation should iterate interfaces; here we sample ifIndex 1
                    def get_scalar(oid):
                        errInd, errStat, errIdx, varBinds = next(getCmd(engine, community, target, ctx, ObjectType(ObjectIdentity(oid))))
                        if not errInd and not errStat:
                            return int(varBinds[0][1])
                        return None
                    in1 = get_scalar('1.3.6.1.2.1.2.2.1.10.1')
                    out1 = get_scalar('1.3.6.1.2.1.2.2.1.16.1')
                    prev_in = info.get('_snmp_prev_in')
                    prev_out = info.get('_snmp_prev_out')
                    prev_ts = info.get('_snmp_prev_ts')
                    nowt = now_ts()
                    if prev_in is not None and prev_out is not None and prev_ts:
                        dt = max(1e-3, nowt - prev_ts)
                        if in1 is not None and out1 is not None:
                            info['bw_down_bps'] = int((in1 - prev_in)/dt)
                            info['bw_up_bps'] = int((out1 - prev_out)/dt)
                    if in1 is not None:
                        info['_snmp_prev_in'] = in1
                    if out1 is not None:
                        info['_snmp_prev_out'] = out1
                    info['_snmp_prev_ts'] = nowt
                    # Memory percent (if available via UCD-SNMP)
                    # memAvailReal.0 and memTotalReal.0
                    try:
                        avail = get_scalar('1.3.6.1.4.1.2021.4.6.0')
                        total = get_scalar('1.3.6.1.4.1.2021.4.5.0')
                        if avail is not None and total:
                            used_pct = 100.0 * (1.0 - (avail/total))
                            info['mem_pct'] = round(used_pct, 1)
                    except Exception:
                        pass
                    devices[ip] = info
                except Exception as e:
                    # Ignore errors per device to continue polling others
                    pass
            socketio.emit('devices', list(devices.values()))
        except Exception:
            pass
        time.sleep(15)

# -------- Dashboard (Flask + SocketIO) --------
INDEX_HTML = """
<!doctype html>
<html>
  <head>
    <title>Realtime Network Monitor</title>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <script src="https://cdn.socket.io/4.6.1/socket.io.min.js"></script>
    <script src="https://cdn.tailwindcss.com"></script>
    <style>
      body { font-family: Arial, sans-serif; margin: 10px; }
            .chart { width: 48%; display:inline-block; vertical-align: top; }
      .panel { padding: 6px; border: 1px solid #ddd; margin-bottom: 8px; border-radius:6px; }
            .tabs { display:flex; gap:8px; margin: 8px 0; }
            .tab { padding:6px 10px; border: 1px solid #aaa; border-radius:6px; cursor:pointer }
            .tab.active { background:#eee; }
            .hidden { display:none; }
            table { border-collapse: collapse; width:100%; }
            th, td { padding:6px; font-size: 13px; }
        .admin-only { display:none; }
            @media (max-width: 900px){
                .optcols { display:none; }
                .chart { width: 100%; display:block; }
            }
    </style>
  </head>
  <body>
        <div class="flex items-center justify-between mb-4 p-4 bg-gray-50 rounded-lg">
            <h2 class="text-2xl font-bold text-gray-800 m-0">Realtime Network Monitor</h2>
            <div id="userbar" class="flex items-center space-x-3">
                <span id="whoami" class="text-sm text-gray-600"></span>
                <span id="authlinks"></span>
                <a href="/login" id="loginLink" class="text-blue-600 hover:text-blue-800 text-sm font-medium">Login</a>
            </div>
        </div>
    <div class="panel">
      <strong>Uptime:</strong> <span id="uptime">loading...</span>
      &nbsp; | &nbsp; <strong>Top apps (PID -> bytes):</strong> <span id="topapps">loading...</span>
    </div>

        <div class="panel" style="width:98%">
            <div style="display:flex; gap:12px; flex-wrap:wrap">
                <div id="kpi-devices" style="flex:1; min-width:180px; border-left:6px solid gray; padding-left:8px">
                    <div><strong>Devices</strong></div>
                    <div><span id="kpi-up">0</span> up / <span id="kpi-down">0</span> down</div>
                </div>
                <div id="kpi-latency" style="flex:1; min-width:180px; border-left:6px solid gray; padding-left:8px">
                    <div><strong>Latency</strong></div>
                    <div>RTT: <span id="kpi-rtt">-</span> ms, Jitter: <span id="kpi-jitter">-</span> ms</div>
                </div>
                <div id="kpi-bandwidth" style="flex:1; min-width:180px; border-left:6px solid gray; padding-left:8px">
                    <div><strong>Bandwidth</strong></div>
                    <div>Total: <span id="kpi-bw">-</span> B/s</div>
                </div>
            </div>
        </div>

        <div class="tabs">
            <div id="tab-dashboard" class="tab active">Dashboard</div>
            <div id="tab-devices" class="tab">Devices</div>
            <div id="tab-alerts" class="tab">Alerts</div>
            <div id="tab-reports" class="tab">Reports</div>
            <div id="tab-topology" class="tab">Topology</div>
        </div>

        <div id="view-dashboard">
            <div class="chart">
                <h4>Interface traffic (last samples)</h4>
                <canvas id="ifaceChart"></canvas>
            </div>

            <div class="chart">
                <h4>Latency / Loss / Jitter</h4>
                <canvas id="latChart"></canvas>
            </div>

            <div class="chart" style="width:98%">
                <h4>Top Bandwidth Consumers</h4>
                <canvas id="talkersChart"></canvas>
            </div>
        </div>

        <div id="view-devices" class="hidden">
            <div class="panel">
                <form id="addForm" onsubmit="return false" style="display:flex; gap:6px; flex-wrap:wrap" class="admin-only">
                    <select id="dtype">
                        <option>Router</option>
                        <option>Switch</option>
                        <option>Server</option>
                        <option>Firewall</option>
                        <option>Device</option>
                    </select>
                    <input id="dip" placeholder="IP address"/>
                    <input id="dlabel" placeholder="Label"/>
                    <input id="dmac" placeholder="MAC (optional)"/>
                    <label style="display:flex; align-items:center; gap:4px"><input id="dsnmp" type="checkbox"/> SNMP</label>
                    <button id="addBtn">Add</button>
                    <select id="filterType">
                        <option value="">All</option>
                        <option>Router</option>
                        <option>Switch</option>
                        <option>Server</option>
                        <option>Firewall</option>
                        <option>Device</option>
                    </select>
                </form>
            </div>

            <div class="panel">
                <table>
                    <thead>
                        <tr>
                            <th>Status</th><th>Name</th><th>Type</th><th>IP</th><th class="optcols">MAC</th>
                            <th>Latency</th><th class="optcols">Loss%</th><th class="optcols">CPU%</th><th class="optcols">MEM%</th><th class="optcols">Up B/s</th><th class="optcols">Down B/s</th><th>Actions</th>
                        </tr>
                    </thead>
                    <tbody id="devBody"></tbody>
                </table>
            </div>
        </div>

        <div id="view-alerts" class="hidden">
            <div class="panel">
                <h4>Alerts</h4>
                <ul id="alerts"></ul>
            </div>
        </div>

        <div id="view-reports" class="hidden">
            <div class="panel">
                <h4>Reports</h4>
                <div style="display:flex; gap:8px; align-items:center; flex-wrap:wrap">
                    <label>Range</label>
                    <select id="repRange">
                        <option value="1h">Last hour</option>
                        <option value="24h" selected>Last 24h</option>
                        <option value="7d">Last 7 days</option>
                    </select>
                    <button id="repRun">Run</button>
                    <button id="repExportJson">Export JSON</button>
                    <button id="repExportCsv">Export CSV</button>
                </div>
                <div style="display:flex; gap:10px; flex-wrap:wrap">
                    <div style="flex:1; min-width:280px">
                        <h5>Latency (ms)</h5>
                        <canvas id="repLatChart"></canvas>
                    </div>
                    <div style="flex:1; min-width:280px">
                        <h5>Total Bandwidth (B/s)</h5>
                        <canvas id="repBwChart"></canvas>
                    </div>
                </div>
                <pre id="repOut" style="white-space:pre-wrap"></pre>
            </div>
        </div>

        <div id="view-topology" class="hidden">
            <div class="panel">
                <h4>Topology</h4>
                <canvas id="topologyCanvas" width="900" height="500" style="border:1px solid #ddd"></canvas>
            </div>
        </div>

        <div class="panel" style="width:98%">
            <h4>Devices</h4>
            <table id="devtable" border="1" cellspacing="0" cellpadding="4">
                <thead>
                    <tr><th>IP</th><th>Label</th><th>Status</th><th>RTT (ms)</th><th>Last Seen</th></tr>
                </thead>
                <tbody></tbody>
            </table>
        </div>

        <div class="panel" style="width:98%">
            <h4>Top devices by traffic</h4>
            <ul id="topdev"></ul>
        </div>

        <div class="panel" style="width:98%">
            <h4>Alerts</h4>
            <ul id="alerts"></ul>
        </div>

        <!-- Floating Chatbot -->
        <div id="chatToggle" class="fixed bottom-4 right-4 bg-blue-500 hover:bg-blue-600 text-white p-3 rounded-full cursor-pointer shadow-lg">
            💬
        </div>
        <div id="chatWindow" class="fixed bottom-20 right-4 w-80 h-96 bg-white border border-gray-300 rounded-lg shadow-xl hidden flex flex-col">
            <div class="bg-blue-500 text-white p-3 rounded-t-lg">
                <h4 class="m-0 text-sm font-medium">Network Assistant</h4>
            </div>
            <div id="chatMessages" class="flex-1 p-3 overflow-y-auto text-sm">
                <div class="text-gray-500">Ask me about your network status, devices, or alerts...</div>
            </div>
            <div class="p-3 border-t">
                <div class="flex gap-2">
                    <input id="chatInput" type="text" placeholder="Type your question..." class="flex-1 px-2 py-1 border rounded text-sm" />
                    <button id="chatSend" class="px-3 py-1 bg-blue-500 text-white rounded text-sm hover:bg-blue-600">Send</button>
                </div>
            </div>
        </div>

    <script>
            const socket = io();
            async function refreshUser(){
                try{
                    const r = await fetch('/whoami');
                    const u = await r.json();
                    document.getElementById('whoami').innerText = u.user ? `${u.user.username} (${u.user.role})` : 'Guest';
                    document.getElementById('authlinks').innerHTML = u.user ? '<a href="/logout">Logout</a>' : '';
                    document.getElementById('loginLink').style.display = u.user ? 'none' : '';
                    // toggle admin-only controls
                    window.isAdmin = !!(u.user && u.user.role === 'admin');
                    document.querySelectorAll('.admin-only').forEach(el => el.style.display = window.isAdmin ? '' : 'none');
                }catch(e){}
            }
            refreshUser();
      let ifaceData = [];
      let ifaceLabels = [];
      const ifaceCtx = document.getElementById('ifaceChart').getContext('2d');
    const latCtx = document.getElementById('latChart').getContext('2d');
    const talkCtx = document.getElementById('talkersChart')?.getContext('2d');

      const ifaceChart = new Chart(ifaceCtx, {
        type:'bar',
        data: { labels: [], datasets: [] },
        options: { responsive:true, plugins:{legend:{display:true}} }
      });

      const latChart = new Chart(latCtx, {
        type:'line',
                data: { labels: [], datasets: [
                    {label:'RTT ms', data:[]},
                    {label:'Loss %', data:[], yAxisID: 'loss'},
                    {label:'Jitter ms', data:[], borderDash:[5,5]}
                ] },
        options: { scales: { y: { beginAtZero:true }, loss: { position:'right', beginAtZero:true } } }
      });

    socket.on('connect', () => console.log("connected to server"));
      socket.on('interfaces', (data) => {
        // show aggregated per-interface totals as stacked bar: simplify: show total per interface for the last sample
        const labels = Object.keys(data.interfaces);
        const totals = labels.map(l => data.interfaces[l].total);
        ifaceChart.data.labels = labels;
        ifaceChart.data.datasets = [{label:'bytes/sec', data:totals}];
        ifaceChart.update();
      });

      socket.on('latency', (data) => {
        const ts = new Date(data.ts * 1000).toLocaleTimeString();
        latChart.data.labels.push(ts);
        latChart.data.datasets[0].data.push(data.rtt_ms || 0);
        latChart.data.datasets[1].data.push(data.loss_pct || 0);
                latChart.data.datasets[2].data.push(data.jitter_ms || 0);
        if(latChart.data.labels.length>30){
          latChart.data.labels.shift();
          latChart.data.datasets.forEach(d=>d.data.shift());
        }
        latChart.update();
      });

      socket.on('uptime', (d) => {
        const s = Math.floor(d.uptime_seconds);
        document.getElementById('uptime').innerText = s + "s (boot " + new Date(d.boot_time*1000).toLocaleString() + ")";
      });

            // devices updates
            socket.on('devices', (list) => {
                const tbody = document.querySelector('#devtable tbody');
                tbody.innerHTML = '';
                list.sort((a,b) => (a.ip > b.ip ? 1 : -1));
                for (const d of list) {
                    const tr = document.createElement('tr');
                    const color = d.status === 'up' ? 'green' : (d.status === 'down' ? 'red' : 'gray');
                    tr.innerHTML = `<td>${d.ip}</td><td>${d.label||d.ip}</td><td style="color:${color}">${d.status||'unknown'}</td><td>${d.rtt_ms?.toFixed?.(1) || ''}</td><td>${d.last_seen_ts? new Date(d.last_seen_ts*1000).toLocaleTimeString():''}</td>`;
                    tbody.appendChild(tr);
                }
            });

                    // alerts updates
            socket.on('alert', (a) => {
                const ul = document.getElementById('alerts');
                const li = document.createElement('li');
                li.innerText = `[${new Date(a.ts*1000).toLocaleTimeString()}] ${a.kind}: ${a.subject}`;
                ul.prepend(li);
                while (ul.children.length > 50) ul.removeChild(ul.lastChild);
            });

            // request top items periodically
      setInterval(async () => {
        const resp = await fetch('/top');
        const json = await resp.json();
        document.getElementById('topapps').innerText = json.top_apps;
                const ul = document.getElementById('topdev');
                ul.innerHTML = '';
                json.top_devices.forEach(it => {
          const li = document.createElement('li');
          li.innerText = it;
          ul.appendChild(li);
        });
      }, 3000);

                    // KPI summary updater
                    async function refreshSummary(){
                        try{
                            const r = await fetch('/summary');
                            const s = await r.json();
                            document.getElementById('kpi-up').innerText = s.devices_up;
                            document.getElementById('kpi-down').innerText = s.devices_down;
                            document.getElementById('kpi-rtt').innerText = s.rtt_ms?.toFixed?.(1) || '-';
                            document.getElementById('kpi-jitter').innerText = s.jitter_ms?.toFixed?.(1) || '-';
                            document.getElementById('kpi-bw').innerText = s.total_bw_bytes || '-';
                            // colors
                            const devColor = s.devices_down > 0 ? 'red' : 'green';
                            document.getElementById('kpi-devices').style.borderLeftColor = devColor;
                            const latColor = (s.rtt_ms||0) > (s.thresholds?.high_rtt_ms||500) || (s.loss_pct||0) > (s.thresholds?.high_loss_pct||50) ? 'red' : 'green';
                            document.getElementById('kpi-latency').style.borderLeftColor = latColor;
                            const bwColor = 'green'; // simple for now
                            document.getElementById('kpi-bandwidth').style.borderLeftColor = bwColor;
                        }catch(e){/* ignore */}
                    }
                            setInterval(refreshSummary, 3000);
                            refreshSummary();

                            // talkers chart
                            const talkersChart = new Chart(talkCtx, {
                                type:'bar',
                                data: { labels: [], datasets: [{label:'Bytes/sec', data:[]}] },
                                options: { responsive:true, plugins:{legend:{display:true}} }
                            });
                            async function refreshTalkers(){
                                try{
                                    const r = await fetch('/top_talkers');
                                    const data = await r.json();
                                    talkersChart.data.labels = data.labels;
                                    talkersChart.data.datasets[0].data = data.values;
                                    talkersChart.update();
                                }catch(e){}
                            }
                            setInterval(refreshTalkers, 4000);
                            refreshTalkers();

                            // device table rendering with filter
                            let allDevices = [];
                            function renderDevices(){
                                const ft = document.getElementById('filterType').value;
                                const tbody = document.getElementById('devBody');
                                tbody.innerHTML = '';
                                allDevices
                                    .filter(d => !ft || d.type === ft)
                                    .sort((a,b)=> (a.label||a.ip).localeCompare(b.label||b.ip))
                                    .forEach(d => {
                                        const tr = document.createElement('tr');
                                        const color = d.status === 'up' ? 'green' : (d.status === 'warning' ? 'orange' : (d.status === 'down' ? 'red' : 'gray'));
                                        tr.innerHTML = `
                                            <td style="color:${color}">${d.status||'unknown'}</td>
                                            <td>${d.label||d.ip}</td>
                                            <td>${d.type||'Device'}</td>
                                            <td>${d.ip}</td>
                                            <td class="optcols">${d.mac||''}</td>
                                            <td>${(d.rtt_ms??'')!=='' ? (d.rtt_ms.toFixed? d.rtt_ms.toFixed(1):d.rtt_ms):''}</td>
                                            <td class="optcols">${d.loss_pct??''}</td>
                                            <td class="optcols">${d.cpu_pct??''}</td>
                                            <td class="optcols">${d.mem_pct??''}</td>
                                            <td class="optcols">${d.bw_up_bps??''}</td>
                                            <td class="optcols">${d.bw_down_bps??''}</td>
                                            <td><button data-ip="${d.ip}" class="rmBtn admin-only">Remove</button></td>`;
                                        tbody.appendChild(tr);
                                    });
                                // reflect admin visibility
                                document.querySelectorAll('.admin-only').forEach(el => el.style.display = (window.isAdmin ? '' : 'none'));
                                document.querySelectorAll('.rmBtn').forEach(btn=>{
                                    btn.onclick = async (e)=>{
                                        const ip = e.target.getAttribute('data-ip');
                                        await fetch(`/devices/${ip}`, { method:'DELETE' });
                                    };
                                })
                            }
                            socket.on('devices', (list) => { allDevices = list; renderDevices(); });
                            document.getElementById('filterType').onchange = renderDevices;

                            document.getElementById('addBtn').onclick = async () => {
                                const body = {
                                    ip: document.getElementById('dip').value,
                                    label: document.getElementById('dlabel').value,
                                    type: document.getElementById('dtype').value,
                                    mac: document.getElementById('dmac').value,
                                    snmp_enabled: !!document.getElementById('dsnmp').checked,
                                };
                                await fetch('/devices', { method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify(body)});
                            };

                            // tabs logic
                            function s(id,on){ document.getElementById(id).classList.toggle('hidden', !on); }
                            function t(id,on){ document.getElementById(id).classList.toggle('active', !!on); }
                                                        document.getElementById('tab-dashboard').onclick = ()=>{ s('view-dashboard',true); s('view-devices',false); s('view-alerts',false); s('view-reports',false); s('view-topology',false); t('tab-dashboard',true); t('tab-devices',false); t('tab-alerts',false); t('tab-reports',false); t('tab-topology',false); };
                                                        document.getElementById('tab-devices').onclick = ()=>{ s('view-dashboard',false); s('view-devices',true); s('view-alerts',false); s('view-reports',false); s('view-topology',false); t('tab-dashboard',false); t('tab-devices',true); t('tab-alerts',false); t('tab-reports',false); t('tab-topology',false); };
                                                        document.getElementById('tab-alerts').onclick = ()=>{ s('view-dashboard',false); s('view-devices',false); s('view-alerts',true); s('view-reports',false); s('view-topology',false); t('tab-dashboard',false); t('tab-devices',false); t('tab-alerts',true); t('tab-reports',false); t('tab-topology',false); };
                                                        document.getElementById('tab-reports').onclick = ()=>{ s('view-dashboard',false); s('view-devices',false); s('view-alerts',false); s('view-reports',true); s('view-topology',false); t('tab-dashboard',false); t('tab-devices',false); t('tab-alerts',false); t('tab-reports',true); t('tab-topology',false); };
                                                        document.getElementById('tab-topology').onclick = ()=>{ s('view-dashboard',false); s('view-devices',false); s('view-alerts',false); s('view-reports',false); s('view-topology',true); t('tab-dashboard',false); t('tab-devices',false); t('tab-alerts',false); t('tab-reports',false); t('tab-topology',true); drawTopology(); };

                                                        async function drawTopology(){
                                                            const canvas = document.getElementById('topologyCanvas');
                                                            const ctx = canvas.getContext('2d');
                                                            ctx.clearRect(0,0,canvas.width,canvas.height);
                                                            const r = await fetch('/topology');
                                                            const g = await r.json();
                                                            const nodes = g.nodes;
                                                            const links = g.links;
                                                            // naive layout: place center controller at middle, devices on circle
                                                            const center = nodes.find(n=>n.id==='local') || nodes[0];
                                                            const cx = canvas.width/2, cy = canvas.height/2;
                                                            const radius = Math.min(cx, cy) - 60;
                                                            const others = nodes.filter(n=>n.id!=='local');
                                                            others.forEach((n, idx) => {
                                                                const angle = (idx/Math.max(1,others.length))*Math.PI*2;
                                                                n.x = cx + radius*Math.cos(angle);
                                                                n.y = cy + radius*Math.sin(angle);
                                                            });
                                                            center.x = cx; center.y = cy;
                                                            // draw links
                                                            ctx.strokeStyle = '#999'; ctx.lineWidth = 1;
                                                            links.forEach(l => {
                                                                const a = nodes.find(n=>n.id===l.source);
                                                                const b = nodes.find(n=>n.id===l.target);
                                                                if(!a||!b) return;
                                                                ctx.beginPath(); ctx.moveTo(a.x,a.y); ctx.lineTo(b.x,b.y); ctx.stroke();
                                                            });
                                                            // draw nodes
                                                            nodes.forEach(n => {
                                                                const color = n.status==='up' ? 'green' : (n.status==='warning' ? 'orange' : (n.status==='down' ? 'red' : 'gray'));
                                                                ctx.beginPath(); ctx.fillStyle=color; ctx.arc(n.x, n.y, 10, 0, Math.PI*2); ctx.fill();
                                                                ctx.fillStyle = '#000'; ctx.font = '12px Arial'; ctx.fillText(n.label||n.id, n.x+12, n.y+4);
                                                            });
                                                        }

                                                        // Reports charts
                                                        const repLatCtx = document.getElementById('repLatChart')?.getContext('2d');
                                                        const repBwCtx = document.getElementById('repBwChart')?.getContext('2d');
                                                        const repLatChart = new Chart(repLatCtx, { type:'line', data:{ labels:[], datasets:[{label:'RTT', data:[]}, {label:'Jitter', data:[]}, {label:'Loss %', data:[], yAxisID:'loss'}] }, options:{ scales:{ loss:{ position:'right', beginAtZero:true }}}});
                                                        const repBwChart = new Chart(repBwCtx, { type:'line', data:{ labels:[], datasets:[{label:'Total B/s', data:[]}] }, options:{}});

                                                        async function runReport(){
                                                            const range = document.getElementById('repRange').value;
                                                            // summary
                                                            const r = await fetch(`/reports/summary?range=${encodeURIComponent(range)}`);
                                                            const summary = await r.json();
                                                            document.getElementById('repOut').innerText = JSON.stringify(summary, null, 2);
                                                            // timeseries
                                                            const t = await fetch(`/reports/timeseries?range=${encodeURIComponent(range)}`);
                                                            const tsdata = await t.json();
                                                            const latLabels = tsdata.latency.map(x => new Date(x.ts*1000).toLocaleTimeString());
                                                            const rttSeries = tsdata.latency.map(x => x.rtt_ms||0);
                                                            const jitterSeries = tsdata.latency.map(x => x.jitter_ms||0);
                                                            const lossSeries = tsdata.latency.map(x => x.loss_pct||0);
                                                            repLatChart.data.labels = latLabels;
                                                            repLatChart.data.datasets[0].data = rttSeries;
                                                            repLatChart.data.datasets[1].data = jitterSeries;
                                                            repLatChart.data.datasets[2].data = lossSeries;
                                                            repLatChart.update();
                                                            const bwLabels = tsdata.interfaces.map(x => new Date(x.ts*1000).toLocaleTimeString());
                                                            const bwSeries = tsdata.interfaces.map(x => x.total||0);
                                                            repBwChart.data.labels = bwLabels;
                                                            repBwChart.data.datasets[0].data = bwSeries;
                                                            repBwChart.update();
                                                        }
                                                        document.getElementById('repRun').onclick = runReport;
                            // preload on first show
                            document.getElementById('tab-reports').addEventListener('click', runReport, { once: true });

                            // exports
                            document.getElementById('repExportJson').onclick = async () => {
                                const range = document.getElementById('repRange').value;
                                const r = await fetch(`/reports/export?kind=latency&format=json&range=${encodeURIComponent(range)}`);
                                const j = await r.json();
                                document.getElementById('repOut').innerText = JSON.stringify(j, null, 2);
                            };
                            document.getElementById('repExportCsv').onclick = async () => {
                                const range = document.getElementById('repRange').value;
                                const r = await fetch(`/reports/export?kind=latency&format=csv&range=${encodeURIComponent(range)}`);
                                const text = await r.text();
                                document.getElementById('repOut').innerText = text;
                            };

                            // Chatbot functionality
                            const chatToggle = document.getElementById('chatToggle');
                            const chatWindow = document.getElementById('chatWindow');
                            const chatMessages = document.getElementById('chatMessages');
                            const chatInput = document.getElementById('chatInput');
                            const chatSend = document.getElementById('chatSend');
                            
                            chatToggle.onclick = () => {
                                chatWindow.classList.toggle('hidden');
                            };
                            
                            async function sendMessage() {
                                const msg = chatInput.value.trim();
                                if (!msg) return;
                                
                                // Add user message
                                const userMsg = document.createElement('div');
                                userMsg.className = 'mb-2 text-right';
                                userMsg.innerHTML = `<span class="bg-blue-100 px-2 py-1 rounded inline-block">${msg}</span>`;
                                chatMessages.appendChild(userMsg);
                                
                                chatInput.value = '';
                                chatMessages.scrollTop = chatMessages.scrollHeight;
                                
                                try {
                                    const response = await fetch('/chat', {
                                        method: 'POST',
                                        headers: {'Content-Type': 'application/json'},
                                        body: JSON.stringify({question: msg})
                                    });
                                    const data = await response.json();
                                    
                                    // Add bot response
                                    const botMsg = document.createElement('div');
                                    botMsg.className = 'mb-2';
                                    botMsg.innerHTML = `<span class="bg-gray-100 px-2 py-1 rounded inline-block">${data.answer || 'Sorry, I could not process that.'}</span>`;
                                    chatMessages.appendChild(botMsg);
                                } catch (e) {
                                    const errorMsg = document.createElement('div');
                                    errorMsg.className = 'mb-2';
                                    errorMsg.innerHTML = `<span class="bg-red-100 px-2 py-1 rounded inline-block text-red-700">Error: Could not get response</span>`;
                                    chatMessages.appendChild(errorMsg);
                                }
                                
                                chatMessages.scrollTop = chatMessages.scrollHeight;
                            }
                            
                            chatSend.onclick = sendMessage;
                            chatInput.onkeypress = (e) => {
                                if (e.key === 'Enter') sendMessage();
                            };    </script>
  </body>
</html>
"""

@app.route('/')
def index():
    return render_template_string(INDEX_HTML)

LOGIN_HTML = """
<!doctype html>
<html><head><title>Login</title>
    <style>
        body{font-family:Arial; background:#0f172a; color:#e5e7eb}
        .card{max-width:340px; margin:10% auto; background:#111827; padding:16px; border-radius:10px; border:1px solid #374151}
        input{width:100%; padding:8px; margin:6px 0; border-radius:8px; border:1px solid #334155; background:#0b1220; color:#e5e7eb}
        button{width:100%; padding:8px; border-radius:8px; border:1px solid #334155; background:#0b3b4a; color:#e5e7eb; cursor:pointer}
        a{color:#22d3ee}
    </style>
</head>
<body>
    <div class="card">
        <h3>Sign in</h3>
        <form method="post">
            <input name="username" placeholder="Username" />
            <input name="password" placeholder="Password" type="password" />
            <button type="submit">Login</button>
        </form>
        <div style="margin-top:8px"><a href="/">Back</a></div>
    </div>
</body></html>
"""

@app.route('/login', methods=['GET','POST'])
def login():
        if request.method == 'GET':
                return LOGIN_HTML
        username = request.form.get('username')
        password = request.form.get('password')
        acct = ACCOUNTS.get(username)
        if not acct or acct.get('password') != password:
                return LOGIN_HTML, 401
        session['user'] = {"username": username, "role": acct['role']}
        return redirect(url_for('index'))

@app.route('/logout')
def logout():
        session.pop('user', None)
        return redirect(url_for('index'))

@app.route('/whoami')
def whoami():
        return jsonify({"user": current_user()})

@app.route('/top')
def top_summary():
    # top apps by app_usage
    with portmap_lock:
        apps = sorted(app_usage.items(), key=lambda kv: kv[1], reverse=True)[:10]
    apps_str = ", ".join([f"{pid}:{bytes}" for pid,bytes in apps])
    devices = sorted(device_usage.items(), key=lambda kv: kv[1], reverse=True)[:10]
    devices_str = [f"{ip}:{bytes}" for ip,bytes in devices]
    return json.dumps({"top_apps": apps_str, "top_devices": devices_str})

@app.route('/config', methods=['GET'])
def get_config():
    return jsonify(CONFIG)

@app.route('/config', methods=['POST'])
def set_config():
    if not is_admin(request):
        return jsonify({"error": "unauthorized"}), 401
    data = request.json or {}
    for k in ["traffic_spike_factor", "high_rtt_ms", "high_loss_pct"]:
        if k in data:
            try:
                CONFIG[k] = float(data[k]) if "loss" not in k else float(data[k])
            except Exception:
                pass
    return jsonify(CONFIG)

@app.route('/summary', methods=['GET'])
def get_summary():
    # devices up/down
    ups = sum(1 for d in devices.values() if d.get('status') == 'up')
    downs = sum(1 for d in devices.values() if d.get('status') == 'down')
    # latest latency sample across targets (average)
    rtts = [s.get('rtt_ms') for s in list(latency_history)[-10:] if s.get('rtt_ms') is not None]
    jitters = [s.get('jitter_ms') for s in list(latency_history)[-10:] if s.get('jitter_ms') is not None]
    losses = [s.get('loss_pct') for s in list(latency_history)[-10:] if s.get('loss_pct') is not None]
    rtt_avg = sum(rtts)/len(rtts) if rtts else None
    jitter_avg = sum(jitters)/len(jitters) if jitters else None
    loss_avg = sum(losses)/len(losses) if losses else None
    # total bandwidth last interface sample
    total_bw = 0
    if interface_history:
        last = interface_history[-1]
        total_bw = sum(v.get('total',0) for v in last.get('interfaces',{}).values())
    return jsonify({
        "devices_up": ups,
        "devices_down": downs,
        "rtt_ms": rtt_avg,
        "jitter_ms": jitter_avg,
        "loss_pct": loss_avg,
        "total_bw_bytes": total_bw,
        "thresholds": CONFIG,
    })

@app.route('/devices', methods=['GET'])
def get_devices():
    return jsonify(list(devices.values()))

@app.route('/alerts', methods=['GET'])
def get_alerts():
    return jsonify(list(alerts))

@app.route('/devices', methods=['POST'])
def add_device():
    if not is_admin(request):
        return jsonify({"error": "unauthorized"}), 401
    data = request.json or {}
    ip = data.get('ip')
    label = data.get('label') or ip
    dtype = data.get('type') or 'Device'
    mac = data.get('mac') or ''
    snmp_enabled = bool(data.get('snmp_enabled'))
    try:
        ipaddress.ip_address(ip)
    except Exception:
        return jsonify({"error": "invalid ip"}), 400
    info = devices.get(ip, {"ip": ip})
    info.update({
        "label": label,
        "type": dtype,
        "mac": mac,
        "snmp_enabled": snmp_enabled,
        "status": info.get("status", "unknown"),
        "last_seen_ts": info.get("last_seen_ts", 0),
        "rtt_ms": info.get("rtt_ms"),
        "loss_pct": info.get("loss_pct"),
        "cpu_pct": info.get("cpu_pct"),
        "mem_pct": info.get("mem_pct"),
        "bw_up_bps": info.get("bw_up_bps", 0),
        "bw_down_bps": info.get("bw_down_bps", 0),
    })
    devices[ip] = info
    save_devices()
    # upsert device into Mongo devices collection
    try:
        if col_devices:
            col_devices.update_one({"ip": ip}, {"$set": {"label": label, "type": dtype, "mac": mac, "snmp_enabled": snmp_enabled}}, upsert=True)
    except Exception:
        pass
    socketio.emit('devices', list(devices.values()))
    return jsonify(info)

@app.route('/devices/<ip>', methods=['DELETE'])
def remove_device(ip):
    if not is_admin(request):
        return jsonify({"error": "unauthorized"}), 401
    if ip in devices:
        devices.pop(ip)
        save_devices()
        socketio.emit('devices', list(devices.values()))
        return jsonify({"ok": True})
    return jsonify({"error": "not found"}), 404

@app.route('/top_talkers', methods=['GET'])
def top_talkers():
    # Combine cumulative device_usage and simulated instantaneous bw as heuristic
    items = []
    for ip, total in device_usage.items():
        items.append((ip, total))
    # Also consider current per-device bw_down_bps if device exists
    for ip, info in devices.items():
        items.append((ip, info.get('bw_down_bps', 0) + info.get('bw_up_bps', 0)))
    # aggregate by ip
    agg = {}
    for ip, val in items:
        agg[ip] = agg.get(ip, 0) + val
    top5 = sorted(agg.items(), key=lambda kv: kv[1], reverse=True)[:5]
    labels = [k for k,v in top5]
    values = [v for k,v in top5]
    return jsonify({"labels": labels, "values": values})

@app.route('/reports/timeseries', methods=['GET'])
def reports_timeseries():
    rng = request.args.get('range', '24h')
    now = now_ts()
    if rng == '1h':
        since = now - 3600
    elif rng == '7d':
        since = now - 7*24*3600
    else:
        since = now - 24*3600
    lat = [s for s in latency_history if s.get('ts',0) >= since]
    iface = [s for s in interface_history if s.get('ts',0) >= since]
    iface_series = [{"ts": s['ts'], "total": sum(v.get('total',0) for v in s.get('interfaces',{}).values())} for s in iface]
    return jsonify({
        "range": rng,
        "since_ts": since,
        "latency": lat,
        "interfaces": iface_series,
    })

@app.route('/reports/export', methods=['GET'])
def reports_export():
    kind = request.args.get('kind', 'latency')
    fmt = request.args.get('format', 'json')
    rng = request.args.get('range', '24h')
    now = now_ts()
    if rng == '1h':
        since = now - 3600
    elif rng == '7d':
        since = now - 7*24*3600
    else:
        since = now - 24*3600

    def filter_range(data):
        return [d for d in data if d.get('ts',0) >= since]

    if kind == 'latency':
        data = filter_range(list(latency_history))
        headers = ['ts','host','rtt_ms','loss_pct','jitter_ms']
        rows = [[d.get('ts'), d.get('host'), d.get('rtt_ms'), d.get('loss_pct'), d.get('jitter_ms')] for d in data]
    elif kind == 'interfaces':
        data = filter_range(list(interface_history))
        headers = ['ts','total']
        rows = [[d.get('ts'), sum(v.get('total',0) for v in d.get('interfaces',{}).values())] for d in data]
    elif kind == 'alerts':
        data = filter_range(list(alerts))
        headers = ['ts','kind','subject','body']
        rows = [[d.get('ts'), d.get('kind'), d.get('subject'), d.get('body')] for d in data]
    elif kind == 'device_status':
        # if DB, prefer from DB; else derive a snapshot from devices
        if col_device_status:
            try:
                cur = col_device_status.find({"ts": {"$gte": since}}).sort("ts", 1)
                data = list(cur)
                headers = ['ts','ip','status','rtt_ms','loss_pct','cpu_pct','mem_pct','bw_up_bps','bw_down_bps']
                rows = [[d.get('ts'), d.get('ip'), d.get('status'), d.get('rtt_ms'), d.get('loss_pct'), d.get('cpu_pct'), d.get('mem_pct'), d.get('bw_up_bps'), d.get('bw_down_bps')] for d in data]
            except Exception:
                data = []
                headers = ['ts','ip','status']
                rows = []
        else:
            data = [{"ts": now, **v} for v in devices.values()]
            headers = ['ts','ip','status']
            rows = [[d.get('ts'), d.get('ip'), d.get('status')] for d in data]
    else:
        return jsonify({"error": "unknown kind"}), 400

    if fmt == 'csv':
        try:
            import io, csv
            buf = io.StringIO()
            writer = csv.writer(buf)
            writer.writerow(headers)
            for r in rows:
                writer.writerow(r)
            out = buf.getvalue()
            return app.response_class(out, mimetype='text/csv', headers={'Content-Disposition': f'attachment; filename="{kind}_{int(now)}.csv"'})
        except Exception as e:
            return jsonify({"error": str(e)}), 500
    else:
        return jsonify({"headers": headers, "rows": rows})

@app.route('/topology', methods=['GET'])
def topology():
    # local node at center and edges to each device
    nodes = [{"id": "local", "label": socket.gethostname(), "status": "up"}]
    links = []
    for ip, info in devices.items():
        nodes.append({"id": ip, "label": info.get('label') or ip, "status": info.get('status') or 'unknown'})
        links.append({"source": "local", "target": ip})
    return jsonify({"nodes": nodes, "links": links})

@app.route('/chat', methods=['POST'])
def chat():
    """Simple local Q&A over current network data"""
    data = request.json or {}
    question = data.get('question', '').lower()
    
    # Simple keyword-based responses
    if 'devices' in question or 'device' in question:
        total = len(devices)
        up = len([d for d in devices.values() if d.get('status') == 'up'])
        down = len([d for d in devices.values() if d.get('status') == 'down'])
        answer = f"You have {total} devices: {up} up, {down} down."
    elif 'alerts' in question or 'alert' in question:
        recent = len([a for a in alerts if now_ts() - a.get('ts', 0) < 3600])
        answer = f"There are {recent} alerts in the last hour. Recent types: {', '.join(set(a.get('kind', 'unknown') for a in list(alerts)[-5:]))}"
    elif 'latency' in question or 'ping' in question:
        if latency_history:
            recent_rtt = [s.get('rtt_ms') for s in list(latency_history)[-5:] if s.get('rtt_ms')]
            if recent_rtt:
                avg_rtt = sum(recent_rtt) / len(recent_rtt)
                answer = f"Recent average latency: {avg_rtt:.1f}ms"
            else:
                answer = "No recent latency data available."
        else:
            answer = "No latency data available."
    elif 'bandwidth' in question or 'traffic' in question:
        if interface_history:
            last = interface_history[-1]
            total = sum(v.get('total', 0) for v in last.get('interfaces', {}).values())
            answer = f"Current total bandwidth: {total} bytes/sec"
        else:
            answer = "No bandwidth data available."
    elif 'status' in question or 'health' in question:
        ups = len([d for d in devices.values() if d.get('status') == 'up'])
        warnings = len([d for d in devices.values() if d.get('status') == 'warning'])
        downs = len([d for d in devices.values() if d.get('status') == 'down'])
        answer = f"Network status: {ups} devices up, {warnings} warnings, {downs} down. System uptime: {uptime_info.get('uptime_seconds', 0):.0f}s"
    elif 'help' in question:
        answer = "I can help with: devices, alerts, latency, bandwidth, status. Try asking 'How many devices are up?' or 'What is the current latency?'"
    else:
        answer = "I'm not sure about that. Try asking about devices, alerts, latency, bandwidth, or network status."
    
    return jsonify({"answer": answer})

@app.route('/reports/summary', methods=['GET'])
def reports_summary():
    """
    Simple rollup for a given time range.
    Query param: range = 1h|24h|7d
    Returns aggregates: avg_rtt, avg_loss, avg_jitter, avg_bw_total (approx), alerts_count, by_kind
    """
    rng = request.args.get('range', '24h')
    now = now_ts()
    if rng == '1h':
        since = now - 3600
    elif rng == '7d':
        since = now - 7*24*3600
    else:
        since = now - 24*3600

    # Collect from in-memory history first
    lat_samples = [s for s in latency_history if s.get('ts', 0) >= since]
    iface_samples = [s for s in interface_history if s.get('ts', 0) >= since]
    rtts = [s.get('rtt_ms') for s in lat_samples if s.get('rtt_ms') is not None]
    losses = [s.get('loss_pct') for s in lat_samples if s.get('loss_pct') is not None]
    jitters = [s.get('jitter_ms') for s in lat_samples if s.get('jitter_ms') is not None]
    bw_totals = []
    for s in iface_samples:
        try:
            bw_totals.append(sum(v.get('total',0) for v in s.get('interfaces',{}).values()))
        except Exception:
            pass

    result = {
        "range": rng,
        "since_ts": since,
        "samples": {
            "latency": len(lat_samples),
            "interfaces": len(iface_samples),
        },
        "avg_rtt_ms": (sum(rtts)/len(rtts)) if rtts else None,
        "avg_loss_pct": (sum(losses)/len(losses)) if losses else None,
        "avg_jitter_ms": (sum(jitters)/len(jitters)) if jitters else None,
        "avg_total_bw_Bps": (sum(bw_totals)/len(bw_totals)) if bw_totals else None,
        "alerts": {
            "count": 0,
            "by_kind": {}
        }
    }

    # Alerts from in-memory deque
    recent_alerts = [a for a in alerts if a.get('ts',0) >= since]
    result['alerts']['count'] = len(recent_alerts)
    by_kind = {}
    for a in recent_alerts:
        k = a.get('kind') or 'other'
        by_kind[k] = by_kind.get(k, 0) + 1
    result['alerts']['by_kind'] = by_kind

    # If Mongo is available, also fetch counts to be more complete (best-effort)
    if mongo_db and col_alerts:
        try:
            result['alerts']['count_db'] = col_alerts.count_documents({"ts": {"$gte": since}})
        except Exception:
            pass
    return jsonify(result)

# -------- Start background threads --------
def start_background_threads():
    threading.Thread(target=monitor_interfaces, daemon=True).start()
    threading.Thread(target=monitor_ping_targets, daemon=True).start()
    threading.Thread(target=monitor_uptime, daemon=True).start()
    threading.Thread(target=intrusion_detector, daemon=True).start()
    threading.Thread(target=start_sniffer, daemon=True).start()
    load_devices()
    threading.Thread(target=device_discovery_loop, daemon=True).start()
    threading.Thread(target=device_monitor_loop, daemon=True).start()
    threading.Thread(target=simulate_metrics_loop, daemon=True).start()
    threading.Thread(target=snmp_poll_loop, daemon=True).start()

# -------- Main entrypoint --------
if __name__ == '__main__':
    print("\n" + "="*60)
    print("   Network Monitoring Dashboard")
    print("="*60)
    print(f"\n🚀 Starting server on http://{BIND_HOST}:{BIND_PORT}")
    print(f"📊 Features: Real-time monitoring, Reports, Topology, Chat")
    print(f"🔐 Login: admin/admin (admin) or viewer/viewer (viewer)")
    
    # Initialize Mongo (if configured) before starting background threads
    try:
        init_mongo()
    except Exception as e:
        if MONGO_URI:
            print(f"⚠️  MongoDB connection failed: {e}")
    
    print(f"\n✅ Initializing monitoring threads...")
    start_background_threads()
    
    print(f"✅ Server ready! Open http://localhost:{BIND_PORT} in your browser\n")
    print("="*60 + "\n")
    
    # use socketio.run to allow websocket support
    socketio.run(app, host=BIND_HOST, port=BIND_PORT, log_output=False)
