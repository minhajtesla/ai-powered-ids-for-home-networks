# 🚀 Quick Start Guide - WiFi Network Monitor

## ⚡ 3-Minute Setup

### Step 1: Open Administrator Terminal

```bash
# Windows Search → cmd → Right-click → "Run as administrator"
cd D:\github project Network\ai-powered-ids-for-home-networks
venv\Scripts\activate
```

### Step 2: Check Network Interface

```bash
python -c "from scapy.all import get_if_list; print('\n'.join(get_if_list()))"
```

**Note:** আপনার WiFi interface name (usually "Wi-Fi") note করুন

### Step 3: Start Dashboard

```bash
streamlit run dashboard\app.py
```

Browser automatically open হবে → **http://localhost:8501**

---

## 🎮 Dashboard Usage

### Sidebar Controls:

1. **📡 Network Interface** → Select "Wi-Fi" (your current WiFi)
2. **📦 Packet Count** → Set to `-1` (unlimited monitoring)
3. **🔑 AbuseIPDB API Key** → (Optional) Paste your API key
4. **🟢 Start Sniffer** → Click to start packet capture
5. **☑️ Enable Real-time Detection** → Check to enable ML detection
6. **▶️ Start Detection** → Click to start threat detection
7. **🔄 Auto-refresh** → Check for live updates every 5 seconds

---

## 📊 What You'll See

### Network Statistics:
- **Total Packets** - সব capture করা packets
- **Normal Traffic** - Safe traffic count
- **Alerts** - Detected threats
- **Unique Devices** - কতগুলো device connected
- **Detection Rate** - Model accuracy

### Connected Devices Table:
```
IP Address     | Packets | Total Bytes | Protocols | Connections | Status
192.168.1.2    | 1,245   | 1.2 MB      | TCP, UDP  | 15          | ✅ Normal
192.168.1.15   | 450     | 450 KB      | TCP       | 8           | ⚠️ Suspicious
192.168.1.20   | 2,340   | 2.5 MB      | TCP, ICMP | 50          | 🚨 Threat
```

### Real-time Alerts:
- **🚨 Red alerts** → Attacks detected (DDoS, Port Scan)
- **⚠️ Yellow alerts** → Suspicious activity
- **✅ Green** → All clear

---

## 🧪 Testing

### Test 1: Normal Traffic
```bash
# Phone দিয়ে YouTube browse করুন
# Dashboard এ দেখবেন: ✅ Normal traffic
```

### Test 2: Port Scan Detection
```bash
# Kali Linux বা terminal থেকে
nmap -sS 192.168.1.1

# Dashboard এ alert আসবে: 🚨 Port Scan Detected
```

### Test 3: Multiple Devices
```bash
# বিভিন্ন devices connect করুন WiFi তে
# Dashboard এ সব devices এর traffic দেখবেন
```

---

## 🔧 Troubleshooting

### Problem: "Permission Denied"
```bash
# Administrator PowerShell এ run করুন
Set-ExecutionPolicy RemoteSigned -Scope CurrentUser
```

### Problem: Sniffer Not Starting
```bash
# Scapy reinstall করুন
pip uninstall scapy
pip install scapy
```

### Problem: Dashboard Blank
```bash
# Refresh করুন browser (Ctrl+R)
# Auto-refresh enable করুন sidebar থেকে
```

### Problem: No Packets Captured
```bash
# Administrator mode check করুন
# Correct WiFi interface selected আছে কি check করুন
# Firewall temporarily disable করুন (test purpose)
```

---

## 📱 Monitor Your WiFi Network

আপনার **current WiFi network** monitor করতে পারবেন:

1. ✅ কে কে connected আছে
2. ✅ কতো data use করছে
3. ✅ কোন device suspicious activity করছে
4. ✅ Real-time attacks detect করা
5. ✅ Automatic IP blocking (threats)

---

## 🆘 Quick Commands

```bash
# Check interfaces
python -c "from scapy.all import get_if_list; print('\n'.join(get_if_list()))"

# Start dashboard
streamlit run dashboard\app.py

# Stop dashboard
Ctrl+C

# Clear captured data
del data\captured_packets.csv
del data\alerts.log
```

---

## 🎯 Next Steps

1. **Get AbuseIPDB API Key** → https://www.abuseipdb.com/register
2. **Enable Auto-refresh** → Live updates every 5 seconds
3. **Test with attacks** → Port scan, DDoS simulation
4. **Monitor 24/7** → Keep dashboard running

---

**আপনার network এখন fully monitored! 🛡️**
