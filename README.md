# NetSleuth 🕵️‍♂️  
**Real-Time Network Threat Detector & PCAP Analyzer**

---

## 📌 Overview

**NetSleuth** is a powerful Python-based tool designed to analyze PCAP files or capture live network traffic in real-time. It monitors HTTP activity and TCP connections to detect:

- Suspicious ports often used in malware/backdoors
- Binary file downloads (e.g., `.exe`, `.zip`, `.dll`)
- Suspicious domains or URIs (e.g., containing keywords like `malware`, `cmd`, `c2`)
- MIME types indicating file transfers

Whenever any suspicious behavior is detected, NetSleuth **immediately displays an alert** with key packet information.

---

## ⚙️ Features

- ✅ **Live Capture Mode** – Real-time packet inspection with alerts
- 📁 **Offline PCAP Analysis** – Analyze `.pcap` or `.pcapng` files
- 🎯 **Detection of Common Threat Indicators**
  - Suspicious TCP ports (default: 23, 4444, 6667, 31337, 12345)
  - Downloads of binary/media files
  - Suspicious HTTP request hosts/URIs
- 🧠 Smart MIME & Extension Matching
- 📊 Interactive terminal reports (via [Rich](https://github.com/Textualize/rich))
- 🧪 Optional verbose mode for debugging and analysis

---

## 🚨 Live Capture Mode

When using **Live Capture**, NetSleuth:

- Continuously monitors the specified network interface
- Sends real-time alerts when it detects:
  - HTTP file downloads
  - Access to suspicious domains or URLs
  - TCP connections to suspicious ports
- Keeps running **until you press `q` and hit Enter**  
  You are always in control!

---

## 🖥️ Usage

### 🔍 Analyze PCAP File
```bash
python3 netsleuth.py -i path/to/file.pcap
```

### 📡 Start Live Capture on Interface
```bash
python3 netsleuth.py -l eth0
```

### 💾 Export Report to JSON
```bash
python3 netsleuth.py -i file.pcap -o report.json
```

### 🛡️ Customize Suspicious Ports
```bash
python3 netsleuth.py -l wlan0 --suspicious-ports 1337 8888 6666
```

### 🐛 Enable Verbose Debug Logs
```bash
python3 netsleuth.py -i traffic.pcap --verbose
```

---

## 📄 Output Example

When threats are found, NetSleuth displays formatted tables such as:

```
┌─────────────── HTTP Requests ───────────────┐
│ Time       │ Method │ Host        │ URI     │
│------------│--------│-------------│---------│
│ 12:01:23   │ GET    │ evil.com    │ /load   │

┌────────────── File Downloads ───────────────┐
│ Time       │ Filename      │ Mime  │ Disposition │
│------------│---------------│-------│-------------│
│ 12:01:24   │ /malware.exe  │ app/  │ attachment  │

┌──── Suspicious Connections (Ports) ─────┐
│ Time     │ Src IP     │ Dst IP     │ Port Info  │
│----------│------------│------------│------------│
│ 12:01:25 │ 10.0.0.5   │ 23.45.67.8 │ dport: 4444│
```

---

## 🧠 Requirements

- Python 3.7+
- [PyShark](https://github.com/KimiNewt/pyshark)
- [Rich](https://github.com/Textualize/rich)
- Wireshark/tshark installed (`sudo apt install tshark` on Linux)

---

## 🧪 Ideal For:

- Cybersecurity Analysts
- Malware Researchers
- Network Engineers
- Students learning Packet Analysis / Digital Forensics

---

## 📛 Name Meaning

**NetSleuth**  
> “Sleuth” is a term for an investigator or detective.  
> **NetSleuth** = “The Network Detective”  
> It actively sniffs out signs of threats in real-time.

---

## 📬 License

MIT License – Free to use and modify.

---

## 🧑‍💻 Author

Amjad Qandeel – Cybersecurity Expert
