# 🛡️ Real-time Network Intrusion Detection System

![NIDS Dashboard Screenshot]([Your-Dashboard-Screenshot.png])

A real-time Network Intrusion Detection System (NIDS) built with Python, Scapy, and Flask. This system monitors live network traffic, uses pattern recognition to detect common attacks, and provides a beautiful, interactive web dashboard for visualization.

A key feature of this project is its focus on security for the system itself. All generated alert logs are secured using **Symmetric-key Authenticated Cryptography** to ensure their confidentiality and integrity.

[![Python Version](https://img.shields.io/badge/Python-3.8+-blue.svg)](https://www.python.org/)
[![Flask Version](https://img.shields.io/badge/Flask-3.0+-green.svg)](https://flask.palletsprojects.com/)
[![License](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

---

## ✨ Features

-   ✅ **Real-time Packet Capture:** Monitors live network traffic on any specified interface.
-   ✅ **Advanced Attack Detection:**
    -   **Port Scanning:** Detects when a single source tries to connect to many ports.
    -   **DDoS/Flood Attacks:** Identifies SYN Floods and ICMP Floods by tracking packet rates.
-   ✅ **Secure, Encrypted Logging:**
    -   Uses **Symmetric-key Authenticated Cryptography (Fernet)** to encrypt all alert logs.
    -   Ensures log files are confidential and tamper-proof.
-   ✅ **Interactive Web Dashboard:**
    -   Futuristic, animated UI with a "glassmorphism" and cyberpunk aesthetic.
    -   Real-time charts for traffic flow and protocol distribution.
    -   Live-updating statistics and alert table.
-   ✅ **User-Friendly Controls:** Start/Stop scanning and clear alerts directly from the UI.

---

## 🛠️ Technology Stack

| Area      | Technology                                                                                             |
| :-------- | :----------------------------------------------------------------------------------------------------- |
| **Backend** | **Python 3.8+**, **Scapy** (Packet Sniffing), **Flask** (Web Server), **Flask-SocketIO** (Real-time), **Cryptography** (Log Encryption) |
| **Frontend**  | **HTML5**, **CSS3**, **JavaScript**, **Chart.js** (Visualizations), **Bootstrap 5** (Layout), **Socket.IO** (Client) |

---

## 🚀 Installation & Setup Guide

Follow these steps carefully to get the NIDS running on your local machine.

### Step 1: Prerequisites

-   **Python 3.8 or higher:** [Download Python](https://www.python.org/downloads/)
-   **Git:** [Download Git](https://git-scm.com/downloads/)
-   **System Packet Capture Library:**
    -   **Linux (Debian/Ubuntu):** `sudo apt-get update && sudo apt-get install libpcap-dev`
    -   **Windows:** Install **Npcap**. [Download from here](https://npcap.com/).
        -   **Important:** During installation, check the box for **"Install Npcap in WinPcap API-compatible Mode"**.
    -   **macOS:** Xcode Command Line Tools should include the necessary libraries.

### Step 2: Clone the Repository

Open your terminal and clone this project.

```bash
git clone <your-repository-url>
cd network-ids
```

### Step 3: Create a Virtual Environment

This isolates the project's dependencies.

```bash
# Create the virtual environment
python -m venv venv

# Activate it
# On Linux/macOS:
source venv/bin/activate
# On Windows:
venv\Scripts\activate
```

### Step 4: Install Dependencies

First, create a `requirements.txt` file with the following content:

```txt
flask==3.0.3
scapy==2.5.0
flask-socketio==5.3.0
python-socketio==5.9.0
cryptography==4.1.0
```

Now, install the packages using pip:

```bash
pip install -r requirements.txt
```

### Step 5: Run the Application

🚨 **This command MUST be run with administrator/root privileges** to allow packet sniffing.

```bash
# On Linux/macOS
sudo python app.py

# On Windows (run Command Prompt or PowerShell as Administrator)
python app.py
```

The terminal will show that the server is running. A new file, `logs/secret.key`, will be generated on the first run. **Do not share this key!**

### Step 6: Access the Dashboard

Open your web browser and navigate to:
**[http://localhost:5000](http://localhost:5000)**

---

## 🎮 Usage Guide

1.  **Start Scanning:** Click the green **"Start Scan"** button. The status will change to "ONLINE", and you will see real-time data flowing into the dashboard.
2.  **Monitor Traffic:** Watch the KPI cards, charts, and packet flow update live as network activity occurs.
3.  **View Alerts:** If a threat is detected, the "Threats Detected" count will increase, and a detailed entry will appear in the alerts table.
4.  **Clear Alerts:** Click the **"Clear Alerts"** button to clear the alerts table on the dashboard.
5.  **Stop Scanning:** Click the red **"Stop Scan"** button to halt packet capture.

---

## 🔐 The Cryptography Component Explained

This project's core cryptography feature is the secure logging of threat alerts.

#### What type of cryptography is used?

The system uses **Symmetric-key Authenticated Cryptography** via the **Fernet** implementation in Python's `cryptography` library.

1.  **Symmetric-key:** This means a single secret key (stored in `logs/secret.key`) is used to both **encrypt** and **decrypt** the alert logs. This method is chosen for its high speed, which is essential in a real-time system.
2.  **Authenticated Cryptography:** This is a critical feature. In addition to being encrypted, each log entry is signed with a secure signature (HMAC). This guarantees **data integrity**, meaning the log file is **tamper-proof**. If an attacker tries to alter the encrypted log, the signature will be invalid, and the decryption will fail, proving that the logs have been compromised.

#### How does it work?

-   When a threat is detected, the `AlertManager` takes the alert data.
-   It uses the secret key to encrypt the alert into unreadable ciphertext.
-   This ciphertext is written to the `logs/alerts.log.encrypted` file.
-   This ensures that even if an attacker gains access to the server, they cannot read or modify the history of detected threats without the secret key.

---

## 🧪 How to Test the Threat Detection

To see the NIDS in action, you can simulate common attacks.

### Test 1: Port Scan

Open a **new terminal** and run `nmap` (install if necessary).

```bash
nmap localhost
```

**Result:** A **"High"** severity **"Port Scan"** alert will immediately appear on the dashboard.

### Test 2: SYN Flood Attack

Open a **new terminal** and run `hping3` (install if necessary).

```bash
# On Linux/macOS
sudo hping3 -S -p 80 --flood localhost
```

**Result:** A **"Critical"** severity **"SYN Flood"** alert will appear, and the packet rate will spike. Press `Ctrl+C` to stop the flood.

---

## 📄 License

This project is licensed under the MIT License. See the `LICENSE` file for details.
