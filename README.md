# 🔐 Secure File Transfer Monitoring System

### Real-Time File Activity Monitoring & Integrity Verification Tool

🔗 **Project Repository:** https://github.com/your-username/secure-file-monitor

![Python](https://img.shields.io/badge/Python-3.x-blue?logo=python)
![Security](https://img.shields.io/badge/Domain-Cybersecurity-red)
![Status](https://img.shields.io/badge/Project-Completed-brightgreen)

---

## 📌 Overview

The **Secure File Transfer Monitoring System** is a lightweight cybersecurity tool designed to monitor file system activities in real time and detect suspicious behavior.

It tracks operations such as file creation, modification, deletion, and movement, while ensuring data integrity using SHA-256 hashing.

---

## 🚀 Key Features

✔ Real-time file monitoring
✔ Detection of file creation, modification, deletion
✔ SHA-256 based integrity verification
✔ Sensitive directory monitoring
✔ Threshold-based suspicious activity detection
✔ Alert generation for abnormal events
✔ Structured logging for forensic analysis

---

## 🛠️ Tech Stack

| Technology     | Purpose                |
| -------------- | ---------------------- |
| Python         | Core logic             |
| Watchdog       | File system monitoring |
| Hashlib        | SHA-256 hashing        |
| Logging Module | Event logging          |

---

## 🐍 Python Version

Python 3.x (Recommended: Python 3.8 or above)

---

## ⚙️ Installation

```bash
# Clone repository
git clone https://github.com/your-username/secure-file-monitor.git

# Navigate to project
cd secure-file-monitor

# Install dependencies
pip install -r requirements.txt

# Run application
python monitor.py
```

---

## 🧪 Usage

1. Run the monitoring script
2. Perform file operations in the monitored directory

---

## 🔍 Test Scenarios

| Action         | Example                       |
| -------------- | ----------------------------- |
| Create file    | report.txt                    |
| Modify file    | Edit file content             |
| Delete file    | Remove file                   |
| Sensitive file | Modify file in /sensitive/    |
| Bulk activity  | Modify multiple files quickly |

---

## 🧠 Detection Techniques

### 🔹 File Event Monitoring

Tracks real-time file system events:

* Create
* Modify
* Delete
* Move

### 🔹 Hash-Based Integrity Verification

* Uses SHA-256 hashing
* Detects file tampering by comparing hash values

### 🔹 Sensitive Directory Monitoring

* Flags activities inside protected folders
* Generates alerts for critical file access

### 🔹 Threshold-Based Detection

* Monitors frequency of file operations
* Detects bulk file movement (possible data exfiltration)

---

## 🏗️ System Architecture

```
File System → Watchdog Observer → Event Handler  
            → Integrity Check → Activity Analyzer  
            → Alert System → Logging Module
```

---

## 🔄 Workflow

1. System starts monitoring
2. File event detected
3. Event passed to handler
4. Sensitive directory check
5. Integrity verification (hash check)
6. Activity frequency analyzed
7. Alert generated (if suspicious)
8. Event logged

---

## 📊 Output

* File events displayed in terminal
* Alerts for suspicious activity
* Logs stored in `logs/activity.log`

### Example Output

```
CREATED -> report.txt  
MODIFIED -> report.txt  
ALERT: Sensitive file MODIFIED -> sensitive/passwords.txt  
INTEGRITY ALERT: File modified -> report.txt  
SUSPICIOUS MOVEMENT: 10 files changed within 60 seconds  
```

---

## 📁 Project Structure

```
secure-file-monitor/
│── monitor.py
│── requirements.txt
│── logs/
│   └── activity.log
│── sensitive/
│── screenshots/
│── README.md
```

---

## ✅ Advantages

* Real-time monitoring
* Detects unauthorized file activity
* Ensures file integrity
* Useful for forensic analysis
* Simple and lightweight

---

## ⚠️ Limitations

* Monitors only local file systems
* No user identification
* Limited external device tracking

---

## 🚀 Future Improvements

* Email alert notifications
* Real-time dashboard
* Cloud storage monitoring
* Machine learning-based anomaly detection
* SIEM integration

---

## 📚 Learning Outcomes

* File system monitoring
* Cryptographic hashing (SHA-256)
* Log analysis
* Threat detection techniques
* Python-based security tool development

---

## 🏁 Conclusion

This project demonstrates how file monitoring systems enhance security by detecting suspicious activities and maintaining data integrity. It provides practical exposure to cybersecurity monitoring techniques used in real-world environments.

---

## 📦 Deliverables

* Python monitoring script
* Log files
* Architecture diagram
* Flowchart
* Documentation

---

## 📖 References

* Python Documentation – https://docs.python.org
* Watchdog Documentation
* NIST Cybersecurity Guidelines
* Digital Forensics Concepts

---

## 👩‍💻 Author

**Vaishali Vasant Kadam**
Cyber Security Internship Project
Unified Mentor


---

⭐ *If you like this project, consider giving it a star!*
