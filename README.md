# SpecterScope 🕵️‍♀️🔭

![SpecterScope Logo](logo.png)

SpecterScope is a lightweight, asynchronous reconnaissance tool written in Python.  
It helps security professionals quickly gather DNS, WHOIS, and HTTP header information about one or more targets — ideal as a starting point for deeper assessments.

---

## ✨ Features

- **Passive Reconnaissance**:
  - DNS `A` and `MX` records
  - WHOIS information
  - HTTP headers
- **Multi-target support** via a targets file
- **Asynchronous engine** for faster scans
- **JSON export** with timestamps for easy parsing
- **Cross-platform** (Linux, macOS, Windows with Python 3.10+)

---

## 🚀 Installation

Clone the repository and install dependencies in a virtual environment:

```bash
git clone https://github.com/RitaNoble/SpecterScope.git
cd SpecterScope
python3 -m venv specterscope-env
source specterscope-env/bin/activate
pip install -r requirements.txt
