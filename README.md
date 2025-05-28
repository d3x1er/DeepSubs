![License](https://img.shields.io/badge/license-MIT-blue.svg)
![Python](https://img.shields.io/badge/python-3.7+-blue.svg)

# 🔎 DeepSubs - Advanced Subdomain Enumeration Tool

**DeepSubs** is an advanced, modular subdomain enumeration framework designed for security professionals, red teamers, and bug bounty hunters.

It orchestrates multiple OSINT sources and external tools to collect, consolidate, and de-duplicate subdomain information for a target domain. DeepSubs is highly configurable, scriptable, and extensible.

# Contents

- [✨ Features](#sparkles-features)
- [🔧 Supported Sources](#wrench-supported-sources)
- [🔑 API Keys](#key-api-keys)
- [🛠️ System Requirements](#hammer_and_wrench-system-requirements)
- [🚀 Usage](#rocket-usage)
    - [🔍 Examples](#mag-examples)
- [⚙️ Options](#gear-options)
- [📁 Output](#file_folder-output)
- [⚠️ Notes](#warning-notes)
- [📦 Installation](#package-installation)
- [📃 License](#page_with_curl-license)
- [🤝 Contributing](#handshake-contributing)

* * *

## ✨ Features

- 🧩 Supports 15+ data sources (CLI tools + APIs)
- 🎯 Automatic deduplication of results
- ⚙️ Customizable tool selection via `--tools`
- 🧵 Optional DNS probing with multithreaded support
- 📦 Output to list, JSON, or CSV formats
- 📛 Graceful error handling for missing tools or APIs

* * *

## 🔧 Supported Sources

DeepSubs integrates the following sources for comprehensive coverage:

| Source | Type |
| --- | --- |
| `subfinder` | CLI Tool |
| `amass` | CLI Tool |
| `assetfinder` | CLI Tool |
| `findomain` | CLI Tool |
| `knockpy` | CLI Tool |
| `sublist3r` | CLI Tool |
| `anubis` | CLI Tool |
| `crt.sh` | Public CT API |
| `hackertarget` | Web Service |
| `threatcrowd` | OSINT API |
| `shodan` | API |
| `virustotal` | API |
| `securitytrails` | API |
| `dnsdumpster` | API |
| `urlscan.io` | API |

> ✅ If a source is unavailable or not installed, DeepSubs will skip it gracefully and continue.

* * *

## 🔑 API Keys

Some sources require API keys. You must insert them manually inside the script:

```python
# ====== INSERT YOUR API KEYS HERE ======
VIRUSTOTAL_API_KEY = "your-key"
SECURITYTRAILS_API_KEY = "your-key"
SHODAN_API_KEY = "your-key"
URLSCAN_API_KEY = "your-key"
DNSDUMPSTER_API_KEY = "your-key"
# =======================================
```

* * *

## 🛠️ System Requirements

- Python 3.7+
    
- `pip install -r requirements.txt`
    
- Some tools must be available in your `$PATH`:
    
    - `subfinder`, `amass`, `assetfinder`, `findomain`, `knockpy`, `sublist3r`, `anubis`

To install the CLI tools, follow their respective documentation or use `apt`, `brew`, or `go install`.

* * *

## 🚀 Usage

`python3 deepsub.py <domain> [options]`

### 🔍 Examples

```bash
# Default: run all tools and output simple list
python3 deepsub.py example.com

# Output results in JSON format
python3 deepsub.py example.com --output json

# Use only selected tools
python3 deepsub.py example.com --tools subfinder,amass,crt.sh

# Run with DNS probing and multithreading
python3 deepsub.py example.com --probe --threads 100 --output csv

```

* * *

## ⚙️ Options

| Option | Description |
| --- | --- |
| `--tools` | Comma-separated list of tools to use |
| `--probe` | Probe DNS records for discovered domains |
| `--threads` | Thread count for probing (default: 50) |
| `--output` | Output format: `list`, `json`, `csv` |

* * *

## 📁 Output

At the end of each scan, DeepSubs produces:

- A **deduplicated list** of discovered subdomains
    
- Optional DNS probing results
    
- Exportable data formats for integration with other tools or pipelines
    

## 📤 Output Formats

- `list` (default) – clean line-separated list
    
- `json` – structured JSON array
    
- `csv` – exportable format with fields
    

* * *

## ⚠️ Notes

- Some data sources (e.g. `amass`, `<span style="color: #383a42;">knockpy</span>`, `<span style="color: #383a42;">anubis</span>`) may be slow — this is expected.
    
- Results from different tools may overlap — DeepSubs ensures a clean, unique set.
    
- API-based sources may enforce rate limits or quota restrictions.
    

* * *

## 📦 Installation

```bash
git clone https://github.com/your-username/deepsubs.git
cd deepsubs
pip install -r requirements.txt

```

* * *

## 📃 License

This project is licensed under the MIT License.

* * *

## 🤝 Contributing

Pull requests, feature suggestions, and feedback are welcome! Please submit an issue to discuss improvements or integrations.

&nbsp;
