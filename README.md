# Detective Joe v1.5 — Next-Gen Recon Framework

## 📌 Overview
Detective Joe (**DJ**) v1.5 is a **next-generation automated reconnaissance framework** built for security professionals and researchers. Instead of running individual tools one by one, DJ chains reconnaissance tools through an async plugin architecture, executes them efficiently in parallel, and merges results into comprehensive, structured reports.

**Think of DJ as your intelligent recon operator** — you define the target and profile once, it handles the orchestration, execution, and analysis.

---

## 🚀 v1.5 Features

### Core Framework Capabilities
- **🔄 Async Worker Pool**: Parallel task execution with configurable worker limits
- **🧩 Plugin Architecture**: Modular, extensible plugin system for reconnaissance tools
- **⚙️ Profile System**: Configurable investigation profiles (quick, standard, deep, custom)
- **🖥️ Dual Interface**: Both CLI arguments and interactive menu support
- **📊 Structured Reports**: TXT reports with parsed data and execution statistics
- **💾 State Management**: Caching, state persistence, and execution history

### Investigation Categories
- 🌐 **Website Investigation**: Domain analysis, subdomain discovery, web security
- 🏢 **Organisation Investigation**: Company intelligence, employee discovery, infrastructure mapping  
- 👤 **People Investigation**: OSINT on individuals, social media presence, contact discovery
- 🖥️ **IP / Server Investigation**: Network analysis, service detection, vulnerability assessment

### Built-in Plugins (Proof of Concept)
- **Nmap Plugin**: Network scanning with intelligent command building
- **theHarvester Plugin**: Email harvesting and OSINT data collection
- **Extensible Framework**: Easy addition of new tool plugins

---

## 🏗️ v1.5 Technical Architecture

### Directory Structure
```
detective-joe/
├── detectivejoe.py          # Main CLI script with async execution
├── config.py                # Legacy tool configurations (v1 compatibility)
├── profiles.yaml            # Investigation profiles and settings
├── async_worker.py          # Async worker pool implementation
├── requirements.txt         # Python dependencies
├── plugins/                 # Plugin architecture
│   ├── __init__.py         #   Plugin package initialization
│   ├── base.py             #   Base plugin class and interface
│   ├── nmap_plugin.py      #   Nmap reconnaissance plugin
│   └── theharvester_plugin.py #  theHarvester OSINT plugin
├── reports/                 # Generated investigation reports
├── cache/                   # Cached tool outputs and results
├── state/                   # Framework state and execution logs
├── tests/                   # Test infrastructure
│   └── test_framework.py   #   Comprehensive test suite
└── README.md               # This documentation
```

### Plugin System Architecture
```python
# Plugin Interface
class PluginBase(ABC):
    @abstractmethod
    async def execute(target, category, **kwargs) -> Dict[str, Any]
    @abstractmethod  
    def build_command(target, category, **kwargs) -> str
    @abstractmethod
    def parse_output(output, target, category) -> Dict[str, Any]
```

### Async Execution Model
- **Worker Pool**: Configurable number of parallel workers
- **Task Queue**: Async task distribution and load balancing  
- **Timeout Handling**: Per-task and global timeout management
- **Result Aggregation**: Structured result collection and formatting

---

## 📥 Installation

```bash
git clone https://github.com/vinothvbt/Detective-Joe.git
cd Detective-Joe
pip install -r requirements.txt
chmod +x detectivejoe.py
```

### System Dependencies
Detective Joe v1.5 leverages existing reconnaissance tools. Install them via:

**Kali Linux (recommended):**
```bash
sudo apt update
sudo apt install nmap theharvester sublist3r amass wafw00f whatweb nikto dirb sslscan dnsrecon
```

**Other Linux distributions:**
```bash
# Install tools according to your distribution's package manager
# Many tools are also available via GitHub or pip
```

---

## ▶️ Usage

### CLI Mode (New in v1.5)
```bash
# Website investigation using standard profile
python3 detectivejoe.py -c website -t example.com

# Deep organisation scan with custom workers
python3 detectivejoe.py -c organisation -t company.com -p deep --workers 8

# Quick IP investigation with custom timeout
python3 detectivejoe.py -c ip -t 192.168.1.1 -p quick --timeout 60

# List available profiles and plugins
python3 detectivejoe.py --list-profiles
python3 detectivejoe.py --list-plugins
```

### Interactive Mode (Enhanced)
```bash
python3 detectivejoe.py --interactive
```

Example CLI Session:
```
$ python3 detectivejoe.py -c website -t example.com -p standard

╔══════════════════════════════════════════════════════════════╗
║                    DETECTIVE JOE v1.5                       ║
║                 Next-Gen Recon Framework                     ║
║                                                              ║
║  Profile: standard           Workers: 4                      ║
║  Async Execution │ Plugin Architecture │ CLI & Interactive   ║
╚══════════════════════════════════════════════════════════════╝

[*] Starting website investigation for: example.com
[*] Using profile: standard
[*] Executing 2 plugins: ['nmap', 'theharvester']
[✓] Investigation completed successfully!
[✓] Report saved: reports/example.com_website_2025-01-15_14-30-45.txt

SUMMARY:
  Tasks executed: 2
  Success rate: 100.0%
  Total time: 45.23s
```

---

## ⚙️ Configuration

### Profiles System (profiles.yaml)
```yaml
profiles:
  quick:
    name: "Quick Scan"
    timeout: 60
    parallel_workers: 3
    enabled_categories: [website, ip_server]
    tools:
      website: [nmap, theharvester]
      
  standard:
    name: "Standard Scan"  
    timeout: 120
    parallel_workers: 4
    tools:
      website: [nmap, theharvester, whatweb]
      organisation: [theharvester, nmap]
      
  deep:
    name: "Deep Scan"
    timeout: 300
    parallel_workers: 6
    tools:
      website: [nmap, theharvester, sublist3r, amass, whatweb, nikto]
```

### Plugin Configuration
Each plugin automatically:
- Validates target compatibility
- Checks tool availability  
- Builds appropriate commands
- Parses and structures output
- Handles errors and timeouts

---

## 📄 Report Output

### Enhanced Report Structure
```
DETECTIVE JOE v1.5 INVESTIGATION REPORT
=======================================
Investigation Type: Website Investigation
Target: example.com
Profile: standard
Date: 2025-01-15T14:30:45

EXECUTIVE SUMMARY
-----------------
Total Tasks Executed: 2
Successful Tasks: 2  
Success Rate: 100.0%
Total Execution Time: 45.23 seconds

[NMAP] - Status: COMPLETED
==================================================
Command: nmap -sV -sC -A --top-ports 1000 example.com -T4

STRUCTURED DATA:
--------------------
HOSTS: 
  - example.com (93.184.216.34)
OPEN_PORTS:
  - 80/tcp (http)
  - 443/tcp (https)
SERVICES:
  - 80: Apache httpd 2.4.41
  - 443: Apache httpd 2.4.41 (SSL)

[THEHARVESTER] - Status: COMPLETED  
==================================================
Command: theHarvester -d example.com -b google,bing,duckduckgo,yahoo -l 500

STRUCTURED DATA:
--------------------
EMAILS:
  - admin@example.com
  - info@example.com
HOSTS:
  - www.example.com
  - mail.example.com
```

---

## 🧪 Testing

Run the comprehensive test suite:
```bash
cd tests
python3 test_framework.py
```

Tests cover:
- Plugin base class functionality
- Async worker pool operations
- Plugin execution and parsing
- Integration workflows
- Error handling and edge cases

---

## 🛣️ v1.5 Technical Vision & Roadmap

### Current Release (v1.5)
✅ **Foundation Architecture**
- Async execution framework with worker pools
- Plugin architecture with extensible base classes
- Profile-based configuration system
- CLI argument parsing alongside interactive mode
- Comprehensive test infrastructure
- Structured report generation

✅ **Proof-of-Concept Plugins**
- Nmap plugin with intelligent command building
- theHarvester plugin with output parsing
- Plugin availability checking and validation

### Upcoming Releases

**v1.6 - Extended Plugin Library**
- Additional built-in plugins (sublist3r, amass, whatweb, nikto)
- Plugin dependency management
- Plugin marketplace/registry concept
- Enhanced error recovery and retry logic

**v1.7 - Advanced Intelligence**
- AI-powered result correlation and analysis
- Intelligent scan prioritization
- Vulnerability scoring and risk assessment
- Automated follow-up recommendations

**v1.8 - Enterprise Features**
- Distributed scanning across multiple nodes
- REST API for programmatic access
- Web-based dashboard and real-time monitoring
- Database storage for historical analysis

**v2.0 - Professional Platform**
- Multi-tenant support for teams/organizations
- Advanced reporting with PDF/HTML outputs
- Integration with SIEM and security platforms
- Compliance reporting and audit trails

---

## 🔧 Development & Extension

### Adding New Plugins
```python
from plugins.base import PluginBase

class MyToolPlugin(PluginBase):
    def __init__(self):
        super().__init__("mytool", "1.0")
    
    @property
    def tool_name(self):
        return "mytool"
    
    @property
    def categories(self):
        return ["website", "ip_server"]
    
    @property
    def required_tools(self):
        return ["mytool"]
    
    def build_command(self, target, category, **kwargs):
        return f"mytool --target {target}"
    
    def parse_output(self, output, target, category):
        return {"raw_output": output, "target": target}
```

### Profile Customization
Create custom profiles in `profiles.yaml`:
```yaml
profiles:
  my_custom:
    name: "My Custom Profile"
    timeout: 180
    parallel_workers: 6
    tools:
      website: [nmap, theharvester, mytool]
```

---

## ⚠️ Legal Disclaimer
This tool is intended for:
- **Educational purposes and security research**
- **Authorized penetration testing and security assessments**
- **OSINT research within legal boundaries**

**Unauthorized use against systems you do not own or have explicit permission to test is illegal** and may result in criminal charges. Users are responsible for ensuring compliance with applicable laws and regulations.

---

## 💡 Author & Credits
- **Framework Architecture**: Detective Joe v1.5 Development Team
- **Original Concept**: Detective Joe v1.0 (Kali-focused recon tool)
- **Plugin System**: Inspired by modern security framework architectures
- **Async Implementation**: Built on Python asyncio for performance

**Contributing**: We welcome contributions! Please see our contribution guidelines and submit pull requests for new plugins, features, or improvements.

---

*Detective Joe v1.5 - Where intelligence meets automation.*
