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
├── intelligence.py          # Intelligence engine for artifact management
├── reports.py               # Multi-format report generators (TXT/HTML/JSON)
├── state_manager.py         # State persistence and resume functionality
├── anonymity.py             # TOR/proxy/UA rotation for anonymous recon
├── requirements.txt         # Python dependencies
├── plugins/                 # Plugin architecture
│   ├── __init__.py         #   Plugin package initialization
│   ├── base.py             #   Base plugin class and interface
│   ├── discovery.py        #   Plugin auto-discovery and manifest system
│   ├── nmap.yml            #   Nmap plugin manifest
│   ├── nmap_plugin.py      #   Nmap reconnaissance plugin
│   ├── theharvester.yml    #   theHarvester plugin manifest
│   └── theharvester_plugin.py #  theHarvester OSINT plugin
├── reports/                 # Generated investigation reports
├── cache/                   # Cached tool outputs and results
├── state/                   # Framework state and execution logs
│   └── intelligence/       #   Artifact database and intelligence files
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

### Plugin Auto-Discovery
```yaml
# Plugin Manifest (plugins/example.yml)
name: "plugin_name"
version: "1.0"
description: "Plugin description"
tool_name: "underlying_tool"
required_tools: ["tool1", "tool2"]
categories: ["website", "organisation"]
plugin_class: "PluginClassName"
module_path: "plugin_module"
artifacts:
  produces: ["emails", "domains", "ips"]
  consumes: ["domains", "organizations"]
chain_priority: 1
tags: ["osint", "recon"]
```

### Intelligence Engine Architecture
```python
# Artifact Management
class Artifact:
    id: str
    type: str  # email, domain, ip, port, service, etc.
    value: str
    source_plugin: str
    confidence: float
    tags: List[str]
    metadata: Dict[str, Any]

# Intelligence Processing
- Automatic artifact extraction from plugin results
- Deduplication based on type and value
- CVE enrichment for services and vulnerabilities  
- Confidence scoring and metadata enrichment
- Persistent storage with JSON and binary formats
```

### Async Execution Model
- **Worker Pool**: Configurable number of parallel workers
- **Task Queue**: Async task distribution and load balancing  
- **Timeout Handling**: Per-task and global timeout management
- **Result Aggregation**: Structured result collection and formatting

---

## 📥 Installation

### 🚀 Automated Setup (Recommended)
The easiest way to set up Detective Joe, especially on Kali Linux and systems with PEP 668 restrictions:

```bash
git clone https://github.com/vinothvbt/Detective-Joe.git
cd Detective-Joe
chmod +x setup.sh
./setup.sh
```

The setup script will:
- ✅ Check Python 3 and pip availability
- ✅ Create a virtual environment in `.venv/`
- ✅ Install all requirements safely
- ✅ Provide clear next steps

After setup, always activate the virtual environment before using Detective Joe:
```bash
source .venv/bin/activate
python3 detectivejoe.py --help
```

### 🔧 Manual Setup
For manual installation or if you prefer to manage dependencies yourself:

```bash
git clone https://github.com/vinothvbt/Detective-Joe.git
cd Detective-Joe

# Create and activate virtual environment
python3 -m venv .venv
source .venv/bin/activate

# Install requirements
pip install -r requirements.txt

# Make script executable
chmod +x detectivejoe.py
```

**Important for Kali Linux users:** Due to PEP 668 externally-managed-environment restrictions, Detective Joe **requires** a virtual environment. The automated setup handles this automatically.

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

### 🚀 Quick Start with Demo Mode
If you want to test Detective Joe immediately without installing external tools:

```bash
# After setup, try the demo mode
source .venv/bin/activate
python3 detectivejoe.py -c website -t example.com -p demo
```

The demo profile uses basic system tools (curl, echo) to demonstrate the framework without requiring nmap or theharvester. This is perfect for:
- ✅ Testing the framework functionality
- ✅ Understanding the report generation
- ✅ Learning the command structure
- ✅ CI/CD environments

---

## ▶️ Usage

### CLI Mode (New in v1.5)
```bash
# 🚀 Demo mode - works without external tools
python3 detectivejoe.py -c website -t example.com -p demo

# Website investigation using standard profile
python3 detectivejoe.py -c website -t example.com

# Deep organisation scan with custom workers
python3 detectivejoe.py -c organisation -t company.com -p deep --workers 8

# Quick IP investigation with custom timeout
python3 detectivejoe.py -c ip -t 192.168.1.1 -p quick --timeout 60

# Stealth investigation with anonymity
python3 detectivejoe.py -c website -t example.com -p stealth

# List available profiles and plugins
python3 detectivejoe.py --list-profiles
python3 detectivejoe.py --list-plugins
```

### State Management
```bash
# Resume interrupted investigation
python3 detectivejoe.py --resume investigation_id

# List saved states
python3 detectivejoe.py --list-states

# Kill active investigation (Ctrl+C also works)
python3 detectivejoe.py --kill
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
[*] Processing 15 artifacts through intelligence engine
[*] Performing artifact chaining with depth 2
[*] Chained 3 additional tasks from discovered targets
[✓] Investigation completed successfully!
[✓] TXT report saved: reports/example.com_website_2025-01-15_14-30-45.txt
[✓] HTML report saved: reports/example.com_website_2025-01-15_14-30-45.html
[✓] JSON report saved: reports/example.com_website_2025-01-15_14-30-45.json

SUMMARY:
  Tasks executed: 5
  Success rate: 100.0%
  Total time: 45.23s
  Artifacts found: 15
  Chained tasks: 3
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
    scan_depth: 1
    aggressiveness: "low"
    enable_chaining: false
    anonymity:
      use_tor: false
      use_proxy: false
      user_agent_rotation: false
    tools:
      website: ["nmap"]
      
  standard:
    name: "Standard Scan"  
    timeout: 120
    parallel_workers: 4
    scan_depth: 2
    aggressiveness: "medium"
    enable_chaining: true
    anonymity:
      use_tor: false
      use_proxy: false
      user_agent_rotation: true
    tools:
      website: ["nmap", "theharvester"]
      organisation: ["theharvester", "nmap"]
      
  deep:
    name: "Deep Scan"
    timeout: 300
    parallel_workers: 6
    scan_depth: 3
    aggressiveness: "high"
    enable_chaining: true
    tools:
      website: ["nmap", "theharvester"]
      
  stealth:
    name: "Stealth Scan"
    timeout: 600
    parallel_workers: 2
    aggressiveness: "low"
    anonymity:
      use_tor: true
      use_proxy: true
      user_agent_rotation: true
      request_delay: 5
      randomize_timing: true
    tools:
      website: ["theharvester"]
```

### Plugin Configuration
Plugins are automatically discovered from the `plugins/` directory through YAML manifests:

**Auto-Discovery Process:**
1. Scans `plugins/` for `.yml`/`.yaml` manifest files
2. Validates manifest structure and required fields
3. Dynamically loads plugin classes from specified modules
4. Registers plugins with the global plugin registry
5. Checks tool availability and marks plugins as available/unavailable

**Plugin Chaining:**
- Artifacts discovered by plugins automatically feed into subsequent plugins
- Chain priority determines execution order
- Configurable scan depth controls chaining levels
- Aggressiveness setting limits number of chained targets

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
Total Tasks Executed: 5
Successful Tasks: 5  
Success Rate: 100.0%
Total Execution Time: 45.23 seconds
Artifacts Found: 15
Chained Tasks: 3

ARTIFACTS DISCOVERED
--------------------
Emails: 3
Domains: 5  
IPs: 2
Open Ports: 4
Services: 3

[NMAP] - Status: COMPLETED
==================================================
Command: nmap -sV -sC -A --top-ports 1000 example.com -T4

STRUCTURED DATA:
--------------------
HOSTS: 
  - example.com (93.184.216.34)
OPEN_PORTS:
  - 80/tcp (http) - Apache httpd 2.4.41
  - 443/tcp (https) - Apache httpd 2.4.41 (SSL)

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

DETAILED ARTIFACTS
==================
EMAIL ARTIFACTS:
------------------------------
Value: admin@example.com
Source: theharvester
Confidence: 0.80
Tags: email, contact
Metadata: {"domain": "example.com"}

[Additional formats: HTML with interactive features, JSON with structured data]
```

---

## 🧪 Testing

Run the comprehensive test suite:
```bash
cd tests
python3 test_framework.py
```

Tests cover:
- Plugin base class functionality and async execution
- Plugin auto-discovery and manifest loading
- Async worker pool operations and task management
- Intelligence engine artifact processing
- Report generation in multiple formats
- State management and persistence
- Integration workflows and error handling

---

## 🛣️ v1.5 Technical Vision & Implementation Status

### 🏗️ Current Implementation Status

**✅ Core Framework (Fully Functional)**
- Async execution framework with configurable worker pools
- Plugin architecture with auto-discovery from YAML manifests
- Profile-based configuration with advanced controls
- CLI and interactive modes with comprehensive argument parsing
- Multi-format report generation (TXT/HTML/JSON)
- Comprehensive test infrastructure with async support

**✅ Framework Components (Implemented)**
- Artifact extraction and management system
- Automatic deduplication with confidence scoring
- Basic CVE pattern recognition in output
- Persistent artifact database (JSON/binary)
- State management with save/resume/kill functionality
- Investigation persistence and recovery
- Anonymity layer with TOR/proxy/User-Agent rotation
- Plugin chaining based on artifact types

**⚠️ Plugin System (Requires External Tools)**
- YAML-based plugin manifests with metadata ✅
- Auto-discovery and dynamic loading ✅
- Nmap plugin with intelligent command building ⚠️ *requires nmap installation*
- theHarvester plugin with comprehensive parsing ⚠️ *requires theharvester installation*
- Graceful handling of missing tools ✅

**📋 Dependencies Required for Full Functionality**
Detective Joe's plugins require external reconnaissance tools to be installed:
```bash
# Ubuntu/Debian
sudo apt install nmap

# Install theHarvester
pip install theHarvester
# OR
git clone https://github.com/laramies/theHarvester
```

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

**1. Create Plugin YAML Manifest:**
```yaml
# plugins/mytool.yml
name: "mytool"
version: "1.0"
description: "Custom reconnaissance tool"
tool_name: "mytool"
required_tools: ["mytool"]
categories: ["website", "ip_server"]
plugin_class: "MyToolPlugin"
module_path: "mytool_plugin"
artifacts:
  produces: ["vulnerabilities", "services"]
  consumes: ["domains", "ips"]
chain_priority: 3
tags: ["security", "scanning"]
```

**2. Implement Plugin Class:**
```python
# plugins/mytool_plugin.py
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

**3. Plugin Auto-Discovery:**
Plugins are automatically discovered and loaded on framework startup.

### Profile Customization
Create custom profiles in `profiles.yaml`:
```yaml
profiles:
  my_custom:
    name: "My Custom Profile"
    description: "Tailored reconnaissance profile"
    timeout: 180
    parallel_workers: 6
    scan_depth: 2
    aggressiveness: "medium"
    enable_chaining: true
    anonymity:
      use_tor: false
      use_proxy: true
      proxy_list: ["http://proxy1:8080"]
      user_agent_rotation: true
      request_delay: 2
    tools:
      website: ["nmap", "theharvester", "mytool"]
```

### Advanced Configuration
```yaml
global_settings:
  max_parallel_workers: 8
  default_timeout: 120
  cache_enabled: true
  state_persistence: true
  intelligence_engine: true
  artifact_chaining: true
  cve_enrichment: true
  report_formats: ["txt", "html", "json"]
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
