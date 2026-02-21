# RANSOMRUN

**Ransomware Simulation Lab Platform for Security Training**

A local lab platform for simulating ransomware attacks and automated incident response. Designed for university capstone projects and security training.

![Python](https://img.shields.io/badge/Python-3.10+-blue.svg)
![FastAPI](https://img.shields.io/badge/FastAPI-0.104+-green.svg)
![License](https://img.shields.io/badge/License-Educational-yellow.svg)

---

## ⚠️ IMPORTANT DISCLAIMER

**This platform is for EDUCATIONAL and LAB use only!**

- Only run on isolated, non-production systems
- The agent performs real file operations and system changes
- Some actions (like shadow copy deletion) are destructive
- Never run on production systems or networks

---

## Features

### Core Features
- **Host Registration**: Windows agents register with the platform
- **Simulation Scenarios**: Pre-defined ransomware simulation behaviors
- **ELK SIEM Integration**: Connect to Elasticsearch/OpenSearch for security alerts
- **Automated Playbooks**: Map alerts to response actions
- **Incident Reports**: Detailed run reports with MITRE ATT&CK mapping
- **Web Dashboard**: Bootstrap-based UI for management

### Advanced Features (v3.0)

#### 1. Behavior DNA Lab
- **Behavior Fingerprinting**: Generates unique behavior profiles for each simulation run
- **MITRE Technique Extraction**: Automatically identifies ATT&CK techniques used
- **Intensity & Stealthiness Scores**: Quantifies attack aggressiveness and detection evasion
- **DNA Vector**: Compact fingerprint showing encryption, recovery inhibition, exfil, persistence levels
- **Profile Labels**: Categorizes attacks as LOUD_CRYPTO, STEALTH_CRYPTO, EXFIL_FOCUSED, etc.

#### 2. What-If Time Machine
- **Counterfactual Analysis**: Simulate how outcomes would change with different defenses
- **Pre-defined Scenarios**: EDR present, extra Wazuh rules, no local admin, faster response
- **Recalculated Metrics**: New detection time, files impacted, risk score
- **Side-by-side Comparison**: Compare actual vs hypothetical outcomes

#### 3. Blue Team Skill Profile & SOC CV
- **Analyst Tracking**: Track individual analyst performance across IR sessions
- **Skill Metrics**: Average detection time, response time, runs handled
- **Strengths/Weaknesses**: Auto-generated skill assessment
- **SOC CV Export**: Printable analyst performance profile

#### 4. Adaptive Coach Mode
- **Post-Run Feedback**: Automatic feedback generation after each simulation
- **Positives**: What went well during incident response
- **Negatives**: Areas that need improvement
- **Recommendations**: Actionable suggestions for skill development

#### 5. Business Impact Simulator
- **Technical to $$$**: Translate incident metrics to business costs
- **Configurable Parameters**: Business unit, criticality, cost per hour
- **Downtime & Recovery Estimates**: Hours of disruption calculated
- **Total Cost Estimation**: Full financial impact assessment

#### 6. Compliance/Regulatory View
- **GDPR-style Reports**: Management and regulator-friendly incident reports
- **Timeline Documentation**: Incident start, detection, containment times
- **Data Impact Assessment**: Personal data involvement, risk to individuals
- **Notification Requirement**: Automatic assessment of regulatory notification needs
- **Mitigation Recommendations**: Prevention guidance based on incident analysis

---

## Quick Start

### 1. Install Dependencies

```bash
# Create virtual environment
python -m venv venv

# Activate (Windows)
venv\Scripts\activate

# Activate (Linux/Mac)
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt
```

### 2. Start the Backend Server

```bash
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

The server will:
- Initialize the SQLite database
- Seed default scenarios and playbooks
- Start accepting connections

### 3. Open the Web UI

Navigate to: **http://localhost:8000**

You'll see the dashboard with:
- Statistics overview
- Recent alerts
- Quick action buttons

---

## Running the Windows Agent

### Prerequisites

- Windows 10/11 (or Windows Server)
- Python 3.10+ installed
- `requests` library: `pip install requests`

### Setup

1. Copy `agent/agent.py` to the Windows victim machine

2. Edit the configuration at the top of the script:

```python
# Backend server URL (change to your server's IP)
BACKEND_URL = "http://192.168.1.100:8000"

# Agent ID - leave empty to use hostname
AGENT_ID = ""

# Test directory for ransomware simulation
TEST_DIR = r"C:\RansomTest"
```

3. Run the agent:

```bash
python agent.py
```

Or with command-line options:

```bash
python agent.py --server http://192.168.1.100:8000 --agent-id MyTestPC
```

### Agent Utility Commands

```bash
# Restore "encrypted" files (remove .locked extension)
python agent.py --restore

# Remove network isolation (delete firewall rule)
python agent.py --unisolate
```

---

## Starting a Simulation

### Via Web UI

1. Go to **http://localhost:8000/simulate**
2. Select a registered host
3. Select a scenario
4. Click "Start Simulation"

### Via API

```bash
curl -X POST http://localhost:8000/api/run-simulation \
  -H "Content-Type: application/json" \
  -d '{"host_id": 1, "scenario_id": 1}'
```

---

## ELK SIEM Integration

RansomRun integrates with **Elasticsearch** (ELK Stack) as the SIEM backend with **live alert streaming** and **Sysmon-based ransomware detection**.

### Quick Start

1. **Configure ELK connection** - Copy `app/.env.example` to `app/.env`:

```env
ELASTICSEARCH_URL=http://localhost:9200
ELASTICSEARCH_USERNAME=elastic
ELASTICSEARCH_PASSWORD=changeme
ELK_INDEX=winlogbeat-*
SIEM_MODE=elastic  # Use "mock" for offline development
```

2. **Start the backend**:
```bash
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

3. **Open the ELK Dashboard**: http://localhost:8000/siem/elk

### SIEM Modes

| Mode | Description |
|------|-------------|
| `mock` | Simulated data for offline development (no ELK required) |
| `elastic` | Live connection to Elasticsearch with real-time detection |

### Detection Engine

When `SIEM_MODE=elastic`, RansomRun runs a background detection engine that:
- Polls Elasticsearch every 3 seconds for Sysmon events
- Runs behavior detection rules against events
- Creates alerts in the database
- Streams alerts to the UI via SSE (no page refresh needed)

### Detection Rules

| Rule ID | Name | MITRE | Description |
|---------|------|-------|-------------|
| RR-2001 | Mass File Create Spike | T1486 | Detects high rate of file creation (ransomware encryption) |
| RR-2002 | Shadow Copy Deletion | T1490, T1562 | Detects vssadmin/wbadmin/bcdedit backup deletion |
| RR-2003 | Office → Script → Network | T1059.001, T1071 | Detects Office macro spawning script with network activity |
| RR-2004 | LSASS Access | T1003.001 | Detects credential dumping attempts |

### API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/elk/status` | Connection status |
| GET | `/elk/alerts` | Get security alerts |
| GET | `/elk/stats` | Dashboard statistics |
| GET | `/elk/mitre/heatmap` | MITRE technique frequency |
| GET | `/elk/mode` | Get current SIEM mode |
| GET | `/api/siem/elk/events` | Raw Sysmon events (debug) |
| GET | `/api/siem/elk/detections/status` | Detection engine status |
| GET | `/api/alerts/stream` | SSE stream for live alerts |

### Live Alert Streaming

The ELK Dashboard includes a **Live Alerts Feed** widget that:
- Connects to `/api/alerts/stream` via Server-Sent Events
- Displays alerts in real-time without page refresh
- Shows severity badges, MITRE techniques, and host info
- Click any alert to view full details (process, command line, etc.)

### Sysmon Requirements

The detection engine expects Sysmon events in `winlogbeat-*` index with:
- `event.provider` = `Microsoft-Windows-Sysmon`
- Event IDs: 1 (ProcessCreate), 3 (NetworkConnect), 10 (ProcessAccess), 11 (FileCreate)

### Kibana Access

Kibana is bound to `127.0.0.1:5601` by default. To expose externally:

```yaml
# kibana.yml
server.host: "0.0.0.0"
```

### Troubleshooting

| Issue | Solution |
|-------|----------|
| Connection refused | Check `ELASTICSEARCH_URL` and ensure ES is running |
| No events found | Verify `ELK_INDEX` matches your Winlogbeat index pattern |
| Field mapping errors | Check Sysmon field names (may vary by Winlogbeat version) |
| Detection engine not starting | Ensure `SIEM_MODE=elastic` in `.env` |

---

## Simulation Scenarios

RansomRun v2.0 includes an advanced **Scenario Engine** with configurable JSON-based scenarios.

### Available Scenarios

| Scenario | Category | Description |
|----------|----------|-------------|
| `crypto_basic` | crypto | Basic ransomware: file rename, ransom note, vssadmin |
| `crypto_aggressive` | crypto | Multi-directory, high file count, persistence, network beacon |
| `locker_desktop` | locker | Screen locker simulation, desktop ransom note, persistence |
| `wiper_sim` | wiper | Destructive wiper (files moved to quarantine, not deleted) |
| `exfil_only` | exfil | Data exfiltration prep: ZIP staging, no network upload |
| `fake_ransom_training` | fake | Minimal impact training scenario, educational ransom note |
| `multi_stage_combo` | multi-stage | Persistence → Encryption → Exfiltration with delays |

### Scenario Configuration

Each scenario has a JSON config that controls:
- `directories_to_target` - Target directories
- `file_extensions` - File types to affect
- `rename_pattern` - Extension to add (e.g., `.locked`)
- `ransom_note` - Filename, content, and locations
- `simulate_vssadmin` - Delete shadow copies
- `simulate_persistence` - Create registry persistence
- `simulate_exfiltration` - Create staging ZIP
- `simulate_network_beacon` - Log C2 beacon simulation
- `intensity_level` - 1-5, controls file count
- `optional_delay_seconds` - Dwell time simulation
- `tags` - MITRE techniques and training level

---

## Custom Ransomware Scenarios

RansomRun v3.2 introduces a **Custom Scenario Builder** that allows you to create, edit, clone, and manage your own ransomware simulation scenarios.

### ⚠️ Safety Design

**All custom scenarios are SIMULATION ONLY:**
- No real encryption - files are only renamed
- No network exfiltration - only local ZIP staging
- No destructive deletion - wiper mode uses quarantine folder
- System directories (C:\Windows, C:\Program Files) are blocked
- Maximum file limit enforced (1000 files)

### Creating a Custom Scenario

#### Via Web UI

1. Navigate to **Scenarios** page
2. Click **Create Custom Scenario**
3. Fill in the form:
   - **Basic Info**: Name, description, category, behavior style, intensity
   - **Targets**: Directories, file extensions, max files, rename extension
   - **Ransom Note**: Filename, content, drop locations
   - **Options**: Shadow copy deletion, persistence, exfiltration
   - **Tags**: MITRE techniques, training levels
4. Click **Create Scenario**

#### Via API

```bash
curl -X POST http://localhost:8000/api/scenarios \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Finance Locker Lab",
    "description": "Custom scenario for finance department training",
    "category": "crypto",
    "behavior_style": "LOUD_CRYPTO",
    "intensity_level": 3,
    "target_dirs": ["C:\\RansomLab", "C:\\TestData"],
    "file_extensions": [".docx", ".xlsx", ".pdf"],
    "max_files": 100,
    "rename_extension": ".locked",
    "ransom_note_filename": "READ_ME_NOW.txt",
    "ransom_note_content": "Your files have been encrypted... (SIMULATION)",
    "ransom_note_locations": ["target_root", "desktop"],
    "simulate_vssadmin": true,
    "simulate_persistence": true,
    "persistence_type": "registry_run_key",
    "simulate_exfiltration": false,
    "delay_seconds": 5,
    "tags": ["MITRE:T1486", "TRAINING:INTERMEDIATE"]
  }'
```

### Scenario Configuration Fields

| Field | Type | Description |
|-------|------|-------------|
| `target_dirs` | List[str] | Directories to target (system dirs blocked) |
| `file_extensions` | List[str] | File extensions to affect (e.g., `.docx`) |
| `max_files` | int | Maximum files to process (1-1000) |
| `rename_extension` | str | Extension added to "encrypted" files |
| `ransom_note` | object | Note filename, content, and locations |
| `simulate_vssadmin` | bool | Run vssadmin shadow copy deletion |
| `simulate_persistence` | bool | Create persistence mechanism |
| `persistence_type` | str | `registry_run_key` or `scheduled_task` |
| `simulate_exfiltration` | bool | Create local ZIP archive |
| `exfil_target_dir` | str | Directory for exfil staging |
| `intensity_level` | int | 1-5 scale (affects file count) |
| `delay_seconds` | int | Delay between steps (dwell time) |
| `behavior_style` | str | `LOUD_CRYPTO`, `STEALTHY`, or `LOCKER_LIKE` |
| `tags` | List[str] | MITRE techniques, training levels |

### Cloning Scenarios

Clone any scenario (built-in or custom) to create a new custom version:

1. Navigate to the scenario detail page
2. Click **Clone to Custom**
3. Enter a new name
4. Edit the cloned scenario as needed

### Export/Import Scenarios

#### Export

```bash
# Via API
curl http://localhost:8000/api/scenarios/1/export > scenario.json

# Via UI: Click "Export as JSON" on scenario detail page
```

#### Import

```bash
# Via API
curl -X POST http://localhost:8000/api/scenarios/import \
  -H "Content-Type: application/json" \
  -d @scenario.json

# Via UI: Click "Import Scenario" on scenarios list page
```

### Scenario API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/scenarios` | List all scenarios |
| GET | `/api/scenarios/{id}` | Get scenario details |
| POST | `/api/scenarios` | Create custom scenario |
| PUT | `/api/scenarios/{id}` | Update custom scenario |
| DELETE | `/api/scenarios/{id}` | Delete custom scenario |
| POST | `/api/scenarios/{id}/clone` | Clone scenario |
| GET | `/api/scenarios/{id}/export` | Export scenario JSON |
| POST | `/api/scenarios/import` | Import scenario JSON |
| GET | `/api/scenarios/by-key/{key}` | Get scenario by key (for agents) |

### How the Agent Uses Custom Scenarios

When a simulation is started:

1. The backend sends the `scenario_key` and `scenario_config` to the agent
2. The agent interprets the config fields:
   - Iterates `target_dirs` and collects matching files by extension
   - Limits files based on `max_files` and `intensity_level`
   - Renames files with `rename_extension`
   - Creates ransom notes in specified locations
   - Optionally runs vssadmin, creates persistence, prepares exfil ZIP
3. Agent reports detailed results including affected files, IOCs, and metrics

### Validation Rules

The backend enforces these safety rules:

- **Forbidden directories**: C:\Windows, C:\Program Files, C:\Program Files (x86), etc.
- **Max files limit**: Cannot exceed 1000
- **Intensity range**: Must be 1-5
- **Extension format**: Must start with a dot (e.g., `.docx`)
- **Exfil method**: Only `zip_only` (local) allowed
- **Delay limit**: Cannot exceed 300 seconds

---

## Response Playbooks

Playbooks automatically trigger response actions when alerts are received.

### Default Playbooks

| Rule ID | Trigger | Actions |
|---------|---------|---------|
| 100101 | Shadow copy deletion | Kill vssadmin, Kill PowerShell, Isolate host |
| 100102 | Mass file rename | Isolate host |
| 100103 | Ransom note creation | Kill notepad, Disable user |

### Response Action Types

- `response_kill_process` - Terminates a process via `taskkill`
- `response_disable_user` - Disables Windows user via `net user`
- `response_isolate_host` - Isolates host based on policy (firewall, NIC, or hybrid)
- `response_reisolate_host` - Re-applies isolation after cleanup
- `response_deisolate_host` - Removes isolation, restores connectivity

### Recovery Action Types

- `recovery_enable_user` - Re-enables a disabled Windows user
- `recovery_restore_files_from_quarantine` - Restores files from quarantine directory

---

## Containment & Recovery Workflow

RansomRun v3.1 introduces a comprehensive containment and recovery system.

### Host Isolation

Hosts can be isolated using three policies:

| Policy | Description |
|--------|-------------|
| `FIREWALL_BLOCK` | Blocks all inbound/outbound traffic via Windows Firewall rules |
| `DISABLE_NIC` | Disables network adapter(s) using PowerShell |
| `HYBRID` | Combines firewall blocking with NIC disable |

#### Automatic Isolation (via Wazuh Playbooks)

When Wazuh alerts are received for high-severity ransomware indicators, playbooks can automatically trigger isolation:

```json
{
  "name": "Auto-Isolate on Shadow Copy Deletion",
  "rule_id": "100101",
  "actions": [
    {"type": "response_isolate_host", "parameters": {"policy": "FIREWALL_BLOCK"}},
    {"type": "response_kill_process", "parameters": {"process_name": "powershell.exe"}}
  ]
}
```

#### Manual Isolation (via UI)

1. Navigate to **Hosts → [Host Name]**
2. In the **Isolation & Containment** section:
   - Select an isolation policy
   - Click **Isolate Host**
3. The agent will apply the isolation and report back

#### Re-Isolation

If isolation is suspected to have failed or been partially restored:
1. Click **Re-Isolate Host**
2. This cleans up old rules and re-applies fresh isolation

#### De-Isolation

To restore normal connectivity:
1. Click **De-Isolate Host**
2. Firewall rules are removed and/or NICs are re-enabled

### Recovery Phase

After containment, start a structured recovery:

1. Navigate to **Runs → [Run ID]**
2. In the **Recovery Phase** panel, click **Start Recovery Phase**
3. The system creates a `RecoveryPlan` and generates tasks:
   - `response_deisolate_host` - If host is isolated
   - `recovery_enable_user` - For each user disabled during containment
   - `recovery_restore_files_from_quarantine` - If quarantine mode was used

#### Recovery Events

The recovery timeline tracks:
- `RECOVERY_STARTED` - Plan initiated
- `RECOVERY_TASK_CREATED` - Each task created
- `HOST_DEISOLATED` - Host connectivity restored
- `USER_REENABLED` - User account re-enabled
- `FILES_RESTORED_FROM_QUARANTINE` - Files restored

#### Business Impact Integration

When recovery completes:
- **Actual recovery hours** are calculated
- **Actual total cost** is computed based on cost-per-hour
- Compare estimated vs actual in the Business Impact panel

#### Compliance Report Integration

Recovery information is added to compliance reports:
- Time of de-isolation
- Time of recovery completion
- Summary of containment actions
- Summary of recovery actions

### API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/hosts/{id}/isolate` | Isolate a host |
| POST | `/api/hosts/{id}/reisolate` | Re-isolate a host |
| POST | `/api/hosts/{id}/deisolate` | De-isolate a host |
| POST | `/api/hosts/{id}/isolation-policy` | Set isolation policy |
| GET | `/api/hosts/{id}/isolation-status` | Get isolation status |
| POST | `/api/runs/{id}/recovery/start` | Start recovery phase |
| GET | `/api/runs/{id}/recovery` | Get recovery plan |
| GET | `/api/runs/{id}/containment` | Get containment status |
| POST | `/api/runs/{id}/recovery/check-completion` | Check/update recovery completion |

---

## API Reference

### Agent Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/agent/register` | Register/update agent |
| GET | `/api/agent/tasks?agent_id=...` | Poll for pending tasks |
| POST | `/api/agent/task-result` | Report task completion |

### Alert Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/alerts/wazuh` | Receive Wazuh alert |
| GET | `/api/alerts/` | List all alerts |

### Simulation Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/run-simulation` | Start new simulation |
| GET | `/api/runs` | List all runs |
| GET | `/api/runs/{id}` | Get run details |

### Data Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/hosts` | List all hosts |
| GET | `/api/hosts/{id}` | Get host details |
| GET | `/api/scenarios` | List scenarios |
| GET | `/api/playbooks` | List playbooks |

### SIEM Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/siem/stats` | Get alert statistics |
| GET | `/api/siem/alerts` | Filtered alert query |
| GET | `/api/siem/alerts/{id}` | Get alert detail |
| GET | `/api/siem/top-rules` | Top triggered rules |
| GET | `/api/siem/wazuh/status` | Wazuh connection status |
| GET | `/api/siem/wazuh/agents` | List Wazuh agents |
| POST | `/api/siem/wazuh/sync-alerts/{agent}` | Sync alerts from Wazuh |
| POST | `/api/siem/wazuh/config` | Configure Wazuh API |

---

## SIEM Integration

### Wazuh API Configuration

RansomRun can connect directly to the Wazuh REST API for deeper integration.

1. Navigate to **SIEM → Overview** in the web UI
2. Or use the API:

```bash
curl -X POST http://localhost:8000/api/siem/wazuh/config \
  -H "Content-Type: application/json" \
  -d '{
    "api_url": "https://wazuh-manager:55000",
    "username": "wazuh-wui",
    "password": "your-password",
    "enabled": true
  }'
```

### SIEM Dashboard Features

- **Overview**: Alert statistics, top rules, severity breakdown
- **Explorer**: Filter and search alerts by host, rule, time, severity
- **Alert Detail**: Raw JSON, MITRE mapping, linked simulation

### Forensic Data Collection

The agent now collects and reports:
- **Affected Files**: Original path, new path, action type
- **IOCs**: File paths, command lines, registry keys, network indicators
- **Metrics**: Files touched, execution time, expected alerts
- **Timeline Events**: Detailed event log for incident reconstruction

---

## MITRE ATT&CK Mapping

| Rule ID | Technique | Name |
|---------|-----------|------|
| 100101 | T1490 | Inhibit System Recovery |
| 100102 | T1486 | Data Encrypted for Impact |
| 100103 | T1491 | Defacement |
| 100104 | T1489 | Service Stop |
| 100105 | T1562 | Impair Defenses |
| 100106 | T1059 | Command and Scripting Interpreter |
| 100107 | T1047 | Windows Management Instrumentation |
| 100108 | T1112 | Modify Registry |

---

## Project Structure

```
RansomRun/
├── app/
│   ├── __init__.py
│   ├── main.py              # FastAPI application (v3.0)
│   ├── models.py            # SQLAlchemy models (extended)
│   ├── database.py          # Database configuration
│   ├── schemas.py           # Pydantic schemas (extended)
│   ├── crud.py              # Database operations (extended)
│   ├── seed.py              # Advanced scenario seeding
│   ├── wazuh_client.py      # Wazuh REST API client
│   ├── routers/
│   │   ├── agents.py        # Agent API endpoints
│   │   ├── alerts.py        # Wazuh webhook endpoint
│   │   ├── runs.py          # Simulation runs API
│   │   ├── siem.py          # SIEM API endpoints
│   │   ├── advanced.py      # Advanced features API
│   │   ├── recovery.py      # Recovery & containment API
│   │   ├── scenarios.py     # Custom scenarios CRUD API
│   │   └── ui.py            # Web UI routes (extended)
│   ├── services/            # Business logic modules
│   │   ├── behavior.py      # Behavior DNA generation
│   │   ├── whatif.py        # What-If analysis
│   │   ├── coach.py         # Coach feedback generation
│   │   ├── business_impact.py # Business impact calculation
│   │   └── compliance.py    # Compliance report generation
│   └── templates/
│       ├── base.html        # Base template with nav
│       ├── dashboard.html   # Dashboard page
│       ├── hosts.html       # Hosts list
│       ├── host_detail.html # Host details
│       ├── scenarios.html   # Scenarios list (with custom support)
│       ├── scenario_form.html    # Create/edit scenario form
│       ├── scenario_detail.html  # Scenario detail view
│       ├── runs.html        # Runs list
│       ├── run_detail.html  # Incident report with advanced features
│       ├── simulate.html    # Start simulation form
│       ├── playbooks.html   # Playbooks list
│       ├── alerts.html      # Alerts list
│       ├── siem_overview.html    # SIEM dashboard
│       ├── siem_explorer.html    # Alert explorer
│       ├── siem_alert_detail.html # Alert detail
│       ├── dna_lab.html     # Behavior DNA Lab
│       ├── users.html       # Analysts list
│       ├── user_detail.html # Analyst profile / SOC CV
│       ├── compliance_report.html # Compliance report view
│       └── error.html       # Error page
├── agent/
│   └── agent.py             # Windows agent with scenario engine
├── requirements.txt
└── README.md
```

---

## Advanced Features API

### Behavior DNA

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/advanced/behavior/profiles` | GET | List all behavior profiles |
| `/api/advanced/behavior/run/{run_id}` | GET | Get behavior profile for a run |
| `/api/advanced/behavior/generate/{run_id}` | POST | Generate behavior profile |

### What-If Analysis

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/advanced/whatif/templates` | GET | Get available What-If templates |
| `/api/advanced/whatif/run/{run_id}` | GET | Get What-If scenarios for a run |
| `/api/advanced/whatif/run/{run_id}` | POST | Create What-If scenario from template |

### Coach Feedback

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/advanced/coach/run/{run_id}` | GET | Get coach feedback for a run |
| `/api/advanced/coach/generate/{run_id}` | POST | Generate coach feedback |

### Business Impact

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/advanced/impact/run/{run_id}` | GET | Get business impact for a run |
| `/api/advanced/impact/calculate/{run_id}` | POST | Calculate business impact |
| `/api/advanced/impact/run/{run_id}/comparison` | GET | Compare impact to other runs |

### Compliance Reports

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/advanced/compliance/run/{run_id}` | GET | Get compliance report |
| `/api/advanced/compliance/generate/{run_id}` | POST | Generate compliance report |
| `/api/advanced/compliance/run/{run_id}/export` | GET | Export report as text |

### Users/Analysts

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/advanced/users` | GET | List all users |
| `/api/advanced/users` | POST | Create new user |
| `/api/advanced/users/{user_id}` | GET | Get user details with skill profile |
| `/api/advanced/users/{user_id}/start-session/{run_id}` | POST | Start IR session |

---

## Troubleshooting

### Agent can't connect to server
- Check firewall rules on both machines
- Verify the `BACKEND_URL` is correct
- Ensure the server is running and accessible

### Tasks not being picked up
- Verify the agent is registered (check Hosts page)
- Check agent logs at `C:\RansomTest\agent.log`
- Ensure polling is working (agent should log each poll)

### Shadow copy deletion fails
- Requires Administrator privileges
- Run agent as Administrator

### Network isolation blocks agent
- Use `python agent.py --unisolate` to remove the firewall rule
- Or manually delete the rule: `netsh advfirewall firewall delete rule name=RANSOMRUN_ISOLATION`

---

## Development

### Running in Development Mode

```bash
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

### Database Reset

Delete `ransomrun.db` and restart the server to reset all data.

### Adding New Scenarios

Edit `app/seed.py` and add to the `scenarios` list.

### Adding New Playbooks

Edit `app/seed.py` and add to the `playbooks` list.

---

## License

This project is for educational purposes only. Use responsibly in isolated lab environments.

---

## Credits

Built for University Capstone Project - Security Operations & Incident Response Training

**Tech Stack:**
- FastAPI (Python web framework)
- SQLAlchemy (ORM)
- SQLite (Database)
- Jinja2 (Templating)
- Bootstrap 5 (UI)
