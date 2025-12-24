# Project Roadmap

## Goal

Design and implement a lightweight smart-home network threat monitoring system that:
- generates high-signal, low-noise network security events,
- automates triage and response using n8n,
- optionally leverages an LLM for analyst-style categorization and summarization,
- is testable using manually generated traffic.

The project prioritizes signal quality, explainability, and modularity over raw packet-level alerting.

---

## High-Level Architecture

```less
[ Smart Home Devices ]
        |
        v
[ Raspberry Pi Gateway ]
  - Packet capture
  - Metadata extraction
  - Rule-based detection
  - Aggregation & deduplication
        |
        v
[ Signal Gateway ]
  - Structured JSON events
        |
        v
[ n8n ]
  - Workflow automation
  - LLM-assisted triage
  - Routing & notifications
        |
        v
[ User / Logs / Alerts ]
```

---

## Phase 1 — NIDS & Signal Quality

### 1.1 Sensor Placement

- Raspberry Pi acts as gateway for IoT subnet
- At minimum, the camera traffic must traverse the Pi

### 1.2 Traffic Collection

- Capture traffic using **tcpdump** or **tshark**
- Focus on metadata only, not payloads:
    - DNS queries/responses
    - New connections (src/dst/proto/port)
    - Traffic volume over time windows

### 1.3 Detection Logic (Rule Set)

1. IoT device outbound internet access
    - Camera sends traffic to public IPs

2. Suspicious DNS behavior
    - First-seen domains
    - High-frequency or random-looking queries

3. Scanning-like behavior
    - One host contacts many destinations or ports

4. Unexpected protocol usage
    - Camera using UDP or uncommon ports

### 1.4 Noise Control

- Aggregation: summarize over time windows
- Deduplication: suppress repeated identical signals
- Thresholds: emit only if meaningful
- Whitelisting: known-good destinations/services

### 1.5 Signal Contract

Define a **stable JSON event schema** that all downstream systems consume.

**Example fields:**
- timestamp
- device identity
- signal type
- severity
- confidence
- human-readable summary
- structured evidence

**Exit Criteria:**
- NIDS produces **few, meaningful** JSON events
- No raw packet floods
- Signals are understandable without PCAPs

---

## Phase 2 - n8n & LLM-Assisted Triage

### 2.1 n8n Setup

- Run n8n on PC or server in same LAN
- Expose webhook endpoint for NIDS events

### 2.2 Input Handling

- Validate incoming event schema
- Reject malformed or duplicate events

### 2.3 LLM Integration

- Send structured event + system prompt to LLM
- Check the n8n activity before integrating LLM API-keys ([Free models](https://github.com/cheahjs/free-llm-api-resources))
- LLM outputs strict JSON, not free text

- Categorize event:
    - policy_violation
    - privacy_risk
    - benign
    - suspicious
    - unknown
- Assign severity & confidence
- Provide short analyst-style explanation
- Suggest recommended action (non-binding)

**Important Design Rule:**
- LLM may **suggest**
- Rules decide **actions**

### 2.4 n8n Decision Logic

- Branch workflows based on:
    - severity
    - category
    - confidence
- Actions may include:
    - log event
    - notify user
    - escalate for review

**Exit criteria:**
- End-to-end flow: NIDS → n8n → LLM → decision
- No manual intervention required for normal operation

---

## Phase 3 — Testing & Validation

### 3.1 Manual Traffic Generation

Create traffic intentionally to trigger detections:
- DNS queries (dig, random subdomains)
- Port scanning (nmap)
- UDP bursts (hping3)
- HTTP/HTTPS (curl)
- PCAP replay (tcpreplay)

### 3.2 Validation Goals

- Expected signals are generated
- Unexpected noise is suppressed
- LLM categorization is reasonable and consistent
- n8n routing behaves as designed

### 3.3 Documentation

- Document each test:
    - traffic generated
    - expected signal
    - actual outcome

- Add a “Lessons Learned” section

**Exit Criteria**

- System behaves predictably under test traffic
- False positives are minimal and explained