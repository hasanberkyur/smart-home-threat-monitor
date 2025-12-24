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

### 1.3 Detection Logic (Incident-Class Rule Set)

The NIDS generates **exactly one primary signal per incident**, chosen deterministically using a fixed precedence order.
Lower-level detections contribute **features** (context), not additional signals.

**Signal Precedence (highest → lowest)**

```nginx
POLICY_VIOLATION
RECON_ACTIVITY
SUSPICIOUS_DESTINATION
ANOMALOUS_BEHAVIOR
```

**Signal Types**

1. **POLICY_VIOLATION**
   Triggered when a device violates an explicitly defined network policy.

   * IoT device attempts outbound communication to public (non-RFC1918) IPs
   * IoT device uses forbidden protocols or ports (e.g., SMB, SSH)
   * Any traffic that crosses a hard isolation boundary

   *Rationale:* Policy violations are binary and actionable, and therefore take highest priority.

2. **RECON_ACTIVITY**
   Triggered when a host exhibits network reconnaissance behavior.

   * One host contacts many destinations in a short time window
   * One host probes many ports on one or more targets
   * ARP or discovery storms exceeding thresholds

   *Rationale:* Reconnaissance has a distinct traffic shape (breadth) and indicates potential lateral movement or scanning.

3. **SUSPICIOUS_DESTINATION**
   Triggered when a device connects to destinations that are novel or potentially risky.

   * First-seen public IPs, domains, or ASNs
   * Destinations outside historical or expected patterns
   * Optional reputation or tracker list hits

   *Rationale:* This signal focuses on *where* traffic goes, independent of whether it is explicitly allowed.

4. **ANOMALOUS_BEHAVIOR**
   Triggered when traffic significantly deviates from established baselines but does not meet higher-priority criteria.

   * Sudden traffic volume spikes
   * Unusual protocol or port usage that is not forbidden
   * Persistent timing or rate anomalies

   *Rationale:* Acts as a controlled catch-all for meaningful deviations that warrant triage without indicating a clear violation.

**Features (Context Only)**

Lower-level observations such as unusual ports, high rates, or first-seen domains are recorded as **features** and attached to the primary signal.
Features **do not** influence routing or signal selection directly.

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

### 2.2 Input Handling (n8n as Event Gateway)
n8n acts as the event gateway between the NIDS and all downstream actions.

**Responsibilities**
- Validate incoming JSON against the signal schema
- Normalize fields
- Apply deduplication / rate limiting
- Enrich events with routing metadata

**Exit Criteria**
- Malformed inputs are rejected early
- Duplicate/noisy repeats are suppressed before any branching or LLM calls

### 2.3 LLM Integration

- Incoming events are first routed by **signal type** in n8n
- Send structured event to LLM
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