# 🛡️ Industrial Control Systems (ICS) AASG Threat Modeler
## Architecture Diagram Analyzer & Attack Surface Graph Generator (v2.1)

An AI-assisted security-analysis platform for **Industrial Control System (ICS) / Operational Technology (OT)** networks. It ingests three independent sources — an **architecture diagram** (image or text), an **RBAC policy**, and a **firewall rule set** — merges them into one canonical model, compiles that into a formal **Authorization Attack Surface Graph (AASG)**, and then runs a full battery of security analytics: attack-path discovery, quantitative risk scoring, MITRE ATT&CK for ICS mapping, blast-radius, threat-propagation, and lateral-movement detection. Results are rendered as an interactive React Flow graph in a premium dark-mode interface.

This document describes the whole system, the modular directory structure, and instructions for setup and running in a single command.

---

## 🎯 What is this Project?
Securing Industrial Control Systems (ICS/OT) requires keeping secure network boundaries (conduits) between different equipment zones (e.g., separating business workstations from physical PLCs and sensors, as defined by the **ISA/IEC 62443** standard). 

This project is a **visual threat modeling tool** that takes your network diagrams, firewall configs, and access rules, analyzes them, and automatically shows you:
1. An **interactive network map** organized by Purdue level.
2. **Security violations** (e.g., insecure connections bypassing firewalls).
3. **Attack vectors** (how an attacker could hop from the internet to control physical hardware).
4. **Compromise blast radius** (what else gets infected if a specific machine is compromised).

---

## 1. The Formal Model: `A = {Z, E, S, O, R}` → `G = (V, E, Z)`

Everything downstream operates on one canonical model built by merging the three inputs:

| Symbol | Meaning | Source of truth |
| --- | --- | --- |
| `Z` | ISA/IEC 62443 security **zones** / trust boundaries | Architecture |
| `S` | **Subjects** — operators, roles, software agents | **RBAC only** (never invented by the LLM) |
| `O` | **Objects** — assets: PLCs, HMIs, SCADA, sensors, actuators | Architecture |
| `R` | **Actions** — read, write, program, admin, … | **RBAC only** |
| `Ea` | **Authorization edges** `S × O`, labeled with an action `r ∈ R` | RBAC permissions |
| `Ec` | **Communication edges** `O × O`, labeled with a protocol `p` | Architecture **∩** firewall-allowed |

A communication edge exists **iff** the diagram shows the link *and* the firewall permits it: `Ec = architecture_candidates ∩ firewall_rules`. Subjects and objects live in **separate ID namespaces** so an asset name can never collapse into a role name (or vice-versa).

The merged model is compiled into a formal graph `G = (V, E, Z)` where `V = S ∪ O` and `E = Ea ∪ Ec`.

---

## 2. Repository Layout

```
ICS_Architecture/
├── docs/                            ★ In-depth documentation folder
│   └── FLOW_AND_ARCHITECTURE.md     Full data-flow & mathematical calculation details
├── backend/                         FastAPI service (Python)
│   ├── main.py                      API Server entry point
│   ├── start.ps1 / start.bat        Dev server running scripts
│   ├── app/                         FastAPI Application Source
│   │   ├── api/                     API route handlers
│   │   │   ├── routes.py            Aggregated route setup
│   │   │   ├── upload.py            File uploading endpoint
│   │   │   └── analysis.py          Analysis endpoints (risk, MITRE, reachability)
│   │   ├── core/                    Core system configuration
│   │   │   ├── config.py            FastAPI settings
│   │   │   ├── constants.py         Static tactic & protocol lookup structures
│   │   │   ├── logger.py            Centralized logger
│   │   │   ├── exceptions.py        Application exception classes
│   │   │   └── utils.py             Formatting utilities
│   │   ├── schemas/                 Pydantic validation schemas
│   │   ├── parsers/                 Phase 1 parsing modules
│   │   │   ├── text/                Natural language parser
│   │   │   ├── image/               OpenCV + LLM Vision parser
│   │   │   ├── firewall/            Cisco ASA/ACL firewall rules parser
│   │   │   ├── rbac/                Casbin, JSON, and CSV RBAC parser
│   │   │   ├── ontology.py          Normalization and protocol inference engine
│   │   │   └── unified_model.py     Merger of inputs into canonical A={Z,E,S,O,R}
│   │   ├── graph/                   Phase 2 Graph & Layout modules
│   │   │   ├── builder.py           NetworkX ICSSecurityGraph construction
│   │   │   ├── validator.py         Security policy & structural DAG validator
│   │   │   ├── layer_assignment.py  Purdue level tier mapping
│   │   │   └── dag_generator.py     Cycle resolver & React Flow payload generator
│   │   ├── analysis/                Phase 3 Analysis modules
│   │   │   ├── reachability.py      Cyber-physical path & ISA-62443 matrix
│   │   │   ├── path_analysis.py     Attack-path finder & Blast Radius analyzer
│   │   │   ├── risk_engine.py       Quantitative Risk Scoring engine
│   │   │   ├── threat_propagation.py BFS threat infection spread simulation
│   │   │   ├── lateral_movement.py  Privilege escalation & cross-zone lateral hop auditor
│   │   │   ├── empirical_metrics.py AAF and TEL metrics calculations
│   │   │   └── aasg.py              Formal mathematical AASG model definitions
│   │   └── intelligence/            Phase 4 Threat Intelligence modules
│   │       ├── mitre_mapper.py      MITRE ATT&CK for ICS mapping coordinator
│   │       └── llm_mapper.py        Multi-agent LLM reasoning mapping coordinator
│   └── tests/                       Unit and Integration verification tests
│       ├── test_imports.py          Import verification
│       └── test_api.py              FastAPI endpoints test
├── frontend/                        React + Vite + React Flow UI
│   └── src/
│       ├── main.jsx                 Single-file app: graph, panels, tabs
│       └── style.css                Styles + animations
├── setup.ps1                        ★ Automated setup script
└── start.ps1                        ★ Automated run script
```

---

## 3. Simplified Setup & Running

You can set up and run the **Backend** and **Frontend** separately or concurrently using simple commands.

### 3.1 Prerequisite
Create a `.env` file in the `backend/` directory with your API configuration:
```env
BACKEND_HOST=127.0.0.1
BACKEND_PORT=7429
MITRE_MAPPER_MODE=llm
OPENAI_API_KEY=your_openai_key_here
```

### 3.2 Backend Subsystem
Open a terminal in the `backend/` directory:
- **Setup**:
  ```bash
  npm install
  ```
  *(This automatically creates the Python virtual environment and installs the backend packages).*
- **Run**:
  ```bash
  npm start
  ```

### 3.3 Frontend Subsystem
Open a terminal in the `frontend/` directory:
- **Setup**:
  ```bash
  npm install
  ```
- **Run**:
  ```bash
  npm run dev
  ```

---

### Alternative: Unified Root Commands
If you want to set up and run both subsystems concurrently from the **root project directory**:
- **Setup**: `npm install` (installs both backend & frontend packages).
- **Run**: `npm start` (starts both backend & frontend dev servers concurrently).

If using PowerShell, you can also use:
- **Setup**: `./setup.ps1`
- **Run**: `./start.ps1` (runs backend in a new window and frontend in the current window).

---

## 4. API Endpoints (FastAPI)

| Method | Path | Purpose |
| --- | --- | --- |
| `GET`  | `/health` | Liveness check |
| `POST` | `/upload` | Upload architecture + RBAC + firewall files → full analysis |
| `POST` | `/generate-from-text` | Same pipeline from pasted text instead of files |
| `POST` | `/blast-radius` | Downstream exposure of a compromised node |
| `POST` | `/threat-propagation` | BFS infection simulation from an origin |
| `POST` | `/lateral-movement` | Cross-zone / privilege / protocol pivots |
| `POST` | `/mitre-mapping` | MITRE ATT&CK technique/tactic mapping |
| `POST` | `/risk-scoring` | Quantitative path risk scoring |

---

## 5. Architectural Features

### 5.1 Centralized Ontology & Normalization
Identifiers from separate inputs (e.g. `SCADA_Server` in firewall, `scada-srv` in RBAC, `scada` in diagram) are normalized to a delimiter-insensitive form and matched using fuzzy similarity thresholding ($\ge 82\%$). Synonyms can be updated centrally in `backend/app/parsers/ontology.py`.

### 5.2 Device-Pair Protocol Inference
If communication links lack a protocol label, default protocols are inferred from target asset categories (e.g. HMI-PLC $\to$ Modbus, SCADA-PLC $\to$ OPC-UA), enhancing down-stream MITRE ATT&CK mapping accuracy.

### 5.3 Richer Visual Layouts
- Edges are color-coded: authorization links are purple and dashed, communication links are blue, and cyber-physical target links are violet.
- Hovering over a node displays its criticality, zone, Purdue level, type, risk score, and all protocols traversing it.
- Marching-dash path animations visually show active threat pathways.

### 5.4 Weighted Attack-Path Model
Attack-path cost calculations dynamically penalize crossing network zones, descending Purdue levels, traversing firewall boundaries, and using highly sensitive admin permissions.

### 5.5 LLM-Assisted MITRE ATT&CK Mapping
Features a self-correcting multi-agent reasoning chain (comprising Context Builder, Candidate Selection, Attack Chain Reasoning, MITRE Reasoning, Semantic Validation, KB Verification, Confidence Calibration, and Graph Consistency agents) with a validation feedback loop to ensure ATT&CK technique mapping accuracy.
