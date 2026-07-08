# Industrial Control Systems (ICS) AASG Threat Modeler
## System Presentation & Flow Guide (Version 2.1)

Welcome to the comprehensive technical documentation for the **ICS AASG Threat Modeler**. This document provides an exhaustive, in-depth architectural guide, mapping out the entire system flow from raw inputs to finalized analysis reports. 

---

## Table of Contents
1. [System Overview & Purpose](#1-system-overview--purpose)
2. [End-to-End Core Data Flow](#2-end-to-end-core-data-flow)
3. [Input and Output Specifications](#3-input-and-output-specifications)
4. [Module-by-Module Technical Breakdown](#4-module-by-module-technical-breakdown)
    - [4.1 Parser Subsystem (Phase 1)](#41-parser-subsystem-phase-1)
    - [4.2 Graph and Layout Subsystem](#42-graph-and-layout-subsystem)
    - [4.3 Advanced Security Analysis Subsystem](#43-advanced-security-analysis-subsystem)
    - [4.4 Threat Intelligence Subsystem](#44-threat-intelligence-subsystem)
5. [Mathematical Formulations and Calculations](#5-mathematical-formulations-and-calculations)
    - [5.1 Attack Path Cost Model](#51-attack-path-cost-model)
    - [5.2 Risk Scoring Engine](#52-risk-scoring-engine)
    - [5.3 Threat Propagation BFS Simulation](#53-threat-propagation-bfs-simulation)
    - [5.4 Empirical Evaluation Metrics](#54-empirical-evaluation-metrics)
6. [Operational Manual and Local Setup](#6-operational-manual-and-local-setup)

---

## 1. System Overview & Purpose
Securing Industrial Control Systems (ICS) and Operational Technology (OT) networks requires rigorous structural boundaries. The industry-standard **ISA/IEC 62443** specifies that networks must be segmented into distinct logical zones, and any traffic traversing zone boundaries must pass through dedicated, policy-enforcing conduits (firewalls or gateways). Furthermore, access permissions must adhere to Role-Based Access Control (RBAC) to limit operations at different levels of the **Purdue Model** (Purdue Levels 0–5).

The **ICS AASG Threat Modeler** is a visual threat-modeling platform that ingests network architecture diagrams (as images/PDFs or text), firewall rule sets, and RBAC policies. It merges these inputs into a canonical model, builds a formal **Authorization Attack Surface Graph (AASG)**, and runs downstream algorithms (attack-path calculations, risk scoring, threat propagation, blast radius, lateral movement, and LLM-assisted MITRE ATT&CK for ICS mapping) to generate an interactive GUI showing security posture.

---

## 2. End-to-End Core Data Flow

The following diagram illustrates how data propagates from the initial raw inputs through the parsers, the graph merger, the analysis engines, and finally compiles into the visual payload.

```
[Architecture Diagram] ──► [Image Parser] ──┐
                                            │
[Architecture Text]   ──► [Text Parser]   ──┼─► [Ontology Engine] ──► [Unified Merger] ──► [AASG Graph] ──► [NetworkX Graph]
                                            │          ▲
[RBAC Policy]         ──► [RBAC Parser]   ──┤          │
                                            ├──────────┘
[Firewall Rules]      ──► [Firewall Parser]─┘
                                                        │
         ┌──────────────────────────────────────────────┴──────────────────────────────────────────────┐
         ▼                                              ▼                                              ▼
[Attack Path Analyzer]                      [Threat Propagation Sim]                        [MITRE ATT&CK Mapper]
         │                                              │                                              │
         ▼                                              ▼                                              ▼
[Risk Scoring Engine]                       [Lateral Movement Detector]                     [Empirical Evaluation]
         │                                              │                                              │
         └──────────────────────────────────────────────┬──────────────────────────────────────────────┘
                                                        │
                                                        ▼
                                            [DAG Layout Generator]
                                                        │
                                                        ▼
                                            [React Flow JSON Payload]
                                                        │
                                                        ▼
                                            [Interactive Frontend GUI]
```

---

## 3. Input and Output Specifications

### 3.1 Raw Inputs
1. **Architecture Input**:
   - **Image/PDF**: An engineering network diagram outlining zones (e.g., Enterprise Zone, Control Zone), assets (e.g., PLCs, HMIs, SCADA), and network links.
   - **Text**: Natural language description specifying zones, their assets, their Purdue levels, and the network communication connections.
2. **RBAC Policy**: A text or JSON representation listing subjects, actions (roles), and their permitted target assets (e.g., `Engineer` can `write` to `PLC_1`).
3. **Firewall Rules**: Network ACLs detailing source zone/IP, destination zone/IP, allowed protocol, and port.

### 3.2 System Outputs
The backend outputs a single JSON response containing:
- **`react_flow_asset_view`**: A detailed React Flow JSON layout where nodes represent physical assets and subjects, and edges represent either network links or RBAC permissions.
- **`react_flow_macro_zone_view`**: A high-level, zone-to-zone React Flow layout depicting ISA-62443 conduits.
- **`attack_paths`**: Ranked vulnerability pathways from cyber entry points (e.g., VPNs, Enterprise Workstations) to physical processes (e.g., PLCs, Safety Controllers).
- **`risk_analysis`**: Risk scores per path and critical node rankings.
- **`mitre_mapping`**: Context-aware mapping detailing the specific technique, tactic, and confidence score for every path transition.
- **`blast_radius`**: Calculated downstream operational exposure for each critical asset.
- **`threat_propagation`**: Infection probabilities across the network starting from designated entry points.
- **`lateral_movement`**: Audit details on cross-zone pivots, protocol hops, and privilege escalations.
- **`reachability_data`**: A ISA-62443 zone communication reachability matrix.
- **`empirical_evaluation`**: Quantitative security metrics (AAF and TEL).

---

## 4. Module-by-Module Technical Breakdown

### 4.1 Parser Subsystem (Phase 1)

#### 4.1.1 RBAC Parser (`app/parsers/rbac/parser.py`)
- **Inputs**: A text block containing Role-Based Access Control policy definitions.
- **Methodology**: 
  - Parses comma-separated and natural language lines like `role, subject, target, action`.
  - Normalizes whitespace and text case.
  - Extracts subject groups $S$, action categories $R$, and builds authorization rules representing permitted mappings.
- **Outputs**: Dictionary with lists of subjects `S`, actions `R`, and direct permission links `permissions` containing source subject, target asset, and action label.

#### 4.1.2 Firewall Parser (`app/parsers/firewall/parser.py`)
- **Inputs**: A text block containing Cisco ASA-style ACLs or JSON rules.
- **Methodology**:
  - Employs regex patterns to detect typical firewall command parameters: `access-list <id> permit <proto> host <src> host <dst> eq <port>` or standard JSON fields.
  - Resolves source-destination host pairs and matches them to network ports.
- **Outputs**: A `FirewallParser` class containing a list of `rules` and a parsed list of `allowed_pairs` (dictionaries with `src`, `dst`, `port`, `proto`, and `action` keys).

#### 4.1.3 Image Parser (`app/parsers/image/parser.py`)
- **Inputs**: Absolute path to an uploaded image file (PNG, JPG, etc.) or a single-page PDF.
- **Methodology**:
  - If a PDF is provided, PyMuPDF (`fitz`) renders the first page to a high-resolution JPEG (`dpi=150`).
  - Utilizes the OpenAI Vision model (`gpt-4-vision-preview` or configured version) with a strict system prompt. The prompt directs the LLM to identify all network zones, assets (extracting their names, types, and Purdue levels), and directional connections.
  - Uses the JSON-extraction regex helpers (`_extract_json`) to convert raw text output into structured JSON.
- **Outputs**: Dictionary representing raw diagram structures:
  ```json
  {
    "zones": [{"id": "zone_1", "name": "Control Zone", "purdue_level": "2"}],
    "assets": [{"id": "plc_1", "type": "plc", "zone": "zone_1"}],
    "communications": [{"src": "hmi_1", "dst": "plc_1", "protocol": "modbus"}]
  }
  ```

#### 4.1.4 Text Parser (`app/parsers/text/parser.py`)
- **Inputs**: Natural language descriptions of the network layout.
- **Methodology**:
  - Sends the text to the OpenAI LLM, which parses and structures the text into standard zones, assets, and connections.
- **Outputs**: Same JSON schema as the Image Parser.

#### 4.1.5 Ontology and Normalization Engine (`app/parsers/ontology.py`)
- **Inputs**: Un-normalized identifier strings from different files (e.g. `SCADA_Server` in firewall, `scada-srv` in RBAC, `scada` in diagram).
- **Methodology**:
  - **Normalization**: Translates names into a delimiter-insensitive form (lowercase, removing hyphens, underscores, spaces) to resolve naming inconsistencies.
  - **Fuzzy Resolution**: Tries exact matching, delimiter-insensitive matching, suffix-stem matching, token-set matching, and Levenshtein distance fallback (similarity threshold $\ge 80\%$) using custom algorithms to match raw strings to known canonical asset IDs.
  - **Protocol Inference**: Evaluates communication pairs without specified protocols. Maps target asset types to logical default ports and protocols:
    - `HMI ↔ PLC` defaults to `modbus`
    - `SCADA ↔ PLC` defaults to `opc_ua`
    - `Firewall ↔ VPN` defaults to `ipsec`
    - `SCADA ↔ RTU` defaults to `dnp3`
    - `PLC ↔ Sensor` defaults to `hart`
- **Outputs**: Resolved canonical identifiers, normalized node types, and inferred network protocols.

#### 4.1.6 Unified Model Merger (`app/parsers/unified_model.py`)
- **Inputs**: Extracted raw data from RBAC, firewall, and architecture parsers.
- **Methodology**:
  - **Merger Engine**: Builds the canonical five-tuple model $A = \{Z, E, S, O, R\}$.
  - Registers zones $Z$ and objects $O$ from the architecture.
  - Registers subjects $S$ and actions $R$ exclusively from the RBAC source.
  - Normalizes all references using the Ontology Engine, ensuring subjects and objects live in separate ID namespaces to prevent collisions.
  - Filters candidate communication links using the firewall rules: `Ec = architecture_candidates ∩ firewall_allowed`. Unallowed communication links are filtered out and logged as `firewall_blocked`.
- **Outputs**: Dictionary representing the unified system model $A$.

---

### 4.2 Graph and Layout Subsystem

#### 4.2.1 Graph Builder (`app/graph/builder.py`)
- **Inputs**: Unified model dictionary.
- **Methodology**:
  - Instantiates a NetworkX `MultiDiGraph` representation named `ICSSecurityGraph`. Why NetworkX? NetworkX provides efficient graph representations, cycle detection, path traversals (Dijkstra, BFS), and edge manipulation utilities.
  - Adds zones as subgraph structures.
  - Adds assets and subjects as vertices $V$. Annotates each vertex with metadata: `purdue_level`, `type`, `criticality`, and `zone`.
  - Populates edges $E$:
    - **Authorization Edges ($Ea$)**: Directed from Subject $\to$ Object, annotated as `edge_class = "authorization"` and labeled with the permitted actions.
    - **Communication Edges ($Ec$)**: Directed from Object $\to$ Object, annotated as `edge_class = "communication"` and labeled with the network protocol.
- **Outputs**: Populated `ICSSecurityGraph` instance.

#### 4.2.2 Validator (`app/graph/validator.py`)
- **Inputs**: `ICSSecurityGraph` instance.
- **Methodology**:
  - Validates that the underlying graph is a directed graph.
  - Audits security policy compliance: checks for zone bypasses, insecure protocols (e.g. telnet, plaintext HTTP in Purdue Level 1/2), and direct connections traversing more than two Purdue levels without an intermediate firewall node.
- **Outputs**: Dictionary with compliance report lists (`errors`, `warnings`, `is_valid` flag, and graph statistics).

#### 4.2.3 Layer Assignment (`app/graph/layer_assignment.py`)
- **Inputs**: Purdue Level numeric representation or asset properties.
- **Methodology**:
  - Maps Purdue Levels to designated graphical rendering layers (tiers 0 to 6):
    - Level 5 (Enterprise) $\to$ Tier 0
    - Level 4 (DMZ) $\to$ Tier 1
    - Level 3 (Operations Support) $\to$ Tier 2
    - Boundary Devices (Firewalls, VPN gateways) $\to$ Tier 3
    - Level 2 (Control Systems) $\to$ Tier 4
    - Level 1 (Local Control - PLCs, HMIs) $\to$ Tier 5
    - Level 0 (Physical Process - Sensors, Actuators) $\to$ Tier 6
- **Outputs**: Integer tier representation.

#### 4.2.4 DAG Layout Generator (`app/graph/dag_generator.py`)
- **Inputs**: `ICSSecurityGraph` instance, Purdue tier dictionary, and active attack pathways.
- **Methodology**:
  - **Cycle Resolution**: Resolves cycles by finding feedback arc sets and temporarily reversing feedback edges to compute a hierarchical topological sort.
  - Computes logical X and Y layout coordinates for a clean, hierarchical top-to-bottom layout in the GUI.
  - Formats elements into a React Flow JSON payload, configuring node styling, custom colors by zone, dashed/colored lines for edge categories, and animation status for edges in active attack paths.
- **Outputs**: React Flow view dictionaries (`react_flow_asset_view` and `react_flow_macro_zone_view`).

---

### 4.3 Advanced Security Analysis Subsystem

#### 4.3.1 Reachability Engine (`app/analysis/reachability.py`)
- **Inputs**: `ICSSecurityGraph` instance.
- **Methodology**:
  - Traces cyber-to-physical paths from high Purdue levels to Level 0/1 process hardware.
  - Constructs a zone-to-zone communication matrix: computes whether any communication path exists between Zone $Z_i$ and Zone $Z_j$, identifying ISA-62443 conduit exposure.
- **Outputs**: List of cyber-physical exposure paths and a 2D zone reachability matrix dictionary.

#### 4.3.2 Attack Path Analyzer (`app/analysis/path_analysis.py`)
- **Inputs**: `ICSSecurityGraph` instance.
- **Methodology**:
  - Computes paths from external entry points to critical targets using a customized weighted cost function.
  - Integrates a `BlastRadiusValidationAgent` to run Dijkstra's shortest path calculations, incorporating penalties for crossing zones, descending Purdue levels, traversing firewalls, and utilizing sensitive access roles.
- **Outputs**: Ranked list of attack paths, with step-by-step nodes, edge classes, and overall traversal costs.

#### 4.3.3 Blast Radius Analyzer (`app/analysis/path_analysis.py`)
- **Inputs**: Target node identifier.
- **Methodology**:
  - Simulates the downstream impact if the target node is compromised.
  - Traverses the graph outwards along communication ($Ec$) and authorization ($Ea$) links.
  - Computes exposure levels based on downstream connectivity, asset criticalities, and compromised zones.
- **Outputs**: Blast radius summary containing lists of exposed assets, compromised zones, and an operational severity score.

#### 4.3.4 Threat Propagation Sim (`app/analysis/threat_propagation.py`)
- **Inputs**: Compromised origin nodes, max depth, minimum probability.
- **Methodology**:
  - Runs a Breadth-First Search (BFS) simulation modeling malware/threat propagation.
  - Calculates the probability of infection at each step, decaying as the distance from the source increases. High-security enforcement points (firewalls) act as mitigation filters, significantly reducing propagation probability.
- **Outputs**: Simulation results detailing infected nodes, their parent nodes, BFS depth, and calculated infection probabilities.

#### 4.3.5 Lateral Movement Detector (`app/analysis/lateral_movement.py`)
- **Inputs**: `ICSSecurityGraph` instance.
- **Methodology**:
  - Analyzes the graph for lateral movement hops: pivots across zone boundaries, protocol changes, and privilege escalation (moving from low-privilege subjects to high-privilege administrative sessions).
- **Outputs**: List of detected lateral movement vectors, cross-zone counts, and privilege escalations.

#### 4.3.6 Empirical Evaluation Engine (`app/analysis/empirical_metrics.py`)
- **Inputs**: Calculated attack paths and `ICSSecurityGraph` instance.
- **Methodology**:
  - Computes structural metrics:
    - **Attack Ability Factor (AAF)**: Measure of the ease with which an attacker can execute actions on target assets.
    - **Threat Exposure Level (TEL)**: Cumulative threat exposure score over all active paths.
- **Outputs**: Empirical analysis summary with AAF scores per role/level and average/maximum TEL.

---

### 4.4 Threat Intelligence Subsystem

#### 4.4.1 MITRE ATT&CK Mapper (`app/intelligence/mitre_mapper.py`)
- **Inputs**: Unified AASG and `ICSSecurityGraph` instances.
- **Methodology**:
  - Scans each edge to determine its context (source, destination, protocol, and action).
  - Matches the context to a deterministic rule matrix (Rule Mode) mapping specific configurations to official MITRE ATT&CK for ICS techniques.
  - If LLM Mode is enabled, it invokes `LLMMITREMapper` to execute a multi-agent reasoning chain.
- **Outputs**: Structured mappings of authorization and communication edges to MITRE techniques.

#### 4.4.2 Multi-Agent LLM Mapper (`app/intelligence/llm_mapper.py`)
- **Inputs**: Edge context dictionary (source, target, types, protocol, action, firewall status, and reachability).
- **Methodology**:
  - Implements a self-correcting multi-agent verification pipeline.
  - **Agent 1: Context Builder**: Gathers and enriches edge metadata.
  - **Agent 2: Candidate Selection**: Applies deterministic rules to select a shortlist of compatible MITRE techniques based on asset type and protocol.
  - **Agent 3: Attack Chain Reasoning**: Determines the attacker's progression stage (e.g. Initial Access, Discovery, Lateral Movement, Impair Process Control).
  - **Agent 4: MITRE Reasoning**: Invokes the LLM to choose a technique from the shortlist and generate a detailed justification.
  - **Agent 5: Semantic Validation**: Evaluates the LLM's response, checking for naming consistency, firewall status alignment, and proper tactic ranking.
  - **Agent 6: KB Verification**: Audits the selected technique against the ATT&CK catalog.
  - **Agent 7: Confidence Calibration**: Dynamically adjusts the confidence score based on firewall status, reachability, and ontology matching.
  - **Agent 8: Graph Consistency**: Validates that tactic progression follows a logical, sequential flow (no Initial Access tactics occurring after Impair Process Control).
  - **Self-Correction Feedback Loop**: If validation fails, Agent 4 receives the feedback, refines the prompt, and retries (up to 3 attempts).
- **Outputs**: Confirmed MITRE technique ID, name, tactic, reason, evidence trace, and calibrated confidence score.

---

## 5. Mathematical Formulations and Calculations

### 5.1 Attack Path Cost Model
The cost $C(e)$ of traversing an edge $e = (u, v)$ is calculated dynamically in the Dijkstra shortest path finder:

$$C(e) = \alpha + \beta_{fw}(e) + \gamma_{zone}(e) + \delta_{priv}(e) + \epsilon_{purdue}(e)$$

Where:
- $\alpha$: Base hop cost (default = `10`).
- $\beta_{fw}(e)$: Firewall traversal penalty. If target node $v$ is a firewall or VPN enforcement point, a cost of `+30` is added.
- $\gamma_{zone}(e)$: Trust boundary penalty. If the source node $u$ and target node $v$ reside in different network zones, a cost of `+15` is added.
- $\delta_{priv}(e)$: Privilege action-sensitivity weight. Applied on authorization edges ($Ea$) based on the sensitivity of the role action:
  - Critical control actions (`write`, `program`, `admin`, `firmware`): `+18`
  - Access actions (`connect`, `login`): `+10`
  - Read-only actions (`read`, `monitor`, `view`): `+6`
- $\epsilon_{purdue}(e)$: Purdue level descent penalty. If the attacker pivots down the network hierarchy (e.g. Level 3 to Level 2), a cost of `+20` is added to reflect the difficulty of traversing deep conduits.

---

### 5.2 Risk Scoring Engine
For each attack path $\pi = (e_1, e_2, \dots, e_k)$, the overall path risk score $R(\pi)$ is calculated as the product of its cumulative Impact and cumulative Likelihood:

$$R(\pi) = \text{Impact}(\pi) \times \text{Likelihood}(\pi)$$

#### 5.2.1 Path Impact
The impact $I(\pi)$ is determined by the criticality of the final target node $v_{target}$ in the path:

$$I(\pi) = \text{CriticalityWeight}(v_{target})$$

Where:
- Criticality `"high"` / `"critical"` $\to 10.0$
- Criticality `"medium"` $\to 6.0$
- Criticality `"low"` $\to 3.0$

#### 5.2.2 Path Likelihood
The likelihood $L(\pi)$ is calculated based on the path's overall traversal cost:

$$L(\pi) = \max\left(0.05, 1.0 - \frac{\sum_{i=1}^{k} C(e_i)}{500}\right)$$

This calculation ensures that shorter, less costly paths yield a higher attack likelihood.

---

### 5.3 Threat Propagation BFS Simulation
Starting from a set of compromised entry nodes, threat propagation calculates the probability $P(n)$ of a node $n$ being infected at BFS depth $d$:

$$P(n) = P(\text{parent}) \times P_{\text{transition}}(e)$$

Where:
- The base transition probability $P_{\text{transition}}$ is `0.8` for communication links and `0.5` for authorization permissions.
- If the edge traverses a firewall boundary, the probability is filtered:
  
  $$P_{\text{transition}}' = P_{\text{transition}} \times (1.0 - \text{MitigationStrength})$$
  
  (Firewall Mitigation Strength default = `0.85`).
- The probability decays as depth increases:
  
  $$P(n)_d = P(n)_{d-1} \times e^{-\lambda d}$$
  
  (Decay constant $\lambda = 0.05$).

---

### 5.4 Empirical Evaluation Metrics

#### 5.4.1 Attack Ability Factor (AAF)
The AAF measures the ease with which an attacker can execute actions on target assets. For a set of paths $\Pi_{s, t}$ from source $s$ to target $t$:

$$\text{AAF}(s, t) = \sum_{\pi \in \Pi_{s, t}} \frac{1}{\text{Cost}(\pi)}$$

Higher AAF scores indicate more exposed pathways and weaker defenses between nodes.

#### 5.4.2 Threat Exposure Level (TEL)
The TEL measures the cumulative exposure of a target node $t$ across all possible paths:

$$\text{TEL}(t) = \sum_{s \in \text{EntryPoints}} \sum_{\pi \in \Pi_{s, t}} R(\pi) \cdot e^{-\eta \cdot \text{Cost}(\pi)}$$

Where $\eta$ is a scaling factor (default = `0.01`).

---

## 6. Operational Manual and Local Setup

Follow these steps to set up and run the threat modeler locally.

### Step 1: Install System Dependencies
Ensure you have the following installed on your machine:
- **Python 3.10** or higher
- **Node.js 18** or higher
- **git** (to clone and manage repositories)

### Step 2: Environment Variables
Create a file named `.env` in the `backend/` directory:
```env
BACKEND_HOST=127.0.0.1
BACKEND_PORT=7429
MITRE_MAPPER_MODE=llm
OPENAI_API_KEY=your_openai_api_key_here
OPENAI_MITRE_MODEL=gpt-4
```

### Step 3: Run Setup and Launch
Run the start commands:
- **Backend Setup & Run**:
  ```powershell
  cd backend
  python -m venv .venv
  .venv\Scripts\activate   # (or source .venv/bin/activate on Linux/macOS)
  pip install -r requirements.txt
  python main.py
  ```
- **Frontend Setup & Run**:
  ```powershell
  cd frontend
  npm install
  npm run dev
  ```

---
*End of Flow and Architecture Documentation (v2.1)*
