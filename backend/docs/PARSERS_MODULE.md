# Parsers Subsystem Documentation
## Phase 1 Data Extraction & Normalization

This document details the architecture, design philosophy, implementation, and correctness standards of the Parsers Subsystem.

---

## 1. What is Done
The Parsers Subsystem successfully implements:
- **RBAC Policy Extraction**: Parses Casbin, CSV, JSON, and YAML formats to isolate subjects ($S$), actions ($R$), and permissions ($Ea$).
- **Firewall ACL Parsing**: Uses regular expressions to parse Cisco ASA ACL rule sets and maps ports to protocols.
- **AI-Assisted Architecture Extraction**: Integrates OpenCV and GPT Vision to extract zones, assets, and connections from drawings/PDFs, and parses text layouts.
- **Centralized Ontology Normalization**: Cleans, canonicalizes, and deduplicates asset names, and infers default protocols (e.g. Modbus for HMI-PLC links).
- **Unified Model Merging**: Assembles data into the canonical five-tuple model $A = \{Z, E, S, O, R\}$, filtering connections using firewall rules.

---

## 2. How it is Done

### 2.1 Subsystem Workflow Diagram
```
+---------------------------------------------------------------------------------+
|                                 PARSING PIPELINE                                 |
+---------------------------------------------------------------------------------+
   [Raw Diagram]      ──► Image/Text Parser (LLM) ──► Raw Architecture JSON
                                                            │
   [Raw RBAC Rules]   ──► RBAC Parser (Casbin/CSV) ──► Raw Permissions JSON
                                                            │
   [Raw Firewall]     ──► Firewall Parser (Cisco ASA) ──► Raw Firewall JSON
                                                            │
                                                            ▼
                                                [Centralized Ontology]
                                                  ├─ Standardizes spelling
                                                  ├─ Resolves duplicate IDs
                                                  └─ Infers default protocols
                                                            │
                                                            ▼
                                                  [Unified Model Merger]
                                                    ├─ Separates S and O namespaces
                                                    └─ Enforces Ec = Connections ∩ Firewall
                                                            │
                                                            ▼
                                                 Canonical A = {Z, E, S, O, R}
```

### 2.2 Parsing Specifications & Core Logic

#### 2.2.1 RBAC Parser (`app/parsers/rbac/parser.py`)
- **Inputs**: Raw string containing user permissions.
- **Logic**: Evaluates comma-separated values to isolate subjects, actions, target assets, and rule provenances.
- **Outputs**: Lists of subjects `S`, actions `R`, and authorization maps `permissions`.

#### 2.2.2 Firewall Parser (`app/parsers/firewall/parser.py`)
- **Inputs**: Raw string containing firewall rules.
- **Logic**: Uses regex to extract allowed source-destination host pairs and matches them to network ports.
- **Outputs**: Parsed lists of rules and allowed pairs.

#### 2.2.3 Image/Text Parser (`app/parsers/image/parser.py` & `text/parser.py`)
- **Inputs**: Network diagrams (images/PDFs) or natural language text descriptions.
- **Logic**: Converts PDFs to images via PyMuPDF. Prompts the OpenAI Vision/LLM API with system prompts directing the model to extract zones, assets, and connections, returning strict JSON.
- **Outputs**: Dictionary of zones, assets, and connections.

#### 2.2.4 Ontology Engine (`app/parsers/ontology.py`)
- **Inputs**: Un-normalized naming strings and device classes.
- **Logic**: Standardizes strings by converting to lowercase and stripping delimiters. Runs suffix stem, token-set, and Levenshtein fuzzy matching ($\ge 82\%$) to resolve duplicates. Confirms default protocols (e.g. HMI-PLC $\to$ Modbus, SCADA-PLC $\to$ OPC-UA) when connections lack protocol labels.
- **Outputs**: Normalized identifiers and inferred network protocols.

#### 2.2.5 Unified Merger (`app/parsers/unified_model.py`)
- **Inputs**: Raw extracted data from the parsing modules.
- **Logic**: Combines data in a strict merge order: `zones -> assets -> subjects -> actions -> permissions -> connections`. Filters out visual connections that are not explicitly permitted by a firewall rule, logging them as `firewall_blocked`.
- **Outputs**: Unified canonical model $A = \{Z, E, S, O, R\}$.

---

## 3. Correctness Standards & Validation

To ensure the integrity of the threat-modeling calculations, the platform enforces the following correctness criteria:
1. **Namespace Separation**: Subjects ($S$) and objects ($O$) must reside in separate ID namespaces. An asset name (e.g. `SCADA_Server`) can never resolve onto a user role name (e.g. `scada_admin`), preventing false access pathways in path-finding calculations.
2. **Authorized-Only Permissions**: User permissions ($Ea$) are derived *exclusively* from the RBAC policy file, preventing the LLM from inventing privileges during diagram processing.
3. **Firewall Filter Enforcement**: Communication edges ($Ec$) are generated using the intersection formula:
   
   $$Ec = \text{visual\_connections} \cap \text{firewall\_allowed}$$
   
   Any link depicted in the architecture diagram that is not explicitly permitted by a firewall rule is excluded from the graph.
