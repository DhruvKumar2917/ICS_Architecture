# ICS AASG Analyzer — Architecture Diagram Generator v2

An AI-assisted security-analysis platform for **Industrial Control System (ICS) / Operational Technology (OT)** networks. It ingests three independent sources — an **architecture diagram** (image or text), an **RBAC policy**, and a **firewall rule set** — merges them into one canonical model, compiles that into a formal **Authorization Attack Surface Graph (AASG)**, and then runs a full battery of security analytics: attack-path discovery, quantitative risk scoring, MITRE ATT&CK for ICS mapping, blast-radius, threat-propagation, and lateral-movement detection. Results are rendered as an interactive React Flow graph.

This document describes the whole system **and** details the improvements implemented in this revision (centralized ontology/alias resolution, device-pair protocol inference, richer graph visualization, and a refined weighted attack-path cost model).

---

## 1. The formal model: `A = {Z, E, S, O, R}` → `G = (V, E, Z)`

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

## 2. Repository layout

```
architecture-diagram-generator-v2/
├── backend/                         FastAPI service (Python)
│   ├── main.py                      API + 13-step analysis pipeline
│   ├── parsers/
│   │   ├── ontology.py              ★ NEW — alias / normalization / protocol inference
│   │   ├── unified_model.py         Canonical A={Z,E,S,O,R} merger
│   │   ├── rbac_parser.py           Subjects, actions, permissions  → S, R, Ea
│   │   ├── firewall_parser.py       Allow/deny rules with protocol+port → Ec filter
│   │   ├── image_parser.py          Diagram (image/PDF) extractor → Z, O, connections
│   │   └── text_parser.py           Free-text architecture extractor
│   └── DAG/
│       ├── aasg.py                  Formal AASG graph (schema validation)
│       ├── graph_builder.py         NetworkX ICSSecurityGraph + risk/role tagging
│       ├── graph_validator.py       Compliance audit (enforcement-point checks)
│       ├── layer_assignment.py      Purdue-level layering for layout
│       ├── dag_generator.py         Cycle resolution + React Flow payload
│       ├── path_analysis.py         Weighted attack-path discovery + blast radius
│       ├── risk_engine.py           Quantitative impact × likelihood scoring
│       ├── mitre_mapper.py          Context-aware MITRE ATT&CK for ICS mapping
│       ├── threat_propagation.py    BFS infection simulation
│       ├── lateral_movement.py      Cross-zone / privilege / protocol pivots
│       └── reachability.py          Cyber→physical exposure
└── frontend/                        React + Vite + React Flow UI
    └── src/
        ├── main.jsx                 Single-file app: graph, panels, tabs
        └── style.css                Styles + animations
```

> Note: the uploaded archive bundles per-OS virtual environments (`backend/venv`, `backend/myenv`, `frontend/node_modules`) captured on Windows. They are **not** portable; recreate them per the setup steps below.

---

## 3. The analysis pipeline (in `main.py`)

```
RBAC ┐
Firewall ┼─► unified_model.build_unified_model() ─► A = {Z,E,S,O,R}
Arch ┘                                                 │
                                                       ▼
   AASGGraph ─► ICSSecurityGraph ─► dag_generator ─► React Flow payload
                     │                                   │
                     ├─► path_analysis (weighted) ───────┤
                     ├─► risk_engine (impact×likelihood) ─┤
                     ├─► mitre_mapper (context-aware) ────┤
                     ├─► threat_propagation (BFS) ────────┤
                     └─► lateral_movement / reachability ─┘
```

The merge order matters: `zones → objects → subjects → actions → permissions → connections`, because connection and permission resolution depend on the canonical IDs registered earlier.

---

## 4. What was improved in this revision

The five items below were the requested improvements. Two of them (**weighted path ranking** and **context-aware MITRE**) were already present in the codebase; this revision adds the three genuinely missing pieces and refines a fourth.

### 4.1 ★ Centralized ontology, alias mapping & object normalization — **NEW**

**Problem.** The same asset appears under different spellings across the three files:

```
OEM_SCADA          (firewall rule)
OEM-SCADA          (RBAC object)
oem_scada_server   (architecture diagram)
```

Previously, the merger tried to bridge these with ad-hoc fuzzy matching and a few hardcoded aliases scattered through `unified_model.py`. That caused both **missed merges** (the three names above didn't unify) and **false merges** (e.g. `oem_firewall` collapsing into `oem_scada_server`).

**Solution.** A new module `backend/parsers/ontology.py` is the single source of truth for naming. It centralizes three concerns:

1. **Alias mapping** — an explicit `ALIASES` table keyed by a *delimiter-insensitive* form, so one entry catches every spelling:

   ```python
   ALIASES = {
       "oemscada":       "oem_scada_server",   # catches OEM_SCADA, OEM-SCADA, oem scada …
       "oemscadaserver": "oem_scada_server",
       "vpngw":          "customer_vpn",
       "hmimaster":      "master_hmi",
       # …
   }
   ```

2. **Object normalization** — deterministic resolution that does **not** rely on aliases alone:
   `resolve_against(raw, registry)` tries, in priority order: exact alias → delimiter-insensitive equality (`oem-scada == oem_scada`) → suffix-stem equality (`oem_scada == oem_scada_server`) → token-set equality (`hmi_master == master_hmi`) → fuzzy ratio ≥ threshold (last resort).

3. **Device-type ontology** — keyword → canonical type (`scada`, `plc`, `hmi`, `firewall`, `vpn`, `enterprise`, …), used both for normalization and to drive protocol inference.

**Wiring.** The per-set `Canonicalizer` in `unified_model.py` now calls `ontology.normalize_identifier()` first, then `ontology.resolve_against()` to reconcile against already-registered IDs; `_resolve_object_alias()` delegates entirely to the ontology layer. Adding a new synonym is now a one-line edit to `ALIASES`.

**Verified:** `OEM-SCADA` (connection) and `OEM_SCADA` (permission object) both resolve onto the diagram's `oem_scada_server` — no duplicate object is created.

### 4.2 ★ Device-pair protocol inference — **NEW**

**Problem.** When neither the diagram nor a firewall rule supplied a protocol, the communication edge was labeled `unknown`, which degraded MITRE mapping accuracy (and `main.py` already counts/warns about unknown-protocol edges).

**Solution.** `ontology.infer_protocol(src_type, dst_type, src_id, dst_id)` infers the conventional ICS/OT protocol from the device pair. It resolves device types from declared types *and* identifiers, then consults a direction-insensitive pair table:

| Device pair | Inferred protocol |
| --- | --- |
| HMI ↔ PLC | Modbus |
| SCADA ↔ PLC | OPC-UA |
| Firewall ↔ VPN | IPSec |
| Enterprise ↔ SCADA | HTTPS |
| Engineering ↔ PLC | S7comm |
| SCADA ↔ RTU | DNP3 |
| RTU ↔ Sensor | IEC 61850 |
| PLC ↔ Sensor/Actuator | HART |
| PLC/RTU ↔ Physical process | Fieldbus |

(plus a single-side fallback, e.g. any link into a `plc` defaults to Modbus). Inference runs in `_ingest_connections` only when the protocol is still `unknown`, and the resulting edge carries `protocol_inferred: true` so the UI can distinguish inferred from observed protocols.

**Verified:** `master_hmi → plc_1` ⇒ `modbus`; `oem_scada_server → plc_1` ⇒ `opc-ua`. Every protocol the inferrer can emit is already present in the MITRE protocol map, so inferred edges map to techniques cleanly.

### 4.3 ★ Richer graph visualization — **NEW**

In `frontend/src/main.jsx` / `style.css`:

- **Edge colors by category** in the idle view: authorization edges (`Ea`, `HUMAN_PERM`) render **purple and dashed**; communication edges (`Ec`, `COMM_LINK`) render **blue**; cyber-physical edges render **violet**. A small **legend panel** (top-left of the canvas) documents the key.
- **Hover details** on every node: a composed tooltip shows **criticality, zone, Purdue level, type, security role, risk score, and the protocols touching that node** (aggregated from its communication edges).
- **Attack-path traversal animation**: highlighted in-path edges use an `edgeFlow` keyframe (marching dashes) plus React Flow's animated flag, so the traversal visibly "flows" from entry point to target.

The frontend was rebuilt (`npm run build`) so `frontend/dist/` reflects these changes.

### 4.4 Weighted attack-path ranking — **present, refined**

`path_analysis.py` already ranks paths with a weighted cost rather than pure shortest-path:

```
cost = base_hop_cost
     + firewall_strength      (+30 if next node is a firewall/VPN/enforcement point)
     + zone_crossing          (+15 per trust-boundary crossing)
     + privilege_required     (per HUMAN_PERM edge)
     + purdue_descent_penalty (+20 when pivoting down toward the process layer)
```

Candidates are generated with `nx.shortest_simple_paths(weight='weight')` and then re-ranked by the `risk_engine` score. **Refinement added here:** `privilege_required` is now tied to **action sensitivity** instead of a flat value — a privileged control action (`write`, `program`, `modify`, `admin`, `firmware`, …) costs more to traverse (+18) than standard access (+10) or a read-only action (+6), producing a more realistic attacker model.

### 4.5 Context-aware MITRE mapping — **present**

`mitre_mapper.py` already resolves techniques from the *combination* of source type, target type, action, and protocol via `get_contextual_mapping()`. For example:

```python
if proto in ("modbus","modbus_tcp") and act in ("write","send_command","modify"):
    return T0831  # Modify Controller Tasking
```

It also covers PLC/RTU manipulation (T0831/T0836), Monitor Process State (T0801), Remote Services (T0866), Spoof Reporting (T0856), Valid Accounts (T0859), Safety-system tampering (T0857/T0838), and attaches tactic severity, an ATT&CK URL, and a documented real-world example (Stuxnet, Triton, Industroyer, …) to each hop. Inferred protocols from §4.2 feed straight into this mapper.

---

## 5. Setup & run

### Prerequisites
- Python 3.10+ and Node.js 18+
- An LLM API key for diagram/text extraction (`backend/.env`, e.g. `OPENAI_API_KEY=…`)

### Backend
```bash
cd architecture-diagram-generator-v2/backend
python -m venv .venv
# Windows:  .venv\Scripts\activate
# macOS/Linux:  source .venv/bin/activate
pip install -r requirements.txt
uvicorn main:app --reload --port 8000
```

### Frontend
```bash
cd architecture-diagram-generator-v2/frontend
npm install          # recreate node_modules for your OS (the bundled one is Windows-only)
npm run dev          # dev server (Vite)
# or:
npm run build        # production build into dist/
```

If `npm run build` fails with a missing `rolldown` native binding, install the one for your platform, e.g. on Linux x64:
```bash
npm install @rolldown/binding-linux-x64-gnu --no-save
```

---

## 6. API endpoints (FastAPI)

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

The `/upload` and `/generate-from-text` responses include `react_flow_asset_view`, `react_flow_macro_zone_view`, `attack_paths`, `mitre_mapping`, `lateral_movement`, `threat_propagation`, validation issues, and the `raw_model_data` reused by the per-node endpoints.

---

## 7. Extending the system

- **Add a name synonym:** add one line to `ALIASES` in `parsers/ontology.py` (use the delimiter-insensitive key, e.g. `"newscada": "oem_scada_server"`), or call `ontology.register_alias(raw, canonical)` at runtime.
- **Add a protocol rule:** add an entry to `_PAIR_PROTOCOL` (keyed by `frozenset({type_a, type_b})`) in `parsers/ontology.py`; add the protocol to `MITRE_PROTOCOL_MAP` in `mitre_mapper.py` if it isn't already mapped.
- **Add a device type:** extend `_DEVICE_TYPE_KEYWORDS` in `parsers/ontology.py` (most-specific keyword first).
- **Tune path cost:** adjust the weights in `path_analysis.analyze_attack_paths` (firewall/zone/privilege/Purdue terms).
- **Add a MITRE rule:** extend `get_contextual_mapping()` in `mitre_mapper.py`.

---

## 8. Design guarantees worth remembering

- Subjects (`S`) and actions (`R`) come **only** from RBAC; architecture assets are filtered out of `S`.
- `Ec` requires both diagram evidence **and** firewall permission (intra-zone and recognized control-chain links are allowed by default unless explicitly denied).
- Naming is reconciled in exactly one place (`ontology.py`); separate canonicalizers keep zone/subject/object ID spaces isolated.
- Protocols are never silently left `unknown` when a sensible device-pair inference exists, and inferred protocols are flagged as such.
