# Empirical Analysis Subsystem Documentation
## Attack Ability Factor (AAF) & Threat Exposure Level (TEL)

This document details the architecture, algorithms, implementation, and correctness standards of the Empirical Analysis Subsystem.

---

## 1. What is Done
The Empirical Analysis Subsystem implements:
- **AAF Calculator**: Computes accessibility scores per subject role and target asset.
- **TEL Calculator**: Computes cumulative threat exposure scores along all active paths.
- **Metrics Compiler**: Compiles statistical summaries grouped by Purdue levels and zones.

---

## 2. How it is Done

### 2.1 Subsystem Workflow Diagram
```
+---------------------------------------------------------------------------------+
|                             METRICS CALCULATION FLOW                            |
+---------------------------------------------------------------------------------+
   Calculated Attack Paths & ICSSecurityGraph Metadata
             │
             ├───────────────┐
             ▼               ▼
        [AAF Engine]    [TEL Engine]
             │               │
             ▼               ▼
   [AAF Formula]   [TEL Formula]
             │               │
             └───────┬───────┘
                     │
                     ▼
   [Metrics Compiler]
             ├─► AAF scores per subject role
             ├─► Cumulative TEL per target asset
             └─► Zone & Purdue level exposure summaries
```

### 2.2 Core Logic & Mathematical Formulations

#### 2.2.1 Attack Ability Factor (AAF)
The AAF measures the ease with which an attacker can execute actions on target assets. For a set of paths $\Pi_{s, t}$ from source $s$ to target $t$:

$$\text{AAF}(s, t) = \sum_{\pi \in \Pi_{s, t}} \frac{1}{\text{Cost}(\pi)}$$

Where:
- $\text{Cost}(\pi)$ is the cumulative cost weight of all hops in path $\pi$.
- Shorter paths yield higher AAF scores, indicating weaker defenses between nodes.
- **High-Impact Filter**: To prevent inflation from low-severity reconnaissance or discovery-tier hops, the numerator $A_{HI}$ only includes unique mapped MITRE techniques whose tactic classifications carry a **HIGH** or **CRITICAL** severity rating (e.g., Impair Process Control, Inhibit Response Function, Lateral Movement, Execution).

#### 2.2.2 Threat Exposure Level (TEL)
The TEL measures the cumulative exposure of a target node $t$ across all possible paths:

$$\text{TEL}(t) = \sum_{s \in \text{EntryPoints}} \sum_{\pi \in \Pi_{s, t}} R(\pi) \cdot e^{-\eta \cdot \text{Cost}(\pi)}$$

Where:
- $R(\pi)$ is the risk score of path $\pi$: $R(\pi) = \text{Impact}(\pi) \times \text{Likelihood}(\pi)$.
- $\eta$ is a scaling factor (default = `0.01`).
- Nodes reachable via high-risk, low-cost pathways yield significantly higher TEL scores.
- **Fully Unenforced Flag**: Paths with zero authorization constraints (no policy-enforced links crossed, `last_policy_idx == -1`) are explicitly flagged with a `"fully_unenforced": True` marker to help audit dashboards distinguish completely open pathways from shallow enforcement.

---

## 3. Correctness Standards & Validation

To ensure calculation accuracy, the platform enforces the following correctness criteria:
1. **Mathematical Consistency**: Costs and risk scores must align with the parameters defined in the pathfinding and risk engines.
2. **Path Convergence**: The TEL engine aggregates data from all possible pathways, accounting for multiple entry points and redundant conduits.
3. **Weight Calibration**: The scaling factor $\eta$ is calibrated to ensure that extremely high-cost paths are properly discounted in the final exposure score.
4. **Structural Parity Check**: To eliminate consistency risk between the exported AASG JSON model and in-memory analytical paths, a model consistency validation check verifies that:
   
   $$\text{len}(Ea) + \text{len}(Ec) \approx \text{graph\_edges}(\text{HUMAN\_PERM} \cup \text{COMM\_LINK})$$
   
   If these values diverge, a warning is logged and a flag is attached to the API response.
