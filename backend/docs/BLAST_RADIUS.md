# Blast Radius Analysis Subsystem Documentation
## Forward Path Traversal & Operational Impact

This document details the architecture, algorithms, implementation, and correctness standards of the Blast Radius Analysis Subsystem.

---

## 1. What is Done
The Blast Radius Subsystem implements:
- **Forward Traversal Engine**: Traces reachable nodes from a compromised origin.
- **Exposure Analyzer**: Identifies compromised assets and network zones.
- **Operational Severity Calculator**: Computes risk scores based on asset criticalities.

---

## 2. How it is Done

### 2.1 Subsystem Workflow Diagram
```
+---------------------------------------------------------------------------------+
|                               BLAST RADIUS PIPELINE                             |
+---------------------------------------------------------------------------------+
   Compromised Target Node ID
             │
             ▼
   [Forward Traversal Engine]
             ├─► Traces communications (Ec) outward
             ├─► Traces authorization permissions (Ea) outward
             └─► Handles feedback loops to prevent infinite loops
                     │
                     ▼
   [Exposure Analyzer]
             ├─► Gathers exposed assets (objects & subjects)
             └─► Identifies compromised network zones
                     │
                     ▼
   [Operational Severity Calculator]
             ├─► Sums asset criticality weights
             └─► Computes zone exposure ratios
                     │
                     ▼
   Blast Radius Report (Reachable Assets, Compromised Zones, Severity Score)
```

### 2.2 Core Logic & Calculations

#### 2.2.1 Forward Traversal
The engine performs a directed search starting from the target node, traversing along both communication ($Ec$) and authorization ($Ea$) links:
- **Asset Exposure**: Tracks the count and criticality of reachable nodes.
- **Zone Exposure**: Tracks the count of network zones that can be reached from the compromised node.

#### 2.2.2 Severity Scoring
The operational severity score $S(n)$ for a compromised node $n$ is calculated as:

$$S(n) = \sum_{v \in \text{ExposedNodes}} \text{CriticalityWeight}(v) \times \text{ZoneWeight}(\text{zone}(v))$$

Where:
- Criticality weight: `"high"` / `"critical"` = `10.0`, `"medium"` = `6.0`, `"low"` = `3.0`.
- Zone weight: Determined by the Purdue level of the zone (e.g. Level 1 Control zone weight = `1.5`, Level 5 Enterprise zone weight = `0.8`).

---

## 3. Correctness Standards & Validation

To ensure calculation accuracy, the platform enforces the following correctness criteria:
1. **Directional Traversal**: Traversal is strictly directional along out-edges, representing the forward spread of a threat.
2. **Cycle Prevention**: Employs visited-node sets to prevent infinite loops when traversing circular dependency paths.
3. **Zone Mapping**: Validates that zone exposure correctly reflects the ISA-62443 zone boundaries traversed.
4. **Separation of Concerns**: Differentiates between physical process exposure (Level 0/1) and logical cyber exposure (Level 2/3/4) in the final severity report.
