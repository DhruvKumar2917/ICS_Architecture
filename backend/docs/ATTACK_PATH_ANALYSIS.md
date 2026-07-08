# Attack Path Analysis Subsystem Documentation
## Dijkstra Pathfinding & Risk Scoring

This document details the architecture, algorithms, implementation, and correctness standards of the Attack Path Analysis Subsystem.

---

## 1. What is Done
The Attack Path Analysis Subsystem implements:
- **Dijkstra-Based Path Finder**: Calculates the shortest path between entry points and targets based on cost weights.
- **Dynamic Cost Weights Engine**: Calculates traversal difficulty based on zone boundaries, firewalls, and privilege levels.
- **Risk Scoring Engine**: Computes overall risk scores:
  
  $$\text{Risk} = \text{Impact} \times \text{Likelihood}$$
  
- **Vulnerability Narrative Generator**: Translates raw path steps into readable descriptions.

---

## 2. How it is Done

### 2.1 Subsystem Workflow Diagram
```
+---------------------------------------------------------------------------------+
|                               PATHFINDING PIPELINE                              |
+---------------------------------------------------------------------------------+
   [ICSSecurityGraph] ──► Entry Points & Target Assets
             │
             ▼
   [Dynamic Cost Weights Engine]
             ├─► Base Hop Cost (10)
             ├─► Firewall Boundary (+30)
             ├─► Zone Boundary (+15)
             ├─► Purdue Descent (+20)
             └─► Action Sensitivity (Write: +18, Access: +10, Read: +6)
                     │
                     ▼
   [Dijkstra Path Finder] ──► Finds top N paths based on cumulative cost
                     │
                     ▼
   [Risk Scoring Engine]
             ├─► Impact = Target Criticality Weight
             └─► Likelihood = 1.0 - (Cumulative Cost / 500)
                     │
                     ▼
   [Narrative Generator] ──► Generates step-by-step vulnerability reports
```

### 2.2 Core Algorithms & Mathematical Formulations

#### 2.2.1 Edge Cost Calculation
The cost $C(e)$ of traversing an edge $e = (u, v)$ is calculated dynamically in the Dijkstra shortest path finder:

$$C(e) = \alpha_{\text{base}} + \beta_{fw}(e) + \gamma_{zone}(e) + \delta_{priv}(e) + \epsilon_{purdue}(e)$$

Where:
- $\alpha_{\text{base}}$: Base hop cost (default = `10`).
- $\beta_{fw}(e)$: Firewall traversal penalty. If target node $v$ is a firewall or VPN enforcement point, a cost of `+30` is added.
- $\gamma_{zone}(e)$: Trust boundary penalty. If the source node $u$ and target node $v$ reside in different network zones, a cost of `+15` is added.
- $\delta_{priv}(e)$: Privilege action-sensitivity weight. Applied on authorization edges ($Ea$) based on the sensitivity of the role action:
  - Critical control actions (`write`, `program`, `admin`, `firmware`): `+18`
  - Access actions (`connect`, `login`): `+10`
  - Read-only actions (`read`, `monitor`, `view`): `+6`
- $\epsilon_{purdue}(e)$: Purdue level descent penalty. If the attacker pivots down the network hierarchy (e.g. Level 3 to Level 2), a cost of `+20` is added.

#### 2.2.2 Risk Scoring
For each attack path $\pi = (e_1, e_2, \dots, e_k)$, the overall path risk score $R(\pi)$ is calculated as:

$$R(\pi) = \text{Impact}(\pi) \times \text{Likelihood}(\pi)$$

- **Impact** $I(\pi)$ is determined by the criticality weight of the target node $v_{target}$:
  - Criticality `"high"` / `"critical"` $\to 10.0$
  - Criticality `"medium"` $\to 6.0$
  - Criticality `"low"` $\to 3.0$
- **Likelihood** $L(\pi)$ is derived from the cumulative path cost:
  
  $$L(\pi) = \max\left(0.05, 1.0 - \frac{\sum_{i=1}^{k} C(e_i)}{500}\right)$$

---

## 3. Correctness Standards & Validation

To ensure pathfinding accuracy, the platform enforces the following correctness criteria:
1. **Dijkstra Cost Representation**: Applying penalties for crossing firewalls and descending Purdue levels ensures that shorter, less secure paths are ranked higher (yielding a higher attack likelihood).
2. **Blast Radius Validation**: Paths are validated using the `BlastRadiusValidationAgent` to confirm that all network hops and access privileges are structurally reachable.
3. **Plausibility Enforcement**: Paths must start at valid entry points (nodes with in-degree = 0 or marked as entry points) and end at target assets (nodes with out-degree = 0 or marked as targets).
