# DAG Formation & Layout Subsystem Documentation
## Phase 2 Graph Compilation & Visualization Layout

This document details the architecture, algorithms, implementation, and correctness standards of the DAG Formation and Layout Subsystem.

---

## 1. What is Done
The DAG Formation Subsystem implements:
- **NetworkX Graph Builder**: Compiles the unified model into an `ICSSecurityGraph` instance.
- **Purdue Level Tier Assignment**: Maps Purdue Levels to designated graphical rendering layers (tiers 0 to 6).
- **Cycle Resolution Engine**: Identifies visual loops, reverses feedback edges, and calculates a topological sort.
- **Grid Layout Calculator**: Computes node coordinate matrices to prevent overlapping zones.
- **React Flow Renderer**: Translates the graph into a React Flow JSON payload.

---

## 2. How it is Done

### 2.1 Subsystem Workflow Diagram
```
+---------------------------------------------------------------------------------+
|                                 LAYOUT PIPELINE                                 |
+---------------------------------------------------------------------------------+
   Canonical A = {Z, E, S, O, R}
             │
             ▼
   [NetworkX Graph Builder] ──► MultiDiGraph representation (G = (V, E, Z))
             │
             ├─► [Validator] ──► Cycle detection & Purdue conduit checks
             │
             ▼
   [Cycle Resolution Engine]
             ├─► Detects back-edges (simple cycles)
             ├─► Temporarily reverses back-edges to form a DAG
             └─► Calculates topological sort for rendering order
                     │
                     ▼
   [Grid Layout Calculator]
             ├─► Y-coordinates: Purdue tiers (0 to 6)
             └─► X-coordinates: Grouped horizontally by zone
                     │
                     ▼
   [React Flow Compiler] ──► Generates custom node shapes & animated active paths
```

### 2.2 Core Logic & Calculations

#### 2.2.1 Graph Builder (`app/graph/builder.py`)
- **Inputs**: Canonical model $A = \{Z, E, S, O, R\}$.
- **Logic**: Instantiates a NetworkX `MultiDiGraph` named `ICSSecurityGraph`. Adds assets and subjects as vertices $V$ and populates authorization edges ($Ea$) and communication edges ($Ec$).
- **Outputs**: Populated `ICSSecurityGraph` instance.

#### 2.2.2 Graph Validator (`app/graph/validator.py`)
- **Inputs**: `ICSSecurityGraph` instance.
- **Logic**: Validates that the underlying graph is a directed graph. Checks for cycles, Purdue level conduit bypasses, and insecure protocols in industrial control levels.
- **Outputs**: Compliance report lists (`errors`, `warnings`, `is_valid` flag).

#### 2.2.3 Layer Assignment (`app/graph/layer_assignment.py`)
- **Inputs**: Purdue Level numeric representation or asset properties.
- **Logic**: Maps Purdue Levels to designated graphical rendering layers (tiers 0 to 6) to construct a top-down network diagram.
- **Outputs**: Integer tier representation.

#### 2.2.4 DAG Layout Generator (`app/graph/dag_generator.py`)
- **Inputs**: `ICSSecurityGraph` instance, Purdue tier dictionary, and active attack pathways.
- **Logic**: Resolves cycles by finding feedback arc sets and temporarily reversing feedback edges during layout calculations to create a true DAG, enabling a clean topological sort. Computes coordinates by grouping assets by their network zones.
- **Outputs**: React Flow view dictionaries (`react_flow_asset_view` and `react_flow_macro_zone_view`).

---

## 3. Correctness Standards & Validation

To ensure rendering accuracy, the platform enforces the following correctness criteria:
1. **Preservation of Analytical Cycles**: Cycle resolution only reverses edges during coordinate calculations. The underlying analytical graph preserves all loops to enable realistic path-finding simulations.
2. **Deterministic Placement**: Node coordinates are calculated deterministically to prevent overlapping zones and ensure a clean, legible layout.
3. **Zone Containment**: Subgraphs represent network zones, and assets are visually grouped within their assigned zone boundaries to preserve ISA-62443 trust boundaries.
