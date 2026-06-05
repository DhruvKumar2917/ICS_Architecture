import logging
import networkx as nx
from collections import defaultdict

logger = logging.getLogger(__name__)

# Spatial Layout Constants for React Flow
VERTICAL_SPACING = 250         # Y-axis distance between Purdue Layers
HORIZONTAL_NODE_SPACING = 300  # X-axis distance between sibling nodes
ZONE_PADDING = 100             # Internal padding for the Zone container
MIN_ZONE_WIDTH = 600           # Minimum width for a zone container
ZONE_MARGIN = 150              # Padding between different Zone containers

class ICSAnalysisDAGBuilder:
    """
    Transforms the ICS Security Graph into a UI-ready, cycle-resolved Analysis DAG.
    Features Dynamic Zone Widths, Attack Path Protection, Macro Zone Views, 
    and Deterministic Node Placement.
    """
    def __init__(self, ics_graph, layer_matrix, active_attack_paths=None):
        self.original_graph = ics_graph.asset_graph
        self.layer_matrix = layer_matrix
        self.dag_view = self.original_graph.copy()
        
        self.suppressed_edges = []
        self.cycle_categories = defaultdict(int)
        
        # Flatten attack paths for O(1) lookup during cycle breaking & frontend generation
        self.attack_nodes = set()
        self.attack_edges = set()
        if active_attack_paths:
            for path_data in active_attack_paths:
                path = path_data.get("path", [])
                self.attack_nodes.update(path)
                for i in range(len(path) - 1):
                    self.attack_edges.add((path[i], path[i+1]))

    def _score_edge_for_removal(self, u, v, edge_data):
        """
        Advanced Semantic Scoring: Protects critical assets, physical logic, 
        and explicitly safeguards known Attack Paths.
        """
        score = 0.0
        confidence = edge_data.get("confidence", 1.0)
        edge_type = edge_data.get("edge_type", "COMM_LINK")
        u_attrs = self.dag_view.nodes[u]
        v_attrs = self.dag_view.nodes[v]

        # 1. Break inferred paths first
        if confidence < 0.6: score += 100
        elif confidence < 0.9: score += 30

        # 2. Break Permissions, Protect Physics
        if edge_type == "HUMAN_PERM": score += 80
        elif edge_type == "CYBER_PHYSICAL": score -= 500  
        
        # 3. Protect Critical Assets & Low Purdue Levels
        if u_attrs.get("criticality") == "critical" or v_attrs.get("criticality") == "critical":
            score -= 200
        
        u_purdue = str(u_attrs.get("purdue_level", "")).lower()
        if "level 0" in u_purdue or "level 1" in u_purdue:
            score -= 150

        # 4. Break redundant cross-zone routing
        if edge_data.get("is_boundary_crossing"): score += 50

        # 5. ABSOLUTE PROTECTION: Never break an active attack path
        if (u, v) in self.attack_edges:
            score -= 1000

        return score

    def _resolve_cycles_semantically(self):
        """Resolves topological cycles while preserving operational feedback loops for the UI."""
        while not nx.is_directed_acyclic_graph(self.dag_view):
            try:
                cycle_edges = nx.find_cycle(self.dag_view, orientation='original')
                weakest_edge = None
                highest_removal_score = -float('inf')
                
                for u, v in cycle_edges:
                    edge_data = self.dag_view[u][v]
                    removal_score = self._score_edge_for_removal(u, v, edge_data)
                    
                    if removal_score > highest_removal_score:
                        highest_removal_score = removal_score
                        weakest_edge = (u, v, edge_data)

                u, v, data = weakest_edge
                self.dag_view.remove_edge(u, v)
                
                self.suppressed_edges.append({
                    "id": str(data.get("id", f"suppressed_{u}_{v}")),
                    "source": str(u),
                    "target": str(v),
                    "type": "straight",
                    "animated": False,
                    "data": {**data, "is_suppressed": True, "removal_reason": "cycle_resolution"}
                })
            except nx.NetworkXNoCycle:
                break

    def _generate_zone_conduit_dag(self):
        """Generates a macro-level ISA-62443 Zone-to-Zone dependency graph."""
        zone_nodes = {}
        zone_edges = []
        seen_conduits = set()

        for u, v, d in self.dag_view.edges(data=True):
            u_zone = self.dag_view.nodes[u].get("zone", "unassigned")
            v_zone = self.dag_view.nodes[v].get("zone", "unassigned")

            if u_zone not in zone_nodes:
                zone_nodes[u_zone] = {"id": f"macro_{u_zone}", "data": {"label": u_zone.replace("_", " ").title()}}
            if v_zone not in zone_nodes:
                zone_nodes[v_zone] = {"id": f"macro_{v_zone}", "data": {"label": v_zone.replace("_", " ").title()}}

            if u_zone != v_zone:
                conduit_id = f"{u_zone}->{v_zone}"
                if conduit_id not in seen_conduits:
                    zone_edges.append({
                        "id": f"macro_e_{u_zone}_{v_zone}",
                        "source": f"macro_{u_zone}",
                        "target": f"macro_{v_zone}",
                        "animated": True
                    })
                    seen_conduits.add(conduit_id)

        return {"nodes": list(zone_nodes.values()), "edges": zone_edges}

    def _generate_react_flow_payload(self):
        """Compiles X/Y UI coordinates with dynamic zone widths and deterministic sorting."""
        rf_nodes = []
        rf_edges = []
        
        zone_bounds = defaultdict(lambda: {"min_layer": float('inf'), "max_layer": 0, "max_nodes_per_layer": 0})
        zone_layer_nodes = defaultdict(lambda: defaultdict(list))
        
        for node_id, meta in self.layer_matrix.items():
            if not self.dag_view.has_node(node_id): continue
            layer_idx = meta.get("layer", 0)
            zone_id = meta.get("zone", "unassigned_zone")
            
            zone_layer_nodes[zone_id][layer_idx].append(node_id)
            zone_bounds[zone_id]["min_layer"] = min(zone_bounds[zone_id]["min_layer"], layer_idx)
            zone_bounds[zone_id]["max_layer"] = max(zone_bounds[zone_id]["max_layer"], layer_idx)

        # Calculate Dynamic Widths based on the widest layer in each zone
        for zone_id, layers in zone_layer_nodes.items():
            for layer_idx, nodes in layers.items():
                zone_bounds[zone_id]["max_nodes_per_layer"] = max(zone_bounds[zone_id]["max_nodes_per_layer"], len(nodes))
            
            zone_bounds[zone_id]["computed_width"] = max(
                MIN_ZONE_WIDTH, 
                (zone_bounds[zone_id]["max_nodes_per_layer"] * HORIZONTAL_NODE_SPACING) + (ZONE_PADDING * 2)
            )

        current_zone_x_offset = 0
        zone_x_anchors = {}

        # 1. Render Zone Containers dynamically sized
        for zone_id in sorted(zone_layer_nodes.keys()):
            zone_x_anchors[zone_id] = current_zone_x_offset
            width = zone_bounds[zone_id]["computed_width"]
            height = ((zone_bounds[zone_id]["max_layer"] - zone_bounds[zone_id]["min_layer"] + 1) * VERTICAL_SPACING)
            
            rf_nodes.append({
                "id": f"group_{zone_id}",
                "type": "group",
                "position": {"x": current_zone_x_offset, "y": (zone_bounds[zone_id]["min_layer"] * VERTICAL_SPACING) - ZONE_PADDING},
                "data": { "label": zone_id.replace("_", " ").title() },
                "style": { "width": width, "height": height }
            })
            current_zone_x_offset += width + ZONE_MARGIN 

        # Criticality Ranking for Deterministic Placement
        crit_rank = {"critical": 0, "high": 1, "medium": 2, "low": 3, "none": 4}

        # 2. Render Child Nodes (Sorted & Centered dynamically)
        for zone_id, layers in zone_layer_nodes.items():
            base_x = zone_x_anchors[zone_id] + ZONE_PADDING
            zone_width = zone_bounds[zone_id]["computed_width"]
            
            for layer_idx, nodes in layers.items():
                y_coord = layer_idx * VERTICAL_SPACING
                
                # Deterministic Sorting: Critical -> High -> Medium -> Low -> Alphabetical
                nodes.sort(key=lambda n: (
                    crit_rank.get(self.dag_view.nodes[n].get("criticality", "none"), 4),
                    n
                ))

                layer_width = len(nodes) * HORIZONTAL_NODE_SPACING
                start_x = base_x + (zone_width - layer_width) / 2 

                for i, node_id in enumerate(nodes):
                    meta = self.layer_matrix[node_id]
                    node_attrs = self.dag_view.nodes[node_id]
                    
                    rf_nodes.append({
                        "id": str(node_id),
                        "type": "icsNode",
                        "parentNode": f"group_{zone_id}",
                        "extent": "parent",
                        "position": { "x": start_x + (i * HORIZONTAL_NODE_SPACING) - base_x, "y": y_coord - ((zone_bounds[zone_id]["min_layer"] * VERTICAL_SPACING) - ZONE_PADDING) },
                        "data": {
                            **meta, 
                            **node_attrs,
                            "in_attack_path": node_id in self.attack_nodes 
                        }
                    })

        # 3. Render Edges
        for u, v, edge_attrs in self.dag_view.edges(data=True):
            in_attack_path = (u, v) in self.attack_edges
            rf_edges.append({
                "id": str(edge_attrs.get("id", f"e_{u}_{v}")),
                "source": str(u),
                "target": str(v),
                "type": "smoothstep",
                "animated": edge_attrs.get("edge_type") == "COMM_LINK" or in_attack_path,
                "data": {**edge_attrs, "in_attack_path": in_attack_path}
            })

        return rf_nodes, rf_edges

    def build(self):
        """Compiles the final dual-view payload (Asset DAG + Zone Conduit DAG)."""
        logger.info("Resolving cycles, calculating UI grouping coordinates, and sorting nodes...")
        
        self._resolve_cycles_semantically()
        rf_nodes, rf_edges = self._generate_react_flow_payload()
        macro_zone_view = self._generate_zone_conduit_dag()
        
        # Compile Purdue & Asset Stats
        purdue_levels = set()
        critical_count = 0
        physical_count = 0
        
        for n, d in self.dag_view.nodes(data=True):
            if "purdue_level" in d: purdue_levels.add(str(d["purdue_level"]))
            if d.get("criticality") == "critical": critical_count += 1
            if d.get("node_category") == "PHYSICAL_ASSET": physical_count += 1

        return {
            "react_flow_asset_view": {
                "nodes": rf_nodes,
                "edges": rf_edges,
                "suppressed_edges": self.suppressed_edges 
            },
            "react_flow_macro_zone_view": macro_zone_view,
            "layout_metadata": {
                "max_depth": max((m.get("layer", 0) for m in self.layer_matrix.values()), default=0),
                "zones_rendered": list(set(m.get("zone") for m in self.layer_matrix.values())),
                "purdue_levels_present": sorted(list(purdue_levels)),
                "critical_assets_count": critical_count,
                "physical_assets_count": physical_count
            }
        }