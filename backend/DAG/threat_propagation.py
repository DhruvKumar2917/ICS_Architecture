"""
Threat Propagation Simulator for ICS Networks.

Models how malware or attacker control spreads through the ICS network
after an initial node compromise. Uses BFS (Breadth-First Search) for
layered propagation simulation and DFS for deep infection chain analysis.

Distinguishes from attack paths:
  - Attack path = possible route (planned attacker movement)
  - Threat propagation = simulated infection spread (worm/malware behaviour)

Key outputs:
  - propagation_tree: BFS tree rooted at the infection origin
  - affected_zones:   zones reached by propagation
  - spread_depth:     how many hops the infection spreads
  - propagation_timeline: step-by-step simulation

Usage:
    from DAG.threat_propagation import ThreatPropagator
    propagator = ThreatPropagator(ics_graph)
    result = propagator.simulate(origin_node="OEM_SCADA_Server")
"""

import logging
from collections import deque
from typing import Any, Dict, List, Optional, Set

import networkx as nx

logger = logging.getLogger(__name__)

# Propagation speed modifiers per edge type
# (how easily the threat spreads across that edge)
PROPAGATION_WEIGHTS = {
    "COMM_LINK":      1.0,   # Network connection → easy spread
    "CYBER_PHYSICAL": 0.8,   # Cyber-physical → slower but possible
    "HUMAN_PERM":     0.5,   # Credential-based → conditional spread
}

# Node categories that act as propagation barriers (slow spread)
BARRIER_TYPES = {"firewall", "vpn", "gateway"}

# Maximum default propagation depth (configurable)
DEFAULT_MAX_DEPTH = 10


class ThreatPropagator:
    """
    Simulates infection/malware spread across the ICS Security Graph.

    Uses BFS for layered simulation (each BFS layer = one propagation step).
    Tracks:
      - Which nodes get infected at each depth level
      - Zone crossings during propagation
      - Whether enforcement points were bypassed
      - Final impact metrics
    """

    def __init__(self, ics_graph):
        self.ics_graph   = ics_graph
        self.asset_graph = ics_graph.asset_graph

    # ------------------------------------------------------------------ #
    # Internal helpers
    # ------------------------------------------------------------------ #

    def _propagation_probability(self, u: str, v: str) -> float:
        """
        Estimate the probability of threat spreading from u to v.
        Incorporates edge weights, firewall resistance, privilege/security levels, and zone boundaries.
        """
        if not self.asset_graph.has_edge(u, v):
            return 0.0

        edge_data = self.asset_graph[u][v]
        edge_type = edge_data.get("edge_type", "COMM_LINK")
        
        # 1. Edge-type base probability
        # Network Comm link is easy; cyber-physical or human credential-based is harder
        base_weights = {
            "COMM_LINK":      0.9,
            "CYBER_PHYSICAL": 0.5,
            "HUMAN_PERM":     0.4
        }
        prob = base_weights.get(edge_type, 0.6)

        u_attrs = self.asset_graph.nodes[u]
        v_attrs = self.asset_graph.nodes[v]
        v_type = str(v_attrs.get("type", "")).lower()

        # 2. Firewall / Enforcement Point Resistance
        if v_attrs.get("is_enforcement_point") or v_type in BARRIER_TYPES or v_type == "firewall":
            prob *= 0.25  # Firewalls/enforcement points heavily resist propagation

        # 3. Privilege / Security Level Resistance
        # Critical assets have higher defenses
        if str(v_attrs.get("criticality", "")).lower() == "critical":
            prob *= 0.7

        # Purdue level drop (moving deeper into control levels requires protocol pivot)
        try:
            def get_level(node_attrs):
                lvl_str = str(node_attrs.get("purdue_level", "")).lower()
                for lvl in ["level 5", "level 4", "level 3", "level 2", "level 1", "level 0"]:
                    if lvl in lvl_str:
                        return int(lvl[-1])
                return None

            u_p = get_level(u_attrs)
            v_p = get_level(v_attrs)
            if u_p is not None and v_p is not None and u_p > v_p:
                prob *= 0.8  # Crossing down into OT control levels is more resistant
        except Exception:
            pass

        # 4. Zone / Boundary Penalties
        u_zone = u_attrs.get("zone", "?")
        v_zone = v_attrs.get("zone", "?")
        if edge_data.get("is_boundary_crossing") or (u_zone != v_zone and u_zone != "?" and v_zone != "?"):
            prob *= 0.6  # Inter-zone traversal reduces probability

            # Check if IT-to-OT pivot
            try:
                if u_p is not None and v_p is not None and u_p >= 3 and v_p <= 2:
                    prob *= 0.4  # Severe penalty for IT-to-OT crossing
            except Exception:
                pass

        return round(max(prob, 0.0), 3)

    def _classify_node_impact(self, node: str) -> str:
        """Classify the impact of infecting a node."""
        attrs    = self.asset_graph.nodes[node]
        category = attrs.get("node_category", "")
        crit     = str(attrs.get("criticality", "")).lower()

        if category == "PHYSICAL_ASSET":
            return "PHYSICAL_IMPACT"
        if crit == "critical":
            return "CRITICAL_SYSTEM"
        if attrs.get("is_enforcement_point"):
            return "SECURITY_CONTROL_BYPASSED"
        if category == "CYBER_ASSET":
            return "OPERATIONAL_IMPACT"
        return "MINOR_IMPACT"

    # ------------------------------------------------------------------ #
    # BFS Propagation Simulation
    # ------------------------------------------------------------------ #

    def simulate(
        self,
        origin_node:  str,
        max_depth:    int  = DEFAULT_MAX_DEPTH,
        min_prob:     float = 0.1,
        only_comm:    bool  = False,
    ) -> Dict[str, Any]:
        """
        Simulate threat propagation from a single compromised origin node.

        Args:
            origin_node: The initially compromised node ID.
            max_depth:   Maximum propagation depth.
            min_prob:    Minimum probability threshold to allow propagation.
            only_comm:   If True, spread only through COMM_LINK edges
                         (simulates network worm, not credential propagation).

        Returns:
            Structured propagation report dict.
        """
        if not self.asset_graph.has_node(origin_node):
            return {
                "error": f"Node '{origin_node}' not found in graph.",
                "infection_origin": origin_node,
            }

        visited:   Dict[str, int]   = {origin_node: 0}   # node → depth infected
        queue:     deque             = deque([(origin_node, 0)])
        timeline:  List[Dict]        = []
        zones_hit: Set[str]          = set()

        origin_zone = self.asset_graph.nodes[origin_node].get("zone", "unknown")
        zones_hit.add(origin_zone)

        timeline.append({
            "step":          0,
            "depth":         0,
            "infected_node": origin_node,
            "from_node":     None,
            "probability":   1.0,
            "impact":        self._classify_node_impact(origin_node),
            "zone":          origin_zone,
        })

        propagation_tree: Dict[str, List[str]] = {origin_node: []}  # parent → [children]
        max_reached_depth = 0

        while queue:
            current, depth = queue.popleft()

            if depth >= max_depth:
                continue

            neighbors = list(self.asset_graph.successors(current))
            for neighbor in neighbors:
                if neighbor in visited:
                    continue

                edge_data  = self.asset_graph[current][neighbor]
                edge_type  = edge_data.get("edge_type", "COMM_LINK")

                if only_comm and edge_type not in ("COMM_LINK", "CYBER_PHYSICAL"):
                    continue

                prob = self._propagation_probability(current, neighbor)
                if prob < min_prob:
                    continue

                next_depth = depth + 1
                visited[neighbor]  = next_depth
                max_reached_depth  = max(max_reached_depth, next_depth)

                n_zone = self.asset_graph.nodes[neighbor].get("zone", "unknown")
                zones_hit.add(n_zone)

                propagation_tree.setdefault(current, []).append(neighbor)
                propagation_tree.setdefault(neighbor, [])

                timeline.append({
                    "step":          len(timeline),
                    "depth":         next_depth,
                    "infected_node": neighbor,
                    "from_node":     current,
                    "probability":   prob,
                    "impact":        self._classify_node_impact(neighbor),
                    "zone":          n_zone,
                    "edge_type":     edge_type,
                })

                queue.append((neighbor, next_depth))

        # Summarise affected nodes by category
        affected_nodes  = [n for n in visited if n != origin_node]
        physical_nodes  = [
            n for n in affected_nodes
            if self.asset_graph.nodes[n].get("node_category") == "PHYSICAL_ASSET"
        ]
        critical_nodes  = [
            n for n in affected_nodes
            if str(self.asset_graph.nodes[n].get("criticality", "")).lower() == "critical"
        ]
        ep_bypassed     = [
            n for n in affected_nodes
            if self.asset_graph.nodes[n].get("is_enforcement_point")
        ]

        # Compute aggregate impact score (0–100)
        impact_score = min(
            (len(affected_nodes) * 5)
            + (len(physical_nodes) * 20)
            + (len(critical_nodes) * 10)
            + (len(ep_bypassed) * 15)
            + (len(zones_hit) * 8),
            100,
        )

        logger.info(
            f"[ThreatPropagator] Origin='{origin_node}', "
            f"depth={max_reached_depth}, nodes={len(affected_nodes)}, "
            f"zones={len(zones_hit)}, score={impact_score}"
        )

        return {
            "infection_origin":   origin_node,
            "spread_depth":       max_reached_depth,
            "total_affected":     len(visited),  # includes origin
            "affected_nodes":     affected_nodes,
            "physical_nodes_hit": physical_nodes,
            "critical_nodes_hit": critical_nodes,
            "enforcement_bypassed": ep_bypassed,
            "zones_compromised":  list(zones_hit),
            "impact_score":       impact_score,
            "propagation_tree":   propagation_tree,
            "propagation_timeline": timeline,
            "simulation_params": {
                "max_depth":  max_depth,
                "min_prob":   min_prob,
                "only_comm":  only_comm,
            },
        }

    def simulate_multi_origin(
        self,
        origin_nodes: List[str],
        max_depth: int = DEFAULT_MAX_DEPTH,
        min_prob:  float = 0.1,
    ) -> Dict[str, Any]:
        """
        Simulate independent threat propagation from multiple origins
        and merge the results into a combined impact report.
        """
        individual_results = []
        union_affected: Set[str] = set()
        union_zones:    Set[str] = set()

        for origin in origin_nodes:
            result = self.simulate(origin, max_depth=max_depth, min_prob=min_prob)
            individual_results.append(result)
            union_affected.update(result.get("affected_nodes", []))
            union_zones.update(result.get("zones_compromised", []))

        return {
            "origins":          origin_nodes,
            "union_affected":   list(union_affected),
            "union_zones":      list(union_zones),
            "total_unique_affected": len(union_affected),
            "individual_simulations": individual_results,
        }

    def compute_propagation_risk_matrix(self) -> List[Dict]:
        """
        Compute propagation risk for every node in the graph as a potential
        infection origin. Useful for risk-ranking 'most dangerous to compromise' nodes.

        Returns a list sorted by impact_score descending.
        """
        matrix = []
        for node in self.asset_graph.nodes():
            result = self.simulate(node, max_depth=6, min_prob=0.15)
            matrix.append({
                "node":           node,
                "label":          self.asset_graph.nodes[node].get("label", node),
                "zone":           self.asset_graph.nodes[node].get("zone", "unknown"),
                "spread_depth":   result.get("spread_depth", 0),
                "total_affected": result.get("total_affected", 0),
                "physical_hit":   len(result.get("physical_nodes_hit", [])),
                "critical_hit":   len(result.get("critical_nodes_hit", [])),
                "impact_score":   result.get("impact_score", 0),
            })

        matrix.sort(key=lambda x: x["impact_score"], reverse=True)
        return matrix
