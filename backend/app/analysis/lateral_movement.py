"""
Lateral Movement Analyzer for ICS Security Graphs.
"""

import logging
from itertools import islice
from typing import Any, Dict, List, Optional, Set, Tuple

import networkx as nx

logger = logging.getLogger(__name__)

# Node types that indicate elevated privilege
HIGH_PRIVILEGE_TYPES = {
    "plc", "rtu", "safety_controller", "historian",
    "engineering", "scada", "server",
}

# Actions that represent remote / long-range access
REMOTE_ACTION_KEYWORDS = {
    "remote", "vpn", "ssh", "rdp", "telnet",
    "remote_login", "remote_access", "vpn_access",
}

# Protocol pivot pairs — switching from IT to OT protocol mid-path is suspicious
PROTOCOL_PIVOT_PAIRS = [
    ({"https", "http", "tcp", "udp", "ssh"},   {"modbus", "opc", "dnp3", "s7comm", "profinet", "iec61850"}),
    ({"modbus", "opc", "dnp3"},                {"io_link", "iolink", "hart", "profibus"}),
]


def _parse_purdue_level(level_str: str) -> Optional[int]:
    if not level_str:
        return None
    try:
        digits = "".join(filter(str.isdigit, str(level_str)))
        return int(digits) if digits else None
    except (ValueError, TypeError):
        return None


class LateralMovementAnalyzer:
    def __init__(self, ics_graph):
        self.ics_graph   = ics_graph
        self.asset_graph = ics_graph.asset_graph

    def _detect_cross_zone(self, u: str, v: str, edge_data: Dict) -> Optional[Dict]:
        u_zone = self.asset_graph.nodes[u].get("zone")
        v_zone = self.asset_graph.nodes[v].get("zone")

        if u_zone and v_zone and u_zone != v_zone:
            u_purdue = _parse_purdue_level(self.asset_graph.nodes[u].get("purdue_level"))
            v_purdue = _parse_purdue_level(self.asset_graph.nodes[v].get("purdue_level"))

            if u_purdue is not None and v_purdue is not None and u_purdue >= 3 and v_purdue <= 2:
                return {
                    "movement_type": "IT_OT_PIVOT",
                    "severity":      "CRITICAL",
                    "from_node":     u,
                    "to_node":       v,
                    "from_zone":     u_zone,
                    "to_zone":       v_zone,
                    "via":           str(edge_data.get("label", "unknown")),
                    "edge_type":     edge_data.get("edge_type", "COMM_LINK"),
                    "description":   f"Critical IT-to-OT pivot: attacker crosses from Enterprise/Operation zone '{u_zone}' (L{u_purdue}) to Industrial Control zone '{v_zone}' (L{v_purdue}).",
                }

            severity = "HIGH"
            v_type = str(self.asset_graph.nodes[v].get("type", "")).lower()
            if "safety" in str(v_zone).lower() or v_type == "safety_controller":
                severity = "CRITICAL"

            return {
                "movement_type": "CROSS_ZONE",
                "severity":      severity,
                "from_node":     u,
                "to_node":       v,
                "from_zone":     u_zone,
                "to_zone":       v_zone,
                "via":           str(edge_data.get("label", "unknown")),
                "edge_type":     edge_data.get("edge_type", "COMM_LINK"),
                "description":   f"Attacker moves from zone '{u_zone}' to '{v_zone}' — trust boundary crossed.",
            }
        return None

    def _detect_privilege_escalation(self, u: str, v: str, edge_data: Dict) -> Optional[Dict]:
        u_type = str(self.asset_graph.nodes[u].get("type", "")).lower()
        v_type = str(self.asset_graph.nodes[v].get("type", "")).lower()
        u_crit = str(self.asset_graph.nodes[u].get("criticality", "")).lower()
        v_crit = str(self.asset_graph.nodes[v].get("criticality", "")).lower()

        crit_rank = {"low": 0, "medium": 1, "high": 2, "critical": 3}
        u_rank = crit_rank.get(u_crit, 1)
        v_rank = crit_rank.get(v_crit, 1)

        v_is_high_priv = (v_type in HIGH_PRIVILEGE_TYPES) or (v_rank > u_rank)

        if v_is_high_priv and u_type not in HIGH_PRIVILEGE_TYPES:
            return {
                "movement_type": "PRIVILEGE_ESCALATION",
                "severity":      "CRITICAL" if v_type in {"plc", "safety_controller"} else "HIGH",
                "from_node":     u,
                "to_node":       v,
                "from_type":     u_type or "unknown",
                "to_type":       v_type or "unknown",
                "via":           str(edge_data.get("label", "unknown")),
                "edge_type":     edge_data.get("edge_type", "COMM_LINK"),
                "description":   (
                    f"Attacker pivots from '{u_type or u}' to high-privilege '{v_type or v}' "
                    f"(criticality: {u_crit} → {v_crit})"
                ),
            }
        return None

    def _detect_remote_access_chain(self, u: str, v: str, edge_data: Dict) -> Optional[Dict]:
        label  = str(edge_data.get("label", "")).lower()
        action = str(edge_data.get("action", "")).lower()

        is_remote = any(kw in label or kw in action for kw in REMOTE_ACTION_KEYWORDS)
        edge_type = edge_data.get("edge_type", "")

        if is_remote or (edge_type == "HUMAN_PERM" and any(kw in label for kw in REMOTE_ACTION_KEYWORDS)):
            u_zone = self.asset_graph.nodes[u].get("zone", "unknown")
            v_zone = self.asset_graph.nodes[v].get("zone", "unknown")
            return {
                "movement_type": "REMOTE_ACCESS_CHAIN",
                "severity":      "HIGH",
                "from_node":     u,
                "to_node":       v,
                "from_zone":     u_zone,
                "to_zone":       v_zone,
                "via":           label or "remote_link",
                "edge_type":     edge_type,
                "description":   (
                    f"Remote access from '{u}' ({u_zone}) to '{v}' ({v_zone}) "
                    f"via '{label or 'unknown protocol'}'"
                ),
            }
        return None

    def _detect_purdue_violation(self, u: str, v: str, edge_data: Dict) -> Optional[Dict]:
        u_purdue = _parse_purdue_level(self.asset_graph.nodes[u].get("purdue_level"))
        v_purdue = _parse_purdue_level(self.asset_graph.nodes[v].get("purdue_level"))

        if u_purdue is not None and v_purdue is not None:
            gap = abs(u_purdue - v_purdue)
            if gap > 1:
                return {
                    "movement_type": "PURDUE_VIOLATION",
                    "severity":      "CRITICAL" if gap >= 3 else "HIGH",
                    "from_node":     u,
                    "to_node":       v,
                    "from_level":    u_purdue,
                    "to_level":      v_purdue,
                    "level_gap":     gap,
                    "via":           str(edge_data.get("label", "unknown")),
                    "edge_type":     edge_data.get("edge_type", "COMM_LINK"),
                    "description":   (
                        f"Purdue model violation: L{u_purdue} directly to L{v_purdue} "
                        f"(skips {gap - 1} intermediate layers) — {u} → {v}"
                    ),
                }
        return None

    def _detect_protocol_pivot(
        self,
        path_edges: List[Tuple[str, str, Dict]],
    ) -> List[Dict]:
        pivots = []
        if len(path_edges) < 2:
            return pivots

        for i in range(len(path_edges) - 1):
            _, _, e1 = path_edges[i]
            u2, v2, e2 = path_edges[i + 1]

            proto1 = str(e1.get("label", "")).lower().replace("-", "_").replace(" ", "_")
            proto2 = str(e2.get("label", "")).lower().replace("-", "_").replace(" ", "_")

            for it_set, ot_set in PROTOCOL_PIVOT_PAIRS:
                if (any(p in proto1 for p in it_set) and any(p in proto2 for p in ot_set)):
                    pivots.append({
                        "movement_type": "PROTOCOL_PIVOT",
                        "severity":      "HIGH",
                        "from_node":     u2,
                        "to_node":       v2,
                        "from_protocol": proto1,
                        "to_protocol":   proto2,
                        "description":   (
                            f"Protocol pivot at '{u2}': IT protocol '{proto1}' → OT protocol '{proto2}'. "
                            f"Classic IT-to-OT bridging pattern."
                        ),
                    })
                    break

        return pivots

    def analyze_path_lateral_movement(self, path: List[str]) -> Dict[str, Any]:
        movements:   List[Dict] = []
        path_edges:  List[Tuple] = []

        for i in range(len(path) - 1):
            u, v = path[i], path[i + 1]
            if not self.asset_graph.has_edge(u, v):
                continue

            edge_data = dict(self.asset_graph[u][v])
            path_edges.append((u, v, edge_data))

            for rule_fn in [
                self._detect_cross_zone,
                self._detect_privilege_escalation,
                self._detect_remote_access_chain,
                self._detect_purdue_violation,
            ]:
                result = rule_fn(u, v, edge_data)
                if result:
                    movements.append(result)

        movements.extend(self._detect_protocol_pivot(path_edges))

        sev_order = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}
        max_sev = max(
            (m.get("severity", "LOW") for m in movements),
            key=lambda s: sev_order.get(s, 0),
            default="LOW",
        ) if movements else "LOW"

        unique_types = list({m["movement_type"] for m in movements})

        return {
            "path":           path,
            "path_str":       " → ".join(str(n) for n in path),
            "movements":      movements,
            "movement_count": len(movements),
            "movement_types": unique_types,
            "max_severity":   max_sev,
            "is_lateral":     len(movements) > 0,
        }

    def analyze(self, top_paths: int = 5) -> Dict[str, Any]:
        entries  = list(self.ics_graph.entry_points)
        targets  = list(
            self.ics_graph.critical_assets | self.ics_graph.physical_targets
        ) or [
            n for n, d in self.asset_graph.out_degree()
            if d == 0 and self.asset_graph.in_degree(n) > 0
        ]

        all_events:  List[Dict]   = []
        path_reports: List[Dict]  = []

        for u, v, edge_data in self.asset_graph.edges(data=True):
            edata = dict(edge_data)
            for rule_fn in [
                self._detect_cross_zone,
                self._detect_privilege_escalation,
                self._detect_remote_access_chain,
                self._detect_purdue_violation,
            ]:
                result = rule_fn(u, v, edata)
                if result:
                    all_events.append(result)

        if entries and targets:
            for entry in entries[:5]:
                for target in targets[:5]:
                    try:
                        if not nx.has_path(self.asset_graph, entry, target):
                            continue
                        gen = nx.shortest_simple_paths(self.asset_graph, entry, target)
                        for path in islice(gen, top_paths):
                            if len(path) < 2:
                                continue
                            report = self.analyze_path_lateral_movement(path)
                            if report["is_lateral"]:
                                path_reports.append(report)
                                for mv in report["movements"]:
                                    if mv["movement_type"] == "PROTOCOL_PIVOT":
                                        all_events.append(mv)
                    except (nx.NetworkXNoPath, nx.NetworkXError):
                        pass

        seen_keys: Set[str] = set()
        unique_events: List[Dict] = []
        for ev in all_events:
            key = f"{ev['movement_type']}|{ev.get('from_node','')}|{ev.get('to_node','')}"
            if key not in seen_keys:
                seen_keys.add(key)
                unique_events.append(ev)

        type_counts: Dict[str, int] = {}
        for ev in unique_events:
            mt = ev["movement_type"]
            type_counts[mt] = type_counts.get(mt, 0) + 1

        path_reports.sort(key=lambda x: x["movement_count"], reverse=True)

        logger.info(
            f"[LateralMovement] {len(unique_events)} total movement events, "
            f"types={type_counts}, {len(path_reports)} lateral paths found."
        )

        return {
            "movement_events":            unique_events,
            "total_movement_events":      len(unique_events),
            "cross_zone_count":           type_counts.get("CROSS_ZONE", 0),
            "it_ot_pivot_count":          type_counts.get("IT_OT_PIVOT", 0),
            "privilege_escalation_count": type_counts.get("PRIVILEGE_ESCALATION", 0),
            "remote_chain_count":         type_counts.get("REMOTE_ACCESS_CHAIN", 0),
            "purdue_violation_count":     type_counts.get("PURDUE_VIOLATION", 0),
            "protocol_pivot_count":       type_counts.get("PROTOCOL_PIVOT", 0),
            "high_risk_paths":            path_reports[:top_paths],
            "summary": {
                "has_cross_zone_movement":  type_counts.get("CROSS_ZONE", 0) > 0,
                "has_it_ot_pivots":         type_counts.get("IT_OT_PIVOT", 0) > 0,
                "has_privilege_escalation": type_counts.get("PRIVILEGE_ESCALATION", 0) > 0,
                "has_remote_chains":        type_counts.get("REMOTE_ACCESS_CHAIN", 0) > 0,
                "has_purdue_violations":    type_counts.get("PURDUE_VIOLATION", 0) > 0,
                "has_protocol_pivots":      type_counts.get("PROTOCOL_PIVOT", 0) > 0,
            },
        }
