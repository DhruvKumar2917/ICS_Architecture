"""
Risk Scoring Engine for ICS Attack Paths.

Implements a multi-factor risk scoring model based on:
  - Target criticality and Purdue level
  - Access method (remote, VPN, direct)
  - Zone traversal (cross-zone attacks)
  - Firewall / enforcement point bypass
  - Path length (attack complexity)
  - Physical process exposure

Outputs structured risk records with severity classification
(CRITICAL / HIGH / MEDIUM / LOW) suitable for dashboard display.

Usage:
    from DAG.risk_engine import RiskEngine
    engine = RiskEngine(ics_graph)
    scored_paths = engine.score_attack_paths(raw_attack_paths)
"""

import logging
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Scoring Constants
# ---------------------------------------------------------------------------

# Criticality base scores
CRITICALITY_SCORES = {
    "critical": 40,
    "high":     30,
    "medium":   20,
    "low":      10,
}

# Purdue level bonuses (lower level = more dangerous target)
PURDUE_SCORES = {
    "level 0": 30,
    "level 1": 25,
    "level 2": 15,
    "level 3": 10,
    "level 4":  5,
}

# Edge type risk modifiers
EDGE_TYPE_SCORES = {
    "HUMAN_PERM":     10,   # Credential-based access adds risk
    "COMM_LINK":       5,   # Network hop
    "CYBER_PHYSICAL": 20,   # Cyber-physical bridge is very high risk
}

# Action-based risk additions
ACTION_RISK_MAP = {
    "remote_login":    15,
    "remote_access":   15,
    "vpn_access":      12,
    "modify_firewall": 18,
    "send_command":    20,
    "write_plc":       20,
    "program_plc":     20,
    "firmware_update": 18,
    "admin_access":    15,
    "inhibit":         18,
    "shutdown":        18,
    "block_command":   16,
}

# Severity thresholds
SEVERITY_THRESHOLDS = [
    (80, "CRITICAL"),
    (55, "HIGH"),
    (30, "MEDIUM"),
    (0,  "LOW"),
]


# ---------------------------------------------------------------------------
# Risk Engine
# ---------------------------------------------------------------------------

class RiskEngine:
    """
    Quantitative risk scorer for ICS attack paths.

    Accepts raw path analysis results (from ICSPathAnalyzer) and
    enriches them with structured risk scores, severity labels, and
    detailed per-factor breakdowns.
    """

    def __init__(self, ics_graph):
        self.ics_graph   = ics_graph
        self.asset_graph = ics_graph.asset_graph

    # ------------------------------------------------------------------ #
    # Internal helpers
    # ------------------------------------------------------------------ #

    def _get_node_attrs(self, node_id: str) -> Dict:
        if self.asset_graph.has_node(node_id):
            return dict(self.asset_graph.nodes[node_id])
        return {}

    def _target_criticality_score(self, path: List[str]) -> Dict[str, Any]:
        """Score based on the most critical asset and its Purdue level in the path."""
        best_crit_score = 0
        best_purdue_score = 0
        best_node = None
        best_crit = "low"
        best_purdue = "unknown"

        for node in path:
            attrs = self._get_node_attrs(node)
            crit = str(attrs.get("criticality", "low")).lower()
            purdue = str(attrs.get("purdue_level", "")).lower()

            crit_score = 5
            if crit == "critical":
                crit_score = 30
            elif crit == "high":
                crit_score = 20
            elif crit == "medium":
                crit_score = 10

            purdue_score = 5
            if "level 0" in purdue or "level 1" in purdue:
                purdue_score = 20
            elif "level 2" in purdue:
                purdue_score = 15
            elif "level 3" in purdue:
                purdue_score = 10

            node_total = crit_score + purdue_score
            if node_total > (best_crit_score + best_purdue_score):
                best_crit_score = crit_score
                best_purdue_score = purdue_score
                best_node = node
                best_crit = crit
                best_purdue = purdue

        total_crit = best_crit_score + best_purdue_score
        return {
            "score": total_crit,
            "node": best_node,
            "crit": best_crit,
            "purdue": best_purdue,
            "reason": f"Criticality score: {total_crit} (Target '{best_node}' criticality={best_crit.upper()}, purdue={best_purdue})",
        }

    def _cross_zone_score(self, path: List[str]) -> Dict[str, Any]:
        """Score cross-zone boundary traversals and IT-to-OT transitions."""
        total = 0
        reasons = []
        zones_seen = set()
        boundary_crossings = 0
        it_ot_pivot = False

        for i in range(len(path) - 1):
            u, v = path[i], path[i + 1]
            if not self.asset_graph.has_edge(u, v):
                continue
            edge_data = self.asset_graph[u][v]
            u_attrs = self.asset_graph.nodes[u]
            v_attrs = self.asset_graph.nodes[v]
            
            u_zone = u_attrs.get("zone", "?")
            v_zone = v_attrs.get("zone", "?")
            zones_seen.update([u_zone, v_zone])

            if edge_data.get("is_boundary_crossing") or (u_zone != v_zone and u_zone != "?" and v_zone != "?"):
                boundary_crossings += 1
                total += 10
                reasons.append(f"+10: Zone boundary crossed: {u_zone} → {v_zone}")

            # Detect IT-to-OT pivot: purdue level 3/4/5 -> purdue level <= 2
            try:
                def get_level_num(node_attrs):
                    p_level = str(node_attrs.get("purdue_level", "")).lower()
                    for lvl in ["level 5", "level 4", "level 3", "level 2", "level 1", "level 0"]:
                        if lvl in p_level:
                            return int(lvl[-1])
                    return None

                u_lvl = get_level_num(u_attrs)
                v_lvl = get_level_num(v_attrs)
                if u_lvl is not None and v_lvl is not None and u_lvl >= 3 and v_lvl <= 2:
                    it_ot_pivot = True
            except Exception:
                pass

        if it_ot_pivot:
            total += 20
            reasons.append("+20: IT-to-OT trust boundary pivot detected (Level >=3 to Level <=2)")

        # Cap cross-zone penalty at 40
        final_score = min(total, 40)
        return {
            "score": final_score,
            "zones_traversed": list(zones_seen),
            "reasons": reasons,
            "reason": f"Cross-zone penalty: {final_score} ({boundary_crossings} crossings, IT-OT pivot: {it_ot_pivot})"
        }

    def _physical_exposure_score(self, path: List[str]) -> Dict[str, Any]:
        """Physical impact score for paths reaching physical processes or safety systems."""
        total = 0
        reasons = []
        has_physical = False
        has_safety = False

        for node in path:
            attrs = self._get_node_attrs(node)
            node_type = str(attrs.get("type", "")).lower()
            category = attrs.get("node_category", "")

            if category == "PHYSICAL_ASSET" or node_type in ("plc", "sensor", "actuator"):
                has_physical = True
            if node_type == "safety_controller":
                has_safety = True

        if has_physical:
            total += 30
            reasons.append("+30: Direct physical controller or asset exposure (Level 0/1)")
        if has_safety:
            total += 15
            reasons.append("+15: Safety instrumentation system / safety controller exposure")

        # Cap physical impact at 45
        final_score = min(total, 45)
        return {
            "score": final_score,
            "reasons": reasons,
            "reason": f"Physical impact score: {final_score} (Physical asset: {has_physical}, Safety system: {has_safety})"
        }

    def _mitre_severity_score(self, path: List[str]) -> Dict[str, Any]:
        """Calculates MITRE severity contribution based on techniques along the path."""
        # Use the fast, local rule-based mapper for candidate path scoring
        # to avoid slow LLM API calls during path traversal timeouts.
        from DAG.mitre_mapper import MITREMapper
        mapper = MITREMapper(use_llm=False)
        
        # Map attack path hops to MITRE techniques
        hops = mapper.map_attack_path(path, self.ics_graph)
        
        severity_values = {"CRITICAL": 20, "HIGH": 15, "MEDIUM": 10, "LOW": 5}
        max_sev_value = 0
        max_tactic = "None"
        
        for hop in hops:
            mitre_data = hop.get("mitre", {})
            tactic = mitre_data.get("tactic", "Unknown")
            severity_str = mitre_data.get("severity", "LOW")
            sev_val = severity_values.get(severity_str, 5)
            if sev_val > max_sev_value:
                max_sev_value = sev_val
                max_tactic = tactic

        # Depth bonus to reflect complex tactic chains
        depth_bonus = min(len(hops) * 2, 15)
        total_mitre = max_sev_value + depth_bonus
        final_score = min(total_mitre, 35)

        return {
            "score": final_score,
            "max_tactic": max_tactic,
            "reason": f"MITRE severity score: {final_score} (Max tactic: {max_tactic}, Depth bonus: {depth_bonus})"
        }

    def _exposure_score(self, path: List[str]) -> Dict[str, Any]:
        """Exposure score based on remote ingress methods and firewall bypasses."""
        total = 0
        reasons = []
        remote_access = False
        firewall_bypass = False
        known_entry = False

        # 1. Detect remote / VPN actions on path
        for i in range(len(path) - 1):
            u, v = path[i], path[i + 1]
            if not self.asset_graph.has_edge(u, v):
                continue
            edge_data = self.asset_graph[u][v]
            label = str(edge_data.get("label", "")).lower()
            edge_type = edge_data.get("edge_type", "")

            for kw in ACTION_RISK_MAP.keys():
                if kw in label or kw in edge_type.lower():
                    remote_access = True
                    break

        if remote_access:
            total += 15
            reasons.append("+15: Remote / VPN / SSH access mechanism used on path")

        # 2. Detect firewall bypass (cross-zone but no enforcement points)
        ep_count = 0
        has_cross_zone = False
        for i in range(len(path) - 1):
            u, v = path[i], path[i + 1]
            if self.asset_graph.has_edge(u, v):
                if self.asset_graph[u][v].get("is_boundary_crossing"):
                    has_cross_zone = True

        for node in path:
            attrs = self._get_node_attrs(node)
            if attrs.get("is_enforcement_point") or attrs.get("type", "") == "firewall":
                ep_count += 1

        if has_cross_zone and ep_count == 0:
            firewall_bypass = True
            total += 20
            reasons.append("+20: Zone boundary crossing without passing through any firewall/enforcement points")

        # 3. Known entry point at start
        start_node = path[0]
        start_attrs = self._get_node_attrs(start_node)
        if start_attrs.get("security_role") == "ENTRY_POINT":
            known_entry = True
            total += 10
            reasons.append(f"+10: Path starts at designated external entry point '{start_node}'")

        final_score = min(total, 45)
        return {
            "score": final_score,
            "reasons": reasons,
            "reason": f"Exposure score: {final_score} (Remote: {remote_access}, Bypass: {firewall_bypass}, Known entry: {known_entry})"
        }

    def _classify_severity(self, score: float) -> str:
        """Map numeric risk score to severity label."""
        for threshold, label in SEVERITY_THRESHOLDS:
            if score >= threshold:
                return label
        return "LOW"

    # ------------------------------------------------------------------ #
    # Public API
    # ------------------------------------------------------------------ #

    def score_path(self, path: List[str]) -> Dict[str, Any]:
        """
        Compute a full risk breakdown for a single attack path.

        Returns a dict with:
          - total_risk_score (float, 0-100 scale)
          - severity         (CRITICAL | HIGH | MEDIUM | LOW)
          - score_breakdown  (per-factor contributions)
          - path             (original node sequence)
          - path_str         (human-readable arrow notation)
        """
        if len(path) < 2:
            return {
                "path": path,
                "path_str": " → ".join(path),
                "total_risk_score": 0,
                "severity": "LOW",
                "score_breakdown": {},
            }

        crit_result = self._target_criticality_score(path)
        zone_result = self._cross_zone_score(path)
        phys_result = self._physical_exposure_score(path)
        mitre_result = self._mitre_severity_score(path)
        exposure_result = self._exposure_score(path)

        raw_score = (
            crit_result["score"]
            + zone_result["score"]
            + phys_result["score"]
            + mitre_result["score"]
            + exposure_result["score"]
        )

        total_score = round(min(max(raw_score, 0), 100), 1)
        severity = self._classify_severity(total_score)

        return {
            "path":             path,
            "path_str":         " → ".join(str(n) for n in path),
            "total_risk_score": total_score,
            "severity":         severity,
            "score_breakdown": {
                "target_criticality": {
                    "score":  crit_result["score"],
                    "detail": crit_result["reason"],
                },
                "cross_zone_traversal": {
                    "score":           zone_result["score"],
                    "zones_traversed": zone_result["zones_traversed"],
                    "details":         zone_result["reasons"],
                },
                "physical_exposure": {
                    "score":   phys_result["score"],
                    "details": phys_result["reasons"],
                },
                "mitre_severity": {
                    "score":   mitre_result["score"],
                    "detail":  mitre_result["reason"],
                },
                "exposure": {
                    "score":   exposure_result["score"],
                    "details": exposure_result["reasons"],
                },
            },
        }

    def score_attack_paths(self, attack_paths: List[Dict]) -> List[Dict]:
        """
        Enrich a list of raw attack path records with risk scores.

        Args:
            attack_paths: Output from ICSPathAnalyzer.analyze_attack_paths()

        Returns:
            Same list with 'risk_score', 'severity', and 'score_breakdown' added,
            sorted by risk_score descending.
        """
        enriched = []
        for ap in attack_paths:
            path     = ap.get("path", [])
            risk_rec = self.score_path(path)

            merged = {**ap, **{
                "risk_score":      risk_rec["total_risk_score"],
                "severity":        risk_rec["severity"],
                "path_str":        risk_rec["path_str"],
                "score_breakdown": risk_rec["score_breakdown"],
            }}
            enriched.append(merged)

        enriched.sort(key=lambda x: x["risk_score"], reverse=True)
        logger.info(f"[RiskEngine] Scored {len(enriched)} attack paths. "
                    f"Top risk: {enriched[0]['risk_score'] if enriched else 0}")
        return enriched

    def rank_critical_nodes(self) -> List[Dict]:
        """
        Rank all nodes in the graph by their structural risk score.

        Useful for identifying 'crown jewel' assets or high-risk pivot points
        without needing full path analysis.
        """
        ranked = []
        for node, attrs in self.asset_graph.nodes(data=True):
            base_crit  = CRITICALITY_SCORES.get(str(attrs.get("criticality", "low")).lower(), 10)
            purdue     = str(attrs.get("purdue_level", "")).lower()
            purdue_score = 0
            for lvl, score in PURDUE_SCORES.items():
                if lvl in purdue:
                    purdue_score = score
                    break

            physical_bonus = 20 if attrs.get("node_category") == "PHYSICAL_ASSET" else 0
            ep_bonus       = 10 if attrs.get("is_enforcement_point") else 0
            # Connectivity bonus: highly connected nodes are more dangerous pivots
            in_deg  = self.asset_graph.in_degree(node)
            out_deg = self.asset_graph.out_degree(node)
            conn_bonus = min((in_deg + out_deg) * 2, 20)

            score    = base_crit + purdue_score + physical_bonus + ep_bonus + conn_bonus
            severity = self._classify_severity(score)

            ranked.append({
                "node":           node,
                "label":          attrs.get("label", node),
                "type":           attrs.get("type", "unknown"),
                "zone":           attrs.get("zone", "unknown"),
                "criticality":    attrs.get("criticality", "unknown"),
                "purdue_level":   attrs.get("purdue_level", "unknown"),
                "risk_score":     round(score, 1),
                "severity":       severity,
                "in_degree":      in_deg,
                "out_degree":     out_deg,
                "is_physical":    attrs.get("node_category") == "PHYSICAL_ASSET",
                "is_enforcement": attrs.get("is_enforcement_point", False),
            })

        ranked.sort(key=lambda x: x["risk_score"], reverse=True)
        return ranked
