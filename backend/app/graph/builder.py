import logging
import networkx as nx
from collections import defaultdict

logger = logging.getLogger(__name__)

class ICSSecurityGraph:
    """
    An ISA-62443 aware security model managing parallel asset and zone topologies.
    Tracks risk scores, trust boundaries, and structural attack roles natively.
    """
    def __init__(self):
        self.asset_graph = nx.DiGraph()
        self.zone_graph = nx.DiGraph()
        
        self.indexes = {
            "by_zone": defaultdict(list),
            "by_criticality": defaultdict(list),
            "by_purdue_level": defaultdict(list),
            "by_node_category": defaultdict(list),
            "by_security_role": defaultdict(list)
        }
        
        self.entry_points = set()
        self.enforcement_points = set()
        self.critical_assets = set()
        self.physical_targets = set()

        self.validation_report = {
            "missing_nodes": set(),
            "orphan_nodes": set(),
            "duplicate_nodes": set(),
            "cross_zone_leaks": []
        }

    def _calculate_risk_score(self, attributes):
        crit_map = {"critical": 40, "high": 30, "medium": 20, "low": 10}
        base_crit = crit_map.get(str(attributes.get("criticality")).lower(), 20)
        
        purdue_map = {"level 0": 30, "level 1": 30, "level 2": 20, "level 3": 10}
        purdue_bonus = purdue_map.get(str(attributes.get("purdue_level")).lower(), 0)
        
        multiplier = 1.0
        if attributes.get("node_category") == "PHYSICAL_ASSET":
            multiplier += 0.5
        if attributes.get("is_enforcement_point"):
            multiplier += 0.2

        return float((base_crit + purdue_bonus) * multiplier)

    def _classify_security_role(self, node_id, attributes):
        category = attributes.get("node_category")
        node_type = str(attributes.get("type", "")).lower()
        purdue = str(attributes.get("purdue_level", "")).lower()

        if category == "HUMAN_ACTOR" or attributes.get("zone") == "external_transit":
            return "ENTRY_POINT"

        if attributes.get("is_enforcement_point") or node_type in ["firewall", "vpn", "gateway"]:
            return "BOUNDARY_DEVICE"

        if (category == "PHYSICAL_ASSET"
                or node_type in ["plc", "rtu", "safety_controller", "sensor", "actuator"]
                or "level 0" in purdue or "level 1" in purdue):
            return "FINAL_TARGET"

        if (node_type in ["scada", "hmi", "historian", "server", "workstation", "engineering"]
                or "level 2" in purdue or "level 3" in purdue):
            return "PIVOT_POINT"

        return "GENERIC_NODE"

    def add_node_with_semantics(self, node_id, attributes):
        if self.asset_graph.has_node(node_id):
            self.validation_report["duplicate_nodes"].add(node_id)

        attributes["risk_score"] = self._calculate_risk_score(attributes)
        attributes["security_role"] = self._classify_security_role(node_id, attributes)

        self.asset_graph.add_node(node_id, **attributes)

        role = attributes["security_role"]
        if role == "ENTRY_POINT": self.entry_points.add(node_id)
        elif role == "BOUNDARY_DEVICE": self.enforcement_points.add(node_id)
        elif role == "FINAL_TARGET": self.physical_targets.add(node_id)
        
        if attributes.get("criticality") == "critical":
            self.critical_assets.add(node_id)

        self.indexes["by_zone"][attributes.get("zone")].append(node_id)
        self.indexes["by_criticality"][attributes.get("criticality")].append(node_id)
        self.indexes["by_purdue_level"][attributes.get("purdue_level")].append(node_id)
        self.indexes["by_node_category"][attributes.get("node_category")].append(node_id)
        self.indexes["by_security_role"][role].append(node_id)

    def add_edge_with_semantics(self, edge_id, source, target, attributes):
        if not source or not target: return

        if not self.asset_graph.has_node(source):
            self.validation_report["missing_nodes"].add(source)
            self.add_node_with_semantics(source, {"label": source, "type": "inferred_node", "node_category": "CYBER_ASSET"})
        if not self.asset_graph.has_node(target):
            self.validation_report["missing_nodes"].add(target)
            self.add_node_with_semantics(target, {"label": target, "type": "inferred_node", "node_category": "CYBER_ASSET"})

        source_zone = self.asset_graph.nodes[source].get("zone")
        target_zone = self.asset_graph.nodes[target].get("zone")

        if source_zone and target_zone and source_zone != target_zone:
            attributes["is_boundary_crossing"] = True
            attributes["boundary_pair"] = (source_zone, target_zone)
            
            if not self.zone_graph.has_edge(source_zone, target_zone):
                self.zone_graph.add_edge(source_zone, target_zone, links=[edge_id], conduit_type=attributes.get("edge_type"))
            else:
                self.zone_graph[source_zone][target_zone]["links"].append(edge_id)

            src_zone_has_ep = any(
                self.asset_graph.nodes[node].get("is_enforcement_point")
                for node in self.indexes["by_zone"].get(source_zone, [])
            )
            tgt_zone_has_ep = any(
                self.asset_graph.nodes[node].get("is_enforcement_point")
                for node in self.indexes["by_zone"].get(target_zone, [])
            )
            is_enforced = (
                self.asset_graph.nodes[source].get("is_enforcement_point") or
                self.asset_graph.nodes[target].get("is_enforcement_point") or
                src_zone_has_ep or
                tgt_zone_has_ep
            )
            if not is_enforced:
                if self.enforcement_points:
                    ep_node = sorted(list(self.enforcement_points))[0]
                    ep_attrs_src = attributes.copy()
                    ep_attrs_src["is_inferred_routing"] = True
                    ep_attrs_src["inference_reason"] = "cross_zone_enforcement_interception"
                    ep_source_zone = self.asset_graph.nodes[source].get("zone")
                    ep_target_zone = self.asset_graph.nodes[ep_node].get("zone")
                    ep_attrs_src["is_boundary_crossing"] = (ep_source_zone != ep_target_zone)
                    if ep_attrs_src["is_boundary_crossing"]:
                        ep_attrs_src["boundary_pair"] = (ep_source_zone, ep_target_zone)
                    self.asset_graph.add_edge(source, ep_node, id=f"{edge_id}_to_ep", **ep_attrs_src)

                    ep_attrs_tgt = attributes.copy()
                    ep_attrs_tgt["is_inferred_routing"] = True
                    ep_attrs_tgt["inference_reason"] = "cross_zone_enforcement_interception"
                    ep_source_zone2 = self.asset_graph.nodes[ep_node].get("zone")
                    ep_target_zone2 = self.asset_graph.nodes[target].get("zone")
                    ep_attrs_tgt["is_boundary_crossing"] = (ep_source_zone2 != ep_target_zone2)
                    if ep_attrs_tgt["is_boundary_crossing"]:
                        ep_attrs_tgt["boundary_pair"] = (ep_source_zone2, ep_target_zone2)
                    self.asset_graph.add_edge(ep_node, target, id=f"ep_to_{edge_id}", **ep_attrs_tgt)
                    
                    print(f"  [graph_builder] Routed cross-zone leak {source} -> {target} through enforcement point {ep_node}", flush=True)
                    return
                else:
                    self.validation_report["cross_zone_leaks"].append({
                        "edge_id": edge_id, "source": source, "target": target, "from_zone": source_zone, "to_zone": target_zone
                    })
        else:
            attributes["is_boundary_crossing"] = False

        self.asset_graph.add_edge(source, target, id=edge_id, **attributes)

    def finalize_model(self):
        for node in self.asset_graph.nodes():
            if self.asset_graph.degree(node) == 0:
                self.validation_report["orphan_nodes"].add(node)


def build_graph(data):
    model = ICSSecurityGraph()
    if not data: return model

    for zone in data.get("zones", []):
        z_id = zone.get("id")
        if z_id:
            model.zone_graph.add_node(z_id, label=zone.get("name"), parent_zone=zone.get("parent_zone"), type="ZONE")

    for asset in data.get("assets", []):
        a_id = asset.get("id")
        if not a_id: continue
        model.add_node_with_semantics(a_id, {
            "label": asset.get("name", "Unknown Asset"),
            "type": asset.get("type", "unknown"),
            "node_category": "CYBER_ASSET",
            "zone": asset.get("zone"),
            "criticality": asset.get("criticality", "medium"),
            "purdue_level": asset.get("purdue_level", "unknown"),
            "is_enforcement_point": asset.get("is_enforcement_point", False)
        })

    for role in data.get("roles", []):
        r_id = role.get("id")
        if not r_id: continue
        model.add_node_with_semantics(r_id, {
            "label": role.get("name", "Operator Role"),
            "type": "operator",
            "node_category": "HUMAN_ACTOR",
            "zone": "external_transit",
            "criticality": "high",
            "purdue_level": "unmapped"
        })

    for phys in data.get("physical_dependencies", []):
        p_id = phys.get("physical_process")
        if not p_id or model.asset_graph.has_node(p_id): continue
        model.add_node_with_semantics(p_id, {
            "label": p_id.replace("_", " ").title(),
            "type": "physical_process",
            "node_category": "PHYSICAL_ASSET",
            "zone": "turbine_local_control",
            "criticality": "critical",
            "purdue_level": "Level 0"
        })

    for i, comm in enumerate(data.get("communications", [])):
        model.add_edge_with_semantics(f"comm_{i}", comm.get("source"), comm.get("target"), {
            "label": comm.get("protocol", "network_traffic"),
            "edge_type": "COMM_LINK",
            "empirical_edge_type": comm.get("edge_type", "assumption-based")
        })

    for i, perm in enumerate(data.get("permissions", [])):
        model.add_edge_with_semantics(f"perm_{i}", perm.get("subject"), perm.get("object"), {
            "label": perm.get("action", "access"),
            "edge_type": "HUMAN_PERM",
            "empirical_edge_type": perm.get("edge_type", "policy-enforced")
        })

    for i, phys in enumerate(data.get("physical_dependencies", [])):
        model.add_edge_with_semantics(f"phys_{i}", phys.get("cyber_asset"), phys.get("physical_process"), {
            "label": phys.get("relationship", "controls"),
            "edge_type": "CYBER_PHYSICAL",
            "empirical_edge_type": "assumption-based"
        })

    model.finalize_model()
    return model
