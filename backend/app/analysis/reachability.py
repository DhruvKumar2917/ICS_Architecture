import logging
import math
import networkx as nx
from collections import defaultdict

logger = logging.getLogger(__name__)

class AdvancedICSReachabilityEngine:
    """
    Advanced ICS Reachability Engine featuring confidence propagation,
    severity classification, zone-to-zone maps, and cyber-to-physical validation.
    """
    def __init__(self, ics_graph):
        self.ics_graph = ics_graph
        self.asset_graph = ics_graph.asset_graph
        self._route_cache = {}

    def _compute_path_confidence(self, path):
        if not path:
            return 0.0
            
        edge_confidences = []
        node_confidences = []
        
        for i, node in enumerate(path):
            node_confidences.append(self.asset_graph.nodes[node].get("confidence", 1.0))
            if i < len(path) - 1:
                edge_data = self.asset_graph[path[i]][path[i+1]]
                edge_confidences.append(edge_data.get("confidence", 1.0))
                
        avg_node_conf = sum(node_confidences) / len(node_confidences)
        
        prod_edge_conf = 1.0
        for ec in edge_confidences:
            prod_edge_conf *= ec
            
        return round(prod_edge_conf * avg_node_conf, 2)

    def _classify_severity(self, target_node):
        attrs = self.asset_graph.nodes[target_node]
        category = attrs.get("node_category", "UNKNOWN")
        criticality = attrs.get("criticality", "medium")
        purdue = str(attrs.get("purdue_level", "")).lower()

        if category == "PHYSICAL_ASSET" or "level 0" in purdue or "level 1" in purdue:
            return "CRITICAL"
        if "level 3" in purdue or criticality == "critical":
            return "HIGH"
        if "level 2" in purdue or category == "CYBER_ASSET":
            return "MEDIUM"
        return "LOW"

    def _generate_explanation(self, path):
        boundaries = 0
        enforcement_points = 0
        purdue_levels = set()
        
        for i, node in enumerate(path):
            attrs = self.asset_graph.nodes[node]
            p_level = attrs.get("purdue_level")
            if p_level:
                purdue_levels.add(str(p_level))
                
            if attrs.get("is_enforcement_point"):
                enforcement_points += 1
                
            if i < len(path) - 1:
                if self.asset_graph[path[i]][path[i+1]].get("is_boundary_crossing"):
                    boundaries += 1

        return {
            "summary": f"Traverses layers {', '.join(sorted(list(purdue_levels)))} across {boundaries} trust boundaries.",
            "boundaries_crossed_count": boundaries,
            "enforcement_points_encountered": enforcement_points,
            "purdue_levels_traversed": sorted(list(purdue_levels))
        }

    def check_cyber_to_physical_reachability(self, entry_points=None):
        entries = entry_points or [n for n, d in self.asset_graph.nodes(data=True) if d.get("security_role") == "ENTRY_POINT"]
        physical_targets = [n for n, d in self.asset_graph.nodes(data=True) if d.get("node_category") == "PHYSICAL_ASSET"]
        
        critical_vectors = []
        
        comm_graph = nx.DiGraph()
        for u, v, d in self.asset_graph.edges(data=True):
            if d.get("edge_type") == "COMM_LINK":
                comm_graph.add_edge(u, v)

        for entry in entries:
            for target in physical_targets:
                if nx.has_path(self.asset_graph, entry, target):
                    path = nx.shortest_path(self.asset_graph, entry, target)
                    
                    is_reachable = True
                    cyber_nodes = [n for n in path if self.asset_graph.nodes[n].get("node_category") == "CYBER_ASSET"]
                    for idx in range(len(cyber_nodes) - 1):
                        u_cyber = cyber_nodes[idx]
                        v_cyber = cyber_nodes[idx+1]
                        if u_cyber != v_cyber and not nx.has_path(comm_graph, u_cyber, v_cyber):
                            is_reachable = False
                            break
                            
                    if not is_reachable:
                        continue
                        
                    confidence = self._compute_path_confidence(path)
                    
                    critical_vectors.append({
                        "source": entry,
                        "target": target,
                        "path_length": len(path) - 1,
                        "confidence": confidence,
                        "explanation": self._generate_explanation(path)
                    })
                    
        return sorted(critical_vectors, key=lambda x: (x["confidence"], -x["path_length"]), reverse=True)

    def compute_zone_to_zone_matrix(self):
        zone_map = defaultdict(set)
        
        for source in self.asset_graph.nodes():
            src_zone = self.asset_graph.nodes[source].get("zone", "unassigned")
            descendants = nx.descendants(self.asset_graph, source)
            
            for dest in descendants:
                dest_zone = self.asset_graph.nodes[dest].get("zone", "unassigned")
                if src_zone != dest_zone:
                    zone_map[src_zone].add(dest_zone)
                    
        return {src: list(dests) for src, dests in zone_map.items()}
