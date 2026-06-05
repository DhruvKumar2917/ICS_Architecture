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
        """
        Calculates path confidence by multiplying edge confidence coefficients 
        and factoring in average node extraction confidence scores.
        """
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
        
        # Cumulative product of edge confidences scaled by average node confidence
        prod_edge_conf = 1.0
        for ec in edge_confidences:
            prod_edge_conf *= ec
            
        return round(prod_edge_conf * avg_node_conf, 2)

    def _classify_severity(self, target_node):
        """Categorizes operational impact severity based on the asset characteristics."""
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
        """Generates detailed architectural context describing the path traversal mechanics."""
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

    # ==========================================
    # PUBLIC API ENDPOINTS
    # ==========================================

    def check_cyber_to_physical_reachability(self, entry_points=None):
        """
        Validates whether any external or higher-level cyber entry points 
        can establish direct or multi-hop path connections to physical assets.
        """
        entries = entry_points or [n for n, d in self.asset_graph.nodes(data=True) if d.get("security_role") == "ENTRY_POINT"]
        physical_targets = [n for n, d in self.asset_graph.nodes(data=True) if d.get("node_category") == "PHYSICAL_ASSET"]
        
        critical_vectors = []
        
        for entry in entries:
            for target in physical_targets:
                if nx.has_path(self.asset_graph, entry, target):
                    path = nx.shortest_path(self.asset_graph, entry, target)
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
        """
        Aggregates individual asset interactions into an ISA-62443 
        conduit mapping of zone-to-zone reachability permissions.
        """
        zone_map = defaultdict(set)
        
        for source in self.asset_graph.nodes():
            src_zone = self.asset_graph.nodes[source].get("zone", "unassigned")
            descendants = nx.descendants(self.asset_graph, source)
            
            for dest in descendants:
                dest_zone = self.asset_graph.nodes[dest].get("zone", "unassigned")
                if src_zone != dest_zone:
                    zone_map[src_zone].add(dest_zone)
                    
        return {src: list(dests) for src, dests in zone_map.items()}

    def get_prioritized_reachability(self, source_node, min_confidence=0.0):
        """
        Returns a sorted, categorized overview of all assets exposed 
        from a source node, filtered by data confidence criteria.
        """
        if not self.asset_graph.has_node(source_node):
            return []

        cache_key = (source_node, min_confidence)
        if cache_key in self._route_cache:
            return self._route_cache[cache_key]

        reachable_targets = nx.descendants(self.asset_graph, source_node)
        prioritized_results = []

        for target in reachable_targets:
            path = nx.shortest_path(self.asset_graph, source_node, target)
            confidence = self._compute_path_confidence(path)
            
            if confidence < min_confidence:
                continue

            severity = self._classify_severity(target)
            explanation = self._generate_explanation(path)

            prioritized_results.append({
                "asset_id": target,
                "severity": severity,
                "confidence": confidence,
                "path": path,
                "explanation": explanation
            })

        # Sort criteria: Highest severity tier first, then by extraction confidence
        severity_weight = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}
        prioritized_results.sort(key=lambda x: (severity_weight.get(x["severity"], 0), x["confidence"]), reverse=True)
        
        self._route_cache[cache_key] = prioritized_results
        return prioritized_results