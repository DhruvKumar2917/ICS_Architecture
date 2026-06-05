import logging
import time
import networkx as nx
from itertools import islice

logger = logging.getLogger(__name__)

class ICSPathAnalyzer:
    """
    Quantitative cyber-physical risk engine.
    Calculates isolated Impact and Likelihood scores, generates analyst narratives,
    and maps operational blast radii.
    """
    def __init__(self, ics_graph):
        self.ics_graph = ics_graph
        self.asset_graph = ics_graph.asset_graph
        # In-memory caching for expensive route calculations
        self._route_cache = {}
        self._blast_radius_cache = {}

    def _parse_purdue_level(self, level_str):
        if not level_str: return None
        try:
            return float(''.join(filter(str.isdigit, str(level_str))))
        except ValueError:
            return None

    def _generate_narrative(self, path, metrics):
        """Translates machine metrics into a human-readable analyst explanation."""
        stages = []
        for node in path:
            role = self.asset_graph.nodes[node].get("security_role", "PIVOT")
            if role == "ENTRY_POINT": stages.append(f"[{node} (Entry)]")
            elif role == "FINAL_TARGET": stages.append(f"[{node} (Target)]")
            elif self.asset_graph.nodes[node].get("is_enforcement_point"): stages.append(f"[{node} (Enforcement)]")
            else: stages.append(node)

        narrative = " ➔ ".join(stages) + "\n\n"
        narrative += f"Summary: Path crosses {metrics['boundaries_crossed']} trust boundaries and traverses {metrics['enforcement_points']} enforcement points. "
        
        if metrics["reaches_physics"]:
            narrative += "CRITICAL: Path successfully bridges cyber-to-physical domains."
        elif metrics["critical_assets"]:
            narrative += f"High Risk: Path reaches {len(metrics['critical_assets'])} critical cyber assets."
            
        return narrative

    def _evaluate_path(self, path):
        """
        Transforms a raw node sequence into a decoupled Impact/Likelihood security finding.
        """
        metrics = {
            "path": path,
            "length": len(path) - 1,
            "critical_assets": [],
            "boundaries_crossed": 0,
            "enforcement_points": 0,
            "reaches_physics": False,
            "purdue_trajectory": [],
            "impact_score": 0.0,
            "likelihood_score": 1.0, # Starts at 100% probability of success
            "overall_risk": 0.0,
            "is_realistic": True,
            "realism_warnings": [],
            "narrative": ""
        }

        impact_accumulator = 0.0

        # 1. Analyze Nodes (Impact & Trajectory)
        for i, node in enumerate(path):
            attrs = self.asset_graph.nodes[node]
            
            if attrs.get("criticality") == "critical":
                metrics["critical_assets"].append(node)
                impact_accumulator += 25.0  # Base critical asset impact
                
            if attrs.get("is_enforcement_point"):
                metrics["enforcement_points"] += 1
                
            if attrs.get("node_category") == "PHYSICAL_ASSET":
                metrics["reaches_physics"] = True
                impact_accumulator += 50.0  # Massive physical impact weight

            purdue = attrs.get("purdue_level")
            if purdue: metrics["purdue_trajectory"].append(f"L{self._parse_purdue_level(purdue)}")

        # 2. Analyze Edges (Likelihood Degradation & Contextual Validation)
        for i in range(len(path) - 1):
            u, v = path[i], path[i+1]
            edge_data = self.asset_graph[u][v]
            u_attrs = self.asset_graph.nodes[u]
            v_attrs = self.asset_graph.nodes[v]

            # Edge weight likelihood reductions
            edge_type = edge_data.get("edge_type")
            if edge_type == "HUMAN_PERM":
                metrics["likelihood_score"] *= 0.9  # Requires credential compromise
            elif edge_type == "CYBER_PHYSICAL":
                metrics["likelihood_score"] *= 0.8  # Requires understanding of ICS protocols/physics

            if edge_data.get("is_boundary_crossing"):
                metrics["boundaries_crossed"] += 1
                metrics["likelihood_score"] *= 0.7  # Crossing zones degrades success probability

            if v_attrs.get("is_enforcement_point"):
                metrics["likelihood_score"] *= 0.4  # Firewalls/Gateways heavily degrade likelihood

            # Contextual Purdue Validation
            u_p = self._parse_purdue_level(u_attrs.get("purdue_level"))
            v_p = self._parse_purdue_level(v_attrs.get("purdue_level"))
            
            if u_p is not None and v_p is not None and abs(u_p - v_p) > 1:
                # Direct jumps from Enterprise/DMZ directly to PLC/Physics without pivot
                if u_p >= 3 and v_p <= 1 and not v_attrs.get("is_enforcement_point"):
                    metrics["is_realistic"] = False
                    metrics["realism_warnings"].append(f"Suspicious Architecture Bypass: L{u_p} directly to L{v_p} ({u} ➔ {v})")

        # 3. Final Calculations ($Risk = Impact \times Likelihood$)
        # Ensure path length slightly degrades likelihood (noise, detection probability)
        metrics["likelihood_score"] *= (0.95 ** metrics["length"])
        
        metrics["impact_score"] = round(max(impact_accumulator, 10.0), 2) # Minimum impact of 10
        metrics["likelihood_score"] = round(metrics["likelihood_score"], 3)
        metrics["overall_risk"] = round(metrics["impact_score"] * metrics["likelihood_score"], 2)
        
        # 4. Generate Analyst Narrative
        metrics["narrative"] = self._generate_narrative(path, metrics)

        return metrics

    def analyze_attack_paths(self, entry_points=None, targets=None, top_n=3, max_depth=8, max_time_sec=5.0):
        """
        Discovers the top N highest-risk paths from entry points to targets.
        Includes execution time limits and depth limits to prevent exponential explosion.
        """
        entries = entry_points or self.ics_graph.entry_points
        critical_targets = targets or self.ics_graph.critical_assets
        analyzed_paths = []
        
        start_time = time.time()

        for entry in entries:
            for target in critical_targets:
                # Time limit circuit breaker
                if time.time() - start_time > max_time_sec:
                    logger.warning("Path analysis hit time limit. Yielding partial results.")
                    break

                cache_key = (entry, target)
                if cache_key in self._route_cache:
                    analyzed_paths.extend(self._route_cache[cache_key])
                    continue

                if not nx.has_path(self.asset_graph, entry, target):
                    continue
                
                local_paths = []
                try:
                    path_generator = nx.shortest_simple_paths(self.asset_graph, entry, target)
                    for raw_path in islice(path_generator, top_n):
                        if len(raw_path) - 1 > max_depth:
                            continue
                            
                        enriched_path = self._evaluate_path(raw_path)
                        local_paths.append(enriched_path)
                except nx.NetworkXNoPath:
                    pass
                
                self._route_cache[cache_key] = local_paths
                analyzed_paths.extend(local_paths)

        # Sort by Overall Risk (Impact * Likelihood) rather than just impact or length
        analyzed_paths.sort(key=lambda x: x["overall_risk"], reverse=True)
        return analyzed_paths

    def analyze_blast_radius(self, compromised_node_id):
        """
        Calculates operational impact of a node compromise.
        Now summarizes risk structurally rather than just listing arrays.
        """
        if compromised_node_id in self._blast_radius_cache:
            return self._blast_radius_cache[compromised_node_id]

        if not self.asset_graph.has_node(compromised_node_id):
            raise ValueError(f"Node {compromised_node_id} does not exist.")

        reachable_nodes = nx.descendants(self.asset_graph, compromised_node_id)
        
        report = {
            "compromised_node": compromised_node_id,
            "operational_summary": {
                "total_assets_exposed": len(reachable_nodes),
                "zones_compromised": 0,
                "critical_assets_exposed": 0,
                "physical_processes_exposed": 0
            },
            "exposed_entities": {
                "critical_assets": [],
                "physical_processes": [],
                "zones": set()
            }
        }

        for node in reachable_nodes:
            attrs = self.asset_graph.nodes[node]
            report["exposed_entities"]["zones"].add(attrs.get("zone", "unknown"))
            
            if attrs.get("criticality") == "critical":
                report["exposed_entities"]["critical_assets"].append(node)
                report["operational_summary"]["critical_assets_exposed"] += 1
                
            if attrs.get("node_category") == "PHYSICAL_ASSET":
                report["exposed_entities"]["physical_processes"].append(node)
                report["operational_summary"]["physical_processes_exposed"] += 1

        report["exposed_entities"]["zones"] = list(report["exposed_entities"]["zones"])
        report["operational_summary"]["zones_compromised"] = len(report["exposed_entities"]["zones"])
        
        self._blast_radius_cache[compromised_node_id] = report
        return report

# Backward compatibility functions
def analyze_attack_paths(graph, entry_points, critical_assets):
    analyzer = ICSPathAnalyzer(graph)
    return analyzer.analyze_attack_paths(entry_points, critical_assets)