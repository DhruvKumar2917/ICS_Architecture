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
        Transforms a raw node sequence into a decoupled Impact/Likelihood security finding
        and enriches it with the research-grade risk score from RiskEngine.
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
        metrics["likelihood_score"] *= (0.95 ** metrics["length"])
        metrics["impact_score"] = round(max(impact_accumulator, 10.0), 2)
        metrics["likelihood_score"] = round(metrics["likelihood_score"], 3)

        # Integrate the official RiskEngine score
        from DAG.risk_engine import RiskEngine
        engine = RiskEngine(self.ics_graph)
        risk_rec = engine.score_path(path)

        metrics["overall_risk"] = risk_rec["total_risk_score"]
        metrics["risk_score"] = risk_rec["total_risk_score"]
        metrics["severity"] = risk_rec["severity"]
        metrics["score_breakdown"] = risk_rec["score_breakdown"]
        
        # 4. Generate Analyst Narrative
        metrics["narrative"] = self._generate_narrative(path, metrics)

        return metrics

    def analyze_attack_paths(self, entry_points=None, targets=None, top_n=3, max_depth=8, max_time_sec=5.0):
        """
        Discovers the top N highest-risk paths from entry points to targets.
        Generates 30 candidates per entry/target pair and prioritizes high-risk paths.
        """
        entries = entry_points or self.ics_graph.entry_points
        critical_targets = targets or self.ics_graph.critical_assets
        analyzed_paths = []

        # --- Guard: empty graph ---
        if self.asset_graph.number_of_edges() == 0:
            logger.warning(
                "analyze_attack_paths: graph has no edges — skipping path analysis. "
                "Ensure RBAC permissions and architecture connections were parsed correctly."
            )
            return []

        if not entries:
            logger.warning("analyze_attack_paths: no entry points defined — skipping.")
            return []

        if not critical_targets:
            logger.warning("analyze_attack_paths: no critical targets defined — skipping.")
            return []

        start_time = time.time()

        # Build combined traversal graph with weights (costs)
        combined_graph = nx.DiGraph()
        for u, v, d in self.asset_graph.edges(data=True):
            edge_type = d.get("edge_type", "")
            if edge_type in ("HUMAN_PERM", "COMM_LINK", "CYBER_PHYSICAL"):
                # cost = firewall_strength + zone_crossings + privilege_required
                cost = 1.0  # Base cost to prefer fewer hops when weights are equal
                
                u_attrs = self.asset_graph.nodes[u]
                v_attrs = self.asset_graph.nodes[v]
                
                # 1. Firewall / Enforcement Point (firewall_strength)
                if v_attrs.get("is_enforcement_point") or str(v_attrs.get("type")).lower() in ("firewall", "vpn", "gateway"):
                    cost += 30.0
                
                # 2. Zone Crossings
                u_zone = u_attrs.get("zone")
                v_zone = v_attrs.get("zone")
                if u_zone and v_zone and u_zone != v_zone:
                    cost += 15.0
                    
                # 3. Privilege / Difficulty Required
                #    Tie the privilege cost to the sensitivity of the action so
                #    that high-impact writes/programming cost more to traverse
                #    than a passive read (a more realistic attacker model).
                if edge_type == "HUMAN_PERM":
                    action = str(d.get("label", "")).lower()
                    _high   = ("write", "program", "modify", "admin", "root", "super", "config", "firmware", "download", "send_command", "stop")
                    _medium = ("connect", "access", "execute", "upload", "maintenance")
                    if any(k in action for k in _high):
                        cost += 18.0   # privileged control action
                    elif any(k in action for k in _medium):
                        cost += 10.0   # standard authenticated access
                    else:
                        cost += 6.0    # read-only / low-impact
                
                # Purdue drop penalty (moving down to target/process layers)
                u_p = self._parse_purdue_level(u_attrs.get("purdue_level"))
                v_p = self._parse_purdue_level(v_attrs.get("purdue_level"))
                if u_p is not None and v_p is not None and u_p > v_p:
                    cost += 20.0  # Pivot down is more difficult
                
                combined_graph.add_edge(u, v, weight=cost, **d)

        # Communication-only subgraph — used to validate cyber node reachability
        comm_graph = nx.DiGraph()
        for u, v, d in self.asset_graph.edges(data=True):
            if d.get("edge_type") == "COMM_LINK":
                comm_graph.add_edge(u, v)

        path_counter = 0
        for entry in entries:
            for target in critical_targets:
                if time.time() - start_time > max_time_sec:
                    logger.warning("Path analysis hit time limit. Yielding partial results.")
                    break

                cache_key = (entry, target)
                if cache_key in self._route_cache:
                    analyzed_paths.extend(self._route_cache[cache_key])
                    continue

                if not combined_graph.has_node(entry) or not combined_graph.has_node(target):
                    continue

                if not nx.has_path(combined_graph, entry, target):
                    continue
                
                local_candidates = []
                try:
                    # Generate a wider set of candidates (up to 30) using cost weights
                    path_generator = nx.shortest_simple_paths(combined_graph, entry, target, weight='weight')
                    for raw_path in islice(path_generator, 30):
                        if len(raw_path) < 2:
                            continue
                        if len(raw_path) - 1 > max_depth:
                            continue
                            
                        has_meaningful_edge = False
                        for idx in range(len(raw_path) - 1):
                            u_node, v_node = raw_path[idx], raw_path[idx+1]
                            if self.asset_graph.has_edge(u_node, v_node):
                                et = self.asset_graph[u_node][v_node].get("edge_type", "")
                                if et in ("COMM_LINK", "HUMAN_PERM", "CYBER_PHYSICAL"):
                                    has_meaningful_edge = True
                                    break
                        if not has_meaningful_edge:
                            continue

                        # Verify communication reachability between adjacent cyber assets
                        is_reachable = True
                        cyber_nodes = [
                            n for n in raw_path
                            if self.asset_graph.nodes.get(n, {}).get("node_category") == "CYBER_ASSET"
                        ]
                        for idx in range(len(cyber_nodes) - 1):
                            u_cyber = cyber_nodes[idx]
                            v_cyber = cyber_nodes[idx+1]
                            if self.asset_graph.has_edge(u_cyber, v_cyber):
                                pass
                            elif (
                                u_cyber != v_cyber
                                and comm_graph.has_node(u_cyber)
                                and comm_graph.has_node(v_cyber)
                                and not nx.has_path(comm_graph, u_cyber, v_cyber)
                            ):
                                is_reachable = False
                                break
                        if not is_reachable:
                            continue

                        path_counter += 1
                        enriched_path = self._evaluate_path(raw_path)
                        enriched_path["path_id"]    = f"path_{path_counter}"
                        enriched_path["source"]     = raw_path[0]
                        enriched_path["target"]     = raw_path[-1]
                        enriched_path["steps"]      = raw_path
                        enriched_path["risk_score"] = enriched_path["overall_risk"]
                        local_candidates.append(enriched_path)
                except nx.NetworkXNoPath:
                    pass
                
                # Sort candidates by overall_risk descending and pick top_n
                local_candidates.sort(key=lambda x: x["overall_risk"], reverse=True)
                top_candidates = local_candidates[:top_n]

                self._route_cache[cache_key] = top_candidates
                analyzed_paths.extend(top_candidates)

        # Sort the overall results by risk descending
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
