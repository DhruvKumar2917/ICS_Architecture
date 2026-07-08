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
        self._route_cache = {}
        self._blast_radius_cache = {}

    def _parse_purdue_level(self, level_str):
        if not level_str: return None
        try:
            return float(''.join(filter(str.isdigit, str(level_str))))
        except ValueError:
            return None

    def _generate_narrative(self, path, metrics):
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
        metrics = {
            "path": path,
            "length": len(path) - 1,
            "critical_assets": [],
            "boundaries_crossed": 0,
            "enforcement_points": 0,
            "reaches_physics": False,
            "purdue_trajectory": [],
            "impact_score": 0.0,
            "likelihood_score": 1.0,
            "overall_risk": 0.0,
            "is_realistic": True,
            "realism_warnings": [],
            "narrative": ""
        }

        impact_accumulator = 0.0

        for i, node in enumerate(path):
            attrs = self.asset_graph.nodes[node]
            
            if attrs.get("criticality") == "critical":
                metrics["critical_assets"].append(node)
                impact_accumulator += 25.0
                
            if attrs.get("is_enforcement_point"):
                metrics["enforcement_points"] += 1
                
            if attrs.get("node_category") == "PHYSICAL_ASSET":
                metrics["reaches_physics"] = True
                impact_accumulator += 50.0

            purdue = attrs.get("purdue_level")
            if purdue: metrics["purdue_trajectory"].append(f"L{self._parse_purdue_level(purdue)}")

        for i in range(len(path) - 1):
            u, v = path[i], path[i+1]
            edge_data = self.asset_graph[u][v]
            u_attrs = self.asset_graph.nodes[u]
            v_attrs = self.asset_graph.nodes[v]

            edge_type = edge_data.get("edge_type")
            if edge_type == "HUMAN_PERM":
                metrics["likelihood_score"] *= 0.9
            elif edge_type == "CYBER_PHYSICAL":
                metrics["likelihood_score"] *= 0.8

            if edge_data.get("is_boundary_crossing"):
                metrics["boundaries_crossed"] += 1
                metrics["likelihood_score"] *= 0.7

            if v_attrs.get("is_enforcement_point"):
                metrics["likelihood_score"] *= 0.4

            u_p = self._parse_purdue_level(u_attrs.get("purdue_level"))
            v_p = self._parse_purdue_level(v_attrs.get("purdue_level"))
            
            if u_p is not None and v_p is not None and abs(u_p - v_p) > 1:
                if u_p >= 3 and v_p <= 1 and not v_attrs.get("is_enforcement_point"):
                    metrics["is_realistic"] = False
                    metrics["realism_warnings"].append(f"Suspicious Architecture Bypass: L{u_p} directly to L{v_p} ({u} ➔ {v})")

        metrics["likelihood_score"] *= (0.95 ** metrics["length"])
        metrics["impact_score"] = round(max(impact_accumulator, 10.0), 2)
        metrics["likelihood_score"] = round(metrics["likelihood_score"], 3)

        from app.analysis.risk_engine import RiskEngine
        engine = RiskEngine(self.ics_graph)
        risk_rec = engine.score_path(path)

        metrics["overall_risk"] = risk_rec["total_risk_score"]
        metrics["risk_score"] = risk_rec["total_risk_score"]
        metrics["severity"] = risk_rec["severity"]
        metrics["score_breakdown"] = risk_rec["score_breakdown"]
        
        metrics["narrative"] = self._generate_narrative(path, metrics)

        return metrics

    def analyze_attack_paths(self, entry_points=None, targets=None, top_n=3, max_depth=8, max_time_sec=5.0):
        entries = entry_points or self.ics_graph.entry_points
        critical_targets = targets or self.ics_graph.critical_assets
        analyzed_paths = []

        if self.asset_graph.number_of_edges() == 0:
            logger.warning("analyze_attack_paths: graph has no edges — skipping path analysis.")
            return []

        if not entries:
            logger.warning("analyze_attack_paths: no entry points defined — skipping.")
            return []

        if not critical_targets:
            logger.warning("analyze_attack_paths: no critical targets defined — skipping.")
            return []

        start_time = time.time()

        combined_graph = nx.DiGraph()
        for u, v, d in self.asset_graph.edges(data=True):
            edge_type = d.get("edge_type", "")
            if edge_type in ("HUMAN_PERM", "COMM_LINK", "CYBER_PHYSICAL"):
                cost = 1.0
                
                u_attrs = self.asset_graph.nodes[u]
                v_attrs = self.asset_graph.nodes[v]
                
                if v_attrs.get("is_enforcement_point") or str(v_attrs.get("type")).lower() in ("firewall", "vpn", "gateway"):
                    cost += 30.0
                
                u_zone = u_attrs.get("zone")
                v_zone = v_attrs.get("zone")
                if u_zone and v_zone and u_zone != v_zone:
                    cost += 15.0
                    
                if edge_type == "HUMAN_PERM":
                    action = str(d.get("label", "")).lower()
                    _high   = ("write", "program", "modify", "admin", "root", "super", "config", "firmware", "download", "send_command", "stop")
                    _medium = ("connect", "access", "execute", "upload", "maintenance")
                    if any(k in action for k in _high):
                        cost += 18.0
                    elif any(k in action for k in _medium):
                        cost += 10.0
                    else:
                        cost += 6.0
                
                u_p = self._parse_purdue_level(u_attrs.get("purdue_level"))
                v_p = self._parse_purdue_level(v_attrs.get("purdue_level"))
                if u_p is not None and v_p is not None and u_p > v_p:
                    cost += 20.0
                
                combined_graph.add_edge(u, v, weight=cost, **d)

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
                
                local_candidates.sort(key=lambda x: x["overall_risk"], reverse=True)
                top_candidates = local_candidates[:top_n]

                self._route_cache[cache_key] = top_candidates
                analyzed_paths.extend(top_candidates)

        analyzed_paths.sort(key=lambda x: x["overall_risk"], reverse=True)
        return analyzed_paths

    def get_edge_propagation_prob(self, u: str, v: str) -> float:
        if not self.asset_graph.has_edge(u, v):
            return 0.0
        edge_data = self.asset_graph[u][v]
        edge_type = edge_data.get("edge_type", "COMM_LINK")
        label = str(edge_data.get("label", "")).lower()
        
        base_weights = {
            "COMM_LINK":      0.9,
            "CYBER_PHYSICAL": 0.5,
            "HUMAN_PERM":     0.4
        }
        prob = base_weights.get(edge_type, 0.6)
        
        if edge_type == "HUMAN_PERM":
            _privileged = ("write", "program", "modify", "admin", "root", "super", "config", "firmware", "send_command")
            if any(p in label for p in _privileged):
                prob = 0.8
                
        insecure_protocols = ("modbus", "dnp3", "ethernet/ip", "http", "ftp", "telnet", "s7comm")
        secure_protocols = ("opc-ua", "opcua", "https", "ssh", "ipsec", "ssl", "tls")
        if any(p in label for p in insecure_protocols):
            prob *= 1.15
        elif any(p in label for p in secure_protocols):
            prob *= 0.6
            
        v_attrs = self.asset_graph.nodes[v]
        v_type = str(v_attrs.get("type", "")).lower()
        
        if v_attrs.get("is_enforcement_point") or v_type in ("firewall", "vpn", "gateway"):
            prob *= 0.20
            
        if str(v_attrs.get("criticality", "")).lower() == "critical":
            prob *= 0.7
            
        u_attrs = self.asset_graph.nodes[u]
        u_zone = u_attrs.get("zone", "?")
        v_zone = v_attrs.get("zone", "?")
        
        if edge_data.get("is_boundary_crossing") or (u_zone != v_zone and u_zone != "?" and v_zone != "?"):
            prob *= 0.6
            
        u_p = self._parse_purdue_level(u_attrs.get("purdue_level"))
        v_p = self._parse_purdue_level(v_attrs.get("purdue_level"))
        if u_p is not None and v_p is not None:
            if u_p > v_p:
                prob *= (0.7 ** (u_p - v_p))
                if u_p >= 3.0 and v_p <= 2.0:
                    prob *= 0.4
                    
        return round(max(min(prob, 1.0), 0.0), 3)

    def reconstruct_attack_path_details(self, path):
        steps = []
        i = 0
        while i < len(path) - 1:
            u = path[i]
            v = path[i+1]
            
            if self.asset_graph.has_edge(u, v):
                edge_data = self.asset_graph[u][v]
                edge_type = edge_data.get("edge_type", "COMM_LINK")
                label = edge_data.get("label", "network traffic")
                is_boundary = edge_data.get("is_boundary_crossing", False)
                is_inferred = edge_data.get("is_inferred_routing", False)
                
                desc = f"Attacker moved from '{u}' to '{v}' via {edge_type} ({label})."
                if is_boundary:
                    desc += " This traversed a trust boundary between security zones."
                if is_inferred:
                    desc += " The traffic was inspected/routed through an enforcement point (firewall)."
                
                steps.append({
                    "step_number": len(steps) + 1,
                    "type": "direct_movement",
                    "from_node": u,
                    "to_node": v,
                    "edge_type": edge_type,
                    "label": label,
                    "description": desc
                })
                i += 1
            else:
                if i + 2 < len(path):
                    s = path[i+1]
                    w = path[i+2]
                    if (self.asset_graph.has_edge(s, u) and self.asset_graph.has_edge(s, w) and
                        self.asset_graph[s][u].get("edge_type") == "HUMAN_PERM" and
                        self.asset_graph[s][w].get("edge_type") == "HUMAN_PERM"):
                        
                        desc = f"Privilege Escalation: Attacker harvested credentials of identity '{s}' from compromised asset '{u}', and reused them to access '{w}'."
                        steps.append({
                            "step_number": len(steps) + 1,
                            "type": "privilege_escalation",
                            "from_node": u,
                            "identity_compromised": s,
                            "to_node": w,
                            "description": desc
                        })
                        i += 2
                        continue
                
                desc = f"Attacker moved from '{u}' to '{v}'."
                steps.append({
                    "step_number": len(steps) + 1,
                    "type": "unknown_pivot",
                    "from_node": u,
                    "to_node": v,
                    "description": desc
                })
                i += 1
        return steps

    def estimate_physical_disruption(self, node: str) -> dict:
        attrs = self.asset_graph.nodes[node]
        v_type = str(attrs.get("type", "")).lower()
        label = str(attrs.get("label", node)).lower()
        zone = str(attrs.get("zone", "")).lower()
        
        disruption_type = "UNKNOWN"
        severity = "LOW"
        description = "Operational disruption of physical process loop."
        remediation = "Establish physical override controls and segment controller communication."
        
        if "safety" in label or "safety" in zone or v_type == "safety_controller":
            disruption_type = "SAFETY_SYSTEM_COMPROMISE"
            severity = "CRITICAL"
            description = (
                "Safety Instrumented System (SIS) compromised. Attacker can inhibit emergency shutdown trip signals, "
                "potentially allowing thermal runaway, physical overpressure, or mechanical failure to go uncontrolled."
            )
            remediation = "Isolate SIS from control network (Level 1). Mandate physical interlocks."
        elif "turbine" in label or "turbine" in zone:
            disruption_type = "TURBINE_TRIP_OR_OVERSPEED"
            severity = "HIGH"
            description = (
                "Turbine rotation speed controller compromise. Loss of governor valve control can lead to emergency trip "
                "or catastrophic mechanical overspeed damage, leading to prolonged generator offline state."
            )
            remediation = "Implement redundant mechanical overspeed limiters. Restrict turbine PLC modification permissions."
        elif "generator" in label or "generator" in zone:
            disruption_type = "GENERATOR_DESYNCHRONIZATION"
            severity = "HIGH"
            description = (
                "Generator excitation and voltage regulation system compromise. Risk of out-of-phase grid connection, "
                "leading to winding damage, trip, or localized power blackouts."
            )
            remediation = "Deploy hardware-in-the-loop synchrocheck relays that cannot be bypassed via cyber commands."
        elif "actuator" in v_type or "valve" in label or "actuator" in label:
            disruption_type = "ACTUATOR_COMMAND_SPOOFING"
            severity = "MEDIUM"
            description = (
                "Control valve or actuator position signal manipulation. Attacker can override PLC control loops to spoof "
                "open/close commands, resulting in fluid/gas pressure oscillations or safety relief valve blowdowns."
            )
            remediation = "Implement rate-of-change limiters and localized control loop integrity checks."
        elif "sensor" in v_type or "telemetry" in label or "sensor" in label or "temp" in label or "press" in label:
            disruption_type = "TELEMETRY_BLINDING_OR_SPOOFING"
            severity = "MEDIUM"
            description = (
                "Sensor telemetry feedback blinding. Attacker can inject stale or false process values (temperature, pressure) "
                "into the control loop, causing operators or PLCs to take incorrect actions based on false metrics."
            )
            remediation = "Verify telemetry values across independent sensor channels. Implement Kalman filtering."
        elif v_type in ("plc", "rtu"):
            disruption_type = "CONTROLLER_LOGIC_MANIPULATION"
            severity = "HIGH"
            description = (
                "Programmable Logic Controller logic compromise. Attacker can download modified rung logic, corrupt the firmware, "
                "or force physical output coils to unsafe states, directly impacting field hardware."
            )
            remediation = "Enable physical run/program keys on PLCs. Enforce cryptographically signed code downloads."
            
        return {
            "disruption_type": disruption_type,
            "severity": severity,
            "description": description,
            "remediation": remediation
        }

    def analyze_blast_radius(
        self,
        compromised_node_id,
        max_hops=6,
        decay=0.75,
        allow_human_perm_bypass=False,
    ):
        cache_key = (str(compromised_node_id), max_hops, bool(allow_human_perm_bypass))
        if cache_key in self._blast_radius_cache:
            return self._blast_radius_cache[cache_key]

        if isinstance(compromised_node_id, list):
            origins = list(compromised_node_id)
        elif isinstance(compromised_node_id, str):
            origins = [compromised_node_id]
        else:
            origins = [str(compromised_node_id)]

        visited = {}
        queue = []
        for origin in origins:
            if self.asset_graph.has_node(origin):
                visited[origin] = {
                    "hop": 0,
                    "prob": 1.0,
                    "path": [origin],
                    "exposure_types": {"compromise_origin"}
                }
                queue.append((origin, 0, 1.0, [origin]))

        while queue:
            u, hop_dist, u_prob, u_path = queue.pop(0)
            if hop_dist >= max_hops:
                continue

            for v in self.asset_graph.successors(u):
                edge_data = self.asset_graph[u][v]
                edge_type = edge_data.get("edge_type", "")

                p_edge = self.get_edge_propagation_prob(u, v)
                next_prob = u_prob * p_edge
                if next_prob < 0.05:
                    continue

                v_attrs = self.asset_graph.nodes[v]
                blocked_by_enforcement = (
                    v_attrs.get("is_enforcement_point")
                    and not (allow_human_perm_bypass and edge_type == "HUMAN_PERM")
                    and v not in origins
                )

                if v not in visited or (next_prob > visited[v]["prob"]):
                    visited[v] = {
                        "hop": hop_dist + 1,
                        "prob": round(next_prob, 3),
                        "path": u_path + [v],
                        "exposure_types": {edge_type} if v not in visited else visited[v]["exposure_types"] | {edge_type}
                    }
                    if not blocked_by_enforcement:
                        queue.append((v, hop_dist + 1, next_prob, u_path + [v]))

            for s in self.asset_graph.predecessors(u):
                if self.asset_graph[s][u].get("edge_type") == "HUMAN_PERM":
                    for w in self.asset_graph.successors(s):
                        if w == u or w in origins:
                            continue
                        if self.asset_graph[s][w].get("edge_type") == "HUMAN_PERM":
                            p_reuse = 0.8
                            next_prob = u_prob * p_reuse
                            if next_prob < 0.05:
                                continue

                            w_attrs = self.asset_graph.nodes[w]
                            blocked_by_enforcement = (
                                w_attrs.get("is_enforcement_point")
                                and w not in origins
                            )

                            if w not in visited or (next_prob > visited[w]["prob"]):
                                visited[w] = {
                                    "hop": hop_dist + 1,
                                    "prob": round(next_prob, 3),
                                    "path": u_path + [s, w],
                                    "exposure_types": {"PRIVILEGE_ESCALATION"} if w not in visited else visited[w]["exposure_types"] | {"PRIVILEGE_ESCALATION"}
                                }
                                if not blocked_by_enforcement:
                                    queue.append((w, hop_dist + 1, next_prob, u_path + [s, w]))

        reachable = {n: d for n, d in visited.items() if n not in origins}

        exposed_entities = {
            "critical_assets": [],
            "physical_processes": [],
            "zones": set(),
            "purdue_levels": set()
        }
        scored_nodes = []
        summary = {
            "total_assets_exposed": len(reachable),
            "zones_compromised": 0,
            "critical_assets_exposed": 0,
            "physical_processes_exposed": 0,
            "max_propagation_depth": 0,
            "affected_purdue_levels": []
        }

        for node, info in reachable.items():
            attrs = self.asset_graph.nodes[node]
            zone = attrs.get("zone", "unknown")
            purdue = attrs.get("purdue_level", "unknown")
            exposed_entities["zones"].add(zone)
            exposed_entities["purdue_levels"].add(purdue)
            
            if info["hop"] > summary["max_propagation_depth"]:
                summary["max_propagation_depth"] = info["hop"]

            v_type = str(attrs.get("type", "")).lower()
            category = attrs.get("node_category", "")

            if v_type == "safety_controller" or "safety" in zone.lower():
                base_weight = 100.0
            elif v_type in ("plc", "rtu"):
                base_weight = 80.0
            elif v_type in ("scada", "hmi"):
                base_weight = 60.0
            elif v_type == "engineering":
                base_weight = 50.0
            elif v_type == "historian":
                base_weight = 45.0
            elif v_type == "server":
                base_weight = 30.0
            elif v_type == "workstation":
                base_weight = 20.0
            elif v_type in ("firewall", "vpn", "gateway"):
                base_weight = 15.0
            elif category == "PHYSICAL_ASSET" or v_type in ("sensor", "actuator"):
                base_weight = 40.0
            else:
                base_weight = 10.0

            crit_bonus = 0.0
            crit_val = str(attrs.get("criticality", "")).lower()
            if crit_val == "critical":
                crit_bonus = 30.0
            elif crit_val == "high":
                crit_bonus = 20.0
            elif crit_val == "medium":
                crit_bonus = 10.0

            purdue_mult = 1.0
            p_level = self._parse_purdue_level(purdue)
            if p_level is not None:
                if p_level <= 1.0:
                    purdue_mult = 1.5
                elif p_level == 2.0:
                    purdue_mult = 1.3
                elif p_level == 3.0:
                    purdue_mult = 1.1

            w_v = (base_weight + crit_bonus) * purdue_mult

            impact_score = round(w_v * (decay ** info["hop"]) * info["prob"], 2)

            path_trace = self.reconstruct_attack_path_details(info["path"])

            expl = f"Asset '{node}' (Purdue L{purdue}, Zone '{zone}') compromised from '{compromised_node_id}' after {info['hop']} hop(s) with {round(info['prob'] * 100, 1)}% probability. "
            if v_type == "safety_controller" or "safety" in zone.lower():
                expl += "Compromising safety controllers directly threatens the physical safety interlocks of the process."
            elif v_type in ("plc", "rtu"):
                expl += "Compromising the controller allows direct manipulation of physical field equipment."
            elif v_type in ("scada", "hmi"):
                expl += "Compromising SCADA/HMI allows attackers to spoof operator screens and send malicious manual commands."
            elif category == "PHYSICAL_ASSET":
                expl += "Compromising physical hardware disrupts the actual process operations."
            else:
                expl += "Compromising this host allows lateral pivot further into operational technology (OT) zones."

            physical_impact = None
            if category == "PHYSICAL_ASSET" or v_type in ("sensor", "actuator"):
                physical_impact = self.estimate_physical_disruption(node)

            node_record = {
                "node_id": node,
                "hop_distance": info["hop"],
                "impact_score": impact_score,
                "exposure_probability": info["prob"],
                "exposure_type": sorted(info["exposure_types"]),
                "path_from_origin": info["path"],
                "attack_path_details": path_trace,
                "compromise_explanation": expl,
                "zone": zone,
                "purdue_level": purdue,
                "is_physical": (category == "PHYSICAL_ASSET" or v_type in ("sensor", "actuator")),
                "is_critical": (crit_val == "critical"),
                "physical_disruption_impact": physical_impact
            }
            scored_nodes.append(node_record)

            if attrs.get("criticality") == "critical":
                exposed_entities["critical_assets"].append(node)
                summary["critical_assets_exposed"] += 1
            if category == "PHYSICAL_ASSET" or v_type in ("sensor", "actuator", "plc"):
                exposed_entities["physical_processes"].append(node)
                summary["physical_processes_exposed"] += 1

        scored_nodes.sort(key=lambda x: x["impact_score"], reverse=True)
        exposed_entities["zones"] = list(exposed_entities["zones"])
        exposed_entities["purdue_levels"] = list(exposed_entities["purdue_levels"])
        summary["zones_compromised"] = len(exposed_entities["zones"])
        summary["total_blast_radius_score"] = round(sum(n["impact_score"] for n in scored_nodes), 2)
        summary["affected_purdue_levels"] = exposed_entities["purdue_levels"]

        validator = BlastRadiusValidationAgent(self)
        origin_ref = origins[0] if origins else str(compromised_node_id)
        validation_report = validator.validate(origin_ref, scored_nodes, max_hops=max_hops)

        report = {
            "compromised_node": compromised_node_id,
            "operational_summary": summary,
            "assumptions": {
                "allow_human_perm_bypass": bool(allow_human_perm_bypass),
                "enforcement_points_stop_traversal": not bool(allow_human_perm_bypass),
                "max_hops": max_hops,
                "decay": decay,
            },
            "exposed_entities": exposed_entities,
            "exposed_nodes_ranked": scored_nodes,
            "validation_metrics": {
                "reachability_verified": validation_report["reachability_verified_count"] == validation_report["total_nodes_checked"],
                "attack_path_alignment_pct": validation_report["alignment_pct"],
                "validation_report": validation_report
            }
        }

        self._blast_radius_cache[cache_key] = report
        return report


class BlastRadiusValidationAgent:
    def __init__(self, path_analyzer):
        self.analyzer = path_analyzer
        self.asset_graph = path_analyzer.asset_graph
        
    def validate(self, origin_node, exposed_nodes_ranked, max_hops=6):
        errors = []
        warnings = []
        is_consistent = True
        
        exposed_ids = {n["node_id"] for n in exposed_nodes_ranked}
        
        reachability_status = {}
        for target in exposed_ids:
            has_path = False
            try:
                if nx.has_path(self.asset_graph, origin_node, target):
                    has_path = True
            except nx.NetworkXError:
                pass
            
            reachability_status[target] = has_path
            if not has_path:
                msg = f"Blast node '{target}' is not reachable from origin '{origin_node}' via visual network edges."
                errors.append(msg)
                is_consistent = False
                
        path_alignment = {}
        attack_paths = []
        critical_targets = self.analyzer.ics_graph.critical_assets
        for ct in critical_targets:
            if ct == origin_node:
                continue
            try:
                if nx.has_path(self.asset_graph, origin_node, ct):
                    for p in islice(nx.all_simple_paths(self.asset_graph, origin_node, ct, cutoff=max_hops), 5):
                        attack_paths.append(p)
            except Exception:
                pass
                
        attack_path_nodes = {n for path in attack_paths for n in path if n != origin_node}
        
        for target in exposed_ids:
            in_attack_path = (target in attack_path_nodes)
            path_alignment[target] = in_attack_path
            
        missing_critical_assets = []
        for ct in critical_targets:
            if ct == origin_node:
                continue
            try:
                if nx.has_path(self.asset_graph, origin_node, ct):
                    if ct not in exposed_ids:
                        missing_critical_assets.append(ct)
                        msg = f"Critical asset '{ct}' is reachable from origin '{origin_node}', but is missing from blast radius."
                        errors.append(msg)
                        is_consistent = False
            except Exception:
                pass
                
        alignment_pct = 100.0
        if exposed_ids:
            aligned_count = sum(1 for n in exposed_ids if n in attack_path_nodes)
            alignment_pct = round((aligned_count / len(exposed_ids)) * 100, 1)
            
        summary = (
            "Blast radius corresponds perfectly with reachability and attack paths."
            if is_consistent else
            f"Consistency warning: Found {len(errors)} mismatches/unreachable nodes during verification."
        )
        
        return {
            "is_consistent": is_consistent,
            "errors": errors,
            "warnings": warnings,
            "validation_summary": summary,
            "alignment_pct": alignment_pct,
            "missing_critical_assets": missing_critical_assets,
            "reachability_verified_count": sum(1 for status in reachability_status.values() if status),
            "total_nodes_checked": len(exposed_ids),
        }

    def simulate_remediation_impact(
        self,
        compromised_node_id,
        remove_edges=None,
        remove_nodes=None,
        max_hops=6,
        decay=0.75,
        allow_human_perm_bypass=False,
    ):
        original_graph = self.asset_graph.copy()
        
        if remove_nodes:
            for node in remove_nodes:
                if self.asset_graph.has_node(node):
                    self.asset_graph.remove_node(node)
        if remove_edges:
            for u, v in remove_edges:
                if self.asset_graph.has_edge(u, v):
                    self.asset_graph.remove_edge(u, v)
                    
        try:
            remediated_report = self.analyze_blast_radius(
                compromised_node_id,
                max_hops=max_hops,
                decay=decay,
                allow_human_perm_bypass=allow_human_perm_bypass,
            )
            remediated_score = remediated_report["operational_summary"]["total_blast_radius_score"]
        finally:
            self.asset_graph = original_graph
            
        baseline_report = self.analyze_blast_radius(
            compromised_node_id,
            max_hops=max_hops,
            decay=decay,
            allow_human_perm_bypass=allow_human_perm_bypass,
        )
        baseline_score = baseline_report["operational_summary"]["total_blast_radius_score"]
        
        reduction = baseline_score - remediated_score
        reduction_pct = round(reduction / baseline_score * 100, 1) if baseline_score > 0 else 0.0
        
        return {
            "compromised_node": compromised_node_id,
            "baseline_score": baseline_score,
            "remediated_score": remediated_score,
            "score_reduction": round(reduction, 2),
            "percentage_reduction": reduction_pct,
            "removed_nodes": remove_nodes or [],
            "removed_edges": remove_edges or [],
        }
