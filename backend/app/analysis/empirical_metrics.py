import logging
from typing import Dict, List, Any, Set, Tuple

logger = logging.getLogger(__name__)

def evaluate_empirical(scored_paths: List[Dict], ics_graph) -> Dict[str, Any]:
    """
    Evaluates empirical security metrics for the given set of attack paths.
    
    Metrics computed:
      - Path-level & Role-level Authorization Amplification Factor (AAF)
      - Trust Expansion Length (TEL)
      - Cross-Zone Impact Span (CZIS)
      - Zone traversal summaries
    """
    if not scored_paths:
        return {
            "paths": [],
            "role_level_aaf": {},
            "avg_tel": 0.0,
            "max_tel": 0,
            "zone_summary": []
        }

    asset_graph = ics_graph.asset_graph
    evaluated_paths = []
    
    total_tel = 0
    max_tel = 0
    all_zones_touched = set()
    
    role_high_impact_actions: Dict[str, Set[str]] = {}
    role_first_hop_edges: Dict[str, Set[Tuple[str, str]]] = {}

    for path_rec in scored_paths:
        path = path_rec.get("steps", path_rec.get("path", []))
        if len(path) < 2:
            continue
            
        mitre_hops = path_rec.get("mitre_hops", [])
        if not mitre_hops:
            from app.intelligence.mitre_mapper import MITREMapper
            try:
                mapper = MITREMapper(use_llm=False)
                mitre_hops = mapper.map_attack_path_with_context(path, ics_graph)
                path_rec["mitre_hops"] = mitre_hops
            except Exception as e:
                logger.warning(f"Failed to dynamically generate mitre_hops: {e}")
        
        mitre_map = {}
        for hop in mitre_hops:
            u = hop.get("from")
            v = hop.get("to")
            mitre_data = hop.get("mitre", {})
            if isinstance(mitre_data, dict):
                tid = mitre_data.get("id")
                tactic = mitre_data.get("tactic", "Unknown")
                if u and v and tid and tid.lower() != "unknown":
                    mitre_map[(u, v)] = (tid, tactic)
                    
        policy_edges_count = 0
        assumption_edges_count = 0
        path_tids = set()
        hops_details = []
        
        last_policy_idx = -1
        
        for i in range(len(path) - 1):
            u, v = path[i], path[i+1]
            edge_data = asset_graph.get_edge_data(u, v, default={})
            
            empirical_type = edge_data.get("empirical_edge_type")
            if not empirical_type:
                struct_type = edge_data.get("edge_type")
                if struct_type == "HUMAN_PERM":
                    empirical_type = "policy-enforced"
                else:
                    empirical_type = "assumption-based"
                    
            if empirical_type == "policy-enforced":
                policy_edges_count += 1
                last_policy_idx = i
            else:
                assumption_edges_count += 1
                
            tid_info = mitre_map.get((u, v))
            tid = None
            if tid_info:
                tid, tactic = tid_info
                from app.intelligence.mitre_mapper import TACTIC_SEVERITY
                # Filter AAF: only count techniques with HIGH or CRITICAL severity tactics (excludes Discovery/Collection etc.)
                if TACTIC_SEVERITY.get(tactic, "LOW") in ("HIGH", "CRITICAL"):
                    path_tids.add(tid)
                
            hops_details.append({
                "from": u,
                "to": v,
                "edge_type": empirical_type,
                "mitre_id": tid
            })
            
        aaf = len(path_tids) / max(1, policy_edges_count)
        
        if last_policy_idx == -1:
            tel = len(path) - 1
            fully_unenforced = True
        else:
            tel = (len(path) - 1) - 1 - last_policy_idx
            fully_unenforced = False
            
        total_tel += tel
        if tel > max_tel:
            max_tel = tel
            
        path_zones = []
        for node in path:
            z = asset_graph.nodes[node].get("zone", "unknown")
            if z and z != "unknown":
                path_zones.append(z)
                all_zones_touched.add(z)
                
        seen_zones = set()
        zone_sequence = [z for z in path_zones if not (z in seen_zones or seen_zones.add(z))]
        czis = len(seen_zones)
        
        evaluated_paths.append({
            "path": path,
            "length": len(path) - 1,
            "hops": hops_details,
            "policy_enforced_count": policy_edges_count,
            "assumption_based_count": assumption_edges_count,
            "aaf": round(aaf, 2),
            "tel": tel,
            "fully_unenforced": fully_unenforced,
            "czis": czis,
            "zone_sequence": zone_sequence,
            "mitre_techniques": sorted(list(path_tids)),
            "narrative": path_rec.get("narrative", "")
        })
        
        entry_role = path[0]
        first_hop = (path[0], path[1])
        
        if entry_role not in role_high_impact_actions:
            role_high_impact_actions[entry_role] = set()
            role_first_hop_edges[entry_role] = set()
            
        role_high_impact_actions[entry_role].update(path_tids)
        role_first_hop_edges[entry_role].add(first_hop)

    role_level_aaf = {}
    for role, actions in role_high_impact_actions.items():
        first_hop_edges = role_first_hop_edges[role]
        policy_first_hops = 0
        for u, v in first_hop_edges:
            edge_data = asset_graph.get_edge_data(u, v, default={})
            empirical_type = edge_data.get("empirical_edge_type")
            if not empirical_type:
                struct_type = edge_data.get("edge_type")
                empirical_type = "policy-enforced" if struct_type == "HUMAN_PERM" else "assumption-based"
                
            if empirical_type == "policy-enforced":
                policy_first_hops += 1
                
        role_level_aaf[role] = round(len(actions) / max(1, policy_first_hops), 2)

    avg_tel = round(total_tel / len(evaluated_paths), 2) if evaluated_paths else 0.0

    return {
        "paths": evaluated_paths,
        "role_level_aaf": role_level_aaf,
        "avg_tel": avg_tel,
        "max_tel": max_tel,
        "zone_summary": sorted(list(all_zones_touched))
    }
