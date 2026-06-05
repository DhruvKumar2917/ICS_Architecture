import logging
import networkx as nx

logger = logging.getLogger(__name__)

def parse_purdue_level(level_str):
    """Helper to convert 'Level 2' string into an integer for math comparisons."""
    if not isinstance(level_str, str):
        return None
    try:
        # Extracts the number from strings like "Level 3" or "L3"
        return int(''.join(filter(str.isdigit, level_str)))
    except ValueError:
        return None

def validate_graph(ics_graph):
    """
    Acts as an ICS architecture quality auditor. 
    Validates structure, security semantics, zone relationships, 
    Purdue hierarchy, trust boundaries, and attack-surface consistency.
    """
    nx_graph = ics_graph.asset_graph
    
    report = {
        "is_valid": True,
        "errors": [],
        "warnings": [],
        "stats": {
            "total_nodes": nx_graph.number_of_nodes(),
            "total_edges": nx_graph.number_of_edges()
        }
    }

    if nx_graph.number_of_nodes() == 0:
        report["errors"].append("Graph is entirely empty.")
        report["is_valid"] = False
        return report

    # 1. DAG Validation (Crucial for Topological Sorting later)
    if not nx.is_directed_acyclic_graph(nx_graph):
        report["is_valid"] = False
        try:
            cycles = list(nx.simple_cycles(nx_graph))
            report["errors"].append(f"Cycle detected! Graph is not a valid DAG. Found {len(cycles)} cycles.")
            # Show the first cycle for debugging
            report["errors"].append(f"Example cycle: {' -> '.join(cycles[0])} -> {cycles[0][0]}")
        except nx.NetworkXNoCycle:
            pass

    # 2. Orphan Nodes Validation
    orphans = [n for n, d in nx_graph.degree() if d == 0]
    if orphans:
        report["warnings"].append(f"Found {len(orphans)} orphan (isolated) nodes. They have no connections.")

    # 3. Entry-Point Validation
    if not ics_graph.entry_points:
        report["warnings"].append("No entry points detected (e.g., VPNs, Operators, External IPs). Attack-path analysis may fail.")

    # 4. Critical Asset Validation
    if not ics_graph.critical_assets:
        report["warnings"].append("No critical assets detected. Ensure PLCs or physical targets are labeled correctly.")
    else:
        for crit_node in ics_graph.critical_assets:
            if nx_graph.in_degree(crit_node) == 0 and crit_node not in orphans:
                report["warnings"].append(f"Critical asset '{crit_node}' is totally unreachable (in-degree 0).")

    # 5. Zone and Semantic Edge Validation
    for node, attrs in nx_graph.nodes(data=True):
        cat = attrs.get("node_category")
        
        # Check Zone Assignments
        if cat == "CYBER_ASSET" and not attrs.get("zone"):
            report["warnings"].append(f"Cyber asset '{node}' is missing a zone assignment.")

    for u, v, attrs in nx_graph.edges(data=True):
        u_attrs = nx_graph.nodes[u]
        v_attrs = nx_graph.nodes[v]
        
        u_cat = u_attrs.get("node_category")
        v_cat = v_attrs.get("node_category")
        edge_type = attrs.get("edge_type")

        # Check Edge Semantics
        if edge_type == "COMM_LINK" and u_cat == "HUMAN_ACTOR" and v_cat == "HUMAN_ACTOR":
            report["warnings"].append(f"Invalid communication semantics: Human '{u}' communicating via network with Human '{v}'.")
            
        if edge_type == "CYBER_PHYSICAL" and v_cat != "PHYSICAL_ASSET":
            report["warnings"].append(f"Semantic mismatch: Cyber-physical edge '{u} -> {v}' does not terminate at a physical asset.")

        # 6. Purdue Consistency Validation (Detecting architectural bypasses)
        if edge_type == "COMM_LINK":
            u_level = parse_purdue_level(u_attrs.get("purdue_level"))
            v_level = parse_purdue_level(v_attrs.get("purdue_level"))
            
            if u_level is not None and v_level is not None:
                if abs(u_level - v_level) > 1:
                    report["warnings"].append(f"Purdue violation: Direct connection skips layers between '{u}' (L{u_level}) and '{v}' (L{v_level}).")

    # 7. Trust-Boundary Validation (Imported from the Builder)
    cross_zone_leaks = ics_graph.validation_report.get("cross_zone_leaks", [])
    if cross_zone_leaks:
        report["warnings"].append(f"Found {len(cross_zone_leaks)} un-enforced cross-zone leaks (communications crossing boundaries without an enforcement point).")

    # Final wrap-up
    if report["errors"]:
        logger.error(f"Graph validation FAILED with {len(report['errors'])} errors.")
    else:
        logger.info("Graph validation PASSED structurally (DAG).")
        
    if report["warnings"]:
        logger.warning(f"Graph validation generated {len(report['warnings'])} architectural warnings.")

    return report