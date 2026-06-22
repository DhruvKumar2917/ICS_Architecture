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

    All warnings and errors are printed to stdout for immediate visibility
    in the backend terminal log.
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

    print(f"[validate_graph] Validating graph: "
          f"{nx_graph.number_of_nodes()} nodes, {nx_graph.number_of_edges()} edges", flush=True)

    if nx_graph.number_of_nodes() == 0:
        msg = "Graph is entirely empty."
        report["errors"].append(msg)
        report["is_valid"] = False
        print(f"[validate_graph] [FAIL] ERROR: {msg}", flush=True)
        return report

    # 1. DAG Validation (Crucial for Topological Sorting later)
    if not nx.is_directed_acyclic_graph(nx_graph):
        report["is_valid"] = False
        try:
            cycles = list(nx.simple_cycles(nx_graph))
            msg = f"Cycle detected! Graph is not a valid DAG. Found {len(cycles)} cycles."
            report["errors"].append(msg)
            print(f"[validate_graph] [FAIL] ERROR: {msg}", flush=True)
            cycle_msg = f"Example cycle: {' -> '.join(cycles[0])} -> {cycles[0][0]}"
            report["errors"].append(cycle_msg)
            print(f"[validate_graph]   {cycle_msg}", flush=True)
        except nx.NetworkXNoCycle:
            pass

    # 2. Orphan Nodes Validation
    orphans = [n for n, d in nx_graph.degree() if d == 0]
    if orphans:
        msg = f"Found {len(orphans)} orphan (isolated) nodes: {', '.join(str(o) for o in orphans[:5])}"
        if len(orphans) > 5:
            msg += f" ... and {len(orphans)-5} more"
        report["warnings"].append(msg)
        print(f"[validate_graph] [WARN] WARNING: {msg}", flush=True)

    # 3. Entry-Point Validation
    if not ics_graph.entry_points:
        msg = "No entry points detected (e.g., VPNs, Operators, External IPs). Attack-path analysis may fail."
        report["warnings"].append(msg)
        print(f"[validate_graph] [WARN] WARNING: {msg}", flush=True)
    else:
        print(f"[validate_graph] [OK] Entry points: {', '.join(str(e) for e in list(ics_graph.entry_points)[:5])}", flush=True)

    # 4. Critical Asset Validation
    if not ics_graph.critical_assets:
        msg = "No critical assets detected. Ensure PLCs or physical targets are labeled correctly."
        report["warnings"].append(msg)
        print(f"[validate_graph] [WARN] WARNING: {msg}", flush=True)
    else:
        print(f"[validate_graph] [OK] Critical assets: {', '.join(str(c) for c in list(ics_graph.critical_assets)[:5])}", flush=True)
        for crit_node in ics_graph.critical_assets:
            if nx_graph.in_degree(crit_node) == 0 and crit_node not in orphans:
                msg = f"Critical asset '{crit_node}' is totally unreachable (in-degree 0)."
                report["warnings"].append(msg)
                print(f"[validate_graph] [WARN] WARNING: {msg}", flush=True)

    # 5. Zone and Semantic Edge Validation
    unzoned = []
    for node, attrs in nx_graph.nodes(data=True):
        cat = attrs.get("node_category")
        if cat == "CYBER_ASSET" and not attrs.get("zone"):
            unzoned.append(node)
            msg = f"Cyber asset '{node}' is missing a zone assignment."
            report["warnings"].append(msg)

    if unzoned:
        print(f"[validate_graph] [WARN] WARNING: {len(unzoned)} assets without zone assignment: "
              f"{', '.join(unzoned[:5])}", flush=True)

    for u, v, attrs in nx_graph.edges(data=True):
        u_attrs = nx_graph.nodes[u]
        v_attrs = nx_graph.nodes[v]

        u_cat = u_attrs.get("node_category")
        v_cat = v_attrs.get("node_category")
        edge_type = attrs.get("edge_type")

        # Check Edge Semantics
        if edge_type == "COMM_LINK" and u_cat == "HUMAN_ACTOR" and v_cat == "HUMAN_ACTOR":
            msg = f"Invalid communication semantics: Human '{u}' communicating via network with Human '{v}'."
            report["warnings"].append(msg)
            print(f"[validate_graph] [WARN] WARNING: {msg}", flush=True)

        if edge_type == "CYBER_PHYSICAL" and v_cat != "PHYSICAL_ASSET":
            msg = f"Semantic mismatch: Cyber-physical edge '{u} -> {v}' does not terminate at a physical asset."
            report["warnings"].append(msg)
            print(f"[validate_graph] [WARN] WARNING: {msg}", flush=True)

        # 6. Purdue Consistency Validation (Detecting architectural bypasses)
        if edge_type == "COMM_LINK":
            u_level = parse_purdue_level(u_attrs.get("purdue_level"))
            v_level = parse_purdue_level(v_attrs.get("purdue_level"))

            if u_level is not None and v_level is not None:
                if abs(u_level - v_level) > 1:
                    msg = f"Purdue violation: Direct connection skips layers between '{u}' (L{u_level}) and '{v}' (L{v_level})."
                    report["warnings"].append(msg)
                    print(f"[validate_graph] [WARN] WARNING: {msg}", flush=True)

    # 7. Trust-Boundary Validation (Imported from the Builder)
    cross_zone_leaks = ics_graph.validation_report.get("cross_zone_leaks", [])
    if cross_zone_leaks:
        msg = (f"Found {len(cross_zone_leaks)} un-enforced cross-zone leaks "
               f"(communications crossing boundaries without an enforcement point).")
        report["warnings"].append(msg)
        print(f"[validate_graph] [WARN] WARNING: {msg}", flush=True)

    # Final wrap-up
    if report["errors"]:
        logger.error(f"Graph validation FAILED with {len(report['errors'])} errors.")
        print(f"[validate_graph] [FAIL] FAILED - {len(report['errors'])} error(s), "
              f"{len(report['warnings'])} warning(s)", flush=True)
    elif report["warnings"]:
        logger.warning(f"Graph validation generated {len(report['warnings'])} architectural warnings.")
        print(f"[validate_graph] [WARN] PASSED with {len(report['warnings'])} warning(s)", flush=True)
    else:
        logger.info("Graph validation PASSED structurally (DAG).")
        print("[validate_graph] [OK] PASSED - no errors or warnings", flush=True)

    return report