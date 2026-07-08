import logging
import os
import json
from typing import Dict, List, Any, Optional
from fastapi import APIRouter, Body

from app.analysis.aasg import AASGGraph
from app.graph.builder import build_graph
from app.graph.validator import validate_graph
from app.analysis.path_analysis import ICSPathAnalyzer
from app.analysis.reachability import AdvancedICSReachabilityEngine
from app.graph.dag_generator import ICSAnalysisDAGBuilder
from app.graph.layer_assignment import _parse_purdue_to_tier
from app.intelligence.mitre_mapper import MITREMapper
from app.analysis.risk_engine import RiskEngine
from app.analysis.threat_propagation import ThreatPropagator
from app.analysis.lateral_movement import LateralMovementAnalyzer
from app.parsers.text.parser import text_to_graph
from app.parsers.rbac.parser import parse_rbac
from app.parsers.firewall.parser import FirewallParser
from app.parsers.unified_model import build_unified_model

logger = logging.getLogger(__name__)

router = APIRouter()

def _layer_matrix_from_graph(ics_graph) -> dict:
    layer_matrix = {}
    for node_id, attrs in ics_graph.asset_graph.nodes(data=True):
        purdue = attrs.get("purdue_level")
        tier   = _parse_purdue_to_tier(purdue)

        if tier is None:
            role      = attrs.get("security_role", "")
            node_cat  = attrs.get("node_category", "")
            node_type = str(attrs.get("type", "")).lower()

            if role == "ENTRY_POINT" or node_cat == "HUMAN_ACTOR":
                tier = 0
            elif role == "FINAL_TARGET" or node_cat == "PHYSICAL_ASSET" or node_type in ["plc", "sensor", "actuator"]:
                tier = 6
            elif role == "BOUNDARY_DEVICE" or node_type in ["firewall", "vpn"]:
                tier = 3
            elif node_type in ["server", "scada", "hmi"]:
                tier = 4
            else:
                tier = 5

        layer_matrix[node_id] = {
            "layer": tier,
            "zone":  attrs.get("zone") or "unassigned_zone",
        }
    return layer_matrix


def _print_aasg_summary(aasg_graph: AASGGraph, ics_graph, validation_report: dict,
                         attack_paths: list, unified_data: dict) -> None:
    subjects  = [v for v in aasg_graph.V if v["vertex_type"] == "subject"]
    objects   = [v for v in aasg_graph.V if v["vertex_type"] == "object"]
    ea_edges  = aasg_graph.Ea
    ec_edges  = aasg_graph.Ec

    unknown_ec = sum(1 for e in ec_edges if e["label"].get("protocol") in ("unknown", "", None))

    print("\n" + "="*60, flush=True)
    print("  AASG PIPELINE SUMMARY - G = (V, E, Z)", flush=True)
    print("="*60, flush=True)

    print("\n[PHASE 1] Canonical A = {Z, E, S, O, R}", flush=True)
    print(f"  Zones          (Z): {len(aasg_graph.Z)}", flush=True)
    print(f"  Subjects       (S): {len(subjects)}", flush=True)
    if subjects:
        names = ", ".join(v["id"] for v in subjects[:8])
        print(f"    -> {names}", flush=True)
    print(f"  Objects        (O): {len(objects)}", flush=True)
    print(f"  Actions        (R): {len(aasg_graph.R)}", flush=True)

    print("\n[PHASE 2] Formal G = (V, E, Z)", flush=True)
    print(f"  Vertices   |V| = {len(aasg_graph.V)} (S union O - NO action/role/policy nodes)", flush=True)
    print(f"  Auth Edges |Ea|= {len(ea_edges)} (subject -> object, action as label)", flush=True)
    print(f"  Comm Edges |Ec|= {len(ec_edges)} (object -> object, protocol as label)", flush=True)
    if unknown_ec > 0:
        print(f"  [WARN] WARNING: {unknown_ec}/{len(ec_edges)} Ec edges have unknown protocol", flush=True)
    else:
        print(f"  [OK] All Ec edges have named protocols", flush=True)

    blocked = unified_data.get("firewall_blocked", [])
    if blocked:
        print(f"\n[FIREWALL] Blocked {len(blocked)} architecture connections (Ec filtered)", flush=True)
        for b in blocked[:5]:
            print(f"  [FAIL] {b['src']} -> {b['dst']}: {b.get('reason','blocked')}", flush=True)
        if len(blocked) > 5:
            print(f"  ... and {len(blocked)-5} more", flush=True)
    else:
        print(f"\n[FIREWALL] No firewall file uploaded - all architecture connections included in Ec", flush=True)

    print(f"\n[VALIDATION]", flush=True)
    print(f"  Valid: {validation_report.get('is_valid', True)}", flush=True)
    errors = validation_report.get("errors", [])
    warnings = validation_report.get("warnings", [])
    if errors:
        for e in errors:
            print(f"  [FAIL] ERROR: {e}", flush=True)
    if warnings:
        for w in warnings:
            print(f"  [WARN] WARNING: {w}", flush=True)
    if not errors and not warnings:
        print("  [OK] No errors or warnings", flush=True)

    print(f"\n[ATTACK PATHS] {len(attack_paths)} risk vector(s) found", flush=True)
    for i, p in enumerate(attack_paths[:3]):
        path_str = " -> ".join(p["path"])
        print(f"  #{i+1}: risk={p['overall_risk']} | {path_str}", flush=True)
    if len(attack_paths) > 3:
        print(f"  ... and {len(attack_paths)-3} more", flush=True)

    nx_graph = ics_graph.asset_graph
    print(f"\n[NETWORKX GRAPH]", flush=True)
    print(f"  Nodes: {nx_graph.number_of_nodes()}", flush=True)
    print(f"  Edges: {nx_graph.number_of_edges()}", flush=True)
    print(f"  Entry points:    {len(ics_graph.entry_points)}", flush=True)
    print(f"  Critical assets: {len(ics_graph.critical_assets)}", flush=True)
    print(f"  Physical targets: {len(ics_graph.physical_targets)}", flush=True)

    val_issues = unified_data.get("validation_issues", [])
    if val_issues:
        print(f"\n[UNIFIED MODEL] {len(val_issues)} validation issue(s):", flush=True)
        for v in val_issues[:5]:
            print(f"  [WARN] {v}", flush=True)

    print("="*60 + "\n", flush=True)


def _build_code_review_graph(
    unified_data: dict,
    validation_report: dict,
    attack_paths: list,
    scored_paths: list,
    mitre_results: dict,
    blast_radii: dict,
    propagation_results: dict,
    lateral_report: dict,
) -> dict:
    nodes = []

    def add_node(node_id: str, label: str, status: str, metrics: dict):
        nodes.append({"id": node_id, "label": label, "status": status, "metrics": metrics})

    unified_e = unified_data.get("E", {})
    add_node(
        "unified",
        "Unified Model",
        "ok" if len(unified_data.get("Z", [])) and len(unified_data.get("O", [])) else "fail",
        {
            "zones": len(unified_data.get("Z", [])),
            "subjects": len(unified_data.get("S", [])),
            "objects": len(unified_data.get("O", [])),
            "actions": len(unified_data.get("R", [])),
            "ea": len(unified_e.get("Ea", [])),
            "ec": len(unified_e.get("Ec", [])),
            "blocked": len(unified_data.get("firewall_blocked", [])),
        },
    )

    warnings = validation_report.get("warnings", [])
    add_node(
        "validation",
        "Graph Validation",
        "ok" if validation_report.get("is_valid", True) and not warnings else ("warn" if validation_report.get("is_valid", True) else "fail"),
        {
            "is_valid": validation_report.get("is_valid", True),
            "errors": len(validation_report.get("errors", [])),
            "warnings": len(warnings),
        },
    )

    add_node(
        "paths",
        "Attack Paths",
        "ok" if attack_paths else "warn",
        {
            "count": len(attack_paths),
            "top_risk": scored_paths[0]["risk_score"] if scored_paths else 0,
        },
    )

    ctx = mitre_results.get("context_stats", {})
    quality = ctx.get("quality_checks", {})
    mitre_status = "ok"
    if not mitre_results.get("technique_summary"):
        mitre_status = "fail"
    elif (
        ctx.get("avg_confidence", 0.0) < 0.45
        or ctx.get("suppression_rate_pct", 0.0) > 25
        or quality.get("id_name_conflicts", 0) > 0
        or quality.get("reason_keyword_conflicts", 0) > 0
        or quality.get("generic_remote_ratio", 0.0) > 0.6
    ):
        mitre_status = "warn"

    add_node(
        "mitre",
        "MITRE Mapping",
        mitre_status,
        {
            "mode": mitre_results.get("mapping_mode", "unknown"),
            "techniques": len(mitre_results.get("technique_summary", [])),
            "total_mappings": ctx.get("total_mappings", 0),
            "avg_confidence": ctx.get("avg_confidence", 0.0),
            "suppressed": ctx.get("suppressed", 0),
            "firewall_verified": ctx.get("firewall_verified", 0),
            "id_name_conflicts": quality.get("id_name_conflicts", 0),
            "reason_keyword_conflicts": quality.get("reason_keyword_conflicts", 0),
            "generic_remote_ratio": quality.get("generic_remote_ratio", 0.0),
            "unique_mapping_ratio": quality.get("unique_mapping_ratio", 0.0),
        },
    )

    blast_errors = sum(1 for v in blast_radii.values() if isinstance(v, dict) and v.get("error"))
    if not blast_radii:
        blast_status = "fail"
    elif blast_errors == len(blast_radii):
        blast_status = "fail"
    elif blast_errors > 0:
        blast_status = "warn"
    else:
        blast_status = "ok"

    add_node(
        "blast",
        "Blast Radius",
        blast_status,
        {"nodes_analyzed": len(blast_radii), "errors": blast_errors},
    )

    add_node(
        "propagation",
        "Threat Propagation",
        "ok" if propagation_results else "warn",
        {"origins": len(propagation_results)},
    )

    add_node(
        "lateral",
        "Lateral Movement",
        "ok",
        {
            "events": lateral_report.get("total_movement_events", 0),
            "cross_zone": lateral_report.get("cross_zone_count", 0),
            "privilege_escalation": lateral_report.get("privilege_escalation_count", 0),
        },
    )

    edges = [
        {"from": "unified", "to": "validation"},
        {"from": "validation", "to": "paths"},
        {"from": "paths", "to": "mitre"},
        {"from": "paths", "to": "blast"},
        {"from": "paths", "to": "propagation"},
        {"from": "paths", "to": "lateral"},
    ]

    pipeline_status = "ok"
    if any(n["status"] == "fail" for n in nodes):
        pipeline_status = "fail"
    elif any(n["status"] == "warn" for n in nodes):
        pipeline_status = "warn"

    return {
        "nodes": nodes,
        "edges": edges,
        "summary": {
            "pipeline_status": pipeline_status,
            "failed_stages": [n["id"] for n in nodes if n["status"] == "fail"],
            "warning_stages": [n["id"] for n in nodes if n["status"] == "warn"],
        },
    }


def run_security_analysis(unified_data: dict, rbac_summary: dict, firewall_summary: dict, selected_role: str = None) -> dict:
    aasg_graph = AASGGraph(unified_data)
    ics_graph = build_graph(unified_data)
    validation_report = validate_graph(ics_graph)

    entries = set()
    if selected_role:
        if ics_graph.asset_graph.has_node(selected_role):
            entries.add(selected_role)
        else:
            for n, d in ics_graph.asset_graph.nodes(data=True):
                if d.get("label", "").lower() == selected_role.lower() or n.lower() == selected_role.lower():
                    entries.add(n)
                    break

    if not entries:
        entries = ics_graph.entry_points

    if not entries:
        entries = {
            n for n, d in ics_graph.asset_graph.in_degree()
            if d == 0 and ics_graph.asset_graph.out_degree(n) > 0
        }

    targets = ics_graph.critical_assets or ics_graph.physical_targets or {
        n for n, d in ics_graph.asset_graph.out_degree() if d == 0 and ics_graph.asset_graph.in_degree(n) > 0
    }

    print("[pipeline] Step 4: Attack Path Generation (Ea U Ec)...", flush=True)
    path_analyzer = ICSPathAnalyzer(ics_graph)
    attack_paths  = path_analyzer.analyze_attack_paths(entry_points=entries, targets=targets)
    print(f"[pipeline]   -> {len(attack_paths)} attack path(s) found", flush=True)

    print("[pipeline] Step 5: Risk Scoring...", flush=True)
    risk_engine   = RiskEngine(ics_graph)
    scored_paths  = risk_engine.score_attack_paths(attack_paths)
    node_rankings = risk_engine.rank_critical_nodes()
    print(f"[pipeline]   -> Top risk score: {scored_paths[0]['risk_score'] if scored_paths else 0}", flush=True)

    _mapper_mode = os.getenv("MITRE_MAPPER_MODE", "llm").lower()
    _use_llm = _mapper_mode != "rules"
    _fw_allowed_pairs = firewall_summary.get("allowed_pairs", [])
    print(f"[pipeline] Step 6: MITRE ATT&CK Mapping (mode={'LLM' if _use_llm else 'rules'})...", flush=True)

    try:
        mitre_mapper = MITREMapper(use_llm=_use_llm)
        mitre_results = mitre_mapper.map_aasg_with_context(
            aasg_graph,
            ics_graph,
            firewall_rules=_fw_allowed_pairs,
            zone_mapping=firewall_summary.get("zone_mapping", {}),
        )
        for path_rec in scored_paths:
            path_rec["mitre_hops"] = mitre_mapper.map_attack_path_with_context(
                path_rec.get("steps", path_rec.get("path", [])), ics_graph
            )
    except Exception as e:
        if _use_llm:
            print(f"[pipeline] [WARN] MITRE LLM mapping failed ({e}); falling back to rules mode", flush=True)
            mitre_mapper = MITREMapper(use_llm=False)
            mitre_results = mitre_mapper.map_aasg_with_context(
                aasg_graph,
                ics_graph,
                firewall_rules=_fw_allowed_pairs,
                zone_mapping=firewall_summary.get("zone_mapping", {}),
            )
            for path_rec in scored_paths:
                path_rec["mitre_hops"] = mitre_mapper.map_attack_path_with_context(
                    path_rec.get("steps", path_rec.get("path", [])), ics_graph
                )
            _use_llm = False
        else:
            raise

    _ctx = mitre_results.get("context_stats", {})
    _llm_stats = mitre_results.get("llm_stats", {})
    print(
        f"[pipeline]   -> {len(mitre_results.get('technique_summary', []))} unique MITRE techniques. "
        f"Mode: {'LLM' if _use_llm else 'rules'}. "
        f"Suppressed: {_ctx.get('suppressed', 0)}, "
        f"Avg confidence: {_ctx.get('avg_confidence', 0):.2f}, "
        f"Reachability verified: {_ctx.get('reachability_verified', 0)}/{_ctx.get('total_mappings', 0)}"
        + (f", LLM calls: {_llm_stats.get('llm_calls', 0)}, Cache hits: {_llm_stats.get('cache_hits', 0)}" if _llm_stats else ""),
        flush=True,
    )

    print("[pipeline] Step 9.5: Empirical Evaluation Metrics...", flush=True)
    from app.analysis.empirical_metrics import evaluate_empirical
    try:
        empirical_results = evaluate_empirical(scored_paths, ics_graph)
    except Exception as e:
        print(f"[pipeline] [WARN] Empirical evaluation failed: {e}", flush=True)
        empirical_results = {
            "paths": [],
            "role_level_aaf": {},
            "avg_tel": 0.0,
            "max_tel": 0,
            "zone_summary": []
        }

    print("[pipeline] Step 7: Blast Radius Analysis...", flush=True)
    blast_radii = {}
    priority_nodes = list(entries)[:5] + [
        n["node"] for n in node_rankings[:5]
        if n["node"] not in entries
    ]
    for node_id in priority_nodes:
        try:
            blast_radii[node_id] = path_analyzer.analyze_blast_radius(
                node_id,
                allow_human_perm_bypass=False,
            )
        except Exception as e:
            blast_radii[node_id] = {"error": str(e)}
    print(f"[pipeline]   -> Blast radius computed for {len(blast_radii)} node(s)", flush=True)

    print("[pipeline] Step 8: Threat Propagation Simulation...", flush=True)
    propagator = ThreatPropagator(ics_graph)
    propagation_results = {}
    for origin in list(entries)[:3]:
        try:
            propagation_results[origin] = propagator.simulate(origin, max_depth=8)
        except Exception as e:
            propagation_results[origin] = {"error": str(e)}
    print(f"[pipeline]   -> Propagation simulated from {len(propagation_results)} origin(s)", flush=True)

    print("[pipeline] Step 9: Lateral Movement Detection...", flush=True)
    lateral_analyzer = LateralMovementAnalyzer(ics_graph)
    lateral_report   = lateral_analyzer.analyze()
    print(
        f"[pipeline]   -> {lateral_report['total_movement_events']} movement events: "
        f"cross-zone={lateral_report['cross_zone_count']}, "
        f"privilege-esc={lateral_report['privilege_escalation_count']}, "
        f"remote-chains={lateral_report['remote_chain_count']}",
        flush=True,
    )

    print("[pipeline] Step 10-11: Reachability + Zone Matrix...", flush=True)
    reachability_engine    = AdvancedICSReachabilityEngine(ics_graph)
    cyber_physical_vectors = reachability_engine.check_cyber_to_physical_reachability(entry_points=entries)
    zone_matrix            = reachability_engine.compute_zone_to_zone_matrix()

    print("[pipeline] Step 12: Layout DAG...", flush=True)
    layer_matrix = _layer_matrix_from_graph(ics_graph)
    dag_builder  = ICSAnalysisDAGBuilder(ics_graph, layer_matrix, active_attack_paths=scored_paths)
    layout_data  = dag_builder.build()

    serialized_validation = {
        "is_valid":  validation_report.get("is_valid", True),
        "errors":    list(validation_report.get("errors", [])),
        "warnings":  list(validation_report.get("warnings", [])),
        "stats":     validation_report.get("stats", {}),
    }

    _print_aasg_summary(aasg_graph, ics_graph, serialized_validation, scored_paths, unified_data)

    print("\n" + "="*60, flush=True)
    print("  MITRE ATT&CK & FORMAL ANALYSIS JSON OUTPUT", flush=True)
    print("="*60, flush=True)
    mitre_console_output = {
        "mitre_mapping": {
            "technique_summary": mitre_results.get("technique_summary", []),
            "tactic_summary": mitre_results.get("tactic_summary", {}),
            "mapping_mode": mitre_results.get("mapping_mode", "llm"),
            "context_stats": mitre_results.get("context_stats", {})
        },
        "formal_analysis": mitre_results.get("formal_analysis", {})
    }
    print(json.dumps(mitre_console_output, indent=2), flush=True)
    print("="*60 + "\n", flush=True)

    code_review_graph = _build_code_review_graph(
        unified_data=unified_data,
        validation_report=serialized_validation,
        attack_paths=attack_paths,
        scored_paths=scored_paths,
        mitre_results=mitre_results,
        blast_radii=blast_radii,
        propagation_results=propagation_results,
        lateral_report=lateral_report,
    )

    return {
        "react_flow_asset_view":      layout_data["react_flow_asset_view"],
        "react_flow_macro_zone_view": layout_data["react_flow_macro_zone_view"],
        "layout_metadata":            layout_data["layout_metadata"],
        "validation_report": serialized_validation,
        "attack_paths":  scored_paths,
        "risk_analysis": {
            "scored_paths":   scored_paths,
            "node_rankings":  node_rankings[:20],
        },
        "mitre_mapping": mitre_results,
        "formal_analysis": mitre_results.get("formal_analysis", {}),
        "blast_radius": blast_radii,
        "threat_propagation": propagation_results,
        "lateral_movement": lateral_report,
        "reachability_data": {
            "cyber_physical_vectors": cyber_physical_vectors,
            "zone_matrix":            zone_matrix,
        },
        "empirical_evaluation": empirical_results,
        "aasg": {
            **aasg_graph.to_dict(ics_graph.asset_graph),
            "empirical_evaluation": empirical_results,
        },
        "raw_model_data": unified_data,
        "rbac_summary":     rbac_summary,
        "firewall_summary": firewall_summary,
        "code_review_graph": code_review_graph,
    }


@router.post("/generate-from-text")
async def generate_from_text(payload: dict = Body(...)):
    try:
        text          = payload.get("text", "")
        role          = payload.get("role", None)
        rbac_text     = payload.get("rbac_text", "")
        firewall_text = payload.get("firewall_text", "")

        if not text.strip():
            return {"error": "No architecture text provided."}

        rbac_data    = parse_rbac(rbac_text) if rbac_text else {"S": [], "R": [], "permissions": []}
        fw_parser    = FirewallParser().parse(firewall_text) if firewall_text else None
        fw_summary   = fw_parser.to_dict() if fw_parser else {"rules": [], "allowed_pairs": [], "allowed_count": 0}

        print(f"[text] RBAC: {len(rbac_data.get('S',[]))} subjects, "
              f"{len(rbac_data.get('R',[]))} actions, "
              f"{len(rbac_data.get('permissions',[]))} permissions", flush=True)
        if fw_parser:
            print(f"[text] Firewall: {len(fw_parser.rules)} rules", flush=True)

        arch_data = text_to_graph(text)

        print(f"[text] Architecture: "
              f"{len(arch_data.get('Z',[]))} zones, "
              f"{len(arch_data.get('O',[]))} objects, "
              f"{len(arch_data.get('E',{}).get('connections',[]))} connections",
              flush=True)

        unified_data = build_unified_model(arch_data, rbac_data, fw_parser)

        print(f"[text] Unified model: "
              f"Z={len(unified_data.get('Z',[]))}, "
              f"S={len(unified_data.get('S',[]))}, "
              f"O={len(unified_data.get('O',[]))}, "
              f"R={len(unified_data.get('R',[]))}, "
              f"Ea={len((unified_data.get('E') or {}).get('Ea',[]))}, "
              f"Ec={len((unified_data.get('E') or {}).get('Ec',[]))}",
              flush=True)

        return run_security_analysis(unified_data, rbac_data, fw_summary, selected_role=role)

    except Exception as e:
        import traceback
        traceback.print_exc()
        return {"error": str(e)}


@router.post("/blast-radius")
async def blast_radius(payload: dict = Body(...)):
    graph_data = payload.get("graph_data", {})
    node_id    = payload.get("node_id", "")
    if not graph_data or not node_id:
        return {"error": "Missing graph_data or node_id"}
    try:
        ics_graph = build_graph(graph_data)
        analyzer  = ICSPathAnalyzer(ics_graph)
        result    = analyzer.analyze_blast_radius(node_id)
        print(f"[blast-radius] Node '{node_id}': "
              f"{result['operational_summary']['total_assets_exposed']} assets exposed, "
              f"{result['operational_summary']['zones_compromised']} zones",
              flush=True)
        return result
    except Exception as e:
        import traceback
        traceback.print_exc()
        return {"error": str(e)}


@router.post("/threat-propagation")
async def threat_propagation_endpoint(payload: dict = Body(...)):
    graph_data  = payload.get("graph_data", {})
    origin_node = payload.get("origin_node", "")
    origins     = payload.get("origins", [])
    max_depth   = payload.get("max_depth", 8)
    min_prob    = payload.get("min_prob", 0.1)

    if not graph_data:
        return {"error": "Missing graph_data"}

    try:
        ics_graph  = build_graph(graph_data)
        propagator = ThreatPropagator(ics_graph)

        if origin_node:
            result = propagator.simulate(origin_node, max_depth=max_depth, min_prob=min_prob)
        elif origins:
            result = propagator.simulate_multi_origin(origins, max_depth=max_depth, min_prob=min_prob)
        else:
            entry_list = list(ics_graph.entry_points)[:3]
            if not entry_list:
                return {"error": "No entry points found and no origin specified."}
            result = propagator.simulate_multi_origin(entry_list, max_depth=max_depth, min_prob=min_prob)

        return result
    except Exception as e:
        import traceback
        traceback.print_exc()
        return {"error": str(e)}


@router.post("/lateral-movement")
async def lateral_movement_endpoint(payload: dict = Body(...)):
    graph_data = payload.get("graph_data", {})
    top_paths  = payload.get("top_paths", 5)

    if not graph_data:
        return {"error": "Missing graph_data"}

    try:
        ics_graph        = build_graph(graph_data)
        lateral_analyzer = LateralMovementAnalyzer(ics_graph)
        result           = lateral_analyzer.analyze(top_paths=top_paths)

        print(
            f"[lateral-movement] {result['total_movement_events']} events: "
            f"cross-zone={result['cross_zone_count']}, "
            f"priv-esc={result['privilege_escalation_count']}, "
            f"remote={result['remote_chain_count']}, "
            f"purdue-violation={result['purdue_violation_count']}",
            flush=True,
        )
        return result
    except Exception as e:
        import traceback
        traceback.print_exc()
        return {"error": str(e)}


@router.post("/mitre-mapping")
async def mitre_mapping_endpoint(payload: dict = Body(...)):
    graph_data = payload.get("graph_data", {})
    mode       = payload.get("mode", os.getenv("MITRE_MAPPER_MODE", "llm")).lower()
    if not graph_data:
        return {"error": "Missing graph_data"}

    try:
        aasg_graph   = AASGGraph(graph_data)
        ics_graph    = build_graph(graph_data)
        mitre_mapper = MITREMapper(use_llm=(mode != "rules"))
        result = mitre_mapper.map_aasg_with_context(
            aasg_graph,
            ics_graph,
            firewall_rules=[],
            zone_mapping=graph_data.get("zone_mapping", {}),
        )

        _ctx = result.get("context_stats", {})
        print(
            f"[mitre-mapping] Mode: {mode}. "
            f"{len(result['authorization_mappings'])} Ea mappings, "
            f"{len(result['communication_mappings'])} Ec mappings, "
            f"{len(result['technique_summary'])} unique techniques. "
            f"Suppressed: {_ctx.get('suppressed', 0)}, "
            f"Avg confidence: {_ctx.get('avg_confidence', 0):.2f}",
            flush=True,
        )
        return result
    except Exception as e:
        import traceback
        traceback.print_exc()
        return {"error": str(e)}


@router.post("/evaluate-empirical")
async def evaluate_empirical_endpoint(payload: dict = Body(...)):
    graph_data = payload.get("graph_data", {})
    if not graph_data:
        return {"error": "Missing graph_data"}
        
    try:
        aasg_graph = AASGGraph(graph_data)
        ics_graph = build_graph(graph_data)
        
        entries = ics_graph.entry_points or {
            n for n, d in ics_graph.asset_graph.in_degree()
            if d == 0 and ics_graph.asset_graph.out_degree(n) > 0
        }
        targets = ics_graph.critical_assets or ics_graph.physical_targets or {
            n for n, d in ics_graph.asset_graph.out_degree() if d == 0 and ics_graph.asset_graph.in_degree(n) > 0
        }
        
        path_analyzer = ICSPathAnalyzer(ics_graph)
        scored_paths = path_analyzer.analyze_attack_paths(entry_points=entries, targets=targets)
        
        mitre_mapper = MITREMapper(use_llm=False)
        for path_rec in scored_paths:
            path_rec["mitre_hops"] = mitre_mapper.map_attack_path_with_context(
                path_rec.get("steps", path_rec.get("path", [])), ics_graph
            )
            
        metrics = evaluate_empirical(scored_paths, ics_graph)
        return metrics
    except Exception as e:
        import traceback
        traceback.print_exc()
        return {"error": str(e)}


@router.post("/risk-scoring")
async def risk_scoring_endpoint(payload: dict = Body(...)):
    graph_data   = payload.get("graph_data", {})
    attack_paths = payload.get("attack_paths", None)

    if not graph_data:
        return {"error": "Missing graph_data"}

    try:
        ics_graph   = build_graph(graph_data)
        risk_engine = RiskEngine(ics_graph)

        if attack_paths is None:
            path_analyzer = ICSPathAnalyzer(ics_graph)
            attack_paths  = path_analyzer.analyze_attack_paths(
                entry_points=ics_graph.entry_points,
                targets=ics_graph.critical_assets,
            )

        scored_paths  = risk_engine.score_attack_paths(attack_paths)
        node_rankings = risk_engine.rank_critical_nodes()

        print(
            f"[risk-scoring] {len(scored_paths)} paths scored. "
            f"Top: {scored_paths[0]['risk_score'] if scored_paths else 0}. "
            f"{len(node_rankings)} nodes ranked.",
            flush=True,
        )

        return {
            "scored_paths":  scored_paths,
            "node_rankings": node_rankings[:30],
        }
    except Exception as e:
        import traceback
        traceback.print_exc()
        return {"error": str(e)}
