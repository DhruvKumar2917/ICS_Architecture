"""
ICS AASG Backend - FastAPI Application.

Full Security Analysis Pipeline:
  1.  Parse RBAC file      -> parsers.rbac_parser      -> {S, R, permissions}
  2.  Parse Firewall file  -> parsers.firewall_parser   -> {rules, allowed_pairs}
  3.  Parse Architecture   -> parsers.image_parser /    -> {Z, O, E.connections}
                             parsers.text_parser
  4.  Merge               -> parsers.unified_model      -> canonical A={Z,E,S,O,R}
  5.  Build AASG          -> DAG.aasg.AASGGraph         -> formal G=(V,E,Z)
  6.  Build ICS graph     -> DAG.graph_builder          -> ICSSecurityGraph
  7.  Generate layout     -> DAG.dag_generator          -> React Flow payload
  8.  Attack Path Gen.    -> DAG.path_analysis          -> Ea U Ec traversal paths
  9.  Risk Scoring        -> DAG.risk_engine            -> ranked risk scores + severity
  10. MITRE ATT&CK Map    -> DAG.mitre_mapper           -> technique + tactic mapping
  11. Blast Radius        -> DAG.path_analysis          -> per-node impact analysis
  12. Threat Propagation  -> DAG.threat_propagation     -> BFS infection simulation
  13. Lateral Movement    -> DAG.lateral_movement       -> cross-zone + pivot detection
  14. Reachability        -> DAG.reachability           -> cyber-physical exposure
"""

from fastapi import FastAPI, File, UploadFile, Body, Query
from fastapi.middleware.cors import CORSMiddleware
from pathlib import Path
import os
from dotenv import load_dotenv

# Load environment variables from .env file immediately at startup
load_dotenv(dotenv_path=Path(__file__).parent / ".env", override=True)

BACKEND_HOST = os.getenv("BACKEND_HOST", "127.0.0.1")
BACKEND_PORT = int(os.getenv("BACKEND_PORT", os.getenv("PORT", "7429")))

import shutil
import traceback
import uuid
from typing import Optional

from parsers.rbac_parser      import parse_rbac, RBACParser
from parsers.firewall_parser  import parse_firewall, FirewallParser
from parsers.text_parser      import text_to_graph
from parsers.image_parser     import image_to_graph
from parsers.unified_model    import build_unified_model, UnifiedModel

from DAG.aasg              import AASGGraph
from DAG.graph_builder     import build_graph
from DAG.graph_validator   import validate_graph
from DAG.path_analysis     import ICSPathAnalyzer
from DAG.reachability      import AdvancedICSReachabilityEngine
from DAG.dag_generator     import ICSAnalysisDAGBuilder
from DAG.layer_assignment  import _parse_purdue_to_tier
from DAG.mitre_mapper      import MITREMapper
from DAG.risk_engine       import RiskEngine
from DAG.threat_propagation import ThreatPropagator
from DAG.lateral_movement  import LateralMovementAnalyzer


app = FastAPI(title="ICS AASG — Authorization Attack Surface Graph API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)

UPLOAD_DIR = Path("uploads")
UPLOAD_DIR.mkdir(exist_ok=True)


# ---------------------------------------------------------------------------
# Health
# ---------------------------------------------------------------------------

@app.get("/")
def home():
    return {"status": "ICS AASG backend running", "version": "2.0"}

@app.get("/health")
def health():
    return {"status": "ok"}


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(
        "main:app",
        host=BACKEND_HOST,
        port=BACKEND_PORT,
        reload=True,
    )


# ---------------------------------------------------------------------------
# Core security analysis pipeline
# ---------------------------------------------------------------------------

def _layer_matrix_from_graph(ics_graph) -> dict:
    """Build layer/zone matrix for DAG layout generator."""
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
    """
    Print a comprehensive AASG pipeline summary to stdout.
    This verifies both Phase 1 and Phase 2 correctness.
    """
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

    # Firewall filtering
    blocked = unified_data.get("firewall_blocked", [])
    if blocked:
        print(f"\n[FIREWALL] Blocked {len(blocked)} architecture connections (Ec filtered)", flush=True)
        for b in blocked[:5]:
            print(f"  [FAIL] {b['src']} -> {b['dst']}: {b.get('reason','blocked')}", flush=True)
        if len(blocked) > 5:
            print(f"  ... and {len(blocked)-5} more", flush=True)
    else:
        print(f"\n[FIREWALL] No firewall file uploaded - all architecture connections included in Ec", flush=True)

    # Validation
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

    # Attack paths
    print(f"\n[ATTACK PATHS] {len(attack_paths)} risk vector(s) found", flush=True)
    for i, p in enumerate(attack_paths[:3]):
        path_str = " -> ".join(p["path"])
        print(f"  #{i+1}: risk={p['overall_risk']} | {path_str}", flush=True)
    if len(attack_paths) > 3:
        print(f"  ... and {len(attack_paths)-3} more", flush=True)

    # NetworkX graph stats
    nx_graph = ics_graph.asset_graph
    print(f"\n[NETWORKX GRAPH]", flush=True)
    print(f"  Nodes: {nx_graph.number_of_nodes()}", flush=True)
    print(f"  Edges: {nx_graph.number_of_edges()}", flush=True)
    print(f"  Entry points:    {len(ics_graph.entry_points)}", flush=True)
    print(f"  Critical assets: {len(ics_graph.critical_assets)}", flush=True)
    print(f"  Physical targets: {len(ics_graph.physical_targets)}", flush=True)

    # Unified model validation issues
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
    """Build a stage-by-stage pipeline quality graph for quick diagnostics."""
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
    """
    Execute the full 13-step security analysis pipeline on the unified A={Z,E,S,O,R} model.

    Steps:
      1.  Build formal AASG G=(V,E,Z)    - from unified_data
      2.  Build ICSSecurityGraph          - for path analysis and visualization
      3.  Validate graph structure
      4.  Attack Path Generation          - traverses Ea U Ec combined graph
      5.  Risk Scoring                    — multi-factor scoring per path
      6.  MITRE ATT&CK Mapping            — maps Ea/Ec edges to ICS techniques
      7.  Blast Radius Analysis           — per-node downstream exposure
      8.  Threat Propagation Simulation   — BFS infection spread from entry points
      9.  Lateral Movement Detection      — cross-zone, privilege, protocol pivots
      10. Cyber-Physical Reachability     — entry → physical asset vectors
      11. Zone-to-Zone Matrix             — ISA-62443 conduit reachability map
      12. Layout DAG                      — React Flow payload generation
    """
    # Step 1: Formal AASG
    aasg_graph = AASGGraph(unified_data)

    # Step 2: ICS Security Graph (for path analysis and visualization)
    ics_graph = build_graph(unified_data)

    # Step 3: Validation
    validation_report = validate_graph(ics_graph)

    # Determine entry points and targets
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

    # Fallback: if no entry points are classified structurally, use source nodes (in-degree = 0)
    if not entries:
        entries = {
            n for n, d in ics_graph.asset_graph.in_degree()
            if d == 0 and ics_graph.asset_graph.out_degree(n) > 0
        }

    targets = ics_graph.critical_assets or ics_graph.physical_targets or {
        n for n, d in ics_graph.asset_graph.out_degree() if d == 0 and ics_graph.asset_graph.in_degree(n) > 0
    }

    # Step 4: Attack Path Generation — Ea U Ec combined graph traversal
    print("[pipeline] Step 4: Attack Path Generation (Ea U Ec)...", flush=True)
    path_analyzer = ICSPathAnalyzer(ics_graph)
    attack_paths  = path_analyzer.analyze_attack_paths(entry_points=entries, targets=targets)
    print(f"[pipeline]   -> {len(attack_paths)} attack path(s) found", flush=True)

    # Step 5: Risk Scoring
    print("[pipeline] Step 5: Risk Scoring...", flush=True)
    risk_engine   = RiskEngine(ics_graph)
    scored_paths  = risk_engine.score_attack_paths(attack_paths)
    node_rankings = risk_engine.rank_critical_nodes()
    print(f"[pipeline]   -> Top risk score: {scored_paths[0]['risk_score'] if scored_paths else 0}", flush=True)

    # Step 6: MITRE ATT&CK Mapping (LLM-assisted with formal verification)
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
        )
        # Map each attack path's hops with full multi-hop chain context
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

    # Step 7: Blast Radius Analysis
    print("[pipeline] Step 7: Blast Radius Analysis...", flush=True)
    blast_radii = {}
    # Compute blast radius for every entry point and top critical nodes
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

    # Step 8: Threat Propagation Simulation
    print("[pipeline] Step 8: Threat Propagation Simulation...", flush=True)
    propagator = ThreatPropagator(ics_graph)
    propagation_results = {}
    for origin in list(entries)[:3]:   # limit to top 3 entry points
        try:
            propagation_results[origin] = propagator.simulate(origin, max_depth=8)
        except Exception as e:
            propagation_results[origin] = {"error": str(e)}
    print(f"[pipeline]   -> Propagation simulated from {len(propagation_results)} origin(s)", flush=True)

    # Step 9: Lateral Movement Detection
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

    # Step 10 & 11: Cyber-Physical Reachability + Zone Matrix
    print("[pipeline] Step 10-11: Reachability + Zone Matrix...", flush=True)
    reachability_engine    = AdvancedICSReachabilityEngine(ics_graph)
    cyber_physical_vectors = reachability_engine.check_cyber_to_physical_reachability(entry_points=entries)
    zone_matrix            = reachability_engine.compute_zone_to_zone_matrix()

    # Step 12: Layout DAG
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

    # Print comprehensive AASG summary
    _print_aasg_summary(aasg_graph, ics_graph, serialized_validation, scored_paths, unified_data)

    # Print MITRE mapping JSON to stdout for easy CLI copy-paste/inspection
    import json
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
        # ── Layout ────────────────────────────────────────────────────────
        "react_flow_asset_view":      layout_data["react_flow_asset_view"],
        "react_flow_macro_zone_view": layout_data["react_flow_macro_zone_view"],
        "layout_metadata":            layout_data["layout_metadata"],

        # ── Core analysis ─────────────────────────────────────────────────
        "validation_report": serialized_validation,

        # Step 4: Attack paths (Ea U Ec traversal)
        "attack_paths":  scored_paths,

        # Step 5: Risk scoring
        "risk_analysis": {
            "scored_paths":   scored_paths,
            "node_rankings":  node_rankings[:20],  # top 20 risky nodes
        },

        # Step 6: MITRE ATT&CK mapping (LLM-assisted + formal verification)
        "mitre_mapping": mitre_results,

        # Formal analysis (μ, Θ, ρ)
        "formal_analysis": mitre_results.get("formal_analysis", {}),

        # Step 7: Blast radius
        "blast_radius": blast_radii,

        # Step 8: Threat propagation
        "threat_propagation": propagation_results,

        # Step 9: Lateral movement
        "lateral_movement": lateral_report,

        # Steps 10-11: Reachability
        "reachability_data": {
            "cyber_physical_vectors": cyber_physical_vectors,
            "zone_matrix":            zone_matrix,
        },

        # ── AASG formal model ─────────────────────────────────────────────
        "aasg": aasg_graph.to_dict(),

        # ── Raw data ──────────────────────────────────────────────────────
        "raw_model_data": unified_data,

        # ── Source summaries ──────────────────────────────────────────────
        "rbac_summary":     rbac_summary,
        "firewall_summary": firewall_summary,

        # ── Code-review stage graph ───────────────────────────────────────
        "code_review_graph": code_review_graph,
    }


# ---------------------------------------------------------------------------
# Helper: read uploaded file as text
# ---------------------------------------------------------------------------

async def _read_text(uploaded_file: Optional[UploadFile]) -> str:
    if not uploaded_file:
        return ""
    try:
        content_bytes = await uploaded_file.read()
        await uploaded_file.seek(0)
        return content_bytes.decode("utf-8", errors="ignore")
    except Exception as e:
        print(f"[read_text] Error: {e}")
        return ""


# ---------------------------------------------------------------------------
# Helper: PDF → image conversion
# ---------------------------------------------------------------------------

def _convert_pdf_to_image(pdf_path: str) -> str:
    import fitz
    doc  = fitz.open(pdf_path)
    page = doc.load_page(0)
    pix  = page.get_pixmap(dpi=150)
    img_path = pdf_path.replace(".pdf", "_rendered.jpg")
    pix.save(img_path)
    return img_path


# ---------------------------------------------------------------------------
# Endpoint: /upload  (primary — image + RBAC + firewall)
# ---------------------------------------------------------------------------

@app.post("/upload")
async def upload(
    file: Optional[UploadFile]             = File(None),
    architecture_file: Optional[UploadFile] = File(None),
    rbac_file:         Optional[UploadFile] = File(None),
    firewall_file:     Optional[UploadFile] = File(None),
    role: str = Query(None),
):
    """
    Phase 1 extraction endpoint.

    Accepts three input files:
      architecture_file — image (PNG/JPG/WebP) or PDF
      rbac_file         — JSON / CSV / TXT with role policies
      firewall_file     — JSON / CSV / TXT with firewall rules
    """
    try:
        arch_file = architecture_file or file
        if not arch_file:
            return {"error": "No architecture file uploaded. Please provide an architecture diagram."}

        # ── Save architecture file ──────────────────────────────────────
        suffix     = Path(arch_file.filename).suffix.lower()
        saved_name = f"{uuid.uuid4().hex}{suffix}"
        file_path  = UPLOAD_DIR / saved_name

        with open(file_path, "wb") as buffer:
            shutil.copyfileobj(arch_file.file, buffer)

        # ── Step 1: Parse RBAC (authoritative source for S and R) ───────
        rbac_text    = await _read_text(rbac_file)
        rbac_data    = parse_rbac(rbac_text) if rbac_text else {"S": [], "R": [], "permissions": []}
        rbac_summary = rbac_data.copy()
        print(f"[upload] RBAC: {len(rbac_data.get('S', []))} subjects, "
              f"{len(rbac_data.get('R', []))} actions, "
              f"{len(rbac_data.get('permissions', []))} permissions", flush=True)
        if rbac_data.get("S"):
            subj_names = ", ".join(s.get("id","?") for s in rbac_data["S"][:6])
            print(f"[upload]   Subjects: {subj_names}", flush=True)
        if rbac_text and not rbac_data.get("S"):
            print("[upload] [WARN] WARNING: RBAC file was uploaded but no subjects were extracted. "
                  "Check RBAC file format.", flush=True)

        # ── Step 2: Parse Firewall rules ─────────────────────────────────
        fw_text      = await _read_text(firewall_file)
        fw_parser    = FirewallParser().parse(fw_text) if fw_text else None
        fw_summary   = fw_parser.to_dict() if fw_parser else {"rules": [], "allowed_pairs": [], "allowed_count": 0}
        if fw_parser:
            print(f"[upload] Firewall: {len(fw_parser.rules)} rules, "
                  f"{len(fw_parser.allowed_pairs)} allowed pairs", flush=True)
        else:
            print("[upload] Firewall: No firewall file - all architecture connections will be included in Ec", flush=True)

        # ── Step 3: Extract architecture (zones, objects, connections) ───
        if suffix in (".png", ".jpg", ".jpeg", ".webp"):
            arch_raw = image_to_graph(str(file_path))
        elif suffix == ".pdf":
            try:
                img_path = _convert_pdf_to_image(str(file_path))
                arch_raw = image_to_graph(img_path)
            except Exception as e:
                print(f"[upload] PDF->image failed: {e}; trying text extraction", flush=True)
                arch_raw = {"raw_model_data": {}, "error": str(e)}
        else:
            return {"error": f"Unsupported architecture file type: {suffix}"}

        if "error" in arch_raw and not arch_raw.get("raw_model_data"):
            return arch_raw

        # image_to_graph returns raw_model_data with {Z, O, E.connections}
        arch_data = arch_raw.get("raw_model_data", arch_raw)

        print(f"[upload] Architecture extracted: "
              f"{len(arch_data.get('Z', arch_data.get('zones', [])))} zones, "
              f"{len(arch_data.get('O', arch_data.get('assets', [])))} objects, "
              f"{len((arch_data.get('E') or {}).get('connections', arch_data.get('communications', [])))} connections",
              flush=True)

        # ── Step 4: Merge into canonical A={Z,E,S,O,R} ──────────────────
        print("[upload] Merging into unified model...", flush=True)
        unified_data = build_unified_model(arch_data, rbac_data, fw_parser)

        print(f"[upload] Unified model: "
              f"Z={len(unified_data.get('Z',[]))}, "
              f"S={len(unified_data.get('S',[]))}, "
              f"O={len(unified_data.get('O',[]))}, "
              f"R={len(unified_data.get('R',[]))}, "
              f"Ea={len((unified_data.get('E') or {}).get('Ea',[]))}, "
              f"Ec={len((unified_data.get('E') or {}).get('Ec',[]))}, "
              f"blocked={len(unified_data.get('firewall_blocked',[]))}",
              flush=True)

        # ── Step 5: Run full analysis pipeline ───────────────────────────
        print("[upload] Running security analysis pipeline...", flush=True)
        return run_security_analysis(unified_data, rbac_summary, fw_summary, selected_role=role)

    except Exception as e:
        traceback.print_exc()
        return {"error": str(e)}


# ---------------------------------------------------------------------------
# Endpoint: /generate-from-text  (alternative architecture source)
# ---------------------------------------------------------------------------

@app.post("/generate-from-text")
async def generate_from_text(payload: dict = Body(...)):
    """
    Alternative architecture source: text description.

    Accepts a plain-text description of the ICS architecture, plus optional
    RBAC and firewall content.  Produces the same unified A={Z,E,S,O,R} output
    as the image upload endpoint.
    """
    try:
        text          = payload.get("text", "")
        role          = payload.get("role", None)
        rbac_text     = payload.get("rbac_text", "")
        firewall_text = payload.get("firewall_text", "")

        if not text.strip():
            return {"error": "No architecture text provided."}

        # Parse RBAC and firewall
        rbac_data    = parse_rbac(rbac_text) if rbac_text else {"S": [], "R": [], "permissions": []}
        fw_parser    = FirewallParser().parse(firewall_text) if firewall_text else None
        fw_summary   = fw_parser.to_dict() if fw_parser else {"rules": [], "allowed_pairs": [], "allowed_count": 0}

        print(f"[text] RBAC: {len(rbac_data.get('S',[]))} subjects, "
              f"{len(rbac_data.get('R',[]))} actions, "
              f"{len(rbac_data.get('permissions',[]))} permissions", flush=True)
        if fw_parser:
            print(f"[text] Firewall: {len(fw_parser.rules)} rules", flush=True)

        # Parse architecture from text — now returns canonical {Z, O, E} schema
        arch_data = text_to_graph(text)

        print(f"[text] Architecture: "
              f"{len(arch_data.get('Z',[]))} zones, "
              f"{len(arch_data.get('O',[]))} objects, "
              f"{len(arch_data.get('E',{}).get('connections',[]))} connections",
              flush=True)

        # Merge and analyse
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
        traceback.print_exc()
        return {"error": str(e)}


# ---------------------------------------------------------------------------
# Endpoint: /blast-radius
# ---------------------------------------------------------------------------

@app.post("/blast-radius")
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
        traceback.print_exc()
        return {"error": str(e)}


# ---------------------------------------------------------------------------
# Endpoint: /threat-propagation
# ---------------------------------------------------------------------------

@app.post("/threat-propagation")
async def threat_propagation_endpoint(payload: dict = Body(...)):
    """
    Simulate threat propagation (malware/infection spread) from one or more
    compromised origin nodes through the ICS graph.

    Body:
        graph_data   — unified model dict (raw_model_data from a previous analysis)
        origin_node  — single node ID to simulate from (optional if origins provided)
        origins      — list of node IDs (optional, alternative to origin_node)
        max_depth    — maximum BFS propagation depth (default 8)
        min_prob     — minimum edge propagation probability (default 0.1)
    """
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
            # Default: simulate from all entry points
            entry_list = list(ics_graph.entry_points)[:3]
            if not entry_list:
                return {"error": "No entry points found and no origin specified."}
            result = propagator.simulate_multi_origin(entry_list, max_depth=max_depth, min_prob=min_prob)

        return result
    except Exception as e:
        traceback.print_exc()
        return {"error": str(e)}


# ---------------------------------------------------------------------------
# Endpoint: /lateral-movement
# ---------------------------------------------------------------------------

@app.post("/lateral-movement")
async def lateral_movement_endpoint(payload: dict = Body(...)):
    """
    Detect lateral movement patterns in the ICS graph.

    Body:
        graph_data — unified model dict
        top_paths  — max number of lateral movement paths to return (default 5)
    """
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
        traceback.print_exc()
        return {"error": str(e)}


# ---------------------------------------------------------------------------
# Endpoint: /mitre-mapping
# ---------------------------------------------------------------------------

@app.post("/mitre-mapping")
async def mitre_mapping_endpoint(payload: dict = Body(...)):
    """
    Map AASG edges to MITRE ATT&CK for ICS techniques.

    Body:
        graph_data — unified model dict (raw_model_data from a previous analysis)
    """
    graph_data = payload.get("graph_data", {})
    mode       = payload.get("mode", os.getenv("MITRE_MAPPER_MODE", "llm")).lower()
    if not graph_data:
        return {"error": "Missing graph_data"}

    try:
        aasg_graph   = AASGGraph(graph_data)
        ics_graph    = build_graph(graph_data)
        mitre_mapper = MITREMapper(use_llm=(mode != "rules"))
        # Use context-aware mapping with graph reachability and firewall verification
        result = mitre_mapper.map_aasg_with_context(
            aasg_graph,
            ics_graph,
            firewall_rules=[],   # no separate firewall payload in this endpoint
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
        traceback.print_exc()
        return {"error": str(e)}


# ---------------------------------------------------------------------------
# Endpoint: /risk-scoring
# ---------------------------------------------------------------------------

@app.post("/risk-scoring")
async def risk_scoring_endpoint(payload: dict = Body(...)):
    """
    Score attack paths and rank all nodes by structural risk.

    Body:
        graph_data   — unified model dict
        attack_paths — pre-computed attack paths list (optional; if absent,
                       paths will be computed fresh)
    """
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
        traceback.print_exc()
        return {"error": str(e)}
