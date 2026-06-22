"""
ICS AASG Backend — FastAPI Application.

Pipeline (Phase 1 Extraction):
  1. Parse RBAC file     → parsers.rbac_parser     → {S, R, permissions}
  2. Parse Firewall file → parsers.firewall_parser  → {rules, allowed_pairs}
  3. Parse Architecture  → parsers.image_parser /   → {Z, O, E.connections}
                           parsers.text_parser
  4. Merge              → parsers.unified_model     → canonical A={Z,E,S,O,R}
  5. Build AASG         → DAG.aasg.AASGGraph        → formal G=(V,E,Z)
  6. Build ICS graph    → DAG.graph_builder         → ICSSecurityGraph (for visualization)
  7. Generate layout    → DAG.dag_generator         → React Flow payload
  8. Analyze paths      → DAG.path_analysis         → attack vectors (post-AASG)
  9. Compute blast radii → DAG.reachability         → cyber-physical exposure

Attack paths and blast radii are computed AFTER the AASG is stable.
MITRE ATT&CK mapping is deferred to Phase 3 (not performed here).
"""

from fastapi import FastAPI, File, UploadFile, Body, Query
from fastapi.middleware.cors import CORSMiddleware
from pathlib import Path
import shutil
import traceback
import uuid
from typing import Optional

from parsers.rbac_parser      import parse_rbac, RBACParser
from parsers.firewall_parser  import parse_firewall, FirewallParser
from parsers.text_parser      import text_to_graph
from parsers.image_parser     import image_to_graph
from parsers.unified_model    import build_unified_model, UnifiedModel

from DAG.aasg            import AASGGraph
from DAG.graph_builder   import build_graph
from DAG.graph_validator import validate_graph
from DAG.path_analysis   import ICSPathAnalyzer
from DAG.reachability    import AdvancedICSReachabilityEngine
from DAG.dag_generator   import ICSAnalysisDAGBuilder
from DAG.layer_assignment import _parse_purdue_to_tier


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


def run_security_analysis(unified_data: dict, rbac_summary: dict, firewall_summary: dict, selected_role: str = None) -> dict:
    """
    Execute the full analysis pipeline on the unified A={Z,E,S,O,R} model.

    Steps:
      1. Build formal AASG G=(V,E,Z)  — from unified_data
      2. Build ICSSecurityGraph        — for visualization and path analysis
      3. Validate graph structure
      4. Analyze attack paths          — AFTER AASG is built
      5. Compute cyber-physical reachability
      6. Generate React Flow layout
    """
    # Step 1: Formal AASG
    aasg_graph = AASGGraph(unified_data)

    # Step 2: ICS Security Graph (for path analysis and visualization)
    ics_graph = build_graph(unified_data)

    # Step 3: Validation
    validation_report = validate_graph(ics_graph)

    # Step 4: Attack paths — computed AFTER AASG is stable
    analyzer = ICSPathAnalyzer(ics_graph)

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

    targets = ics_graph.critical_assets or ics_graph.physical_targets or {
        n for n, d in ics_graph.asset_graph.out_degree() if d == 0 and ics_graph.asset_graph.in_degree(n) > 0
    }

    attack_paths = analyzer.analyze_attack_paths(entry_points=entries, targets=targets)

    # Step 5: Reachability
    reachability_engine      = AdvancedICSReachabilityEngine(ics_graph)
    cyber_physical_vectors   = reachability_engine.check_cyber_to_physical_reachability(entry_points=entries)
    zone_matrix              = reachability_engine.compute_zone_to_zone_matrix()

    # Step 6: Layout DAG
    layer_matrix = _layer_matrix_from_graph(ics_graph)
    dag_builder  = ICSAnalysisDAGBuilder(ics_graph, layer_matrix, active_attack_paths=attack_paths)
    layout_data  = dag_builder.build()

    serialized_validation = {
        "is_valid":  validation_report.get("is_valid", True),
        "errors":    list(validation_report.get("errors", [])),
        "warnings":  list(validation_report.get("warnings", [])),
        "stats":     validation_report.get("stats", {}),
    }

    # Print comprehensive AASG summary
    _print_aasg_summary(aasg_graph, ics_graph, serialized_validation, attack_paths, unified_data)

    return {
        # Layout
        "react_flow_asset_view":      layout_data["react_flow_asset_view"],
        "react_flow_macro_zone_view": layout_data["react_flow_macro_zone_view"],
        "layout_metadata":            layout_data["layout_metadata"],

        # Analysis results
        "validation_report": serialized_validation,
        "attack_paths":      attack_paths,
        "reachability_data": {
            "cyber_physical_vectors": cyber_physical_vectors,
            "zone_matrix":            zone_matrix,
        },

        # Formal AASG model G = (V, E, Z)
        "aasg": aasg_graph.to_dict(),

        # Canonical A = {Z, E, S, O, R} for download / debugging
        "raw_model_data": unified_data,

        # Source summaries for the frontend panels
        "rbac_summary":     rbac_summary,
        "firewall_summary": firewall_summary,
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
            print("[upload] Firewall: No firewall file — all architecture connections will be included in Ec", flush=True)

        # ── Step 3: Extract architecture (zones, objects, connections) ───
        if suffix in (".png", ".jpg", ".jpeg", ".webp"):
            arch_raw = image_to_graph(str(file_path))
        elif suffix == ".pdf":
            try:
                img_path = _convert_pdf_to_image(str(file_path))
                arch_raw = image_to_graph(img_path)
            except Exception as e:
                print(f"[upload] PDF→image failed: {e}; trying text extraction", flush=True)
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