from fastapi import FastAPI, UploadFile, File, Body, Query
from fastapi.middleware.cors import CORSMiddleware
from pathlib import Path
import shutil
import uuid
import traceback

from parsers.text_parser import text_to_graph
from parsers.pdf_parser import extract_pdf_text
from parsers.table_parser import table_to_graph
from parsers.image_parser import image_to_graph

from DAG.graph_builder import build_graph
from DAG.graph_validator import validate_graph
from DAG.path_analysis import ICSPathAnalyzer
from DAG.reachability import AdvancedICSReachabilityEngine
from DAG.dag_generator import ICSAnalysisDAGBuilder
from DAG.layer_assignment import _parse_purdue_to_tier

app = FastAPI(title="Architecture Diagram Generator API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5173",
        "http://127.0.0.1:5173",
        "http://localhost:5174",
        "http://127.0.0.1:5174",
        "http://localhost:5175",
        "http://127.0.0.1:5175",
    ],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)

UPLOAD_DIR = Path("uploads")
UPLOAD_DIR.mkdir(exist_ok=True)


@app.get("/")
def home():
    return {"status": "Backend running"}


@app.get("/health")
def health():
    return {"status": "ok"}


def normalize_to_structured_schema(parse_output):
    """
    Ensures parser output is normalized to the rich schema needed by build_graph.
    """
    if not parse_output:
        return {}

    # If it already has raw_model_data (from image LLM), use that.
    if "raw_model_data" in parse_output and isinstance(parse_output["raw_model_data"], dict):
        return parse_output["raw_model_data"]

    # Otherwise, it's a flat nodes/edges structure. Let's build the structured schema.
    nodes = parse_output.get("nodes", [])
    edges = parse_output.get("edges", [])

    zones = []
    assets = []
    roles = []
    communications = []
    permissions = []
    physical_dependencies = []

    # Map nodes to zones, assets, and roles
    for node in nodes:
        node_id = node.get("id")
        label = node.get("label", "")
        node_type = node.get("type", "component")

        clean_type = str(node_type).lower()

        if clean_type == "user":
            roles.append({
                "id": node_id,
                "name": label
            })
        elif clean_type == "zone":
            zones.append({
                "id": node_id,
                "name": label,
                "parent_zone": None
            })
        else:
            purdue_level = "unknown"
            criticality = "medium"

            if clean_type == "plc":
                purdue_level = "Level 1"
                criticality = "critical"
            elif clean_type == "hmi":
                purdue_level = "Level 2"
                criticality = "high"
            elif clean_type in ["server", "scada"]:
                purdue_level = "Level 3"
                criticality = "high"
            elif clean_type == "vpn":
                purdue_level = "Level 4"
                criticality = "medium"
            elif clean_type == "firewall":
                purdue_level = "Level 4"
                criticality = "low"
            elif clean_type in ["sensor", "actuator"]:
                purdue_level = "Level 0"
                criticality = "critical"

            assets.append({
                "id": node_id,
                "name": label,
                "type": node_type,
                "zone": "unassigned_zone",
                "criticality": criticality,
                "purdue_level": purdue_level,
                "is_enforcement_point": (clean_type in ["firewall", "vpn"])
            })

    # Map edges to communications, permissions, and cyber_physical dependencies
    for i, edge in enumerate(edges):
        source = edge.get("source")
        target = edge.get("target")
        edge_label = edge.get("label", "connects")

        source_node = next((n for n in nodes if n["id"] == source), None)
        target_node = next((n for n in nodes if n["id"] == target), None)

        src_type = str(source_node.get("type", "")).lower() if source_node else ""
        tgt_type = str(target_node.get("type", "")).lower() if target_node else ""

        if src_type == "user":
            permissions.append({
                "subject": source,
                "object": target,
                "action": edge_label if edge_label != "connects" else "configure"
            })
        elif tgt_type in ["sensor", "actuator"] or "physical" in edge_label.lower():
            physical_dependencies.append({
                "cyber_asset": source,
                "physical_process": target,
                "relationship": edge_label if edge_label != "connects" else "controls"
            })
        else:
            communications.append({
                "source": source,
                "target": target,
                "protocol": edge_label
            })

    if assets:
        zones.append({
            "id": "unassigned_zone",
            "name": "General Zone",
            "parent_zone": None
        })

    return {
        "zones": zones,
        "trust_boundaries": [],
        "roles": roles,
        "assets": assets,
        "communications": communications,
        "conduits": [],
        "permissions": permissions,
        "physical_dependencies": physical_dependencies
    }


def run_security_analysis(structured_data: dict, selected_role: str = None):
    """
    Executes the advanced analysis and returns layout coordinates + reports.
    """
    ics_graph = build_graph(structured_data)
    validation_report = validate_graph(ics_graph)

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

    targets = ics_graph.critical_assets
    if not targets:
        targets = ics_graph.physical_targets
    if not targets:
        targets = {n for n, d in ics_graph.asset_graph.out_degree() if d == 0 and ics_graph.asset_graph.in_degree(n) > 0}

    attack_paths = analyzer.analyze_attack_paths(entry_points=entries, targets=targets)

    reachability_engine = AdvancedICSReachabilityEngine(ics_graph)
    cyber_physical_vectors = reachability_engine.check_cyber_to_physical_reachability(entry_points=entries)
    zone_matrix = reachability_engine.compute_zone_to_zone_matrix()

    layer_matrix = {}
    for node_id, attrs in ics_graph.asset_graph.nodes(data=True):
        purdue = attrs.get("purdue_level")
        tier = _parse_purdue_to_tier(purdue)
        
        if tier is None:
            role = attrs.get("security_role")
            node_cat = attrs.get("node_category")
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
            "zone": attrs.get("zone", "unassigned_zone")
        }

    dag_builder = ICSAnalysisDAGBuilder(ics_graph, layer_matrix, active_attack_paths=attack_paths)
    layout_data = dag_builder.build()

    serialized_validation = {
        "is_valid": validation_report.get("is_valid", True),
        "errors": list(validation_report.get("errors", [])),
        "warnings": list(validation_report.get("warnings", [])),
        "stats": validation_report.get("stats", {})
    }

    return {
        "react_flow_asset_view": layout_data["react_flow_asset_view"],
        "react_flow_macro_zone_view": layout_data["react_flow_macro_zone_view"],
        "layout_metadata": layout_data["layout_metadata"],
        "validation_report": serialized_validation,
        "attack_paths": attack_paths,
        "reachability_data": {
            "cyber_physical_vectors": cyber_physical_vectors,
            "zone_matrix": zone_matrix
        },
        "raw_model_data": structured_data
    }


def safe_text_to_graph(text: str):
    try:
        return text_to_graph(text)
    except Exception as e:
        traceback.print_exc()
        return {"nodes": [], "edges": [], "error": str(e)}


@app.post("/generate-from-text")
async def generate_from_text(payload: dict = Body(...)):
    text = payload.get("text", "")
    role = payload.get("role", None)
    parsed = safe_text_to_graph(text)
    if "error" in parsed:
        return parsed
    structured = normalize_to_structured_schema(parsed)
    return run_security_analysis(structured, selected_role=role)


@app.post("/generate-text")
async def generate_text(payload: dict = Body(...)):
    text = payload.get("text", "")
    role = payload.get("role", None)
    parsed = safe_text_to_graph(text)
    if "error" in parsed:
        return parsed
    structured = normalize_to_structured_schema(parsed)
    return run_security_analysis(structured, selected_role=role)


def process_uploaded_file(file_path: Path, suffix: str):
    if suffix == ".txt":
        return safe_text_to_graph(file_path.read_text(encoding="utf-8", errors="ignore"))

    if suffix == ".pdf":
        extracted_text = extract_pdf_text(str(file_path))
        return safe_text_to_graph(extracted_text)

    if suffix in [".csv", ".xlsx"]:
        return table_to_graph(str(file_path))

    if suffix in [".png", ".jpg", ".jpeg", ".webp"]:
        return image_to_graph(str(file_path))

    return {"nodes": [], "edges": [], "error": f"Unsupported file type: {suffix}"}


@app.post("/upload")
async def upload(file: UploadFile = File(...), role: str = Query(None)):
    try:
        suffix = Path(file.filename).suffix.lower()
        saved_name = f"{uuid.uuid4().hex}{suffix}"
        file_path = UPLOAD_DIR / saved_name

        with open(file_path, "wb") as buffer:
            shutil.copyfileobj(file.file, buffer)

        parsed = process_uploaded_file(file_path, suffix)
        if "error" in parsed:
            return parsed
        structured = normalize_to_structured_schema(parsed)
        return run_security_analysis(structured, selected_role=role)

    except Exception as e:
        traceback.print_exc()
        return {"nodes": [], "edges": [], "error": str(e)}


@app.post("/generate-file")
async def generate_file(file: UploadFile = File(...), role: str = Query(None)):
    return await upload(file, role=role)