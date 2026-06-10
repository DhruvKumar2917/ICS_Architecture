import base64
import json
import os
import re
from pathlib import Path
from PIL import Image

from dotenv import load_dotenv
from openai import OpenAI

# Load .env from the backend directory
load_dotenv(dotenv_path=Path(__file__).parent.parent / ".env")

# Initialize OpenAI client (reads OPENAI_API_KEY from .env automatically)
client = OpenAI(api_key=os.getenv("OPENAI_API_KEY"))

# Model to use – GPT-4.1 supports vision natively via the Chat Completions API
VISION_MODEL = os.getenv("OPENAI_VISION_MODEL", "gpt-4.1")


def preprocess_image(image_path):
    """
    Resizes the image to a maximum width of 1500px to reduce token cost
    while keeping enough detail for GPT-4.1 to read labels accurately.
    GPT-4.1 supports high-detail vision natively, so we do NOT need EasyOCR.
    """
    img = Image.open(image_path).convert("RGB")
    max_width = 1500
    if img.width > max_width:
        ratio = max_width / img.width
        new_height = int(img.height * ratio)
        img = img.resize((max_width, new_height), Image.LANCZOS)
    new_path = str(Path(image_path).with_name("preprocessed_" + Path(image_path).name))
    img.save(new_path, format="JPEG", quality=92)
    return new_path


def extract_json(text):
    """Robustly extracts the first valid JSON object from a model response."""
    try:
        return json.loads(text)
    except Exception:
        pass
    match = re.search(r"\{[\s\S]*\}", text)
    if match:
        try:
            return json.loads(match.group(0))
        except Exception:
            pass
    return None


def transform_to_dag(graph_data):
    """
    Converts the Phase 1 ICS JSON into a flat DAG format.
    Captures deep semantics: nested zones, purdue levels, physical processes,
    trust boundaries, and conduits.
    """
    nodes = []
    edges = []
    valid_node_ids = set()

    if not graph_data:
        return {"nodes": [], "edges": []}

    # 1. Map Zones to Nodes (Supporting Nesting)
    for i, zone in enumerate(graph_data.get("zones", [])):
        z_id = str(zone.get("id", f"zone_{i}"))
        nodes.append({
            "id": z_id,
            "label": zone.get("name", "Unknown Zone"),
            "type": "zone",
            "parent_zone": zone.get("parent_zone", None)
        })
        valid_node_ids.add(z_id)

    # 2. Map Assets to Nodes (with Criticality & Purdue Level)
    for i, asset in enumerate(graph_data.get("assets", [])):
        n_id = str(asset.get("id", f"asset_{i}"))
        nodes.append({
            "id": n_id,
            "label": asset.get("name", "Unknown Asset"),
            "type": asset.get("type", "device"),
            "zone": asset.get("zone", "unknown"),
            "criticality": asset.get("criticality", "medium"),
            "purdue_level": asset.get("purdue_level", "unknown"),
            "is_enforcement_point": asset.get("is_enforcement_point", False)
        })
        valid_node_ids.add(n_id)

    # 3. Map Roles / Human Actors to Nodes
    for i, role in enumerate(graph_data.get("roles", [])):
        n_id = str(role.get("id", f"role_{i}"))
        nodes.append({
            "id": n_id,
            "label": role.get("name", "Unknown Role"),
            "type": "user"
        })
        valid_node_ids.add(n_id)

    # Helper: safely append an edge and inject missing endpoint nodes
    def add_edge_safely(edge_id, source, target, label, edge_type="default"):
        if not source or not target or source == "None" or target == "None":
            return
        if source not in valid_node_ids:
            nodes.append({"id": source, "label": source.replace("_", " ").title(), "type": "inferred_node"})
            valid_node_ids.add(source)
        if target not in valid_node_ids:
            nodes.append({"id": target, "label": target.replace("_", " ").title(), "type": "inferred_node"})
            valid_node_ids.add(target)
        edges.append({"id": edge_id, "source": source, "target": target, "label": label, "edge_type": edge_type})

    # 4. Network Communications (asset-to-asset links)
    for i, comm in enumerate(graph_data.get("communications", [])):
        add_edge_safely(f"comm_{i}", str(comm.get("source")), str(comm.get("target")),
                        comm.get("protocol") or "network_traffic", "communication")

    # 5. Conduits (zone-to-zone links)
    for i, conduit in enumerate(graph_data.get("conduits", [])):
        add_edge_safely(f"cond_{i}", str(conduit.get("source_zone")), str(conduit.get("target_zone")),
                        conduit.get("channel", "conduit"), "conduit")

    # 6. Human → Asset Permissions
    for i, perm in enumerate(graph_data.get("permissions", [])):
        add_edge_safely(f"perm_{i}", str(perm.get("subject")), str(perm.get("object")),
                        perm.get("action") or "interact", "permission")

    # 7. Cyber → Physical dependencies (control chains)
    for i, phys in enumerate(graph_data.get("physical_dependencies", [])):
        add_edge_safely(f"phys_{i}", str(phys.get("cyber_asset")), str(phys.get("physical_process")),
                        phys.get("relationship", "controls"), "cyber_physical")

    return {"nodes": nodes, "edges": edges}


def image_to_graph(image_path):
    """
    Main entry point: preprocess image → call GPT-4.1 vision API → parse JSON → DAG.
    No EasyOCR needed – GPT-4.1 reads text labels from the image natively.
    """
    try:
        # Step 1: Resize image for cost efficiency
        processed_path = preprocess_image(image_path)

        # Step 2: Base64-encode the preprocessed image
        with open(processed_path, "rb") as img_file:
            encoded_image = base64.b64encode(img_file.read()).decode("utf-8")

        # Step 3: Build the expert ICS extraction prompt
        prompt = """You are an Expert Industrial Control System (ICS) Security Architect.
Analyse the attached architecture diagram and reconstruct a complete, highly detailed
Cyber-Physical Threat Model in JSON.

=== EXTRACTION MANDATES ===

1. CONTROL HIERARCHY & PURDUE MODEL:
   Assign a purdue_level to EVERY asset:
     Level 5 / Level 4 – Enterprise / Business WAN
     Level 3            – SCADA Servers, Historians
     Level 2            – HMIs, Engineering Workstations
     Level 1            – PLCs, RTUs, Safety Controllers
     Level 0            – I/O Modules, Sensors, Actuators
   Do NOT collapse separate devices into one node.

2. ASSET CRITICALITY:
   PLCs, RTUs, Safety Controllers, Sensors → "critical"
   HMIs, SCADA Servers                    → "high"
   Workstations, Historians               → "medium"
   Firewalls (from OT perspective)        → "low"

3. ZONE NESTING & TRUST BOUNDARIES:
   Every asset must belong to a zone (use the zone id string).
   Use parent_zone for nested zones.
   Populate trust_boundaries: list every firewall/VPN and which two
   zones it separates.

4. SEPARATE HUMANS FROM NETWORKS:
   Humans/Roles are NEVER network endpoints.
   Communications are strictly asset-to-asset.
   Humans connect only via the permissions array.

5. GRANULAR PERMISSIONS:
   Use only: "monitor", "read", "configure", "control", "administer".

6. PROTOCOLS & PHYSICAL DEPENDENCIES:
   Infer protocols where visible (Modbus, OPC-UA, VPN, TCP/IP, etc.).
   physical_dependencies must list every PLC/RTU → physical process link.

Required JSON structure (return ONLY this JSON, no markdown, no commentary):
{
  "zones": [
    {"id": "zone_id", "name": "Zone Display Name", "parent_zone": null}
  ],
  "trust_boundaries": [
    {"id": "tb_1", "enforcement_point": "asset_id", "separates": ["zone_a", "zone_b"]}
  ],
  "roles": [
    {"id": "vendor_operator", "name": "Vendor Operator"}
  ],
  "assets": [
    {"id": "master_hmi", "name": "Master HMI", "type": "hmi",
     "zone": "turbine_local_control", "criticality": "high",
     "purdue_level": "Level 2", "is_enforcement_point": false}
  ],
  "communications": [
    {"source": "asset_id_a", "target": "asset_id_b", "protocol": "Modbus"}
  ],
  "conduits": [
    {"id": "vpn_1", "source_zone": "zone_a", "target_zone": "zone_b", "channel": "VPN"}
  ],
  "permissions": [
    {"subject": "vendor_operator", "object": "master_hmi", "action": "control"}
  ],
  "physical_dependencies": [
    {"cyber_asset": "turbine_plc", "physical_process": "wind_turbine_generator",
     "relationship": "controls_physics"}
  ]
}

CRITICAL: Every ID used as source, target, subject, object, cyber_asset, zone,
or enforcement_point MUST be defined in the main arrays first.
Extract ALL components visible in the diagram. Do not truncate.
Return ONLY valid JSON."""

        # Step 4: Call GPT-4.1 Chat Completions with vision
        response = client.chat.completions.create(
            model=VISION_MODEL,
            response_format={"type": "json_object"},   # Enforces strict JSON output
            messages=[
                {
                    "role": "user",
                    "content": [
                        {
                            "type": "text",
                            "text": prompt
                        },
                        {
                            "type": "image_url",
                            "image_url": {
                                "url": f"data:image/jpeg;base64,{encoded_image}",
                                "detail": "high"   # Uses high-res tiling for small labels
                            }
                        }
                    ]
                }
            ],
            temperature=0.1,
            max_tokens=4096
        )

        # Step 5: Parse the response JSON
        raw_text = response.choices[0].message.content
        graph = extract_json(raw_text)

        if graph:
            dag_data = transform_to_dag(graph)
            return {
                "ocr_text": "Extracted via GPT-4.1 native vision (no separate OCR required)",
                "nodes": dag_data["nodes"],
                "edges": dag_data["edges"],
                "raw_model_data": graph,
                "model_used": VISION_MODEL,
                "tokens_used": {
                    "prompt": response.usage.prompt_tokens,
                    "completion": response.usage.completion_tokens,
                    "total": response.usage.total_tokens
                }
            }

        return {
            "ocr_text": raw_text,
            "nodes": [],
            "edges": [],
            "error": "GPT-4.1 did not return valid JSON. Raw response stored in ocr_text."
        }

    except Exception as e:
        return {"nodes": [], "edges": [], "error": f"OpenAI API Error: {str(e)}"}