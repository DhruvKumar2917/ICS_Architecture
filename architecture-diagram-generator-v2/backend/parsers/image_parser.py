import base64
import json
import re
import requests
from pathlib import Path
from PIL import Image

from parsers.ocr_parser import extract_ocr_text

OLLAMA_URL = "http://localhost:11434/api/generate"
VISION_MODEL = "llava"

def preprocess_image(image_path):
    img = Image.open(image_path).convert("RGB")
    max_width = 1000
    if img.width > max_width:
        ratio = max_width / img.width
        new_height = int(img.height * ratio)
        img = img.resize((max_width, new_height))
    new_path = str(Path(image_path).with_name("preprocessed_" + Path(image_path).name))
    img.save(new_path, quality=90)
    return new_path

def extract_json(text):
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
    Converts the Advanced Phase 1 ICS JSON into a flat DAG format.
    Captures deep semantics: nested zones, purdue levels, physical processes, and strict boundaries.
    """
    nodes = []
    edges = []
    valid_node_ids = set()

    if not graph_data:
        return {"nodes": [], "edges": []}

    # 1. Map Zones to Nodes (Supporting Nesting)
    for i, zone in enumerate(graph_data.get('zones', [])):
        z_id = str(zone.get('id', f"zone_{i}"))
        nodes.append({
            "id": z_id,
            "label": zone.get('name', 'Unknown Zone'),
            "type": "zone",
            "parent_zone": zone.get('parent_zone', None)
        })
        valid_node_ids.add(z_id)

    # 2. Map Assets to Nodes (Adding Criticality & Purdue Level)
    for i, asset in enumerate(graph_data.get('assets', [])):
        n_id = str(asset.get('id', f"asset_{i}"))
        nodes.append({
            "id": n_id,
            "label": asset.get('name', 'Unknown Asset'),
            "type": asset.get('type', 'device'),
            "zone": asset.get('zone', 'unknown'),
            "criticality": asset.get('criticality', 'medium'),
            "purdue_level": asset.get('purdue_level', 'unknown'),
            "is_enforcement_point": asset.get('is_enforcement_point', False)
        })
        valid_node_ids.add(n_id)

    # 3. Map Roles to Nodes
    for i, role in enumerate(graph_data.get('roles', [])):
        n_id = str(role.get('id', f"role_{i}"))
        nodes.append({
            "id": n_id,
            "label": role.get('name', 'Unknown Role'),
            "type": "user"
        })
        valid_node_ids.add(n_id)

    # Helper function to safely map edges
    def add_edge_safely(edge_id, source, target, label, edge_type="default", metadata=None):
        if not source or not target or source == "None" or target == "None":
            return

        if source not in valid_node_ids:
            nodes.append({"id": source, "label": source.replace('_', ' ').title(), "type": "inferred_node"})
            valid_node_ids.add(source)
        if target not in valid_node_ids:
            nodes.append({"id": target, "label": target.replace('_', ' ').title(), "type": "inferred_node"})
            valid_node_ids.add(target)

        edges.append({
            "id": edge_id,
            "source": source,
            "target": target,
            "label": label,
            "edge_type": edge_type,
            "metadata": metadata or {}
        })

    # 4. Map Network Communications
    for i, comm in enumerate(graph_data.get('communications', [])):
        add_edge_safely(
            f"comm_{i}",
            str(comm.get('source')),
            str(comm.get('target')),
            comm.get('protocol') or "network_traffic",
            "communication"
        )

    # 5. Map Conduits (Zone Links)
    for i, conduit in enumerate(graph_data.get('conduits', [])):
        add_edge_safely(
            f"cond_{i}",
            str(conduit.get('source_zone')),
            str(conduit.get('target_zone')),
            conduit.get('channel', 'conduit'),
            "conduit"
        )

    # 6. Map Human Permissions
    for i, perm in enumerate(graph_data.get('permissions', [])):
        add_edge_safely(
            f"perm_{i}",
            str(perm.get('subject')),
            str(perm.get('object')),
            perm.get('action') or "interact",
            "permission"
        )

    # 7. Map Cyber-Physical Dependencies (Control Chains)
    for i, phys in enumerate(graph_data.get('physical_dependencies', [])):
        add_edge_safely(
            f"phys_{i}",
            str(phys.get('cyber_asset')),
            str(phys.get('physical_process')),
            phys.get('relationship', 'controls'),
            "cyber_physical"
        )

    return {"nodes": nodes, "edges": edges}

def image_to_graph(image_path):
    try:
        ocr_text = extract_ocr_text(image_path)

        image_path = preprocess_image(image_path)
        with open(image_path, "rb") as img:
            encoded = base64.b64encode(img.read()).decode("utf-8")

        prompt = f"""
You are an Expert Industrial Control System (ICS) Security Architect.
Your task is to reconstruct a complete, highly detailed Phase 2 Cyber-Physical Threat Model graph from the architecture diagram and OCR text. 

OCR TEXT:
{ocr_text}

=== PHASE 2 ADVANCED EXTRACTION MANDATES ===

1. CONTROL HIERARCHY & PURDUE MODEL: 
You must reconstruct the entire control chain down to the physics. Assign a `purdue_level` to every asset (e.g., Level 3 for SCADA, Level 2 for HMI, Level 1 for PLC, Level 0 for I/O and Sensors). 
Extract specific granular assets: Master HMI, Slave HMI, PLC, Distributed I/O. Do not collapse them.

2. ASSET CRITICALITY:
Assign `criticality` strictly: PLCs, Safety Controllers, and Sensors are "critical". HMIs and SCADA are "high". Workstations are "medium". External firewalls are "low" (from an OT process perspective).

3. EXPLICIT ZONE NESTING & TRUST BOUNDARIES:
Every asset belongs to a zone. If a zone is inside another zone (e.g., Turbine Local Control inside Wind Farm Control), use the `parent_zone` property. 
You MUST populate the `trust_boundaries` array to explicitly define which security device separates which zones.

4. SEPARATE HUMANS FROM NETWORKS:
CRITICAL RULE: Humans/Roles are NEVER network endpoints. Communications are strictly ASSET-TO-ASSET. Humans only interact with assets via `permissions`. 

5. GRANULAR PERMISSIONS:
Roles must connect to assets using specific actions. Allowed actions: "monitor", "read", "configure", "control", "administer". Do not use generic "access".

6. PROTOCOLS & PHYSICAL DEPENDENCIES:
Infer network protocols if obvious (e.g., VPN, Modbus, TCP/IP).
Use the `physical_dependencies` array to explicitly link cyber assets to physical equipment (e.g., PLC controls Turbine Generator).

Required JSON Structure:
{{
  "zones": [
    {{ "id": "wind_farm_control", "name": "Wind Farm Control Center", "parent_zone": null }},
    {{ "id": "turbine_local_control", "name": "Turbine Local Control", "parent_zone": "wind_farm_control" }}
  ],
  "trust_boundaries": [
    {{ "id": "boundary_1", "enforcement_point": "vendor_firewall", "separates": ["external_wan", "vendor_domain"] }}
  ],
  "roles": [
    {{ "id": "vendor_operator", "name": "Vendor Operator" }}
  ],
  "assets": [
    {{ "id": "master_hmi", "name": "Master HMI", "type": "hmi", "zone": "turbine_local_control", "criticality": "high", "purdue_level": "Level 2", "is_enforcement_point": false }},
    {{ "id": "turbine_plc", "name": "Turbine PLC", "type": "plc", "zone": "turbine_local_control", "criticality": "critical", "purdue_level": "Level 1", "is_enforcement_point": false }}
  ],
  "communications": [
    {{ "source": "master_hmi", "target": "turbine_plc", "protocol": "ot_traffic" }}
  ],
  "conduits": [
    {{ "id": "vpn_tunnel_1", "source_zone": "external_wan", "target_zone": "vendor_domain", "channel": "VPN" }}
  ],
  "permissions": [
    {{ "subject": "vendor_operator", "object": "master_hmi", "action": "control" }}
  ],
  "physical_dependencies": [
    {{ "cyber_asset": "turbine_plc", "physical_process": "wind_turbine_generator", "relationship": "controls_physics" }}
  ]
}}

CRITICAL DAG RULE: Every ID referenced as a source, target, subject, object, cyber_asset, or zone MUST be defined in the main arrays. Extract comprehensively. Do not stop at a few nodes.
Return ONLY valid JSON. No markdown.
"""

        response = requests.post(
            OLLAMA_URL,
            json={
                "model": VISION_MODEL,
                "prompt": prompt,
                "images": [encoded],
                "stream": False,
                "options": {
                    "temperature": 0.1,
                    "num_predict": 4000 # Maximized to ensure long, complex architectures do not cut off
                }
            },
            timeout=300
        )

        response.raise_for_status()
        result = response.json()
        raw_text = result.get("response", "")

        graph = extract_json(raw_text)

        if graph:
            dag_data = transform_to_dag(graph)
            return {
                "ocr_text": ocr_text,
                "nodes": dag_data["nodes"],
                "edges": dag_data["edges"],
                "raw_model_data": graph
            }

        return {
            "ocr_text": ocr_text,
            "nodes": [],
            "edges": [],
            "error": "Model did not return valid JSON."
        }

    except Exception as e:
        return {"nodes": [], "edges": [], "error": str(e)}