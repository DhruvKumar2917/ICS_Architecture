import base64
import json
import os
import re
from pathlib import Path
from typing import Any, Dict, Optional

from PIL import Image
from dotenv import load_dotenv
from openai import OpenAI

# Load .env from the backend directory
load_dotenv(dotenv_path=Path(__file__).parent.parent / ".env")

# Initialize OpenAI client
client = OpenAI(api_key=os.getenv("OPENAI_API_KEY"))

# Model to use
VISION_MODEL = os.getenv("OPENAI_VISION_MODEL", "gpt-4.1")


def preprocess_image(image_path: str) -> str:
    """
    Resize image to a max width of 1500px to reduce token cost while keeping
    enough detail for GPT-4.1 to read labels.
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


def extract_json(text: str) -> Optional[Dict[str, Any]]:
    """Robustly extract JSON from model output."""
    if not text:
        return None

    cleaned = text.strip()
    cleaned = re.sub(r"^```(?:json)?\s*", "", cleaned, flags=re.IGNORECASE)
    cleaned = re.sub(r"\s*```$", "", cleaned)

    try:
        parsed = json.loads(cleaned)
        if isinstance(parsed, dict):
            return parsed
    except Exception:
        pass

    start = cleaned.find("{")
    end = cleaned.rfind("}")
    if start != -1 and end != -1 and end > start:
        candidate = cleaned[start : end + 1]
        try:
            parsed = json.loads(candidate)
            if isinstance(parsed, dict):
                return parsed
        except Exception:
            pass

    match = re.search(r"\{[\s\S]*\}", cleaned)
    if match:
        try:
            parsed = json.loads(match.group(0))
            if isinstance(parsed, dict):
                return parsed
        except Exception:
            pass

    return None


def slugify(value: Any, prefix: str = "x") -> str:
    value = str(value or "").strip().lower()
    value = re.sub(r"[^a-z0-9]+", "_", value)
    value = re.sub(r"_+", "_", value).strip("_")
    return value or prefix


def safe_list(value: Any):
    return value if isinstance(value, list) else []


def confidence_value(x: Any, default: float = 0.75) -> float:
    try:
        v = float(x)
        if 0.0 <= v <= 1.0:
            return v
    except Exception:
        pass
    return default


def normalize_action(action: Any) -> str:
    raw = slugify(action)
    mapping = {
        "monitor": "monitor",
        "read": "read",
        "write": "write",
        "configure": "configure",
        "control": "control",
        "administer": "administer",
        "execute": "execute",
        "maintain": "maintain",
        "observe": "observe",
    }
    return mapping.get(raw, raw or "read")


def build_authorization_prompt() -> str:
    return """
You are an expert ICS/OT architecture extractor for ISA/IEC 62443 security analysis.

Your ONLY task is to extract ZONES, OBJECTS, and raw COMMUNICATION LINKS from the
provided architecture diagram image.

=== CRITICAL RULES — VIOLATIONS WILL BREAK THE SECURITY MODEL ===

1. DO NOT extract, guess, or invent any subjects (roles, users, operators).
   Subjects such as VendorMaint, OEMOps, WFTech, NetAdmin come from a separate
   RBAC policy file and will be injected by a dedicated parser. You must leave
   S = [] (empty list) in your output.

2. DO NOT extract, guess, or invent any permissions or authorization rules.
   Permissions come from the RBAC policy file only. You must leave
   E.permissions = [] (empty list) in your output.

3. DO NOT generate MITRE ATT&CK technique IDs.
4. DO NOT generate attack paths or risk scores.
5. DO NOT invent information not visible in the diagram.

=== WHAT YOU MUST EXTRACT ===

Z (Zones): All security zones, network segments, or trust boundaries visible in the
  diagram. Examples: Vendor Control Room, Wind Farm Control Room, OEM Domain,
  Turbine Local Control, External Transit, DMZ, Enterprise Zone.

O (Objects): ALL physical and logical assets visible in the diagram. These are the
  PROTECTED OBJECTS that RBAC permissions will reference. Include:
  - PLCs, HMIs, SCADA servers, historians, engineering workstations
  - Firewalls, VPN gateways, routers, switches (mark is_enforcement_point=true)
  - Sensors, actuators, field devices
  - Servers, databases, cloud endpoints
  Assign each object to its visible zone and estimate its Purdue level.

E.connections: Raw communication links VISIBLE in the diagram between objects or
  zones. Do NOT filter by firewall rules — include all visual connections.

=== PROTOCOL INFERENCE — VERY IMPORTANT ===
You MUST infer the protocol from context. Do NOT use "unknown" if context exists.
Use these rules:
- VPN gateway or VPN tunnel label → "vpn" or "ipsec"
- OPC-UA label or OPC server → "opc-ua"
- Modbus label or PLC↔sensor link → "modbus"
- DNP3 label or RTU communication → "dnp3"
- EtherNet/IP label or industrial Ethernet → "ethernetip"
- IEC 104 / IEC 60870 label → "iec104"
- RDP label or remote desktop → "rdp"
- SSH label → "ssh"
- HTTP/HTTPS label or web → "https"
- PCN (Process Control Network) links → "pcn"
- HMI ↔ PLC link without explicit label → "modbus" (most common)
- HMI ↔ SCADA link → "opc-ua"
- Firewall ↔ firewall or cross-zone link → "tcp-ip"
- SCADA ↔ historian → "opc-da"
- Control room to field device without label → "industrial-ethernet"
- If a link is simply a network connection with no clues → "tcp-ip"
Only use "unknown" if there is absolutely no contextual information whatsoever.

=== CRITICALITY INFERENCE RULES ===
- PLC, RTU, safety controller → "critical"
- Sensor, actuator, physical device → "critical"
- SCADA server, master HMI → "critical"
- Firewall, VPN gateway → "high"
- Historian, engineering workstation → "high"
- HMI (non-master), server → "medium"
- Monitoring-only devices → "low"

=== IS_ENFORCEMENT_POINT RULES ===
Set is_enforcement_point=true for: firewalls, VPN gateways, security gateways,
unidirectional gateways, data diodes, proxy servers, DMZ servers.

=== OUTPUT JSON SCHEMA (strict) ===
{
  "Z": [
    { "id": "zone_id_snake_case", "name": "Human Readable Zone Name" }
  ],
  "S": [],
  "O": [
    {
      "id": "object_id_snake_case",
      "name": "Object Name",
      "type": "plc|hmi|scada|historian|workstation|server|sensor|actuator|firewall|vpn|gateway|unknown",
      "zone": "zone_id_or_null",
      "purdue_level": "Level 0|Level 1|Level 2|Level 3|Level 4|Level 5|unknown",
      "criticality": "critical|high|medium|low",
      "is_enforcement_point": true_or_false
    }
  ],
  "R": [],
  "E": {
    "permissions": [],
    "connections": [
      {
        "source": "source_object_id",
        "target": "target_object_id",
        "protocol": "inferred_protocol_name"
      }
    ]
  }
}

Constraints:
- All IDs must be lowercase snake_case.
- Return ONLY valid JSON. No markdown fences, no explanations.
- If you are unsure of a zone, use null for the zone field.
- NEVER use "unknown" for protocol if you can infer it from topology or labels.
"""


def transform_to_aasg(graph_data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Convert architecture extractor output {Z, O, E.connections} into a flat
    node/edge list for downstream compatibility.  Subjects and permissions are
    NOT included here — they are injected by the UnifiedModel merger later.
    """
    nodes = []
    edges = []
    valid_node_ids = set()

    if not graph_data:
        return {"nodes": [], "edges": [], "derived_paths": []}

    def add_node(node_id: str, label: str, node_type: str, data: Dict[str, Any]):
        if not node_id or node_id in valid_node_ids:
            return
        nodes.append(
            {
                "id": node_id,
                "label": label,
                "type": node_type,
                "data": data,
            }
        )
        valid_node_ids.add(node_id)

    def add_edge(edge_id: str, source: str, target: str, label: str, edge_type: str, data: Dict[str, Any]):
        if not source or not target or source == "None" or target == "None":
            return
        if source not in valid_node_ids:
            add_node(source, source.replace("_", " ").title(), "inferred_node", {"kind": "inferred"})
        if target not in valid_node_ids:
            add_node(target, target.replace("_", " ").title(), "inferred_node", {"kind": "inferred"})
        edges.append(
            {
                "id": edge_id,
                "source": source,
                "target": target,
                "label": label,
                "edge_type": edge_type,
                "data": data,
            }
        )

    # Zones (Z)
    for i, zone in enumerate(safe_list(graph_data.get("Z"))):
        zid = str(zone.get("id") or f"zone_{i}")
        add_node(
            zid,
            zone.get("name", zid.replace("_", " ").title()),
            "zone",
            {
                "kind": "zone",
                "parent_zone": zone.get("parent_zone"),
            },
        )

    # Subjects (S) — should be empty from image parser; populated by RBAC parser
    for i, subject in enumerate(safe_list(graph_data.get("S"))):
        sid = str(subject.get("id") or f"subject_{i}")
        add_node(
            sid,
            subject.get("name", sid.replace("_", " ").title()),
            "user",
            {
                "kind": "subject",
                "zone": "external_transit",
            },
        )

    # Objects (O)
    for i, obj in enumerate(safe_list(graph_data.get("O"))):
        oid = str(obj.get("id") or f"object_{i}")
        o_type = obj.get("type", "component")
        add_node(
            oid,
            obj.get("name", oid.replace("_", " ").title()),
            o_type,
            {
                "kind": "object",
                "object_type": o_type,
                "zone": obj.get("zone"),
                "purdue_level": obj.get("purdue_level", "unknown"),
                "criticality": obj.get("criticality", "medium"),
                "is_enforcement_point": obj.get("is_enforcement_point", False),
            },
        )

    e_data = graph_data.get("E", {})
    if not isinstance(e_data, dict):
        e_data = {}

    # Connections (E.connections)
    for i, conn in enumerate(safe_list(e_data.get("connections"))):
        src = conn.get("source")
        tgt = conn.get("target")
        proto = conn.get("protocol", "tcp-ip") or "tcp-ip"
        add_edge(
            f"comm_{i}",
            src,
            tgt,
            proto,
            "COMM_LINK",
            {"protocol": proto}
        )

    # Permissions (E.permissions) — should be empty from image parser
    for i, perm in enumerate(safe_list(e_data.get("permissions"))):
        sub = perm.get("subject")
        obj = perm.get("object")
        act = perm.get("action", "access")
        add_edge(
            f"perm_{i}",
            sub,
            obj,
            act,
            "HUMAN_PERM",
            {"action": act}
        )

    return {"nodes": nodes, "edges": edges, "derived_paths": []}


def _print_graph_summary(graph: Dict[str, Any]) -> None:
    """Print a small summary of what the model returned."""
    def n(x):
        return len(x) if isinstance(x, list) else 0

    e_data = graph.get("E", {})
    if not isinstance(e_data, dict):
        e_data = {}

    conns = e_data.get("connections", [])
    unknown_proto = sum(1 for c in conns if c.get("protocol", "unknown") in ("unknown", ""))

    print("\n[LLM OUTPUT SUMMARY]", flush=True)
    print(f"  Zones (Z): {n(graph.get('Z'))}", flush=True)
    print(f"  Subjects (S): {n(graph.get('S'))}", flush=True)
    print(f"  Objects (O): {n(graph.get('O'))}", flush=True)
    print(f"  Actions (R): {n(graph.get('R'))}", flush=True)
    print(f"  Permissions (E.permissions): {n(e_data.get('permissions'))}", flush=True)
    print(f"  Connections (E.connections): {n(conns)}", flush=True)
    if unknown_proto > 0:
        print(f"  WARNING: {unknown_proto}/{n(conns)} connections have unknown protocol", flush=True)
    else:
        print(f"  Protocol quality: All connections have named protocols [OK]", flush=True)
    print(flush=True)


def image_to_graph(image_path: str, rbac_content: str = "", firewall_content: str = ""):
    """
    Main entry point:
    preprocess image -> GPT-4.1 vision -> parse authorization JSON -> build AASG graph.
    """
    try:
        print(f"[image_to_graph] Starting extraction for: {image_path}", flush=True)

        if not Path(image_path).exists():
            raise FileNotFoundError(f"Image not found: {image_path}")

        processed_path = preprocess_image(image_path)
        print(f"[image_to_graph] Preprocessed image saved at: {processed_path}", flush=True)

        with open(processed_path, "rb") as img_file:
            encoded_image = base64.b64encode(img_file.read()).decode("utf-8")

        print(f"[image_to_graph] Base64 image length: {len(encoded_image)}", flush=True)
        print("[image_to_graph] Calling OpenAI model...", flush=True)

        prompt = build_authorization_prompt()
        if rbac_content:
            prompt += f"\n\n### RBAC Policy File:\n{rbac_content}"
        if firewall_content:
            prompt += f"\n\n### Firewall Rules File:\n{firewall_content}"

        response = client.chat.completions.create(
            model=VISION_MODEL,
            response_format={"type": "json_object"},
            messages=[
                {
                    "role": "system",
                    "content": (
                        "You extract authorization models from ICS/OT architecture diagrams. "
                        "Be conservative, precise, infer protocols from topology context, "
                        "and output only valid JSON."
                    ),
                },
                {
                    "role": "user",
                    "content": [
                        {"type": "text", "text": prompt},
                        {
                            "type": "image_url",
                            "image_url": {
                                "url": f"data:image/jpeg;base64,{encoded_image}",
                                "detail": "high",
                            },
                        },
                    ],
                },
            ],
            temperature=0.1,
            max_tokens=4096,
        )

        raw_text = response.choices[0].message.content or ""

        print("\n[LLM RAW RESPONSE START]\n", flush=True)
        print(raw_text[:4000], flush=True)
        if len(raw_text) > 4000:
            print("\n... [TRUNCATED RAW RESPONSE] ...\n", flush=True)
        print("[LLM RAW RESPONSE END]\n", flush=True)

        graph = extract_json(raw_text)

        if not graph:
            print("[image_to_graph] ERROR: Could not parse JSON.", flush=True)
            return {
                "ocr_text": raw_text,
                "nodes": [],
                "edges": [],
                "error": "Model did not return valid JSON.",
            }

        print("[image_to_graph] JSON parsed successfully.", flush=True)
        _print_graph_summary(graph)

        aasg_data = transform_to_aasg(graph)

        usage = getattr(response, "usage", None)
        tokens_used = {
            "prompt": getattr(usage, "prompt_tokens", None) if usage else None,
            "completion": getattr(usage, "completion_tokens", None) if usage else None,
            "total": getattr(usage, "total_tokens", None) if usage else None,
        }

        print(
            f"[image_to_graph] Built graph with {len(aasg_data['nodes'])} nodes and {len(aasg_data['edges'])} edges.",
            flush=True,
        )

        return {
            "ocr_text": "Extracted via GPT-4.1 native vision",
            "nodes": aasg_data["nodes"],
            "edges": aasg_data["edges"],
            "derived_paths": aasg_data["derived_paths"],
            "raw_model_data": graph,
            "model_used": VISION_MODEL,
            "tokens_used": tokens_used,
        }

    except Exception as e:
        print(f"[image_to_graph] OpenAI API Error: {str(e)}", flush=True)
        return {
            "nodes": [],
            "edges": [],
            "error": f"OpenAI API Error: {str(e)}",
        }