"""
Text Parser — Alternative architecture source for ICS/OT topology descriptions.

Converts plain-text architecture descriptions into the canonical A = {Z, E, S, O, R}
schema consumed by unified_model.build_unified_model().

Output schema matches image_parser output:
  {
    "Z": [...],   # Zones
    "S": [],      # Always empty — subjects come from RBAC parser
    "O": [...],   # Objects / assets
    "R": [],      # Always empty — actions come from RBAC parser
    "E": {
      "permissions": [],    # Always empty — from RBAC parser
      "connections": [...]  # Communication links
    }
  }
"""

import re
from typing import Any, Dict, List, Optional


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _slug(value: Any, prefix: str = "x") -> str:
    value = str(value or "").strip().lower()
    value = re.sub(r"[^a-z0-9]+", "_", value)
    value = re.sub(r"_+", "_", value).strip("_")
    return value or prefix


def _clean(value: str) -> str:
    if value is None:
        return ""
    value = str(value).replace("\n", " ")
    value = re.sub(r"\s+", " ", value)
    return value.strip()


# ---------------------------------------------------------------------------
# Asset type inference from label keywords
# ---------------------------------------------------------------------------

_TYPE_RULES = [
    (["firewall", "fw", "acl"], "firewall"),
    (["vpn", "gateway", "gw"], "vpn"),
    (["scada"], "scada"),
    (["hmi"], "hmi"),
    (["plc", "programmable logic"], "plc"),
    (["rtu", "remote terminal"], "rtu"),
    (["historian"], "historian"),
    (["database", " db "], "database"),
    (["server", "workstation", "engineering station"], "server"),
    (["sensor", "transmitter"], "sensor"),
    (["actuator", "pump", "valve", "motor"], "actuator"),
    (["switch", "router", "network"], "server"),
    (["internet", "wan", "cloud"], "server"),
]

def _guess_type(label: str) -> str:
    lower = label.lower()
    for keywords, asset_type in _TYPE_RULES:
        if any(k in lower for k in keywords):
            return asset_type
    return "component"


def _is_enforcement_point(label: str) -> bool:
    lower = label.lower()
    return any(k in lower for k in ["firewall", "vpn", "gateway", "fw", "gw"])


def _guess_criticality(label: str) -> str:
    lower = label.lower()
    if any(k in lower for k in ["plc", "rtu", "sensor", "actuator", "scada", "master hmi"]):
        return "critical"
    if any(k in lower for k in ["firewall", "vpn", "historian", "engineering"]):
        return "high"
    if any(k in lower for k in ["hmi", "server", "workstation"]):
        return "medium"
    return "medium"


def _guess_purdue(label: str) -> str:
    lower = label.lower()
    if any(k in lower for k in ["sensor", "actuator", "physical", "pump", "valve", "motor"]):
        return "Level 0"
    if any(k in lower for k in ["plc", "rtu", "safety controller", "distributed i/o", "field device"]):
        return "Level 1"
    if any(k in lower for k in ["hmi", "local control", "engineering station"]):
        return "Level 2"
    if any(k in lower for k in ["scada", "historian", "dcs", "ods", "firewall", "vpn", "gateway"]):
        return "Level 3"
    if any(k in lower for k in ["site", "business", "scheduler"]):
        return "Level 4"
    if any(k in lower for k in ["enterprise", "erp", "corporate"]):
        return "Level 5"
    return "unknown"


# ---------------------------------------------------------------------------
# Protocol inference from connection label text
# ---------------------------------------------------------------------------

_PROTO_RULES = [
    (["vpn", "ipsec", "tunnel"], "vpn"),
    (["opc-ua", "opc ua", "opc"], "opc-ua"),
    (["modbus", "mb"], "modbus"),
    (["dnp3", "dnp"], "dnp3"),
    (["ethernetip", "ethernet/ip", "enip"], "ethernetip"),
    (["iec 104", "iec104", "iec-104"], "iec104"),
    (["rdp", "remote desktop"], "rdp"),
    (["ssh"], "ssh"),
    (["https", "http"], "https"),
    (["pcn", "process control network"], "pcn"),
    (["industrial ethernet"], "industrial-ethernet"),
    (["profibus", "profinet"], "profibus"),
    (["can bus", "canbus"], "can"),
    (["serial", "rs-232", "rs232", "rs485"], "serial"),
    (["wifi", "wireless", "zigbee"], "wireless"),
    (["connects", "link", "connect", "network", "tcp", "ip"], "tcp-ip"),
]

def _infer_protocol(edge_label: str, src_label: str = "", tgt_label: str = "") -> str:
    combined = f"{edge_label} {src_label} {tgt_label}".lower()
    for keywords, proto in _PROTO_RULES:
        if any(k in combined for k in keywords):
            return proto
    # Heuristics based on node types
    if "plc" in combined and ("sensor" in combined or "actuator" in combined or "i/o" in combined):
        return "modbus"
    if "hmi" in combined and "plc" in combined:
        return "modbus"
    if "scada" in combined or "hmi" in combined:
        return "opc-ua"
    if "firewall" in combined or "gateway" in combined:
        return "tcp-ip"
    return "tcp-ip"


# ---------------------------------------------------------------------------
# Zone detection from text
# ---------------------------------------------------------------------------

# Well-known zone patterns in ICS/wind-farm architectures
_KNOWN_ZONES = [
    ("wind turbine control center", "wind_turbine_control_center"),
    ("wind turbine", "wind_turbine"),
    ("wind farm control room", "wind_farm_control_room"),
    ("wind-farm control room", "wind_farm_control_room"),
    ("oem domain", "oem_domain"),
    ("oem control room", "oem_control_room"),
    ("vendor control room", "vendor_control_room"),
    ("vendor domain", "vendor_domain"),
    ("customer control room", "customer_control_room"),
    ("customer domain", "customer_domain"),
    ("enterprise zone", "enterprise_zone"),
    ("enterprise network", "enterprise_network"),
    ("dmz", "dmz"),
    ("external transit", "external_transit"),
    ("turbine local control", "turbine_local_control"),
    ("field zone", "field_zone"),
    ("control zone", "control_zone"),
    ("scada zone", "scada_zone"),
    ("corporate zone", "corporate_zone"),
    ("internet", "external_transit"),
]


def _detect_zones_from_text(text: str) -> List[Dict]:
    """Find any known zone names mentioned in the text."""
    normalized_text = text.lower().replace("_", " ").replace("-", " ")
    found = []
    seen_ids = set()
    for name, zone_id in _KNOWN_ZONES:
        norm_name = name.lower().replace("_", " ").replace("-", " ")
        if norm_name in normalized_text and zone_id not in seen_ids:
            found.append({"id": zone_id, "name": name.title()})
            seen_ids.add(zone_id)
    return found


def _assign_zone_from_label(label: str, zones: List[Dict]) -> Optional[str]:
    """Try to assign a zone to an asset based on its label keywords."""
    lower = label.lower()
    
    # 1. Exact or substring match with zone name/id
    for z in zones:
        z_id_clean = z["id"].lower()
        z_name_clean = z["name"].lower()
        if z_id_clean in lower or z_name_clean in lower or z_id_clean.replace("_", "") in lower.replace("_", "").replace("-", ""):
            return z["id"]

    # 2. Heuristic matches
    if any(k in lower for k in ["sensor", "actuator", "physical", "plc", "hmi", "distributed i/o"]):
        for z in zones:
            if "turbine" in z["id"]:
                return z["id"]
    if any(k in lower for k in ["scada", "pcn"]):
        for z in zones:
            if "control_center" in z["id"] or "oem" in z["id"]:
                return z["id"]
    if any(k in lower for k in ["firewall", "vpn", "gateway"]):
        # Assign to whichever zone seems most likely by position in text
        if zones:
            return zones[0]["id"]
    return zones[0]["id"] if zones else "unassigned_zone"


# ---------------------------------------------------------------------------
# Main text parser — canonical schema output
# ---------------------------------------------------------------------------

def text_to_graph(text: str) -> Dict[str, Any]:
    """
    Parse a plain-text architecture description and return canonical
    A = {Z, O, E} schema compatible with unified_model.build_unified_model().

    Subjects (S) and actions (R) are always [] — they come from the RBAC parser.

    Supports patterns:
      - "A connects to B"
      - "A -> B"
      - "A → B"
      - "A connects to B via VPN"
      - "A connects to B using Modbus"
    """
    text = _clean(text)

    # -- Step 1: Parse edge declarations ------------------------------------
    edge_patterns = [
        # "A connects to B [via/using PROTOCOL]"
        r"([^\.\n,;]+?)\s+connects\s+to\s+([^\.\n,;]+?)(?:\s+(?:via|using|over|through)\s+([^\.\n,;]+?))?(?:\.|$|,|;|\n)",
        # "A -> B [: PROTOCOL]"
        r"([^\.\n,;]+?)\s*->\s*([^\.\n,;:]+?)(?:\s*:\s*([^\.\n,;]+?))?(?:\.|$|,|;|\n)",
        # "A → B"
        r"([^\.\n,;]+?)\s*→\s*([^\.\n,;]+?)(?:\.|$|,|;|\n)",
    ]

    raw_edges = []
    for pattern in edge_patterns:
        matches = re.findall(pattern, text, flags=re.IGNORECASE)
        for m in matches:
            src = _clean(m[0])
            tgt = _clean(m[1])
            proto_hint = _clean(m[2]) if len(m) > 2 else ""
            if src and tgt:
                raw_edges.append({"src": src, "tgt": tgt, "proto_hint": proto_hint})

    # -- Step 2: Collect unique node labels ---------------------------------
    label_to_slug: Dict[str, str] = {}

    def get_or_create(label: str) -> str:
        label = _clean(label)
        if label not in label_to_slug:
            label_to_slug[label] = _slug(label)
        return label_to_slug[label]

    # Register all nodes from edges
    for e in raw_edges:
        get_or_create(e["src"])
        get_or_create(e["tgt"])

    # If no edges found, try to parse standalone comma/semicolon-separated asset lists
    if not raw_edges:
        # Fallback: look for "X, Y, Z are assets" style text
        for line in text.split("\n"):
            parts = re.split(r"[,;]", line)
            if len(parts) > 1:
                for p in parts:
                    p = _clean(p)
                    if p and len(p) > 2:
                        get_or_create(p)

    # -- Step 3: Detect zones from text -------------------------------------
    zones = _detect_zones_from_text(text)
    if not zones:
        # Create a generic zone
        zones = [{"id": "ics_network", "name": "ICS Network"}]
    # Always ensure unassigned_zone exists
    zone_ids = {z["id"] for z in zones}
    if "unassigned_zone" not in zone_ids:
        zones.append({"id": "unassigned_zone", "name": "Unassigned Zone"})

    # Parse explicit zone assignments (e.g. "A is in B" or "A belongs to B")
    explicit_zones = {}
    zone_assign_patterns = [
        r"(?:the\s+)?([^\.\n,;]+?)\s+is\s+in\s+(?:the\s+)?([^\.\n,;]+)",
        r"(?:the\s+)?([^\.\n,;]+?)\s+belongs\s+to\s+(?:the\s+)?([^\.\n,;]+)"
    ]
    for pattern in zone_assign_patterns:
        matches = re.findall(pattern, text, flags=re.IGNORECASE)
        for m in matches:
            asset_label = _clean(m[0])
            if asset_label.lower().startswith("the "):
                asset_label = asset_label[4:].strip()
            zone_label = _clean(m[1])
            if zone_label.lower().startswith("the "):
                zone_label = zone_label[4:].strip()
                
            if asset_label and zone_label:
                zone_slug = _slug(zone_label)
                # Map to known zone ID if similar
                matched_zone_id = None
                for z in zones:
                    if z["id"] == zone_slug or z["name"].lower() == zone_label.lower() or z["id"].replace("_", "") == zone_slug.replace("_", ""):
                        matched_zone_id = z["id"]
                        break
                if not matched_zone_id:
                    matched_zone_id = zone_slug
                explicit_zones[_slug(asset_label)] = matched_zone_id

    # -- Step 4: Build objects ----------------------------------------------
    objects = []
    for label, slug in label_to_slug.items():
        # Skip things that look like zone names
        label_lower = label.lower()
        is_zone = any(
            zone["name"].lower() in label_lower or zone["id"] in _slug(label)
            for zone in zones
        )
        if is_zone:
            continue

        asset_type = _guess_type(label)
        criticality = _guess_criticality(label)
        purdue = _guess_purdue(label)
        
        # Check explicit zone assignments first, otherwise fall back to heuristics
        zone_id = explicit_zones.get(slug)
        if not zone_id:
            zone_id = _assign_zone_from_label(label, [z for z in zones if z["id"] != "unassigned_zone"])
        is_ep = _is_enforcement_point(label)

        objects.append({
            "id": slug,
            "name": label,
            "type": asset_type,
            "zone": zone_id or "unassigned_zone",
            "purdue_level": purdue,
            "criticality": criticality,
            "is_enforcement_point": is_ep,
        })

    # -- Step 5: Build connections ------------------------------------------
    connections = []
    seen_pairs = set()
    for e in raw_edges:
        src_slug = label_to_slug.get(e["src"])
        tgt_slug = label_to_slug.get(e["tgt"])
        if not src_slug or not tgt_slug:
            continue
        pair = (src_slug, tgt_slug)
        if pair in seen_pairs:
            continue
        seen_pairs.add(pair)

        protocol = _infer_protocol(e.get("proto_hint", ""), e["src"], e["tgt"])
        connections.append({
            "source": src_slug,
            "target": tgt_slug,
            "protocol": protocol,
        })

    result = {
        "Z": zones,
        "S": [],   # Subjects come from RBAC parser only
        "O": objects,
        "R": [],   # Actions come from RBAC parser only
        "E": {
            "permissions": [],   # From RBAC parser only
            "connections": connections,
        },
    }

    print(f"[text_to_graph] Parsed: {len(zones)} zones, {len(objects)} objects, {len(connections)} connections", flush=True)
    return result