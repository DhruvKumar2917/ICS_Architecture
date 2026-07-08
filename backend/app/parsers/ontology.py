"""
Ontology & Normalization Layer  —  the single source of truth for naming.
"""

from __future__ import annotations

import re
from difflib import SequenceMatcher
from typing import Dict, List, Optional, Tuple
from app.core.utils import slugify

def slug(value: object, fallback: str = "x") -> str:
    return slugify(value, fallback)


def squash(value: object) -> str:
    return re.sub(r"[^a-z0-9]", "", str(value or "").lower())


ALIASES: Dict[str, str] = {
    "oemscada":        "oem_scada_server",
    "oemscadaserver":  "oem_scada_server",
    "oemscadahost":    "oem_scada_server",
    "vpn":             "customer_vpn",
    "vpngw":           "customer_vpn",
    "vpngateway":      "customer_vpn",
    "hmimaster":       "master_hmi",
    "masterhmi":       "master_hmi",
    "oemfirewall":     "oem_firewall",
    "vendorfirewall":  "vendor_firewall",
}


def register_alias(raw: str, canonical: str) -> None:
    ALIASES[squash(raw)] = slug(canonical)


_DEVICE_TYPE_KEYWORDS: List[Tuple[str, str]] = [
    ("safety_controller", "safety_controller"),
    ("safetyplc",         "safety_controller"),
    ("historian",         "historian"),
    ("engineering",       "engineering"),
    ("workstation",       "workstation"),
    ("firewall",          "firewall"),
    ("scada",             "scada"),
    ("hmi",               "hmi"),
    ("plc",               "plc"),
    ("rtu",               "rtu"),
    ("ied",               "rtu"),
    ("vpn",               "vpn"),
    ("gateway",           "gateway"),
    ("gw",                "gateway"),
    ("router",            "router"),
    ("switch",            "switch"),
    ("sensor",            "sensor"),
    ("actuator",          "actuator"),
    ("turbine",           "physical_process"),
    ("motor",             "physical_process"),
    ("pump",              "physical_process"),
    ("enterprise",        "enterprise"),
    ("erp",               "enterprise"),
    ("cloud",             "enterprise"),
    ("server",            "server"),
    ("host",              "server"),
]

_STRIP_SUFFIXES = (
    "_server", "_host", "_gateway", "_gw", "_router", "_switch",
    "_controller", "_node", "_device", "_system", "_unit",
)


def classify_device_type(identifier: object, declared_type: object = None) -> str:
    declared = slug(declared_type) if declared_type else ""
    if declared and declared not in ("unknown", "x", "component", "inferred_node"):
        for kw, canon in _DEVICE_TYPE_KEYWORDS:
            if kw in declared:
                return canon
        return declared

    ident = slug(identifier)
    for kw, canon in _DEVICE_TYPE_KEYWORDS:
        if kw in ident:
            return canon
    return "unknown"


def normalize_identifier(raw: object) -> str:
    sq = squash(raw)
    if sq in ALIASES:
        return ALIASES[sq]
    return slug(raw)


def id_variants(raw: object, zone_mapping: Optional[Dict[str, str]] = None) -> List[str]:
    base = slug(raw)
    variants = [normalize_identifier(raw), base, str(raw).strip().lower()]

    if zone_mapping:
        sq = squash(raw)
        if sq in zone_mapping:
            variants.append(zone_mapping[sq])
        else:
            for k, v in zone_mapping.items():
                if base == v or sq == squash(v):
                    variants.append(k)
                    break

    for suffix in _STRIP_SUFFIXES:
        if base.endswith(suffix):
            variants.append(base[: -len(suffix)])

    seen, out = set(), []
    for v in variants:
        v = (v or "").strip("_")
        if v and v not in seen:
            seen.add(v)
            out.append(v)
    return out


def resolve_against(raw: object, registry, threshold: float = 0.92) -> Optional[str]:
    registry = list(registry)
    norm = normalize_identifier(raw)
    if norm in registry:
        return norm

    raw_squash = squash(raw)
    raw_stem = norm
    for suffix in _STRIP_SUFFIXES:
        if raw_stem.endswith(suffix):
            raw_stem = raw_stem[: -len(suffix)]
            break
    raw_tokens = set(t for t in norm.split("_") if t)

    best, best_sim = None, 0.0
    for cand in registry:
        cand_squash = squash(cand)
        if raw_squash == cand_squash:
            return cand
        cand_stem = cand
        for suffix in _STRIP_SUFFIXES:
            if cand_stem.endswith(suffix):
                cand_stem = cand_stem[: -len(suffix)]
                break
        if raw_stem and (raw_stem == cand_stem or squash(raw_stem) == squash(cand_stem)):
            return cand
        generic = {"server", "host", "device", "zone", "network", "system", "gw", "gateway"}
        cand_tokens = set(t for t in cand.split("_") if t)
        if raw_tokens and (raw_tokens - generic) == (cand_tokens - generic) and (raw_tokens - generic):
            return cand
        sim = SequenceMatcher(None, norm, cand).ratio()
        if sim > best_sim:
            best, best_sim = cand, sim

    return best if best_sim >= threshold else None


_PAIR_PROTOCOL: Dict[frozenset, str] = {
    frozenset({"hmi", "plc"}):              "modbus",
    frozenset({"hmi", "rtu"}):              "modbus",
    frozenset({"scada", "plc"}):            "opc-ua",
    frozenset({"scada", "rtu"}):            "dnp3",
    frozenset({"firewall", "vpn"}):         "ipsec",
    frozenset({"vpn", "gateway"}):          "ipsec",
    frozenset({"enterprise", "scada"}):     "https",
    frozenset({"enterprise", "historian"}): "https",
    frozenset({"historian", "scada"}):      "opc-ua",
    frozenset({"engineering", "plc"}):      "s7comm",
    frozenset({"plc", "sensor"}):           "hart",
    frozenset({"plc", "actuator"}):         "hart",
    frozenset({"rtu", "sensor"}):           "iec_61850",
    frozenset({"safety_controller", "plc"}): "opc-ua",
    frozenset({"plc", "physical_process"}): "fieldbus",
    frozenset({"rtu", "physical_process"}): "fieldbus",
}

_SINGLE_HINT_PROTOCOL: Dict[str, str] = {
    "plc": "modbus",
    "rtu": "dnp3",
    "scada": "opc-ua",
    "hmi": "modbus",
    "vpn": "ipsec",
    "firewall": "ipsec",
    "historian": "opc-ua",
    "enterprise": "https",
}


def infer_protocol(
    src_type: object,
    dst_type: object,
    src_id: object = "",
    dst_id: object = "",
) -> Optional[str]:
    st = classify_device_type(src_id, src_type)
    dt = classify_device_type(dst_id, dst_type)

    pair = frozenset({st, dt})
    if pair in _PAIR_PROTOCOL:
        return _PAIR_PROTOCOL[pair]

    for cand in (dt, st):
        if cand in _SINGLE_HINT_PROTOCOL:
            return _SINGLE_HINT_PROTOCOL[cand]

    return None
