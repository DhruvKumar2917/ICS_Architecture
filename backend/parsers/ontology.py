"""
Ontology & Normalization Layer  —  the single source of truth for naming.

PROBLEM THIS SOLVES
-------------------
The same physical asset shows up under many spellings across the three input
sources (architecture diagram, RBAC policy, firewall rules):

    OEM_SCADA          (firewall rule, upper snake)
    OEM-SCADA          (RBAC object, dash delimited)
    oem_scada_server   (architecture diagram, full noun)

Before this module, each parser/merger tried to bridge those gaps with its own
ad-hoc fuzzy matching and a handful of hardcoded aliases scattered across
`unified_model.py`. That produced both false negatives (the three names above
not merging) and false positives (`oem_firewall` merging into
`oem_scada_server` at a low similarity threshold).

This module centralises three concerns that used to be duplicated:

  1. ALIAS MAPPING      — explicit raw->canonical overrides (highest priority).
  2. OBJECT NORMALIZATION — deterministic slug + delimiter + suffix folding so
                          that `OEM-SCADA` and `oem_scada` collapse without any
                          alias entry being required.
  3. ONTOLOGY MAPPING   — keyword -> canonical device *type* (hmi, plc, scada …)
                          which both feeds normalization and drives protocol
                          inference.

It also owns PROTOCOL INFERENCE: given a (source, target) device pair whose
link protocol is unknown, infer the conventional ICS/OT protocol for that pair
(HMI<->PLC = Modbus, SCADA<->PLC = OPC-UA, Firewall<->VPN = IPSec, …).

Everything here is pure / side-effect free so it can be unit-tested in
isolation and reused by every parser.
"""

from __future__ import annotations

import re
from difflib import SequenceMatcher
from typing import Dict, List, Optional, Tuple


# ===========================================================================
# 1. Low-level slug + delimiter normalization
# ===========================================================================

def slug(value: object, fallback: str = "x") -> str:
    """Lower-case, collapse any run of non-alphanumerics to a single '_'."""
    text = str(value or "").strip().lower()
    text = re.sub(r"[^a-z0-9]+", "_", text)
    text = re.sub(r"_+", "_", text).strip("_")
    return text or fallback


def squash(value: object) -> str:
    """Delimiter-insensitive key: 'OEM-SCADA' and 'oem_scada' -> 'oemscada'."""
    return re.sub(r"[^a-z0-9]", "", str(value or "").lower())


# ===========================================================================
# 2. Alias mapping  (raw squashed-key -> canonical slug)
# ===========================================================================
#
# Keys are stored in *squashed* form (no delimiters) so that every delimiter
# variant of a name resolves through a single entry.  e.g. the single key
# "oemscada" below catches  OEM_SCADA / OEM-SCADA / oem scada / oemScada.
#
# Add site-specific synonyms here.  This is the ONE place to edit when a new
# spelling of a known asset appears in a customer's files.

ALIASES: Dict[str, str] = {
    # --- The motivating OEM SCADA case -----------------------------------
    "oemscada":        "oem_scada_server",
    "oemscadaserver":  "oem_scada_server",
    "oemscadahost":    "oem_scada_server",

    # --- VPN / remote access synonyms ------------------------------------
    "vpn":             "customer_vpn",
    "vpngw":           "customer_vpn",
    "vpngateway":      "customer_vpn",

    # --- HMI synonyms ----------------------------------------------------
    "hmimaster":       "master_hmi",
    "masterhmi":       "master_hmi",

    # --- Firewall synonyms ----------------------------------------------
    "oemfirewall":     "oem_firewall",
    "vendorfirewall":  "vendor_firewall",
}


def register_alias(raw: str, canonical: str) -> None:
    """Programmatically add an alias at runtime (e.g. learned from a file)."""
    ALIASES[squash(raw)] = slug(canonical)


# ===========================================================================
# 3. Device-type ontology  (keyword -> canonical device type)
# ===========================================================================
#
# Order matters: the FIRST keyword found in an identifier wins, and more
# specific keywords are listed before generic ones (e.g. "safety_controller"
# before "controller", "engineering" before "workstation").

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

# Generic suffixes the LLM/diagram appends but firewall/RBAC files omit.
_STRIP_SUFFIXES = (
    "_server", "_host", "_gateway", "_gw", "_router", "_switch",
    "_controller", "_node", "_device", "_system", "_unit",
)


def classify_device_type(identifier: object, declared_type: object = None) -> str:
    """
    Resolve a canonical device type from an explicit declared type first,
    then by scanning the identifier for ontology keywords.

    Returns 'unknown' if nothing matches.
    """
    declared = slug(declared_type) if declared_type else ""
    if declared and declared not in ("unknown", "x", "component", "inferred_node"):
        # Trust an explicit, meaningful type but still normalise synonyms.
        for kw, canon in _DEVICE_TYPE_KEYWORDS:
            if kw in declared:
                return canon
        return declared

    ident = slug(identifier)
    for kw, canon in _DEVICE_TYPE_KEYWORDS:
        if kw in ident:
            return canon
    return "unknown"


# ===========================================================================
# 4. Object normalization  (the public entry point used by the merger)
# ===========================================================================

def normalize_identifier(raw: object) -> str:
    """
    Produce the canonical slug for an identifier using, in priority order:

        1. exact alias hit on the squashed key            (ALIASES)
        2. plain slug                                      (delimiter folding)

    This is intentionally conservative: it does NOT fuzzy-merge distinct
    names.  Fuzzy/stem reconciliation against an *existing* registry is done
    by `resolve_against`, so that 'oem_scada' can still collapse onto an
    already-registered 'oem_scada_server' without an alias entry.
    """
    sq = squash(raw)
    if sq in ALIASES:
        return ALIASES[sq]
    return slug(raw)


def id_variants(raw: object, zone_mapping: Optional[Dict[str, str]] = None) -> List[str]:
    """
    Generate matching variants of an identifier for cross-file reconciliation
    (used by firewall lookups). Includes the canonical form, the bare slug, the
    suffix-stripped stem, and any zone-number translation.
    """
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

    # De-dupe, preserve order, drop empties.
    seen, out = set(), []
    for v in variants:
        v = (v or "").strip("_")
        if v and v not in seen:
            seen.add(v)
            out.append(v)
    return out


def resolve_against(raw: object, registry, threshold: float = 0.92) -> Optional[str]:
    """
    Try to resolve `raw` onto an ID already present in `registry` (any iterable
    of canonical slugs) using, in priority order:

        1. exact alias / normalized-slug hit
        2. delimiter-insensitive equality        (oem-scada == oem_scada)
        3. suffix-stripped stem equality          (oem_scada == oem_scada_server)
        4. token-set equality                     (hmi_master == master_hmi)
        5. fuzzy ratio >= threshold               (last resort)

    Returns the matching canonical ID, or None.
    """
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
        # (2) delimiter-insensitive
        if raw_squash == cand_squash:
            return cand
        # (3) suffix-stripped stem
        cand_stem = cand
        for suffix in _STRIP_SUFFIXES:
            if cand_stem.endswith(suffix):
                cand_stem = cand_stem[: -len(suffix)]
                break
        if raw_stem and (raw_stem == cand_stem or squash(raw_stem) == squash(cand_stem)):
            return cand
        # (4) token-set equality (ignoring generic tokens)
        generic = {"server", "host", "device", "zone", "network", "system", "gw", "gateway"}
        cand_tokens = set(t for t in cand.split("_") if t)
        if raw_tokens and (raw_tokens - generic) == (cand_tokens - generic) and (raw_tokens - generic):
            return cand
        # (5) fuzzy
        sim = SequenceMatcher(None, norm, cand).ratio()
        if sim > best_sim:
            best, best_sim = cand, sim

    return best if best_sim >= threshold else None


# ===========================================================================
# 5. Protocol inference  (device pair -> conventional ICS/OT protocol)
# ===========================================================================
#
# Keyed by a frozenset of the two canonical device types so the rule is
# direction-insensitive.  This is the table requested in the spec:
#
#     HMI       <-> PLC        Modbus
#     SCADA     <-> PLC        OPC-UA
#     Firewall  <-> VPN        IPSec
#     Enterprise<-> SCADA      HTTPS
#
# plus a set of sensible ICS extensions.

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

# Fallback when only ONE side is a recognised OT device.
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
    """
    Infer the conventional protocol for a communication link whose protocol is
    unknown. Resolves device types from declared types AND identifiers, then
    consults the device-pair table, then a single-side hint table.

    Returns a protocol slug (e.g. 'modbus', 'opc-ua', 'ipsec', 'https') or
    None if nothing sensible can be inferred.
    """
    st = classify_device_type(src_id, src_type)
    dt = classify_device_type(dst_id, dst_type)

    pair = frozenset({st, dt})
    if pair in _PAIR_PROTOCOL:
        return _PAIR_PROTOCOL[pair]

    # Single-side hint: prefer the more "OT-deep" side (target first).
    for cand in (dt, st):
        if cand in _SINGLE_HINT_PROTOCOL:
            return _SINGLE_HINT_PROTOCOL[cand]

    return None
