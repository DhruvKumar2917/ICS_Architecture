"""
Unified Model Merger — Canonical A = {Z, E, S, O, R} Builder.
"""

import re
from difflib import SequenceMatcher
from typing import Any, Dict, List, Optional, Set, Tuple

from app.parsers.firewall.parser import FirewallParser
from app.parsers import ontology
from app.core.utils import slugify

def _slug(value: Any, prefix: str = "x") -> str:
    return slugify(value, prefix)


def _similarity(a: str, b: str) -> float:
    return SequenceMatcher(None, a, b).ratio()


# ---------------------------------------------------------------------------
# Per-set Canonicalizer
# ---------------------------------------------------------------------------

class Canonicalizer:
    SIMILARITY_THRESHOLD = 0.92

    def __init__(self, label: str = ""):
        self._label = label
        self._registry: Dict[str, str] = {}
        self._alias_map: Dict[str, str] = {}

    def register(self, raw_id: str) -> str:
        slug = ontology.normalize_identifier(raw_id)
        if not slug or slug == "x":
            return "unknown"

        if slug in self._alias_map:
            return self._alias_map[slug]

        match = ontology.resolve_against(slug, self._registry.keys(),
                                         threshold=self.SIMILARITY_THRESHOLD)
        if match is not None and match != slug:
            self._alias_map[slug] = match
            print(f"  [Canonicalizer/{self._label}] merge '{slug}' -> '{match}' "
                  f"(ontology)", flush=True)
            return match

        self._registry[slug] = slug
        self._alias_map[slug] = slug
        return slug

    def resolve(self, raw_id: str) -> str:
        slug = ontology.normalize_identifier(raw_id)
        if slug in self._alias_map:
            return self._alias_map[slug]
        match = ontology.resolve_against(slug, self._registry.keys(),
                                         threshold=self.SIMILARITY_THRESHOLD)
        return match if match is not None else slug

    def registered(self) -> Set[str]:
        return set(self._registry.keys())


# ---------------------------------------------------------------------------
# Firewall stem-matching helpers (Issue 2)
# ---------------------------------------------------------------------------

_STRIP_SUFFIXES = [
    "_server", "_host", "_gateway", "_gw", "_router", "_switch",
    "_controller", "_node", "_device", "_system",
]

def _id_variants(raw: str, custom_mapping: Optional[Dict[str, str]] = None) -> List[str]:
    base = _slug(raw)
    variants = [base, raw.strip()]
    
    zone_mapping = {
        "zone1": "wind_turbine_control_center",
        "zone2": "wind_farm_control_room",
        "zone3": "customer_control_room",
        "zone4": "vendor_control_room",
        "zone5": "wind_turbine",
    }
    if custom_mapping:
        zone_mapping.update(custom_mapping)
    
    clean_base = base.replace("_", "").replace("-", "")
    if clean_base in zone_mapping:
        variants.append(zone_mapping[clean_base])
    else:
        for k, v in zone_mapping.items():
            if base == v or clean_base == v.replace("_", ""):
                variants.append(k)
                break

    for suffix in _STRIP_SUFFIXES:
        if base.endswith(suffix):
            variants.append(base[: -len(suffix)])
    variants.append(re.sub(r"[\-\s]+", "_", raw.strip().lower()))
    seen = set()
    result = []
    for v in variants:
        v = v.strip("_")
        if v and v not in seen:
            seen.add(v)
            result.append(v)
    return result


def _firewall_is_allowed(firewall: FirewallParser, src_raw: str, dst_raw: str):
    custom_mapping = getattr(firewall, "zone_mapping", None)
    src_variants = _id_variants(src_raw, custom_mapping)
    dst_variants = _id_variants(dst_raw, custom_mapping)

    for sv in src_variants:
        for dv in dst_variants:
            rule = firewall.is_allowed(sv, dv)
            if rule is not None:
                return rule
    return None


def _firewall_is_denied(firewall: FirewallParser, src_raw: str, dst_raw: str):
    custom_mapping = getattr(firewall, "zone_mapping", None)
    src_variants = _id_variants(src_raw, custom_mapping)
    dst_variants = _id_variants(dst_raw, custom_mapping)

    for sv in src_variants:
        for dv in dst_variants:
            rule = firewall.is_denied(sv, dv)
            if rule is not None:
                return rule
    return None


def _is_control_chain_comm(src_id: str, dst_id: str, src_type: str, dst_type: str) -> bool:
    src_id_l = src_id.lower()
    dst_id_l = dst_id.lower()
    src_type_l = src_type.lower()
    dst_type_l = dst_type.lower()

    if (src_type_l in ("hmi", "scada", "server", "workstation") or "hmi" in src_id_l or "scada" in src_id_l) and \
       (dst_type_l in ("plc", "rtu") or "plc" in dst_id_l or "rtu" in dst_id_l):
        return True

    if (src_type_l in ("plc", "rtu") or "plc" in src_id_l or "rtu" in src_id_l) and \
       (dst_type_l in ("sensor", "actuator", "component", "unknown") or "io" in dst_id_l or "sensor" in dst_id_l or "actuator" in dst_id_l or "physical" in dst_id_l):
        return True

    if ("io" in src_id_l or src_type_l in ("component", "unknown")) and \
       (dst_type_l in ("sensor", "actuator") or "sensor" in dst_id_l or "actuator" in dst_id_l or "physical" in dst_id_l):
        return True

    return False


# ---------------------------------------------------------------------------
# Unified model
# ---------------------------------------------------------------------------

class UnifiedModel:
    def __init__(self):
        self.Z: List[Dict] = []
        self.S: List[Dict] = []
        self.O: List[Dict] = []
        self.R: List[Dict] = []

        self.Ea: List[Dict] = []
        self.Ec: List[Dict] = []

        self.firewall_blocked:  List[Dict] = []
        self.validation_issues: List[str]  = []
        self.zone_mapping:      Dict[str, str] = {}

        self._zone_canon    = Canonicalizer("zone")
        self._subject_canon = Canonicalizer("subject")
        self._object_canon  = Canonicalizer("object")

        self._zone_ids:    Set[str] = set()
        self._subject_ids: Set[str] = set()
        self._object_ids:  Set[str] = set()
        self._action_ids:  Set[str] = set()

        self._needs_unassigned_zone: bool = False

    def _ingest_zones(self, zones: List[Dict]):
        print(f"  [unified] Ingesting {len(zones)} zones...", flush=True)
        for z in zones:
            raw_id = z.get("id") or z.get("name", "")
            if not raw_id:
                continue
            clean_raw_id = _slug(raw_id).replace("_", "").replace("-", "")
            zone_mapping = {
                "zone1": "wind_turbine_control_center",
                "zone2": "wind_farm_control_room",
                "zone3": "customer_control_room",
                "zone4": "vendor_control_room",
                "zone5": "wind_turbine",
            }
            if clean_raw_id in zone_mapping:
                raw_id = zone_mapping[clean_raw_id]

            zid = self._zone_canon.register(raw_id)
            if zid not in self._zone_ids:
                self.Z.append({"id": zid, "name": z.get("name", raw_id)})
                self._zone_ids.add(zid)
        print(f"  [unified] Zones registered: {sorted(self._zone_ids)}", flush=True)

    def _ensure_unassigned_zone(self):
        if "unassigned_zone" not in self._zone_ids:
            self.Z.append({"id": "unassigned_zone", "name": "Unassigned Zone"})
            self._zone_ids.add("unassigned_zone")
            self._zone_canon.register("unassigned_zone")
            print("  [unified] Created unassigned_zone (lazy, needed by an object)", flush=True)

    def _is_architecture_asset(self, sid: str) -> bool:
        exclude_keywords = {"firewall", "gw", "gateway", "server", "host", "plc", "hmi", "switch", "router", "sensor", "actuator", "device"}
        sid_lower = sid.lower()
        if any(kw in sid_lower for kw in exclude_keywords):
            return True
            
        for obj_id in self._object_ids:
            if sid_lower == obj_id.lower():
                return True
            if re.sub(r'[^a-z0-9]', '', sid_lower) == re.sub(r'[^a-z0-9]', '', obj_id.lower()):
                return True
            if _similarity(sid_lower, obj_id.lower()) > 0.8:
                return True
                
        return False

    def _resolve_object_alias(self, obj_raw: str) -> Optional[str]:
        return ontology.resolve_against(obj_raw, self._object_ids, threshold=0.88)

    def _ingest_subjects(self, subjects: List[Dict]):
        print(f"  [unified] Ingesting {len(subjects)} subjects from RBAC...", flush=True)
        for s in subjects:
            raw_id = s.get("id") or s.get("name", "")
            if not raw_id:
                continue
            sid = self._subject_canon.register(raw_id)
            if sid not in self._subject_ids:
                if self._is_architecture_asset(sid):
                    print(f"  [unified] Subject '{sid}' identified as architecture asset - skipping S ingestion", flush=True)
                    continue
                self.S.append({
                    "id":   sid,
                    "name": s.get("name", raw_id),
                    "kind": s.get("kind", "role"),
                })
                self._subject_ids.add(sid)
        print(f"  [unified] Subjects registered: {sorted(self._subject_ids)}", flush=True)

    def _ingest_objects(self, objects: List[Dict]):
        print(f"  [unified] Ingesting {len(objects)} objects from architecture...", flush=True)
        for o in objects:
            raw_id = o.get("id") or o.get("name", "")
            if not raw_id:
                continue
            oid = self._object_canon.register(raw_id)

            zone_raw = o.get("zone") or o.get("zone_id", "")
            if not zone_raw or str(zone_raw).lower() in ("null", "none", ""):
                obj_slug = _slug(raw_id)
                obj_tokens = set(obj_slug.split("_"))
                
                best_zone = None
                for zid in self._zone_ids:
                    if zid == "unassigned_zone":
                        continue
                    zone_tokens = set(zid.split("_"))
                    shared = zone_tokens & obj_tokens - {"zone", "room", "center", "local", "control"}
                    if shared:
                        best_zone = zid
                        break
                        
                if not best_zone:
                    valid_zones = [z for z in self._zone_ids if z != "unassigned_zone"]
                    if valid_zones:
                        best_zone = sorted(valid_zones)[0]

                if best_zone:
                    zone_raw = best_zone
                    print(f"  [unified] Object '{raw_id}' has no zone; auto-mapped to zone '{best_zone}'", flush=True)

            if zone_raw:
                clean_zone_raw = _slug(zone_raw).replace("_", "").replace("-", "")
                zone_mapping = {
                    "zone1": "wind_turbine_control_center",
                    "zone2": "wind_farm_control_room",
                    "zone3": "customer_control_room",
                    "zone4": "vendor_control_room",
                    "zone5": "wind_turbine",
                }
                if clean_zone_raw in zone_mapping:
                    zone_raw = zone_mapping[clean_zone_raw]

                zone_id = self._zone_canon.resolve(zone_raw)
                if zone_id not in self._zone_ids:
                    zone_slug = _slug(zone_raw)
                    if zone_slug in self._zone_ids:
                        zone_id = zone_slug
                    else:
                        valid_zones = [z for z in self._zone_ids if z != "unassigned_zone"]
                        if valid_zones:
                            zone_id = sorted(valid_zones)[0]
                            print(f"  [unified] Object '{raw_id}' referenced unknown zone '{zone_raw}'; mapped to valid zone '{zone_id}'", flush=True)
                        else:
                            self._ensure_unassigned_zone()
                            zone_id = "unassigned_zone"
                            self.validation_issues.append(
                                f"Object '{raw_id}' references unknown zone '{zone_raw}'; "
                                f"assigned to unassigned_zone."
                            )
            else:
                valid_zones = [z for z in self._zone_ids if z != "unassigned_zone"]
                if valid_zones:
                    zone_id = sorted(valid_zones)[0]
                else:
                    self._ensure_unassigned_zone()
                    zone_id = "unassigned_zone"

            if oid not in self._object_ids:
                self.O.append({
                    "id":                   oid,
                    "name":                 o.get("name", raw_id),
                    "type":                 o.get("type", "unknown"),
                    "zone":                 zone_id,
                    "purdue_level":         o.get("purdue_level", "unknown"),
                    "criticality":          o.get("criticality", "medium"),
                    "is_enforcement_point": o.get("is_enforcement_point", False),
                })
                self._object_ids.add(oid)
            else:
                print(f"  [unified] Object '{oid}' (from '{raw_id}') already registered - skipped",
                      flush=True)

        print(f"  [unified] Objects registered: {len(self._object_ids)} - {sorted(self._object_ids)[:10]}",
              flush=True)

    def _ingest_actions(self, actions: List[Dict]):
        print(f"  [unified] Ingesting {len(actions)} actions from RBAC...", flush=True)
        for a in actions:
            raw_id = a.get("id") or a.get("name", "")
            if not raw_id:
                continue
            aid = _slug(raw_id)
            if aid and aid not in self._action_ids:
                self.R.append({"id": aid, "name": a.get("name", raw_id)})
                self._action_ids.add(aid)
        print(f"  [unified] Actions registered: {sorted(self._action_ids)}", flush=True)

    def _ingest_permissions(self, permissions: List[Dict]):
        print(f"  [unified] Ingesting {len(permissions)} permissions...", flush=True)
        ea_built = 0

        for i, perm in enumerate(permissions):
            sub_raw = perm.get("subject", "")
            obj_raw = perm.get("object", "")
            act_raw = perm.get("action", "access")

            if not sub_raw or not obj_raw:
                print(f"  [unified] Permission #{i}: skipped (empty subject or object)", flush=True)
                continue

            sub_id = self._subject_canon.resolve(sub_raw)
            obj_id = self._object_canon.resolve(obj_raw)
            act_id = _slug(act_raw) if act_raw else "access"

            print(f"  [unified] Permission #{i}: {sub_raw!r} --{act_raw!r}--> {obj_raw!r}"
                  f"  =>  {sub_id} --{act_id}--> {obj_id}", flush=True)

            if self._is_architecture_asset(sub_id):
                print(f"  [unified] Permission #{i} skipped: source '{sub_id}' is a device, not a subject", flush=True)
                continue

            if sub_id not in self._subject_ids:
                if self._is_architecture_asset(sub_id):
                    print(f"  [unified] Auto-inject subject '{sub_id}' skipped because it is an architecture asset", flush=True)
                else:
                    self.S.append({"id": sub_id, "name": sub_raw, "kind": "role"})
                    self._subject_ids.add(sub_id)
                    print(f"  [unified] Auto-injected subject: {sub_id}", flush=True)

            if obj_id not in self._object_ids:
                found = self._resolve_object_alias(obj_raw)
                if found is None:
                    found = self._resolve_object_alias(obj_id)

                if found:
                    obj_id = found
                    print(f"  [unified] Permission object '{obj_raw}' resolved to existing '{found}'",
                          flush=True)
                else:
                    self._ensure_unassigned_zone()
                    self.O.append({
                        "id": obj_id, "name": obj_raw, "type": "unknown",
                        "zone": "unassigned_zone", "purdue_level": "unknown",
                        "criticality": "medium", "is_enforcement_point": False,
                    })
                    self._object_ids.add(obj_id)
                    self.validation_issues.append(
                        f"RBAC references object '{obj_raw}' (resolved: '{obj_id}') "
                        f"not found in architecture diagram."
                    )
                    print(f"  [unified] Auto-injected missing object: {obj_id}", flush=True)

            src_zone = "external_transit"
            dst_zone = next(
                (o["zone"] for o in self.O if o["id"] == obj_id),
                "unassigned_zone",
            )

            self.Ea.append({
                "id":         f"ea_{i}",
                "source":     sub_id,
                "target":     obj_id,
                "edge_set":   "Ea",
                "label": {
                    "sm":               "a",
                    "action":           act_id,
                    "role_provenance":  perm.get("role_provenance", sub_id),
                    "source_zone":      src_zone,
                    "target_zone":      dst_zone,
                    "destination_type": next(
                        (o["type"] for o in self.O if o["id"] == obj_id), "unknown"
                    ),
                },
                "confidence":  perm.get("confidence", 1.0),
                "source_file": perm.get("source", "rbac_file"),
            })
            ea_built += 1

        print(f"  [unified] Ea edges built: {ea_built}", flush=True)

    def _ingest_connections(
        self,
        connections: List[Dict],
        firewall: Optional[FirewallParser],
    ):
        print(f"  [unified] Ingesting {len(connections)} architecture connections...", flush=True)

        if firewall and firewall.rules:
            print(f"  [unified] Firewall active: {len(firewall.rules)} rules, "
                  f"{len(firewall.allowed_pairs)} allowed pairs", flush=True)
            for pair in list(firewall.allowed_pairs)[:20]:
                print(f"    [firewall allow] {pair[0]} -> {pair[1]}", flush=True)
        else:
            print("  [unified] Firewall: OPEN POLICY (all connections permitted)", flush=True)

        seen: Set[Tuple[str, str]] = set()
        ec_built = 0

        for i, conn in enumerate(connections):
            src_raw = conn.get("source", conn.get("src", ""))
            dst_raw = conn.get("target", conn.get("dst", ""))
            proto   = conn.get("protocol", conn.get("proto", "unknown"))

            if not src_raw or not dst_raw:
                continue

            src_id = self._object_canon.resolve(src_raw)
            dst_id = self._object_canon.resolve(dst_raw)

            pair = (src_id, dst_id)
            if pair in seen:
                continue
            seen.add(pair)

            src_zone = next((o["zone"] for o in self.O if o["id"] == src_id), "unassigned_zone")
            dst_zone = next((o["zone"] for o in self.O if o["id"] == dst_id), "unassigned_zone")

            fw_port = None
            if firewall and firewall.rules:
                rule = _firewall_is_allowed(firewall, src_raw, dst_raw)
                if rule is None:
                    rule = _firewall_is_allowed(firewall, src_id, dst_id)
                if rule is None and src_zone and dst_zone:
                    rule = _firewall_is_allowed(firewall, src_zone, dst_zone)
                if rule is None and src_zone:
                    rule = _firewall_is_allowed(firewall, src_zone, dst_id)
                if rule is None and dst_zone:
                    rule = _firewall_is_allowed(firewall, src_id, dst_zone)

                if rule is None:
                    is_intra_zone = (src_zone == dst_zone) and bool(src_zone)
                    
                    src_type = next((o["type"] for o in self.O if o["id"] == src_id), "unknown")
                    dst_type = next((o["type"] for o in self.O if o["id"] == dst_id), "unknown")
                    is_control_chain = _is_control_chain_comm(src_id, dst_id, src_type, dst_type)
                    
                    deny_rule = None
                    if is_intra_zone or is_control_chain:
                        deny_rule = _firewall_is_denied(firewall, src_raw, dst_raw)
                        if deny_rule is None:
                            deny_rule = _firewall_is_denied(firewall, src_id, dst_id)
                        if deny_rule is None and src_zone and dst_zone:
                            deny_rule = _firewall_is_denied(firewall, src_zone, dst_zone)
                        if deny_rule is None and src_zone:
                            deny_rule = _firewall_is_denied(firewall, src_zone, dst_id)
                        if deny_rule is None and dst_zone:
                            deny_rule = _firewall_is_denied(firewall, src_id, dst_zone)

                    if (is_intra_zone or is_control_chain) and deny_rule is None:
                        proto = conn.get("protocol", conn.get("proto", "unknown")) or "unknown"
                        fw_port = conn.get("port", None)
                        print(f"  [unified] ALLOWED control/intra-zone (by default) {src_id} -> {dst_id} [{proto}]",
                              flush=True)
                    else:
                        reason = (
                            f"No matching allow rule. "
                            f"Tried: src={_id_variants(src_raw)[:3]} or zone={src_zone}, "
                            f"dst={_id_variants(dst_raw)[:3]} or zone={dst_zone}"
                        )
                        if deny_rule:
                            reason = f"Explicitly denied by rule: {deny_rule.get('description') or 'deny'}"
                        self.firewall_blocked.append({
                            "src": src_id, "dst": dst_id, "reason": reason,
                        })
                        print(f"  [unified] BLOCKED {src_id} -> {dst_id}: {reason}", flush=True)
                        continue
                else:
                    proto = rule.get("protocol", proto) or proto
                    fw_port = rule.get("port")
                    print(f"  [unified] ALLOWED {src_id} -> {dst_id} [{proto}] (fw rule matched)",
                          flush=True)
            else:
                print(f"  [unified] ALLOWED {src_id} -> {dst_id} [{proto}] (open policy)",
                      flush=True)
                fw_port = conn.get("port", None)

            proto_norm = str(proto or "").strip().lower()
            proto_inferred = False
            if proto_norm in ("", "unknown", "any", "network_traffic"):
                src_type = next((o["type"] for o in self.O if o["id"] == src_id), "unknown")
                dst_type = next((o["type"] for o in self.O if o["id"] == dst_id), "unknown")
                guess = ontology.infer_protocol(src_type, dst_type, src_id, dst_id)
                if guess:
                    proto = guess
                    proto_inferred = True
                    print(f"  [unified] Inferred protocol for {src_id} -> {dst_id}: "
                          f"{guess} (from {src_type or '?'}<->{dst_type or '?'})", flush=True)

            self.Ec.append({
                "id":       f"ec_{i}",
                "source":   src_id,
                "target":   dst_id,
                "edge_set": "Ec",
                "label": {
                    "sm":              "c",
                    "protocol":        proto or "unknown",
                    "protocol_inferred": proto_inferred,
                    "port":            fw_port,
                    "source_zone":     src_zone,
                    "target_zone":     dst_zone,
                    "destination_type": next(
                        (o["type"] for o in self.O if o["id"] == dst_id), "unknown"
                    ),
                },
                "confidence":  conn.get("confidence", 0.9),
                "source_file": "architecture_diagram",
            })
            ec_built += 1

        print(f"  [unified] Ec edges built: {ec_built} (blocked: {len(self.firewall_blocked)})",
              flush=True)

    def _validate(self):
        zone_set = {z["id"] for z in self.Z}

        for o in self.O:
            if o["zone"] not in zone_set:
                self.validation_issues.append(
                    f"Object '{o['id']}' has invalid zone '{o['zone']}'."
                )
                o["zone"] = "unassigned_zone"

        for ea in self.Ea:
            if not ea["label"].get("action"):
                self.validation_issues.append(
                    f"Authorization edge {ea['id']} missing action label."
                )

        for ec in self.Ec:
            if not ec["label"].get("protocol"):
                self.validation_issues.append(
                    f"Communication edge {ec['id']} missing protocol context."
                )

    def build(
        self,
        arch_data: Dict,
        rbac_data: Dict,
        firewall_parser: Optional[FirewallParser] = None,
    ) -> "UnifiedModel":
        print("\n" + "="*55, flush=True)
        print("  UNIFIED MODEL BUILD - Stage-by-Stage Debug", flush=True)
        print("="*55, flush=True)

        zones       = arch_data.get("Z") or arch_data.get("zones", [])
        objects     = arch_data.get("O") or arch_data.get("assets", [])
        connections = []
        e_data = arch_data.get("E") or {}
        if isinstance(e_data, dict):
            connections = e_data.get("connections", arch_data.get("communications", []))
        else:
            connections = arch_data.get("communications", [])

        print(f"\n[INPUT] arch: {len(zones)} zones, {len(objects)} objects, "
              f"{len(connections)} connections", flush=True)
        print(f"[INPUT] rbac: S={len(rbac_data.get('S', []))}, "
              f"R={len(rbac_data.get('R', []))}, "
              f"permissions={len(rbac_data.get('permissions', []))}", flush=True)
        if firewall_parser:
            self.zone_mapping = getattr(firewall_parser, "zone_mapping", {}).copy()
            print(f"[INPUT] firewall: {len(firewall_parser.rules)} rules", flush=True)
        else:
            self.zone_mapping = {}
            print("[INPUT] firewall: None (open policy)", flush=True)

        print("\n--- Stage 1: Zones ---", flush=True)
        self._ingest_zones(zones)

        print("\n--- Stage 2: Objects ---", flush=True)
        self._ingest_objects(objects)

        print("\n--- Stage 3: Subjects ---", flush=True)
        self._ingest_subjects(rbac_data.get("S", []))

        print("\n--- Stage 4: Actions ---", flush=True)
        self._ingest_actions(rbac_data.get("R", []))

        print("\n--- Stage 5: Permissions (-> Ea) ---", flush=True)
        self._ingest_permissions(rbac_data.get("permissions", []))

        print("\n--- Stage 6: Connections (-> Ec, firewall filter) ---", flush=True)
        self._ingest_connections(connections, firewall_parser)

        self._validate()

        print(f"\n{'='*55}", flush=True)
        print(f"  UNIFIED MODEL COMPLETE", flush=True)
        print(f"  Z={len(self.Z)}  S={len(self.S)}  O={len(self.O)}  "
              f"R={len(self.R)}  Ea={len(self.Ea)}  Ec={len(self.Ec)}", flush=True)
        if self.validation_issues:
            print(f"  Validation issues: {len(self.validation_issues)}", flush=True)
            for vi in self.validation_issues[:5]:
                print(f"    [WARN] {vi}", flush=True)
        print("="*55 + "\n", flush=True)

        return self

    def to_dict(self) -> Dict:
        return {
            "Z":  self.Z,
            "S":  self.S,
            "O":  self.O,
            "R":  self.R,
            "E": {
                "Ea": self.Ea,
                "Ec": self.Ec,
            },
            "zones":  self.Z,
            "roles":  self.S,
            "assets": self.O,
            "communications": [
                {
                    "source":    e["source"],
                    "target":    e["target"],
                    "protocol":  e["label"].get("protocol", "unknown"),
                    "edge_type": "assumption-based",
                }
                for e in self.Ec
            ],
            "permissions": [
                {
                    "subject":          e["source"],
                    "object":           e["target"],
                    "action":           e["label"].get("action", "access"),
                    "role_provenance":  e["label"].get("role_provenance"),
                    "edge_type":        "policy-enforced",
                }
                for e in self.Ea
            ],
            "physical_dependencies": [],
            "firewall_blocked":  self.firewall_blocked,
            "validation_issues": self.validation_issues,
            "zone_mapping":      self.zone_mapping,
        }


def build_unified_model(
    arch_data: Dict,
    rbac_data: Dict,
    firewall_parser: Optional[FirewallParser] = None,
) -> Dict:
    model = UnifiedModel()
    model.build(arch_data, rbac_data, firewall_parser)
    return model.to_dict()
