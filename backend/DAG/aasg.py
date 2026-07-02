"""
Authorization Attack Surface Graph (AASG) - Formal G = (V, E, Z).

Strictly conforms to the professor's mathematical definition:

  G = (V, E, Z)  where:
    Z  = set of security zones
    V  = S union O   (subjects only and objects only - NO action/policy/role nodes)
    E  = Ea union Ec
         Ea: authorization edges   (subject -> object,  action  as edge label)
         Ec: communication edges   (object  -> object,  protocol as edge label)

Edge label schema for every em = (vi, vj):
    lem = ⟨ sm, p(em), tvj, θ(vi), θ(vj) ⟩
    where:
      sm     = "a" for Ea, "c" for Ec
      p(em)  = action (Ea) or protocol (Ec)
      tvj    = type of destination vertex
      θ(vi)  = zone of source vertex
      θ(vj)  = zone of destination vertex

Roles, actions, policies, and authorization paths are NOT vertices.
They appear only as label metadata on edges.

No attack paths are generated here. Phase 1 extracts structure only.
MITRE ATT&CK mapping and attack-path traversal belong to later phases.
"""

import logging
from typing import Any, Dict, List, Set

logger = logging.getLogger(__name__)


class AASGGraph:
    """
    Formal Authorization Attack Surface Graph G = (V, E, Z).

    Vertex normalization step is applied during construction to prevent
    duplicate vertices from inconsistent naming across data sources.
    """

    def __init__(self, unified_data: Dict[str, Any]):
        self.Z: List[str]        = []    # Zone IDs
        self.V: List[Dict]       = []    # Vertices = S union O (subjects and objects only)
        self.Ea: List[Dict]      = []    # Authorization edges
        self.Ec: List[Dict]      = []    # Communication edges
        self.R:  List[Dict]      = []    # Action catalogue (metadata, not vertices)

        self._vertex_ids: Set[str] = set()
        self._zone_map:   Dict[str, str] = {}   # vertex_id → zone_id
        self._type_map:   Dict[str, str] = {}   # vertex_id → asset type

        self._build(unified_data)

    # ------------------------------------------------------------------ #
    # Internal helpers
    # ------------------------------------------------------------------ #

    def _theta(self, vertex_id: str) -> str:
        """Zone mapping function φ(v) → z."""
        return self._zone_map.get(vertex_id, "unassigned_zone")

    def _type_of(self, vertex_id: str) -> str:
        return self._type_map.get(vertex_id, "unknown")

    def _ensure_vertex(self, vid: str, vertex_type: str, zone: str, asset_type: str = "unknown"):
        """Add a vertex to V if not already present. V = S union O only."""
        if not vid or vid in self._vertex_ids:
            return

        self._zone_map[vid] = zone or "unassigned_zone"
        self._type_map[vid] = asset_type

        self.V.append({
            "id":          vid,
            "vertex_type": vertex_type,   # "subject" or "object"
            "label": {
                "theta": zone or "unassigned_zone",     # φ(v)
                "type":  asset_type,
            },
        })
        self._vertex_ids.add(vid)

    # ------------------------------------------------------------------ #
    # Main builder
    # ------------------------------------------------------------------ #

    def _build(self, data: Dict[str, Any]):
        # 1. Populate Z
        for z in data.get("Z", data.get("zones", [])):
            zid = z.get("id") if isinstance(z, dict) else str(z)
            if zid and zid not in self.Z:
                self.Z.append(zid)

        # 2. Action catalogue R (metadata only, not vertices)
        self.R = data.get("R", [])

        # 3. Add subjects S → vertex_type = "subject"
        for s in data.get("S", data.get("roles", [])):
            sid   = s.get("id")
            szone = s.get("zone", "external_transit")
            if sid:
                self._ensure_vertex(sid, "subject", szone, asset_type="subject")

        # 4. Add objects O → vertex_type = "object"
        for o in data.get("O", data.get("assets", [])):
            oid   = o.get("id")
            ozone = o.get("zone", "unassigned_zone")
            otype = o.get("type", "unknown")
            if oid:
                self._ensure_vertex(oid, "object", ozone, asset_type=otype)

        # 5. Populate Ea from explicit Ea list (preferred, from unified model)
        ea_list = []
        e_data = data.get("E", {})
        if isinstance(e_data, dict):
            ea_list = e_data.get("Ea", [])
        if not ea_list:
            # Fallback: legacy permissions list
            ea_list = data.get("permissions", [])

        for i, ea in enumerate(ea_list):
            if isinstance(ea, dict) and "label" in ea:
                # Already in canonical edge format from UnifiedModel
                sub = ea.get("source", "")
                obj = ea.get("target", "")
                if not sub or not obj:
                    continue
                # Guarantee vertices exist
                self._ensure_vertex(sub, "subject", "external_transit")
                self._ensure_vertex(obj, "object", self._theta(obj))
                # Build Ea edge with formal label
                lbl = ea.get("label", {})
                self.Ea.append({
                    "id":     ea.get("id", f"ea_{i}"),
                    "source": sub,
                    "target": obj,
                    "label": {
                        "sm":              "a",
                        "action":          lbl.get("action", "access"),
                        "role_provenance": lbl.get("role_provenance", sub),
                        "destination_type": self._type_of(obj),
                        "source_zone":     self._theta(sub),
                        "target_zone":     self._theta(obj),
                    },
                    "confidence":  ea.get("confidence", 1.0),
                    "source_file": ea.get("source_file", "rbac_file"),
                })
            else:
                # Legacy format: {subject, object, action}
                sub = str(ea.get("subject", ""))
                obj = str(ea.get("object", ""))
                act = str(ea.get("action", "access"))
                prov = ea.get("role_provenance", sub)
                if not sub or not obj:
                    continue
                self._ensure_vertex(sub, "subject", "external_transit")
                self._ensure_vertex(obj, "object", self._theta(obj))
                self.Ea.append({
                    "id":     f"ea_{i}",
                    "source": sub,
                    "target": obj,
                    "label": {
                        "sm":              "a",
                        "action":          act,
                        "role_provenance": str(prov),
                        "destination_type": self._type_of(obj),
                        "source_zone":     self._theta(sub),
                        "target_zone":     self._theta(obj),
                    },
                    "confidence":  1.0,
                    "source_file": "rbac_file",
                })

        # 6. Populate Ec from explicit Ec list (preferred) or communications
        ec_list = []
        if isinstance(e_data, dict):
            ec_list = e_data.get("Ec", [])
        if not ec_list:
            ec_list = data.get("communications", [])

        for i, ec in enumerate(ec_list):
            if isinstance(ec, dict) and "label" in ec:
                # Canonical edge format from UnifiedModel
                src = ec.get("source", "")
                tgt = ec.get("target", "")
                if not src or not tgt:
                    continue
                self._ensure_vertex(src, "object", self._theta(src))
                self._ensure_vertex(tgt, "object", self._theta(tgt))
                lbl = ec.get("label", {})
                self.Ec.append({
                    "id":     ec.get("id", f"ec_{i}"),
                    "source": src,
                    "target": tgt,
                    "label": {
                        "sm":              "c",
                        "protocol":        lbl.get("protocol", "unknown"),
                        "port":            lbl.get("port"),
                        "destination_type": self._type_of(tgt),
                        "source_zone":     self._theta(src),
                        "target_zone":     self._theta(tgt),
                    },
                    "confidence":  ec.get("confidence", 0.9),
                    "source_file": ec.get("source_file", "architecture_diagram"),
                })
            else:
                # Legacy format: {source, target, protocol}
                src   = str(ec.get("source", ""))
                tgt   = str(ec.get("target", ""))
                proto = str(ec.get("protocol", "unknown"))
                if not src or not tgt:
                    continue
                self._ensure_vertex(src, "object", self._theta(src))
                self._ensure_vertex(tgt, "object", self._theta(tgt))
                self.Ec.append({
                    "id":     f"ec_{i}",
                    "source": src,
                    "target": tgt,
                    "label": {
                        "sm":              "c",
                        "protocol":        proto,
                        "port":            None,
                        "destination_type": self._type_of(tgt),
                        "source_zone":     self._theta(src),
                        "target_zone":     self._theta(tgt),
                    },
                    "confidence":  0.9,
                    "source_file": "architecture_diagram",
                })

    # ------------------------------------------------------------------ #
    # Serialisation
    # ------------------------------------------------------------------ #

    def to_dict(self) -> Dict[str, Any]:
        return {
            "Z":  self.Z,
            "V":  self.V,
            "E": {
                "E_a": self.Ea,
                "E_c": self.Ec,
            },
            "R":  self.R,
            # Summary statistics for the frontend AASG panel
            "stats": {
                "subject_count": sum(1 for v in self.V if v["vertex_type"] == "subject"),
                "object_count":  sum(1 for v in self.V if v["vertex_type"] == "object"),
                "ea_count":      len(self.Ea),
                "ec_count":      len(self.Ec),
                "zone_count":    len(self.Z),
            },
        }
