"""
Authorization Attack Surface Graph (AASG) - Formal G = (V, E, Z).
"""

import logging
from typing import Any, Dict, List, Set

logger = logging.getLogger(__name__)


class AASGGraph:
    """
    Formal Authorization Attack Surface Graph G = (V, E, Z).
    """

    def __init__(self, unified_data: Dict[str, Any]):
        self.Z: List[str]        = []
        self.V: List[Dict]       = []
        self.Ea: List[Dict]      = []
        self.Ec: List[Dict]      = []
        self.R:  List[Dict]      = []

        self._vertex_ids: Set[str] = set()
        self._zone_map:   Dict[str, str] = {}
        self._type_map:   Dict[str, str] = {}

        self._build(unified_data)

    def _theta(self, vertex_id: str) -> str:
        return self._zone_map.get(vertex_id, "unassigned_zone")

    def _type_of(self, vertex_id: str) -> str:
        return self._type_map.get(vertex_id, "unknown")

    def _ensure_vertex(self, vid: str, vertex_type: str, zone: str, asset_type: str = "unknown"):
        if not vid or vid in self._vertex_ids:
            return

        self._zone_map[vid] = zone or "unassigned_zone"
        self._type_map[vid] = asset_type

        self.V.append({
            "id":          vid,
            "vertex_type": vertex_type,
            "label": {
                "theta": zone or "unassigned_zone",
                "type":  asset_type,
            },
        })
        self._vertex_ids.add(vid)

    def _build(self, data: Dict[str, Any]):
        for z in data.get("Z", data.get("zones", [])):
            zid = z.get("id") if isinstance(z, dict) else str(z)
            if zid and zid not in self.Z:
                self.Z.append(zid)

        self.R = data.get("R", [])

        for s in data.get("S", data.get("roles", [])):
            sid   = s.get("id")
            szone = s.get("zone", "external_transit")
            if sid:
                self._ensure_vertex(sid, "subject", szone, asset_type="subject")

        for o in data.get("O", data.get("assets", [])):
            oid   = o.get("id")
            ozone = o.get("zone", "unassigned_zone")
            otype = o.get("type", "unknown")
            if oid:
                self._ensure_vertex(oid, "object", ozone, asset_type=otype)

        ea_list = []
        e_data = data.get("E", {})
        if isinstance(e_data, dict):
            ea_list = e_data.get("Ea", [])
        if not ea_list:
            ea_list = data.get("permissions", [])

        for i, ea in enumerate(ea_list):
            if isinstance(ea, dict) and "label" in ea:
                sub = ea.get("source", "")
                obj = ea.get("target", "")
                if not sub or not obj:
                    continue
                self._ensure_vertex(sub, "subject", "external_transit")
                self._ensure_vertex(obj, "object", self._theta(obj))
                lbl = ea.get("label", {})
                self.Ea.append({
                    "id":     ea.get("id", f"ea_{i}"),
                    "source": sub,
                    "target": obj,
                    "edge_type": "policy-enforced",
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
                    "edge_type": "policy-enforced",
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

        ec_list = []
        if isinstance(e_data, dict):
            ec_list = e_data.get("Ec", [])
        if not ec_list:
            ec_list = data.get("communications", [])

        for i, ec in enumerate(ec_list):
            if isinstance(ec, dict) and "label" in ec:
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
                    "edge_type": "assumption-based",
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
                    "edge_type": "assumption-based",
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

    def validate_consistency(self, asset_graph) -> Dict[str, Any]:
        """
        Validates that the edges in AASGGraph match the edges in the compiled NetworkX asset_graph.
        """
        graph_comm_count = sum(1 for u, v, d in asset_graph.edges(data=True) if d.get("edge_type") == "COMM_LINK")
        graph_perm_count = sum(1 for u, v, d in asset_graph.edges(data=True) if d.get("edge_type") == "HUMAN_PERM")
        
        aasg_ea_count = len(self.Ea)
        aasg_ec_count = len(self.Ec)
        
        divergence_detected = (aasg_ea_count != graph_perm_count) or (aasg_ec_count != graph_comm_count)
        
        status = {
            "divergence_detected": divergence_detected,
            "aasg_ea_count": aasg_ea_count,
            "graph_perm_count": graph_perm_count,
            "aasg_ec_count": aasg_ec_count,
            "graph_comm_count": graph_comm_count,
            "msg": f"AASG Ea/Ec count matches NetworkX graph edges: Ea={aasg_ea_count}/{graph_perm_count}, Ec={aasg_ec_count}/{graph_comm_count}"
        }
        if divergence_detected:
            logger.warning(f"AASG-NetworkX Divergence: {status['msg']}")
        return status

    def to_dict(self, asset_graph=None) -> Dict[str, Any]:
        res = {
            "Z":  self.Z,
            "V":  self.V,
            "E": {
                "E_a": self.Ea,
                "E_c": self.Ec,
            },
            "R":  self.R,
            "stats": {
                "subject_count": sum(1 for v in self.V if v["vertex_type"] == "subject"),
                "object_count":  sum(1 for v in self.V if v["vertex_type"] == "object"),
                "ea_count":      len(self.Ea),
                "ec_count":      len(self.Ec),
                "zone_count":    len(self.Z),
            },
        }
        if asset_graph is not None:
            res["consistency_check"] = self.validate_consistency(asset_graph)
        return res
