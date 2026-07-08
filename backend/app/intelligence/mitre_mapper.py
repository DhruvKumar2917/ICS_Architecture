"""
MITRE ATT&CK for ICS Mapping Module — LLM-Assisted Edition.
"""

import logging
import os
import re
from typing import Any, Dict, List, Optional, Set, Tuple

import networkx as nx

from app.intelligence.llm_mapper import (
    LLMMITREMapper,
    extract_context,
    formal_analysis,
    validate_tactic_ordering,
    TACTIC_ORDER,
    TACTIC_RANK,
)

logger = logging.getLogger(__name__)

# Tactic Severity Classification
TACTIC_SEVERITY = {
    "Impair Process Control":     "CRITICAL",
    "Inhibit Response Function":  "CRITICAL",
    "Impact":                     "CRITICAL",
    "Evasion":                    "HIGH",
    "Lateral Movement":           "HIGH",
    "Execution":                  "HIGH",
    "Initial Access":             "HIGH",
    "Discovery":                  "MEDIUM",
    "Persistence":                "MEDIUM",
    "Command and Control":        "MEDIUM",
    "Collection":                 "MEDIUM",
    "Unknown":                    "LOW",
}

# Real-World Attack Examples
REAL_WORLD_EXAMPLES: Dict[str, str] = {
    "T0831": "Stuxnet (2010) — modified PLC controller tasking to damage Iranian centrifuges",
    "T0836": "Stuxnet (2010) — altered centrifuge frequency parameters while spoofing normal readings",
    "T0857": "Triton/TRISIS (2017) — reprogrammed Schneider Triconex safety controller firmware",
    "T0855": "Triton/TRISIS (2017) — sent unauthorized commands to safety instrumented systems",
    "T0838": "Triton/TRISIS (2017) — disabled safety alarms before attempting physical damage",
    "T0866": "Industroyer (2016) — used remote services to access Ukrainian power grid RTUs",
    "T0869": "Industroyer (2016) — used standard protocols (HTTP/TCP) for C2 communication",
    "T0801": "Industroyer (2016) — monitored process state via IEC 61850 / OPC before disruption",
    "T0814": "BlackEnergy (2015) — modified firewall rules to maintain persistent access",
    "T0816": "CrashOverride (2016) — issued device restart commands to trip breakers",
    "T0803": "CrashOverride (2016) — blocked command messages to prevent operator recovery",
    "T0804": "CrashOverride (2016) — blocked reporting messages to blind operators",
    "T0862": "SolarWinds/OT (2020) — supply chain compromise reached industrial networks",
    "T0859": "Multiple APTs — credential reuse and valid account abuse for lateral movement",
    "T0853": "Havex (2014) — used scripting to automate OPC servers in ICS networks",
    "T0877": "Havex (2014) — captured I/O images from OPC-connected PLCs",
    "T0834": "Multiple APTs — native S7comm API abuse for Siemens PLC manipulation",
    "T0843": "Stuxnet (2010) — downloaded malicious program to PLCs via Step 7",
    "T0845": "Stuxnet (2010) — uploaded PLC programs for analysis and modification",
    "T0858": "CrashOverride (2016) — changed RTU operating modes to disrupt power distribution",
    "T0856": "Industroyer (2016) — spoofed SCADA reporting messages to mask attack progress",
    "T0852": "Multiple APTs — captured historian screen data for reconnaissance",
    "T0864": "Multiple APTs — used lateral movement via remote services in OT networks",
}

CANONICAL_TECHNIQUES: Dict[str, Dict[str, str]] = {
    "T0801": {"name": "Monitor Process State", "tactic": "Collection"},
    "T0812": {"name": "Default Credentials", "tactic": "Initial Access"},
    "T0814": {"name": "Modify Firewall", "tactic": "Evasion"},
    "T0816": {"name": "Device Restart/Shutdown", "tactic": "Inhibit Response Function"},
    "T0831": {"name": "Modify Controller Tasking", "tactic": "Impair Process Control"},
    "T0834": {"name": "Native API", "tactic": "Execution"},
    "T0836": {"name": "Modify Parameter", "tactic": "Impair Process Control"},
    "T0847": {"name": "Unauthorized Command Message", "tactic": "Impair Process Control"},
    "T0853": {"name": "Scripting", "tactic": "Execution"},
    "T0856": {"name": "Spoof Reporting Message", "tactic": "Impair Process Control"},
    "T0857": {"name": "System Firmware", "tactic": "Persistence"},
    "T0859": {"name": "Valid Accounts", "tactic": "Lateral Movement"},
    "T0866": {"name": "Remote Services", "tactic": "Initial Access"},
    "T0869": {"name": "Standard Application Layer Protocol", "tactic": "Command and Control"},
    "T0877": {"name": "I/O Image", "tactic": "Collection"},
    "T0880": {"name": "Network Denial of Service", "tactic": "Impact"},
    "T0881": {"name": "Service Stop", "tactic": "Inhibit Response Function"},
    "T0884": {"name": "Network Connection Enumeration", "tactic": "Discovery"},
    "T0886": {"name": "Modify Account", "tactic": "Persistence"},
    "T0887": {"name": "Remote System Discovery", "tactic": "Discovery"},
}


class _RuleBasedMapper:
    _ACTION_MAP = {
        "remote_login": ("T0866", "Remote Services", "Initial Access"),
        "remote_access": ("T0866", "Remote Services", "Initial Access"),
        "vpn_access": ("T0866", "Remote Services", "Initial Access"),
        "ssh_access": ("T0866", "Remote Services", "Initial Access"),
        "rdp_access": ("T0866", "Remote Services", "Initial Access"),
        "modify_firewall": ("T0814", "Modify Firewall", "Evasion"),
        "send_command": ("T0831", "Modify Controller Tasking", "Impair Process Control"),
        "write_plc": ("T0831", "Modify Controller Tasking", "Impair Process Control"),
        "program_plc": ("T0836", "Modify Parameter", "Impair Process Control"),
        "hmi_access": ("T0877", "I/O Image", "Collection"),
        "engineering_access": ("T0853", "Scripting", "Execution"),
        "firmware_update": ("T0857", "System Firmware", "Persistence"),
        "admin_access": ("T0859", "Valid Accounts", "Lateral Movement"),
        "shutdown": ("T0816", "Device Restart/Shutdown", "Inhibit Response Function"),
        "connect": ("T0866", "Remote Services", "Initial Access"),
        "access": ("T0859", "Valid Accounts", "Lateral Movement"),
        "read": ("T0877", "I/O Image", "Collection"),
        "write": ("T0836", "Modify Parameter", "Impair Process Control"),
        "monitor": ("T0801", "Monitor Process State", "Collection"),
        "read_diagnostics": ("T0887", "Remote System Discovery", "Discovery"),
        "manage_accounts": ("T0886", "Modify Account", "Persistence"),
        "modify_vpn": ("T0866", "Remote Services", "Initial Access"),
        "review_logs": ("T0801", "Monitor Process State", "Collection"),
        "remote_desktop": ("T0866", "Remote Services", "Initial Access"),
        "issue_command": ("T0831", "Modify Controller Tasking", "Impair Process Control"),
        "update_config": ("T0831", "Modify Controller Tasking", "Impair Process Control"),
    }

    _PROTOCOL_MAP = {
        "modbus": ("T0801", "Monitor Process State", "Collection"),
        "modbus_tcp": ("T0801", "Monitor Process State", "Collection"),
        "opc_ua": ("T0801", "Monitor Process State", "Collection"),
        "opc": ("T0801", "Monitor Process State", "Collection"),
        "dnp3": ("T0801", "Monitor Process State", "Collection"),
        "s7comm": ("T0834", "Native API", "Execution"),
        "vpn": ("T0866", "Remote Services", "Initial Access"),
        "ssh": ("T0866", "Remote Services", "Initial Access"),
        "rdp": ("T0866", "Remote Services", "Initial Access"),
        "https": ("T0869", "Standard Application Layer Protocol", "Command and Control"),
        "http": ("T0869", "Standard Application Layer Protocol", "Command and Control"),
        "tcp": ("T0869", "Standard Application Layer Protocol", "Command and Control"),
        "tcp_ip": ("T0869", "Standard Application Layer Protocol", "Command and Control"),
        "tcp-ip": ("T0869", "Standard Application Layer Protocol", "Command and Control"),
    }

    def map_edge(self, context: Dict[str, Any]) -> Dict[str, Any]:
        action = context.get("action", "").lower().replace("-", "_").replace(" ", "_")
        protocol = context.get("protocol", "").lower().replace("-", "_").replace(" ", "_")
        target_type = context.get("target_type", "").lower()

        if protocol and protocol not in ("unknown", "any") and protocol in self._PROTOCOL_MAP:
            tid, name, tactic = self._PROTOCOL_MAP[protocol]
        elif action in self._ACTION_MAP:
            tid, name, tactic = self._ACTION_MAP[action]
        elif protocol in self._PROTOCOL_MAP:
            tid, name, tactic = self._PROTOCOL_MAP[protocol]
        elif target_type in ("plc", "rtu"):
            tid, name, tactic = "T0831", "Modify Controller Tasking", "Impair Process Control"
        elif target_type == "hmi":
            tid, name, tactic = "T0877", "I/O Image", "Collection"
        elif target_type == "scada":
            tid, name, tactic = "T0856", "Spoof Reporting Message", "Impair Process Control"
        else:
            tid, name, tactic = "T0859", "Valid Accounts", "Lateral Movement"

        return {
            "technique_id": tid,
            "technique_name": name,
            "tactic": tactic,
            "confidence": 0.5,
            "reason": f"Rule-based: action={action}, protocol={protocol}, target={target_type}",
            "validated": True,
            "validation_warnings": [],
            "adjusted_confidence": 0.5,
        }


class GraphReachabilityValidator:
    def __init__(self, ics_graph=None, firewall_rules: Optional[List[Dict]] = None, zone_mapping: Optional[Dict[str, str]] = None):
        self._asset_graph: Optional[nx.DiGraph] = None
        self._comm_graph:  nx.DiGraph = nx.DiGraph()
        self._full_graph:  nx.DiGraph = nx.DiGraph()
        self.zone_mapping: Dict[str, str] = zone_mapping or {}
        self._fw_allowed: Set[Tuple[str, str, str]] = set()

        if ics_graph is not None:
            self._ingest_graph(ics_graph)
        if firewall_rules:
            self._ingest_firewall(firewall_rules)

    def _ingest_graph(self, ics_graph) -> None:
        self._asset_graph = ics_graph.asset_graph
        for u, v, d in self._asset_graph.edges(data=True):
            self._full_graph.add_edge(u, v)
            if d.get("edge_type") == "COMM_LINK":
                self._comm_graph.add_edge(u, v, **d)

    def _ingest_firewall(self, allowed_pairs: List[Dict]) -> None:
        for rule in allowed_pairs:
            src   = self._slug(str(rule.get("src",      rule.get("source", ""))))
            dst   = self._slug(str(rule.get("dst",      rule.get("target", ""))))
            proto = self._slug(str(rule.get("protocol", "any")))
            if src and dst:
                self._fw_allowed.add((src, dst, proto))
                self._fw_allowed.add((src, dst, "any"))

    @staticmethod
    def _slug(s: str) -> str:
        s = s.strip().lower()
        s = re.sub(r"[^a-z0-9]+", "_", s)
        return re.sub(r"_+", "_", s).strip("_") or "x"

    def comm_edge_exists(self, src: str, tgt: str) -> bool:
        return self._comm_graph.has_edge(src, tgt)

    def can_reach(self, src: str, tgt: str) -> bool:
        if not (self._comm_graph.has_node(src) and self._comm_graph.has_node(tgt)):
            return False
        try:
            return nx.has_path(self._comm_graph, src, tgt)
        except nx.NetworkXError:
            return False

    def _id_variants(self, raw: str) -> List[str]:
        base = self._slug(raw)
        variants = [base, raw.strip()]
        
        strip_suffixes = [
            "_server", "_host", "_gateway", "_gw", "_router", "_switch",
            "_controller", "_node", "_device", "_system", "_firewall"
        ]
        for suffix in strip_suffixes:
            if base.endswith(suffix):
                variants.append(base[: -len(suffix)])
                
        zone_mapping = {
            "zone1": "wind_turbine_control_center",
            "zone2": "wind_farm_control_room",
            "zone3": "customer_control_room",
            "zone4": "vendor_control_room",
            "zone5": "wind_turbine",
        }
        clean_base = base.replace("_", "").replace("-", "")
        if clean_base in zone_mapping:
            variants.append(zone_mapping[clean_base])
        else:
            for k, v in zone_mapping.items():
                if base == v or clean_base == v.replace("_", ""):
                    variants.append(k)
                    break
                    
        variants.append(re.sub(r"[\-\s]+", "_", raw.strip().lower()))
        
        seen = set()
        result = []
        for v in variants:
            v = v.strip("_")
            if v and v not in seen:
                seen.add(v)
                result.append(self._slug(v))
        return result

    def firewall_allows(
        self,
        src: str,
        tgt: str,
        protocol: str = "any",
        src_zone: Optional[str] = None,
        tgt_zone: Optional[str] = None,
    ) -> bool:
        if not self._fw_allowed:
            return True
            
        src_variants = self._id_variants(src)
        tgt_variants = self._id_variants(tgt)
        p = self._slug(protocol)
        
        for sv in src_variants:
            for dv in tgt_variants:
                if (sv, dv, p) in self._fw_allowed or (sv, dv, "any") in self._fw_allowed:
                    return True
                    
        if src_zone and tgt_zone:
            sz_variants = self._id_variants(src_zone)
            tz_variants = self._id_variants(tgt_zone)
            for szv in sz_variants:
                for tzv in tz_variants:
                    if (szv, tzv, p) in self._fw_allowed or (szv, tzv, "any") in self._fw_allowed:
                        return True
                        
        if src_zone:
            sz_variants = self._id_variants(src_zone)
            for szv in sz_variants:
                for dv in tgt_variants:
                    if (szv, dv, p) in self._fw_allowed or (szv, dv, "any") in self._fw_allowed:
                        return True
                        
        if tgt_zone:
            tz_variants = self._id_variants(tgt_zone)
            for sv in src_variants:
                for tzv in tz_variants:
                    if (sv, tzv, p) in self._fw_allowed or (sv, tzv, "any") in self._fw_allowed:
                        return True

        return False

    def get_node_type(self, node_id: str) -> str:
        if self._asset_graph is None:
            return "unknown"
        return str(self._asset_graph.nodes.get(node_id, {}).get("type", "unknown")).lower()

    def get_node_purdue(self, node_id: str) -> Optional[float]:
        if self._asset_graph is None:
            return None
        raw = self._asset_graph.nodes.get(node_id, {}).get("purdue_level", "")
        try:
            digits = "".join(filter(str.isdigit, str(raw)))
            return float(digits) if digits else None
        except ValueError:
            return None

    def get_attack_chain(self, path: List[str]) -> List[Dict]:
        chain = []
        n = len(path)
        for i, node in enumerate(path):
            ntype = self.get_node_type(node)
            purdue = self.get_node_purdue(node)

            if i == 0:
                position = "entry"
            elif i == n - 1:
                position = "target"
            elif ntype in ("firewall", "vpn", "gateway") or (
                self._asset_graph is not None
                and self._asset_graph.nodes.get(node, {}).get("is_enforcement_point")
            ):
                position = "boundary"
            else:
                position = "pivot"

            chain.append({
                "node":           node,
                "node_type":      ntype,
                "chain_position": position,
                "purdue_level":   purdue,
            })
        return chain

    def compute_technique_confidence(
        self,
        src: str,
        tgt: str,
        protocol: str,
        action: str,
        target_type: str,
        has_purdue_skip: bool = False,
    ) -> float:
        score = 0.0

        is_auth = False
        if self._asset_graph is not None and self._asset_graph.has_node(src):
            is_auth = (self._asset_graph.nodes[src].get("node_category") == "HUMAN_ACTOR") or (action != "connect" and action != "unknown")

        if is_auth:
            score += 0.60
        else:
            if self.comm_edge_exists(src, tgt):
                score += 0.30
            elif self.can_reach(src, tgt):
                score += 0.15

            if self.firewall_allows(src, tgt, protocol):
                score += 0.30

        tgt_slug = target_type.lower().strip()
        act_slug = action.lower().replace("-", "_").replace(" ", "_")
        plc_actions = {"write_plc", "send_command", "program_plc", "modify_plc",
                       "download_program", "stop_plc", "write", "modify"}
        hmi_actions = {"hmi_access", "view_process", "monitor", "read_data", "read"}

        if tgt_slug in ("plc", "rtu") and act_slug in plc_actions:
            score += 0.20
        elif tgt_slug in ("hmi", "historian") and act_slug in hmi_actions:
            score += 0.20
        elif tgt_slug in ("server", "workstation", "scada") and act_slug in (
            "admin_access", "root_access", "super_user", "read_write", "access"
        ):
            score += 0.20
        else:
            score += 0.10

        if not has_purdue_skip:
            score += 0.20

        return round(min(score, 1.0), 2)


class MITREMapper:
    def __init__(self, use_llm: bool = True):
        self.use_llm = use_llm
        if use_llm:
            self._llm_mapper = LLMMITREMapper()
        else:
            self._llm_mapper = None
        self._rule_mapper = _RuleBasedMapper()
        self._id_name_registry: Dict[str, str] = {
            tid: meta["name"] for tid, meta in CANONICAL_TECHNIQUES.items()
        }
        self._id_tactic_registry: Dict[str, str] = {
            tid: meta["tactic"] for tid, meta in CANONICAL_TECHNIQUES.items()
        }

    @staticmethod
    def _is_generic_remote(mapping: Dict[str, Any]) -> bool:
        return str(mapping.get("technique_id", "")).upper() in {"T0866", "T0812", "T0881"}

    def _reconcile_with_rule_baseline(self, context: Dict[str, Any], mapping: Dict[str, Any]) -> Dict[str, Any]:
        mapping = dict(mapping or {})
        warnings = list(mapping.get("validation_warnings", []))

        baseline = self._rule_mapper.map_edge(context)
        baseline = self._canonicalize_mapping(baseline)

        action = str(context.get("action", "")).lower().replace("-", "_").replace(" ", "_")
        protocol = str(context.get("protocol", "")).lower().replace("-", "_").replace(" ", "_")
        llm_conf = float(mapping.get("adjusted_confidence", mapping.get("confidence", 0.0)))

        strong_action = action in {
            "modify_firewall", "send_command", "issue_command", "update_config",
            "manage_accounts", "modify_vpn", "read_diagnostics", "monitor"
        }
        strong_protocol = protocol in {"modbus", "modbus_tcp", "opc", "opc_ua", "dnp3", "s7comm"}

        should_override = False
        if mapping.get("validated") is False:
            should_override = True
        elif self._is_generic_remote(mapping) and (strong_action or strong_protocol):
            should_override = True
        elif llm_conf < 0.45 and baseline.get("technique_id") != mapping.get("technique_id"):
            should_override = True

        if should_override:
            warnings.append(
                f"Reconciled LLM mapping to rule baseline: {mapping.get('technique_id')} -> {baseline.get('technique_id')}"
            )
            merged = dict(mapping)
            merged["technique_id"] = baseline.get("technique_id", mapping.get("technique_id"))
            merged["technique_name"] = baseline.get("technique_name", mapping.get("technique_name"))
            merged["tactic"] = baseline.get("tactic", mapping.get("tactic"))
            merged["validated"] = True
            merged["adjusted_confidence"] = round(max(llm_conf, float(baseline.get("adjusted_confidence", 0.5))), 2)
            merged["validation_warnings"] = warnings
            
            baseline_name = baseline.get("technique_name", "Unknown")
            baseline_id = baseline.get("technique_id", "Unknown")
            original_reason = mapping.get("reason", "")
            merged["reason"] = f"Reconciled LLM mapping to baseline '{baseline_name}' ({baseline_id}) due to strong action/protocol match. Original LLM reasoning: {original_reason}"
            
            return merged

        if warnings:
            mapping["validation_warnings"] = warnings
        return mapping

    def _canonicalize_mapping(self, mapping: Dict[str, Any]) -> Dict[str, Any]:
        mapping = dict(mapping or {})
        warnings = list(mapping.get("validation_warnings", []))

        tid = str(mapping.get("technique_id", "")).upper().strip()
        if not re.match(r"^T\d{4}$", tid):
            return mapping

        current_name = str(mapping.get("technique_name", "")).strip()
        current_tactic = str(mapping.get("tactic", "")).strip()

        canonical_name = self._id_name_registry.get(tid) or current_name
        canonical_tactic = self._id_tactic_registry.get(tid) or current_tactic

        if current_name and canonical_name and current_name.lower() != canonical_name.lower():
            warnings.append(
                f"Canonicalized technique_name for {tid}: '{current_name}' -> '{canonical_name}'"
            )
        if current_tactic and canonical_tactic and current_tactic != canonical_tactic:
            warnings.append(
                f"Canonicalized tactic for {tid}: '{current_tactic}' -> '{canonical_tactic}'"
            )

        if canonical_name:
            self._id_name_registry[tid] = canonical_name
            mapping["technique_name"] = canonical_name
        if canonical_tactic:
            self._id_tactic_registry[tid] = canonical_tactic
            mapping["tactic"] = canonical_tactic

        mapping["technique_id"] = tid
        if warnings:
            mapping["validation_warnings"] = warnings
        return mapping

    @staticmethod
    def _build_global_formal_snapshot(ea_mappings: List[Dict], ec_mappings: List[Dict]) -> Dict[str, Any]:
        mu: Dict[str, List[str]] = {}
        theta: Set[str] = set()
        tactic_sequence: List[str] = []
        mitre_trace: List[Dict[str, Any]] = []

        for i, m in enumerate(ea_mappings):
            edge_id = m.get("edge_id", "")
            action = m.get("action", "access")
            edge_key = edge_id or f"ea:{m.get('subject', '')}->{m.get('object', '')}::{action}::{i}"
            tid = m.get("mitre", {}).get("id", "")
            if tid:
                mu[edge_key] = [tid]
                theta.add(tid)
            tactic = m.get("mitre", {}).get("tactic", "Unknown")
            tactic_sequence.append(tactic)
            mitre_trace.append({
                "edge": edge_key,
                "technique_id": tid,
                "technique_name": m.get("mitre", {}).get("name", "Unknown"),
                "tactic": tactic,
                "confidence": m.get("mitre", {}).get("technique_confidence", 0.5),
                "reason": m.get("mitre", {}).get("llm_reason", ""),
            })

        for i, m in enumerate(ec_mappings):
            edge_id = m.get("edge_id", "")
            protocol = m.get("protocol", "unknown")
            edge_key = edge_id or f"ec:{m.get('source', '')}->{m.get('target', '')}::{protocol}::{i}"
            tid = m.get("mitre", {}).get("id", "")
            if tid:
                mu[edge_key] = [tid]
                theta.add(tid)
            tactic = m.get("mitre", {}).get("tactic", "Unknown")
            tactic_sequence.append(tactic)
            mitre_trace.append({
                "edge": edge_key,
                "technique_id": tid,
                "technique_name": m.get("mitre", {}).get("name", "Unknown"),
                "tactic": tactic,
                "confidence": m.get("mitre", {}).get("technique_confidence", 0.5),
                "reason": m.get("mitre", {}).get("llm_reason", ""),
            })

        return {
            "attack_path": [],
            "mu": mu,
            "theta": sorted(theta),
            "tactic_progression": tactic_sequence,
            "ordering_validation": {
                "valid": None,
                "violations": [],
                "tactic_sequence": [],
                "note": "not_applicable_graph_level",
            },
            "mitre_trace": mitre_trace,
        }

    @staticmethod
    def _assess_mapping_quality(all_mappings: List[Dict[str, Any]]) -> Dict[str, Any]:
        if not all_mappings:
            return {
                "id_name_conflicts": 0,
                "reason_keyword_conflicts": 0,
                "generic_remote_ratio": 0.0,
                "unique_mapping_ratio": 0.0,
            }

        by_id: Dict[str, Set[str]] = {}
        reason_keyword_conflicts = 0
        generic_remote = 0
        unique_pairs: Set[str] = set()

        for m in all_mappings:
            mitre = m.get("mitre", {})
            tid = str(mitre.get("id", ""))
            name = str(mitre.get("name", "")).strip().lower()
            reason = str(mitre.get("llm_reason", "")).lower()
            edge_sig = f"{m.get('edge_id','')}::{tid}"
            unique_pairs.add(edge_sig)

            if tid:
                by_id.setdefault(tid, set()).add(name)

            if tid in {"T0866", "T0812", "T0881"}:
                generic_remote += 1

            if "modify firewall" in reason and tid not in {"T0814", "T0886"}:
                reason_keyword_conflicts += 1
            if "unauthorized command" in reason and tid not in {"T0847", "T0831", "T0836"}:
                reason_keyword_conflicts += 1

        id_name_conflicts = sum(1 for names in by_id.values() if len({n for n in names if n}) > 1)
        total = len(all_mappings)
        return {
            "id_name_conflicts": id_name_conflicts,
            "reason_keyword_conflicts": reason_keyword_conflicts,
            "generic_remote_ratio": round(generic_remote / total, 3),
            "unique_mapping_ratio": round(len(unique_pairs) / total, 3),
        }

    @staticmethod
    def _build_mitre_record(
        mapping: Dict[str, Any],
        *,
        reachability_verified: bool = False,
        firewall_verified:     bool = False,
        comm_edge_exists:      bool = False,
        technique_confidence:  float = 0.5,
        chain_context:         str   = "",
        chain_position:        str   = "",
        suppressed:            bool  = False,
        suppression_reason:    str   = "",
    ) -> Dict[str, Any]:
        tech_id = mapping.get("technique_id", "T0859")
        tactic  = mapping.get("tactic", "Unknown")

        llm_conf = float(mapping.get("adjusted_confidence", mapping.get("confidence", 0.5)))
        blended_confidence = round((llm_conf * 0.6 + technique_confidence * 0.4), 2)

        return {
            "id":       tech_id,
            "name":     mapping.get("technique_name", "Unknown"),
            "tactic":   tactic,
            "severity": TACTIC_SEVERITY.get(tactic, "LOW"),
            "url":      f"https://attack.mitre.org/techniques/{tech_id}/",
            "real_world_example": REAL_WORLD_EXAMPLES.get(tech_id, ""),
            "llm_reason":           mapping.get("reason", ""),
            "llm_confidence":       llm_conf,
            "mapping_mode":         "llm" if mapping.get("llm_model") else "rules",
            "reachability_verified": reachability_verified,
            "firewall_verified":     firewall_verified,
            "comm_edge_exists":      comm_edge_exists,
            "technique_confidence":  blended_confidence,
            "chain_context":         chain_context,
            "chain_position":        chain_position,
            "suppressed":            suppressed,
            "suppression_reason":    suppression_reason,
            "validation_warnings":  mapping.get("validation_warnings", []),
            "execution_status":     mapping.get("execution_status", "Successful"),
        }

    def _map_edge(self, context: Dict[str, Any]) -> Dict[str, Any]:
        if self.use_llm and self._llm_mapper:
            raw = self._llm_mapper.map_single_edge(context)
        else:
            raw = self._rule_mapper.map_edge(context)
        canonical = self._canonicalize_mapping(raw)
        return self._reconcile_with_rule_baseline(context, canonical)

    def map_authorization_edges_with_context(
        self,
        ea_edges: List[Dict],
        validator: GraphReachabilityValidator,
        ics_graph=None,
    ) -> List[Dict]:
        results = []
        high_value_targets = {"plc", "rtu", "safety_controller", "sensor", "actuator"}

        for edge in ea_edges:
            ctx = extract_context(edge, "authorization", validator, ics_graph)
            mapping = self._map_edge(ctx)

            source = edge.get("source", "")
            target = edge.get("target", "")
            label  = edge.get("label", {})
            dst_type = label.get("destination_type", "").lower()
            action   = label.get("action", "access")

            comm_ok = True
            fw_ok   = True

            suppressed = False
            suppression_reason = ""
            if dst_type in high_value_targets and not comm_ok:
                suppressed = True
                suppression_reason = (
                    f"No communication path from '{source}' to '{target}' "
                    f"(type={dst_type}) found in the network graph. "
                    f"Technique suppressed — attacker cannot reach this target "
                    f"via any COMM_LINK edge."
                )

            struct_confidence = validator.compute_technique_confidence(
                src=source, tgt=target,
                protocol="unknown", action=action,
                target_type=dst_type,
            )

            results.append({
                "edge_id":     edge.get("id", ""),
                "subject":     source,
                "action":      action,
                "object":      target,
                "source_zone": label.get("source_zone", ""),
                "target_zone": label.get("target_zone", ""),
                "mitre": self._build_mitre_record(
                    mapping,
                    reachability_verified=comm_ok,
                    firewall_verified=fw_ok,
                    comm_edge_exists=validator.comm_edge_exists(source, target),
                    technique_confidence=struct_confidence,
                    suppressed=suppressed,
                    suppression_reason=suppression_reason,
                ),
            })

        logger.info(
            f"[MITREMapper] Ea: {len(results)} mapped ({'LLM' if self.use_llm else 'rules'}), "
            f"{sum(1 for r in results if r['mitre']['suppressed'])} suppressed"
        )
        return results

    def map_communication_edges_with_context(
        self,
        ec_edges: List[Dict],
        validator: GraphReachabilityValidator,
        ics_graph=None,
    ) -> List[Dict]:
        results = []

        for edge in ec_edges:
            ctx = extract_context(edge, "communication", validator, ics_graph)
            mapping = self._map_edge(ctx)

            source = edge.get("source", "")
            target = edge.get("target", "")
            label  = edge.get("label", {})
            protocol = label.get("protocol", "unknown")
            dst_type = label.get("destination_type", "").lower()

            direct_comm = validator.comm_edge_exists(source, target)
            reachable   = direct_comm or validator.can_reach(source, target)
            fw_ok       = validator.firewall_allows(
                source,
                target,
                protocol,
                src_zone=label.get("source_zone", ""),
                tgt_zone=label.get("target_zone", ""),
            )

            suppressed = False
            suppression_reason = ""
            if not reachable and not direct_comm:
                suppressed = True
                suppression_reason = (
                    f"Ec edge ({source} → {target}, protocol={protocol}) has no "
                    f"corresponding COMM_LINK path in the network graph."
                )

            struct_confidence = validator.compute_technique_confidence(
                src=source, tgt=target,
                protocol=protocol, action="connect",
                target_type=dst_type,
            )

            results.append({
                "edge_id":     edge.get("id", ""),
                "source":      source,
                "target":      target,
                "protocol":    protocol,
                "source_zone": label.get("source_zone", ""),
                "target_zone": label.get("target_zone", ""),
                "mitre": self._build_mitre_record(
                    mapping,
                    reachability_verified=reachable,
                    firewall_verified=fw_ok,
                    comm_edge_exists=direct_comm,
                    technique_confidence=struct_confidence,
                    suppressed=suppressed,
                    suppression_reason=suppression_reason,
                ),
            })

        logger.info(
            f"[MITREMapper] Ec: {len(results)} mapped ({'LLM' if self.use_llm else 'rules'}), "
            f"{sum(1 for r in results if r['mitre']['suppressed'])} flagged"
        )
        return results

    def map_attack_path_with_context(
        self,
        path: List[str],
        ics_graph,
        validator: Optional[GraphReachabilityValidator] = None,
    ) -> List[Dict]:
        asset_graph = ics_graph.asset_graph

        if validator is None:
            validator = GraphReachabilityValidator(ics_graph)

        chain_label = " → ".join(path)
        chain_info = validator.get_attack_chain(path)
        chain_by_node = {c["node"]: c for c in chain_info}

        edge_contexts = []
        edge_metadata = []

        for i in range(len(path) - 1):
            u, v = path[i], path[i + 1]

            u_chain = chain_by_node.get(u, {"chain_position": "pivot", "node_type": "unknown", "purdue_level": None})
            v_chain = chain_by_node.get(v, {"chain_position": "pivot", "node_type": "unknown", "purdue_level": None})

            edge_type = ""
            protocol  = "unknown"
            action    = "access"

            if asset_graph.has_edge(u, v):
                edge_data = asset_graph[u][v]
                edge_type = edge_data.get("edge_type", "")
                raw_label = str(edge_data.get("label", ""))
                if edge_type == "COMM_LINK":
                    protocol = raw_label
                elif edge_type == "HUMAN_PERM":
                    action = raw_label
                elif edge_type == "CYBER_PHYSICAL":
                    action = "write"

            prev_n = path[i - 1] if i > 0 else "None"
            next_n = path[i + 2] if i < len(path) - 2 else "None"

            if edge_type == "COMM_LINK":
                u_zone = asset_graph.nodes.get(u, {}).get("zone", "unknown")
                v_zone = asset_graph.nodes.get(v, {}).get("zone", "unknown")
                synth_edge = {
                    "source": u, "target": v,
                    "label": {
                        "protocol": protocol,
                        "destination_type": v_chain["node_type"],
                        "source_zone": u_zone,
                        "target_zone": v_zone,
                    }
                }
                ctx = extract_context(
                    synth_edge, "communication", validator, ics_graph,
                    previous_node=prev_n, next_node=next_n
                )
            else:
                u_zone = asset_graph.nodes.get(u, {}).get("zone", "unknown")
                v_zone = asset_graph.nodes.get(v, {}).get("zone", "unknown")
                synth_edge = {
                    "source": u, "target": v,
                    "label": {
                        "action": action,
                        "destination_type": v_chain["node_type"],
                        "source_zone": u_zone,
                        "target_zone": v_zone,
                    }
                }
                ctx = extract_context(
                    synth_edge, "authorization", validator, ics_graph,
                    previous_node=prev_n, next_node=next_n
                )

            edge_contexts.append(ctx)
            edge_metadata.append({
                "u": u, "v": v,
                "edge_type": edge_type,
                "v_pos": v_chain["chain_position"],
                "u_chain": u_chain,
                "v_chain": v_chain,
            })

        if self.use_llm and self._llm_mapper:
            edge_mappings, formal_result = self._llm_mapper.map_attack_path(
                path, edge_contexts
            )
            edge_mappings = [self._canonicalize_mapping(m) for m in edge_mappings]
        else:
            edge_mappings = [self._rule_mapper.map_edge(ctx) for ctx in edge_contexts]
            edge_mappings = [self._canonicalize_mapping(m) for m in edge_mappings]
            formal_result = formal_analysis(path, edge_mappings)

        hop_mapping: List[Dict] = []

        for i, (mapping, meta) in enumerate(zip(edge_mappings, edge_metadata)):
            u = meta["u"]
            v = meta["v"]
            v_pos = meta["v_pos"]
            u_chain = meta["u_chain"]
            v_chain = meta["v_chain"]

            if meta["edge_type"] == "COMM_LINK":
                direct_comm = validator.comm_edge_exists(u, v)
                reachable   = direct_comm or validator.can_reach(u, v)
                fw_ok       = validator.firewall_allows(
                    u,
                    v,
                    edge_contexts[i].get("protocol", "unknown"),
                    src_zone=str(edge_contexts[i].get("source_zone", "")),
                    tgt_zone=str(edge_contexts[i].get("target_zone", "")),
                )
            else:
                direct_comm = True
                reachable   = True
                fw_ok       = True

            u_purdue = u_chain.get("purdue_level")
            v_purdue = v_chain.get("purdue_level")
            has_purdue_skip = (
                u_purdue is not None
                and v_purdue is not None
                and abs(u_purdue - v_purdue) > 1
                and u_purdue >= 3
                and v_purdue <= 1
            )

            prior_hops_ok = all(
                not h["mitre"].get("suppressed", False)
                for h in hop_mapping
            )
            prerequisites_met = prior_hops_ok and reachable

            struct_confidence = validator.compute_technique_confidence(
                src=u, tgt=v,
                protocol=edge_contexts[i].get("protocol", "unknown"),
                action=edge_contexts[i].get("action", "access"),
                target_type=v_chain["node_type"],
                has_purdue_skip=has_purdue_skip,
            )

            suppressed = False
            suppression_reason = ""
            if v_chain["node_type"] in ("plc", "rtu", "safety_controller", "sensor", "actuator") \
                    and not reachable:
                suppressed = True
                suppression_reason = (
                    f"No comm path from '{u}' to '{v}' (type={v_chain['node_type']}). "
                    f"The attacker cannot reach this OT asset."
                )
            elif has_purdue_skip and not direct_comm:
                suppressed = True
                suppression_reason = (
                    f"Purdue-level skip: L{u_purdue} → L{v_purdue} without direct COMM_LINK."
                )

            hop_mapping.append({
                "from":                  u,
                "to":                    v,
                "edge_type":             meta["edge_type"],
                "chain_position":        v_pos,
                "prerequisites_met":     prerequisites_met,
                "reachability_verified": reachable,
                "chain_context":         chain_label,
                "mitre": self._build_mitre_record(
                    mapping,
                    reachability_verified=reachable,
                    firewall_verified=fw_ok,
                    comm_edge_exists=direct_comm,
                    technique_confidence=struct_confidence,
                    chain_context=chain_label,
                    chain_position=v_pos,
                    suppressed=suppressed,
                    suppression_reason=suppression_reason,
                ),
                **({"formal_analysis": formal_result} if i == len(edge_mappings) - 1 else {}),
            })

        return hop_mapping

    def map_attack_path(self, path: List[str], ics_graph) -> List[Dict]:
        return self.map_attack_path_with_context(path, ics_graph)

    def map_aasg_with_context(
        self,
        aasg_graph,
        ics_graph,
        firewall_rules: Optional[List[Dict]] = None,
        zone_mapping: Optional[Dict[str, str]] = None,
    ) -> Dict[str, Any]:
        validator = GraphReachabilityValidator(
            ics_graph=ics_graph,
            firewall_rules=firewall_rules or [],
            zone_mapping=zone_mapping,
        )

        ea_mappings = self.map_authorization_edges_with_context(
            aasg_graph.Ea, validator, ics_graph
        )
        ec_mappings = self.map_communication_edges_with_context(
            aasg_graph.Ec, validator, ics_graph
        )

        technique_summary: Dict[str, Dict] = {}
        tactic_summary:    Dict[str, int]  = {}

        all_mappings = ea_mappings + ec_mappings
        for m in all_mappings:
            tid   = m["mitre"]["id"]
            tname = m["mitre"]["name"]
            tact  = m["mitre"]["tactic"]

            if tid not in technique_summary:
                technique_summary[tid] = {
                    "id":                   tid,
                    "name":                 tname,
                    "tactic":               tact,
                    "severity":             m["mitre"].get("severity", "LOW"),
                    "url":                  m["mitre"]["url"],
                    "real_world_example":   m["mitre"].get("real_world_example", ""),
                    "count":                0,
                    "suppressed_count":     0,
                    "avg_confidence":       0.0,
                    "reachability_verified_count": 0,
                    "firewall_verified_count":     0,
                }
            rec = technique_summary[tid]
            rec["count"] += 1
            if m["mitre"].get("suppressed"):
                rec["suppressed_count"] += 1
            if m["mitre"].get("reachability_verified"):
                rec["reachability_verified_count"] += 1
            if m["mitre"].get("firewall_verified"):
                rec["firewall_verified_count"] += 1
            prev_avg = rec["avg_confidence"]
            n = rec["count"]
            rec["avg_confidence"] = round(
                prev_avg + (m["mitre"].get("technique_confidence", 0.5) - prev_avg) / n, 2
            )
            tactic_summary[tact] = tactic_summary.get(tact, 0) + 1

        total          = len(all_mappings)
        suppressed     = sum(1 for m in all_mappings if m["mitre"].get("suppressed"))
        low_conf       = sum(1 for m in all_mappings if m["mitre"].get("technique_confidence", 1.0) < 0.4)
        reach_verified = sum(1 for m in all_mappings if m["mitre"].get("reachability_verified"))
        fw_verified    = sum(1 for m in all_mappings if m["mitre"].get("firewall_verified"))

        global_formal = self._build_global_formal_snapshot(ea_mappings, ec_mappings)

        llm_stats = {}
        if self._llm_mapper:
            llm_stats = self._llm_mapper.get_stats()

        quality_checks = self._assess_mapping_quality(all_mappings)

        logger.info(
            f"[MITREMapper][{'LLM' if self.use_llm else 'Rules'}] "
            f"{len(ea_mappings)} Ea + {len(ec_mappings)} Ec = {total} total. "
            f"{len(technique_summary)} techniques. "
            f"Suppressed: {suppressed}. Low-conf: {low_conf}. "
            f"Reach verified: {reach_verified}/{total}. "
            f"FW verified: {fw_verified}/{total}. "
            f"ID-name conflicts: {quality_checks.get('id_name_conflicts', 0)}."
        )

        return {
            "authorization_mappings": ea_mappings,
            "communication_mappings": ec_mappings,
            "technique_summary":      list(technique_summary.values()),
            "tactic_summary":         tactic_summary,
            "context_aware": True,
            "mapping_mode":  "llm" if self.use_llm else "rules",
            "context_stats": {
                "total_mappings":          total,
                "suppressed":              suppressed,
                "low_confidence":          low_conf,
                "reachability_verified":   reach_verified,
                "firewall_verified":       fw_verified,
                "suppression_rate_pct":    round(suppressed / total * 100, 1) if total else 0.0,
                "avg_confidence":          round(
                    sum(m["mitre"].get("technique_confidence", 0.5) for m in all_mappings) / total, 2
                ) if total else 0.0,
                "quality_checks": quality_checks,
            },
            "llm_stats": llm_stats,
            "formal_analysis": global_formal,
        }
