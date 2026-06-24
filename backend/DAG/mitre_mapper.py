"""
MITRE ATT&CK for ICS Mapping Module.

Maps RBAC actions and communication protocols extracted from the AASG
(Authorization Attack Surface Graph) to known MITRE ATT&CK for ICS
techniques (https://attack.mitre.org/matrices/ics/).

Usage:
    from DAG.mitre_mapper import MITREMapper
    mapper = MITREMapper()
    results = mapper.map_aasg(aasg_graph)
"""

import logging
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Tactic Severity Classification
# ---------------------------------------------------------------------------
# Maps MITRE ATT&CK for ICS tactics to risk severity levels.
# Used to weight attack paths by the most dangerous tactic they trigger.

TACTIC_SEVERITY = {
    "Impair Process Control":     "CRITICAL",
    "Inhibit Response Function":  "CRITICAL",
    "Evasion":                    "HIGH",
    "Lateral Movement":           "HIGH",
    "Execution":                  "HIGH",
    "Initial Access":             "HIGH",
    "Persistence":                "MEDIUM",
    "Command and Control":        "MEDIUM",
    "Collection":                 "MEDIUM",
    "Unknown":                    "LOW",
}

# ---------------------------------------------------------------------------
# Real-World Attack Examples
# ---------------------------------------------------------------------------
# Maps technique IDs to documented ICS attacks that used them.

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
    "T0853": "Havex (2014) — used scripting to enumerate OPC servers in ICS networks",
    "T0877": "Havex (2014) — captured I/O images from OPC-connected PLCs",
    "T0834": "Multiple APTs — native S7comm API abuse for Siemens PLC manipulation",
    "T0843": "Stuxnet (2010) — downloaded malicious program to PLCs via Step 7",
    "T0845": "Stuxnet (2010) — uploaded PLC programs for analysis and modification",
    "T0858": "CrashOverride (2016) — changed RTU operating modes to disrupt power distribution",
    "T0856": "Industroyer (2016) — spoofed SCADA reporting messages to mask attack progress",
    "T0852": "Multiple APTs — captured historian screen data for reconnaissance",
}

# ---------------------------------------------------------------------------
# MITRE ATT&CK for ICS Technique Catalogue
# ---------------------------------------------------------------------------

# Action-based mapping: maps RBAC action slugs → ATT&CK technique(s)
MITRE_ACTION_MAP: Dict[str, Dict[str, Any]] = {
    # ── Remote access / initial access ────────────────────────────────────
    "remote_login":        {"technique": "T0866", "name": "Remote Services",              "tactic": "Initial Access"},
    "remote_access":       {"technique": "T0866", "name": "Remote Services",              "tactic": "Initial Access"},
    "vpn_access":          {"technique": "T0866", "name": "Remote Services",              "tactic": "Initial Access"},
    "ssh_access":          {"technique": "T0866", "name": "Remote Services",              "tactic": "Initial Access"},
    "rdp_access":          {"technique": "T0866", "name": "Remote Services",              "tactic": "Initial Access"},

    # ── Firewall / network manipulation ───────────────────────────────────
    "modify_firewall":     {"technique": "T0814", "name": "Modify Firewall",              "tactic": "Evasion"},
    "firewall_config":     {"technique": "T0814", "name": "Modify Firewall",              "tactic": "Evasion"},
    "network_config":      {"technique": "T0814", "name": "Modify Firewall",              "tactic": "Evasion"},

    # ── PLC / controller manipulation ─────────────────────────────────────
    "send_command":        {"technique": "T0831", "name": "Modify Controller Tasking",    "tactic": "Impair Process Control"},
    "write_plc":           {"technique": "T0831", "name": "Modify Controller Tasking",    "tactic": "Impair Process Control"},
    "program_plc":         {"technique": "T0836", "name": "Modify Parameter",             "tactic": "Impair Process Control"},
    "modify_plc":          {"technique": "T0836", "name": "Modify Parameter",             "tactic": "Impair Process Control"},
    "download_program":    {"technique": "T0843", "name": "Program Download",             "tactic": "Impair Process Control"},
    "upload_program":      {"technique": "T0845", "name": "Program Upload",               "tactic": "Collection"},
    "stop_plc":            {"technique": "T0858", "name": "Change Operating Mode",        "tactic": "Impair Process Control"},

    # ── Configuration updates ──────────────────────────────────────────────
    "update_config":       {"technique": "T0803", "name": "Block Command Message",        "tactic": "Impair Process Control"},
    "config_change":       {"technique": "T0803", "name": "Block Command Message",        "tactic": "Impair Process Control"},
    "modify_config":       {"technique": "T0836", "name": "Modify Parameter",             "tactic": "Impair Process Control"},
    "write_config":        {"technique": "T0836", "name": "Modify Parameter",             "tactic": "Impair Process Control"},

    # ── Engineering / HMI access ──────────────────────────────────────────
    "hmi_access":          {"technique": "T0877", "name": "I/O Image",                    "tactic": "Collection"},
    "engineering_access":  {"technique": "T0853", "name": "Scripting",                    "tactic": "Execution"},
    "view_process":        {"technique": "T0877", "name": "I/O Image",                    "tactic": "Collection"},
    "monitor":             {"technique": "T0877", "name": "I/O Image",                    "tactic": "Collection"},
    "read_data":           {"technique": "T0877", "name": "I/O Image",                    "tactic": "Collection"},

    # ── Maintenance / service actions ─────────────────────────────────────
    "maintenance":         {"technique": "T0862", "name": "Supply Chain Compromise",      "tactic": "Initial Access"},
    "firmware_update":     {"technique": "T0857", "name": "System Firmware",              "tactic": "Persistence"},
    "patch":               {"technique": "T0857", "name": "System Firmware",              "tactic": "Persistence"},

    # ── Privilege escalation / lateral movement ───────────────────────────
    "admin_access":        {"technique": "T0859", "name": "Valid Accounts",               "tactic": "Lateral Movement"},
    "super_user":          {"technique": "T0859", "name": "Valid Accounts",               "tactic": "Lateral Movement"},
    "root_access":         {"technique": "T0859", "name": "Valid Accounts",               "tactic": "Lateral Movement"},
    "read_write":          {"technique": "T0859", "name": "Valid Accounts",               "tactic": "Lateral Movement"},

    # ── Denial of service / disruption ────────────────────────────────────
    "inhibit":             {"technique": "T0816", "name": "Device Restart/Shutdown",      "tactic": "Inhibit Response Function"},
    "shutdown":            {"technique": "T0816", "name": "Device Restart/Shutdown",      "tactic": "Inhibit Response Function"},
    "restart":             {"technique": "T0816", "name": "Device Restart/Shutdown",      "tactic": "Inhibit Response Function"},
    "block_command":       {"technique": "T0803", "name": "Block Command Message",        "tactic": "Inhibit Response Function"},
    "block_report":        {"technique": "T0804", "name": "Block Reporting Message",      "tactic": "Inhibit Response Function"},

    # ── Data collection ───────────────────────────────────────────────────
    "read":                {"technique": "T0877", "name": "I/O Image",                    "tactic": "Collection"},
    "access":              {"technique": "T0859", "name": "Valid Accounts",               "tactic": "Lateral Movement"},
    "connect":             {"technique": "T0866", "name": "Remote Services",              "tactic": "Initial Access"},
    "write":               {"technique": "T0836", "name": "Modify Parameter",             "tactic": "Impair Process Control"},
}

# Protocol-based mapping: maps network protocol slugs → ATT&CK technique(s)
MITRE_PROTOCOL_MAP: Dict[str, Dict[str, Any]] = {
    # ── ICS / OT protocols ────────────────────────────────────────────────
    "modbus":          {"technique": "T0801", "name": "Monitor Process State",            "tactic": "Collection"},
    "modbus_tcp":      {"technique": "T0801", "name": "Monitor Process State",            "tactic": "Collection"},
    "opc_ua":          {"technique": "T0801", "name": "Monitor Process State",            "tactic": "Collection"},
    "opc":             {"technique": "T0801", "name": "Monitor Process State",            "tactic": "Collection"},
    "dnp3":            {"technique": "T0801", "name": "Monitor Process State",            "tactic": "Collection"},
    "profinet":        {"technique": "T0801", "name": "Monitor Process State",            "tactic": "Collection"},
    "ethercat":        {"technique": "T0801", "name": "Monitor Process State",            "tactic": "Collection"},
    "s7comm":          {"technique": "T0834", "name": "Native API",                       "tactic": "Execution"},
    "bacnet":          {"technique": "T0801", "name": "Monitor Process State",            "tactic": "Collection"},
    "iec_61850":       {"technique": "T0801", "name": "Monitor Process State",            "tactic": "Collection"},
    "iec61850":        {"technique": "T0801", "name": "Monitor Process State",            "tactic": "Collection"},
    "hart":            {"technique": "T0801", "name": "Monitor Process State",            "tactic": "Collection"},
    "io_link":         {"technique": "T0801", "name": "Monitor Process State",            "tactic": "Collection"},
    "iolink":          {"technique": "T0801", "name": "Monitor Process State",            "tactic": "Collection"},
    "canbus":          {"technique": "T0801", "name": "Monitor Process State",            "tactic": "Collection"},
    "profibus":        {"technique": "T0801", "name": "Monitor Process State",            "tactic": "Collection"},
    "fieldbus":        {"technique": "T0801", "name": "Monitor Process State",            "tactic": "Collection"},

    # ── IT / network protocols ────────────────────────────────────────────
    "vpn":             {"technique": "T0866", "name": "Remote Services",                  "tactic": "Initial Access"},
    "openvpn":         {"technique": "T0866", "name": "Remote Services",                  "tactic": "Initial Access"},
    "ipsec":           {"technique": "T0866", "name": "Remote Services",                  "tactic": "Initial Access"},
    "ssh":             {"technique": "T0866", "name": "Remote Services",                  "tactic": "Initial Access"},
    "rdp":             {"technique": "T0866", "name": "Remote Services",                  "tactic": "Initial Access"},
    "https":           {"technique": "T0869", "name": "Standard Application Layer Protocol", "tactic": "Command and Control"},
    "http":            {"technique": "T0869", "name": "Standard Application Layer Protocol", "tactic": "Command and Control"},
    "tcp":             {"technique": "T0869", "name": "Standard Application Layer Protocol", "tactic": "Command and Control"},
    "udp":             {"technique": "T0869", "name": "Standard Application Layer Protocol", "tactic": "Command and Control"},
    "scada_protocol":  {"technique": "T0801", "name": "Monitor Process State",            "tactic": "Collection"},
    "proprietary":     {"technique": "T0834", "name": "Native API",                       "tactic": "Execution"},
}

# Node-type based mapping: maps RBAC targets/objects to techniques
MITRE_NODE_TYPE_MAP: Dict[str, Dict[str, Any]] = {
    "plc":               {"technique": "T0831", "name": "Modify Controller Tasking",  "tactic": "Impair Process Control"},
    "rtu":               {"technique": "T0831", "name": "Modify Controller Tasking",  "tactic": "Impair Process Control"},
    "hmi":               {"technique": "T0877", "name": "I/O Image",                  "tactic": "Collection"},
    "scada":             {"technique": "T0856", "name": "Spoof Reporting Message",     "tactic": "Impair Process Control"},
    "historian":         {"technique": "T0852", "name": "Screen Capture",              "tactic": "Collection"},
    "firewall":          {"technique": "T0814", "name": "Modify Firewall",             "tactic": "Evasion"},
    "vpn":               {"technique": "T0866", "name": "Remote Services",             "tactic": "Initial Access"},
    "server":            {"technique": "T0859", "name": "Valid Accounts",              "tactic": "Lateral Movement"},
    "workstation":       {"technique": "T0859", "name": "Valid Accounts",              "tactic": "Lateral Movement"},
    "sensor":            {"technique": "T0855", "name": "Unauthorized Command Message","tactic": "Impair Process Control"},
    "actuator":          {"technique": "T0855", "name": "Unauthorized Command Message","tactic": "Impair Process Control"},
    "safety_controller": {"technique": "T0838", "name": "Modify Alarm Settings",      "tactic": "Inhibit Response Function"},
    "engineering":       {"technique": "T0853", "name": "Scripting",                  "tactic": "Execution"},
    "operator":          {"technique": "T0859", "name": "Valid Accounts",              "tactic": "Lateral Movement"},
}


# ---------------------------------------------------------------------------
# Main Mapper Class
# ---------------------------------------------------------------------------

class MITREMapper:
    """
    Maps AASG edges and nodes to MITRE ATT&CK for ICS techniques.

    Processes:
      - Ea (authorization edges) → maps action labels
      - Ec (communication edges) → maps protocol labels
      - V (vertices/nodes)       → maps node types
    """

    def __init__(self):
        self.action_map    = MITRE_ACTION_MAP
        self.protocol_map  = MITRE_PROTOCOL_MAP
        self.node_type_map = MITRE_NODE_TYPE_MAP

    def _lookup_action(self, action: str) -> Optional[Dict[str, Any]]:
        """Fuzzy-match an action string to a MITRE technique."""
        if not action:
            return None
        slug = action.lower().replace("-", "_").replace(" ", "_")
        if slug in self.action_map:
            return self.action_map[slug]
        # Partial match: check if any key is a substring of the action
        for key, tech in self.action_map.items():
            if key in slug or slug in key:
                return tech
        return None

    def _lookup_protocol(self, protocol: str) -> Optional[Dict[str, Any]]:
        """Fuzzy-match a protocol string to a MITRE technique."""
        if not protocol:
            return None
        slug = protocol.lower().replace("-", "_").replace(" ", "_").replace("/", "_")
        if slug in self.protocol_map:
            return self.protocol_map[slug]
        for key, tech in self.protocol_map.items():
            if key in slug or slug in key:
                return tech
        return None

    def _lookup_node_type(self, node_type: str) -> Optional[Dict[str, Any]]:
        """Match a node type to a MITRE technique."""
        if not node_type:
            return None
        slug = node_type.lower().strip()
        if slug in self.node_type_map:
            return self.node_type_map[slug]
        for key, tech in self.node_type_map.items():
            if key in slug:
                return tech
        return None

    def get_contextual_mapping(self, source_type: str, target_type: str, action: str, protocol: str) -> Dict[str, Any]:
        """
        Dynamically resolves the MITRE ATT&CK for ICS technique based on context:
        source_type, target_type, action/permission, and protocol.
        """
        src = str(source_type or "").lower().strip()
        tgt = str(target_type or "").lower().strip()
        act = str(action or "").lower().strip()
        proto = str(protocol or "").lower().strip()

        # Context-Aware Rule: Modbus write/modify commands -> Modify Controller Tasking (T0831)
        if proto in ("modbus", "modbus_tcp") and act in ("write", "write_plc", "modify", "send_command"):
            return {"technique": "T0831", "name": "Modify Controller Tasking", "tactic": "Impair Process Control"}

        # Rule 1: Controller Manipulation / Modify Controller Tasking (T0831)
        if tgt in ("plc", "rtu") and (act in ("write", "write_plc", "send_command", "modify", "program", "program_plc") or proto in ("modbus", "modbus_tcp", "s7comm", "profinet", "ethercat")):
            return {"technique": "T0831", "name": "Modify Controller Tasking", "tactic": "Impair Process Control"}

        # Rule 2: Modify Parameter (T0836)
        if tgt in ("plc", "rtu") and act in ("modify_plc", "program_plc", "write_config", "modify_config", "update_config", "config_change", "modify_parameter"):
            return {"technique": "T0836", "name": "Modify Parameter", "tactic": "Impair Process Control"}

        # Rule 3: Monitor Process State / Collection (T0801)
        if proto in ("opc", "opc_ua", "dnp3", "iec_61850", "bacnet", "hart", "modbus", "modbus_tcp") and act in ("read", "monitor", "view", "read_data", "view_process"):
            return {"technique": "T0801", "name": "Monitor Process State", "tactic": "Collection"}

        # Rule 4: System Firmware Update / Safety System Manipulation (T0857)
        if tgt == "safety_controller" and act in ("firmware_update", "patch", "modify", "write"):
            return {"technique": "T0857", "name": "System Firmware", "tactic": "Persistence"}

        # Rule 5: Modify Alarm Settings / Inhibit Response (T0838)
        if tgt == "safety_controller" and act in ("disable_alarm", "modify_alarm", "block_report", "block_command"):
            return {"technique": "T0838", "name": "Modify Alarm Settings", "tactic": "Inhibit Response Function"}

        # Rule 6: Remote Services (T0866)
        if act in ("vpn_access", "remote_login", "ssh_access", "rdp_access") or proto in ("vpn", "rdp", "ssh"):
            return {"technique": "T0866", "name": "Remote Services", "tactic": "Initial Access"}

        # Rule 7: Spoof Reporting Message (T0856)
        if tgt in ("scada", "historian") and (act in ("write", "send_command") or proto in ("http", "https")):
            return {"technique": "T0856", "name": "Spoof Reporting Message", "tactic": "Impair Process Control"}

        # Rule 8: Valid Accounts (T0859)
        if act in ("admin_access", "super_user", "root_access", "read_write"):
            return {"technique": "T0859", "name": "Valid Accounts", "tactic": "Lateral Movement"}

        # Fallbacks
        mitre = None
        if act:
            mitre = self._lookup_action(act)
        if not mitre and proto:
            mitre = self._lookup_protocol(proto)
        if not mitre and tgt:
            mitre = self._lookup_node_type(tgt)

        return mitre or {
            "technique": "T0859",
            "name": "Valid Accounts",
            "tactic": "Lateral Movement",
        }

    def map_authorization_edges(self, ea_edges: List[Dict]) -> List[Dict]:
        """
        Map Ea (authorization) edges to MITRE techniques via action labels.

        Returns a list of enriched edge records, each with a 'mitre' field.
        """
        results = []
        for edge in ea_edges:
            label   = edge.get("label", {})
            action  = label.get("action", "access")
            subject = edge.get("source", "")
            obj     = edge.get("target", "")

            dst_type = label.get("destination_type", "")
            mitre = self.get_contextual_mapping(
                source_type="subject",
                target_type=dst_type,
                action=action,
                protocol="unknown"
            )

            tech_id = mitre["technique"]
            tactic  = mitre.get("tactic", "Unknown")
            results.append({
                "edge_id":  edge.get("id", ""),
                "subject":  subject,
                "action":   action,
                "object":   obj,
                "source_zone": label.get("source_zone", ""),
                "target_zone": label.get("target_zone", ""),
                "mitre": {
                    "id":       tech_id,
                    "name":     mitre["name"],
                    "tactic":   tactic,
                    "severity": TACTIC_SEVERITY.get(tactic, "LOW"),
                    "url":      f"https://attack.mitre.org/techniques/{tech_id}/",
                    "real_world_example": REAL_WORLD_EXAMPLES.get(tech_id, ""),
                },
            })

        logger.info(f"[MITREMapper] Mapped {len(results)} Ea edges to MITRE techniques")
        return results

    def map_communication_edges(self, ec_edges: List[Dict]) -> List[Dict]:
        """
        Map Ec (communication) edges to MITRE techniques via protocol labels.
        """
        results = []
        for edge in ec_edges:
            label    = edge.get("label", {})
            protocol = label.get("protocol", "unknown")
            src      = edge.get("source", "")
            tgt      = edge.get("target", "")

            dst_type = label.get("destination_type", "")
            mitre = self.get_contextual_mapping(
                source_type="unknown",
                target_type=dst_type,
                action="connect",
                protocol=protocol
            )

            tech_id = mitre["technique"]
            tactic  = mitre.get("tactic", "Unknown")
            results.append({
                "edge_id":  edge.get("id", ""),
                "source":   src,
                "target":   tgt,
                "protocol": protocol,
                "source_zone": label.get("source_zone", ""),
                "target_zone": label.get("target_zone", ""),
                "mitre": {
                    "id":       tech_id,
                    "name":     mitre["name"],
                    "tactic":   tactic,
                    "severity": TACTIC_SEVERITY.get(tactic, "LOW"),
                    "url":      f"https://attack.mitre.org/techniques/{tech_id}/",
                    "real_world_example": REAL_WORLD_EXAMPLES.get(tech_id, ""),
                },
            })

        logger.info(f"[MITREMapper] Mapped {len(results)} Ec edges to MITRE techniques")
        return results

    def map_attack_path(self, path: List[str], ics_graph) -> List[Dict]:
        """
        Map each hop in an attack path to the most relevant MITRE technique,
        using edge type and node type data from the ICS graph.
        """
        asset_graph = ics_graph.asset_graph
        hop_mapping = []

        for i in range(len(path) - 1):
            u, v = path[i], path[i + 1]
            if not asset_graph.has_edge(u, v):
                continue

            edge_data  = asset_graph[u][v]
            edge_type  = edge_data.get("edge_type", "")
            label      = edge_data.get("label", "")
            
            u_attrs = asset_graph.nodes[u]
            v_attrs = asset_graph.nodes[v]
            u_type = u_attrs.get("type", "")
            v_type = v_attrs.get("type", "")

            mitre = None
            if edge_type == "HUMAN_PERM":
                action = str(label)
                mitre = self.get_contextual_mapping(
                    source_type=u_type,
                    target_type=v_type,
                    action=action,
                    protocol="unknown"
                )
            elif edge_type == "COMM_LINK":
                proto = str(label)
                mitre = self.get_contextual_mapping(
                    source_type=u_type,
                    target_type=v_type,
                    action="connect",
                    protocol=proto
                )
            elif edge_type == "CYBER_PHYSICAL":
                mitre = self.get_contextual_mapping(
                    source_type=u_type,
                    target_type=v_type,
                    action="write",
                    protocol="unknown"
                )

            if not mitre:
                mitre = self.get_contextual_mapping(
                    source_type=u_type,
                    target_type=v_type,
                    action="access",
                    protocol="unknown"
                )

            tech_id = mitre["technique"]
            tactic  = mitre.get("tactic", "Unknown")
            hop_mapping.append({
                "from":      u,
                "to":        v,
                "edge_type": edge_type,
                "mitre": {
                    "id":       tech_id,
                    "name":     mitre["name"],
                    "tactic":   tactic,
                    "severity": TACTIC_SEVERITY.get(tactic, "LOW"),
                    "url":      f"https://attack.mitre.org/techniques/{tech_id}/",
                    "real_world_example": REAL_WORLD_EXAMPLES.get(tech_id, ""),
                },
            })

        return hop_mapping

    def map_aasg(self, aasg_graph) -> Dict[str, Any]:
        """
        Full AASG mapping: maps both Ea and Ec edges to MITRE techniques.

        Args:
            aasg_graph: AASGGraph instance with .Ea and .Ec lists.

        Returns:
            {
                "authorization_mappings": [...],   # Ea → MITRE
                "communication_mappings": [...],   # Ec → MITRE
                "technique_summary":      {...},   # unique techniques found
                "tactic_summary":         {...},   # unique tactics found
            }
        """
        ea_mappings = self.map_authorization_edges(aasg_graph.Ea)
        ec_mappings = self.map_communication_edges(aasg_graph.Ec)

        # Aggregate unique techniques and tactics
        technique_summary: Dict[str, Dict] = {}
        tactic_summary:    Dict[str, int]   = {}

        for m in ea_mappings + ec_mappings:
            tid   = m["mitre"]["id"]
            tname = m["mitre"]["name"]
            tact  = m["mitre"]["tactic"]

            if tid not in technique_summary:
                technique_summary[tid] = {
                    "id":       tid,
                    "name":     tname,
                    "tactic":   tact,
                    "severity": m["mitre"].get("severity", "LOW"),
                    "url":      m["mitre"]["url"],
                    "real_world_example": m["mitre"].get("real_world_example", ""),
                    "count":    0,
                }
            technique_summary[tid]["count"] += 1

            tactic_summary[tact] = tactic_summary.get(tact, 0) + 1

        logger.info(
            f"[MITREMapper] Total: {len(ea_mappings)} Ea, {len(ec_mappings)} Ec mappings. "
            f"{len(technique_summary)} unique techniques, {len(tactic_summary)} tactics."
        )

        return {
            "authorization_mappings": ea_mappings,
            "communication_mappings": ec_mappings,
            "technique_summary":      list(technique_summary.values()),
            "tactic_summary":         tactic_summary,
        }
