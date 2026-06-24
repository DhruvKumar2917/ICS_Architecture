"""
Firewall Rules Parser — Determines which object-to-object or zone-to-zone
communication paths are ACTUALLY permitted.

This constrains the Ec (communication edges) set in the AASG model.
Ec = architecture_connections ∩ firewall_allowed

IMPORTANT: This parser outputs structured rules with protocol and port metadata,
NOT just (src, dst) pairs.  Protocol context (VPN, OPC-UA, Modbus, RDP, HTTP)
is preserved because later attack-path analysis depends on knowing what service
enables each communication.

Supported formats:
  JSON      — {"rules": [{"src":..., "dst":..., "action":"allow", "protocol":..., "port":...}]}
  CSV       — src,dst,action,protocol,port
  Plain text — "allow from zone_a to zone_b on port 502 via Modbus"
  iptables   — "-A FORWARD -s 10.0.0.1 -d 10.0.0.2 --dport 502 -j ACCEPT"
"""

import csv
import io
import json
import re
from typing import Any, Dict, List, Optional, Set, Tuple


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _slug(value: Any) -> str:
    value = str(value or "").strip().lower()
    value = re.sub(r"[^a-z0-9]+", "_", value)
    return re.sub(r"_+", "_", value).strip("_") or "x"


def _first(*candidates) -> str:
    for c in candidates:
        if c and str(c).strip():
            return str(c).strip()
    return ""


_ALLOW_VERDICTS = {"allow", "accept", "permit", "pass", "allowed", "yes", "true", "1"}
_DENY_VERDICTS  = {"deny", "drop", "reject", "block", "blocked", "no", "false", "0"}

# Well-known ICS/OT protocol → port mappings for enrichment
_PROTO_PORT_MAP = {
    "502": "modbus", "102": "iso-tsap", "20000": "dnp3",
    "44818": "ethernetip", "2404": "iec104", "4840": "opc-ua",
    "3389": "rdp", "22": "ssh", "23": "telnet", "80": "http",
    "443": "https", "500": "ike-vpn", "1194": "openvpn",
    "4500": "ipsec-nat-t",
}

# Zone Translation Map for mapping placeholder zones to actual architecture zones
_ZONE_TRANSLATION = {
    "zone1": "wind_turbine_control_center",
    "zone2": "wind_farm_control_room",
    "zone3": "customer_control_room",
    "zone4": "vendor_control_room",
    "zone5": "wind_turbine",
}


def _enrich_protocol(protocol: str, port: Optional[str]) -> str:
    """Attempt to resolve a more descriptive protocol name from port if unknown."""
    if protocol and protocol not in ("unknown", "any", ""):
        return protocol.lower()
    if port and str(port) in _PROTO_PORT_MAP:
        return _PROTO_PORT_MAP[str(port)]
    return protocol or "unknown"


# ---------------------------------------------------------------------------
# Core parser class
# ---------------------------------------------------------------------------

class FirewallParser:
    """
    Parses a firewall rule file into structured communication constraint rules.

    Each rule contains:
      src        : source identifier (slug)
      dst        : destination identifier (slug)
      src_raw    : original string from file
      dst_raw    : original string from file
      action     : "allow" or "deny"
      protocol   : service/protocol name (modbus, opc-ua, rdp, vpn, …)
      port       : destination port string (optional)
      description: human-readable summary of the rule
    """

    def __init__(self):
        self.rules: List[Dict]           = []
        # (src_slug, dst_slug) pairs that are allowed — used for O(1) lookup
        self.allowed_pairs: Set[Tuple]   = set()
        # Instance-level zone mapping (can be updated dynamically from config, Problem 6)
        self.zone_mapping: Dict[str, str] = {
            "zone1": "wind_turbine_control_center",
            "zone2": "wind_farm_control_room",
            "zone3": "customer_control_room",
            "zone4": "vendor_control_room",
            "zone5": "wind_turbine",
        }

    # ------------------------------------------------------------------ #
    # Internal builder
    # ------------------------------------------------------------------ #

    def _add_rule(
        self,
        src: str,
        dst: str,
        action: str,
        protocol: str = "unknown",
        port: Optional[str] = None,
        description: Optional[str] = None,
    ):
        src_clean = _slug(src).replace("_", "").replace("-", "")
        dst_clean = _slug(dst).replace("_", "").replace("-", "")
        
        src_mapped = self.zone_mapping.get(src_clean, src)
        dst_mapped = self.zone_mapping.get(dst_clean, dst)
        
        src_slug   = _slug(src_mapped)
        dst_slug   = _slug(dst_mapped)
        action_n   = action.lower().strip()
        protocol_n = _enrich_protocol(protocol, port)

        if not src_slug or not dst_slug:
            return

        rule = {
            "src":         src_slug,
            "dst":         dst_slug,
            "src_raw":     src_mapped,
            "dst_raw":     dst_mapped,
            "action":      action_n,
            "protocol":    protocol_n,
            "port":        str(port) if port else None,
            "description": description or f"{action_n} {src_mapped} -> {dst_mapped} [{protocol_n}]",
        }
        self.rules.append(rule)

        if action_n in _ALLOW_VERDICTS:
            self.allowed_pairs.add((src_slug, dst_slug))

    # ------------------------------------------------------------------ #
    # Format-specific parsers
    # ------------------------------------------------------------------ #

    def parse_dict(self, data: Any) -> bool:
        if isinstance(data, dict):
            # Check for custom zone mappings in the JSON config (Problem 6)
            custom_map = data.get("zone_mapping", data.get("mappings", data.get("aliases", {})))
            if isinstance(custom_map, dict):
                for k, v in custom_map.items():
                    k_clean = _slug(k).replace("_", "").replace("-", "")
                    self.zone_mapping[k_clean] = str(v)
                    print(f"  [firewall_parser] Custom zone mapping loaded: {k_clean} -> {v}", flush=True)

            rules = data.get("rules", data.get("firewall_rules", data.get("policies", [])))
        elif isinstance(data, list):
            rules = data
        else:
            return False

        if not isinstance(rules, list):
            return False

        for rule in rules:
            if not isinstance(rule, dict):
                continue
            src      = _first(
                rule.get("src"), rule.get("source"), rule.get("from"),
                rule.get("source_zone"), rule.get("src_zone"),
                rule.get("source_asset"), rule.get("src_asset")
            )
            dst      = _first(
                rule.get("dst"), rule.get("destination"), rule.get("to"),
                rule.get("dest_zone"), rule.get("dst_zone"),
                rule.get("destination_zone"), rule.get("target"),
                rule.get("target_zone"), rule.get("destination_asset"),
                rule.get("dst_asset")
            )
            action   = _first(rule.get("action"), rule.get("verdict"), rule.get("decision")) or "allow"
            protocol = _first(rule.get("protocol"), rule.get("service"), rule.get("proto")) or "unknown"
            port     = _first(rule.get("port"), rule.get("dport"), rule.get("dst_port")) or None
            desc     = rule.get("description", rule.get("comment", None))

            if src and dst:
                self._add_rule(src, dst, action, protocol, port, desc)

        return len(self.rules) > 0

    def parse_json(self, content: str) -> bool:
        try:
            data = json.loads(content)
        except json.JSONDecodeError:
            return False
        return self.parse_dict(data)

    def parse_yaml(self, content: str) -> bool:
        """Parses YAML firewall rules using PyYAML or a regex fallback."""
        data = None
        try:
            import yaml
            data = yaml.safe_load(content)
        except Exception:
            data = self._parse_yaml_regex_fallback(content)
            
        if not data:
            return False
            
        return self.parse_dict(data)

    def _parse_yaml_regex_fallback(self, content: str) -> Optional[List[Dict]]:
        """Fallback block parser for YAML firewall rules."""
        rules = []
        # Split on items starting with "- "
        blocks = re.split(r'\n-\s+', '\n' + content)
        for block in blocks:
            if not block.strip() or block.strip().startswith("rules:"):
                continue
            
            src, dst, action, protocol, port = None, None, "deny", "unknown", None
            for line in block.splitlines():
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                
                m_src = re.search(r'\b(src|source|from|source_zone):\s*[\'"]?([\w_\-]+)[\'"]?', line)
                if m_src: src = m_src.group(2)
                
                m_dst = re.search(r'\b(dst|destination|to|dest_zone):\s*[\'"]?([\w_\-]+)[\'"]?', line)
                if m_dst: dst = m_dst.group(2)
                
                m_act = re.search(r'\b(action|verdict|decision):\s*[\'"]?([\w_\-]+)[\'"]?', line)
                if m_act: action = m_act.group(2)
                
                m_proto = re.search(r'\b(protocol|service|proto):\s*[\'"]?([\w_\-]+)[\'"]?', line)
                if m_proto: protocol = m_proto.group(2)
                
                m_port = re.search(r'\b(port|dport|dst_port):\s*[\'"]?(\d+)[\'"]?', line)
                if m_port: port = m_port.group(2)
                
            if src and dst:
                rules.append({
                    "src": src, "dst": dst, "action": action,
                    "protocol": protocol, "port": port
                })
        return rules if rules else None

    def parse_csv(self, content: str) -> bool:
        try:
            reader = csv.DictReader(io.StringIO(content))
            parsed = False
            for row in reader:
                r = {k.strip().lower(): (v or "").strip() for k, v in row.items() if k}

                src      = _first(r.get("src"), r.get("source"), r.get("from"))
                dst      = _first(r.get("dst"), r.get("destination"), r.get("to"))
                action   = _first(r.get("action"), r.get("verdict"), r.get("decision")) or "deny"
                protocol = _first(r.get("protocol"), r.get("service"), r.get("proto")) or "unknown"
                port     = r.get("port", r.get("dport", None)) or None

                if src and dst:
                    self._add_rule(src, dst, action, protocol, port)
                    parsed = True
            return parsed
        except Exception:
            return False

    def parse_plaintext(self, content: str) -> bool:
        """
        Handles plain-text firewall rules including:
          - "allow from zone_a to zone_b on port 502 via Modbus"
          - "deny zone_vendor_control -> zone_turbine"
          - iptables:  "-A FORWARD -s SRC -d DST --dport 502 -j ACCEPT"
          - "Zone_A -> Zone_B : allowed (VPN/OPC-UA)"
        """
        parsed = False

        # Pattern A: (allow|deny) from? SRC to DST [on port P] [via PROTO]
        pA = re.compile(
            r"(allow|deny|permit|block|drop|accept|reject)\s+(?:from\s+)?([\w\-\.]+)\s+"
            r"(?:to\s+|->\s*)([\w\-\.]+)"
            r"(?:\s+(?:on\s+)?port\s+(\d+))?"
            r"(?:\s+(?:via|using|protocol|proto)\s+([\w\-/]+))?",
            re.IGNORECASE,
        )

        # Pattern B: iptables FORWARD rule
        pB = re.compile(
            r"-A\s+\w+\s+.*?-s\s+([\w\./\-]+).*?-d\s+([\w\./\-]+).*?"
            r"(?:--dport\s+(\d+))?\s*-j\s+(ACCEPT|DROP|REJECT|RETURN)",
            re.IGNORECASE,
        )

        # Pattern C: "SRC -> DST : allow (Protocol)"
        pC = re.compile(
            r"([\w\-_]+)\s*->\s*([\w\-_]+)\s*:\s*(allow\w*|deny\w*|permit\w*|block\w*|drop\w*)"
            r"(?:\s*\(([^)]+)\))?",
            re.IGNORECASE,
        )

        for line in content.splitlines():
            line = line.strip()
            if not line or line.startswith("#") or line.startswith("//"):
                continue

            m = pA.search(line)
            if m:
                action, src, dst, port, proto = m.groups()
                self._add_rule(src, dst, action, proto or "unknown", port)
                parsed = True
                continue

            m = pB.search(line)
            if m:
                src, dst, port, action = m.groups()
                verdict = "allow" if action.upper() == "ACCEPT" else "deny"
                self._add_rule(src, dst, verdict, "unknown", port)
                parsed = True
                continue

            m = pC.search(line)
            if m:
                src, dst, action, proto_desc = m.groups()
                self._add_rule(src, dst, action, proto_desc or "unknown")
                parsed = True

        return parsed

    # ------------------------------------------------------------------ #
    # Public API
    # ------------------------------------------------------------------ #

    def parse(self, content: str) -> "FirewallParser":
        """Auto-detect format and parse firewall rules."""
        if not content or not content.strip():
            return self

        content = content.strip()

        # JSON
        if content.startswith("{") or content.startswith("["):
            if self.parse_json(content):
                pass
            else:
                self.parse_plaintext(content)
        # YAML
        elif "rules:" in content or "firewall_rules:" in content or re.search(r'^\s*-\s+\w+:', content):
            if not self.parse_yaml(content):
                self.parse_plaintext(content)
        # CSV
        elif "," in content and "\n" in content:
            if not self.parse_csv(content):
                self.parse_plaintext(content)
        # Plain text
        else:
            self.parse_plaintext(content)

        print(f"  [firewall_parser] Parsed {len(self.rules)} rules, "
              f"{len(self.allowed_pairs)} allowed pairs", flush=True)
        for pair in sorted(self.allowed_pairs):
            print(f"    [allow] {pair[0]} -> {pair[1]}", flush=True)

        return self

    def is_allowed(self, src: str, dst: str) -> Optional[Dict]:
        """
        Check whether communication from src to dst is permitted.

        Returns the first matching ALLOW rule (with protocol metadata),
        or None if the connection is denied or has no matching rule.

        Matching strategy (in order):
          1. Exact slug match
          2. Prefix/substring match (zone-level wildcard rules)
          3. Token-prefix match — 'oem_scada_server' matches rule 'oem_scada'
        """
        src_s = _slug(src)
        dst_s = _slug(dst)

        for rule in self.rules:
            r_src = rule["src"]
            r_dst = rule["dst"]

            # 1. Exact match
            if r_src == src_s and r_dst == dst_s:
                if rule["action"] in _ALLOW_VERDICTS:
                    return rule
                return None

            # 2. Partial / prefix match (zone-level wildcard rules)
            prefix_match = (
                (src_s.startswith(r_src) or r_src.startswith(src_s)) and
                (dst_s.startswith(r_dst) or r_dst.startswith(dst_s))
            )
            if prefix_match:
                if rule["action"] in _ALLOW_VERDICTS:
                    return rule
                return None

            # 3. Token-prefix match: 'oem_scada_server' should match 'oem_scada'
            #    Split on underscore and check if rule tokens are a prefix of query tokens
            src_tokens = src_s.split("_")
            dst_tokens = dst_s.split("_")
            r_src_tokens = r_src.split("_")
            r_dst_tokens = r_dst.split("_")

            src_token_match = (
                src_tokens[:len(r_src_tokens)] == r_src_tokens or
                r_src_tokens[:len(src_tokens)] == src_tokens
            )
            dst_token_match = (
                dst_tokens[:len(r_dst_tokens)] == r_dst_tokens or
                r_dst_tokens[:len(dst_tokens)] == dst_tokens
            )

            if src_token_match and dst_token_match:
                if rule["action"] in _ALLOW_VERDICTS:
                    return rule
                return None

            # 4. Token subset match (any order, non-empty, non-generic)
            rule_src_set = set(r_src_tokens) - {""}
            rule_dst_set = set(r_dst_tokens) - {""}
            query_src_set = set(src_tokens) - {""}
            query_dst_set = set(dst_tokens) - {""}

            generic_terms = {"server", "host", "device", "zone", "network", "system"}
            
            src_ok = (rule_src_set.issubset(query_src_set) and not (rule_src_set <= generic_terms)) or \
                     (query_src_set.issubset(rule_src_set) and not (query_src_set <= generic_terms))
            dst_ok = (rule_dst_set.issubset(query_dst_set) and not (rule_dst_set <= generic_terms)) or \
                     (query_dst_set.issubset(rule_dst_set) and not (query_dst_set <= generic_terms))

            if src_ok and dst_ok:
                if rule["action"] in _ALLOW_VERDICTS:
                    return rule
                return None

        # No matching rule — default deny (fail-closed)
        return None

    def is_denied(self, src: str, dst: str) -> Optional[Dict]:
        """
        Check whether communication from src to dst is explicitly denied.

        Returns the first matching DENY rule,
        or None if the connection is allowed or has no matching rule.
        """
        src_s = _slug(src)
        dst_s = _slug(dst)

        for rule in self.rules:
            r_src = rule["src"]
            r_dst = rule["dst"]

            # 1. Exact match
            if r_src == src_s and r_dst == dst_s:
                if rule["action"] in _DENY_VERDICTS:
                    return rule
                return None

            # 2. Partial / prefix match (zone-level wildcard rules)
            prefix_match = (
                (src_s.startswith(r_src) or r_src.startswith(src_s)) and
                (dst_s.startswith(r_dst) or r_dst.startswith(dst_s))
            )
            if prefix_match:
                if rule["action"] in _DENY_VERDICTS:
                    return rule
                return None

            # 3. Token-prefix match: 'oem_scada_server' should match 'oem_scada'
            src_tokens = src_s.split("_")
            dst_tokens = dst_s.split("_")
            r_src_tokens = r_src.split("_")
            r_dst_tokens = r_dst.split("_")

            src_token_match = (
                src_tokens[:len(r_src_tokens)] == r_src_tokens or
                r_src_tokens[:len(src_tokens)] == src_tokens
            )
            dst_token_match = (
                dst_tokens[:len(r_dst_tokens)] == r_dst_tokens or
                r_dst_tokens[:len(dst_tokens)] == dst_tokens
            )

            if src_token_match and dst_token_match:
                if rule["action"] in _DENY_VERDICTS:
                    return rule
                return None

            # 4. Token subset match (any order, non-empty, non-generic)
            rule_src_set = set(r_src_tokens) - {""}
            rule_dst_set = set(r_dst_tokens) - {""}
            query_src_set = set(src_tokens) - {""}
            query_dst_set = set(dst_tokens) - {""}

            generic_terms = {"server", "host", "device", "zone", "network", "system"}
            
            src_ok = (rule_src_set.issubset(query_src_set) and not (rule_src_set <= generic_terms)) or \
                     (query_src_set.issubset(rule_src_set) and not (query_src_set <= generic_terms))
            dst_ok = (rule_dst_set.issubset(query_dst_set) and not (rule_dst_set <= generic_terms)) or \
                     (query_dst_set.issubset(rule_dst_set) and not (query_dst_set <= generic_terms))

            if src_ok and dst_ok:
                if rule["action"] in _DENY_VERDICTS:
                    return rule
                return None

        return None

    def to_dict(self) -> Dict:
        return {
            "rules":         self.rules,
            "allowed_count": len(self.allowed_pairs),
            "allowed_pairs": [{"src": s, "dst": d} for s, d in sorted(self.allowed_pairs)],
        }


# ---------------------------------------------------------------------------
# Convenience entry point
# ---------------------------------------------------------------------------

def parse_firewall(content: str) -> Dict:
    """Parse a firewall rules file and return structured connectivity constraints."""
    return FirewallParser().parse(content).to_dict()
