"""
Quick test: runs MITREMapper on a synthetic ICS attack path
and prints the JSON output to the terminal.
"""
import sys
import os
sys.path.insert(0, os.path.dirname(__file__))

import json
import networkx as nx
from DAG.mitre_mapper import MITREMapper, GraphReachabilityValidator

# ── Build a minimal synthetic ICS graph ──────────────────────────────────────

class FakeICSGraph:
    def __init__(self):
        G = nx.DiGraph()

        # Nodes: (id, type, purdue_level, criticality, zone, category)
        nodes = [
            ("operator_workstation", {"type": "workstation", "purdue_level": "L3",
              "zone": "enterprise", "criticality": "normal",
              "node_category": "CYBER_ASSET", "security_role": "ENTRY_POINT"}),
            ("scada_server",         {"type": "scada",       "purdue_level": "L2",
              "zone": "control",    "criticality": "critical",
              "node_category": "CYBER_ASSET", "security_role": "PIVOT",
              "is_enforcement_point": False}),
            ("firewall",             {"type": "firewall",    "purdue_level": "L3",
              "zone": "dmz",        "criticality": "normal",
              "node_category": "CYBER_ASSET", "security_role": "PIVOT",
              "is_enforcement_point": True}),
            ("plc_unit_1",           {"type": "plc",         "purdue_level": "L1",
              "zone": "field",      "criticality": "critical",
              "node_category": "CYBER_ASSET", "security_role": "FINAL_TARGET"}),
        ]
        for nid, attrs in nodes:
            G.add_node(nid, **attrs)

        # Edges with edge_type
        G.add_edge("operator_workstation", "firewall",
                   edge_type="COMM_LINK", label="vpn",
                   is_boundary_crossing=True)
        G.add_edge("firewall", "scada_server",
                   edge_type="COMM_LINK", label="rdp",
                   is_boundary_crossing=True)
        G.add_edge("scada_server", "plc_unit_1",
                   edge_type="COMM_LINK", label="modbus",
                   is_boundary_crossing=False)
        G.add_edge("operator_workstation", "scada_server",
                   edge_type="HUMAN_PERM", label="admin_access",
                   is_boundary_crossing=True)

        self.asset_graph  = G
        self.entry_points = ["operator_workstation"]
        self.critical_assets = ["plc_unit_1"]


# ── Run the mapper ────────────────────────────────────────────────────────────

print("\n" + "=" * 70)
print("  MITRE MAPPER -- Terminal JSON Output Test")
print("=" * 70)

ics = FakeICSGraph()

# Use rule-based mode (no LLM API key needed) for instant results
mapper = MITREMapper(use_llm=False)

attack_paths = [
    ["operator_workstation", "firewall", "scada_server", "plc_unit_1"],
    ["operator_workstation", "scada_server", "plc_unit_1"],
]

for path in attack_paths:
    print(f"\n" + "-" * 70)
    print(f"  Running path: {' -> '.join(path)}")
    print("-" * 70)
    # This call internally prints the JSON block to terminal
    hops = mapper.map_attack_path(path, ics)

print("\n" + "=" * 70)
print(f"  Done. {len(attack_paths)} path(s) analyzed.")
print("=" * 70 + "\n")
