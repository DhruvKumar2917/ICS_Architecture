import re


def clean_name(value):
    if value is None:
        return ""

    value = str(value)
    value = value.replace("\n", " ")
    value = re.sub(r"\s+", " ", value)
    return value.strip()


def guess_type(label):
    lower = label.lower()

    if "firewall" in lower:
        return "firewall"
    if "vpn" in lower:
        return "vpn"
    if "database" in lower or "db" in lower:
        return "database"
    if "server" in lower or "scada" in lower:
        return "server"
    if "plc" in lower:
        return "plc"
    if "hmi" in lower:
        return "component"
    if "sensor" in lower or "actuator" in lower:
        return "component"
    if "internet" in lower or "wan" in lower:
        return "network"
    if "domain" in lower or "zone" in lower or "control room" in lower:
        return "zone"
    if "admin" in lower or "user" in lower or "vendor" in lower:
        return "user"

    return "component"


def build_graph_from_edges(edge_rows):
    nodes = []
    edges = []
    node_map = {}

    def add_node(label):
        label = clean_name(label)
        if not label:
            return None

        if label not in node_map:
            node_id = f"n{len(node_map) + 1}"
            node_map[label] = node_id
            nodes.append({
                "id": node_id,
                "label": label,
                "type": guess_type(label)
            })

        return node_map[label]

    for row in edge_rows:
        source = clean_name(row.get("source", ""))
        target = clean_name(row.get("target", ""))
        label = clean_name(row.get("label", "connects"))

        if not source or not target:
            continue

        source_id = add_node(source)
        target_id = add_node(target)

        if source_id and target_id:
            edges.append({
                "id": f"e{len(edges) + 1}",
                "source": source_id,
                "target": target_id,
                "label": label
            })

    return {
        "nodes": nodes,
        "edges": edges
    }


def text_to_graph(text):
    text = clean_name(text)

    edge_rows = []

    patterns = [
        r"(.+?)\s+connects to\s+(.+?)(?:\.|$)",
        r"(.+?)\s*->\s*(.+?)(?:\.|$)",
        r"(.+?)\s*→\s*(.+?)(?:\.|$)",
    ]

    for pattern in patterns:
        matches = re.findall(pattern, text, flags=re.IGNORECASE)

        for source, target in matches:
            edge_rows.append({
                "source": clean_name(source),
                "target": clean_name(target),
                "label": "connects"
            })

    # domain/zone table extraction hints
    known_items = [
        "OEM domain",
        "Vendor domain",
        "Customer domain",
        "Wind-farm control room",
        "Turbine local control",
        "External transit",
        "OEM SCADA server",
        "PCN",
        "Vendor control room",
        "Customer control room",
        "Customer grid control server",
        "Wind-farm control room server",
        "Master HMI",
        "Slave HMI",
        "PLC",
        "Distributed I/O",
        "Sensors",
        "Actuators",
        "Internet",
        "Customer WAN",
        "VPN links",
    ]

    nodes = []
    node_map = {}

    def add_standalone_node(label):
        label = clean_name(label)
        if label and label.lower() in text.lower() and label not in node_map:
            node_id = f"n{len(node_map) + 1}"
            node_map[label] = node_id
            nodes.append({
                "id": node_id,
                "label": label,
                "type": guess_type(label)
            })

    if edge_rows:
        return build_graph_from_edges(edge_rows)

    for item in known_items:
        add_standalone_node(item)

    edges = []

    def add_edge(source, target, label):
        if source in node_map and target in node_map:
            edges.append({
                "id": f"e{len(edges) + 1}",
                "source": node_map[source],
                "target": node_map[target],
                "label": label
            })

    add_edge("Vendor domain", "OEM domain", "Vendor VPN over Internet")
    add_edge("Customer domain", "Wind-farm control room", "Customer WAN")
    add_edge("Wind-farm control room", "Turbine local control", "Control-room to field path")
    add_edge("External transit", "VPN links", "Transit connectivity")
    add_edge("OEM domain", "OEM SCADA server", "contains")
    add_edge("OEM domain", "PCN", "contains")
    add_edge("Turbine local control", "PLC", "contains")
    add_edge("Turbine local control", "Master HMI", "contains")
    add_edge("Turbine local control", "Slave HMI", "contains")
    add_edge("PLC", "Distributed I/O", "control")
    add_edge("Distributed I/O", "Sensors", "reads")
    add_edge("Distributed I/O", "Actuators", "controls")

    return {
        "nodes": nodes,
        "edges": edges
    }