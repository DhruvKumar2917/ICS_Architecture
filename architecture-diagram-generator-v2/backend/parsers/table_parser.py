import pandas as pd
from parsers.text_parser import build_graph_from_edges, clean_name


def table_to_graph(path: str):
    """
    Expected table columns:
    Source, Destination
    Optional: Type, Label, Protocol, Zone

    Example:
    Source,Destination,Protocol
    Firewall,Web Server,HTTPS
    Web Server,Database,SQL
    """

    if path.lower().endswith(".csv"):
        df = pd.read_csv(path)
    else:
        df = pd.read_excel(path)

    columns = {c.lower().strip(): c for c in df.columns}

    source_col = None
    target_col = None

    for possible in ["source", "from", "src"]:
        if possible in columns:
            source_col = columns[possible]

    for possible in ["destination", "target", "to", "dst"]:
        if possible in columns:
            target_col = columns[possible]

    if not source_col or not target_col:
        return {
            "nodes": [],
            "edges": [],
            "error": "Table must contain Source and Destination columns"
        }

    edge_pairs = []

    for _, row in df.iterrows():
        source = clean_name(str(row[source_col]))
        target = clean_name(str(row[target_col]))

        if source and target and source.lower() != "nan" and target.lower() != "nan":
            edge_pairs.append((source, target))

    graph = build_graph_from_edges(edge_pairs)

    # Add edge label from protocol/type/label if available
    label_col = None
    for possible in ["label", "type", "protocol"]:
        if possible in columns:
            label_col = columns[possible]
            break

    if label_col:
        for i, (_, row) in enumerate(df.iterrows()):
            if i < len(graph["edges"]):
                graph["edges"][i]["label"] = str(row[label_col])

    return graph
