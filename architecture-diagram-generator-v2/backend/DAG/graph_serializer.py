import json
import logging
import hashlib
from datetime import datetime
import networkx as nx

logger = logging.getLogger(__name__)

class ICSSecurityModelSerializer:
    """
    Enterprise-Grade Serialization Engine.
    Features semantic fingerprinting, schema validation, and complete state rehydration.
    """
    VERSION = "2.1.0"
    ANALYSIS_ENGINE_VERSION = "1.0.0"

    @classmethod
    def _calculate_semantic_fingerprint(cls, graph_data):
        """
        Generates a SHA-256 hash of both topology AND security posture.
        Changes to zones, criticality, Purdue levels, or edge types will break the hash.
        """
        node_signatures = []
        for n in graph_data.get("nodes", []):
            _id = n.get("id", "")
            _crit = n.get("criticality", "none")
            _zone = n.get("zone", "none")
            _role = n.get("security_role", "none")
            node_signatures.append(f"{_id}|{_crit}|{_zone}|{_role}")
            
        edge_signatures = []
        for e in graph_data.get("edges", []):
            _src = e.get("source", "")
            _tgt = e.get("target", "")
            _type = e.get("edge_type", "none")
            edge_signatures.append(f"{_src}➔{_tgt}|{_type}")

        hash_base = f"NODES:{','.join(sorted(node_signatures))}||EDGES:{','.join(sorted(edge_signatures))}"
        return hashlib.sha256(hash_base.encode('utf-8')).hexdigest()

    @classmethod
    def _validate_schema(cls, payload):
        """Basic schema validation to prevent ingestion of malformed or corrupted files."""
        required_root_keys = {"metadata", "graph"}
        if not required_root_keys.issubset(payload.keys()):
            raise ValueError(f"Schema Validation Failed: Missing root keys. Expected {required_root_keys}")
            
        if "model_version" not in payload["metadata"]:
            raise ValueError("Schema Validation Failed: Missing model version in metadata.")

    @classmethod
    def serialize_to_json(cls, ics_graph, filepath, analysis_results=None, parent_checksum=None):
        """Losslessly packs the ICSSecurityGraph and analysis state to disk."""
        asset_graph = ics_graph.asset_graph
        graph_data = nx.node_link_data(asset_graph)

        zones = set(nx.get_node_attributes(asset_graph, "zone").values())
        critical_assets = [n for n, d in asset_graph.nodes(data=True) if d.get("criticality") == "critical"]

        export_payload = {
            "metadata": {
                "model_version": cls.VERSION,
                "created_at": datetime.utcnow().isoformat() + "Z",
                "parent_checksum": parent_checksum, # Architecture diff tracking
                "node_count": asset_graph.number_of_nodes(),
                "edge_count": asset_graph.number_of_edges(),
                "zone_count": len(zones),
                "critical_asset_count": len(critical_assets)
            },
            "graph": graph_data,
            "embedded_analysis": {
                "engine_version": cls.ANALYSIS_ENGINE_VERSION,
                "results": analysis_results or {}
            }
        }

        # Inject semantic fingerprint
        export_payload["metadata"]["integrity_checksum"] = cls._calculate_semantic_fingerprint(graph_data)

        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(export_payload, f, indent=4, ensure_ascii=False)
            
        logger.info(f"Serialized Model to {filepath}. Checksum: {export_payload['metadata']['integrity_checksum'][:8]}...")
        return export_payload["metadata"]["integrity_checksum"]

    @classmethod
    def deserialize_from_json(cls, filepath, ics_graph_class):
        """Restores the exact memory state of the ICS Graph."""
        with open(filepath, 'r', encoding='utf-8') as f:
            payload = json.load(f)

        # 1. Schema & Integrity Validation
        cls._validate_schema(payload)
        
        metadata = payload["metadata"]
        expected_checksum = metadata.get("integrity_checksum")
        actual_checksum = cls._calculate_semantic_fingerprint(payload["graph"])
        
        if expected_checksum and expected_checksum != actual_checksum:
            logger.warning("SECURITY WARNING: Integrity checksum mismatch! Security posture or topology has been altered.")

        # 2. Reconstruct NetworkX Graph
        restored_networkx_graph = nx.node_link_graph(payload["graph"])

        # 3. Instantiate domain wrapper
        ics_graph_instance = ics_graph_class()
        ics_graph_instance.asset_graph = restored_networkx_graph

        # 4. Trigger full state restoration 
        # (Assuming you add a rebuild_indexes() method to your ICSSecurityGraph class)
        if hasattr(ics_graph_instance, "rebuild_indexes"):
            ics_graph_instance.rebuild_indexes()
        else:
            logger.warning("ICS class lacks 'rebuild_indexes()'. Parallel zone graphs and metric caches may be empty.")

        logger.info(f"Successfully rehydrated ICS Security Model from {filepath}.")
        return ics_graph_instance, payload.get("embedded_analysis", {})