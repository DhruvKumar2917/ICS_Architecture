class Graph:
    """
    Represents the entire graph with nodes and edges.
    """
    def __init__(self):
        self.nodes = set()
        self.edges = set()
        self._node_map = {}

    def add_node(self, node):
        self.nodes.add(node)
        self._node_map[node.id] = node

    def add_edge(self, edge):
        if edge.source in self.nodes and edge.target in self.nodes:
            self.edges.add(edge)
        else:
            raise ValueError("Edge connects non-existent nodes")

    def get_node(self, node_id):
        return self._node_map.get(node_id)

    def __repr__(self):
        return f"Graph(nodes={len(self.nodes)}, edges={len(self.edges)})"
