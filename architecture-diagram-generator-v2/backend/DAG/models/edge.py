class Edge:
    """
    Represents a directed edge in the graph.
    """
    def __init__(self, source, target, label=None, protocol=None):
        self.source = source
        self.target = target
        self.label = label
        self.protocol = protocol

    def __repr__(self):
        return f"Edge({self.source.id} -> {self.target.id})"
