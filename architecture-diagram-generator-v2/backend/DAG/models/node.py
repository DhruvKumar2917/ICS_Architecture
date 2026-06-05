class Node:
    """
    Represents a node in the graph.
    """
    def __init__(self, id, label, type=None, criticality=None):
        self.id = id
        self.label = label
        self.type = type
        self.criticality = criticality

    def __repr__(self):
        return f"Node(id={self.id}, label='{self.label}')"

    def __eq__(self, other):
        return isinstance(other, Node) and self.id == other.id

    def __hash__(self):
        return hash(self.id)
