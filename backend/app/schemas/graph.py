from pydantic import BaseModel
from typing import List
from app.schemas.node import NodeSchema
from app.schemas.edge import EdgeSchema

class GraphSchema(BaseModel):
    nodes: List[NodeSchema]
    edges: List[EdgeSchema]
