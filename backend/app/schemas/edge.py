from pydantic import BaseModel
from typing import Optional, Dict, Any

class EdgeSchema(BaseModel):
    id: str
    source: str
    target: str
    label: str
    edge_type: str
    data: Optional[Dict[str, Any]] = None
