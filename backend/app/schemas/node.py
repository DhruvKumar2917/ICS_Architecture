from pydantic import BaseModel
from typing import Optional, Dict, Any

class NodeSchema(BaseModel):
    id: str
    label: str
    type: str
    data: Optional[Dict[str, Any]] = None
