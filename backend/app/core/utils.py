import re
from typing import Any, Optional, Dict

def slugify(value: Any, prefix: str = "x") -> str:
    """Return a lowercase, snake_case, unique-safe identifier."""
    value = str(value or "").strip().lower()
    value = re.sub(r"[^a-z0-9]+", "_", value)
    value = re.sub(r"_+", "_", value).strip("_")
    return value or prefix

def safe_list(value: Any):
    return value if isinstance(value, list) else []
