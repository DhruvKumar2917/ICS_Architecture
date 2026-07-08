import re

def _parse_purdue_to_tier(purdue_level_str):
    """Resilient parser for LLM Purdue level inconsistencies."""
    if not purdue_level_str:
        return None
        
    clean_str = str(purdue_level_str).lower()
    
    if "enterprise" in clean_str or "corporate" in clean_str: return 0
    if "dmz" in clean_str: return 2
    
    match = re.search(r'(?:level|l|purdue)\s*[-_]*\s*(\d+(?:\.\d+)?)', clean_str)
    if match:
        level_num = float(match.group(1))
        mapping = {5: 0, 4: 1, 3.5: 2, 3: 3, 2: 4, 1: 5, 0: 6}
        return mapping.get(level_num, None)
        
    return None
