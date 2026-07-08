class ICSException(Exception):
    """Base exception for all ICS Security Architecture analysis errors."""
    pass

class ParsingException(ICSException):
    """Raised when parsing fails."""
    pass

class GraphException(ICSException):
    """Raised when graph validation or building fails."""
    pass

class AnalysisException(ICSException):
    """Raised when security analysis fails."""
    pass
