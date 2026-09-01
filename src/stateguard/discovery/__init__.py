"""Project discovery and Python/FastAPI Source Index services."""

from .files import ProjectDiscoveryError
from .service import (
    DiscoveryArtifacts,
    StaleSourceIndexError,
    discover_and_index_project,
    validate_indexed_source_snapshot,
)

__all__ = [
    "DiscoveryArtifacts",
    "ProjectDiscoveryError",
    "StaleSourceIndexError",
    "discover_and_index_project",
    "validate_indexed_source_snapshot",
]
