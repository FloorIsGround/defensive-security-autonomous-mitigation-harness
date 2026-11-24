"""DefSecAutMit reasoning plane (Phase 5).

Optional automated episodic investigation worker (`reasoner-d`), replaceable
model adapters, provenance-safe prompt assembly, and the synthetic
adaptive-vs-static benchmark harness described in the system design document
(Sections 6.5, 7.1, 7.2, 7.4, 7.5, and 9).

Everything in this package runs on the Python 3.12 standard library only.
"""

from defsec_reasoner.canonical import canonical_json, canonical_sha256_hex, sha256_hex
from defsec_reasoner.models import (
    ModelAdapter,
    ModelTurnResult,
    ProviderError,
    ScriptedMockAdapter,
    ToolCall,
)
from defsec_reasoner.rpc_client import ControlRpcClient, RpcError
from defsec_reasoner.wire import MAX_FRAME_BYTES, FrameError

__version__ = "0.1.0"

PROMPT_SCHEMA_VERSION = "defsec.reasoner.prompts.v1"

__all__ = [
    "PROMPT_SCHEMA_VERSION",
    "ControlRpcClient",
    "FrameError",
    "MAX_FRAME_BYTES",
    "ModelAdapter",
    "ModelTurnResult",
    "ProviderError",
    "RpcError",
    "ScriptedMockAdapter",
    "ToolCall",
    "canonical_json",
    "canonical_sha256_hex",
    "sha256_hex",
    "__version__",
]
