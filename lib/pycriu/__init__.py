import os
import sys

# Python 3.14 introduced changes that break some older protobuf C-extension
# builds shipped by certain distributions. If the user has not explicitly
# selected an implementation, default to the pure-Python backend to avoid
# import failures (e.g. "Metaclasses with custom tp_new are not supported").
#
# This is a temporary compatibility workaround and should be removed once
# protobuf packages fully support Python 3.14+.
if sys.version_info >= (3, 14):
    os.environ.setdefault("PROTOCOL_BUFFERS_PYTHON_IMPLEMENTATION", "python")

from . import rpc_pb2 as rpc
from . import images
from .criu import criu, CRIUExceptionExternal, CRIUException
from .criu import CR_DEFAULT_SERVICE_ADDRESS
from .version import __version__

__all__ = (
    "rpc",
    "images",
    "criu",
    "CRIUExceptionExternal",
    "CRIUException",
    "CR_DEFAULT_SERVICE_ADDRESS",
    "__version__",
)
