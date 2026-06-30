import sys, os
sys.path.append(os.path.dirname(os.path.realpath(__file__)))
from .magic import *
from .images import (load, loads, dump, dumps, info,
                     handlers, MagicException, entry_handler)
from .pb import *
