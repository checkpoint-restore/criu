from .cg_freezer import get_freezer
from .criu_config import criu_config
from .exceptions import TestFailException, TestFailExpectedException
from .groups_test import GroupsTest
from .inherit_fd_test import InheritFdTest
from .utils import (
    decode_flav,
    encode_flav,
    flavors,
    get_test_desc,
    print_sep,
    test_flag,
    try_run_hook
)
from .zdtm import ZdtmTest

test_classes = {'zdtm': ZdtmTest, 'inhfd': InheritFdTest, 'groups': GroupsTest}

__all__ = [
    'criu_config',
    'get_freezer',
    'get_test_desc',
    'test_flag',
    'encode_flav',
    'decode_flav',
    'flavors',
    'try_run_hook',
    'print_sep',
    'test_classes',
    'TestFailException',
    'TestFailExpectedException',
]
