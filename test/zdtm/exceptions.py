"""
Exceptions thrown when something inside a ZDTM test goes wrong,
e.g. test doesn't start, criu returns with non zero code or
test checks fail.
"""
from builtins import str


class TestFailException(Exception):
    def __init__(self, step):
        self.step = step

    def __str__(self):
        return str(self.step)


class TestFailExpectedException(Exception):
    def __init__(self, cr_action):
        self.cr_action = cr_action
