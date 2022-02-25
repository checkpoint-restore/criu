"""
A user namespace flavor test is the same as namespace flavor,
but it also includes user namespace.
"""
from __future__ import unicode_literals

import os

from .ns_flavor import NsFlavor


class UserNsFlavor(NsFlavor):
    def __init__(self, opts):
        NsFlavor.__init__(self, opts)
        self.name = "userns"
        self.uns = True

    def init(self, l_bins, x_bins):
        # To be able to create roots_yard in CRIU
        os.chmod(".", os.stat(".").st_mode | 0o077)
        NsFlavor.init(self, l_bins, x_bins)

    @staticmethod
    def clean():
        pass
