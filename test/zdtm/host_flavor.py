"""
A host flavor test runs in the same set of namespaces as criu.
"""


class HostFlavor:
    def __init__(self, opts):
        self.name = "host"
        self.ns = False
        self.root = None

    def init(self, l_bins, x_bins):
        pass

    def fini(self):
        pass

    @staticmethod
    def clean():
        pass
