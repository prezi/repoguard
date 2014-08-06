import unittest
import os
from repoguard import RepoGuard


class BaseTestCase(unittest.TestCase):
    def setUp(self):
        self.rg = RepoGuard()
        self.test_data_folder = "%s/test_data/" % os.path.dirname(os.path.realpath(__file__))
