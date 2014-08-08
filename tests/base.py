import unittest
import os
from mock import patch, Mock
from repoguard import RepoGuard


class BaseTestCase(unittest.TestCase):
    def setUp(self):
        self.mock_logger_patcher = patch('repoguard.logging.getLogger')
        self.mock_logger = self.mock_logger_patcher.start()

        self.rg = RepoGuard()
        test_dir = os.path.dirname(os.path.realpath(__file__))
        print '%srepoguard/etc/config.yml.template' % self.rg.APP_DIR
        self.rg.readConfig('%s/repoguard/etc/config.yml.template' % self.rg.APP_DIR)
        self.test_data_folder = "%s/test_data/" % test_dir

    def tearDown(self):
        self.mock_logger_patcher.stop()
