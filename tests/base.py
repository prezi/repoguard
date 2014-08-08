import unittest
import os
from mock import patch, MagicMock
from repoguard import RepoGuard


class BaseTestCase(unittest.TestCase):
    def setUp(self):
        self.mock_logger_patcher = patch('repoguard.logging.getLogger')
        self.mock_logger = self.mock_logger_patcher.start()

        self.rg = RepoGuard()
        self.rg.readConfig('%s/repoguard/etc/config.yml.template' % self.rg.APP_DIR)
        self.test_data_folder = "%s/test_data/" % os.path.dirname(os.path.realpath(__file__))
        self.rg.WORKING_DIRECTORY = self.test_data_folder
        self.rg.repositoryHandler = MagicMock()

    def tearDown(self):
        self.mock_logger_patcher.stop()
