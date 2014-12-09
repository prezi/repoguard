import unittest

from mock import patch, Mock
from core.repository_handler import Repository, RepositoryHandler


class RepositoryTestCase(unittest.TestCase):
    def setUp(self):
        self.repo_data = {"url_with_token": "https://%s@github.com/prezi/repo1.git", "name": "test_repo", "language": "Python", "private": True, "fork": False}
        self.repo = Repository("repo_id", self.repo_data, "working_directory", logger=Mock())

    def test_add_status_info_from_json(self):
        status_info = {"last_checked_commit_hashes": ["aaaaa", "bbbbb"]}
        self.repo.add_status_info_from_json(status_info)
        self.assertEquals(self.repo.last_checked_commit_hashes, status_info["last_checked_commit_hashes"])

    def test_add_commit_hash_to_checked_only_if_not_yet_there(self):
        self.assertEquals(len(self.repo.last_checked_commit_hashes), 0)
        self.repo.add_commit_hash_to_checked("qqqqqqq")
        self.repo.add_commit_hash_to_checked("qqqqqqq")
        self.assertEquals(len(self.repo.last_checked_commit_hashes), 1)
        self.repo.add_commit_hash_to_checked("zzzzzzz")
        self.assertEquals(len(self.repo.last_checked_commit_hashes), 2)

    @patch('core.repository_handler.Repository.call_command', return_value=None)
    def test_get_last_commit_hashes(self, *mocks):
        self.assertEquals(self.repo.get_last_commit_hashes(), [])
        self.assertTrue(mocks[0].called)

    @patch('core.repository_handler.Repository.get_last_commit_hashes', return_value=["aaa", "bbb", "ccc"])
    @patch('core.repository_handler.Repository.get_last_checked_commit_hashes', return_value=["aaa"])
    @patch('core.repository_handler.Repository.get_not_checked_commit_hashes', return_value=["ccc"])
    def test_detect_new_commit_hashes(self, *mocks):
        original_length = len(self.repo.not_checked_commit_hashes)
        self.repo.detect_new_commit_hashes()
        self.assertEquals(len(self.repo.not_checked_commit_hashes), original_length+1)
        self.assertTrue("bbb" in self.repo.not_checked_commit_hashes)


class RepositoryHandlerTestCase(unittest.TestCase):
    def setUp(self):
        pass

    @patch('core.repository_handler.RepositoryHandler.load_repo_list_from_file',
           return_value={"11111": {"ssh_url": "git@github.com:prezi/repo1.git", "name":
                                   "test_repo", "language": "Python"}})
    @patch('core.repository_handler.RepositoryHandler.load_repo_status_from_file',
           return_value={"11111": {"last_checked_hashes": ["aaaa"], "name": "test_repo"}})
    @patch('core.repository_handler.Repository')
    def test_create_repo_list_and_status_from_files(self, *mocks):
        logger = Mock()
        self.repository_handler = RepositoryHandler("test_work_dir", logger=logger)
        self.repository_handler.create_repo_list_and_status_from_files()
        mocks[0].assert_called_with('11111', {'name': 'test_repo', 'language': 'Python',
                                              'ssh_url': 'git@github.com:prezi/repo1.git'}, 'test_work_dir', logger)
        pass
