import unittest
from mock import patch

from core.repository_handler import Repository, RepositoryHandler


class RepositoryTestCase(unittest.TestCase):
    def setUp(self):
        self.repo_data = {"ssh_url": "git@github.com:prezi/repo1.git", "name": "test_repo", "language": "Python"}
        self.repo = Repository("repo_id", self.repo_data, "working_directory")

    def test_add_status_info_from_json(self):
        status_info = {}
        status_info["last_checked_commit_hashes"] = ["aaaaa", "bbbbb"]
        self.repo.addStatusInfoFromJson(status_info)
        self.assertEquals(self.repo.last_checked_commit_hashes, status_info["last_checked_commit_hashes"])

    def test_add_commit_hash_to_checked_only_if_not_yet_there(self):
        self.assertEquals(len(self.repo.last_checked_commit_hashes), 0)
        self.repo.addCommitHashToChecked("qqqqqqq")
        self.repo.addCommitHashToChecked("qqqqqqq")
        self.assertEquals(len(self.repo.last_checked_commit_hashes), 1)
        self.repo.addCommitHashToChecked("zzzzzzz")
        self.assertEquals(len(self.repo.last_checked_commit_hashes), 2)

    @patch('core.repository_handler.Repository.callCommand', side_effect=Exception())
    def test_get_last_commit_hashes(self, *mocks):
        self.assertEquals(self.repo.getLastCommitHashes(), [])
        self.assertTrue(mocks[0].called)

    @patch('core.repository_handler.Repository.getLastCommitHashes', return_value=["aaa", "bbb", "ccc"])
    @patch('core.repository_handler.Repository.getLastCheckedCommitHashes', return_value=["aaa"])
    @patch('core.repository_handler.Repository.getNotCheckedCommitHashes', return_value=["ccc"])
    def test_detect_new_commit_hashes(self, *mocks):
        original_length = len(self.repo.not_checked_commit_hashes)
        self.repo.detectNewCommitHashes()
        self.assertEquals(len(self.repo.not_checked_commit_hashes), original_length+1)
        self.assertTrue("bbb" in self.repo.not_checked_commit_hashes)


class RepositoryHandlerTestCase(unittest.TestCase):
    def setUp(self):
        pass

    @patch('core.repository_handler.RepositoryHandler.loadRepoListFromFile',
           return_value={"11111": {"ssh_url": "git@github.com:prezi/repo1.git", "name": "test_repo", "language": "Python"}})
    @patch('core.repository_handler.RepositoryHandler.loadRepoStatusFromFile',
           return_value={"11111": {"last_checked_hashes": ["aaaa"], "name": "test_repo"}})
    @patch('core.repository_handler.Repository')
    @patch('core.repository_handler.RepositoryHandler.getRepoById')
    def test_create_repo_list_and_status_from_files(self, *mocks):
        self.repository_handler = RepositoryHandler("test_work_dir")
        self.repository_handler.createRepoListAndStatusFromFiles()
        mocks[0].assert_called_with('11111', {'name': 'test_repo', 'language': 'Python', 'ssh_url': 'git@github.com:prezi/repo1.git'}, 'test_work_dir')
        pass
