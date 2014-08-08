import sys
from mock import patch, Mock, call, MagicMock
from StringIO import StringIO

from base import BaseTestCase
from codechecker import CodeCheckerFactory


class LocalRepoTestCase(BaseTestCase):
    def setUp(self):
        super(LocalRepoTestCase, self).setUp()
        self.rg.resetRepoLimits()

    def test_search_repo_dir(self):
        dirlist = ['test_1234', 'test2_123', 'test_test', '0test_123', '.test_123456',
                   'test', 'test_other_12345', '12345']
        self.assertEqual(self.rg.searchRepoDir(dirlist, 'test', '1234'), 'test_1234')
        self.assertFalse(self.rg.searchRepoDir(dirlist, 'test2', '1234'))
        self.assertFalse(self.rg.searchRepoDir(dirlist, 'test', '12345'))
        self.assertFalse(self.rg.searchRepoDir(dirlist, 'test', '123456'))
        self.assertFalse(self.rg.searchRepoDir(dirlist, '', '12345'))
        self.assertEqual(self.rg.searchRepoDir(dirlist, 'test_other', '12345'), 'test_other_12345')

    @patch('subprocess.check_output', return_value='1163bec4351\nAAAAbec49999\n')
    def test_get_last_commit_hashes(self, *mocks):
        retVal = self.rg.getLastCommitHashes('123123', 'reponameABCD')
        self.assertEqual(mocks[0].call_args_list[0][0], (['git', 'rev-list', '--remotes', '--max-count=100'],))
        self.assertEqual(retVal, ['1163bec4351', 'AAAAbec49999'])

    def test_should_skip_due_name(self):
        rd = {}
        rd["name"] = "reponame"
        rd["language"] = "python"
        self.rg.resetRepoLimits()
        self.rg.setSkipRepoList(['a', 'reponame', 'b'])
        self.assertTrue(self.rg.shouldSkip(rd))

    def test_should_skip_due_name_false(self):
        rd = {}
        rd["name"] = "reponame"
        rd["language"] = "python"
        self.rg.resetRepoLimits()
        self.rg.setSkipRepoList(['notreponame'])
        self.assertFalse(self.rg.shouldSkip(rd))

    def test_get_new_hashes(self):
        self.rg.repoStatusNew["8742897"]["last_checked_hashes"] = ["d", "c", "b", "a"]
        self.rg.repoStatus["8742897"]["last_checked_hashes"] = ["b", "a"]
        ret_arr = self.rg.getNewHashes("8742897")
        self.assertEqual(ret_arr, ["d", "c"])

    @patch('repoguard.RepoGuard.shouldSkip', return_value=False)
    @patch('os.listdir', return_value=[])
    @patch('subprocess.check_output')
    @patch('repoguard.RepoGuard.updateRepoStatusById')
    def test_update_local_repos_no_prev_dirs(self, *mocks):
        self.rg.updateLocalRepos()
        # check if git clone is called as required everywhere
        self.assertEqual(mocks[1].call_args_list[0][0], ([u'git', u'clone', u'git@github.com:prezi/repo2.git', u'%srepo2_6125572' % self.rg.WORKING_DIR],))
        self.assertEqual(mocks[1].call_args_list[1][0], ([u'git', u'clone', u'git@github.com:prezi/repo1.git', u'%srepo1_7092651' % self.rg.WORKING_DIR],))
        self.assertEqual(mocks[1].call_args_list[2][0], ([u'git', u'clone', u'git@github.com:prezi/repo3.git', u'%srepo3_7271766' % self.rg.WORKING_DIR],))
        self.assertEqual(self.rg.repoStatus['6125572']['last_checked_hashes'], [])
        self.assertEqual(self.rg.repoStatus['7092651']['last_checked_hashes'], [])
        self.assertEqual(self.rg.repoStatus['7271766']['last_checked_hashes'], [])
        self.assertEqual(len(mocks[1].call_args_list), 3)

    @patch('os.listdir', return_value=[])
    @patch('subprocess.check_output')
    @patch('repoguard.RepoGuard.updateRepoStatusById')
    def test_update_local_repos_no_prev_dirs_skip_repo(self, *mocks):
        self.rg.setSkipRepoList(('repo1'))
        self.rg.updateLocalRepos()

        # check if git clone is called as required everywhere
        self.assertEqual(mocks[1].call_args_list[0][0], ([u'git', u'clone', u'git@github.com:prezi/repo2.git', u'%srepo2_6125572' % self.rg.WORKING_DIR],))
        self.assertEqual(mocks[1].call_args_list[1][0], ([u'git', u'clone', u'git@github.com:prezi/repo3.git', u'%srepo3_7271766' % self.rg.WORKING_DIR],))
        self.assertEqual(self.rg.repoStatus['6125572']['last_checked_hashes'], [])
        self.assertEqual(self.rg.repoStatus['7271766']['last_checked_hashes'], [])
        self.assertEqual(len(mocks[1].call_args_list), 2)

    @patch('repoguard.RepoGuard.shouldSkip', return_value=False)
    @patch('os.listdir', return_value=['repo1_7092651'])
    @patch('subprocess.check_output')
    @patch('repoguard.RepoGuard.updateRepoStatusById')
    def test_update_local_repos_both_clone_and_pull(self, *mocks):
        self.rg.updateLocalRepos()
        # check if git clones and pulls are called as required everywhere
        self.assertEqual(mocks[1].call_args_list[0][0], ([u'git', u'clone', u'git@github.com:prezi/repo2.git', u'%srepo2_6125572' % self.rg.WORKING_DIR],))
        self.assertEqual(mocks[1].call_args_list[1][0], ([u'git', u'pull'],))
        self.assertEqual(mocks[1].call_args_list[1][1], {'cwd': '%srepo1_7092651/' % self.rg.WORKING_DIR})
        self.assertEqual(mocks[1].call_args_list[2][0], ([u'git', u'clone', u'git@github.com:prezi/repo3.git', u'%srepo3_7271766' % self.rg.WORKING_DIR],))
        self.assertEqual(self.rg.repoStatus['6125572']['last_checked_hashes'], [])
        self.assertEqual(self.rg.repoStatus['7271766']['last_checked_hashes'], [])
        self.assertEqual(len(mocks[1].call_args_list), 3)

    @patch('os.listdir', return_value=['repo1_7092651', 'repo2_6125572', 'repo3_7271766'])
    @patch('repoguard.RepoGuard.shouldSkipByName', return_value=False)
    @patch('repository_handler.Repository.gitClone')
    @patch('repository_handler.Repository.gitResetToOldestHash')
    @patch('repository_handler.Repository.callCommand')
    def test_update_local_repos_only_pulls(self, *mocks):
        self.rg.updateLocalRepos()
        #self.assertEqual(mocks, '')
        self.assertTrue(mocks[0].called)
        self.assertTrue(mocks[1].called)
        self.assertFalse(mocks[2].called)


class CheckNewCodeTest(BaseTestCase):
    def setUp(self):
        super(CheckNewCodeTest, self).setUp()

        rules = {
            "test::file_modified": {
                "diff": "del",
                "line": [{"match": "^-- a/zuisite/my/views\\.py"}]
            },
            "test::function_modified": {
                "line": [{"match": "def settings_and_license"}],
                "description": "settings_and_license function modified"
            },
            "test::string_matches": {
                "diff": "add",
                "line": [{"match": "datetime\\.date\\.today\\(\\).*"}],
                "description": "datetime.date.today() called"
            }
        }
        self.rg.code_checker = CodeCheckerFactory(rules).create()
        self.rg.loadRepoListFromFile(self.test_data_folder + 'test_repo_list.json')
        self.rg.readRepoStatusFromFile(self.test_data_folder + 'test_repo_status.json')
        self.rg.resetRepoLimits()

    @patch('os.listdir', return_value=['aaaa-test', 'bbbb_test', '.444444_test3'])
    @patch('os.path.isdir', return_value=True)
    @patch('subprocess.check_output')
    def test_no_repo_dirs(self, *mocks):
        self.rg.checkNewCode()

        self.mock_logger.assert_call_with('skip aaaa-test (not repo directory)')
        self.mock_logger.assert_call_with('skip bbbb_test (not repo directory)')
        self.mock_logger.assert_call_with('skip .444444_test3 (not repo directory)')

    @patch('os.listdir', return_value=['newrepo_123456'])
    @patch('os.path.isdir', return_value=True)
    @patch('subprocess.check_output')
    def test_insert_new_repo(self, *mocks):
        self.rg.checkNewCode()
        self.assertIn('123456', self.rg.repoStatus)
        self.assertEqual(self.rg.repoStatus['123456']['last_checked_hashes'], [])

    @patch('subprocess.check_output')
    def test_check_by_rev_hash(self, *mocks):
        mocks[0].return_value = open(self.test_data_folder + 'test_git_show.txt', 'r').read()
        res = self.rg.checkByRevHash('de74d131fbcca4bacac02523ef8d45c1dc8e2bde', 'testdir', '123123')

        self.assertEqual(res[0].repo, 'testdir')
        self.assertEqual(res[0].commit, 'de74d131fbcca4bacac02523ef8d45c1dc8e2bde')
        self.assertEqual(res[0].line, '--- a/zuisite/my/views.py')
        self.assertEqual(res[0].filename, 'zuisite/feature_switches.py')
        self.assertEqual(res[0].rule.name, 'test::file_modified')

        self.assertEqual(res[1].repo, 'testdir')
        self.assertEqual(res[1].commit, 'de74d131fbcca4bacac02523ef8d45c1dc8e2bde')
        self.assertEqual(res[1].line, ' def settings_and_license(request, tab=None, group_id=None, grouplicense=False):')
        self.assertEqual(res[1].filename, 'zuisite/feature_switches.py')
        self.assertEqual(res[1].rule.name, 'test::function_modified')

        self.assertEqual(res[2].repo, 'testdir')
        self.assertEqual(res[2].commit, 'de74d131fbcca4bacac02523ef8d45c1dc8e2bde')
        self.assertEqual(res[2].line, '+                    "expired": True if group_license_expiry < datetime.date.today() else False,')
        self.assertEqual(res[2].filename, 'zuisite/feature_switches.py')
        self.assertEqual(res[2].rule.name, 'test::string_matches')

    @patch('subprocess.check_output', return_value='1163be000000\n')
    @patch('repoguard.RepoGuard.getNewHashes', return_value=['1163be000000'])
    @patch('repoguard.RepoGuard.checkByRevHash', return_value=['test_alert', 'test_path/test_file.py', '1163be000000', 'matching line ...'])
    def test_check_by_repo_id_with_new_hashes(self, *mocks):
        tres = self.rg.checkByRepoId('8742897', 'zuisite')
        self.assertEqual(tres, ['test_alert', 'test_path/test_file.py', '1163be000000', 'matching line ...'])

    @patch('subprocess.check_output', return_value='1163be000000\n')
    @patch('repoguard.RepoGuard.getNewHashes', return_value=[])
    @patch('repoguard.RepoGuard.checkByRevHash', return_value=['test_alert', 'test_path/test_file.py', '1163be000000', 'matching line ...'])
    def test_check_by_repo_id_without_new_hashes(self, *mocks):
        tres = self.rg.checkByRepoId('8742897', 'zuisite')
        self.assertEqual(tres, [])


class AlertSubscriptionTestCase(BaseTestCase):
    def setUp(self):
        super(AlertSubscriptionTestCase, self).setUp()

        self.rg.subscribers = {"xxe::simple": ["A", "B", "C"], "xxe::*": ["A", "D"]}

    def test_simple_match(self):
        users = self.rg.find_subscribed_users("xxe::simple")
        self.assertIn("A", users)
        self.assertIn("B", users)
        self.assertIn("C", users)
        self.assertIn("D", users)

    def test_limit_match(self):
        users = self.rg.find_subscribed_users("xxe::simplealert")
        self.assertIn("A", users)
        self.assertNotIn("B", users)
        self.assertNotIn("C", users)
        self.assertIn("D", users)

    @patch('notifier.EmailNotifier.create_notification')
    def test_send_alerts(self, *mocks):
        self.rg.checkResults = [
            ("xxe::test", "file", "1231commit", "line1", "repo"),
            ("xxe::simple", "file", "1231commit", "line1", "repo"),
            ("test::test", "file", "1231commit", "line1", "repo")
        ]
        mock_notification = Mock()
        mocks[0].return_value = mock_notification

        self.rg.sendResults()

        self.assertEqual(4, mocks[0].call_count)
