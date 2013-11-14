#!/usr/bin/env python
import os
import unittest
import repoguard
import sys
from mock import patch
from httpretty import HTTPretty,httprettified
from StringIO import StringIO

APPDIR = "%s/" % os.path.dirname(os.path.realpath(__file__))

class GithubConnectionTestCase(unittest.TestCase):
	def setUp(self):
		self.ra = repoguard.RepoAlerter()
		self.ra.resetRepoLimits()

	@httprettified
	def test_fetch_repo_list_wrong_response_status(self):
		HTTPretty.register_uri(HTTPretty.GET, "https://api.github.com/orgs/prezi/repos",
			body='Not found',
			status=404)
		self.ra.refreshRepoList()
		self.assertTrue(self.ra.stop)

	@httprettified
	def test_fetch_repo_list_one_site_only(self):
		HTTPretty.register_uri(HTTPretty.GET, "https://api.github.com/orgs/prezi/repos",
			body=open(APPDIR+'tests/test_response_01.json').read(),
			status=200)
		self.ra.refreshRepoList()
		self.assertEqual(len(self.ra.repoList), 2)

	@httprettified
	def test_fetch_repo_list_multiple_sites(self):
		self.ra.TOKEN = 'sdsadfdsadfadfadsfsdf'
		HTTPretty.register_uri(HTTPretty.GET, "https://api.github.com/orgs/prezi/repos",
			responses = [
				HTTPretty.Response(
					body=open(APPDIR+'tests/test_response_01.json').read(),
					status=200,
					link='<https://api.github.com/organizations/1989101/repos?access_token=sdsadfdsadfadfadsfsdf&page=2>; rel="next", <https://api.github.com/organizations/1989101/repos?access_token=sdsadfdsadfadfadsfsdf&page=3>; rel="last"'),
				HTTPretty.Response(
					body=open(APPDIR+'tests/test_response_02.json').read(),
					status=200,
					link='<https://api.github.com/organizations/1989101/reposaccess_token=sdsadfdsadfadfadsfsdf&page=3>; rel="next", <https://api.github.com/organizations/1989101/reposaccess_token=sdsadfdsadfadfadsfsdf&page=3>; rel="last"'),
				HTTPretty.Response(
					body=open(APPDIR+'tests/test_response_03.json').read(),
					status=200,
					link='<https://api.github.com/organizations/1989101/repos?access_token=sdsadfdsadfadfadsfsdf&page=3>; rel="last"'),
			])
		self.ra.refreshRepoList()
		self.assertEqual(len(self.ra.repoList), 6)

	@httprettified
	def test_fetch_repo_list_reached_ratelimit(self):
		HTTPretty.register_uri(HTTPretty.GET, "https://api.github.com/orgs/prezi/repos",
			body='Out of X-Rate-Limit',
			X_RateLimit_Remaining = '0',
			X_RateLimit_Limit = '5000',
			status=200)
		self.ra.refreshRepoList()
		self.assertTrue(self.ra.stop)


class LocalRepoTestCase(unittest.TestCase):
	def setUp(self):
		self.ra = repoguard.RepoAlerter()
		# patch test repo list
		self.ra.REPO_LIST_PATH=APPDIR+'tests/test_repo_list.json'
		self.ra.loadRepoListFromFile()
		self.ra.resetRepoLimits()

	def mock_os_listdir(self):
		return ['aaaaa','bbbbb','ccccc']

	def test_search_repo_dir(self):
		dirlist = ['test_1234', 'test2_123', 'test_test', '0test_123', '.test_123456', 'test', 'test_other_12345', '12345']
		self.assertEqual(self.ra.searchRepoDir(dirlist, 'test', '1234'), 'test_1234')
		self.assertFalse(self.ra.searchRepoDir(dirlist, 'test2', '1234'))
		self.assertFalse(self.ra.searchRepoDir(dirlist, 'test', '12345'))
		self.assertFalse(self.ra.searchRepoDir(dirlist, 'test', '123456'))
		self.assertFalse(self.ra.searchRepoDir(dirlist, '', '12345'))
		self.assertEqual(self.ra.searchRepoDir(dirlist, 'test_other', '12345'), 'test_other_12345')

	
	@patch('subprocess.check_output')
	def test_get_current_hash(self, *mocks):
		mocks[0].return_value = "commit 1163bec4351413be354f7c88317647815b2e9812\nAuthor: Attila Szabo <attila.szabo@prezi.com>\nDate:   Thu Mar 28 11:51:54 2013 +0100\n\n[workgroup] simplify expied condition"
		tres = self.ra.getCurrentHash('12345','fake_repo_name')
		self.assertEqual(mocks[0].call_args_list[0][1], {'cwd': '%s/fake_repo_name_12345/' % self.ra.WORKING_DIR})
		self.assertEqual(tres, '1163bec4351413be354f7c88317647815b2e9812')
		mocks[0].return_value = "fatal: Not a git repository (or any of the parent directories): .git\n"
		self.assertFalse(self.ra.getCurrentHash('12345','fake_repo_name'))

	#@patch('subprocess.check_output')
	#def test_get_hash_before(self, *mocks):
	#	mocks[0].return_value = "1163bec4351413be354f7c88317647815b2e9812"
	#	self.assertEqual(self.ra.getHashBefore('12345', 'fake_repo_name', '1 month ago'), "1163bec4351413be354f7c88317647815b2e9812")
	#	self.assertEqual(mocks[0].call_args_list[0][1], {'cwd': '%s/fake_repo_name_12345/' % self.ra.WORKING_DIR})
	#	mocks[0].return_value = ""
	#	self.assertFalse(self.ra.getHashBefore('12345', 'fake_repo_name', '1 month ago'))
	#	mocks[0].return_value = "fatal: ambiguous argument 'abcdef': unknown revision or path not in the working tree.\nsfdasfsdf"
	#	self.assertFalse(self.ra.getHashBefore('12345', 'fake_repo_name', '1 month ago'))

	@patch('os.listdir', return_value=[])
	@patch('subprocess.check_output')
	@patch('repoguard.RepoAlerter.getCurrentHash', return_value='1163bec4351413be354f7c88317647815b2e9812')
	def test_update_repos_no_prev_dirs(self, *mocks):
		self.ra.updateLocalRepos()
		# check if git clone is called as required everywhere
		self.assertEqual(mocks[1].call_args_list[0][0], ([u'git', u'clone', u'git@github.com:prezi/object-library-service.git', u'%s/object-library-service_6125572' % self.ra.WORKING_DIR],))
		self.assertEqual(mocks[1].call_args_list[1][0], ([u'git', u'clone', u'git@github.com:prezi/project-startup.git', u'%s/project-startup_7092651' % self.ra.WORKING_DIR],))
		self.assertEqual(mocks[1].call_args_list[2][0], ([u'git', u'clone', u'git@github.com:prezi/data-research.git', u'%s/data-research_7271766' % self.ra.WORKING_DIR],))
		self.assertEqual(self.ra.repoStatus['6125572']['last_hash'], '1163bec4351413be354f7c88317647815b2e9812')
		self.assertEqual(self.ra.repoStatus['7092651']['last_hash'], '1163bec4351413be354f7c88317647815b2e9812')
		self.assertEqual(self.ra.repoStatus['7271766']['last_hash'], '1163bec4351413be354f7c88317647815b2e9812')
		self.assertEqual(len(mocks[1].call_args_list), 3)

	@patch('os.listdir', return_value=[])
	@patch('subprocess.check_output')
	@patch('repoguard.RepoAlerter.getCurrentHash', return_value='1163bec4351413be354f7c88317647815b2e9812')
	def test_update_repos_no_prev_dirs_skip_repo(self, *mocks):
		self.ra.setSkipRepoList( ('project-startup') )
		self.ra.updateLocalRepos()
		# check if git clone is called as required everywhere
		self.assertEqual(mocks[1].call_args_list[0][0], ([u'git', u'clone', u'git@github.com:prezi/object-library-service.git', u'%s/object-library-service_6125572' % self.ra.WORKING_DIR],))
		self.assertEqual(mocks[1].call_args_list[1][0], ([u'git', u'clone', u'git@github.com:prezi/data-research.git', u'%s/data-research_7271766' % self.ra.WORKING_DIR],))
		self.assertEqual(self.ra.repoStatus['6125572']['last_hash'], '1163bec4351413be354f7c88317647815b2e9812')
		self.assertEqual(self.ra.repoStatus['7271766']['last_hash'], '1163bec4351413be354f7c88317647815b2e9812')
		self.assertEqual(len(mocks[1].call_args_list), 2)

	@patch('os.listdir', return_value=[])
	@patch('subprocess.check_output')
	@patch('repoguard.RepoAlerter.getCurrentHash', return_value='1163bec4351413be354f7c88317647815b2e9812')
	def test_update_repos_no_prev_dirs_limit_language(self, *mocks):
		self.ra.setTestRepoLanguages( ('python') )
		self.ra.updateLocalRepos()
		# check if git clone is called as required everywhere
		self.assertEqual(mocks[1].call_args_list[0][0], ([u'git', u'clone', u'git@github.com:prezi/object-library-service.git', u'%s/object-library-service_6125572' % self.ra.WORKING_DIR],))
		self.assertEqual(mocks[1].call_args_list[1][0], ([u'git', u'clone', u'git@github.com:prezi/project-startup.git', u'%s/project-startup_7092651' % self.ra.WORKING_DIR],))
		self.assertEqual(self.ra.repoStatus['6125572']['last_hash'], '1163bec4351413be354f7c88317647815b2e9812')
		self.assertEqual(self.ra.repoStatus['7092651']['last_hash'], '1163bec4351413be354f7c88317647815b2e9812')
		self.assertEqual(len(mocks[1].call_args_list), 2)


	@patch('os.listdir', return_value=['project-startup_7092651'])
	@patch('subprocess.check_output')
	@patch('repoguard.RepoAlerter.getCurrentHash', return_value='1163bec4351413be354f7c88317647815b2e9812')
	def test_update_repos_both_clone_and_pull(self, *mocks):
		self.ra.updateLocalRepos()
		# check if git clones and pulls are called as required everywhere
		self.assertEqual(mocks[1].call_args_list[0][0], ([u'git', u'clone', u'git@github.com:prezi/object-library-service.git', u'%s/object-library-service_6125572' % self.ra.WORKING_DIR],))
		self.assertEqual(mocks[1].call_args_list[1][0], ([u'git', u'pull'],))
		self.assertEqual(mocks[1].call_args_list[1][1], {'cwd': '%s/project-startup_7092651/' % self.ra.WORKING_DIR})
		self.assertEqual(mocks[1].call_args_list[2][0], ([u'git', u'clone', u'git@github.com:prezi/data-research.git', u'%s/data-research_7271766' % self.ra.WORKING_DIR],))
		self.assertEqual(self.ra.repoStatus['6125572']['last_hash'], '1163bec4351413be354f7c88317647815b2e9812')
		self.assertEqual(self.ra.repoStatus['7271766']['last_hash'], '1163bec4351413be354f7c88317647815b2e9812')
		self.assertEqual(len(mocks[1].call_args_list), 3)


	@patch('os.listdir', return_value=['project-startup_7092651', 'object-library-service_6125572', 'data-research_7271766'])
	@patch('subprocess.check_output')
	@patch('repoguard.RepoAlerter.getCurrentHash', return_value='1163bec4351413be354f7c88317647815b2e9812')
	def test_update_repos_only_pulls(self, *mocks):
		self.ra.updateLocalRepos()
		# check if git pull is called as required everywhere
		self.assertEqual(mocks[1].call_args_list[0][0], ([u'git', u'pull'],))
		self.assertEqual(mocks[1].call_args_list[0][1], {'cwd': '%s/object-library-service_6125572/' % self.ra.WORKING_DIR})
		self.assertEqual(mocks[1].call_args_list[1][0], ([u'git', u'pull'],))
		self.assertEqual(mocks[1].call_args_list[1][1], {'cwd': '%s/project-startup_7092651/' % self.ra.WORKING_DIR})
		self.assertEqual(mocks[1].call_args_list[2][0], ([u'git', u'pull'],))
		self.assertEqual(mocks[1].call_args_list[2][1], {'cwd': '%s/data-research_7271766/' % self.ra.WORKING_DIR})


class CheckNewCodeTest(unittest.TestCase):
	def setUp(self):
		self.ra = repoguard.RepoAlerter()
		self.ra.ALERT_CONFIG_PATH=APPDIR+'tests/test_alert_config.json'
		self.ra.readAlertConfigFromFile()
		self.ra.REPO_LIST_PATH=APPDIR+'tests/test_repo_list.json'
		self.ra.loadRepoListFromFile()
		self.ra.REPO_STATUS_PATH=APPDIR+'tests/test_repo_status.json'
		self.ra.readRepoStatusFromFile()
		self.ra.resetRepoLimits()
		self.output = StringIO()
		self.saved_stdout = sys.stdout
		sys.stdout = self.output

	def tearDown(self):
		self.output.close()
		sys.stdout = self.saved_stdout
	
	@patch('os.listdir', return_value=['aaaa-test', 'bbbb_test', '.444444_test3'])
	@patch('os.path.isdir', return_value=True)
	@patch('subprocess.check_output')
	@patch('repoguard.RepoAlerter.getCurrentHash', return_value='1163bec4351413be354f7c88317647815b2e9812')
	def test_no_repo_dirs(self, *mocks):
		self.ra.checkNewCode()
		self.assertEqual(self.output.getvalue(), "skip aaaa-test (not repo directory)\nskip bbbb_test (not repo directory)\nskip .444444_test3 (not repo directory)\n")

	@patch('os.listdir', return_value=['newrepo_123456'])
	@patch('os.path.isdir', return_value=True)
	@patch('subprocess.check_output')
	@patch('repoguard.RepoAlerter.getCurrentHash', return_value='1163bec4351413be354f7c88317647815b2e9812')
	def test_insert_new_repo(self, *mocks):
		self.ra.checkNewCode()
		self.assertIn('123456', self.ra.repoStatus)
		self.assertEqual(self.ra.repoStatus['123456']['last_hash'], '1163bec4351413be354f7c88317647815b2e9812')

	@patch('subprocess.check_output')
	def test_check_by_rev_hash(self, *mocks):
		mocks[0].return_value = open(APPDIR+'tests/test_git_show.txt','r').read()
		res = self.ra.checkByRevHash('de74d131fbcca4bacac02523ef8d45c1dc8e2bde', 'testdir', '123123')
		expected_res = [
			(	u'file_modified', 
				'/zuisite/my/views.py',
				'de74d131fbcca4bacac02523ef8d45c1dc8e2bde', 'diff --git a/zuisite/my/views.py b/zuisite/my/views.py', 'testdir', '123123'), 
			(	u'function_modified', 
				'/zuisite/my/views.py', 
				'de74d131fbcca4bacac02523ef8d45c1dc8e2bde', 
				' def settings_and_license(request, tab=None, group_id=None, grouplicense=False):', 'testdir', '123123'), 
			(	u'string_matches', 
				'/zuisite/my/views.py', 
				'de74d131fbcca4bacac02523ef8d45c1dc8e2bde', 
				'+                    "expired": True if group_license_expiry < datetime.date.today() else False,', 'testdir', '123123')
		]
		self.assertEqual(res, expected_res)

	@patch('subprocess.check_output', return_value='1163bec4351413be354f7c88317647815b000000\n')
	@patch('repoguard.RepoAlerter.checkByRevHash', return_value=['test_alert', 'test_path/test_file.py', '1163bec4351413be354f7c88317647815b000000', 'matching line ...'])
	def test_check_by_repo_id(self, *mocks):
		tres = self.ra.checkByRepoId('8742897','zuisite')
		self.assertEqual(mocks[1].call_args_list[0][0], (['git', 'rev-list', '--remotes', u'--since="2013-03-29 13:04:40"', 'HEAD'],))
		self.assertEqual(mocks[1].call_args_list[0][1], {'cwd': '%s/zuisite_8742897/' % self.ra.WORKING_DIR})
		self.assertEqual(tres, ['test_alert', 'test_path/test_file.py', '1163bec4351413be354f7c88317647815b000000', 'matching line ...'])

def main():
    unittest.main()

if __name__ == '__main__':
    main()