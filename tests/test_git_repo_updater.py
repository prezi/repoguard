#!/usr/bin/env python
import os
import unittest
from mock import patch
from httpretty import HTTPretty, httprettified

import git_repo_updater
import repoguard

APPDIR = "%s/" % os.path.dirname(os.path.realpath(__file__))


class GithubConnectionTestCase(unittest.TestCase):
    @patch('repoguard.git_repo_updater.GitRepoUpdater.parseSecretConfig')
    def setUp(self, *mocks):
        self.ra = repoguard.createInitializedRepoguardInstance()

        self.git_repo_updater_obj = repoguard.git_repo_updater.GitRepoUpdater(self.ra.SECRET_CONFIG_PATH, self.ra.REPO_LIST_PATH)
        self.ra.resetRepoLimits()

    @httprettified
    def test_fetch_repo_list_wrong_response_status(self):
        HTTPretty.register_uri(HTTPretty.GET, "https://api.github.com/orgs/prezi/repos",
                               body='Not found', status=404)
        self.git_repo_updater_obj.refreshRepoList()
        self.assertTrue(self.git_repo_updater_obj.stop)

    @httprettified
    def test_fetch_repo_list_one_site_only(self):
        HTTPretty.register_uri(HTTPretty.GET, "https://api.github.com/orgs/prezi/repos",
                               body=open(APPDIR+'test_data/test_response_01.json').read(), status=200)
        self.git_repo_updater_obj.refreshRepoList()
        self.assertEqual(len(self.git_repo_updater_obj.repo_list_cache), 2)

    @httprettified
    def test_fetch_repo_list_multiple_sites(self):
        self.git_repo_updater_obj.setToken('sdsadfdsadfadfadsfsdf')
        HTTPretty.register_uri(HTTPretty.GET, "https://api.github.com/orgs/prezi/repos",
                               responses=[
                                   HTTPretty.Response(
                                       body=open(APPDIR+'test_data/test_response_01.json').read(),
                                       status=200,
                                       link='<https://api.github.com/organizations/1989101/repos?access_token=sdsadfdsadfadfadsfsdf&page=2>; rel="next", <https://api.github.com/organizations/1989101/repos?access_token=sdsadfdsadfadfadsfsdf&page=3>; rel="last"'),
                                   HTTPretty.Response(
                                       body=open(APPDIR+'test_data/test_response_02.json').read(),
                                       status=200,
                                       link='<https://api.github.com/organizations/1989101/reposaccess_token=sdsadfdsadfadfadsfsdf&page=3>; rel="next", <https://api.github.com/organizations/1989101/reposaccess_token=sdsadfdsadfadfadsfsdf&page=3>; rel="last"'),
                                   HTTPretty.Response(
                                       body=open(APPDIR+'test_data/test_response_03.json').read(),
                                       status=200,
                                       link='<https://api.github.com/organizations/1989101/repos?access_token=sdsadfdsadfadfadsfsdf&page=3>; rel="last"'),
                               ])
        self.git_repo_updater_obj.refreshRepoList()
        self.assertEqual(len(self.git_repo_updater_obj.repo_list_cache), 6)

    @httprettified
    def test_fetch_repo_list_reached_ratelimit(self):
        HTTPretty.register_uri(HTTPretty.GET, "https://api.github.com/orgs/prezi/repos", body='Out of X-Rate-Limit',
                               X_RateLimit_Remaining='0', X_RateLimit_Limit='5000', status=200)
        self.git_repo_updater_obj.refreshRepoList()
        self.assertTrue(self.git_repo_updater_obj.stop)


def main():
    unittest.main()

if __name__ == '__main__':
    main()
