from mock import patch
from httpretty import HTTPretty, httprettified

from core.git_repo_updater import GitRepoUpdater
from base import BaseTestCase


class GithubConnectionTestCase(BaseTestCase):

    def setUp(self, *mocks):
        super(GithubConnectionTestCase, self).setUp()

        repo_list_file = self.test_data_folder + 'test_repo_list.json'
        self.git_repo_updater_obj = GitRepoUpdater('some_org', 'foobar_token', repo_list_file, self.mock_logger)
        self.rg.skip_repo_list = []

    @httprettified
    def test_fetch_repo_list_wrong_response_status(self):
        HTTPretty.register_uri(HTTPretty.GET, "https://api.github.com/orgs/some_org/repos",
                               body='Not found', status=404)
        self.git_repo_updater_obj.refresh_repo_list()
        self.assertTrue(self.git_repo_updater_obj.stop)

    @httprettified
    def test_fetch_repo_list_one_site_only(self):
        HTTPretty.register_uri(HTTPretty.GET, "https://api.github.com/orgs/some_org/repos",
                               body=open(self.test_data_folder + 'test_response_01.json').read(), status=200)
        self.git_repo_updater_obj.refresh_repo_list()
        self.assertEqual(len(self.git_repo_updater_obj.repo_list_cache), 2)

    @httprettified
    def test_fetch_repo_list_multiple_sites(self):
        responses = [
            HTTPretty.Response(
                body=open(self.test_data_folder + 'test_response_01.json').read(),
                status=200,
                link='<https://api.github.com/organizations/1989101/repos?access_token=sdsadfdsadfadfadsfsdf&page=2>;'
                     ' rel="next", '
                     '<https://api.github.com/organizations/1989101/repos?access_token=sdsadfdsadfadfadsfsdf&page=3>; '
                     'rel="last"'),
            HTTPretty.Response(
                body=open(self.test_data_folder + 'test_response_02.json').read(),
                status=200,
                link='<https://api.github.com/organizations/1989101/reposaccess_token=sdsadfdsadfadfadsfsdf&page=3>; '
                     'rel="next", '
                     '<https://api.github.com/organizations/1989101/reposaccess_token=sdsadfdsadfadfadsfsdf&page=3>;'
                     ' rel="last"'),
            HTTPretty.Response(
                body=open(self.test_data_folder + 'test_response_03.json').read(),
                status=200,
                link='<https://api.github.com/organizations/1989101/repos?access_token=sdsadfdsadfadfadsfsdf&page=3>; '
                     'rel="last"'),
        ]
        HTTPretty.register_uri(HTTPretty.GET, "https://api.github.com/orgs/some_org/repos", responses=responses)
        self.git_repo_updater_obj.refresh_repo_list()
        self.assertEqual(len(self.git_repo_updater_obj.repo_list_cache), 6)

    @httprettified
    def test_fetch_repo_list_reached_ratelimit(self):
        HTTPretty.register_uri(HTTPretty.GET, "https://api.github.com/orgs/some_org/repos", body='Out of X-Rate-Limit',
                               X_RateLimit_Remaining='0', X_RateLimit_Limit='5000', status=200)
        self.git_repo_updater_obj.refresh_repo_list()
        self.assertTrue(self.git_repo_updater_obj.stop)
