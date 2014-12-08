from mock import patch, Mock
from base import BaseTestCase

from core.codechecker import Alert, Rule


class RepoguardTestCase(BaseTestCase):
    def setUp(self):
        super(RepoguardTestCase, self).setUp()

    def test_should_skip_by_name_with_limits_arg(self):
        self.rg.args.limit = ['alice', 'bob']
        self.assertFalse(self.rg.should_skip_by_name('alice'))
        self.assertFalse(self.rg.should_skip_by_name('bob'))
        self.assertTrue(self.rg.should_skip_by_name('whatever_else'))

    def test_build_repo_groups(self):
        raw_repo_groups = {
            'skipped_repos': ['junk'],
            'not_a_list': {},
            'not_a_leaf': ['foo', '@skipped_repos']
        }
        expected_result = {'not_a_leaf': ['foo', '@skipped_repos'], 'skipped_repos': ['junk']}

        self.assertEquals(self.rg.build_repo_groups(raw_repo_groups), expected_result)


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

    @patch('core.notifier.EmailNotifier.create_notification')
    def test_send_alerts(self, *mocks):
        rule1 = Rule("xxe::test", Mock(), {'description': 'descr1'})
        rule2 = Rule("xxe::simple", Mock(), {'description': 'descr2'})
        repo = Mock()
        repo.name = "repo"
        repo.private = True
        repo.fork = False
        self.rg.check_results = [
            Alert(rule1, "file", repo, "1231commit", "line1", "author1", 'commit_descr1'),
            Alert(rule2, "file", repo, "1231commit", "line1", "author2", 'commit_descr1'),
            Alert(rule1, "file", repo, "1231commit", "line1", "author1", 'commit_descr1')
        ]
        mock_notification = Mock()
        mocks[0].return_value = mock_notification

        self.rg.send_results()

        self.assertEqual(4, mocks[0].call_count)
