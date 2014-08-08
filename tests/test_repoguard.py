import sys
from mock import patch, Mock, call
from StringIO import StringIO

from base import BaseTestCase
from codechecker import CodeCheckerFactory, Alert, Rule


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
        rule1 = Rule("xxe::test", Mock(), {'description': 'descr1'})
        rule2 = Rule("xxe::simple", Mock(), {'description': 'descr2'})
        self.rg.checkResults = [
            Alert(rule1, "file", "repo", "1231commit", "line1"),
            Alert(rule2, "file", "repo", "1231commit", "line1"),
            Alert(rule1, "file", "repo", "1231commit", "line1")
        ]
        mock_notification = Mock()
        mocks[0].return_value = mock_notification

        self.rg.sendResults()

        self.assertEqual(4, mocks[0].call_count)
