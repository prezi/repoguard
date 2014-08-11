import unittest

from core.notifier import EmailNotifier


class EmailNotifierTestCase(unittest.TestCase):

    def setUp(self):
        self.notifier = EmailNotifier(
            "from@from.prezi.com",
            "to@to.prezi.com",
            "subject",
            "message text")

    def test_init(self):
        self.assertEqual(self.notifier.mime_message["Subject"], "subject")
        self.assertEqual(self.notifier.mime_message["From"], "from@from.prezi.com")
        self.assertEqual(self.notifier.mime_message["To"], "to@to.prezi.com")

    def testCreateMimeMessage(self):
        self.notifier.create_mime_message("modified message text")
        self.assertEqual(
            self.notifier.mime_message.get_payload()[0].as_string(),
            'Content-Type: text/plain; charset="us-ascii"\nMIME-Version: 1.0\nContent-Transfer-Encoding: 7bit\n\nmessage text')
