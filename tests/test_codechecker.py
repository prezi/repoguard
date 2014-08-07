import unittest
from mock import Mock

from codechecker import CodeChecker


class CodeCheckerTestCase(unittest.TestCase):

    def setUp(self):
        self.code = [
            "I have given suck, and know",
            "How tender 'tis to love the babe that milks me:",
            "I would, while it was smiling in my face,"
            "Have pluck'd my nipple from his boneless gums,"
            "And dash'd the brains out, had I so sworn as you",
            "Have done to this."
        ]

    def test_context_processors_called(self):
        context_processor = Mock()
        context_processor.preprocess = Mock(return_value={})
        code_checker = CodeChecker([context_processor], [])

        alerts = code_checker.check(self.code, "macbeth.txt")

        self.assertEquals(len(self.code), context_processor.preprocess.call_count)

    def test_evaluators_called(self):
        evaluator = Mock()
        evaluator.key = "line"
        evaluator.matches = Mock(return_value=False)
        rule = Mock()
        rule.name = "test"
        rule.evaluators = [evaluator]
        code_checker = CodeChecker([], [rule])

        alert = code_checker.check(self.code, "macbeth.txt")

        self.assertEquals(len(self.code), evaluator.matches.call_count)

    def test_filter_nonmatching_file_rules(self):
        file_evaluator = Mock()
        file_evaluator.key = "file"
        file_evaluator.matches = Mock(return_value=False)
        line_evaluator = Mock()
        line_evaluator.key = "line"
        line_evaluator.matches = Mock(return_value=False)
        rule = Mock()
        rule.name = "test"
        rule.evaluators = [file_evaluator, line_evaluator]
        code_checker = CodeChecker([], [rule])

        alert = code_checker.check(self.code, "macbeth.txt")

        self.assertEquals(1, file_evaluator.matches.call_count)
        self.assertEquals(0, line_evaluator.matches.call_count)

    def test_alert_format(self):
        line_evaluator = Mock()
        line_evaluator.key = "line"
        line_evaluator.matches = Mock(return_value=True)
        rule = Mock()
        rule.name = "test"
        rule.evaluators = [line_evaluator]
        code_checker = CodeChecker([], [rule])

        result = code_checker.check(self.code, "macbeth.txt")
        print repr(result[0])

        self.assertEquals(len(self.code), len(result))
        self.assertIn(self.code[0], result[0])

    '''
        Long lines are not readable, but very resource intensive to
        match regexes to. Don't parse lines longer than 512 characters,
        since they are usually auto-compressed and not readable anyways.
    '''
    def test_long_lines(self):
        line_evaluator = Mock()
        line_evaluator.key = "line"
        line_evaluator.matches = Mock(return_value=True)
        rule = Mock()
        rule.name = "test"
        rule.evaluators = [line_evaluator]
        code_checker = CodeChecker([], [rule])
        code = ["l0", "X"*513, "l2"]

        alerts = code_checker.check(code, "macbeth.txt")

        self.assertEquals(len(code) - 1, len(alerts))
