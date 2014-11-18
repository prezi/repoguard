import unittest

from core.evaluators import LineEvalFactory, FileEvalFactory


class LineEvaluatorTestCase(unittest.TestCase):

    def setUp(self):
        self.rule = {
            "line": [
                {"match": "hello"},
                {"except": "world"}
            ]
        }

    def test_has_key(self):
        lef = LineEvalFactory(mode=LineEvalFactory.MODE_DIFF)
        evaluator = lef.create(self.rule)

        self.assertEquals("line", evaluator.key)

    def test_diff_add(self):
        lines = [
            "  hello world",
            "+ hello world",
            "+ hello foobar",
            "  have a nice day"
        ]
        self.rule["diff"] = "add"

        lef = LineEvalFactory(mode=LineEvalFactory.MODE_DIFF)
        evaluator = lef.create(self.rule)

        self.assertFalse(evaluator.matches({}, lines[0]))
        self.assertFalse(evaluator.matches({}, lines[1]))
        self.assertTrue(evaluator.matches({}, lines[2]))
        self.assertFalse(evaluator.matches({}, lines[3]))

    def test_diff_del(self):
        lines = [
            "  hello world",
            "- hello world",
            "- hello foobar",
            "  have a nice day"
        ]
        self.rule["diff"] = "del"

        lef = LineEvalFactory(mode=LineEvalFactory.MODE_DIFF)
        evaluator = lef.create(self.rule)

        self.assertFalse(evaluator.matches({}, lines[0]))
        self.assertFalse(evaluator.matches({}, lines[1]))
        self.assertTrue(evaluator.matches({}, lines[2]))
        self.assertFalse(evaluator.matches({}, lines[3]))

    def test_diff_any(self):
        lines = [
            "  hello greeter",
            "+ hello greeter",
            "- hello greeter",
            "  hello world"
        ]

        lef = LineEvalFactory(mode=LineEvalFactory.MODE_DIFF)
        evaluator = lef.create(self.rule)

        self.assertTrue(evaluator.matches({}, lines[0]))
        self.assertTrue(evaluator.matches({}, lines[1]))
        self.assertTrue(evaluator.matches({}, lines[2]))
        self.assertFalse(evaluator.matches({}, lines[3]))

    def test_normal_del(self):
        lines = [
            "hello greeter",
            "hello world"
        ]
        self.rule["diff"] = "del"

        lef = LineEvalFactory(mode=LineEvalFactory.MODE_SINGLE)
        evaluator = lef.create(self.rule)

        self.assertFalse(evaluator.matches({}, lines[0]))
        self.assertFalse(evaluator.matches({}, lines[1]))

    def test_multisearch_criteria(self):
        lines = [
            "hello",
            "bello",
            "hello world"
        ]
        self.rule["line"].append({"match": "bello"})

        lef = LineEvalFactory(mode=LineEvalFactory.MODE_SINGLE)
        evaluator = lef.create(self.rule)

        self.assertTrue(evaluator.matches({}, lines[0]))
        self.assertTrue(evaluator.matches({}, lines[1]))
        self.assertFalse(evaluator.matches({}, lines[2]))


class FileEvaluatorTestCase(unittest.TestCase):

    def setUp(self):
        self.files = [
            "vuln.scala",
            "vuln.java",
            "test_vuln.scala",
            "Test_vuln.scala"
        ]
        self.rule = {
            "file": [
                {"match": ".+\\.scala"},
                {"match": ".+\\.java"},
                {"except": "test_.+"}
            ]
        }

    def test_multisearch_criteria(self):
        fef = FileEvalFactory()
        evaluator = fef.create(self.rule)

        self.assertTrue(evaluator.matches({"filename": self.files[0]}, None))
        self.assertTrue(evaluator.matches({"filename": self.files[1]}, None))
        self.assertFalse(evaluator.matches({"filename": self.files[2]}, None))

    def test_case_sensitivity(self):
        self.rule["case_sensitive"] = True
        fef = FileEvalFactory()
        evaluator = fef.create(self.rule)
        self.assertFalse(evaluator.matches({"filename": self.files[2]}, None))
        self.assertTrue(evaluator.matches({"filename": self.files[3]}, None))

    def test_no_file_rule_provided(self):
        self.rule = {
            "line": [
                {"match": ".*"}
            ]
        }
        fef = FileEvalFactory()
        evaluator = fef.create(self.rule)
        self.assertEquals(evaluator, None)
