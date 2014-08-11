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

    def test_multisearch_criteria(self):
        files = [
            "vuln.scala",
            "vuln.java",
            "test_vuln.scala"
        ]
        rule = {
            "file": [
                {"match": ".+\\.scala"},
                {"match": ".+\\.java"},
                {"except": "test_.+"}
            ]
        }

        fef = FileEvalFactory()
        evaluator = fef.create(rule)

        self.assertTrue(evaluator.matches({"filename": files[0]}, None))
        self.assertTrue(evaluator.matches({"filename": files[1]}, None))
        self.assertFalse(evaluator.matches({"filename": files[2]}, None))
