import unittest
from mock import Mock

from repoguard.evaluators import LineEvalFactory

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