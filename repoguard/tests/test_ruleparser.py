import unittest
from mock import patch

from repoguard.ruleparser import RuleLoader
from repoguard.ruleparser import merge_rules, merge_many_rules

class RuleLoaderTestCase(unittest.TestCase):
	
	def setUp(self):
		pass

	def test_finds_namespace_simple(self):
		cp = RuleLoader("test.yaml")
		self.assertEquals("test", cp._find_default_namespace())

	def test_finds_namespace_withpath(self):
		cp = RuleLoader("foo/bar/test.yaml")
		self.assertEquals("test", cp._find_default_namespace())
		self.assertEquals("test", cp.namespace)

	def test_parse_name(self):
		yaml = "#!foo\nbar:woo\n"
		cp = RuleLoader("test.yaml")

		self.assertEquals("test::foo", cp._get_key(yaml))

	def test_parse_name_with_space(self):
		yaml = "#! foo \nbar:woo\n"
		cp = RuleLoader("test.yaml")

		self.assertEquals("test::foo", cp._get_key(yaml))

	def test_parse_without_name(self):
		yaml = "bar:woo\n"
		cp = RuleLoader("test.yaml")

		self.assertEquals("test::gen1", cp._get_key(yaml))


class RuleInheritanceTestCase(unittest.TestCase):
	
	def setUp(self):
		self.base = {"foo1": "bar", "foo2": {1:1, 2:2}, "foo3": [3, 4, 5], "foo4": [{1:2}, {2:3}]}

	def test_merge_rules_simple(self):
		simple = {"foo5": "bar"}

		merge_rules(self.base, simple)

		self.assertEquals(5, len(self.base))

	def test_merge_rules_first_wins(self):
		tt = {"foo1": "whee"}

		merge_rules(self.base, tt)

		self.assertEquals(4, len(self.base))
		self.assertEquals("bar", self.base["foo1"])

	def test_merge_rules_list(self):
		tt = {"foo3": {1:1}, "foo4": [6]}

		merge_rules(self.base, tt)

		self.assertEquals(4, len(self.base))
		self.assertIn({1:1}, self.base["foo3"])
		self.assertEquals(4, len(self.base["foo3"]))
		self.assertIn(6, self.base["foo4"])
		self.assertEquals(3, len(self.base["foo4"]))

	def test_merge_rules_dict(self):
		tt = {"foo2": {1:2, 3:3}}

		merge_rules(self.base, tt)

		self.assertEquals(3, len(self.base["foo2"]))
		self.assertIn(3, self.base["foo2"])
		self.assertEquals(1, self.base["foo2"][1]) # doesn't override

	def test_merge_many_rules(self):
		tt0 = {"foo1": "whee"}
		tt1 = {"foo2": {2:3, 3:4}}
		tt2 = {"foo3": [4,5,6]}

		res = merge_many_rules(self.base, [tt0, tt1, tt2])

		self.assertNotEqual(res, self.base)
		self.assertEquals("bar", res["foo1"])
		self.assertEquals(2, res["foo2"][2])
		self.assertEquals(4, res["foo2"][3])
		self.assertIn(6, res["foo3"])
		self.assertEquals(4, len(res["foo3"]))

	def test_merge_many_rules_first_wins(self):
		tt0 = {"foo2": {3:3}}
		tt1 = {"foo2": {3:4}}

		res = merge_many_rules(self.base, [tt0, tt1])

		self.assertEquals(3, res["foo2"][3])
