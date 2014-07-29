import unittest

from repoguard.ruleparser import RuleLoader
from repoguard.ruleparser import merge_rules
from repoguard.ruleparser import merge_many_rules
from repoguard.ruleparser import resolve_rule

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


class RuleMergingTestCase(unittest.TestCase):
	
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


class RuleInheritanceTestCase(unittest.TestCase):

	def setUp(self):
		self.rule_0 = {"extends": "base", "diff": "add"}
		self.rule_1 = {"extends": "ns1::base", "line": [{"match": "system("}]}
		self.rule_2 = {"line": [{"match": "Popen("}]}
		self.rule_3 = {"extends": "ns1::foo", "file": [{"match": "*.py"}]}

	def test_no_inheritance(self):
		rule = resolve_rule("ns1::sys", {"ns1::sys": self.rule_2, "ns1::base": self.rule_2})

		self.assertIn("line", rule)
		self.assertEquals(1, len(rule))
		self.assertEquals(1, len(rule["line"]))

	def test_inheritance_with_ns(self):
		rule = resolve_rule("ns1::sys", {"ns1::sys": self.rule_1, "ns1::base": self.rule_2})

		self.assertIn("line", rule)
		self.assertEquals(2, len(rule)) #extends, line
		self.assertEquals(2, len(rule["line"]))

	def test_inheritance_with_implicit_ns(self):
		rule = resolve_rule("ns1::sys", {"ns1::sys": self.rule_0, "ns1::base": self.rule_2})

		self.assertIn("line", rule)
		self.assertEquals(3, len(rule)) #extends, line, diff
		self.assertEquals(1, len(rule["line"]))

	def test_circular_deps(self):
		with self.assertRaises(Exception):
			resolve_rule("ns1::foo", {"ns1::foo": self.rule_1, "ns1::base": self.rule_3})

	def test_inheritance_from_abstract_base(self):
		rule = resolve_rule("ns1::sys", {"ns1::sys": self.rule_0, "ns1::~base": self.rule_2})

		self.assertIn("line", rule)
		self.assertEquals(3, len(rule)) #extends, line, diff
		self.assertEquals(1, len(rule["line"]))
