import unittest
from mock import patch

from repoguard.ruleparser import ConfigParser

class LocalRepoTestCase(unittest.TestCase):
	def setUp(self):
		pass

	def test_finds_namespace_simple(self):
		cp = ConfigParser("test.yaml")
		self.assertEquals("test", cp._find_default_namespace())

	def test_finds_namespace_withpath(self):
		cp = ConfigParser("foo/bar/test.yaml")
		self.assertEquals("test", cp._find_default_namespace())
		self.assertEquals("test", cp.namespace)

	def test_parse_name(self):
		yaml = "#!foo\nbar:woo\n"
		cp = ConfigParser("test.yaml")

		self.assertEquals("test::foo", cp._get_key(yaml))

	def test_parse_name_with_space(self):
		yaml = "#! foo \nbar:woo\n"
		cp = ConfigParser("test.yaml")

		self.assertEquals("test::foo", cp._get_key(yaml))

	def test_parse_without_name(self):
		yaml = "bar:woo\n"
		cp = ConfigParser("test.yaml")

		self.assertEquals("test::gen1", cp._get_key(yaml))