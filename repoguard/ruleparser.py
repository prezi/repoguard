import copy
import sys
import yaml

class RuleLoader:
	file_name = None
	namespace = None
	autoincr_base = 0

	def __init__(self, file_name):
		self.file_name = file_name
		self.namespace = self._find_default_namespace()

	def load(self):
		with open(self.file_name) as f:
			content = f.read()
			return {self._get_key(c): yaml.load(c) for c in content.split('---') if len(c) > 0}

	def _find_default_namespace(self):
		dpos = self.file_name.rfind("/")
		if dpos < 0:
			dpos = 0
		else:
			dpos += 1
		ppos = self.file_name.rfind(".")
		if ppos < 0:
			ppos = len(self.file_name)

		return self.file_name[dpos:ppos]

	def _get_key(self, document):
		d = document.lstrip()
		if d.startswith("#!"):
			end = d.find("\n")
			return "%s::%s" % (self.namespace, d[2:end].strip())
		else:
			self.autoincr_base += 1
			return "%s::gen%d" % (self.namespace, self.autoincr_base) 


## Helper method to load configs in a dir:
def load_rules(rule_dir):
	from os import listdir
	from os.path import isfile, join
	rule_files = [join(rule_dir, f) for f in listdir(rule_dir) if isfile(join(rule_dir,f)) and f.endswith(".yml")]
	rules = {}
	for rf in rule_files:
		try:
			rules.update(RuleLoader(rf).load())
		except Exception as e:
			raise Exception("Error parsing file %s" % rf), None, sys.exc_info()[2]
	return rules

## Resolves rule hierarchy, and omits abstract rules
def build_resolved_ruleset(rules):
	return {name: resolve_rule(name, rules) for name in rules if not _is_abstract(name)}

def _is_abstract(rule_name):
	ns, name = rule_name.split("::")
	return name.startswith("~")

## Resolves a rule
def resolve_rule(rule_name, ruleset, in_progress=()):
	if rule_name not in ruleset:
		raise Exception("Unknown rule: %s", rule_name)
	if rule_name in in_progress:
		raise Exception("Circular depencencies found: %s -> %s" % (" -> ".join(in_progress), rule_name))
	rule_specs = ruleset[rule_name]
	namespace, localname = rule_name.split("::")
	if "extends" in rule_specs:
		base_rule_names = [b.strip() for b in rule_specs["extends"].split(",")]
		base_rule_fqdns = ["%s::%s" % (namespace, rn) if "::" not in rn else rn for rn in base_rule_names]
		base_rules = [resolve_rule(rname, ruleset, in_progress + (rule_name,)) for rname in base_rule_fqdns]
		return merge_many_rules(rule_specs, base_rules)
	else:
		return rule_specs

def merge_many_rules(target, sources):
	rule = copy.deepcopy(target)
	for base_rule in sources:
		merge_rules(rule, base_rule)
	return rule

def merge_rules(target, source):
	if isinstance(source, dict):
		for k, v in source.iteritems():
			if isinstance(target, dict) and k not in target:
				target[k] = v
			elif isinstance(target, list) and {k: v} not in target:
				target.append({k: v})
			else:
				merge_rules(target[k], v)
	elif isinstance(source, list):
		for e in source:
			if e not in target:
				target.append(e)

