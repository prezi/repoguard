import argparse
import re
import os
import os.path

from codechecker import CodeCheckerFactory
from evaluators import LineEvalFactory
from ruleparser import load_rules, build_resolved_ruleset


parser = argparse.ArgumentParser(description='Check a sourcecode repo')
parser.add_argument('--rules','-r', default="etc/", help='Directory of rules')
parser.add_argument('--alerts', '-a', default=False, help='Limit running only the given alert checks (comma separated list)')
parser.add_argument('files', metavar='file', nargs='*', default=None, help='Files to check')
args = parser.parse_args()

bare_rules = load_rules(args.rules)
resolved_rules = build_resolved_ruleset(bare_rules)

# filter for items in --alerts parameter
enabled_alerts = [a.strip() for a in args.alerts.split(',')] if args.alerts else False
applied_alerts = {aid: adata for aid, adata 
	in resolved_rules.iteritems() 
	if not enabled_alerts or any(aid.startswith(ea) for ea in enabled_alerts)}
		
code_checker = CodeCheckerFactory(applied_alerts).create(LineEvalFactory.MODE_SINGLE)

alerts = []
for path in args.files:
	if os.path.isdir(path):
		for root, subFolders, files in os.walk(path):
			for fname in files:
				with open(root + "/" + fname) as f:
					content = f.readlines()
					actual_alert = [(fname, alert, line) for alert, line in code_checker.check(content, fname)]
					alerts.extend(actual_alert)
	else:
		with open(path) as f:
			content = f.readlines()
			alerts.extend(code_checker.check(content, path))

for fname, alert, line in alerts:
	print "%s\n%s\n%s\n\n" % (fname, alert, line.strip())


