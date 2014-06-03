import argparse
import re

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

for fname in args.files:
	with open(fname) as f:
		content = f.readlines()
		print code_checker.check(content, fname)
