import argparse
import os
import os.path
import re
import sys

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

if not applied_alerts:
	print "No matching alers"
	sys.exit()

code_checker = CodeCheckerFactory(applied_alerts).create(LineEvalFactory.MODE_SINGLE)

textchars = ''.join(map(chr, [7,8,9,10,12,13,27] + range(0x20, 0x100)))
is_binary_string = lambda bytes: bool(bytes.translate(None, textchars))
for path in args.files:
	print "Checking " + path
	alerts = []
	if os.path.isdir(path):
		for root, subFolders, files in os.walk(path):
			print root
			for fname in files:
				fpath = root + "/" + fname
				if not os.path.islink(fpath):
					with open(fpath) as f:
						if is_binary_string(f.read(128)):
							continue
						else:
							f.seek(0)
						content = f.readlines()
						actual_alert = [(fpath, alert, line) for alert, line in code_checker.check(content, fname)]
						alerts.extend(actual_alert)
	else:
		with open(path) as f:
			content = f.readlines()
			actual_alert = [(path, alert, line) for alert, line in code_checker.check(content, fname)]
			alerts.extend(actual_alert)
	for fname, alert, line in alerts:
		print "%s\n%s\n%s\n\n" % (fname, alert, line.strip())


