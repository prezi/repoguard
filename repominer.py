# !/usr/bin/env python
# -*- coding: utf-8 -*-
import argparse
import os
import os.path
import sys

from core.codechecker import CodeCheckerFactory, Alert
from core.evaluators import LineEvalFactory
from core.ruleparser import load_rules, build_resolved_ruleset
from core.datastore import DataStore, DataStoreException
import datetime


def check_alerts_in_file(code_checker, file, filename):
    content = file.readlines()
    result = code_checker.check(content, filename)
    actual_alerts = [Alert(rule, filename, '', '', line, None) for rule, line in result]
    return actual_alerts

parser = argparse.ArgumentParser(description='Check a sourcecode repo')
parser.add_argument('--rule-dir', default="rules/", help='Directory of rules')
parser.add_argument('--alerts', '-a', default=False,
                    help='Limit running only the given alert checks (comma separated list)')
parser.add_argument('--store', '-S', default=False, help='ElasticSearch node (host:port)')
parser.add_argument('files', metavar='file', nargs='*', default=None, help='Files to check')
args = parser.parse_args()

bare_rules = load_rules(args.rule_dir)
resolved_rules = build_resolved_ruleset(bare_rules)

# filter for items in --alerts parameter
enabled_alerts = [a.strip() for a in args.alerts.split(',')] if args.alerts else False
applied_alerts = {aid: adata for aid, adata in resolved_rules.iteritems()
                  if not enabled_alerts or any(aid.startswith(ea) for ea in enabled_alerts)}

if not applied_alerts:
    print "No matching alerts"
    sys.exit()
if not args.files:
    print "No files given."
    parser.print_help()
    sys.exit()

code_checker = CodeCheckerFactory(applied_alerts).create(LineEvalFactory.MODE_SINGLE)

textchars = ''.join(map(chr, [7, 8, 9, 10, 12, 13, 27] + range(0x20, 0x100)))
is_binary_string = lambda bytes: bool(bytes.translate(None, textchars))
for path in args.files:
    print "Checking " + path
    alerts = []
    if os.path.isdir(path):
        for root, subFolders, files in os.walk(path):
            for fname in files:
                fpath = os.path.join(root, fname)
                if not os.path.islink(fpath):
                    with open(fpath) as f:
                        if is_binary_string(f.read(128)):
                            continue
                        else:
                            f.seek(0)
                        alerts.extend(check_alerts_in_file(code_checker, f, fname))
    else:
        with open(path) as f:
            alerts.extend(check_alerts_in_file(code_checker, f, path))

    data_store = None
    if args.store:
        (host, port) = args.store.split(":")
        data_store = DataStore(host=host, port=port, default_doctype="repoguard", default_index="repoguard")

    for alert in alerts:
        print 'file:\t%s\nrule:\t%s\nline:\t%s\ndescr:\t%s\n' % (
            alert.filename, alert.rule.name,
            alert.line[0:200].strip().replace("\t", " ").decode('utf-8', 'replace'), alert.rule.description,
        )
        if args.store:
            try:
                body = {
                    "check_id": alert.rule.name,
                    "description": alert.rule.description,
                    "filename": alert.filename,
                    "commit_id": alert.commit,
                    "matching_line": alert.line[0:200].replace("\t", " ").decode('utf-8', 'replace'),
                    "repo_name": alert.repo,
                    "@timestamp": datetime.datetime.utcnow().isoformat(),
                    "type": "repoguard",
                    "false_positive": False,
                    "last_reviewer": "repoguard",
                    "author": alert.author,
                    "commit_description": alert.commit_description
                }

                data_store.store(body=body)
            except DataStoreException:
                print 'Got exception during storing results to ES.'
