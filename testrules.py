#!/usr/bin/env python
# -*- coding: utf-8 -*-
import os
import sys
import traceback
import argparse

from core.evaluators import LineEvalFactory
from core.ruleparser import load_rules, build_resolved_ruleset


parser = argparse.ArgumentParser(description='Watch git repos for changes...')
parser.add_argument('--rule-dir', default='rules/', help='Path to the rule directory')
args = parser.parse_args()

bare_rules = load_rules(args.rule_dir)
resolved_rules = build_resolved_ruleset(bare_rules)

testable_rules = {rn: rule for rn, rule in resolved_rules.iteritems() if 'tests' in rule}

errors = []
line_eval_factory = LineEvalFactory(LineEvalFactory.MODE_SINGLE)
for name, rule in testable_rules.iteritems():
    try:
        evaluator = line_eval_factory.create(rule)
        tests = rule.get('tests', [])
        for test in tests:
            test_string = test.get('pass', test.get('fail', ''))
            expected = 'pass' in test
            actual = evaluator.matches({}, test_string)
            if expected == actual:
                sys.stdout.write('.')
            else:
                sys.stdout.write('F')
                errors.append(('F', 'Name: %s, Rules: %s' % (name, rule.get('line')),
                               'Actual: %s, Expected: %s, Test string: %s' % (actual, expected, test_string)))
    except:
        errors.append(('E', name, traceback.format_exc()))
        sys.stdout.write('E')

print
if errors:
    print
    for error in errors:
        print error[0], error[1]
        print error[2], '\n\n'
    print 'FAIL'
    exit(1)
else:
    print 'OK'
    exit(0)
