import os
import sys
import traceback

from core.evaluators import LineEvalFactory
from core.ruleparser import load_rules

rules_dir = os.environ.get('REPOGUARD_RULES','rules')
bare_rules = load_rules(rules_dir)

testable_rules = {rn: rule for rn, rule in bare_rules.iteritems() if 'tests' in rule}

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
                errors.append(('F', name, test_string))
    except:
        errors.append(('E', name, traceback.format_exc()))
        sys.stdout.write('E')

print
if errors:
    print
    for error in errors:
        print error[0], error[1]
        print error[2], '\n\n'
    exit(1)
else:
    exit(0)
