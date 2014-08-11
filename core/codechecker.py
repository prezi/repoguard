from evaluators import *


class CodeChecker:

    def __init__(self, context_processors, rules):
        self.context_processors = context_processors
        self.rules = rules

    def check(self, lines, filename):
        # initial context:
        context = {"filename": filename}
        # pre-filter rules with filename:
        applicable_rules = filter(self._check_filename(context), self.rules)
        # check each line
        alerts, line_ctx = reduce(self._check_all(applicable_rules), lines, (list(), context))
        # we do not use line_ctx at alerting, so we drop it
        return alerts

    def _check_filename(self, context):
        def filename_filter(rule):
            return all(e.matches(context, None) for e in rule.evaluators if e.key == "file")
        return filename_filter

    def _check_all(self, rules):
        def check_line(check_ctx, line):
            if len(line) > 512:
                # probably not readable source, but it's hard to match regexes at least
                # TODO: logging
                return check_ctx
            alerts, line_ctx = check_ctx
            line_ctx = reduce(lambda ctx, cp: cp.preprocess(ctx, line), self.context_processors, line_ctx)
            for rule in rules:
                if all(e.matches(line_ctx, line) for e in rule.evaluators):
                    alerts.append((rule, line))
            return (alerts, line_ctx)
        return check_line


class Alert:
    def __init__(self, rule, filename, repo, commit, line):
        self.rule = rule
        self.filename = filename
        self.repo = repo
        self.commit = commit
        self.line = line


class Rule:
    def __init__(self, name, evaluators, rule_config):
        self.name = name
        self.evaluators = evaluators
        self.description = rule_config.get('description')


class CodeCheckerFactory:
    def __init__(self, ruleset):
        self.ruleset = ruleset

    def create(self, mode=LineEvalFactory.MODE_DIFF):
        factories = [LineEvalFactory(mode), InScriptEvalFactory(), FileEvalFactory()]
        context_processors = [InScriptEvalFactory.ContextProcessor()]
        rules = [self.create_single(rn, factories) for rn in self.ruleset]
        return CodeChecker(context_processors, rules)

    def create_single(self, rule_name, factories):
        rule = self.ruleset[rule_name]
        evaluators = filter(lambda e: e is not None, [f.create(rule) for f in factories])
        return Rule(rule_name, evaluators, rule)
