from evaluators import *


class CodeChecker:
    def __init__(self, context_processors, rules, repo_groups={}, rules_to_groups={}):
        self.context_processors = context_processors
        self.rules = rules
        self.repo_groups = repo_groups
        self.rules_to_groups = rules_to_groups

    def check(self, lines, context, repo=None):
        rules_applied_for_this_repo = filter(self._filter_rules(repo.name), self.rules) if repo else self.rules
        # pre-filter rules with line-invariant rules:
        applicable_rules = filter(self._check_line_invariants(context), rules_applied_for_this_repo)
        # check each line
        alerts, line_ctx = reduce(self._check_all(applicable_rules), lines, (list(), context))
        # we do not use line_ctx at alerting, so we drop it
        return alerts

    def _filter_rules(self, repo_name):
        def rule_filter(rule):
            for group_name, repo_group in self.repo_groups.iteritems():
                rules_to_group = self.rules_to_groups.get(group_name) + self.rules_to_groups.get('*', [])
                if repo_name in repo_group and rules_to_group:
                    # repo_name is in a group which has rules assigned to it
                    positive_patterns = [re.compile(r["match"]) for r in rules_to_group if "match" in r]
                    negative_patterns = [re.compile(r["except"]) for r in rules_to_group if "except" in r]

                    ctx = reduce(lambda acc, p: acc or p.search(rule.name) is not None, positive_patterns, False)
                    return ctx and reduce(lambda ctx, p: ctx and p.search(rule.name) is None, negative_patterns, ctx)
            return True

        return rule_filter

    def _check_line_invariants(self, context):
        def filename_filter(rule):
            return all(e.matches(context, None) for e in rule.evaluators if e.key in ["file", "message", "author"])

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
                matches = [e.matches(line_ctx, line) for e in rule.evaluators]
                if len(matches) > 0 and all(matches):
                    alerts.append((rule, line))
            return (alerts, line_ctx)

        return check_line


class Alert:
    def __init__(self, rule, filename, repo, commit, line, line_number, author=None, commit_description=None):
        self.rule = rule
        self.filename = filename
        self.repo = repo
        self.commit = commit
        self.line = line
        self.line_number = line_number
        self.author = author
        self.commit_description = commit_description


class Rule:
    def __init__(self, name, evaluators, rule_config):
        self.name = name
        self.evaluators = evaluators
        self.description = rule_config.get('description', 'no description')
        self.email_template = rule_config.get('preferred_email_template', None)

    def __str__(self):
        return self.name


class CodeCheckerFactory:
    def __init__(self, ruleset, repo_groups={}, rules_to_groups={}):
        self.ruleset = ruleset
        self.repo_groups = repo_groups
        self.rules_to_groups = rules_to_groups

    def create(self, mode=LineEvalFactory.MODE_DIFF):
        factories = [LineEvalFactory(mode), InScriptEvalFactory(), FileEvalFactory(),
                     CommitMessageEvalFactory(), AuthorEvalFactory()]
        context_processors = [InScriptEvalFactory.ContextProcessor()]
        rules = [self.create_single(rn, factories) for rn in self.ruleset]
        return CodeChecker(context_processors, rules, self.repo_groups, self.rules_to_groups)

    def create_single(self, rule_name, factories):
        rule = self.ruleset[rule_name]
        evaluators = filter(lambda e: e is not None, [f.create(rule) for f in factories])
        return Rule(rule_name, evaluators, rule)
