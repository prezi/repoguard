
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

		return alerts

	def _check_filename(self, context):
		def filename_filter(rule):
			return all(e.matches(context, None) for e in rule.evaluators if e.key == "file")
		return filename_filter

	def _check_all(self, rules):
		def check_line(check_ctx, line):
			alerts, line_ctx = check_ctx
			line_ctx = reduce(lambda ctx, cp: cp.preprocess(ctx), self.context_processors, line_ctx)
			for r in rules:
				if all(e.matches(line_ctx, line) for e in r.evaluators):
					alerts.append((r.name, line))
			return (alerts, line_ctx)
		return check_line

class CodeCheckerFactory:
	MODE_DIFF = 1
	MODE_SINGLE = 2

	def __init__(self, ruleset):
		self.ruleset = ruleset

	def create(mode=MODE_DIFF):
		pass