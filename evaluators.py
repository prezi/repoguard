import re


class InScriptEvalFactory:
    def __init__(self):
        self.evaluator = self.InScriptEvaluator()

    def create(self, rule):
        return self.evaluator if "inscripttag" in rule else None

    class InScriptEvaluator:
        key = "inscripttag"

        def matches(self, line_context, line):
            value = line_context["inside_script_tag"]
            return value is not None and value > 0

    class ContextProcessor:
        def __init__(self):
            self.script_begin_re = re.compile(r'(?!.+type="text/(tpl|template|html)".+)<script[^>]*>')
            self.script_end_re = re.compile(r'</script\s*>')

        def preprocess(self, line_context, line):
            if "inside_script_tag" not in line_context:
                # initialise
                line_context["inside_script_tag"] = 0
            tag_start_cnt = len(self.script_begin_re.findall(line))
            tag_end_cnt = len(self.script_end_re.findall(line))
            line_context["inside_script_tag"] += (tag_start_cnt - tag_end_cnt)
            return line_context


class LineEvalFactory:
    MODE_DIFF = 1
    MODE_SINGLE = 2

    def __init__(self, mode=MODE_DIFF):
        self.mode = mode

    def create(self, rule):
        if "line" not in rule:
            return None
        else:
            positive_patterns = [re.compile(r["match"]) for r in rule["line"] if "match" in r]
            negative_patterns = [re.compile(r["except"]) for r in rule["line"] if "except" in r]
            diff_mode = rule["diff"] if "diff" in rule else "all"
            diff_mode = diff_mode if diff_mode in ("add", "del", "mod") else "all"
            if self.mode == self.MODE_DIFF:
                diff_mode_prefixes = {"add": ("+", ), "del": ("-",), "mod": ("+", "-")}
                must_begin_with = diff_mode_prefixes.get(diff_mode, None)
                return self.DiffLineEvaluator(positive_patterns, negative_patterns, must_begin_with)
            else:
                if diff_mode != "del":
                    return self.SimpleLineEvaluator(positive_patterns, negative_patterns)
                else:
                    return self.AlwaysFalseLineEvaluator()

    class SimpleLineEvaluator:
        key = "line"

        def __init__(self, positive_patterns, negative_patterns):
            self.positive_patterns = positive_patterns
            self.negative_patterns = negative_patterns

        def matches(self, line_context, line):
            if line is None or len(line) == 0:
                return False
            ctx = reduce(lambda ctx, p: ctx or p.search(line) is not None, self.positive_patterns, False)
            return ctx and reduce(lambda ctx, p: ctx and p.search(line) is None, self.negative_patterns, ctx)

    class DiffLineEvaluator:
        key = "line"

        def __init__(self, positive_patterns, negative_patterns, must_begin_with=None):
            self.must_begin_with = must_begin_with
            self.positive_patterns = positive_patterns
            self.negative_patterns = negative_patterns

        def matches(self, line_context, line):
            if line is None or len(line) <= 2:
                return False

            ctx = True
            if self.must_begin_with is not None:
                ctx = line.startswith(self.must_begin_with)
                line = line[1:]
            ctx = ctx and reduce(lambda ctx, p: ctx or p.search(line) is not None, self.positive_patterns, False)
            return ctx and reduce(lambda ctx, p: ctx and p.search(line) is None, self.negative_patterns, ctx)

    class AlwaysFalseLineEvaluator:
        key = "line"

        def matches(self, line_context, line):
            return False


class FileEvalFactory:

    def create(self, rule):
        return self.FileEvaluator(rule["file"]) if "file" in rule else None

    class FileEvaluator:
        key = "file"

        def __init__(self, rules):
            self.positive_patterns = []
            self.negative_patterns = []
            for rule in rules:
                if "match" in rule:
                    self.positive_patterns.append(re.compile(rule["match"], flags=re.IGNORECASE))
                elif "except" in rule:
                    self.negative_patterns.append(re.compile(rule["except"], flags=re.IGNORECASE))
                else:
                    raise Exception("Unknown key in %s" % str(rule))

        def matches(self, line_context, line):
            if line is not None:
                # bit ugly, but this is a speed improvement: we check first if a file-keyed
                # evaluator matches to a filename, and at that point the line is None. When
                # it's not None, we don't need to run the costly checks, since once it was
                # matching already
                return True

            filename = line_context["filename"]

            pos = not self.positive_patterns or reduce(lambda ctx, p: ctx or p.match(filename), self.positive_patterns, False)
            neg = reduce(lambda ctx, p: ctx and not p.match(filename), self.negative_patterns, True)
            return pos and neg
