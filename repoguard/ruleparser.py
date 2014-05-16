import yaml

class ConfigParser:
	file_name = None
	namespace = None
	autoincr_base = 0

	def __init__(self, file_name):
		self.file_name = file_name
		self.namespace = self._find_default_namespace()

	def load(self):
		with open(self.file_name) as f:
			content = f.read()
			return {self._get_key(c): c for c in content.split('---') if len(c) > 0}

	def _find_default_namespace(self):
		dpos = self.file_name.rfind("/")
		if dpos < 0:
			dpos = 0
		else:
			dpos += 1
		ppos = self.file_name.rfind(".")
		if ppos < 0:
			ppos = len(self.file_name)

		return self.file_name[dpos:ppos]

	def _get_key(self, document):
		d = document.lstrip()
		if d.startswith("#!"):
			end = d.find("\n")
			return "%s::%s" % (self.namespace, d[2:end].strip())
		else:
			self.autoincr_base += 1
			return "%s::gen%d" % (self.namespace, self.autoincr_base) 
