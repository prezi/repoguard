#!/usr/bin/env python
#coding: utf-8
import json
import re
import os
import subprocess
import datetime
import hashlib
import argparse
import smtplib
import logging
import ConfigParser
import git_repo_updater
from elasticsearch import Elasticsearch
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from ruleparser import load_rules

class RepoGuard:
	def __init__(self, evaluatorFactories):
		self.CONFIG = {}
		self.RUNNING_ON_PROD = False
		self.evaluatorFactories = evaluatorFactories

		self.detectPaths()
		self.readCommonConfig()
		self.transformConfigOptionsToLists( ('SKIP_REPO_LIST','REPO_LANGUAGE_LIMITATION','ENFORCE_CHECK_REPO_LIST') )

		self.repoList = {}
		self.repoStatus = {}
		self.repoStatusNew = {}
		self.alertConfig = {}
		self.checkResults = []
		self.parseArgs()
		self.readAlertConfigFromFile()

		root_logger = logging.getLogger()
		root_logger.setLevel(logging.DEBUG)
		ch = logging.StreamHandler()
		logging.getLogger('elasticsearch').addHandler(ch)

	def parseArgs(self):
		parser = argparse.ArgumentParser(description='Watch git repos for changes...')
		parser.add_argument('--since','-s', default=False, help='Search for alerts in older git commits (git rev-list since, e.g. 2013-05-05 01:00)')
		parser.add_argument('--refresh','-r', action='store_true', default=False, help='Refresh repo list and locally stored repos from github api')
		parser.add_argument('--limit', '-l', default=False, help='Limit checks only to run on the given repos (comma separated list)')
		parser.add_argument('--alerts', '-a', default=False, help='Limit running only the given alert checks (comma separated list)')
		parser.add_argument('--nopull', action='store_true', default=False, help='No repo pull if set')
		parser.add_argument('--forcerefresh', action='store_true', default=False, help='Force script to refresh local repo status file')
		parser.add_argument('--notify', '-N', action='store_true', default=False, help='Notify pre-defined contacts via e-mail')
		parser.add_argument('--store', '-S', default=False, help='ElasticSearch node (host:port)')

		self.args = parser.parse_args()

		if self.args.limit:
			self.args.limit = self.args.limit.split(',')
		if self.args.alerts:
			self.args.alerts = self.args.alerts.split(',')


	def detectPaths(self):
		if os.path.isfile('/etc/prezi/repoguard/secret.ini'):
			self.RUNNING_ON_PROD = True

		if self.RUNNING_ON_PROD:
			self.SECRET_CONFIG_PATH='/etc/prezi/repoguard/secret.ini'
			self.APP_DIR = '/opt/prezi/repoguard/'
			self.WORKING_DIR = '/mnt/prezi/repoguard/repos/'
		else:
			self.SECRET_CONFIG_PATH="%s/etc/secret.ini" % os.path.dirname(os.path.realpath(__file__))
			self.APP_DIR = '%s/' % os.path.abspath(os.path.join(__file__, os.pardir, os.pardir))
			self.WORKING_DIR = '%srepos' % self.APP_DIR
		
		self.COMMON_CONFIG_PATH="%s/etc/common.cfg" % os.path.dirname(os.path.realpath(__file__))

		self.REPO_LIST_PATH = self.APP_DIR+'repo_list.json'
		self.REPO_STATUS_PATH = self.APP_DIR+'repo_status.json'
		self.ALERT_CONFIG_DIR = '%s/rules' % os.path.dirname(os.path.realpath(__file__))


	def readCommonConfig(self):
		parser = ConfigParser.ConfigParser()
		parser.read(self.COMMON_CONFIG_PATH)
		for config_option, config_value in parser.items('__main__'):
			self.setConfigOptionValue(config_option, config_value)
		
	def transformConfigOptionsToLists(self, list_of_options_to_transform):
		for config_option in list_of_options_to_transform:
			self.setConfigOptionValue(config_option, self.getConfigOptionValue(config_option).replace(' ','').split(','))

	def getConfigOptionValue(self, option_name):
		return self.CONFIG[option_name.upper()]

	def setConfigOptionValue(self, option_name, value):
		self.CONFIG[option_name.upper()] = value

	def setRepoLanguageLimitation(self, value):
		self.setConfigOptionValue('REPO_LANGUAGE_LIMITATION', value)

	def setSkipRepoList(self, value):
		self.setConfigOptionValue('SKIP_REPO_LIST', value)

	def resetRepoLimits(self):
		self.setRepoLanguageLimitation( [''] )
		self.setSkipRepoList( [''] )


	def printRepoData(self):
		for repoId, repoData in self.repoList.iteritems():
			print "%s -> (id: %s, ssh_url: %s) " % (repoId, repoData["name"], repoData["ssh_url"])


	def searchRepoDir(self,directory_contents, name, repo_id):
		dirname = '%s_%s' % (name, repo_id)
		if dirname in directory_contents:
			return dirname
		else:
			return False


	def getLastCommitHashes(self, repo_id, repo_name):
		try:
			cwd = '%s/%s_%s/' % (self.WORKING_DIR, repo_name, repo_id)
			output = subprocess.check_output("git rev-list --remotes --max-count=100".split(), cwd=cwd)
			output = output.strip().split('\n')
		except subprocess.CalledProcessError:
			return []
		return output
		

	def shouldSkip(self, repo_data):
		if self.isCheckEnforcedForRepo(repo_data["name"]):
			return False

		if self.args.limit:
			if repo_data["name"] not in self.args.limit:
				return False

		skip_due_language = self.shouldSkipDueLanguageLimitation(repo_data['language'])
		skip_due_repo_name = self.shouldSkipDueRepoNameIsOnSkipList(repo_data['name'])

		return skip_due_language or skip_due_repo_name

	def isCheckEnforcedForRepo(self, repo_name):
		return True if repo_name in self.getConfigOptionValue('ENFORCE_CHECK_REPO_LIST') else False

	def shouldSkipDueLanguageLimitation(self, repo_language):
		if self.getConfigOptionValue('REPO_LANGUAGE_LIMITATION') != ['']:
			return str(repo_language).lower() not in self.getConfigOptionValue('REPO_LANGUAGE_LIMITATION')
		return False

	def shouldSkipDueRepoNameIsOnSkipList(self, repo_name):
		if self.getConfigOptionValue('SKIP_REPO_LIST') != ['']:
			return repo_name in self.getConfigOptionValue('SKIP_REPO_LIST')
		return False

	# repoList required
	def updateLocalRepos(self):
		working_dir = os.listdir(self.WORKING_DIR)

		for repoId, repoData in self.repoList.iteritems():
			repoDir = self.searchRepoDir(working_dir, repoData["name"], repoId)

			if self.shouldSkip(repoData):
				#print '... skipping %s ' % repoData["name"]
				continue

			if repoDir:
				#print 'Updating *** %s (%s) ***' % (repoData["name"], repoId)
				# DIRECTORY EXISTING --> git pull
				cwd = "%s/%s/" % (self.WORKING_DIR, repoDir)
				cmd = "git pull"
				try:
					subprocess.check_output(cmd.split(), cwd=cwd)
					self.updateRepoStatusById(repoId, repoData["name"])
				except subprocess.CalledProcessError, e:
					print "Error when updating %s (%s)" % (repoData["name"], e)
			else:
				# DIRECTORY NOT EXISTING --> git clone
				try:
					cmd = "git clone %s %s/%s_%s" % (repoData["ssh_url"], self.WORKING_DIR, repoData["name"], repoId)
					subprocess.check_output(cmd.split())
	 				self.setInitialRepoStatusById(repoId, repoData["name"])
	 				self.updateRepoStatusById(repoId, repoData["name"])
	 			except Exception as e:
	 				print "Failed cloning %s: %s" % (repoData["name"], e)


	def readRepoStatusFromFile(self):
		filename = self.REPO_STATUS_PATH
		try:
			with open(filename) as repo_status:
				self.repoStatus = json.load(repo_status)
				# load again for the new timestamps
				repo_status.seek(0,0)
				self.repoStatusNew = json.load(repo_status)
		except IOError:
			print "repo_status.json not existing, no cache to load..."


	def checkRepoStatusFile(self):
		return os.path.isfile(self.REPO_STATUS_PATH)


	def writeNewRepoStatusToFile(self):
		filename = self.REPO_STATUS_PATH
		with open(filename, 'w') as repo_status:
			json.dump(self.repoStatusNew, repo_status)


	def checkNewCode(self):
		working_dir = os.listdir(self.WORKING_DIR)
		repodir_re = re.compile('^([\w\_-]+)\_([0-9]+)$')
		# go through local repo directories
		for repo_dir in working_dir:
			repodir_match = repodir_re.match(repo_dir)
			if repodir_match and os.path.isdir('%s/%s/.git' % (self.WORKING_DIR, repo_dir) ):
				
				repo_id = repodir_match.groups()[1]
				repo_name = repodir_match.groups()[0]
				
				if self.args.limit:
					if repo_name not in self.args.limit:
						continue

				if repo_id not in self.repoStatus:
					print "%s (%s) not yet in status, initializing" % (repo_name, repo_id)
					self.setInitialRepoStatusById(repo_id, repo_name)
					self.updateRepoStatusById(repo_id,repo_name)

				if repo_id in self.repoList:
					if self.shouldSkip(self.repoList[repo_id]):
						#print '... %s skip code check' % repo_name
						continue
				else:
					#print '... skip code check (not in repoList)'
					continue

				check_results = self.checkByRepoId(repo_id, repo_name) 
				if check_results:
					self.checkResults = self.checkResults + check_results
					if not self.args.notify:
						for issue in check_results:
							#print '### id: %s\nfile:\t%s\ncommit:\thttps://github.com/prezi/%s/commit/%s\nmatch:\t%s\n\n' % (issue[0],issue[1],issue[4],issue[2],issue[3])
							try:
								print '%s\t%s\t%s\thttps://github.com/prezi/%s/commit/%s\t%s' % (repo_name, issue[0],issue[1],issue[4],issue[2],issue[3][0:200].replace("\t"," ").decode('utf-8', 'replace'))
							except UnicodeEncodeError:
								print '%s\t%s\t%s\thttps://github.com/prezi/%s/commit/%s\t%s' % (repo_name, issue[0],issue[1],issue[4],issue[2],'failed to get the details due to some unicode error madness')
							

			else:
				print 'skip %s (not repo directory)' % repo_dir

	def storeResults(self):
		(host, port) = self.args.store.split(":")
		es = Elasticsearch([{"host": host, "port": port}])

		for issue in self.checkResults:
			try:
				body = {
					"check_id": issue[0],
					"description": self.alertConfig[issue[0]]['description'],
					"filename": issue[1],
					"commit_id": issue[2],
					"matching_line": issue[3][0:200].decode('utf-8', 'replace'),
					"repo_name": issue[4],
					"@timestamp": datetime.datetime.utcnow().isoformat(),
					"type": "repoguard"
				}

				es.create(body=body, id=hashlib.sha1(str(body)).hexdigest(), index='repoguard', doc_type='repoguard')
			except Exception as e:
				print e

	# TODO: test
	def sendResults(self):
		alert_per_notify_person = {}

		if not self.checkResults:
			return False

		print '### SENDING NOTIFICATION EMAIL ###'

		for issue in self.checkResults:
			check_id = issue[0]
			filename = issue[1]
			commit_id = issue[2]
			matching_line = issue[3][0:200].decode('utf-8', 'replace')
			repo_name = issue[4]
			#repo_id = issue[5]
			alert_data = self.alertConfig[check_id]

			if alert_data['notify'] not in alert_per_notify_person:
				alert_per_notify_person[alert_data['notify']] = "The following change(s) might introduce new security risks:\n\n"
			
			alert_per_notify_person[alert_data['notify']] += (u"check_id: %s \n"
																	"path: %s \n"
																	"commit: https://github.com/prezi/%s/commit/%s\n"
																	"matching line: %s\n"
																	"description: %s\n"
																	"repo name: %s\n\n" %  (check_id, filename, repo_name, commit_id, matching_line, alert_data['description'], repo_name) ) 
		for mail_addr in alert_per_notify_person:
			print "sending mail to: %s" % mail_addr
			now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M")
			#print "mail content: %s\n\n" % alert_per_notify_person[mail_addr]
			self.send_email("mihaly.zagon+repoguard@prezi.com", [mail_addr], "[repoguard] possibly vulnerable changes - %s" % now, alert_per_notify_person[mail_addr])


	def send_email(self, email_from, email_to, subject, txt):
		recipients = ", ".join(email_to)
		
		msg = MIMEMultipart()
		msg["Subject"] = subject
		msg['From'] = email_from
		msg['To'] = recipients

		msg.attach(MIMEText(txt.encode("utf-8"), "plain"))
		
		smtp = smtplib.SMTP('localhost')
		smtp.sendmail(email_from, email_to, msg.as_string())
		smtp.quit()


	def setInitialRepoStatusById(self, repo_id, repo_name):
		self.repoStatus[repo_id] = {
			"name" : repo_name,
			"last_run" : False,
			"last_checked_hashes" : []
		}


	def updateRepoStatusById(self, repo_id, repo_name):
		self.repoStatusNew[repo_id] = {
			"name" : repo_name,
			"last_run" : datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
			"last_checked_hashes" : self.getLastCommitHashes(repo_id, repo_name)
		}


	def getNewHashes(self, repo_id):
		ret_arr = []
		for commit in self.repoStatusNew[repo_id]["last_checked_hashes"]:
			if commit not in self.repoStatus[repo_id]["last_checked_hashes"]:
				ret_arr.append(commit)
		return ret_arr


	def checkByRepoId(self, repo_id, repo_name):
		matches_in_repo = []
		cwd = "%s/%s_%s/" % (self.WORKING_DIR, repo_name, repo_id)
		
		# check by timestamp if --since specified, otherwise check for new commits
		if self.args.since:
			rev_list = []
			try:
				last_run = self.args.since
				rev_list_output = subprocess.check_output(["git","rev-list", "--remotes", "--since=\"%s\"" % last_run, "HEAD"], cwd=cwd)
				rev_list = rev_list_output.split("\n")[:-1]
			except Exception as e:
				print "Failed getting commits from a given timestamp (exception: %s)" % e
		else:
			rev_list = self.getNewHashes(repo_id)

		for rev_hash in rev_list:
			rev_result = self.checkByRevHash(rev_hash, repo_name, repo_id)
			if rev_result:
				matches_in_repo = matches_in_repo + rev_result
		if len(rev_list)>0:
			print "checked commits %s %s" % (repo_name, len(rev_list))
		
		return matches_in_repo


	def checkByRevHash(self, rev_hash, repo_name, repo_id):
		matches_in_rev = []
		cwd = "%s/%s_%s/" % (self.WORKING_DIR, repo_name, repo_id)
		cmd = "git show --function-context %s" % rev_hash
		try:
			diff_output = subprocess.check_output(cmd.split(), cwd=cwd)
			# initial setup:
			lineCtx = {"filename": None, "inside_script_tag": 0, "repo": repo_name, "languange": None}

			# we ignore the first 3 lines which are commit info for sure
			for diff_line in diff_output.split("\n")[3:]:
				lineCtx = reduce(lambda ctx, ef: ef.processLineInfo(diff_line, ctx), self.evaluatorFactories, lineCtx)
				alerts = self.checkLine(lineCtx)
				matches_in_rev.extend(
					[(alert, lineCtx["filename"], rev_hash, diff_line, repo_name, repo_id) for alert in alerts])
		except subprocess.CalledProcessError as e:
			print 'Failed running %s (exception: %s)' % (cmd, e)

		return matches_in_rev


	def loadRepoListFromFile(self):
		filename = self.REPO_LIST_PATH
		try:
			with open(filename) as repo_file:
				self.repoList = json.load(repo_file)
		except IOError:
			print "repo_list.json not existing"


	def readAlertConfigFromFile(self):
		self.alertConfig_o = load_rules(self.ALERT_CONFIG_DIR)

		# filter for items in --alerts parameter
		applied_alerts = [(aid, adata) for aid, adata 
			in self.alertConfig_o.iteritems() 
			if not self.args.alerts or aid in self.args.alerts ]
		
		self.alertConfig = {}
		for alert_id, alert_data in applied_alerts:
			try:
				alert_data['evaluators'] = [fact.create(alert_data) for fact 
					in self.evaluatorFactories
					if fact.key in alert_data]
				self.alertConfig[alert_id] = alert_data
			except Exception:
				print '!! Failure during configuring rule "%s"' % alert_id
				raise

	def checkLine(self, line_info):
		# a bit dirty here, but don't check line if it's empty
		if "line" in line_info and (line_info["line"] is None or len(line_info["line"].strip()) == 0):
			return []

		# run checks
		from itertools import imap
		return [alert_id for alert_id, alert_data in self.alertConfig.iteritems()
			if all(imap(lambda e: e.evaluate(line_info), alert_data['evaluators']))]


	def putLock(self):
		lockfile = open(self.APP_DIR+"repoguard.pid", "w")
		lockfile.write(str(os.getpid()))
		lockfile.close()


	def releaseLock(self):
		os.remove(self.APP_DIR+"repoguard.pid")


	def isLocked(self):
		if os.path.isfile(self.APP_DIR+"repoguard.pid"):
			lockfile = open(self.APP_DIR+"repoguard.pid","r")
			pid = lockfile.readline().strip()
			lockfile.close()

			if os.path.exists("/proc/%s" % pid):
				return True
			else:
				print 'Lock there but script not running, removing lock entering aborted state...'
				self.send_email(	'mihaly.zagon+repoguard@prezi.com', 
									['security@prezi.com'], 
									'[repoguard] invalid lock, entering aborted state', 
									'Found lock with PID %s, but process not found... entering aborted state (someone should check the logs and restart manually!)' % pid
								)

				self.releaseLock()
				self.setAborted()
				return False
		else:
			print "pid file not found, not locked..."
			return False


	def setAborted(self):
		aborted_state_file = open(self.APP_DIR+"aborted_state.lock","w")
		aborted_state_file.write('1')
		aborted_state_file.close()


	def isAborted(self):
		return os.path.isfile(self.APP_DIR+'aborted_state.lock')


	def run(self):
		now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
		print '* run started at %s' % now

		# only struggle with locking if running on prod env
		if self.RUNNING_ON_PROD:
			if self.isAborted():
				print 'Aborted state, quiting!'
				return

			if self.isLocked():
				print 'Locked, script running... waiting.'
				return

			self.putLock()
			
		# skip online update by default (only if --refresh specified or status cache json files not exist)
		if self.args.refresh or not self.checkRepoStatusFile():
			git_repo_updater_obj = git_repo_updater.GitRepoUpdater(self.SECRET_CONFIG_PATH, self.REPO_LIST_PATH)
			git_repo_updater_obj.refreshRepoList()
			git_repo_updater_obj.writeRepoListToFile()

		# read repo status json file
		self.readRepoStatusFromFile()

		# working from cached repo list file
		self.loadRepoListFromFile()
		
		# updating local repos (and repo status files if necessary)
		if not self.args.nopull:
			self.updateLocalRepos()

		# check for new code
		self.checkNewCode()

		# send alert mail (only if prod)
		if self.args.notify:
			self.sendResults()

		# store things in ES:
		if self.args.store:
			self.storeResults()

		# save repo status changes
		self.writeNewRepoStatusToFile()
		
		if self.RUNNING_ON_PROD:
			self.releaseLock()
		
		now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
		print "* run finished at %s" % now


class EvaluatorBase(object):
	def __init__(self):
		super(EvaluatorBase, self).__init__()


	def evaluate(self, line_info):
		from exceptions import NotImplementedError
		raise NotImplementedError()
		

class EvaluatorFactoryBase(object):
	def __init__(self, key):
		super(EvaluatorFactoryBase, self).__init__()
		self.key = key


	def key(self):
		return self.key


	def processLineInfo(self, line, line_info):
		return line_info


	def create(self, configuration):
		from exceptions import NotImplementedError
		raise NotImplementedError()


class NegateFactory(EvaluatorFactoryBase):
	def __init__(self, ef):
		super(NegateFactory, self).__init__("-%s" % ef.key)
		self.ef = ef


	def create(self, configuration):
		return self.NegateEvaluator(self.ef.create(configuration))


	class NegateEvaluator(EvaluatorBase):
		def __init__(self, evaluator):
			super(NegateFactory.NegateEvaluator, self).__init__()
			self.evaluator = evaluator

		def evaluate(self, line_info):
			orig = self.evaluator.evaluate(line_info)
			return not orig if orig is not None else None


class FileEvalFactory(EvaluatorFactoryBase):
	def __init__(self):
		super(FileEvalFactory, self).__init__("file")


	def processLineInfo(self, line, line_info):
		if line[0:13]=='diff --git a/':
			line_info["filename"] = line[12:line.find(' b/')]
		
		return line_info


	def create(self, configuration):
		return self.FileEvaluator(re.compile(configuration, flags=re.IGNORECASE))


	class FileEvaluator(EvaluatorBase):
		def __init__(self, pattern):
			super(FileEvalFactory.FileEvaluator, self).__init__()
			self.pattern = pattern


		def evaluate(self, line_info):
			value = line_info["filename"]
			return None if value is None else self.pattern.match(value) is not None


class RepoEvalFactory(EvaluatorFactoryBase):
	def __init__(self):
		super(RepoEvalFactory, self).__init__("repo")


	def create(self, configuration):
		return self.RepoEvaluator(re.compile(configuration, flags=re.IGNORECASE))


	class RepoEvaluator(EvaluatorBase):
		def __init__(self, pattern):
			super(RepoEvalFactory.RepoEvaluator, self).__init__()
			self.pattern = pattern


		def evaluate(self, line_info):
			value = line_info["repo"]
			return None if value is None else self.pattern.match(value) is not None


class InScriptEvalFactory(EvaluatorFactoryBase):
	def __init__(self):
		super(InScriptEvalFactory, self).__init__("inscripttag")
		self.script_begin_re = re.compile(r'(?!.+type="text/(tpl|template)".+)<script[^>]*>')
		self.script_end_re = re.compile(r'</script\s*>')


	def processLineInfo(self, line, line_info):
		if line[0:13]=='diff --git a/':
			line_info["inside_script_tag"] = 0
		else:
			line_info["inside_script_tag"] += len(self.script_begin_re.findall(line)) - len(self.script_end_re.findall(line))

		return line_info


	def create(self, rule):
		return self.InScriptEvaluator()


	class InScriptEvaluator(EvaluatorBase):
		def __init__(self):
			super(InScriptEvalFactory.InScriptEvaluator, self).__init__()


		def evaluate(self, line_info):
			value = line_info["inside_script_tag"]
			return None if value is None else value > 0


class LineEvalFactory(EvaluatorFactoryBase):
	def __init__(self):
		super(LineEvalFactory, self).__init__("line")

	def processLineInfo(self, line, line_info):
		line_info["line"] = line
		return line_info

	def create(self, rule):
		if "diff" in rule:
			if rule["diff"] == "add":
				return self.LineEvaluator(rule["line"], "+")
			elif rule["diff"] == "del":
				return self.LineEvaluator(rule["line"], "-")
			elif rule["diff"] == "all":
				return self.LineEvaluator(rule["line"])
			else:
				raise Exception("Unknown diff strategy: %s", rule["diff"])
		else:
			return self.LineEvaluator(rule["line"])


	class LineEvaluator(EvaluatorBase):
		def __init__(self, rules):
			super(LineEvalFactory.LineEvaluator, self).__init__()
			self.positive_patterns = []
			self.negative_patterns = []
			for rule in rules:
				if "match" in rule:
					self.positive_patterns.append(re.compile(rule["match"], flags=re.IGNORECASE))
				elif "except" in rule:
					self.negative_patterns.append(re.compile(rule["except"], flags=re.IGNORECASE))
				else:
					raise Exception("Unknown key in %s" % str(rule))

		def evaluate(self, line_info):
			if "line" not in line_info:
				return None
			else:
				value = line_info["line"]
			
			ctx = reduce(lambda ctx, p: ctx and p.match(value), self.positive_patterns, True)
			return reduce(lambda ctx, p: ctx and not p.match(value), self.negative_patterns, ctx)



def createInitializedRepoguardInstance():
	baseEvaluators = [LineEvalFactory(), InScriptEvalFactory()]
	#evaluators = reduce(list.__add__, map(lambda e: [e, NegateFactory(e)], baseEvaluators))
	return RepoGuard(baseEvaluators)


if __name__ == '__main__':
	createInitializedRepoguardInstance().run()
	
