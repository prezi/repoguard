#!/usr/bin/env python
import requests
import json
import re
import os
import subprocess
import datetime
import argparse
import smtplib
import ConfigParser

APPDIR = "%s/" % os.path.dirname(os.path.realpath(__file__))

class RepoAlerter:
	def __init__(self):
		parser = ConfigParser.ConfigParser()
		parser.read(APPDIR+'etc/secret.ini')

		self.TOKEN = parser.get('github-api','token')
		self.PREZI_URL = 'https://api.github.com/orgs/prezi/repos'
		self.WORKING_DIR = '%s/repos' % os.path.abspath(os.path.join(__file__, os.pardir, os.pardir))

# removed from history
# removed from history
# removed from history
# removed from history
# removed from history
# removed from history
# removed from history
# removed from history
# removed from history
# removed from history
# removed from history
# removed from history
# removed from history
# removed from history
		self.TEST_REPO_LANGUAGES = ( ) # empty = no language based limitation

# removed from history

		self.url = self.PREZI_URL + "?access_token=" + self.TOKEN
		self.actpage = 1
		self.lastpage = 1
		self.repoList = {}
		self.repoStatus = {}
		self.repoStatusNew = {}
		self.stop = False
		self.alertConfig = {}
		self.checkLastFile = ''
		self.checkResults = []
		self.last_run = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

		parser = argparse.ArgumentParser(description='Watch git repos for changes...')
		parser.add_argument('--since','-s', default=False, help='Search for alerts in older git commits (git rev-list since, e.g. 2013-05-05 01:00)')
		parser.add_argument('--refresh','-r', action='store_true', default=False, help='Refresh repo list and locally stored repos from github api')
		parser.add_argument('--limit', '-l', default=False, help='Limit checks only to run on the given repos (comma separated list)')
		parser.add_argument('--alerts', '-a', default=False, help='Limit running only the given alert checks (comma separated list)')
		parser.add_argument('--nopull', action='store_true', default=False, help='No repo pull if set')
		parser.add_argument('--forcerefresh', action='store_true', default=False, help='Force script to refresh local repo status file')
		parser.add_argument('--notify', '-N', action='store_true', default=False, help='Notify pre-defined contacts via e-mail')

		self.args = parser.parse_args()

		self.readAlertConfigFromFile()
		if self.args.limit:
			self.args.limit = self.args.limit.split(',')
		if self.args.alerts:
			self.args.alerts = self.args.alerts.split(',')

	def setTestRepoLanguages(self, value):
		self.TEST_REPO_LANGUAGES = value

	def setSkipRepoList(self, value):
		self.SKIP_REPO_LIST = value

	def resetRepoLimits(self):
		self.setTestRepoLanguages( () )
		self.setSkipRepoList( () )

	def fetchRepoList(self):
		r = requests.get(self.url, verify=True)
		print self.url
		if (r.status_code ==200):
			if 'X-RateLimit-Remaining' in r.headers:
				if int(r.headers['X-RateLimit-Remaining']) == 0:
					print 'OUT OF RATELIMIT'
					self.stop = True
					return
			try:
				lasturl_re = re.compile('.*<([\w\:\/\.]+)\?access_token=%s&page=([0-9]+)>; rel="last"' % self.TOKEN)
				lasturl = lasturl_re.match(r.headers['link']).groups()
				self.lastpage = int(lasturl[1])
				print "PAGE %s/%s" % (self.actpage, self.lastpage)
			except:
				print "... finished"
				print "(rate limit: %s / %s)" % (r.headers['X-RateLimit-Remaining'], r.headers['X-RateLimit-Limit'])
			repoItems = json.loads(r.text or r.content)
			for rItem in repoItems:
				if rItem["name"] not in self.repoList or self.args.forcerefresh:
					self.repoList[rItem["id"]] = {"name": rItem["name"], "ssh_url": rItem["ssh_url"], "language": rItem["language"]}
		else:
			print "REQUEST ERROR!"
			self.stop = True

	def printRepoData(self):
		for repoId, repoData in self.repoList.iteritems():
			print "%s -> (id: %s, ssh_url: %s) " % (repoId, repoData["name"], repoData["ssh_url"])

	def refreshRepoList(self):
		while self.actpage <= self.lastpage and not self.stop:
			self.fetchRepoList()
			self.actpage+=1
			self.url = "%s?access_token=%s&page=%s" % (self.PREZI_URL, self.TOKEN, self.actpage)

	def searchRepoDir(self,directory_contents, name, repo_id):
		dirname = '%s_%s' % (name, repo_id)
		if dirname in directory_contents:
			return dirname
		else:
			return False

	def getCurrentHash(self, repo_id, repo_name):
		commit_re = re.compile('^commit ([\w]+)\n')
		cwd = '%s/%s_%s/' % (self.WORKING_DIR, repo_name, repo_id)
		output = subprocess.check_output("git log --remotes -1".split(), cwd=cwd)
		commit_match = commit_re.match(str(output))
		if commit_match:
			return commit_match.groups()[0]
		return False

	#def getHashBefore(self, repo_id, repo_name, before):
	#	hash_re = re.compile('^([a-zA-Z0-9]{40})')
	#	cwd = '%s/%s_%s/' % (self.WORKING_DIR, repo_name, repo_id)
	#	output = subprocess.check_output( ["git","rev-list", "--remotes", "-n1", "--before=\"%s\"" % before, "HEAD"], cwd=cwd)
	#	hash_match = hash_re.match(str(output))
	#	if hash_match:
	#		return hash_match.groups()[0]
	#	return False
	#	#

	def shouldSkip(self, repo_data):
		skip_due_language = False
		skip_due_repo_name = False

		# if test list empty --> skip nothing, else skip if not listed
		if len(self.TEST_REPO_LANGUAGES) > 0:
			skip_due_language = str(repo_data["language"]).lower() not in self.TEST_REPO_LANGUAGES

		if len(self.SKIP_REPO_LIST) > 0:
			skip_due_repo_name = repo_data["name"] in self.SKIP_REPO_LIST

		if repo_data["name"] in self.OVERRIDE_SKIP_LIST:
			return False

		return skip_due_language or skip_due_repo_name


	# repoList required
	def updateLocalRepos(self):
		working_dir = os.listdir(self.WORKING_DIR)

		for repoId, repoData in self.repoList.iteritems():
			repoDir = self.searchRepoDir(working_dir, repoData["name"], repoId)

			if self.shouldSkip(repoData):
				#print '... skipping %s ' % repoData["name"]
				continue

			if self.args.limit:
					if repoData["name"] not in self.args.limit:
						continue
			
			if repoDir:
				print 'Updating *** %s (%s) ***' % (repoData["name"], repoId)
				# DIRECTORY EXISTING --> git pull
				cwd = "%s/%s/" % (self.WORKING_DIR, repoDir)
				cmd = "git pull"
				# print cmd
				try:
					subprocess.check_output(cmd.split(), cwd=cwd)
					self.updateRepoStatusById(repoId, repoData["name"])
				except subprocess.CalledProcessError, e:
					print e
			else:
				# DIRECTORY NOT EXISTING --> git clone
				#print 'Cloning *** %s (%s) ***' % (repoData["name"], repoId)
				cmd = "git clone %s %s/%s_%s" % (repoData["ssh_url"], self.WORKING_DIR, repoData["name"], repoId)
				# print cmd
				subprocess.check_output(cmd.split())
				#  update repo status  --> last_hash should be False if configured for historical review...
				self.repoStatus[repoId] = {
					"name" : repoData["name"],
					"last_rum" : False,
					"last_hash" : self.getCurrentHash(repoId, repoData["name"])
				}

	def readRepoStatusFromFile(self, filename=APPDIR+'repo_status.json'):
		try:
			with open(filename) as repo_status:
				self.repoStatus = json.load(repo_status)
				# load again for the new timestamps
				repo_status.seek(0,0)
				self.repoStatusNew = json.load(repo_status)
		except IOError:
			print "repo_status.json not existing, no cache to load..."

	def checkRepoStatusFile(self, filename=APPDIR+'repo_status.json'):
		if not os.path.isfile(filename):
			return False
		return True

	def writeNewRepoStatusToFile(self, filename=APPDIR+'repo_status.json'):
		with open(filename, 'w') as repo_status:
			json.dump(self.repoStatusNew, repo_status)

	def checkNewCode(self):
		#sampleData = {
		#	"8742897" : {
		#		"name" 			: "zuisite",
		#		"last_run"	: False,
		#		"last_hash" : False
		#	}
		#}

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
					print "%s (%s) not yet in status, inserting current hash" % (repo_name, repo_id)
					self.updateRepoStatusById(repo_id, repo_name, True)

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
							print '%s\t%s\thttps://github.com/prezi/%s/commit/%s\t%s' % (issue[0],issue[1],issue[4],issue[2],issue[3].decode('utf-8'))

			else:
				print 'skip %s (not repo directory)' % repo_dir

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
			matching_line = issue[3]
			repo_name = issue[4]
			#repo_id = issue[5]
			alert_data = self.alertConfig[check_id]

			if alert_data['notify'] not in alert_per_notify_person:
				alert_per_notify_person[alert_data['notify']] = "The following change(s) might introduce new security risks:\n\n"
			
			alert_per_notify_person[alert_data['notify']] += ("check_id: %s \n"
																	"path: %s \n"
																	"commit: https://github.com/prezi/%s/commit/%s\n"
																	"matching line: %s\n"
																	"repo name: %s\n\n" %  (check_id, filename, repo_name, commit_id, matching_line, repo_name) ) 
		for mail_addr in alert_per_notify_person:
			print "sending mail to: %s" % mail_addr
			#print "mail content: %s\n\n" % alert_per_notify_person[mail_addr]
			self.send_email("mihaly.zagon+repoguard@prezi.com", [mail_addr], "[repoguard] possibly vulnerable change", alert_per_notify_person[mail_addr])

	def send_email(self, email_from, email_to, subject, txt):
	    recipients = ", ".join(email_to)
	    body = "\r\n".join(
	        [
	        "From: %s" % email_from,
	        "To: %s" % recipients,
	        "Subject: %s" % subject,
	        "",
	        txt
	        ])
	    smtp = smtplib.SMTP('localhost')
	    smtp.sendmail(email_from, email_to, body)
	    smtp.quit()

	def updateRepoStatusById(self, repo_id, repo_name, update_current=False):
		self.repoStatusNew[repo_id] = {
			"name" : repo_name,
			"last_run" : datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
			"last_hash" : self.getCurrentHash(repo_id, repo_name)
		}
		if update_current:
			self.repoStatus[repo_id] = self.repoStatusNew[repo_id]
		#print self.repoStatus[repo_id]

	def checkByRepoId(self, repo_id, repo_name):
		matches_in_repo = []
		cwd = "%s/%s_%s/" % (self.WORKING_DIR, repo_name, repo_id)
		#print "Get rev-list since the previous check *** %s (%s) ***" % (repo_name, repo_id)
		
		# check if before arg should be used instead of the last_hash
		last_run = False
		if self.args.since:
			last_run = self.args.since
		elif "last_run" in self.repoStatus[repo_id]:
			# bugfix: cheating, but always check since 2 minues before the last run...
			last_run = datetime.datetime.strptime(self.repoStatus[repo_id]["last_run"],"%Y-%m-%d %H:%M:%S") - datetime.timedelta(minutes=2)
		
		if last_run:
			#cmd = "git rev-list --remotes --since=\"%s\" HEAD" % last_run
			rev_list_output = subprocess.check_output(["git","rev-list", "--remotes", "--since=\"%s\"" % last_run, "HEAD"], cwd=cwd)
			rev_list = rev_list_output.split("\n")[:-1]
			for rev_hash in rev_list:
				rev_result = self.checkByRevHash(rev_hash, repo_name, repo_id)
				if rev_result:
					matches_in_repo = matches_in_repo + rev_result
			if len(rev_list)>0:
				print "checked commits %s %s" % (repo_name, len(rev_list))
		else:
			print "alert: no github hash found that should be checked, maybe try with smaller time frame"
		return matches_in_repo

	def checkByRevHash(self, rev_hash, repo_name, repo_id):
		matches_in_rev = []
		cwd = "%s/%s_%s/" % (self.WORKING_DIR, repo_name, repo_id)
		cmd = "git show --function-context %s" % rev_hash
		diff_output = subprocess.check_output(cmd.split(), cwd=cwd)
		for diff_line in diff_output.split("\n")[3:]:
			check_res = self.checkLine(diff_line)
			if check_res:
				matches_in_rev.append( (check_res, self.checkLastFile, rev_hash, diff_line, repo_name, repo_id) )

		return matches_in_rev

	def loadRepoListFromFile(self, filename=APPDIR+'repo_list.json'):
		try:
			with open(filename) as repo_file:
				self.repoList = json.load(repo_file)
		except IOError:
			print "repo_list.json not existing"

	def writeRepoListToFile(self, filename=APPDIR+'repo_list.json'):
		with open(filename,'w') as repo_file:
			json.dump(self.repoList, repo_file)

	def readAlertConfigFromFile(self, filename=APPDIR+'alert_config.json'):
		with open(filename) as alert_config:
			self.alertConfig_o = json.load(alert_config)

		for alert_id, alert_data in self.alertConfig_o.iteritems():
			if self.args.alerts:
				if alert_id not in self.args.alerts:
					continue
				else:
					print "%s alert enabled" % alert_id

			self.alertConfig[alert_id] = self.alertConfig_o[alert_id]
			to_compile = ('pattern', 'repo_pattern', 'file_pattern', 'language_pattern')
			for tc in to_compile:
				self.alertConfig[alert_id]['%s_compiled'] = False
				if tc in alert_data:
					if len(alert_data[tc])>0:
						#print 'creating compiled pattern for %s (%s)' % (tc, alert_data[tc])
						self.alertConfig[alert_id]['%s_compiled' % tc] = re.compile(alert_data[tc], flags=re.IGNORECASE)



	def checkLine(self, line):
		# check only added lines
		if len(line)==0:
			return False
		# store the file actually modified (line starting with diff --git a/ until b/)
		if line[0:13]=='diff --git a/':
			self.checkLastFile = line[12:line.find(' b/')]
		for alert_id, alert_data in self.alertConfig.iteritems():
			# skip if file pattern set
			if "file_pattern_compiled" in alert_data:
				if not alert_data['file_pattern_compiled'].match(self.checkLastFile) and self.checkLastFile:
					continue
			if alert_data['pattern_compiled'].match(line):
				return(alert_id)

	def putLock(self):
		lockfile = open(APPDIR+"repoguard.pid", "w")
		lockfile.write(str(os.getpid()))
		lockfile.close()

	def releaseLock(self):
		os.remove(APPDIR+"repoguard.pid")

	def isLocked(self):
		if os.path.isfile(APPDIR+"repoguard.pid"):
			lockfile = open(APPDIR+"repoguard.pid","r")
			pid = lockfile.readline().strip()
			lockfile.close()

			if os.path.exists("/proc/%s" % pid):
				return True
			else:
				print 'Lock there but script not running, removing lock and running script...'
				self.send_email(	'mihaly.zagon@prezi.com', 
									['mihaly.zagon@prezi.com'], 
									'[repoguard] invalid lock, removed', 
									'Found lock with PID %s, but process not found... script restarted.' % pid
								)

				self.releaseLock()
				self.setAborted()
				return False
		else:
			print "pid file not found, not locked..."
			return False

	def setAborted(self):
		aborted_state_file = open(APPDIR+"aborted_state.lock","w")
		aborted_state_file.write('1')
		aborted_state_file.close()

	def isAborted(self):
		return os.path.isfile(APPDIR+'aborted_state.lock')

	def run(self):
		now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
		print '* run started at %s' % now
		if self.isAborted():
			print 'Aborted state, quiting!'
			return

		if self.isLocked():
			print 'Locked, script running... waiting.'
			return

		self.putLock()
		
		# skip online update by default (only if --refresh specified or status cache json files not exist)
		if self.args.refresh or not self.checkRepoStatusFile():
			self.refreshRepoList()
			self.writeRepoListToFile()

		# read repo status json file
		self.readRepoStatusFromFile()

		# working from cached repo list file
		self.loadRepoListFromFile()
		
		self.last_run = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

		# updating local repos (and repo status files if necessary)
		if not self.args.nopull:
			self.updateLocalRepos()

		# check for new code
		self.checkNewCode()

		# send alert mail
		if self.args.notify:
			self.sendResults()

		# save repo status changes
		self.writeNewRepoStatusToFile()
		self.releaseLock()
		now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
		print "* run finished at %s" % now

if __name__ == '__main__':

	ra = RepoAlerter()
	ra.run()
	
