#!/usr/bin/env python
# -*- coding: utf-8 -*-
import json
import yaml
import re
import os
import subprocess
import datetime
import hashlib
import argparse
import smtplib
import logging
import sys
from git_repo_updater import GitRepoUpdater
from codechecker import CodeCheckerFactory
from elasticsearch import Elasticsearch
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from ruleparser import build_resolved_ruleset
from ruleparser import load_rules
from notifier import EmailNotifier


class RepoGuard:
    def __init__(self):
        self.CONFIG = {}
        self.repoList = {}
        self.repoStatus = {}
        self.repoStatusNew = {}
        self.checkResults = []

        self.logger = logging.getLogger()
        # create formatter and add it to the handlers
        formatter = logging.Formatter('%(asctime)s %(processName)-10s %(name)s %(levelname)-8s %(message)s')
        # create console handler with a higher log level
        ch = logging.StreamHandler()
        ch.setFormatter(formatter)
        # Setup logger output
        self.logger.addHandler(ch)
        # Supress logging

        self.parseArgs()
        self.detectPaths()
        self.readConfig(self.CONFIG_PATH)
        self.readAlertConfigFromFile()

    def parseArgs(self):
        parser = argparse.ArgumentParser(description='Watch git repos for changes...')
        parser.add_argument('--config', '-c', default='etc/config.yml', help='Path to the config.yml file')
        # parser.add_argument('--rule-dirs', default='rules', help='Path to rule directories (comma separated list)')
        parser.add_argument('--rule-dir', default='rules/', help='Path to the rule directory')
        parser.add_argument('--working-dir', default='../repos/', help='Path to the rule directory')
        parser.add_argument('--since', '-s', default=False, help='Search for alerts in older git commits (git rev-list since, e.g. 2013-05-05 01:00)')
        parser.add_argument('--refresh', '-r', action='store_true', default=False, help='Refresh repo list and locally stored repos from github api')
        parser.add_argument('--limit', '-l', default=False, help='Limit checks only to run on the given repos (comma separated list)')
        parser.add_argument('--alerts', '-a', default=False, help='Limit running only the given alert checks (comma separated list)')
        parser.add_argument('--nopull', action='store_true', default=False, help='No repo pull if set')
        parser.add_argument('--notify', '-N', action='store_true', default=False, help='Notify pre-defined contacts via e-mail')
        parser.add_argument('--silent', action="count", help='Supress log messages lower than warning')
        parser.add_argument('--store', '-S', default=False, help='ElasticSearch node (host:port)')

        self.args = parser.parse_args()

        # if self.args.rule_dirs:
        #     self.args.rule_dirs = self.args.rule_dirs.split(',')
        if self.args.limit:
            self.args.limit = self.args.limit.split(',')
        if self.args.alerts:
            self.args.alerts = self.args.alerts.split(',')

        if self.args.silent:
            self.logger.setLevel(logging.WARNING)
        else:
            self.logger.setLevel(logging.DEBUG)

    def detectPaths(self):

        # if self.RUNNING_ON_PROD:
        #     self.SECRET_CONFIG_PATH = '/etc/prezi/repoguard/secret.ini'
        #     self.APP_DIR = '/opt/prezi/repoguard/'
        #     self.WORKING_DIR = '/mnt/prezi/repoguard/repos/'

        self.APP_DIR = '%s/' % os.path.abspath(os.path.join(__file__, os.pardir, os.pardir))
        self.CONFIG_PATH = self.args.config
        self.WORKING_DIR = self.args.working_dir
        self.ALERT_CONFIG_DIR = self.args.rule_dir

    def readConfig(self, path):
        try:
            with open(path) as f:
                self.config = yaml.load(f.read())
                self.setSkipRepoList(self.config['skip_repo_list'])
                self.subscribers = self.config['subscribers']
                self.org_name = self.config['github']['organization_name']
                for key in ['default_notification_src_address', 'default_notification_to_address']:
                    self.setConfigOptionValue(key, self.config[key])
        except KeyError as e:
            self.logger.critical('%s not found in config file' % e)
            sys.exit()
        except Exception:
            self.logger.exception("Error loading config file: %s\n" % path)
            sys.exit()

    def getConfigOptionValue(self, option_name):
        return self.CONFIG[option_name.upper()]

    def setConfigOptionValue(self, option_name, value):
        self.CONFIG[option_name.upper()] = value

    def setSkipRepoList(self, value):
        self.setConfigOptionValue('SKIP_REPO_LIST', value)

    def resetRepoLimits(self):
        self.setSkipRepoList([])

    def printRepoData(self):
        for repoId, repoData in self.repoList.iteritems():
            print "%s -> (id: %s, ssh_url: %s) " % (repoId, repoData["name"], repoData["ssh_url"])

    def searchRepoDir(self, directory_contents, name, repo_id):
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
        if self.args.limit:
            if repo_data["name"] not in self.args.limit:
                self.logger.debug('Got --limit param and repo (%s) is not among them, skipping.' % repo_data['name'])
                return True

        return repo_data["name"] in self.getConfigOptionValue('SKIP_REPO_LIST')

    # repoList required
    def updateLocalRepos(self):
        working_dir = os.listdir(self.WORKING_DIR)

        for repoId, repoData in self.repoList.iteritems():
            if self.shouldSkip(repoData):
                self.logger.debug('... skipping %s ' % repoData["name"])
                continue

            repoDir = self.searchRepoDir(working_dir, repoData["name"], repoId)
            if repoDir:
                # DIRECTORY EXISTING --> git pull
                self.logger.debug('git pull *** %s (%s) ***' % (repoData["name"], repoId))
                cwd = "%s%s/" % (self.WORKING_DIR, repoDir)
                try:
                    subprocess.check_output(['git', 'pull'], cwd=cwd)
                    self.updateRepoStatusById(repoId, repoData["name"])
                except subprocess.CalledProcessError, e:
                    self.logger.error("Error when updating %s (%s)" % (repoData["name"], e))
            else:
                # DIRECTORY NOT EXISTING --> git clone
                self.logger.debug('git clone *** %s (%s) ***' % (repoData["name"], repoId))
                try:
                    repo_dir = "%s%s_%s" % (self.WORKING_DIR, repoData["name"], repoId)
                    subprocess.check_output(['git', 'clone', repoData["ssh_url"], repo_dir])
                    # only if there is no status yet (maybe someone deleted this directory from repos dir?)
                    self.setInitialRepoStatusById(repoId, repoData["name"])
                    self.updateRepoStatusById(repoId, repoData["name"])
                except Exception as e:
                    self.logger.exception("Failed cloning %s: %s" % (repoData["name"], e))

    def readRepoStatusFromFile(self, filename):
        try:
            with open(filename) as repo_status:
                self.repoStatus = json.load(repo_status)
                # load again for the new timestamps
                repo_status.seek(0, 0)
                self.repoStatusNew = json.load(repo_status)
        except IOError:
            self.logger.info("repo_status.json not existing, no cache to load...")

    def checkRepoStatusFile(self, filename):
        return os.path.isfile(filename)

    def writeNewRepoStatusToFile(self, filename):
        with open(filename, 'w') as repo_status:
            json.dump(self.repoStatusNew, repo_status)

    def checkNewCode(self):
        working_dir = os.listdir(self.WORKING_DIR)
        repodir_re = re.compile('^([\w\-\._]+)\_([0-9]+)$')
        # go through local repo directories
        for repo_dir in working_dir:
            repodir_match = repodir_re.match(repo_dir)
            if repodir_match and os.path.isdir('%s/%s/.git' % (self.WORKING_DIR, repo_dir)):

                repo_id = repodir_match.groups()[1]
                repo_name = repodir_match.groups()[0]

                if self.args.limit:
                    if repo_name not in self.args.limit:
                        continue

                if repo_id not in self.repoStatus:
                    self.logger.debug("%s (%s) not yet in status, initializing" % (repo_name, repo_id))
                    self.setInitialRepoStatusById(repo_id, repo_name)
                    self.updateRepoStatusById(repo_id, repo_name)

                if repo_id in self.repoList:
                    if self.shouldSkip(self.repoList[repo_id]):
                        self.logger.debug('... %s skip code check' % repo_name)
                        continue
                else:
                    self.logger.debug('... skip code check (not in repoList)')
                    continue

                check_results = self.checkByRepoId(repo_id, repo_name)
                if check_results:
                    self.checkResults += check_results
                    if not self.args.notify:
                        for issue in check_results:
                            try:
                                print '%s\t%s\thttps://github.com/%s/\t%s/%s/commit/%s\t%s' % \
                                    (repo_name, issue[0], issue[1], self.org_name, issue[4], issue[2], issue[3][0:200].replace("\t", " ").decode('utf-8', 'replace'))
                            except UnicodeEncodeError:
                                self.logger.exception('failed to get the details due to some unicode error madness')
            else:
                self.logger.debug('skip %s (not repo directory)' % repo_dir)

    def storeResults(self):
        (host, port) = self.args.store.split(":")
        es = Elasticsearch([{"host": host, "port": port}])

        for issue in self.checkResults:
            try:
                body = {
                    "check_id": issue[0],
                    "description": "",  # TODO
                    "filename": issue[1],
                    "commit_id": issue[2],
                    "matching_line": issue[3][0:200].decode('utf-8', 'replace'),
                    "repo_name": issue[4],
                    "@timestamp": datetime.datetime.utcnow().isoformat(),
                    "type": "repoguard"
                }

                es.create(body=body, id=hashlib.sha1(str(body)).hexdigest(), index='repoguard', doc_type='repoguard')
            except Exception as e:
                self.logger.exception('Got exception during storing results to ES.')

    # TODO: test
    def sendResults(self):
        alert_per_notify_person = {}
        if not self.checkResults:
            return False

        self.logger.info('### SENDING NOTIFICATION EMAIL ###')

        for issue in self.checkResults:
            check_id = issue[0]
            filename = issue[1]
            commit_id = issue[2]
            matching_line = issue[3][0:200].decode('utf-8', 'replace')
            repo_name = issue[4]

            alert = (u"check_id: %s \n"
                     "path: %s \n"
                     "commit: https://github.com/%s/%s/commit/%s\n"
                     "matching line: %s\n"
                     "description: %s\n"
                     "repo name: %s\n\n" % (check_id, filename, self.org_name, repo_name, commit_id, matching_line, "TODO", repo_name))

            notify_users = self.find_subscribed_users(check_id)
            for u in notify_users:
                if u not in alert_per_notify_person:
                    alert_per_notify_person[u] = "The following change(s) might introduce new security risks:\n\n"
                alert_per_notify_person[u] += alert

        from_addr = self.getConfigOptionValue("default_notification_src_address")
        for to_addr, text in alert_per_notify_person.iteritems():
            email_notification = EmailNotifier.create_notification(from_addr, to_addr, text)
            email_notification.send_if_fine()

    def find_subscribed_users(self, alert):
        import fnmatch
        import itertools
        matching_subscriptions = [users for pattern, users in self.subscribers.iteritems() if fnmatch.fnmatch(alert, pattern)]
        return set(itertools.chain(*matching_subscriptions))

    def setInitialRepoStatusById(self, repo_id, repo_name):
        self.repoStatus[repo_id] = {
            "name": repo_name,
            "last_run": False,
            "last_checked_hashes": []
        }

    def updateRepoStatusById(self, repo_id, repo_name):
        self.repoStatusNew[repo_id] = {
            "name": repo_name,
            "last_run": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "last_checked_hashes": self.getLastCommitHashes(repo_id, repo_name)
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
                rev_list_output = subprocess.check_output(["git", "rev-list", "--remotes", "--since=\"%s\"" % last_run, "HEAD"], cwd=cwd)
                rev_list = rev_list_output.split("\n")[:-1]
            except Exception as e:
                self.logger.exception("Failed getting commits from a given timestamp")
        else:
            rev_list = self.getNewHashes(repo_id)

        for rev_hash in rev_list:
            rev_result = self.checkByRevHash(rev_hash, repo_name, repo_id)
            if rev_result:
                matches_in_repo = matches_in_repo + rev_result
        if len(rev_list) > 0:
            self.logger.info("checked commits %s %s" % (repo_name, len(rev_list)))

        return matches_in_repo

    def checkByRevHash(self, rev_hash, repo_name, repo_id):
        matches_in_rev = []
        cwd = "%s/%s_%s/" % (self.WORKING_DIR, repo_name, repo_id)
        cmd = "git show --function-context %s" % rev_hash

        try:
            diff_output = subprocess.check_output(cmd.split(), cwd=cwd)
            lines = []
            filename = None
            # we ignore the first 3 lines which are commit info for sure
            for diff_line in diff_output.split("\n")[3:]:
                newfile = diff_line.startswith('diff --git a/')
                if newfile and filename is not None:
                    alerts = self.code_checker.check(lines, filename)
                    extended_alerts = [(alert[0], filename, rev_hash, alert[1], repo_name, repo_id) for alert in alerts]
                    matches_in_rev.extend(extended_alerts)
                    lines = []
                    filename = diff_line[12:diff_line.find(' b/')]
                elif newfile and filename is None:
                    filename = diff_line[12:diff_line.find(' b/')]
                    lines = []
                else:
                    lines.append(diff_line)
            if filename is not None:
                alerts = self.code_checker.check(lines, filename)
                extended_alerts = [(alert[0], filename, rev_hash, alert[1], repo_name, repo_id) for alert in alerts]
                matches_in_rev.extend(extended_alerts)
        except subprocess.CalledProcessError as e:
            self.logger.exception('Failed running: %s' % (cmd))

        return matches_in_rev

    def loadRepoListFromFile(self, filename):
        try:
            with open(filename) as repo_file:
                self.repoList = json.load(repo_file)
        except IOError:
            self.logger.info("repo_list.json not existing")

    def readAlertConfigFromFile(self):
        bare_rules = load_rules(self.ALERT_CONFIG_DIR)
        resolved_rules = build_resolved_ruleset(bare_rules)

        # filter for items in --alerts parameter
        applied_alerts = {aid: adata for aid, adata in resolved_rules.iteritems()
                          if not self.args.alerts or aid in self.args.alerts}

        self.code_checker = CodeCheckerFactory(applied_alerts).create()

    def putLock(self):
        lockfile = open(self.APP_DIR + "repoguard.pid", "w")
        lockfile.write(str(os.getpid()))
        lockfile.close()

    def releaseLock(self):
        os.remove(self.APP_DIR + "repoguard.pid")

    def isLocked(self):
        if os.path.isfile(self.APP_DIR + "repoguard.pid"):
            lockfile = open(self.APP_DIR + "repoguard.pid", "r")
            pid = lockfile.readline().strip()
            lockfile.close()

            if os.path.exists("/proc/%s" % pid):
                return True
            else:
                self.logger.error('Lock there but script not running, removing lock entering aborted state...')
                # email_notification = EmailNotifier(
                #     self.getConfigOptionValue("default_notification_src_address"),
                #     self.getConfigOptionValue("default_notification_to_address"),
                #     "[repoguard] invalid lock, entering aborted state",
                #     "Found lock with PID %s, but process not found... entering aborted state (someone should check the logs and restart manually!)")
                #
                # email_notification.send_if_fine()

                self.releaseLock()
                self.setAborted()
                return False
        else:
            self.logger.debug("pid file not found, not locked...")
            return False

    def setAborted(self):
        aborted_state_file = open(self.WORKING_DIR + "aborted_state.lock", "w")
        aborted_state_file.write('1')
        aborted_state_file.close()

    def isAborted(self):
        return os.path.isfile(self.WORKING_DIR + 'aborted_state.lock')

    def run(self):
        self.logger.info('* run started')
        repo_status_file = self.WORKING_DIR + 'repo_status.json'
        repo_list_file = self.WORKING_DIR + 'repo_list.json'

        # locking
        # if self.isAborted():
        #     self.logger.info('Aborted state, quiting!')
        #     return

        if self.isLocked():
            self.logger.info('Locked, script running... waiting.')
            return

        self.putLock()

        # skip online update by default (only if --refresh specified or status cache json files not exist)
        if self.args.refresh or not self.checkRepoStatusFile(repo_status_file):
            git_repo_updater_obj = GitRepoUpdater(self.org_name, self.config['github']['token'], repo_list_file, self.logger)
            git_repo_updater_obj.refreshRepoList()
            git_repo_updater_obj.writeRepoListToFile()

        # read repo status json file
        self.readRepoStatusFromFile(repo_status_file)

        # working from cached repo list file
        self.loadRepoListFromFile(repo_list_file)

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
        self.writeNewRepoStatusToFile(repo_status_file)

        self.releaseLock()

        self.logger.info("* run finished")


if __name__ == '__main__':
    RepoGuard().run()
