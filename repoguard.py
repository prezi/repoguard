#!/usr/bin/env python
# -*- coding: utf-8 -*-
import subprocess
import datetime
import argparse
import logging
import sys
from copy import deepcopy
from multiprocessing import Pool
import re
import os
import fnmatch
import itertools
from collections import defaultdict
from functools import partial
from hashlib import md5

import yaml
from mock import Mock

from lockfile import LockFile, LockTimeout

from core.datastore import DataStore, DataStoreException
from core.git_repo_updater import GitRepoUpdater
from core.codechecker import CodeCheckerFactory, Alert
from core.ruleparser import build_resolved_ruleset, load_rules
from core.notifier import EmailNotifier, EmailNotifierException
from core.repository_handler import RepositoryHandler, git_clone_or_pull


DEFAULT_EMAIL_TEMPLATE = None
EMAIL_TEMPLATES = {
    DEFAULT_EMAIL_TEMPLATE: (
        "[repoguard] possibly vulnerable changes - %(date)s",
        "The following change(s) might introduce new security risks:"
    ),
    'guidelines': (
        "[repoguard] guidelines might have been violated - %(date)s",
        "The following change(s) might not follow the repo's guidelines:"
    )
}

class RepoGuard:
    def __init__(self, instance_id="repoguard-app"):
        self.repo_list = {}
        self.repo_status = {}
        self.repo_status_new = {}
        self.check_results = []
        self.instance_id = instance_id
        self.es_type = "repoguard"
        self.worker_pool = Pool()
        self.logger = logging.getLogger('repoguard')

        self.parse_args()
        self.detect_paths()

        self.lock_handler = LockFile(self.WORKING_DIR)

    def parse_args(self):
        parser = argparse.ArgumentParser(description='Watch git repos for changes...')
        parser.add_argument('--config', '-c', default='etc/config.yml', help='Path to the config.yml file')
        parser.add_argument('--rule-dir', default='rules/', help='Path to the rule directory')
        parser.add_argument('--working-dir', default='../repos/', help='Path to the git repositories directory')
        parser.add_argument('--since', '-s', default=False,
                            help='Search for alerts in older git commits (git rev-list since, e.g. 2013-05-05 01:00)')
        parser.add_argument('--refresh', '-r', action='store_true', default=False,
                            help='Refresh repo list and locally stored repos from github api')
        parser.add_argument('--limit', '-l', default=False,
                            help='Limit checks only to run on the given repos (comma separated list)')
        parser.add_argument('--alerts', '-a', default=False,
                            help='Limit running only the given alert checks (comma separated list)')
        parser.add_argument('--nopull', action='store_true', default=False, help='No repo pull if set')
        parser.add_argument('--notify', '-N', action='store_true', default=False,
                            help='Notify pre-defined contacts via e-mail')
        parser.add_argument('--verbose', '-v', action="count", default=False, help='Verbose mode')
        parser.add_argument('--store', '-S', default=False, help='ElasticSearch node (host:port)')
        parser.add_argument('--sentry', default=None, help='Sentry url with user:pass (optional)')
        parser.add_argument('--ignorestatus', action='store_true', default=False,
                            help='If true repoguard will not skip commits which were already '
                                 'checked based on the status file')
        parser.add_argument('--overridelock', default=False,
                            help='Ignores the lock file so multiple repoguard can run in parallel')

        self.args = parser.parse_args()

        if self.args.limit:
            self.args.limit = self.args.limit.split(',')
        if self.args.alerts:
            self.args.alerts = self.args.alerts.split(',')

        if self.args.verbose:
            self.logger.setLevel(logging.DEBUG)
        else:
            self.logger.setLevel(logging.INFO)

        if self.args.sentry:
            from raven import Client
            from raven.handlers.logging import SentryHandler

            client = Client(self.args.sentry)
            handler = SentryHandler(client)
            handler.setLevel(logging.ERROR)
            self.logger.addHandler(handler)

    def detect_paths(self):
        self.APP_DIR = '%s/' % os.path.abspath(os.path.join(__file__, os.pardir, os.pardir))
        self.CONFIG_PATH = os.path.abspath(self.args.config)
        self.WORKING_DIR = os.path.abspath(self.args.working_dir) + '/'
        self.ALERT_CONFIG_DIR = os.path.abspath(self.args.rule_dir)

    def build_repo_groups(self, raw_repo_groups):
        repo_groups = {}
        for k, v in raw_repo_groups.iteritems():
            if isinstance(v, dict):  # node
                # TODO: traverse dict obj and expand @node references
                # repo_groups[k]  = add_node(k, v)
                pass
            elif isinstance(v, list):  # leaf
                repo_groups[k] = v
            else:
                raise ValueError('First level entries in repo_groups must be lists.')
        return repo_groups

    def read_config(self, path):
        try:
            with open(path) as f:
                config = yaml.load(f.read())
                self.default_notification_src_address = config['default_notification_src_address']
                self.default_notification_to_address = config['default_notification_to_address']
                self.detect_rename = config['git']['detect_rename']
                self.full_scan_triggered_rules = config.get('full_scan_triggered_rules', False)
                self.github_token = config['github']['token']
                self.notifications = config['notifications']
                self.org_name = config['github']['organization_name']
                self.repo_groups = self.build_repo_groups(config['repo_groups'])
                self.rules_to_groups = config['rules_to_groups']
                self.skipped_repos = config['skip_repo_list']
                self.smtp_host = config['smtp']['host']
                self.smtp_password = config['smtp']['password']
                self.smtp_port = config['smtp']['port']
                self.smtp_username = config['smtp']['username']
                self.subscribers = config['subscribers']
                self.use_tls = config['smtp']['use_tls']
        except KeyError as e:
            self.logger.exception('Key %s not found in config file' % e)
            sys.exit()
        except yaml.YAMLError:
            self.logger.exception("YAML Error while loading configuration file: %s" % path)
            sys.exit()
        except IOError:
            self.logger.exception("IO Error loading configuration file: %s" % path)
            sys.exit()

    def should_skip_by_name(self, repo_name):
        return (self.args.limit and repo_name not in self.args.limit) or repo_name in self.skipped_repos

    def set_up_repository_handler(self):
        self.repository_handler = RepositoryHandler(self.WORKING_DIR, self.logger)
        if not self.args.since:
            self.repository_handler.load_status_info_from_file()

    def update_local_repos(self):
        self.logger.debug('Updating local repositories.')
        existing_repo_dirs = os.listdir(self.WORKING_DIR)

        repos_to_update = [r for r in self.repository_handler.get_repo_list() if not self.should_skip_by_name(r.name)]

        self.worker_pool.map(partial(git_clone_or_pull, existing_repo_dirs, self.github_token), repos_to_update)

    def check_new_code(self, detect_rename=False):
        existing_repo_dirs = os.listdir(self.WORKING_DIR)

        repo_list = list(self.repository_handler.get_repo_list())
        self.logger.debug('Checking new commits for %d repositories.' % len(repo_list))
        for idx, repo in enumerate(repo_list):
            self.logger.info('Checking repo "%s/%s" (%d/%d) %2.2f%%' % (self.org_name, repo.name, idx, len(repo_list),
                                                                        float(idx) * 100 / len(repo_list)))
            if self.should_skip_by_name(repo.name):
                self.logger.debug('Skipping code check for %s' % repo.name)
            else:
                if repo.dir_name in existing_repo_dirs:
                    self.check_results += self.check_by_repo(repo, detect_rename=detect_rename)
                else:
                    self.logger.debug('Skip repo %s because directory doesnt exist' % repo.dir_name)

        if not self.args.notify:
            for alert in self.check_results:
                try:
                    print '\t'.join([
                        alert.rule.name, alert.repo.name, alert.commit, '%s:%d' % (alert.filename, alert.line_number),
                        alert.rule.description, alert.line[0:200].replace("\t", " ").decode('utf-8', 'replace')
                    ])
                except UnicodeEncodeError:
                    self.logger.exception('failed to get the details due to some unicode error madness')

    def store_results(self):
        (host, port) = self.args.store.split(":")
        data_store = DataStore(host=host, port=port, default_doctype="repoguard", default_index="repoguard")
        self.logger.info('Storing %d results to ES (%s).' % (len(self.check_results), data_store))
        for alert in self.check_results:
            try:
                body = {
                    "check_id": alert.rule.name,
                    "description": alert.rule.description,
                    "filename": alert.filename,
                    "commit_id": alert.commit,
                    "matching_line": alert.line[0:200].replace("\t", " ").decode('utf-8', 'replace'),
                    "line_number": alert.line_number,
                    "repo_name": alert.repo.name,
                    "repo_private": alert.repo.private,
                    "repo_fork": alert.repo.fork,
                    "@timestamp": datetime.datetime.utcnow().isoformat() + 'Z',
                    "type": self.es_type,
                    "false_positive": False,
                    "last_reviewer": self.es_type,
                    "author": alert.author,
                    "commit_description": alert.commit_description
                }

                data_store.store(body=body)
            except DataStoreException:
                self.logger.exception('Got exception during storing results to ES.')

    def alert_details_text(self, alert):
        check_id = alert.rule.name
        filename = alert.filename
        commit_id = alert.commit
        matching_line = alert.line[0:200].replace("\t", " ").decode('utf-8', 'replace')
        description = alert.rule.description

        return (u"check_id: %s \n"
                 "path: %s \n"
                 "commit: https://github.com/%s/%s/commit/%s?diff=split#diff-%sR%s\n"
                 "matching line: %s\n"
                 "description: %s\n"
                 "repo name: %s\n"
                 "repo is private: %s\n"
                 "repo is fork: %s\n"
                 "\n" % (check_id, filename, self.org_name, alert.repo.name,
                         commit_id, md5(filename).hexdigest(), alert.line_number, matching_line, description,
                         alert.repo.name, alert.repo.private, alert.repo.fork))


    def send_results(self):
        alert_per_notify_person = defaultdict(list)

        if not self.check_results:
            return False

        self.logger.info('### SENDING NOTIFICATION EMAIL ###')

        for alert in self.check_results:
            check_id = alert.rule.name

            notify_users = self.find_subscribed_users(check_id)
            self.logger.debug('notify_users %s' % repr(notify_users))
            for u in notify_users:
                alert_per_notify_person[u].append(alert)

            # no subscribed email, send it to default address
            if not notify_users:
                alert_per_notify_person[self.default_notification_to_address].append(alert)

        from_addr = self.default_notification_src_address
        smtp_conn_string = self.smtp_host + ":" + str(self.smtp_port)
        self.logger.debug('Notifiying them: %s', repr(alert_per_notify_person.keys()))
        for to_addr, alerts in alert_per_notify_person.iteritems():
            email_template = alerts[0].rule.email_template
            if not all(x.rule.email_template == email_template for x in alerts):
                # if each rule requests a different email template, we fall back to the default
                email_template = DEFAULT_EMAIL_TEMPLATE
            elif email_template not in EMAIL_TEMPLATES:
                email_template = DEFAULT_EMAIL_TEMPLATE

            subject, body_intro = EMAIL_TEMPLATES[email_template]
            subject = subject % {'date': datetime.datetime.now().strftime("%Y-%m-%d %H:%M")}

            body_details = ''.join(self.alert_details_text(x) for x in alerts)
            body_text = body_intro + "\n\n" + body_details

            email_notification = EmailNotifier.create_notification(from_addr, to_addr, subject, body_text,
                                                                   smtp_conn_string,
                                                                   self.smtp_username,
                                                                   self.smtp_password,
                                                                   self.use_tls)
            try:
                email_notification.send_if_fine()
            except EmailNotifierException, e:
                self.logger.exception("Error while sending email: " + str(e))

    def find_subscribed_users(self, alert):
        matching_subscriptions = [users for pattern, users in self.subscribers.iteritems()
                                  if fnmatch.fnmatch(alert, pattern)]
        return set(itertools.chain(*matching_subscriptions))

    def check_by_repo(self, repo, detect_rename=False):
        matches_in_repo = []

        if self.args.since:
            rev_list_to_check = repo.get_rev_list_since_date(self.args.since)
        else:
            if self.args.ignorestatus:
                rev_list_to_check = repo.get_last_commit_hashes()
            else:
                repo.detect_new_commit_hashes()
                rev_list_to_check = repo.get_not_checked_commit_hashes()

        for rev_hash in rev_list_to_check:
            repo.add_commit_hash_to_checked(rev_hash)
            rev_result = self.check_by_rev_hash(rev_hash, repo, detect_rename)
            if rev_result:
                matches_in_repo = matches_in_repo + rev_result
        if len(rev_list_to_check) > 0:
            self.logger.info("checked commits %s %s" % (repo.name, len(rev_list_to_check)))
        if len(matches_in_repo) > 0:
            self.logger.info("found matches %s %s" % (repo.name, len(matches_in_repo)))

        return matches_in_repo

    def check_by_rev_hash(self, rev_hash, repo, detect_rename=False):
        matches_in_rev = []
        cmd = "git show --function-context %s%s" % ('-M100% ' if detect_rename else '--no-renames ', rev_hash)

        try:
            diff_output = subprocess.check_output(cmd.split(), cwd=repo.full_dir_path)
            author = diff_output.split("Author: ")[1].split("\n")[0]
            splitted = re.split(r'^diff --git a/\S* b/(\S+)$', diff_output, flags=re.MULTILINE)[1:]
            commit_description_cmd = "git log --pretty=%s -n 1 " + rev_hash
            commit_description = subprocess.check_output(commit_description_cmd.split(),
                                                         cwd=repo.full_dir_path).rstrip()

            def create_alert(rule, vuln_line, diff, diff_first_line):
                def get_vuln_line_number():
                    curr_line = diff_first_line
                    for line in diff.splitlines():
                        if line == vuln_line:
                            return curr_line
                        if len(line) > 0 and line[0] != '-':
                            curr_line += 1
                    return 0

                return Alert(rule, filename, repo, rev_hash, line, get_vuln_line_number(), author, commit_description)

            for i in xrange(len(splitted) / 2):
                filename = splitted[i * 2]
                raw_diff = splitted[i * 2 + 1]
                match = re.split(r'^@@ -\d+(?:|,\d+) \+(?P<line_no>\d+)(?:|,\d+) @@.*\n', raw_diff, maxsplit=1,
                                 flags=re.MULTILINE)
                if match and len(match) == 3:
                    diff_first_line = int(match[1])
                    diff = match[2]
                else:
                    if 'Binary files ' not in raw_diff and 'rename from' not in raw_diff and 'new file mode' not in raw_diff:
                        self.logger.warning('Was not able to parse unified diff header for diff: %s, match: %s',
                                            repr(raw_diff), match)
                    diff = raw_diff
                    diff_first_line = 0

                check_context = {
                    "filename": filename,
                    "author": author,
                    "commit_message": commit_description
                }
                result = self.code_checker.check(diff.split('\n'), check_context, repo)
                alerts = [create_alert(rule, line, diff, diff_first_line) for rule, line in result]

                matches_in_rev.extend(alerts)
        except (subprocess.CalledProcessError, OSError) as e:
            self.logger.exception('Failed running: %s' % cmd)

        return matches_in_rev

    def read_alert_config_from_file(self):
        bare_rules = load_rules(self.ALERT_CONFIG_DIR)
        resolved_rules = build_resolved_ruleset(bare_rules)

        # filter for items in --alerts parameter
        applied_alerts = {aid: adata for aid, adata in resolved_rules.iteritems()
                          if not self.args.alerts or aid in self.args.alerts}

        # self.logger.debug('applied_alerts: %s' % repr(applied_alerts))
        self.code_checker = CodeCheckerFactory(applied_alerts, self.repo_groups, self.rules_to_groups).create()

    def launch_full_repoguard_scan_on_repo(self, repo_name):
        self.logger.info("Spawning a new repoguard for %s " % (repo_name))
        full_scan_repoguard = RepoGuard("full_scan_%s" % repo_name)
        full_scan_repoguard.args = deepcopy(self.args)
        full_scan_repoguard.args.overridelock = True
        full_scan_repoguard.args.refresh = False
        full_scan_repoguard.args.nopull = False
        full_scan_repoguard.args.ignorestatus = True
        full_scan_repoguard.args.since = "1970-01-01"
        full_scan_repoguard.args.limit = [repo_name]
        full_scan_repoguard.args.alerts = self.full_scan_triggered_rules
        full_scan_repoguard.es_type = "repoguard_fullscan"
        full_scan_repoguard.run()

    def check_and_alert_on_new_repos(self, git_repo_updater_obj):
        new_public_repo_list = git_repo_updater_obj.refresh_repos_and_detect_new_public_repos()
        self.logger.info('New public repos: %s', new_public_repo_list)
        git_repo_updater_obj.write_repo_list_to_file()

        new_public_rule = Mock()
        new_public_rule.name = 'internal::new_public_repo'
        new_public_rule.description = 'This repository has been made public, please check for sensitive info!'

        for new_public_repo_json in new_public_repo_list:
            repo_obj = Mock()
            repo_obj.name = new_public_repo_json['name']
            repo_obj.private = new_public_repo_json['private']
            repo_obj.fork = new_public_repo_json['fork']
            self.launch_full_repoguard_scan_on_repo(repo_obj.name)
            self.check_results += [
                Alert(rule=new_public_rule, filename='', repo=repo_obj, commit='', line='', line_number=0)]

    def try_to_lock(self):
        try:
            self.lock_handler.acquire(timeout=3)
            self.logger.debug("Pid file not found, creating %s..." % self.lock_handler.path)
        except LockTimeout as e:
            self.logger.critical('Locked, script running... exiting.')
            if self.notifications:
                email_notification = EmailNotifier(
                    self.default_notification_src_address,
                    self.default_notification_to_address,
                    "[repoguard] lock file found (another process is runnning?)",
                    str(e))

                email_notification.send_if_fine()
            sys.exit()

    def run(self):
        self.logger.info('* run started')
        self.logger.debug('Called with arguments: %s' % self.args)

        self.read_config(self.CONFIG_PATH)

        self.try_to_lock()
        self.read_alert_config_from_file()
        self.set_up_repository_handler()

        if self.args.refresh or not self.repository_handler.get_repo_list():
            git_repo_updater_obj = GitRepoUpdater(self.org_name, self.github_token,
                                                  self.repository_handler.repo_list_file, self.logger)
            if self.full_scan_triggered_rules:
                # this is a run triggered by another repoguard
                self.check_and_alert_on_new_repos(git_repo_updater_obj)
            else:
                git_repo_updater_obj.refresh_repo_list()
                git_repo_updater_obj.write_repo_list_to_file()
                # TODO: it should not be necessary...
                self.repository_handler.create_repo_list_and_status_from_files()

        if not self.args.nopull:
            self.update_local_repos()

        self.check_new_code(self.detect_rename)

        if self.args.notify:
            self.send_results()

        if self.args.store:
            self.store_results()

        if not self.args.since:
            self.repository_handler.save_repo_status_to_file()

        self.logger.info("* run finished")
        self.lock_handler.release()


if __name__ == '__main__':
    logging.basicConfig(format='%(asctime)s %(processName)-10s %(name)s %(levelname)-8s %(message)s',
                        level=logging.DEBUG)
    RepoGuard().run()
