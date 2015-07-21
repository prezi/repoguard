import json
import logging
import os
from collections import OrderedDict
import subprocess
import shutil


module_logger = logging.getLogger("repoguard.repository_handler")


class RepositoryException(Exception):
    pass


def git_clone_or_pull(existing_repo_dirs, github_token, repo):
    if repo.dir_name in existing_repo_dirs:
        repo.git_reset_to_oldest_hash()
        if not repo.git_pull(github_token):
            # if there was any error on pulling, let's reclone the directory
            module_logger.debug('Git pull failed, reclone repository.')
            repo.remove()
            repo.git_clone(github_token)
    else:
        module_logger.debug('Repository not in existing repo dirs, cloning it.')
        repo.git_clone(github_token)

    repo.detect_new_commit_hashes()


class Repository():
    def __init__(self, repo_id, github_repo_json_response, working_directory, logger):
        self._status_json_attributes = ("name", "last_checked_commit_hashes")
        self.repo_id = repo_id
        self.name = github_repo_json_response["name"]
        self.working_directory = working_directory
        self.url_with_token = github_repo_json_response["url_with_token"]
        self.language = github_repo_json_response["language"]
        self.fork = github_repo_json_response["fork"]
        self.private = github_repo_json_response["private"]
        self.dir_name = '%s_%s' % (self.name, self.repo_id)
        self.full_dir_path = '%s%s' % (working_directory, self.dir_name)
        self.last_checked_commit_hashes = []
        self.not_checked_commit_hashes = []
        self.logger = logging.getLogger('repository_handler.Repository')

    def add_status_info_from_json(self, repo_status_info_json):
        self.last_checked_commit_hashes = repo_status_info_json["last_checked_commit_hashes"]

    def add_commit_hash_to_checked(self, rev_hash):
        if rev_hash not in self.get_last_checked_commit_hashes():
            self.last_checked_commit_hashes.append(rev_hash)

    def get_last_commit_hashes(self):
        result = self.call_command("git rev-list --remotes --no-merges --max-count=100 HEAD")
        return result.split('\n')[:-1] if result is not None else []

    def detect_new_commit_hashes(self):
        for commit_sha in self.get_last_commit_hashes():
            if commit_sha not in self.get_last_checked_commit_hashes() \
                    and commit_sha not in self.get_not_checked_commit_hashes():
                self.not_checked_commit_hashes.append(commit_sha)

    def get_last_checked_commit_hashes(self):
        return self.last_checked_commit_hashes

    def get_not_checked_commit_hashes(self):
        return self.not_checked_commit_hashes

    def get_rev_list_since_date(self, since):
        cmd = "git", "rev-list", "--remotes", "--no-merges", "--since=\"%s\"" % since, "HEAD"
        try:
            return subprocess.check_output(cmd, cwd=self.full_dir_path).split("\n")[:-1]
        except subprocess.CalledProcessError, e:
            error_msg = "Error when calling %s (cwd: %s): %s" % (repr(cmd), self.full_dir_path, e)
            self.logger.error(error_msg)
        return []

    def git_reset_to_oldest_hash(self):
        if self.last_checked_commit_hashes:
            self.call_command("git reset --hard %s" % self.last_checked_commit_hashes[0])

    def git_clone(self, token):
        # using git pull to avoid storing the token in .git/config
        # see: https://github.com/blog/1270-easier-builds-and-deployments-using-git-over-https-and-oauth
        os.mkdir(self.full_dir_path)
        self.call_command('git init')
        self.call_command("git pull %s" % (self.url_with_token % token), cwd=self.full_dir_path)

    def git_pull(self, token):
        return self.call_command("git pull %s" % (self.url_with_token % token), cwd=self.full_dir_path)

    def remove(self):
        try:
            shutil.rmtree(self.full_dir_path)
        except:
            self.logger.exception('Failed to remove repo_dir: %s', self.full_dir_path)

    def call_command(self, cmd, cwd=None):
        cwd = self.full_dir_path if not cwd else cwd
        self.logger.debug("Calling %s (cwd: %s)" % (cmd, cwd))
        try:
            cmd_output = subprocess.check_output(cmd.split(), cwd=cwd)
            return cmd_output
        except:
            self.logger.exception("Error when calling %s (cwd: %s)" % (cmd, cwd))
        return None

    def to_dict(self):
        state = self.__dict__.copy()
        for attr in self.__dict__:
            if attr not in self._status_json_attributes:
                del state[attr]
        return state

    def __getstate__(self):
        state = self.__dict__.copy()
        for attr in self.__dict__:
            if attr in ['logger']:
                del state[attr]
        return state

    def __setstate__(self, state):
        # Restore instance attributes (i.e., filename and lineno).
        self.__dict__.update(state)
        # Restore the previously opened file's state. To do so, we need to
        # reopen it and read from it until the line count is restored.
        self.logger = logging.getLogger('repository_handler.Repository')


class RepositoryHandler():
    def __init__(self, working_directory, logger):
        self.logger = logger
        self.working_directory = working_directory
        self.repo_list_file = working_directory + 'repo_list.json'
        self.repo_status_file = working_directory + 'repo_status.json'
        self.repo_list = OrderedDict()
        self.create_repo_list_and_status_from_files()
        self.logger.debug("Repository handler started")

    def create_repo_list_and_status_from_files(self):
        repo_list = self.load_repo_list_from_file()
        for repo_id, repo_data in sorted(repo_list.iteritems(), key=lambda r: r[1]['name']):
            try:
                self.repo_list[repo_id] = Repository(repo_id, repo_list[repo_id], self.working_directory, self.logger)
            except KeyError:
                self.logger.exception('Got KeyError during Repository instantiation.')

    def load_status_info_from_file(self):
        repo_status_info = self.load_repo_status_from_file()
        for repo_id, repo_data in self.repo_list.iteritems():
            if repo_status_info and repo_id in repo_status_info:
                self.get_repo_by_id(repo_id).add_status_info_from_json(repo_status_info[repo_id])

    def get_repo_list(self):
        return self.repo_list.values()

    def get_repo_by_id(self, repo_id):
        return self.repo_list[repo_id]

    def load_repo_status_from_file(self):
        try:
            with open(self.repo_status_file) as repo_status:
                return json.load(repo_status)
        except IOError:
            self.logger.info("repo status file %s doesn't exist" % self.repo_status_file)
            return {}

    def load_repo_list_from_file(self):
        try:
            with open(self.repo_list_file) as repo_list:
                return json.load(repo_list)
        except IOError:
            self.logger.critical("repo list file %s doesn't exist" % self.repo_list_file)
            return {}

    def save_repo_status_to_file(self):
        if not self.repo_list:
            self.logger.warning('Got empty repository list, not updating status file!')
            return

        with open(self.repo_status_file, 'w') as repo_status:
            json.dump({k: v.to_dict() for k, v in self.repo_list.iteritems()}, repo_status, indent=4, sort_keys=True)
