import json
import jsonpickle
import logging
import subprocess
import sys


class Repository():
    def __init__(self, repo_id, repo_data_json, working_directory):
        self._status_json_attributes = ("name", "last_checked_commit_hashes")
        self.repo_id = repo_id
        self.name = repo_data_json["name"]
        self.working_directory = working_directory
        self.ssh_url = repo_data_json["ssh_url"]
        self.language = repo_data_json["language"]
        self.dir_name = '%s_%s' % (self.name, self.repo_id)
        self.full_dir_path = '%s%s' % (working_directory, self.dir_name)
        self.last_checked_commit_hashes = []
        self.not_checked_commit_hashes = []
        self.logger = logging.getLogger()

    def addStatusInfoFromJson(self, repo_status_info_json):
        self.last_checked_commit_hashes = repo_status_info_json["last_checked_commit_hashes"]

    def addCommitHashToChecked(self, rev_hash):
        if rev_hash not in self.last_checked_commit_hashes:
            self.last_checked_commit_hashes.append(rev_hash)

    def detectNewCommitHashes(self):
        try:
            last_commit_hashes = self.callCommand("git rev-list --remotes --max-count=100", raise_exception=True).split('\n')[:-1]
        except:
            last_commit_hashes = []
        for commit_sha in last_commit_hashes:
            if commit_sha not in self.last_checked_commit_hashes and commit_sha not in self.not_checked_commit_hashes:
                self.not_checked_commit_hashes.append(commit_sha)

    def getNotCheckedCommitHashes(self):
        return self.not_checked_commit_hashes

    def gitRevListSinceDate(self, since):
        cmd = "git", "rev-list", "--remotes", "--since=\"%s\"" % since, "HEAD"
        try:
            cmd_output = subprocess.check_output(cmd, cwd=self.full_dir_path).split("\n")[:-1]
        except subprocess.CalledProcessError, e:
            error_msg = "Error when calling %s (cwd: %s): %s" % (repr(cmd), self.full_dir_path, e)
            self.logger.error(error_msg)
            cmd_output = []
        return cmd_output

    def gitResetToOldestHash(self):
        if self.last_checked_commit_hashes:
            self.callCommand("git reset --hard %s" % self.last_checked_commit_hashes[0])

    def gitClone(self):
        self.callCommand("git clone %s %s" % (self.ssh_url, self.dir_name), cwd=self.working_directory)

    def callCommand(self, cmd, cwd=None, raise_exception=False):
        cmd_output = None
        cwd = self.full_dir_path if not cwd else cwd
        self.logger.debug("calling %s (cwd: %s)" % (cmd, cwd))
        try:
            cmd_output = subprocess.check_output(cmd.split(), cwd=cwd)
        except subprocess.CalledProcessError, e:
            error_msg = "Error when calling %s (cwd: %s): %s" % (cmd, cwd, e)
            self.logger.error(error_msg)
            if raise_exception:
                raise Exception(error_msg)
        return cmd_output

    def __getstate__(self):
        state = self.__dict__.copy()
        for attr in self.__dict__:
            if attr not in self._status_json_attributes:
                del state[attr]
        return state


class RepositoryHandler():
    def __init__(self, working_directory):
        self.logger = logging.getLogger()
        self.working_directory = working_directory
        self.repo_list_file = working_directory + 'repo_list.json'
        self.repo_status_file = working_directory + 'repo_status.json'
        self.repo_list = {}
        self.createRepoListAndStatusFromFiles()
        self.logger.debug("repository handler started")

    def createRepoListAndStatusFromFiles(self):
        repo_list = self.loadRepoListFromFile()
        repo_status_info = self.loadRepoStatusFromFile()
        for repo_id, repo_data in repo_list.iteritems():
            self.repo_list[repo_id] = Repository(repo_id, repo_data, self.working_directory)
            if repo_status_info and repo_id in repo_status_info:
                self.getRepoById(repo_id).addStatusInfoFromJson(repo_status_info[repo_id])

    def getRepoList(self):
        return (v for k, v in self.repo_list.iteritems())

    def getRepoById(self, repo_id):
        return self.repo_list[repo_id]

    def loadRepoStatusFromFile(self):
        try:
            with open(self.repo_status_file) as repo_status:
                return json.load(repo_status)
        except IOError:
            self.logger.info("repo status file %s doesn't exist" % self.repo_status_file)
            return {}

    def loadRepoListFromFile(self):
        try:
            with open(self.repo_list_file) as repo_list:
                return json.load(repo_list)
        except IOError:
            self.logger.critical("repo list file %s doesn't exist" % self.repo_list_file)
            return {}

    def saveRepoStatusToFile(self):
        with open(self.repo_status_file, 'w') as repo_status:
            repo_status.write(jsonpickle.encode(self.repo_list, unpicklable=False))
