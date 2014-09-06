import json
import jsonpickle
import logging
import subprocess


class RepositoryException(Exception):
    pass


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

    def add_status_info_from_json(self, repo_status_info_json):
        self.last_checked_commit_hashes = repo_status_info_json["last_checked_commit_hashes"]

    def add_commit_hash_to_checked(self, rev_hash):
        if rev_hash not in self.get_last_checked_commit_hashes():
            self.last_checked_commit_hashes.append(rev_hash)

    def get_last_commit_hashes(self):
        result = self.call_command("git rev-list --remotes --max-count=100")
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
        cmd = "git", "rev-list", "--remotes", "--since=\"%s\"" % since, "HEAD"
        try:
            cmd_output = subprocess.check_output(cmd, cwd=self.full_dir_path).split("\n")[:-1]
        except subprocess.CalledProcessError, e:
            error_msg = "Error when calling %s (cwd: %s): %s" % (repr(cmd), self.full_dir_path, e)
            self.logger.error(error_msg)
            cmd_output = []
        return cmd_output

    def git_reset_to_oldest_hash(self):
        if self.last_checked_commit_hashes:
            self.call_command("git reset --hard %s" % self.last_checked_commit_hashes[0])

    def git_clone(self):
        self.call_command("git clone %s %s" % (self.ssh_url, self.dir_name), cwd=self.working_directory)

    def call_command(self, cmd, cwd=None):
        cwd = self.full_dir_path if not cwd else cwd
        self.logger.debug("calling %s (cwd: %s)" % (cmd, cwd))
        try:
            cmd_output = subprocess.check_output(cmd.split(), cwd=cwd)
            return cmd_output
        except:
            self.logger.exception("Error when calling %s (cwd: %s)" % (cmd, cwd))
        return None

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
        self.create_repo_list_and_status_from_files()
        self.logger.debug("repository handler started")

    def create_repo_list_and_status_from_files(self):
        repo_list = self.load_repo_list_from_file()
        for repo_id, repo_data in repo_list.iteritems():
            self.repo_list[repo_id] = Repository(repo_id, repo_data, self.working_directory)

    def load_status_info_from_file(self):
        repo_status_info = self.load_repo_status_from_file()
        for repo_id, repo_data in self.repo_list.iteritems():
            if repo_status_info and repo_id in repo_status_info:
                self.get_repo_by_id(repo_id).add_status_info_from_json(repo_status_info[repo_id])

    def get_repo_list(self):
        return (v for k, v in self.repo_list.iteritems())

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
        with open(self.repo_status_file, 'w') as repo_status:
            repo_status.write(jsonpickle.encode(self.repo_list, unpicklable=False))
