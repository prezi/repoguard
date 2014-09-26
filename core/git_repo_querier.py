from github import Github

class GitRepoQuerier():
    def __init__(self, org_name, github_token):
        self.github_connection = Github(github_token)
        self.organization = self.github_connection.get_organization(org_name)

    def get_file_contents(self, repo, filename, commit_id):
        repo = self.organization.get_repo(repo)
        file_contents = repo.get_contents(filename, commit_id)
        return file_contents.decoded_content
