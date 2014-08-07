import requests
import json
import ConfigParser
import re


class GitRepoUpdater:
    def __init__(self, github_token, repo_list_path):
        self.REPO_LIST_PATH = repo_list_path
        self.PREZI_URL = 'https://api.github.com/orgs/prezi/repos'
        self.TOKEN = github_token

        self.setToken(self.TOKEN)

        self.actpage = 1
        self.lastpage = 1
        self.stop = False

        self.repo_list_cache = {}

    def setToken(self, token_value):
        self.TOKEN = token_value
        self.url = self.PREZI_URL + "?access_token=" + self.TOKEN

    def refreshRepoList(self):
        while self.actpage <= self.lastpage and not self.stop:
            self.fetchRepoList()
            self.actpage += 1
            self.url = "%s?access_token=%s&page=%s" % (self.PREZI_URL, self.TOKEN, self.actpage)

    def fetchRepoList(self):
        r = requests.get(self.url, verify=True)
        print self.url
        if (r.status_code == 200):
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
                print "... finished (PAGE: %s)" % self.actpage
                print "(rate limit: %s / %s)" % (r.headers['X-RateLimit-Remaining'], r.headers['X-RateLimit-Limit'])
            repoItems = json.loads(r.text or r.content)
            for rItem in repoItems:
                if rItem["name"] not in self.repo_list_cache or self.repo_guard_obj.args.forcerefresh:
                    self.repo_list_cache[rItem["id"]] = {"name": rItem["name"], "ssh_url": rItem["ssh_url"], "language": rItem["language"]}
        else:
            print "REQUEST ERROR!"
            self.stop = True

    def writeRepoListToFile(self):
        filename = self.REPO_LIST_PATH
        with open(filename, 'w') as repo_file:
            json.dump(self.repo_list_cache, repo_file)
