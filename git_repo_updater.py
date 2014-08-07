#!/usr/bin/env python
# -*- coding: utf-8 -*-
import requests
import json
import ConfigParser
import re


class GitRepoUpdater:
    def __init__(self, org_name, github_token, repo_list_path, logger):
        self.REPO_LIST_PATH = repo_list_path
        self.api_url = 'https://api.github.com/orgs/%s/repos?access_token=%s' % (org_name, github_token)
        self.logger = logger

        self.actpage = 0
        self.lastpage = 0
        self.stop = False

        self.repo_list_cache = {}

    def refreshRepoList(self):
        while self.actpage <= self.lastpage and not self.stop:
            self.fetchRepoList("%s&page=%s" % (self.api_url, self.actpage))
            self.actpage += 1

    def fetchRepoList(self, url):
        try:
            self.logger.debug('Fetching %s...' % url)
            r = requests.get(url, verify=True)

            if (r.status_code == 200):
                if 'X-RateLimit-Remaining' in r.headers:
                    if int(r.headers['X-RateLimit-Remaining']) == 0:
                        print 'OUT OF RATELIMIT'
                        self.stop = True
                        return
                try:
                    lasturl_re = re.compile('.*<([\w\:\/\.]+)\?access_token=[^&]+&page=([0-9]+)>; rel="last"')
                    lasturl = lasturl_re.match(r.headers['link']).groups()
                    self.lastpage = int(lasturl[1])
                    print "PAGE %s/%s" % (self.actpage, self.lastpage)
                except:
                    print "... finished (PAGE: %s)" % self.actpage
                    print "(rate limit: %s / %s)" % (r.headers['X-RateLimit-Remaining'], r.headers['X-RateLimit-Limit'])
                repoItems = json.loads(r.text or r.content)
                for rItem in repoItems:
                    if rItem["name"] not in self.repo_list_cache:
                        self.repo_list_cache[rItem["id"]] = {"name": rItem["name"], "ssh_url": rItem["ssh_url"], "language": rItem["language"]}
            else:
                self.logger.error('github.com returned non-200 status code: %s' % r.text)
                self.stop = True
        except:
            self.logger.exception('Exception during HTTP request.')

    def writeRepoListToFile(self):
        filename = self.REPO_LIST_PATH
        with open(filename, 'w') as repo_file:
            json.dump(self.repo_list_cache, repo_file)
