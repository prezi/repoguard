#!/usr/bin/env python
# -*- coding: utf-8 -*-
import requests
import requests.exceptions
import json
import re


class GitRepoUpdater:
    def __init__(self, org_name, github_token, repo_list_path, logger):
        self.REPO_LIST_PATH = repo_list_path
        self.api_url = 'https://api.github.com/orgs/%s/repos' % (org_name)
        self.request_headers = {'Authorization': 'token %s' % github_token}
        self.repo_attributes_to_store = ('name', 'ssh_url', 'language', 'private', 'fork')
        self.logger = logger

        self.actpage = 0
        self.lastpage = 0
        self.stop = False

        self.repo_list_cache = {}

    def refresh_repo_list(self):
        while self.actpage <= self.lastpage and not self.stop:
            self.fetch_repo_list("%s?page=%s" % (self.api_url, self.actpage))
            self.actpage += 1

    def get_repo_attributes_from_repo_json_obj(self, repo_json_obj):
        repo_info_to_store = {}
        for repo_attribute in self.repo_attributes_to_store:
            repo_info_to_store[repo_attribute] = repo_json_obj[repo_attribute]
        return repo_info_to_store

    def store_repo_attributes_from_response_json(self, response_json):
        for repo in response_json:
            repo_id = str(repo["id"])
            if repo_id not in self.repo_list_cache:
                self.repo_list_cache[repo_id] = self.get_repo_attributes_from_repo_json_obj(repo)

    def fetch_repo_list(self, url):
        try:
            self.logger.debug('Fetching %s...' % url)
            r = requests.get(url, verify=True, headers=self.request_headers)

            if r.status_code == 200:
                if 'X-RateLimit-Remaining' in r.headers:
                    if int(r.headers['X-RateLimit-Remaining']) == 0:
                        print 'OUT OF RATELIMIT'
                        self.stop = True
                        return
                try:
                    lasturl_re = re.compile('.*<([\w\:\/\.]+)\?page=([0-9]+)>; rel="last"')
                    lasturl = lasturl_re.match(r.headers['link']).groups()
                    self.lastpage = int(lasturl[1])
                    print "PAGE %s/%s" % (self.actpage, self.lastpage)
                # TODO (KR): this is too broad. figure out what needs to be caught.
                except:
                    print "... finished (PAGE: %s)" % self.actpage
                    print "(rate limit: %s / %s)" % (r.headers['X-RateLimit-Remaining'], r.headers['X-RateLimit-Limit'])
                self.store_repo_attributes_from_response_json(json.loads(r.text or r.content))
            else:
                self.logger.error('github.com returned non-200 status code: %s' % r.text)
                self.stop = True
        except requests.exceptions.RequestException:
            self.logger.exception('Exception during HTTP request.')

    def write_repo_list_to_file(self):
        with open(self.REPO_LIST_PATH, 'w') as repo_file:
            json.dump(self.repo_list_cache, repo_file)

    def read_repo_list_from_file(self):
        with open(self.REPO_LIST_PATH, 'r') as repo_file:
            return json.load(repo_file)

    def refresh_repos_and_detect_new_public_repos(self):
        new_public_repos = []
        self.refresh_repo_list()
        original_repo_status = self.read_repo_list_from_file()
        for repo_id in self.repo_list_cache:
            if self.repo_list_cache[repo_id]["private"] == False:
                if repo_id not in original_repo_status:
                    self.logger.debug("Totally new public repo %s" % self.repo_list_cache[repo_id]["name"])
                    new_public_repos.append(self.repo_list_cache[repo_id])
                elif original_repo_status[repo_id]["private"] == True:
                    self.logger.debug("Previously private repo set to public %s" % self.repo_list_cache[repo_id]["name"])
                    new_public_repos.append(self.repo_list_cache[repo_id])
        return new_public_repos