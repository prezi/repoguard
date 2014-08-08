# Repoguard

Repoguard is a simple tool to check and alert on interesting changes in a git repository.
It can track all the repositories in a Github organization and send email (or store the result in Elasticsearch)
if it founds a dangerous or interesting line. It uses an easily extendable ruleset (regular expressions) with
existing rules for languages like Python, Java, Javascript, C(++), Chef or Scala.

We encourage everyone to add new rules or improve the existing ones! :)

## Repominer

Repominer is the little brother of Repoguard. It can be used to check a local directory for dangerous lines.
It uses the same ruleset and configuration.

## Installation

Installing and running the project is pretty simple:

```
$ virtualenv virtualenv
$ . virtualenv/bin/activate
$ pip install -r requirements.txt
$ python repoguard.py --config <file> --working-dir '../repos' --since '2014-08-01 00:00:00' --refresh
```

And setup a cron job which calls this script periodically.

## The configuration file

Repoguard needs a Github API token (can be generated on Github's settings page) in order to be able to fetch
the repositories of your organization. It has to be defined in the config file:
```
github:
    token: "<github_api_token>"
    organization_name: "<your_github_organization_name>"
```

It is possible to send specific alerts to specific email addresses, therefore it is possible to define
custom rules which is only interesting for a subset of people (e.g. our data team defined).

## The status file

This file is used to store the status between each run so Repoguard knows which commits to check and does not alert
on the same change twice.

## Project layout

```
[project dir]
\- core          (core files)
\- etc           (configuration files)
\- rules         (rule files)
\- tests         (unit tests)
\- repoguard.py  (repoguard executable)
\- repominer.py  (repominer executable)
```

## How do we use it at Prezi?

We run it periodically every 10 minutes and also every hour with the ```--refresh``` option (which fetches new repositories
from Github). The alerts are sent to ElasticSearch and then an internal tool creates Trac tickets from them but for a long time we received the alerts via email which was a feasible workflow as well.

## Do you want to contribute?

Extend or fine-tune the ruleset, improve the code or the documentation and send a pull request!
Tests are highly appreciated.
