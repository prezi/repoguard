# Repoguard

Repoguard is a simple generic tool to check and alert on any change in git repositories which might be interesting for you.

We created repoguard to help us (the security team at Prezi) to detect changes which might lead to security issues in the high amount of commits and repositories we have.

It can track all the repositories in a Github organization and send email (or store the result in Elasticsearch)
if it founds a dangerous or interesting line. It uses an easily extendable ruleset (regular expressions) with
existing rules for languages like Python, Java, Javascript, C(++), Chef or Scala.

We encourage everyone to add new rules or improve the existing ones! :)

## Repominer

Repominer is the little brother of Repoguard. It can be used to check a local directory for dangerous lines. We believe it could be useful for security code reviews, where you don't have to care about previous commits, but just the current state.
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

## Usage

Syncing with Github API (--refresh), pulling changes and alerting in mail (--notify):
```
python repoguard.py --refresh --notify --working-dir ../repos/
```

Pulling new changes, checking for alerts and notifying in mail (--notify) + send results to ElasticSearch (--store):
```
python repoguard.py --notify --store elasticsearch.host:9200 --working-dir ../repos/
```

Don't pull new changes (--nopull), check for alerts since given time (--since):
```
python repoguard.py --nopull --since "2014-08-12 03:00" --working-dir ../repos/
```

Pull new changes and check commits which were already checked (--ignorestatus) with custom rules defined in directory "custom_rules" (--rule-dir):
```
python repoguard.py --ignorestatus --rule-dir ../custom_rules --working-dir ../repos/
```

Don't pull new changes (--nopull) only for repository "foobaar" and "starfleet" (--limit) and check all allerts defined in "xss.yml" and "xxe.yml" (--alerts) since long-long time ago (--since):
```
python repoguard.py --nopull --limit "foobaar,starfleet" --alerts "xss::*,xxe::*" --since "2010-01-01" --working-dir ../repos/

```

## The configuration file

Repoguard needs a Github API token (can be generated on Github's settings page) in order to be able to fetch
the repositories of your organization. It has to be defined in the config file:
```
github:
    token: "<github_api_token>"
    organization_name: "<your_github_organization_name>"
```

It is possible to send specific alerts to specific email addresses, therefore it is possible to define
custom rules which is only interesting for a subset of people (e.g. our data team has their own rules
for detecting changes in the log format).

## Creating rules

We've shared most of our rules within the "rules" folder of this repository, but of course you can create your own ones as well (if you do so, we are happy to receive pull requests ;)). The rule files are pretty self explaining yaml files, however let's see an example and clarify what kind of things are possible.

### namespaces

Repoguard will read all "yml" files recursively in the directory you define with the "--rule-dir" argument. Each yml rule file will have its own namespace (based on the filename). For example xss.yml rules will be under the xss:: namespace.

### abstract rules

You can create abstract rules, which you can later use to set some defaults / extend other rules. All sections starting with ```#!~```` are handled as abstract rules, these won't run automatically (but you will be able to refer to them):

```
--- #!~base
description: "Unescaped user input might lead to Cross-site scripting issues, please ensure that input can only come from trusted sources"
extends: whitelisted_files::whitelisted_files,comments::comments
```

### basic rule - simple line matching

The following simple rule will extend the base abstract rule (inherit its settigns like description) and detect any change which adds a new line containing the string "|safe" or "{% autoescape off %}". 

```
--- #!django
extends: base
diff: add
line:
    - match: \|safe
    - match: "{% autoescape off %}"
```

Possible options for "diff" are:

- all (default): no restrictions on the git diff, since we get the context as well it can match on anything within the context of the change (like method name / class name)
- add: the diff line starts with +
- del: the diff line starts with -
- mod: the diff line starts with + or -

Possible options for "line":
- match: alert if the line contains the given regex
- except: don't alert if the line contains the given regex (even if it matched any "match" line rules)

There is an "or" condition between the different "match" regex patterns, there is an "or" condition between the different "except" regex pattern and an "and" condition between the "match" and "except" groups.

### advanced rule - line and file name matching

The following rule will alert if the newly introduced code ("diff: add") matches the given regex (```(WebSocket|\.listen\(|http\.request|socket\.io).*```) except if it matches ```EventListener\.```. The rule will only check code if the file name matches ```.*\.(hx|js)$``` (hs or js file extension).

```
--- #!js_network_listen
extends: base
diff: add
line:
    - match: (WebSocket|\.listen\(|http\.request|socket\.io).*
    - except: EventListener\.
file:
    - match: .*\.(hx|js)$
```

### matching on context

The following rule will alert if there were any changes within any method (line starts with "def") containing the string "auth" or "login" in any .py file except those which's filename contain the string "test":

```
extends: base
diff: any
line:
    - match: \s+def.*(auth|login).*
file:
    - match: .*\.py$
    - except: .*test.*
```

### matching within script tags

To detect possibly exploitable XSS attacks it is important to know if the matching line is within a script tag or not. The reason is simple: some frameworks do decent job in escaping strings in template files, however within a script tag the default escaping might not be enough. The following rule will alert if the added line contains {{SOMETHING except urlencode}}. In django the double curly brackets refer to a template variable, which if comes from a user supplied input proper escaping would be cruicial:

```
--- #!django_inscripttags
extends: base
diff: add
line:
    - match: "{{((?!urlencode).)+}}"
inscripttag: true
```

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
from Github). The alerts are sent to ElasticSearch and then an internal tool creates Trac tickets from them but
for a long time we received the alerts via email which was a feasible workflow as well.

## How can you contribute?

Extend or fine-tune the ruleset, improve the code or the documentation and send a pull request!
Tests are highly appreciated.
