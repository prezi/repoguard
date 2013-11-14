#!/bin/sh
#
# SupervisorD command/script that runs your service in the server. #cook#deploy#idoc
#
# Note: The service command shouldn't be a daemon process, thus it should run in the foreground.
# For more information you can look at (http://supervisord.org/subprocess.html#nondaemonizing-of-subprocesses)
#
# Using "exec" is needed so when supervisor restarts or stops your service it will stop your daemon process
# and not only the shell.

# EDITME

#exec python -m SimpleHTTPServer 8000