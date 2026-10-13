#!/bin/sh
# 05-coraza-check.sh: run by the official nginx entrypoint before nginx
# starts (/docker-entrypoint.d). Refuses to start with a rule set that
# does not compile, instead of starting a master with dead workers.
#
# It runs as the worker user: the parser opens the audit/debug logs and
# data files, and a root-owned file created here would later be
# unwritable by the workers.
set -eu
setpriv --reuid=nginx --regid=nginx --init-groups \
	/usr/local/bin/coraza-check /etc/nginx/coraza/main.conf
