#!/usr/bin/env python

## Example provisioner script.
##
## This script is called by the following pam.conf entry:
## sshd-kbdint account required pam_provision.so.1 exec=/tmp/provision.py %u %s %m
##
## The "exec=" parameter MUST be the last option, since it implies
## extra arguments to the provisioner script.  Those arguments are
## expanded as follows:
##
## %u   authenticating user
## %s   service user has authenticated under (login, sshd-kbdint, etc)
## %m   pam module class (account, session, etc)
## %h   host name being authenticated to
## %r   remote host being logged in from (for applicable services)
## %%   percent sign
##
## If you do not know what service to use, try "other" and watch your logs
## to see what service is identified by a login attempt.
##
## pam_provision.so collects output from this script and sends it to syslog.
##

import os
import sys
import pwd


def main(prog, args):
	# Assume arguments "%u %s %m"
	user, service, module = args

	# Get pw entry for user, or fail
	p = pwd.getpwnam(user)
	if p is None:
		print >>sys.stderr, "cannot look up user %s" % user
		return 10

	# Check whether home dir exists
	if os.path.exists(p.pw_dir):
		print "%s:%s (%s) home directory %s exists" % \
		      (user, module, service, p.pw_dir)
		return 0

	# If not, create it with mode 0750
	os.mkdir(p.pw_dir, 0750)
	os.chown(p.pw_dir, p.pw_uid, p.pw_gid)
	print "%s:%s (%s) home directory %s created" % \
	      (user, module, service, p.pw_dir)

	# You can populate it with a skeleton here, if you wish.  See
	# the python module 'shutil' for an easy approach.


# Run the main() function, exiting with its return value
if __name__ == '__main__':
	sys.exit(main(sys.argv[0], sys.argv[1:]))
