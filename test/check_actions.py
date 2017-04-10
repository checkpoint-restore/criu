#!/usr/bin/env python2

import sys
import os

actions = set(['pre-dump', 'pre-restore', 'post-dump', 'setup-namespaces', \
		'post-setup-namespaces', 'post-restore', 'post-resume', \
		'network-lock', 'network-unlock' ])
errors = []
af = os.path.dirname(os.path.abspath(__file__)) + '/actions_called.txt'

for act in open(af):
	act = act.strip().split()
	act.append('EMPTY')
	act.append('EMPTY')

	if act[0] == 'EMPTY':
		raise Exception("Error in test, bogus actions line")

	if act[1] == 'EMPTY':
		errors.append('Action %s misses CRTOOLS_IMAGE_DIR' % act[0])

	if act[0] in ('post-dump', 'setup-namespaces', 'post-setup-namespaces', \
			'post-restore', 'post-resume', 'network-lock', 'network-unlock'):
		if act[2] == 'EMPTY':
			errors.append('Action %s misses CRTOOLS_INIT_PID' % act[0])
		elif not act[2].isdigit() or int(act[2]) == 0:
			errors.append('Action %s PID is not number (%s)' % (act[0], act[2]))

	actions -= set([act[0]])

if actions:
	errors.append('Not all actions called: %r' % actions)

if errors:
	for x in errors:
		print x
	sys.exit(1)

print 'PASS'
