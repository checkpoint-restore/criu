#!/bin/env python2

import py as pycriu
import sys
import os
import subprocess

find = subprocess.Popen(['find', 'test/dump/', '-size', '+0', '-name', '*.img'],
		stdout = subprocess.PIPE)

test_pass = True

def recode_and_check(imgf, o_img, pretty):
	try:
		pb = pycriu.images.loads(o_img, pretty)
	except pycriu.images.MagicException as me:
		print "%s magic %x error" % (imgf, me.magic)
		return False
	except:
		print "%s %sdecode fails" % (imgf, pretty and 'pretty ' or '')
		return False

	try:
		r_img = pycriu.images.dumps(pb)
	except:
		print "%s %sencode fails" % (imgf, pretty and 'pretty ' or '')
		return False

	if o_img != r_img:
		print "%s %srecode mismatch" % (imgf, pretty and 'pretty ' or '')
		return False

	return True


for imgf in find.stdout.readlines():
	imgf = imgf.strip()
	imgf_b = os.path.basename(imgf)

	if imgf_b.startswith('pages-'):
		continue
	if imgf_b.startswith('iptables-'):
		continue
	if imgf_b.startswith('ip6tables-'):
		continue
	if imgf_b.startswith('route-'):
		continue
	if imgf_b.startswith('route6-'):
		continue
	if imgf_b.startswith('ifaddr-'):
		continue
	if imgf_b.startswith('tmpfs-'):
		continue
	if imgf_b.startswith('netns-ct-'):
		continue
	if imgf_b.startswith('netns-exp-'):
		continue
	if imgf_b.startswith('rule-'):
		continue

	o_img = open(imgf).read()
	if not recode_and_check(imgf, o_img, False):
		test_pass = False
	if not recode_and_check(imgf, o_img, True):
		test_pass = False

find.wait()

if not test_pass:
	print "FAIL"
	sys.exit(1)

print "PASS"
