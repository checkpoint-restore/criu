#!/usr/bin/env python
# vim: noet ts=8 sw=8 sts=8

import pycriu
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
		print("%s magic %x error" % (imgf, me.magic))
		return False
	except Exception as e:
		print("%s %sdecode fails: %s" % (imgf, pretty and 'pretty ' or '', e))
		return False

	try:
		r_img = pycriu.images.dumps(pb)
	except Exception as e:
		r_img = pycriu.images.dumps(pb)
		print("%s %s encode fails: %s" % (imgf, pretty and 'pretty ' or '', e))
		return False

	if o_img != r_img:
		print("%s %s recode mismatch" % (imgf, pretty and 'pretty ' or ''))
		return False

	return True


for imgf in find.stdout.readlines():
	imgf = imgf.strip()
	imgf_b = os.path.basename(imgf)

	if imgf_b.startswith(b'pages-'):
		continue
	if imgf_b.startswith(b'iptables-'):
		continue
	if imgf_b.startswith(b'ip6tables-'):
		continue
	if imgf_b.startswith(b'route-'):
		continue
	if imgf_b.startswith(b'route6-'):
		continue
	if imgf_b.startswith(b'ifaddr-'):
		continue
	if imgf_b.startswith(b'tmpfs-'):
		continue
	if imgf_b.startswith(b'netns-ct-'):
		continue
	if imgf_b.startswith(b'netns-exp-'):
		continue
	if imgf_b.startswith(b'rule-'):
		continue

	o_img = open(imgf.decode(), "rb").read()
	if not recode_and_check(imgf, o_img, False):
		test_pass = False
	if not recode_and_check(imgf, o_img, True):
		test_pass = False

find.wait()

if not test_pass:
	print("FAIL")
	sys.exit(1)

print("PASS")
