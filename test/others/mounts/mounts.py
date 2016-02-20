import os
import tempfile, random

def mount(src, dst, shared, private, slave):
	cmd = "mount"
	if shared:
		cmd += " --make-shared"
	if private:
		cmd += " --make-private"
	if slave:
		cmd += " --make-slave"
	if src:
		cmd += " --bind '%s' '%s'" % (src, dst)
	else:
		cmd += " -t tmpfs none '%s'" % (dst)

	print cmd
	ret = os.system(cmd)
	if ret:
		print "failed"

root = tempfile.mkdtemp(prefix = "root.mount", dir = "/tmp")
mount(None, root, 1, 0, 0)
mounts = [root]

for i in xrange(10):
	dstdir = random.choice(mounts)
	dst = tempfile.mkdtemp(prefix = "mount", dir = dstdir)
	src = random.choice(mounts + [None])
	mount(src, dst, random.randint(0,100) > 50, random.randint(0,100) > 90, random.randint(0,100) > 50)
	mounts.append(dst)
