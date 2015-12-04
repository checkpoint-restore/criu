#!/usr/bin/env python
# vim: noet
import argparse
import os
import subprocess
import time
import tempfile
import shutil
import re
import stat
import signal
import atexit
import sys
import linecache
import random
import string
import imp
import socket
import fcntl

os.chdir(os.path.dirname(os.path.abspath(__file__)))

prev_line = None
def traceit(f, e, a):
	if e == "line":
		lineno = f.f_lineno
		fil = f.f_globals["__file__"]
		if fil.endswith("zdtm.py"):
			global prev_line
			line = linecache.getline(fil, lineno)
			if line == prev_line:
				print "        ..."
			else:
				prev_line = line
				print "+%4d: %s" % (lineno, line.rstrip())

	return traceit


# Root dir for ns and uns flavors. All tests
# sit in the same dir
tests_root = None

def clean_tests_root():
	global tests_root
	if tests_root:
		os.rmdir(tests_root)

def make_tests_root():
	global tests_root
	if not tests_root:
		tests_root = tempfile.mkdtemp("", "criu-root-", "/tmp")
		atexit.register(clean_tests_root)
	return tests_root

# Report generation

report_dir = None

def init_report(path):
	global report_dir
	report_dir = path
	if not os.access(report_dir, os.F_OK):
		os.makedirs(report_dir)

def add_to_report(path, tgt_name):
	global report_dir
	if report_dir:
		tgt_path = os.path.join(report_dir, tgt_name)
		att = 0
		while os.access(tgt_path, os.F_OK):
			tgt_path = os.path.join(report_dir, tgt_name + ".%d" % att)
			att += 1

		if os.path.isdir(path):
			shutil.copytree(path, tgt_path)
		else:
			shutil.copy2(path, tgt_path)


# Arch we run on
arch = os.uname()[4]

#
# Flavors
#  h -- host, test is run in the same set of namespaces as criu
#  ns -- namespaces, test is run in itw own set of namespaces
#  uns -- user namespace, the same as above plus user namespace
#

class host_flavor:
	def __init__(self, opts):
		self.name = "host"
		self.ns = False
		self.root = None

	def init(self, test_bin, deps):
		pass

	def fini(self):
		pass

class ns_flavor:
	def __init__(self, opts):
		self.name = "ns"
		self.ns = True
		self.uns = False
		self.root = make_tests_root()
		self.root_mounted = False

	def __copy_one(self, fname):
		if not os.access(fname, os.F_OK):
			raise test_fail_exc("Deps check (%s doesn't exist)" % fname)

		tfname = self.root + fname
		if not os.access(tfname, os.F_OK):
			# Copying should be atomic as tests can be
			# run in parallel
			try:
				os.makedirs(self.root + os.path.dirname(fname))
			except:
				pass
			dst = tempfile.mktemp(".tso", "", self.root + os.path.dirname(fname))
			shutil.copy2(fname, dst)
			os.rename(dst, tfname)

	def __copy_libs(self, binary):
		ldd = subprocess.Popen(["ldd", binary], stdout = subprocess.PIPE)
		xl = re.compile('^(linux-gate.so|linux-vdso(64)?.so|not a dynamic)')

		# This Mayakovsky-style code gets list of libraries a binary
		# needs minus vdso and gate .so-s
		libs = map(lambda x: x[1] == '=>' and x[2] or x[0],		\
				map(lambda x: x.split(),			\
					filter(lambda x: not xl.match(x),	\
						map(lambda x: x.strip(),	\
							filter(lambda x: x.startswith('\t'), ldd.stdout.readlines())))))
		ldd.wait()

		for lib in libs:
			self.__copy_one(lib)

	def __mknod(self, name, rdev = None):
		name = "/dev/" + name
		if not rdev:
			if not os.access(name, os.F_OK):
				print "Skipping %s at root" % name
				return
			else:
				rdev = os.stat(name).st_rdev

		name = self.root + name
		os.mknod(name, stat.S_IFCHR, rdev)
		os.chmod(name, 0666)

	def __construct_root(self):
		for dir in ["/bin", "/sbin", "/etc", "/lib", "/lib64", "/dev", "/dev/pts", "/dev/net", "/tmp", "/usr", "/proc"]:
			os.mkdir(self.root + dir)
			os.chmod(self.root + dir, 0777)

		for ldir in [ "/bin", "/sbin", "/lib", "/lib64" ]:
			os.symlink(".." + ldir, self.root + "/usr" + ldir)

		self.__mknod("tty", os.makedev(5, 0))
		self.__mknod("null", os.makedev(1, 3))
		self.__mknod("net/tun")
		self.__mknod("rtc")

	def init(self, test_bin, deps):
		subprocess.check_call(["mount", "--make-private", "--bind", ".", self.root])
		self.root_mounted = True

		if not os.access(self.root + "/.constructed", os.F_OK):
			with open(os.path.abspath(__file__)) as o:
				fcntl.flock(o, fcntl.LOCK_EX)
				if not os.access(self.root + "/.constructed", os.F_OK):
					print "Construct root for %s" % test_bin
					self.__construct_root()
					os.mknod(self.root + "/.constructed", stat.S_IFREG | 0600)

		self.__copy_libs(test_bin)
		for dep in deps:
			self.__copy_one(dep)
			self.__copy_libs(dep)

	def fini(self):
		if self.root_mounted:
			subprocess.check_call(["mount", "--make-private", self.root])
			subprocess.check_call(["umount", "-l", self.root])
			self.root_mounted = False

class userns_flavor(ns_flavor):
	def __init__(self, opts):
		ns_flavor.__init__(self, opts)
		self.name = "userns"
		self.uns = True

	def init(self, test_bin, deps):
		# To be able to create roots_yard in CRIU
		os.chmod(".", os.stat(".").st_mode | 0077)
		ns_flavor.init(self, test_bin, deps)

flavors = { 'h': host_flavor, 'ns': ns_flavor, 'uns': userns_flavor }

#
# Helpers
#

def tail(path):
	p = subprocess.Popen(['tail', '-n1', path],
			stdout = subprocess.PIPE)
	return p.stdout.readline()

def rpidfile(path):
	return open(path).readline().strip()

def wait_pid_die(pid, who, tmo = 30):
	stime = 0.1
	while stime < tmo:
		try:
			os.kill(int(pid), 0)
		except: # Died
			break

		print "Wait for %s to die for %f" % (who, stime)
		time.sleep(stime)
		stime *= 2
	else:
		raise test_fail_exc("%s die" % who)

def test_flag(tdesc, flag):
	return flag in tdesc.get('flags', '').split()

#
# Exception thrown when something inside the test goes wrong,
# e.g. test doesn't start, criu returns with non zero code or
# test checks fail
#

class test_fail_exc:
	def __init__(self, step):
		self.step = step

class test_fail_expected_exc:
	def __init__(self, cr_action):
		self.cr_action = cr_action

#
# A test from zdtm/ directory.
#

class zdtm_test:
	def __init__(self, name, desc, flavor):
		self.__name = name
		self.__desc = desc
		self.__make_action('cleanout')
		self.__pid = 0
		self.__flavor = flavor
		self.auto_reap = True

	def __make_action(self, act, env = None, root = None):
		sys.stdout.flush() # Not to let make's messages appear before ours
		tpath = self.__name + '.' + act
		s_args = ['make', '--no-print-directory', \
			 	'-C', os.path.dirname(tpath), \
				      os.path.basename(tpath)]

		if env:
			env = dict(os.environ, **env)

		s = subprocess.Popen(s_args, env = env, cwd = root)
		s.wait()

	def __pidfile(self):
		if self.__flavor.ns:
			return self.__name + '.init.pid'
		else:
			return self.__name + '.pid'

	def __wait_task_die(self):
		wait_pid_die(int(self.__pid), self.__name)

	def start(self):
		env = {}
		self.__flavor.init(self.__name, self.__desc.get('deps', []))

		print "Start test"

		env['ZDTM_THREAD_BOMB'] = "5"
		if not test_flag(self.__desc, 'suid'):
			env['ZDTM_UID'] = "18943"
			env['ZDTM_GID'] = "58467"
			env['ZDTM_GROUPS'] = "27495 48244"

			# Add write perms for .out and .pid files
			p = os.path.dirname(self.__name)
			os.chmod(p, os.stat(p).st_mode | 0222)
		else:
			print "Test is SUID"

		if self.__flavor.ns:
			env['ZDTM_NEWNS'] = "1"
			env['ZDTM_PIDFILE'] = os.path.realpath(self.__name + '.init.pid')
			env['ZDTM_ROOT'] = self.__flavor.root

			if self.__flavor.uns:
				env['ZDTM_USERNS'] = "1"
				p = os.path.dirname(self.__name)
				os.chmod(p, os.stat(p).st_mode | 0222)

		self.__make_action('pid', env, self.__flavor.root)

		try:
			os.kill(int(self.getpid()), 0)
		except:
			raise test_fail_exc("start")

	def kill(self, sig = signal.SIGKILL):
		if self.__pid:
			os.kill(int(self.__pid), sig)
			self.gone(sig == signal.SIGKILL)

		self.__flavor.fini()

	def stop(self):
		self.getpid() # Read the pid from pidfile back
		self.kill(signal.SIGTERM)

		res = tail(self.__name + '.out')
		if not 'PASS' in res.split():
			raise test_fail_exc("result check")

	def getpid(self):
		if self.__pid == 0:
			self.__pid = rpidfile(self.__pidfile())

		return self.__pid

	def getname(self):
		return self.__name

	def __getcropts(self):
		opts = self.__desc.get('opts', '').split() + ["--pidfile", os.path.realpath(self.__pidfile())]
		if self.__flavor.ns:
			opts += ["--root", self.__flavor.root]
		if test_flag(self.__desc, 'crlib'):
			opts += ["-L", os.path.dirname(os.path.realpath(self.__name)) + '/lib']
		return opts

	def getdopts(self):
		return self.__getcropts()

	def getropts(self):
		return self.__getcropts()

	def gone(self, force = True):
		if not self.auto_reap:
			pid, status = os.waitpid(int(self.__pid), 0)
			if pid != int(self.__pid):
				raise test_fail_exc("kill pid mess")

		self.__wait_task_die()
		self.__pid = 0
		if force or self.__flavor.ns:
			os.unlink(self.__pidfile())

	def print_output(self):
		if os.access(self.__name + '.out', os.R_OK):
			print "Test output: " + "=" * 32
			print open(self.__name + '.out').read()
			print " <<< " + "=" * 32

	def static(self):
		return self.__name.split('/')[2] == 'static'

	def blocking(self):
		return test_flag(self.__desc, 'crfail')

	@staticmethod
	def available():
		if not os.access("zdtm_ct", os.X_OK):
			subprocess.check_call(["make", "zdtm_ct"])
		if not os.access("zdtm/lib/libzdtmtst.a", os.F_OK):
			subprocess.check_call(["make", "-C", "zdtm/"])
		subprocess.check_call(["flock", "zdtm_mount_cgroups", "./zdtm_mount_cgroups"])


class inhfd_test:
	def __init__(self, name, desc, flavor):
		self.__name = os.path.basename(name)
		print "Load %s" % name
		self.__fdtyp = imp.load_source(self.__name, name)
		self.__my_file = None
		self.__peer_pid = 0
		self.__peer_file = None
		self.__peer_file_name = None
		self.__dump_opts = None

	def start(self):
		self.__message = "".join([random.choice(string.ascii_letters) for _ in range(16)])
		(self.__my_file, peer_file) = self.__fdtyp.create_fds()

		# Check FDs returned for inter-connection
		self.__my_file.write(self.__message)
		self.__my_file.flush()
		if peer_file.read(16) != self.__message:
			raise test_fail_exc("FDs screwup")

		start_pipe = os.pipe()
		self.__peer_pid = os.fork()
		if self.__peer_pid == 0:
			os.setsid()
			os.close(0)
			os.close(1)
			os.close(2)
		 	self.__my_file.close()
			os.close(start_pipe[0])
			os.close(start_pipe[1])
			try:
				data = peer_file.read(16)
			except:
				sys.exit(1)

			sys.exit(data == self.__message and 42 or 2)

		os.close(start_pipe[1])
		os.read(start_pipe[0], 12)
		os.close(start_pipe[0])

		self.__peer_file_name = self.__fdtyp.filename(peer_file)
		self.__dump_opts = self.__fdtyp.dump_opts(peer_file)

	def stop(self):
		self.__my_file.write(self.__message)
		self.__my_file.flush()
		pid, status = os.waitpid(self.__peer_pid, 0)
		if not os.WIFEXITED(status) or os.WEXITSTATUS(status) != 42:
			raise test_fail_exc("test failed with %d" % status)

	def kill(self):
		if self.__peer_pid:
			os.kill(self.__peer_pid, signal.SIGKILL)

	def getname(self):
		return self.__name

	def getpid(self):
		return "%s" % self.__peer_pid

	def gone(self, force = True):
		os.waitpid(self.__peer_pid, 0)
		wait_pid_die(self.__peer_pid, self.__name)
		self.__my_file = None
		self.__peer_file = None

	def getdopts(self):
		return self.__dump_opts

	def getropts(self):
		(self.__my_file, self.__peer_file) = self.__fdtyp.create_fds()
		return ["--restore-sibling", "--inherit-fd", "fd[%d]:%s" % (self.__peer_file.fileno(), self.__peer_file_name)]

	def print_output(self):
		pass

	def static(self):
		return True

	def blocking(self):
		return False

	@staticmethod
	def available():
		pass


test_classes = { 'zdtm': zdtm_test, 'inhfd': inhfd_test }

#
# CRIU when launched using CLI
#

criu_bin = "../criu"
class criu_cli:
	def __init__(self, opts):
		self.__test = None
		self.__dump_path = None
		self.__iter = 0
		self.__prev_dump_iter = None
		self.__page_server = (opts['page_server'] and True or False)
		self.__restore_sibling = (opts['sibling'] and True or False)
		self.__fault = (opts['fault'])
		self.__sat = (opts['sat'] and True or False)
		self.__dedup = (opts['dedup'] and True or False)

	def logs(self):
		return self.__dump_path

	def set_test(self, test):
		self.__test = test
		self.__dump_path = "dump/" + test.getname() + "/" + test.getpid()
		if os.path.exists(self.__dump_path):
			for i in xrange(100):
				newpath = self.__dump_path + "." + str(i)
				if not os.path.exists(newpath):
					os.rename(self.__dump_path, newpath)
					break
			else:
				raise test_fail_exc("couldn't find dump dir %s" % self.__dump_path)

		os.makedirs(self.__dump_path)

	def cleanup(self):
		if self.__dump_path:
			print "Removing %s" % self.__dump_path
			shutil.rmtree(self.__dump_path)

	def __ddir(self):
		return os.path.join(self.__dump_path, "%d" % self.__iter)

	@staticmethod
	def __criu(action, args, fault = None, strace = []):
		env = None
		if fault:
			print "Forcing %s fault" % fault
			env = dict(os.environ, CRIU_FAULT = fault)
		cr = subprocess.Popen(strace + [criu_bin, action] + args, env = env)
		return cr.wait()

	def __criu_act(self, action, opts, log = None):
		if not log:
			log = action + ".log"

		s_args = ["-o", log, "-D", self.__ddir(), "-v4"] + opts

		with open(os.path.join(self.__ddir(), action + '.cropt'), 'w') as f:
			f.write(' '.join(s_args) + '\n')
		print "Run criu " + action

		strace = []
		if self.__sat:
			strace = ["strace", "-o", os.path.join(self.__ddir(), action + '.strace'), '-T']
			if action == 'restore':
				strace += [ '-f' ]
				s_args += [ '--action-script', os.getcwd() + '/../scripts/fake-restore.sh' ]

		ret = self.__criu(action, s_args, self.__fault, strace)
		grep_errors(os.path.join(self.__ddir(), log))
		if ret != 0:
			if self.__fault or self.__test.blocking() or (self.__sat and action == 'restore'):
				raise test_fail_expected_exc(action)
			else:
				raise test_fail_exc("CRIU %s" % action)

	def dump(self, action, opts = []):
		self.__iter += 1
		os.mkdir(self.__ddir())

		a_opts = ["-t", self.__test.getpid()]
		if self.__prev_dump_iter:
			a_opts += ["--prev-images-dir", "../%d" % self.__prev_dump_iter, "--track-mem"]
		self.__prev_dump_iter = self.__iter

		if self.__page_server:
			print "Adding page server"

			ps_opts = [ "--port", "12345", "--daemon", "--pidfile", "ps.pid" ]
			if self.__dedup:
				ps_opts += [ "--auto-dedup" ]

			self.__criu_act("page-server", opts = ps_opts)
			a_opts += ["--page-server", "--address", "127.0.0.1", "--port", "12345"]

		a_opts += self.__test.getdopts()

		if self.__dedup:
			a_opts += [ "--auto-dedup" ]

		self.__criu_act(action, opts = a_opts + opts)

		if self.__page_server:
			wait_pid_die(int(rpidfile(self.__ddir() + "/ps.pid")), "page server")

	def restore(self):
		r_opts = []
		if self.__restore_sibling:
			r_opts = ["--restore-sibling"]
			self.__test.auto_reap = False
		r_opts += self.__test.getropts()

		self.__prev_dump_iter = None
		self.__criu_act("restore", opts = r_opts + ["--restore-detached"])

	@staticmethod
	def check(feature):
		return criu_cli.__criu("check", ["-v0", "--feature", feature]) == 0

	@staticmethod
	def available():
		if not os.access(criu_bin, os.X_OK):
			print "CRIU binary not built"
			sys.exit(1)


def try_run_hook(test, args):
	hname = test.getname() + '.hook'
	if os.access(hname, os.X_OK):
		print "Running %s(%s)" % (hname, ', '.join(args))
		hook = subprocess.Popen([hname] + args)
		if hook.wait() != 0:
			raise test_fail_exc("hook " + " ".join(args))

#
# Main testing entity -- dump (probably with pre-dumps) and restore
#

def iter_parm(opt, dflt):
	x = ((opt or str(dflt)) + ":0").split(':')
	return (xrange(0, int(x[0])), float(x[1]))

def cr(cr_api, test, opts):
	if opts['nocr']:
		return

	cr_api.set_test(test)

	iters = iter_parm(opts['iters'], 1)
	for i in iters[0]:
		pres = iter_parm(opts['pre'], 0)
		for p in pres[0]:
			if opts['snaps']:
				cr_api.dump("dump", opts = ["--leave-running"])
			else:
				cr_api.dump("pre-dump")
			time.sleep(pres[1])

		if opts['norst']:
			cr_api.dump("dump", opts = ["--leave-running"])
		else:
			cr_api.dump("dump")
			test.gone()
			try_run_hook(test, ["--pre-restore"])
			cr_api.restore()

		time.sleep(iters[1])


# Additional checks that can be done outside of test process

def get_maps(test):
	maps = [[0,0]]
	last = 0
	for mp in open("/proc/%s/maps" % test.getpid()).readlines():
		m = map(lambda x: int('0x' + x, 0), mp.split()[0].split('-'))
		if maps[last][1] == m[0]:
			maps[last][1] = m[1]
		else:
			maps.append(m)
			last += 1
	maps.pop(0)
	return maps

def get_fds(test):
	return map(lambda x: int(x), os.listdir("/proc/%s/fdinfo" % test.getpid()))

def cmp_lists(m1, m2):
	return len(m1) != len(m2) or filter(lambda x: x[0] != x[1], zip(m1, m2))

def get_visible_state(test):
	if test.static():
		fds = get_fds(test)
		maps = get_maps(test)
		return (fds, maps)
	else:
		return ([], [])

def check_visible_state(test, state):
	new = get_visible_state(test)
	if cmp_lists(new[0], state[0]):
		raise test_fail_exc("fds compare")
	if cmp_lists(new[1], state[1]):
		s_new = set(map(lambda x: '%x-%x' % (x[0], x[1]), new[1]))
		s_old = set(map(lambda x: '%x-%x' % (x[0], x[1]), state[1]))

		print "Old maps lost:"
		print s_old - s_new
		print "New maps appeared:"
		print s_new - s_old

		raise test_fail_exc("maps compare")

def do_run_test(tname, tdesc, flavs, opts):
	tcname = tname.split('/')[0]
	tclass = test_classes.get(tcname, None)
	if not tclass:
		print "Unknown test class %s" % tcname
		return

	if opts['report']:
		init_report(opts['report'])

	for f in flavs:
		print
		print_sep("Run %s in %s" % (tname, f))
		flav = flavors[f](opts)
		t = tclass(tname, tdesc, flav)
		cr_api = criu_cli(opts)

		try:
			t.start()
			s = get_visible_state(t)
			try:
				cr(cr_api, t, opts)
			except test_fail_expected_exc as e:
				if e.cr_action == "dump":
					t.stop()
				try_run_hook(t, ["--fault", e.cr_action])
			else:
				check_visible_state(t, s)
				t.stop()
				try_run_hook(t, ["--clean"])
		except test_fail_exc as e:
			print_sep("Test %s FAIL at %s" % (tname, e.step), '#')
			t.print_output()
			t.kill()
			add_to_report(cr_api.logs(), "cr_logs")
			if opts['keep_img'] == 'never':
				cr_api.cleanup()
			# This exit does two things -- exits from subprocess and
			# aborts the main script execution on the 1st error met
			sys.exit(1)
		else:
			if opts['keep_img'] != 'always':
				cr_api.cleanup()
			print_sep("Test %s PASS" % tname)

class launcher:
	def __init__(self, opts, nr_tests):
		self.__opts = opts
		self.__total = nr_tests
		self.__nr = 0
		self.__max = int(opts['parallel'] or 1)
		self.__subs = {}
		self.__fail = False

	def __show_progress(self):
		perc = self.__nr * 16 / self.__total
		print "=== Run %d/%d %s" % (self.__nr, self.__total, '=' * perc + '-' * (16 - perc))

	def run_test(self, name, desc, flavor):

		if len(self.__subs) >= self.__max:
			self.wait()

		if test_flag(desc, 'excl'):
			self.wait_all()

		self.__nr += 1
		self.__show_progress()

		nd = ('nocr', 'norst', 'pre', 'iters', 'page_server', 'sibling', \
				'fault', 'keep_img', 'report', 'snaps', 'sat', 'dedup')
		arg = repr((name, desc, flavor, { d: self.__opts[d] for d in nd }))
		log = name.replace('/', '_') + ".log"
		sub = subprocess.Popen(["./zdtm_ct", "zdtm.py"], \
				env = dict(os.environ, CR_CT_TEST_INFO = arg ), \
				stdout = open(log, "w"), stderr = subprocess.STDOUT)
		self.__subs[sub.pid] = { 'sub': sub, 'log': log }

		if test_flag(desc, 'excl'):
			self.wait()

	def __wait_one(self, flags):
		pid, status = os.waitpid(0, flags)
		if pid != 0:
			sub = self.__subs.pop(pid)
			if status != 0:
				self.__fail = True
				add_to_report(sub['log'], "output")

			print open(sub['log']).read()
			os.unlink(sub['log'])
			return True

		return False

	def __wait_all(self):
		while self.__subs:
			self.__wait_one(0)

	def wait(self):
		self.__wait_one(0)
		while self.__subs:
			if not self.__wait_one(os.WNOHANG):
				break
		if self.__fail:
			raise test_fail_exc('')

	def wait_all(self):
		self.__wait_all()
		if self.__fail:
			raise test_fail_exc('')

	def finish(self):
		self.__wait_all()
		if self.__fail:
			print_sep("FAIL", "#")
			sys.exit(1)

def all_tests(opts):
	desc = eval(open(opts['set'] + '.desc').read())
	lst = subprocess.Popen(['find', desc['dir'], '-type', 'f', '-executable' ], \
			stdout = subprocess.PIPE)
	excl = map(lambda x: os.path.join(desc['dir'], x), desc['exclude'])
	tlist = filter(lambda x: \
			not x.endswith('.checkskip') and \
			not x.endswith('.hook') and \
			not x in excl, \
				map(lambda x: x.strip(), lst.stdout.readlines()) \
		)
	lst.wait()
	return tlist


# Descriptor for abstract test not in list
default_test={ }


def get_test_desc(tname):
	d_path = tname + '.desc'
	if os.access(d_path, os.F_OK):
		return eval(open(d_path).read())

	return default_test


def self_checkskip(tname):
	chs = tname  + '.checkskip'
	if os.access(chs, os.X_OK):
		ch = subprocess.Popen([chs])
		return ch.wait() == 0 and False or True

	return False

def print_sep(title, sep = "=", width = 80):
	print (" " + title + " ").center(width, sep)

def grep_errors(fname):
	first = True
	for l in open(fname):
		if "Error" in l:
			if first:
				print_sep("grep Error", "-", 60)
				first = False
			print l,
	if not first:
		print_sep("ERROR OVER", "-", 60)

def run_tests(opts):
	excl = None
	features = {}

	if opts['all']:
		torun = all_tests(opts)
		run_all = True
	elif opts['tests']:
		r = re.compile(opts['tests'])
		torun = filter(lambda x: r.match(x), all_tests(opts))
		run_all = True
	elif opts['test']:
		torun = opts['test']
		run_all = False
	else:
		print "Specify test with -t <name> or -a"
		return

	if opts['exclude']:
		excl = re.compile(".*(" + "|".join(opts['exclude']) + ")")
		print "Compiled exclusion list"

	if opts['report']:
		init_report(opts['report'])

	l = launcher(opts, len(torun))
	try:
		for t in torun:
			global arch

			if excl and excl.match(t):
				print "Skipping %s (exclude)" % t
				continue

			tdesc = get_test_desc(t)
			if tdesc.get('arch', arch) != arch:
				print "Skipping %s (arch %s)" % (t, tdesc['arch'])
				continue

			if run_all and test_flag(tdesc, 'noauto'):
				print "Skipping test %s (manual run only)" % t
				continue

			feat = tdesc.get('feature', None)
			if feat:
				if not features.has_key(feat):
					print "Checking feature %s" % feat
					features[feat] = criu_cli.check(feat)

				if not features[feat]:
					print "Skipping %s (no %s feature)" % (t, feat)
					continue

			if self_checkskip(t):
				print "Skipping %s (self)" % t
				continue

			test_flavs = tdesc.get('flavor', 'h ns uns').split()
			opts_flavs = (opts['flavor'] or 'h,ns,uns').split(',')
			run_flavs = set(test_flavs) & set(opts_flavs)

			if run_flavs:
				l.run_test(t, tdesc, run_flavs)
	finally:
		l.finish()


sti_fmt = "%-40s%-10s%s"

def show_test_info(t):
	tdesc = get_test_desc(t)
	flavs = tdesc.get('flavor', '')
	return sti_fmt % (t, flavs, tdesc.get('flags', ''))


def list_tests(opts):
	tlist = all_tests(opts)
	if opts['info']:
		print sti_fmt % ('Name', 'Flavors', 'Flags')
		tlist = map(lambda x: show_test_info(x), tlist)
	print '\n'.join(tlist)

#
# main() starts here
#

if os.environ.has_key('CR_CT_TEST_INFO'):
	# Fork here, since we're new pidns init and are supposed to
	# collect this namespace's zombies
	status = 0
	pid = os.fork()
	if pid == 0:
		tinfo = eval(os.environ['CR_CT_TEST_INFO'])
		do_run_test(tinfo[0], tinfo[1], tinfo[2], tinfo[3])
	else:
		while True:
			wpid, status = os.wait()
			if wpid == pid:
				if not os.WIFEXITED(status) or os.WEXITSTATUS(status) != 0:
					status = 1
				break;

	sys.exit(status)

p = argparse.ArgumentParser("CRIU test suite")
p.add_argument("--debug", help = "Print what's being executed", action = 'store_true')
p.add_argument("--set", help = "Which set of tests to use", default = 'zdtm')

sp = p.add_subparsers(help = "Use --help for list of actions")

rp = sp.add_parser("run", help = "Run test(s)")
rp.set_defaults(action = run_tests)
rp.add_argument("-a", "--all", action = 'store_true')
rp.add_argument("-t", "--test", help = "Test name", action = 'append')
rp.add_argument("-T", "--tests", help = "Regexp")
rp.add_argument("-f", "--flavor", help = "Flavor to run")
rp.add_argument("-x", "--exclude", help = "Exclude tests from --all run", action = 'append')

rp.add_argument("--sibling", help = "Restore tests as siblings", action = 'store_true')
rp.add_argument("--pre", help = "Do some pre-dumps before dump (n[:pause])")
rp.add_argument("--snaps", help = "Instead of pre-dumps do full dumps", action = 'store_true')
rp.add_argument("--dedup", help = "Auto-deduplicate images on iterations", action = 'store_true')
rp.add_argument("--nocr", help = "Do not CR anything, just check test works", action = 'store_true')
rp.add_argument("--norst", help = "Don't restore tasks, leave them running after dump", action = 'store_true')
rp.add_argument("--iters", help = "Do CR cycle several times before check (n[:pause])")
rp.add_argument("--fault", help = "Test fault injection")
rp.add_argument("--sat", help = "Generate criu strace-s for sat tool (restore is fake, images are kept)", action = 'store_true')

rp.add_argument("--page-server", help = "Use page server dump", action = 'store_true')
rp.add_argument("-p", "--parallel", help = "Run test in parallel")

rp.add_argument("-k", "--keep-img", help = "Whether or not to keep images after test",
		choices = [ 'always', 'never', 'failed' ], default = 'failed')
rp.add_argument("--report", help = "Generate summary report in directory")

lp = sp.add_parser("list", help = "List tests")
lp.set_defaults(action = list_tests)
lp.add_argument('-i', '--info', help = "Show more info about tests", action = 'store_true')

opts = vars(p.parse_args())
if opts.get('sat', False):
	opts['keep_img'] = 'always'

if opts['debug']:
	sys.settrace(traceit)

criu_cli.available()
for tst in test_classes.values():
	tst.available()

opts['action'](opts)
