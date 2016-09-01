#!/usr/bin/env python2
# vim: noet
import argparse
import glob
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
import fcntl
import errno
import datetime
import yaml
import criu as crpc

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
	if tests_root and tests_root[0] == os.getpid():
		os.rmdir(tests_root[1])


def make_tests_root():
	global tests_root
	if not tests_root:
		tests_root = (os.getpid(), tempfile.mkdtemp("", "criu-root-", "/tmp"))
		atexit.register(clean_tests_root)
	return tests_root[1]

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
			if not os.path.exists(os.path.dirname(tgt_path)):
				os.mkdir(os.path.dirname(tgt_path))
			shutil.copy2(path, tgt_path)


def add_to_output(path):
	global report_dir
	if not report_dir:
		return

	fdi = open(path, "r")
	fdo = open(os.path.join(report_dir, "output"), "a")
	while True:
		buf = fdi.read(1 << 20)
		if not buf:
			break
		fdo.write(buf)


prev_crash_reports = set(glob.glob("/tmp/zdtm-core-*.txt"))


def check_core_files():
	reports = set(glob.glob("/tmp/zdtm-core-*.txt")) - prev_crash_reports
	if not reports:
		return False

	while subprocess.Popen("ps axf | grep 'abrt\.sh'", shell = True).wait() == 0:
		time.sleep(1)

	for i in reports:
		add_to_report(i, os.path.basename(i))
		print_sep(i)
		print open(i).read()
		print_sep(i)

	return True

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

	def init(self, l_bins, x_bins):
		pass

	def fini(self):
		pass

	@staticmethod
	def clean():
		pass


class ns_flavor:
	__root_dirs = ["/bin", "/sbin", "/etc", "/lib", "/lib64", "/dev", "/dev/pts", "/dev/net", "/tmp", "/usr", "/proc"]

	def __init__(self, opts):
		self.name = "ns"
		self.ns = True
		self.uns = False
		self.root = make_tests_root()
		self.root_mounted = False

	def __copy_one(self, fname):
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
		libs = map(lambda x: x[1] == '=>' and x[2] or x[0],
				map(lambda x: x.split(),
					filter(lambda x: not xl.match(x),
						map(lambda x: x.strip(),
							filter(lambda x: x.startswith('\t'), ldd.stdout.readlines())))))
		ldd.wait()

		for lib in libs:
			if not os.access(lib, os.F_OK):
				raise test_fail_exc("Can't find lib %s required by %s" % (lib, binary))
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
		for dir in self.__root_dirs:
			os.mkdir(self.root + dir)
			os.chmod(self.root + dir, 0777)

		for ldir in ["/bin", "/sbin", "/lib", "/lib64"]:
			os.symlink(".." + ldir, self.root + "/usr" + ldir)

		self.__mknod("tty", os.makedev(5, 0))
		self.__mknod("null", os.makedev(1, 3))
		self.__mknod("net/tun")
		self.__mknod("rtc")
		self.__mknod("autofs", os.makedev(10, 235))

	def __copy_deps(self, deps):
		for d in deps.split('|'):
			if os.access(d, os.F_OK):
				self.__copy_one(d)
				self.__copy_libs(d)
				return
		raise test_fail_exc("Deps check %s failed" % deps)

	def init(self, l_bins, x_bins):
		subprocess.check_call(["mount", "--make-slave", "--bind", ".", self.root])
		self.root_mounted = True

		if not os.access(self.root + "/.constructed", os.F_OK):
			with open(os.path.abspath(__file__)) as o:
				fcntl.flock(o, fcntl.LOCK_EX)
				if not os.access(self.root + "/.constructed", os.F_OK):
					print "Construct root for %s" % l_bins[0]
					self.__construct_root()
					os.mknod(self.root + "/.constructed", stat.S_IFREG | 0600)

		for b in l_bins:
			self.__copy_libs(b)
		for b in x_bins:
			self.__copy_deps(b)

	def fini(self):
		if self.root_mounted:
			subprocess.check_call(["./umount2", self.root])
			self.root_mounted = False

	@staticmethod
	def clean():
		for d in ns_flavor.__root_dirs:
			p = './' + d
			print 'Remove %s' % p
			if os.access(p, os.F_OK):
				shutil.rmtree('./' + d)

		if os.access('./.constructed', os.F_OK):
			os.unlink('./.constructed')


class userns_flavor(ns_flavor):
	def __init__(self, opts):
		ns_flavor.__init__(self, opts)
		self.name = "userns"
		self.uns = True

	def init(self, l_bins, x_bins):
		# To be able to create roots_yard in CRIU
		os.chmod(".", os.stat(".").st_mode | 0077)
		ns_flavor.init(self, l_bins, x_bins)

	@staticmethod
	def clean():
		pass


flavors = {'h': host_flavor, 'ns': ns_flavor, 'uns': userns_flavor}

#
# Helpers
#


def encode_flav(f):
	return (flavors.keys().index(f) + 128)


def decode_flav(i):
	i = i - 128
	if i in flavors:
		return flavors.keys()[i - 128]
	return "unknown"


def tail(path):
	p = subprocess.Popen(['tail', '-n1', path],
			stdout = subprocess.PIPE)
	out = p.stdout.readline()
	p.wait()
	return out


def rpidfile(path):
	return open(path).readline().strip()


def wait_pid_die(pid, who, tmo = 30):
	stime = 0.1
	while stime < tmo:
		try:
			os.kill(int(pid), 0)
		except:  # Died
			break

		print "Wait for %s(%d) to die for %f" % (who, pid, stime)
		time.sleep(stime)
		stime *= 2
	else:
		subprocess.Popen(["ps", "-p", str(pid)]).wait()
		subprocess.Popen(["ps", "axf", str(pid)]).wait()
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
	def __init__(self, name, desc, flavor, freezer):
		self.__name = name
		self.__desc = desc
		self.__freezer = None
		self.__make_action('cleanout')
		self.__pid = 0
		self.__flavor = flavor
		self.__freezer = freezer
		self._bins = [name]
		self._env = {}
		self._deps = desc.get('deps', [])
		self.auto_reap = True

	def __make_action(self, act, env = None, root = None):
		sys.stdout.flush()  # Not to let make's messages appear before ours
		tpath = self.__name + '.' + act
		s_args = ['make', '--no-print-directory',
				'-C', os.path.dirname(tpath),
				      os.path.basename(tpath)]

		if env:
			env = dict(os.environ, **env)

		s = subprocess.Popen(s_args, env = env, cwd = root, close_fds = True,
				preexec_fn = self.__freezer and self.__freezer.attach or None)
		s.wait()

		if self.__freezer:
			self.__freezer.freeze()

	def __pidfile(self):
		return self.__name + '.pid'

	def __wait_task_die(self):
		wait_pid_die(int(self.__pid), self.__name)

	def __add_wperms(self):
		# Add write perms for .out and .pid files
		for b in self._bins:
			p = os.path.dirname(b)
			os.chmod(p, os.stat(p).st_mode | 0222)

	def start(self):
		self.__flavor.init(self._bins, self._deps)

		print "Start test"

		env = self._env
		if not self.__freezer.kernel:
			env['ZDTM_THREAD_BOMB'] = "5"

		if not test_flag(self.__desc, 'suid'):
			# Numbers should match those in criu
			env['ZDTM_UID'] = "18943"
			env['ZDTM_GID'] = "58467"
			env['ZDTM_GROUPS'] = "27495 48244"
			self.__add_wperms()
		else:
			print "Test is SUID"

		if self.__flavor.ns:
			env['ZDTM_NEWNS'] = "1"
			env['ZDTM_ROOT'] = self.__flavor.root
			env['PATH'] = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

			if self.__flavor.uns:
				env['ZDTM_USERNS'] = "1"
				self.__add_wperms()
			if os.getenv("GCOV"):
				criu_dir = os.path.dirname(os.getcwd())
				criu_dir_r = "%s%s" % (self.__flavor.root, criu_dir)

				env['ZDTM_CRIU'] = os.path.dirname(os.getcwd())
				subprocess.check_call(["mkdir", "-p", criu_dir_r])

		self.__make_action('pid', env, self.__flavor.root)

		try:
			os.kill(int(self.getpid()), 0)
		except:
			raise test_fail_exc("start")

		if not self.static():
			# Wait less than a second to give the test chance to
			# move into some semi-random state
			time.sleep(random.random())

	def kill(self, sig = signal.SIGKILL):
		self.__freezer.thaw()
		if self.__pid:
			print "Send the %d signal to  %s" % (sig, self.__pid)
			os.kill(int(self.__pid), sig)
			self.gone(sig == signal.SIGKILL)

		self.__flavor.fini()

	def stop(self):
		self.__freezer.thaw()
		self.getpid()  # Read the pid from pidfile back
		self.kill(signal.SIGTERM)

		res = tail(self.__name + '.out')
		if 'PASS' not in res.split():
			if os.access(self.__name + '.out.inprogress', os.F_OK):
				print_sep(self.__name + '.out.inprogress')
				print open(self.__name + '.out.inprogress').read()
				print_sep(self.__name + '.out.inprogress')
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
		return self.__getcropts() + self.__freezer.getdopts() + self.__desc.get('dopts', '').split()

	def getropts(self):
		return self.__getcropts() + self.__freezer.getropts() + self.__desc.get('ropts', '').split()

	def gone(self, force = True):
		if not self.auto_reap:
			pid, status = os.waitpid(int(self.__pid), 0)
			if pid != int(self.__pid):
				raise test_fail_exc("kill pid mess")

		self.__wait_task_die()
		self.__pid = 0
		if force:
			os.unlink(self.__pidfile())

	def print_output(self):
		if os.access(self.__name + '.out', os.R_OK):
			print "Test output: " + "=" * 32
			print open(self.__name + '.out').read()
			print " <<< " + "=" * 32

	def static(self):
		return self.__name.split('/')[1] == 'static'

	def ns(self):
		return self.__flavor.ns

	def blocking(self):
		return test_flag(self.__desc, 'crfail')

	@staticmethod
	def available():
		if not os.access("umount2", os.X_OK):
			subprocess.check_call(["make", "umount2"])
		if not os.access("zdtm_ct", os.X_OK):
			subprocess.check_call(["make", "zdtm_ct"])
		if not os.access("zdtm/lib/libzdtmtst.a", os.F_OK):
			subprocess.check_call(["make", "-C", "zdtm/"])
		subprocess.check_call(["flock", "zdtm_mount_cgroups.lock", "./zdtm_mount_cgroups"])


class inhfd_test:
	def __init__(self, name, desc, flavor, freezer):
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

			getattr(self.__fdtyp, "child_prep", lambda fd: None)(peer_file)

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


class groups_test(zdtm_test):
	def __init__(self, name, desc, flavor, freezer):
		zdtm_test.__init__(self, 'zdtm/lib/groups', desc, flavor, freezer)
		if flavor.ns:
			self.__real_name = name
			self.__subs = map(lambda x: x.strip(), open(name).readlines())
			print "Subs:\n%s" % '\n'.join(self.__subs)
		else:
			self.__real_name = ''
			self.__subs = []

		self._bins += self.__subs
		self._deps += get_test_desc('zdtm/lib/groups')['deps']
		self._env = {'ZDTM_TESTS': self.__real_name}

	def __get_start_cmd(self, name):
		tdir = os.path.dirname(name)
		tname = os.path.basename(name)

		s_args = ['make', '--no-print-directory', '-C', tdir]
		subprocess.check_call(s_args + [tname + '.cleanout'])
		s = subprocess.Popen(s_args + ['--dry-run', tname + '.pid'], stdout = subprocess.PIPE)
		cmd = s.stdout.readlines().pop().strip()
		s.wait()

		return 'cd /' + tdir + ' && ' + cmd

	def start(self):
		if (self.__subs):
			with open(self.__real_name + '.start', 'w') as f:
				for test in self.__subs:
					cmd = self.__get_start_cmd(test)
					f.write(cmd + '\n')

			with open(self.__real_name + '.stop', 'w') as f:
				for test in self.__subs:
					f.write('kill -TERM `cat /%s.pid`\n' % test)

		zdtm_test.start(self)

	def stop(self):
		zdtm_test.stop(self)

		for test in self.__subs:
			res = tail(test + '.out')
			if 'PASS' not in res.split():
				raise test_fail_exc("sub %s result check" % test)


test_classes = {'zdtm': zdtm_test, 'inhfd': inhfd_test, 'groups': groups_test}

#
# CRIU when launched using CLI
#

criu_bin = "../criu/criu"
join_ns_file = '/run/netns/zdtm_netns'


class criu_cli:
	@staticmethod
	def run(action, args, fault = None, strace = [], preexec = None):
		env = None
		if fault:
			print "Forcing %s fault" % fault
			env = dict(os.environ, CRIU_FAULT = fault)
		cr = subprocess.Popen(strace + [criu_bin, action] + args, env = env, preexec_fn = preexec)
		return cr.wait()


class criu_rpc:
	@staticmethod
	def __set_opts(criu, args, ctx):
		while len(args) != 0:
			arg = args.pop(0)
			if arg == '-v4':
				criu.opts.log_level = 4
				continue
			if arg == '-o':
				criu.opts.log_file = args.pop(0)
				continue
			if arg == '-D':
				criu.opts.images_dir_fd = os.open(args.pop(0), os.O_DIRECTORY)
				ctx['imgd'] = criu.opts.images_dir_fd
				continue
			if arg == '-t':
				criu.opts.pid = int(args.pop(0))
				continue
			if arg == '--pidfile':
				ctx['pidf'] = args.pop(0)
				continue
			if arg == '--timeout':
				criu.opts.timeout = int(args.pop(0))
				continue
			if arg == '--restore-detached':
				# Set by service by default
				ctx['rd'] = True
				continue
			if arg == '--root':
				criu.opts.root = args.pop(0)
				continue

			raise test_fail_exc('RPC for %s required' % arg)

	@staticmethod
	def run(action, args, fault = None, strace = [], preexec = None):
		if fault:
			raise test_fail_exc('RPC and FAULT not supported')
		if strace:
			raise test_fail_exc('RPC and SAT not supported')
		if preexec:
			raise test_fail_exc('RPC and PREEXEC not supported')

		ctx = {}  # Object used to keep info untill action is done
		criu = crpc.criu()
		criu.use_binary(criu_bin)
		criu_rpc.__set_opts(criu, args, ctx)

		if action == 'dump':
			criu.dump()
		elif action == 'restore':
			if 'rd' not in ctx:
				raise test_fail_exc('RPC Non-detached restore is impossible')

			res = criu.restore()
			pidf = ctx.get('pidf')
			if pidf:
				open(pidf, 'w').write('%d\n' % res.pid)
		else:
			raise test_fail_exc('RPC for %s required' % action)

		imgd = ctx.get('imgd')
		if imgd:
			os.close(imgd)
		return 0


class criu:
	def __init__(self, opts):
		self.__test = None
		self.__dump_path = None
		self.__iter = 0
		self.__prev_dump_iter = None
		self.__page_server = (opts['page_server'] and True or False)
		self.__restore_sibling = (opts['sibling'] and True or False)
		self.__join_ns = (opts['join_ns'] and True or False)
		self.__fault = (opts['fault'])
		self.__script = opts['script']
		self.__sat = (opts['sat'] and True or False)
		self.__dedup = (opts['dedup'] and True or False)
		self.__mdedup = (opts['noauto_dedup'] and True or False)
		self.__user = (opts['user'] and True or False)
		self.__leave_stopped = (opts['stop'] and True or False)
		self.__criu = (opts['rpc'] and criu_rpc or criu_cli)

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

	def set_user_id(self):
		# Numbers should match those in zdtm_test
		os.setresgid(58467, 58467, 58467)
		os.setresuid(18943, 18943, 18943)

	def __criu_act(self, action, opts, log = None):
		if not log:
			log = action + ".log"

		s_args = ["-o", log, "-D", self.__ddir(), "-v4"] + opts

		with open(os.path.join(self.__ddir(), action + '.cropt'), 'w') as f:
			f.write(' '.join(s_args) + '\n')
		print "Run criu " + action

		strace = []
		if self.__sat:
			fname = os.path.join(self.__ddir(), action + '.strace')
			print_fname(fname, 'strace')
			strace = ["strace", "-o", fname, '-T']
			if action == 'restore':
				strace += ['-f']
				s_args += ['--action-script', os.getcwd() + '/../scripts/fake-restore.sh']

		if self.__script:
			s_args += ['--action-script', self.__script]

		if action == "restore":
			preexec = None
		else:
			preexec = self.__user and self.set_user_id or None

		__ddir = self.__ddir()

		ret = self.__criu.run(action, s_args, self.__fault, strace, preexec)
		grep_errors(os.path.join(__ddir, log))
		if ret != 0:
			if self.__fault and int(self.__fault) < 128:
				try_run_hook(self.__test, ["--fault", action])
				if action == "dump":
					# create a clean directory for images
					os.rename(__ddir, __ddir + ".fail")
					os.mkdir(__ddir)
					os.chmod(__ddir, 0777)
				else:
					# on restore we move only a log file, because we need images
					os.rename(os.path.join(__ddir, log), os.path.join(__ddir, log + ".fail"))
				# try again without faults
				print "Run criu " + action
				ret = self.__criu.run(action, s_args, False, strace, preexec)
				grep_errors(os.path.join(__ddir, log))
				if ret == 0:
					return
			if self.__test.blocking() or (self.__sat and action == 'restore'):
				raise test_fail_expected_exc(action)
			else:
				raise test_fail_exc("CRIU %s" % action)

	def dump(self, action, opts = []):
		self.__iter += 1
		os.mkdir(self.__ddir())
		os.chmod(self.__ddir(), 0777)

		a_opts = ["-t", self.__test.getpid()]
		if self.__prev_dump_iter:
			a_opts += ["--prev-images-dir", "../%d" % self.__prev_dump_iter, "--track-mem"]
		self.__prev_dump_iter = self.__iter

		if self.__page_server:
			print "Adding page server"

			ps_opts = ["--port", "12345", "--daemon", "--pidfile", "ps.pid"]
			if self.__dedup:
				ps_opts += ["--auto-dedup"]

			self.__criu_act("page-server", opts = ps_opts)
			a_opts += ["--page-server", "--address", "127.0.0.1", "--port", "12345"]

		a_opts += self.__test.getdopts()

		if self.__dedup:
			a_opts += ["--auto-dedup"]

		a_opts += ["--timeout", "10"]

		criu_dir = os.path.dirname(os.getcwd())
		if os.getenv("GCOV"):
			a_opts.append("--ext-mount-map")
			a_opts.append("%s:zdtm" % criu_dir)

		if self.__leave_stopped:
			a_opts += ['--leave-stopped']

		self.__criu_act(action, opts = a_opts + opts)
		if self.__mdedup and self.__iter > 1:
			self.__criu_act("dedup", opts = [])

		if self.__leave_stopped:
			pstree_check_stopped(self.__test.getpid())
			pstree_signal(self.__test.getpid(), signal.SIGKILL)

		if self.__page_server:
			wait_pid_die(int(rpidfile(self.__ddir() + "/ps.pid")), "page server")

	def restore(self):
		r_opts = []
		if self.__restore_sibling:
			r_opts = ["--restore-sibling"]
			self.__test.auto_reap = False
		r_opts += self.__test.getropts()
		if self.__join_ns:
			r_opts.append("--join-ns")
			r_opts.append("net:%s" % join_ns_file)

		self.__prev_dump_iter = None
		criu_dir = os.path.dirname(os.getcwd())
		if os.getenv("GCOV"):
			r_opts.append("--ext-mount-map")
			r_opts.append("zdtm:%s" % criu_dir)

		if self.__leave_stopped:
			r_opts += ['--leave-stopped']

		self.__criu_act("restore", opts = r_opts + ["--restore-detached"])

		if self.__leave_stopped:
			pstree_check_stopped(self.__test.getpid())
			pstree_signal(self.__test.getpid(), signal.SIGCONT)

	@staticmethod
	def check(feature):
		return criu_cli.run("check", ["-v0", "--feature", feature]) == 0

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
# Step by step execution
#

do_sbs = False


def init_sbs():
	if sys.stdout.isatty():
		global do_sbs
		do_sbs = True
	else:
		print "Can't do step-by-step in this runtime"


def sbs(what):
	if do_sbs:
		raw_input("Pause at %s. Press any key to continue." % what)


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
				try_run_hook(test, ["--post-pre-dump"])
			time.sleep(pres[1])

		sbs('pre-dump')

		if opts['norst']:
			cr_api.dump("dump", opts = ["--leave-running"])
		else:
			cr_api.dump("dump")
			test.gone()
			sbs('pre-restore')
			try_run_hook(test, ["--pre-restore"])
			cr_api.restore()
			sbs('post-restore')

		time.sleep(iters[1])


# Additional checks that can be done outside of test process

def get_visible_state(test):
	maps = {}
	files = {}
	mounts = {}

	if not getattr(test, "static", lambda: False)() or \
	   not getattr(test, "ns", lambda: False)():
		return ({}, {}, {})

	r = re.compile('^[0-9]+$')
	pids = filter(lambda p: r.match(p), os.listdir("/proc/%s/root/proc/" % test.getpid()))
	for pid in pids:
		files[pid] = set(os.listdir("/proc/%s/root/proc/%s/fd" % (test.getpid(), pid)))

		cmaps = [[0, 0, ""]]
		last = 0
		for mp in open("/proc/%s/root/proc/%s/maps" % (test.getpid(), pid)):
			m = map(lambda x: int('0x' + x, 0), mp.split()[0].split('-'))

			m.append(mp.split()[1])

			f = "/proc/%s/root/proc/%s/map_files/%s" % (test.getpid(), pid, mp.split()[0])
			if os.access(f, os.F_OK):
				st = os.lstat(f)
				m.append(oct(st.st_mode))

			if cmaps[last][1] == m[0] and cmaps[last][2] == m[2]:
				cmaps[last][1] = m[1]
			else:
				cmaps.append(m)
				last += 1

		maps[pid] = set(map(lambda x: '%x-%x %s' % (x[0], x[1], x[2:]), cmaps))

		cmounts = []
		try:
			r = re.compile("^\S+\s\S+\s\S+\s(\S+)\s(\S+)")
			for m in open("/proc/%s/root/proc/%s/mountinfo" % (test.getpid(), pid)):
				cmounts.append(r.match(m).groups())
		except IOError, e:
			if e.errno != errno.EINVAL:
				raise e
		mounts[pid] = cmounts
	return files, maps, mounts


def check_visible_state(test, state, opts):
	new = get_visible_state(test)

	for pid in state[0].keys():
		fnew = new[0][pid]
		fold = state[0][pid]
		if fnew != fold:
			print "%s: Old files lost: %s" % (pid, fold - fnew)
			print "%s: New files appeared: %s" % (pid, fnew - fold)
			raise test_fail_exc("fds compare")

		old_maps = state[1][pid]
		new_maps = new[1][pid]
		if old_maps != new_maps:
			print "%s: Old maps lost: %s" % (pid, old_maps - new_maps)
			print "%s: New maps appeared: %s" % (pid, new_maps - old_maps)
			if not opts['fault']:  # skip parasite blob
				raise test_fail_exc("maps compare")

		old_mounts = state[2][pid]
		new_mounts = new[2][pid]
		for i in xrange(len(old_mounts)):
			m = old_mounts.pop(0)
			if m in new_mounts:
				new_mounts.remove(m)
			else:
				old_mounts.append(m)
		if old_mounts or new_mounts:
			print "%s: Old mounts lost: %s" % (pid, old_mounts)
			print "%s: New mounts appeared: %s" % (pid, new_mounts)
			raise test_fail_exc("mounts compare")

	if '--link-remap' in test.getdopts():
		import glob
		link_remap_list = glob.glob(os.path.dirname(test.getname()) + '/link_remap*')
		if link_remap_list:
			print "%s: link-remap files left: %s" % (test.getname(), link_remap_list)
			raise test_fail_exc("link remaps left")


class noop_freezer:
	def __init__(self):
		self.kernel = False

	def attach(self):
		pass

	def freeze(self):
		pass

	def thaw(self):
		pass

	def getdopts(self):
		return []

	def getropts(self):
		return []


class cg_freezer:
	def __init__(self, path, state):
		self.__path = '/sys/fs/cgroup/freezer/' + path
		self.__state = state
		self.kernel = True

	def attach(self):
		if not os.access(self.__path, os.F_OK):
			os.makedirs(self.__path)
		with open(self.__path + '/tasks', 'w') as f:
			f.write('0')

	def __set_state(self, state):
		with open(self.__path + '/freezer.state', 'w') as f:
			f.write(state)

	def freeze(self):
		if self.__state.startswith('f'):
			self.__set_state('FROZEN')

	def thaw(self):
		if self.__state.startswith('f'):
			self.__set_state('THAWED')

	def getdopts(self):
		return ['--freeze-cgroup', self.__path, '--manage-cgroups']

	def getropts(self):
		return ['--manage-cgroups']


def get_freezer(desc):
	if not desc:
		return noop_freezer()

	fd = desc.split(':')
	fr = cg_freezer(path = fd[0], state = fd[1])
	return fr


def cmp_ns(ns1, match, ns2, msg):
	ns1_ino = os.stat(ns1).st_ino
	ns2_ino = os.stat(ns2).st_ino
	if eval("%r %s %r" % (ns1_ino, match, ns2_ino)):
		print "%s match (%r %s %r) fail" % (msg, ns1_ino, match, ns2_ino)
		raise test_fail_exc("%s compare" % msg)


def check_joinns_state(t):
	cmp_ns("/proc/%s/ns/net" % t.getpid(), "!=", join_ns_file, "join-ns")


def pstree_each_pid(root_pid):
	f_children_path = "/proc/{0}/task/{0}/children".format(root_pid)
	child_pids = []
	try:
		with open(f_children_path, "r") as f_children:
			pid_line = f_children.readline().strip(" \n")
			if pid_line:
				child_pids += pid_line.split(" ")
	except:
		return  # process is dead

	yield root_pid
	for child_pid in child_pids:
		for pid in pstree_each_pid(child_pid):
			yield pid


def is_proc_stopped(pid):
	def get_thread_status(thread_dir):
		try:
			with open(os.path.join(thread_dir, "status")) as f_status:
				for line in f_status.readlines():
					if line.startswith("State:"):
						return line.split(":", 1)[1].strip().split(" ")[0]
		except:
			pass  # process is dead
		return None

	def is_thread_stopped(status):
		return (status is None) or (status == "T") or (status == "Z")

	tasks_dir = "/proc/%s/task" % pid
	thread_dirs = []
	try:
		thread_dirs = os.listdir(tasks_dir)
	except:
		pass  # process is dead

	for thread_dir in thread_dirs:
		thread_status = get_thread_status(os.path.join(tasks_dir, thread_dir))
		if not is_thread_stopped(thread_status):
			return False

	if not is_thread_stopped(get_thread_status("/proc/%s" % pid)):
		return False

	return True


def pstree_check_stopped(root_pid):
	for pid in pstree_each_pid(root_pid):
		if not is_proc_stopped(pid):
			raise test_fail_exc("CRIU --leave-stopped %s" % pid)


def pstree_signal(root_pid, signal):
	for pid in pstree_each_pid(root_pid):
		try:
			os.kill(int(pid), signal)
		except:
			pass  # process is dead


def do_run_test(tname, tdesc, flavs, opts):
	tcname = tname.split('/')[0]
	tclass = test_classes.get(tcname, None)
	if not tclass:
		print "Unknown test class %s" % tcname
		return

	if opts['report']:
		init_report(opts['report'])
	if opts['sbs']:
		init_sbs()

	fcg = get_freezer(opts['freezecg'])

	for f in flavs:
		print
		print_sep("Run %s in %s" % (tname, f))
		if opts['dry_run']:
			continue
		flav = flavors[f](opts)
		t = tclass(tname, tdesc, flav, fcg)
		cr_api = criu(opts)

		try:
			t.start()
			s = get_visible_state(t)
			try:
				cr(cr_api, t, opts)
			except test_fail_expected_exc as e:
				if e.cr_action == "dump":
					t.stop()
			else:
				check_visible_state(t, s, opts)
				if opts['join_ns']:
					check_joinns_state(t)
				t.stop()
				try_run_hook(t, ["--clean"])
		except test_fail_exc as e:
			print_sep("Test %s FAIL at %s" % (tname, e.step), '#')
			t.print_output()
			t.kill()
			if cr_api.logs():
				add_to_report(cr_api.logs(), tname.replace('/', '_') + "_" + f + "/images")
			if opts['keep_img'] == 'never':
				cr_api.cleanup()
			# When option --keep-going not specified this exit
			# does two things: exits from subprocess and aborts the
			# main script execution on the 1st error met
			sys.exit(encode_flav(f))
		else:
			if opts['keep_img'] != 'always':
				cr_api.cleanup()
			print_sep("Test %s PASS" % tname)


class launcher:
	def __init__(self, opts, nr_tests):
		self.__opts = opts
		self.__total = nr_tests
		self.__runtest = 0
		self.__nr = 0
		self.__max = int(opts['parallel'] or 1)
		self.__subs = {}
		self.__fail = False
		self.__file_report = None
		if self.__max > 1 and self.__total > 1:
			self.__use_log = True
		elif opts['report']:
			self.__use_log = True
		else:
			self.__use_log = False

		if opts['report'] and (opts['keep_going'] or self.__total == 1):
			now = datetime.datetime.now()
			att = 0
			reportname = os.path.join(report_dir, "criu-testreport.tap")
			while os.access(reportname, os.F_OK):
				reportname = os.path.join(report_dir, "criu-testreport" + ".%d.tap" % att)
				att += 1

			self.__file_report = open(reportname, 'a')
			print >> self.__file_report, "# Hardware architecture: " + arch
			print >> self.__file_report, "# Timestamp: " + now.strftime("%Y-%m-%d %H:%M") + " (GMT+1)"
			print >> self.__file_report, "# "
			print >> self.__file_report, "TAP version 13"
			print >> self.__file_report, "1.." + str(nr_tests)

	def __show_progress(self):
		perc = self.__nr * 16 / self.__total
		print "=== Run %d/%d %s" % (self.__nr, self.__total, '=' * perc + '-' * (16 - perc))

	def skip(self, name, reason):
		print "Skipping %s (%s)" % (name, reason)
		self.__nr += 1
		self.__runtest += 1
		if self.__file_report:
			testline = "ok %d - %s # SKIP %s" % (self.__runtest, name, reason)
			print >> self.__file_report, testline

	def run_test(self, name, desc, flavor):

		if len(self.__subs) >= self.__max:
			self.wait()

		if test_flag(desc, 'excl'):
			self.wait_all()

		self.__nr += 1
		self.__show_progress()

		nd = ('nocr', 'norst', 'pre', 'iters', 'page_server', 'sibling', 'stop',
				'fault', 'keep_img', 'report', 'snaps', 'sat', 'script', 'rpc',
				'join_ns', 'dedup', 'sbs', 'freezecg', 'user', 'dry_run', 'noauto_dedup')
		arg = repr((name, desc, flavor, {d: self.__opts[d] for d in nd}))

		if self.__use_log:
			logf = name.replace('/', '_') + ".log"
			log = open(logf, "w")
		else:
			logf = None
			log = None

		sub = subprocess.Popen(["./zdtm_ct", "zdtm.py"],
				env = dict(os.environ, CR_CT_TEST_INFO = arg),
				stdout = log, stderr = subprocess.STDOUT, close_fds = True)
		self.__subs[sub.pid] = {'sub': sub, 'log': logf, 'name': name}

		if test_flag(desc, 'excl'):
			self.wait()

	def __wait_one(self, flags):
		pid, status = os.waitpid(0, flags)
		self.__runtest += 1
		if pid != 0:
			sub = self.__subs.pop(pid)
			if status != 0:
				self.__fail = True
				failed_flavor = decode_flav(os.WEXITSTATUS(status))
				if self.__file_report:
					testline = "not ok %d - %s # flavor %s" % (self.__runtest, sub['name'], failed_flavor)
					details = {'output': open(sub['log']).read()}
					print >> self.__file_report, testline
					print >> self.__file_report, yaml.dump(details, explicit_start=True, explicit_end=True, default_style='|')
				if sub['log']:
					add_to_output(sub['log'])
			else:
				if self.__file_report:
					testline = "ok %d - %s" % (self.__runtest, sub['name'])
					print >> self.__file_report, testline

			if sub['log']:
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
		if self.__fail and not opts['keep_going']:
			raise test_fail_exc('')

	def wait_all(self):
		self.__wait_all()
		if self.__fail and not opts['keep_going']:
			raise test_fail_exc('')

	def finish(self):
		self.__wait_all()
		if not opts['fault'] and check_core_files():
			self.__fail = True
		if self.__file_report:
			self.__file_report.close()
		if self.__fail:
			print_sep("FAIL", "#")
			sys.exit(1)


def all_tests(opts):
	desc = eval(open(opts['set'] + '.desc').read())
	lst = subprocess.Popen(['find', desc['dir'], '-type', 'f', '-executable'],
			stdout = subprocess.PIPE)
	excl = map(lambda x: os.path.join(desc['dir'], x), desc['exclude'])
	tlist = filter(lambda x:
			not x.endswith('.checkskip') and
			not x.endswith('.hook') and
			x not in excl,
			map(lambda x: x.strip(), lst.stdout.readlines())
			)
	lst.wait()
	return tlist


# Descriptor for abstract test not in list
default_test = {}


def get_test_desc(tname):
	d_path = tname + '.desc'
	if os.access(d_path, os.F_OK):
		return eval(open(d_path).read())

	return default_test


def self_checkskip(tname):
	chs = tname + '.checkskip'
	if os.access(chs, os.X_OK):
		ch = subprocess.Popen([chs])
		return not ch.wait() == 0

	return False


def print_fname(fname, typ):
	print "=[%s]=> %s" % (typ, fname)


def print_sep(title, sep = "=", width = 80):
	print (" " + title + " ").center(width, sep)


def grep_errors(fname):
	first = True
	for l in open(fname):
		if "Error" in l:
			if first:
				print_fname(fname, 'log')
				print_sep("grep Error", "-", 60)
				first = False
			print l,
	if not first:
		print_sep("ERROR OVER", "-", 60)


def run_tests(opts):
	excl = None
	features = {}

	if opts['pre'] or opts['snaps']:
		if not criu.check("mem_dirty_track"):
			print "Tracking memory is not available"
			return

	if opts['keep_going'] and (not opts['all']):
		print "[WARNING] Option --keep-going is more useful with option --all."

	if opts['all']:
		torun = all_tests(opts)
		run_all = True
	elif opts['tests']:
		r = re.compile(opts['tests'])
		torun = filter(lambda x: r.match(x), all_tests(opts))
		opts['keep_going'] = False
		run_all = True
	elif opts['test']:
		torun = opts['test']
		opts['keep_going'] = False
		run_all = False
	elif opts['from']:
		if not os.access(opts['from'], os.R_OK):
			print "No such file"
			return

		torun = map(lambda x: x.strip(), open(opts['from']))
		opts['keep_going'] = False
		run_all = True
	else:
		print "Specify test with -t <name> or -a"
		return

	if opts['exclude']:
		excl = re.compile(".*(" + "|".join(opts['exclude']) + ")")
		print "Compiled exclusion list"

	if opts['report']:
		init_report(opts['report'])

	if opts['parallel'] and opts['freezecg']:
		print "Parallel launch with freezer not supported"
		opts['parallel'] = None

	if opts['join_ns']:
		if subprocess.Popen(["ip", "netns", "add", "zdtm_netns"]).wait():
			raise Exception("Unable to create a network namespace")
		if subprocess.Popen(["ip", "netns", "exec", "zdtm_netns", "ip", "link", "set", "up", "dev", "lo"]).wait():
			raise Exception("ip link set up dev lo")

	l = launcher(opts, len(torun))
	try:
		for t in torun:
			global arch

			if excl and excl.match(t):
				l.skip(t, "exclude")
				continue

			tdesc = get_test_desc(t)
			if tdesc.get('arch', arch) != arch:
				l.skip(t, "arch %s" % tdesc['arch'])
				continue

			if run_all and test_flag(tdesc, 'noauto'):
				l.skip(t, "manual run only")
				continue

			feat = tdesc.get('feature', None)
			if feat:
				if feat not in features:
					print "Checking feature %s" % feat
					features[feat] = criu.check(feat)

				if not features[feat]:
					l.skip(t, "no %s feature" % feat)
					continue

			if self_checkskip(t):
				l.skip(t, "checkskip failed")
				continue

			if opts['user']:
				if test_flag(tdesc, 'suid'):
					l.skip(t, "suid test in user mode")
					continue
				if test_flag(tdesc, 'nouser'):
					l.skip(t, "criu root prio needed")
					continue

			if opts['join_ns']:
				if test_flag(tdesc, 'samens'):
					l.skip(t, "samens test in the same namespace")
					continue

			test_flavs = tdesc.get('flavor', 'h ns uns').split()
			opts_flavs = (opts['flavor'] or 'h,ns,uns').split(',')
			if opts_flavs != ['best']:
				run_flavs = set(test_flavs) & set(opts_flavs)
			else:
				run_flavs = set([test_flavs.pop()])
			if not criu.check("userns"):
				run_flavs -= set(['uns'])
			if opts['user']:
				# FIXME -- probably uns will make sense
				run_flavs -= set(['ns', 'uns'])

			# remove ns and uns flavor in join_ns
			if opts['join_ns']:
				run_flavs -= set(['ns', 'uns'])

			if run_flavs:
				l.run_test(t, tdesc, run_flavs)
			else:
				l.skip(t, "no flavors")
	finally:
		l.finish()
		if opts['join_ns']:
			subprocess.Popen(["ip", "netns", "delete", "zdtm_netns"])

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


class group:
	def __init__(self, tname, tdesc):
		self.__tests = [tname]
		self.__desc = tdesc
		self.__deps = set()

	def __is_mergeable_desc(self, desc):
		# For now make it full match
		if self.__desc.get('flags') != desc.get('flags'):
			return False
		if self.__desc.get('flavor') != desc.get('flavor'):
			return False
		if self.__desc.get('arch') != desc.get('arch'):
			return False
		if self.__desc.get('opts') != desc.get('opts'):
			return False
		if self.__desc.get('feature') != desc.get('feature'):
			return False
		return True

	def merge(self, tname, tdesc):
		if not self.__is_mergeable_desc(tdesc):
			return False

		self.__deps |= set(tdesc.get('deps', []))
		self.__tests.append(tname)
		return True

	def size(self):
		return len(self.__tests)

	# common method to write a "meta" auxiliary script (hook/checkskip)
	# which will call all tests' scripts in turn
	def __dump_meta(self, fname, ext):
		scripts = filter(lambda names: os.access(names[1], os.X_OK),
				map(lambda test: (test, test + ext),
				self.__tests))
		if scripts:
			f = open(fname + ext, "w")
			f.write("#!/bin/sh -e\n")

			for test, script in scripts:
				f.write("echo 'Running %s for %s'\n" % (ext, test))
				f.write('%s "$@"\n' % script)

			f.write("echo 'All %s scripts OK'\n" % ext)
			f.close()
			os.chmod(fname + ext, 0700)

	def dump(self, fname):
		f = open(fname, "w")
		for t in self.__tests:
			f.write(t + '\n')
		f.close()
		os.chmod(fname, 0700)

		if len(self.__desc) or len(self.__deps):
			f = open(fname + '.desc', "w")
			if len(self.__deps):
				self.__desc['deps'] = list(self.__deps)
			f.write(repr(self.__desc))
			f.close()

		# write "meta" .checkskip and .hook scripts
		self.__dump_meta(fname, '.checkskip')
		self.__dump_meta(fname, '.hook')


def group_tests(opts):
	excl = None
	groups = []
	pend_groups = []
	maxs = int(opts['max_size'])

	if not os.access("groups", os.F_OK):
		os.mkdir("groups")

	tlist = all_tests(opts)
	random.shuffle(tlist)
	if opts['exclude']:
		excl = re.compile(".*(" + "|".join(opts['exclude']) + ")")
		print "Compiled exclusion list"

	for t in tlist:
		if excl and excl.match(t):
			continue

		td = get_test_desc(t)

		for g in pend_groups:
			if g.merge(t, td):
				if g.size() == maxs:
					pend_groups.remove(g)
					groups.append(g)
				break
		else:
			g = group(t, td)
			pend_groups.append(g)

	groups += pend_groups

	nr = 0
	suf = opts['name'] or 'group'

	for g in groups:
		if maxs > 1 and g.size() == 1:  # Not much point in group test for this
			continue

		fn = os.path.join("groups", "%s.%d" % (suf, nr))
		g.dump(fn)
		nr += 1

	print "Generated %d group(s)" % nr


def clean_stuff(opts):
	print "Cleaning %s" % opts['what']
	if opts['what'] == 'nsroot':
		for f in flavors:
			f = flavors[f]
			f.clean()


#
# main() starts here
#

if 'CR_CT_TEST_INFO' in os.environ:
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
				if os.WIFEXITED(status):
					status = os.WEXITSTATUS(status)
				else:
					status = 1
				break

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
rp.add_argument("-F", "--from", help = "From file")
rp.add_argument("-f", "--flavor", help = "Flavor to run")
rp.add_argument("-x", "--exclude", help = "Exclude tests from --all run", action = 'append')

rp.add_argument("--sibling", help = "Restore tests as siblings", action = 'store_true')
rp.add_argument("--join-ns", help = "Restore tests and join existing namespace", action = 'store_true')
rp.add_argument("--pre", help = "Do some pre-dumps before dump (n[:pause])")
rp.add_argument("--snaps", help = "Instead of pre-dumps do full dumps", action = 'store_true')
rp.add_argument("--dedup", help = "Auto-deduplicate images on iterations", action = 'store_true')
rp.add_argument("--noauto-dedup", help = "Manual deduplicate images on iterations", action = 'store_true')
rp.add_argument("--nocr", help = "Do not CR anything, just check test works", action = 'store_true')
rp.add_argument("--norst", help = "Don't restore tasks, leave them running after dump", action = 'store_true')
rp.add_argument("--stop", help = "Check that --leave-stopped option stops ps tree.", action = 'store_true')
rp.add_argument("--iters", help = "Do CR cycle several times before check (n[:pause])")
rp.add_argument("--fault", help = "Test fault injection")
rp.add_argument("--sat", help = "Generate criu strace-s for sat tool (restore is fake, images are kept)", action = 'store_true')
rp.add_argument("--sbs", help = "Do step-by-step execution, asking user for keypress to continue", action = 'store_true')
rp.add_argument("--freezecg", help = "Use freeze cgroup (path:state)")
rp.add_argument("--user", help = "Run CRIU as regular user", action = 'store_true')
rp.add_argument("--rpc", help = "Run CRIU via RPC rather than CLI", action = 'store_true')

rp.add_argument("--page-server", help = "Use page server dump", action = 'store_true')
rp.add_argument("-p", "--parallel", help = "Run test in parallel")
rp.add_argument("--dry-run", help="Don't run tests, just pretend to", action='store_true')
rp.add_argument("--script", help="Add script to get notified by criu")
rp.add_argument("-k", "--keep-img", help = "Whether or not to keep images after test",
		choices = ['always', 'never', 'failed'], default = 'failed')
rp.add_argument("--report", help = "Generate summary report in directory")
rp.add_argument("--keep-going", help = "Keep running tests in spite of failures", action = 'store_true')

lp = sp.add_parser("list", help = "List tests")
lp.set_defaults(action = list_tests)
lp.add_argument('-i', '--info', help = "Show more info about tests", action = 'store_true')

gp = sp.add_parser("group", help = "Generate groups")
gp.set_defaults(action = group_tests)
gp.add_argument("-m", "--max-size", help = "Maximum number of tests in group")
gp.add_argument("-n", "--name", help = "Common name for group tests")
gp.add_argument("-x", "--exclude", help = "Exclude tests from --all run", action = 'append')

cp = sp.add_parser("clean", help = "Clean something")
cp.set_defaults(action = clean_stuff)
cp.add_argument("what", choices = ['nsroot'])

opts = vars(p.parse_args())
if opts.get('sat', False):
	opts['keep_img'] = 'always'

if opts['debug']:
	sys.settrace(traceit)

criu.available()
for tst in test_classes.values():
	tst.available()

opts['action'](opts)
