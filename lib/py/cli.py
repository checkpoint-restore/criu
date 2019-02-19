from __future__ import print_function
import argparse
import sys
import json
import os

import pycriu

def inf(opts):
	if opts['in']:
		return open(opts['in'], 'rb')
	else:
		return sys.stdin

def outf(opts):
	if opts['out']:
		return open(opts['out'], 'w+')
	else:
		return sys.stdout

def dinf(opts, name):
	return open(os.path.join(opts['dir'], name))

def decode(opts):
	indent = None

	try:
		img = pycriu.images.load(inf(opts), opts['pretty'], opts['nopl'])
	except pycriu.images.MagicException as exc:
		print("Unknown magic %#x.\n"\
				"Maybe you are feeding me an image with "\
				"raw data(i.e. pages.img)?" % exc.magic, file=sys.stderr)
		sys.exit(1)

	if opts['pretty']:
		indent = 4

	f = outf(opts)
	json.dump(img, f, indent=indent)
	if f == sys.stdout:
		f.write("\n")

def encode(opts):
	img = json.load(inf(opts))
	pycriu.images.dump(img, outf(opts))

def info(opts):
	infs = pycriu.images.info(inf(opts))
	json.dump(infs, sys.stdout, indent = 4)
	print()

def get_task_id(p, val):
	return p[val] if val in p else p['ns_' + val][0]
#
# Explorers
#

class ps_item:
	def __init__(self, p, core):
		self.pid = get_task_id(p, 'pid')
		self.ppid = p['ppid']
		self.p = p
		self.core = core
		self.kids = []

def show_ps(p, opts, depth = 0):
	print("%7d%7d%7d   %s%s" % (p.pid, get_task_id(p.p, 'pgid'), get_task_id(p.p, 'sid'),
			' ' * (4 * depth), p.core['tc']['comm']))
	for kid in p.kids:
		show_ps(kid, opts, depth + 1)

def explore_ps(opts):
	pss = { }
	ps_img = pycriu.images.load(dinf(opts, 'pstree.img'))
	for p in ps_img['entries']:
		core = pycriu.images.load(dinf(opts, 'core-%d.img' % get_task_id(p, 'pid')))
		ps = ps_item(p, core['entries'][0])
		pss[ps.pid] = ps

	# Build tree
	psr = None
	for pid in pss:
		p = pss[pid]
		if p.ppid == 0:
			psr = p
			continue

		pp = pss[p.ppid]
		pp.kids.append(p)

	print("%7s%7s%7s   %s" % ('PID', 'PGID', 'SID', 'COMM'))
	show_ps(psr, opts)

files_img = None

def ftype_find_in_files(opts, ft, fid):
	global files_img

	if files_img is None:
		try:
			files_img = pycriu.images.load(dinf(opts, "files.img"))['entries']
		except:
			files_img = []

	if len(files_img) == 0:
		return None

	for f in files_img:
		if f['id'] == fid:
			return f

	return None


def ftype_find_in_image(opts, ft, fid, img):
	f = ftype_find_in_files(opts, ft, fid)
	if f:
		return f[ft['field']]

	if ft['img'] == None:
		ft['img'] = pycriu.images.load(dinf(opts, img))['entries']
	for f in ft['img']:
		if f['id'] == fid:
			return f
	return None

def ftype_reg(opts, ft, fid):
	rf = ftype_find_in_image(opts, ft, fid, 'reg-files.img')
	return rf and rf['name'] or 'unknown path'

def ftype_pipe(opts, ft, fid):
	p = ftype_find_in_image(opts, ft, fid, 'pipes.img')
	return p and 'pipe[%d]' % p['pipe_id'] or 'pipe[?]'

def ftype_unix(opts, ft, fid):
	ux = ftype_find_in_image(opts, ft, fid, 'unixsk.img')
	if not ux:
		return 'unix[?]'

	n = ux['name'] and ' %s' % ux['name'] or ''
	return 'unix[%d (%d)%s]' % (ux['ino'], ux['peer'], n)

file_types = {
	'REG':		{'get': ftype_reg,	'img': None,	'field': 'reg'},
	'PIPE':		{'get': ftype_pipe,	'img': None,	'field': 'pipe'},
	'UNIXSK':	{'get': ftype_unix,	'img': None,	'field': 'usk'},
}

def ftype_gen(opts, ft, fid):
	return '%s.%d' % (ft['typ'], fid)

files_cache = { }

def get_file_str(opts, fd):
	key = (fd['type'], fd['id'])
	f = files_cache.get(key, None)
	if not f:
		ft = file_types.get(fd['type'], {'get': ftype_gen, 'typ': fd['type']})
		f = ft['get'](opts, ft, fd['id'])
		files_cache[key] = f

	return f

def explore_fds(opts):
	ps_img = pycriu.images.load(dinf(opts, 'pstree.img'))
	for p in ps_img['entries']:
		pid = get_task_id(p, 'pid')
		idi = pycriu.images.load(dinf(opts, 'ids-%s.img' % pid))
		fdt = idi['entries'][0]['files_id']
		fdi = pycriu.images.load(dinf(opts, 'fdinfo-%d.img' % fdt))

		print("%d" % pid)
		for fd in fdi['entries']:
			print("\t%7d: %s" % (fd['fd'], get_file_str(opts, fd)))

		fdi = pycriu.images.load(dinf(opts, 'fs-%d.img' % pid))['entries'][0]
		print("\t%7s: %s" % ('cwd', get_file_str(opts, {'type': 'REG', 'id': fdi['cwd_id']})))
		print("\t%7s: %s" % ('root', get_file_str(opts, {'type': 'REG', 'id': fdi['root_id']})))


class vma_id:
	def __init__(self):
		self.__ids = {}
		self.__last = 1

	def get(self, iid):
		ret = self.__ids.get(iid, None)
		if not ret:
			ret = self.__last
			self.__last += 1
			self.__ids[iid] = ret

		return ret

def explore_mems(opts):
	ps_img = pycriu.images.load(dinf(opts, 'pstree.img'))
	vids = vma_id()
	for p in ps_img['entries']:
		pid = get_task_id(p, 'pid')
		mmi = pycriu.images.load(dinf(opts, 'mm-%d.img' % pid))['entries'][0]

		print("%d" % pid)
		print("\t%-36s    %s" % ('exe', get_file_str(opts, {'type': 'REG', 'id': mmi['exe_file_id']})))

		for vma in mmi['vmas']:
			st = vma['status']
			if st & (1 << 10):
				fn = ' ' + 'ips[%lx]' % vids.get(vma['shmid'])
			elif st & (1 << 8):
				fn = ' ' + 'shmem[%lx]' % vids.get(vma['shmid'])
			elif st & (1 << 11):
				fn = ' ' + 'packet[%lx]' % vids.get(vma['shmid'])
			elif st & ((1 << 6) | (1 << 7)):
				fn = ' ' + get_file_str(opts, {'type': 'REG', 'id': vma['shmid']})
				if vma['pgoff']:
					fn += ' + %#lx' % vma['pgoff']
				if st & (1 << 7):
					fn += ' (s)'
			elif st & (1 << 1):
				fn = ' [stack]'
			elif st & (1 << 2):
				fn = ' [vsyscall]'
			elif st & (1 << 3):
				fn = ' [vdso]'
			elif vma['flags'] & 0x0100: # growsdown
				fn = ' [stack?]'
			else:
				fn = ''

			if not st & (1 << 0):
				fn += ' *'

			prot = vma['prot'] & 0x1 and 'r' or '-'
			prot += vma['prot'] & 0x2 and 'w' or '-'
			prot += vma['prot'] & 0x4 and 'x' or '-'

			astr = '%08lx-%08lx' % (vma['start'], vma['end'])
			print("\t%-36s%s%s" % (astr, prot, fn))


def explore_rss(opts):
	ps_img = pycriu.images.load(dinf(opts, 'pstree.img'))
	for p in ps_img['entries']:
		pid = get_task_id(p, 'pid')
		vmas = pycriu.images.load(dinf(opts, 'mm-%d.img' % pid))['entries'][0]['vmas']
		pms = pycriu.images.load(dinf(opts, 'pagemap-%d.img' % pid))['entries']

		print("%d" % pid)
		vmi = 0
		pvmi = -1
		for pm in pms[1:]:
			pstr = '\t%lx / %-8d' % (pm['vaddr'], pm['nr_pages'])
			while vmas[vmi]['end'] <= pm['vaddr']:
				vmi += 1

			pme = pm['vaddr'] + (pm['nr_pages'] << 12)
			vstr = ''
			while vmas[vmi]['start'] < pme:
				vma = vmas[vmi]
				if vmi == pvmi:
					vstr += ' ~'
				else:
					vstr += ' %08lx / %-8d' % (vma['start'], (vma['end'] - vma['start'])>>12)
					if vma['status'] & ((1 << 6) | (1 << 7)):
						vstr += ' ' + get_file_str(opts, {'type': 'REG', 'id': vma['shmid']})
					pvmi = vmi
				vstr += '\n\t%23s' % ''
				vmi += 1

			vmi -= 1

			print('%-24s%s' % (pstr, vstr))



explorers = { 'ps': explore_ps, 'fds': explore_fds, 'mems': explore_mems, 'rss': explore_rss }

def explore(opts):
	explorers[opts['what']](opts)

def main():
	desc = 'CRiu Image Tool'
	parser = argparse.ArgumentParser(description=desc,
			formatter_class=argparse.RawTextHelpFormatter)

	subparsers = parser.add_subparsers(help='Use crit CMD --help for command-specific help')

	# Decode
	decode_parser = subparsers.add_parser('decode',
			help = 'convert criu image from binary type to json')
	decode_parser.add_argument('--pretty',
			help = 'Multiline with indents and some numerical fields in field-specific format',
			action = 'store_true')
	decode_parser.add_argument('-i',
			    '--in',
			help = 'criu image in binary format to be decoded (stdin by default)')
	decode_parser.add_argument('-o',
			    '--out',
			help = 'where to put criu image in json format (stdout by default)')
	decode_parser.set_defaults(func=decode, nopl=False)

	# Encode
	encode_parser = subparsers.add_parser('encode',
			help = 'convert criu image from json type to binary')
	encode_parser.add_argument('-i',
			    '--in',
			help = 'criu image in json format to be encoded (stdin by default)')
	encode_parser.add_argument('-o',
			    '--out',
			help = 'where to put criu image in binary format (stdout by default)')
	encode_parser.set_defaults(func=encode)

	# Info
	info_parser = subparsers.add_parser('info',
			help = 'show info about image')
	info_parser.add_argument("in")
	info_parser.set_defaults(func=info)

	# Explore
	x_parser = subparsers.add_parser('x', help = 'explore image dir')
	x_parser.add_argument('dir')
	x_parser.add_argument('what', choices = [ 'ps', 'fds', 'mems', 'rss'])
	x_parser.set_defaults(func=explore)

	# Show
	show_parser = subparsers.add_parser('show',
			help = "convert criu image from binary to human-readable json")
	show_parser.add_argument("in")
	show_parser.add_argument('--nopl', help = 'do not show entry payload (if exists)', action = 'store_true')
	show_parser.set_defaults(func=decode, pretty=True, out=None)

	opts = vars(parser.parse_args())

	if not opts:
		sys.stderr.write(parser.format_usage())
		sys.stderr.write("crit: error: too few arguments\n")
		sys.exit(1)

	opts["func"](opts)

if __name__ == '__main__':
	main()
